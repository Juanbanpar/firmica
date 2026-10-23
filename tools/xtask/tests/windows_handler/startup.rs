//! Read-only startup metadata; never records command lines, lock names or document data.
use super::*;
use serde_json::{json, Value};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        CloseThreadWaitChainSession, GetThreadWaitChain, OpenThreadWaitChainSession, WctThreadType,
        WAITCHAIN_NODE_INFO, WCT_MAX_NODE_COUNT,
    },
    StationsAndDesktops::{
        GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW, UOI_NAME,
    },
};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM},
    UI::WindowsAndMessaging::{EnumThreadWindows, GetClassNameW, GetWindowTextW, IsWindowVisible},
};

unsafe extern "system" fn window_metadata(window: HWND, context: LPARAM) -> i32 {
    let items = unsafe { &mut *(context as *mut Vec<Value>) };
    let mut class = [0u16; 128];
    let count = unsafe { GetClassNameW(window, class.as_mut_ptr(), class.len() as i32) };
    let mut title = [0u16; 128];
    let title_count = unsafe { GetWindowTextW(window, title.as_mut_ptr(), title.len() as i32) };
    items.push(json!({"class":String::from_utf16_lossy(&class[..count.max(0) as usize]),
        "visible":unsafe {IsWindowVisible(window)}!=0,
        "firmica_title":String::from_utf16_lossy(&title[..title_count.max(0) as usize])=="Firmica"}));
    1
}

fn windows(thread: u32) -> Value {
    let mut items = Vec::<Value>::new();
    unsafe {
        EnumThreadWindows(
            thread,
            Some(window_metadata),
            (&mut items as *mut Vec<Value>) as isize,
        );
    }
    json!(items)
}

fn object_name(handle: HANDLE) -> Option<String> {
    let mut name = [0u16; 256];
    let mut needed = 0;
    if unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            mem::size_of_val(&name) as u32,
            &mut needed,
        )
    } == 0
    {
        return None;
    }
    String::from_utf16(&name[..name.iter().position(|unit| *unit == 0)?]).ok()
}

fn wait_chain(thread: u32) -> Value {
    let session = unsafe { OpenThreadWaitChainSession(0, None) };
    if session.is_null() {
        return json!({"error":std::io::Error::last_os_error().raw_os_error()});
    }
    let mut nodes = [WAITCHAIN_NODE_INFO::default(); WCT_MAX_NODE_COUNT as usize];
    let mut count = WCT_MAX_NODE_COUNT;
    let mut cycle = 0;
    let success = unsafe {
        GetThreadWaitChain(
            session,
            0,
            0,
            thread,
            &mut count,
            nodes.as_mut_ptr(),
            &mut cycle,
        )
    };
    let error = std::io::Error::last_os_error().raw_os_error();
    unsafe {
        CloseThreadWaitChainSession(session);
    }
    if success == 0 {
        return json!({"error":error});
    }
    json!({"cycle":cycle!=0,"nodes":nodes.iter().take(count as usize).map(|node| {
        let mut item = json!({"type":node.ObjectType,"status":node.ObjectStatus});
        if node.ObjectType == WctThreadType {
            let owner = unsafe { node.Anonymous.ThreadObject };
            item["process"] = json!(owner.ProcessId);
            item["thread"] = json!(owner.ThreadId);
            item["wait_time"] = json!(owner.WaitTime);
        }
        item
    }).collect::<Vec<_>>()})
}

pub(super) fn sample(
    staged: PathBuf,
    application: PathBuf,
    thread: u32,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(15));
        let chain = wait_chain(thread);
        let probe = support::try_output(&mut Command::new(application), 5);
        let report = json!({
            "window_station":object_name(unsafe { GetProcessWindowStation() }),
            "application_desktop":object_name(unsafe { GetThreadDesktop(thread) }),
            "application_windows":windows(thread),
            "wait_chain":chain,
            "warm_launch_exit":probe.as_ref().ok().and_then(|result|result.status.code()),
            "warm_launch_error":probe.err().map(|error|format!("{:?}",error.kind()))
        });
        let _ = fs::write(staged.join("startup.json"), report.to_string());
    })
}

pub(super) fn host_events(evidence: &Path) {
    let script = r#"
$since = (Get-Date).AddMinutes(-5)
$logs = @('Microsoft-Windows-CodeIntegrity/Operational','Microsoft-Windows-AppLocker/EXE and DLL','System','Application')
$report = foreach ($name in $logs) {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$name;StartTime=$since} -MaxEvents 100 -ErrorAction Stop |
            Where-Object { $_.Message -like '*firmica*' -or $_.Message -like '*msedgewebview*' } |
            Select-Object -First 20 TimeCreated,Id,ProviderName,LevelDisplayName,Message)
        @{log=$name;events=$events}
    } catch { @{log=$name;unavailable=$true} }
}

$report | ConvertTo-Json -Depth 5
"#;
    if let Ok(result) = support::try_output(
        Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]),
        30,
    ) {
        let _ = fs::write(evidence.join("startup-events.json"), result.stdout);
    }
}

/// Capture only the WebView2 provider. Raw traces stay in the disposable staging
/// directory; retained events omit URLs, paths, command lines and binary data.
pub(super) struct Trace {
    name: String,
    path: PathBuf,
}

impl Trace {
    pub(super) fn start(staged: &Path) -> Option<Self> {
        let trace = Self {
            name: format!("Firmica-WebView2-{}", std::process::id()),
            path: staged.join("webview.etl"),
        };
        let result = support::try_output(
            Command::new("logman.exe")
                .args([
                    "start",
                    &trace.name,
                    "-ets",
                    "-p",
                    "{E16EC3D2-BB0F-4E8F-BDB8-DE0BEA82DC3D}",
                    "0x3F0000054404",
                    "5",
                    "-o",
                ])
                .arg(&trace.path),
            15,
        )
        .ok()?;
        result.status.success().then_some(trace)
    }

    pub(super) fn finish(self, staged: &Path, evidence: &Path) {
        let _ = support::try_output(
            Command::new("logman.exe").args(["stop", &self.name, "-ets"]),
            15,
        );
        let script = r#"
$application = [uint32](Get-Content -LiteralPath $env:FIRMICA_STARTUP_PID)
$events = @(Get-WinEvent -Path $env:FIRMICA_STARTUP_TRACE -Oldest -ErrorAction Stop |
    Where-Object { $_.ProcessId -eq $application } | Select-Object -First 2000 | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $fields = @($xml.SelectNodes('//*[local-name()="EventData" or local-name()="UserData"]//*[not(*)]') | ForEach-Object {
            $value = $_.InnerText
            # Preserve numeric results and short diagnostic labels. Never retain
            # paths, URLs, command lines or arbitrary encoded payloads.
            if ($value -notmatch '^(0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_][A-Za-z_ .:()0-9-]{0,159})$' -or
                $value -match '(?i)(afirma|https?|wss?):|password|command.?line|token|secret') { $value = $null }
            @{name=$_.LocalName;field=$_.GetAttribute('Name');value=$value}
        })
        @{id=$_.Id;task=$_.TaskDisplayName;level=$_.Level;fields=$fields;
          structure=@($xml.SelectNodes('//*') | ForEach-Object { $_.LocalName } | Select-Object -Unique)}
    })
@{events=$events} | ConvertTo-Json -Depth 8
"#;
        if let Ok(result) = support::try_output(
            Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .env("FIRMICA_STARTUP_PID", staged.join("application.pid"))
                .env("FIRMICA_STARTUP_TRACE", &self.path),
            30,
        ) {
            fs::write(evidence.join("webview-events.json"), result.stdout).unwrap();
        }
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        let _ = support::try_output(
            Command::new("logman.exe").args(["stop", &self.name, "-ets"]),
            15,
        );
    }
}
