//! A fresh logon and HKCU hive, not a filtered administrator token.
#[path = "desktop_access.rs"]
mod desktop_access;
#[path = "startup.rs"]
mod startup;
use super::*;
use std::{
    ffi::OsStr,
    mem,
    os::windows::ffi::OsStrExt,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0},
    NetworkManagement::NetManagement::{
        NetLocalGroupAddMembers, NetUserAdd, NetUserDel, LOCALGROUP_MEMBERS_INFO_0,
        UF_NORMAL_ACCOUNT, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
    },
    Security::{
        Authorization::ConvertSidToStringSidW,
        CopySid, CreateWellKnownSid,
        Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        GetTokenInformation, LookupAccountNameW, LookupAccountSidW, TokenElevationType,
        TokenElevationTypeDefault, TokenLogonSid, WinBuiltinUsersSid, TOKEN_GROUPS, TOKEN_QUERY,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::{
            CreateProcessW, CreateProcessWithLogonW, GetCurrentProcess, GetExitCodeProcess,
            OpenProcessToken, ResumeThread, TerminateProcess, WaitForSingleObject,
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, LOGON_WITH_PROFILE,
            PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
        },
    },
    UI::Shell::DeleteProfileW,
};

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct Account {
    name: Vec<u16>,
    sid: Option<Vec<u16>>,
    logged_on: bool,
}
impl Drop for Account {
    fn drop(&mut self) {
        let mut removed = !self.logged_on;
        if let Some(sid) = self.sid.as_ref().filter(|_| self.logged_on) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if unsafe { DeleteProfileW(sid.as_ptr(), ptr::null(), ptr::null()) } != 0 {
                    removed = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let status = unsafe { NetUserDel(ptr::null(), self.name.as_ptr()) };
        if !std::thread::panicking() {
            assert!(removed, "could not remove the disposable user profile");
            assert_eq!(status, 0, "could not remove the disposable account");
        }
    }
}

fn account_sid(name: &[u16]) -> (Vec<u16>, [usize; 16]) {
    let mut sid = [0usize; 16];
    let mut size = mem::size_of_val(&sid) as u32;
    let mut domain = [0u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut kind = 0;
    assert_ne!(
        unsafe {
            LookupAccountNameW(
                ptr::null(),
                name.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut size,
                domain.as_mut_ptr(),
                &mut domain_size,
                &mut kind,
            )
        },
        0
    );
    let mut text = ptr::null_mut();
    assert_ne!(
        unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) },
        0
    );
    let mut length = 0;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        let result = std::slice::from_raw_parts(text, length + 1).to_vec();
        LocalFree(text.cast());
        (result, sid)
    }
}

fn users_group() -> Vec<u16> {
    let mut sid = [0usize; 16];
    let mut size = mem::size_of_val(&sid) as u32;
    assert_ne!(
        unsafe {
            CreateWellKnownSid(
                WinBuiltinUsersSid,
                ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        },
        0
    );
    let mut name = vec![0u16; 256];
    let mut name_size = name.len() as u32;
    let mut domain = [0u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut kind = 0;
    assert_ne!(
        unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid.as_mut_ptr().cast(),
                name.as_mut_ptr(),
                &mut name_size,
                domain.as_mut_ptr(),
                &mut domain_size,
                &mut kind,
            )
        },
        0
    );
    name.truncate(name_size as usize + 1);
    name
}

fn assert_standard_token() {
    assert_eq!(
        unsafe { IsUserAnAdmin() },
        0,
        "registration must run without administrator membership"
    );
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = Handle(token);
    let mut elevation = 0i32;
    let mut size = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevationType,
                (&mut elevation as *mut i32).cast(),
                mem::size_of_val(&elevation) as u32,
                &mut size,
            )
        },
        0
    );
    assert_eq!(
        elevation, TokenElevationTypeDefault,
        "a filtered administrator token is not a standard account"
    );
    let denied = LOCAL_MACHINE
        .options()
        .write()
        .open(r"Software\Classes")
        .expect_err("standard account must not have machine registry write access");
    assert_eq!(denied.code().0 as u32, 0x80070005);
}

fn process_logon_sid(process: HANDLE) -> [usize; 16] {
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) },
        0
    );
    let token = Handle(token);
    let mut groups = [0usize; 32];
    let mut needed = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenLogonSid,
                groups.as_mut_ptr().cast(),
                mem::size_of_val(&groups) as u32,
                &mut needed,
            )
        },
        0
    );
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    assert_eq!(groups.GroupCount, 1);
    let mut sid = [0usize; 16];
    assert_ne!(
        unsafe {
            CopySid(
                mem::size_of_val(&sid) as u32,
                sid.as_mut_ptr().cast(),
                groups.Groups[0].Sid,
            )
        },
        0
    );
    sid
}

fn copy_bundle(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_bundle(&entry.path(), &target);
        } else {
            assert!(kind.is_file(), "bundle contains a nonregular entry");
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn packaged_registration(staged: &Path) {
    let bundle = staged.join("Bundle space & 'apostrophe'");
    let application = bundle.join("firmica.exe");
    let script = bundle.join("handler.ps1");
    let _cleanup = Registration { machine: false };
    checked(
        Command::new(&application).args(["tls", "init", "--origin", "https://example.invalid"]),
        30,
    );
    let profile =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join("firmica-config/browser-tls");
    assert!(profile.join("private-key.pem").is_file());
    checked(Command::new(&application).args(["tls", "status"]), 30);
    invoke(&script, "Install", &[], true);
    assert!(invoke(&script, "Status", &[], true).contains("Registered executable:"));
    let command = read(&format!(r"{}\shell\open\command", KEYS[1]), "");
    let arguments = parse_command(&command.replace("%1", "afirma://save?ver=4.1"));
    assert_eq!(
        PathBuf::from(&arguments[0]).canonicalize().unwrap(),
        application.canonicalize().unwrap()
    );
    assert_eq!(&arguments[1..], &["--", "afirma://save?ver=4.1"]);
    invoke(&script, "Uninstall", &[], true);
    assert!(invoke(&script, "Status", &[], true).contains("not registered"));
    assert!(!KEYS.iter().any(|path| exists(path)));
}

fn native_application(staged: &Path) -> (Handle, u32, u32, u16, PathBuf) {
    use std::os::windows::io::AsRawHandle;
    let bundle = staged.join("Bundle space & 'apostrophe'");
    let application = bundle.join(format!("firmica-qa-{}.exe", std::process::id()));
    fs::rename(bundle.join("firmica.exe"), &application).unwrap();
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut environment: Vec<_> = std::env::vars()
        .filter(|(name, _)| {
            ![
                "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
                "WEBVIEW2_USER_DATA_FOLDER",
            ]
            .iter()
            .any(|key| name.eq_ignore_ascii_case(key))
        })
        .collect();
    environment.extend([
        (
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS".into(),
            format!(
                "--remote-debugging-port={port} --enable-logging --log-file=\"{}\"",
                staged.join("browser-startup.log").display()
            ),
        ),
        (
            "WEBVIEW2_USER_DATA_FOLDER".into(),
            staged.join("standard-webview").to_str().unwrap().into(),
        ),
    ]);
    environment.sort_by_cached_key(|(name, _)| name.to_ascii_uppercase());
    let environment: Vec<u16> = environment
        .into_iter()
        .flat_map(|(name, value)| wide(format!("{name}={value}")))
        .chain(Some(0))
        .collect();
    let mut desktop = wide(r"WinSta0\Default");
    let log = fs::File::create(staged.join("native-application.log")).unwrap();
    let input = fs::File::open("NUL").unwrap();
    for handle in [log.as_raw_handle(), input.as_raw_handle()] {
        assert_ne!(
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
    }
    let startup = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: desktop.as_mut_ptr(),
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: input.as_raw_handle(),
        hStdOutput: log.as_raw_handle(),
        hStdError: log.as_raw_handle(),
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    let mut command = wide(format!("\"{}\"", application.display()));
    // Keep the GUI in the explicitly selected desktop of the fresh logon. Python
    // attaches to this process; its subprocess launcher does not expose lpDesktop.
    assert_ne!(
        unsafe {
            CreateProcessW(
                wide(&application).as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                wide(&bundle).as_ptr(),
                &startup,
                &mut process,
            )
        },
        0,
        "cannot launch the standard-user application on the interactive desktop"
    );
    drop(Handle(process.hThread));
    fs::write(
        staged.join("application.pid"),
        process.dwProcessId.to_string(),
    )
    .unwrap();
    (
        Handle(process.hProcess),
        process.dwProcessId,
        process.dwThreadId,
        port,
        application,
    )
}

#[test]
#[ignore = "requires a disposable administrator desktop, Python native UI tooling and a built portable app; creates a standard account/profile"]
fn registration_under_standard_account() {
    let executable = std::env::current_exe().unwrap();
    let staged = executable.parent().unwrap();
    let child = staged.join("standard-account.fixture.exe").is_file();
    if child {
        let log = staged.join("child.log");
        std::panic::set_hook(Box::new(move |info| {
            let _ = fs::write(&log, format!("{info}\n"));
        }));
        assert_standard_token();
        registration_checks(
            &staged.join("handler.ps1"),
            Some(&staged.join("standard-account.fixture.exe")),
        );
        packaged_registration(staged);
        let tools: serde_json::Value =
            serde_json::from_slice(&fs::read(staged.join("tools.json")).unwrap()).unwrap();
        let python = Path::new(tools["python"].as_str().unwrap());
        let openssl = Path::new(tools["openssl"].as_str().unwrap());
        let paths = std::env::join_paths(
            [
                openssl.parent().unwrap().to_owned(),
                python.parent().unwrap().to_owned(),
            ]
            .into_iter()
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        let (application_process, pid, thread, port, application) = native_application(staged);
        let startup = startup::sample(staged.to_owned(), application.clone(), thread);
        let result = output(
            Command::new(python)
                .arg(staged.join("windows-signing.py"))
                .arg("--app")
                .arg(application)
                .arg("--attach-pid")
                .arg(pid.to_string())
                .arg("--debug-port")
                .arg(port.to_string())
                .arg("--output")
                .arg(staged.join("native-signing"))
                .arg("--require-standard-account")
                .env("PATH", paths),
            240,
        );
        startup.join().unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(application_process.0, 10_000) },
            WAIT_OBJECT_0,
            "native GUI driver did not stop the standard-user application"
        );
        fs::write(
            staged.join("native-signing.log"),
            [&result.stdout[..], &result.stderr[..]].concat(),
        )
        .unwrap();
        assert!(
            result.status.success(),
            "standard-account native signing failed; see native-signing.log"
        );
        let signed: serde_json::Value =
            serde_json::from_slice(&fs::read(staged.join("native-signing/result.json")).unwrap())
                .unwrap();
        assert_eq!(signed["passed"], true);
        assert_eq!(signed["administrator"], false);
        support::report(
            &staged.join("result.json"),
            &serde_json::json!({"passed":true,"administrator":false,"filtered_administrator":false,"machine_registry_write_denied":true,"packaged_tls_and_registration":true,"interactive_signing":true,"registration":"install/status/uninstall, ownership, collisions and quoting"}),
        );
        return;
    }
    assert_ne!(
        unsafe { IsUserAnAdmin() },
        0,
        "account provisioning requires a disposable administrator test host"
    );
    let temporary = tempfile::Builder::new()
        .prefix("firmica-standard-")
        .tempdir_in(std::env::var_os("PUBLIC").expect("PUBLIC"))
        .unwrap();
    let evidence = support::root().join(".test-artifacts/windows-standard-account");
    if evidence.exists() {
        fs::remove_dir_all(&evidence).unwrap();
    }
    fs::create_dir_all(&evidence).unwrap();
    let nonce = temporary.path().file_name().unwrap().to_string_lossy();
    let name = format!("Firmica{}", nonce.trim_start_matches("firmica-standard-"));
    let mut random = [0u8; 32];
    assert_eq!(
        unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                random.as_mut_ptr(),
                random.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        },
        0
    );
    let mut password = wide(format!(
        "F!rmica9-{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let mut name_wide = wide(&name);
    let user = USER_INFO_1 {
        usri1_name: name_wide.as_mut_ptr(),
        usri1_password: password.as_mut_ptr(),
        usri1_priv: USER_PRIV_USER,
        usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT,
        ..Default::default()
    };
    assert_eq!(
        unsafe {
            NetUserAdd(
                ptr::null(),
                1,
                (&user as *const USER_INFO_1).cast(),
                ptr::null_mut(),
            )
        },
        0,
        "could not provision standard account"
    );
    let mut account = Account {
        name: name_wide,
        sid: None,
        logged_on: false,
    };
    let (sid_text, mut sid) = account_sid(&account.name);
    account.sid = Some(sid_text);
    let member = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: sid.as_mut_ptr().cast(),
    };
    let status = unsafe {
        NetLocalGroupAddMembers(
            ptr::null(),
            users_group().as_ptr(),
            0,
            (&member as *const LOCALGROUP_MEMBERS_INFO_0).cast(),
            1,
        )
    };
    assert!(
        status == 0 || status == 1378,
        "could not add account to Users: {status}"
    );
    let application = temporary.path().join("registration-tests.exe");
    fs::copy(&executable, &application).unwrap();
    fs::copy(
        support::root().join("tools/windows/handler.ps1"),
        temporary.path().join("handler.ps1"),
    )
    .unwrap();
    compile_fixture(&temporary.path().join("standard-account.fixture.exe"));
    let packaged = support::root()
        .join(
            std::env::var_os("FIRMICA_TEST_APP")
                .expect("FIRMICA_TEST_APP must point to a built portable firmica.exe"),
        )
        .canonicalize()
        .unwrap();
    assert!(packaged.is_file());
    copy_bundle(
        packaged.parent().unwrap(),
        &temporary.path().join("Bundle space & 'apostrophe'"),
    );
    for script in ["windows-signing.py", "windows_gui.py"] {
        fs::copy(
            support::root().join("tests/interop").join(script),
            temporary.path().join(script),
        )
        .unwrap();
    }
    let python = checked(
        Command::new("python").args(["-c", "import sys; print(sys.executable)"]),
        15,
    );
    let openssl = checked(Command::new("where.exe").arg("openssl"), 15);
    fs::write(
        temporary.path().join("tools.json"),
        serde_json::json!({"python":python.trim(),"openssl":openssl.lines().next().unwrap()})
            .to_string(),
    )
    .unwrap();
    checked(
        Command::new("icacls.exe").arg(temporary.path()).args([
            "/T",
            "/grant:r",
            &format!("{name}:(OI)(CI)F"),
        ]),
        15,
    );
    let application = wide(&application);
    let directory = wide(temporary.path());
    let mut command = wide(format!("\"{}\" --exact windows_standard_account::registration_under_standard_account --ignored --nocapture", temporary.path().join("registration-tests.exe").display()));
    let station = desktop_access::DesktopAccess::grant(&mut sid, true);
    let desktop = desktop_access::DesktopAccess::grant(&mut sid, false);
    // A timed-out GUI driver must not leave an application holding this profile open.
    let job = Handle(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) });
    assert!(!job.0.is_null());
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    assert_ne!(
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                mem::size_of_val(&limits) as u32,
            )
        },
        0
    );
    let mut desktop_name = wide(r"WinSta0\Default");
    let startup = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: desktop_name.as_mut_ptr(),
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // A fresh logon with its own loaded HKCU and environment. No caller token or
    // environment block is reused; no password is passed on a command line.
    let created = unsafe {
        CreateProcessWithLogonW(
            account.name.as_ptr(),
            wide(".").as_ptr(),
            password.as_ptr(),
            LOGON_WITH_PROFILE,
            application.as_ptr(),
            command.as_mut_ptr(),
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            ptr::null(),
            directory.as_ptr(),
            &startup,
            &mut process,
        )
    };
    password.fill(0);
    assert_ne!(
        created,
        0,
        "standard logon failed: {}",
        std::io::Error::last_os_error()
    );
    account.logged_on = true;
    let process_handle = Handle(process.hProcess);
    let thread_handle = Handle(process.hThread);
    let assigned = unsafe { AssignProcessToJobObject(job.0, process_handle.0) };
    if assigned == 0 {
        unsafe {
            TerminateProcess(process_handle.0, 1);
            WaitForSingleObject(process_handle.0, 10_000);
        }
    }
    assert_ne!(assigned, 0, "cannot supervise the disposable process tree");
    // Match an interactive logon: grant this logon's SID before GUI children start.
    let mut logon_sid = process_logon_sid(process_handle.0);
    let logon_station = desktop_access::DesktopAccess::grant(&mut logon_sid, true);
    let logon_desktop = desktop_access::DesktopAccess::grant(&mut logon_sid, false);
    let trace = startup::Trace::start(temporary.path());
    assert_ne!(unsafe { ResumeThread(thread_handle.0) }, u32::MAX);
    let waited = unsafe { WaitForSingleObject(process_handle.0, 400_000) };
    if waited != WAIT_OBJECT_0 {
        let _ = output(
            Command::new("taskkill.exe").args([
                "/F",
                "/T",
                "/PID",
                &process.dwProcessId.to_string(),
            ]),
            15,
        );
        unsafe {
            TerminateProcess(process_handle.0, 1);
            WaitForSingleObject(process_handle.0, 10_000);
        }
    }
    drop(job);
    if let Some(trace) = trace {
        trace.finish(temporary.path(), &evidence);
    }
    for name in [
        "result.json",
        "child.log",
        "native-signing.log",
        "native-application.log",
        "startup.json",
    ] {
        if temporary.path().join(name).exists() {
            fs::copy(temporary.path().join(name), evidence.join(name)).unwrap();
        }
    }
    if temporary.path().join("native-signing").exists() {
        copy_bundle(
            &temporary.path().join("native-signing"),
            &evidence.join("native-signing"),
        );
    }
    let mut exit = 1;
    assert_ne!(
        unsafe { GetExitCodeProcess(process_handle.0, &mut exit) },
        0
    );
    if exit != 0 {
        startup::host_events(&evidence);
    }
    drop(thread_handle);
    drop(process_handle);
    drop(logon_desktop);
    drop(logon_station);
    drop(desktop);
    drop(station);
    assert_eq!(waited, WAIT_OBJECT_0, "standard-account test timed out");
    assert_eq!(
        exit, 0,
        "standard-account test failed; see .test-artifacts/windows-standard-account/child.log"
    );
    assert!(
        temporary.path().join("result.json").is_file(),
        "standard-account child did not run"
    );
    drop(account);
}
