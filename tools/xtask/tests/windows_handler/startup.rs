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
            item["wait_ms"] = json!(owner.WaitTime);
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
            "wait_chain":chain,
            "warm_launch_exit":probe.as_ref().ok().and_then(|result|result.status.code()),
            "warm_launch_error":probe.err().map(|error|format!("{:?}",error.kind()))
        });
        let _ = fs::write(staged.join("startup.json"), report.to_string());
    })
}
