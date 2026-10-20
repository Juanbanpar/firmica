#![cfg(windows)]
mod support;
use openssl::ssl::{SslConnector, SslMethod};
use serde_json::json;
use std::{
    env, fs,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};
use support::{checked, output, wait_for, Process};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM},
    UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    },
};

fn windows_for(pid: u32) -> usize {
    struct Search {
        pid: u32,
        count: usize,
    }
    unsafe extern "system" fn visit(window: HWND, data: LPARAM) -> i32 {
        // EnumWindows invokes this callback synchronously with our live Search.
        let search = unsafe { &mut *(data as *mut Search) };
        let mut owner = 0;
        let mut title = [0u16; 256];
        unsafe {
            GetWindowThreadProcessId(window, &mut owner);
            let length = GetWindowTextW(window, title.as_mut_ptr(), title.len() as i32);
            if owner == search.pid
                && IsWindowVisible(window) != 0
                && String::from_utf16_lossy(&title[..length as usize]) == "Firmica"
            {
                search.count += 1;
            }
        }
        1
    }
    let mut search = Search { pid, count: 0 };
    assert_ne!(
        unsafe { EnumWindows(Some(visit), &mut search as *mut Search as LPARAM) },
        0
    );
    search.count
}

fn visible(process: &mut Process) -> Option<()> {
    assert!(
        process.0.try_wait().unwrap().is_none(),
        "application exited before displaying its window"
    );
    (windows_for(process.0.id()) == 1).then_some(())
}

#[test]
#[ignore = "requires FIRMICA_TEST_APP, OpenSSL and a native Windows desktop session"]
fn cold_warm_invocation_and_crash_recovery() {
    let app = support::root()
        .join(PathBuf::from(
            env::var_os("FIRMICA_TEST_APP").expect("FIRMICA_TEST_APP"),
        ))
        .canonicalize()
        .unwrap();
    let output_dir = support::root().join(".test-artifacts/windows");
    fs::create_dir_all(&output_dir).unwrap();
    let result_path = output_dir.join("result.json");
    let mut report = json!({"platform": "Windows", "executable_sha256": support::sha256(&app), "passed": false, "checks": []});
    // Write a failure marker before launch; panics cannot leave stale passing evidence.
    support::report(&result_path, &report);
    let temp = tempfile::tempdir().unwrap();
    let certificate = temp.path().join("cert.pem");
    let key = temp.path().join("key.pem");
    checked(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-days",
                "1",
                "-subj",
                "/CN=Firmica invocation test",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate),
        30,
    );
    let log = fs::File::create(output_dir.join("application.log")).unwrap();
    let configuration = || {
        let mut command = Command::new(&app);
        command
            .arg("--tls-cert")
            .arg(&certificate)
            .arg("--tls-key")
            .arg(&key)
            .args(["--origin", "http://127.0.0.1:8123"])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log.try_clone().unwrap()));
        command
    };
    let invoke = |arguments: &[&str], success: bool| {
        let result = output(Command::new(&app).args(arguments), 10);
        assert_eq!(
            result.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    let mut process = Process(configuration().arg("afirma://save?ver=4").spawn().unwrap());
    wait_for(30, || visible(&mut process));
    let mut checks = vec!["cold CLI invocation creates one native Dioxus window"];
    invoke(&[], true);
    checks.push("warm launch without a URI exits successfully");
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    invoke(
        &[&format!(
            "afirma://websocket?v=4&jvc=4&ports={port}&idsession=0123456789abcdef"
        )],
        true,
    );
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&certificate).unwrap();
    let connector = connector.build();
    wait_for(10, || {
        visible(&mut process)?;
        let stream = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_secs(1),
        )
        .ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        connector.connect("127.0.0.1", stream).ok().map(|_| ())
    });
    assert_eq!(windows_for(process.0.id()), 1);
    checks.push("warm bootstrap reaches the running app and opens its configured TLS listener");
    invoke(&["https://example.invalid/"], false);
    assert!(visible(&mut process).is_some());
    checks.push("invalid invocation fails without replacing the running window");
    process.0.kill().unwrap();
    process.0.wait().unwrap();
    process = Process(configuration().spawn().unwrap());
    wait_for(30, || visible(&mut process));
    invoke(&[], true);
    checks.push("application recovers its private pipe after a forced termination");
    report["checks"] = json!(checks);
    report["passed"] = json!(true);
    support::report(&result_path, &report);
}
