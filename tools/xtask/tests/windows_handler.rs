#![cfg(windows)]
mod support;
#[path = "windows_handler/standard_account.rs"]
mod windows_standard_account;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use support::{checked, output};
use windows_registry::{CLASSES_ROOT, CURRENT_USER, LOCAL_MACHINE};
use windows_sys::Win32::{
    Foundation::LocalFree,
    UI::Shell::{CommandLineToArgvW, IsUserAnAdmin},
};

const KEYS: [&str; 3] = [
    r"Software\Classes\afirma",
    r"Software\Classes\Firmica.afirma",
    r"Software\Firmica\Capabilities",
];
const REGISTERED: &str = r"Software\RegisteredApplications";

fn exists(path: &str) -> bool {
    match CURRENT_USER.open(path) {
        Ok(_) => true,
        Err(error) if matches!(error.code().0 as u32, 0x80070002 | 0x80070003) => false,
        Err(error) => panic!("could not inspect registry key {path}: {error}"),
    }
}
fn read(path: &str, name: &str) -> String {
    CURRENT_USER.open(path).unwrap().get_string(name).unwrap()
}
fn write(path: &str, value: &str) {
    CURRENT_USER
        .create(path)
        .unwrap()
        .set_string("", value)
        .unwrap();
}
fn remove(path: &str) {
    if exists(path) {
        CURRENT_USER.remove_tree(path).unwrap();
    }
}

struct Registration {
    machine: bool,
}
impl Drop for Registration {
    fn drop(&mut self) {
        for path in KEYS {
            remove(path);
        }
        if exists(REGISTERED) {
            let _ = CURRENT_USER
                .create(REGISTERED)
                .unwrap()
                .remove_value("Firmica");
        }
        if self.machine {
            LOCAL_MACHINE.remove_tree(KEYS[1]).unwrap();
        }
    }
}

fn invoke(script: &Path, action: &str, arguments: &[String], success: bool) -> String {
    let result = output(
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .args(["-Action", action])
            .args(arguments),
        30,
    );
    assert_eq!(
        result.status.success(),
        success,
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

fn parse_command(command: &str) -> Vec<String> {
    let wide: Vec<_> = command.encode_utf16().chain(Some(0)).collect();
    let mut count = 0;
    // CommandLineToArgvW allocates one block, including its strings. Copy before LocalFree.
    unsafe {
        let parsed = CommandLineToArgvW(wide.as_ptr(), &mut count);
        assert!(!parsed.is_null());
        let arguments = std::slice::from_raw_parts(parsed, count as usize)
            .iter()
            .map(|&value| {
                let mut length = 0;
                while *value.add(length) != 0 {
                    length += 1;
                }
                String::from_utf16(std::slice::from_raw_parts(value, length)).unwrap()
            })
            .collect();
        LocalFree(parsed.cast());
        arguments
    }
}

#[test]
#[ignore = "changes disposable Windows account associations; requires no existing Firmica/afirma handler"]
fn registration_ownership_quoting_and_gui_exit_status() {
    registration_checks(&support::root().join("tools/windows/handler.ps1"), None);
}

fn registration_checks(script_source: &Path, fixture: Option<&Path>) {
    assert!(
        !KEYS.iter().any(|path| exists(path)),
        "use a disposable Windows account without existing registrations"
    );
    if exists(REGISTERED) {
        match CURRENT_USER.open(REGISTERED).unwrap().get_string("Firmica") {
            Ok(_) => panic!("Firmica already appears in RegisteredApplications"),
            Err(error) => assert_eq!(error.code().0 as u32, 0x80070002),
        }
    }
    for name in ["afirma", "Firmica.afirma"] {
        match CLASSES_ROOT.open(name) {
            Ok(_) => panic!("{name} already has a machine handler; use a clean test host"),
            Err(error) => assert!(matches!(error.code().0 as u32, 0x80070002 | 0x80070003)),
        }
    }
    let mut cleanup = Registration { machine: false };
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("App space & 'apostrophe'");
    fs::create_dir(&directory).unwrap();
    let script = directory.join("handler.ps1");
    fs::copy(script_source, &script).unwrap();
    let app = directory.join("firmica.exe");
    if let Some(fixture) = fixture {
        fs::copy(fixture, &app).unwrap();
    } else {
        compile_fixture(&app);
    }
    let certificate = directory.join("TLS certificate.pem");
    let key = directory.join("TLS key.pem");
    fs::write(&certificate, "synthetic certificate path fixture").unwrap();
    fs::write(&key, "synthetic key path fixture").unwrap();
    let flags: Vec<String> = vec![
        "-TlsCertificate".into(),
        certificate.to_str().unwrap().into(),
        "-TlsKey".into(),
        key.to_str().unwrap().into(),
        "-Origin".into(),
        "https://example.invalid".into(),
    ];
    assert!(invoke(&script, "Status", &[], true).contains("not registered"));
    invoke(&script, "Install", &[], false);
    assert!(!KEYS.iter().any(|path| exists(path)));
    let ready = app.with_file_name("firmica.exe.ready");
    fs::write(&ready, "synthetic profile fixture").unwrap();
    assert!(invoke(&script, "Install", &[], true).contains("Synthetic profile validated"));
    let command_key = format!(r"{}\shell\open\command", KEYS[1]);
    let scheme_key = format!(r"{}\shell\open\command", KEYS[0]);
    let managed = read(&command_key, "");
    assert!(managed.ends_with(" -- \"%1\"") && !managed.contains("--tls-cert"));
    invoke(&script, "Uninstall", &[], true);
    fs::remove_file(ready).unwrap();
    assert!(!KEYS.iter().any(|path| exists(path)));
    invoke(&script, "Install", &flags, true);
    let launch = read(&command_key, "");
    assert_eq!(read(&scheme_key, ""), launch);
    assert_eq!(read(REGISTERED, "Firmica"), KEYS[2]);
    assert_eq!(
        read(&format!(r"{}\URLAssociations", KEYS[2]), "afirma"),
        "Firmica.afirma"
    );
    let uri = "afirma://save?ver=4&name=a%22%20b&dat=YWJj";
    let argv = parse_command(&launch.replace("%1", uri));
    assert_eq!(argv.len(), 9);
    assert_eq!(
        [
            argv[1].as_str(),
            &argv[3],
            &argv[5],
            &argv[6],
            &argv[7],
            &argv[8]
        ],
        [
            "--tls-cert",
            "--tls-key",
            "--origin",
            "https://example.invalid",
            "--",
            uri
        ]
    );
    for (actual, expected) in [(&argv[0], &app), (&argv[2], &certificate), (&argv[4], &key)] {
        assert_eq!(
            PathBuf::from(actual).canonicalize().unwrap(),
            expected.canonicalize().unwrap()
        );
    }
    invoke(&script, "Install", &flags, true);
    assert_eq!(read(&command_key, ""), launch);
    for origin in [
        "https://example.invalid/",
        "file:///tmp/",
        "https://user@example.invalid",
        "https://example.invalid/path",
    ] {
        let mut invalid = flags.clone();
        *invalid.last_mut().unwrap() = origin.into();
        invoke(&script, "Install", &invalid, false);
        assert_eq!(read(&command_key, ""), launch);
    }
    assert!(invoke(&script, "Status", &[], true).contains("Registered executable:"));
    invoke(&script, "Uninstall", &[], true);
    assert!(!KEYS.iter().any(|path| exists(path)));
    invoke(&script, "Uninstall", &[], true);
    write(KEYS[0], "foreign handler");
    write(&scheme_key, "\"foreign.exe\" \"%1\"");
    invoke(&script, "Install", &flags, true);
    assert_eq!(read(KEYS[0], ""), "foreign handler");
    assert_eq!(read(&scheme_key, ""), "\"foreign.exe\" \"%1\"");
    invoke(&script, "Uninstall", &[], true);
    assert!(exists(KEYS[0]) && !exists(KEYS[1]));
    remove(KEYS[0]);
    invoke(&script, "Install", &flags, true);
    write(&scheme_key, "replacement command");
    invoke(&script, "Install", &flags, true);
    assert_eq!(read(&scheme_key, ""), "replacement command");
    invoke(&script, "Uninstall", &[], true);
    assert_eq!(read(&scheme_key, ""), "replacement command");
    remove(KEYS[0]);
    write(KEYS[1], "foreign provider");
    invoke(&script, "Install", &flags, false);
    invoke(&script, "Uninstall", &[], false);
    assert_eq!(read(KEYS[1], ""), "foreign provider");
    remove(KEYS[1]);
    if unsafe { IsUserAnAdmin() } != 0 {
        LOCAL_MACHINE
            .create(KEYS[1])
            .unwrap()
            .set_string("", "foreign machine provider")
            .unwrap();
        cleanup.machine = true;
        invoke(&script, "Install", &flags, false);
        assert!(!KEYS.iter().any(|path| exists(path)));
        assert_eq!(
            LOCAL_MACHINE.open(KEYS[1]).unwrap().get_string("").unwrap(),
            "foreign machine provider"
        );
        LOCAL_MACHINE.remove_tree(KEYS[1]).unwrap();
        cleanup.machine = false;
    }
    let percent = temp.path().join("literal %1 path");
    fs::create_dir(&percent).unwrap();
    fs::copy(&app, percent.join("firmica.exe")).unwrap();
    fs::copy(&script, percent.join("handler.ps1")).unwrap();
    invoke(&percent.join("handler.ps1"), "Install", &flags, false);
    assert!(!KEYS.iter().any(|path| exists(path)));
}

fn compile_fixture(destination: &Path) {
    checked(
        Command::new("rustc")
            .args(["--edition=2021", "--crate-name", "handler_fixture"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/handler.rs"))
            .arg("-o")
            .arg(destination),
        60,
    );
}
