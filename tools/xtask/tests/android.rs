mod support;
use serde_json::json;
use std::{
    env, fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use support::{checked, FixtureServer};
const PACKAGE: &str = "org.firmica.client";

struct Android {
    adb: std::ffi::OsString,
    serial: String,
}
impl Android {
    fn adb(&self, args: &[&str]) -> Vec<u8> {
        let result = support::output(
            Command::new(&self.adb)
                .args(["-s", &self.serial])
                .args(args),
            40,
        );
        assert!(
            result.status.success(),
            "adb: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    }
    fn shell(&self, args: &[&str]) -> String {
        // adb shell concatenates arguments; quote URI ampersands for the device's shell.
        let command = args
            .iter()
            .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        String::from_utf8(self.adb(&["shell", &command]))
            .unwrap()
            .trim()
            .to_owned()
    }
    fn tree(&self) -> String {
        let text =
            String::from_utf8(self.adb(&["exec-out", "uiautomator", "dump", "/dev/tty"])).unwrap();
        let start = text.find("<?xml").expect("accessibility hierarchy XML");
        let end = text
            .rfind("</hierarchy>")
            .expect("accessibility hierarchy closing tag")
            + "</hierarchy>".len();
        text[start..end].to_owned()
    }
    fn has_text(&self, value: &str) -> bool {
        let xml = self.tree();
        roxmltree::Document::parse(&xml)
            .unwrap()
            .descendants()
            .any(|node| node.attribute("text") == Some(value))
    }
    fn wait_text(&self, value: &str, browser: bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.has_text(value) {
                return;
            }
            if browser && self.has_text("Open in App") {
                self.tap("Open in App", false);
            }
            assert!(
                Instant::now() < deadline,
                "expected accessibility text: {value}"
            );
        }
    }
    fn tap(&self, value: &str, towards_top: bool) {
        for attempt in 0..3 {
            let xml = self.tree();
            let document = roxmltree::Document::parse(&xml).unwrap();
            if let Some(node) = document
                .descendants()
                .find(|node| node.attribute("text") == Some(value))
            {
                let [left, top, right, bottom] = bounds(node.attribute("bounds").unwrap());
                self.shell(&[
                    "input",
                    "tap",
                    &((left + right) / 2).to_string(),
                    &((top + bottom) / 2).to_string(),
                ]);
                return;
            }
            if attempt == 2 {
                break;
            }
            let Some(node) = document
                .descendants()
                .find(|node| node.attribute("scrollable") == Some("true"))
            else {
                break;
            };
            let [left, top, right, bottom] = bounds(node.attribute("bounds").unwrap());
            let x = ((left + right) / 2).to_string();
            let high = (top + (bottom - top) / 4).to_string();
            let low = (top + 3 * (bottom - top) / 4).to_string();
            let (start, end) = if towards_top {
                (&high, &low)
            } else {
                (&low, &high)
            };
            self.shell(&["input", "swipe", &x, start, &x, end, "400"]);
        }
        panic!("accessible control not found after scrolling: {value}");
    }
    fn launch(&self, operation: &str, version: &str) {
        let uri = format!("afirma://{operation}?ver={version}&format=CAdES&dat=c3ludGhldGlj");
        let result = self.shell(&[
            "am",
            "start",
            "-W",
            "-a",
            "android.intent.action.VIEW",
            "-c",
            "android.intent.category.BROWSABLE",
            "-d",
            &uri,
            "-p",
            PACKAGE,
        ]);
        assert!(
            !result.contains("Error:") && !result.contains("Exception"),
            "Android launch failed: {result}"
        );
    }
    fn pid(&self) -> String {
        self.shell(&["pidof", "-s", PACKAGE])
    }
}
impl Drop for Android {
    fn drop(&mut self) {
        // Do not turn diagnostic/cleanup failures into a second panic.
        let _ = support::try_output(
            Command::new(&self.adb).args([
                "-s",
                &self.serial,
                "shell",
                "am",
                "force-stop",
                PACKAGE,
            ]),
            10,
        );
    }
}
fn bounds(value: &str) -> [i32; 4] {
    let values: Vec<i32> = value
        .split(['[', ']', ','])
        .filter(|part| !part.is_empty())
        .map(|part| part.parse().unwrap())
        .collect();
    values.try_into().expect("four accessibility bounds")
}
fn version(info: &str) -> Option<&str> {
    info.split("versionName=").nth(1)?.split_whitespace().next()
}

#[test]
#[ignore = "requires FIRMICA_TEST_APK and a booted Android emulator; optionally ANDROID_SERIAL and FIRMICA_TEST_BROWSER"]
fn cold_warm_intents_and_browser_review() {
    let apk = support::root()
        .join(PathBuf::from(
            env::var_os("FIRMICA_TEST_APK").expect("FIRMICA_TEST_APK"),
        ))
        .canonicalize()
        .unwrap();
    let adb = env::var_os("ADB").unwrap_or_else(|| "adb".into());
    let list = checked(Command::new(&adb).arg("devices"), 40);
    let devices: Vec<_> = list
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 2 && fields[1] == "device").then(|| fields[0].to_owned())
        })
        .collect();
    let serial = env::var("ANDROID_SERIAL").unwrap_or_else(|_| {
        assert_eq!(
            devices.len(),
            1,
            "select exactly one emulator with ANDROID_SERIAL"
        );
        devices[0].clone()
    });
    assert!(
        devices.contains(&serial),
        "selected device unavailable or unauthorized"
    );
    // Refuse personal devices before installation, input events or cleanup become possible.
    let qemu = checked(
        Command::new(&adb).args(["-s", &serial, "shell", "getprop", "ro.kernel.qemu"]),
        40,
    );
    assert_eq!(qemu.trim(), "1", "this test requires an emulator");
    let android = Android { adb, serial };
    let output_dir = support::root().join(".test-artifacts/android");
    fs::create_dir_all(&output_dir).unwrap();
    let result = output_dir.join("result.json");
    if result.exists() {
        fs::remove_file(&result).unwrap();
    }
    android.adb(&["install", "-r", "-t", apk.to_str().unwrap()]);
    android.shell(&["am", "force-stop", PACKAGE]);
    let mut checks = Vec::new();
    android.launch("sign", "4");
    android.wait_text("sign", false);
    let pid = android.pid();
    assert!(!pid.is_empty());
    fs::write(
        output_dir.join("cold-review.png"),
        android.adb(&["exec-out", "screencap", "-p"]),
    )
    .unwrap();
    checks.push("cold ACTION_VIEW reaches Rust and visible Dioxus review");
    android.launch("save", "4");
    assert_eq!(android.pid(), pid);
    assert!(android.has_text("sign"));
    checks.push("warm intent reuses process and cannot replace pending review");
    android.tap("Rechazar", false);
    android.wait_text("Solicitud rechazada.", false);
    android.launch("cosign", "3");
    android.wait_text("cosign", false);
    checks.push("new warm invocation appears after explicit rejection");
    android.shell(&["input", "keyevent", "KEYCODE_HOME"]);
    android.launch("save", "4");
    assert_eq!(android.pid(), pid);
    assert!(android.has_text("cosign"));
    checks.push("background return preserves pending review");
    android.shell(&[
        "am",
        "start",
        "-W",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        "afirma://sign?dat=%00",
        "-p",
        PACKAGE,
    ]);
    assert_eq!(android.pid(), pid);
    assert!(android.has_text("cosign"));
    checks.push("malformed URI is rejected without process or state loss");
    android.tap("English", true);
    android.tap("Acknowledge review", false);
    android.wait_text(
        "Review acknowledged. This operation is not implemented yet.",
        false,
    );
    checks.push("English controls acknowledge review without signing");
    android.shell(&["am", "force-stop", PACKAGE]);
    android.launch("selectcert", "4");
    android.wait_text("selectcert", false);
    checks.push("fresh process accepts a new invocation without replaying old consent");
    let browser = env::var("FIRMICA_TEST_BROWSER").ok().map(|browser| {
        let server = FixtureServer::new(|route| {
            let operation = if route == "/warm" { "cosign" } else { "sign" };
            format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Firmica invocation test</title><a href=\"afirma://{operation}?ver=4&amp;format=CAdES\">Open Firmica {operation}</a></html>")
        });
        let reverse = format!("tcp:{}", server.port);
        android.adb(&["reverse", &reverse, &reverse]);
        struct Reverse<'a>(&'a Android, String);
        impl Drop for Reverse<'_> { fn drop(&mut self) { let _ = support::try_output(Command::new(&self.0.adb).args(["-s", &self.0.serial, "reverse", "--remove", &self.1]), 10); } }
        let _reverse = Reverse(&android, reverse);
        android.shell(&["am", "force-stop", PACKAGE]);
        let mut browser_pid = String::new();
        for (route, operation) in [("/cold", "sign"), ("/warm", "cosign")] {
            let url = format!("http://127.0.0.1:{}{route}", server.port);
            android.shell(&["am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", &url, "-p", &browser]);
            let link = format!("Open Firmica {operation}");
            android.wait_text(&link, false); android.tap(&link, false); android.wait_text(operation, true);
            if operation == "sign" {
                browser_pid = android.pid();
                assert!(android.shell(&["dumpsys", "activity", "activities"]).contains(&format!("launchedFromPackage={browser}")));
                android.tap("Rechazar", false); android.wait_text("Solicitud rechazada.", false);
            } else { assert_eq!(android.pid(), browser_pid); }
        }
        checks.push("browser link resolves untargeted cold/warm intents into visible review");
        fs::write(output_dir.join("browser-review.png"), android.adb(&["exec-out", "screencap", "-p"])).unwrap();
        let info = android.shell(&["dumpsys", "package", &browser]);
        json!({"package": browser, "version": version(&info)})
    });
    let package = android.shell(&["dumpsys", "package", PACKAGE]);
    support::report(
        &result,
        &json!({"package": PACKAGE, "appVersion": version(&package),
        "androidRelease": android.shell(&["getprop", "ro.build.version.release"]),
        "androidSdk": android.shell(&["getprop", "ro.build.version.sdk"]),
        "abi": android.shell(&["getprop", "ro.product.cpu.abi"]), "browser": browser,
        "webview": android.shell(&["dumpsys", "webviewupdate"]).lines().nth(1).unwrap_or("").trim(),
        "apkSha256": support::sha256(&apk), "checks": checks,
        "scope": "URI invocation only; AutoScript mobile services, browser return, signing and physical devices not tested"}),
    );
}
