#![cfg(target_os = "macos")]
mod support;
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf, process::Command};
use support::{checked, output, FixtureServer};
const PACKAGE: &str = "org.firmica.client";

struct Simulator {
    device: String,
    output: PathBuf,
    passed: bool,
}
impl Drop for Simulator {
    fn drop(&mut self) {
        // Preserve diagnostics before deleting this test's simulator, including on a failed assertion.
        if !self.passed {
            if let Ok(result) = support::try_output(
                Command::new("xcrun").args([
                    "simctl",
                    "spawn",
                    &self.device,
                    "log",
                    "show",
                    "--last",
                    "5m",
                    "--style",
                    "compact",
                    "--predicate",
                    "process == \"installd\" OR process == \"SpringBoard\"",
                ]),
                30,
            ) {
                let _ = fs::write(
                    self.output.join("simulator.log"),
                    [result.stdout, result.stderr].concat(),
                );
            }
        }
        for action in ["shutdown", "delete"] {
            let _ = support::try_output(
                Command::new("xcrun").args(["simctl", action, &self.device]),
                30,
            );
        }
    }
}

#[test]
#[ignore = "requires FIRMICA_TEST_APP, macOS, Xcode and an iOS 18.5 Simulator runtime"]
fn safari_cold_warm_invocation_and_review() {
    let app = support::root()
        .join(PathBuf::from(
            env::var_os("FIRMICA_TEST_APP").expect("FIRMICA_TEST_APP"),
        ))
        .canonicalize()
        .unwrap();
    let info: Value = serde_json::from_str(&checked(
        Command::new("plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(app.join("Info.plist")),
        30,
    ))
    .unwrap();
    assert_eq!(info["CFBundleIdentifier"], PACKAGE);
    assert!(info["CFBundleURLTypes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["CFBundleURLSchemes"]
            .as_array()
            .is_some_and(|schemes| schemes.iter().any(|scheme| scheme == "afirma"))));
    let output_dir = support::root().join(".test-artifacts/ios");
    fs::create_dir_all(&output_dir).unwrap();
    let result = output_dir.join("result.json");
    if result.exists() {
        fs::remove_file(&result).unwrap();
    }
    fs::copy(app.join("Info.plist"), output_dir.join("Info.plist")).unwrap();
    let runtimes: Value = serde_json::from_str(&checked(
        Command::new("xcrun").args(["simctl", "list", "runtimes", "--json"]),
        60,
    ))
    .unwrap();
    let version = env::var("FIRMICA_TEST_IOS_RUNTIME").unwrap_or_else(|_| "18.5".into());
    let runtime = runtimes["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| {
            runtime["isAvailable"] == true
                && runtime["version"] == version
                && runtime["identifier"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("com.apple.CoreSimulator.SimRuntime.iOS-")
        })
        .expect("requested iOS Simulator runtime");
    // This unique temporary name identifies only this test's simulator.
    let marker = tempfile::Builder::new()
        .prefix("Firmica-")
        .tempdir()
        .unwrap();
    let name = marker.path().file_name().unwrap().to_str().unwrap();
    let device = checked(
        Command::new("xcrun").args([
            "simctl",
            "create",
            name,
            "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
            runtime["identifier"].as_str().unwrap(),
        ]),
        60,
    )
    .trim()
    .to_owned();
    let mut simulator = Simulator {
        device,
        output: output_dir.clone(),
        passed: false,
    };
    let server = FixtureServer::new(|_| {
        "<!doctype html><html lang=\"en\"><meta name=\"viewport\" content=\"width=device-width\"><title>Firmica invocation test</title><style>a{display:block;padding:20px}</style><a href=\"afirma://sign?ver=4&format=CAdES&dat=c3ludGhldGlj\">Sign request</a><a href=\"afirma://save?ver=4\">Save request</a><a href=\"afirma://cosign?ver=3&format=CAdES\">Co-sign request</a><a href=\"afirma://sign?ver=4&dat=%00\">Malformed request</a><a href=\"afirma://selectcert?ver=4\">Certificate request</a></html>".into()
    });
    checked(
        Command::new("xcrun").args(["simctl", "boot", &simulator.device]),
        60,
    );
    checked(
        Command::new("xcrun").args(["simctl", "bootstatus", &simulator.device, "-b"]),
        180,
    );
    checked(
        Command::new("xcrun")
            .args(["simctl", "install", &simulator.device])
            .arg(&app),
        180,
    );
    let source = support::root().join("tests/interop/ios");
    let directory = output_dir.join("project");
    if directory.exists() {
        fs::remove_dir_all(&directory).unwrap();
    }
    let project = directory.join("Invocation.xcodeproj");
    let schemes = project.join("xcshareddata/xcschemes");
    fs::create_dir_all(&schemes).unwrap();
    fs::copy(
        source.join("InvocationTests.swift"),
        directory.join("InvocationTests.swift"),
    )
    .unwrap();
    fs::copy(
        source.join("Invocation.xcodeproj/project.pbxproj"),
        project.join("project.pbxproj"),
    )
    .unwrap();
    let scheme = fs::read_to_string(
        source.join("Invocation.xcodeproj/xcshareddata/xcschemes/Invocation.xcscheme"),
    )
    .unwrap();
    fs::write(
        schemes.join("Invocation.xcscheme"),
        scheme.replace(
            "__FIRMICA_TEST_ORIGIN__",
            &format!("http://127.0.0.1:{}", server.port),
        ),
    )
    .unwrap();
    let bundle = output_dir.join("Invocation.xcresult");
    if bundle.exists() {
        fs::remove_dir_all(&bundle).unwrap();
    }
    let completed = output(
        Command::new("xcodebuild")
            .args(["test", "-project"])
            .arg(&project)
            .args([
                "-scheme",
                "Invocation",
                "-destination",
                &format!("id={}", simulator.device),
                "-derivedDataPath",
            ])
            .arg(output_dir.join("DerivedData"))
            .arg("-resultBundlePath")
            .arg(&bundle)
            .args([
                "-parallel-testing-enabled",
                "NO",
                "-testLanguage",
                "en",
                "-testRegion",
                "US",
            ]),
        480,
    );
    let log = [completed.stdout, completed.stderr].concat();
    fs::write(output_dir.join("xcodebuild.log"), &log).unwrap();
    checked(
        Command::new("xcrun")
            .args(["xcresulttool", "export", "attachments", "--path"])
            .arg(&bundle)
            .arg("--output-path")
            .arg(output_dir.join("attachments")),
        60,
    );
    assert!(
        completed.status.success(),
        "XCTest invocation failed: {}",
        String::from_utf8_lossy(&log)
    );
    support::report(
        &result,
        &json!({"platform": "iOS Simulator", "runtime": runtime, "device": "iPhone 16",
        "xcode": checked(Command::new("xcodebuild").arg("-version"), 60).trim(),
        "applicationSha256": support::sha256(&app.join(info["CFBundleExecutable"].as_str().unwrap())),
        "actual": "passed", "checks": ["packaged afirma scheme", "Safari cold link", "warm pending protection", "background return", "rejection", "warm cosign and language retention", "unsupported result", "malformed request rejection", "fresh-process selectcert"],
        "scope": "simulator invocation and review; no signing, intermediate services, browser return or physical-device proof"}),
    );
    simulator.passed = true;
}
