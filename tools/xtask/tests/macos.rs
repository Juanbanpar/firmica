#![cfg(target_os = "macos")]
mod macos_support;
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};
use support::{checked, output, FixtureServer, Process};

#[test]
#[ignore = "requires a disposable macOS desktop, Xcode, Firefox, NSS, Poppler and XMLSec"]
fn extracted_bundle_signs_local_documents_and_unmodified_autoscript_requests() {
    let root = support::root();
    let app = PathBuf::from(env::var_os("FIRMICA_TEST_APP").expect("FIRMICA_TEST_APP"))
        .canonicalize()
        .unwrap();
    let info: Value = serde_json::from_str(&checked(
        Command::new("plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(app.join("Contents/Info.plist")),
        15,
    ))
    .unwrap();
    assert_eq!(info["CFBundleIdentifier"], "org.firmica.client");
    assert_eq!(info["LSMinimumSystemVersion"], "15.0");
    assert!(info["CFBundleURLTypes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["CFBundleURLSchemes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scheme| scheme == "afirma")));
    checked(
        Command::new("codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(&app),
        30,
    );
    let executable = app
        .join("Contents/MacOS")
        .join(info["CFBundleExecutable"].as_str().unwrap());
    let output_dir = root.join(".test-artifacts/macos");
    fs::create_dir_all(&output_dir).unwrap();
    let temporary = tempfile::Builder::new()
        .prefix("firmica-native-")
        .tempdir()
        .unwrap();
    let fixtures = temporary.path();
    let certificates = macos_support::identities(fixtures);
    let mut local = Vec::new();
    let mut browser = Vec::new();
    for algorithm in ["rsa", "ec"] {
        for mode in ["cades", "pades", "enveloped", "enveloping", "detached"] {
            let content: &[u8] = match mode {
                "pades" => include_bytes!("../../../crates/pades/tests/fixtures/document.pdf"),
                "enveloped" => {
                    b"<document xmlns=\"urn:firmica:test\">Synthetic XML &amp; bytes</document>"
                }
                _ => b"Synthetic macOS document\x00\xff\r\n",
            };
            let index = local.len();
            let document = fixtures.join(format!("document-{index}"));
            fs::write(&document, content).unwrap();
            let case = json!({"index":index,"algorithm":algorithm,"mode":mode,"document":document,
                "certificate":fixtures.join(format!("{algorithm}.p12")),"content":STANDARD.encode(content),
                "hash":format!("{:x}",sha2::Sha256::digest(content)),"output":fixtures.join(format!("local-{index}.{}", match mode { "cades" => "csig", "pades" => "pdf", _ => "xml" })),
                "format":match mode {"cades"=>"CAdES","pades"=>"PAdES",_=>"XAdES"},
                "properties":match mode {"cades"=>"mode=explicit","pades"=>"signaturePage=1\nsignaturePositionOnPageLowerLeftX=40\nsignaturePositionOnPageLowerLeftY=30\nsignaturePositionOnPageUpperRightX=400\nsignaturePositionOnPageUpperRightY=70\nlayer2Text=Signed with Firmica", "enveloped"=>"format=XAdES Enveloped", "enveloping"=>"format=XAdES Enveloping", _=>"format=XAdES Detached"}, "action":"sign"});
            local.push(case.clone());
            browser.push(case);
        }
    }
    for action in ["cancel", "worker-failure", "disconnect"] {
        let mut case = browser[0].clone();
        case["action"] = json!(action);
        case["index"] = json!(browser.len());
        browser.push(case);
    }
    use sha2::Digest;
    let configuration = json!({"local":local,"browser":browser,"fixtures":fixtures,"evidence":output_dir,"password":macos_support::PASSWORD});
    let state = Arc::new(Mutex::new(
        json!({"index":0,"started":false,"prepared":false,"native_done":false,"local_done":false}),
    ));
    let served_state = state.clone();
    let served_configuration = configuration.clone();
    let script = checked(Command::new("node").current_dir(&root).args(["--input-type=module", "--eval", "import {autoscript} from './tests/interop/autoscript.mjs';process.stdout.write(await autoscript());"]), 120);
    let server = FixtureServer::new(move |route| {
        if route == "/autoscript.js" {
            return script.clone();
        }
        if route == "/config" {
            return served_configuration.to_string();
        }
        let mut state = served_state.lock().unwrap();
        if route == "/state" {
            return state.to_string();
        }
        if route == "/local-done" {
            state["local_done"] = json!(true);
        }
        if route == "/started" {
            state["started"] = json!(true);
        }
        if route == "/result-received" {
            state["result_received"] = json!(true);
        }
        if route == "/prepared" {
            state["prepared"] = json!(true);
        }
        if route == "/native-done" {
            state["native_done"] = json!(true);
        }
        if route == "/next" {
            let index = state["index"].as_u64().unwrap() + 1;
            *state = json!({"index":index,"local_done":true,"started":false,"prepared":false,"native_done":false});
        }
        if route == "/case" {
            return served_configuration["browser"][state["index"].as_u64().unwrap() as usize]
                .to_string();
        }
        if route != "/" {
            return "{}".into();
        }
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><title>Firmica synthetic signing</title><button id="sign" disabled>Sign synthetic document</button><script src="/autoscript.js"></script><script>
        AutoScript.enableProgressDialog(false);AutoScript.setPortRange(49152,49154);AutoScript.cargarAppAfirma();AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12);
        fetch('/case').then(r=>r.json()).then(c=>{let b=document.getElementById('sign');b.disabled=false;b.onclick=()=>AutoScript.sign(c.content,c.algorithm==='rsa'?'SHA256withRSA':'SHA256withECDSA',c.format,c.properties,(signature,certificate)=>window.result={signature,certificate},(type,message,code)=>window.result={type,message,code});});
        </script></html>"#.into()
    });
    let origin = format!("http://127.0.0.1:{}", server.port);
    let _profile = macos_support::Profile::initialize(&executable, &origin);
    let _handler = macos_support::Handler::register(&app);
    let native = root.join("tests/interop/macos");
    let project = output_dir.join("Signing.xcodeproj");
    let schemes = project.join("xcshareddata/xcschemes");
    fs::create_dir_all(&schemes).unwrap();
    fs::copy(
        native.join("Signing.xcodeproj/project.pbxproj"),
        project.join("project.pbxproj"),
    )
    .unwrap();
    fs::copy(
        native.join("SigningTests.swift"),
        output_dir.join("SigningTests.swift"),
    )
    .unwrap();
    fs::write(
        schemes.join("Signing.xcscheme"),
        fs::read_to_string(
            native.join("Signing.xcodeproj/xcshareddata/xcschemes/Signing.xcscheme"),
        )
        .unwrap()
        .replace("__FIRMICA_TEST_ORIGIN__", &origin),
    )
    .unwrap();
    let browser_log = fs::File::create(output_dir.join("firefox.log")).unwrap();
    let mut browser_process = Process(
        Command::new("node")
            .current_dir(&root)
            .arg("tests/interop/macos/firefox.mjs")
            .arg(&origin)
            .arg(temporary.path().join("firefox"))
            .arg(&_profile.path)
            .arg(&output_dir)
            .stdout(browser_log.try_clone().unwrap())
            .stderr(browser_log)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let result_bundle = output_dir.join("Signing.xcresult");
    if result_bundle.exists() {
        fs::remove_dir_all(&result_bundle).unwrap();
    }
    let result = output(
        Command::new("xcodebuild")
            .args(["test", "-project"])
            .arg(project)
            .args([
                "-scheme",
                "Signing",
                "-destination",
                "platform=macOS",
                "-parallel-testing-enabled",
                "NO",
                "-testLanguage",
                "en",
                "-testRegion",
                "US",
                "-derivedDataPath",
            ])
            .arg(output_dir.join("DerivedData"))
            .arg("-resultBundlePath")
            .arg(&result_bundle),
        1000,
    );
    fs::write(
        output_dir.join("xcodebuild.log"),
        [&result.stdout[..], &result.stderr[..]].concat(),
    )
    .unwrap();
    assert!(
        result.status.success(),
        "native UI acceptance failed; see .test-artifacts/macos/xcodebuild.log"
    );
    let browser_status = support::wait_for(30, || browser_process.0.try_wait().unwrap());
    assert!(
        browser_status.success(),
        "Firefox acceptance failed; see firefox.log"
    );
    for case in configuration["local"].as_array().unwrap() {
        macos_support::verify(
            case,
            Path::new(case["output"].as_str().unwrap()),
            &certificates,
            fixtures,
        );
    }
    for (index, case) in configuration["browser"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let result: Value = serde_json::from_slice(
            &fs::read(output_dir.join(format!("browser-{index}.json"))).unwrap(),
        )
        .unwrap();
        match case["action"].as_str().unwrap() {
            "sign" => {
                let returned = macos_support::decode(result["certificate"].as_str().unwrap());
                assert_eq!(
                    returned,
                    fs::read(fixtures.join(format!("{}.der", case["algorithm"].as_str().unwrap())))
                        .unwrap()
                );
                let path = fixtures.join(format!("browser-{index}.signed"));
                fs::write(
                    &path,
                    macos_support::decode(result["signature"].as_str().unwrap()),
                )
                .unwrap();
                macos_support::verify(case, &path, &certificates, fixtures);
            }
            "cancel" => assert_eq!(
                result["type"],
                "es.gob.afirma.core.AOCancelledOperationException"
            ),
            "worker-failure" => {
                assert!(result["signature"].is_null());
                assert!(result["code"].as_str().unwrap().starts_with("SAF_09:"));
            }
            "disconnect" => assert_eq!(result["disconnected"], true),
            _ => unreachable!(),
        }
    }
    let browser_checks: Value =
        serde_json::from_slice(&fs::read(output_dir.join("browser-checks.json")).unwrap()).unwrap();
    assert_eq!(browser_checks["untrusted_profile_rejected"], true);
    support::report(
        &output_dir.join("result.json"),
        &json!({"passed":true,"architecture":env::consts::ARCH,"local_signatures":local.len(),"browser_scenarios":browser.len(),"browser":browser_checks}),
    );
}
