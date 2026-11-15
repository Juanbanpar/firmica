#![allow(dead_code)]
use super::{signing_support, support};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

pub fn fixtures(directory: &Path) -> Value {
    signing_support::identities(directory);
    let mut local = Vec::new();
    for algorithm in ["rsa", "ec"] {
        for mode in [
            "cades",
            "pades",
            "pades-visible",
            "enveloped",
            "enveloping",
            "detached",
        ] {
            let content: &[u8] = match mode {
                "pades" | "pades-visible" => {
                    include_bytes!("../../../../crates/pades/tests/fixtures/document.pdf")
                }
                "enveloped" => {
                    b"<document xmlns=\"urn:firmica:test\">Synthetic XML &amp; bytes</document>"
                }
                _ => b"Synthetic Windows document\x00\xff\r\n",
            };
            let name = format!("{algorithm}-{mode}");
            let document = directory.join(format!("{name}.input"));
            fs::write(&document, content).unwrap();
            let extension = match mode {
                "cades" => "csig",
                "pades" | "pades-visible" => "pdf",
                _ => "xsig",
            };
            local.push(json!({
                "name":name,"algorithm":algorithm,"mode":if mode=="pades-visible" {"pades"} else {mode},
                "visible":mode=="pades-visible","document":document,
                "certificate":directory.join(format!("{algorithm}.p12")),
                "content":STANDARD.encode(content),"hash":format!("{:x}",Sha256::digest(content)),
                "fingerprint":support::sha256(&directory.join(format!("{algorithm}.der"))),
                "output":directory.join(format!("{name}.{extension}")),
                "format":match mode {"cades"=>"CAdES","pades"|"pades-visible"=>"PAdES",_=>"XAdES"},
                "attached":mode=="cades" && algorithm=="ec",
                "properties":match mode {
                    "cades"=>if algorithm=="ec" {"mode=implicit"} else {"mode=explicit"},
                    "pades"=>"",
                    "pades-visible"=>"signaturePage=1\nsignaturePositionOnPageLowerLeftX=40\nsignaturePositionOnPageLowerLeftY=30\nsignaturePositionOnPageUpperRightX=400\nsignaturePositionOnPageUpperRightY=70\nlayer2Text=Signed with Firmica",
                    "enveloped"=>"format=XAdES Enveloped", "enveloping"=>"format=XAdES Enveloping", _=>"format=XAdES Detached"
                },"action":"sign"
            }));
        }
    }
    let mut browser = Vec::new();
    for protocol in ["4", "4.1"] {
        for mut case in local.clone() {
            case["protocol"] = json!(protocol);
            case["name"] = json!(format!(
                "protocol{}-{}",
                protocol,
                case["name"].as_str().unwrap()
            ));
            case["output"] =
                json!(directory.join(format!("{}.signed", case["name"].as_str().unwrap())));
            browser.push(case);
        }
        for action in ["cancel", "worker-failure"] {
            let mut case = browser
                .iter()
                .find(|case| case["protocol"] == protocol)
                .unwrap()
                .clone();
            case["name"] = json!(format!("protocol{protocol}-{action}"));
            case["action"] = json!(action);
            case["output"] =
                json!(directory.join(format!("{}.signed", case["name"].as_str().unwrap())));
            browser.push(case);
        }
    }
    let config = json!({"local":local,"browser":browser,"password":signing_support::PASSWORD});
    fs::write(
        directory.join("cases.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    config
}

pub fn verify(config: &Value, suite: &str, directory: &Path, evidence: &Path) {
    for case in config[suite].as_array().unwrap() {
        let path = Path::new(case["output"].as_str().unwrap());
        if case["action"] != "sign" {
            assert!(!path.exists(), "failed operation published a signature");
            continue;
        }
        signing_support::verify(case, path, directory, directory, evidence);
        println!("independently verified {}", case["name"]);
    }
    let tools = [
        ("openssl", vec!["version"]),
        ("pdfsig", vec!["-v"]),
        ("xmlsec1", vec!["--version"]),
    ]
    .into_iter()
    .map(|(tool, args)| {
        (tool.to_owned(), {
            let result = support::output(Command::new(tool).args(args), 30);
            assert!(result.status.success());
            json!(String::from_utf8([result.stdout, result.stderr].concat()).unwrap())
        })
    })
    .collect::<serde_json::Map<_, _>>();
    support::report(
        &evidence.join("verification.json"),
        &json!({"passed":true,"cases":config[suite].as_array().unwrap().len(),"tools":tools}),
    );
}
