//! Browser wire conformance; AutoScript itself still negotiates protocol 4.
use super::{transfer_tests::Peer, *};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use std::{
    fs,
    io::Write,
    process::{Child, Command, Stdio},
    time::Instant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Browser(Child);
impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Node, Playwright Chromium/Firefox, OpenSSL and NSS certutil"]
async fn protocol_41_in_chromium_and_firefox() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let evidence = root.join(".test-artifacts/protocol41");
    fs::create_dir_all(&evidence).unwrap();
    for browser in ["chromium", "firefox"] {
        let temporary = tempfile::tempdir().unwrap();
        let profile = temporary.path().join("firefox");
        fs::create_dir(&profile).unwrap();
        assert!(Command::new("certutil")
            .args(["-N", "-d"])
            .arg(format!("sql:{}", profile.display()))
            .arg("--empty-password")
            .status()
            .unwrap()
            .success());
        let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin = format!("http://{}", http.local_addr().unwrap());
        let mut peers = Vec::new();
        let mut workers = Vec::new();
        let mut cases = Vec::new();
        let mut releases = Vec::new();
        let mut pins = Vec::new();
        let outcomes = [
            ("cancel", "err-11:=AF500001 - Operation cancelled by user"),
            ("unsupported", "err-00:=AF600002 - Operation not supported"),
            (
                "parameters",
                "err-00:=AF620016 - Invalid request parameters",
            ),
            ("failure", "err-00:=AF200115 - Signing failed"),
            (
                "abandoned",
                "err-11:=AF500001 - Operation cancelled by user",
            ),
            ("signed", "-_8=|AQI="),
        ];
        for (index, (name, _)) in outcomes.iter().enumerate() {
            let mut peer = Peer::configured("4.1", &origin).await;
            let public = Command::new("openssl")
                .args(["x509", "-pubkey", "-noout", "-in"])
                .arg(&peer.certificate)
                .output()
                .unwrap();
            assert!(public.status.success());
            let mut process = Command::new("openssl")
                .args(["pkey", "-pubin", "-outform", "DER"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            process
                .stdin
                .take()
                .unwrap()
                .write_all(&public.stdout)
                .unwrap();
            let der = process.wait_with_output().unwrap();
            assert!(der.status.success());
            use sha2::{Digest, Sha256};
            pins.push(STANDARD.encode(Sha256::digest(&der.stdout)));
            // Trust is confined to this disposable NSS database.
            assert!(Command::new("certutil")
                .args(["-A", "-d"])
                .arg(format!("sql:{}", profile.display()))
                .args(["-n", &format!("synthetic-{index}"), "-t", "C,,", "-i"])
                .arg(&peer.authority)
                .status()
                .unwrap()
                .success());
            cases.push(json!({"name":name,"endpoint":format!("wss://{}/",peer.address)}));
            let (release, released) = oneshot::channel();
            releases.push(Some(release));
            let mut requests = std::mem::replace(&mut peer.requests, mpsc::channel(1).1);
            workers.push(tokio::spawn(async move {
                let pending = requests.recv().await.unwrap();
                assert_eq!(
                    pending.request.version,
                    ProtocolVersion { major: 4, minor: 1 }
                );
                assert_eq!(pending.request.operation, Operation::Sign);
                released.await.unwrap();
                let decision = match index {
                    0 => Some(Decision::Reject),
                    1 => Some(Decision::Unsupported),
                    2 => Some(Decision::InvalidParameters),
                    3 => Some(Decision::Failed),
                    4 => None,
                    _ => Some(Decision::Signed(
                        firmica_protocol::signing::SignResponse::new(&[251, 255], &[1, 2]).unwrap(),
                    )),
                };
                if let Some(decision) = decision {
                    pending.reply.send(decision).unwrap();
                }
                requests
            }));
            peers.push(peer);
        }
        let service = tokio::spawn(async move {
            loop {
                let (mut socket, _) = http.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let count = socket.read(&mut request).await.unwrap();
                let route = std::str::from_utf8(&request[..count])
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                if let Some(index) = route.strip_prefix("/release/") {
                    releases[index.parse::<usize>().unwrap()]
                        .take()
                        .unwrap()
                        .send(())
                        .unwrap();
                }
                let body = "<!doctype html><title>Synthetic protocol conformance</title>";
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let config = temporary.path().join("browser.json");
        fs::write(
            &config,
            json!({"browser":browser,"origin":origin,"profile":profile,"pins":pins,"cases":cases})
                .to_string(),
        )
        .unwrap();
        let report = evidence.join(format!("{browser}.json"));
        let _ = fs::remove_file(&report);
        let log = fs::File::create(evidence.join(format!("{browser}.log"))).unwrap();
        let mut child = Browser(
            Command::new("node")
                .current_dir(&root)
                .arg("tests/interop/protocol41.mjs")
                .arg(config)
                .arg(&report)
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(90);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "browser timed out; see .test-artifacts/protocol41"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(
            status.success(),
            "{browser} failed ({status}); see .test-artifacts/protocol41"
        );
        let observed: serde_json::Value =
            serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
        for (index, (name, expected)) in outcomes.iter().enumerate() {
            let case = &observed["cases"][index];
            assert_eq!(case["name"], *name);
            assert_eq!(
                case["initial"],
                json!([
                    "OK",
                    "err-00:=AF620010 - Invalid WebSocket session",
                    "err-00:=AF600002 - Operation not supported",
                    "err-00:=AF620016 - Invalid request parameters",
                    "#wait",
                    "#wait"
                ])
            );
            assert_eq!(case["reconnected"], json!(["OK", "#wait"]));
            assert_eq!(case["result"], *expected);
            assert_eq!(
                case["consumed"],
                json!([
                    "err-00:=AF600002 - Operation not supported",
                    "err-00:=AF600002 - Operation not supported"
                ])
            );
        }
        for worker in workers {
            assert!(
                worker.await.unwrap().try_recv().is_err(),
                "replayed request reached the application"
            );
        }
        service.abort();
        drop(peers);
    }
}
