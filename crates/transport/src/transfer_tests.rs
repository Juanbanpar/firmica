//! Real TLS/WebSocket boundary tests. All credentials and trust are ephemeral.
use super::*;
use std::process::Command;
use tokio::io::AsyncWriteExt;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{
    client_async,
    tungstenite::{
        client::IntoClientRequest,
        protocol::frame::{
            coding::{Data, OpCode},
            Frame,
        },
    },
    WebSocketStream,
};

const SESSION: &str = "0123456789abcdef";
const ORIGIN: &str = "https://example.invalid";
type Client = WebSocketStream<TlsStream<TcpStream>>;

struct Peer {
    address: SocketAddr,
    client: Arc<rustls::ClientConfig>,
    requests: mpsc::Receiver<PendingRequest>,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("tls.pem");
        let key = directory.path().join("tls.key");
        let generated = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Firmica synthetic transport test",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .output()
            .expect("OpenSSL CLI is required for transport tests");
        assert!(
            generated.status.success(),
            "cannot generate synthetic TLS credentials"
        );
        let tls = load_tls(&certificate, &key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(&certificate).unwrap() {
            roots.add(certificate.unwrap()).unwrap();
        }
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let bootstrap = WebSocketBootstrap::from_request(
            &ProtocolRequest::parse(&format!(
                "afirma://websocket?v=4&jvc=4&ports=49152&idsession={SESSION}"
            ))
            .unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = Server {
            listener,
            tls,
            origin: ORIGIN.into(),
            session: Arc::new(Mutex::new(Session {
                bootstrap,
                used: false,
                result: None,
            })),
        };
        let (sender, requests) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            server.run(sender).await.unwrap();
        });
        Self {
            address,
            client: Arc::new(client),
            requests,
            task,
        }
    }

    async fn connect(&self) -> Client {
        let stream = TcpStream::connect(self.address).await.unwrap();
        let stream = TlsConnector::from(self.client.clone())
            .connect("127.0.0.1".try_into().unwrap(), stream)
            .await
            .unwrap();
        let mut request = format!("wss://{}/", self.address)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Origin", ORIGIN.parse().unwrap());
        client_async(request, stream).await.unwrap().0
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn received(socket: &mut Client) -> Message {
    timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn large_requests_authenticate_and_work_with_whole_or_fragmented_messages() {
    let mut peer = Peer::start().await;
    let mut socket = peer.connect().await;
    let data = "A".repeat(1024 * 1024);
    let wrong = format!("afirma://sign?idsession=wrong&dat={data}");
    socket.send(Message::Text(wrong.into())).await.unwrap();
    assert_eq!(
        received(&mut socket).await.to_text().unwrap(),
        "SAF_46: Invalid WebSocket session"
    );
    assert!(peer.requests.try_recv().is_err());
    socket.close(None).await.unwrap();
    for fragmented in [false, true] {
        // Each bootstrap permits one operation, so use a fresh server after the first.
        if fragmented {
            peer = Peer::start().await;
        }
        let mut socket = peer.connect().await;
        let uri = format!("afirma://sign?idsession={SESSION}&dat={data}");
        if fragmented {
            let middle = uri.len() / 2;
            socket
                .send(Message::Frame(Frame::message(
                    uri.as_bytes()[..middle].to_vec(),
                    OpCode::Data(Data::Text),
                    false,
                )))
                .await
                .unwrap();
            assert!(peer.requests.try_recv().is_err());
            socket
                .send(Message::Frame(Frame::message(
                    uri.as_bytes()[middle..].to_vec(),
                    OpCode::Data(Data::Continue),
                    true,
                )))
                .await
                .unwrap();
        } else {
            socket.send(Message::Text(uri.into())).await.unwrap();
        }
        assert_eq!(received(&mut socket).await.to_text().unwrap(), "#wait");
        let pending = timeout(Duration::from_secs(5), peer.requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.request.parameter("dat"), Some(data.as_str()));
        pending.reply.send(Decision::Reject).unwrap();
        socket
            .send(Message::Text(
                format!("getresult?idsession={SESSION}").into(),
            ))
            .await
            .unwrap();
        assert_eq!(received(&mut socket).await.to_text().unwrap(), "CANCEL");
    }
}

#[tokio::test]
async fn oversized_metadata_and_frames_never_reach_the_application() {
    let mut peer = Peer::start().await;
    let mut socket = peer.connect().await;
    socket
        .send(Message::Text(
            format!(
                "afirma://sign?idsession={SESSION}&unknown={}",
                "x".repeat(MAX_URI_BYTES)
            )
            .into(),
        ))
        .await
        .unwrap();
    assert!(
        matches!(received(&mut socket).await, Message::Close(Some(frame)) if frame.code == CloseCode::Size)
    );
    assert!(peer.requests.try_recv().is_err());
    let mut socket = peer.connect().await;
    // A masked text frame header declaring too much payload must be rejected
    // before the server receives or allocates the advertised body.
    let mut header = vec![0x81, 0xff];
    header.extend_from_slice(&((MAX_WEBSOCKET_REQUEST_BYTES + 1) as u64).to_be_bytes());
    header.extend_from_slice(&[0; 4]);
    socket.get_mut().write_all(&header).await.unwrap();
    socket.get_mut().flush().await.unwrap();
    let response = timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap();
    assert!(matches!(
        response,
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
    assert!(peer.requests.try_recv().is_err());
    let mut socket = peer.connect().await;
    let chunk_bytes = 1024 * 1024;
    let fragments = MAX_WEBSOCKET_REQUEST_BYTES / chunk_bytes + 1;
    for index in 0..fragments {
        socket
            .send(Message::Frame(Frame::message(
                vec![b'A'; chunk_bytes],
                OpCode::Data(if index == 0 {
                    Data::Text
                } else {
                    Data::Continue
                }),
                index + 1 == fragments,
            )))
            .await
            .unwrap();
    }
    // Individually valid frames must not bypass the aggregate message limit.
    let response = timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap();
    assert!(matches!(
        response,
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
    assert!(peer.requests.try_recv().is_err());
    // Invalid connections must not consume the one permitted operation.
    let mut socket = peer.connect().await;
    socket
        .send(Message::Text(
            format!("afirma://sign?idsession={SESSION}&dat=AA==").into(),
        ))
        .await
        .unwrap();
    assert_eq!(received(&mut socket).await.to_text().unwrap(), "#wait");
    assert!(timeout(Duration::from_secs(5), peer.requests.recv())
        .await
        .unwrap()
        .is_some());
}
