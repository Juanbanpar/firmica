//! Real TLS/WebSocket boundary tests. All credentials and trust are ephemeral.
use super::{load_tls, Decision, PendingRequest, Server};
use firmica_protocol::{
    ProtocolRequest, WebSocketBootstrap, MAX_URI_BYTES, MAX_WEBSOCKET_REQUEST_BYTES,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    net::{Ipv4Addr, SocketAddr},
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer},
    },
    TlsConnector,
};
use tokio_tungstenite::{
    client_async,
    tungstenite::{
        client::IntoClientRequest,
        protocol::{
            frame::{
                coding::{CloseCode, Data, OpCode},
                Frame,
            },
            Message,
        },
    },
    WebSocketStream,
};

const SESSION: &str = "0123456789abcdef";
const ORIGIN: &str = "https://example.invalid";
type Client = WebSocketStream<TlsStream<TcpStream>>;

pub(super) struct Peer {
    pub(super) address: SocketAddr,
    #[cfg(target_os = "linux")]
    pub(super) certificate: std::path::PathBuf,
    #[cfg(target_os = "linux")]
    pub(super) authority: std::path::PathBuf,
    _directory: tempfile::TempDir,
    client: Arc<rustls::ClientConfig>,
    pub(super) requests: mpsc::Receiver<PendingRequest>,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    async fn start() -> Self {
        Self::configured("4", ORIGIN).await
    }

    pub(super) async fn configured(version: &str, origin: &str) -> Self {
        Self::with_origins(version, 4, &[origin]).await
    }

    async fn with_origins(version: &str, jvc: u8, origins: &[&str]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("tls.pem");
        let key = directory.path().join("tls.key");
        let authority = directory.path().join("ca.pem");
        let authority_key = directory.path().join("ca.key");
        let request = directory.path().join("tls.csr");
        let extensions = directory.path().join("tls.ext");
        std::fs::write(&extensions, "subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        for command in [
            Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Firmica synthetic transport CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                    "-keyout",
                ])
                .arg(&authority_key)
                .arg("-out")
                .arg(&authority),
            Command::new("openssl")
                .args([
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    "/CN=Firmica synthetic transport test",
                    "-keyout",
                ])
                .arg(&key)
                .arg("-out")
                .arg(&request),
            Command::new("openssl")
                .args(["x509", "-req", "-days", "1", "-in"])
                .arg(&request)
                .arg("-CA")
                .arg(&authority)
                .arg("-CAkey")
                .arg(&authority_key)
                .arg("-CAcreateserial")
                .arg("-extfile")
                .arg(&extensions)
                .arg("-out")
                .arg(&certificate),
        ] {
            assert!(
                command
                    .output()
                    .expect("OpenSSL CLI is required for transport tests")
                    .status
                    .success(),
                "cannot generate synthetic TLS credentials"
            );
        }
        let tls = load_tls(&certificate, &key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(&authority).unwrap() {
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
                "afirma://websocket?v={version}&jvc={jvc}&ports=49152&idsession={SESSION}"
            ))
            .unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = Server::with_listener(
            listener,
            bootstrap,
            tls,
            origins.iter().map(|origin| (*origin).to_owned()).collect(),
        );
        let (sender, requests) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            server.run(sender).await.unwrap();
        });
        Self {
            address,
            #[cfg(target_os = "linux")]
            certificate,
            #[cfg(target_os = "linux")]
            authority,
            _directory: directory,
            client: Arc::new(client),
            requests,
            task,
        }
    }

    async fn connect(&self) -> Client {
        self.connect_with_origins(&[ORIGIN]).await.unwrap()
    }

    async fn connect_with_origins(
        &self,
        origins: &[&str],
    ) -> Result<Client, tokio_tungstenite::tungstenite::Error> {
        let stream = TcpStream::connect(self.address).await.unwrap();
        let stream = TlsConnector::from(self.client.clone())
            .connect("127.0.0.1".try_into().unwrap(), stream)
            .await
            .unwrap();
        let mut request = format!("wss://{}/", self.address)
            .into_client_request()
            .unwrap();
        for origin in origins {
            request
                .headers_mut()
                .append("Origin", origin.parse().unwrap());
        }
        client_async(request, stream)
            .await
            .map(|(socket, _)| socket)
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

// Keep real time active during TLS and WebSocket I/O so the clock only jumps
// when the test explicitly advances it.
async fn elapse(seconds: u64) {
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(seconds)).await;
    tokio::time::resume();
}

#[tokio::test]
async fn synchronous_review_expires_without_a_decision() {
    let mut peer = Peer::with_origins("4", 3, &[ORIGIN]).await;
    let mut socket = peer.connect().await;
    socket
        .send(Message::Text(
            format!("afirma://cosign?idsession={SESSION}").into(),
        ))
        .await
        .unwrap();
    let pending = timeout(Duration::from_secs(5), peer.requests.recv())
        .await
        .unwrap()
        .unwrap();

    elapse(59).await;
    assert!(!pending.reply.is_closed());
    elapse(2).await;
    assert_eq!(received(&mut socket).await.to_text().unwrap(), "CANCEL");
    assert!(pending.reply.send(Decision::Reject).is_err());
}

#[tokio::test]
async fn asynchronous_review_survives_reconnect_until_listener_expires() {
    let mut peer = Peer::start().await;
    let mut socket = peer.connect().await;
    let sign = Message::Text(format!("afirma://sign?idsession={SESSION}&dat=AA==").into());
    socket.send(sign.clone()).await.unwrap();
    assert_eq!(received(&mut socket).await.to_text().unwrap(), "#wait");
    let mut pending = timeout(Duration::from_secs(5), peer.requests.recv())
        .await
        .unwrap()
        .unwrap();
    socket.close(None).await.unwrap();
    drop(socket);

    elapse(119).await;
    let mut socket = peer.connect().await;
    socket
        .send(Message::Text(
            format!("getresult?idsession={SESSION}").into(),
        ))
        .await
        .unwrap();
    assert_eq!(received(&mut socket).await.to_text().unwrap(), "#wait");
    socket.send(sign).await.unwrap();
    assert_eq!(
        received(&mut socket).await.to_text().unwrap(),
        "err-00:=AF600002 - Operation not supported"
    );
    assert!(peer.requests.try_recv().is_err());

    elapse(2).await;
    timeout(Duration::from_secs(5), pending.reply.closed())
        .await
        .unwrap();
    timeout(Duration::from_secs(5), &mut peer.task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn listener_certificate_requires_explicit_trust() {
    let peer = Peer::start().await;
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let stream = TcpStream::connect(peer.address).await.unwrap();
    let error = TlsConnector::from(Arc::new(client))
        .connect("127.0.0.1".try_into().unwrap(), stream)
        .await
        .unwrap_err();
    assert!(matches!(
        error.get_ref().and_then(|error| error.downcast_ref()),
        Some(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer
        ))
    ));
    peer.connect().await;
}

#[tokio::test]
async fn exact_origin_authorization_binds_a_session_and_its_result() {
    const OTHER: &str = "https://other.invalid:8443";
    const INVALID_SESSION: &str = "err-00:=AF620010 - Invalid WebSocket session";
    let mut peer = Peer::with_origins("4", 4, &[ORIGIN, OTHER]).await;
    for headers in [
        &[][..],
        &["https://example.invalid:443"],
        &["https://other.invalid"],
        &["https://sub.example.invalid"],
        &[ORIGIN, OTHER],
        &[ORIGIN, ORIGIN],
    ] {
        let error = peer.connect_with_origins(headers).await.unwrap_err();
        assert!(matches!(
            error,
            tokio_tungstenite::tungstenite::Error::Http(response)
                if response.status() == 403
        ));
    }

    let mut first = peer.connect().await;
    first
        .send(Message::Text("echo=-idsession=wrong@EOF".into()))
        .await
        .unwrap();
    assert_eq!(
        received(&mut first).await.to_text().unwrap(),
        INVALID_SESSION
    );

    let mut owner = peer.connect_with_origins(&[OTHER]).await.unwrap();
    let echo = format!("echo=-idsession={SESSION}@EOF");
    owner
        .send(Message::Text(echo.clone().into()))
        .await
        .unwrap();
    assert_eq!(received(&mut owner).await.to_text().unwrap(), "OK");
    first.send(Message::Text(echo.into())).await.unwrap();
    assert_eq!(
        received(&mut first).await.to_text().unwrap(),
        INVALID_SESSION
    );

    owner
        .send(Message::Text(
            format!("afirma://sign?idsession={SESSION}&dat=AA==").into(),
        ))
        .await
        .unwrap();
    assert_eq!(received(&mut owner).await.to_text().unwrap(), "#wait");
    let pending = timeout(Duration::from_secs(5), peer.requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.browser_origin, OTHER);
    pending.reply.send(Decision::Reject).unwrap();
    owner.close(None).await.unwrap();
    let poll = format!("getresult?idsession={SESSION}");
    first
        .send(Message::Text(poll.clone().into()))
        .await
        .unwrap();
    assert_eq!(
        received(&mut first).await.to_text().unwrap(),
        INVALID_SESSION
    );
    let mut owner = peer.connect_with_origins(&[OTHER]).await.unwrap();
    owner
        .send(Message::Text(poll.clone().into()))
        .await
        .unwrap();
    assert_eq!(
        received(&mut owner).await.to_text().unwrap(),
        "err-11:=AF500001 - Operation cancelled by user"
    );
    owner.send(Message::Text(poll.into())).await.unwrap();
    assert_eq!(
        received(&mut owner).await.to_text().unwrap(),
        super::ProtocolError::Unsupported.wire("4.1".parse().unwrap())
    );
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
        "err-00:=AF620010 - Invalid WebSocket session"
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
                format!("getresult?idsession={SESSION}&extra=unexpected").into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            received(&mut socket).await.to_text().unwrap(),
            "err-00:=AF620010 - Invalid WebSocket session",
        );
        socket
            .send(Message::Text(
                format!("getresult?idsession={SESSION}").into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            received(&mut socket).await.to_text().unwrap(),
            "err-11:=AF500001 - Operation cancelled by user"
        );
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
