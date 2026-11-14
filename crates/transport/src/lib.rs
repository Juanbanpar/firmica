//! Bounded local WSS service. The application supplies explicitly approved signing
//! results or errors; the transport never accesses documents or private keys.

use firmica_protocol::{
    parse_query, Operation, ParseError, ProtocolRequest, ProtocolVersion, WebSocketBootstrap,
    MAX_URI_BYTES, MAX_WEBSOCKET_REQUEST_BYTES,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Mutex, Semaphore},
    time::timeout,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        self,
        handshake::server::{Request, Response},
        protocol::{frame::coding::CloseCode, CloseFrame, Message, WebSocketConfig},
    },
};

/// Application outcome for one authenticated request.
#[derive(Debug, Eq, PartialEq)]
pub enum Decision {
    Reject,
    Unsupported,
    /// Invalid or unsupported request parameters.
    InvalidParameters,
    /// Signing or key cleanup failed; no result may be delivered.
    Failed,
    /// A verified signature, released only after explicit approval and key cleanup.
    Signed(firmica_protocol::signing::SignResponse),
}

/// A bounded handoff to the application. Dropping the reply cancels the request.
pub struct PendingRequest {
    pub request: ProtocolRequest,
    pub reply: oneshot::Sender<Decision>,
}

/// Protocol-level errors used by the prototype. Codes come from the pinned upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Cancelled,
    Unsupported,
    Session,
    Parameters,
    SigningFailed,
}

impl ProtocolError {
    pub fn wire(self, version: ProtocolVersion) -> String {
        let (legacy, code, message) = match self {
            Self::SigningFailed => ("SAF_09", "200115", "Signing failed"),
            Self::Cancelled => ("CANCEL", "500001", "Operation cancelled by user"),
            Self::Unsupported => ("SAF_04", "600002", "Operation not supported"),
            Self::Session => ("SAF_46", "620010", "Invalid WebSocket session"),
            Self::Parameters => ("SAF_03", "620016", "Invalid request parameters"),
        };
        if version >= (ProtocolVersion { major: 4, minor: 1 }) {
            let prefix = if self == Self::Cancelled {
                "err-11:="
            } else {
                "err-00:="
            };
            format!("{prefix}AF{code} - {message}")
        } else if self == Self::Cancelled {
            legacy.into()
        } else {
            format!("{legacy}: {message}")
        }
    }
}

/// Loads a caller-provided certificate chain and matching PKCS#8/PKCS#1/SEC1 key.
/// No certificate is installed into a browser or system trust store.
pub fn load_tls(
    certificate: &Path,
    key: &Path,
) -> Result<Arc<rustls::ServerConfig>, TransportError> {
    let certificates =
        CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key)?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    Ok(Arc::new(config))
}

/// One bootstrap permits one reviewed operation, including across reconnects.
struct Session {
    bootstrap: WebSocketBootstrap,
    used: bool,
    result: Option<oneshot::Receiver<Decision>>,
}

impl Session {
    fn authenticated(&self, message: &str) -> bool {
        let query = if let Some(value) = message
            .strip_prefix("echo=-idsession=")
            .and_then(|v| v.strip_suffix("@EOF"))
        {
            return value == self.bootstrap.session();
        } else if let Some(query) = message.strip_prefix("getresult?") {
            query
        } else if let Some((_, query)) = message.split_once('?') {
            query
        } else {
            return false;
        };
        parse_query(query)
            .ok()
            .and_then(|p| p.get("idsession").cloned())
            .as_deref()
            == Some(self.bootstrap.session())
    }
}

/// Checks that a setting is exactly one canonical HTTP(S) browser origin.
/// Paths, credentials, queries, fragments and opaque origins are rejected.
pub fn validate_origin(origin: &str) -> Result<(), TransportError> {
    if origin.len() > 2048 {
        return Err(TransportError::Origin);
    }
    let parsed = url::Url::parse(origin).map_err(|_| TransportError::Origin)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(TransportError::Origin);
    }
    Ok(())
}

/// Listener bound only to IPv4 loopback. Origin is an explicit local setting,
/// never an identity supplied by the invocation. Server lifetime is at most 120 s.
pub struct Server {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    origin: String,
    session: Arc<Mutex<Session>>,
}

impl Server {
    pub async fn bind(
        bootstrap: WebSocketBootstrap,
        tls: Arc<rustls::ServerConfig>,
        origin: String,
    ) -> Result<Self, TransportError> {
        validate_origin(&origin)?;
        let mut last_error = None;
        for port in &bootstrap.ports {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).await {
                Ok(listener) => {
                    return Ok(Self {
                        listener,
                        tls,
                        origin,
                        session: Arc::new(Mutex::new(Session {
                            bootstrap,
                            used: false,
                            result: None,
                        })),
                    })
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::other("no listener port"))
            .into())
    }

    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.listener.local_addr()
    }

    /// Runs until expiry or cancellation by dropping this future. All child connections
    /// are aborted on exit. At most four connections and one operation are admitted.
    pub async fn run(self, requests: mpsc::Sender<PendingRequest>) -> Result<(), TransportError> {
        let mut tasks = tokio::task::JoinSet::new();
        let permits = Arc::new(Semaphore::new(4));
        let deadline = tokio::time::sleep(Duration::from_secs(120));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = self.listener.accept() => {
                    let (stream, remote) = accepted?;
                    if remote.ip() != Ipv4Addr::LOCALHOST { continue; }
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                    let tls = self.tls.clone();
                    let origin = self.origin.clone();
                    let session = self.session.clone();
                    let requests = requests.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        // Errors contain library-provided untrusted details; do not log them.
                        let _ = timeout(Duration::from_secs(90), connection(stream, tls, origin, session, requests)).await;
                    });
                }
            }
        }
        tasks.abort_all();
        Ok(())
    }
}

async fn connection(
    stream: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    origin: String,
    session: Arc<Mutex<Session>>,
    requests: mpsc::Sender<PendingRequest>,
) -> Result<(), TransportError> {
    let expected_host = stream.local_addr()?.to_string();
    let acceptor = TlsAcceptor::from(tls);
    let stream = timeout(Duration::from_secs(5), acceptor.accept(stream))
        .await
        .map_err(|_| TransportError::Timeout)??;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WEBSOCKET_REQUEST_BYTES))
        .max_frame_size(Some(MAX_WEBSOCKET_REQUEST_BYTES))
        .max_write_buffer_size(
            firmica_protocol::signing::MAX_SIGN_RESPONSE_BYTES + 128 * 1024 + 14,
        );
    // Tungstenite requires its concrete HTTP ErrorResponse as the callback error type.
    #[allow(clippy::result_large_err)]
    let callback = move |request: &Request, response: Response| {
        let origin_ok = request
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            == Some(origin.as_str());
        let host_ok = request.headers().get("host").and_then(|v| v.to_str().ok())
            == Some(expected_host.as_str());
        if origin_ok && host_ok && request.uri().path() == "/" {
            Ok(response)
        } else {
            Err(tungstenite::http::Response::builder()
                .status(403)
                .body(Some("Forbidden".into()))
                .unwrap())
        }
    };
    let mut socket = timeout(
        Duration::from_secs(5),
        accept_hdr_async_with_config(stream, callback, Some(config)),
    )
    .await
    .map_err(|_| TransportError::Timeout)??;
    while let Some(message) = timeout(Duration::from_secs(60), socket.next())
        .await
        .map_err(|_| TransportError::Timeout)?
    {
        let message = message?;
        let Message::Text(message) = message else {
            if matches!(message, Message::Close(_)) {
                break;
            }
            if matches!(message, Message::Ping(_) | Message::Pong(_)) {
                continue;
            }
            break;
        };
        let mut state = session.lock().await;
        let version = state.bootstrap.version;
        // Parse document-bearing requests once. Authentication must not allocate
        // and decode a second copy of a large document merely to find its session.
        let request = message
            .starts_with("afirma://")
            .then(|| ProtocolRequest::parse_websocket(&message));
        if message.len() > MAX_URI_BYTES && !matches!(&request, Some(Ok(_))) {
            drop(state);
            socket
                .close(Some(CloseFrame {
                    code: CloseCode::Size,
                    reason: "invalid or oversized request".into(),
                }))
                .await?;
            break;
        }
        let authenticated = match &request {
            Some(Ok(request)) => request.parameter("idsession") == Some(state.bootstrap.session()),
            _ => state.authenticated(&message),
        };
        let response = if !authenticated {
            ProtocolError::Session.wire(version)
        } else if message.starts_with("echo=-idsession=") {
            "OK".into()
        } else if message.starts_with("getresult?") {
            match state.result.as_mut().map(oneshot::Receiver::try_recv) {
                Some(Ok(decision)) => {
                    state.result = None;
                    decision_wire(decision, version)
                }
                Some(Err(oneshot::error::TryRecvError::Empty)) => "#wait".into(),
                Some(Err(oneshot::error::TryRecvError::Closed)) => {
                    state.result = None;
                    ProtocolError::Cancelled.wire(version)
                }
                None => ProtocolError::Unsupported.wire(version),
            }
        } else if state.used {
            ProtocolError::Unsupported.wire(version)
        } else {
            match request.unwrap_or(Err(ParseError::Scheme)) {
                Ok(mut request)
                    if !matches!(request.operation, Operation::WebSocket | Operation::Service) =>
                {
                    // Operation URIs sent over WSS inherit the negotiated channel version.
                    request.version = version;
                    let (reply, result) = oneshot::channel();
                    if requests
                        .try_send(PendingRequest { request, reply })
                        .is_err()
                    {
                        ProtocolError::Unsupported.wire(version)
                    } else {
                        state.used = true;
                        if state.bootstrap.asynchronous {
                            state.result = Some(result);
                            "#wait".into()
                        } else {
                            drop(state);
                            let decision = timeout(Duration::from_secs(60), result)
                                .await
                                .ok()
                                .and_then(Result::ok)
                                .unwrap_or(Decision::Reject);
                            socket
                                .send(Message::Text(decision_wire(decision, version).into()))
                                .await?;
                            continue;
                        }
                    }
                }
                Err(ParseError::Operation) => ProtocolError::Unsupported.wire(version),
                _ => ProtocolError::Parameters.wire(version),
            }
        };
        drop(state);
        socket.send(Message::Text(response.into())).await?;
    }
    Ok(())
}

fn decision_wire(decision: Decision, version: ProtocolVersion) -> String {
    match decision {
        Decision::Reject => ProtocolError::Cancelled.wire(version),
        Decision::Unsupported => ProtocolError::Unsupported.wire(version),
        Decision::Failed => ProtocolError::SigningFailed.wire(version),
        Decision::InvalidParameters => ProtocolError::Parameters.wire(version),
        Decision::Signed(result) => result.into_wire(),
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O failure")]
    Io(#[from] io::Error),
    #[error("invalid PEM file")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("TLS configuration failure")]
    Tls(#[from] rustls::Error),
    #[error("WebSocket failure")]
    WebSocket(#[from] tungstenite::Error),
    #[error("handshake or request timed out")]
    Timeout,
    #[error("an explicit HTTP(S) test origin is required")]
    Origin,
}

#[cfg(test)]
mod transfer_tests;

#[cfg(all(test, target_os = "linux"))]
mod browser_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_origin_settings_are_exact_and_canonical() {
        for origin in [
            "https://example.invalid",
            "http://127.0.0.1:8080",
            "https://example.invalid:8443",
        ] {
            assert!(validate_origin(origin).is_ok());
        }
        for origin in [
            "null",
            "file:///tmp",
            "https://example.invalid/",
            "https://example.invalid/path",
            "https://user@example.invalid",
            "https://example.invalid?query",
            "https://example.invalid#fragment",
            "https://example.invalid\r\n",
            "https://example.invalid:443",
            "https://EXAMPLE.invalid",
            "https://example.invalid ",
        ] {
            assert!(validate_origin(origin).is_err(), "{origin:?}");
        }
    }
    #[test]
    fn wire_errors_are_version_specific() {
        let v4 = ProtocolVersion { major: 4, minor: 0 };
        let v41 = ProtocolVersion { major: 4, minor: 1 };
        assert_eq!(ProtocolError::Cancelled.wire(v4), "CANCEL");
        assert_eq!(
            ProtocolError::Unsupported.wire(v4),
            "SAF_04: Operation not supported"
        );
        assert_eq!(
            ProtocolError::Session.wire(v41),
            "err-00:=AF620010 - Invalid WebSocket session"
        );
        assert_eq!(
            ProtocolError::Cancelled.wire(v41),
            "err-11:=AF500001 - Operation cancelled by user"
        );
        assert_eq!(
            decision_wire(Decision::Failed, v4),
            "SAF_09: Signing failed"
        );
        assert_eq!(
            decision_wire(Decision::Failed, v41),
            "err-00:=AF200115 - Signing failed"
        );
        assert_eq!(
            decision_wire(
                Decision::Signed(
                    firmica_protocol::signing::SignResponse::new(&[255], &[1]).unwrap()
                ),
                v4
            ),
            "_w==|AQ=="
        );
    }
    #[test]
    fn session_authentication_uses_exact_fields() {
        let request =
            ProtocolRequest::parse("afirma://websocket?v=4&ports=49152&idsession=0123456789abcdef")
                .unwrap();
        let state = Session {
            bootstrap: WebSocketBootstrap::from_request(&request).unwrap(),
            used: false,
            result: None,
        };
        for text in [
            "echo=-idsession=0123456789abcdef@EOF",
            "getresult?idsession=0123456789abcdef",
            "afirma://sign?idsession=0123456789abcdef&dat=YWJj",
        ] {
            assert!(state.authenticated(text));
        }
        for text in [
            "echo=garbageidsession=0123456789abcdef@EOF",
            "afirma://sign?dat=idsession=0123456789abcdef",
            "afirma://sign?idsession=0123456789abcdef&idsession=attacker",
            "getresult?idsession=0123456789abcdefsuffix",
            "getresult?idsession=wrong",
        ] {
            assert!(!state.authenticated(text));
        }
    }
}
