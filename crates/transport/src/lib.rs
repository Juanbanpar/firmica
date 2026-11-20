//! Bounded local WSS service. The application supplies explicitly approved signing
//! results or errors; the transport never accesses documents or private keys.

mod connection;
mod server;
mod session;
mod tls;
mod wire;

use firmica_protocol::ProtocolRequest;
use std::io;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio_rustls::rustls;
use tokio_tungstenite::tungstenite;

pub use server::Server;
pub use tls::{load_tls, validate_origin};
pub use tokio_rustls::rustls::ServerConfig;
pub use wire::ProtocolError;

/// In-memory protocol boundary for the repository fuzz targets.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use super::session::Session;
    use firmica_protocol::{ProtocolRequest, WebSocketBootstrap};
    use std::sync::LazyLock;

    /// Exercises control-message authentication and parsing of document-bearing messages.
    pub fn authenticates_message(message: &str) -> bool {
        static BOOTSTRAP: LazyLock<WebSocketBootstrap> = LazyLock::new(|| {
            let request = ProtocolRequest::parse(
                "afirma://websocket?v=4&jvc=4&ports=49152&idsession=syntheticSession",
            )
            .unwrap();
            WebSocketBootstrap::from_request(&request).unwrap()
        });
        let session = Session::new(BOOTSTRAP.clone());
        let parsed = message
            .starts_with("afirma://")
            .then(|| ProtocolRequest::parse_websocket(message));
        match parsed {
            Some(Ok(request)) => {
                request.parameter("idsession") == Some(session.bootstrap.session())
            }
            _ => session.authenticated(message),
        }
    }
}

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
    /// Exact allowed Origin header of the connection carrying this authenticated
    /// request. This identifies a browser origin, not the remote operator.
    pub browser_origin: String,
    pub reply: oneshot::Sender<Decision>,
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
    #[error("at least one exact HTTP(S) browser origin is required")]
    Origin,
}

#[cfg(test)]
mod transfer_tests;

#[cfg(all(test, target_os = "linux"))]
mod browser_tests;
