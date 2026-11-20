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
pub use wire::ProtocolError;

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
