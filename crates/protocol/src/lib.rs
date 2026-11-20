//! Bounded AutoFirma URI envelopes. Parsing does not authorize or execute an operation.
//!
//! Behaviour is source-derived, not a declaration of AutoFirma interoperability.

mod bootstrap;
mod envelope;
mod operation;
pub mod signing;

pub use bootstrap::WebSocketBootstrap;
pub use envelope::{
    parse_query, ParseError, ProtocolRequest, MAX_INLINE_BASE64_BYTES, MAX_URI_BYTES,
    MAX_WEBSOCKET_REQUEST_BYTES,
};
pub use operation::{Operation, ProtocolVersion};

#[cfg(test)]
mod tests;
