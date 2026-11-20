use crate::{Operation, ParseError, ProtocolRequest, ProtocolVersion};
use std::fmt;

/// Validated channel bootstrap for the restricted protocol-4.x WSS prototype.
/// Debug output never includes the session identifier.
#[derive(Clone)]
pub struct WebSocketBootstrap {
    pub version: ProtocolVersion,
    pub ports: Vec<u16>,
    session: String,
    pub asynchronous: bool,
}

impl fmt::Debug for WebSocketBootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketBootstrap")
            .field("version", &self.version)
            .field("ports", &self.ports)
            .field("asynchronous", &self.asynchronous)
            .finish_non_exhaustive()
    }
}

impl WebSocketBootstrap {
    /// Requires protocol 4/4.1, an ASCII alphanumeric session and 1–3 unprivileged ports.
    pub fn from_request(request: &ProtocolRequest) -> Result<Self, ParseError> {
        if request.operation != Operation::WebSocket || request.version.major != 4 {
            return Err(ParseError::Version);
        }
        let session = request.parameter("idsession").ok_or(ParseError::Session)?;
        if !(16..=128).contains(&session.len())
            || !session.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(ParseError::Session);
        }
        let ports: Vec<u16> = request
            .parameter("ports")
            .ok_or(ParseError::Ports)?
            .split(',')
            .map(|v| v.parse().map_err(|_| ParseError::Ports))
            .collect::<Result<_, _>>()?;
        if ports.is_empty() || ports.len() > 3 || ports.iter().any(|p| *p < 1024) {
            return Err(ParseError::Ports);
        }
        let jvc: u16 = request
            .parameter("jvc")
            .unwrap_or("1")
            .parse()
            .map_err(|_| ParseError::Version)?;
        if !(1..=4).contains(&jvc) {
            return Err(ParseError::Version);
        }
        Ok(Self {
            version: request.version,
            ports,
            session: session.to_owned(),
            asynchronous: jvc > 3,
        })
    }

    /// Session secret for exact comparison at the transport boundary.
    pub fn session(&self) -> &str {
        &self.session
    }
}
