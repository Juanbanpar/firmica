//! Bounded AutoFirma URI envelopes. Parsing does not authorize or execute an operation.
//!
//! Behaviour is source-derived, not a declaration of AutoFirma interoperability.

use percent_encoding::percent_decode_str;
use std::{collections::BTreeMap, fmt, str::FromStr};
use thiserror::Error;

/// Maximum encoded URI size accepted by the feasibility prototype.
pub const MAX_URI_BYTES: usize = 64 * 1024;
const MAX_PARAMETERS: usize = 64;

/// AutoFirma protocol version, independent of application and AutoScript versions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    /// Whether two versions share the compatibility-breaking major identifier.
    pub fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }
}

impl FromStr for ProtocolVersion {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        fn number(value: &str) -> Result<u16, ParseError> {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::Version);
            }
            value.parse().map_err(|_| ParseError::Version)
        }
        let (major, minor) = value.split_once('.').unwrap_or((value, "0"));
        let version = Self {
            major: number(major)?,
            minor: number(minor)?,
        };
        if version.major > 4 || (version.minor != 0 && !(version.major == 4 && version.minor == 1))
        {
            return Err(ParseError::Version);
        }
        Ok(version)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.major)?;
        if self.minor != 0 {
            write!(f, ".{}", self.minor)?;
        }
        Ok(())
    }
}

/// Operation names dispatched by the inspected desktop launcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Sign,
    Cosign,
    Countersign,
    SignAndSave,
    SelectCert,
    Batch,
    Load,
    Save,
    WebSocket,
    Service,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Cosign => "cosign",
            Self::Countersign => "countersign",
            Self::SignAndSave => "signandsave",
            Self::SelectCert => "selectcert",
            Self::Batch => "batch",
            Self::Load => "load",
            Self::Save => "save",
            Self::WebSocket => "websocket",
            Self::Service => "service",
        }
    }
}

impl FromStr for Operation {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sign" => Ok(Self::Sign),
            "cosign" => Ok(Self::Cosign),
            "countersign" => Ok(Self::Countersign),
            "signandsave" => Ok(Self::SignAndSave),
            "selectcert" => Ok(Self::SelectCert),
            "batch" => Ok(Self::Batch),
            "load" => Ok(Self::Load),
            "save" => Ok(Self::Save),
            "websocket" => Ok(Self::WebSocket),
            "service" => Ok(Self::Service),
            _ => Err(ParseError::Operation),
        }
    }
}

/// Parsed envelope. Parameter values may contain documents, credentials, or session secrets.
/// `Debug` deliberately omits them. No URLs or paths are dereferenced.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtocolRequest {
    pub operation: Operation,
    pub version: ProtocolVersion,
    parameters: BTreeMap<String, String>,
}

impl fmt::Debug for ProtocolRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolRequest")
            .field("operation", &self.operation)
            .field("version", &self.version)
            .field("parameter_count", &self.parameters.len())
            .finish()
    }
}

impl ProtocolRequest {
    /// Parses only the invocation envelope; operation-specific validation remains required.
    ///
    /// Rejects malformed escapes, invalid UTF-8, duplicate keys, controls, fragments,
    /// unknown operations/versions and oversized input. Unlike upstream, duplicates do
    /// not overwrite earlier values and malformed versions do not fall back to zero.
    pub fn parse(uri: &str) -> Result<Self, ParseError> {
        if uri.len() > MAX_URI_BYTES {
            return Err(ParseError::TooLarge);
        }
        if uri.chars().any(char::is_control) || uri.contains('#') {
            return Err(ParseError::Syntax);
        }
        let body = uri.strip_prefix("afirma://").ok_or(ParseError::Scheme)?;
        let (operation, query) = body.split_once('?').ok_or(ParseError::Syntax)?;
        let operation = operation.strip_suffix('/').unwrap_or(operation).parse()?;
        let parameters = parse_query(query)?;
        let key = if matches!(operation, Operation::WebSocket | Operation::Service) {
            "v"
        } else {
            "ver"
        };
        let version = parameters
            .get(key)
            .map(|v| v.parse())
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            operation,
            version,
            parameters,
        })
    }

    /// Returns an untrusted decoded value. Do not log it or treat it as user consent.
    pub fn parameter(&self, key: &str) -> Option<&str> {
        self.parameters.get(key).map(String::as_str)
    }
}

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

/// Parses a query without interpreting operation-specific fields. Values use form encoding.
pub fn parse_query(query: &str) -> Result<BTreeMap<String, String>, ParseError> {
    if query.len() > MAX_URI_BYTES {
        return Err(ParseError::TooLarge);
    }
    let mut parameters = BTreeMap::new();
    if query.is_empty() {
        return Ok(parameters);
    }
    for (index, pair) in query.split('&').enumerate() {
        if index >= MAX_PARAMETERS {
            return Err(ParseError::TooLarge);
        }
        let (key, value) = pair.split_once('=').ok_or(ParseError::Syntax)?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(ParseError::Syntax);
        }
        let bytes = value.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'%'
                && (i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit())
            {
                return Err(ParseError::Encoding);
            }
        }
        let value = value.replace('+', " ");
        let value = percent_decode_str(&value)
            .decode_utf8()
            .map_err(|_| ParseError::Encoding)?
            .into_owned();
        // Newlines in Base64-encoded properties are allowed; NUL and other controls are not.
        if value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Err(ParseError::Encoding);
        }
        if parameters.insert(key.to_owned(), value).is_some() {
            return Err(ParseError::Duplicate);
        }
    }
    Ok(parameters)
}

/// Errors are deliberately static: no untrusted values appear in diagnostics.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ParseError {
    #[error("invocation exceeds prototype limits")]
    TooLarge,
    #[error("expected afirma:// scheme")]
    Scheme,
    #[error("invalid invocation syntax")]
    Syntax,
    #[error("invalid parameter encoding")]
    Encoding,
    #[error("duplicate parameter")]
    Duplicate,
    #[error("unsupported operation")]
    Operation,
    #[error("unsupported or malformed protocol version")]
    Version,
    #[error("invalid session identifier")]
    Session,
    #[error("invalid listener ports")]
    Ports,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_source_derived_envelopes() {
        for op in [
            "sign",
            "cosign",
            "countersign",
            "signandsave",
            "selectcert",
            "batch",
            "load",
            "save",
            "websocket",
            "service",
        ] {
            for slash in ["", "/"] {
                let req = ProtocolRequest::parse(&format!(
                    "afirma://{op}{slash}?dat=YWJj%3D&properties=a%2Bb+c%2520"
                ))
                .unwrap();
                assert_eq!(req.operation.as_str(), op);
                assert_eq!(req.parameter("dat"), Some("YWJj="));
                assert_eq!(req.parameter("properties"), Some("a+b c%20"));
            }
        }
    }
    #[test]
    fn separates_protocol_and_javascript_versions() {
        let req = ProtocolRequest::parse(
            "afirma://websocket?v=4&jvc=4&ports=49152,49153&idsession=0123456789abcdef",
        )
        .unwrap();
        let channel = WebSocketBootstrap::from_request(&req).unwrap();
        assert_eq!(channel.version.to_string(), "4");
        assert!(channel.asynchronous);
        assert_eq!(channel.ports, [49152, 49153]);
        assert!(!format!("{channel:?}").contains(channel.session()));
        for v in ["0", "1", "2", "3", "4", "4.1"] {
            let req = ProtocolRequest::parse(&format!("afirma://sign?ver={v}")).unwrap();
            assert_eq!(req.version.to_string(), v);
        }
        assert!("4.1"
            .parse::<ProtocolVersion>()
            .unwrap()
            .is_compatible_with("4".parse().unwrap()));
    }
    #[test]
    fn rejects_ambiguous_and_malformed_input() {
        for uri in [
            "https://sign?dat=a",
            "afirma://sign",
            "afirma://sign/path?dat=a",
            "afirma://sign?dat=%",
            "afirma://sign?dat=%ff",
            "afirma://sign?dat=%00",
            "afirma://sign?dat=a&dat=b",
            "afirma://sign?d%61t=a",
            "afirma://sign?dat=a#x",
            "afirma://sign?dat=a\n",
            "afirma://sign?ver=4.2",
            "afirma://sign?ver=bad",
            "afirma://sign?ver=1.2.3",
            "afirma://sign?ver=+1",
            "afirma://sign?&&",
            "afirma://unknown?",
        ] {
            assert!(ProtocolRequest::parse(uri).is_err(), "accepted {uri}");
        }
        assert_eq!(
            ProtocolRequest::parse(&"a".repeat(MAX_URI_BYTES + 1)),
            Err(ParseError::TooLarge)
        );
        assert!(parse_query(
            &(0..65)
                .map(|i| format!("k{i}=a"))
                .collect::<Vec<_>>()
                .join("&")
        )
        .is_err());
    }
    #[test]
    fn rejects_unsafe_bootstraps() {
        for suffix in [
            "v=3&idsession=0123456789abcdef&ports=49152",
            "v=4&idsession=short&ports=49152",
            "v=4&idsession=0123456789abcdef&ports=80",
            "v=4&idsession=0123456789abcdef&ports=65536",
            "v=4&idsession=0123456789abcde_&ports=49152",
            "v=4&idsession=0123456789abcdef&ports=49152&jvc=5",
        ] {
            let req = ProtocolRequest::parse(&format!("afirma://websocket?{suffix}")).unwrap();
            assert!(WebSocketBootstrap::from_request(&req).is_err());
        }
    }
    #[test]
    fn debug_redacts_sensitive_data() {
        let req = ProtocolRequest::parse(
            "afirma://sign?dat=secret&key=password&idsession=1234567890123456",
        )
        .unwrap();
        let text = format!("{req:?}");
        for secret in ["secret", "password", "1234567890123456"] {
            assert!(!text.contains(secret));
        }
    }
}
