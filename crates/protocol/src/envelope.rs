use crate::{Operation, ProtocolVersion};
use firmica_signing::limits::MAX_CONTENT_BYTES;
use percent_encoding::percent_decode_str;
use std::{borrow::Cow, collections::BTreeMap, fmt};
use thiserror::Error;

/// Maximum native invocation, control query, or WebSocket metadata size.
pub const MAX_URI_BYTES: usize = 64 * 1024;
/// Maximum Base64 document size before percent encoding.
pub const MAX_INLINE_BASE64_BYTES: usize = MAX_CONTENT_BYTES.div_ceil(3) * 4;
/// Maximum WebSocket request: one inline document plus bounded URI metadata.
/// Native OS invocations retain [`MAX_URI_BYTES`].
pub const MAX_WEBSOCKET_REQUEST_BYTES: usize = MAX_INLINE_BASE64_BYTES + MAX_URI_BYTES;
const MAX_PARAMETERS: usize = 64;

/// Parsed envelope. Parameter values may contain documents, credentials, or session secrets.
/// `Debug` deliberately omits them. No URLs or paths are dereferenced.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtocolRequest {
    pub operation: Operation,
    pub version: ProtocolVersion,
    pub(super) parameters: BTreeMap<String, String>,
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
        Self::parse_bounded(uri, false)
    }

    /// Parses a WebSocket operation without widening native URI limits.
    /// Only `sign` may exceed 64 KiB; its decoded Base64 `dat` field is bounded
    /// by [`MAX_INLINE_BASE64_BYTES`], and all other encoded fields together by
    /// [`MAX_URI_BYTES`]. Decoded document size/format and session authentication
    /// must still be checked by the application and transport respectively.
    pub fn parse_websocket(uri: &str) -> Result<Self, ParseError> {
        Self::parse_bounded(uri, true)
    }

    fn parse_bounded(uri: &str, websocket: bool) -> Result<Self, ParseError> {
        if uri.len()
            > if websocket {
                MAX_WEBSOCKET_REQUEST_BYTES
            } else {
                MAX_URI_BYTES
            }
        {
            return Err(ParseError::TooLarge);
        }
        if uri.chars().any(char::is_control) || uri.contains('#') {
            return Err(ParseError::Syntax);
        }
        let body = uri.strip_prefix("afirma://").ok_or(ParseError::Scheme)?;
        let (operation, query) = body.split_once('?').ok_or(ParseError::Syntax)?;
        let operation = operation.strip_suffix('/').unwrap_or(operation).parse()?;
        let inline_data = websocket && operation == Operation::Sign;
        if !inline_data && uri.len() > MAX_URI_BYTES {
            return Err(ParseError::TooLarge);
        }
        let parameters = parse_query_bounded(query, inline_data)?;
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

/// Parses a query without interpreting operation-specific fields. Values use form encoding.
pub fn parse_query(query: &str) -> Result<BTreeMap<String, String>, ParseError> {
    parse_query_bounded(query, false)
}

fn parse_query_bounded(
    query: &str,
    inline_data: bool,
) -> Result<BTreeMap<String, String>, ParseError> {
    if query.len()
        > if inline_data {
            MAX_WEBSOCKET_REQUEST_BYTES
        } else {
            MAX_URI_BYTES
        }
    {
        return Err(ParseError::TooLarge);
    }
    let mut parameters = BTreeMap::new();
    if query.is_empty() {
        return Ok(parameters);
    }
    let mut metadata_bytes = 0;
    for (index, pair) in query.split('&').enumerate() {
        if index >= MAX_PARAMETERS {
            return Err(ParseError::TooLarge);
        }
        let (key, value) = pair.split_once('=').ok_or(ParseError::Syntax)?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(ParseError::Syntax);
        }
        if inline_data && key != "dat" {
            metadata_bytes += pair.len() + 1;
            if metadata_bytes > MAX_URI_BYTES {
                return Err(ParseError::TooLarge);
            }
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
        let value = if value.contains('+') {
            Cow::Owned(value.replace('+', " "))
        } else {
            Cow::Borrowed(value)
        };
        let value = percent_decode_str(&value)
            .decode_utf8()
            .map_err(|_| ParseError::Encoding)?
            .into_owned();
        if inline_data && key == "dat" && value.len() > MAX_INLINE_BASE64_BYTES {
            return Err(ParseError::TooLarge);
        }
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
    #[error("request exceeds size limits")]
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
