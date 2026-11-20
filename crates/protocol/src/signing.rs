//! Restricted inline signing requests and the unencrypted local WebSocket result.
//!
//! The wire format follows AutoScript 1.10.1 at clienteafirma revision
//! `0d7f3cf01fb65d2be5b245622d2c8f490f36e718`. Decoding is not consent.

mod properties;
mod response;

use crate::{Operation, ProtocolRequest};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine,
};
use firmica_signing::{format::Format, limits::MAX_CONTENT_BYTES, SignatureAlgorithm};
use properties::{decode_format, properties};
use thiserror::Error;

pub use response::{SignResponse, MAX_SIGNATURE_BYTES, MAX_SIGN_RESPONSE_BYTES};

/// A decoded document and fixed signing choices. No paths, URLs or credentials.
/// No Debug implementation: document contents must not enter diagnostics.
pub struct SignRequest {
    document: Vec<u8>,
    algorithm: SignatureAlgorithm,
    format: Format,
}

impl SignRequest {
    /// Accepts protocol 4.x `sign`, inline Base64, SHA-256 RSA/P-256 and the
    /// documented CAdES/PAdES/XAdES format choices. CAdES defaults to detached;
    /// XAdES defaults to enveloping, matching the pinned upstream signer.
    /// Unknown fields/properties, sticky certificates, stores other than PKCS12, prehashes,
    /// policies, remote data and other operations are rejected, never ignored.
    /// Session authentication remains the transport's responsibility.
    pub fn decode(request: &ProtocolRequest) -> Result<Self, RequestError> {
        if request.operation != Operation::Sign || request.version.major != 4 {
            return Err(RequestError::Unsupported);
        }
        for key in request.parameters.keys() {
            if !matches!(
                key.as_str(),
                "op" | "idsession"
                    | "ver"
                    | "format"
                    | "algorithm"
                    | "dat"
                    | "properties"
                    | "ksb64"
                    | "sticky"
                    | "resetsticky"
                    | "appname"
            ) {
                return Err(RequestError::Unsupported);
            }
        }
        if request.parameter("op").is_some_and(|value| value != "sign")
            || request
                .parameter("sticky")
                .is_some_and(|value| value != "false")
            || request
                .parameter("resetsticky")
                .is_some_and(|value| !matches!(value, "true" | "false"))
        {
            return Err(RequestError::Unsupported);
        }
        if let Some(encoded) = request.parameter("ksb64") {
            if encoded.len() > 64 {
                return Err(RequestError::Invalid);
            }
            if decode(encoded)? != b"PKCS12" {
                return Err(RequestError::Unsupported);
            }
        }
        let algorithm = match request.parameter("algorithm") {
            Some("SHA256withRSA") => SignatureAlgorithm::RsaPkcs1v15Sha256,
            Some("SHA256withECDSA") => SignatureAlgorithm::EcdsaP256Sha256,
            _ => return Err(RequestError::Unsupported),
        };
        let format = decode_format(
            request.parameter("format"),
            properties(request.parameter("properties"))?,
        )?;
        let document = decode(request.parameter("dat").ok_or(RequestError::Invalid)?)?;
        if document.len() > MAX_CONTENT_BYTES {
            return Err(RequestError::Invalid);
        }
        Ok(Self {
            document,
            algorithm,
            format,
        })
    }

    /// Signing algorithm fixed by the browser request.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
    /// Format, placement and appearance fixed by the request; decoding is not consent.
    pub fn format(&self) -> &Format {
        &self.format
    }
    /// Exact inline document, retained for a retry after an incorrect password.
    pub fn document(&self) -> &[u8] {
        &self.document
    }
    /// Consumes the request, moving its document into the frozen approval workflow.
    pub fn into_document(self) -> Vec<u8> {
        self.document
    }
}

fn decode(value: &str) -> Result<Vec<u8>, RequestError> {
    URL_SAFE
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| RequestError::Invalid)
}

/// Static failures contain no document, parameter or origin strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum RequestError {
    /// The request asks for behavior outside the implemented signing contract.
    #[error("unsupported signing request")]
    Unsupported,
    /// Required data is missing or not canonical Base64/UTF-8.
    #[error("invalid signing request")]
    Invalid,
}

#[cfg(test)]
mod tests;
