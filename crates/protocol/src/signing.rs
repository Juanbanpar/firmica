//! Restricted, inline CAdES requests and the unencrypted local WebSocket result.
//!
//! The wire format follows AutoScript 1.10.1 at clienteafirma revision
//! `0d7f3cf01fb65d2be5b245622d2c8f490f36e718`. Decoding is not consent.

use crate::{Operation, ProtocolRequest};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine,
};
use firmica_cades::ContentMode;
use firmica_signing::SignatureAlgorithm;
use thiserror::Error;

/// A decoded document and fixed signing choices. No paths, URLs or credentials.
/// No Debug implementation: document contents must not enter diagnostics.
pub struct CadesRequest {
    document: Vec<u8>,
    algorithm: SignatureAlgorithm,
    mode: ContentMode,
}

impl CadesRequest {
    /// Accepts protocol 4.x `sign`, inline Base64, SHA-256 RSA/P-256 and
    /// `mode=explicit` (detached, the upstream default) or `mode=implicit`.
    /// Unknown fields/properties, sticky certificates, stores other than PKCS12, prehashes,
    /// policies, remote data and other operations are rejected, never ignored.
    /// Session authentication remains the transport's responsibility.
    pub fn decode(request: &ProtocolRequest) -> Result<Self, RequestError> {
        if request.operation != Operation::Sign
            || request.version.major != 4
            || request.parameter("format") != Some("CAdES")
        {
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
        let mut mode = ContentMode::Detached;
        if let Some(encoded) = request.parameter("properties") {
            if encoded.len() > 4096 {
                return Err(RequestError::Invalid);
            }
            let bytes = decode(encoded)?;
            let properties = std::str::from_utf8(&bytes).map_err(|_| RequestError::Invalid)?;
            let mut seen = false;
            for line in properties
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                if seen {
                    return Err(RequestError::Unsupported);
                }
                let value = line
                    .strip_prefix("mode=")
                    .ok_or(RequestError::Unsupported)?;
                mode = if value.eq_ignore_ascii_case("explicit") {
                    ContentMode::Detached
                } else if value.eq_ignore_ascii_case("implicit") {
                    ContentMode::Attached
                } else {
                    return Err(RequestError::Unsupported);
                };
                seen = true;
            }
        }
        let document = decode(request.parameter("dat").ok_or(RequestError::Invalid)?)?;
        Ok(Self {
            document,
            algorithm,
            mode,
        })
    }

    /// Signing algorithm fixed by the browser request.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
    /// Whether the exact inline document is embedded in the CMS result.
    pub fn mode(&self) -> ContentMode {
        self.mode
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

/// A bounded response: URL-safe Base64 certificate, `|`, Base64 CMS signature.
/// Construct only after explicit consent, output verification and key cleanup.
/// Debug deliberately omits the response contents.
#[derive(Eq, PartialEq)]
pub struct SignResponse(String);

impl SignResponse {
    /// Rejects empty or oversized output. The 3 MiB CMS limit covers the bounded
    /// inline document, 32 worker certificates and signature without unbounded IPC.
    /// This encodes bytes; it does not validate CMS or authenticate the certificate.
    pub fn new(certificate: &[u8], signature: &[u8]) -> Result<Self, RequestError> {
        if certificate.is_empty()
            || certificate.len() > 64 * 1024
            || signature.is_empty()
            || signature.len() > 3 * 1024 * 1024
        {
            return Err(RequestError::Invalid);
        }
        Ok(Self(format!(
            "{}|{}",
            URL_SAFE.encode(certificate),
            URL_SAFE.encode(signature)
        )))
    }
    /// Consumes the result for delivery over its authenticated local session.
    pub fn into_wire(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for SignResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignResponse").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(extra: &str) -> ProtocolRequest {
        ProtocolRequest::parse(&format!(
            "afirma://sign?ver=4&format=CAdES&algorithm=SHA256withRSA&dat=AP8%3D{extra}"
        ))
        .unwrap()
    }
    #[test]
    fn decodes_binary_data_and_fixed_choices() {
        for (properties, expected) in [
            ("", ContentMode::Detached),
            ("mode=explicit", ContentMode::Detached),
            ("mode=implicit", ContentMode::Attached),
        ] {
            let parsed = CadesRequest::decode(&request(&format!(
                "&op=sign&sticky=false&ksb64=UEtDUzEy&properties={}",
                URL_SAFE.encode(properties)
            )))
            .unwrap();
            assert_eq!(parsed.algorithm(), SignatureAlgorithm::RsaPkcs1v15Sha256);
            assert_eq!(parsed.mode(), expected);
            assert_eq!(parsed.into_document(), [0, 255]);
        }
        let mut ec = request("");
        ec.parameters
            .insert("algorithm".into(), "SHA256withECDSA".into());
        assert_eq!(
            CadesRequest::decode(&ec).unwrap().algorithm(),
            SignatureAlgorithm::EcdsaP256Sha256
        );
    }
    #[test]
    fn refuses_unimplemented_semantics_and_malformed_data() {
        for extra in [
            "&sticky=true",
            "&ksb64=TU9aX1VOSQ==",
            "&fileid=123",
            "&key=secret",
            "&op=cosign",
            "&unknown=x",
            "&servicetimeout=1",
        ] {
            assert!(CadesRequest::decode(&request(extra)).is_err());
        }
        for value in [
            "mode=implicit\nmode=explicit",
            "mode=explicit\npolicyIdentifier=1.2.3",
            "precalculatedHashAlgorithm=SHA-256",
            "mode=other",
            "mode:explicit",
            "mode=explicit\\",
            "mode=explicit\0",
        ] {
            assert!(CadesRequest::decode(&request(&format!(
                "&properties={}",
                URL_SAFE.encode(value)
            )))
            .is_err());
        }
        for (field, value) in [
            ("dat", "https://example.invalid/document"),
            ("dat", "AP9="),
            ("dat", "AP8"),
            ("format", "PAdES"),
            ("algorithm", "SHA1withRSA"),
            ("properties", "_w=="),
        ] {
            let mut parsed = request("");
            parsed.parameters.insert(field.into(), value.into());
            assert!(CadesRequest::decode(&parsed).is_err());
        }
        let mut parsed = request("");
        parsed.parameters.remove("dat");
        assert!(CadesRequest::decode(&parsed).is_err());
        parsed = request("");
        parsed.version.major = 3;
        assert!(CadesRequest::decode(&parsed).is_err());
    }
    #[test]
    fn response_is_url_safe_and_redacted() {
        let response = SignResponse::new(&[255], &[0, 255]).unwrap();
        assert_eq!(format!("{response:?}"), "SignResponse { .. }");
        assert_eq!(response.into_wire(), "_w==|AP8=");
        assert!(SignResponse::new(&[], &[1]).is_err());
        assert!(SignResponse::new(&[1], &vec![0; 3 * 1024 * 1024 + 1]).is_err());
    }
}
