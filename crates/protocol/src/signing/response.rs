use super::RequestError;
use base64::{engine::general_purpose::URL_SAFE, Engine};
use firmica_signing::limits::MAX_CERTIFICATE_BYTES;

/// Maximum response signature, including base64 XML content and certificates (26 MiB).
pub const MAX_SIGNATURE_BYTES: usize = 26 * 1024 * 1024;
/// Maximum encoded certificate-plus-signature WebSocket response size.
pub const MAX_SIGN_RESPONSE_BYTES: usize =
    MAX_CERTIFICATE_BYTES.div_ceil(3) * 4 + 1 + MAX_SIGNATURE_BYTES.div_ceil(3) * 4;

/// A bounded response: URL-safe Base64 certificate, `|`, Base64 signature.
/// Construct only after explicit consent, output verification and key cleanup.
/// Debug deliberately omits the response contents.
#[derive(Eq, PartialEq)]
pub struct SignResponse(String);

impl SignResponse {
    /// Rejects empty or oversized output. The signature limit includes embedded document
    /// content and certificates. This encodes the result without validating its format
    /// or authenticating the certificate.
    pub fn new(certificate: &[u8], signature: &[u8]) -> Result<Self, RequestError> {
        if certificate.is_empty()
            || certificate.len() > MAX_CERTIFICATE_BYTES
            || signature.is_empty()
            || signature.len() > MAX_SIGNATURE_BYTES
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
