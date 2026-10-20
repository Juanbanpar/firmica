//! Restricted inline signing requests and the unencrypted local WebSocket result.
//!
//! The wire format follows AutoScript 1.10.1 at clienteafirma revision
//! `0d7f3cf01fb65d2be5b245622d2c8f490f36e718`. Decoding is not consent.

use crate::{Operation, ProtocolRequest};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine,
};
use firmica_cades::ContentMode;
use firmica_signing::format::{Appearance, Format, PdfOptions, XmlMode};
use firmica_signing::SignatureAlgorithm;
use std::collections::BTreeMap;
use thiserror::Error;

/// Maximum response signature, including base64 XML content and certificates (26 MiB).
pub const MAX_SIGNATURE_BYTES: usize = 26 * 1024 * 1024;
/// Maximum encoded certificate-plus-signature WebSocket response size.
pub const MAX_SIGN_RESPONSE_BYTES: usize =
    (64_usize * 1024).div_ceil(3) * 4 + 1 + MAX_SIGNATURE_BYTES.div_ceil(3) * 4;

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
        if document.len() > firmica_cades::MAX_CONTENT_BYTES {
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

fn properties(encoded: Option<&str>) -> Result<BTreeMap<String, String>, RequestError> {
    let mut properties = BTreeMap::new();
    if let Some(encoded) = encoded {
        if encoded.len() > 4096 {
            return Err(RequestError::Invalid);
        }
        let bytes = decode(encoded)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| RequestError::Invalid)?;
        for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
            let (key, value) = line.split_once('=').ok_or(RequestError::Unsupported)?;
            // Java Properties escapes/continuations are outside this bounded
            // subset; interpreting them literally would change requested text.
            if key.contains('\\') || value.contains('\\') {
                return Err(RequestError::Unsupported);
            }
            if properties
                .insert(key.to_owned(), value.to_owned())
                .is_some()
            {
                return Err(RequestError::Unsupported);
            }
        }
    }
    Ok(properties)
}

fn decode_format(
    name: Option<&str>,
    mut properties: BTreeMap<String, String>,
) -> Result<Format, RequestError> {
    let format = match name {
        Some("CAdES") => {
            let mode = match properties.remove("mode") {
                None => ContentMode::Detached,
                Some(mode) if mode.eq_ignore_ascii_case("explicit") => ContentMode::Detached,
                Some(mode) if mode.eq_ignore_ascii_case("implicit") => ContentMode::Attached,
                _ => return Err(RequestError::Unsupported),
            };
            Format::Cades(mode)
        }
        Some("PAdES") => {
            let appearance = if properties.contains_key("signaturePage") {
                let page = properties
                    .remove("signaturePage")
                    .unwrap()
                    .parse::<u32>()
                    .map_err(|_| RequestError::Invalid)?;
                if page == 0 {
                    return Err(RequestError::Unsupported);
                }
                let mut rectangle = [0.; 4];
                for (coordinate, name) in rectangle.iter_mut().zip([
                    "signaturePositionOnPageLowerLeftX",
                    "signaturePositionOnPageLowerLeftY",
                    "signaturePositionOnPageUpperRightX",
                    "signaturePositionOnPageUpperRightY",
                ]) {
                    *coordinate = properties
                        .remove(name)
                        .ok_or(RequestError::Unsupported)?
                        .parse::<f32>()
                        .map_err(|_| RequestError::Invalid)?;
                    if !coordinate.is_finite() {
                        return Err(RequestError::Invalid);
                    }
                }
                let text = properties
                    .remove("layer2Text")
                    .ok_or(RequestError::Unsupported)?;
                if text.is_empty()
                    || text.len() > 120
                    || !text.bytes().all(|b| (32..=126).contains(&b))
                    || rectangle[0] >= rectangle[2]
                    || rectangle[1] >= rectangle[3]
                {
                    return Err(RequestError::Unsupported);
                }
                Some(Appearance {
                    page,
                    rectangle,
                    text,
                })
            } else {
                None
            };
            Format::Pades(PdfOptions { appearance })
        }
        Some(name @ ("XAdES" | "XAdES Enveloped" | "XAdES Enveloping" | "XAdES Detached")) => {
            let placement = properties.remove("format");
            if name != "XAdES" && placement.as_ref().is_some_and(|value| value != name) {
                return Err(RequestError::Unsupported);
            }
            let placement = placement.as_deref().unwrap_or(if name == "XAdES" {
                "XAdES Enveloping"
            } else {
                name
            });
            let mode = match placement {
                "XAdES Enveloped" => XmlMode::Enveloped,
                "XAdES Enveloping" => XmlMode::Enveloping,
                "XAdES Detached" => XmlMode::Detached,
                _ => return Err(RequestError::Unsupported),
            };
            // Explicit XML mode can request caller-provided digests upstream.
            if properties
                .remove("mode")
                .is_some_and(|m| !m.eq_ignore_ascii_case("implicit"))
            {
                return Err(RequestError::Unsupported);
            }
            Format::Xades(mode)
        }
        _ => return Err(RequestError::Unsupported),
    };
    if !properties.is_empty() {
        return Err(RequestError::Unsupported);
    }
    Ok(format)
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
    /// Rejects empty or oversized output. The CMS limit covers a 16 MiB attached
    /// document, 32 worker certificates and signature without unbounded output.
    /// This encodes bytes; it does not validate CMS or authenticate the certificate.
    pub fn new(certificate: &[u8], signature: &[u8]) -> Result<Self, RequestError> {
        if certificate.is_empty()
            || certificate.len() > 64 * 1024
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_format_specific_placement_and_pdf_appearance_without_ignoring_options() {
        for (name, property, expected) in [
            ("PAdES", "", Format::Pades(PdfOptions::default())),
            ("XAdES", "", Format::Xades(XmlMode::Enveloping)),
            (
                "XAdES",
                "format=XAdES Enveloped",
                Format::Xades(XmlMode::Enveloped),
            ),
            (
                "XAdES Detached",
                "mode=implicit",
                Format::Xades(XmlMode::Detached),
            ),
        ] {
            let mut request = request("");
            request.parameters.insert("format".into(), name.into());
            request
                .parameters
                .insert("properties".into(), URL_SAFE.encode(property));
            assert_eq!(SignRequest::decode(&request).unwrap().format(), &expected);
        }
        let properties="signaturePage=1\nsignaturePositionOnPageLowerLeftX=40\nsignaturePositionOnPageLowerLeftY=30\nsignaturePositionOnPageUpperRightX=400\nsignaturePositionOnPageUpperRightY=70\nlayer2Text=Reviewed label";
        let mut req = request("");
        req.parameters.insert("format".into(), "PAdES".into());
        req.parameters
            .insert("properties".into(), URL_SAFE.encode(properties));
        assert_eq!(
            SignRequest::decode(&req).unwrap().format(),
            &Format::Pades(PdfOptions {
                appearance: Some(Appearance {
                    page: 1,
                    rectangle: [40., 30., 400., 70.],
                    text: "Reviewed label".into()
                })
            })
        );
        for (name, properties) in [
            ("PAdES", "signaturePage=1"),
            ("PAdES", "signaturePage=-1"),
            ("PAdES", "mode=explicit"),
            ("PAdES", "policyIdentifier=urn:test"),
            ("XAdES", "format=XAdES Externally Detached"),
            ("XAdES", "mode=explicit"),
            ("XAdES Enveloped", "format=XAdES Detached"),
            ("XAdES", "xmlTransforms=any"),
            ("XAdES", "format=XAdES Enveloping\nformat=XAdES Enveloped"),
        ] {
            req.parameters.insert("format".into(), name.into());
            req.parameters
                .insert("properties".into(), URL_SAFE.encode(properties));
            assert!(SignRequest::decode(&req).is_err(), "{name}: {properties}");
        }
    }
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
            let parsed = SignRequest::decode(&request(&format!(
                "&op=sign&sticky=false&ksb64=UEtDUzEy&properties={}",
                URL_SAFE.encode(properties)
            )))
            .unwrap();
            assert_eq!(parsed.algorithm(), SignatureAlgorithm::RsaPkcs1v15Sha256);
            assert_eq!(parsed.format(), &Format::Cades(expected));
            assert_eq!(parsed.into_document(), [0, 255]);
        }
        let mut ec = request("");
        ec.parameters
            .insert("algorithm".into(), "SHA256withECDSA".into());
        assert_eq!(
            SignRequest::decode(&ec).unwrap().algorithm(),
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
            assert!(SignRequest::decode(&request(extra)).is_err());
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
            assert!(SignRequest::decode(&request(&format!(
                "&properties={}",
                URL_SAFE.encode(value)
            )))
            .is_err());
        }
        for (field, value) in [
            ("dat", "https://example.invalid/document"),
            ("dat", "AP9="),
            ("dat", "AP8"),
            ("format", "PAdEStri"),
            ("algorithm", "SHA1withRSA"),
            ("properties", "_w=="),
        ] {
            let mut parsed = request("");
            parsed.parameters.insert(field.into(), value.into());
            assert!(SignRequest::decode(&parsed).is_err());
        }
        let mut parsed = request("");
        parsed.parameters.remove("dat");
        assert!(SignRequest::decode(&parsed).is_err());
        parsed = request("");
        parsed.version.major = 3;
        assert!(SignRequest::decode(&parsed).is_err());
    }
    #[test]
    fn response_is_url_safe_and_redacted() {
        let response = SignResponse::new(&[255], &[0, 255]).unwrap();
        assert_eq!(format!("{response:?}"), "SignResponse { .. }");
        assert_eq!(response.into_wire(), "_w==|AP8=");
        assert!(SignResponse::new(&[], &[1]).is_err());
        assert!(SignResponse::new(&[1], &vec![0; MAX_SIGNATURE_BYTES + 1]).is_err());
    }

    #[test]
    fn decoded_document_limit_handles_base64_rounding() {
        // One byte over the document limit has the same encoded length as the limit.
        let encoded = URL_SAFE.encode(vec![0; firmica_cades::MAX_CONTENT_BYTES + 1]);
        assert_eq!(encoded.len(), crate::MAX_INLINE_BASE64_BYTES);
        let uri = format!("afirma://sign?ver=4&format=CAdES&algorithm=SHA256withRSA&dat={encoded}");
        let request = ProtocolRequest::parse_websocket(&uri).unwrap();
        assert!(matches!(
            SignRequest::decode(&request),
            Err(RequestError::Invalid)
        ));
    }

    #[test]
    fn response_bound_includes_both_base64_fields_and_separator() {
        let response =
            SignResponse::new(&vec![0; 64 * 1024], &vec![0; MAX_SIGNATURE_BYTES]).unwrap();
        assert_eq!(response.into_wire().len(), MAX_SIGN_RESPONSE_BYTES);
    }
}
