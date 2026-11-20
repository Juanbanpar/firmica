use super::*;
use firmica_signing::format::{Appearance, ContentMode, PdfOptions, XmlMode};

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
    let properties = concat!(
        "! Visible signature\r\nsignaturePage : 1\r\n",
        "signaturePositionOnPageLowerLeftX=40\r",
        "signaturePositionOnPageLowerLeftY\t30\n",
        "signaturePositionOnPageUpperRightX=400\n",
        "signaturePositionOnPageUpperRightY=70\n",
        "layer2Text= Reviewed label  "
    );
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
                text: "Reviewed label  ".into()
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
        (
            " # integration defaults\r\n  mode : explicit",
            ContentMode::Detached,
        ),
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
        "mode=explicit\nmode : implicit",
        "=explicit",
        "mode=explicit\\",
        "mode=explicit\0",
    ] {
        assert!(
            SignRequest::decode(&request(&format!("&properties={}", URL_SAFE.encode(value))))
                .is_err()
        );
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
fn distinguishes_malformed_sign_requests_from_unsupported_options() {
    for extra in [
        "&op=cosign",
        "&sticky=maybe",
        "&resetsticky=",
        "&properties=%25",
    ] {
        assert_eq!(
            SignRequest::decode(&request(extra)).err(),
            Some(RequestError::Invalid)
        );
    }
    for field in ["format", "algorithm", "dat"] {
        let mut request = request("");
        request.parameters.remove(field);
        assert_eq!(
            SignRequest::decode(&request).err(),
            Some(RequestError::Invalid)
        );
    }
    assert_eq!(
        SignRequest::decode(&request("&sticky=true")).err(),
        Some(RequestError::Unsupported)
    );
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
    let encoded = URL_SAFE.encode(vec![0; MAX_CONTENT_BYTES + 1]);
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
    let response = SignResponse::new(&vec![0; 64 * 1024], &vec![0; MAX_SIGNATURE_BYTES]).unwrap();
    assert_eq!(response.into_wire().len(), MAX_SIGN_RESPONSE_BYTES);
}
