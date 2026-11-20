use super::*;
use firmica_signing::limits::MAX_CONTENT_BYTES;

#[test]
fn websocket_documents_have_separate_size_and_metadata_limits() {
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    let document = vec![0xff; MAX_CONTENT_BYTES];
    let encoded = URL_SAFE.encode(&document);
    let uri = format!("afirma://sign?ver=4&format=CAdES&algorithm=SHA256withRSA&dat={encoded}");
    assert_eq!(ProtocolRequest::parse(&uri), Err(ParseError::TooLarge));
    assert_eq!(
        parse_query(uri.split_once('?').unwrap().1),
        Err(ParseError::TooLarge)
    );
    let request = ProtocolRequest::parse_websocket(&uri).unwrap();
    assert_eq!(
        signing::SignRequest::decode(&request).unwrap().document(),
        document
    );
    assert_eq!(
        ProtocolRequest::parse_websocket(&uri.replacen("sign?", "save?", 1)),
        Err(ParseError::TooLarge)
    );
    assert_eq!(
        ProtocolRequest::parse_websocket(&format!("{uri}&unknown={}", "x".repeat(MAX_URI_BYTES))),
        Err(ParseError::TooLarge)
    );
    assert_eq!(
        ProtocolRequest::parse_websocket(&format!("{uri}&idsession=first&idsession=second")),
        Err(ParseError::Duplicate)
    );
    assert_eq!(
        ProtocolRequest::parse_websocket(&format!("{uri}&dat=AAAA")),
        Err(ParseError::Duplicate)
    );
    assert_eq!(
        ProtocolRequest::parse_websocket(&format!("{uri}%GG")),
        Err(ParseError::Encoding)
    );
}

#[test]
fn oversized_base64_is_rejected_before_document_decoding() {
    let uri = format!(
        "afirma://sign?dat={}",
        "A".repeat(MAX_INLINE_BASE64_BYTES + 4)
    );
    assert_eq!(
        ProtocolRequest::parse_websocket(&uri),
        Err(ParseError::TooLarge)
    );
    assert_eq!(
        ProtocolRequest::parse_websocket(&"x".repeat(MAX_WEBSOCKET_REQUEST_BYTES + 1)),
        Err(ParseError::TooLarge)
    );
    // Non-sign operations retain the whole-URI limit, including their prefix.
    assert_eq!(
        ProtocolRequest::parse_websocket(&format!(
            "afirma://save?dat={}",
            "A".repeat(MAX_URI_BYTES - "dat=".len())
        )),
        Err(ParseError::TooLarge)
    );
}
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
    let req =
        ProtocolRequest::parse("afirma://sign?dat=secret&key=password&idsession=1234567890123456")
            .unwrap();
    let text = format!("{req:?}");
    for secret in ["secret", "password", "1234567890123456"] {
        assert!(!text.contains(secret));
    }
}
