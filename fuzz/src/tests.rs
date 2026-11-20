use super::*;

#[test]
fn invocation_and_query_corpus() {
    assert!(uri_query(include_bytes!("../corpus/uri_query/invocation")));
    assert!(uri_query(include_bytes!("../corpus/uri_query/query")));
    assert!(!uri_query(include_bytes!("../corpus/uri_query/duplicate")));
}

#[test]
fn signing_property_corpus() {
    assert!(signing_properties(include_bytes!(
        "../corpus/signing_properties/mode"
    )));
    assert!(signing_properties(include_bytes!(
        "../corpus/signing_properties/appearance"
    )));
    assert!(!signing_properties(include_bytes!(
        "../corpus/signing_properties/duplicate"
    )));
}

#[test]
fn websocket_text_corpus() {
    assert!(websocket(include_bytes!("../corpus/websocket/echo")));
    assert!(websocket(include_bytes!("../corpus/websocket/poll")));
    assert!(websocket(include_bytes!("../corpus/websocket/sign")));
    assert!(!websocket(include_bytes!("../corpus/websocket/duplicate")));
}

#[test]
fn worker_ipc_corpus() {
    assert!(worker_ipc(include_bytes!("../corpus/worker_ipc/import")));
    assert!(worker_ipc(include_bytes!("../corpus/worker_ipc/sign")));
    assert!(worker_ipc(include_bytes!("../corpus/worker_ipc/identity")));
    assert!(!worker_ipc(include_bytes!(
        "../corpus/worker_ipc/truncated"
    )));
    assert!(!worker_ipc(include_bytes!("../corpus/worker_ipc/trailing")));
    assert!(!worker_ipc(include_bytes!(
        "../corpus/worker_ipc/oversized"
    )));
}

#[test]
fn pdf_document_corpus() {
    assert!(pdf_preflight(include_bytes!(
        "../corpus/pdf_preflight/document.pdf"
    )));
    assert!(!pdf_preflight(include_bytes!(
        "../corpus/pdf_preflight/incomplete"
    )));
}

#[test]
fn enveloped_xml_corpus() {
    assert!(xml_preflight(include_bytes!(
        "../corpus/xml_preflight/document.xml"
    )));
    assert!(!xml_preflight(include_bytes!(
        "../corpus/xml_preflight/incomplete"
    )));
}
