//! Shared parser entry points for the checked-in corpus and the LibFuzzer targets.
use base64::{engine::general_purpose::URL_SAFE, Engine};
use firmica_protocol::{parse_query, signing::SignRequest, ProtocolRequest};

const MAX_INPUT: usize = 64 * 1024;

fn text(input: &[u8]) -> Option<&str> {
    if input.len() > MAX_INPUT {
        return None;
    }
    std::str::from_utf8(input).ok()
}

/// Parses a native invocation or an encoded query.
pub fn uri_query(input: &[u8]) -> bool {
    text(input)
        .is_some_and(|input| ProtocolRequest::parse(input).is_ok() || parse_query(input).is_ok())
}

/// Runs the Java properties decoder and each signing format's property validation.
pub fn signing_properties(input: &[u8]) -> bool {
    if input.len() > 4096 {
        return false;
    }
    let properties = URL_SAFE.encode(input);
    let mut accepted = false;
    for format in ["CAdES", "PAdES", "XAdES"] {
        let uri = format!(
            "afirma://sign?ver=4&format={format}&algorithm=SHA256withRSA&dat=AA==&properties={properties}"
        );
        if let Ok(request) = ProtocolRequest::parse(&uri) {
            accepted |= SignRequest::decode(&request).is_ok();
        }
    }
    accepted
}

/// Parses a WebSocket text message using a synthetic session.
pub fn websocket(input: &[u8]) -> bool {
    text(input).is_some_and(firmica_transport::fuzzing::authenticates_message)
}

/// Decodes a worker IPC frame in memory.
pub fn worker_ipc(input: &[u8]) -> bool {
    firmica_key_worker::fuzzing::accepts_frame(input)
}

/// Checks the structure of a PDF before signing.
pub fn pdf_preflight(input: &[u8]) -> bool {
    input.len() <= MAX_INPUT && firmica_pades::preflight(input, &Default::default()).is_ok()
}

/// Checks enveloped XML input before signing.
pub fn xml_preflight(input: &[u8]) -> bool {
    input.len() <= MAX_INPUT
        && firmica_xades::preflight(input, firmica_xades::XmlMode::Enveloped).is_ok()
}

#[cfg(test)]
mod tests;
