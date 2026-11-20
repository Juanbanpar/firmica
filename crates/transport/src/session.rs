use crate::Decision;
use firmica_protocol::{parse_query, WebSocketBootstrap};
use tokio::sync::oneshot;

/// One bootstrap permits one reviewed operation, including across reconnects.
pub(super) struct Session {
    pub(super) bootstrap: WebSocketBootstrap,
    pub(super) used: bool,
    pub(super) result: Option<oneshot::Receiver<Decision>>,
}

impl Session {
    pub(super) fn new(bootstrap: WebSocketBootstrap) -> Self {
        Self {
            bootstrap,
            used: false,
            result: None,
        }
    }

    pub(super) fn authenticated(&self, message: &str) -> bool {
        let query = if let Some(value) = message
            .strip_prefix("echo=-idsession=")
            .and_then(|v| v.strip_suffix("@EOF"))
        {
            return value == self.bootstrap.session();
        } else if let Some(query) = message.strip_prefix("getresult?") {
            query
        } else if let Some((_, query)) = message.split_once('?') {
            query
        } else {
            return false;
        };
        parse_query(query)
            .ok()
            .and_then(|p| p.get("idsession").cloned())
            .as_deref()
            == Some(self.bootstrap.session())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firmica_protocol::ProtocolRequest;

    #[test]
    fn session_authentication_uses_exact_fields() {
        let request =
            ProtocolRequest::parse("afirma://websocket?v=4&ports=49152&idsession=0123456789abcdef")
                .unwrap();
        let state = Session::new(WebSocketBootstrap::from_request(&request).unwrap());
        for text in [
            "echo=-idsession=0123456789abcdef@EOF",
            "getresult?idsession=0123456789abcdef",
            "afirma://sign?idsession=0123456789abcdef&dat=YWJj",
        ] {
            assert!(state.authenticated(text));
        }
        for text in [
            "echo=garbageidsession=0123456789abcdef@EOF",
            "afirma://sign?dat=idsession=0123456789abcdef",
            "afirma://sign?idsession=0123456789abcdef&idsession=attacker",
            "getresult?idsession=0123456789abcdefsuffix",
            "getresult?idsession=wrong",
        ] {
            assert!(!state.authenticated(text));
        }
    }
}
