use crate::Decision;
use firmica_protocol::{parse_query, WebSocketBootstrap};
use tokio::sync::oneshot;

/// One bootstrap permits one reviewed operation, including across reconnects.
pub(super) struct Session {
    pub(super) bootstrap: WebSocketBootstrap,
    pub(super) used: bool,
    pub(super) result: Option<oneshot::Receiver<Decision>>,
    origin: Option<String>,
}

impl Session {
    pub(super) fn new(bootstrap: WebSocketBootstrap) -> Self {
        Self {
            bootstrap,
            used: false,
            result: None,
            origin: None,
        }
    }

    pub(super) fn accept_origin(&mut self, origin: &str) -> bool {
        self.origin.get_or_insert_with(|| origin.to_owned()) == origin
    }

    pub(super) fn authenticated(&self, message: &str) -> bool {
        if let Some(value) = message.strip_prefix("echo=-idsession=") {
            return value.strip_suffix("@EOF") == Some(self.bootstrap.session());
        }
        let Some((operation, query)) = message.split_once('?') else {
            return false;
        };
        parse_query(query).is_ok_and(|fields| {
            (operation != "getresult" || fields.len() == 1)
                && fields.get("idsession").map(String::as_str) == Some(self.bootstrap.session())
        })
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
            "echo=-idsession=wrong?idsession=0123456789abcdef",
            "afirma://sign?dat=idsession=0123456789abcdef",
            "afirma://sign?idsession=0123456789abcdef&idsession=attacker",
            "getresult?idsession=0123456789abcdefsuffix",
            "getresult?idsession=wrong",
            "getresult?idsession=0123456789abcdef&extra=unexpected",
        ] {
            assert!(!state.authenticated(text));
        }
    }
}
