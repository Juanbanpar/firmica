use crate::Decision;
use firmica_protocol::ProtocolVersion;

/// Protocol-level errors used by the prototype. Codes come from the pinned upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Cancelled,
    Unsupported,
    Session,
    Parameters,
    SigningFailed,
}

impl ProtocolError {
    pub fn wire(self, version: ProtocolVersion) -> String {
        let (legacy, code, message) = match self {
            Self::SigningFailed => ("SAF_09", "200115", "Signing failed"),
            Self::Cancelled => ("CANCEL", "500001", "Operation cancelled by user"),
            Self::Unsupported => ("SAF_04", "600002", "Operation not supported"),
            Self::Session => ("SAF_46", "620010", "Invalid WebSocket session"),
            Self::Parameters => ("SAF_03", "620016", "Invalid request parameters"),
        };
        if version >= (ProtocolVersion { major: 4, minor: 1 }) {
            let prefix = if self == Self::Cancelled {
                "err-11:="
            } else {
                "err-00:="
            };
            format!("{prefix}AF{code} - {message}")
        } else if self == Self::Cancelled {
            legacy.into()
        } else {
            format!("{legacy}: {message}")
        }
    }
}

pub(super) fn decision_wire(decision: Decision, version: ProtocolVersion) -> String {
    match decision {
        Decision::Reject => ProtocolError::Cancelled.wire(version),
        Decision::Unsupported => ProtocolError::Unsupported.wire(version),
        Decision::Failed => ProtocolError::SigningFailed.wire(version),
        Decision::InvalidParameters => ProtocolError::Parameters.wire(version),
        Decision::Signed(result) => result.into_wire(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_errors_are_version_specific() {
        let v4 = ProtocolVersion { major: 4, minor: 0 };
        let v41 = ProtocolVersion { major: 4, minor: 1 };
        assert_eq!(ProtocolError::Cancelled.wire(v4), "CANCEL");
        assert_eq!(
            ProtocolError::Unsupported.wire(v4),
            "SAF_04: Operation not supported"
        );
        assert_eq!(
            ProtocolError::Session.wire(v41),
            "err-00:=AF620010 - Invalid WebSocket session"
        );
        assert_eq!(
            ProtocolError::Cancelled.wire(v41),
            "err-11:=AF500001 - Operation cancelled by user"
        );
        assert_eq!(
            decision_wire(Decision::Failed, v4),
            "SAF_09: Signing failed"
        );
        assert_eq!(
            decision_wire(Decision::Failed, v41),
            "err-00:=AF200115 - Signing failed"
        );
        assert_eq!(
            decision_wire(
                Decision::Signed(
                    firmica_protocol::signing::SignResponse::new(&[255], &[1]).unwrap()
                ),
                v4
            ),
            "_w==|AQ=="
        );
    }
}
