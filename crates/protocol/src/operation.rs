use crate::ParseError;
use std::{fmt, str::FromStr};

/// AutoFirma protocol version, independent of application and AutoScript versions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    /// Whether two versions share the compatibility-breaking major identifier.
    pub fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }
}

impl FromStr for ProtocolVersion {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        fn number(value: &str) -> Result<u16, ParseError> {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::Version);
            }
            value.parse().map_err(|_| ParseError::Version)
        }
        let (major, minor) = value.split_once('.').unwrap_or((value, "0"));
        let version = Self {
            major: number(major)?,
            minor: number(minor)?,
        };
        if version.major > 4 || (version.minor != 0 && !(version.major == 4 && version.minor == 1))
        {
            return Err(ParseError::Version);
        }
        Ok(version)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.major)?;
        if self.minor != 0 {
            write!(f, ".{}", self.minor)?;
        }
        Ok(())
    }
}

/// Operation names dispatched by the inspected desktop launcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Sign,
    Cosign,
    Countersign,
    SignAndSave,
    SelectCert,
    Batch,
    Load,
    Save,
    WebSocket,
    Service,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Cosign => "cosign",
            Self::Countersign => "countersign",
            Self::SignAndSave => "signandsave",
            Self::SelectCert => "selectcert",
            Self::Batch => "batch",
            Self::Load => "load",
            Self::Save => "save",
            Self::WebSocket => "websocket",
            Self::Service => "service",
        }
    }
}

impl FromStr for Operation {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sign" => Ok(Self::Sign),
            "cosign" => Ok(Self::Cosign),
            "countersign" => Ok(Self::Countersign),
            "signandsave" => Ok(Self::SignAndSave),
            "selectcert" => Ok(Self::SelectCert),
            "batch" => Ok(Self::Batch),
            "load" => Ok(Self::Load),
            "save" => Ok(Self::Save),
            "websocket" => Ok(Self::WebSocket),
            "service" => Ok(Self::Service),
            _ => Err(ParseError::Operation),
        }
    }
}
