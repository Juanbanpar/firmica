use crate::WorkerError;
use std::path::Path;

/// A publicly visible, persistent X.509 certificate reported by a PKCS#11 token.
#[derive(Eq, PartialEq)]
pub struct Pkcs11Certificate {
    /// Object URI scoped to its token, without query attributes or credentials.
    pub uri: String,
    /// Exact bytes reported by the token for this certificate.
    pub der: Vec<u8>,
}

/// An initialized PKCS#11 token and its publicly visible certificates.
#[derive(Eq, PartialEq)]
pub struct Pkcs11Token {
    /// Token URI based on its identity metadata, without a slot ID or credentials.
    pub uri: String,
    /// Persistent public X.509 objects seen without logging in.
    pub certificates: Vec<Pkcs11Certificate>,
}

/// Inspect an explicitly trusted local PKCS#11 module in a controlled child.
///
/// Both paths must be absolute, and the module path must be UTF-8. Use the
/// packaged worker from the same build and a trusted module from local
/// configuration. Never derive the
/// module path from an invocation or an object URI. Enumeration uses read-only
/// sessions, requires no PIN and performs no signing operation. A certificate's
/// presence establishes neither access to a matching key nor certificate trust.
/// Discovery with no initialized tokens succeeds with an empty list.
///
/// # Errors
/// Fails on unsupported platforms, invalid paths, module or token errors,
/// ambiguous selectors, oversized replies, or a worker failure. The child
/// must close its sessions, finalize the module and exit successfully before
/// discovery results are returned.
pub fn discover_pkcs11(executable: &Path, module: &Path) -> Result<Vec<Pkcs11Token>, WorkerError> {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        use crate::{process::Process, wire, OPERATION_TIMEOUT};
        use secrecy::ExposeSecret;
        use std::time::Instant;

        if !executable.is_absolute() {
            return Err(WorkerError::InvalidInput);
        }
        let request = wire::pkcs11::request(module)?;
        let mut process = Process::spawn(executable)?;
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let result = (|| {
            if process.receive(deadline)?.expose_secret() != wire::HELLO {
                return Err(WorkerError::Protocol);
            }
            process.send(&request, deadline)?;
            let reply = process.receive(deadline)?;
            process.finish(deadline)?;
            wire::pkcs11::decode_reply(reply.expose_secret())
        })();
        match result {
            Ok(tokens) => Ok(tokens),
            Err(error) => Err(process.abort(error)),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (executable, module);
        Err(WorkerError::UnsupportedPlatform)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) fn discover(
    module: &Path,
    max_tokens: usize,
    mut remaining_certificates: usize,
) -> Result<Vec<Pkcs11Token>, WorkerError> {
    use pkcs11_client::{
        object_locator, object_reference, Attribute, AttributeRead, AttributeType, Authentication,
        CertificateDocument, ObjectClass, Provider, SessionMode,
    };

    fn is_public_certificate(attributes: &[AttributeRead]) -> bool {
        let mut values = attributes
            .iter()
            .filter_map(|attribute| attribute.values.as_ref())
            .flat_map(|values| values.expose_values());
        values
            .clone()
            .any(|value| *value == Attribute::Class(ObjectClass::CERTIFICATE))
            && values.any(|value| *value == Attribute::Private(false))
    }

    let provider = Provider::load(module).map_err(|_| WorkerError::Unavailable)?;
    let outcome = (|| {
        let tokens = provider.tokens().map_err(|_| WorkerError::Unavailable)?;
        let mut result = Vec::new();
        for token in tokens.iter().filter(|token| token.info.token_initialized()) {
            if result.len() == max_tokens {
                return Err(WorkerError::Protocol);
            }
            let uri = token.uri().map_err(|_| WorkerError::Unavailable)?;
            let mut session = provider
                .management(&uri, SessionMode::ReadOnly, Authentication::None)
                .map_err(|_| WorkerError::Unavailable)?;
            let certificates = (|| {
                let objects = session
                    .objects(&[
                        AttributeType::Class,
                        AttributeType::Private,
                        AttributeType::Id,
                        AttributeType::Label,
                    ])
                    .map_err(|_| WorkerError::Unavailable)?;
                let mut certificates = Vec::new();
                for attributes in objects
                    .iter()
                    .filter(|object| is_public_certificate(object))
                {
                    let Some(locator) =
                        object_locator(&uri, attributes).map_err(|_| WorkerError::Unavailable)?
                    else {
                        continue;
                    };
                    remaining_certificates = remaining_certificates
                        .checked_sub(1)
                        .ok_or(WorkerError::Protocol)?;
                    let uri = locator.to_string();
                    let object = object_reference(locator).map_err(|_| WorkerError::Unavailable)?;
                    let der = session
                        .export_public(&object)
                        .map_err(|_| WorkerError::Unavailable)?;
                    if der.is_empty() || der.len() > crate::MAX_CERTIFICATE_BYTES {
                        return Err(WorkerError::Protocol);
                    }
                    if let Ok(certificate) = CertificateDocument::from_der(der) {
                        certificates.push(Pkcs11Certificate {
                            uri,
                            der: certificate.der().to_vec(),
                        });
                    }
                }
                Ok(certificates)
            })();
            session.close().map_err(|_| WorkerError::CleanupFailed)?;
            result.push(Pkcs11Token {
                uri: uri.to_string(),
                certificates: certificates?,
            });
        }
        Ok(result)
    })();
    provider
        .finalize()
        .map_err(|_| WorkerError::CleanupFailed)?;
    outcome
}
