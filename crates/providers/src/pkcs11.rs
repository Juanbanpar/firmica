//! Local PKCS#11 provider. Native modules and sessions live in the controlled worker.

use crate::{
    session::WorkerProviderKey, Authentication, Availability, CertificateCandidate, Credentials,
    Error, IdentityReference, Provider, ProviderId, ProviderKey, Selection,
};
use firmica_key_worker::{discover_pkcs11, WorkerError, WorkerKey};
use firmica_signing::CertificateIdentity;
use pkcs11_client::Pkcs11Uri;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub use firmica_key_worker::Pkcs11Pins;

/// One user-configured trusted local module.
pub struct Pkcs11Provider {
    executable: PathBuf,
    module: PathBuf,
    id: ProviderId,
}

impl Pkcs11Provider {
    /// Set up a source without loading code. Use the packaged worker and a module
    /// chosen through explicit, trusted local configuration.
    ///
    /// # Errors
    /// Rejects relative paths. The worker validates path encoding and length.
    pub fn new(executable: PathBuf, module: PathBuf) -> Result<Self, Error> {
        if !executable.is_absolute() || !module.is_absolute() {
            return Err(WorkerError::InvalidInput.into());
        }
        let hash = Sha256::digest(module.as_os_str().as_encoded_bytes());
        Ok(Self {
            executable,
            module,
            id: ProviderId::new(format!("pkcs11-{hash:x}")),
        })
    }

    /// Token and object metadata for distinguishing certificates with the same subject.
    pub fn selection_label(candidate: &CertificateCandidate) -> Option<String> {
        let uri: Pkcs11Uri = std::str::from_utf8(candidate.reference().key())
            .ok()?
            .parse()
            .ok()?;
        let text = |name| {
            let value = std::str::from_utf8(uri.path_attribute(name)?).ok()?;
            Some(
                value
                    .chars()
                    .filter(|character| !character.is_control())
                    .collect::<String>(),
            )
        };
        let id = uri.path_attribute("id")?;
        let id = id
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        Some(format!("{} · {} · {id}", text("token")?, text("serial")?))
    }
}

impl Provider for Pkcs11Provider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn is_available(&self) -> bool {
        true
    }

    fn discover(&self) -> Result<Vec<CertificateCandidate>, Error> {
        let mut candidates = Vec::new();
        for token in discover_pkcs11(&self.executable, &self.module)? {
            for certificate in token.certificates {
                let uri: Pkcs11Uri = certificate.uri.parse().map_err(|_| Error::Backend)?;
                let availability = if uri.path_attribute("id").is_some_and(|id| !id.is_empty()) {
                    Availability::Locked
                } else {
                    Availability::PublicOnly
                };
                candidates.push(CertificateCandidate::new(
                    IdentityReference::new(self.id.clone(), certificate.uri.into_bytes()),
                    CertificateIdentity {
                        certificate_der: certificate.der,
                        additional_certificates: Vec::new(),
                    },
                    Vec::new(),
                    Authentication::Pin,
                    availability,
                ));
            }
        }
        Ok(candidates)
    }

    fn open(
        &mut self,
        selection: Selection<'_>,
        credentials: Credentials,
    ) -> Result<Box<dyn ProviderKey>, Error> {
        let Selection::Candidate(candidate) = selection else {
            return Err(Error::StaleIdentity);
        };
        let reference = candidate.reference();
        if reference.provider() != &self.id {
            return Err(Error::StaleIdentity);
        }
        let locator = std::str::from_utf8(reference.key()).map_err(|_| Error::StaleIdentity)?;
        let pins = match credentials {
            Credentials::Pin(user) => Pkcs11Pins {
                user,
                context: None,
            },
            Credentials::Token(pins) => pins,
            _ => return Err(Error::AuthenticationRequired),
        };
        let key = WorkerKey::open_pkcs11(&self.executable, &self.module, locator, pins).map_err(
            |error| match error {
                WorkerError::TokenIdentity => Error::StaleIdentity,
                WorkerError::TokenUnsupported => Error::NotSigningIdentity,
                _ => Error::from(error),
            },
        )?;
        Ok(Box::new(WorkerProviderKey::new(key, reference.clone())))
    }
}
