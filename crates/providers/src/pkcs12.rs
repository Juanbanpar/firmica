//! One user-selected PKCS#12 or PFX container, opened in the isolated key worker.

use crate::{
    session::WorkerProviderKey, CertificateCandidate, Credentials, Error, IdentityReference,
    Provider, ProviderId, ProviderKey, Selection,
};
use firmica_key_worker::WorkerKey;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub use firmica_certificates::MAX_PKCS12_BYTES;
pub use firmica_key_worker::WorkerError;

/// A provider configured with one bounded, user-selected container.
/// Certificates become available only after explicitly unlocking the container.
pub struct Pkcs12Provider {
    executable: PathBuf,
    container: Option<SecretBox<Vec<u8>>>,
    reference: IdentityReference,
}

impl Pkcs12Provider {
    /// Configure the selected bytes and trusted companion executable. Import
    /// consumes the bytes. It never reopens the original container path.
    ///
    /// # Errors
    /// Rejects empty containers and those larger than [`MAX_PKCS12_BYTES`].
    pub fn new(executable: PathBuf, container: SecretBox<Vec<u8>>) -> Result<Self, Error> {
        let bytes = container.expose_secret();
        if bytes.is_empty() || bytes.len() > MAX_PKCS12_BYTES {
            return Err(WorkerError::InvalidInput.into());
        }
        let reference =
            IdentityReference::new(ProviderId::new("pkcs12"), Sha256::digest(bytes).to_vec());
        Ok(Self {
            executable,
            container: Some(container),
            reference,
        })
    }

    /// A reference bound to the selected container bytes for explicit import.
    pub fn reference(&self) -> &IdentityReference {
        &self.reference
    }
}

impl Provider for Pkcs12Provider {
    fn id(&self) -> &ProviderId {
        self.reference.provider()
    }

    fn is_available(&self) -> bool {
        cfg!(any(target_os = "linux", target_os = "macos", windows)) && self.container.is_some()
    }

    fn discover(&self) -> Result<Vec<CertificateCandidate>, Error> {
        // Discovery does not parse untrusted containers or ask for a password.
        Ok(Vec::new())
    }

    fn open(
        &mut self,
        selection: Selection<'_>,
        credentials: Credentials,
    ) -> Result<Box<dyn ProviderKey>, Error> {
        if !matches!(selection, Selection::Import(reference) if reference == &self.reference) {
            return Err(Error::StaleIdentity);
        }
        let Credentials::Password(password) = credentials else {
            return Err(Error::AuthenticationRequired);
        };
        let container = self.container.take().ok_or(Error::Unavailable)?;
        let key = WorkerKey::import(&self.executable, container, password)?;
        Ok(Box::new(WorkerProviderKey::new(
            key,
            self.reference.clone(),
        )))
    }
}
