//! Read-only macOS Keychain identity discovery and signing through Security.framework.
//!
//! Discovery and review use certificates and persistent item references. The private
//! key is opened by Security.framework only during the authorized signing operation,
//! which may display native authentication UI. Handles are released on that thread.

#[allow(unsafe_code)]
mod native;
#[cfg(test)]
#[allow(unsafe_code)]
mod tests;

use crate::{
    Authentication, Availability, CertificateCandidate, Credentials, Error, IdentityReference,
    Provider, ProviderId, ProviderKey, Selection,
};
use firmica_certificates::{signature_algorithm, verify_sha256_signature};
use firmica_signing::{
    limits::MAX_CERTIFICATE_BYTES, CertificateIdentity, InputKind, Signature, SignatureAlgorithm,
    SigningCapability, SigningError, SigningInput, SigningKey,
};
use openssl::{bn::BigNumContext, ec::PointConversionForm, x509::X509};
use security_framework::{
    identity::SecIdentity,
    key::{Algorithm, SecKey},
    os::macos::keychain::SecKeychain,
};
use sha2::{Digest, Sha256};

/// Keychain identities from the current macOS Keychain search list.
pub struct KeychainProvider {
    id: ProviderId,
    keychains: Vec<SecKeychain>,
}

impl Default for KeychainProvider {
    fn default() -> Self {
        Self {
            id: ProviderId::new("macos-keychain"),
            keychains: Vec::new(),
        }
    }
}

impl Provider for KeychainProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn is_available(&self) -> bool {
        true
    }

    fn discover(&self) -> Result<Vec<CertificateCandidate>, Error> {
        Ok(native::identities(&self.keychains)?
            .into_iter()
            .filter_map(|item| {
                let der = certificate_der(&item.identity).ok()?;
                let capabilities = profile(&der)
                    .map_or_else(|_| Vec::new(), |(_, algorithm)| capabilities(algorithm));
                let (authentication, availability) = if capabilities.is_empty() {
                    (Authentication::None, Availability::Unavailable)
                } else {
                    (Authentication::ProviderManaged, Availability::Locked)
                };
                Some(CertificateCandidate::new(
                    IdentityReference::new(self.id.clone(), item.reference),
                    CertificateIdentity {
                        certificate_der: der,
                        additional_certificates: Vec::new(),
                    },
                    capabilities,
                    authentication,
                    availability,
                ))
            })
            .collect())
    }

    fn open(
        &mut self,
        selection: Selection<'_>,
        credentials: Credentials,
    ) -> Result<Box<dyn ProviderKey>, Error> {
        let Selection::Candidate(candidate) = selection else {
            return Err(Error::StaleIdentity);
        };
        if !matches!(credentials, Credentials::None) {
            return Err(Error::AuthenticationRequired);
        }
        if candidate.reference().provider() != &self.id
            || !candidate.identity().additional_certificates.is_empty()
        {
            return Err(Error::StaleIdentity);
        }
        let (certificate, algorithm) = profile(&candidate.identity().certificate_der)?;
        let key = KeychainKey {
            keychains: self.keychains.clone(),
            candidate: candidate.clone(),
            certificate,
            algorithm,
            capabilities: capabilities(algorithm),
        };
        key.resolve()?;
        Ok(Box::new(key))
    }
}

fn certificate_der(identity: &SecIdentity) -> Result<Vec<u8>, Error> {
    let der = identity
        .certificate()
        .map_err(|_| Error::StaleIdentity)?
        .to_der();
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(Error::NotSigningIdentity);
    }
    Ok(der)
}

fn profile(der: &[u8]) -> Result<(X509, SignatureAlgorithm), Error> {
    let certificate = X509::from_der(der).map_err(|_| Error::NotSigningIdentity)?;
    let key = certificate
        .public_key()
        .map_err(|_| Error::NotSigningIdentity)?;
    let algorithm = signature_algorithm(&key).map_err(|_| Error::NotSigningIdentity)?;
    Ok((certificate, algorithm))
}

fn capabilities(algorithm: SignatureAlgorithm) -> Vec<SigningCapability> {
    [InputKind::Message, InputKind::Sha256Digest]
        .map(|input| SigningCapability { algorithm, input })
        .into()
}

struct KeychainKey {
    keychains: Vec<SecKeychain>,
    candidate: CertificateCandidate,
    certificate: X509,
    algorithm: SignatureAlgorithm,
    capabilities: Vec<SigningCapability>,
}

impl KeychainKey {
    fn resolve(&self) -> Result<SecIdentity, Error> {
        let mut items = native::identities(&self.keychains)?
            .into_iter()
            .filter(|item| item.reference == self.candidate.reference().key());
        let item = items.next().ok_or(Error::StaleIdentity)?;
        if items.next().is_some() {
            return Err(Error::AmbiguousIdentity);
        }
        if certificate_der(&item.identity)? != self.identity().certificate_der {
            return Err(Error::StaleIdentity);
        }
        Ok(item.identity)
    }

    fn matches_public_key(&self, key: &SecKey) -> Result<bool, SigningError> {
        let actual = key
            .public_key()
            .and_then(|public_key| public_key.external_representation())
            .ok_or(SigningError::BackendFailure)?;
        let expected = (|| {
            let key = self.certificate.public_key()?;
            match self.algorithm {
                SignatureAlgorithm::RsaPkcs1v15Sha256 => key.rsa()?.public_key_to_der_pkcs1(),
                SignatureAlgorithm::EcdsaP256Sha256 => {
                    let key = key.ec_key()?;
                    let mut context = BigNumContext::new()?;
                    key.public_key().to_bytes(
                        key.group(),
                        PointConversionForm::UNCOMPRESSED,
                        &mut context,
                    )
                }
            }
        })()
        .map_err(|_| SigningError::BackendFailure)?;
        Ok(actual.bytes() == expected)
    }
}

impl SigningKey for KeychainKey {
    fn identity(&self) -> &CertificateIdentity {
        self.candidate.identity()
    }

    fn capabilities(&self) -> &[SigningCapability] {
        &self.capabilities
    }

    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        self.sign_if_active(algorithm, input, &|| false)
    }
}

impl ProviderKey for KeychainKey {
    fn revalidate(&mut self, reference: &IdentityReference) -> Result<(), Error> {
        if reference != self.candidate.reference() {
            return Err(Error::StaleIdentity);
        }
        self.resolve().map(drop)
    }

    fn sign_if_active(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Signature, SigningError> {
        if algorithm != self.algorithm {
            return Err(SigningError::UnsupportedOperation);
        }
        if cancelled() {
            return Err(SigningError::BackendFailure);
        }
        let digest = match input {
            SigningInput::Message(bytes) => Sha256::digest(bytes).into(),
            SigningInput::Sha256Digest(digest) => *digest,
        };
        let identity = self.resolve().map_err(|_| SigningError::BackendFailure)?;
        if cancelled() {
            return Err(SigningError::BackendFailure);
        }
        let key = identity
            .private_key()
            .map_err(|_| SigningError::BackendFailure)?;
        let native_algorithm = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15Sha256 => Algorithm::RSASignatureDigestPKCS1v15SHA256,
            SignatureAlgorithm::EcdsaP256Sha256 => Algorithm::ECDSASignatureDigestX962SHA256,
        };
        if !native::supports_signing(&key, native_algorithm) {
            return Err(SigningError::UnsupportedOperation);
        }
        if !self.matches_public_key(&key)? || cancelled() {
            return Err(SigningError::BackendFailure);
        }
        let value = key
            .create_signature(native_algorithm, &digest)
            .map_err(|_| SigningError::BackendFailure)?;
        drop(key);
        drop(identity);
        verify_sha256_signature(&self.certificate, algorithm, &digest, &value)?;
        Ok(Signature { algorithm, value })
    }

    fn close(self: Box<Self>) -> Result<(), Error> {
        // Each operation owns and releases its SecIdentity and SecKey references.
        Ok(())
    }
}
