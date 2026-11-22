//! Read-only Windows certificate stores and CAPI/CNG document-signing keys.
//!
//! Candidate discovery reads public certificates and persisted key-provider
//! metadata. Native authentication and key acquisition occur during the authorized
//! signing operation. Auxiliary stores are exposed for certificate inspection.

#[allow(unsafe_code)]
mod key;
#[allow(unsafe_code)]
mod store;
#[cfg(test)]
#[allow(unsafe_code)]
mod tests;

use crate::{
    Authentication, Availability, CertificateCandidate, Credentials, Error, IdentityReference,
    Provider, ProviderId, ProviderKey, Selection,
};
use firmica_certificates::{signature_algorithm, verify_sha256_signature};
use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use openssl::x509::X509;
use sha2::{Digest, Sha256};
use store::{Context, KeyInfo, Source};
use windows_sys::Win32::Security::Cryptography::{
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
};

/// Windows system stores available through the read-only provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemStore {
    /// Current User personal certificates and associated signing keys.
    CurrentUserPersonal,
    /// Local Machine personal certificates. Key use depends on the caller's access.
    LocalMachinePersonal,
    /// Current User address book, for public-certificate inspection.
    AddressBook,
    /// Current User intermediate-authority store, for inspection.
    IntermediateAuthorities,
    /// Current User root store, for inspection.
    Roots,
}

/// One locally configured Windows system store. The private key stays in its CSP
/// or KSP. Resource handles are acquired and released on the signing thread.
pub struct WindowsProvider {
    id: ProviderId,
    source: Source,
}

impl WindowsProvider {
    /// Configure a system store without opening it or checking for private keys.
    pub fn new(store: SystemStore) -> Self {
        let (id, location, name, public_only) = match store {
            SystemStore::CurrentUserPersonal => (
                "windows-user-my",
                CERT_SYSTEM_STORE_CURRENT_USER,
                "MY",
                false,
            ),
            SystemStore::LocalMachinePersonal => (
                "windows-machine-my",
                CERT_SYSTEM_STORE_LOCAL_MACHINE,
                "MY",
                false,
            ),
            SystemStore::AddressBook => (
                "windows-user-address-book",
                CERT_SYSTEM_STORE_CURRENT_USER,
                "AddressBook",
                true,
            ),
            SystemStore::IntermediateAuthorities => (
                "windows-user-ca",
                CERT_SYSTEM_STORE_CURRENT_USER,
                "CA",
                true,
            ),
            SystemStore::Roots => (
                "windows-user-root",
                CERT_SYSTEM_STORE_CURRENT_USER,
                "Root",
                true,
            ),
        };
        Self {
            id: ProviderId::new(id),
            source: Source::new(name, location, public_only),
        }
    }
}

impl Provider for WindowsProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn is_available(&self) -> bool {
        self.source.read(|_| Ok(())).is_ok()
    }

    fn discover(&self) -> Result<Vec<CertificateCandidate>, Error> {
        let mut candidates = Vec::new();
        let mut public_references = std::collections::HashSet::new();
        self.source.read(|store| {
            store.enumerate(|context| {
                let Some(der) = context.der() else {
                    return Ok(());
                };
                let key_info = if self.source.public_only {
                    Ok(None)
                } else {
                    context.key_info()
                };
                let reference = reference(
                    &self.id,
                    der,
                    key_info.as_ref().ok().and_then(Option::as_ref),
                );
                let (availability, capabilities) = match key_info {
                    Ok(Some(info)) => match Profile::from_der(der, info.cng) {
                        Ok((_, profile)) => (Availability::Locked, profile.capabilities()),
                        Err(_) => (Availability::Unavailable, vec![]),
                    },
                    Ok(None) => (Availability::PublicOnly, vec![]),
                    Err(_) => (Availability::Unavailable, vec![]),
                };
                if capabilities.is_empty() && !public_references.insert(reference.clone()) {
                    return Ok(());
                }
                let authentication = if capabilities.is_empty() {
                    Authentication::None
                } else {
                    Authentication::ProviderManaged
                };
                candidates.push(CertificateCandidate::new(
                    reference,
                    CertificateIdentity {
                        certificate_der: der.to_vec(),
                        additional_certificates: vec![],
                    },
                    capabilities,
                    authentication,
                    availability,
                ));
                Ok(())
            })
        })?;
        Ok(candidates)
    }

    fn open(
        &mut self,
        selection: Selection<'_>,
        credentials: Credentials,
    ) -> Result<Box<dyn ProviderKey>, Error> {
        let Selection::Candidate(selected) = selection else {
            return Err(Error::StaleIdentity);
        };
        if self.source.public_only {
            return Err(Error::NotSigningIdentity);
        }
        if !matches!(credentials, Credentials::None) {
            return Err(Error::AuthenticationRequired);
        }
        if selected.reference().provider() != &self.id
            || !selected.identity().additional_certificates.is_empty()
        {
            return Err(Error::StaleIdentity);
        }
        let (certificate, profile) = with_selected(&self.source, selected, |_, info| {
            Profile::from_der(&selected.identity().certificate_der, info.cng)
        })?;
        Ok(Box::new(WindowsKey {
            source: self.source.clone(),
            selection: selected.clone(),
            certificate,
            capabilities: profile.capabilities(),
            profile,
            cleanup_failed: false,
        }))
    }
}

struct Profile {
    algorithm: SignatureAlgorithm,
    width: usize,
}

impl Profile {
    fn from_der(der: &[u8], cng: bool) -> Result<(X509, Self), Error> {
        let certificate = X509::from_der(der).map_err(|_| Error::NotSigningIdentity)?;
        let public_key = certificate
            .public_key()
            .map_err(|_| Error::NotSigningIdentity)?;
        let algorithm = signature_algorithm(&public_key).map_err(|_| Error::NotSigningIdentity)?;
        let width = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15Sha256 => public_key.size(),
            SignatureAlgorithm::EcdsaP256Sha256 if cng => 64,
            _ => return Err(Error::NotSigningIdentity),
        };
        Ok((certificate, Self { algorithm, width }))
    }

    fn capabilities(&self) -> Vec<SigningCapability> {
        [InputKind::Message, InputKind::Sha256Digest]
            .map(|input| SigningCapability {
                algorithm: self.algorithm,
                input,
            })
            .into()
    }
}

fn reference(id: &ProviderId, der: &[u8], key: Option<&KeyInfo>) -> IdentityReference {
    let mut reference = Sha256::digest(der).to_vec();
    if let Some(key) = key {
        reference.extend_from_slice(&key.fingerprint);
    }
    IdentityReference::new(id.clone(), reference)
}

fn with_selected<T>(
    source: &Source,
    selected: &CertificateCandidate,
    action: impl FnOnce(&Context, KeyInfo) -> Result<T, Error>,
) -> Result<T, Error> {
    source.read(|store| {
        let mut selected_context = None;
        store.enumerate(|context| {
            let Some(der) = context.der() else {
                return Ok(());
            };
            if der != selected.identity().certificate_der {
                return Ok(());
            }
            let Some(info) = context.key_info()? else {
                return Ok(());
            };
            let expected = selected.reference();
            if &reference(expected.provider(), der, Some(&info)) != expected {
                return Ok(());
            }
            if selected_context.is_some() {
                return Err(Error::AmbiguousIdentity);
            }
            selected_context = Some((context.duplicate()?, info));
            Ok(())
        })?;
        let (context, info) = selected_context.ok_or(Error::StaleIdentity)?;
        let result = action(&context, info);
        context.close()?;
        result
    })
}

struct WindowsKey {
    source: Source,
    selection: CertificateCandidate,
    certificate: X509,
    capabilities: Vec<SigningCapability>,
    profile: Profile,
    cleanup_failed: bool,
}

impl SigningKey for WindowsKey {
    fn identity(&self) -> &CertificateIdentity {
        self.selection.identity()
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

impl ProviderKey for WindowsKey {
    fn revalidate(&mut self, reference: &IdentityReference) -> Result<(), Error> {
        if self.selection.reference() != reference {
            return Err(Error::StaleIdentity);
        }
        let result = with_selected(&self.source, &self.selection, |_, _| Ok(()));
        self.cleanup_failed |= result == Err(Error::Cleanup);
        result
    }

    fn sign_if_active(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Signature, SigningError> {
        if algorithm != self.profile.algorithm {
            return Err(SigningError::UnsupportedOperation);
        }
        if self.cleanup_failed || cancelled() {
            return Err(SigningError::BackendFailure);
        }
        let digest = match input {
            SigningInput::Message(bytes) => Sha256::digest(bytes).into(),
            SigningInput::Sha256Digest(digest) => *digest,
        };
        let signature = with_selected(&self.source, &self.selection, |context, info| {
            key::sign(
                context,
                algorithm,
                &digest,
                self.profile.width,
                info.cng,
                cancelled,
            )
        });
        self.cleanup_failed |= matches!(&signature, Err(Error::Cleanup));
        let value = signature.map_err(|_| SigningError::BackendFailure)?;
        verify_sha256_signature(&self.certificate, algorithm, &digest, &value)?;
        Ok(Signature { algorithm, value })
    }

    fn close(self: Box<Self>) -> Result<(), Error> {
        if self.cleanup_failed {
            return Err(Error::Cleanup);
        }
        Ok(())
    }
}
