use firmica_signing::{CertificateIdentity, SigningCapability};
use sha2::{Digest, Sha256};

/// Stable application-assigned name for a configured provider source.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProviderId(String);

impl ProviderId {
    /// Construct a provider identifier. Use a distinct name for each configured source.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Application identifier, suitable for matching a configured provider.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A provider-scoped key reference. Deliberately omits `Debug` and serialization.
///
/// The backend defines the bytes and their lifetime. They must distinguish keys
/// independently of display names. Callers must treat them as opaque.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct IdentityReference {
    provider: ProviderId,
    key: Vec<u8>,
}

impl IdentityReference {
    /// Construct a reference from provider-defined bytes. Never embed credentials.
    pub fn new(provider: ProviderId, key: Vec<u8>) -> Self {
        Self { provider, key }
    }

    /// Configured source that owns this reference.
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Opaque reference bytes for use by the owning backend.
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Interaction that may be required before the selected key can be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authentication {
    /// No credential requested by the provider.
    None,
    /// File or store password.
    Password,
    /// Token PIN.
    Pin,
    /// The native provider performs its own authorization.
    ProviderManaged,
}

/// Observed key availability. It says nothing about certificate trust or policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    /// A signing key appears usable.
    Available,
    /// The provider requires authentication before confirming access.
    Locked,
    /// The provider exposes only public certificate data for this identity.
    PublicOnly,
    /// A referenced key is missing or the provider cannot currently access it.
    Unavailable,
}

/// Public certificate metadata and the provider reference used to select its key.
#[derive(Clone)]
pub struct CertificateCandidate {
    reference: IdentityReference,
    identity: CertificateIdentity,
    fingerprint: [u8; 32],
    capabilities: Vec<SigningCapability>,
    authentication: Authentication,
    availability: Availability,
}

impl CertificateCandidate {
    /// Describe an identity observed by a provider. The SHA-256 fingerprint is
    /// computed from the exact leaf DER bytes. Discovery need not unlock the key
    /// and may report an empty capabilities list for a locked identity.
    pub fn new(
        reference: IdentityReference,
        identity: CertificateIdentity,
        capabilities: Vec<SigningCapability>,
        authentication: Authentication,
        availability: Availability,
    ) -> Self {
        let fingerprint = Sha256::digest(&identity.certificate_der).into();
        Self {
            reference,
            identity,
            fingerprint,
            capabilities,
            authentication,
            availability,
        }
    }

    /// Stable provider-scoped reference used for selection.
    pub fn reference(&self) -> &IdentityReference {
        &self.reference
    }

    /// Leaf DER and any additional certificates, without a trust decision.
    pub fn identity(&self) -> &CertificateIdentity {
        &self.identity
    }

    /// SHA-256 fingerprint of the selected leaf DER.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Algorithm/input pairs observed during discovery or opening.
    pub fn capabilities(&self) -> &[SigningCapability] {
        &self.capabilities
    }

    /// Authentication required to obtain or use the key.
    pub fn authentication(&self) -> Authentication {
        self.authentication
    }

    /// Observed availability at discovery or opening.
    pub fn availability(&self) -> Availability {
        self.availability
    }
}
