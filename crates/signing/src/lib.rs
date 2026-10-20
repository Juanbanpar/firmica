//! Signing-provider contracts and owned format choices, independent of encoders,
//! key storage and UI.
//!
//! These operations neither authorize a signature nor establish certificate trust.
//! Callers must obtain consent and apply certificate policy before signing. Implementations
//! may block for native cryptography or token I/O; use them outside the UI event loop.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod format;

/// Precisely specified initial algorithms; no implicit hash or RSA padding selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 and a modulus of at least 2048 bits.
    RsaPkcs1v15Sha256,
    /// ECDSA on NIST P-256 with SHA-256.
    EcdsaP256Sha256,
}

/// Wire representation of the cryptographic signature, before a format embeds it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureEncoding {
    /// Unsigned, big-endian RSA value, padded to the modulus length.
    RsaBigEndian,
    /// DER SEQUENCE of positive INTEGERs r and s; never PKCS#11's raw r || s.
    EcdsaDer,
}

impl SignatureAlgorithm {
    /// Required output encoding for this algorithm.
    pub const fn encoding(self) -> SignatureEncoding {
        match self {
            Self::RsaPkcs1v15Sha256 => SignatureEncoding::RsaBigEndian,
            Self::EcdsaP256Sha256 => SignatureEncoding::EcdsaDer,
        }
    }
}

/// Distinguishes hashing by the provider from signing an already computed hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputKind {
    /// Hash the supplied message exactly once with SHA-256.
    Message,
    /// Sign an existing 32-byte SHA-256 digest without hashing it again.
    Sha256Digest,
}

/// Borrowed signing input. Deliberately has no `Debug` implementation.
#[derive(Clone, Copy)]
pub enum SigningInput<'a> {
    /// Message bytes; the provider computes SHA-256.
    Message(&'a [u8]),
    /// A SHA-256 digest, with its size enforced by the type system.
    Sha256Digest(&'a [u8; 32]),
}

impl SigningInput<'_> {
    /// Whether the provider must hash this input.
    pub const fn kind(self) -> InputKind {
        match self {
            Self::Message(_) => InputKind::Message,
            Self::Sha256Digest(_) => InputKind::Sha256Digest,
        }
    }
}

/// One operation advertised by a key. Token policy can still deny it at execution time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningCapability {
    /// Hash, key type and padding/curve requirements.
    pub algorithm: SignatureAlgorithm,
    /// Message or precomputed digest operation.
    pub input: InputKind,
}

/// Leaf certificate and additional certificates supplied by a provider.
///
/// Additional certificates are an unordered, untrusted collection, not a validated
/// chain. No private-key material or authentication secrets belong in this value.
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateIdentity {
    /// DER-encoded leaf X.509 certificate.
    pub certificate_der: Vec<u8>,
    /// Other DER-encoded X.509 certificates, without trust or ordering guarantees.
    pub additional_certificates: Vec<Vec<u8>>,
}

/// Signature bytes with their algorithm and therefore their required encoding.
/// No document, certificate chain or trust decision is encoded here.
pub struct Signature {
    /// Algorithm used to generate the signature.
    pub algorithm: SignatureAlgorithm,
    /// Value in the encoding returned by [`SignatureAlgorithm::encoding`].
    pub value: Vec<u8>,
}

/// Static errors that do not disclose message bytes, passwords, PINs or native stacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SigningError {
    /// The key does not advertise this exact algorithm/input combination.
    #[error("the key does not support this signing operation")]
    UnsupportedOperation,
    /// A native operation failed, including token removal or missing authentication.
    #[error("the signing backend failed")]
    BackendFailure,
    /// Output failed verification against the selected certificate.
    #[error("the signature does not match the selected certificate")]
    InvalidSignature,
}

/// Access to a signing key, including a non-exportable key in a native provider.
///
/// There is deliberately no private-key export operation. The mutable receiver
/// serializes operations on a handle. Providers must verify successful output against
/// the selected leaf certificate before returning it. Authentication and native-session
/// cleanup are separate lifecycle responsibilities documented by each provider.
pub trait SigningKey {
    /// Selected identity; this does not imply trust, validity or signing authorization.
    fn identity(&self) -> &CertificateIdentity;

    /// Supported algorithm/input pairs, without a promise of token availability.
    fn capabilities(&self) -> &[SigningCapability];

    /// Perform exactly one operation, returning a verified cryptographic signature.
    ///
    /// # Errors
    /// Returns [`SigningError::UnsupportedOperation`] before invoking the key when the
    /// pair is unsupported. Other failures must not return partially produced output.
    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
    ) -> Result<Signature, SigningError>;
}
