//! Certificate provider discovery, selection and checked signing-session cleanup.
//!
//! Discovery is non-interactive. Opening may require explicit user interaction.
//! The caller applies certificate policy and obtains consent before signing, then
//! checks session cleanup before publishing output. Provider operations can block.

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod candidate;
pub mod pkcs12;
mod registry;
mod session;
#[cfg(windows)]
pub mod windows;

pub use candidate::{
    Authentication, Availability, CertificateCandidate, IdentityReference, ProviderId,
};
pub use registry::{Credentials, Provider, Registry, Selection};
pub use session::{ProviderKey, SigningSession};

/// Provider failures without credentials, paths, native handles or certificate data.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// No configured provider can currently service the selection.
    #[error("the certificate provider is unavailable")]
    Unavailable,
    /// A provider with the same source identifier is already configured.
    #[error("the certificate provider is already registered")]
    DuplicateProvider,
    /// The selected reference, certificate or capabilities no longer match.
    #[error("the selected certificate identity changed or is no longer available")]
    StaleIdentity,
    /// Discovery could not distinguish two identities in the same provider.
    #[error("the certificate provider returned ambiguous identities")]
    AmbiguousIdentity,
    /// Credentials have not been supplied or the credential type is unsuitable.
    #[error("the certificate provider requires authentication")]
    AuthenticationRequired,
    /// The selection does not have a usable signing key.
    #[error("the selected identity does not support signing")]
    NotSigningIdentity,
    /// The provider could not complete a native operation.
    #[error("the certificate provider operation failed")]
    Backend,
    /// Required cleanup could not be confirmed. Discard any signing output.
    #[error("certificate provider cleanup failed")]
    Cleanup,
    /// The isolated file-import worker failed.
    #[error(transparent)]
    Worker(#[from] pkcs12::WorkerError),
}

#[cfg(test)]
mod tests;
