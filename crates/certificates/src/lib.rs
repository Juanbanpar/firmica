//! Native signing-key providers. Independent of Dioxus and document formats.
//!
//! PKCS#12 import accepts caller-selected local bytes and borrows a secret password.
//! It does not persist passwords or expose private-key bytes. OpenSSL owns decrypted
//! keys; zeroization of all temporary native buffers, including the binding's password
//! conversion, is not guaranteed. The caller owns and must clear any plaintext input
//! buffers. Input size is bounded, but OpenSSL's KDF work is not bounded by this API:
//! do not accept remote/browser-supplied containers. A
//! resource-controlled import worker is required before exposing untrusted imports.
//!
//! Certificate trust, validity, key usage, revocation and user authorization are not
//! evaluated here. Additional certificates are retained without building a trusted chain.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "pkcs11")]
pub mod pkcs11;
mod pkcs12;

pub use pkcs12::Pkcs12Key;

use firmica_signing::{SignatureAlgorithm, SigningError, SigningInput};
use openssl::{
    md::Md,
    nid::Nid,
    pkey::{Id, PKeyRef, Public},
    pkey_ctx::PkeyCtx,
    rsa::Padding,
    sha::sha256,
    x509::X509,
};

/// Maximum encoded PKCS#12 size accepted before invoking native parsing (8 MiB).
pub const MAX_PKCS12_BYTES: usize = 8 * 1024 * 1024;

/// Import/selection failures with no passwords, PINs or certificate data in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CertificateError {
    /// Input is empty, oversized, malformed or not a canonical complete DER object.
    #[error("invalid certificate container")]
    InvalidContainer,
    /// Embedded NUL would cause the OpenSSL binding to panic.
    #[error("the password contains an unsupported NUL character")]
    InvalidPassword,
    /// Password, integrity protection or encryption is invalid/unsupported.
    #[error("the certificate container could not be unlocked")]
    UnlockFailed,
    /// A leaf certificate and a private key were not both present.
    #[error("the container has no complete signing identity")]
    MissingIdentity,
    /// The certificate public key does not match the private key.
    #[error("the certificate and signing key do not match")]
    KeyMismatch,
    /// Unsupported algorithm, curve, key size or token authentication requirement.
    #[error("the signing key is unsupported")]
    UnsupportedKey,
    /// A native metadata/query operation failed.
    #[error("the certificate backend failed")]
    BackendFailure,
}

fn algorithm(key: &PKeyRef<Public>) -> Result<SignatureAlgorithm, CertificateError> {
    match key.id() {
        Id::RSA if key.bits() >= 2048 => Ok(SignatureAlgorithm::RsaPkcs1v15Sha256),
        Id::EC
            if key
                .ec_key()
                .map_err(|_| CertificateError::UnsupportedKey)?
                .group()
                .curve_name()
                == Some(Nid::X9_62_PRIME256V1) =>
        {
            Ok(SignatureAlgorithm::EcdsaP256Sha256)
        }
        _ => Err(CertificateError::UnsupportedKey),
    }
}

fn digest(input: SigningInput<'_>) -> [u8; 32] {
    match input {
        SigningInput::Message(message) => sha256(message),
        SigningInput::Sha256Digest(digest) => *digest,
    }
}

fn verify(
    certificate: &X509,
    algorithm: SignatureAlgorithm,
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), SigningError> {
    let check = || {
        let key = certificate.public_key()?;
        let mut context = PkeyCtx::new(&key)?;
        context.verify_init()?;
        context.set_signature_md(Md::sha256())?;
        if algorithm == SignatureAlgorithm::RsaPkcs1v15Sha256 {
            context.set_rsa_padding(Padding::PKCS1)?;
        }
        context.verify(digest, signature)
    };
    match check() {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(SigningError::InvalidSignature),
    }
}
