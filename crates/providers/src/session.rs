use crate::{CertificateCandidate, Error, IdentityReference};
use std::sync::atomic::{AtomicBool, Ordering};

use firmica_signing::{
    CertificateIdentity, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};

/// An opened key with provider-specific identity checks and ownership of its
/// resources. Backends must supply verified signatures as required by [`SigningKey`].
pub trait ProviderKey: SigningKey + Send {
    /// Check that the live key still corresponds to the selected reference.
    ///
    /// # Errors
    /// Reject changed or ambiguous identities. Do not prompt or perform a
    /// private-key operation. If a key can be replaced between this check and
    /// signing, the backend must bind the actual operation to the checked key.
    fn revalidate(&mut self, reference: &IdentityReference) -> Result<(), Error>;

    /// Sign if the caller is still active. Backends that acquire or authenticate
    /// a key during signing can check cancellation again before invoking it.
    ///
    /// # Errors
    /// Returns a signing error if cancelled or signing fails.
    fn sign_if_active(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Signature, SigningError> {
        if cancelled() {
            return Err(SigningError::BackendFailure);
        }
        self.sign(algorithm, input)
    }

    /// Release the session and any native resources, consuming the opened handle.
    ///
    /// # Errors
    /// Report detectable release failures. Discard any signature on failure.
    fn close(self: Box<Self>) -> Result<(), Error>;
}

/// Owns the selected key through review, signing and checked cleanup.
///
/// The certificate and capabilities presented for review are frozen. The
/// provider reference and live metadata are checked before each supported
/// operation. A backend failure invalidates further signing. Drop performs
/// best-effort cleanup and can block. Call [`Self::close`] before publishing output.
pub struct SigningSession {
    candidate: CertificateCandidate,
    key: Option<Box<dyn ProviderKey>>,
    failed: bool,
}

impl SigningSession {
    pub(crate) fn new(candidate: CertificateCandidate, key: Box<dyn ProviderKey>) -> Self {
        Self {
            candidate,
            key: Some(key),
            failed: false,
        }
    }

    /// Certificate metadata and key reference bound to this session.
    pub fn candidate(&self) -> &CertificateCandidate {
        &self.candidate
    }

    /// Confirm cleanup and consume the handle. Also used to cancel without signing.
    ///
    /// # Errors
    /// Returns any backend error reported during cleanup.
    pub fn close(mut self) -> Result<(), Error> {
        self.key.take().expect("open session").close()
    }

    /// Borrow this session with cancellation checks before validation and before
    /// invoking the private key. Callers must still check cancellation and close
    /// the session before publishing output.
    pub fn cancellable<'a>(&'a mut self, cancelled: &'a AtomicBool) -> impl SigningKey + 'a {
        CancellableKey {
            session: self,
            cancelled,
        }
    }

    fn sign_checked(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
        cancelled: impl Fn() -> bool,
    ) -> Result<Signature, SigningError> {
        let capability = SigningCapability {
            algorithm,
            input: input.kind(),
        };
        if !self.candidate.capabilities().contains(&capability) {
            return Err(SigningError::UnsupportedOperation);
        }
        if self.failed || cancelled() {
            self.failed = true;
            return Err(SigningError::BackendFailure);
        }

        let key = self.key.as_mut().expect("open session");
        let result = key
            .revalidate(self.candidate.reference())
            .map_err(|_| SigningError::BackendFailure)
            .and_then(|()| {
                if key.identity() != self.candidate.identity() {
                    return Err(SigningError::BackendFailure);
                }
                if !key.capabilities().contains(&capability) {
                    return Err(SigningError::UnsupportedOperation);
                }
                key.sign_if_active(algorithm, input, &cancelled)
            });
        self.failed = result.is_err();
        result
    }
}

impl SigningKey for SigningSession {
    fn identity(&self) -> &CertificateIdentity {
        self.candidate.identity()
    }

    fn capabilities(&self) -> &[SigningCapability] {
        self.candidate.capabilities()
    }

    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        self.sign_checked(algorithm, input, || false)
    }
}

struct CancellableKey<'a> {
    session: &'a mut SigningSession,
    cancelled: &'a AtomicBool,
}

impl SigningKey for CancellableKey<'_> {
    fn identity(&self) -> &CertificateIdentity {
        self.session.identity()
    }

    fn capabilities(&self) -> &[SigningCapability] {
        self.session.capabilities()
    }

    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        self.session
            .sign_checked(algorithm, input, || self.cancelled.load(Ordering::Acquire))
    }
}

impl Drop for SigningSession {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let _ = key.close();
        }
    }
}
