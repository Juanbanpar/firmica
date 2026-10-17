//! One-shot approval bound to an owned document and selected certificate identity.
//!
//! This API supports standalone CAdES operations. It is not connected to browser
//! requests or application controls. Preparing a review does not sign anything;
//! applications must display its details and obtain explicit consent before calling
//! [`CadesReview::approve`]. The type transition records the caller's decision, not
//! proof of human presence. Low-level signing APIs remain available independently.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use firmica_cades::{
    ContentMode, SigningOptions, MAX_CERTIFICATES, MAX_CERTIFICATE_BYTES, MAX_CONTENT_BYTES,
};
use firmica_signing::{CertificateIdentity, SignatureAlgorithm, SigningKey};
use firmica_validation::{
    assess_document_signing, AssessmentError, CertificateAssessment, Restriction,
};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// Static failures or local restrictions; never includes names, document bytes or secrets.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApprovalError {
    /// A display name is empty, all whitespace or longer than 4096 UTF-8 bytes.
    #[error("invalid document display name")]
    InvalidDocumentName,
    /// Document size or certificate count/size exceeds the CAdES encoder limits.
    #[error("signing review exceeds an input limit")]
    InputTooLarge,
    /// The selected leaf cannot be assessed.
    #[error(transparent)]
    Assessment(#[from] AssessmentError),
    /// Local leaf restrictions block signing; these are not trust findings.
    #[error("certificate constraints block document signing")]
    CertificateRestricted(Vec<Restriction>),
    /// The key no longer advertises a usable operation for the chosen algorithm.
    #[error("selected key does not support the chosen algorithm")]
    UnsupportedAlgorithm,
    /// Leaf or additional certificates differ from the identity reviewed by the user.
    #[error("selected certificate identity changed after review")]
    IdentityChanged,
    /// CAdES validation, encoding or the signing provider failed.
    #[error(transparent)]
    Cades(#[from] firmica_cades::CadesError),
}

/// Immutable review of one owned document, algorithm, content mode and identity.
///
/// Has no signing operation, `Clone` or `Debug`. Drop to cancel. Neither the
/// document nor certificate identity can be replaced after construction.
pub struct CadesReview {
    name: String,
    document: Vec<u8>,
    document_hash: [u8; 32],
    identity: CertificateIdentity,
    algorithm: SignatureAlgorithm,
    mode: ContentMode,
    assessment: CertificateAssessment,
}

impl CadesReview {
    /// Prepare a review without invoking the private key or accessing files/network.
    ///
    /// Owns the exact bytes to avoid a file changing between review and signing.
    /// Empty documents are supported. Certificate validity uses the local system
    /// clock. The display name is an untrusted label, never a path to open later.
    ///
    /// # Errors
    /// Rejects input limits, malformed leaf certificates, local certificate
    /// restrictions and unsupported algorithms. Additional certificates are bounded
    /// here and parsed by the encoder before any private-key operation.
    pub fn prepare(
        name: String,
        document: Vec<u8>,
        key: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        mode: ContentMode,
    ) -> Result<Self, ApprovalError> {
        Self::prepare_at(name, document, key, algorithm, mode, SystemTime::now())
    }

    fn prepare_at(
        name: String,
        document: Vec<u8>,
        key: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        mode: ContentMode,
        now: SystemTime,
    ) -> Result<Self, ApprovalError> {
        if name.len() > 4096 || name.trim().is_empty() {
            return Err(ApprovalError::InvalidDocumentName);
        }
        let identity = key.identity();
        if document.len() > MAX_CONTENT_BYTES
            || identity.additional_certificates.len() >= MAX_CERTIFICATES
            || std::iter::once(&identity.certificate_der)
                .chain(&identity.additional_certificates)
                .any(|encoded| encoded.len() > MAX_CERTIFICATE_BYTES)
        {
            return Err(ApprovalError::InputTooLarge);
        }
        require_capability(key, algorithm)?;
        let assessment = permitted_assessment(&identity.certificate_der, now)?;
        Ok(Self {
            name,
            document_hash: Sha256::digest(&document).into(),
            document,
            identity: identity.clone(),
            algorithm,
            mode,
            assessment,
        })
    }

    /// Selected document's untrusted display label. Escape it when rendering.
    pub fn document_name(&self) -> &str {
        &self.name
    }

    /// Exact number of selected bytes, including for detached signatures.
    pub fn document_size(&self) -> usize {
        self.document.len()
    }

    /// SHA-256 of the exact document bytes retained by this review.
    pub fn document_hash(&self) -> &[u8; 32] {
        &self.document_hash
    }

    /// Explicitly chosen hash/key algorithm; no implicit algorithm selection.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Whether the resulting CAdES embeds the document bytes.
    pub fn content_mode(&self) -> ContentMode {
        self.mode
    }

    /// Leaf claims, local restrictions and unperformed trust/revocation checks.
    pub fn certificate(&self) -> &CertificateAssessment {
        &self.assessment
    }

    /// Record explicit approval of this exact review, consuming the pending state.
    ///
    /// Call only after presenting the document name, size/hash, selected certificate,
    /// algorithm, content mode and **all unperformed checks**. Local constraints do
    /// not establish issuer authenticity, chain trust, revocation or qualification;
    /// consent must not describe the certificate as trusted or fully validated.
    /// Approval is neither cloneable nor reusable after an execution attempt.
    pub fn approve(self) -> ApprovedCades {
        ApprovedCades(self)
    }
}

/// Approval for one execution attempt. Has no `Clone` or `Debug` implementation.
pub struct ApprovedCades(CadesReview);

impl ApprovedCades {
    /// Recheck the selected identity, capability and certificate constraints, then sign.
    ///
    /// Consumes approval on success or failure. Uses the local clock immediately
    /// before encoding; the resulting signing-time attribute is not a trusted time.
    /// The provider must honor the [`SigningKey`] contract, including verification
    /// against its selected certificate. Perform this blocking work off the UI loop.
    ///
    /// **Before publishing any returned bytes**, complete the provider's required
    /// cleanup and check its result (for example, `WorkerKey::close`). Cleanup failure
    /// must discard the signature. This borrowed-key API does not close the provider.
    ///
    /// # Errors
    /// Identity changes, lost capability, newly applicable restrictions and encoder/
    /// provider errors return no output. Preflight failures do not invoke the key.
    pub fn sign(self, key: &mut dyn SigningKey) -> Result<Vec<u8>, ApprovalError> {
        self.sign_at(key, SystemTime::now())
    }

    fn sign_at(self, key: &mut dyn SigningKey, now: SystemTime) -> Result<Vec<u8>, ApprovalError> {
        let review = self.0;
        if key.identity() != &review.identity {
            return Err(ApprovalError::IdentityChanged);
        }
        require_capability(key, review.algorithm)?;
        let assessment = permitted_assessment(&review.identity.certificate_der, now)?;
        Ok(firmica_cades::sign(
            key,
            &review.document,
            SigningOptions {
                algorithm: review.algorithm,
                mode: review.mode,
                signing_time: assessment.assessed_at(),
            },
        )?)
    }
}

fn require_capability(
    key: &dyn SigningKey,
    algorithm: SignatureAlgorithm,
) -> Result<(), ApprovalError> {
    if key
        .capabilities()
        .iter()
        .any(|capability| capability.algorithm == algorithm)
    {
        Ok(())
    } else {
        Err(ApprovalError::UnsupportedAlgorithm)
    }
}

fn permitted_assessment(
    encoded: &[u8],
    now: SystemTime,
) -> Result<CertificateAssessment, ApprovalError> {
    let assessment = assess_document_signing(encoded, now)?;
    if !assessment.permits_local_signing() {
        return Err(ApprovalError::CertificateRestricted(
            assessment.restrictions().to_vec(),
        ));
    }
    Ok(assessment)
}

#[cfg(test)]
mod tests;
