//! Local restrictions on using a leaf certificate for document signing.
//!
//! Checks validity, key usage, extended key usage, basic constraints and private-key
//! usage periods. Unhandled critical extensions block signing. This is **not** an
//! RFC 5280 path validator: certificate signatures, issuer chains, trust anchors,
//! revocation and legal qualification are not assessed. Subject and issuer names
//! are untrusted certificate claims, even when no local restriction blocks signing.
//!
//! Absent KU/EKU extensions impose no restriction. When KU is present it must allow
//! digitalSignature or contentCommitment. When EKU is present it must include
//! id-kp-documentSigning (RFC 9336) or anyExtendedKeyUsage. TLS, code-signing and
//! email-only purposes are not treated as permission to sign arbitrary documents.
//! CA certificates and keys marked keyCertSign are excluded by application policy.
//! See [RFC 5280 §4.2](https://www.rfc-editor.org/rfc/rfc5280#section-4.2)
//! and [RFC 9336](https://www.rfc-editor.org/rfc/rfc9336).
//!
//! No files, network, native crypto libraries or system trust stores are accessed.
//! The selected signing provider remains responsible for key/algorithm support and
//! verification of its output. These checks do not authorize use of a private key.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use der::{
    asn1::{ObjectIdentifier, UintRef},
    Decode, Encode,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::SystemTime};
use x509_cert::{
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, PrivateKeyUsagePeriod},
    Certificate,
};

/// Maximum encoded leaf size accepted before ASN.1 parsing (64 KiB).
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

const DOCUMENT_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.36");
const ANY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");

/// Checks deliberately outside the local assessment's scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UncheckedCheck {
    /// The issuer's signature over this certificate has not been verified.
    CertificateSignature,
    /// No certification path to a configured trust anchor has been validated.
    CertificationPath,
    /// No OCSP or CRL evidence has been checked.
    Revocation,
    /// No trusted-list or legal qualification assessment has been performed.
    Qualification,
}

/// Conditions that block local document signing without claiming a trust decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Restriction {
    /// The assessment time precedes the certificate's notBefore value.
    #[error("certificate is not yet valid")]
    NotYetValid,
    /// The assessment time follows the certificate's notAfter value.
    #[error("certificate has expired")]
    Expired,
    /// Basic constraints or key usage designate a certification authority key.
    #[error("CA keys are not permitted for document signing")]
    CertificateAuthority,
    /// KU is present without digitalSignature or contentCommitment.
    #[error("key usage does not permit document signing")]
    KeyUsage,
    /// EKU is present without documentSigning or anyExtendedKeyUsage.
    #[error("extended key usage does not permit document signing")]
    ExtendedKeyUsage,
    /// A critical extension has not been processed by this assessment.
    #[error("certificate has an unhandled critical extension")]
    UnhandledCriticalExtension,
    /// The private-key usage period has not begun.
    #[error("private-key usage period has not begun")]
    PrivateKeyNotYetValid,
    /// The private-key usage period has ended.
    #[error("private-key usage period has ended")]
    PrivateKeyExpired,
}

/// Failures to obtain a reliable local assessment; contains no certificate data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AssessmentError {
    /// Encoded certificate exceeds the bound checked before parsing.
    #[error("certificate exceeds the assessment size limit")]
    InputTooLarge,
    /// Invalid DER, duplicate extensions, malformed processed constraints or inverted dates.
    #[error("invalid certificate or signing constraints")]
    InvalidCertificate,
}

/// Immutable certificate claims and local restrictions at one instant.
///
/// Deliberately has no `Debug` implementation to avoid logging personal names.
pub struct CertificateAssessment {
    subject: String,
    issuer: String,
    serial: Vec<u8>,
    fingerprint: [u8; 32],
    not_before: SystemTime,
    not_after: SystemTime,
    assessed_at: SystemTime,
    restrictions: Vec<Restriction>,
}

impl CertificateAssessment {
    /// Claimed subject in RFC 4514 form. Treat as untrusted display text.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Claimed issuer in RFC 4514 form; does not establish a certification path.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Unsigned, big-endian serial bytes as represented by the X.509 parser.
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// SHA-256 of the exact, complete DER certificate, suitable for review binding.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Inclusive start of the claimed certificate validity period.
    pub fn not_before(&self) -> SystemTime {
        self.not_before
    }

    /// Inclusive end of the claimed certificate validity period.
    pub fn not_after(&self) -> SystemTime {
        self.not_after
    }

    /// Clock instant supplied to [`assess_document_signing`].
    pub fn assessed_at(&self) -> SystemTime {
        self.assessed_at
    }

    /// All detected local restrictions, without duplicates.
    pub fn restrictions(&self) -> &[Restriction] {
        &self.restrictions
    }

    /// Whether local constraints permit signing at the assessment instant.
    /// This does not establish trust, revocation status or authorization.
    pub fn permits_local_signing(&self) -> bool {
        self.restrictions.is_empty()
    }

    /// Unperformed checks that must remain visible when presenting the assessment.
    pub fn unchecked_checks(&self) -> &'static [UncheckedCheck] {
        &[
            UncheckedCheck::CertificateSignature,
            UncheckedCheck::CertificationPath,
            UncheckedCheck::Revocation,
            UncheckedCheck::Qualification,
        ]
    }
}

/// Assess a leaf at an explicit clock instant without authorizing a signature.
///
/// Reassess immediately before signing; an assessment is not a durable permission.
/// Validity and private-key usage endpoints are inclusive, with the supplied clock's
/// precision. Unknown noncritical extensions are ignored. Known constraints are
/// parsed regardless of criticality. Malformed constraints never become permission.
///
/// # Errors
/// Returns an error for oversize/noncanonical DER, any duplicate extension, an empty
/// KU/EKU/private-key period, negative serial, or inverted validity/usage periods. Other blocking
/// conditions are retained in [`CertificateAssessment::restrictions`]. The parser's
/// UTCTime support begins in 1970; certificates with earlier UTCTime dates fail.
pub fn assess_document_signing(
    encoded: &[u8],
    now: SystemTime,
) -> Result<CertificateAssessment, AssessmentError> {
    use AssessmentError::InvalidCertificate;
    if encoded.len() > MAX_CERTIFICATE_BYTES {
        return Err(AssessmentError::InputTooLarge);
    }
    let certificate = Certificate::from_der(encoded).map_err(|_| InvalidCertificate)?;
    if certificate.to_der().map_err(|_| InvalidCertificate)? != encoded {
        return Err(InvalidCertificate);
    }
    let tbs = &certificate.tbs_certificate;
    // x509-cert also decodes negative serials for compatibility. Do not expose
    // their two's-complement bytes as an unsigned serial in the review metadata.
    let serial_der = tbs.serial_number.to_der().map_err(|_| InvalidCertificate)?;
    let serial = UintRef::from_der(&serial_der).map_err(|_| InvalidCertificate)?;
    let not_before = tbs.validity.not_before.to_system_time();
    let not_after = tbs.validity.not_after.to_system_time();
    if not_before > not_after {
        return Err(InvalidCertificate);
    }
    let mut report = CertificateAssessment {
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        serial: serial.as_bytes().to_vec(),
        fingerprint: Sha256::digest(encoded).into(),
        not_before,
        not_after,
        assessed_at: now,
        restrictions: Vec::new(),
    };
    let mut restrict = |restriction| {
        if !report.restrictions.contains(&restriction) {
            report.restrictions.push(restriction);
        }
    };
    if now < not_before {
        restrict(Restriction::NotYetValid);
    }
    if now > not_after {
        restrict(Restriction::Expired);
    }
    let mut seen = BTreeSet::new();
    for extension in tbs.extensions.iter().flatten() {
        if !seen.insert(extension.extn_id) {
            return Err(InvalidCertificate);
        }
        let bytes = extension.extn_value.as_bytes();
        match extension.extn_id {
            <KeyUsage as der::oid::AssociatedOid>::OID => {
                let usage = decode_constraint::<KeyUsage>(bytes)?;
                if usage.0.is_empty()
                    || ((usage.encipher_only() || usage.decipher_only()) && !usage.key_agreement())
                {
                    return Err(InvalidCertificate);
                }
                if usage.key_cert_sign() {
                    restrict(Restriction::CertificateAuthority);
                }
                if !usage.digital_signature() && !usage.non_repudiation() {
                    restrict(Restriction::KeyUsage);
                }
            }
            <BasicConstraints as der::oid::AssociatedOid>::OID => {
                let constraints = decode_constraint::<BasicConstraints>(bytes)?;
                if !constraints.ca && constraints.path_len_constraint.is_some() {
                    return Err(InvalidCertificate);
                }
                if constraints.ca {
                    restrict(Restriction::CertificateAuthority);
                }
            }
            <ExtendedKeyUsage as der::oid::AssociatedOid>::OID => {
                let usage = decode_constraint::<ExtendedKeyUsage>(bytes)?;
                if usage.0.is_empty() {
                    return Err(InvalidCertificate);
                }
                if !usage.0.contains(&DOCUMENT_SIGNING) && !usage.0.contains(&ANY_USAGE) {
                    restrict(Restriction::ExtendedKeyUsage);
                }
            }
            <PrivateKeyUsagePeriod as der::oid::AssociatedOid>::OID => {
                let period = decode_constraint::<PrivateKeyUsagePeriod>(bytes)?;
                let start = period.not_before.map(|time| time.to_system_time());
                let end = period.not_after.map(|time| time.to_system_time());
                if (start.is_none() && end.is_none())
                    || matches!((start, end), (Some(start), Some(end)) if start > end)
                {
                    return Err(InvalidCertificate);
                }
                if start.is_some_and(|start| now < start) {
                    restrict(Restriction::PrivateKeyNotYetValid);
                }
                if end.is_some_and(|end| now > end) {
                    restrict(Restriction::PrivateKeyExpired);
                }
            }
            _ if extension.critical => restrict(Restriction::UnhandledCriticalExtension),
            _ => {}
        }
    }
    Ok(report)
}

// Extension OCTET STRING contents are opaque to the outer certificate decoder.
// In particular FlagSet decoding truncates unknown KU bits; round-trip the value
// itself so unknown bits and noncanonical constraint encodings cannot disappear.
fn decode_constraint<'a, T: Decode<'a> + Encode>(bytes: &'a [u8]) -> Result<T, AssessmentError> {
    let value = T::from_der(bytes).map_err(|_| AssessmentError::InvalidCertificate)?;
    if value
        .to_der()
        .map_err(|_| AssessmentError::InvalidCertificate)?
        != bytes
    {
        return Err(AssessmentError::InvalidCertificate);
    }
    Ok(value)
}
