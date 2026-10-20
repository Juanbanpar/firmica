use super::*;
use firmica_cades::ContentMode;
use firmica_signing::{InputKind, Signature, SigningCapability, SigningError, SigningInput};
use std::time::{Duration, UNIX_EPOCH};

const RSA: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
const EC: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;
// Public, self-signed P-256 certificate with CA:FALSE, digitalSignature and
// documentSigning EKU. No private key is retained. Tests derive their clock from
// its encoded period, so they remain deterministic after the fixture expires.
const CERTIFICATE: &[u8] = include_bytes!("fixtures/document-signer.der");
const DOCUMENT: &[u8] = b"document\x00\xff\r\n";

#[test]
fn formats_remain_bound_to_review_and_share_one_use_certificate_checks() {
    use firmica_signing::format::{PdfOptions, XmlMode};
    let pdf = include_bytes!("../../../pades/tests/fixtures/document.pdf");
    for (format, document) in [
        (Format::Pades(PdfOptions::default()), pdf.as_slice()),
        (Format::Xades(XmlMode::Enveloped), b"<document/>".as_slice()),
        (Format::Xades(XmlMode::Enveloping), DOCUMENT),
        (Format::Xades(XmlMode::Detached), DOCUMENT),
    ] {
        let mut key = CountingKey::new();
        let pending = SigningReview::prepare_at(
            "test".into(),
            document.to_vec(),
            &key,
            EC,
            format.clone(),
            period().0,
        )
        .unwrap();
        assert_eq!(pending.format(), &format);
        assert_eq!(key.calls, 0);
        assert!(pending.approve().sign_at(&mut key, period().0).is_err());
        assert_eq!(
            key.calls, 1,
            "a format must reach the existing provider exactly once"
        );
        let approved = SigningReview::prepare_at(
            "test".into(),
            document.to_vec(),
            &key,
            EC,
            format,
            period().0,
        )
        .unwrap()
        .approve();
        key.identity
            .additional_certificates
            .push(CERTIFICATE.to_vec());
        assert_eq!(
            approved.sign_at(&mut key, period().0),
            Err(ApprovalError::IdentityChanged)
        );
        assert_eq!(key.calls, 1);
    }
    let key = CountingKey::new();
    assert!(matches!(
        SigningReview::prepare_at(
            "test".into(),
            DOCUMENT.to_vec(),
            &key,
            EC,
            Format::Pades(PdfOptions::default()),
            period().0
        ),
        Err(ApprovalError::Pades(_))
    ));
    assert!(matches!(
        SigningReview::prepare_at(
            "test".into(),
            b"<!DOCTYPE r><r/>".to_vec(),
            &key,
            EC,
            Format::Xades(XmlMode::Enveloped),
            period().0
        ),
        Err(ApprovalError::Xades(_))
    ));
    assert_eq!(key.calls, 0);
}

struct CountingKey {
    identity: CertificateIdentity,
    capabilities: Vec<SigningCapability>,
    calls: usize,
}

impl CountingKey {
    fn new() -> Self {
        Self {
            identity: CertificateIdentity {
                certificate_der: CERTIFICATE.to_vec(),
                additional_certificates: Vec::new(),
            },
            capabilities: vec![SigningCapability {
                algorithm: EC,
                input: InputKind::Message,
            }],
            calls: 0,
        }
    }
}

impl SigningKey for CountingKey {
    fn identity(&self) -> &CertificateIdentity {
        &self.identity
    }
    fn capabilities(&self) -> &[SigningCapability] {
        &self.capabilities
    }
    fn sign(
        &mut self,
        _: SignatureAlgorithm,
        _: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        self.calls += 1;
        Err(SigningError::BackendFailure)
    }
}

fn period() -> (SystemTime, SystemTime) {
    let report = assess_document_signing(CERTIFICATE, UNIX_EPOCH).unwrap();
    (report.not_before(), report.not_after())
}
fn review(key: &CountingKey) -> SigningReview {
    SigningReview::prepare_at(
        "synthetic.bin".into(),
        DOCUMENT.to_vec(),
        key,
        EC,
        ContentMode::Detached,
        period().0,
    )
    .unwrap()
}

#[test]
fn preparing_and_cancelling_never_use_the_key() {
    let key = CountingKey::new();
    let pending = review(&key);
    assert_eq!(pending.document_name(), "synthetic.bin");
    assert_eq!(pending.document_size(), DOCUMENT.len());
    assert_eq!(
        pending.document_hash(),
        &<[u8; 32]>::from(Sha256::digest(DOCUMENT))
    );
    assert_eq!(pending.algorithm(), EC);
    assert_eq!(pending.format(), &Format::Cades(ContentMode::Detached));
    assert_eq!(
        pending.certificate().fingerprint(),
        &<[u8; 32]>::from(Sha256::digest(CERTIFICATE))
    );
    assert_eq!(pending.certificate().unchecked_checks().len(), 4);
    drop(pending);
    assert_eq!(key.calls, 0);
}

#[test]
fn approval_consumes_one_attempt_and_propagates_provider_failure() {
    let mut key = CountingKey::new();
    let approved = review(&key).approve();
    assert_eq!(key.calls, 0);
    assert_eq!(
        approved.sign_at(&mut key, period().0),
        Err(ApprovalError::Cades(firmica_cades::CadesError::Signing(
            SigningError::BackendFailure
        )))
    );
    assert_eq!(key.calls, 1);
}

#[test]
fn changed_leaf_or_additional_certificates_block_execution() {
    for change_leaf in [false, true] {
        let mut key = CountingKey::new();
        let approved = review(&key).approve();
        if change_leaf {
            key.identity.certificate_der.push(0);
        } else {
            key.identity
                .additional_certificates
                .push(CERTIFICATE.to_vec());
        }
        assert_eq!(
            approved.sign_at(&mut key, period().0),
            Err(ApprovalError::IdentityChanged)
        );
        assert_eq!(key.calls, 0);
    }
}

#[test]
fn lost_capability_blocks_execution_without_using_the_key() {
    let mut key = CountingKey::new();
    let approved = review(&key).approve();
    key.capabilities.clear();
    assert_eq!(
        approved.sign_at(&mut key, period().0),
        Err(ApprovalError::UnsupportedAlgorithm)
    );
    assert_eq!(key.calls, 0);
}

#[test]
fn expiry_and_clock_rollback_are_rechecked_after_approval() {
    let (start, end) = period();
    // Windows SystemTime uses 100 ns intervals; 1 ns arithmetic rounds to zero.
    for (time, expected) in [
        (start - Duration::from_millis(1), Restriction::NotYetValid),
        (end + Duration::from_millis(1), Restriction::Expired),
    ] {
        let mut key = CountingKey::new();
        let approved = review(&key).approve();
        assert_eq!(
            approved.sign_at(&mut key, time),
            Err(ApprovalError::CertificateRestricted(vec![expected]))
        );
        assert_eq!(key.calls, 0);
    }
}

#[test]
fn preflight_rejects_invalid_names_limits_certificates_and_algorithms() {
    let mut key = CountingKey::new();
    let now = period().0;
    for name in [String::new(), " \n\t".into(), "x".repeat(4097)] {
        assert_eq!(
            SigningReview::prepare_at(name, vec![], &key, EC, ContentMode::Attached, now).err(),
            Some(ApprovalError::InvalidDocumentName)
        );
    }
    assert_eq!(
        SigningReview::prepare_at("test".into(), vec![], &key, RSA, ContentMode::Attached, now)
            .err(),
        Some(ApprovalError::UnsupportedAlgorithm)
    );
    assert_eq!(
        SigningReview::prepare_at(
            "test".into(),
            vec![0; MAX_CONTENT_BYTES + 1],
            &key,
            EC,
            ContentMode::Attached,
            now
        )
        .err(),
        Some(ApprovalError::InputTooLarge)
    );
    key.identity.additional_certificates = vec![CERTIFICATE.to_vec(); MAX_CERTIFICATES];
    assert_eq!(
        SigningReview::prepare_at("test".into(), vec![], &key, EC, ContentMode::Attached, now)
            .err(),
        Some(ApprovalError::InputTooLarge)
    );
    key.identity.additional_certificates.clear();
    key.identity.certificate_der = vec![0; MAX_CERTIFICATE_BYTES + 1];
    assert_eq!(
        SigningReview::prepare_at("test".into(), vec![], &key, EC, ContentMode::Attached, now)
            .err(),
        Some(ApprovalError::InputTooLarge)
    );
    key.identity.certificate_der = vec![0];
    assert_eq!(
        SigningReview::prepare_at("test".into(), vec![], &key, EC, ContentMode::Attached, now)
            .err(),
        Some(ApprovalError::Assessment(
            AssessmentError::InvalidCertificate
        ))
    );
    assert_eq!(key.calls, 0);
}

#[test]
fn expired_certificate_cannot_be_prepared_and_empty_documents_are_supported() {
    let mut key = CountingKey::new();
    assert_eq!(
        SigningReview::prepare_at(
            "test".into(),
            vec![],
            &key,
            EC,
            ContentMode::Attached,
            period().1 + Duration::from_secs(1)
        )
        .err(),
        Some(ApprovalError::CertificateRestricted(vec![
            Restriction::Expired
        ]))
    );
    let pending = SigningReview::prepare_at(
        "empty.bin".into(),
        vec![],
        &key,
        EC,
        ContentMode::Attached,
        period().0,
    )
    .unwrap();
    assert_eq!(pending.document_size(), 0);
    assert!(pending.approve().sign_at(&mut key, period().0).is_err());
    assert_eq!(key.calls, 1);
}

#[test]
fn malformed_additional_certificate_is_rejected_before_the_private_key() {
    let mut key = CountingKey::new();
    key.identity.additional_certificates.push(vec![0]);
    let approved = review(&key).approve();
    assert_eq!(
        approved.sign_at(&mut key, period().0),
        Err(ApprovalError::Cades(
            firmica_cades::CadesError::InvalidCertificate
        ))
    );
    assert_eq!(key.calls, 0);
}
