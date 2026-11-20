use der::{
    asn1::{GeneralizedTime, Ia5String, ObjectIdentifier, OctetString},
    oid::AssociatedOid,
    Any, Decode, Encode,
};
use firmica_validation::{
    assess_document_signing, AssessmentError, Restriction, UncheckedCheck, MAX_CERTIFICATE_BYTES,
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509Name, X509},
};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::{
    ext::{
        pkix::{
            certpolicy::{PolicyInformation, PolicyQualifierInfo},
            BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage, KeyUsages,
            PrivateKeyUsagePeriod,
        },
        Extension,
    },
    time::Time,
    Certificate,
};

const NOW: u64 = 1_700_000_000;
fn instant(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn fixture() -> Certificate {
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "Synthetic, untrusted subject")
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(17).unwrap()).unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix((NOW - 60) as i64).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix((NOW + 60) as i64).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    Certificate::from_der(&builder.build().to_der().unwrap()).unwrap()
}

// Mutations intentionally do not re-sign: local restrictions cannot authenticate
// certificate claims. Every resulting assessment must retain that unchecked scope.
fn extend<T: AssociatedOid + Encode>(certificate: &mut Certificate, value: T, critical: bool) {
    raw_extension(certificate, T::OID, value.to_der().unwrap(), critical);
}
fn raw_extension(
    certificate: &mut Certificate,
    oid: ObjectIdentifier,
    value: Vec<u8>,
    critical: bool,
) {
    certificate
        .tbs_certificate
        .extensions
        .get_or_insert_with(Vec::new)
        .push(Extension {
            extn_id: oid,
            critical,
            extn_value: OctetString::new(value).unwrap(),
        });
}
fn restrictions(certificate: &Certificate, seconds: u64) -> Vec<Restriction> {
    assess_document_signing(&certificate.to_der().unwrap(), instant(seconds))
        .unwrap()
        .restrictions()
        .to_vec()
}
fn invalid(certificate: &Certificate) {
    assert_eq!(
        assess_document_signing(&certificate.to_der().unwrap(), instant(NOW)).err(),
        Some(AssessmentError::InvalidCertificate)
    );
}

#[test]
fn reports_claims_and_exact_fingerprint_without_implying_trust() {
    let certificate = fixture();
    let encoded = certificate.to_der().unwrap();
    let report = assess_document_signing(&encoded, instant(NOW)).unwrap();
    assert!(report.permits_local_signing());
    assert_eq!(report.subject(), "CN=Synthetic\\, untrusted subject");
    assert_eq!(report.issuer(), report.subject());
    assert_eq!(report.serial(), &[17]);
    assert_eq!(
        report.fingerprint(),
        &<[u8; 32]>::from(Sha256::digest(&encoded))
    );
    assert_eq!(report.not_before(), instant(NOW - 60));
    assert_eq!(report.not_after(), instant(NOW + 60));
    assert_eq!(report.assessed_at(), instant(NOW));
    assert_eq!(
        report.unchecked_checks(),
        &[
            UncheckedCheck::CertificateSignature,
            UncheckedCheck::CertificationPath,
            UncheckedCheck::Revocation,
            UncheckedCheck::Qualification,
        ]
    );
}

#[test]
fn validity_is_inclusive_and_inverted_periods_are_invalid() {
    let mut certificate = fixture();
    assert!(restrictions(&certificate, NOW - 60).is_empty());
    assert!(restrictions(&certificate, NOW + 60).is_empty());
    assert_eq!(
        restrictions(&certificate, NOW - 61),
        [Restriction::NotYetValid]
    );
    assert_eq!(restrictions(&certificate, NOW + 61), [Restriction::Expired]);
    certificate.tbs_certificate.validity.not_before = Time::try_from(instant(NOW + 61)).unwrap();
    invalid(&certificate);
}

#[test]
fn key_usage_and_ca_restrictions_apply_independently() {
    for usage in [KeyUsages::DigitalSignature, KeyUsages::NonRepudiation] {
        let mut certificate = fixture();
        extend(&mut certificate, KeyUsage(usage.into()), true);
        assert!(restrictions(&certificate, NOW).is_empty());
    }
    let mut certificate = fixture();
    extend(
        &mut certificate,
        KeyUsage(KeyUsages::KeyEncipherment.into()),
        false,
    );
    extend(
        &mut certificate,
        BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        },
        true,
    );
    assert_eq!(
        restrictions(&certificate, NOW),
        [Restriction::KeyUsage, Restriction::CertificateAuthority]
    );
    let mut certificate = fixture();
    extend(
        &mut certificate,
        KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyCertSign),
        true,
    );
    extend(
        &mut certificate,
        BasicConstraints {
            ca: true,
            path_len_constraint: None,
        },
        true,
    );
    assert_eq!(
        restrictions(&certificate, NOW),
        [Restriction::CertificateAuthority]
    );
}

#[test]
fn eku_requires_document_purpose_or_any_usage_when_present() {
    for oid in [
        "1.3.6.1.5.5.7.3.36",
        "1.3.6.1.4.1.311.10.3.12",
        "2.5.29.37.0",
    ] {
        let mut certificate = fixture();
        extend(
            &mut certificate,
            ExtendedKeyUsage(vec![ObjectIdentifier::new(oid).unwrap()]),
            true,
        );
        assert!(restrictions(&certificate, NOW).is_empty());
    }
    for oid in [
        "1.3.6.1.5.5.7.3.1",
        "1.3.6.1.5.5.7.3.2",
        "1.3.6.1.5.5.7.3.3",
        "1.3.6.1.5.5.7.3.4",
        "1.2.840.113583.1.1.5",
    ] {
        let mut certificate = fixture();
        extend(
            &mut certificate,
            ExtendedKeyUsage(vec![ObjectIdentifier::new(oid).unwrap()]),
            false,
        );
        assert_eq!(
            restrictions(&certificate, NOW),
            [Restriction::ExtendedKeyUsage]
        );
    }
    let mut certificate = fixture();
    extend(
        &mut certificate,
        ExtendedKeyUsage(vec![ObjectIdentifier::new("1.3.6.1.5.5.7.3.36").unwrap()]),
        false,
    );
    extend(
        &mut certificate,
        KeyUsage(KeyUsages::KeyEncipherment.into()),
        true,
    );
    assert_eq!(restrictions(&certificate, NOW), [Restriction::KeyUsage]);
}

#[test]
fn fnmt_citizen_profile_document_eku_is_accepted_with_its_key_usage() {
    // FNMT Citizen Profiles v2.6, sections 3 (Usuarios) and 5 (Usuarios G2).
    for key_usage in [
        KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
        KeyUsages::DigitalSignature | KeyUsages::NonRepudiation | KeyUsages::KeyEncipherment,
    ] {
        let mut certificate = fixture();
        extend(&mut certificate, KeyUsage(key_usage), true);
        extend(
            &mut certificate,
            ExtendedKeyUsage(vec![
                ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"),
                ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.12"),
                ObjectIdentifier::new_unwrap("1.2.840.113583.1.1.5"),
            ]),
            false,
        );
        assert!(restrictions(&certificate, NOW).is_empty());
        assert_eq!(restrictions(&certificate, NOW + 61), [Restriction::Expired]);
        raw_extension(
            &mut certificate,
            ObjectIdentifier::new_unwrap("1.2.3.4"),
            vec![5, 0],
            true,
        );
        assert_eq!(
            restrictions(&certificate, NOW),
            [Restriction::UnhandledCriticalExtension]
        );
    }
}

#[test]
fn dnie_authentication_policy_is_blocked_even_without_eku() {
    // DNIe DPC v3.4, section 7.1.2. Neither profile contains an EKU.
    for (id, usage, expected) in [
        ("2.16.724.1.2.2.2.3", KeyUsages::NonRepudiation, &[][..]),
        (
            "2.16.724.1.2.2.2.4",
            KeyUsages::DigitalSignature,
            &[Restriction::KeyUsage][..],
        ),
    ] {
        let mut certificate = fixture();
        extend(&mut certificate, KeyUsage(usage.into()), true);
        extend(
            &mut certificate,
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
            true,
        );
        extend(
            &mut certificate,
            CertificatePolicies(vec![PolicyInformation {
                policy_identifier: ObjectIdentifier::new(id).unwrap(),
                policy_qualifiers: None,
            }]),
            false,
        );
        assert_eq!(restrictions(&certificate, NOW), expected);
        extend(
            &mut certificate,
            ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.36")]),
            false,
        );
        assert_eq!(restrictions(&certificate, NOW), expected);
    }
}

#[test]
fn certificate_policies_are_parsed_without_processing_critical_policy_semantics() {
    let policy = PolicyInformation {
        policy_identifier: ObjectIdentifier::new_unwrap("2.16.724.1.2.2.2.3"),
        policy_qualifiers: Some(vec![PolicyQualifierInfo {
            policy_qualifier_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.1"),
            qualifier: Some(
                Any::encode_from(&Ia5String::new("https://example.invalid/cps").unwrap()).unwrap(),
            ),
        }]),
    };
    for (critical, expected) in [
        (false, &[][..]),
        (true, &[Restriction::UnhandledCriticalExtension][..]),
    ] {
        let mut certificate = fixture();
        extend(
            &mut certificate,
            CertificatePolicies(vec![policy.clone()]),
            critical,
        );
        assert_eq!(restrictions(&certificate, NOW), expected);
    }
    for policies in [vec![], vec![policy.clone(), policy]] {
        let mut certificate = fixture();
        extend(&mut certificate, CertificatePolicies(policies), false);
        invalid(&certificate);
    }
    for qualifiers in [
        vec![],
        vec![PolicyQualifierInfo {
            policy_qualifier_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.1"),
            qualifier: None,
        }],
    ] {
        let mut certificate = fixture();
        extend(
            &mut certificate,
            CertificatePolicies(vec![PolicyInformation {
                policy_identifier: ObjectIdentifier::new_unwrap("2.16.724.1.2.2.2.3"),
                policy_qualifiers: Some(qualifiers),
            }]),
            false,
        );
        invalid(&certificate);
    }
}

#[test]
fn unknown_critical_extensions_block_but_noncritical_ones_do_not() {
    for critical in [false, true] {
        let mut certificate = fixture();
        raw_extension(
            &mut certificate,
            ObjectIdentifier::new_unwrap("1.2.3.4"),
            vec![5, 0],
            critical,
        );
        assert_eq!(
            restrictions(&certificate, NOW),
            if critical {
                vec![Restriction::UnhandledCriticalExtension]
            } else {
                vec![]
            }
        );
    }
}

#[test]
fn duplicates_and_malformed_constraints_never_become_permission() {
    let mut certificate = fixture();
    for _ in 0..2 {
        raw_extension(
            &mut certificate,
            ObjectIdentifier::new_unwrap("1.2.3.4"),
            vec![5, 0],
            false,
        );
    }
    invalid(&certificate);
    for oid in [
        KeyUsage::OID,
        ExtendedKeyUsage::OID,
        BasicConstraints::OID,
        CertificatePolicies::OID,
        PrivateKeyUsagePeriod::OID,
    ] {
        let mut certificate = fixture();
        raw_extension(&mut certificate, oid, vec![5, 0], false);
        invalid(&certificate);
    }
    let mut certificate = fixture();
    extend(&mut certificate, KeyUsage(Default::default()), true);
    invalid(&certificate);
    let mut certificate = fixture();
    extend(&mut certificate, ExtendedKeyUsage(vec![]), false);
    invalid(&certificate);
    let mut certificate = fixture();
    extend(
        &mut certificate,
        BasicConstraints {
            ca: false,
            path_len_constraint: Some(0),
        },
        true,
    );
    invalid(&certificate);
    let mut certificate = fixture();
    extend(
        &mut certificate,
        KeyUsage(KeyUsages::DigitalSignature | KeyUsages::EncipherOnly),
        true,
    );
    invalid(&certificate);
    // A digitalSignature bit plus an unknown bit. FlagSet alone truncates the latter.
    let mut certificate = fixture();
    raw_extension(
        &mut certificate,
        KeyUsage::OID,
        vec![3, 3, 6, 0x80, 0x40],
        true,
    );
    invalid(&certificate);
}

#[test]
fn private_key_usage_period_is_enforced_even_when_noncritical() {
    let mut certificate = fixture();
    let start = GeneralizedTime::from_system_time(instant(NOW - 10)).unwrap();
    let end = GeneralizedTime::from_system_time(instant(NOW + 10)).unwrap();
    extend(
        &mut certificate,
        PrivateKeyUsagePeriod {
            not_before: Some(start),
            not_after: Some(end),
        },
        false,
    );
    assert!(restrictions(&certificate, NOW - 10).is_empty());
    assert!(restrictions(&certificate, NOW + 10).is_empty());
    assert_eq!(
        restrictions(&certificate, NOW - 11),
        [Restriction::PrivateKeyNotYetValid]
    );
    assert_eq!(
        restrictions(&certificate, NOW + 11),
        [Restriction::PrivateKeyExpired]
    );
    for period in [
        PrivateKeyUsagePeriod {
            not_before: None,
            not_after: None,
        },
        PrivateKeyUsagePeriod {
            not_before: Some(end),
            not_after: Some(start),
        },
    ] {
        let mut certificate = fixture();
        extend(&mut certificate, period, false);
        invalid(&certificate);
    }
    for period in [
        PrivateKeyUsagePeriod {
            not_before: Some(start),
            not_after: None,
        },
        PrivateKeyUsagePeriod {
            not_before: None,
            not_after: Some(end),
        },
    ] {
        let mut certificate = fixture();
        extend(&mut certificate, period, false);
        assert!(restrictions(&certificate, NOW).is_empty());
    }
}

#[test]
fn rejects_empty_malformed_trailing_and_oversize_der() {
    let mut certificate = fixture();
    certificate.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::from_der(&[2, 1, 0xff]).unwrap();
    invalid(&certificate);
    for encoded in [vec![], vec![0x30, 0], {
        let mut bytes = fixture().to_der().unwrap();
        bytes.push(0);
        bytes
    }] {
        assert_eq!(
            assess_document_signing(&encoded, instant(NOW)).err(),
            Some(AssessmentError::InvalidCertificate)
        );
    }
    assert_eq!(
        assess_document_signing(&vec![0; MAX_CERTIFICATE_BYTES + 1], instant(NOW)).err(),
        Some(AssessmentError::InputTooLarge)
    );
}
