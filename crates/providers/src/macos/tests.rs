use super::*;
use crate::Registry;
use core_foundation::base::TCFType;
use firmica_core::signing::SigningReview;
use firmica_signing::format::{ContentMode, Format, PdfOptions, XmlMode};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    cms::{CMSOptions, CmsContentInfo},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Verifier,
    x509::X509Name,
};
use security_framework::{import_export::Pkcs12ImportOptions, os::macos::keychain::CreateOptions};
use security_framework_sys::base::SecKeychainRef;
use std::sync::atomic::AtomicBool;

extern "C" {
    fn SecKeychainLock(keychain: SecKeychainRef) -> i32;
    fn SecKeychainDelete(keychain: SecKeychainRef) -> i32;
}

const PASSWORD: &str = "synthetic Firmica Keychain test";
const DOCUMENT: &[u8] = b"Firmica Keychain test document";
const RSA: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
const EC: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;

#[test]
fn temporary_keychain_signs_and_rejects_unusable_or_removed_identities() {
    // A hosted test cannot answer authorization prompts. Production discovery uses
    // query-local options and never changes this process-global setting.
    let _interaction = SecKeychain::user_interaction_allowed()
        .unwrap()
        .then(|| SecKeychain::disable_user_interaction().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let mut keychain = CreateOptions::new()
        .password(PASSWORD)
        .create(dir.path().join("fixture.keychain"))
        .unwrap();
    let (rsa, rsa_identity) = import(
        &keychain,
        PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
        1,
    );
    let (p256, p256_identity) = import(&keychain, ec(Nid::X9_62_PRIME256V1), 2);
    let (p384, unsupported_identity) = import(&keychain, ec(Nid::SECP384R1), 3);

    let provider = KeychainProvider {
        keychains: vec![keychain.clone()],
        ..Default::default()
    };
    let id = provider.id().clone();
    let mut registry = Registry::default();
    registry.register(provider).unwrap();
    let candidates = registry.discover(&id).unwrap();
    let by_der = |der: &[u8]| {
        candidates
            .iter()
            .find(|candidate| candidate.identity().certificate_der == der)
            .expect("temporary Keychain identity must be discovered")
    };
    let unsupported = by_der(&p384);
    assert_eq!(unsupported.availability(), Availability::Unavailable);
    assert!(matches!(
        registry.open(Selection::Candidate(unsupported), Credentials::None),
        Err(Error::Unavailable)
    ));

    let rsa_selection = Selection::Candidate(by_der(&rsa));
    let ec_selection = Selection::Candidate(by_der(&p256));
    for (algorithm, selection, der) in [(RSA, rsa_selection, &rsa), (EC, ec_selection, &p256)] {
        exercise(&mut registry, selection, algorithm, der);
    }

    let mut cancelled_session = registry.open(ec_selection, Credentials::None).unwrap();
    assert!(matches!(
        cancelled_session
            .cancellable(&AtomicBool::new(true))
            .sign(EC, SigningInput::Message(DOCUMENT)),
        Err(SigningError::BackendFailure)
    ));
    cancelled_session.close().unwrap();

    let mut locked_session = registry.open(rsa_selection, Credentials::None).unwrap();
    // SAFETY: this is the test's private Keychain. Only its lock state is changed.
    assert_eq!(
        unsafe { SecKeychainLock(keychain.as_concrete_TypeRef()) },
        0
    );
    assert!(locked_session
        .sign(RSA, SigningInput::Message(DOCUMENT))
        .is_err());
    locked_session.close().unwrap();
    keychain.unlock(Some(PASSWORD)).unwrap();

    let mut stale_session = registry.open(rsa_selection, Credentials::None).unwrap();
    rsa_identity.delete().unwrap();
    assert!(stale_session
        .sign(RSA, SigningInput::Message(DOCUMENT))
        .is_err());
    stale_session.close().unwrap();
    assert!(matches!(
        registry.open(rsa_selection, Credentials::None),
        Err(Error::StaleIdentity)
    ));
    drop((p256_identity, unsupported_identity, registry));
    // SAFETY: the test created this Keychain and retains the last local reference.
    assert_eq!(
        unsafe { SecKeychainDelete(keychain.as_concrete_TypeRef()) },
        0
    );
}

fn exercise(
    registry: &mut Registry,
    selection: Selection<'_>,
    algorithm: SignatureAlgorithm,
    certificate: &[u8],
) {
    let certificate = X509::from_der(certificate).unwrap();
    let public_key = certificate.public_key().unwrap();
    for input in [
        SigningInput::Message(DOCUMENT),
        SigningInput::Sha256Digest(&Sha256::digest(DOCUMENT).into()),
    ] {
        let mut session = registry.open(selection, Credentials::None).unwrap();
        let signature = session.sign(algorithm, input).unwrap();
        session.close().unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
        verifier.update(DOCUMENT).unwrap();
        assert!(verifier.verify(&signature.value).unwrap());
    }

    let pdf = include_bytes!("../../../pades/tests/fixtures/document.pdf");
    for (format, document) in [
        (Format::Cades(ContentMode::Attached), DOCUMENT),
        (Format::Pades(PdfOptions::default()), pdf.as_slice()),
        (Format::Xades(XmlMode::Enveloped), b"<document/>".as_slice()),
    ] {
        let mut session = registry.open(selection, Credentials::None).unwrap();
        let review = SigningReview::prepare(
            "synthetic".into(),
            document.to_vec(),
            &session,
            algorithm,
            format.clone(),
        )
        .unwrap();
        let output = review.approve().sign(&mut session).unwrap();
        session.close().unwrap();
        match format {
            Format::Cades(_) => {
                let mut cms = CmsContentInfo::from_der(&output).unwrap();
                let mut content = Vec::new();
                cms.verify(
                    None,
                    None,
                    None,
                    Some(&mut content),
                    CMSOptions::NO_SIGNER_CERT_VERIFY,
                )
                .unwrap();
                assert_eq!(content, DOCUMENT);
            }
            Format::Pades(_) => assert!(output.starts_with(pdf) && output.len() > pdf.len()),
            Format::Xades(_) => assert!(String::from_utf8(output)
                .unwrap()
                .contains("<ds:SignatureValue>")),
        }
    }
}

fn ec(curve: Nid) -> PKey<Private> {
    let group = EcGroup::from_curve_name(curve).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn import(keychain: &SecKeychain, key: PKey<Private>, serial: u32) -> (Vec<u8>, SecIdentity) {
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "Firmica synthetic Keychain signer")
        .unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap())
        .unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate.sign(&key, MessageDigest::sha256()).unwrap();
    let certificate = certificate.build();
    let pkcs12 = Pkcs12::builder()
        .pkey(&key)
        .cert(&certificate)
        // The synthetic fixture uses the file-based Keychain's legacy import format.
        .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .cert_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .mac_md(MessageDigest::sha1())
        .build2(PASSWORD)
        .unwrap()
        .to_der()
        .unwrap();
    let mut items = Pkcs12ImportOptions::new()
        .passphrase(PASSWORD)
        .keychain(keychain.clone())
        .import(&pkcs12)
        .unwrap();
    assert_eq!(items.len(), 1);
    (
        certificate.to_der().unwrap(),
        items.remove(0).identity.unwrap(),
    )
}
