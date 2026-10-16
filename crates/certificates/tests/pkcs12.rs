mod common;

use common::{certificate, key, verify_with_cli, MESSAGE};
use firmica_certificates::{CertificateError, Pkcs12Key, MAX_PKCS12_BYTES};
use firmica_signing::{InputKind, SignatureAlgorithm, SigningError, SigningInput, SigningKey};
use openssl::{
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::PKey,
    rsa::Rsa,
    sha::sha256,
    stack::Stack,
};
use secrecy::SecretString;

fn archive(algorithm: SignatureAlgorithm) -> Vec<u8> {
    let key = key(algorithm);
    let cert = certificate(&key, &key);
    let mut chain = Stack::new().unwrap();
    chain.push(certificate(&key, &key)).unwrap();
    Pkcs12::builder()
        .pkey(&key)
        .cert(&cert)
        .ca(chain)
        .build2("synthetic-only ü")
        .unwrap()
        .to_der()
        .unwrap()
}

#[test]
fn rsa_and_ecdsa_messages_and_digests_verify_without_double_hashing() {
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        SignatureAlgorithm::EcdsaP256Sha256,
    ] {
        let der = archive(algorithm);
        let mut provider =
            Pkcs12Key::from_der(&der, &SecretString::from("synthetic-only ü")).unwrap();
        assert_eq!(provider.identity().additional_certificates.len(), 1);
        let certificate =
            openssl::x509::X509::from_der(&provider.identity().certificate_der).unwrap();
        let digest = sha256(MESSAGE);
        let signing_key: &mut dyn SigningKey = &mut provider;
        assert_eq!(signing_key.capabilities().len(), 2);
        assert!(signing_key
            .capabilities()
            .iter()
            .any(|c| c.input == InputKind::Sha256Digest));
        for input in [
            SigningInput::Message(MESSAGE),
            SigningInput::Sha256Digest(&digest),
        ] {
            let signature = signing_key.sign(algorithm, input).unwrap();
            assert_eq!(signature.algorithm, algorithm);
            assert!(verify_with_cli(&certificate, &signature, MESSAGE));
            assert!(!verify_with_cli(
                &certificate,
                &signature,
                b"different document"
            ));
            if algorithm == SignatureAlgorithm::EcdsaP256Sha256 {
                let parsed = EcdsaSig::from_der(&signature.value).unwrap();
                assert_eq!(parsed.to_der().unwrap(), signature.value);
            } else {
                assert_eq!(signature.value.len(), 256);
            }
        }
        let other = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15Sha256 => SignatureAlgorithm::EcdsaP256Sha256,
            _ => SignatureAlgorithm::RsaPkcs1v15Sha256,
        };
        assert_eq!(
            signing_key
                .sign(other, SigningInput::Message(MESSAGE))
                .err(),
            Some(SigningError::UnsupportedOperation)
        );
        // Empty message has defined hashing semantics and must not be confused with no input.
        let signature = signing_key
            .sign(algorithm, SigningInput::Message(b""))
            .unwrap();
        assert!(verify_with_cli(&certificate, &signature, b""));
    }
}

#[test]
fn import_rejects_bad_password_integrity_der_and_nul_without_panicking() {
    let mut der = archive(SignatureAlgorithm::RsaPkcs1v15Sha256);
    let password = SecretString::from("synthetic-only ü");
    assert_eq!(
        Pkcs12Key::from_der(&der, &SecretString::from("wrong")).err(),
        Some(CertificateError::UnlockFailed)
    );
    assert_eq!(
        Pkcs12Key::from_der(&der, &SecretString::from("bad\0password")).err(),
        Some(CertificateError::InvalidPassword)
    );
    for invalid in [vec![], b"not DER".to_vec(), vec![0; MAX_PKCS12_BYTES + 1]] {
        assert_eq!(
            Pkcs12Key::from_der(&invalid, &password).err(),
            Some(CertificateError::InvalidContainer)
        );
    }
    der.push(0);
    assert_eq!(
        Pkcs12Key::from_der(&der, &password).err(),
        Some(CertificateError::InvalidContainer)
    );
    der.pop();
    let last = der.len() - 1;
    der[last] ^= 1;
    assert_eq!(
        Pkcs12Key::from_der(&der, &password).err(),
        Some(CertificateError::UnlockFailed)
    );
}

#[test]
fn unsupported_keys_and_certificates_without_private_keys_are_rejected() {
    let password = SecretString::from("test");
    let issuer = key(SignatureAlgorithm::RsaPkcs1v15Sha256);
    let mut chain = Stack::new().unwrap();
    chain.push(certificate(&issuer, &issuer)).unwrap();
    let der = Pkcs12::builder()
        .ca(chain)
        .build2("test")
        .unwrap()
        .to_der()
        .unwrap();
    assert_eq!(
        Pkcs12Key::from_der(&der, &password).err(),
        Some(CertificateError::MissingIdentity)
    );
    for unsupported in [
        PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap(),
        PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
        )
        .unwrap(),
    ] {
        let cert = certificate(&unsupported, &issuer);
        let der = Pkcs12::builder()
            .pkey(&unsupported)
            .cert(&cert)
            .build2("test")
            .unwrap()
            .to_der()
            .unwrap();
        assert_eq!(
            Pkcs12Key::from_der(&der, &password).err(),
            Some(CertificateError::UnsupportedKey)
        );
    }
}

#[test]
fn empty_password_and_legacy_triple_des_key_encryption_are_handled_explicitly() {
    let algorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
    let key = key(algorithm);
    let cert = certificate(&key, &key);
    for password in ["", "synthetic-only"] {
        let der = Pkcs12::builder()
            .pkey(&key)
            .cert(&cert)
            .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
            .build2(password)
            .unwrap()
            .to_der()
            .unwrap();
        let mut provider = Pkcs12Key::from_der(&der, &SecretString::from(password)).unwrap();
        let signature = provider
            .sign(algorithm, SigningInput::Message(MESSAGE))
            .unwrap();
        assert!(verify_with_cli(&cert, &signature, MESSAGE));
    }
}
