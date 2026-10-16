#![cfg(feature = "pkcs11")]

mod common;

use common::{certificate, key, verify_cades_with_cli, verify_with_cli, MESSAGE};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeInfo, AttributeType},
    session::UserType,
    types::AuthPin,
};
use der::{asn1::OctetStringRef, Decode};
use firmica_cades::{sign, ContentMode, SigningOptions};
use firmica_certificates::{pkcs11::Pkcs11Key, CertificateError};
use firmica_signing::{SignatureAlgorithm, SigningError, SigningInput, SigningKey};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    sha::sha256,
};
use std::{env, fs, process::Command};

#[test]
#[ignore = "requires explicit FIRMICA_PKCS11_MODULE pointing to SoftHSM, and softhsm2-util"]
fn non_exportable_rsa_and_ecdsa_keys_use_the_shared_contract(
) -> Result<(), Box<dyn std::error::Error>> {
    // This test creates its own token store. It must never open a user's existing store.
    let module = env::var("FIRMICA_PKCS11_MODULE")?;
    let temporary = tempfile::tempdir()?;
    let tokens = temporary.path().join("tokens");
    fs::create_dir(&tokens)?;
    let config = temporary.path().join("softhsm2.conf");
    fs::write(
        &config,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )?;
    // Only one test in this integration-test process uses environment/native module state.
    env::set_var("SOFTHSM2_CONF", &config);
    let initialize = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "firmica-synthetic",
            "--so-pin",
            "synthetic-so-1234",
            "--pin",
            "synthetic-user-1234",
        ])
        .output()?;
    assert!(
        initialize.status.success(),
        "{}",
        String::from_utf8_lossy(&initialize.stderr)
    );
    let module = Pkcs11::new(module)?;
    module.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    assert!(
        module
            .get_library_info()?
            .manufacturer_id()
            .contains("SoftHSM"),
        "refusing token operations: this test requires the SoftHSM module"
    );
    let slot = module
        .get_slots_with_token()?
        .into_iter()
        .find(|slot| {
            module
                .get_token_info(*slot)
                .is_ok_and(|info| info.label() == "firmica-synthetic")
        })
        .expect("the isolated synthetic token must exist");
    let session = module.open_rw_session(slot)?;
    assert!(session
        .login(UserType::User, Some(&AuthPin::new("wrong-pin".into())))
        .is_err());
    session.close()?;
    let session = module.open_rw_session(slot)?;
    session.login(
        UserType::User,
        Some(&AuthPin::new("synthetic-user-1234".into())),
    )?;
    let issuer = key(SignatureAlgorithm::RsaPkcs1v15Sha256);
    let mut produced = Vec::new();
    let mut cades = Vec::new();
    let operation = (|| -> Result<(), Box<dyn std::error::Error>> {
        for algorithm in [
            SignatureAlgorithm::RsaPkcs1v15Sha256,
            SignatureAlgorithm::EcdsaP256Sha256,
        ] {
            let mut public_template = vec![Attribute::Token(false), Attribute::Verify(true)];
            let private_template = vec![
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::Sign(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::AlwaysAuthenticate(false),
            ];
            let mechanism = match algorithm {
                SignatureAlgorithm::RsaPkcs1v15Sha256 => {
                    public_template.extend([
                        Attribute::ModulusBits(2048.into()),
                        Attribute::PublicExponent(vec![1, 0, 1]),
                    ]);
                    Mechanism::RsaPkcsKeyPairGen
                }
                SignatureAlgorithm::EcdsaP256Sha256 => {
                    // DER OID 1.2.840.10045.3.1.7 (NIST P-256).
                    public_template.push(Attribute::EcParams(vec![
                        6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
                    ]));
                    Mechanism::EccKeyPairGen
                }
            };
            let (public, private) =
                session.generate_key_pair(&mechanism, &public_template, &private_template)?;
            let flags = session.get_attributes(
                private,
                &[AttributeType::Sensitive, AttributeType::Extractable],
            )?;
            assert!(flags.contains(&Attribute::Sensitive(true)));
            assert!(flags.contains(&Attribute::Extractable(false)));
            let secret_attribute = match algorithm {
                SignatureAlgorithm::RsaPkcs1v15Sha256 => AttributeType::PrivateExponent,
                SignatureAlgorithm::EcdsaP256Sha256 => AttributeType::Value,
            };
            assert!(matches!(
                session
                    .get_attribute_info(private, &[secret_attribute])?
                    .as_slice(),
                [AttributeInfo::Sensitive]
            ));
            let public_key = match algorithm {
                SignatureAlgorithm::RsaPkcs1v15Sha256 => {
                    let attributes = session.get_attributes(
                        public,
                        &[AttributeType::Modulus, AttributeType::PublicExponent],
                    )?;
                    let modulus = attributes
                        .iter()
                        .find_map(|a| {
                            if let Attribute::Modulus(v) = a {
                                Some(v)
                            } else {
                                None
                            }
                        })
                        .unwrap();
                    let exponent = attributes
                        .iter()
                        .find_map(|a| {
                            if let Attribute::PublicExponent(v) = a {
                                Some(v)
                            } else {
                                None
                            }
                        })
                        .unwrap();
                    PKey::from_rsa(Rsa::from_public_components(
                        BigNum::from_slice(modulus)?,
                        BigNum::from_slice(exponent)?,
                    )?)?
                }
                SignatureAlgorithm::EcdsaP256Sha256 => {
                    let attributes = session.get_attributes(public, &[AttributeType::EcPoint])?;
                    let encoded = attributes
                        .iter()
                        .find_map(|a| {
                            if let Attribute::EcPoint(v) = a {
                                Some(v)
                            } else {
                                None
                            }
                        })
                        .unwrap();
                    let point = OctetStringRef::from_der(encoded)?.as_bytes();
                    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                    let mut context = BigNumContext::new()?;
                    let point = EcPoint::from_bytes(&group, point, &mut context)?;
                    PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?
                }
            };
            let certificate = certificate(&public_key, &issuer);
            let der = certificate.to_der()?;
            let mut provider = Pkcs11Key::new(&module, &session, private, &der)?;
            let signing_key: &mut dyn SigningKey = &mut provider;
            for mode in [ContentMode::Attached, ContentMode::Detached] {
                let encoded = sign(
                    signing_key,
                    MESSAGE,
                    SigningOptions {
                        algorithm,
                        mode,
                        signing_time: std::time::SystemTime::now(),
                    },
                )?;
                cades.push((certificate.clone(), encoded, mode));
            }
            produced.push((
                certificate.clone(),
                signing_key.sign(algorithm, SigningInput::Message(MESSAGE))?,
            ));
            let digest = sha256(MESSAGE);
            if algorithm == SignatureAlgorithm::EcdsaP256Sha256 {
                produced.push((
                    certificate,
                    signing_key.sign(algorithm, SigningInput::Sha256Digest(&digest))?,
                ));
            } else {
                assert_eq!(
                    signing_key
                        .sign(algorithm, SigningInput::Sha256Digest(&digest))
                        .err(),
                    Some(SigningError::UnsupportedOperation)
                );
            }
            // A certificate of the correct algorithm with a different key cannot bind output.
            let unrelated = key(algorithm);
            let unrelated = common::certificate(&unrelated, &issuer);
            let mut mismatched = Pkcs11Key::new(&module, &session, private, &unrelated.to_der()?)?;
            assert_eq!(
                mismatched
                    .sign(algorithm, SigningInput::Message(MESSAGE))
                    .err(),
                Some(SigningError::InvalidSignature)
            );
            assert_eq!(
                Pkcs11Key::new(&module, &session, public, &der).err(),
                Some(CertificateError::UnsupportedKey)
            );
            session.logout()?;
            assert_eq!(
                provider
                    .sign(algorithm, SigningInput::Message(MESSAGE))
                    .err(),
                Some(SigningError::BackendFailure)
            );
            session.login(
                UserType::User,
                Some(&AuthPin::new("synthetic-user-1234".into())),
            )?;
        }
        session.logout()?;
        Ok(())
    })();
    // A cleanup failure takes precedence and prevents consuming any signature output.
    session.close()?;
    operation?;
    module.finalize()?;
    for (certificate, encoded, mode) in cades {
        let detached = (mode == ContentMode::Detached).then_some(MESSAGE);
        assert!(verify_cades_with_cli(&certificate, &encoded, detached));
        assert!(!verify_cades_with_cli(
            &certificate,
            &encoded,
            Some(b"modified")
        ));
    }
    for (certificate, signature) in produced {
        assert!(verify_with_cli(&certificate, &signature, MESSAGE));
        assert!(!verify_with_cli(&certificate, &signature, b"modified"));
    }
    Ok(())
}
