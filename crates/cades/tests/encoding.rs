mod reference;

use cms::{
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use der::{
    asn1::{ObjectIdentifier, OctetString},
    Any, Decode, Encode, Reader,
};
use firmica_cades::{
    sign, CadesError, ContentMode, SigningOptions, MAX_CERTIFICATES, MAX_CERTIFICATE_BYTES,
    MAX_CONTENT_BYTES,
};
use firmica_certificates::Pkcs12Key;
use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::PKey,
    rsa::Rsa,
    sha::sha256,
    x509::{extension::KeyUsage, X509Name, X509},
};
use secrecy::SecretString;
use std::{
    fs,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MESSAGE: &[u8] = b"Binary document\0\xff\r\nDo not normalize\n";
const RSA: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
const EC: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;

fn oid(value: &str) -> ObjectIdentifier {
    ObjectIdentifier::new(value).unwrap()
}

fn options(algorithm: SignatureAlgorithm, mode: ContentMode) -> SigningOptions {
    SigningOptions {
        algorithm,
        mode,
        signing_time: SystemTime::now(),
    }
}

struct Fixture {
    provider: Pkcs12Key,
    certificate: X509,
    private_pem: Vec<u8>,
    pkcs12: Vec<u8>,
}

fn fixture(algorithm: SignatureAlgorithm) -> Fixture {
    let private = match algorithm {
        RSA => PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
        EC => PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap(),
    };
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "Firmica synthetic CAdES test")
        .unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(7).unwrap()).unwrap())
        .unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    certificate.set_pubkey(&private).unwrap();
    certificate
        .append_extension(KeyUsage::new().digital_signature().build().unwrap())
        .unwrap();
    certificate.sign(&private, MessageDigest::sha256()).unwrap();
    let certificate = certificate.build();
    let pfx = Pkcs12::builder()
        .pkey(&private)
        .cert(&certificate)
        .build2("synthetic-test")
        .unwrap()
        .to_der()
        .unwrap();
    Fixture {
        provider: Pkcs12Key::from_der(&pfx, &SecretString::from("synthetic-test")).unwrap(),
        certificate,
        private_pem: private.private_key_to_pem_pkcs8().unwrap(),
        pkcs12: pfx,
    }
}

// OpenSSL's CMS verifier parses DER, verifies the signature/content and, with -cades,
// checks the ESS certificate binding. Only this temporary synthetic leaf is trusted.
fn verify(
    encoded: &[u8],
    certificate: &X509,
    detached: Option<&[u8]>,
    cades: bool,
) -> Option<Vec<u8>> {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("signature.der"), encoded).unwrap();
    fs::write(temp.path().join("trust.pem"), certificate.to_pem().unwrap()).unwrap();
    let mut command = Command::new("openssl");
    command.current_dir(temp.path()).args([
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-in",
        "signature.der",
        "-CAfile",
        "trust.pem",
        "-no-CApath",
        "-no-CAstore",
        "-partial_chain",
        "-purpose",
        "any",
        "-out",
        "verified.bin",
    ]);
    if cades {
        command.arg("-cades");
    }
    if let Some(content) = detached {
        fs::write(temp.path().join("content.bin"), content).unwrap();
        command.args(["-content", "content.bin"]);
    }
    let result = command
        .output()
        .expect("OpenSSL CLI is required for CMS integration tests");
    result
        .status
        .success()
        .then(|| fs::read(temp.path().join("verified.bin")).unwrap())
}

fn parse(encoded: &[u8]) -> SignedData {
    let info = ContentInfo::from_der(encoded).unwrap();
    assert_eq!(info.content_type, oid("1.2.840.113549.1.7.2"));
    info.content.decode_as().unwrap()
}

fn attribute(data: &SignedData, id: &str) -> Any {
    let attrs = data
        .signer_infos
        .0
        .get(0)
        .unwrap()
        .signed_attrs
        .as_ref()
        .unwrap();
    let found: Vec<_> = attrs.iter().filter(|attr| attr.oid == oid(id)).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].values.len(), 1);
    found[0].values.get(0).unwrap().clone()
}

#[test]
fn pdf_cms_omits_signing_time_and_retains_ess_binding() {
    for algorithm in [RSA, EC] {
        let mut fixture = fixture(algorithm);
        let encoded =
            firmica_cades::sign_pdf_digest(&mut fixture.provider, sha256(MESSAGE), algorithm)
                .unwrap();
        let data = parse(&encoded);
        assert!(data.encap_content_info.econtent.is_none());
        let attrs = data
            .signer_infos
            .0
            .get(0)
            .unwrap()
            .signed_attrs
            .as_ref()
            .unwrap();
        assert_eq!(attrs.len(), 3);
        assert!(attrs
            .iter()
            .all(|attr| attr.oid != oid("1.2.840.113549.1.9.5")));
        assert_eq!(
            verify(&encoded, &fixture.certificate, Some(MESSAGE), true).unwrap(),
            MESSAGE
        );
        assert!(verify(&encoded, &fixture.certificate, Some(b"tampered"), true).is_none());
    }
}

#[test]
fn attached_and_detached_rsa_and_ecdsa_pass_cades_verification() {
    for algorithm in [RSA, EC] {
        let mut fixture = fixture(algorithm);
        for content in [MESSAGE, b"".as_slice()] {
            for mode in [ContentMode::Attached, ContentMode::Detached] {
                let encoded =
                    sign(&mut fixture.provider, content, options(algorithm, mode)).unwrap();
                let data = parse(&encoded);
                assert_eq!(data.signer_infos.0.len(), 1);
                assert_eq!(data.digest_algorithms.len(), 1);
                assert_eq!(
                    data.digest_algorithms.get(0).unwrap().oid,
                    oid("2.16.840.1.101.3.4.2.1")
                );
                assert!(data.digest_algorithms.get(0).unwrap().parameters.is_none());
                assert!(data.crls.is_none());
                assert_eq!(data.certificates.as_ref().unwrap().0.len(), 1);
                let signer = data.signer_infos.0.get(0).unwrap();
                assert_eq!(signer.version as u8, 1);
                assert!(matches!(
                    signer.sid,
                    SignerIdentifier::IssuerAndSerialNumber(_)
                ));
                assert_eq!(signer.signed_attrs.as_ref().unwrap().len(), 4);
                assert!(signer.unsigned_attrs.is_none());
                assert_eq!(
                    attribute(&data, "1.2.840.113549.1.9.3")
                        .decode_as::<ObjectIdentifier>()
                        .unwrap(),
                    oid("1.2.840.113549.1.7.1")
                );
                assert_eq!(
                    attribute(&data, "1.2.840.113549.1.9.4")
                        .decode_as::<OctetString>()
                        .unwrap()
                        .as_bytes(),
                    sha256(content)
                );
                // Default SHA-256 omitted; one ESSCertIDv2; no issuerSerial/policies.
                let mut expected = vec![0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20];
                expected.extend(sha256(&fixture.certificate.to_der().unwrap()));
                assert_eq!(
                    attribute(&data, "1.2.840.113549.1.9.16.2.47")
                        .to_der()
                        .unwrap(),
                    expected
                );
                if mode == ContentMode::Attached {
                    assert_eq!(
                        data.encap_content_info
                            .econtent
                            .unwrap()
                            .decode_as::<OctetString>()
                            .unwrap()
                            .as_bytes(),
                        content
                    );
                } else {
                    assert!(data.encap_content_info.econtent.is_none());
                }
                let detached = (mode == ContentMode::Detached).then_some(content);
                assert_eq!(
                    verify(&encoded, &fixture.certificate, detached, true).unwrap(),
                    content
                );
                // Even attached signatures must reject substituted external content.
                assert!(verify(&encoded, &fixture.certificate, Some(b"modified"), true).is_none());
                let mut corrupt = parse(&encoded);
                let mut signers = corrupt.signer_infos.0.clone().into_vec();
                let mut value = signers[0].signature.as_bytes().to_vec();
                value[0] ^= 1;
                signers[0].signature = OctetString::new(value).unwrap();
                corrupt.signer_infos.0 = signers.try_into().unwrap();
                assert!(verify(&encode(&corrupt), &fixture.certificate, detached, true).is_none());
            }
        }
    }
}

fn encode(data: &SignedData) -> Vec<u8> {
    ContentInfo {
        content_type: oid("1.2.840.113549.1.7.2"),
        content: Any::encode_from(data).unwrap(),
    }
    .to_der()
    .unwrap()
}

#[test]
fn cades_verifier_rejects_wrong_or_missing_binding_despite_valid_cms_signature() {
    let mut fixture = fixture(RSA);
    let encoded = sign(
        &mut fixture.provider,
        MESSAGE,
        options(RSA, ContentMode::Detached),
    )
    .unwrap();
    for missing in [false, true] {
        let mut data = parse(&encoded);
        let mut signers = data.signer_infos.0.into_vec();
        let mut attrs = signers[0].signed_attrs.take().unwrap().into_vec();
        let id = oid("1.2.840.113549.1.9.16.2.47");
        if missing {
            attrs.retain(|a| a.oid != id);
        } else {
            let attr = attrs.iter_mut().find(|a| a.oid == id).unwrap();
            let mut value = attr.values.get(0).unwrap().to_der().unwrap();
            *value.last_mut().unwrap() ^= 1;
            attr.values = vec![Any::from_der(&value).unwrap()].try_into().unwrap();
        }
        let attrs: x509_cert::attr::Attributes = attrs.try_into().unwrap();
        let signed = fixture
            .provider
            .sign(RSA, SigningInput::Message(&attrs.to_der().unwrap()))
            .unwrap();
        signers[0].signature = OctetString::new(signed.value).unwrap();
        signers[0].signed_attrs = Some(attrs);
        data.signer_infos.0 = signers.try_into().unwrap();
        let encoded = encode(&data);
        assert!(verify(&encoded, &fixture.certificate, Some(MESSAGE), false).is_some());
        assert!(verify(&encoded, &fixture.certificate, Some(MESSAGE), true).is_none());
    }
}

#[test]
fn openssl_cades_reference_has_matching_content_digest_and_certificate_binding() {
    for algorithm in [RSA, EC] {
        let mut fixture = fixture(algorithm);
        let ours = parse(
            &sign(
                &mut fixture.provider,
                MESSAGE,
                options(algorithm, ContentMode::Detached),
            )
            .unwrap(),
        );
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("key.pem"), &fixture.private_pem).unwrap();
        fs::write(
            temp.path().join("cert.pem"),
            fixture.certificate.to_pem().unwrap(),
        )
        .unwrap();
        fs::write(temp.path().join("content.bin"), MESSAGE).unwrap();
        let output = Command::new("openssl")
            .current_dir(temp.path())
            .args([
                "cms",
                "-sign",
                "-cades",
                "-binary",
                "-md",
                "sha256",
                "-nosmimecap",
                "-in",
                "content.bin",
                "-signer",
                "cert.pem",
                "-inkey",
                "key.pem",
                "-outform",
                "DER",
                "-out",
                "reference.der",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference = fs::read(temp.path().join("reference.der")).unwrap();
        assert!(verify(&reference, &fixture.certificate, Some(MESSAGE), true).is_some());
        let reference = parse(&reference);
        for id in ["1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"] {
            assert_eq!(attribute(&ours, id), attribute(&reference, id));
        }
        // OpenSSL includes optional issuerSerial. Compare the certificate hash, not bytes.
        let value = attribute(&reference, "1.2.840.113549.1.9.16.2.47");
        let hash = value
            .sequence(|r| {
                let ids: Any = r.decode()?;
                ids.sequence(|r| {
                    let id: Any = r.decode()?;
                    id.sequence(|r| {
                        let hash: OctetString = r.decode()?;
                        let _: Any = r.decode()?;
                        Ok(hash)
                    })
                })
            })
            .unwrap();
        assert_eq!(
            hash.as_bytes(),
            sha256(&fixture.certificate.to_der().unwrap())
        );
    }
}

struct RestrictedKey {
    provider: Pkcs12Key,
    identity: CertificateIdentity,
    capabilities: Vec<SigningCapability>,
    calls: usize,
    error: Option<SigningError>,
}

impl SigningKey for RestrictedKey {
    fn identity(&self) -> &CertificateIdentity {
        &self.identity
    }
    fn capabilities(&self) -> &[SigningCapability] {
        &self.capabilities
    }
    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        self.calls += 1;
        assert!(self.capabilities.contains(&SigningCapability {
            algorithm,
            input: input.kind()
        }));
        if let Some(error) = self.error {
            return Err(error);
        }
        self.provider.sign(algorithm, input)
    }
}

#[test]
fn digest_only_keys_and_duplicate_certificates_are_supported() {
    let extra = fixture(RSA).certificate.to_der().unwrap();
    let fixture = fixture(EC);
    let mut identity = fixture.provider.identity().clone();
    identity.additional_certificates = vec![identity.certificate_der.clone(); MAX_CERTIFICATES - 1];
    let mut key = RestrictedKey {
        provider: fixture.provider,
        identity,
        capabilities: vec![SigningCapability {
            algorithm: EC,
            input: InputKind::Sha256Digest,
        }],
        calls: 0,
        error: None,
    };
    let encoded = sign(&mut key, MESSAGE, options(EC, ContentMode::Detached)).unwrap();
    assert_eq!(key.calls, 1);
    assert_eq!(parse(&encoded).certificates.unwrap().0.len(), 1);
    assert!(verify(&encoded, &fixture.certificate, Some(MESSAGE), true).is_some());
    key.identity.additional_certificates = vec![extra.clone(), extra];
    let encoded = sign(&mut key, MESSAGE, options(EC, ContentMode::Attached)).unwrap();
    assert_eq!(parse(&encoded).certificates.unwrap().0.len(), 2);
    assert!(verify(&encoded, &fixture.certificate, None, true).is_some());
    let largest = vec![0; MAX_CONTENT_BYTES];
    let encoded = sign(&mut key, &largest, options(EC, ContentMode::Detached)).unwrap();
    assert_eq!(
        verify(&encoded, &fixture.certificate, Some(&largest), true).unwrap(),
        largest
    );
}

#[test]
fn invalid_inputs_and_capabilities_are_rejected_before_key_invocation() {
    let fixture = fixture(RSA);
    let mut key = RestrictedKey {
        identity: fixture.provider.identity().clone(),
        capabilities: fixture.provider.capabilities().to_vec(),
        provider: fixture.provider,
        calls: 0,
        error: None,
    };
    let original = key.identity.clone();
    let opts = options(RSA, ContentMode::Detached);
    assert_eq!(
        sign(&mut key, &vec![0; MAX_CONTENT_BYTES + 1], opts).err(),
        Some(CadesError::InputTooLarge)
    );
    key.identity.certificate_der = vec![0; MAX_CERTIFICATE_BYTES + 1];
    assert_eq!(
        sign(&mut key, MESSAGE, opts).err(),
        Some(CadesError::InputTooLarge)
    );
    key.identity = original.clone();
    key.identity.additional_certificates = vec![vec![]; MAX_CERTIFICATES];
    assert_eq!(
        sign(&mut key, MESSAGE, opts).err(),
        Some(CadesError::InputTooLarge)
    );
    for invalid in [vec![], vec![0x30, 0x00], {
        let mut v = original.certificate_der.clone();
        v.push(0);
        v
    }] {
        key.identity.certificate_der = invalid;
        key.identity.additional_certificates.clear();
        assert_eq!(
            sign(&mut key, MESSAGE, opts).err(),
            Some(CadesError::InvalidCertificate)
        );
    }
    key.identity = original.clone();
    key.identity.additional_certificates.push(vec![0]);
    assert_eq!(
        sign(&mut key, MESSAGE, opts).err(),
        Some(CadesError::InvalidCertificate)
    );
    key.identity = original;
    assert_eq!(
        sign(
            &mut key,
            MESSAGE,
            SigningOptions {
                signing_time: UNIX_EPOCH + Duration::from_secs(253_402_300_800),
                ..opts
            }
        )
        .err(),
        Some(CadesError::InvalidTime)
    );
    assert_eq!(
        sign(
            &mut key,
            MESSAGE,
            SigningOptions {
                signing_time: UNIX_EPOCH - Duration::from_secs(1),
                ..opts
            }
        )
        .err(),
        Some(CadesError::InvalidTime)
    );
    key.capabilities.clear();
    assert_eq!(
        sign(&mut key, MESSAGE, opts).err(),
        Some(CadesError::Signing(SigningError::UnsupportedOperation))
    );
    assert_eq!(key.calls, 0);
}

#[test]
fn signing_time_switches_at_2050_and_backend_failures_return_no_output() {
    let fixture = fixture(EC);
    let mut key = RestrictedKey {
        identity: fixture.provider.identity().clone(),
        capabilities: fixture.provider.capabilities().to_vec(),
        provider: fixture.provider,
        calls: 0,
        error: None,
    };
    for (seconds, tag) in [(2_524_607_999, 0x17), (2_524_608_000, 0x18)] {
        let opts = SigningOptions {
            signing_time: UNIX_EPOCH + Duration::new(seconds, 999_999_999),
            ..options(EC, ContentMode::Detached)
        };
        let data = parse(&sign(&mut key, MESSAGE, opts).unwrap());
        let time = attribute(&data, "1.2.840.113549.1.9.5");
        assert_eq!(time.to_der().unwrap()[0], tag);
        assert_eq!(
            x509_cert::time::Time::from_der(&time.to_der().unwrap())
                .unwrap()
                .to_unix_duration()
                .as_secs(),
            seconds
        );
    }
    key.error = Some(SigningError::BackendFailure);
    assert_eq!(
        sign(&mut key, MESSAGE, options(EC, ContentMode::Attached)).err(),
        Some(CadesError::Signing(SigningError::BackendFailure))
    );
    assert_eq!(key.calls, 3);
}

#[test]
#[ignore = "requires Java 17+; downloads checksum-pinned AutoFirma reference jars"]
fn autofirma_reference_and_spongycastle_verify_shared_semantics() {
    let classpath = reference::classpath();
    for algorithm in [RSA, EC] {
        let mut fixture = fixture(algorithm);
        for mode in [ContentMode::Attached, ContentMode::Detached] {
            for content in [MESSAGE, b"".as_slice()] {
                let temp = tempfile::tempdir().unwrap();
                fs::write(temp.path().join("key.p12"), &fixture.pkcs12).unwrap();
                fs::write(temp.path().join("document.bin"), content).unwrap();
                let encoded =
                    sign(&mut fixture.provider, content, options(algorithm, mode)).unwrap();
                fs::write(temp.path().join("ours.der"), encoded).unwrap();
                let java = Command::new("java")
                    .current_dir(temp.path())
                    .args(["-Djava.awt.headless=true", "--class-path"])
                    .arg(&classpath)
                    .arg(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("tests/CadesReference.java"),
                    )
                    .args([
                        "key.p12",
                        "document.bin",
                        "ours.der",
                        if mode == ContentMode::Attached {
                            "attached"
                        } else {
                            "detached"
                        },
                        if algorithm == RSA {
                            "SHA256withRSA"
                        } else {
                            "SHA256withECDSA"
                        },
                        "reference.der",
                    ])
                    .output()
                    .expect("Java 17+ is required for the reference test");
                assert!(
                    java.status.success(),
                    "{}",
                    String::from_utf8_lossy(&java.stderr)
                );
                let reference = fs::read(temp.path().join("reference.der")).unwrap();
                assert_eq!(
                    verify(
                        &reference,
                        &fixture.certificate,
                        (mode == ContentMode::Detached).then_some(content),
                        true
                    )
                    .unwrap(),
                    content
                );
            }
        }
    }
}
