use base64::{engine::general_purpose::STANDARD as B64, Engine};
use firmica_certificates::Pkcs12Key;
use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use firmica_xades::{preflight, sign, XadesError, XmlMode};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509Name, X509},
};
use secrecy::SecretString;
use std::{fs, process::Command, time::SystemTime};

struct DigestOnly {
    key: Pkcs12Key,
    capabilities: Vec<SigningCapability>,
}
impl SigningKey for DigestOnly {
    fn identity(&self) -> &CertificateIdentity {
        self.key.identity()
    }
    fn capabilities(&self) -> &[SigningCapability] {
        &self.capabilities
    }
    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        assert_eq!(input.kind(), InputKind::Sha256Digest);
        self.key.sign(algorithm, input)
    }
}

fn xmlsec_verify(bytes: &[u8], certificate: &[u8]) -> bool {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("signature.xml"), bytes).unwrap();
    fs::write(
        temp.path().join("certificate.pem"),
        X509::from_der(certificate).unwrap().to_pem().unwrap(),
    )
    .unwrap();
    Command::new("xmlsec1")
        .current_dir(temp.path())
        .args([
            "--verify",
            "--pubkey-cert-pem",
            "certificate.pem",
            "--enabled-reference-uris",
            "empty,same-doc",
            "--id-attr:Id",
            "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
            "--id-attr:Id",
            "http://www.w3.org/2000/09/xmldsig#:Object",
            "signature.xml",
        ])
        .output()
        .expect("XMLSec CLI required for independent verification")
        .status
        .success()
}

#[test]
fn rejects_dtd_wrapping_duplicate_ids_and_external_base() {
    for content in [
        "<!DOCTYPE a SYSTEM 'file:///etc/passwd'><a/>",
        "<!DOCTYPE a [<!ENTITY e 'value'>]><a>&e;</a>",
        "<a><b Id='dup'/><c xml:id='dup'/></a>",
        "<a Id='Firmica-Properties'/>",
        "<a xml:base='https://example.test/'/>",
        "<a xmlns:s='http://www.w3.org/2000/09/xmldsig#'><s:Signature/></a>",
        "not XML",
    ] {
        assert_eq!(
            preflight(content.as_bytes(), XmlMode::Enveloped),
            Err(XadesError::InvalidXml)
        );
    }
    assert!(preflight(b"\0\xff", XmlMode::Enveloped).is_err());
    assert!(preflight(b"\0\xff", XmlMode::Enveloping).is_ok());
    assert!(preflight(b"\0\xff", XmlMode::Detached).is_ok());
}

#[test]
fn properties_bind_the_certificate_content_reference_and_claimed_time() {
    let mut key = key(SignatureAlgorithm::EcdsaP256Sha256);
    for mode in [XmlMode::Enveloped, XmlMode::Enveloping, XmlMode::Detached] {
        let bytes = sign(
            &mut key,
            b"<root/>",
            SignatureAlgorithm::EcdsaP256Sha256,
            mode,
            SystemTime::now(),
        )
        .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let doc = roxmltree::Document::parse(text).unwrap();
        let ns = "http://uri.etsi.org/01903/v1.3.2#";
        let properties = doc
            .descendants()
            .find(|n| n.has_tag_name((ns, "SignedProperties")))
            .unwrap();
        assert_eq!(properties.attribute("Id"), Some("Firmica-Properties"));
        let cert_digest = properties
            .descendants()
            .find(|n| n.has_tag_name((ns, "CertDigest")))
            .unwrap();
        let value = cert_digest
            .descendants()
            .find(|n| n.tag_name().name() == "DigestValue")
            .unwrap()
            .text()
            .unwrap();
        assert_eq!(
            B64.decode(value).unwrap(),
            openssl::sha::sha256(&key.identity().certificate_der)
        );
        assert_eq!(
            doc.descendants()
                .filter(|n| n.tag_name().name() == "Reference")
                .count(),
            2
        );
        assert!(doc
            .descendants()
            .find(|n| n.tag_name().name() == "SigningTime")
            .unwrap()
            .text()
            .unwrap()
            .ends_with('Z'));
        let value = doc
            .descendants()
            .find(|n| n.tag_name().name() == "SignatureValue")
            .unwrap()
            .text()
            .unwrap();
        assert_eq!(B64.decode(value).unwrap().len(), 64);
    }
}

#[test]
#[ignore = "requires XMLSec with the OpenSSL backend"]
fn xmlsec_independently_verifies_all_placements_rsa_ec_and_rejects_tampering() {
    for (algorithm, digest_only) in [
        (SignatureAlgorithm::RsaPkcs1v15Sha256, false),
        (SignatureAlgorithm::RsaPkcs1v15Sha256, true),
        (SignatureAlgorithm::EcdsaP256Sha256, false),
        (SignatureAlgorithm::EcdsaP256Sha256, true),
    ] {
        let provider = key(algorithm);
        let mut key: Box<dyn SigningKey> = if digest_only {
            let capabilities = provider
                .capabilities()
                .iter()
                .copied()
                .filter(|c| c.input == InputKind::Sha256Digest)
                .collect();
            Box::new(DigestOnly {
                key: provider,
                capabilities,
            })
        } else {
            Box::new(provider)
        };
        for mode in [XmlMode::Enveloped, XmlMode::Enveloping, XmlMode::Detached] {
            let cases: &[&[u8]] = if mode == XmlMode::Enveloped {
                &[b"<r/>",b"<?xml version='1.0'?>\r\n<r xmlns='urn:test' xml:lang='es'><p:a xmlns:p='urn:other' z='2' a='1'>hello &amp; world</p:a><!-- comment --></r>"]
            } else {
                &[b"", b"\0\xffBinary document\r\n"]
            };
            for content in cases {
                let signed =
                    sign(key.as_mut(), content, algorithm, mode, SystemTime::now()).unwrap();
                assert!(
                    xmlsec_verify(&signed, &key.identity().certificate_der),
                    "{algorithm:?} {mode:?}: {}",
                    String::from_utf8_lossy(&signed)
                );
                if mode == XmlMode::Enveloping {
                    if let Ok(destination) = std::env::var("FIRMICA_XML_TEST_OUTPUT") {
                        fs::write(destination, &signed).unwrap();
                    }
                }
                // Change an authenticated XAdES property, retaining a valid XML document.
                let text = String::from_utf8(signed)
                    .unwrap()
                    .replace("application/octet-stream", "application/other")
                    .replace("text/xml", "text/other");
                assert!(!xmlsec_verify(
                    text.as_bytes(),
                    &key.identity().certificate_der
                ));
            }
        }
    }
}

fn key(algorithm: SignatureAlgorithm) -> Pkcs12Key {
    let private = match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
        }
        _ => PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap(),
    };
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "Firmica synthetic PDF test")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&private).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&private, MessageDigest::sha256()).unwrap();
    let pfx = Pkcs12::builder()
        .pkey(&private)
        .cert(&cert.build())
        .build2("test")
        .unwrap()
        .to_der()
        .unwrap();
    Pkcs12Key::from_der(&pfx, &SecretString::from("test")).unwrap()
}
