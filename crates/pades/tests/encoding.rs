use firmica_certificates::Pkcs12Key;
use firmica_pades::{preflight, sign, Appearance, PadesError, PdfOptions};
use firmica_signing::SignatureAlgorithm;
use lopdf::{dictionary, Document, Object, Stream};
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

fn pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages = doc.new_object_id();
    let font =
        doc.add_object(dictionary! {"Type"=>"Font", "Subtype"=>"Type1", "BaseFont"=>"Helvetica"});
    let content = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 20 Tf 50 700 Td (Original document) Tj ET".to_vec(),
    ));
    let page = doc.add_object(dictionary! {"Type"=>"Page", "Parent"=>pages,
    "MediaBox"=>vec![0.into(),0.into(),595.into(),842.into()], "Contents"=>content,
    "Resources"=>dictionary! {"Font"=>dictionary! {"F1"=>font}}});
    doc.set_object(
        pages,
        dictionary! {"Type"=>"Pages", "Kids"=>vec![page.into()], "Count"=>1},
    );
    let catalog = doc.add_object(dictionary! {"Type"=>"Catalog", "Pages"=>pages});
    doc.trailer.set("Root", catalog);
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

fn signatures(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let doc = Document::load_mem(bytes).unwrap();
    doc.objects
        .values()
        .filter_map(|o| {
            let d = o.as_dict().ok()?;
            if d.get(b"Type").ok()?.as_name().ok()? != b"Sig" {
                return None;
            }
            let r: Vec<usize> = d
                .get(b"ByteRange")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o.as_i64().unwrap() as usize)
                .collect();
            assert_eq!(r.len(), 4);
            assert_eq!(r[0], 0);
            let mut data = bytes[r[0]..r[0] + r[1]].to_vec();
            data.extend_from_slice(&bytes[r[2]..r[2] + r[3]]);
            Some((d.get(b"Contents").unwrap().as_str().unwrap().to_vec(), data))
        })
        .collect()
}

fn verify(bytes: &[u8]) -> bool {
    signatures(bytes).iter().all(|(cms, data)| {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("sig.der"), cms).unwrap();
        fs::write(temp.path().join("data"), data).unwrap();
        Command::new("openssl")
            .current_dir(temp.path())
            .args([
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                "sig.der",
                "-content",
                "data",
                "-noverify",
                "-out",
                "verified",
            ])
            .output()
            .unwrap()
            .status
            .success()
    })
}

#[test]
fn rsa_and_ec_incremental_signatures_preserve_revisions_and_verify_with_openssl() {
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        SignatureAlgorithm::EcdsaP256Sha256,
    ] {
        let mut key = key(algorithm);
        let original = pdf();
        let first = sign(
            &mut key,
            &original,
            algorithm,
            &PdfOptions::default(),
            SystemTime::now(),
        )
        .unwrap();
        assert!(first.starts_with(&original));
        assert_eq!(signatures(&first).len(), 1);
        assert!(verify(&first));
        let second = sign(
            &mut key,
            &first,
            algorithm,
            &PdfOptions {
                appearance: Some(Appearance {
                    page: 1,
                    rectangle: [40., 30., 400., 70.],
                    text: "Signed by synthetic test (not trusted)".into(),
                }),
            },
            SystemTime::now(),
        )
        .unwrap();
        assert!(second.starts_with(&first));
        assert_eq!(signatures(&second).len(), 2);
        assert!(verify(&second));
        let mut tampered = second;
        let at = tampered
            .windows(17)
            .position(|w| w == b"Original document")
            .unwrap();
        tampered[at] = b'X';
        assert!(!verify(&tampered));
    }
}

#[test]
fn rejects_malformed_restricted_and_invalid_appearance_inputs() {
    assert_eq!(
        preflight(b"not a PDF", &PdfOptions::default()),
        Err(PadesError::InvalidPdf)
    );
    let original = pdf();
    for appearance in [
        Appearance {
            page: 0,
            rectangle: [1., 1., 2., 2.],
            text: "test".into(),
        },
        Appearance {
            page: 1,
            rectangle: [1., 1., f32::NAN, 2.],
            text: "test".into(),
        },
        Appearance {
            page: 1,
            rectangle: [1., 1., 999., 2.],
            text: "test".into(),
        },
        Appearance {
            page: 1,
            rectangle: [1., 1., 2., 2.],
            text: "\n".into(),
        },
    ] {
        assert_eq!(
            preflight(
                &original,
                &PdfOptions {
                    appearance: Some(appearance)
                }
            ),
            Err(PadesError::InvalidAppearance)
        );
    }
    for restriction in ["Perms", "AcroForm", "NestedLock"] {
        let mut doc = Document::load_mem(&original).unwrap();
        let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
        let value = if restriction == "NestedLock" {
            Object::Dictionary(
                dictionary! {"Fields"=>vec![Object::Dictionary(dictionary! {"FT"=>"Sig","Lock"=>dictionary! {}})]},
            )
        } else if restriction == "AcroForm" {
            Object::Dictionary(dictionary! {"XFA"=>Object::Null})
        } else {
            Object::Dictionary(dictionary! {})
        };
        doc.get_object_mut(root)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set(
                if restriction == "NestedLock" {
                    "AcroForm"
                } else {
                    restriction
                },
                value,
            );
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        assert_eq!(
            preflight(&bytes, &PdfOptions::default()),
            Err(PadesError::UnsupportedPdf)
        );
    }
}

#[test]
#[ignore = "requires Poppler pdfsig and pdftoppm"]
fn poppler_independently_verifies_both_revisions_and_renders_appearance() {
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        SignatureAlgorithm::EcdsaP256Sha256,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut key = key(algorithm);
        let first = sign(
            &mut key,
            &pdf(),
            algorithm,
            &PdfOptions::default(),
            SystemTime::now(),
        )
        .unwrap();
        let second = sign(
            &mut key,
            &first,
            algorithm,
            &PdfOptions {
                appearance: Some(Appearance {
                    page: 1,
                    rectangle: [40., 30., 400., 70.],
                    text: "Firmica independent verification".into(),
                }),
            },
            SystemTime::now(),
        )
        .unwrap();
        fs::write(temp.path().join("signed.pdf"), &second).unwrap();
        let result = Command::new("pdfsig")
            .current_dir(temp.path())
            .args(["-nocert", "signed.pdf"])
            .output()
            .expect("Poppler pdfsig required");
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(result.status.success(), "{text}");
        assert_eq!(text.matches("Signature is Valid").count(), 2, "{text}");
        let result = Command::new("pdftoppm")
            .current_dir(temp.path())
            .args([
                "-singlefile",
                "-scale-to",
                "800",
                "-png",
                "signed.pdf",
                "page",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(temp.path().join("page.png").metadata().unwrap().len() > 1000);
        if let Ok(destination) = std::env::var("FIRMICA_PDF_TEST_OUTPUT") {
            fs::copy(temp.path().join("page.png"), &destination).unwrap();
            fs::write(
                std::path::Path::new(&destination).with_extension("input.pdf"),
                pdf(),
            )
            .unwrap();
        }
    }
}
