#![allow(dead_code)]
use super::support::checked;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine,
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
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Name, X509,
    },
};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
pub const PASSWORD: &str = "synthetic-native-test";

pub fn identities(directory: &Path) -> PathBuf {
    for algorithm in ["rsa", "ec"] {
        let key = if algorithm == "rsa" {
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
        } else {
            PKey::from_ec_key(
                EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
            )
            .unwrap()
        };
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Firmica synthetic desktop signer")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(17).unwrap()).unwrap())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        certificate
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = certificate.build();
        let bytes = Pkcs12::builder()
            .pkey(&key)
            .cert(&certificate)
            .build2(PASSWORD)
            .unwrap()
            .to_der()
            .unwrap();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(directory.join(format!("{algorithm}.p12")))
            .unwrap();
        file.write_all(&bytes).unwrap();
        fs::write(
            directory.join(format!("{algorithm}.pem")),
            certificate.to_pem().unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join(format!("{algorithm}.der")),
            certificate.to_der().unwrap(),
        )
        .unwrap();
    }
    directory.to_owned()
}

pub fn decode(encoded: &str) -> Vec<u8> {
    STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .unwrap()
}

pub fn verify(
    case: &Value,
    signature: &Path,
    certificates: &Path,
    directory: &Path,
    evidence: &Path,
) {
    let certificate = certificates.join(format!("{}.pem", case["algorithm"].as_str().unwrap()));
    let original = decode(case["content"].as_str().unwrap());
    match case["mode"].as_str().unwrap() {
        "cades" => {
            let reference = directory.join("reference.bin");
            let verified = directory.join("verified.bin");
            fs::write(&reference, &original).unwrap();
            let mut command = Command::new("openssl");
            command
                .args([
                    "cms", "-verify", "-cades", "-binary", "-inform", "DER", "-in",
                ])
                .arg(signature)
                .arg("-CAfile")
                .arg(certificate)
                .args([
                    "-no-CApath",
                    "-no-CAstore",
                    "-partial_chain",
                    "-purpose",
                    "any",
                ]);
            if case["attached"] != true {
                command.arg("-content").arg(reference);
            }
            command.arg("-out").arg(&verified);
            checked(&mut command, 30);
            assert_eq!(fs::read(verified).unwrap(), original);
        }
        "pades" => {
            assert!(fs::read(signature).unwrap().starts_with(&original));
            let result = checked(Command::new("pdfsig").arg("-nocert").arg(signature), 30);
            assert!(
                result.contains("Signature is Valid"),
                "PDF signature verification failed"
            );
            let image = evidence.join(format!(
                "pdf-{}",
                signature.file_stem().unwrap().to_str().unwrap()
            ));
            checked(
                Command::new("pdftoppm")
                    .args(["-singlefile", "-scale-to", "1000", "-png"])
                    .arg(signature)
                    .arg(&image),
                30,
            );
            assert!(image.with_added_extension("png").metadata().unwrap().len() > 1000);
            if case["visible"] == true
                || case["properties"]
                    .as_str()
                    .is_some_and(|p| p.contains("layer2Text="))
            {
                let reference = directory.join("unsigned.pdf");
                fs::write(&reference, &original).unwrap();
                let baseline = directory.join("unsigned");
                checked(
                    Command::new("pdftoppm")
                        .args(["-singlefile", "-scale-to", "1000", "-png"])
                        .arg(reference)
                        .arg(&baseline),
                    30,
                );
                assert_ne!(
                    fs::read(image.with_added_extension("png")).unwrap(),
                    fs::read(baseline.with_added_extension("png")).unwrap(),
                    "visible appearance did not render"
                );
            }
        }
        _ => {
            let xml = fs::read_to_string(signature).unwrap();
            let parsed = roxmltree::Document::parse(&xml).unwrap();
            let embedded = parsed
                .descendants()
                .find(|node| {
                    node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate"))
                })
                .unwrap();
            assert_eq!(
                decode(embedded.text().unwrap()),
                fs::read(certificates.join(format!("{}.der", case["algorithm"].as_str().unwrap())))
                    .unwrap()
            );
            // XMLSec 1.3 resolves X509Data through its certificate store in strict
            // mode. Trust only the already pinned synthetic fixture certificate.
            let mut xmlsec = Command::new("xmlsec1");
            xmlsec.arg("--verify");
            // MSYS2 can default to Windows CNG. Use its OpenSSL backend for
            // explicit PEM trust and P-256, without consulting Windows stores.
            #[cfg(windows)]
            xmlsec.args(["--crypto", "openssl"]);
            checked(
                xmlsec
                    .args(["--trusted-pem"])
                    .arg(certificate)
                    .args([
                        "--enabled-reference-uris",
                        "empty,same-doc",
                        "--id-attr:Id",
                        "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
                        "--id-attr:Id",
                        "http://www.w3.org/2000/09/xmldsig#:Object",
                    ])
                    .arg(signature),
                30,
            );
            let signature_node = parsed
                .descendants()
                .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature")))
                .unwrap();
            if case["mode"] == "enveloped" {
                assert_eq!(signature_node.parent_element(), Some(parsed.root_element()));
                let expected =
                    roxmltree::Document::parse(std::str::from_utf8(&original).unwrap()).unwrap();
                assert_eq!(
                    parsed.root_element().tag_name(),
                    expected.root_element().tag_name()
                );
                assert_eq!(parsed.root_element().text(), expected.root_element().text());
            } else {
                let object = parsed
                    .descendants()
                    .find(|node| node.attribute("Id") == Some("Firmica-Content"))
                    .unwrap();
                assert_eq!(decode(object.text().unwrap()), original);
                if case["mode"] == "enveloping" {
                    assert_eq!(parsed.root_element(), signature_node);
                    assert_eq!(object.parent_element(), Some(signature_node));
                } else {
                    assert_eq!(case["mode"], "detached");
                    assert_eq!(parsed.root_element().tag_name().name(), "AFIRMA");
                    assert_eq!(signature_node.parent_element(), object.parent_element());
                }
            }
        }
    }
    #[cfg(unix)]
    if signature == Path::new(case["output"].as_str().unwrap()) {
        assert_eq!(
            signature.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
