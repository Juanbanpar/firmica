#![allow(dead_code)]

use firmica_signing::{Signature, SignatureAlgorithm};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPublic, PKey, PKeyRef, Private},
    rsa::Rsa,
    x509::{extension::KeyUsage, X509Name, X509},
};
use std::{fs, process::Command};

pub const MESSAGE: &[u8] = b"Firmica synthetic signing fixture\x00\xff";

pub fn key(algorithm: SignatureAlgorithm) -> PKey<Private> {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
        }
        SignatureAlgorithm::EcdsaP256Sha256 => PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap(),
    }
}

pub fn certificate<T: HasPublic>(public: &PKeyRef<T>, issuer: &PKeyRef<Private>) -> X509 {
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "Firmica synthetic test")
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.set_pubkey(public).unwrap();
    builder
        .append_extension(KeyUsage::new().digital_signature().build().unwrap())
        .unwrap();
    builder.sign(issuer, MessageDigest::sha256()).unwrap();
    builder.build()
}

// A separate CLI/EVP_DigestVerify path detects encoding errors and accidental double hashing.
pub fn verify_with_cli(certificate: &X509, signature: &Signature, message: &[u8]) -> bool {
    let directory = tempfile::tempdir().unwrap();
    let public = directory.path().join("public.pem");
    let value = directory.path().join("signature.bin");
    let document = directory.path().join("document.bin");
    fs::write(
        &public,
        certificate
            .public_key()
            .unwrap()
            .public_key_to_pem()
            .unwrap(),
    )
    .unwrap();
    fs::write(&value, &signature.value).unwrap();
    fs::write(&document, message).unwrap();
    let output = Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(public)
        .arg("-signature")
        .arg(value)
        .arg(document)
        .output()
        .expect("OpenSSL CLI is required for provider integration tests");
    output.status.success()
}

pub fn verify_cades_with_cli(certificate: &X509, encoded: &[u8], detached: Option<&[u8]>) -> bool {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("signature.der"), encoded).unwrap();
    fs::write(
        directory.path().join("trust.pem"),
        certificate.to_pem().unwrap(),
    )
    .unwrap();
    let mut command = Command::new("openssl");
    command.current_dir(directory.path()).args([
        "cms",
        "-verify",
        "-cades",
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
    if let Some(message) = detached {
        fs::write(directory.path().join("document.bin"), message).unwrap();
        command.args(["-content", "document.bin"]);
    }
    let result = command
        .output()
        .expect("OpenSSL CLI is required for CAdES tests");
    result.status.success() && fs::read(directory.path().join("verified.bin")).unwrap() == MESSAGE
}
