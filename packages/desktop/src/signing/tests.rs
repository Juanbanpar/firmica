use super::*;
use firmica_signing::SignatureAlgorithm::{EcdsaP256Sha256 as EC, RsaPkcs1v15Sha256 as RSA};
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
use secrecy::ExposeSecret;
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{symlink, MetadataExt},
    process::Command,
};

const PASSWORD: &str = "synthetic test only";
const DOCUMENT: &[u8] = b"Frozen local document\x00\xff\r\n";

#[test]
fn bounded_reads_reject_nonregular_and_oversize_inputs() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("document");
    fs::write(&path, DOCUMENT).unwrap();
    assert_eq!(
        read_bounded(&path, DOCUMENT.len()).unwrap().expose_secret(),
        DOCUMENT
    );
    assert!(matches!(
        read_bounded(&path, DOCUMENT.len() - 1),
        Err(Error::InputTooLarge)
    ));
    assert!(matches!(
        read_bounded(temp.path(), 1024),
        Err(Error::ReadInput)
    ));
    assert!(matches!(
        read_bounded(&temp.path().join("absent"), 1024),
        Err(Error::ReadInput)
    ));
    let fifo = temp.path().join("pipe");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    assert!(matches!(read_bounded(&fifo, 1024), Err(Error::ReadInput)));
}

#[test]
fn publication_is_private_and_never_overwrites_files_or_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let active = AtomicBool::new(false);
    let target = temp.path().join("result.csig");
    save_new(&target, DOCUMENT, &active).unwrap();
    assert_eq!(fs::read(&target).unwrap(), DOCUMENT);
    assert_eq!(target.metadata().unwrap().mode() & 0o777, 0o600);
    assert!(matches!(
        save_new(&target, b"replacement", &active),
        Err(Error::DestinationExists)
    ));
    assert_eq!(fs::read(&target).unwrap(), DOCUMENT);
    for (name, destination) in [
        ("link", target.clone()),
        ("dangling", temp.path().join("absent")),
    ] {
        let link = temp.path().join(name);
        symlink(&destination, &link).unwrap();
        assert!(matches!(
            save_new(&link, b"replacement", &active),
            Err(Error::DestinationExists)
        ));
        assert_eq!(fs::read_link(&link).unwrap(), destination);
    }
    let cancelled = temp.path().join("cancelled.csig");
    assert!(matches!(
        save_new(&cancelled, DOCUMENT, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(!cancelled.exists());
    assert_eq!(
        fs::read_dir(temp.path()).unwrap().count(),
        3,
        "temporary outputs must be removed"
    );
}

fn fixture(directory: &Path, algorithm: SignatureAlgorithm, ca: bool) -> X509 {
    let key = match algorithm {
        RSA => PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
        EC => PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap(),
    };
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "Firmica synthetic desktop")
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(23).unwrap()).unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if ca {
        constraints.ca();
    }
    builder
        .append_extension(constraints.build().unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let certificate = builder.build();
    let container = Pkcs12::builder()
        .pkey(&key)
        .cert(&certificate)
        .build2(PASSWORD)
        .unwrap()
        .to_der()
        .unwrap();
    fs::write(directory.join("identity.p12"), container).unwrap();
    fs::write(directory.join("document.bin"), DOCUMENT).unwrap();
    fs::write(
        directory.join("certificate.pem"),
        certificate.to_pem().unwrap(),
    )
    .unwrap();
    certificate
}

fn worker() -> PathBuf {
    PathBuf::from(
        std::env::var_os("FIRMICA_TEST_WORKER").expect("set an absolute FIRMICA_TEST_WORKER path"),
    )
}
fn open(
    directory: &Path,
    algorithm: SignatureAlgorithm,
    mode: ContentMode,
) -> Result<Prepared, Error> {
    Prepared::open(
        &worker(),
        &directory.join("document.bin"),
        &directory.join("identity.p12"),
        SecretString::from(PASSWORD),
        algorithm,
        mode,
    )
}
fn children() -> BTreeSet<u32> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .flat_map(|task| {
            fs::read_to_string(task.unwrap().path().join("children"))
                .unwrap_or_default()
                .split_whitespace()
                .map(|pid| pid.parse().unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
#[ignore = "requires FIRMICA_TEST_WORKER; run serially against the built companion"]
fn approved_frozen_documents_verify_after_worker_exit() {
    for algorithm in [RSA, EC] {
        for mode in [ContentMode::Attached, ContentMode::Detached] {
            let temp = tempfile::tempdir().unwrap();
            fixture(temp.path(), algorithm, false);
            let before = children();
            let pending = open(temp.path(), algorithm, mode).unwrap();
            assert_eq!(children().difference(&before).count(), 1);
            assert_eq!(pending.review().document_size(), DOCUMENT.len());
            fs::write(temp.path().join("document.bin"), b"changed after review").unwrap();
            pending
                .sign_and_save(&temp.path().join("result.csig"), &AtomicBool::new(false))
                .unwrap();
            assert_eq!(
                children(),
                before,
                "worker cleanup must complete before publication"
            );
            fs::write(temp.path().join("original.bin"), DOCUMENT).unwrap();
            let mut command = Command::new("openssl");
            command.current_dir(temp.path()).args([
                "cms",
                "-verify",
                "-cades",
                "-binary",
                "-inform",
                "DER",
                "-in",
                "result.csig",
                "-CAfile",
                "certificate.pem",
                "-no-CApath",
                "-no-CAstore",
                "-partial_chain",
                "-purpose",
                "any",
                "-out",
                "verified.bin",
            ]);
            if mode == ContentMode::Detached {
                command.args(["-content", "original.bin"]);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                fs::read(temp.path().join("verified.bin")).unwrap(),
                DOCUMENT
            );
        }
    }
}

#[test]
#[ignore = "requires FIRMICA_TEST_WORKER; run serially against the built companion"]
fn cancellation_policy_import_and_destination_failures_leave_no_output_or_worker() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path(), EC, false);
    let before = children();
    open(temp.path(), EC, ContentMode::Attached)
        .unwrap()
        .cancel()
        .unwrap();
    assert_eq!(children(), before);
    let pending = open(temp.path(), EC, ContentMode::Attached).unwrap();
    assert!(matches!(
        pending.sign_and_save(&temp.path().join("cancelled.csig"), &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(!temp.path().join("cancelled.csig").exists());
    assert_eq!(children(), before);
    let pending = open(temp.path(), EC, ContentMode::Attached).unwrap();
    assert!(matches!(
        pending.sign_and_save(&temp.path().join("document.bin"), &AtomicBool::new(false)),
        Err(Error::DestinationExists)
    ));
    assert_eq!(
        fs::read(temp.path().join("document.bin")).unwrap(),
        DOCUMENT
    );
    assert_eq!(children(), before);
    assert!(matches!(
        Prepared::open(
            &worker(),
            &temp.path().join("document.bin"),
            &temp.path().join("identity.p12"),
            SecretString::from("wrong"),
            EC,
            ContentMode::Attached
        ),
        Err(Error::Worker(_))
    ));
    assert_eq!(children(), before);
    fixture(temp.path(), EC, true);
    assert!(matches!(
        open(temp.path(), EC, ContentMode::Attached),
        Err(Error::Approval(ApprovalError::CertificateRestricted(_)))
    ));
    assert_eq!(children(), before);
}

#[test]
#[ignore = "requires FIRMICA_TEST_WORKER; run serially against the built companion"]
fn worker_failure_blocks_publication_and_is_reaped() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path(), EC, false);
    let before = children();
    let pending = open(temp.path(), EC, ContentMode::Attached).unwrap();
    let pid = *children().difference(&before).next().unwrap();
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(pid as i32).unwrap(),
        rustix::process::Signal::KILL,
    )
    .unwrap();
    assert!(matches!(
        pending.sign_and_save(&temp.path().join("failed.csig"), &AtomicBool::new(false)),
        Err(Error::Worker(_))
    ));
    assert!(!temp.path().join("failed.csig").exists());
    assert_eq!(children(), before);
}
