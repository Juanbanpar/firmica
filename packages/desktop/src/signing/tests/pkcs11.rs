use super::*;
use crate::signing::native::{register, NativeSource};
use firmica_providers::{
    pkcs11::{Pkcs11Pins, Pkcs11Provider},
    pkcs12::WorkerError,
    CertificateCandidate, Error as ProviderError, Selection,
};
use firmica_signing::SigningInput;
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    pkey::{Private, Public},
};
use pkcs11_client::{
    object_reference, Attribute, AttributeType, Authentication, CertificateDocument, KeyKind,
    ManagementSession, NamedCurve, Pin, Provider, PublicKeyRef, SecretText, SessionMode,
};

const PIN: &str = "synthetic-user-1234";
const TOKEN: &str = "pkcs11:token=firmica-signing";

#[test]
#[ignore = "requires SoftHSM module, softhsm2-util, Poppler and XMLSec on Linux"]
fn pkcs11_review_sign_and_save_with_nonexportable_keys() {
    let Some(module) = std::env::var_os("FIRMICA_TEST_PKCS11_MODULE").map(PathBuf::from) else {
        eprintln!("Set FIRMICA_TEST_PKCS11_MODULE to exercise the SoftHSM desktop test");
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let store = Store::new(temp.path(), module);
    let issuer = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let root = certificate(&issuer, &issuer, 10);
    fs::write(temp.path().join("certificate.pem"), root.to_pem().unwrap()).unwrap();
    store.provision(&issuer);

    let (registry, source) = store.registry();
    let candidates = registry.discover(&source).unwrap();
    let input = temp.path().join("document");
    let no_output = temp.path().join("must-not-exist");
    let cancelled = AtomicBool::new(false);
    let format = Format::Cades(ContentMode::Attached);
    for (id, algorithm, context) in [(1, RSA, Some(PIN)), (2, EC, None)] {
        let candidate = find(&candidates, id);
        assert!(candidate.capabilities().is_empty());
        let pdf = include_bytes!("../../../../../crates/pades/tests/fixtures/document.pdf");
        for (format, document) in [
            (format.clone(), DOCUMENT),
            (Format::Pades(PdfOptions::default()), pdf.as_slice()),
            (Format::Xades(XmlMode::Enveloped), b"<document/>".as_slice()),
        ] {
            fs::write(&input, document).unwrap();
            let before = children();
            let pending = store
                .open(&input, candidate, PIN, context, format.clone())
                .unwrap();
            assert_eq!(pending.native_source(), Some(NativeSource::Pkcs11));
            assert_eq!(
                pending.review().certificate().fingerprint(),
                candidate.fingerprint()
            );
            assert_eq!(pending.review().algorithm(), algorithm);
            assert_eq!(*pending.review().format(), format);
            fs::write(&input, b"changed after review").unwrap();
            let target = temp
                .path()
                .join(format!("signature-{id}.{}", format.extension()));
            pending
                .sign_and_save(&target, &cancelled)
                .unwrap_or_else(|error| panic!("{algorithm:?} {format:?}: {error:?}"));
            assert_eq!(children(), before);
            let bytes = fs::read(target).unwrap();
            if matches!(format, Format::Cades(_)) {
                let mut cms = CmsContentInfo::from_der(&bytes).unwrap();
                let mut verified = Vec::new();
                cms.verify(
                    None,
                    None,
                    None,
                    Some(&mut verified),
                    CMSOptions::NO_SIGNER_CERT_VERIFY,
                )
                .unwrap();
                assert_eq!(verified, DOCUMENT);
            } else {
                verify_pdf_or_xml(temp.path(), &format, &bytes);
            }
        }
    }

    let rsa = find(&candidates, 1);
    let raw_rsa = find(&candidates, 5);
    let ec = find(&candidates, 2);
    assert!(matches!(
        store.open(&input, rsa, "wrong", None, format.clone()),
        Err(Error::Provider(ProviderError::Worker(
            WorkerError::TokenAuthentication
        )))
    ));
    assert!(matches!(
        store.open(&input, rsa, PIN, None, format.clone()),
        Err(Error::Provider(ProviderError::Worker(
            WorkerError::TokenAuthentication
        )))
    ));
    let before = children();
    let wrong_context = || {
        store
            .open(&input, rsa, PIN, Some("wrong"), format.clone())
            .unwrap()
    };
    wrong_context().cancel().unwrap();
    assert_eq!(children(), before);
    assert!(wrong_context()
        .sign_and_save(&no_output, &cancelled)
        .is_err());
    assert_eq!(children(), before);

    for id in [3, 4] {
        let result = store.open(&input, find(&candidates, id), PIN, None, format.clone());
        if id == 3 {
            assert!(matches!(
                result,
                Err(Error::Provider(ProviderError::StaleIdentity))
            ));
        } else {
            assert!(result
                .unwrap()
                .sign_and_save(&no_output, &cancelled)
                .is_err());
        }
    }
    assert!(!no_output.exists());

    let before = children();
    let pending = store
        .open(&input, rsa, PIN, Some(PIN), format.clone())
        .unwrap();
    let pid = *children().difference(&before).next().unwrap();
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(pid as i32).unwrap(),
        rustix::process::Signal::KILL,
    )
    .unwrap();
    assert!(pending.sign_and_save(&no_output, &cancelled).is_err());
    assert!(!no_output.exists());
    assert_eq!(children(), before);

    store.configure("slots.mechanisms = -CKM_SHA256_RSA_PKCS\n");
    assert!(matches!(
        store.open(&input, rsa, PIN, Some(PIN), format.clone()),
        Err(Error::Provider(ProviderError::NotSigningIdentity))
    ));
    let (mut registry, _) = store.registry();
    let mut key = registry
        .open(Selection::Candidate(raw_rsa), Credentials::Pin(PIN.into()))
        .unwrap();
    let digest = openssl::sha::sha256(DOCUMENT);
    let signature = key.sign(RSA, SigningInput::Sha256Digest(&digest)).unwrap();
    key.close().unwrap();
    let leaf = X509::from_der(&raw_rsa.identity().certificate_der).unwrap();
    let public = leaf.public_key().unwrap();
    let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &public).unwrap();
    assert!(verifier.verify_oneshot(&signature.value, DOCUMENT).unwrap());

    store.configure("slots.mechanisms = -CKM_ECDSA,CKM_ECDSA_SHA256\n");
    assert!(matches!(
        store.open(&input, ec, PIN, None, format.clone()),
        Err(Error::Provider(ProviderError::NotSigningIdentity))
    ));
    store.configure("");
    let pending = store
        .open(&input, rsa, PIN, Some(PIN), format.clone())
        .unwrap();
    store.with_session(|session| {
        let locator = std::str::from_utf8(rsa.reference().key())
            .unwrap()
            .parse()
            .unwrap();
        session.delete(&object_reference(locator).unwrap()).unwrap();
    });
    assert!(pending.sign_and_save(&no_output, &cancelled).is_err());
    assert!(!no_output.exists());
    assert!(matches!(
        store.open(&input, rsa, PIN, Some(PIN), format.clone()),
        Err(Error::Provider(ProviderError::StaleIdentity))
    ));
    let removed = Command::new("softhsm2-util")
        .args(["--delete-token", "--token", "firmica-signing"])
        .output()
        .unwrap();
    assert!(removed.status.success());
    assert!(matches!(
        store.open(&input, ec, PIN, None, format),
        Err(Error::Provider(ProviderError::StaleIdentity))
    ));
}

fn find(candidates: &[CertificateCandidate], id: u8) -> &CertificateCandidate {
    let id = format!("id=%{id:02X};");
    candidates
        .iter()
        .find(|candidate| {
            std::str::from_utf8(candidate.reference().key())
                .unwrap()
                .contains(&id)
        })
        .unwrap()
}

struct Store {
    module: PathBuf,
    config: PathBuf,
    tokens: PathBuf,
}

impl Store {
    fn new(directory: &Path, module: PathBuf) -> Self {
        let store = Self {
            module,
            config: directory.join("softhsm2.conf"),
            tokens: directory.join("tokens"),
        };
        fs::create_dir(&store.tokens).unwrap();
        store.configure("");
        // Only this test uses SoftHSM in the desktop test binary.
        std::env::set_var("SOFTHSM2_CONF", &store.config);
        let output = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                "firmica-signing",
                "--so-pin",
                "synthetic-so-1234",
                "--pin",
                PIN,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        store
    }

    fn configure(&self, extra: &str) {
        fs::write(
            &self.config,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n{extra}",
                self.tokens.display()
            ),
        )
        .unwrap();
    }

    fn with_session(&self, f: impl FnOnce(&mut ManagementSession<'_>)) {
        let provider = Provider::load(&self.module).unwrap();
        assert!(provider.info().manufacturer_id().contains("SoftHSM"));
        let pin = SecretText::from(PIN);
        let mut session = provider
            .management(
                &TOKEN.parse().unwrap(),
                SessionMode::ReadWrite,
                Authentication::User(Pin::Value(&pin)),
            )
            .unwrap();
        f(&mut session);
        session.close().unwrap();
        provider.finalize().unwrap();
    }

    fn provision(&self, issuer: &PKey<Private>) {
        self.with_session(|session| {
            for (id, kind) in [
                (1, KeyKind::Rsa { bits: 2048 }),
                (2, KeyKind::Ec(NamedCurve::P256)),
                (4, KeyKind::Rsa { bits: 2048 }),
                (5, KeyKind::Rsa { bits: 2048 }),
            ] {
                session
                    .generate_signing_key_pair(kind, &[id], b"synthetic key", id == 1)
                    .unwrap();
                let reference = object_reference(
                    format!("{TOKEN};id=%{id:02X};type=private")
                        .parse()
                        .unwrap(),
                )
                .unwrap();
                let attributes = session
                    .inspect(
                        &reference,
                        &[AttributeType::Sensitive, AttributeType::Extractable],
                    )
                    .unwrap();
                assert!(attributes[0]
                    .values
                    .as_ref()
                    .unwrap()
                    .expose_values()
                    .contains(&Attribute::Sensitive(true)));
                assert!(attributes[1]
                    .values
                    .as_ref()
                    .unwrap()
                    .expose_values()
                    .contains(&Attribute::Extractable(false)));
            }
            let public = |session: &mut ManagementSession<'_>, id| -> PKey<Public> {
                let reference =
                    PublicKeyRef::new(format!("{TOKEN};id=%{id:02X};type=public").parse().unwrap())
                        .unwrap();
                PKey::public_key_from_der(&session.export_classical_public_key(&reference).unwrap())
                    .unwrap()
            };
            for (id, key) in [(1, 1), (2, 2), (3, 1), (4, 1), (5, 5)] {
                let leaf = certificate(&public(session, key), issuer, id.into());
                let leaf = CertificateDocument::from_der(leaf.to_der().unwrap()).unwrap();
                session
                    .import_certificate(&leaf, &[id], b"same label")
                    .unwrap();
            }
        });
    }

    fn registry(&self) -> (Registry, firmica_providers::ProviderId) {
        register(Pkcs11Provider::new(worker(), self.module.clone()).unwrap()).unwrap()
    }

    fn open(
        &self,
        document: &Path,
        candidate: &CertificateCandidate,
        pin: &str,
        context: Option<&str>,
        format: Format,
    ) -> Result<Prepared, Error> {
        let pins = Pkcs11Pins {
            user: pin.into(),
            context: context.map(SecretString::from),
        };
        Prepared::open_native_from_registry(
            document,
            NativeSource::Pkcs11,
            candidate,
            Credentials::Token(pins),
            format,
            self.registry(),
        )
    }
}

fn certificate(
    key: &PKey<impl openssl::pkey::HasPublic>,
    issuer: &PKey<Private>,
    serial: u32,
) -> X509 {
    fn name(common: &str) -> X509Name {
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common).unwrap();
        name.build()
    }
    let is_root = serial == 10;
    let issuer_name = name("Firmica SoftHSM test root");
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap())
        .unwrap();
    let leaf_name = name("Firmica SoftHSM test leaf");
    cert.set_subject_name(if is_root { &issuer_name } else { &leaf_name })
        .unwrap();
    cert.set_issuer_name(&issuer_name).unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    if is_root {
        cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
            .unwrap();
    } else {
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    }
    cert.sign(issuer, MessageDigest::sha256()).unwrap();
    cert.build()
}
