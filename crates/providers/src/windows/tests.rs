use super::*;
use crate::Registry;
use firmica_core::signing::SigningReview;
use firmica_signing::format::{ContentMode, Format, PdfOptions, XmlMode};
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    hash::MessageDigest,
    rand::rand_bytes,
    sign::Verifier,
    x509::X509Name,
};
use std::ptr;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Cryptography::*;

const DOCUMENT: &[u8] = b"Firmica synthetic Windows provider document";

#[test]
fn native_cng_rsa_and_p256_sign_and_verify_all_formats() {
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        SignatureAlgorithm::EcdsaP256Sha256,
    ] {
        let key = TestKey::new(Some(algorithm));
        exercise(&key, algorithm);
    }
}

#[test]
fn native_capi_rsa_signs_with_legacy_provider() {
    let key = TestKey::new(None);
    exercise(&key, SignatureAlgorithm::RsaPkcs1v15Sha256);
}

#[test]
fn native_key_removal_blocks_signing_with_a_retained_certificate() {
    let algorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
    let key = TestKey::new(Some(algorithm));
    let store = TestStore::new();
    let context = store.add(&key, algorithm);
    // SAFETY: release the returned context reference while retaining the store entry.
    assert_ne!(unsafe { CertFreeCertificateContext(context) }, 0);
    let (mut registry, id) = registry_for(store.source.clone());
    let candidates = registry.discover(&id).unwrap();
    let mut session = registry
        .open(Selection::Candidate(&candidates[0]), Credentials::None)
        .unwrap();
    drop(key);
    assert!(matches!(
        session.sign(algorithm, SigningInput::Message(DOCUMENT)),
        Err(SigningError::BackendFailure)
    ));
    session.close().unwrap();
}

fn exercise(key: &TestKey, algorithm: SignatureAlgorithm) {
    let store = TestStore::new();
    let context = store.add(key, algorithm);
    let (mut registry, id) = registry_for(store.source.clone());
    let candidates = registry.discover(&id).unwrap();
    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    assert_eq!(candidate.authentication(), Authentication::ProviderManaged);
    assert_eq!(candidate.availability(), Availability::Locked);
    assert_eq!(candidate.capabilities().len(), 2);

    let mut public_source = store.source.clone();
    public_source.public_only = true;
    let (mut public, public_id) = registry_for(public_source);
    let public_candidates = public.discover(&public_id).unwrap();
    assert_eq!(
        public_candidates[0].availability(),
        Availability::PublicOnly
    );
    assert!(matches!(
        public.open(
            Selection::Candidate(&public_candidates[0]),
            Credentials::None
        ),
        Err(Error::NotSigningIdentity)
    ));

    let selection = Selection::Candidate(candidate);
    let certificate = X509::from_der(&candidate.identity().certificate_der).unwrap();
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
        let encoded = review.approve().sign(&mut session).unwrap();
        session.close().unwrap();
        match format {
            Format::Cades(_) => {
                let mut signature = CmsContentInfo::from_der(&encoded).unwrap();
                let mut content = Vec::new();
                signature
                    .verify(
                        None,
                        None,
                        None,
                        Some(&mut content),
                        CMSOptions::NO_SIGNER_CERT_VERIFY,
                    )
                    .unwrap();
                assert_eq!(content, DOCUMENT);
            }
            Format::Pades(_) => assert!(encoded.starts_with(pdf) && encoded.len() > pdf.len()),
            Format::Xades(_) => assert!(String::from_utf8(encoded)
                .unwrap()
                .contains("<ds:SignatureValue>")),
        }
    }

    let mut session = registry.open(selection, Credentials::None).unwrap();
    let stop = std::sync::atomic::AtomicBool::new(true);
    assert!(matches!(
        session
            .cancellable(&stop)
            .sign(algorithm, SigningInput::Message(DOCUMENT)),
        Err(SigningError::BackendFailure)
    ));
    session.close().unwrap();
    let mut session = registry.open(selection, Credentials::None).unwrap();
    // SAFETY: the context belongs to this unique test store and Delete consumes it.
    assert_ne!(unsafe { CertDeleteCertificateFromStore(context) }, 0);
    assert!(matches!(
        session.sign(algorithm, SigningInput::Message(DOCUMENT)),
        Err(SigningError::BackendFailure)
    ));
    session.close().unwrap();
    assert!(matches!(
        registry.open(selection, Credentials::None),
        Err(Error::StaleIdentity)
    ));
}

fn registry_for(source: Source) -> (Registry, ProviderId) {
    let mut registry = Registry::default();
    let id = ProviderId::new("windows-test");
    registry
        .register(WindowsProvider {
            id: id.clone(),
            source,
        })
        .unwrap();
    (registry, id)
}

struct TestStore {
    source: Source,
    handle: HCERTSTORE,
}

impl TestStore {
    fn new() -> Self {
        let name = unique_name();
        let source = Source::new(&name, CERT_SYSTEM_STORE_CURRENT_USER, false);
        // SAFETY: creates a private, uniquely named store in the current user's registry.
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_REGISTRY_W,
                0,
                0,
                source.location | CERT_STORE_CREATE_NEW_FLAG,
                source.name.as_ptr().cast(),
            )
        };
        assert!(!handle.is_null(), "test store creation failed");
        Self { source, handle }
    }

    fn add(&self, key: &TestKey, algorithm: SignatureAlgorithm) -> *mut CERT_CONTEXT {
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", "Firmica synthetic Windows provider")
            .unwrap();
        let mut der = name.build().to_der().unwrap();
        let subject = CRYPT_INTEGER_BLOB {
            cbData: der.len() as u32,
            pbData: der.as_mut_ptr(),
        };
        let signature = CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: match algorithm {
                SignatureAlgorithm::RsaPkcs1v15Sha256 => szOID_RSA_SHA256RSA,
                SignatureAlgorithm::EcdsaP256Sha256 => szOID_ECDSA_SHA256,
            }
            .cast_mut(),
            ..Default::default()
        };
        let info = key.info();
        // SAFETY: all inputs are live, including the persisted key, provider names and subject.
        let certificate = unsafe {
            CertCreateSelfSignCertificate(
                0,
                &subject,
                0,
                &info,
                &signature,
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        assert!(
            !certificate.is_null(),
            "self-signed certificate creation failed ({:#x})",
            unsafe { GetLastError() }
        );
        let mut stored = ptr::null_mut();
        // SAFETY: persist the synthetic certificate and its key association in this test store.
        let added = unsafe {
            let added = CertAddCertificateContextToStore(
                self.handle,
                certificate,
                CERT_STORE_ADD_NEW,
                &mut stored,
            );
            CertFreeCertificateContext(certificate);
            added
        };
        assert_ne!(added, 0, "test certificate could not be added");
        stored
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        // SAFETY: release the test store and unregister only its unique name.
        unsafe {
            CertCloseStore(self.handle, CERT_CLOSE_STORE_FORCE_FLAG);
            CertUnregisterSystemStore(self.source.name.as_ptr().cast(), self.source.location);
        }
    }
}

struct TestKey {
    name: Vec<u16>,
    provider_name: *const u16,
    cng_provider: usize,
    handle: usize,
}

impl TestKey {
    fn new(cng: Option<SignatureAlgorithm>) -> Self {
        let mut key = Self {
            name: unique_name().encode_utf16().chain([0]).collect(),
            provider_name: if cng.is_some() {
                MS_KEY_STORAGE_PROVIDER
            } else {
                MS_ENH_RSA_AES_PROV_W
            },
            cng_provider: 0,
            handle: 0,
        };
        // SAFETY: all handles and container names are owned by this fixture. Omitting
        // export flags leaves both types of synthetic private key non-exportable.
        unsafe {
            if let Some(algorithm) = cng {
                assert_eq!(
                    NCryptOpenStorageProvider(&mut key.cng_provider, key.provider_name, 0),
                    0
                );
                let native_algorithm = match algorithm {
                    SignatureAlgorithm::RsaPkcs1v15Sha256 => BCRYPT_RSA_ALGORITHM,
                    SignatureAlgorithm::EcdsaP256Sha256 => BCRYPT_ECDSA_P256_ALGORITHM,
                };
                assert_eq!(
                    NCryptCreatePersistedKey(
                        key.cng_provider,
                        &mut key.handle,
                        native_algorithm,
                        key.name.as_ptr(),
                        0,
                        0
                    ),
                    0
                );
                if algorithm == SignatureAlgorithm::RsaPkcs1v15Sha256 {
                    assert_eq!(
                        NCryptSetProperty(
                            key.handle,
                            NCRYPT_LENGTH_PROPERTY,
                            2048u32.to_le_bytes().as_ptr(),
                            4,
                            0
                        ),
                        0
                    );
                }
                assert_eq!(NCryptFinalizeKey(key.handle, 0), 0);
            } else {
                assert_ne!(
                    CryptAcquireContextW(
                        &mut key.handle,
                        key.name.as_ptr(),
                        key.provider_name,
                        PROV_RSA_AES,
                        CRYPT_NEWKEYSET
                    ),
                    0
                );
                let mut generated = 0;
                assert_ne!(
                    CryptGenKey(key.handle, AT_SIGNATURE, 2048 << 16, &mut generated),
                    0
                );
                assert_ne!(CryptDestroyKey(generated), 0);
            }
        }
        key
    }

    fn info(&self) -> CRYPT_KEY_PROV_INFO {
        let legacy = self.cng_provider == 0;
        CRYPT_KEY_PROV_INFO {
            pwszContainerName: self.name.as_ptr().cast_mut(),
            pwszProvName: self.provider_name.cast_mut(),
            dwProvType: if legacy { PROV_RSA_AES } else { 0 },
            dwKeySpec: if legacy {
                AT_SIGNATURE
            } else {
                CERT_NCRYPT_KEY_SPEC
            },
            ..Default::default()
        }
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        // SAFETY: only handles and these unique key names from this fixture are used for cleanup.
        unsafe {
            if self.cng_provider != 0 {
                if self.handle != 0 && NCryptDeleteKey(self.handle, 0) != 0 {
                    NCryptFreeObject(self.handle);
                }
                NCryptFreeObject(self.cng_provider);
            } else if self.handle != 0 {
                CryptReleaseContext(self.handle, 0);
                let mut ignored = 0;
                CryptAcquireContextW(
                    &mut ignored,
                    self.name.as_ptr(),
                    self.provider_name,
                    PROV_RSA_AES,
                    CRYPT_DELETEKEYSET,
                );
            }
        }
    }
}

fn unique_name() -> String {
    let mut bytes = [0; 16];
    rand_bytes(&mut bytes).unwrap();
    format!("FirmicaProviderTest-{:032x}", u128::from_ne_bytes(bytes))
}
