use super::*;
use crate::signing::native::NativeSource;
use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::TCFType,
};
use security_framework::{
    import_export::Pkcs12ImportOptions,
    os::macos::keychain::{CreateOptions, SecKeychain, SecPreferencesDomain},
};
use security_framework_sys::base::SecKeychainRef;
use std::ptr;

extern "C" {
    fn SecKeychainCopyDomainSearchList(
        domain: SecPreferencesDomain,
        search_list: *mut CFArrayRef,
    ) -> i32;
    fn SecKeychainSetDomainSearchList(domain: SecPreferencesDomain, search_list: CFArrayRef)
        -> i32;
    fn SecKeychainDelete(keychain: SecKeychainRef) -> i32;
}

#[test]
#[ignore = "adds and removes a disposable Keychain from the test account's search list"]
fn keychain_selection_reviews_and_saves_with_native_keys() {
    // Never display dialogs on a hosted runner. The app does not use this
    // process-global switch.
    let _interaction = SecKeychain::user_interaction_allowed()
        .unwrap()
        .then(|| SecKeychain::disable_user_interaction().unwrap());
    for (algorithm, profile) in [(RSA, "rsa"), (EC, "p256")] {
        let (mut fixture, der) = KeychainFixture::new(algorithm);
        super::native_store::exercise(NativeSource::Keychain, algorithm, profile, &der, || {
            fixture.remove();
        });
    }
}

struct KeychainFixture {
    keychain: Option<SecKeychain>,
    _dir: tempfile::TempDir,
}

impl KeychainFixture {
    fn new(algorithm: SignatureAlgorithm) -> (Self, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let keychain = CreateOptions::new()
            .password(PASSWORD)
            .create(dir.path().join("firmica-desktop.keychain"))
            .unwrap();
        let fixture = Self {
            keychain: Some(keychain),
            _dir: dir,
        };
        let keychain = fixture.keychain.as_ref().unwrap();
        let (key, certificate) = synthetic_identity(algorithm, false);
        let container = Pkcs12::builder()
            .pkey(&key)
            .cert(&certificate)
            .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
            .cert_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
            .mac_md(MessageDigest::sha1())
            .build2(PASSWORD)
            .unwrap()
            .to_der()
            .unwrap();
        let imported = Pkcs12ImportOptions::new()
            .passphrase(PASSWORD)
            .keychain(keychain.clone())
            .import(&container)
            .unwrap();
        assert_eq!(imported.len(), 1);

        let mut raw_list = ptr::null();
        // SAFETY: the output is writable and a successful call returns an owned array of keychains.
        assert_eq!(
            unsafe { SecKeychainCopyDomainSearchList(SecPreferencesDomain::User, &mut raw_list) },
            0
        );
        assert!(!raw_list.is_null());
        let original = unsafe { CFArray::<SecKeychain>::wrap_under_create_rule(raw_list) };
        let mut list: Vec<SecKeychain> = original
            .iter()
            .map(|keychain| (*keychain).clone())
            .collect();
        list.push(keychain.clone());
        let list = CFArray::from_CFTypes(&list);
        // SAFETY: this array keeps the existing search entries and adds only our disposable keychain.
        assert_eq!(
            unsafe {
                SecKeychainSetDomainSearchList(
                    SecPreferencesDomain::User,
                    list.as_concrete_TypeRef(),
                )
            },
            0
        );
        (fixture, certificate.to_der().unwrap())
    }

    fn remove(&mut self) {
        assert_eq!(self.delete(), 0, "temporary Keychain cleanup failed");
    }

    fn delete(&mut self) -> i32 {
        let Some(keychain) = &self.keychain else {
            return 0;
        };
        // SAFETY: the handle belongs to this fixture. Deletion also removes this keychain
        // from the search list without resetting other entries.
        let status = unsafe { SecKeychainDelete(keychain.as_concrete_TypeRef()) };
        if status == 0 {
            self.keychain.take();
        }
        status
    }
}

impl Drop for KeychainFixture {
    fn drop(&mut self) {
        self.delete();
    }
}
