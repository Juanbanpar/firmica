use crate::Error;
use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    string::{CFString, CFStringRef},
};
use security_framework::{
    identity::SecIdentity,
    key::{Algorithm, SecKey},
    os::macos::keychain::SecKeychain,
};
use security_framework_sys::{
    base::{
        errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
        errSecSuccess as ERR_SEC_SUCCESS,
    },
    item::{
        kSecClass, kSecClassIdentity, kSecMatchLimit, kSecMatchLimitAll, kSecMatchSearchList,
        kSecReturnPersistentRef, kSecReturnRef, kSecUseAuthenticationUI, kSecValueRef,
    },
    key::{kSecKeyOperationTypeSign, SecKeyIsAlgorithmSupported},
    keychain_item::SecItemCopyMatching,
};
use std::ptr;

const INTERACTION_NOT_ALLOWED: i32 = -25308;
const MAX_REFERENCE_BYTES: usize = 8 * 1024;

extern "C" {
    static kSecValuePersistentRef: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
}

pub(super) struct Identity {
    pub(super) identity: SecIdentity,
    pub(super) reference: Vec<u8>,
}

pub(super) fn identities(keychains: &[SecKeychain]) -> Result<Vec<Identity>, Error> {
    let mut pairs = Vec::new();
    // SAFETY: these are live, immutable Security.framework constants. The
    // query retains both keys and values for the synchronous native call.
    unsafe {
        pairs.push((
            CFString::wrap_under_get_rule(kSecClass),
            CFString::wrap_under_get_rule(kSecClassIdentity).into_CFType(),
        ));
        pairs.push((
            CFString::wrap_under_get_rule(kSecMatchLimit),
            CFString::wrap_under_get_rule(kSecMatchLimitAll).into_CFType(),
        ));
        pairs.push((
            CFString::wrap_under_get_rule(kSecReturnRef),
            CFBoolean::true_value().into_CFType(),
        ));
        pairs.push((
            CFString::wrap_under_get_rule(kSecReturnPersistentRef),
            CFBoolean::true_value().into_CFType(),
        ));
        pairs.push((
            CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
            CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
        ));
        if !keychains.is_empty() {
            pairs.push((
                CFString::wrap_under_get_rule(kSecMatchSearchList),
                CFArray::from_CFTypes(keychains).into_CFType(),
            ));
        }
    }

    let query = CFDictionary::from_CFType_pairs(&pairs);
    let mut result = ptr::null();
    // SAFETY: the dictionary is live and the result is a writable output parameter.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    match status {
        ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
        ERR_SEC_AUTH_FAILED | INTERACTION_NOT_ALLOWED => return Err(Error::AuthenticationRequired),
        ERR_SEC_SUCCESS if !result.is_null() => {}
        _ => return Err(Error::Backend),
    }

    // SAFETY: a successful non-null result belongs to the caller. We check the
    // runtime type before treating it as an array of item dictionaries.
    let result = unsafe { CFType::wrap_under_create_rule(result) };
    let items = result.downcast::<CFArray>().ok_or(Error::Backend)?;
    let mut identities = Vec::new();
    for item in &items {
        // SAFETY: array values are Core Foundation objects retained by the array.
        let item = unsafe { CFType::wrap_under_get_rule(*item) };
        let item = item.downcast::<CFDictionary>().ok_or(Error::Backend)?;
        // SAFETY: both keys are Security.framework constants.
        let (reference_key, identity_key) = unsafe { (kSecValuePersistentRef, kSecValueRef) };
        let Some(reference) = value(&item, reference_key).and_then(|v| v.downcast::<CFData>())
        else {
            continue;
        };
        if reference.is_empty() || reference.len() as usize > MAX_REFERENCE_BYTES {
            continue;
        }
        if let Some(identity) = value(&item, identity_key).and_then(|v| v.downcast::<SecIdentity>())
        {
            identities.push(Identity {
                identity,
                reference: reference.bytes().to_vec(),
            });
        }
    }
    Ok(identities)
}

fn value(item: &CFDictionary, key: CFStringRef) -> Option<CFType> {
    let value = item.find(key.cast::<std::ffi::c_void>())?;
    // SAFETY: SecItemCopyMatching returns dictionaries whose values are Core
    // Foundation objects. Retain the value for use beyond this borrow.
    Some(unsafe { CFType::wrap_under_get_rule(*value) })
}

pub(super) fn supports_signing(key: &SecKey, algorithm: Algorithm) -> bool {
    // SAFETY: key is live and the algorithm is one of the framework constants.
    unsafe {
        SecKeyIsAlgorithmSupported(
            key.as_concrete_TypeRef(),
            kSecKeyOperationTypeSign,
            algorithm.into(),
        ) != 0
    }
}
