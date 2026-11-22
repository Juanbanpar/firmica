use crate::Error;
use firmica_signing::limits::MAX_CERTIFICATE_BYTES;
use secrecy::{ExposeSecretMut, SecretBox};
use sha2::{Digest, Sha256};
use std::{mem::size_of, ptr, slice};
use windows_sys::Win32::{
    Foundation::{GetLastError, CRYPT_E_NOT_FOUND, ERROR_NO_MORE_FILES},
    Security::Cryptography::{
        CertCloseStore, CertDuplicateCertificateContext, CertEnumCertificatesInStore,
        CertFreeCertificateContext, CertGetCertificateContextProperty, CertOpenStore,
        CERT_CLOSE_STORE_CHECK_FLAG, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID,
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CRYPT_KEY_PROV_INFO, HCERTSTORE,
    },
};

const MAX_PROPERTY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(super) struct Source {
    pub(super) name: Vec<u16>,
    pub(super) location: u32,
    pub(super) public_only: bool,
}

impl Source {
    pub(super) fn new(name: &str, location: u32, public_only: bool) -> Self {
        Self {
            name: name.encode_utf16().chain([0]).collect(),
            location,
            public_only,
        }
    }

    pub(super) fn read<T>(
        &self,
        read: impl FnOnce(&Store) -> Result<T, Error>,
    ) -> Result<T, Error> {
        // SAFETY: the named-system-store provider expects a terminated UTF-16 name.
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                self.location | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                self.name.as_ptr().cast(),
            )
        };
        if handle.is_null() {
            return Err(Error::Unavailable);
        }
        let store = Store(handle);
        let result = read(&store);
        store.close()?;
        result
    }
}

pub(super) struct Store(HCERTSTORE);

impl Store {
    pub(super) fn enumerate(
        &self,
        mut visit: impl FnMut(&Context) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut previous = Context(ptr::null_mut());
        loop {
            // SAFETY: the live store owns the enumeration; the call takes the previous reference.
            let next = unsafe { CertEnumCertificatesInStore(self.0, previous.take()) };
            if next.is_null() {
                // SAFETY: read immediately after the unsuccessful enumeration.
                let error = unsafe { GetLastError() };
                return if error == CRYPT_E_NOT_FOUND as u32 || error == ERROR_NO_MORE_FILES {
                    Ok(())
                } else {
                    Err(Error::Backend)
                };
            }
            previous = Context(next);
            visit(&previous)?;
        }
    }

    fn close(mut self) -> Result<(), Error> {
        let handle = std::mem::replace(&mut self.0, ptr::null_mut());
        // SAFETY: the handle is live and is closed even when this flag reports open contexts.
        if unsafe { CertCloseStore(handle, CERT_CLOSE_STORE_CHECK_FLAG) } == 0 {
            return Err(Error::Cleanup);
        }
        Ok(())
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this owns the still-live handle.
            unsafe { CertCloseStore(self.0, 0) };
        }
    }
}

pub(super) struct Context(*mut CERT_CONTEXT);

impl Context {
    pub(super) fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.0
    }

    pub(super) fn duplicate(&self) -> Result<Self, Error> {
        // SAFETY: self retains a live context for the duration of the call.
        let context = unsafe { CertDuplicateCertificateContext(self.0) };
        if context.is_null() {
            return Err(Error::Backend);
        }
        Ok(Self(context))
    }

    pub(super) fn der(&self) -> Option<&[u8]> {
        // SAFETY: visits only receive live certificate contexts. The buffer is owned by the context.
        let context = unsafe { &*self.0 };
        let len = context.cbCertEncoded as usize;
        if len == 0 || len > MAX_CERTIFICATE_BYTES || context.pbCertEncoded.is_null() {
            return None;
        }
        // SAFETY: the documented byte length and buffer lifetime belong to the context.
        Some(unsafe { slice::from_raw_parts(context.pbCertEncoded, len) })
    }

    pub(super) fn key_info(&self) -> Result<Option<KeyInfo>, Error> {
        let mut len = 0;
        // SAFETY: the null output asks only for the property size. This does not open the key.
        if unsafe {
            CertGetCertificateContextProperty(
                self.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                ptr::null_mut(),
                &mut len,
            )
        } == 0
        {
            // SAFETY: read immediately after the unsuccessful property lookup.
            return if unsafe { GetLastError() } == CRYPT_E_NOT_FOUND as u32 {
                Ok(None)
            } else {
                Err(Error::Backend)
            };
        }

        let capacity = len as usize;
        if !(size_of::<CRYPT_KEY_PROV_INFO>()..=MAX_PROPERTY_BYTES).contains(&capacity) {
            return Err(Error::Backend);
        }
        // The property writes a structure with pointers followed by its referenced data.
        let mut property = SecretBox::new(Box::new(vec![
            0usize;
            capacity.div_ceil(size_of::<usize>())
        ]));
        let base = property.expose_secret_mut().as_mut_ptr();
        // SAFETY: the allocation is aligned for CRYPT_KEY_PROV_INFO and holds at least len bytes.
        if unsafe {
            CertGetCertificateContextProperty(
                self.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                base.cast(),
                &mut len,
            )
        } == 0
            || !(size_of::<CRYPT_KEY_PROV_INFO>()..=capacity).contains(&(len as usize))
        {
            return Err(Error::Backend);
        }
        // SAFETY: the successful call initialized the structure and the returned bytes.
        let info = unsafe { &*base.cast::<CRYPT_KEY_PROV_INFO>() };
        let bytes = unsafe { slice::from_raw_parts(base.cast::<u8>(), len as usize) };
        let mut hash = Sha256::new();
        hash.update(info.dwProvType.to_le_bytes());
        hash.update(info.dwFlags.to_le_bytes());
        hash.update(info.dwKeySpec.to_le_bytes());
        // Only identifying fields participate. Provider parameters may contain credentials.
        for name in [info.pwszProvName, info.pwszContainerName] {
            let name = property_name(bytes, name)?;
            if name.is_empty() {
                return Err(Error::Backend);
            }
            hash.update((name.len() as u32).to_le_bytes());
            hash.update(name);
        }
        Ok(Some(KeyInfo {
            fingerprint: hash.finalize().into(),
            cng: info.dwProvType == 0,
        }))
    }

    pub(super) fn close(mut self) -> Result<(), Error> {
        let handle = self.take();
        // SAFETY: release the owned reference exactly once.
        if unsafe { CertFreeCertificateContext(handle) } == 0 {
            return Err(Error::Cleanup);
        }
        Ok(())
    }

    fn take(&mut self) -> *mut CERT_CONTEXT {
        std::mem::replace(&mut self.0, ptr::null_mut())
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: release the owned reference on an early return.
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }
}

pub(super) struct KeyInfo {
    pub(super) fingerprint: [u8; 32],
    pub(super) cng: bool,
}

fn property_name(bytes: &[u8], pointer: *const u16) -> Result<&[u8], Error> {
    if pointer.is_null() {
        return Ok(&[]);
    }
    // Use the pointer only as an offset; bound the UTF-16 scan to the returned buffer.
    let offset = (pointer as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .filter(|offset| offset.is_multiple_of(2) && *offset >= size_of::<CRYPT_KEY_PROV_INFO>())
        .ok_or(Error::Backend)?;
    let tail = bytes.get(offset..).ok_or(Error::Backend)?;
    let end = tail
        .as_chunks::<2>()
        .0
        .iter()
        .position(|code_unit| *code_unit == [0, 0])
        .ok_or(Error::Backend)?;
    Ok(&tail[..end * 2])
}
