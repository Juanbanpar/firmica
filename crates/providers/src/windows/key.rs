use super::store::Context;
use crate::Error;
use firmica_signing::SignatureAlgorithm;
use openssl::{bn::BigNum, ecdsa::EcdsaSig};
use std::ptr;
use windows_sys::Win32::Security::Cryptography::{
    CryptAcquireCertificatePrivateKey, CryptCreateHash, CryptDestroyHash, CryptReleaseContext,
    CryptSetHashParam, CryptSignHashW, NCryptFreeObject, NCryptSignHash, AT_KEYEXCHANGE,
    AT_SIGNATURE, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, CALG_SHA_256,
    CERT_NCRYPT_KEY_SPEC, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
    CRYPT_ACQUIRE_NO_HEALING, HP_HASHVAL, NCRYPT_PAD_PKCS1_FLAG,
};

pub(super) fn sign(
    context: &Context,
    algorithm: SignatureAlgorithm,
    digest: &[u8; 32],
    width: usize,
    cng: bool,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, Error> {
    if cancelled() {
        return Err(Error::Backend);
    }
    let key = Key::acquire(context)?;
    let result = match (key.spec, cng) {
        _ if cancelled() => Err(Error::Backend),
        (CERT_NCRYPT_KEY_SPEC, true) => key.sign_cng(algorithm, digest, width),
        (AT_SIGNATURE | AT_KEYEXCHANGE, false)
            if algorithm == SignatureAlgorithm::RsaPkcs1v15Sha256 =>
        {
            key.sign_csp(digest, width, cancelled)
        }
        _ => Err(Error::StaleIdentity),
    };
    key.close()?;
    result
}

struct Key {
    handle: usize,
    spec: u32,
    owned: bool,
}

impl Key {
    fn acquire(context: &Context) -> Result<Self, Error> {
        let (mut handle, mut spec, mut owned) = (0, 0, 0);
        // SAFETY: context is retained until this key is released. Only this signing
        // call may invoke native authorization UI. No cache or store repair is requested.
        let result = unsafe {
            CryptAcquireCertificatePrivateKey(
                context.as_ptr(),
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG
                    | CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                    | CRYPT_ACQUIRE_NO_HEALING,
                ptr::null(),
                &mut handle,
                &mut spec,
                &mut owned,
            )
        };
        if result == 0 || handle == 0 {
            return Err(Error::Backend);
        }
        Ok(Self {
            handle,
            spec,
            owned: owned != 0,
        })
    }

    fn sign_cng(
        &self,
        algorithm: SignatureAlgorithm,
        digest: &[u8; 32],
        width: usize,
    ) -> Result<Vec<u8>, Error> {
        let padding = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
        };
        let (parameters, flags) = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15Sha256 => {
                (ptr::from_ref(&padding).cast(), NCRYPT_PAD_PKCS1_FLAG)
            }
            SignatureAlgorithm::EcdsaP256Sha256 => (ptr::null(), 0),
        };
        let mut bytes = vec![0; width];
        let mut length = 0;
        // SAFETY: the CNG handle is live. The digest, output and optional padding
        // structure remain valid and the supplied lengths match their buffers.
        let status = unsafe {
            NCryptSignHash(
                self.handle,
                parameters,
                digest.as_ptr(),
                digest.len() as u32,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut length,
                flags,
            )
        };
        if status != 0 || length as usize != width {
            return Err(Error::Backend);
        }
        if algorithm == SignatureAlgorithm::EcdsaP256Sha256 {
            return p256_der(&bytes);
        }
        Ok(bytes)
    }

    fn sign_csp(
        &self,
        digest: &[u8; 32],
        width: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, Error> {
        let mut hash = 0;
        // SAFETY: this is the live legacy provider handle returned by CryptoAPI.
        if unsafe { CryptCreateHash(self.handle, CALG_SHA_256, 0, 0, &mut hash) } == 0 {
            return Err(Error::Backend);
        }
        let hash = Hash(hash);
        let mut bytes = vec![0; width];
        let mut length = bytes.len() as u32;
        // SAFETY: HP_HASHVAL expects exactly 32 bytes for the SHA-256 hash. The
        // signing output and length remain writable for the duration of the call.
        let signed = unsafe {
            CryptSetHashParam(hash.0, HP_HASHVAL, digest.as_ptr(), 0) != 0
                && !cancelled()
                && CryptSignHashW(
                    hash.0,
                    self.spec,
                    ptr::null(),
                    0,
                    bytes.as_mut_ptr(),
                    &mut length,
                ) != 0
        };
        hash.close()?;
        if !signed || length as usize != width {
            return Err(Error::Backend);
        }
        // CryptoAPI returns Microsoft CSP RSA signatures in little-endian order.
        bytes.reverse();
        Ok(bytes)
    }

    fn close(mut self) -> Result<(), Error> {
        if self.release() {
            Ok(())
        } else {
            Err(Error::Cleanup)
        }
    }

    fn release(&mut self) -> bool {
        if !std::mem::take(&mut self.owned) {
            return true;
        }
        // SAFETY: only caller-owned handles are released, using the corresponding API.
        unsafe {
            if self.spec == CERT_NCRYPT_KEY_SPEC {
                NCryptFreeObject(self.handle) == 0
            } else {
                CryptReleaseContext(self.handle, 0) != 0
            }
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.release();
    }
}

struct Hash(usize);

impl Hash {
    fn close(mut self) -> Result<(), Error> {
        let handle = std::mem::take(&mut self.0);
        // SAFETY: this hash handle belongs to this call and has not been closed.
        if unsafe { CryptDestroyHash(handle) } == 0 {
            return Err(Error::Cleanup);
        }
        Ok(())
    }
}

impl Drop for Hash {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: release the still-owned hash on an early return.
            unsafe { CryptDestroyHash(self.0) };
        }
    }
}

fn p256_der(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes: &[u8; 64] = bytes.try_into().map_err(|_| Error::Backend)?;
    let to_der = || {
        let r = BigNum::from_slice(&bytes[..32])?;
        let s = BigNum::from_slice(&bytes[32..])?;
        EcdsaSig::from_private_components(r, s)?.to_der()
    };
    to_der().map_err(|_| Error::Backend)
}
