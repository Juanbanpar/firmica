//! Borrowed PKCS#11 signing keys; module loading and authentication stay with the caller.
//!
//! Load only locally configured, trusted modules. A module is native executable code.
//! The caller must initialize the module, select/authenticate a session, and close it
//! explicitly after the key borrow ends. Check cleanup before publishing signatures;
//! a failed close must prevent publishing the result and reusing the module. This
//! adapter neither owns a PIN nor logs out other sessions sharing token login state.

use cryptoki::{
    context::Pkcs11,
    mechanism::{Mechanism, MechanismType},
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::Session,
};
use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use openssl::{bn::BigNum, ecdsa::EcdsaSig, x509::X509};

use crate::{algorithm, digest, verify, CertificateError};

/// A key handle tied to a caller-owned, authenticated session. No key export operation.
///
/// RSA currently uses CKM_SHA256_RSA_PKCS for messages only. ECDSA uses CKM_ECDSA
/// with an explicit SHA-256 digest and converts token r || s into DER. RSA digest
/// signing, RSA-PSS, other curves and CKA_ALWAYS_AUTHENTICATE keys are unsupported.
pub struct Pkcs11Key<'a> {
    session: &'a Session,
    handle: ObjectHandle,
    certificate: X509,
    identity: CertificateIdentity,
    capabilities: Vec<SigningCapability>,
}

impl<'a> Pkcs11Key<'a> {
    /// Bind an existing private-key handle to a selected leaf certificate.
    ///
    /// `context` must be the module that owns `session`; `handle` must belong to that
    /// session. The certificate is not trusted by this call. Binding to its public key
    /// is checked by verifying every generated signature before returning output.
    ///
    /// # Errors
    /// Rejects malformed DER, unsupported certificate keys, non-signing/non-private
    /// objects, per-operation authentication requirements and unavailable mechanisms.
    /// Native metadata/query errors return [`CertificateError::BackendFailure`].
    pub fn new(
        context: &Pkcs11,
        session: &'a Session,
        handle: ObjectHandle,
        certificate_der: &[u8],
    ) -> Result<Self, CertificateError> {
        let certificate =
            X509::from_der(certificate_der).map_err(|_| CertificateError::InvalidContainer)?;
        if certificate
            .to_der()
            .map_err(|_| CertificateError::InvalidContainer)?
            != certificate_der
        {
            return Err(CertificateError::InvalidContainer);
        }
        let public = certificate
            .public_key()
            .map_err(|_| CertificateError::BackendFailure)?;
        let algorithm = algorithm(&public)?;
        let attributes = session
            .get_attributes(
                handle,
                &[
                    AttributeType::Class,
                    AttributeType::KeyType,
                    AttributeType::Sign,
                    AttributeType::AlwaysAuthenticate,
                    AttributeType::AllowedMechanisms,
                ],
            )
            .map_err(|_| CertificateError::BackendFailure)?;
        let key_type = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15Sha256 => KeyType::RSA,
            SignatureAlgorithm::EcdsaP256Sha256 => KeyType::EC,
        };
        if !attributes.contains(&Attribute::Class(ObjectClass::PRIVATE_KEY))
            || !attributes.contains(&Attribute::KeyType(key_type))
            || !attributes.contains(&Attribute::Sign(true))
            || !attributes.contains(&Attribute::AlwaysAuthenticate(false))
        {
            return Err(CertificateError::UnsupportedKey);
        }
        let mechanism = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15Sha256 => MechanismType::SHA256_RSA_PKCS,
            SignatureAlgorithm::EcdsaP256Sha256 => MechanismType::ECDSA,
        };
        let slot = session
            .get_session_info()
            .map_err(|_| CertificateError::BackendFailure)?
            .slot_id();
        if !context
            .get_mechanism_list(slot)
            .map_err(|_| CertificateError::BackendFailure)?
            .contains(&mechanism)
        {
            return Err(CertificateError::UnsupportedKey);
        }
        let info = context
            .get_mechanism_info(slot, mechanism)
            .map_err(|_| CertificateError::BackendFailure)?;
        let disallowed = attributes.iter().any(|attribute| matches!(attribute,
            Attribute::AllowedMechanisms(allowed) if !allowed.is_empty() && !allowed.contains(&mechanism)));
        let bits = public.bits() as usize;
        if !info.sign() || bits < info.min_key_size() || bits > info.max_key_size() || disallowed {
            return Err(CertificateError::UnsupportedKey);
        }
        let mut capabilities = vec![SigningCapability {
            algorithm,
            input: InputKind::Message,
        }];
        if algorithm == SignatureAlgorithm::EcdsaP256Sha256 {
            capabilities.push(SigningCapability {
                algorithm,
                input: InputKind::Sha256Digest,
            });
        }
        Ok(Self {
            session,
            handle,
            certificate,
            identity: CertificateIdentity {
                certificate_der: certificate_der.to_vec(),
                additional_certificates: Vec::new(),
            },
            capabilities,
        })
    }
}

impl SigningKey for Pkcs11Key<'_> {
    fn identity(&self) -> &CertificateIdentity {
        &self.identity
    }
    fn capabilities(&self) -> &[SigningCapability] {
        &self.capabilities
    }

    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        input: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        if !self.capabilities.contains(&SigningCapability {
            algorithm,
            input: input.kind(),
        }) {
            return Err(SigningError::UnsupportedOperation);
        }
        let digest = digest(input);
        let value = match (algorithm, input) {
            (SignatureAlgorithm::RsaPkcs1v15Sha256, SigningInput::Message(message)) => self
                .session
                .sign(&Mechanism::Sha256RsaPkcs, self.handle, message)
                .map_err(|_| SigningError::BackendFailure)?,
            (SignatureAlgorithm::EcdsaP256Sha256, _) => {
                let raw = self
                    .session
                    .sign(&Mechanism::Ecdsa, self.handle, &digest)
                    .map_err(|_| SigningError::BackendFailure)?;
                if raw.len() != 64 {
                    return Err(SigningError::InvalidSignature);
                }
                let convert = || {
                    EcdsaSig::from_private_components(
                        BigNum::from_slice(&raw[..32])?,
                        BigNum::from_slice(&raw[32..])?,
                    )?
                    .to_der()
                };
                convert().map_err(|_| SigningError::InvalidSignature)?
            }
            _ => return Err(SigningError::UnsupportedOperation),
        };
        verify(&self.certificate, algorithm, &digest, &value)?;
        Ok(Signature { algorithm, value })
    }
}
