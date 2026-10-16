use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use openssl::{
    md::Md,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::Padding,
    x509::X509,
};
use secrecy::{ExposeSecret, SecretString};

use crate::{algorithm, digest, verify, CertificateError, MAX_PKCS12_BYTES};

/// An unlocked PKCS#12 identity. Dropping it releases the OpenSSL-owned private key.
///
/// It cannot export the key and has no `Clone` or `Debug` implementation. The password
/// is borrowed only during import, never stored in the key handle.
pub struct Pkcs12Key {
    key: PKey<Private>,
    certificate: X509,
    identity: CertificateIdentity,
    capabilities: [SigningCapability; 2],
}

impl Pkcs12Key {
    /// Unlock one PKCS#12 identity from a container selected by the caller.
    ///
    /// Requires complete DER, a matching leaf certificate/key, RSA >= 2048 bits or
    /// NIST P-256. The active OpenSSL providers determine supported encryption/PBEs;
    /// this function does not enable legacy algorithms globally. See the crate's
    /// import-resource and secret-memory limitations before accepting untrusted files.
    /// OpenSSL selects one matching key/certificate pair; this API does not enumerate
    /// multiple identities or assert that no other identities exist in the container.
    ///
    /// # Errors
    /// Rejects invalid size/DER/password, failed integrity/decryption, missing identity,
    /// mismatched key/certificate, unsupported keys and native metadata failures.
    ///
    /// ```no_run
    /// use firmica_certificates::Pkcs12Key;
    /// use firmica_signing::{Signature, SignatureAlgorithm, SigningInput, SigningKey};
    /// use secrecy::SecretString;
    ///
    /// fn sign_selected_message(
    ///     container: &[u8], password: &SecretString, message: &[u8],
    /// ) -> Result<Signature, Box<dyn std::error::Error>> {
    ///     let mut key = Pkcs12Key::from_der(container, password)?;
    ///     Ok(key.sign(SignatureAlgorithm::RsaPkcs1v15Sha256, SigningInput::Message(message))?)
    /// }
    /// ```
    pub fn from_der(der: &[u8], password: &SecretString) -> Result<Self, CertificateError> {
        if der.is_empty() || der.len() > MAX_PKCS12_BYTES {
            return Err(CertificateError::InvalidContainer);
        }
        if password.expose_secret().contains('\0') {
            return Err(CertificateError::InvalidPassword);
        }
        let container = Pkcs12::from_der(der).map_err(|_| CertificateError::InvalidContainer)?;
        // OpenSSL's DER decoder otherwise accepts a valid prefix with trailing bytes.
        let canonical = secrecy::SecretBox::new(Box::new(
            container
                .to_der()
                .map_err(|_| CertificateError::InvalidContainer)?,
        ));
        if canonical.expose_secret().as_slice() != der {
            return Err(CertificateError::InvalidContainer);
        }
        let parsed = container
            .parse2(password.expose_secret())
            .map_err(|_| CertificateError::UnlockFailed)?;
        let key = parsed.pkey.ok_or(CertificateError::MissingIdentity)?;
        let certificate = parsed.cert.ok_or(CertificateError::MissingIdentity)?;
        let public = certificate
            .public_key()
            .map_err(|_| CertificateError::BackendFailure)?;
        if !key.public_eq(&public) {
            return Err(CertificateError::KeyMismatch);
        }
        let algorithm = algorithm(&public)?;
        let identity = CertificateIdentity {
            certificate_der: certificate
                .to_der()
                .map_err(|_| CertificateError::BackendFailure)?,
            additional_certificates: parsed
                .ca
                .into_iter()
                .flatten()
                .map(|cert| cert.to_der().map_err(|_| CertificateError::BackendFailure))
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            key,
            certificate,
            identity,
            capabilities: [
                SigningCapability {
                    algorithm,
                    input: InputKind::Message,
                },
                SigningCapability {
                    algorithm,
                    input: InputKind::Sha256Digest,
                },
            ],
        })
    }
}

impl SigningKey for Pkcs12Key {
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
        let produce = || {
            let mut context = PkeyCtx::new(&self.key)?;
            context.sign_init()?;
            context.set_signature_md(Md::sha256())?;
            if algorithm == SignatureAlgorithm::RsaPkcs1v15Sha256 {
                context.set_rsa_padding(Padding::PKCS1)?;
            }
            let mut signature = Vec::new();
            context.sign_to_vec(&digest, &mut signature)?;
            Ok::<_, openssl::error::ErrorStack>(signature)
        };
        let value = produce().map_err(|_| SigningError::BackendFailure)?;
        verify(&self.certificate, algorithm, &digest, &value)?;
        Ok(Signature { algorithm, value })
    }
}
