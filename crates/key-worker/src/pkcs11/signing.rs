use crate::WorkerError;
use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use openssl::{bn::BigNum, ecdsa::EcdsaSig};
use pkcs11_client::{
    object_reference, token_uri, Authentication, Certificate, DigestAlgorithm, ErrorKind,
    HashingPolicy, KeyKind, ManagementSession, NamedCurve, ObjectRef, Pin, Pkcs11Uri,
    PrivateKeyRef, Provider, SecretText, SessionMode, SignInput, SignRequest,
    SignatureAlgorithm as Mechanism, SigningPolicy,
};
use std::path::Path;

pub(crate) fn with_key<T>(
    module: &Path,
    locator: &str,
    user: SecretText,
    context: Option<SecretText>,
    operation: impl FnOnce(TokenKey<'_, '_>) -> Result<T, WorkerError>,
) -> Result<T, WorkerError> {
    let uri: Pkcs11Uri = locator.parse().map_err(|_| WorkerError::TokenIdentity)?;
    let id = uri
        .path_attribute("id")
        .filter(|id| !id.is_empty())
        .ok_or(WorkerError::TokenIdentity)?
        .to_vec();
    if uri.path_attribute("type") != Some(b"cert") || uri.query_names().next().is_some() {
        return Err(WorkerError::TokenIdentity);
    }
    let token = token_uri(uri).map_err(|_| WorkerError::TokenIdentity)?;
    let mut key_uri = Pkcs11Uri::builder();
    for (name, value) in token
        .path_attributes()
        .chain([("id", id.as_slice()), ("type", b"private")])
    {
        key_uri = key_uri
            .path_attribute(name, value)
            .map_err(|_| WorkerError::TokenIdentity)?;
    }
    let key = PrivateKeyRef::new(key_uri.build().map_err(|_| WorkerError::TokenIdentity)?)
        .map_err(|_| WorkerError::TokenIdentity)?;
    let reference = object_reference(locator.parse().map_err(|_| WorkerError::TokenIdentity)?)
        .map_err(|_| WorkerError::TokenIdentity)?;

    let provider = Provider::load(module).map_err(|_| WorkerError::Unavailable)?;
    let outcome = (|| {
        let mut session = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .map_err(metadata_error)?;
        let result = (|| {
            let protected_path = user.expose_secret().is_empty();
            let login = if protected_path {
                Pin::ProtectedPath
            } else {
                Pin::Value(&user)
            };
            let authenticated = session.authenticate(Authentication::User(login));
            drop(user);
            authenticated.map_err(|_| WorkerError::TokenAuthentication)?;
            operation(TokenKey::open(
                &mut session,
                reference,
                key,
                context,
                protected_path,
            )?)
        })();
        session.close().map_err(|_| WorkerError::CleanupFailed)?;
        result
    })();
    provider
        .finalize()
        .map_err(|_| WorkerError::CleanupFailed)?;
    outcome
}

fn metadata_error(error: pkcs11_client::Error) -> WorkerError {
    match error.kind() {
        ErrorKind::Selection => WorkerError::TokenIdentity,
        ErrorKind::Policy => WorkerError::TokenUnsupported,
        _ => WorkerError::Unavailable,
    }
}

pub(crate) struct TokenKey<'a, 'module> {
    session: &'a mut ManagementSession<'module>,
    reference: ObjectRef,
    key: PrivateKeyRef,
    certificate: Certificate,
    identity: CertificateIdentity,
    capabilities: Vec<SigningCapability>,
    context: Option<SecretText>,
    context_path: bool,
    policy: SigningPolicy,
    used: bool,
}

impl<'a, 'module> TokenKey<'a, 'module> {
    fn open(
        session: &'a mut ManagementSession<'module>,
        reference: ObjectRef,
        key: PrivateKeyRef,
        context: Option<SecretText>,
        protected_path: bool,
    ) -> Result<Self, WorkerError> {
        let der = session.export_public(&reference).map_err(metadata_error)?;
        if der.len() > crate::MAX_CERTIFICATE_BYTES {
            return Err(WorkerError::TokenUnsupported);
        }
        let certificate = Certificate::from_der(der).map_err(|_| WorkerError::TokenUnsupported)?;
        let (algorithm, mechanism) = match certificate.key_kind() {
            KeyKind::Rsa { bits } if bits >= 2048 => {
                (SignatureAlgorithm::RsaPkcs1v15Sha256, Mechanism::RsaPkcs1)
            }
            KeyKind::Ec(NamedCurve::P256) => {
                (SignatureAlgorithm::EcdsaP256Sha256, Mechanism::Ecdsa)
            }
            _ => return Err(WorkerError::TokenUnsupported),
        };
        let mut policy = SigningPolicy {
            hashing: HashingPolicy::AllowSoftware,
            algorithms: vec![mechanism],
            curves: vec![NamedCurve::P256],
            digests: vec![DigestAlgorithm::Sha256],
            ..SigningPolicy::default()
        };
        let options = session
            .signing_options(&key, &policy)
            .map_err(metadata_error)?;
        if options.choices.is_empty() {
            return Err(WorkerError::TokenUnsupported);
        }
        let context_path = options.always_authenticate && context.is_none() && protected_path;
        if options.always_authenticate && context.is_none() && !context_path {
            return Err(WorkerError::TokenAuthentication);
        }
        let context = context.filter(|_| options.always_authenticate);
        let mut capabilities = vec![SigningCapability {
            algorithm,
            input: InputKind::Message,
        }];
        if options.always_authenticate {
            // The client interleaves context login with its multipart signing API.
            // Raw RSA and ECDSA mechanisms require single-part signing.
            policy.hashing = HashingPolicy::TokenOnly;
            if session
                .signing_options(&key, &policy)
                .map_err(metadata_error)?
                .choices
                .is_empty()
            {
                return Err(WorkerError::TokenUnsupported);
            }
        } else {
            // A software-only message plan selects the same raw mechanism as an explicit digest.
            policy.hashing = HashingPolicy::SoftwareOnly;
            if !session
                .signing_options(&key, &policy)
                .map_err(metadata_error)?
                .choices
                .is_empty()
            {
                capabilities.push(SigningCapability {
                    algorithm,
                    input: InputKind::Sha256Digest,
                });
            }
            policy.hashing = HashingPolicy::AllowSoftware;
        }
        let identity = CertificateIdentity {
            certificate_der: certificate.der().to_vec(),
            additional_certificates: Vec::new(),
        };
        Ok(Self {
            session,
            reference,
            key,
            certificate,
            identity,
            capabilities,
            context,
            context_path,
            policy,
            used: false,
        })
    }
}

impl SigningKey for TokenKey<'_, '_> {
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
        if self.used
            || !self.capabilities.contains(&SigningCapability {
                algorithm,
                input: input.kind(),
            })
        {
            return Err(SigningError::UnsupportedOperation);
        }
        self.used = true;
        let current = self
            .session
            .export_public(&self.reference)
            .map_err(|_| SigningError::BackendFailure)?;
        if current != self.identity.certificate_der {
            return Err(SigningError::BackendFailure);
        }
        let request = SignRequest {
            algorithm: self.policy.algorithms[0],
            digest: DigestAlgorithm::Sha256,
            input: match input {
                SigningInput::Message(bytes) => SignInput::Message(bytes),
                SigningInput::Sha256Digest(bytes) => SignInput::Digest(bytes),
            },
            pss: None,
        };
        let context = self.context.take();
        let pin = if self.context_path {
            Some(Pin::ProtectedPath)
        } else {
            context.as_ref().map(Pin::Value)
        };
        let signature = self.session.sign(&self.key, &request, &self.policy, pin);
        drop(context);
        let mut value = signature.map_err(|_| SigningError::BackendFailure)?;
        self.certificate
            .verify_signature(&request, &value)
            .map_err(|_| SigningError::InvalidSignature)?;
        if algorithm == SignatureAlgorithm::EcdsaP256Sha256 {
            let fixed: &[u8; 64] = value
                .as_slice()
                .try_into()
                .map_err(|_| SigningError::InvalidSignature)?;
            let (r, s) = fixed.split_at(32);
            value = (|| {
                EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?
                    .to_der()
            })()
            .map_err(|_| SigningError::InvalidSignature)?;
        }
        Ok(Signature { algorithm, value })
    }
}
