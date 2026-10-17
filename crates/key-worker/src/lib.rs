//! Resource-controlled PKCS#12 import and signing in a separate native process.
//!
//! Linux workers set a 256 MiB address-space limit, a cumulative five-second CPU
//! limit and non-dumpable status before reading credentials. Parent pipe I/O uses
//! nonblocking descriptors with a ten-second deadline per operation. These are
//! resource controls, not a filesystem/network sandbox or a trust decision.
//! Other platforms fail closed; no in-process fallback is used.
//!
//! The worker keeps the unlocked private key until explicit close or abandonment.
//! Only public identity metadata and verified signatures return over anonymous
//! pipes. Passwords/containers are never command arguments or temporary files.
//! Rust-owned IPC buffers are cleared on drop; native OpenSSL copies, swap and
//! privileged process inspection remain subject to the host's protections.
//!
//! Operations block. Call outside the UI loop. Obtain consent and apply certificate
//! policy separately, then **close successfully before publishing any signature**.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use firmica_certificates::{CertificateError, MAX_PKCS12_BYTES};
use firmica_signing::{
    CertificateIdentity, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::{path::Path, time::Duration};

#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod wire;

/// Maximum UTF-8 password length accepted before launching a worker.
pub const MAX_PASSWORD_BYTES: usize = 4096;
/// Maximum message length sent through [`SigningKey::sign`] (1 MiB).
/// Larger messages can use the fixed-size SHA-256 digest input.
pub const MAX_SIGNING_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum number of public certificates returned, including the leaf.
pub const MAX_CERTIFICATES: usize = 32;
/// Maximum DER size per returned certificate (64 KiB).
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Hard Linux address-space limit for each worker (256 MiB).
pub const MAX_ADDRESS_SPACE_BYTES: u64 = 256 * 1024 * 1024;
/// Hard cumulative CPU-time limit for the whole worker, not per operation.
pub const MAX_CPU_SECONDS: u64 = 5;
/// Parent deadline for the startup handshake/import, each signing operation and close.
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Static failures without credentials, file paths, certificate data or native stacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkerError {
    /// No tested native resource-control implementation exists for this platform.
    #[error("controlled key import is unavailable on this platform")]
    UnsupportedPlatform,
    /// The executable path is not absolute or input exceeds the documented limits.
    #[error("invalid key-worker input")]
    InvalidInput,
    /// Native PKCS#12 import rejected the selected container.
    #[error(transparent)]
    Import(#[from] CertificateError),
    /// A deadline expired. The worker is terminated and must not be reused.
    #[error("the key worker exceeded its operation deadline")]
    TimedOut,
    /// Startup, I/O or process termination failed; the reason is not inferred.
    #[error("the key worker is unavailable")]
    Unavailable,
    /// An unexpected, malformed or oversized IPC response was received.
    #[error("invalid key-worker response")]
    Protocol,
    /// Process cleanup could not be confirmed. Do not publish previous results.
    #[error("key-worker cleanup could not be confirmed")]
    CleanupFailed,
}

/// A signing-key proxy with no private-key export operation, `Clone` or `Debug`.
///
/// Dropping an unclosed proxy terminates/reaps its worker on a best-effort basis.
/// Use [`Self::close`] to detect cleanup failures before publishing results.
pub struct WorkerKey {
    identity: CertificateIdentity,
    capabilities: Vec<SigningCapability>,
    #[cfg(target_os = "linux")]
    process: Option<process::Process>,
    failure: Option<WorkerError>,
}

impl WorkerKey {
    /// Import a caller-selected local container in a trusted worker executable.
    ///
    /// `executable` must be an absolute path to the packaged `firmica-key-worker`
    /// binary from this build; its ownership/integrity is the caller's responsibility.
    /// Input ownership is transferred so the container/password are cleared on drop.
    /// This does not clear copies retained by callers or validate certificate policy.
    ///
    /// # Errors
    /// Rejects unsupported platforms, invalid size/password/path, import failures,
    /// missing worker, oversized public identity, malformed IPC and deadlines.
    ///
    /// ```no_run
    /// use firmica_key_worker::WorkerKey;
    /// use firmica_signing::{CertificateIdentity, SigningKey};
    /// use secrecy::{SecretBox, SecretString};
    /// use std::path::Path;
    ///
    /// fn inspect_selected_container(
    ///     executable: &Path, container: SecretBox<Vec<u8>>, password: SecretString,
    /// ) -> Result<CertificateIdentity, Box<dyn std::error::Error>> {
    ///     let key = WorkerKey::import(executable, container, password)?;
    ///     let identity = key.identity().clone();
    ///     key.close()?;
    ///     Ok(identity)
    /// }
    /// ```
    pub fn import(
        executable: &Path,
        container: SecretBox<Vec<u8>>,
        password: SecretString,
    ) -> Result<Self, WorkerError> {
        if !cfg!(target_os = "linux") {
            return Err(WorkerError::UnsupportedPlatform);
        }
        if !executable.is_absolute()
            || container.expose_secret().is_empty()
            || container.expose_secret().len() > MAX_PKCS12_BYTES
            || password.expose_secret().len() > MAX_PASSWORD_BYTES
            || password.expose_secret().contains('\0')
        {
            return Err(WorkerError::InvalidInput);
        }
        #[cfg(target_os = "linux")]
        {
            let mut process = process::Process::spawn(executable)?;
            let result = (|| {
                let deadline = std::time::Instant::now() + OPERATION_TIMEOUT;
                if process.receive(deadline)?.expose_secret() != wire::HELLO {
                    return Err(WorkerError::Protocol);
                }
                let frame =
                    wire::import_request(container.expose_secret(), password.expose_secret())?;
                // Do not retain the caller's password/container while waiting for native work.
                drop(container);
                drop(password);
                process.send(&frame, deadline)?;
                drop(frame);
                wire::decode_identity(process.receive(deadline)?.expose_secret())
            })();
            match result {
                Ok((identity, capabilities)) => Ok(Self {
                    identity,
                    capabilities,
                    process: Some(process),
                    failure: None,
                }),
                Err(error) => Err(process.abort(error)),
            }
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!()
    }

    /// Destroy the worker's key, confirm its acknowledgement and successful exit.
    ///
    /// # Errors
    /// Returns the prior worker failure if the session was invalidated; otherwise
    /// reports protocol, deadline, exit or cleanup failure. Any error blocks result
    /// publication. Dropping the proxy is not an equivalent success acknowledgement.
    pub fn close(self) -> Result<(), WorkerError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        {
            let mut this = self;
            let mut process = this.process.take().ok_or(WorkerError::Unavailable)?;
            let deadline = std::time::Instant::now() + OPERATION_TIMEOUT;
            let result = (|| {
                process.send(&SecretBox::new(Box::new(vec![wire::CLOSE])), deadline)?;
                if process.receive(deadline)?.expose_secret() != &[wire::CLOSED] {
                    return Err(WorkerError::Protocol);
                }
                process.finish(deadline)
            })();
            match result {
                Ok(()) => Ok(()),
                Err(error) => Err(process.abort(error)),
            }
        }
        #[cfg(not(target_os = "linux"))]
        Err(WorkerError::UnsupportedPlatform)
    }
}

impl SigningKey for WorkerKey {
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
        }) || matches!(input, SigningInput::Message(bytes) if bytes.len() > MAX_SIGNING_INPUT_BYTES)
        {
            return Err(SigningError::UnsupportedOperation);
        }
        #[cfg(target_os = "linux")]
        {
            let process = self.process.as_mut().ok_or(SigningError::BackendFailure)?;
            let result = (|| {
                let deadline = std::time::Instant::now() + OPERATION_TIMEOUT;
                process.send(&wire::sign_request(algorithm, input)?, deadline)?;
                wire::decode_signature(process.receive(deadline)?.expose_secret(), algorithm)
            })();
            match result {
                Ok(signature) => Ok(signature),
                Err(error) => {
                    self.failure = Some(self.process.take().expect("active worker").abort(error));
                    Err(SigningError::BackendFailure)
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        Err(SigningError::UnsupportedOperation)
    }
}

/// Run the worker's stdio protocol; only call from a dedicated child-process entry point.
///
/// Linux resource controls and non-dumpable status are applied **to this process**
/// before reading credentials. Do not call from the application process or UI.
///
/// # Errors
/// Fails closed on other platforms or if controls cannot be installed, and rejects
/// malformed/oversized commands. EOF destroys any imported key. No diagnostics are
/// written to stdout/stderr. The binary exits nonzero on protocol/system failures.
pub fn serve() -> Result<(), WorkerError> {
    #[cfg(target_os = "linux")]
    {
        wire::serve()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(WorkerError::UnsupportedPlatform)
    }
}
