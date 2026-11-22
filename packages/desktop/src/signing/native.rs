use super::{packaged_worker, read_document, Error, Prepared};
#[cfg(target_os = "macos")]
use firmica_providers::macos::KeychainProvider;
#[cfg(windows)]
use firmica_providers::windows::{SystemStore, WindowsProvider};
use firmica_providers::{
    pkcs11::Pkcs11Provider, CertificateCandidate, Credentials, Provider, ProviderId, Registry,
    Selection,
};
use firmica_signing::{format::Format, SigningKey};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSource {
    #[cfg(windows)]
    CurrentUser,
    #[cfg(windows)]
    LocalMachine,
    #[cfg(target_os = "macos")]
    Keychain,
    Pkcs11,
}

impl NativeSource {
    pub const ALL: &'static [Self] = &[
        #[cfg(windows)]
        Self::CurrentUser,
        #[cfg(windows)]
        Self::LocalMachine,
        #[cfg(target_os = "macos")]
        Self::Keychain,
        Self::Pkcs11,
    ];

    pub fn is_configured(self) -> bool {
        self != Self::Pkcs11 || configured_module().is_some()
    }
}

fn configured_module() -> Option<PathBuf> {
    std::env::var_os("FIRMICA_PKCS11_MODULE").map(PathBuf::from)
}

fn registry(source: NativeSource) -> Result<(Registry, ProviderId), Error> {
    match source {
        #[cfg(windows)]
        NativeSource::CurrentUser => {
            register(WindowsProvider::new(SystemStore::CurrentUserPersonal))
        }
        #[cfg(windows)]
        NativeSource::LocalMachine => {
            register(WindowsProvider::new(SystemStore::LocalMachinePersonal))
        }
        #[cfg(target_os = "macos")]
        NativeSource::Keychain => register(KeychainProvider::default()),
        NativeSource::Pkcs11 => {
            let module = configured_module()
                .ok_or(Error::Provider(firmica_providers::Error::Unavailable))?;
            register(Pkcs11Provider::new(packaged_worker()?, module).map_err(Error::Provider)?)
        }
    }
}

pub(super) fn register(provider: impl Provider + 'static) -> Result<(Registry, ProviderId), Error> {
    let id = provider.id().clone();
    let mut registry = Registry::default();
    registry.register(provider).map_err(Error::Provider)?;
    Ok((registry, id))
}

pub fn discover(source: NativeSource) -> Result<Vec<CertificateCandidate>, Error> {
    let (registry, id) = registry(source)?;
    registry.discover(&id).map_err(Error::Provider)
}

impl Prepared {
    pub fn open_native(
        document: &Path,
        source: NativeSource,
        candidate: &CertificateCandidate,
        credentials: Credentials,
        format: Format,
    ) -> Result<Self, Error> {
        Self::open_native_from_registry(
            document,
            source,
            candidate,
            credentials,
            format,
            registry(source)?,
        )
    }

    pub(super) fn open_native_from_registry(
        document: &Path,
        source: NativeSource,
        candidate: &CertificateCandidate,
        credentials: Credentials,
        format: Format,
        (mut registry, id): (Registry, ProviderId),
    ) -> Result<Self, Error> {
        let (name, document) = read_document(document)?;
        if candidate.reference().provider() != &id {
            return Err(Error::Provider(firmica_providers::Error::StaleIdentity));
        }
        let session = registry
            .open(Selection::Candidate(candidate), credentials)
            .map_err(Error::Provider)?;
        let algorithm = session.capabilities()[0].algorithm;
        let mut prepared = Self::prepare(name, document, session, algorithm, format)?;
        prepared.native_source = Some(source);
        Ok(prepared)
    }

    pub fn native_source(&self) -> Option<NativeSource> {
        self.native_source
    }
}
