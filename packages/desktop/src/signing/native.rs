use super::{read_document, Error, Prepared};
#[cfg(target_os = "macos")]
use firmica_providers::macos::KeychainProvider;
#[cfg(windows)]
use firmica_providers::windows::{SystemStore, WindowsProvider};
use firmica_providers::{
    CertificateCandidate, Credentials, Provider, ProviderId, Registry, Selection,
};
use firmica_signing::{format::Format, SignatureAlgorithm};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSource {
    #[cfg(windows)]
    CurrentUser,
    #[cfg(windows)]
    LocalMachine,
    #[cfg(target_os = "macos")]
    Keychain,
}

impl NativeSource {
    pub const ALL: &'static [Self] = &[
        #[cfg(windows)]
        Self::CurrentUser,
        #[cfg(windows)]
        Self::LocalMachine,
        #[cfg(target_os = "macos")]
        Self::Keychain,
    ];

    fn provider(self) -> impl Provider {
        match self {
            #[cfg(windows)]
            Self::CurrentUser => WindowsProvider::new(SystemStore::CurrentUserPersonal),
            #[cfg(windows)]
            Self::LocalMachine => WindowsProvider::new(SystemStore::LocalMachinePersonal),
            #[cfg(target_os = "macos")]
            Self::Keychain => KeychainProvider::default(),
        }
    }
}

fn registry(source: NativeSource) -> Result<(Registry, ProviderId), Error> {
    let provider = source.provider();
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
        algorithm: SignatureAlgorithm,
        format: Format,
    ) -> Result<Self, Error> {
        let (name, document) = read_document(document)?;
        let (mut registry, id) = registry(source)?;
        if candidate.reference().provider() != &id {
            return Err(Error::Provider(firmica_providers::Error::StaleIdentity));
        }
        let session = registry
            .open(Selection::Candidate(candidate), Credentials::None)
            .map_err(Error::Provider)?;
        let mut prepared = Self::prepare(name, document, session, algorithm, format)?;
        prepared.native_source = Some(source);
        Ok(prepared)
    }

    pub fn native_source(&self) -> Option<NativeSource> {
        self.native_source
    }
}
