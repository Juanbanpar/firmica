use super::{read_document, Error, Prepared};
use firmica_providers::{
    windows::{SystemStore, WindowsProvider},
    CertificateCandidate, Credentials, Provider, Registry, Selection,
};
use firmica_signing::{format::Format, SignatureAlgorithm};
use std::path::Path;

fn registry(store: SystemStore) -> Result<(Registry, firmica_providers::ProviderId), Error> {
    let provider = WindowsProvider::new(store);
    let id = provider.id().clone();
    let mut registry = Registry::default();
    registry.register(provider).map_err(Error::Provider)?;
    Ok((registry, id))
}

pub fn discover(store: SystemStore) -> Result<Vec<CertificateCandidate>, Error> {
    let (registry, id) = registry(store)?;
    registry.discover(&id).map_err(Error::Provider)
}

impl Prepared {
    pub fn open_windows(
        document: &Path,
        store: SystemStore,
        candidate: &CertificateCandidate,
        algorithm: SignatureAlgorithm,
        format: Format,
    ) -> Result<Self, Error> {
        let (name, document) = read_document(document)?;
        let (mut registry, id) = registry(store)?;
        if candidate.reference().provider() != &id {
            return Err(Error::Provider(firmica_providers::Error::StaleIdentity));
        }
        let session = registry
            .open(Selection::Candidate(candidate), Credentials::None)
            .map_err(Error::Provider)?;
        let mut prepared = Self::prepare(name, document, session, algorithm, format)?;
        prepared.windows_store = Some(store);
        Ok(prepared)
    }

    pub fn windows_store(&self) -> Option<SystemStore> {
        self.windows_store
    }
}
