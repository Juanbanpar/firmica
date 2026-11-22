use crate::{
    Authentication, Availability, CertificateCandidate, Error, IdentityReference, ProviderId,
    ProviderKey, SigningSession,
};
use secrecy::SecretString;
use std::collections::HashSet;

/// Explicit user selection to open in the owning provider.
#[derive(Clone, Copy)]
pub enum Selection<'a> {
    /// Public metadata previously returned by discovery.
    Candidate(&'a CertificateCandidate),
    /// A user-selected file whose identity cannot be discovered before unlocking.
    /// Only a provider configured with that exact file may accept this selection.
    Import(&'a IdentityReference),
}

impl Selection<'_> {
    /// Reference to reopen and bind to the signing session.
    pub fn reference(&self) -> &IdentityReference {
        match self {
            Self::Candidate(candidate) => candidate.reference(),
            Self::Import(reference) => reference,
        }
    }
}

/// Credentials obtained through explicit user action. Never used in discovery.
pub enum Credentials {
    /// No application-supplied credential, including provider-managed authentication.
    None,
    /// A file or store password.
    Password(SecretString),
    /// A token PIN.
    Pin(SecretString),
}

/// One configured provider source. Discovery must never prompt or use a private
/// key. Opening may authenticate but must never sign or export key material.
pub trait Provider {
    /// Stable source identifier used by every identity returned by this provider.
    fn id(&self) -> &ProviderId;

    /// Whether this provider can be used on this host. Must never prompt.
    fn is_available(&self) -> bool;

    /// List public candidates without authentication or private-key operations.
    ///
    /// # Errors
    /// Return a provider error if discovery cannot be completed.
    fn discover(&self) -> Result<Vec<CertificateCandidate>, Error>;

    /// Open exactly the selected reference and return an independently owned key.
    /// Backends must check the reference and reject replacement or ambiguity.
    /// The registry compares the returned certificates with the selected candidate.
    ///
    /// # Errors
    /// Return a provider error if the identity cannot be opened or authenticated.
    /// Clean up any resources acquired before returning an error.
    fn open(
        &mut self,
        selection: Selection<'_>,
        credentials: Credentials,
    ) -> Result<Box<dyn ProviderKey>, Error>;
}

/// Locally configured providers. A registry does not hold active signing sessions.
#[derive(Default)]
pub struct Registry {
    providers: Vec<Box<dyn Provider>>,
}

impl Registry {
    /// Register one provider source.
    ///
    /// # Errors
    /// Rejects duplicate source identifiers.
    pub fn register(&mut self, provider: impl Provider + 'static) -> Result<(), Error> {
        if self
            .providers
            .iter()
            .any(|existing| existing.id() == provider.id())
        {
            return Err(Error::DuplicateProvider);
        }
        self.providers.push(Box::new(provider));
        Ok(())
    }

    /// Registered identifiers and availability, in registration order.
    pub fn providers(&self) -> impl Iterator<Item = (&ProviderId, bool)> {
        self.providers
            .iter()
            .map(|provider| (provider.id(), provider.is_available()))
    }

    /// Enumerate public candidates from one available source.
    ///
    /// # Errors
    /// Fails for unavailable providers, backend errors, foreign references or
    /// duplicate references. Duplicate display names are allowed.
    pub fn discover(&self, id: &ProviderId) -> Result<Vec<CertificateCandidate>, Error> {
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.id() == id && provider.is_available())
            .ok_or(Error::Unavailable)?;
        let candidates = provider.discover()?;
        let mut references = HashSet::new();
        for candidate in &candidates {
            let reference = candidate.reference();
            if reference.provider() != id {
                return Err(Error::StaleIdentity);
            }
            if !references.insert(reference) {
                return Err(Error::AmbiguousIdentity);
            }
        }
        Ok(candidates)
    }

    /// Open the selected identity after explicit user action.
    ///
    /// # Errors
    /// Rejects unavailable or public-only identities, selection mismatches, and
    /// keys with no usable capabilities. Backend and authentication failures are
    /// returned to the caller. Cleanup failure takes precedence over rejection
    /// after an opened key is received.
    pub fn open(
        &mut self,
        selection: Selection<'_>,
        credentials: Credentials,
    ) -> Result<SigningSession, Error> {
        let reference = selection.reference();
        let provider = self
            .providers
            .iter_mut()
            .find(|provider| provider.id() == reference.provider() && provider.is_available())
            .ok_or(Error::Unavailable)?;
        let (expected, authentication) = match selection {
            Selection::Candidate(candidate) => {
                match candidate.availability() {
                    Availability::PublicOnly => return Err(Error::NotSigningIdentity),
                    Availability::Unavailable => return Err(Error::Unavailable),
                    Availability::Available | Availability::Locked => {}
                }
                (Some(candidate.identity()), candidate.authentication())
            }
            Selection::Import(_) => {
                let authentication = match &credentials {
                    Credentials::None => Authentication::None,
                    Credentials::Password(_) => Authentication::Password,
                    Credentials::Pin(_) => Authentication::Pin,
                };
                (None, authentication)
            }
        };
        let mut key = provider.open(selection, credentials)?;
        let candidate = key.revalidate(reference).and_then(|()| {
            let candidate = CertificateCandidate::new(
                reference.clone(),
                key.identity().clone(),
                key.capabilities().to_vec(),
                authentication,
                Availability::Available,
            );
            if expected.is_some_and(|identity| identity != candidate.identity()) {
                return Err(Error::StaleIdentity);
            }
            if candidate.capabilities().is_empty() {
                return Err(Error::NotSigningIdentity);
            }
            Ok(candidate)
        });
        match candidate {
            Ok(candidate) => Ok(SigningSession::new(candidate, key)),
            Err(error) => {
                key.close()?;
                Err(error)
            }
        }
    }
}
