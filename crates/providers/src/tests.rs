use super::*;
use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningError,
    SigningInput, SigningKey,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    Arc,
};

const RSA: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
const MESSAGE: SigningInput<'_> = SigningInput::Message(b"synthetic");
const CAPABILITY: SigningCapability = SigningCapability {
    algorithm: RSA,
    input: InputKind::Message,
};

#[derive(Default)]
struct State {
    opens: AtomicUsize,
    signs: AtomicUsize,
    closes: AtomicUsize,
    replaced_reference: AtomicBool,
    replaced_certificate: AtomicBool,
    lost_capability: AtomicBool,
    signing_failure: AtomicBool,
    cleanup_failure: AtomicBool,
    cancel_on_validation: AtomicBool,
    cancelled: AtomicBool,
}

struct FakeProvider {
    id: ProviderId,
    candidates: Vec<CertificateCandidate>,
    state: Arc<State>,
    available: bool,
}

impl FakeProvider {
    fn new() -> Self {
        let id = ProviderId::new("test");
        let candidates = [1, 2].map(|key| {
            CertificateCandidate::new(
                IdentityReference::new(id.clone(), vec![key]),
                CertificateIdentity {
                    // Identical certificate and display metadata for distinct keys.
                    certificate_der: b"abc".to_vec(),
                    additional_certificates: vec![],
                },
                vec![CAPABILITY],
                Authentication::None,
                Availability::Available,
            )
        });
        Self {
            id,
            candidates: candidates.into(),
            state: Arc::default(),
            available: true,
        }
    }
}

impl Provider for FakeProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn discover(&self) -> Result<Vec<CertificateCandidate>, Error> {
        Ok(self.candidates.clone())
    }

    fn open(
        &mut self,
        selection: Selection<'_>,
        credentials: Credentials,
    ) -> Result<Box<dyn ProviderKey>, Error> {
        let Selection::Candidate(selected) = selection else {
            return Err(Error::StaleIdentity);
        };
        let candidate = self
            .candidates
            .iter()
            .find(|candidate| candidate.reference() == selected.reference())
            .ok_or(Error::StaleIdentity)?;
        if candidate.authentication() == Authentication::Pin
            && !matches!(credentials, Credentials::Pin(_))
        {
            return Err(Error::AuthenticationRequired);
        }

        self.state.opens.fetch_add(1, SeqCst);
        Ok(Box::new(FakeKey {
            candidate: candidate.clone(),
            replacement: CertificateIdentity {
                certificate_der: b"different".to_vec(),
                additional_certificates: vec![],
            },
            state: Arc::clone(&self.state),
        }))
    }
}

struct FakeKey {
    candidate: CertificateCandidate,
    replacement: CertificateIdentity,
    state: Arc<State>,
}

impl SigningKey for FakeKey {
    fn identity(&self) -> &CertificateIdentity {
        if self.state.replaced_certificate.load(SeqCst) {
            &self.replacement
        } else {
            self.candidate.identity()
        }
    }

    fn capabilities(&self) -> &[SigningCapability] {
        if self.state.lost_capability.load(SeqCst) {
            &[]
        } else {
            self.candidate.capabilities()
        }
    }

    fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        _: SigningInput<'_>,
    ) -> Result<Signature, SigningError> {
        self.state.signs.fetch_add(1, SeqCst);
        if self.state.signing_failure.load(SeqCst) {
            return Err(SigningError::BackendFailure);
        }
        // Synthetic signature marker used only to test dispatch and lifecycle.
        Ok(Signature {
            algorithm,
            value: self.candidate.reference().key().to_vec(),
        })
    }
}

impl ProviderKey for FakeKey {
    fn revalidate(&mut self, reference: &IdentityReference) -> Result<(), Error> {
        if reference != self.candidate.reference() || self.state.replaced_reference.load(SeqCst) {
            return Err(Error::StaleIdentity);
        }
        if self.state.cancel_on_validation.load(SeqCst) {
            self.state.cancelled.store(true, SeqCst);
        }
        Ok(())
    }

    fn close(self: Box<Self>) -> Result<(), Error> {
        self.state.closes.fetch_add(1, SeqCst);
        if self.state.cleanup_failure.load(SeqCst) {
            return Err(Error::Cleanup);
        }
        Ok(())
    }
}

fn registered(provider: FakeProvider) -> (Registry, ProviderId, Arc<State>) {
    let id = provider.id.clone();
    let state = provider.state.clone();
    let mut registry = Registry::default();
    registry.register(provider).unwrap();
    (registry, id, state)
}

fn open_first(registry: &mut Registry, id: &ProviderId) -> SigningSession {
    let candidates = registry.discover(id).unwrap();
    registry
        .open(Selection::Candidate(&candidates[0]), Credentials::None)
        .unwrap()
}

#[test]
fn discovery_and_selection_use_references_even_with_identical_certificates() {
    let (mut registry, id, state) = registered(FakeProvider::new());
    assert_eq!(registry.providers().collect::<Vec<_>>(), [(&id, true)]);
    assert_eq!(
        registry.register(FakeProvider::new()),
        Err(Error::DuplicateProvider)
    );

    let candidates = registry.discover(&id).unwrap();
    let [first, second] = candidates.as_slice() else {
        panic!("expected two candidates")
    };
    assert!(first.identity() == second.identity());
    assert!(first.reference() != second.reference());
    assert_eq!(
        *first.fingerprint(),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );

    assert_eq!(state.opens.load(SeqCst), 0);
    assert_eq!(state.signs.load(SeqCst), 0);
    let mut session = registry
        .open(Selection::Candidate(second), Credentials::None)
        .unwrap();
    assert!(session.candidate().reference() == second.reference());
    assert_eq!(state.signs.load(SeqCst), 0);
    assert_eq!(session.sign(RSA, MESSAGE).unwrap().value, [2]);
    session.close().unwrap();
    assert_eq!(state.closes.load(SeqCst), 1);
}

#[test]
fn rejects_unavailable_ambiguous_and_stale_discovery() {
    let mut provider = FakeProvider::new();
    provider.available = false;
    let (registry, id, _) = registered(provider);
    assert!(matches!(registry.discover(&id), Err(Error::Unavailable)));

    let mut provider = FakeProvider::new();
    provider.candidates.push(provider.candidates[0].clone());
    let (registry, id, _) = registered(provider);
    assert!(matches!(
        registry.discover(&id),
        Err(Error::AmbiguousIdentity)
    ));

    let mut provider = FakeProvider::new();
    let stale = provider.candidates.pop().unwrap();
    let (mut registry, _, state) = registered(provider);
    assert!(matches!(
        registry.open(Selection::Candidate(&stale), Credentials::None),
        Err(Error::StaleIdentity)
    ));
    assert_eq!(state.opens.load(SeqCst), 0);
}

#[test]
fn public_only_candidates_cannot_open_and_locked_candidates_require_explicit_credentials() {
    let mut provider = FakeProvider::new();
    for (index, authentication, availability) in [
        (0, Authentication::None, Availability::PublicOnly),
        (1, Authentication::Pin, Availability::Locked),
    ] {
        let original = &provider.candidates[index];
        provider.candidates[index] = CertificateCandidate::new(
            original.reference().clone(),
            original.identity().clone(),
            vec![CAPABILITY],
            authentication,
            availability,
        );
    }
    let (mut registry, id, state) = registered(provider);
    let candidates = registry.discover(&id).unwrap();
    let public = Selection::Candidate(&candidates[0]);
    let locked = Selection::Candidate(&candidates[1]);
    assert!(matches!(
        registry.open(public, Credentials::None),
        Err(Error::NotSigningIdentity)
    ));
    assert!(matches!(
        registry.open(locked, Credentials::None),
        Err(Error::AuthenticationRequired)
    ));
    assert_eq!(state.opens.load(SeqCst), 0);
    let session = registry
        .open(locked, Credentials::Pin("synthetic".into()))
        .unwrap();
    assert_eq!(session.candidate().availability(), Availability::Available);
    session.close().unwrap();
    assert_eq!(state.signs.load(SeqCst), 0);
}

#[test]
fn rejects_certificate_replacement_at_open_and_checks_cleanup() {
    let (mut registry, id, state) = registered(FakeProvider::new());
    let candidates = registry.discover(&id).unwrap();
    let selection = Selection::Candidate(&candidates[0]);
    state.replaced_certificate.store(true, SeqCst);
    assert!(matches!(
        registry.open(selection, Credentials::None),
        Err(Error::StaleIdentity)
    ));
    state.cleanup_failure.store(true, SeqCst);
    assert!(matches!(
        registry.open(selection, Credentials::None),
        Err(Error::Cleanup)
    ));
    assert_eq!(state.closes.load(SeqCst), 2);
    assert_eq!(state.signs.load(SeqCst), 0);
}

#[test]
fn rejects_live_reference_certificate_and_capability_changes_before_signing() {
    let (mut registry, id, state) = registered(FakeProvider::new());
    for (changed, expected) in [
        (&state.replaced_reference, SigningError::BackendFailure),
        (&state.replaced_certificate, SigningError::BackendFailure),
        (&state.lost_capability, SigningError::UnsupportedOperation),
    ] {
        let mut session = open_first(&mut registry, &id);
        changed.store(true, SeqCst);
        assert_eq!(session.sign(RSA, MESSAGE).err(), Some(expected));
        changed.store(false, SeqCst);
        assert_eq!(
            session.sign(RSA, MESSAGE).err(),
            Some(SigningError::BackendFailure)
        );
        session.close().unwrap();
    }
    assert_eq!(state.closes.load(SeqCst), 3);
    assert_eq!(state.signs.load(SeqCst), 0);
}

#[test]
fn unsupported_input_avoids_key_operation_and_signing_failure_invalidates_session() {
    let (mut registry, id, state) = registered(FakeProvider::new());
    let mut session = open_first(&mut registry, &id);
    assert_eq!(
        session
            .sign(RSA, SigningInput::Sha256Digest(&[0; 32]))
            .err(),
        Some(SigningError::UnsupportedOperation)
    );
    assert_eq!(state.signs.load(SeqCst), 0);
    state.signing_failure.store(true, SeqCst);
    assert_eq!(
        session.sign(RSA, MESSAGE).err(),
        Some(SigningError::BackendFailure)
    );
    state.signing_failure.store(false, SeqCst);
    assert_eq!(
        session.sign(RSA, MESSAGE).err(),
        Some(SigningError::BackendFailure)
    );
    assert_eq!(state.signs.load(SeqCst), 1);
    session.close().unwrap();
}

#[test]
fn cancellation_during_revalidation_prevents_signing_and_abandonment_closes() {
    let (mut registry, id, state) = registered(FakeProvider::new());
    let mut session = open_first(&mut registry, &id);
    state.cancel_on_validation.store(true, SeqCst);
    assert_eq!(
        session
            .cancellable(&state.cancelled)
            .sign(RSA, MESSAGE)
            .err(),
        Some(SigningError::BackendFailure)
    );
    assert!(state.cancelled.load(SeqCst));
    drop(session);
    assert_eq!(state.signs.load(SeqCst), 0);
    assert_eq!(state.closes.load(SeqCst), 1);
}

#[test]
fn parallel_sessions_keep_separate_keys_and_cleanup_results() {
    let (mut registry, id, state) = registered(FakeProvider::new());
    let candidates = registry.discover(&id).unwrap();
    let sessions = candidates
        .iter()
        .map(|candidate| {
            registry
                .open(Selection::Candidate(candidate), Credentials::None)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let gate = std::sync::Barrier::new(2);
    state.cleanup_failure.store(true, SeqCst);
    std::thread::scope(|scope| {
        let gate = &gate;
        let requests = sessions
            .into_iter()
            .map(|mut session| {
                scope.spawn(move || {
                    gate.wait();
                    let signature = session.sign(RSA, MESSAGE).unwrap();
                    (signature.value, session.close())
                })
            })
            .collect::<Vec<_>>();
        for (index, request) in requests.into_iter().enumerate() {
            let (signature, cleanup) = request.join().unwrap();
            assert_eq!(signature, [index as u8 + 1]);
            assert_eq!(cleanup, Err(Error::Cleanup));
        }
    });
    assert_eq!(state.signs.load(SeqCst), 2);
    assert_eq!(state.closes.load(SeqCst), 2);
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn pkcs12_discovery_and_selection_do_not_unlock_the_container() {
    // These synthetic bytes are never parsed and the worker path cannot start.
    let provider = pkcs12::Pkcs12Provider::new(
        "nonexistent-test-worker".into(),
        secrecy::SecretBox::new(Box::new(vec![1, 2, 3])),
    )
    .unwrap();
    let reference = provider.reference().clone();
    let id = reference.provider();
    let mut registry = Registry::default();
    registry.register(provider).unwrap();
    assert!(registry.discover(id).unwrap().is_empty());

    let other_file = IdentityReference::new(id.clone(), vec![0]);
    assert!(matches!(
        registry.open(
            Selection::Import(&other_file),
            Credentials::Password("test".into())
        ),
        Err(Error::StaleIdentity)
    ));
    assert!(matches!(
        registry.open(Selection::Import(&reference), Credentials::None),
        Err(Error::AuthenticationRequired)
    ));
    assert_eq!(registry.providers().collect::<Vec<_>>(), [(id, true)]);
}
