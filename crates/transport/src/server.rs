use crate::{connection, session::Session, validate_origin, PendingRequest, TransportError};
use firmica_protocol::WebSocketBootstrap;
use std::{
    collections::BTreeSet,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex, Semaphore},
    time::timeout,
};
use tokio_rustls::rustls;

/// IPv4 loopback listener with a fixed set of explicitly authorized browser
/// origins. Server lifetime is at most 120 seconds.
pub struct Server {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    origins: Arc<BTreeSet<String>>,
    session: Arc<Mutex<Session>>,
}

impl Server {
    /// Binds a listener for one explicitly authorized browser origin.
    pub async fn bind(
        bootstrap: WebSocketBootstrap,
        tls: Arc<rustls::ServerConfig>,
        origin: String,
    ) -> Result<Self, TransportError> {
        Self::bind_origins(bootstrap, tls, BTreeSet::from([origin])).await
    }

    /// Binds a listener with an immutable authorization snapshot. Every origin
    /// must be canonical, and an empty set is rejected. The first authenticated
    /// message binds the session to its connection's origin, including reconnects.
    pub async fn bind_origins(
        bootstrap: WebSocketBootstrap,
        tls: Arc<rustls::ServerConfig>,
        origins: BTreeSet<String>,
    ) -> Result<Self, TransportError> {
        if origins.is_empty() {
            return Err(TransportError::Origin);
        }
        for origin in &origins {
            validate_origin(origin)?;
        }
        let mut last_error = None;
        for port in &bootstrap.ports {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).await {
                Ok(listener) => return Ok(Self::with_listener(listener, bootstrap, tls, origins)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::other("no listener port"))
            .into())
    }

    pub(super) fn with_listener(
        listener: TcpListener,
        bootstrap: WebSocketBootstrap,
        tls: Arc<rustls::ServerConfig>,
        origins: BTreeSet<String>,
    ) -> Self {
        Self {
            listener,
            tls,
            origins: Arc::new(origins),
            session: Arc::new(Mutex::new(Session::new(bootstrap))),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.listener.local_addr()
    }

    /// Runs until expiry or cancellation by dropping this future. All child connections
    /// are aborted on exit. At most four connections and one operation are admitted.
    pub async fn run(self, requests: mpsc::Sender<PendingRequest>) -> Result<(), TransportError> {
        let mut tasks = tokio::task::JoinSet::new();
        let permits = Arc::new(Semaphore::new(4));
        let deadline = tokio::time::sleep(Duration::from_secs(120));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = self.listener.accept() => {
                    let (stream, remote) = accepted?;
                    if remote.ip() != Ipv4Addr::LOCALHOST { continue; }
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                    let tls = self.tls.clone();
                    let origins = self.origins.clone();
                    let session = self.session.clone();
                    let requests = requests.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        // Errors contain library-provided untrusted details; do not log them.
                        let _ = timeout(Duration::from_secs(90), connection::handle(stream, tls, origins, session, requests)).await;
                    });
                }
            }
        }
        tasks.abort_all();
        Ok(())
    }
}
