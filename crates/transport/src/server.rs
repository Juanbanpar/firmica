use crate::{connection, session::Session, validate_origin, PendingRequest, TransportError};
use firmica_protocol::WebSocketBootstrap;
use std::{
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

/// Listener bound only to IPv4 loopback. Origin is an explicit local setting,
/// never an identity supplied by the invocation. Server lifetime is at most 120 s.
pub struct Server {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    origin: String,
    session: Arc<Mutex<Session>>,
}

impl Server {
    pub async fn bind(
        bootstrap: WebSocketBootstrap,
        tls: Arc<rustls::ServerConfig>,
        origin: String,
    ) -> Result<Self, TransportError> {
        validate_origin(&origin)?;
        let mut last_error = None;
        for port in &bootstrap.ports {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).await {
                Ok(listener) => return Ok(Self::with_listener(listener, bootstrap, tls, origin)),
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
        origin: String,
    ) -> Self {
        Self {
            listener,
            tls,
            origin,
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
                    let origin = self.origin.clone();
                    let session = self.session.clone();
                    let requests = requests.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        // Errors contain library-provided untrusted details; do not log them.
                        let _ = timeout(Duration::from_secs(90), connection::handle(stream, tls, origin, session, requests)).await;
                    });
                }
            }
        }
        tasks.abort_all();
        Ok(())
    }
}
