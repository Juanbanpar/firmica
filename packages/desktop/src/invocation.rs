//! Native invocation adapter for the generated Dioxus desktop entry point.
use clap::Parser;
use dioxus::prelude::*;
use firmica_core::{Inbox, IncomingReview, ReviewOutcome};
use firmica_protocol::{Operation, ProtocolRequest, WebSocketBootstrap};
use firmica_transport::{Decision, PendingRequest, Server};
use std::{path::PathBuf, sync::OnceLock};

static INBOX: OnceLock<Inbox> = OnceLock::new();
pub fn inbox() -> Inbox {
    INBOX.get_or_init(Inbox::default).clone()
}

#[derive(Parser)]
#[command(about = "Firmica electronic-signature client")]
struct Arguments {
    /// Optional afirma:// invocation; it is parsed but never executed as a command.
    uri: Option<String>,
    /// Enable the restricted WSS prototype with an explicit test certificate.
    #[arg(long, requires_all = ["tls_key", "origin"])]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    origin: Option<String>,
}

pub fn launch(app: fn() -> Element) -> Result<(), String> {
    let args = Arguments::parse();
    if let Some(uri) = &args.uri {
        ProtocolRequest::parse(uri).map_err(|e| e.to_string())?;
    }
    let (sender, receiver) = tokio::sync::mpsc::channel::<String>(8);
    #[cfg(target_os = "linux")]
    let _instance = match linux::primary_or_forward(args.uri.as_deref(), sender.clone())? {
        Some(instance) => instance,
        None => return Ok(()),
    };
    let runtime = tokio::runtime::Runtime::new().map_err(|_| "cannot start async runtime")?;
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            Some(firmica_transport::load_tls(cert, key).map_err(|e| e.to_string())?)
        }
        _ => None,
    };
    let initial = args.uri;
    let origin = args.origin;
    runtime.spawn(async move {
        let mut receiver = receiver;
        let mut server_task: Option<tokio::task::JoinHandle<()>> = None;
        while let Some(uri) = receiver.recv().await {
            let Ok(request) = ProtocolRequest::parse(&uri) else {
                eprintln!("Firmica: rejected invalid invocation");
                continue;
            };
            if request.operation == Operation::WebSocket {
                // A second URI must not terminate or replace an active browser session.
                if server_task.as_ref().is_some_and(|task| !task.is_finished()) {
                    eprintln!("Firmica: WSS session already active");
                    continue;
                }
                let Some(tls) = tls.clone() else {
                    eprintln!("Firmica: WSS requires explicit TLS configuration");
                    continue;
                };
                let Some(origin) = origin.clone() else {
                    continue;
                };
                let Ok(bootstrap) = WebSocketBootstrap::from_request(&request) else {
                    eprintln!("Firmica: unsupported WSS bootstrap");
                    continue;
                };
                let server = match Server::bind(bootstrap, tls, origin).await {
                    Ok(server) => server,
                    Err(_) => {
                        eprintln!("Firmica: cannot bind WSS test listener");
                        continue;
                    }
                };
                let (requests, mut pending) = tokio::sync::mpsc::channel::<PendingRequest>(1);
                server_task = Some(tokio::spawn(async move {
                    let _ = server.run(requests).await;
                }));
                tokio::spawn(async move {
                    while let Some(pending) = pending.recv().await {
                        tokio::spawn(forward_review(pending, inbox()));
                    }
                });
            } else if request.operation == Operation::Service {
                eprintln!("Firmica: legacy HTTPS socket transport is not implemented");
            } else if inbox()
                .sender
                .try_send(IncomingReview {
                    request,
                    reply: None,
                })
                .is_err()
            {
                eprintln!("Firmica: invocation queue is full");
            }
        }
    });
    if let Some(uri) = initial {
        sender
            .try_send(uri)
            .map_err(|_| "invocation queue is full")?;
    }
    let native_events = sender.clone();
    let config = dioxus::desktop::Config::new()
        .with_window(dioxus::desktop::WindowBuilder::new().with_title("Firmica"))
        .with_custom_event_handler(move |event, _| {
            if let dioxus::desktop::tao::event::Event::Opened { urls } = event {
                for url in urls {
                    let _ = native_events.try_send(url.to_string());
                }
            }
        });
    dioxus::LaunchBuilder::desktop()
        .with_cfg(config)
        .launch(app);
    drop(runtime);
    Ok(())
}

/// Dropping the UI response receiver invalidates its review when the transport ends.
async fn forward_review(mut pending: PendingRequest, inbox: Inbox) {
    if pending.reply.is_closed() {
        return;
    }
    let (reply, outcome) = async_channel::bounded(1);
    if inbox
        .sender
        .try_send(IncomingReview {
            request: pending.request,
            reply: Some(reply),
        })
        .is_err()
    {
        let _ = pending.reply.send(Decision::Unsupported);
        return;
    }
    tokio::select! {
        biased;
        _ = pending.reply.closed() => {},
        result = outcome.recv() => {
            let decision = match result {
                Ok(ReviewOutcome::Unsupported) => Decision::Unsupported,
                Ok(ReviewOutcome::Failed) => Decision::Failed,
                Ok(ReviewOutcome::InvalidParameters) => Decision::InvalidParameters,
                Ok(ReviewOutcome::Signed(result)) => Decision::Signed(result),
                _ => Decision::Reject,
            };
            let _ = pending.reply.send(decision);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{sync::oneshot, time::timeout};

    fn pending() -> (PendingRequest, oneshot::Receiver<Decision>) {
        let (reply, response) = oneshot::channel();
        (
            PendingRequest {
                request: ProtocolRequest::parse("afirma://sign?ver=4&dat=private").unwrap(),
                reply,
            },
            response,
        )
    }

    #[tokio::test]
    async fn transport_cancellation_closes_the_ui_response_path() {
        let inbox = Inbox::default();
        let (pending, response) = pending();
        let task = tokio::spawn(forward_review(pending, inbox.clone()));
        let incoming = inbox.receiver.recv().await.unwrap();
        let reply = incoming.reply.unwrap();
        assert!(!reply.is_closed());
        drop(response);
        timeout(Duration::from_secs(1), reply.closed())
            .await
            .unwrap();
        task.await.unwrap();
        assert!(reply.try_send(ReviewOutcome::Unsupported).is_err());
    }

    #[tokio::test]
    async fn ui_decisions_reach_the_transport() {
        for (outcome, expected) in [
            (ReviewOutcome::Rejected, Decision::Reject),
            (ReviewOutcome::Unsupported, Decision::Unsupported),
            (
                ReviewOutcome::InvalidParameters,
                Decision::InvalidParameters,
            ),
            (ReviewOutcome::Failed, Decision::Failed),
            (
                ReviewOutcome::Signed(
                    firmica_protocol::signing::SignResponse::new(&[1], &[2]).unwrap(),
                ),
                Decision::Signed(firmica_protocol::signing::SignResponse::new(&[1], &[2]).unwrap()),
            ),
        ] {
            let inbox = Inbox::default();
            let (pending, response) = pending();
            let task = tokio::spawn(forward_review(pending, inbox.clone()));
            let reply = inbox.receiver.recv().await.unwrap().reply.unwrap();
            reply.try_send(outcome).unwrap();
            assert_eq!(response.await.unwrap(), expected);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn expired_request_is_not_queued() {
        let inbox = Inbox::default();
        let (pending, response) = pending();
        drop(response);
        forward_review(pending, inbox.clone()).await;
        assert!(inbox.receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn full_inbox_returns_unsupported_without_waiting_for_the_ui() {
        let inbox = Inbox::default();
        for _ in 0..8 {
            inbox
                .sender
                .try_send(IncomingReview {
                    request: ProtocolRequest::parse("afirma://save?").unwrap(),
                    reply: None,
                })
                .unwrap_or_else(|_| panic!("test inbox filled too early"));
        }
        let (pending, response) = pending();
        forward_review(pending, inbox).await;
        assert_eq!(response.await.unwrap(), Decision::Unsupported);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use firmica_protocol::MAX_URI_BYTES;
    use std::{
        fs,
        os::unix::{
            fs::{DirBuilderExt, MetadataExt},
            net::UnixDatagram,
        },
        time::Duration,
    };

    pub struct Instance {
        path: PathBuf,
        _lock: fs::File,
    }
    impl Drop for Instance {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// Per-user, private Unix datagram handoff; never opens a TCP forwarding port.
    pub fn primary_or_forward(
        uri: Option<&str>,
        incoming: tokio::sync::mpsc::Sender<String>,
    ) -> Result<Option<Instance>, String> {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is required for Linux invocation")?;
        let uid = rustix::process::geteuid().as_raw();
        fn check(path: &std::path::Path, uid: u32) -> Result<(), String> {
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| "cannot inspect private runtime directory")?;
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return Err("runtime directory must be owned by this user with mode 0700".into());
            }
            Ok(())
        }
        check(&runtime, uid)?;
        let private = runtime.join("firmica-phase0");
        match fs::DirBuilder::new().mode(0o700).create(&private) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("cannot create private invocation directory".into()),
        }
        check(&private, uid)?;
        let path = private.join("invocation.sock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(private.join("instance.lock"))
            .map_err(|_| "cannot open invocation lock")?;
        match lock.try_lock() {
            Err(fs::TryLockError::WouldBlock) => {
                let socket =
                    UnixDatagram::unbound().map_err(|_| "cannot create invocation sender")?;
                socket
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .map_err(|_| "cannot configure invocation sender")?;
                // The primary may still be binding its socket. Retry briefly without dropping the URI.
                for attempt in 0..20 {
                    if socket.connect(&path).is_ok() {
                        if let Some(uri) = uri {
                            socket
                                .send(uri.as_bytes())
                                .map_err(|_| "cannot forward invocation")?;
                        }
                        return Ok(None);
                    }
                    if attempt < 19 {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                }
                Err("running instance has no invocation socket".into())
            }
            Err(_) => Err("cannot lock invocation state".into()),
            Ok(()) => {
                // Only the lock holder can remove a socket left behind by a crashed process.
                if let Ok(metadata) = fs::symlink_metadata(&path) {
                    use std::os::unix::fs::FileTypeExt;
                    if !metadata.file_type().is_socket() || metadata.uid() != uid {
                        return Err("unexpected object at invocation socket path".into());
                    }
                    fs::remove_file(&path).map_err(|_| "cannot remove stale invocation socket")?;
                }
                let socket = UnixDatagram::bind(&path)
                    .map_err(|_| "cannot bind private invocation socket")?;
                std::thread::spawn(move || {
                    let mut bytes = vec![0; MAX_URI_BYTES + 1];
                    while let Ok(length) = socket.recv(&mut bytes) {
                        if length > MAX_URI_BYTES {
                            continue;
                        }
                        if let Ok(uri) = std::str::from_utf8(&bytes[..length]) {
                            if ProtocolRequest::parse(uri).is_ok() {
                                let _ = incoming.try_send(uri.to_owned());
                            }
                        }
                    }
                });
                Ok(Some(Instance { path, _lock: lock }))
            }
        }
    }
}
