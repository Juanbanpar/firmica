//! Headless conformance peer. Delayed cancellation exercises AutoScript result polling.
use firmica_protocol::{ProtocolRequest, WebSocketBootstrap};
use firmica_transport::{load_tls, Decision, Server};
use std::{path::Path, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: probe CERT KEY ORIGIN URI".into());
    }
    let request = ProtocolRequest::parse(&args[4])?;
    let bootstrap = WebSocketBootstrap::from_request(&request)?;
    let tls = load_tls(Path::new(&args[1]), Path::new(&args[2]))?;
    let server = Server::bind(bootstrap, tls, args[3].clone()).await?;
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<firmica_transport::PendingRequest>(1);
    tokio::spawn(async move {
        while let Some(pending) = receiver.recv().await {
            assert_eq!(pending.request.operation, firmica_protocol::Operation::Sign);
            // Hold the operation long enough to require at least one getresult query.
            tokio::time::sleep(Duration::from_millis(2500)).await;
            let _ = pending.reply.send(Decision::Reject);
        }
    });
    println!("READY");
    server.run(sender).await?;
    Ok(())
}
