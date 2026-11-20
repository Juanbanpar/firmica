use crate::{
    session::Session, wire::decision_wire, Decision, PendingRequest, ProtocolError, TransportError,
};
use firmica_protocol::{
    Operation, ParseError, ProtocolRequest, MAX_URI_BYTES, MAX_WEBSOCKET_REQUEST_BYTES,
};
use futures_util::{SinkExt, StreamExt};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, Mutex},
    time::timeout,
};
use tokio_rustls::{rustls, TlsAcceptor};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        self,
        handshake::server::{Request, Response},
        protocol::{frame::coding::CloseCode, CloseFrame, Message, WebSocketConfig},
    },
};

pub(super) async fn handle(
    stream: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    origins: Arc<BTreeSet<String>>,
    session: Arc<Mutex<Session>>,
    requests: mpsc::Sender<PendingRequest>,
) -> Result<(), TransportError> {
    let expected_host = stream.local_addr()?.to_string();
    let acceptor = TlsAcceptor::from(tls);
    let stream = timeout(Duration::from_secs(5), acceptor.accept(stream))
        .await
        .map_err(|_| TransportError::Timeout)??;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WEBSOCKET_REQUEST_BYTES))
        .max_frame_size(Some(MAX_WEBSOCKET_REQUEST_BYTES))
        .max_write_buffer_size(
            firmica_protocol::signing::MAX_SIGN_RESPONSE_BYTES + 128 * 1024 + 14,
        );
    let mut origin = None;
    // Tungstenite requires its concrete HTTP ErrorResponse as the callback error type.
    #[allow(clippy::result_large_err)]
    let callback = |request: &Request, response: Response| {
        let mut headers = request.headers().get_all("origin").iter();
        let authorized = headers
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| origins.get(value));
        let host_ok = request.headers().get("host").and_then(|v| v.to_str().ok())
            == Some(expected_host.as_str());
        if let Some(authorized) = authorized
            .filter(|_| headers.next().is_none() && host_ok && request.uri().path() == "/")
        {
            origin = Some(authorized);
            Ok(response)
        } else {
            Err(tungstenite::http::Response::builder()
                .status(403)
                .body(Some("Forbidden".into()))
                .unwrap())
        }
    };
    let mut socket = timeout(
        Duration::from_secs(5),
        accept_hdr_async_with_config(stream, callback, Some(config)),
    )
    .await
    .map_err(|_| TransportError::Timeout)??;
    let origin = origin.ok_or(TransportError::Origin)?;
    while let Some(message) = timeout(Duration::from_secs(60), socket.next())
        .await
        .map_err(|_| TransportError::Timeout)?
    {
        let message = message?;
        let Message::Text(message) = message else {
            if matches!(message, Message::Close(_)) {
                break;
            }
            if matches!(message, Message::Ping(_) | Message::Pong(_)) {
                continue;
            }
            break;
        };
        let mut state = session.lock().await;
        let version = state.bootstrap.version;
        // Parse document-bearing requests once. Authentication must not allocate
        // and decode a second copy of a large document merely to find its session.
        let request = message
            .starts_with("afirma://")
            .then(|| ProtocolRequest::parse_websocket(&message));
        if message.len() > MAX_URI_BYTES && !matches!(&request, Some(Ok(_))) {
            drop(state);
            socket
                .close(Some(CloseFrame {
                    code: CloseCode::Size,
                    reason: "invalid or oversized request".into(),
                }))
                .await?;
            break;
        }
        let authenticated = match &request {
            Some(Ok(request)) => request.parameter("idsession") == Some(state.bootstrap.session()),
            _ => state.authenticated(&message),
        };
        let response = if !authenticated || !state.accept_origin(origin) {
            ProtocolError::Session.wire(version)
        } else if message.starts_with("echo=-idsession=") {
            "OK".into()
        } else if message.starts_with("getresult?") {
            match state.result.as_mut().map(oneshot::Receiver::try_recv) {
                Some(Ok(decision)) => {
                    state.result = None;
                    decision_wire(decision, version)
                }
                Some(Err(oneshot::error::TryRecvError::Empty)) => "#wait".into(),
                Some(Err(oneshot::error::TryRecvError::Closed)) => {
                    state.result = None;
                    ProtocolError::Cancelled.wire(version)
                }
                None => ProtocolError::Unsupported.wire(version),
            }
        } else if state.used {
            ProtocolError::Unsupported.wire(version)
        } else {
            match request.unwrap_or(Err(ParseError::Scheme)) {
                Ok(mut request)
                    if !matches!(request.operation, Operation::WebSocket | Operation::Service) =>
                {
                    // Operation URIs sent over WSS inherit the negotiated channel version.
                    request.version = version;
                    let (reply, result) = oneshot::channel();
                    if requests
                        .try_send(PendingRequest { request, reply })
                        .is_err()
                    {
                        ProtocolError::Unsupported.wire(version)
                    } else {
                        state.used = true;
                        if state.bootstrap.asynchronous {
                            state.result = Some(result);
                            "#wait".into()
                        } else {
                            drop(state);
                            let decision = timeout(Duration::from_secs(60), result)
                                .await
                                .ok()
                                .and_then(Result::ok)
                                .unwrap_or(Decision::Reject);
                            socket
                                .send(Message::Text(decision_wire(decision, version).into()))
                                .await?;
                            continue;
                        }
                    }
                }
                Err(ParseError::Operation) => ProtocolError::Unsupported.wire(version),
                _ => ProtocolError::Parameters.wire(version),
            }
        };
        drop(state);
        socket.send(Message::Text(response.into())).await?;
    }
    Ok(())
}
