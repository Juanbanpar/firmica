use dioxus::prelude::*;

#[component]
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn Home() -> Element {
    rsx! { ui::InvocationReview {} }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[derive(Clone, Copy, PartialEq)]
pub enum BrowserCompletion {
    Sent,
    Rejected,
    Failed,
    Expired,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub struct BrowserOperation {
    generation: u64,
    pub request: firmica_protocol::signing::SignRequest,
    pub version: firmica_protocol::ProtocolVersion,
    pub reply: async_channel::Sender<firmica_core::ReviewOutcome>,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[component]
pub fn Home() -> Element {
    use firmica_core::{Inbox, ReviewOutcome};
    use firmica_protocol::signing::{RequestError, SignRequest};
    let incoming = use_context::<Inbox>();
    // The generic review retains unsupported/direct URI behavior. Only a live
    // transport reply can receive signing output; a bare URI never supplies one.
    let fallback = use_context_provider(Inbox::default);
    let mut browser = use_signal(|| None::<BrowserOperation>);
    let mut completion = use_signal(|| None::<BrowserCompletion>);
    let mut fallback_busy = use_signal(|| false);
    use_future(move || {
        let incoming = incoming.clone();
        let fallback = fallback.clone();
        async move {
            let mut generation = 0_u64;
            while let Ok(incoming) = incoming.receiver.recv().await {
                if browser.peek().is_some() || *fallback_busy.peek() {
                    if let Some(reply) = incoming.reply {
                        let _ = reply.try_send(ReviewOutcome::Unsupported);
                    }
                    continue;
                }
                if let Some(reply) = incoming.reply.as_ref() {
                    if reply.is_closed() {
                        continue;
                    }
                    match SignRequest::decode(&incoming.request) {
                        Ok(request) => {
                            generation = generation.wrapping_add(1);
                            completion.set(None);
                            browser.set(Some(BrowserOperation {
                                generation,
                                request,
                                version: incoming.request.version,
                                reply: reply.clone(),
                            }));
                            continue;
                        }
                        Err(RequestError::Invalid) => {
                            let _ = reply.try_send(ReviewOutcome::InvalidParameters);
                            continue;
                        }
                        Err(RequestError::Unsupported) => {}
                    }
                }
                fallback_busy.set(true);
                if let Err(error) = fallback.sender.try_send(incoming) {
                    fallback_busy.set(false);
                    if let Some(reply) = error.into_inner().reply {
                        let _ = reply.try_send(ReviewOutcome::Unsupported);
                    }
                }
            }
        }
    });
    let generation = browser
        .read()
        .as_ref()
        .map(|operation| operation.generation);
    rsx! {
        if let Some(generation) = generation {
            // A new request must get fresh password, consent and cancellation
            // state even when the previous request ends within the same render.
            for generation in [generation] {
                super::signing::LocalSigning { key: "browser-{generation}", browser: Some(browser), completion: Some(completion) }
            }
        } else {
            if let Some(result) = completion() {
                p { id: "browser-status", role: "status", class: "mx-auto max-w-3xl px-6 pt-6",
                    match result {
                        BrowserCompletion::Sent => "Firma preparada. Comprueba el resultado en el navegador. / Signature prepared. Check the result in the browser.",
                        BrowserCompletion::Rejected => "Solicitud rechazada. / Request rejected.",
                        BrowserCompletion::Failed => "La firma falló. No se ha enviado ningún resultado. / Signing failed. No result was sent.",
                        BrowserCompletion::Expired => "La solicitud ha caducado. Inicia una nueva operación desde el navegador. / The request has expired. Start a new operation from the browser.",
                    }
                }
            }
            ui::InvocationReview { on_pending: move |pending| fallback_busy.set(pending) }
        }
    }
}
