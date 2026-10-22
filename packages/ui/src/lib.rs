//! Shared feasibility UI. Native entry points supply requests through a bounded inbox.
use dioxus::prelude::*;
use firmica_core::{Inbox, Review, ReviewOutcome, ReviewState};

/// Shared screen, with no cryptographic or transport logic.
#[component]
pub fn InvocationReview(on_pending: Option<EventHandler<bool>>) -> Element {
    let inbox = use_context::<Inbox>();
    let mut review = use_signal(Review::default);
    let mut reply = use_signal(|| None::<async_channel::Sender<ReviewOutcome>>);
    let mut spanish = use_signal(|| true);
    use_future(move || {
        let inbox = inbox.clone();
        async move {
            while let Ok(incoming) = inbox.receiver.recv().await {
                // Reclaim an expired review even if its closure task has not run yet.
                if reply
                    .peek()
                    .as_ref()
                    .is_some_and(|sender| sender.is_closed())
                {
                    reply.set(None);
                    review.write().expire();
                    if let Some(handler) = on_pending {
                        handler.call(false);
                    }
                }
                if incoming
                    .reply
                    .as_ref()
                    .is_some_and(|sender| sender.is_closed())
                {
                    continue;
                }
                if review.write().receive(incoming.request) {
                    if let Some(handler) = on_pending {
                        handler.call(true);
                    }
                    reply.set(incoming.reply.clone());
                    if let Some(sender) = incoming.reply {
                        spawn(async move {
                            sender.closed().await;
                            let current = reply
                                .peek()
                                .as_ref()
                                .is_some_and(|current| current.same_channel(&sender));
                            if current {
                                reply.set(None);
                                review.write().expire();
                                if let Some(handler) = on_pending {
                                    handler.call(false);
                                }
                            }
                        });
                    }
                } else if let Some(reply) = incoming.reply {
                    let _ = reply.try_send(ReviewOutcome::Unsupported);
                }
            }
        }
    });
    let request = review.read().request().cloned();
    let state = review.read().state;
    let es = spanish();
    let mut decide = move |outcome| {
        let rejected = matches!(outcome, ReviewOutcome::Rejected);
        if let Some(handler) = on_pending {
            handler.call(false);
        }
        if let Some(sender) = reply.write().take() {
            if sender.try_send(outcome).is_err() {
                review.write().expire();
                return;
            }
        }
        if rejected {
            review.write().reject();
        } else {
            review.write().acknowledge();
        }
    };
    rsx! {
        main { class: "mx-auto max-w-3xl p-6 sm:p-12", lang: if es { "es" } else { "en" },
            header { class: "mb-10 flex items-center justify-between gap-4",
                h1 { class: "text-3xl font-semibold tracking-tight", "Firmica" }
                button {
                    class: "rounded border px-3 py-2 focus-visible:outline-2 focus-visible:outline-offset-4",
                    onclick: move |_| spanish.toggle(),
                    if es { "English" } else { "Español" }
                }
            }
            p { class: "mb-6 text-sm text-slate-600 dark:text-slate-300",
                if es { "Las solicitudes externas solo permiten revisión y cancelación" }
                else { "External requests support review and cancellation only" }
            }
            section { class: "rounded-xl border border-slate-300 p-6 dark:border-slate-700", aria_label: if es { "Solicitud externa" } else { "External request" },
                h2 { class: "mb-4 text-xl font-semibold",
                    if es { "Solicitud externa" } else { "External request" }
                }
                if let Some(request) = request {
                    p { class: "mb-4", role: "alert",
                        if es { "El origen de esta solicitud no está autenticado. No se ha autorizado ninguna firma." }
                        else { "The request origin is unauthenticated. No signature has been authorized." }
                    }
                    dl { class: "mb-6 grid grid-cols-2 gap-3",
                        dt { if es { "Operación" } else { "Operation" } }
                        dd { id: "request-operation", class: "font-mono", "{request.operation.as_str()}" }
                        dt { if es { "Versión del protocolo" } else { "Protocol version" } }
                        dd { id: "request-version", "{request.version}" }
                    }
                    p { class: "mb-6 text-sm",
                        if es { "Solo se ha analizado la estructura de la invocación. No se han leído documentos ni accedido a certificados." }
                        else { "Only the invocation envelope has been parsed. No documents or certificates have been accessed." }
                    }
                    div { class: "flex flex-wrap gap-3",
                        button { id: "reject-request", class: "rounded bg-slate-900 px-4 py-3 text-white focus-visible:outline-2 focus-visible:outline-offset-4 dark:bg-slate-100 dark:text-slate-900",
                            onclick: move |_| decide(ReviewOutcome::Rejected),
                            if es { "Rechazar" } else { "Reject" }
                        }
                        button { id: "acknowledge-request", class: "rounded border px-4 py-3 focus-visible:outline-2 focus-visible:outline-offset-4",
                            onclick: move |_| decide(ReviewOutcome::Unsupported),
                            if es { "Confirmar lectura" } else { "Acknowledge review" }
                        }
                    }
                } else {
                    p { id: "review-status", role: "status",
                        match (state, es) {
                            (ReviewState::Rejected, true) => "Solicitud rechazada.",
                            (ReviewState::Rejected, false) => "Request rejected.",
                            (ReviewState::Unsupported, true) => "Lectura confirmada. Esta operación todavía no está implementada.",
                            (ReviewState::Unsupported, false) => "Review acknowledged. This operation is not implemented yet.",
                            (ReviewState::Expired, true) => "La solicitud ha caducado. Inicia una nueva operación desde el navegador.",
                            (ReviewState::Expired, false) => "The request has expired. Start a new operation from the browser.",
                            (_, true) => "Esperando una invocación afirma://.",
                            (_, false) => "Waiting for an afirma:// invocation.",
                        }
                    }
                }
            }
        }
    }
}

/// Generated platform routers supply their own links through this shared component.
#[component]
pub fn Navbar(children: Element) -> Element {
    rsx! { nav { class: "mx-auto flex max-w-3xl gap-4 px-6 pt-6 sm:px-12", aria_label: "Navigation", {children} } }
}

/// Scope of this build, shared by platform diagnostics routes.
#[component]
pub fn Diagnostics() -> Element {
    rsx! { main { class: "mx-auto max-w-3xl p-6 sm:p-12",
        h1 { class: "mb-4 text-2xl font-semibold", "Diagnostics / Diagnóstico" }
        p { "Linux, macOS and Windows support local CAdES, PAdES and XAdES signing with PKCS#12 certificates. Supported browser signing requests require local TLS setup, browser trust and explicit consent. Bare URI requests permit review and cancellation only. / Linux, macOS y Windows admiten firmas locales CAdES, PAdES y XAdES con certificados PKCS#12. Las solicitudes de firma desde el navegador requieren configurar TLS local, la confianza del navegador y el consentimiento explícito. Las invocaciones URI directas solo permiten revisión y cancelación." }
        p { class: "mt-4", "Android and iOS support invocation review and cancellation; document signing is unavailable. / Android e iOS permiten revisar y cancelar invocaciones; la firma de documentos no está disponible." }
        p { class: "mt-4", "Certificate trust, revocation and legal qualification are not validated. / No se validan la confianza del certificado, su revocación ni su cualificación legal." }
    } }
}
