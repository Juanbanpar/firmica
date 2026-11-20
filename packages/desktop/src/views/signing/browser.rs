use super::{tr, BUTTON};
use crate::views::home::{BrowserCompletion, BrowserOperation};
use dioxus::prelude::*;
use firmica_core::ReviewOutcome;
use firmica_protocol::ProtocolVersion;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct RequestSummary {
    pub(super) size: usize,
    pub(super) algorithm: &'static str,
    pub(super) format: &'static str,
}

#[component]
pub(super) fn BrowserConsent(
    spanish: bool,
    busy: bool,
    version: ProtocolVersion,
    origin: String,
    summary: Option<RequestSummary>,
    on_reject: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        section { class: "mb-6 rounded border p-4",
            p { {tr(spanish, "Si autorizas la firma, esta sesión recibirá la firma y el certificado elegido. Comprueba que coincide con el sitio que estás usando.", "If you approve, this session will receive the signature and the selected certificate. Check that the origin matches the site you are using.")} }
            dl { class: "my-3 grid grid-cols-2 gap-2",
                dt { {tr(spanish, "Origen autorizado", "Authorized origin")} }
                dd { id: "request-origin", class: "break-all font-mono", "{origin}" }
                dt { {tr(spanish, "Operación", "Operation")} } dd { id: "request-operation", "sign" }
                dt { {tr(spanish, "Versión del protocolo", "Protocol version")} } dd { id: "request-version", "{version}" }
                if let Some(summary) = summary {
                    dt { {tr(spanish, "Documento del navegador", "Browser document")} }
                    dd { id: "request-document-size", "{summary.size} bytes" }
                    dt { {tr(spanish, "Formato", "Format")} } dd { "{summary.format}" }
                    dt { {tr(spanish, "Algoritmo", "Algorithm")} } dd { "{summary.algorithm}" }
                }
            }
            button { id: "reject-request", class: BUTTON, disabled: busy, onclick: move |event| on_reject.call(event), {tr(spanish, "Rechazar", "Reject")} }
        }
    }
}

pub(super) fn browser_reply(
    browser: Option<Signal<Option<BrowserOperation>>>,
) -> Option<async_channel::Sender<ReviewOutcome>> {
    browser.and_then(|browser| {
        browser
            .peek()
            .as_ref()
            .map(|operation| operation.reply.clone())
    })
}

pub(super) fn finish_browser(
    browser: Option<Signal<Option<BrowserOperation>>>,
    completion: Option<Signal<Option<BrowserCompletion>>>,
    reply: Option<async_channel::Sender<ReviewOutcome>>,
    outcome: ReviewOutcome,
) {
    let (Some(mut browser), Some(reply)) = (browser, reply) else {
        return;
    };
    if !browser
        .peek()
        .as_ref()
        .is_some_and(|current| current.reply.same_channel(&reply))
    {
        return;
    }
    let result = match outcome {
        ReviewOutcome::Signed(_) => BrowserCompletion::Sent,
        ReviewOutcome::Rejected => BrowserCompletion::Rejected,
        _ => BrowserCompletion::Failed,
    };
    let delivered = reply.try_send(outcome).is_ok();
    if let Some(mut completion) = completion {
        completion.set(Some(if delivered {
            result
        } else {
            BrowserCompletion::Failed
        }));
    }
    browser.set(None);
}
