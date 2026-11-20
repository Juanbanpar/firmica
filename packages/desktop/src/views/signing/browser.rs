use super::{tr, BUTTON};
use crate::views::home::{BrowserCompletion, BrowserOperation};
use dioxus::prelude::*;
use firmica_core::ReviewOutcome;
use firmica_protocol::ProtocolVersion;

#[component]
pub(super) fn BrowserConsent(
    spanish: bool,
    busy: bool,
    version: ProtocolVersion,
    on_reject: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        section { class: "mb-6 rounded border p-4",
            p { role: "alert", {tr(spanish, "Solicitud de navegador: el origen no está autenticado. La firma y el certificado elegido se enviarán a la sesión que solicitó la operación.", "Browser request: the origin is unauthenticated. The signature and selected certificate will be sent to the session that requested the operation.")} }
            dl { class: "my-3 grid grid-cols-2 gap-2",
                dt { {tr(spanish, "Operación", "Operation")} } dd { id: "request-operation", "sign" }
                dt { {tr(spanish, "Versión del protocolo", "Protocol version")} } dd { id: "request-version", "{version}" }
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
