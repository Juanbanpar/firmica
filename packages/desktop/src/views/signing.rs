use super::home::{BrowserCompletion, BrowserOperation};
use crate::signing::{packaged_worker, Error, Prepared};
use dioxus::prelude::*;
use firmica_core::ReviewOutcome;
use firmica_signing::format::{ContentMode, Format};
use firmica_signing::SignatureAlgorithm;
use secrecy::SecretString;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

mod browser;
mod form;
mod messages;
mod review;

use browser::{browser_reply, finish_browser, BrowserConsent};
use form::{file_dialog, Inputs, SigningForm};
use messages::{tr, Status};
use review::{Details, Review};

const BUTTON: &str = "rounded border px-4 py-3 disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-4";
const FIELD: &str = "mt-2 block w-full rounded border bg-transparent px-3 py-2";

#[component]
pub fn LocalSigning(
    browser: Option<Signal<Option<BrowserOperation>>>,
    completion: Option<Signal<Option<BrowserCompletion>>>,
) -> Element {
    let mut es = use_signal(|| true);
    let mut document = use_signal(|| None::<PathBuf>);
    let mut certificate = use_signal(|| None::<PathBuf>);
    let mut password = use_signal(SecretString::default);
    let mut password_generation = use_signal(|| 0_u64);
    let algorithm = use_signal(|| SignatureAlgorithm::RsaPkcs1v15Sha256);
    let format = use_signal(|| Format::Cades(ContentMode::Detached));
    let mut prepared = use_signal(|| None::<Prepared>);
    let mut busy = use_signal(|| false);
    let mut acknowledged = use_signal(|| false);
    let mut status = use_signal(|| Status::Idle);
    let cancelled = use_hook(|| Arc::new(AtomicBool::new(false)));
    let on_unmount = cancelled.clone();
    use_drop(move || on_unmount.store(true, Ordering::Release));
    let expiry_cancellation = cancelled.clone();
    use_future(move || {
        let expiry_cancellation = expiry_cancellation.clone();
        async move {
            if let Some(mut browser) = browser {
                let reply = browser
                    .peek()
                    .as_ref()
                    .map(|operation| operation.reply.clone());
                if let Some(reply) = reply {
                    reply.closed().await;
                    if browser
                        .peek()
                        .as_ref()
                        .is_some_and(|current| current.reply.same_channel(&reply))
                    {
                        expiry_cancellation.store(true, Ordering::Release);
                        prepared.set(None);
                        if let Some(mut completion) = completion {
                            completion.set(Some(BrowserCompletion::Expired));
                        }
                        browser.set(None);
                    }
                }
            }
        }
    });
    let spanish = es();
    let external = browser.is_some();
    let browser_version =
        browser.and_then(|browser| browser.read().as_ref().map(|operation| operation.version));
    let reject_cancellation = cancelled.clone();

    let details = prepared
        .read()
        .as_ref()
        .map(|pending| Details::from_review(pending.review()));
    let text = status.read().text(external, spanish);
    let failed = matches!(&*status.read(), Status::Failed(_));
    let signing_cancellation = cancelled.clone();

    let reject = move |_: MouseEvent| {
        if busy() {
            return;
        }
        reject_cancellation.store(true, Ordering::Release);
        let reply = browser_reply(browser);
        let pending = prepared.write().take();
        busy.set(true);
        spawn(async move {
            let result = if let Some(pending) = pending {
                tokio::task::spawn_blocking(move || pending.cancel())
                    .await
                    .unwrap_or(Err(Error::Task))
            } else {
                Ok(())
            };
            finish_browser(browser, completion, reply, ReviewOutcome::Rejected);
            if let Err(error) = result {
                status.set(Status::Failed(error));
            }
            busy.set(false);
        });
    };

    let sign = move |_: MouseEvent| {
        if busy() || !acknowledged() {
            return;
        }
        busy.set(true);
        let cancellation = signing_cancellation.clone();
        let reply = browser_reply(browser);
        spawn(async move {
            if external {
                let pending = prepared.write().take();
                if let Some(pending) = pending {
                    if reply.as_ref().is_none_or(|reply| reply.is_closed()) {
                        cancellation.store(true, Ordering::Release);
                    }
                    status.set(Status::Signing);
                    let result = tokio::task::spawn_blocking(move || {
                        pending.sign_for_browser(&cancellation)
                    })
                    .await
                    .unwrap_or(Err(Error::Task));
                    match result {
                        Ok(result) => finish_browser(
                            browser,
                            completion,
                            reply,
                            ReviewOutcome::Signed(result),
                        ),
                        Err(error) => {
                            status.set(Status::Failed(error));
                            finish_browser(browser, completion, reply, ReviewOutcome::Failed);
                        }
                    }
                }
                busy.set(false);
                return;
            }
            let (filename, extension) = prepared
                .peek()
                .as_ref()
                .map(|pending| {
                    let review = pending.review();
                    let extension = review.format().extension();
                    (
                        format!("{}.signed.{extension}", review.document_name()),
                        extension,
                    )
                })
                .unwrap_or_else(|| ("signature.csig".into(), "csig"));
            let destination = file_dialog()
                .set_file_name(filename)
                .add_filter("Signature", &[extension])
                .save_file()
                .await;
            if let Some(destination) = destination {
                let pending = prepared.write().take();
                if let Some(pending) = pending {
                    status.set(Status::Signing);
                    let destination = destination.path().to_owned();
                    let result = tokio::task::spawn_blocking(move || {
                        pending.sign_and_save(&destination, &cancellation)
                    })
                    .await
                    .unwrap_or(Err(Error::Task));
                    status.set(match result {
                        Ok(()) => Status::Saved,
                        Err(error) => Status::Failed(error),
                    });
                    acknowledged.set(false);
                }
            }
            busy.set(false);
        });
    };

    let cancel = move |_: MouseEvent| {
        if busy() {
            return;
        }
        let pending = prepared.write().take();
        if let Some(pending) = pending {
            busy.set(true);
            let reply = browser_reply(browser);
            spawn(async move {
                let result = tokio::task::spawn_blocking(move || pending.cancel())
                    .await
                    .unwrap_or(Err(Error::Task));
                status.set(match result {
                    Ok(()) => Status::Cancelled,
                    Err(error) => Status::Failed(error),
                });
                acknowledged.set(false);
                if external {
                    finish_browser(browser, completion, reply, ReviewOutcome::Rejected);
                }
                busy.set(false);
            });
        }
    };

    let prepare = move |_: MouseEvent| {
        if busy() {
            return;
        }
        let Some(certificate_path) = certificate.peek().clone() else {
            return;
        };
        let document_path = document.peek().clone();
        let inline = browser.and_then(|browser| {
            browser
                .peek()
                .as_ref()
                .filter(|operation| !operation.reply.is_closed())
                .map(|operation| {
                    (
                        operation.request.document().to_vec(),
                        operation.request.algorithm(),
                        operation.request.format().clone(),
                    )
                })
        });
        if external && inline.is_none() {
            return;
        }
        let secret = std::mem::take(&mut *password.write());
        *password_generation.write() += 1;
        let algorithm = algorithm();
        let format = format();
        busy.set(true);
        status.set(Status::Opening);
        spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let worker = packaged_worker()?;
                if let Some((document, algorithm, format)) = inline {
                    Prepared::open_document(
                        &worker,
                        "Browser document / Documento del navegador".into(),
                        document,
                        &certificate_path,
                        secret,
                        algorithm,
                        format,
                    )
                } else {
                    Prepared::open(
                        &worker,
                        &document_path.ok_or(Error::ReadInput)?,
                        &certificate_path,
                        secret,
                        algorithm,
                        format,
                    )
                }
            })
            .await
            .unwrap_or(Err(Error::Task));
            match result {
                Ok(pending) => {
                    document.set(None);
                    certificate.set(None);
                    prepared.set(Some(pending));
                    status.set(Status::Ready);
                }
                Err(error) => status.set(Status::Failed(error)),
            }
            busy.set(false);
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl p-6 sm:p-12", lang: if spanish { "es" } else { "en" },
            header { class: "mb-6 flex items-center justify-between gap-4",
                h1 { class: "text-3xl font-semibold tracking-tight", {tr(spanish, "Firmar un documento", "Sign a document")} }
                button { id: "sign-language", class: BUTTON, onclick: move |_| es.toggle(), if spanish { "English" } else { "Español" } }
            }
            if external {
                BrowserConsent { spanish, busy: busy(), version: browser_version.unwrap_or_default(), on_reject: reject }
            } else {
                p { class: "mb-6", {tr(spanish, "Firma local. Revisa el documento y el certificado antes de autorizar la operación.", "Local signing. Review the document and certificate before authorizing the operation.")} }
            }
            p { id: "sign-status", class: "mb-6", role: if failed { "alert" } else { "status" }, "{text}" }
            if let Some(details) = details {
                Review { details, spanish, external, busy: busy(), acknowledged, on_sign: sign, on_cancel: cancel }
            } else {
                SigningForm {
                    inputs: Inputs { document, certificate, password, password_generation, algorithm, format },
                    spanish, external, busy, on_prepare: prepare,
                }
            }
        }
    }
}
