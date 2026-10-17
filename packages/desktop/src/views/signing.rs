use crate::signing::{packaged_worker, Error, Prepared};
use dioxus::prelude::*;
use firmica_cades::ContentMode;
use firmica_core::signing::ApprovalError;
use firmica_key_worker::WorkerError;
use firmica_signing::SignatureAlgorithm;
use firmica_validation::Restriction;
use secrecy::SecretString;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const BUTTON: &str = "rounded border px-4 py-3 disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-4";
const FIELD: &str = "mt-2 block w-full rounded border bg-transparent px-3 py-2";

fn tr(es: bool, spanish: &'static str, english: &'static str) -> &'static str {
    if es {
        spanish
    } else {
        english
    }
}

enum Status {
    Idle,
    Opening,
    Ready,
    Signing,
    Cancelled,
    Saved,
    Failed(Error),
}

struct Details {
    name: String,
    size: usize,
    hash: String,
    subject: String,
    issuer: String,
    serial: String,
    fingerprint: String,
    start: String,
    end: String,
    chosen_algorithm: SignatureAlgorithm,
    mode: ContentMode,
}

#[component]
pub fn LocalSigning() -> Element {
    let mut es = use_signal(|| true);
    let mut document = use_signal(|| None::<PathBuf>);
    let mut certificate = use_signal(|| None::<PathBuf>);
    let mut password = use_signal(SecretString::default);
    let mut password_generation = use_signal(|| 0_u64);
    let mut algorithm = use_signal(|| SignatureAlgorithm::RsaPkcs1v15Sha256);
    let mut attached = use_signal(|| false);
    let mut prepared = use_signal(|| None::<Prepared>);
    let mut busy = use_signal(|| false);
    let mut acknowledged = use_signal(|| false);
    let mut status = use_signal(|| Status::Idle);
    let cancelled = use_hook(|| Arc::new(AtomicBool::new(false)));
    let on_unmount = cancelled.clone();
    use_drop(move || on_unmount.store(true, Ordering::Release));
    let spanish = es();
    let details = prepared.read().as_ref().map(|pending| {
        let review = pending.review();
        let certificate = review.certificate();
        Details {
            name: review.document_name().to_owned(),
            size: review.document_size(),
            hash: hex(review.document_hash()),
            subject: certificate.subject().to_owned(),
            issuer: certificate.issuer().to_owned(),
            serial: hex(certificate.serial()),
            fingerprint: hex(certificate.fingerprint()),
            start: date(certificate.not_before()),
            end: date(certificate.not_after()),
            chosen_algorithm: review.algorithm(),
            mode: review.content_mode(),
        }
    });
    let text = match &*status.read() {
        Status::Idle => tr(
            spanish,
            "Selecciona un documento y un certificado PKCS#12.",
            "Choose a document and a PKCS#12 certificate.",
        )
        .to_owned(),
        Status::Opening => tr(
            spanish,
            "Abriendo el certificado…",
            "Opening the certificate…",
        )
        .to_owned(),
        Status::Ready => tr(
            spanish,
            "Revisa los datos antes de autorizar la firma.",
            "Review the details before authorizing signing.",
        )
        .to_owned(),
        Status::Signing => tr(spanish, "Firmando y guardando…", "Signing and saving…").to_owned(),
        Status::Cancelled => tr(spanish, "Operación cancelada.", "Operation cancelled.").to_owned(),
        Status::Saved => tr(spanish, "Firma guardada.", "Signature saved.").to_owned(),
        Status::Failed(error) => error_text(error, spanish),
    };
    let failed = matches!(&*status.read(), Status::Failed(_));
    let signing_cancellation = cancelled.clone();
    rsx! {
        main { class: "mx-auto max-w-3xl p-6 sm:p-12", lang: if spanish { "es" } else { "en" },
            header { class: "mb-6 flex items-center justify-between gap-4",
                h1 { class: "text-3xl font-semibold tracking-tight", {tr(spanish, "Firmar un documento", "Sign a document")} }
                button { id: "sign-language", class: BUTTON, onclick: move |_| es.toggle(), if spanish { "English" } else { "Español" } }
            }
            p { class: "mb-6", {tr(spanish, "Firma local CAdES. Las solicitudes del navegador no autorizan esta operación.", "Local CAdES signing. Browser requests do not authorize this operation.")} }
            p { id: "sign-status", class: "mb-6", role: if failed { "alert" } else { "status" }, "{text}" }
            if let Some(Details { name, size, hash, subject, issuer, serial, fingerprint, start, end, chosen_algorithm, mode }) = details {
                section { aria_label: tr(spanish, "Revisión de firma", "Signing review"),
                    dl { class: "grid grid-cols-1 gap-2 break-all sm:grid-cols-[10rem_1fr]",
                        dt { {tr(spanish, "Documento", "Document")} } dd { id: "sign-document-name", "{name}" }
                        dt { {tr(spanish, "Tamaño", "Size")} } dd { "{size} bytes" }
                        dt { "SHA-256" } dd { id: "sign-document-hash", class: "font-mono text-xs", "{hash}" }
                        dt { {tr(spanish, "Titular declarado", "Claimed subject")} } dd { id: "sign-subject", "{subject}" }
                        dt { {tr(spanish, "Emisor declarado", "Claimed issuer")} } dd { "{issuer}" }
                        dt { {tr(spanish, "Número de serie", "Serial number")} } dd { class: "font-mono text-sm", "{serial}" }
                        dt { {tr(spanish, "Huella SHA-256", "SHA-256 fingerprint")} } dd { id: "sign-fingerprint", class: "font-mono text-xs", "{fingerprint}" }
                        dt { {tr(spanish, "Válido desde", "Valid from")} } dd { "{start}" }
                        dt { {tr(spanish, "Válido hasta", "Valid until")} } dd { "{end}" }
                        dt { {tr(spanish, "Algoritmo", "Algorithm")} } dd { {algorithm_name(chosen_algorithm)} }
                        dt { {tr(spanish, "Contenido", "Content")} } dd {
                            if mode == ContentMode::Attached { {tr(spanish, "Incluido en la firma", "Embedded in the signature")} }
                            else { {tr(spanish, "Separado; conserva el documento original", "Detached; retain the original document")} }
                        }
                    }
                    p { class: "my-6", id: "sign-unchecked", role: "alert",
                        {tr(spanish,
                            "Las restricciones locales permiten firmar. No se han comprobado la firma del certificado, la cadena de confianza, la revocación ni la cualificación legal. Los nombres anteriores son declaraciones del certificado sin autenticar.",
                            "Local constraints permit signing. The certificate signature, trust chain, revocation and legal qualification have not been checked. The names above are unauthenticated certificate claims.")}
                    }
                    label { class: "mb-6 flex items-start gap-3",
                        input { id: "sign-acknowledge", r#type: "checkbox", checked: acknowledged(), disabled: busy(),
                            onchange: move |event| acknowledged.set(event.checked()),
                        }
                        {tr(spanish, "Autorizo la firma de este documento con este certificado y acepto las comprobaciones pendientes indicadas.", "I authorize signing this document with this certificate and accept the unchecked items shown above.")}
                    }
                    div { class: "flex gap-3",
                        button { id: "sign-save", class: BUTTON, disabled: busy() || !acknowledged(),
                            onclick: move |_| {
                                if busy() || !acknowledged() { return; }
                                busy.set(true);
                                let cancellation = signing_cancellation.clone();
                                spawn(async move {
                                    let filename = prepared.peek().as_ref().map(|pending| format!("{}.csig", pending.review().document_name())).unwrap_or_else(|| "signature.csig".into());
                                    let destination = rfd::AsyncFileDialog::new().set_file_name(filename).add_filter("CAdES", &["csig"]).save_file().await;
                                    if let Some(destination) = destination {
                                        let pending = prepared.write().take();
                                        if let Some(pending) = pending {
                                            status.set(Status::Signing);
                                            let destination = destination.path().to_owned();
                                            let result = tokio::task::spawn_blocking(move || pending.sign_and_save(&destination, &cancellation)).await.unwrap_or(Err(Error::Task));
                                            status.set(match result { Ok(()) => Status::Saved, Err(error) => Status::Failed(error) });
                                            acknowledged.set(false);
                                        }
                                    }
                                    busy.set(false);
                                });
                            }, {tr(spanish, "Firmar y guardar…", "Sign and save…")}
                        }
                        button { id: "sign-cancel", class: BUTTON, disabled: busy(), onclick: move |_| {
                            if busy() { return; }
                            let pending = prepared.write().take();
                            if let Some(pending) = pending {
                                busy.set(true);
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(move || pending.cancel()).await.unwrap_or(Err(Error::Task));
                                    status.set(match result { Ok(()) => Status::Cancelled, Err(error) => Status::Failed(error) });
                                    acknowledged.set(false);
                                    busy.set(false);
                                });
                            }
                        }, {tr(spanish, "Cancelar", "Cancel")} }
                    }
                    p { class: "mt-4 text-sm", {tr(spanish, "Elige un nombre nuevo: no se reemplazan archivos existentes.", "Choose a new filename: existing files are not replaced.")} }
                }
            } else {
                div { class: "space-y-5",
                    label { class: "block", {tr(spanish, "Documento (hasta 16 MiB)", "Document (up to 16 MiB)")}
                        input { id: "sign-document", class: FIELD, r#type: "file", disabled: busy(),
                            onchange: move |event| document.set(event.files().into_iter().next().map(|file| file.path())),
                        }
                    }
                    label { class: "block", {tr(spanish, "Certificado PKCS#12 (hasta 8 MiB)", "PKCS#12 certificate (up to 8 MiB)")}
                        input { id: "sign-certificate", class: FIELD, r#type: "file", accept: ".p12,.pfx", disabled: busy(),
                            onchange: move |event| certificate.set(event.files().into_iter().next().map(|file| file.path())),
                        }
                    }
                    label { class: "block", {tr(spanish, "Contraseña del certificado", "Certificate password")}
                        // A keyed dynamic child replaces the actual input on submission,
                        // clearing the DOM value without rendering the secret as a prop.
                        for generation in [password_generation()] {
                            input { key: "password-{generation}", id: "sign-password", class: FIELD, r#type: "password", autocomplete: "off", maxlength: "4096", disabled: busy(),
                                oninput: move |event| password.set(SecretString::from(event.value())),
                            }
                        }
                    }
                    label { class: "block", {tr(spanish, "Algoritmo", "Algorithm")}
                        select { id: "sign-algorithm", class: FIELD, disabled: busy(), value: if algorithm() == SignatureAlgorithm::RsaPkcs1v15Sha256 { "rsa" } else { "ec" },
                            onchange: move |event| algorithm.set(if event.value() == "ec" { SignatureAlgorithm::EcdsaP256Sha256 } else { SignatureAlgorithm::RsaPkcs1v15Sha256 }),
                            option { value: "rsa", "RSA PKCS#1 v1.5 / SHA-256" }
                            option { value: "ec", "ECDSA P-256 / SHA-256" }
                        }
                    }
                    label { class: "flex items-center gap-3",
                        input { id: "sign-attached", r#type: "checkbox", checked: attached(), disabled: busy(), onchange: move |event| attached.set(event.checked()) }
                        {tr(spanish, "Incluir el documento en la firma", "Embed the document in the signature")}
                    }
                    button { id: "sign-prepare", class: BUTTON, disabled: busy() || document.read().is_none() || certificate.read().is_none(),
                        onclick: move |_| {
                            if busy() { return; }
                            let (Some(document_path), Some(certificate_path)) = (document.peek().clone(), certificate.peek().clone()) else { return; };
                            let secret = std::mem::take(&mut *password.write());
                            *password_generation.write() += 1;
                            let algorithm = algorithm();
                            let mode = if attached() { ContentMode::Attached } else { ContentMode::Detached };
                            busy.set(true);
                            status.set(Status::Opening);
                            spawn(async move {
                                let result = tokio::task::spawn_blocking(move || {
                                    let worker = packaged_worker()?;
                                    Prepared::open(&worker, &document_path, &certificate_path, secret, algorithm, mode)
                                }).await.unwrap_or(Err(Error::Task));
                                match result {
                                    Ok(pending) => {
                                        document.set(None); certificate.set(None);
                                        prepared.set(Some(pending)); status.set(Status::Ready);
                                    }
                                    Err(error) => status.set(Status::Failed(error)),
                                }
                                busy.set(false);
                            });
                        }, {tr(spanish, "Abrir y revisar", "Open and review")}
                    }
                }
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn date(time: std::time::SystemTime) -> String {
    der::DateTime::from_system_time(time)
        .expect("assessed X.509 time")
        .to_string()
}
fn algorithm_name(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => "RSA PKCS#1 v1.5 / SHA-256",
        SignatureAlgorithm::EcdsaP256Sha256 => "ECDSA P-256 / SHA-256",
    }
}
fn error_text(error: &Error, es: bool) -> String {
    match error {
        Error::ReadInput => tr(es, "No se puede leer el archivo seleccionado. Debe ser un archivo normal.", "Cannot read the selected file. It must be a regular file."),
        Error::InputTooLarge => tr(es, "El archivo supera el límite indicado.", "The file exceeds the displayed size limit."),
        Error::MissingWorker => tr(es, "Falta el componente de certificados. Revisa la instalación de Firmica.", "The certificate worker is missing or unprotected. Check the Firmica installation."),
        Error::Worker(WorkerError::Import(_)) => tr(es, "No se puede abrir el certificado. Revisa el archivo y la contraseña.", "Cannot open the certificate. Check the file and password."),
        Error::Worker(_) => tr(es, "No se pudo completar la operación de certificados de forma segura. No se ha guardado ninguna firma.", "The certificate operation could not complete safely. No signature was saved."),
        Error::Approval(ApprovalError::CertificateRestricted(restrictions)) => {
            return format!("{} {}", tr(es, "Firma bloqueada:", "Signing blocked:"), restrictions.iter().map(|restriction| restriction_text(*restriction, es)).collect::<Vec<_>>().join("; "));
        }
        Error::Approval(ApprovalError::UnsupportedAlgorithm) => tr(es, "El certificado no admite el algoritmo elegido.", "The certificate does not support the chosen algorithm."),
        Error::Approval(_) => tr(es, "No se pudo completar la firma. No se ha guardado ningún resultado.", "Signing failed. No result was saved."),
        Error::DestinationExists => tr(es, "El destino ya existe. No se ha reemplazado.", "The destination already exists. It was not replaced."),
        Error::Save => tr(es, "No se pudo guardar la firma. Comprueba el directorio de destino.", "Cannot save the signature. Check the destination directory."),
        Error::Cancelled => tr(es, "Operación cancelada.", "Operation cancelled."),
        Error::Task => tr(es, "La operación se interrumpió. No se ha confirmado una firma guardada.", "The operation was interrupted. A saved signature has not been confirmed."),
    }.to_owned()
}

fn restriction_text(restriction: Restriction, es: bool) -> &'static str {
    match restriction {
        Restriction::NotYetValid => tr(
            es,
            "el certificado aún no es válido",
            "certificate is not yet valid",
        ),
        Restriction::Expired => tr(es, "el certificado ha caducado", "certificate has expired"),
        Restriction::CertificateAuthority => tr(
            es,
            "no se permiten claves de autoridad certificadora",
            "CA keys are not permitted",
        ),
        Restriction::KeyUsage => tr(
            es,
            "el uso de clave no permite firmar documentos",
            "key usage prohibits document signing",
        ),
        Restriction::ExtendedKeyUsage => tr(
            es,
            "el uso extendido no permite firmar documentos",
            "extended key usage prohibits document signing",
        ),
        Restriction::UnhandledCriticalExtension => tr(
            es,
            "extensión crítica sin procesar",
            "unhandled critical extension",
        ),
        Restriction::PrivateKeyNotYetValid => tr(
            es,
            "el periodo de uso de la clave privada aún no ha comenzado",
            "private-key usage period has not begun",
        ),
        Restriction::PrivateKeyExpired => tr(
            es,
            "el periodo de uso de la clave privada ha terminado",
            "private-key usage period has ended",
        ),
    }
}
