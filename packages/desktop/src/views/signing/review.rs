use super::{tr, BUTTON};
use dioxus::prelude::*;
use firmica_core::signing::SigningReview;
use firmica_signing::{
    format::{Format, XmlMode},
    SignatureAlgorithm,
};

#[derive(Clone, PartialEq)]
pub(super) struct Details {
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
    format: Format,
}

impl Details {
    pub(super) fn from_review(review: &SigningReview) -> Self {
        let certificate = review.certificate();
        Self {
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
            format: review.format().clone(),
        }
    }
}

#[component]
pub(super) fn Review(
    details: Details,
    spanish: bool,
    external: bool,
    busy: bool,
    mut acknowledged: Signal<bool>,
    on_sign: EventHandler<MouseEvent>,
    on_cancel: EventHandler<MouseEvent>,
) -> Element {
    let Details {
        name,
        size,
        hash,
        subject,
        issuer,
        serial,
        fingerprint,
        start,
        end,
        chosen_algorithm,
        format,
    } = details;
    rsx! {
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
                dt { {tr(spanish, "Formato", "Format")} } dd { id: "sign-review-format", "{format.label()}" }
                if let Format::Pades(options) = &format {
                    dt { {tr(spanish, "Apariencia", "Appearance")} }
                    dd { id: "sign-review-appearance",
                        if let Some(appearance) = &options.appearance {
                            "{appearance.text} — {appearance.page}: {appearance.rectangle:?}"
                        } else { {tr(spanish, "Invisible", "Invisible")} }
                    }
                }
            }
            if format == Format::Xades(XmlMode::Enveloped) {
                p { class: "mt-4 text-sm", {tr(spanish, "Se firma el XML canónico; los comentarios no quedan firmados.", "The signature covers canonical XML; comments are not signed.")} }
            }
            p { class: "my-6", id: "sign-unchecked", role: "alert",
                {tr(spanish,
                    "Las restricciones locales permiten firmar. No se han comprobado la firma del certificado, la cadena de confianza, la revocación ni la cualificación legal. Los nombres anteriores son declaraciones del certificado sin autenticar.",
                    "Local constraints permit signing. The certificate signature, trust chain, revocation and legal qualification have not been checked. The names above are unauthenticated certificate claims.")}
            }
            label { class: "mb-6 flex items-start gap-3",
                input { id: "sign-acknowledge", r#type: "checkbox", checked: acknowledged(), disabled: busy,
                    onchange: move |event| acknowledged.set(event.checked()),
                }
                {tr(spanish, "Autorizo la firma de este documento con este certificado y acepto las comprobaciones pendientes indicadas.", "I authorize signing this document with this certificate and accept the unchecked items shown above.")}
            }
            div { class: "flex flex-wrap gap-3",
                button { id: "sign-save", class: BUTTON, disabled: busy || !acknowledged(),
                    onclick: move |event| on_sign.call(event), if external { {tr(spanish, "Firmar y enviar al navegador", "Sign and send to browser")} }
                    else { {tr(spanish, "Firmar y guardar…", "Sign and save…")} }
                }
                button { id: "sign-cancel", class: BUTTON, disabled: busy, onclick: move |event| on_cancel.call(event), {tr(spanish, "Cancelar", "Cancel")} }
            }
            if !external {
                p { class: "mt-4 text-sm", {tr(spanish, "Elige un nombre nuevo: no se reemplazan archivos existentes.", "Choose a new filename: existing files are not replaced.")} }
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
pub(super) fn algorithm_name(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => "RSA PKCS#1 v1.5 / SHA-256",
        SignatureAlgorithm::EcdsaP256Sha256 => "ECDSA P-256 / SHA-256",
    }
}
