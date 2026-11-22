use super::{tr, BUTTON, FIELD};
use dioxus::prelude::*;
use firmica_signing::{
    format::{Appearance, ContentMode, Format, PdfOptions, XmlMode},
    SignatureAlgorithm,
};
use secrecy::SecretString;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct Inputs {
    pub(super) document: Signal<Option<PathBuf>>,
    pub(super) certificate: Signal<Option<PathBuf>>,
    pub(super) password: Signal<SecretString>,
    pub(super) password_generation: Signal<u64>,
    pub(super) algorithm: Signal<SignatureAlgorithm>,
    pub(super) format: Signal<Format>,
    #[cfg(windows)]
    pub(super) windows_certificates: Signal<super::windows::Picker>,
}

#[component]
pub(super) fn SigningForm(
    inputs: Inputs,
    spanish: bool,
    external: bool,
    busy: Signal<bool>,
    on_prepare: EventHandler<MouseEvent>,
) -> Element {
    let Inputs {
        document,
        certificate,
        mut password,
        password_generation,
        mut algorithm,
        mut format,
        #[cfg(windows)]
        windows_certificates,
    } = inputs;
    #[cfg(windows)]
    let use_pkcs12 = external || windows_certificates.read().store().is_none();
    #[cfg(not(windows))]
    let use_pkcs12 = true;
    #[cfg(windows)]
    let native_algorithm = if use_pkcs12 {
        None
    } else {
        windows_certificates.read().algorithm()
    };
    #[cfg(not(windows))]
    let native_algorithm: Option<SignatureAlgorithm> = None;
    #[cfg(windows)]
    let sources = {
        let mut generation = password_generation;
        rsx! {
            if !external {
                super::windows::CertificatePicker {
                    picker: windows_certificates, busy, spanish,
                    on_change_source: move |_| {
                        password.set(SecretString::default());
                        *generation.write() += 1;
                    }
                }
            }
        }
    };
    #[cfg(not(windows))]
    let sources = rsx! {};
    let certificate_ready = if use_pkcs12 {
        certificate.read().is_some()
    } else {
        native_algorithm.is_some()
    };
    rsx! {
        div { class: "space-y-5",
            if !external {
            label { class: "block", {tr(spanish, "Documento (hasta 16 MiB)", "Document (up to 16 MiB)")}
                FileSelection { id: "sign-document", selected: document, busy, certificate: false, spanish }
            }
            }
            {sources}
            if use_pkcs12 {
            label { class: "block", {tr(spanish, "Certificado PKCS#12 (hasta 8 MiB)", "PKCS#12 certificate (up to 8 MiB)")}
                FileSelection { id: "sign-certificate", selected: certificate, busy, certificate: true, spanish }
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
            }
            if !external {
            if use_pkcs12 {
            label { class: "block", {tr(spanish, "Algoritmo", "Algorithm")}
                select { id: "sign-algorithm", class: FIELD, disabled: busy(), value: if algorithm() == SignatureAlgorithm::RsaPkcs1v15Sha256 { "rsa" } else { "ec" },
                    onchange: move |event| algorithm.set(if event.value() == "ec" { SignatureAlgorithm::EcdsaP256Sha256 } else { SignatureAlgorithm::RsaPkcs1v15Sha256 }),
                    option { value: "rsa", "RSA PKCS#1 v1.5 / SHA-256" }
                    option { value: "ec", "ECDSA P-256 / SHA-256" }
                }
            }
            } else if let Some(algorithm) = native_algorithm {
                p { {tr(spanish, "Algoritmo de firma", "Signing algorithm")} " · " {super::review::algorithm_name(algorithm)} }
            }
            label { class: "block", {tr(spanish, "Formato", "Format")}
                select { id: "sign-format", class: FIELD, disabled: busy(), value: format_value(&format()),
                    onchange: move |event| format.set(match event.value().as_str() {
                        "pades" => Format::Pades(PdfOptions::default()),
                        "enveloped" => Format::Xades(XmlMode::Enveloped),
                        "enveloping" => Format::Xades(XmlMode::Enveloping),
                        "detached" => Format::Xades(XmlMode::Detached),
                        _ => Format::Cades(ContentMode::Detached),
                    }),
                    option { value: "cades", "CAdES" }
                    option { value: "pades", "PAdES" }
                    option { value: "enveloped", "XAdES (enveloped)" }
                    option { value: "enveloping", "XAdES (enveloping)" }
                    option { value: "detached", "XAdES (internally detached)" }
                }
            }
            if let Format::Cades(mode) = format() {
                label { class: "flex items-center gap-3",
                    input { id: "sign-attached", r#type: "checkbox", checked: mode == ContentMode::Attached, disabled: busy(),
                        onchange: move |event| format.set(Format::Cades(if event.checked() {ContentMode::Attached} else {ContentMode::Detached})) }
                    {tr(spanish, "Incluir el documento en la firma", "Embed the document in the signature")}
                }
            }
            if let Format::Pades(options) = format() {
                label { class: "flex items-center gap-3",
                    input { id: "sign-visible", r#type: "checkbox", checked: options.appearance.is_some(), disabled: busy(),
                        onchange: move |event| format.set(Format::Pades(PdfOptions{appearance:event.checked().then(||Appearance{page:1,rectangle:[40.,30.,400.,70.],text:tr(spanish, "Firmado con Firmica", "Signed with Firmica").into()})})) }
                    {tr(spanish, "Firma visible", "Visible signature")}
                }
                if let Some(appearance) = options.appearance.clone() {
                    fieldset { class: "space-y-3 rounded border p-4", disabled: busy(),
                    legend { class: "px-2", {tr(spanish, "Posición de la firma", "Signature placement")} }
                    label { class: "block", {tr(spanish, "Texto (ASCII)", "Text (ASCII)")}
                        input { id: "sign-visible-text", class: FIELD, value: appearance.text, maxlength: "120",
                            oninput: move |event| { if let Format::Pades(options)=&mut *format.write() {if let Some(a)=&mut options.appearance {a.text=event.value();}} } }
                    }
                    label { class: "block", {tr(spanish, "Número de página (desde 1)", "Page number (starting at 1)")}
                        input { id: "sign-visible-page", class: FIELD, r#type: "number", min: "1", value: appearance.page,
                            oninput: move |event| { if let Format::Pades(options)=&mut *format.write() {if let Some(a)=&mut options.appearance {a.page=event.value().parse().unwrap_or(0);}} } }
                    }
                    p { class: "text-sm", {tr(spanish, "Indica las dos esquinas del rectángulo en puntos PDF (72 puntos por pulgada).", "Enter both corners of the rectangle in PDF points (72 points per inch).")} }
                    div { class: "grid gap-3 sm:grid-cols-2",
                        for (index, label) in [
                            tr(spanish, "Izquierda (X)", "Left (X)"),
                            tr(spanish, "Abajo (Y)", "Bottom (Y)"),
                            tr(spanish, "Derecha (X)", "Right (X)"),
                            tr(spanish, "Arriba (Y)", "Top (Y)"),
                        ].into_iter().enumerate() {
                            label { class: "block", "{label}"
                                input { class: FIELD, r#type: "number", step: "any",
                                    value: if appearance.rectangle[index].is_finite() { appearance.rectangle[index].to_string() } else { String::new() },
                                    oninput: move |event| { if let Format::Pades(options)=&mut *format.write() {if let Some(a)=&mut options.appearance {a.rectangle[index]=event.value().parse().unwrap_or(f32::NAN);}} } }
                            }
                        }
                    }
                    }
                }
            }
            }
            button { id: "sign-prepare", class: BUTTON, disabled: busy() || (!external && document.read().is_none()) || !certificate_ready,
                onclick: move |event| on_prepare.call(event), {tr(spanish, "Abrir y revisar", "Open and review")}
            }
        }
    }
}

fn format_value(format: &Format) -> &'static str {
    match format {
        Format::Cades(_) => "cades",
        Format::Pades(_) => "pades",
        Format::Xades(XmlMode::Enveloped) => "enveloped",
        Format::Xades(XmlMode::Enveloping) => "enveloping",
        Format::Xades(XmlMode::Detached) => "detached",
    }
}

pub(super) fn file_dialog() -> rfd::AsyncFileDialog {
    let dialog = rfd::AsyncFileDialog::new();
    #[cfg(any(windows, target_os = "macos"))]
    let dialog = dialog.set_parent(dioxus::desktop::window().window.as_ref());
    dialog
}

#[component]
fn FileSelection(
    id: &'static str,
    mut selected: Signal<Option<PathBuf>>,
    mut busy: Signal<bool>,
    certificate: bool,
    spanish: bool,
) -> Element {
    let name = selected
        .read()
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned());
    // Linux's WebView picker retains its portal/zenity fallback. Other desktops use
    // the same rfd dependency as saving, with a native parented item dialog.
    #[cfg(target_os = "linux")]
    {
        rsx! { input { id, class: "peer sr-only", r#type: "file",
            accept: if certificate { ".p12,.pfx" } else { "" }, disabled: busy(),
            onchange: move |event| {
                if let Some(file) = event.files().into_iter().next() {
                    selected.set(Some(file.path()));
                }
            },
        }
        span { id: "{id}-selected",
            class: "mt-2 block w-full cursor-pointer break-all rounded border px-3 py-2 peer-disabled:cursor-default peer-disabled:opacity-50 peer-focus-visible:outline-2 peer-focus-visible:outline-offset-4",
            if let Some(name) = name { "{name}" }
            else { {tr(spanish, "Seleccionar archivo…", "Choose file…")} }
        } }
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        rsx! {
            button { id, class: FIELD, r#type: "button", disabled: busy(),
                onclick: move |_| {
                    if busy() { return; }
                    busy.set(true);
                    let mut dialog = file_dialog();
                    if certificate { dialog = dialog.add_filter("PKCS#12", &["p12", "pfx"]); }
                    spawn(async move {
                        if let Some(file) = dialog.pick_file().await {
                            selected.set(Some(file.path().to_owned()));
                        }
                        busy.set(false);
                    });
                },
                if let Some(name) = name { "{name}" }
                else { {tr(spanish, "Seleccionar archivo…", "Choose file…")} }
            }
        }
    }
}
