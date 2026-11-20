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
    } = inputs;
    rsx! {
        div { class: "space-y-5",
            if !external {
            label { class: "block", {tr(spanish, "Documento (hasta 16 MiB)", "Document (up to 16 MiB)")}
                FileSelection { id: "sign-document", selected: document, busy, certificate: false, spanish }
            }
            }
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
            if !external {
            label { class: "block", {tr(spanish, "Algoritmo", "Algorithm")}
                select { id: "sign-algorithm", class: FIELD, disabled: busy(), value: if algorithm() == SignatureAlgorithm::RsaPkcs1v15Sha256 { "rsa" } else { "ec" },
                    onchange: move |event| algorithm.set(if event.value() == "ec" { SignatureAlgorithm::EcdsaP256Sha256 } else { SignatureAlgorithm::RsaPkcs1v15Sha256 }),
                    option { value: "rsa", "RSA PKCS#1 v1.5 / SHA-256" }
                    option { value: "ec", "ECDSA P-256 / SHA-256" }
                }
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
                        onchange: move |event| format.set(Format::Pades(PdfOptions{appearance:event.checked().then(||Appearance{page:1,rectangle:[40.,30.,400.,70.],text:"Signed with Firmica".into()})})) }
                    {tr(spanish, "Firma visible", "Visible signature")}
                }
                if let Some(appearance) = options.appearance.clone() {
                    label { class: "block", {tr(spanish, "Texto (ASCII)", "Text (ASCII)")}
                        input { class: FIELD, value: appearance.text, maxlength: "120", disabled: busy(),
                            oninput: move |event| { if let Format::Pades(options)=&mut *format.write() {if let Some(a)=&mut options.appearance {a.text=event.value();}} } }
                    }
                    label { class: "block", {tr(spanish, "Página", "Page")}
                        input { class: FIELD, r#type: "number", min: "1", value: appearance.page, disabled: busy(),
                            oninput: move |event| { if let Format::Pades(options)=&mut *format.write() {if let Some(a)=&mut options.appearance {a.page=event.value().parse().unwrap_or(0);}} } }
                    }
                    for (index, label) in ["x1", "y1", "x2", "y2"].into_iter().enumerate() {
                        label { class: "block", "{label} (pt)"
                            input { class: FIELD, r#type: "number", step: "any", value: appearance.rectangle[index], disabled: busy(),
                                oninput: move |event| { if let Format::Pades(options)=&mut *format.write() {if let Some(a)=&mut options.appearance {a.rectangle[index]=event.value().parse().unwrap_or(f32::NAN);}} } }
                        }
                    }
                }
            }
            }
            button { id: "sign-prepare", class: BUTTON, disabled: busy() || (!external && document.read().is_none()) || certificate.read().is_none(),
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
    // Linux's WebView picker retains its portal/zenity fallback. Other desktops use
    // the same rfd dependency as saving, with a native parented item dialog.
    #[cfg(target_os = "linux")]
    {
        let _ = spanish;
        rsx! { input { id, class: FIELD, r#type: "file",
            accept: if certificate { ".p12,.pfx" } else { "" }, disabled: busy(),
            onchange: move |event| selected.set(event.files().into_iter().next().map(|file| file.path())),
        } }
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        let name = selected
            .read()
            .as_ref()
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned());
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
