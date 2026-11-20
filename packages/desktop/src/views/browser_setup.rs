use crate::local_tls::{self, ProfileStatus};
use dioxus::prelude::*;

enum Change {
    Refresh,
    Initialize(String),
    Add(String),
    Remove(String),
}

impl Change {
    fn apply(self) -> Result<Option<ProfileStatus>, local_tls::Error> {
        match self {
            Self::Refresh => local_tls::default_status(),
            Self::Initialize(origin) => local_tls::initialize_default(&origin).map(Some),
            Self::Add(origin) => local_tls::update_default_origin(origin, true).map(Some),
            Self::Remove(origin) => local_tls::update_default_origin(origin, false).map(Some),
        }
    }
}

const BUTTON: &str =
    "rounded border px-3 py-2 disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-4";

#[component]
pub fn BrowserSetup() -> Element {
    let mut spanish = use_signal(|| true);
    let mut profile = use_signal(|| None::<ProfileStatus>);
    let mut loaded = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut origin = use_signal(String::new);
    let mut error = use_signal(|| None::<local_tls::Error>);
    let mut apply = move |change: Change| {
        if busy() {
            return;
        }
        busy.set(true);
        let refresh = matches!(change, Change::Refresh);
        let clear_origin = matches!(change, Change::Initialize(_) | Change::Add(_));
        spawn(async move {
            let result = tokio::task::spawn_blocking(move || change.apply())
                .await
                .unwrap_or_else(|_| Err(std::io::Error::other("profile task interrupted").into()));
            match result {
                Ok(snapshot) => {
                    error.set(None);
                    profile.set(snapshot);
                    loaded.set(true);
                    if clear_origin {
                        origin.set(String::new());
                    }
                }
                Err(failure) => {
                    if refresh {
                        loaded.set(false);
                        profile.set(None);
                    }
                    error.set(Some(failure));
                }
            }
            busy.set(false);
        });
    };
    use_future(move || async move { apply(Change::Refresh) });

    let es = spanish();
    let t = |es_text, en_text| if es { es_text } else { en_text };
    let profile = profile.read();
    let has_profile = profile.is_some();
    rsx! {
        main { class: "mx-auto max-w-3xl space-y-6 p-6 sm:p-12", lang: if es { "es" } else { "en" },
            header { class: "flex flex-wrap items-center justify-between gap-4",
                h1 { class: "text-3xl font-semibold tracking-tight", {t("Configurar el navegador", "Browser setup")} }
                button { class: BUTTON, onclick: move |_| spanish.toggle(), if es { "English" } else { "Español" } }
            }
            div { class: "flex flex-wrap items-center gap-3",
                p { id: "browser-tls-status", role: "status",
                    if busy() { {t("Comprobando el perfil TLS…", "Checking the TLS profile…")} }
                    else if has_profile { {t("Perfil TLS local listo", "Local TLS profile ready")} }
                    else if loaded() { {t("Aún no hay un perfil TLS local", "No local TLS profile yet")} }
                    else { {t("Perfil TLS local no disponible", "Local TLS profile unavailable")} }
                }
                button { id: "browser-tls-refresh", class: BUTTON, disabled: busy(),
                    onclick: move |_| apply(Change::Refresh),
                    {t("Actualizar", "Refresh")}
                }
            }
            if let Some(error) = error.read().as_ref() {
                p { id: "browser-tls-error", class: "rounded border border-red-600 p-3", role: "alert", {error_text(error, es)} }
            }
            if let Some(status) = profile.as_ref() {
                section { class: "space-y-3",
                    h2 { class: "text-xl font-semibold", {t("Confianza del navegador", "Browser trust")} }
                    p { {t("Comprueba la huella e importa el certificado de confianza en el perfil del navegador que vas a usar.", "Verify the fingerprint and import the trust certificate into the browser profile you will use.")} }
                    dl { class: "grid gap-2 break-all sm:grid-cols-[10rem_1fr]",
                        dt { {t("Certificado de confianza", "Trust certificate")} }
                        dd { id: "browser-tls-ca", class: "font-mono", "{status.trust_certificate.display()}" }
                        dt { {t("Huella SHA-256", "SHA-256 fingerprint")} }
                        dd { id: "browser-tls-fingerprint", class: "font-mono", "{status.fingerprint}" }
                        dt { {t("Caduca", "Expires")} }
                        dd { id: "browser-tls-expires", "{status.expires}" }
                    }
                }
                section { class: "space-y-3",
                    h2 { class: "text-xl font-semibold", {t("Orígenes autorizados", "Authorized origins")} }
                    if status.origins.is_empty() {
                        p { {t("Autoriza un origen para habilitar nuevas sesiones.", "Authorize an origin to enable new sessions.")} }
                    }
                    ul { id: "browser-tls-origins", class: "divide-y",
                        for website in status.origins.iter().cloned() {
                            li { key: "{website}", class: "flex flex-wrap items-center justify-between gap-2 py-2",
                                span { class: "break-all font-mono", "{website}" }
                                button { class: BUTTON, disabled: busy(),
                                    aria_label: format!("{} {website}", t("Revocar", "Revoke")),
                                    onclick: move |_| apply(Change::Remove(website.clone())),
                                    {t("Revocar", "Revoke")}
                                }
                            }
                        }
                    }
                    p { class: "text-sm", {t("Los cambios se aplican al iniciar el siguiente servicio del navegador.", "Changes apply when the next browser listener starts.")} }
                }
            }
            if loaded() {
                form { class: "space-y-3",
                    onsubmit: move |event| {
                        event.prevent_default();
                        if origin.read().is_empty() { return; }
                        let value = origin.read().clone();
                        apply(if has_profile { Change::Add(value) } else { Change::Initialize(value) });
                    },
                    label { class: "block", r#for: "browser-tls-origin", {t("Origen del sitio web", "Website origin")} }
                    input { id: "browser-tls-origin", class: "block w-full rounded border bg-transparent px-3 py-2",
                        value: "{origin}", placeholder: "https://example.org", maxlength: "2048", disabled: busy(), required: true,
                        aria_describedby: "browser-tls-origin-help", autocomplete: "off", spellcheck: "false",
                        oninput: move |event| origin.set(event.value()),
                    }
                    p { id: "browser-tls-origin-help", class: "text-sm",
                        {t("Introduce el origen HTTP(S) exacto, con el puerto si corresponde.", "Enter the exact HTTP(S) origin, including the port if needed.") }
                    }
                    button { id: "browser-tls-apply", r#type: "submit", class: BUTTON, disabled: busy() || origin.read().is_empty(),
                        if has_profile { {t("Autorizar origen", "Authorize origin")} }
                        else { {t("Crear perfil y autorizar origen", "Create profile and authorize origin")} }
                    }
                }
            }
        }
    }
}

fn error_text(error: &local_tls::Error, es: bool) -> &'static str {
    use local_tls::Error;

    let (spanish, english) = match error {
        Error::Origin => (
            "Comprueba el origen. Usa el esquema, dominio y puerto exactos, sin ruta ni comodines.",
            "Check the origin. Use the exact scheme, domain and port, without paths or wildcards.",
        ),
        Error::OriginLimit => ("La lista de orígenes está llena.", "The origin list is full."),
        Error::Permissions => (
            "Comprueba los permisos y la ubicación privada del perfil TLS.",
            "Check the permissions and private location of the TLS profile.",
        ),
        Error::Invalid => (
            "La identidad TLS es inválida o ha caducado. Renueva el perfil y actualiza la confianza del navegador.",
            "The TLS identity is invalid or expired. Renew the profile and update browser trust.",
        ),
        Error::Exists | Error::Missing => (
            "El perfil TLS ha cambiado. Actualiza su estado.",
            "The TLS profile changed. Refresh its status.",
        ),
        _ => (
            "No se pudo acceder al perfil TLS. Comprueba el directorio de configuración y vuelve a intentarlo.",
            "Could not access the TLS profile. Check the configuration directory and try again.",
        ),
    };
    if es {
        spanish
    } else {
        english
    }
}
