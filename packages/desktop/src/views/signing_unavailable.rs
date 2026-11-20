use dioxus::prelude::*;

#[component]
pub fn LocalSigning() -> Element {
    rsx! { main { class: "mx-auto max-w-3xl p-6 sm:p-12",
        h1 { class: "mb-4 text-3xl font-semibold", "Sign a document / Firmar un documento" }
        p { "Local signing is unavailable on this platform. / La firma local no está disponible en esta plataforma." }
    } }
}
