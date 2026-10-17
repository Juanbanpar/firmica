mod home;
pub use home::Home;
#[cfg(target_os = "linux")]
mod signing;
#[cfg(target_os = "linux")]
pub use signing::LocalSigning;

#[cfg(not(target_os = "linux"))]
#[component]
pub fn LocalSigning() -> Element {
    rsx! { main { class: "mx-auto max-w-3xl p-6 sm:p-12",
        h1 { class: "mb-4 text-3xl font-semibold", "Sign a document / Firmar un documento" }
        p { "Local signing is unavailable on this platform. / La firma local no está disponible en esta plataforma." }
    } }
}

#[component]
pub fn Diagnostics() -> dioxus::prelude::Element {
    dioxus::prelude::rsx! { ui::Diagnostics {} }
}

use dioxus::prelude::*;
