mod home;
pub use home::Home;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod signing;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use signing::LocalSigning;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
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
