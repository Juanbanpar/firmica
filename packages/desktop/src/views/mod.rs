mod home;
pub use home::Home;

#[component]
pub fn Diagnostics() -> dioxus::prelude::Element {
    dioxus::prelude::rsx! { ui::Diagnostics {} }
}

use dioxus::prelude::*;
