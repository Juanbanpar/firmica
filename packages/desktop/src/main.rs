use dioxus::prelude::*;

use ui::Navbar;
use views::{Diagnostics, Home};

mod invocation;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod local_tls;
#[cfg(target_os = "macos")]
mod private_fs;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod signing;
mod views;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(DesktopNavbar)]
    #[route("/")]
    Home {},
    #[route("/sign")]
    LocalSigning {},
    #[route("/diagnostics")]
    Diagnostics {},
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[route("/browser")]
    BrowserSetup {},
}

const MAIN_CSS: Asset = asset!("/assets/tailwind.css");

fn main() {
    if let Err(error) = invocation::launch(App) {
        eprintln!("Firmica: {error}");
        std::process::exit(1);
    }
}

#[component]
fn App() -> Element {
    use_context_provider(invocation::inbox);
    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }

        Router::<Route> {}
    }
}

/// A desktop-specific Router around the shared `Navbar` component
/// which allows us to use the desktop-specific `Route` enum.
#[component]
fn DesktopNavbar() -> Element {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    let browser_setup = rsx! { Link { to: Route::BrowserSetup {}, "Browser setup" } };
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let browser_setup = VNode::empty();
    rsx! {
        Navbar {
            Link {
                to: Route::Home {},
                "Home"
            }
            Link {
                to: Route::LocalSigning {},
                "Sign a document"
            }
            Link {
                to: Route::Diagnostics {},
                "Diagnostics"
            }
            {browser_setup}
        }

        Outlet::<Route> {}
    }
}

#[component]
fn LocalSigning() -> Element {
    rsx! { views::LocalSigning {} }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[component]
fn BrowserSetup() -> Element {
    rsx! { views::BrowserSetup {} }
}
