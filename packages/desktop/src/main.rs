use dioxus::prelude::*;

use ui::Navbar;
use views::{Diagnostics, Home};

mod invocation;
mod views;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(DesktopNavbar)]
    #[route("/")]
    Home {},
    #[route("/diagnostics")]
    Diagnostics {},
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
    rsx! {
        Navbar {
            Link {
                to: Route::Home {},
                "Home"
            }
            Link {
                to: Route::Diagnostics {},
                "Diagnostics"
            }
        }

        Outlet::<Route> {}
    }
}
