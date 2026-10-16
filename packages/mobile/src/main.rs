use dioxus::prelude::*;

use ui::Navbar;
use views::{Diagnostics, Home};

mod views;

// Host tests also compile the JNI API boundary; Android runtime tests remain separate.
#[cfg(any(target_os = "android", test))]
mod android;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(MobileNavbar)]
    #[route("/")]
    Home {},
    #[route("/diagnostics")]
    Diagnostics {},
}

const MAIN_CSS: Asset = asset!("/assets/tailwind.css");

static INBOX: std::sync::OnceLock<firmica_core::Inbox> = std::sync::OnceLock::new();

fn main() {
    let config = dioxus::mobile::Config::new().with_custom_event_handler(|event, _| {
        // Tao emits this for iOS custom URLs; Android uses the activity/JNI adapter.
        if let dioxus::mobile::tao::event::Event::Opened { urls } = event {
            for url in urls {
                receive_invocation(url.as_str());
            }
        }
    });
    dioxus::LaunchBuilder::mobile().with_cfg(config).launch(App);
}

/// Share the parser/queue boundary between native URL events and Android JNI.
fn receive_invocation(uri: &str) -> bool {
    let Ok(request) = firmica_protocol::ProtocolRequest::parse(uri) else {
        return false;
    };
    INBOX
        .get_or_init(Default::default)
        .sender
        .try_send(firmica_core::IncomingReview {
            request,
            reply: None,
        })
        .is_ok()
}

#[component]
fn App() -> Element {
    use_context_provider(|| INBOX.get_or_init(Default::default).clone());
    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }

        Router::<Route> {}
    }
}

/// A mobile-specific Router around the shared `Navbar` component
/// which allows us to use the mobile-specific `Route` enum.
#[component]
fn MobileNavbar() -> Element {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_intake_parses_before_enqueueing_and_bounds_pending_delivery() {
        assert!(!receive_invocation("https://example.invalid/"));
        assert!(!receive_invocation("afirma://sign?dat=%00"));
        assert!(!receive_invocation(&format!(
            "afirma://sign?dat={}",
            "x".repeat(firmica_protocol::MAX_URI_BYTES)
        )));
        for _ in 0..8 {
            assert!(receive_invocation("afirma://sign?ver=4&format=CAdES"));
        }
        assert!(!receive_invocation("afirma://save?ver=4"));
        let inbox = INBOX.get().unwrap();
        for _ in 0..8 {
            let incoming = inbox.receiver.try_recv().unwrap();
            assert_eq!(
                incoming.request.operation,
                firmica_protocol::Operation::Sign
            );
            assert!(incoming.reply.is_none());
        }
        assert!(inbox.receiver.try_recv().is_err());
    }
}
