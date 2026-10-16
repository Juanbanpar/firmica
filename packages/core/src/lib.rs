//! Review state independent of Dioxus. This feasibility build cannot sign documents.

use firmica_protocol::ProtocolRequest;

/// Explicit review transitions survive window focus changes while the process lives.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReviewState {
    #[default]
    Idle,
    AwaitingConsent,
    Rejected,
    Unsupported,
    Expired,
}

/// One operation at a time. A new invocation cannot replace a pending review.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Review {
    request: Option<ProtocolRequest>,
    pub state: ReviewState,
}

impl Review {
    pub fn request(&self) -> Option<&ProtocolRequest> {
        self.request.as_ref()
    }

    /// Returns false when an operation is already awaiting a decision.
    pub fn receive(&mut self, request: ProtocolRequest) -> bool {
        if self.state == ReviewState::AwaitingConsent {
            return false;
        }
        self.request = Some(request);
        self.state = ReviewState::AwaitingConsent;
        true
    }

    /// Terminates the review and releases potentially sensitive request parameters.
    pub fn reject(&mut self) {
        if self.state == ReviewState::AwaitingConsent {
            self.state = ReviewState::Rejected;
            self.request = None;
        }
    }

    /// Acknowledges review, but never pretends a signing engine exists.
    pub fn acknowledge(&mut self) {
        if self.state == ReviewState::AwaitingConsent {
            self.state = ReviewState::Unsupported;
            self.request = None;
        }
    }

    /// Invalidates a pending request whose owner has stopped accepting decisions.
    /// Terminal user decisions are preserved; request parameters are released.
    pub fn expire(&mut self) {
        if self.state == ReviewState::AwaitingConsent {
            self.state = ReviewState::Expired;
            self.request = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_review_cannot_be_replaced_or_implicitly_approved() {
        let mut review = Review::default();
        assert!(review.receive(ProtocolRequest::parse("afirma://sign?dat=first").unwrap()));
        assert!(!review.receive(ProtocolRequest::parse("afirma://save?dat=second").unwrap()));
        assert_eq!(review.request().unwrap().parameter("dat"), Some("first"));
        review.reject();
        assert_eq!(review.state, ReviewState::Rejected);
        assert!(review.request().is_none());
        review.acknowledge();
        assert_eq!(review.state, ReviewState::Rejected);
        assert!(review.receive(ProtocolRequest::parse("afirma://sign?").unwrap()));
        review.acknowledge();
        assert_eq!(review.state, ReviewState::Unsupported);
        assert!(review.request().is_none());
    }

    #[test]
    fn expiry_releases_the_request_and_does_not_override_a_terminal_decision() {
        let mut review = Review::default();
        review.expire();
        assert_eq!(review.state, ReviewState::Idle);
        assert!(review.receive(ProtocolRequest::parse("afirma://sign?dat=private").unwrap()));
        review.expire();
        assert_eq!(review.state, ReviewState::Expired);
        assert!(review.request().is_none());
        review.reject();
        review.acknowledge();
        assert_eq!(review.state, ReviewState::Expired);

        assert!(review.receive(ProtocolRequest::parse("afirma://save?").unwrap()));
        review.reject();
        review.expire();
        assert_eq!(review.state, ReviewState::Rejected);
        assert!(review.receive(ProtocolRequest::parse("afirma://cosign?").unwrap()));
        review.acknowledge();
        review.expire();
        assert_eq!(review.state, ReviewState::Unsupported);
    }
}

/// A final response from the review-only UI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewOutcome {
    Rejected,
    Unsupported,
}

/// An external review and an optional response path. No origin is authenticated by a URI.
pub struct IncomingReview {
    pub request: ProtocolRequest,
    /// The receiver owns this request's lifetime. Closing it invalidates the review;
    /// `None` leaves the lifetime under local UI control.
    pub reply: Option<async_channel::Sender<ReviewOutcome>>,
}

/// Bounded UI handoff, usable without a Dioxus or Tokio runtime.
#[derive(Clone)]
pub struct Inbox {
    pub sender: async_channel::Sender<IncomingReview>,
    pub receiver: async_channel::Receiver<IncomingReview>,
}

impl Default for Inbox {
    fn default() -> Self {
        let (sender, receiver) = async_channel::bounded(8);
        Self { sender, receiver }
    }
}
