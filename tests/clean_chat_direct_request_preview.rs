use catbird_mls::orchestrator::direct_requests::{
    reduce_request_preview, RequestPreviewFailure, RequestPreviewUpdate,
};
use catbird_mls::{
    DirectRequestView, RequestCapabilities, RequestConsent, RequestCrypto, RequestPreview,
};

fn pending(consent: RequestConsent) -> DirectRequestView {
    DirectRequestView {
        conversation_id: "11111111-1111-4111-8111-111111111111".into(),
        first_message_id: Some("22222222-2222-4222-8222-222222222222".into()),
        consent,
        crypto: RequestCrypto::WelcomeAvailable,
        preview: None,
        capabilities: RequestCapabilities::derive(consent, RequestCrypto::WelcomeAvailable, false),
        state_version: 1,
        generation: 0,
    }
}

#[test]
fn pending_intro_decryption_never_authorizes_ordinary_effects_in_either_direction() {
    for consent in [
        RequestConsent::IncomingPending,
        RequestConsent::OutgoingPending,
    ] {
        let view = reduce_request_preview(
            &pending(consent),
            RequestPreviewUpdate::Decrypted {
                text: "Hello".into(),
            },
        );
        assert_eq!(view.consent, consent);
        assert_eq!(view.crypto, RequestCrypto::Ready);
        assert!(view.capabilities.can_preview);
        assert!(!view.capabilities.can_send);
        assert!(!view.capabilities.can_emit_receipts);
        assert!(!view.capabilities.can_administer);
        assert_eq!(
            view.capabilities.can_accept,
            consent == RequestConsent::IncomingPending
        );
    }
}

#[test]
fn malformed_intro_preserves_imported_welcome_and_consent() {
    let imported = reduce_request_preview(
        &pending(RequestConsent::IncomingPending),
        RequestPreviewUpdate::Imported,
    );
    let failed = reduce_request_preview(
        &imported,
        RequestPreviewUpdate::Unavailable {
            code: RequestPreviewFailure::InvalidIntroduction,
        },
    );
    assert_eq!(failed.crypto, RequestCrypto::Ready);
    assert_eq!(failed.consent, RequestConsent::IncomingPending);
    assert_eq!(
        failed.preview,
        Some(RequestPreview::Unavailable {
            code: "InvalidIntroduction".into()
        })
    );
    assert!(!failed.capabilities.can_send);
}

#[test]
fn expired_delivery_cannot_erase_a_decrypted_preview() {
    let ready = reduce_request_preview(
        &pending(RequestConsent::IncomingPending),
        RequestPreviewUpdate::Decrypted {
            text: "Retained".into(),
        },
    );
    let expired = reduce_request_preview(
        &ready,
        RequestPreviewUpdate::Unavailable {
            code: RequestPreviewFailure::ImportExpired,
        },
    );
    assert_eq!(expired, ready);
}

#[test]
fn account_acceptance_does_not_invent_device_readiness() {
    for crypto in [
        RequestCrypto::WelcomeAvailable,
        RequestCrypto::Importing,
        RequestCrypto::Unavailable,
    ] {
        let caps = RequestCapabilities::derive(RequestConsent::Accepted, crypto, false);
        assert!(!caps.can_send);
        assert!(!caps.can_emit_receipts);
        assert!(!caps.can_administer);
    }
    let ready = RequestCapabilities::derive(RequestConsent::Accepted, RequestCrypto::Ready, false);
    assert!(ready.can_send && ready.can_emit_receipts && ready.can_administer);
}
