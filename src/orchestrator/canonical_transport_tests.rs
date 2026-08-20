use super::canonical_transport::{
    prepare_get_conversations, prepare_get_entries, route_for_nsid, CanonicalOperation,
    CleanChatAuthContext, TransportError,
};
use crate::chat_v2::endpoint_error::{ChatErrorCode, EndpointError, RecoveryOutcome};

const DEVICE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

#[test]
fn route_inventory_is_closed_and_contains_no_rebind_endpoint() {
    assert_eq!(CanonicalOperation::ALL.len(), 31);

    for operation in CanonicalOperation::ALL {
        let route = operation.route();
        assert!(route.path.starts_with("/xrpc/blue.catbird.chat."));
        assert_eq!(route_for_nsid(route.nsid), Some(route));
        assert!(!route.nsid.contains("rebindDeviceAuthentication"));
    }

    assert!(route_for_nsid("blue.catbird.chat.rebindDeviceAuthentication").is_none());
    assert!(route_for_nsid("blue.catbird.mlsChat.sendMessage").is_none());
}

#[test]
fn prepared_reads_bind_the_actor_device_in_the_query() {
    let auth = CleanChatAuthContext::new(DEVICE_ID.to_owned());

    let conversations =
        prepare_get_conversations(&auth, 25, Some("next cursor")).expect("valid request");
    assert_eq!(conversations.method, "GET");
    assert!(conversations
        .path
        .contains("actorDeviceId=123e4567-e89b-42d3-a456-426614174000"));
    assert!(conversations.path.contains("pageCursor=next%20cursor"));
    assert!(conversations.body.is_none());

    let entries = prepare_get_entries(&auth, "123e4567-e89b-42d3-a456-426614174001", 7, 50)
        .expect("valid request");
    assert_eq!(entries.method, "GET");
    assert!(entries
        .path
        .contains("actorDeviceId=123e4567-e89b-42d3-a456-426614174000"));
    assert!(entries.path.contains("afterSeq=7"));
}

#[test]
fn invalid_device_identity_fails_before_transport() {
    let missing = CleanChatAuthContext::new(String::new());
    assert_eq!(
        prepare_get_conversations(&missing, 1, None),
        Err(TransportError::MissingDeviceBinding)
    );

    let noncanonical = CleanChatAuthContext::new("123E4567-E89B-42D3-A456-426614174000".into());
    assert!(prepare_get_conversations(&noncanonical, 1, None).is_err());
}

#[test]
fn recovery_outcomes_do_not_turn_device_loss_into_account_logout() {
    let missing = EndpointError::new(
        "blue.catbird.chat.getOwnDevices",
        ChatErrorCode::DeviceNotRegistered,
        None,
    );
    assert!(!missing.requires_reauthentication());
    assert!(missing.requires_device_recovery());
    assert_eq!(
        missing.recovery_outcome(),
        Some(RecoveryOutcome::NeedsEnrollment)
    );

    let expired = EndpointError::new(
        "blue.catbird.chat.getOwnDevices",
        ChatErrorCode::AccountSessionExpired,
        None,
    );
    assert!(expired.requires_reauthentication());
    assert!(!expired.requires_device_recovery());
    assert_eq!(
        expired.recovery_outcome(),
        Some(RecoveryOutcome::AccountSessionExpired)
    );
}

#[test]
fn upgrade_and_binding_failures_are_typed() {
    for (code, expected) in [
        (
            ChatErrorCode::ProtocolUpgradeRequired,
            RecoveryOutcome::ProtocolUpgradeRequired,
        ),
        (
            ChatErrorCode::DeviceBindingMismatch,
            RecoveryOutcome::DeviceBindingMismatch,
        ),
        (ChatErrorCode::DeviceRevoked, RecoveryOutcome::DeviceRevoked),
    ] {
        let error = EndpointError::new("blue.catbird.chat.test", code, None);
        assert_eq!(error.recovery_outcome(), Some(expected));
    }
}
