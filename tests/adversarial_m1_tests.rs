//! Adversarial checks for the standard-AppView transport boundary.

use catbird_mls::orchestrator::{
    prepare_clean_chat_request, CanonicalOperation, CleanChatAuthContextFfi, CleanChatOperationFfi,
};
use serde_json::json;

const DEVICE: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_DEVICE: &str = "22222222-2222-4222-8222-222222222222";

fn auth() -> CleanChatAuthContextFfi {
    CleanChatAuthContextFfi {
        device_id: DEVICE.into(),
        auth_generation: Some(7),
    }
}

#[test]
fn prepared_query_contains_no_account_credentials() {
    let request = prepare_clean_chat_request(
        auth(),
        CleanChatOperationFfi::GetOwnDevices,
        serde_json::to_vec(&json!({"actorDeviceId": DEVICE})).unwrap(),
    )
    .expect("prepare query");

    assert_eq!(request.method, "GET");
    assert!(request.body.is_none());
    let debug = format!("{request:?}");
    assert!(!debug.contains("authorization"));
    assert!(!debug.contains("dpop"));
}

#[test]
fn authenticated_query_cannot_widen_device_authority() {
    let result = prepare_clean_chat_request(
        auth(),
        CleanChatOperationFfi::GetOwnDevices,
        serde_json::to_vec(&json!({"actorDeviceId": OTHER_DEVICE})).unwrap(),
    );
    assert!(result.is_err());
}

#[test]
fn public_operation_inventory_has_no_rebind_route() {
    assert!(!CanonicalOperation::ALL
        .iter()
        .any(|operation| format!("{operation:?}").contains("Rebind")));
}

#[test]
fn malformed_json_fails_closed_before_preparation() {
    let result = prepare_clean_chat_request(
        auth(),
        CleanChatOperationFfi::GetOwnDevices,
        b"{ not valid json".to_vec(),
    );
    assert!(result.is_err());
}

#[test]
fn uppercase_device_uuid_is_rejected() {
    let uppercase_auth = CleanChatAuthContextFfi {
        device_id: "11111111-1111-4111-8111-11111111111A".into(),
        auth_generation: Some(1),
    };
    let result = prepare_clean_chat_request(
        uppercase_auth,
        CleanChatOperationFfi::GetOwnDevices,
        serde_json::to_vec(&json!({"actorDeviceId": "11111111-1111-4111-8111-11111111111A"})).unwrap(),
    );
    assert!(result.is_err());
}

#[test]
fn non_hyphenated_device_uuid_is_rejected() {
    let non_hyphenated_auth = CleanChatAuthContextFfi {
        device_id: "11111111111141118111111111111111".into(),
        auth_generation: Some(1),
    };
    let result = prepare_clean_chat_request(
        non_hyphenated_auth,
        CleanChatOperationFfi::GetOwnDevices,
        serde_json::to_vec(&json!({"actorDeviceId": "11111111111141118111111111111111"})).unwrap(),
    );
    assert!(result.is_err());
}

#[test]
fn empty_device_id_fails_closed() {
    let empty_auth = CleanChatAuthContextFfi {
        device_id: String::new(),
        auth_generation: Some(1),
    };
    let result = prepare_clean_chat_request(
        empty_auth,
        CleanChatOperationFfi::GetOwnDevices,
        serde_json::to_vec(&json!({"actorDeviceId": ""})).unwrap(),
    );
    assert!(result.is_err());
}

#[test]
fn zero_generation_for_read_without_generation_is_accepted() {
    let read_auth = CleanChatAuthContextFfi {
        device_id: DEVICE.into(),
        auth_generation: None,
    };
    let result = prepare_clean_chat_request(
        read_auth,
        CleanChatOperationFfi::GetOwnDevices,
        serde_json::to_vec(&json!({"actorDeviceId": DEVICE})).unwrap(),
    );
    assert!(result.is_ok());
}
