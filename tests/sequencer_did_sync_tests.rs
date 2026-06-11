//! WS-4 rung 2 — `convoView.sequencerDid` exposure tests (ADR-010 D4).
//!
//! Verifies the orchestrator parses, persists (via the optional
//! `set_conversation_sequencer` storage method), and logs the
//! per-conversation sequencer DID — with NO routing behavior change
//! (routing on `sequencerDid` is WS-4 rung 3).

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::storage::OPTIONAL_STORAGE_METHODS;
use catbird_mls::orchestrator::types::ConversationView;
use e2e_harness::TestWorld;

// ---------------------------------------------------------------------------
// Serde back-compat / round-trip
// ---------------------------------------------------------------------------

/// Pre-rung-2 servers and previously persisted views carry no
/// `sequencer_did`; deserialization must default it to `None`.
#[test]
fn conversation_view_deserializes_without_sequencer_did() {
    let json = serde_json::json!({
        "group_id": "abcd",
        "conversation_id": "abcd",
        "epoch": 3,
        "members": [],
        "metadata": null,
        "created_at": null,
        "updated_at": null
    });
    let view: ConversationView = serde_json::from_value(json).expect("deserializes without field");
    assert_eq!(view.sequencer_did, None);
}

#[test]
fn conversation_view_round_trips_sequencer_did() {
    let view = ConversationView {
        group_id: "abcd".to_string(),
        conversation_id: "abcd".to_string(),
        epoch: 7,
        members: vec![],
        metadata: None,
        created_at: None,
        updated_at: None,
        sequencer_did: Some("did:web:ds-b.example".to_string()),
    };

    let value = serde_json::to_value(&view).expect("serializes");
    assert_eq!(
        value.get("sequencer_did").and_then(|v| v.as_str()),
        Some("did:web:ds-b.example")
    );

    let back: ConversationView = serde_json::from_value(value).expect("round-trips");
    assert_eq!(back.sequencer_did.as_deref(), Some("did:web:ds-b.example"));
}

/// `skip_serializing_if`: a `None` sequencer must not appear in serialized
/// output (keeps previously persisted blobs byte-stable).
#[test]
fn conversation_view_omits_none_sequencer_did() {
    let view = ConversationView {
        group_id: "abcd".to_string(),
        conversation_id: "abcd".to_string(),
        epoch: 7,
        members: vec![],
        metadata: None,
        created_at: None,
        updated_at: None,
        sequencer_did: None,
    };
    let value = serde_json::to_value(&view).expect("serializes");
    assert!(value.get("sequencer_did").is_none());
}

// ---------------------------------------------------------------------------
// Capabilities contract (WS-5.6 observability of default no-ops)
// ---------------------------------------------------------------------------

/// `set_conversation_sequencer` ships a default no-op, so it MUST be listed
/// in `OPTIONAL_STORAGE_METHODS` — otherwise a backend that silently drops
/// the mapping is invisible to the orchestrator's init-time capabilities
/// check.
#[test]
fn set_conversation_sequencer_is_declared_optional() {
    assert!(
        OPTIONAL_STORAGE_METHODS.contains(&"set_conversation_sequencer"),
        "set_conversation_sequencer missing from OPTIONAL_STORAGE_METHODS"
    );
}

// ---------------------------------------------------------------------------
// Sync behavior: parse + persist + re-persist on change
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sync_parses_persists_and_repersist_sequencer_did_on_change() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("Alice device registration failed");

    let convo_id = {
        let alice = world.client("Alice");
        let convo = alice
            .orchestrator
            .create_group("Seq Chat", None, None)
            .await
            .expect("create_group failed");
        convo.conversation_id.clone()
    };

    // Server starts reporting a sequencer for the conversation.
    world
        .api_service
        .set_conversation_sequencer_for_test(&convo_id, Some("did:web:ds-b.example".to_string()));

    let alice = world.client("Alice");
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("sync 1 failed");

    // (a) the in-memory conversations map holds the value
    let held = alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&convo_id)
        .and_then(|v| v.sequencer_did.clone());
    assert_eq!(held.as_deref(), Some("did:web:ds-b.example"));

    // (b) the storage backend recorded a set_conversation_sequencer call
    assert_eq!(
        alice.storage.get_persisted_sequencer(&convo_id).as_deref(),
        Some("did:web:ds-b.example")
    );
    let calls_after_first = alice
        .storage
        .set_conversation_sequencer_call_count(&convo_id);
    assert!(
        calls_after_first >= 1,
        "expected at least one persist call, got {calls_after_first}"
    );

    // An unchanged value on the next sync must NOT re-persist.
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("sync 2 failed");
    assert_eq!(
        alice
            .storage
            .set_conversation_sequencer_call_count(&convo_id),
        calls_after_first,
        "unchanged sequencer_did must not re-persist"
    );

    // (c) a changed value on the next sync logs + re-persists
    world
        .api_service
        .set_conversation_sequencer_for_test(&convo_id, Some("did:web:ds-c.example".to_string()));
    let alice = world.client("Alice");
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("sync 3 failed");
    assert_eq!(
        alice.storage.get_persisted_sequencer(&convo_id).as_deref(),
        Some("did:web:ds-c.example")
    );
    assert_eq!(
        alice
            .storage
            .set_conversation_sequencer_call_count(&convo_id),
        calls_after_first + 1,
        "changed sequencer_did must re-persist exactly once"
    );
}
