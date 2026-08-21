mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    CanonicalOperation, OrchestratorError,
};
use e2e_harness::TestWorld;
use serde_json::Value;

#[tokio::test(flavor = "multi_thread")]
async fn add_members_submits_signed_policy_transition_with_exact_fields_and_provenance() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.expect("register alice");
    let bob_did = world.register_device("Bob").await.expect("register bob");
    let alice = world.client("Alice");

    let conversation = alice
        .orchestrator
        .create_group("Policy Invite Test", None, None)
        .await
        .expect("create group");

    let group_id_bytes = hex::decode(&conversation.group_id).expect("group id is hex");
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes.clone())
        .expect("epoch before add");

    let kp_calls_before = world.delivery_service().get_key_packages_call_count();

    // Call add_members with Bob's DID
    alice
        .orchestrator
        .add_members(&conversation.conversation_id, std::slice::from_ref(&bob_did))
        .await
        .expect("add_members should succeed with policy invitation");

    // 1. Verify no key packages were fetched
    let kp_calls_after = world.delivery_service().get_key_packages_call_count();
    assert_eq!(
        kp_calls_before, kp_calls_after,
        "add_members MUST NOT call get_key_packages"
    );

    // 2. Verify local MLS epoch is unchanged (no local commit staged or merged)
    let epoch_after = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes)
        .expect("epoch after add");
    assert_eq!(
        epoch_before, epoch_after,
        "local MLS epoch must remain unchanged during policy invitation"
    );

    // 3. Verify the submitted generic gateway request
    let reqs = world.delivery_service().submitted_prepared_requests();
    let transition_req = reqs
        .iter()
        .rev()
        .find(|r| r.operation == CanonicalOperation::SubmitTransition)
        .expect("SubmitTransition request must be recorded");

    assert_eq!(transition_req.method, "POST");
    assert_eq!(transition_req.path, "/xrpc/blue.catbird.chat.submitTransition");

    let wire: Value = serde_json::from_slice(transition_req.body.as_deref().unwrap())
        .expect("parse wire JSON");

    let signed_req = wire.get("signedRequest").expect("signedRequest present");
    let sig_b64 = signed_req.get("signature").and_then(|v| v.as_str()).expect("signature string");
    assert_eq!(
        STANDARD.decode(sig_b64).expect("decode signature").len(),
        64,
        "signature must be 64 bytes"
    );

    let body = signed_req.get("body").expect("signedRequest body present");
    assert_eq!(
        body.get("$type").and_then(|v| v.as_str()),
        Some("blue.catbird.chat.defs#policyTransitionBody")
    );
    assert_eq!(
        body.get("signatureDomain").and_then(|v| v.as_str()),
        Some("CATBIRD-CHAT-POLICY\0")
    );

    let transition_id = body.get("transitionId").and_then(|v| v.as_str()).expect("transitionId");
    assert!(
        uuid::Uuid::parse_str(transition_id).is_ok(),
        "transitionId must be valid UUIDv4"
    );
    assert_eq!(
        body.get("idempotencyKey").and_then(|v| v.as_str()),
        Some(transition_id),
        "idempotencyKey must match transitionId"
    );

    assert_eq!(
        body.get("actorDid").and_then(|v| v.as_str()),
        Some(alice.did.as_str()),
        "actorDid must match Alice's DID"
    );
    let actor_device_id = alice
        .orchestrator
        .require_actor_device_id()
        .await
        .expect("alice device id");
    assert_eq!(
        body.get("actorDeviceId").and_then(|v| v.as_str()),
        Some(actor_device_id.as_str()),
        "actorDeviceId must match Alice's device ID"
    );

    assert!(body.get("keyId").and_then(|v| v.as_str()).is_some());
    assert!(body.get("authGeneration").and_then(|v| v.as_i64()).unwrap_or(0) >= 1);

    // Verify coordinates
    let prior = body.get("prior").expect("prior coordinates");
    let next = body.get("next").expect("next coordinates");

    let prior_sv = prior.get("stateVersion").and_then(|v| v.as_i64()).expect("prior stateVersion");
    let next_sv = next.get("stateVersion").and_then(|v| v.as_i64()).expect("next stateVersion");
    assert_eq!(
        next_sv,
        prior_sv + 1,
        "next stateVersion must increment prior by exactly 1"
    );

    assert_eq!(prior.get("epoch"), next.get("epoch"), "epoch must be unchanged");
    assert_eq!(prior.get("generation"), next.get("generation"), "generation must be unchanged");
    assert_eq!(prior.get("groupId"), next.get("groupId"), "groupId must be unchanged");
    assert_eq!(prior.get("groupContextHash"), next.get("groupContextHash"), "groupContextHash must be unchanged");
    assert_eq!(prior.get("confirmationTag"), next.get("confirmationTag"), "confirmationTag must be unchanged");
    assert_eq!(prior.get("lifecycle"), next.get("lifecycle"), "lifecycle must be active");
    assert_eq!(prior.get("conversationId"), next.get("conversationId"), "conversationId must match");

    // Verify participantChanges
    let changes = body
        .get("participantChanges")
        .and_then(|v| v.as_array())
        .expect("participantChanges array");
    assert_eq!(changes.len(), 1);

    let change = &changes[0];
    assert_eq!(
        change.get("$type").and_then(|v| v.as_str()),
        Some("blue.catbird.chat.defs#addParticipant")
    );
    assert_eq!(
        change.get("userDid").and_then(|v| v.as_str()),
        Some(bob_did.as_str())
    );
    assert_eq!(
        change.get("role").and_then(|v| v.as_str()),
        Some("member")
    );
    assert_eq!(
        change.get("status").and_then(|v| v.as_str()),
        Some("pending")
    );

    let provenance = change.get("invitationProvenance").expect("invitationProvenance");
    assert_eq!(
        provenance.get("invitationTransitionId").and_then(|v| v.as_str()),
        Some(transition_id)
    );
    assert_eq!(
        provenance.get("invitedByDid").and_then(|v| v.as_str()),
        Some(alice.did.as_str())
    );
    assert_eq!(
        provenance.get("invitedByDeviceId").and_then(|v| v.as_str()),
        Some(actor_device_id.as_str())
    );

    // Verify signedAt timestamp format
    let signed_at = body.get("signedAt").and_then(|v| v.as_str()).expect("signedAt string");
    assert!(
        chrono::DateTime::parse_from_rfc3339(signed_at).is_ok(),
        "signedAt must be RFC 3339 formatted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn add_members_multi_did_strictly_sorted() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.expect("register alice");
    let alice = world.client("Alice");

    let conversation = alice
        .orchestrator
        .create_group("Multi Add Test", None, None)
        .await
        .expect("create group");

    // Pass DIDs in reverse sorted order
    let did_z = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".to_string();
    let did_m = "did:plc:mmmmmmmmmmmmmmmmmmmmmmmm".to_string();
    let did_a = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string();

    alice
        .orchestrator
        .add_members(
            &conversation.conversation_id,
            &[did_z.clone(), did_m.clone(), did_a.clone()],
        )
        .await
        .expect("add_members multi-did");

    let reqs = world.delivery_service().submitted_prepared_requests();
    let transition_req = reqs
        .iter()
        .rev()
        .find(|r| r.operation == CanonicalOperation::SubmitTransition)
        .expect("SubmitTransition request must be recorded");

    let wire: Value = serde_json::from_slice(transition_req.body.as_deref().unwrap())
        .expect("parse wire JSON");

    let body = wire
        .get("signedRequest")
        .and_then(|s| s.get("body"))
        .expect("signedRequest body");

    let changes = body
        .get("participantChanges")
        .and_then(|v| v.as_array())
        .expect("participantChanges array");
    assert_eq!(changes.len(), 3);

    let dids: Vec<&str> = changes
        .iter()
        .filter_map(|c| c.get("userDid").and_then(|v| v.as_str()))
        .collect();

    assert_eq!(
        dids,
        vec![
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "did:plc:mmmmmmmmmmmmmmmmmmmmmmmm",
            "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz"
        ],
        "participantChanges must be strictly sorted by userDid UTF-8 bytes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn add_members_rejects_duplicate_dids_and_self_add() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.expect("register alice");
    let alice = world.client("Alice");

    let conversation = alice
        .orchestrator
        .create_group("Validation Test", None, None)
        .await
        .expect("create group");

    // Self add fails closed
    let self_err = alice
        .orchestrator
        .add_members(&conversation.conversation_id, &[alice.did.clone()])
        .await
        .expect_err("cannot add self");
    assert!(matches!(self_err, OrchestratorError::InvalidInput(_)));

    // Duplicate DID fails closed
    let dup_did = "did:plc:bobduplicatetest12345".to_string();
    let dup_err = alice
        .orchestrator
        .add_members(
            &conversation.conversation_id,
            &[dup_did.clone(), dup_did.clone()],
        )
        .await
        .expect_err("duplicate DIDs must be rejected");
    assert!(matches!(dup_err, OrchestratorError::InvalidInput(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn add_members_fails_closed_for_direct_conversations() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.expect("register alice");
    let bob_did = world.register_device("Bob").await.expect("register bob");
    let alice = world.client("Alice");

    let convo = alice
        .orchestrator
        .create_group("Direct Conversation", Some(&[bob_did]), None)
        .await
        .expect("create direct conversation");

    let charlie_did = "did:plc:charlie1234567890123456".to_string();
    let err = alice
        .orchestrator
        .add_members(&convo.conversation_id, &[charlie_did])
        .await
        .expect_err("direct conversation must reject add_members");

    assert!(matches!(err, OrchestratorError::InvalidInput(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn add_members_fails_closed_on_non_2xx_server_response() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.expect("register alice");
    let alice = world.client("Alice");

    let conversation = alice
        .orchestrator
        .create_group("Server Error Test", None, None)
        .await
        .expect("create group");

    let bob_did = "did:plc:bobservererrortest123".to_string();

    // Inject commit_group_change / SubmitTransition failure
    world
        .delivery_service()
        .fail_next_commit_group_change();

    let err = alice
        .orchestrator
        .add_members(&conversation.conversation_id, &[bob_did])
        .await
        .expect_err("non-2xx server response must fail closed");

    assert!(matches!(err, OrchestratorError::Api(_)));
}
