//! Regression test for Phase D Rust narrow scope: the orchestrator must
//! insert the External Commit ciphertext hash into `own_commits()` so that
//! when the server fans the commit back via the inbound pipeline,
//! `process_incoming` (`messaging.rs:489-503`) recognizes it as own and
//! short-circuits before invoking `decrypt_message`.
//!
//! Other commit producers (`groups.rs:151`, `groups.rs:668`,
//! `staged_commit.rs:156`, `messaging.rs:181`, `messaging.rs:371`) all insert
//! the hash. `recovery.rs::force_rejoin_unlocked` produces an External Commit
//! at line ~963-1005 and historically did NOT insert — that's the gap this
//! test catches.
//!
//! Pattern modeled after `tests/state_machine_tests.rs::test_force_rejoin_cleans_state`,
//! which already drives `orchestrator.force_rejoin(group_id)` end-to-end
//! against the e2e_harness.

#![allow(dead_code)]

mod e2e_harness;

use e2e_harness::TestWorld;
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread")]
async fn force_rejoin_inserts_external_commit_into_own_commits() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;

    let _a = world
        .register_device("Alice")
        .await
        .expect("register_device(Alice) failed");

    let alice = world.client("Alice");

    // Alice creates a group. `create_group` itself inserts the *initial* add
    // commit into own_commits (groups.rs:151), so snapshot AFTER that step to
    // isolate the External Commit insertion below.
    let convo = alice
        .orchestrator
        .create_group("ExtCommit Dedup Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Snapshot own_commits BEFORE force_rejoin so we can identify the new entry.
    let pre_keys: std::collections::HashSet<Vec<u8>> = alice
        .orchestrator
        .own_commits()
        .lock()
        .await
        .keys()
        .cloned()
        .collect();

    // Drive the External Commit path. `force_rejoin` -> `force_rejoin_unlocked`
    // -> `mls_context.create_external_commit(...)` -> `process_external_commit`.
    // The mock api's `process_external_commit` stores the commit ciphertext as
    // a StoredMessage (mock_api_client.rs:982-993) so we can fetch it back to
    // verify the hash.
    alice
        .orchestrator
        .force_rejoin(&convo_id)
        .await
        .expect("force_rejoin failed");

    // Fetch the External Commit ciphertext that was just sent. The mock api
    // stores it in the conversation's message log. The most recently appended
    // message is the External Commit.
    let (messages, _) = world
        .delivery_service()
        .clone_as(&alice.did)
        .get_messages_via_api(&convo_id)
        .await
        .expect("get_messages failed");
    let ext_commit_ciphertext = messages
        .last()
        .expect("at least one message stored after force_rejoin")
        .ciphertext
        .clone();

    let expected_hash = Sha256::digest(&ext_commit_ciphertext).to_vec();

    let post_guard = alice.orchestrator.own_commits().lock().await;
    let post_keys: std::collections::HashSet<Vec<u8>> = post_guard.keys().cloned().collect();
    let new_keys: Vec<&Vec<u8>> = post_keys.difference(&pre_keys).collect();

    // The new entry MUST be present. Without the fix, this assertion fails
    // because recovery.rs never inserts.
    assert!(
        post_guard.contains_key(&expected_hash),
        "External Commit hash NOT inserted into own_commits().\n\
         When the server fans this commit back via subscribeEvents,\n\
         process_incoming will fall through to decrypt_message rather than\n\
         short-circuiting as own.\n\
         pre_keys.len()={}, post_keys.len()={}, new_keys.len()={}\n\
         expected_hash={}",
        pre_keys.len(),
        post_keys.len(),
        new_keys.len(),
        hex::encode(&expected_hash),
    );

    // Exactly one new entry should be present — the External Commit. (If more
    // appear, something else is over-inserting and worth flagging.)
    assert_eq!(
        new_keys.len(),
        1,
        "expected exactly 1 new own_commits entry after force_rejoin (the External Commit); \
         got {} new entries",
        new_keys.len(),
    );
}

// ---------------------------------------------------------------------------
// Tiny extension trait so the test can pull messages out of the mock without
// reaching into private state. Uses only the public MLSAPIClient surface.
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
trait FetchMessagesExt {
    async fn get_messages_via_api(
        &self,
        convo_id: &str,
    ) -> catbird_mls::orchestrator::error::Result<(
        Vec<catbird_mls::orchestrator::types::IncomingEnvelope>,
        Option<String>,
    )>;
}

#[async_trait::async_trait]
impl FetchMessagesExt for e2e_harness::mock_api_client::MockDeliveryService {
    async fn get_messages_via_api(
        &self,
        convo_id: &str,
    ) -> catbird_mls::orchestrator::error::Result<(
        Vec<catbird_mls::orchestrator::types::IncomingEnvelope>,
        Option<String>,
    )> {
        use catbird_mls::orchestrator::MLSAPIClient;
        // limit=1000 to grab everything in the small mock log.
        MLSAPIClient::get_messages(self, convo_id, None, 1000, None, None, None).await
    }
}
