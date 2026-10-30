//! Send authority must survive every awaited callback, including same-account restart.
#![allow(dead_code)]
mod e2e_harness;
use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
use catbird_mls::orchestrator::credentials::CredentialStore;
use e2e_harness::TestWorld;
use std::time::Duration;

#[derive(Clone, Copy)]
enum Change {
    Restart,
    Generation,
    Device,
}

async fn rejects_signer_race(change: Change) {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("actor fence", None, None)
        .await
        .unwrap();
    let before = world
        .api_service
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::SendMessage)
        .count();
    let pause = alice.credentials.pause_next_signature();
    let send = alice
        .orchestrator
        .send_message(&convo.conversation_id, "must remain unsent");
    let change_actor = async {
        tokio::time::timeout(Duration::from_secs(10), pause.wait_entered())
            .await
            .expect("send reached the credential signing callback");
        match change {
            Change::Restart => {
                alice.orchestrator.shutdown().await;
                alice.orchestrator.initialize(&alice.did).await.unwrap();
            }
            Change::Generation => {
                let device = alice
                    .credentials
                    .get_device_uuid(&alice.did)
                    .await
                    .unwrap()
                    .unwrap();
                alice
                    .credentials
                    .set_clean_chat_binding(&alice.did, &device, "test-dpop", Some(2));
            }
            Change::Device => {
                alice
                    .credentials
                    .store_device_uuid(&alice.did, &uuid::Uuid::new_v4().to_string())
                    .await
                    .unwrap();
            }
        }
        pause.release();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(send, change_actor)
    })
    .await
    .expect("race completes without a stuck signer or lifecycle lock");
    assert!(
        result.is_err(),
        "changed authority must invalidate an already signed operation"
    );
    let after = world
        .api_service
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::SendMessage)
        .count();
    assert_eq!(
        after, before,
        "no HTTP send may occur after signer authority changed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn same_account_shutdown_reinitialize_during_signing_aborts_before_http() {
    rejects_signer_race(Change::Restart).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn authentication_generation_change_during_signing_aborts_before_http() {
    rejects_signer_race(Change::Generation).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn device_rotation_during_signing_aborts_before_http() {
    rejects_signer_race(Change::Device).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn same_account_restart_after_server_acceptance_withholds_local_confirmation() {
    use catbird_mls::orchestrator::MLSStorageBackend;
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("ACK fence", None, None)
        .await
        .unwrap();
    let gate = world.api_service.pause_next_send_ack();
    let send = alice
        .orchestrator
        .send_message(&convo.conversation_id, "uncertain delivery");
    let restart = async {
        tokio::time::timeout(Duration::from_secs(10), gate.wait_until_reached())
            .await
            .unwrap();
        alice.orchestrator.shutdown().await;
        alice.orchestrator.initialize(&alice.did).await.unwrap();
        gate.release();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(send, restart)
    })
    .await
    .unwrap();
    assert!(result.is_err(), "ACK belongs to the abandoned lifecycle");
    let sends: Vec<_> = world
        .api_service
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::SendMessage)
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "uncertain accepted send must not be retried"
    );
    let wire: serde_json::Value = serde_json::from_slice(sends[0].body.as_ref().unwrap()).unwrap();
    let id = wire["signedRequest"]["body"]["messageId"].as_str().unwrap();
    assert!(
        !alice.storage.message_exists(id).await.unwrap(),
        "old ACK must not project a sent message into the new lifecycle"
    );
}
