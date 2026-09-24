//! The delivery service presents every mutation response with lexicon
//! `{"$bytes"}` byte fields, including the echoed signed request. The client
//! submits its signed request unchanged and must accept either presentation.
#![allow(dead_code)]
mod e2e_harness;

use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
use e2e_harness::TestWorld;
use serde_json::Value;

const ALICE: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

async fn world(present: bool) -> TestWorld {
    let mut world = TestWorld::new();
    world.add_client_with_did("Alice", ALICE).await;
    world.register_device("Alice").await.unwrap();
    world.delivery_service().present_lexicon_bytes(present);
    world
}

#[tokio::test(flavor = "multi_thread")]
async fn send_accepts_the_lexicon_presented_echo_of_its_bare_signed_request() {
    for present in [true, false] {
        let world = world(present).await;
        let alice = world.client("Alice");
        let created = alice
            .orchestrator
            .create_group("Presented echo", None, None)
            .await
            .unwrap();
        let sent = alice
            .orchestrator
            .send_message(&created.conversation_id, "hello")
            .await
            .unwrap_or_else(|error| panic!("present={present}: {error}"));
        assert_eq!(sent.conversation_id, created.conversation_id);

        // The submitted signed request is unchanged: declared bytes the core
        // spells bare (the identifierBytes AAD fields) are still bare.
        let request = world
            .delivery_service()
            .submitted_prepared_requests()
            .into_iter()
            .rfind(|request| request.operation == CanonicalOperation::SendMessage)
            .unwrap();
        let submitted: Value = serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
        let aad = &submitted["signedRequest"]["body"]["aad"];
        assert!(aad["conversationId"].is_string(), "{aad}");
        assert!(aad["messageId"].is_string(), "{aad}");
    }
}
