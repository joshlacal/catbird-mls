//! Delivery-server device discovery never authorizes an MLS signing key.
//! ADR-009 authority comes exclusively from the root DID's repository records.
#![allow(dead_code)]
mod e2e_harness;

use catbird_mls::chat_v2::ids::KeyId;
use catbird_mls::orchestrator::{canonical_transport::CanonicalOperation, CommitKind};
use e2e_harness::TestWorld;
use serde_json::{json, Value};

const ALICE: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
const BOB: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

async fn fixture() -> TestWorld {
    let mut world = TestWorld::new();
    for (name, did) in [("Alice", ALICE), ("Bob", BOB)] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    world
}

fn directory(device: &str, key: &[u8]) -> Value {
    json!({"devices":[{"userDid":BOB,"deviceId":device,
        "keyId":KeyId::from_public_key(key.try_into().unwrap()).to_string()}]})
}

fn directory_calls(world: &TestWorld) -> usize {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|request| request.operation == CanonicalOperation::GetDevices)
        .count()
}

async fn add_candidate(world: &TestWorld, name: &str) -> (CommitKind, Value) {
    let client = world.client(name);
    let device = client.orchestrator.require_actor_device_id().await.unwrap();
    let package = client
        .orchestrator
        .mls_context()
        .create_key_package(format!("{}#{device}", client.did).into_bytes())
        .unwrap();
    let claimed_authority = directory(&device, &package.signature_public_key);
    (
        CommitKind::AddMembers {
            member_dids: vec![client.did.clone()],
            key_packages: vec![catbird_mls::KeyPackageData {
                data: package.key_package_data,
            }],
        },
        claimed_authority,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn server_directory_cannot_authorize_staging_without_repository_keys() {
    let world = fixture().await;
    let alice = world.client("Alice");
    alice.credentials.clear_authorized_device_keys(BOB);
    let convo = alice
        .orchestrator
        .create_group("repository authority required", None, None)
        .await
        .unwrap();
    let (kind, forged_authority) = add_candidate(&world, "Bob").await;
    // The DS claims the candidate's exact DID/device/key, but it has no
    // repository authority. A fallback to this response would admit the leaf.
    world
        .delivery_service()
        .queue_device_directory_response(200, forged_authority);
    alice
        .orchestrator
        .stage_commit(&convo.conversation_id, kind)
        .await
        .expect_err("server-discovered keys cannot replace repository authority");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&convo.group_id).unwrap())
            .unwrap(),
        0,
        "untrusted server authority cannot mutate the native group"
    );
    assert_eq!(directory_calls(&world), 0);
    assert_eq!(alice.credentials.device_key_lookup_count(BOB), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_repository_key_set_denies_staging_despite_matching_server_directory() {
    let world = fixture().await;
    let alice = world.client("Alice");
    alice.credentials.set_authorized_device_keys(BOB, vec![]);
    let convo = alice
        .orchestrator
        .create_group("repository denial", None, None)
        .await
        .unwrap();
    let (kind, forged_authority) = add_candidate(&world, "Bob").await;
    world
        .delivery_service()
        .queue_device_directory_response(200, forged_authority);
    for _ in 0..2 {
        alice
            .orchestrator
            .stage_commit(&convo.conversation_id, kind.clone())
            .await
            .expect_err("resolved empty repository authority denies every candidate");
    }
    assert_eq!(
        alice.credentials.device_key_lookup_count(BOB),
        2,
        "a cached key miss refreshes once, then fresh empty authority still denies"
    );
    assert_eq!(directory_calls(&world), 0);
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&convo.group_id).unwrap())
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn server_directory_cannot_add_a_key_missing_from_nonempty_repository_authority() {
    let world = fixture().await;
    let alice = world.client("Alice");
    let actor = alice.orchestrator.require_actor_device_id().await.unwrap();
    let different_key = alice
        .orchestrator
        .mls_context()
        .create_key_package(format!("{ALICE}#{actor}").into_bytes())
        .unwrap()
        .signature_public_key;
    alice
        .credentials
        .set_authorized_device_keys(BOB, vec![different_key]);
    let convo = alice
        .orchestrator
        .create_group("repository key mismatch", None, None)
        .await
        .unwrap();
    let (kind, forged_authority) = add_candidate(&world, "Bob").await;
    world
        .delivery_service()
        .queue_device_directory_response(200, forged_authority);
    for _ in 0..2 {
        alice
            .orchestrator
            .stage_commit(&convo.conversation_id, kind.clone())
            .await
            .expect_err("a server fingerprint cannot expand the trusted repository key set");
    }
    assert_eq!(
        alice.credentials.device_key_lookup_count(BOB),
        2,
        "one bounded refresh must still reject an unpublished candidate key"
    );
    assert_eq!(directory_calls(&world), 0);
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&convo.group_id).unwrap())
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn repository_resolution_errors_retry_uncached_without_server_fallback() {
    let world = fixture().await;
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("repository retry", None, None)
        .await
        .unwrap();
    let (kind, forged_authority) = add_candidate(&world, "Bob").await;
    world
        .delivery_service()
        .queue_device_directory_response(200, forged_authority);
    alice
        .credentials
        .set_authorized_device_key_resolution_failure(BOB, true);
    for _ in 0..2 {
        alice
            .orchestrator
            .stage_commit(&convo.conversation_id, kind.clone())
            .await
            .expect_err("repository lookup failure cannot delegate authority to the DS");
    }
    assert_eq!(
        alice.credentials.device_key_lookup_count(BOB),
        2,
        "resolver errors must not be cached"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&convo.group_id).unwrap())
            .unwrap(),
        0
    );

    alice
        .credentials
        .set_authorized_device_key_resolution_failure(BOB, false);
    // These keys were established by explicit fixture device registration,
    // independently of the candidate package and DS response being verified.
    world.install_authorized_device_keys(&alice.credentials, BOB);
    for _ in 0..2 {
        let plan = alice
            .orchestrator
            .stage_commit(&convo.conversation_id, kind.clone())
            .await
            .expect("the same package remains usable after repository resolution recovers");
        assert!(plan.welcome_bytes.is_some());
        alice
            .orchestrator
            .discard_pending(plan.handle)
            .await
            .unwrap();
    }
    assert_eq!(
        alice.credentials.device_key_lookup_count(BOB),
        3,
        "successful repository key authorization is cached"
    );
    assert_eq!(directory_calls(&world), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_admission_requires_repository_key_even_when_server_claims_exact_device() {
    let world = fixture().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let actor = alice.orchestrator.require_actor_device_id().await.unwrap();
    alice.credentials.clear_authorized_device_keys(BOB);
    let convo = alice
        .orchestrator
        .create_group("repository admission", Some(&[BOB.into()]), None)
        .await
        .unwrap();
    let cid = &convo.conversation_id;
    let group = hex::decode(&convo.group_id).unwrap();
    world.delivery_service().set_conversation_leaves_for_test(
        cid,
        vec![json!({"userDid":ALICE,"deviceId":actor,"deviceStatus":"active","leafIndex":0})],
    );
    bob.orchestrator.accept_conversation(cid).await.unwrap();
    let (_, forged_authority) = add_candidate(&world, "Bob").await;
    world
        .delivery_service()
        .queue_device_directory_response(200, forged_authority);
    alice
        .orchestrator
        .fulfill_leaf_recovery(cid)
        .await
        .expect_err("a DS fingerprint cannot authorize a new MLS leaf");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        0
    );
    assert_eq!(directory_calls(&world), 0);

    world.install_authorized_device_keys(&alice.credentials, BOB);
    alice.orchestrator.invalidate_device_key_cache().await;
    alice
        .orchestrator
        .fulfill_leaf_recovery(cid)
        .await
        .expect("repository-published key authorizes actual native admission");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    bob.orchestrator.join_or_rejoin(cid).await.unwrap();
    assert_eq!(bob.orchestrator.mls_context().get_epoch(group).unwrap(), 1);
    assert_eq!(directory_calls(&world), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn cached_repository_keys_refresh_once_for_newly_published_same_did_sibling() {
    let mut world = fixture().await;
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("sibling repository refresh", None, None)
        .await
        .unwrap();
    let (first, forged_authority) = add_candidate(&world, "Bob").await;
    world
        .delivery_service()
        .queue_device_directory_response(200, forged_authority.clone());
    let plan = alice
        .orchestrator
        .stage_commit(&convo.conversation_id, first)
        .await
        .unwrap();
    alice
        .orchestrator
        .discard_pending(plan.handle)
        .await
        .unwrap();
    assert_eq!(alice.credentials.device_key_lookup_count(BOB), 1);

    // Registration publishes the sibling key into the test repository
    // resolver. Keep Alice's older positive cache to exercise automatic refresh.
    world.add_client_with_did("Bob2", BOB).await;
    world.register_device("Bob2").await.unwrap();
    let alice = world.client("Alice");
    let (sibling, sibling_directory) = add_candidate(&world, "Bob2").await;
    assert_ne!(
        forged_authority["devices"][0]["deviceId"],
        sibling_directory["devices"][0]["deviceId"]
    );
    assert_ne!(
        forged_authority["devices"][0]["keyId"],
        sibling_directory["devices"][0]["keyId"]
    );
    for _ in 0..2 {
        let plan = alice
            .orchestrator
            .stage_commit(&convo.conversation_id, sibling.clone())
            .await
            .expect("a newly repository-published sibling bypasses the old key-set cache");
        assert!(plan.welcome_bytes.is_some());
        alice
            .orchestrator
            .discard_pending(plan.handle)
            .await
            .unwrap();
    }
    assert_eq!(
        alice.credentials.device_key_lookup_count(BOB),
        2,
        "the sibling miss triggers one repository refresh, then hits the updated cache"
    );
    assert_eq!(directory_calls(&world), 0);
}
