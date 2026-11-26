//! Spaces-only unit tests for `catbird_mls::labyrinth` (`MemorySpaceHost` + 6-endpoint DS directory).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use labyrinth::records::EpochPublicDef;
use labyrinth::store::pds::MemoryPublicRepoHost;
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::TimeRange;

use super::flush::flush_queue;
use super::queue::{enqueue, ArchiveQueueStore, PendingArchive};
use super::session::{LocalConversationAuthority, LocalGroupSnapshot, SessionDeps};
use super::signer::ChatKeySigner;
use super::state::StateVault;
use super::status::ArchiveStatus;
use super::transport::{GatewayXrpcTransport, LabyrinthGateway};
use super::LabyrinthRequest;
use crate::orchestrator::canonical_transport::{GatewayResponse, PreparedRequest};
use crate::orchestrator::error::Result as OrchResult;
use crate::MLSError;

struct TestChatSigner {
    signing: SigningKey,
}

impl TestChatSigner {
    fn from_seed(seed: u8) -> Self {
        Self {
            signing: SigningKey::from_bytes(&[seed; 32]),
        }
    }
}

impl ChatKeySigner for TestChatSigner {
    fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.signing.sign(msg).to_bytes())
    }
}

#[derive(Default)]
struct MemoryVault {
    entries: Mutex<HashMap<String, Vec<u8>>>,
}

impl StateVault for MemoryVault {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.entries.lock().unwrap().get(key).cloned())
    }

    fn compare_exchange(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        let mut map = self.entries.lock().unwrap();
        if map.get(key).map(Vec::as_slice) != expected {
            return Ok(false);
        }
        map.insert(key.to_owned(), next.to_vec());
        Ok(true)
    }

    fn delete(&self, key: &str) -> Result<(), MLSError> {
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }
}

#[derive(Default)]
struct MemoryQueueStore {
    rows: Mutex<Vec<PendingArchive>>,
    status: Mutex<HashMap<String, ArchiveStatus>>,
}

impl ArchiveQueueStore for MemoryQueueStore {
    fn put(&self, row: &PendingArchive) -> OrchResult<()> {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|r| !(r.did == row.did && r.message_id == row.message_id));
        rows.push(row.clone());
        Ok(())
    }

    fn list(&self, did: &str) -> OrchResult<Vec<PendingArchive>> {
        let mut out: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.did == did)
            .cloned()
            .collect();
        out.sort_by_key(|r| r.timestamp_ms);
        Ok(out)
    }

    fn remove(&self, did: &str, message_id: &str) -> OrchResult<()> {
        self.rows
            .lock()
            .unwrap()
            .retain(|r| !(r.did == did && r.message_id == message_id));
        Ok(())
    }

    fn load_status(&self, did: &str) -> OrchResult<ArchiveStatus> {
        Ok(self
            .status
            .lock()
            .unwrap()
            .get(did)
            .cloned()
            .unwrap_or_default())
    }

    fn save_status(&self, did: &str, status: &ArchiveStatus) -> OrchResult<()> {
        self.status
            .lock()
            .unwrap()
            .insert(did.to_owned(), status.clone());
        Ok(())
    }
}

#[derive(Default)]
struct MockDsState {
    heads: HashMap<String, Vec<EpochPublicDef>>,
    chat_keys: HashMap<String, Vec<[u8; 32]>>,
    conversations: HashMap<String, (String, Vec<String>)>,
    did_docs: HashMap<String, Vec<u8>>,
    publish_epoch_failures: usize,
}

struct MockSixEndpointGateway {
    actor_did: String,
    state: Arc<Mutex<MockDsState>>,
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(v.replace("%3A", ":").replace("%2F", "/"));
        }
    }
    None
}

#[async_trait::async_trait]
impl LabyrinthGateway for MockSixEndpointGateway {
    async fn submit_labyrinth(&self, request: LabyrinthRequest) -> Result<GatewayResponse, String> {
        let mut st = self.state.lock().unwrap();
        match request.nsid.as_str() {
            "blue.catbird.labyrinth.getRecoveryShareCapabilities" => Ok(GatewayResponse {
                status: 200,
                content_type: Some("application/json".into()),
                body: br#"{"supported":true,"version":1,"hpkeSuite":"DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM","keyId":"fixture-kek"}"#.to_vec(),
            }),
            "blue.catbird.labyrinth.deleteRecoveryShare" => Ok(GatewayResponse {
                status: 404,
                content_type: Some("application/json".into()),
                body: br#"{"error":"RecoveryShareNotFound"}"#.to_vec(),
            }),
            "blue.catbird.labyrinth.publishEpochHead" => {
                if st.publish_epoch_failures > 0 {
                    st.publish_epoch_failures -= 1;
                    return Err("injected publishEpochHead failure".into());
                }
                let parsed: serde_json::Value =
                    serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}"))
                        .map_err(|e| e.to_string())?;
                let epoch: EpochPublicDef =
                    serde_json::from_value(parsed["epoch"].clone()).map_err(|e| e.to_string())?;
                let list = st.heads.entry(self.actor_did.clone()).or_default();
                list.retain(|e| e.epoch_number != epoch.epoch_number);
                list.push(epoch);
                list.sort_by_key(|e| e.epoch_number);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
            "blue.catbird.labyrinth.purgeMailbox" | "blue.catbird.labyrinth.deleteAccountData" => {
                st.heads.remove(&self.actor_did);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
            "blue.catbird.labyrinth.getEpochHead" => {
                let did = query_param(&request.path, "did").unwrap_or_default();
                let seq =
                    query_param(&request.path, "epochNumber").and_then(|s| s.parse::<u64>().ok());
                let list = st.heads.get(&did).cloned().unwrap_or_default();
                let found = match seq {
                    Some(n) => list.iter().find(|e| e.epoch_number == n).cloned(),
                    None => list.last().cloned(),
                };
                match found {
                    Some(epoch) => {
                        let chain: Vec<_> = list
                            .iter()
                            .filter(|e| e.epoch_number <= epoch.epoch_number)
                            .cloned()
                            .collect();
                        let floor_seq = chain.first().map(|e| e.epoch_number).unwrap_or(0);
                        Ok(GatewayResponse {
                            status: 200,
                            content_type: Some("application/json".into()),
                            body: serde_json::to_vec(&serde_json::json!({
                                "epoch": epoch,
                                "chain": chain,
                                "floorSeq": floor_seq,
                                "receivedAt": "2026-10-31T00:00:00Z"
                            }))
                            .unwrap(),
                        })
                    }
                    None => Ok(GatewayResponse {
                        status: 404,
                        content_type: Some("application/json".into()),
                        body: br#"{"error":"EpochNotFound","message":"none"}"#.to_vec(),
                    }),
                }
            }
            "blue.catbird.labyrinth.getChatDeviceKeys" => {
                let did = query_param(&request.path, "did").unwrap_or_default();
                let keys = st.chat_keys.get(&did).cloned().unwrap_or_default();
                let items: Vec<_> = keys
                    .into_iter()
                    .map(|k| {
                        serde_json::json!({
                            "signingPublicKey": { "$bytes": STANDARD_NO_PAD.encode(k) }
                        })
                    })
                    .collect();
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({ "items": items })).unwrap(),
                })
            }
            "blue.catbird.labyrinth.getMemberDevices" => {
                let did = query_param(&request.path, "did").unwrap_or_default();
                let keys = st.chat_keys.get(&did).cloned().unwrap_or_default();
                let items: Vec<_> = keys
                    .into_iter()
                    .map(|k| {
                        serde_json::json!({
                            "signingPublicKey": { "$bytes": STANDARD_NO_PAD.encode(k) },
                            "joinedSeq": 0
                        })
                    })
                    .collect();
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({ "items": items })).unwrap(),
                })
            }
            other => Err(format!("unexpected labyrinth endpoint: {other}")),
        }
    }

    async fn submit_canonical(
        &self,
        request: PreparedRequest,
        _headers: Vec<(String, String)>,
    ) -> Result<GatewayResponse, String> {
        let st = self.state.lock().unwrap();
        let conv_id = query_param(&request.path, "conversationId").unwrap_or_default();
        match st.conversations.get(&conv_id) {
            Some((sequencer_did, members)) => {
                let participants: Vec<_> = members
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "userDid": d,
                            "status": "active",
                            "leafCount": 1
                        })
                    })
                    .collect();
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({
                        "state": {
                            "sequencerDid": sequencer_did,
                            "coordinates": { "generation": 0 },
                            "participants": participants
                        }
                    }))
                    .unwrap(),
                })
            }
            None => Ok(GatewayResponse {
                status: 404,
                content_type: Some("application/json".into()),
                body: br#"{"error":"ConversationNotFound","message":"gone"}"#.to_vec(),
            }),
        }
    }

    async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.state.lock().unwrap().did_docs.get(did).cloned())
    }
}

struct StaticAuthority(LocalGroupSnapshot);

#[async_trait::async_trait]
impl LocalConversationAuthority for StaticAuthority {
    async fn current_group_snapshot(
        &self,
        _conversation_id: &str,
        _queued_group_id_hex: Option<&str>,
    ) -> OrchResult<Option<LocalGroupSnapshot>> {
        Ok(Some(self.0.clone()))
    }
}

fn build_deps(
    did: &str,
    device_id: &str,
    seed: u8,
    ds_state: Arc<Mutex<MockDsState>>,
    space_host: &MemorySpaceHost,
    pds_host: &MemoryPublicRepoHost,
    local_authority: Option<Arc<dyn LocalConversationAuthority>>,
) -> SessionDeps {
    let signer = Arc::new(TestChatSigner::from_seed(seed));
    ds_state
        .lock()
        .unwrap()
        .chat_keys
        .entry(did.to_owned())
        .or_default()
        .push(signer.public_key());
    let gw = Arc::new(MockSixEndpointGateway {
        actor_did: did.to_owned(),
        state: ds_state,
    });
    let placements = Arc::new(MemoryVault::default());
    super::recovery_shares::pin_proven_home_service(
        placements.as_ref(),
        did,
        "did:web:fixture-home.example",
    )
    .expect("fixture home service pin");
    SessionDeps {
        did: did.to_owned(),
        transport: Arc::new(
            GatewayXrpcTransport::new(gw, signer.clone(), did.to_owned(), device_id.to_owned())
                .with_home_ds_did("did:web:fixture-home.example".into()),
        ),
        signer,
        vault: Arc::new(MemoryVault::default()),
        pds: Some(Arc::new(pds_host.client(did))),
        space: Some(Arc::new(space_host.client(did))),
        placements,
        local_authority,
        sequencer_receipt_key: None,
        default_conversation_authority_did: None,
    }
}

#[tokio::test]
async fn fresh_device_must_restore_existing_mailbox_before_genesis_writes() {
    let did = "did:plc:archiveowner000000000000000";
    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState::default()));
    let first = build_deps(
        did,
        "dev-a1",
        11,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    first.clone().enable().await.expect("first device genesis");
    assert_eq!(first.list_mailbox_devices().await.unwrap().len(), 1);

    let fresh = build_deps(did, "dev-a2", 12, ds_state, &space_host, &pds_host, None);
    let presence = fresh.recovery_presence().await.unwrap();
    assert!(!presence.local_state);
    assert!(presence.mailbox_epoch);
    assert!(presence.pds_head);
    assert!(presence.ds_head);
    assert!(presence.requires_recovery());
    let error = fresh.enable().await.err().expect("must refuse new genesis");
    assert!(error.to_string().contains("restore"));
    assert_eq!(first.list_mailbox_devices().await.unwrap().len(), 1);
}

#[tokio::test]
async fn revoked_device_surfaces_rekeyed_code_when_ds_head_publish_fails() {
    let did = "did:plc:revokecodeowner000000000000";
    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState::default()));
    let first = build_deps(
        did,
        "dev-a1",
        21,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let mut first_session = first.clone().enable().await.expect("first device genesis");
    let code = first_session
        .create_recovery_code()
        .await
        .expect("create v2 recovery method");
    let second = build_deps(
        did,
        "dev-a2",
        22,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let mut second_session = second
        .restore_with_recovery_code(&code)
        .await
        .expect("restore second device");
    ds_state.lock().unwrap().publish_epoch_failures = 1;

    let report = second_session
        .revoke_device(first_session.device_key_pub())
        .await
        .expect("mailbox rotation remains committed despite DS publication failure");
    assert!(report.rekeyed_recovery_code.is_some());
    assert!(second_session.pending_directory_epoch().is_some());
    assert_eq!(report.new_epoch, second_session.latest_epoch());
}

#[tokio::test]
async fn spaces_only_enable_archive_flush_restore_and_rearchive_before_leave() {
    let alice = "did:plc:alice0000000000000000000";
    let bob = "did:plc:bob000000000000000000000";
    let ds_did = "did:web:ds.catbird.test";
    let conv_id = "11111111-2222-4333-8444-555555555555";

    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState {
        conversations: HashMap::from([(
            conv_id.to_owned(),
            (ds_did.to_owned(), vec![alice.to_owned(), bob.to_owned()]),
        )]),
        ..Default::default()
    }));

    let authority: Arc<dyn LocalConversationAuthority> =
        Arc::new(StaticAuthority(LocalGroupSnapshot {
            group_id_hex: "aa11".into(),
            epoch: 1,
            member_dids: vec![alice.to_owned(), bob.to_owned()],
        }));

    let alice_d1 = build_deps(
        alice,
        "dev-a1",
        11,
        ds_state.clone(),
        &space_host,
        &pds_host,
        Some(authority),
    );
    let bob_d1 = build_deps(
        bob,
        "dev-b1",
        22,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );

    let mut alice_s1 = alice_d1.clone().enable().await.expect("alice enable");
    let mut bob_s1 = bob_d1.clone().enable().await.expect("bob enable");
    let recovery_code = alice_s1
        .create_recovery_code()
        .await
        .expect("recovery code");

    let queue = MemoryQueueStore::default();
    let row = PendingArchive::new(alice, conv_id, "msg-1", 1_700_000_001_000, b"hello spaces")
        .with_mls_snapshot("aa11", 1, vec![alice.to_owned(), bob.to_owned()]);
    assert!(enqueue(&queue, &row).expect("enqueue"));

    let report = flush_queue(&mut alice_s1, &alice_d1, &queue)
        .await
        .expect("flush_queue");
    assert_eq!(report.archived, 1);
    assert_eq!(report.failed_conversations, 0);

    // Bob reads the conversation Space resolved from getConversationState.
    let bob_hist = bob_s1
        .load_history(conv_id, TimeRange::ALL)
        .await
        .expect("bob load_history");
    assert_eq!(bob_hist.messages.len(), 1);
    assert_eq!(bob_hist.messages[0].frame, b"hello spaces");

    // Alice's second device restores via 40-char recovery code (`Gate 3`).
    let alice_d2 = build_deps(
        alice,
        "dev-a2",
        12,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let mut alice_s2 = alice_d2
        .restore_with_recovery_code(&recovery_code)
        .await
        .expect("alice restore");
    let d2_hist = alice_s2
        .load_history(conv_id, TimeRange::ALL)
        .await
        .expect("d2 load_history");
    assert_eq!(d2_hist.messages.len(), 1);
    assert_eq!(d2_hist.messages[0].frame, b"hello spaces");

    // Gate 5 / [CB-22]: re-archive before leave copies into personal mailbox Space and clears sender repo.
    let copied = alice_s2
        .rearchive_before_leave(conv_id)
        .await
        .expect("rearchive_before_leave");
    assert_eq!(copied, 1);
}

#[tokio::test]
async fn fault_line_1_session_persists_mek_pin_and_revocation_before_flush_or_publish_error() {
    let alice = "did:plc:alicefl10000000000000000";
    let bob = "did:plc:bobfl1000000000000000000";
    let ds_did = "did:web:ds.catbird.test";
    let conv_id = "22222222-3333-4444-8555-666666666666";

    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState {
        conversations: HashMap::from([(
            conv_id.to_owned(),
            (ds_did.to_owned(), vec![alice.to_owned(), bob.to_owned()]),
        )]),
        ..Default::default()
    }));

    let alice_d1 = build_deps(
        alice,
        "dev-a1",
        31,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let bob_d1 = build_deps(
        bob,
        "dev-b1",
        32,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );

    let mut alice_s1 = alice_d1.clone().enable().await.expect("alice enable");
    let _bob_s1 = bob_d1.clone().enable().await.expect("bob enable");
    let state_before = alice_d1
        .vault
        .load(alice)
        .expect("load alice state")
        .expect("alice state present");

    // Revoke Alice's Space write permission on the conversation Space BEFORE archive_conversation
    // flushes, forcing `flush_thread` inside `archive_conversation` to fail AFTER `MEK` and
    // `[CB-29]` peer pins for Bob have mutated in memory!
    let convo_space =
        labyrinth::store::space::SpaceRef::conversation(ds_did, &format!("{conv_id}-0"));
    space_host.revoke_space_member(&convo_space, alice);

    let archive_res = alice_s1
        .archive_conversation(
            conv_id,
            std::slice::from_ref(&bob.to_owned()),
            &[(
                "msg-crash-1".to_owned(),
                1_700_000_010_000,
                b"survives flush failure".to_vec(),
            )],
        )
        .await
        .expect("try_finish succeeds and checkpoints state");
    assert!(matches!(archive_res, Err(labyrinth::Error::Forbidden)));

    // VaultStateSink + try_finish MUST have persisted the newly minted MEK and Bob's peer pin
    // into `vault` BEFORE the network flush error surfaced.
    let state_after = alice_d1
        .vault
        .load(alice)
        .expect("load alice state after err")
        .expect("alice state still present");
    assert_ne!(
        state_before, state_after,
        "vault must checkpoint mutated MEK and peer pins even when network flush fails"
    );

    // Reopen session from vault after simulated crash, restore Space membership, and archive a
    // second item: Bob's pin and MEK are intact without re-pinning!
    space_host.grant_space_member(&convo_space, alice);
    space_host.grant_space_member(&convo_space, bob);
    let mut reopened = alice_d1
        .clone()
        .open()
        .await
        .expect("reopen alice_d1")
        .expect("alice_d1 session present");
    let after_reopen = reopened
        .archive_conversation(
            conv_id,
            std::slice::from_ref(&bob.to_owned()),
            &[(
                "msg-crash-2".to_owned(),
                1_700_000_011_000,
                b"after reopen".to_vec(),
            )],
        )
        .await
        .expect("try_finish after reopen");
    assert!(after_reopen.is_ok(), "archive after reopen must succeed");
}

#[tokio::test]
async fn partial_directory_publish_is_durable_visible_and_retried_on_reopen() {
    let alice = "did:plc:alicepublishretry000000000";
    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState::default()));
    let deps = build_deps(
        alice,
        "dev-a1",
        41,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let mut session = deps.clone().enable().await.expect("enable");

    ds_state.lock().unwrap().publish_epoch_failures = 1;
    assert!(session.rotate_epoch().await.is_err());
    assert_eq!(session.pending_directory_epoch(), Some(1));
    assert!(session.directory_publish_attempted());
    assert!(session.directory_publish_error().is_some());
    drop(session);

    let reopened = deps
        .open()
        .await
        .expect("reopen after partial publication")
        .expect("saved session");
    assert_eq!(reopened.pending_directory_epoch(), None);
    assert!(reopened.directory_publish_attempted());
    assert_eq!(reopened.directory_publish_error(), None);
    let state = ds_state.lock().unwrap();
    assert_eq!(
        state
            .heads
            .get(alice)
            .and_then(|heads| heads.last())
            .map(|head| head.epoch_number),
        Some(1)
    );
}

#[tokio::test]
async fn fault_line_2_kick_outbox_fallback_and_cached_history_rescue_import_with_sender_attribution(
) {
    let alice = "did:plc:alicefl20000000000000000";
    let bob = "did:plc:bobfl2000000000000000000";
    let ds_did = "did:web:ds.catbird.test";
    let conv_id = "33333333-4444-4555-8666-777777777777";

    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState {
        conversations: HashMap::from([(
            conv_id.to_owned(),
            (ds_did.to_owned(), vec![alice.to_owned(), bob.to_owned()]),
        )]),
        ..Default::default()
    }));

    let alice_d1 = build_deps(
        alice,
        "dev-a1",
        41,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let bob_d1 = build_deps(
        bob,
        "dev-b1",
        42,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );

    let mut alice_s1 = alice_d1.clone().enable().await.expect("alice enable");
    let _bob_s1 = bob_d1.clone().enable().await.expect("bob enable");
    let recovery_code = alice_s1
        .create_recovery_code()
        .await
        .expect("recovery code");

    // Queue an outbox message on Alice, then kick Alice from both DS conversation roster and Space!
    let queue = MemoryQueueStore::default();
    let row = PendingArchive::new(
        alice,
        conv_id,
        "msg-kicked-outbox",
        1_700_000_020_000,
        b"queued before kick",
    )
    .with_mls_snapshot("bb22", 1, vec![alice.to_owned(), bob.to_owned()]);
    assert!(enqueue(&queue, &row).expect("enqueue"));

    ds_state.lock().unwrap().conversations.insert(
        conv_id.to_owned(),
        (ds_did.to_owned(), vec![bob.to_owned()]),
    );
    let convo_space =
        labyrinth::store::space::SpaceRef::conversation(ds_did, &format!("{conv_id}-0"));
    space_host.revoke_space_member(&convo_space, alice);

    // 1. Outbox flush falls back to owner-mode (`v5` `KIND_ATTRIBUTED_FRAME`) in Alice's personal mailbox Space!
    let report = flush_queue(&mut alice_s1, &alice_d1, &queue)
        .await
        .expect("flush_queue fallback");
    assert_eq!(report.archived, 1);
    assert_eq!(report.failed_conversations, 0);
    assert!(queue.list(alice).unwrap().is_empty());

    // 2. Rescue Bob's locally cached pre-kick message into Alice's personal mailbox Space, preserving `sender_did = bob`!
    let owner_res = alice_s1
        .archive_owner_fallback(
            conv_id,
            &[(
                "msg-bob-cached".to_owned(),
                1_700_000_019_000,
                bob.to_owned(),
                b"from bob before kick".to_vec(),
            )],
        )
        .await
        .expect("archive_owner_fallback finish");
    assert_eq!(owner_res.expect("owner fallback count"), 1);

    // 3. Alice's second device restores via recovery code while still kicked (`Forbidden` on conversation Space)
    // and recovers BOTH messages from her personal mailbox with exact sender attribution (`bob` vs `alice`)!
    let alice_d2 = build_deps(
        alice,
        "dev-a2",
        43,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let mut alice_s2 = alice_d2
        .restore_with_recovery_code(&recovery_code)
        .await
        .expect("alice_d2 restore");
    let hist = alice_s2
        .load_history(conv_id, TimeRange::ALL)
        .await
        .expect("load_history on kicked conversation");
    assert_eq!(hist.messages.len(), 2);
    assert_eq!(hist.messages[0].message_id, "msg-bob-cached");
    assert_eq!(hist.messages[0].sender.as_deref(), Some(bob));
    assert_eq!(hist.messages[0].frame, b"from bob before kick");
    assert_eq!(hist.messages[1].message_id, "msg-kicked-outbox");
    assert_eq!(hist.messages[1].sender.as_deref(), Some(alice));
    assert_eq!(hist.messages[1].frame, b"queued before kick");
}

#[tokio::test]
async fn fault_line_3_session_heals_unanchored_squatted_epoch_and_preserves_anchored_revocation_quarantine(
) {
    use labyrinth::store::space::SpaceRpc as _;

    let alice = "did:plc:alicefl30000000000000000";
    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState::default()));

    let alice_d1 = build_deps(
        alice,
        "dev-a1",
        51,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let mut alice_s1 = alice_d1.clone().enable().await.expect("alice enable");
    let recovery_code = alice_s1
        .create_recovery_code()
        .await
        .expect("create_recovery_code at genesis epoch 0");
    assert_eq!(alice_s1.latest_epoch(), 0);

    // Inject an unanchored squatted `epoch/000000000001` into Alice's personal mailbox Space
    // (simulating an aborted rotation or rogue unanchored write `[CB-40]`).
    let mailbox_space = labyrinth::store::space::SpaceRef::mailbox(alice);
    let mut squatted_val = space_host
        .record(
            &mailbox_space,
            alice,
            labyrinth::records::nsid::EPOCH,
            "000000000000",
        )
        .expect("genesis epoch 0 present");
    squatted_val["epochNumber"] = serde_json::json!(1);
    squatted_val["signatureDeviceId"] = serde_json::json!("rogue000000000000000000000000000");
    space_host
        .client(alice)
        .procedure(
            "com.atproto.space.applyWrites",
            &serde_json::to_vec(&serde_json::json!({
                "repo": alice,
                "space": mailbox_space.to_string(),
                "writes": [{
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": labyrinth::records::nsid::EPOCH,
                    "rkey": "000000000001",
                    "value": squatted_val
                }]
            }))
            .unwrap(),
        )
        .await
        .expect("inject squatted epoch 1");

    // Restoring `alice_d2` automatically heals the unanchored squat at epoch 1 and rotates cleanly!
    let alice_d2 = build_deps(
        alice,
        "dev-a2",
        52,
        ds_state.clone(),
        &space_host,
        &pds_host,
        None,
    );
    let mut alice_s2 = alice_d2
        .restore_with_recovery_code(&recovery_code)
        .await
        .expect("restore_with_recovery_code heals squatted epoch 1 and rotates cleanly");
    assert!(alice_s2.latest_epoch() >= 1);

    // Now legitimately revoke `alice_d1` from `alice_s2` (anchoring the new epoch in PDS + DS).
    let d1_key = alice_s1.device_key_pub();
    let new_ep = alice_s2
        .revoke_device(d1_key)
        .await
        .expect("legitimate revoke_device");

    // `alice_d1.open()` MUST quarantine (fail with `Err`) and MUST NOT delete the anchored revocation epoch!
    let open_res = alice_d1.clone().open().await;
    assert!(
        open_res.is_err(),
        "revoked device must error on open, never delete anchored epoch"
    );
    assert!(
        space_host
            .record(
                &mailbox_space,
                alice,
                labyrinth::records::nsid::EPOCH,
                &format!("{:012}", new_ep.new_epoch),
            )
            .is_some(),
        "directory-anchored revocation epoch must remain intact in Space"
    );
}

#[tokio::test]
async fn fault_line_5_federated_ds_directory_resolves_per_thread_sequencer_and_did_doc_receipt_keys(
) {
    use labyrinth::store::{MailboxDirectory as _, SequencerReceiptKey};
    use p256::ecdsa::SigningKey as P256SigningKey;

    let alice = "did:plc:alicefl50000000000000000";
    let home_ds = "did:web:home-ds.catbird.test";
    let foreign_ds = "did:web:foreign-ds.catbird.test";
    let unknown_ds = "did:web:unknown-ds.catbird.test";
    let home_conv = "conv-home-1";
    let foreign_conv = "conv-foreign-2";
    let unknown_conv = "conv-unknown-3";

    let home_p256_sk = P256SigningKey::from_bytes((&[62u8; 32]).into()).unwrap();
    let home_p256: [u8; 33] = home_p256_sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    let foreign_p256_sk = P256SigningKey::from_bytes((&[72u8; 32]).into()).unwrap();
    let foreign_p256: [u8; 33] = foreign_p256_sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    // Encode foreign DS `#mls-receipt-1` (`[0x80, 0x24]` + 33-byte SEC1 P-256) as
    // `Multikey` (`Base58Btc`).
    let mut p256_mc = Vec::with_capacity(35);
    p256_mc.extend_from_slice(&[0x80, 0x24]);
    p256_mc.extend_from_slice(&foreign_p256);
    let foreign_receipt_mb = multibase::encode(multibase::Base::Base58Btc, &p256_mc);

    let foreign_did_doc = serde_json::json!({
        "id": foreign_ds,
        "verificationMethod": [
            {
                "id": format!("{foreign_ds}#mls-receipt-1"),
                "type": "Multikey",
                "controller": foreign_ds,
                "publicKeyMultibase": foreign_receipt_mb,
            },
        ]
    });

    let ds_state = Arc::new(Mutex::new(MockDsState {
        conversations: HashMap::from([
            (
                home_conv.to_owned(),
                (home_ds.to_owned(), vec![alice.to_owned()]),
            ),
            (
                foreign_conv.to_owned(),
                (foreign_ds.to_owned(), vec![alice.to_owned()]),
            ),
            (
                unknown_conv.to_owned(),
                (unknown_ds.to_owned(), vec![alice.to_owned()]),
            ),
        ]),
        did_docs: HashMap::from([(
            foreign_ds.to_owned(),
            serde_json::to_vec(&foreign_did_doc).unwrap(),
        )]),
        ..Default::default()
    }));

    let signer = Arc::new(TestChatSigner::from_seed(88));
    let gw = Arc::new(MockSixEndpointGateway {
        actor_did: alice.to_owned(),
        state: ds_state,
    });
    let transport = Arc::new(GatewayXrpcTransport::new(
        gw,
        signer,
        alice.to_owned(),
        "dev-fl5".to_owned(),
    ));

    let home_rcpt_key = SequencerReceiptKey {
        did: home_ds.to_owned(),
        public_key_sec1: home_p256.to_vec(),
    };
    let dir = super::transport::DsDirectoryStore::new(transport, Some(home_rcpt_key.clone()));

    // Home conversation resolves the home DS receipt key.
    assert_eq!(
        dir.sequencer_receipt_key(home_conv).await.unwrap(),
        Some(home_rcpt_key)
    );

    // Federated conversation resolves foreign DS's DID document Multikeys, NOT home DS keys!
    assert_eq!(
        dir.sequencer_receipt_key(foreign_conv).await.unwrap(),
        Some(SequencerReceiptKey {
            did: foreign_ds.to_owned(),
            public_key_sec1: foreign_p256.to_vec(),
        })
    );

    // Unknown federated DS with unresolvable DID doc MUST return `None`, NEVER falling back to home DS!
    assert_eq!(dir.sequencer_receipt_key(unknown_conv).await.unwrap(), None);
}

#[tokio::test]
async fn fault_line_5_did_document_url_ssrf_and_fail_closed_on_403_503_with_placement_recovery() {
    use labyrinth::store::{MailboxDirectory as _, SequencerReceiptKey};
    use p256::ecdsa::SigningKey as P256SigningKey;

    use super::space::{thread_placement_key, ThreadPlacement};
    use super::transport::did_document_url;

    // 1. Validate SSRF-hardened `did_document_url`.
    assert_eq!(
        did_document_url("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap(),
        "https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur"
    );
    assert_eq!(
        did_document_url("did:web:foreign-ds.catbird.test").unwrap(),
        "https://foreign-ds.catbird.test/.well-known/did.json"
    );
    assert_eq!(
        did_document_url("did:web:foreign-ds.catbird.test%3A443").unwrap(),
        "https://foreign-ds.catbird.test/.well-known/did.json"
    );
    assert_eq!(
        did_document_url("did:web:foreign-ds.catbird.test:services:mls").unwrap(),
        "https://foreign-ds.catbird.test/services/mls/did.json"
    );
    for bad in [
        "did:web:localhost",
        "did:web:127.0.0.1",
        "did:web:169.254.169.254",
        "did:web:metadata.internal",
        "did:web:printer.local",
        "did:web:evil.example%3A8080",
        "did:web:user@evil.example",
        "did:web:evil.example:..",
        "did:web:evil.example:%2e%2e",
        "did:web:evil.example:foo%2fbar",
        "did:plc:short",
        "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
    ] {
        assert!(
            did_document_url(bad).is_err(),
            "expected SSRF/malformed DID rejection for {bad}"
        );
    }

    // 2. Custom gateway simulating 503 outage and 403 post-kick on `getConversationState`.
    struct StatusGateway {
        status: u16,
        foreign_did: String,
        foreign_doc: Vec<u8>,
    }
    #[async_trait::async_trait]
    impl LabyrinthGateway for StatusGateway {
        async fn submit_labyrinth(
            &self,
            _request: LabyrinthRequest,
        ) -> Result<GatewayResponse, String> {
            Err("unused".into())
        }
        async fn submit_canonical(
            &self,
            _request: PreparedRequest,
            _headers: Vec<(String, String)>,
        ) -> Result<GatewayResponse, String> {
            let body = if self.status == 403 {
                br#"{"error":"Forbidden","message":"removed from conversation"}"#.to_vec()
            } else {
                br#"{"error":"ServiceUnavailable","message":"ds down"}"#.to_vec()
            };
            Ok(GatewayResponse {
                status: self.status,
                content_type: Some("application/json".into()),
                body,
            })
        }
        async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
            if did == self.foreign_did {
                Ok(Some(self.foreign_doc.clone()))
            } else {
                Ok(None)
            }
        }
    }

    let alice = "did:plc:alicefl5hard000000000000";
    let home_ds = "did:web:home-ds.catbird.test";
    let foreign_ds = "did:web:foreign-ds.catbird.test";
    let kicked_conv = "conv-foreign-kicked";

    let home_p256 = P256SigningKey::from_bytes((&[0x32u8; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let foreign_p256 = P256SigningKey::from_bytes((&[0x42u8; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let mut p256_mc = vec![0x80, 0x24];
    p256_mc.extend_from_slice(&foreign_p256);
    let foreign_doc = serde_json::to_vec(&serde_json::json!({
        "id": foreign_ds,
        "verificationMethod": [
            {
                "id": format!("{foreign_ds}#mls-receipt-1"),
                "type": "Multikey",
                "controller": foreign_ds,
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, &p256_mc),
            }
        ]
    }))
    .unwrap();

    let home_rcpt = SequencerReceiptKey {
        did: home_ds.to_owned(),
        public_key_sec1: home_p256,
    };

    // Case A: 503 outage on `getConversationState` MUST propagate `Err`, NEVER returning home DS keys!
    let signer = Arc::new(TestChatSigner::from_seed(91));
    let transport_503 = Arc::new(GatewayXrpcTransport::new(
        Arc::new(StatusGateway {
            status: 503,
            foreign_did: foreign_ds.to_owned(),
            foreign_doc: foreign_doc.clone(),
        }),
        signer.clone(),
        alice.to_owned(),
        "dev-503".into(),
    ));
    let dir_503 = super::transport::DsDirectoryStore::new(transport_503, Some(home_rcpt.clone()));
    assert!(dir_503.sequencer_receipt_key(kicked_conv).await.is_err());

    // Case B: 403 Forbidden WITHOUT saved ThreadPlacement MUST return `Ok(None)`, NEVER home DS keys!
    let transport_403 = Arc::new(GatewayXrpcTransport::new(
        Arc::new(StatusGateway {
            status: 403,
            foreign_did: foreign_ds.to_owned(),
            foreign_doc: foreign_doc.clone(),
        }),
        signer,
        alice.to_owned(),
        "dev-403".into(),
    ));
    let empty_placements: Arc<dyn StateVault> = Arc::new(MemoryVault::default());
    let dir_403_no_pin =
        super::transport::DsDirectoryStore::new(transport_403.clone(), Some(home_rcpt.clone()))
            .with_placements(alice, empty_placements);
    assert_eq!(
        dir_403_no_pin
            .sequencer_receipt_key(kicked_conv)
            .await
            .unwrap(),
        None
    );

    // Case C: 403 Forbidden WITH saved foreign conversation Space ThreadPlacement recovers
    // `foreign_ds` and resolves the foreign DS's DID document keys after kick!
    let pinned_placements = Arc::new(MemoryVault::default());
    let mut pins = std::collections::BTreeMap::new();
    pins.insert(
        kicked_conv.to_owned(),
        ThreadPlacement {
            space: Some(format!(
                "at:space/{foreign_ds}/blue.catbird.labyrinth.conversation/{kicked_conv}-0"
            )),
            generation: 0,
            group_id: None,
        },
    );
    pinned_placements
        .compare_exchange(
            &thread_placement_key(alice),
            None,
            &serde_json::to_vec(&pins).unwrap(),
        )
        .unwrap();

    let dir_403_pinned = super::transport::DsDirectoryStore::new(transport_403, Some(home_rcpt))
        .with_placements(alice, pinned_placements);
    assert_eq!(
        dir_403_pinned
            .sequencer_receipt_key(kicked_conv)
            .await
            .unwrap(),
        Some(SequencerReceiptKey {
            did: foreign_ds.to_owned(),
            public_key_sec1: foreign_p256,
        })
    );
}

#[tokio::test]
async fn fault_line_2_transient_pds_outage_during_deleted_convo_owner_rescue_retains_rows() {
    use labyrinth::store::space::{SpaceError, SpaceRpc};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FlakyWriteSpaceRpc {
        inner: Arc<dyn SpaceRpc>,
        fail_writes: Arc<AtomicBool>,
    }
    #[async_trait::async_trait]
    impl SpaceRpc for FlakyWriteSpaceRpc {
        async fn query(
            &self,
            nsid: &str,
            params: &[(&str, String)],
        ) -> Result<Vec<u8>, SpaceError> {
            self.inner.query(nsid, params).await
        }
        async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(SpaceError::named(
                    503,
                    "ServiceUnavailable",
                    "transient PDS Space outage",
                ));
            }
            self.inner.procedure(nsid, payload).await
        }
    }

    let alice = "did:plc:alicefl2pds5030000000000";
    let gone_conv = "99999999-8888-4777-8666-555555555555";
    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState::default())); // `gone_conv` returns 404 ConversationNotFound

    let fail_writes = Arc::new(AtomicBool::new(false));
    let mut alice_deps = build_deps(alice, "dev-a1", 61, ds_state, &space_host, &pds_host, None);
    alice_deps.space = Some(Arc::new(FlakyWriteSpaceRpc {
        inner: Arc::new(space_host.client(alice)),
        fail_writes: fail_writes.clone(),
    }));

    let mut session = alice_deps.clone().enable().await.expect("enable");
    let queue = MemoryQueueStore::default();
    let row = PendingArchive::new(
        alice,
        gone_conv,
        "msg-deleted-convo-503",
        1_700_000_099_000,
        b"do not drop me on pds 503",
    )
    .with_mls_snapshot("9988", 1, vec![alice.to_owned()]);
    assert!(enqueue(&queue, &row).unwrap());

    // Simulate transient PDS outage while `gone_conv` is 404 on mls-ds:
    fail_writes.store(true, Ordering::SeqCst);
    let report_fail = flush_queue(&mut session, &alice_deps, &queue)
        .await
        .expect("flush_queue handles transient pds error without dropping");
    assert_eq!(
        report_fail.dropped, 0,
        "transient PDS outage must NEVER drop queued rows"
    );
    assert_eq!(report_fail.quarantined, 0);
    assert_eq!(report_fail.archived, 0);
    assert_eq!(report_fail.failed_conversations, 1);
    assert_eq!(queue.list(alice).unwrap().len(), 1);

    // When PDS recovers, retry rescues the row into Alice's personal mailbox Space!
    fail_writes.store(false, Ordering::SeqCst);
    let report_ok = flush_queue(&mut session, &alice_deps, &queue)
        .await
        .expect("retry flush_queue succeeds");
    assert_eq!(report_ok.archived, 1);
    assert_eq!(report_ok.dropped, 0);
    assert!(queue.list(alice).unwrap().is_empty());

    // The conversation no longer exists, so only the owner archive is readable (a missing
    // active Space is an error for `load_history`).
    let hist = session
        .load_owner_history(gone_conv)
        .await
        .expect("load rescued history");
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].frame, b"do not drop me on pds 503");
}

/// A PDS that has no mailbox Space until `createSpace`, as the Spaces reference PDS and
/// Swan both behave: reads and writes of a Space that was never created answer
/// `SpaceNotFound`.
struct UncreatedMailboxRpc {
    inner: Arc<dyn labyrinth::store::space::SpaceRpc>,
    created: std::sync::atomic::AtomicBool,
    /// Every `createSpace` body received, in order.
    creations: Mutex<Vec<serde_json::Value>>,
    /// Calls other than `createSpace` that arrived before the Space existed.
    early_calls: Mutex<Vec<String>>,
    /// When set, `createSpace` is refused with this error name.
    refuse_create: Option<&'static str>,
}

impl UncreatedMailboxRpc {
    fn new(inner: Arc<dyn labyrinth::store::space::SpaceRpc>) -> Self {
        Self {
            inner,
            created: std::sync::atomic::AtomicBool::new(false),
            creations: Mutex::new(Vec::new()),
            early_calls: Mutex::new(Vec::new()),
            refuse_create: None,
        }
    }

    fn missing(&self, nsid: &str) -> Option<labyrinth::store::space::SpaceError> {
        if self.created.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        self.early_calls.lock().unwrap().push(nsid.to_owned());
        Some(labyrinth::store::space::SpaceError::named(
            400,
            "SpaceNotFound",
            "Space not found",
        ))
    }
}

#[async_trait::async_trait]
impl labyrinth::store::space::SpaceRpc for UncreatedMailboxRpc {
    async fn query(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<u8>, labyrinth::store::space::SpaceError> {
        if let Some(error) = self.missing(nsid) {
            return Err(error);
        }
        self.inner.query(nsid, params).await
    }

    async fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, labyrinth::store::space::SpaceError> {
        use labyrinth::store::space::SpaceError;
        use std::sync::atomic::Ordering;

        if nsid == "com.atproto.space.createSpace" {
            let body: serde_json::Value =
                serde_json::from_slice(payload).expect("createSpace body is JSON");
            self.creations.lock().unwrap().push(body);
            if let Some(code) = self.refuse_create {
                return Err(SpaceError::named(400, code, "refused"));
            }
            if self.created.swap(true, Ordering::SeqCst) {
                return Err(SpaceError::named(
                    400,
                    "SpaceAlreadyExists",
                    "Space already exists",
                ));
            }
            return Ok(
                br#"{"space":"at:space/did:plc:fixture/blue.catbird.labyrinth.mailbox/self"}"#
                    .to_vec(),
            );
        }
        if let Some(error) = self.missing(nsid) {
            return Err(error);
        }
        self.inner.procedure(nsid, payload).await
    }
}

fn mailbox_space_deps(did: &str, seed: u8) -> (SessionDeps, Arc<UncreatedMailboxRpc>) {
    let space_host = MemorySpaceHost::default();
    let pds_host = MemoryPublicRepoHost::default();
    let ds_state = Arc::new(Mutex::new(MockDsState::default()));
    let deps = build_deps(did, "dev-m1", seed, ds_state, &space_host, &pds_host, None);
    let rpc = Arc::new(UncreatedMailboxRpc::new(
        deps.space.clone().expect("fixture has a Space client"),
    ));
    (deps, rpc)
}

#[tokio::test]
async fn enable_creates_the_personal_mailbox_space_before_using_it() {
    let did = "did:plc:mailboxspaceowner00000000000";
    let (mut deps, rpc) = mailbox_space_deps(did, 61);
    deps.space = Some(rpc.clone());

    deps.clone()
        .enable()
        .await
        .expect("a new account enables its backup on a PDS with no mailbox Space yet");

    assert_eq!(
        *rpc.creations.lock().unwrap(),
        vec![serde_json::json!({
            "spaceType": "blue.catbird.labyrinth.mailbox",
            "skey": "self",
            "policy": { "$type": "com.atproto.personalspace.policy" },
        })],
        "exactly one owner-only mailbox Space is created, keyed `self`"
    );
    assert!(
        rpc.early_calls.lock().unwrap().is_empty(),
        "nothing reads or writes the mailbox before it exists: {:?}",
        rpc.early_calls.lock().unwrap()
    );
    assert_eq!(deps.list_mailbox_devices().await.unwrap().len(), 1);
}

#[tokio::test]
async fn enable_accepts_a_mailbox_space_that_already_exists() {
    let did = "did:plc:mailboxspaceexists0000000000";
    let (mut deps, rpc) = mailbox_space_deps(did, 62);
    // The Space exists (another device, or an earlier attempt, created it) but is empty.
    rpc.created.store(true, std::sync::atomic::Ordering::SeqCst);
    deps.space = Some(rpc.clone());

    deps.clone()
        .enable()
        .await
        .expect("`SpaceAlreadyExists` is not a failure");

    assert_eq!(rpc.creations.lock().unwrap().len(), 1);
    assert_eq!(deps.list_mailbox_devices().await.unwrap().len(), 1);
}

#[tokio::test]
async fn enable_reports_a_refused_mailbox_space_creation_and_writes_nothing() {
    let did = "did:plc:mailboxspacerefused000000000";
    let (mut deps, rpc) = mailbox_space_deps(did, 63);
    let mut refusing = UncreatedMailboxRpc::new(rpc.inner.clone());
    refusing.refuse_create = Some("NotAuthorized");
    let refusing = Arc::new(refusing);
    deps.space = Some(refusing.clone());

    let error = deps
        .clone()
        .enable()
        .await
        .err()
        .expect("a refused createSpace fails enable");

    let text = error.to_string();
    assert!(
        text.contains("createSpace") && text.contains("NotAuthorized"),
        "the failure names the step and the server's reason: {text}"
    );
    assert!(
        refusing.early_calls.lock().unwrap().is_empty(),
        "nothing is read or written after a refused creation: {:?}",
        refusing.early_calls.lock().unwrap()
    );
}
