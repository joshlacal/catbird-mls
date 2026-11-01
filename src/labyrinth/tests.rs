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

struct MockDsState {
    heads: HashMap<String, Vec<EpochPublicDef>>,
    chat_keys: HashMap<String, Vec<[u8; 32]>>,
    conversations: HashMap<String, (String, Vec<String>)>,
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
            "blue.catbird.labyrinth.publishEpochHead" => {
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

    async fn submit_canonical(&self, request: PreparedRequest) -> Result<GatewayResponse, String> {
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
    SessionDeps {
        did: did.to_owned(),
        transport: Arc::new(GatewayXrpcTransport::new(
            gw,
            signer.clone(),
            did.to_owned(),
            device_id.to_owned(),
        )),
        signer,
        vault: Arc::new(MemoryVault::default()),
        pds: Some(Arc::new(pds_host.client(did))),
        space: Some(Arc::new(space_host.client(did))),
        placements: Arc::new(MemoryVault::default()),
        local_authority,
        sequencer_key: None,
        sequencer_receipt_key: None,
        default_conversation_authority_did: None,
    }
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
        heads: HashMap::new(),
        chat_keys: HashMap::new(),
        conversations: HashMap::from([(
            conv_id.to_owned(),
            (ds_did.to_owned(), vec![alice.to_owned(), bob.to_owned()]),
        )]),
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
