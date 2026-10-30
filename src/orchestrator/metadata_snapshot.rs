//! One metadata snapshot codec for every transition that opens or re-seals the
//! server's `metadataSnapshot`.
//!
//! Two schemes exist. Ordinary groups, and every snapshot re-authored by a
//! later transition, use the legacy `crate::metadata` scheme. The request
//! bootstrap seals with the canonical scheme (`direct_request_bootstrap`), and
//! that chain keeps it for as long as later transitions re-seal it under the
//! same origin. The server state records which one applies: a snapshot whose
//! origin is the conversation's direct request id was sealed by the bootstrap.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::direct_request_bootstrap as canonical;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use crate::error::MLSError;
use crate::metadata::GroupMetadataV1;

/// The codec a snapshot was sealed with, as recorded by the server state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MetadataScheme {
    Legacy,
    Canonical { origin_transition_id: String },
}

impl MetadataScheme {
    /// `state` is a conversation state (`getConversationState.state` or an
    /// inventory item's state) carrying `metadataSnapshot`.
    pub(crate) fn recorded(state: &Value) -> Self {
        let snapshot = &state["metadataSnapshot"];
        let origin = snapshot["originTransitionId"]
            .as_str()
            .or_else(|| snapshot["authorProof"]["originTransitionId"].as_str());
        match (origin, state["directRequest"]["requestId"].as_str()) {
            (Some(origin), Some(request)) if origin == request => MetadataScheme::Canonical {
                origin_transition_id: origin.to_owned(),
            },
            _ => MetadataScheme::Legacy,
        }
    }
}

/// A decrypted snapshot that remembers how to re-seal itself unchanged.
#[derive(Debug, Clone)]
pub(crate) struct OpenedMetadata {
    pub(crate) metadata: GroupMetadataV1,
    pub(crate) version: u64,
    sealed: Sealed,
}

#[derive(Debug, Clone)]
enum Sealed {
    Legacy,
    Canonical {
        origin_transition_id: String,
        plaintext: Vec<u8>,
    },
}

/// The successor coordinate a pending commit produces.
pub(crate) struct SuccessorCoordinate<'a> {
    pub(crate) conversation_id: &'a str,
    pub(crate) generation: u64,
    pub(crate) epoch: u64,
    pub(crate) group_context_hash: &'a [u8],
    pub(crate) confirmation_tag: &'a [u8],
}

fn invalid(message: String) -> OrchestratorError {
    OrchestratorError::InvalidInput(message)
}

/// `{"$bytes": b64}` or bare base64.
fn snapshot_bytes(value: &Value, field: &str) -> Result<Vec<u8>> {
    let encoded = value
        .get("$bytes")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())
        .ok_or_else(|| invalid(format!("metadataSnapshot.{field} is not bytes")))?;
    STANDARD
        .decode(encoded)
        .map_err(|error| OrchestratorError::Serialization(format!("metadataSnapshot.{field}: {error}")))
}

fn key32(key: Vec<u8>) -> Result<[u8; 32]> {
    key.try_into().map_err(|_| {
        OrchestratorError::Mls(MLSError::Internal("metadata key length mismatch".into()))
    })
}

fn mls(context: &str, error: impl std::fmt::Debug) -> OrchestratorError {
    OrchestratorError::Mls(MLSError::Internal(format!("{context}: {error:?}")))
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Decrypt `snapshot` (sealed at its own coordinate) with `scheme`.
    pub(crate) fn open_metadata_snapshot(
        &self,
        snapshot: &Value,
        scheme: &MetadataScheme,
        conversation_id: &str,
        group_id: &[u8],
    ) -> Result<OpenedMetadata> {
        let coordinate = &snapshot["coordinate"];
        let epoch = coordinate["epoch"]
            .as_u64()
            .ok_or_else(|| invalid("metadataSnapshot.coordinate.epoch missing".into()))?;
        let version = snapshot["metadataVersion"]
            .as_u64()
            .ok_or_else(|| invalid("metadataSnapshot.metadataVersion missing".into()))?;
        let nonce: [u8; 12] = snapshot_bytes(&snapshot["nonce"], "nonce")?
            .try_into()
            .map_err(|_| invalid("metadataSnapshot.nonce must be 12 bytes".into()))?;
        let ciphertext = snapshot_bytes(&snapshot["ciphertext"], "ciphertext")?;
        match scheme {
            MetadataScheme::Legacy => {
                let key = key32(self.mls_context().export_metadata_key(group_id.to_vec(), epoch)?)?;
                let metadata = crate::metadata::decrypt_metadata_snapshot(
                    &key, group_id, epoch, version, &nonce, &ciphertext,
                )
                .map_err(|error| mls("decrypt prior metadata snapshot", error))?;
                Ok(OpenedMetadata {
                    metadata,
                    version,
                    sealed: Sealed::Legacy,
                })
            }
            MetadataScheme::Canonical {
                origin_transition_id,
            } => {
                let coordinates = canonical::canonical_metadata_coordinates(
                    conversation_id,
                    &snapshot_bytes(&coordinate["groupId"], "coordinate.groupId")?,
                    coordinate["generation"]
                        .as_u64()
                        .ok_or_else(|| invalid("metadataSnapshot.coordinate.generation missing".into()))?,
                    epoch,
                    &snapshot_bytes(&coordinate["groupContextHash"], "coordinate.groupContextHash")?,
                    &snapshot_bytes(&coordinate["confirmationTag"], "coordinate.confirmationTag")?,
                );
                let key = key32(
                    self.mls_context()
                        .export_canonical_metadata_key(group_id.to_vec(), &coordinates)?,
                )?;
                let plaintext = canonical::open_request_metadata(
                    &key,
                    &coordinates,
                    origin_transition_id,
                    &nonce,
                    &ciphertext,
                )
                .map_err(|error| mls("decrypt prior metadata snapshot", error))?;
                Ok(OpenedMetadata {
                    metadata: canonical::decode_request_metadata(&plaintext)?,
                    version,
                    sealed: Sealed::Canonical {
                        origin_transition_id: origin_transition_id.clone(),
                        plaintext,
                    },
                })
            }
        }
    }

    /// Re-seal the unchanged snapshot under the same origin at the successor
    /// coordinate of the group's pending commit.
    pub(crate) fn reseal_metadata_from_pending(
        &self,
        opened: &OpenedMetadata,
        group_id: &[u8],
        successor: &SuccessorCoordinate<'_>,
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        match &opened.sealed {
            Sealed::Legacy => {
                let key = key32(
                    self.mls_context()
                        .export_metadata_key_from_pending(group_id.to_vec(), successor.epoch)?,
                )?;
                crate::metadata::encrypt_metadata_snapshot_with_nonce(
                    &key,
                    group_id,
                    successor.epoch,
                    opened.version,
                    nonce,
                    &opened.metadata,
                )
                .map_err(|error| mls("encrypt successor metadata snapshot", error))
            }
            Sealed::Canonical {
                origin_transition_id,
                plaintext,
            } => {
                let coordinates = canonical::canonical_metadata_coordinates(
                    successor.conversation_id,
                    group_id,
                    successor.generation,
                    successor.epoch,
                    successor.group_context_hash,
                    successor.confirmation_tag,
                );
                let key = key32(
                    self.mls_context()
                        .export_canonical_metadata_key_from_pending(group_id.to_vec(), &coordinates)?,
                )?;
                canonical::seal_request_metadata(
                    &key,
                    &coordinates,
                    origin_transition_id,
                    nonce,
                    plaintext,
                )
                .map_err(|error| mls("encrypt successor metadata snapshot", error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_e2e_harness::TestWorld;
    use crate::KeyPackageData;
    use serde_json::json;

    const REQUEST: &str = "6f1e7b1c-2d4a-4c1b-9a51-3f1c7e0a9b21";

    fn b(bytes: &[u8]) -> Value {
        json!({ "$bytes": STANDARD.encode(bytes) })
    }

    /// A server-shaped snapshot sealed at the group's current coordinate.
    fn snapshot(cid: &str, gid: &[u8], epoch: u64, gch: &[u8], tag: &[u8], nonce: &[u8; 12], ct: &[u8], origin: &str) -> Value {
        let cid_bytes = uuid::Uuid::parse_str(cid).unwrap();
        json!({
            "coordinate": {"conversationId": STANDARD.encode(cid_bytes.as_bytes()), "groupId": b(gid),
                "generation": 0, "epoch": epoch, "groupContextHash": b(gch), "confirmationTag": b(tag)},
            "metadataVersion": 1, "nonce": b(nonce), "ciphertext": b(ct), "originTransitionId": origin
        })
    }

    fn signed_plaintext(title: &str) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Content<'a> {
            protocol: &'a str,
            title: &'a str,
            description: &'a str,
        }
        #[derive(serde::Serialize)]
        struct Signed<'a> {
            content: Content<'a>,
            #[serde(rename = "contentSignature")]
            content_signature: String,
        }
        serde_ipld_dagcbor::to_vec(&Signed {
            content: Content { protocol: "blue.catbird.chat.metadata", title, description: "first contact" },
            content_signature: STANDARD.encode([7u8; 64]),
        })
        .unwrap()
    }

    /// Alice's real group plus Bob's real KeyPackage, both from their own
    /// MLS contexts; the conversation id is the one the state names.
    async fn world() -> (TestWorld, String, Vec<u8>, KeyPackageData, String) {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world.add_client("Bob").await;
        world.register_device("Alice").await.unwrap();
        world.register_device("Bob").await.unwrap();
        let created = world.client("Alice").orchestrator.create_group("t", None, None).await.unwrap();
        let bob = world.client("Bob");
        let bob_identity = format!("{}#{}", bob.did, bob.orchestrator.require_actor_device_id().await.unwrap());
        let package = bob.orchestrator.mls_context().create_key_package(bob_identity.as_bytes().to_vec()).unwrap();
        let gid = hex::decode(&created.group_id).unwrap();
        (world, created.conversation_id.to_string(), gid, KeyPackageData { data: package.key_package_data }, bob_identity)
    }

    #[test]
    fn recorded_scheme_follows_the_request_origin() {
        let snapshot = |origin: &str| json!({"metadataSnapshot": {"originTransitionId": origin}});
        let mut request = snapshot(REQUEST);
        request["directRequest"] = json!({"requestId": REQUEST});
        assert_eq!(
            MetadataScheme::recorded(&request),
            MetadataScheme::Canonical { origin_transition_id: REQUEST.into() }
        );
        // A later transition re-authored the snapshot under its own origin.
        let mut reauthored = snapshot("11111111-2222-4333-8444-555555555555");
        reauthored["directRequest"] = json!({"requestId": REQUEST});
        assert_eq!(MetadataScheme::recorded(&reauthored), MetadataScheme::Legacy);
        // Ordinary groups carry no direct request.
        assert_eq!(MetadataScheme::recorded(&snapshot(REQUEST)), MetadataScheme::Legacy);
    }

    /// Request-born snapshot through a real Add Commit (the leaf-recovery
    /// fulfillment shape): open with the recorded canonical codec, re-seal the
    /// unchanged signed plaintext from the pending commit at the successor
    /// coordinate, and the joined member opens it from its own context.
    #[tokio::test(flavor = "multi_thread")]
    async fn canonical_snapshot_survives_add_commit_and_joiner_opens_it() {
        let (world, cid, gid, package, bob_identity) = world().await;
        let alice = &world.client("Alice").orchestrator;
        let ctx = alice.mls_context();
        let epoch = ctx.get_epoch(gid.clone()).unwrap();
        let gch = ctx.get_group_context_hash(gid.clone()).unwrap();
        let tag = ctx.get_confirmation_tag(gid.clone()).unwrap();
        let coords = canonical::canonical_metadata_coordinates(&cid, &gid, 0, epoch, &gch, &tag);
        let key: [u8; 32] = ctx.export_canonical_metadata_key(gid.clone(), &coords).unwrap().try_into().unwrap();
        let plaintext = signed_plaintext("Request title");
        let nonce = [1; 12];
        let ct = canonical::seal_request_metadata(&key, &coords, REQUEST, &nonce, &plaintext).unwrap();
        let prior = snapshot(&cid, &gid, epoch, &gch, &tag, &nonce, &ct, REQUEST);
        let state = json!({"metadataSnapshot": prior, "directRequest": {"requestId": REQUEST}});

        // The pre-fix path: the legacy codec cannot open a request-born snapshot.
        assert!(alice.open_metadata_snapshot(&prior, &MetadataScheme::Legacy, &cid, &gid).is_err());
        let opened = alice
            .open_metadata_snapshot(&prior, &MetadataScheme::recorded(&state), &cid, &gid)
            .unwrap();
        assert_eq!(opened.metadata.title, "Request title");
        assert_eq!(opened.metadata.description, "first contact");

        let added = ctx.add_members_with_aad(gid.clone(), vec![package], None).unwrap();
        let next_gch = added.next_group_context_hash.unwrap();
        let next_tag = added.next_confirmation_tag.unwrap();
        let next_nonce = [2; 12];
        let resealed = alice
            .reseal_metadata_from_pending(
                &opened,
                &gid,
                &SuccessorCoordinate {
                    conversation_id: &cid,
                    generation: 0,
                    epoch: epoch + 1,
                    group_context_hash: &next_gch,
                    confirmation_tag: &next_tag,
                },
                &next_nonce,
            )
            .unwrap();
        assert_eq!(resealed.len(), ct.len(), "same plaintext, same size");
        ctx.merge_pending_commit(gid.clone()).unwrap();

        let bob = &world.client("Bob").orchestrator;
        bob.mls_context()
            .process_welcome(added.welcome_data, bob_identity.into_bytes(), None)
            .unwrap();
        assert_eq!(bob.mls_context().get_epoch(gid.clone()).unwrap(), epoch + 1);
        let successor = snapshot(&cid, &gid, epoch + 1, &next_gch, &next_tag, &next_nonce, &resealed, REQUEST);
        let reopened = bob
            .open_metadata_snapshot(
                &successor,
                &MetadataScheme::Canonical { origin_transition_id: REQUEST.into() },
                &cid,
                &gid,
            )
            .unwrap();
        assert_eq!(reopened.metadata, opened.metadata);
        match (&opened.sealed, &reopened.sealed) {
            (Sealed::Canonical { plaintext: a, .. }, Sealed::Canonical { plaintext: b, .. }) => {
                assert_eq!(a, b, "signed plaintext carried unchanged");
                assert_eq!(a, &plaintext);
            }
            other => panic!("expected canonical on both sides, got {other:?}"),
        }
    }

    /// Ordinary groups keep the legacy codec end to end.
    #[tokio::test(flavor = "multi_thread")]
    async fn legacy_snapshot_round_trip_is_unchanged() {
        let (world, cid, gid, package, bob_identity) = world().await;
        let alice = &world.client("Alice").orchestrator;
        let ctx = alice.mls_context();
        let epoch = ctx.get_epoch(gid.clone()).unwrap();
        let gch = ctx.get_group_context_hash(gid.clone()).unwrap();
        let tag = ctx.get_confirmation_tag(gid.clone()).unwrap();
        let metadata = GroupMetadataV1 {
            version: 1,
            title: "Ordinary".into(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        };
        let key: [u8; 32] = ctx.export_metadata_key(gid.clone(), epoch).unwrap().try_into().unwrap();
        let nonce = [3; 12];
        let ct = crate::metadata::encrypt_metadata_snapshot_with_nonce(&key, &gid, epoch, 1, &nonce, &metadata).unwrap();
        let prior = snapshot(&cid, &gid, epoch, &gch, &tag, &nonce, &ct, "11111111-2222-4333-8444-555555555555");
        let scheme = MetadataScheme::recorded(&json!({"metadataSnapshot": prior}));
        assert_eq!(scheme, MetadataScheme::Legacy);
        let opened = alice.open_metadata_snapshot(&prior, &scheme, &cid, &gid).unwrap();
        assert_eq!(opened.metadata, metadata);

        let added = ctx.add_members_with_aad(gid.clone(), vec![package], None).unwrap();
        let next_gch = added.next_group_context_hash.unwrap();
        let next_tag = added.next_confirmation_tag.unwrap();
        let resealed = alice
            .reseal_metadata_from_pending(
                &opened,
                &gid,
                &SuccessorCoordinate {
                    conversation_id: &cid,
                    generation: 0,
                    epoch: epoch + 1,
                    group_context_hash: &next_gch,
                    confirmation_tag: &next_tag,
                },
                &[4; 12],
            )
            .unwrap();
        ctx.merge_pending_commit(gid.clone()).unwrap();
        let bob = &world.client("Bob").orchestrator;
        bob.mls_context()
            .process_welcome(added.welcome_data, bob_identity.into_bytes(), None)
            .unwrap();
        let successor = snapshot(&cid, &gid, epoch + 1, &next_gch, &next_tag, &[4; 12], &resealed, "x");
        let reopened = bob
            .open_metadata_snapshot(&successor, &MetadataScheme::Legacy, &cid, &gid)
            .unwrap();
        assert_eq!(reopened.metadata, metadata);
    }
}
