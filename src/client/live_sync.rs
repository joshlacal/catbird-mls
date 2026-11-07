//! Live `sync()` reconciliation engine for `CatbirdMlsClient` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`, `C33`).
//!
//! Executes strictly outside `MlsAccountDb::write_tx` (`I6`) across four phases:
//! 1. `getConversations` -> `C33` direct-request Welcome/introduction import + pending group invite acceptance.
//! 2. `getPendingWelcomes` -> `StagedWelcome` join as the Welcome of its verified `leafRecoveryFulfillmentEntry` + `acknowledgeWelcome`.
//! 3. `getConversationState.pendingLeafRecoveryRequests` -> `I4`-verified `add_members` commit + `#leafRecoveryFulfillmentBody`.
//! 4. `getEntries` -> `I2`-ordered entries, each verified under its kind's authority before any effect + `I14` `acknowledge_entries_up_to`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use crate::chat_v2::transcript::SignedMutationKind;
use crate::client::chat_wire;
use crate::client::chat_wire::verify_signed_mutation_body;
use crate::client::traits::PlatformChangeEvent;
use crate::client::QueuedLabyrinthArchivePayload;
use crate::error::MLSError;
use crate::messaging::receive::{
    extract_plaintext_body_and_verify_aad, handle_account_deleted_event,
    verify_application_aad_archive_evidence,
};
use crate::metadata::derive_metadata_key_from_group;
use crate::orchestrator::canonical_transport::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use crate::orchestrator::direct_request_bootstrap::{
    DirectRequestBootstrap, DirectRequestIntroductionResult, DirectRequestWelcomeInput,
    C33_OPENING_UNAVAILABLE,
};
use crate::orchestrator::direct_request_shared_crypto::decrypt_introduction_with_provider;
use crate::push::processor::NATIVE_ARCHIVE_RECEIPT_OP;
use crate::push::{root_did_from_credential_bytes, AuthorizedPeerDeviceKey};
use crate::storage::driver_native::map_rusqlite_err;
use crate::storage::{
    ConversationRow, KvWriteOverlay, MessageRow, OpenMlsKvStorage, RequestRow, RusqliteKvBackend,
};

use super::live_plane::{verify_own_answer, PendingCommitTransition};
use super::native_client::CatbirdMlsClient;

fn build_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(5)
        .sender_ratchet_configuration(
            crate::types::GroupConfig::default().sender_ratchet_configuration(),
        )
        .build()
}

/// Bare `I13` sequencing-authority DID that a conversation state view names. A joined group
/// never defaults to this device's home DS: a remote member reads entries another DS sequenced.
fn state_view_sequencer_did(state: &Value) -> Option<&str> {
    state
        .get("sequencerDid")
        .and_then(Value::as_str)
        .filter(|did| did.starts_with("did:") && !did.contains('#'))
}

fn conversation_space_uri(sequencer_did: &str, cid: &str, generation: i64) -> String {
    format!("at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{cid}-{generation}")
}

/// Records an applied, sequenced `accountDeletedEntry`. Archive history loads and restores hide
/// every copy of `deleted_did`'s messages that orders before it: no server redaction covers the
/// witness and owner copies other members already published.
pub(super) fn record_account_deletion(
    tx: &crate::storage::SqlTx<'_>,
    cid: &str,
    deleted_did: &str,
    seq: i64,
    now_ms: i64,
) -> Result<(), MLSError> {
    tx.put_labyrinth_state(
        &chat_wire::account_deletion_key(cid, deleted_did),
        seq.to_string().as_bytes(),
        now_ms,
    )
}

impl CatbirdMlsClient {
    /// Verifies an `accountDeletedEntry`'s `sequencerAuthority` (`I13`) before any effect: it
    /// must bind `cid` and the conversation's pinned `sequencer_did`, and carry a low-S ES256
    /// signature under the exact versioned method named by `keyId`. Returns the deleted DID and
    /// seq, or `None` (logged) for an entry that does not verify; such an entry never hides
    /// anything. `Err` only when that historical method cannot be resolved (retryable).
    pub(super) fn verify_account_deleted_entry(
        &self,
        cid: &str,
        sequencer_did: &str,
        entry: &Value,
    ) -> Result<Option<(String, i64)>, MLSError> {
        let Some(key_id) = chat_wire::account_deleted_entry_key_id(cid, sequencer_did, entry)
        else {
            tracing::warn!(
                cid,
                "ignoring account deletion not bound to this conversation's sequencer"
            );
            return Ok(None);
        };
        let sequencer = sequencer_did.split('#').next().unwrap_or(sequencer_did);
        let key = self
            .resolve_sequencer_receipt_key(sequencer, key_id)?
            .ok_or_else(|| {
                MLSError::Cryptography("I13: account deletion authority key unavailable".into())
            })?;
        let verified =
            chat_wire::verify_account_deleted_entry_signature(cid, sequencer_did, entry, &key);
        if verified.is_none() {
            tracing::warn!(
                cid,
                "ignoring account deletion with an invalid sequencer signature"
            );
        }
        Ok(verified)
    }

    /// Effects of a verified account deletion: no more archive duty for the account, its local
    /// messages go, and archive loads and restores hide its copies ordered before `seq`.
    pub(super) fn apply_verified_account_deletion(
        &self,
        cid: &str,
        deleted_did: &str,
        seq: i64,
    ) -> Result<(), MLSError> {
        let now_ms = self.hooks.now_ms();
        self.db
            .write_tx(|tx| record_account_deletion(tx, cid, deleted_did, seq, now_ms))?;
        handle_account_deleted_event(&self.db, deleted_did)?;
        self.clear_cached_groups();
        Ok(())
    }
}

impl CatbirdMlsClient {
    /// `(did, device, signature key)` of every current leaf of `cid`'s local MLS group, reloaded
    /// so each entry sees the roster the entries before it left. A missing local conversation or
    /// group is an error.
    fn current_leaves(&self, cid: &str) -> Result<Vec<(String, String, Vec<u8>)>, MLSError> {
        self.db.read_tx(|tx| {
            let convo = tx.get_conversation(cid)?.ok_or_else(|| {
                MLSError::Cryptography("control entry has no local conversation".into())
            })?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                .map_err(|e| MLSError::Internal(format!("load control authority: {e:?}")))?
                .ok_or_else(|| {
                    MLSError::Cryptography("control entry has no active MLS group".into())
                })?;
            group
                .members()
                .map(|member| {
                    let (did, device) =
                        root_did_from_credential_bytes(member.credential.serialized_content())?;
                    Ok((did, device, member.signature_key))
                })
                .collect()
        })
    }

    /// PDS authorization alone does not grant conversation authority: the signing device must
    /// hold a current leaf ([`Self::current_leaves`]) whose key is the device's PDS-authorized
    /// key or this device's own. Returns the leaf key.
    fn participant_leaf_key(
        &self,
        cid: &str,
        signed_request: &Value,
        keys: &[AuthorizedPeerDeviceKey],
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Vec<u8>, MLSError> {
        let actor_did = signed_request
            .pointer("/body/actorDid")
            .and_then(Value::as_str);
        let actor_dev = signed_request
            .pointer("/body/actorDeviceId")
            .and_then(Value::as_str);
        self.current_leaves(cid)?
            .into_iter()
            .find(|(did, device, key)| {
                actor_did == Some(did.as_str())
                    && actor_dev == Some(device.as_str())
                    && ((*did == self.normalized_did
                        && device == canonical_dev_id
                        && key.as_slice() == signer.public())
                        || keys.iter().any(|authorized| {
                            authorized.did == *did
                                && authorized.device_id == *device
                                && authorized.signature_public_key == *key
                        }))
            })
            .map(|(_, _, key)| key)
            .ok_or_else(|| {
                MLSError::Cryptography(
                    "I4: control entry signer is not an authorized active participant device"
                        .into(),
                )
            })
    }

    /// The PDS-authorized key of exactly `(did, device)` (`I4`): from the batch's prefetched
    /// keys, or fetched for a DID the batch does not name.
    fn pds_device_key(
        &self,
        did: &str,
        device: &str,
        keys_by_did: &BTreeMap<String, Vec<AuthorizedPeerDeviceKey>>,
    ) -> Result<Vec<u8>, MLSError> {
        let fetched;
        let keys = match keys_by_did.get(did) {
            Some(keys) => keys,
            None => {
                fetched = self.fetch_and_cache_authorized_pds_device_keys(did)?;
                &fetched
            }
        };
        keys.iter()
            .find(|key| key.did == did && key.device_id == device)
            .map(|key| key.signature_public_key.clone())
            .ok_or_else(|| {
                MLSError::Cryptography("I4: signer is not a PDS-authorized device".into())
            })
    }

    /// `did` takes part in `cid`. Without `provenance`, a DID holding a current leaf of the local
    /// group does; any other DID must be the invitee of a `creationEntry` or `policyEntry`. With
    /// `provenance` (a participant acceptance's signed `invitationProvenance`) that invitation
    /// is always required and must be the transition it names.
    ///
    /// The invitation is searched first among `earlier` entries of this sync batch, then by
    /// paging `getEntries` from seq 1 up to `before_seq`. It must verify under the
    /// PDS-authorized key of exactly its signer (with `provenance`, the `invitedBy` device that
    /// names), and its pending row of `did` must carry exactly `provenance`. A found invitation
    /// that does not verify or match is an error, and so is a missing one while this device
    /// reads seq 1. Otherwise it predates this device's readable history (mls-ds never makes a
    /// device that joins later a recipient of earlier control entries), and the caller's
    /// device signature and coordinate step stand alone: a residual of the protocol.
    #[allow(clippy::too_many_arguments)]
    fn require_participant(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        cid: &str,
        did: &str,
        provenance: Option<&Value>,
        before_seq: i64,
        earlier: &[Value],
        keys_by_did: &BTreeMap<String, Vec<AuthorizedPeerDeviceKey>>,
    ) -> Result<(), MLSError> {
        let refused = |what: &str| MLSError::Cryptography(format!("invitation chain: {what}"));
        if provenance.is_none()
            && self
                .current_leaves(cid)?
                .iter()
                .any(|(leaf_did, _, _)| leaf_did == did)
        {
            return Ok(());
        }
        let invites = |entry: &Value| {
            let body = &entry["signedRequest"]["body"];
            chat_wire::signed_entry_kind(entry).is_ok_and(|kind| match provenance {
                Some(provenance) => {
                    matches!(
                        kind,
                        SignedMutationKind::Creation | SignedMutationKind::PolicyTransition
                    ) && provenance["invitationTransitionId"].is_string()
                        && body["transitionId"] == provenance["invitationTransitionId"]
                }
                None => chat_wire::invitation_provenance(kind, body, cid, did).is_some(),
            })
        };
        let mut found = earlier.iter().find(|entry| invites(entry)).cloned();
        let mut reads_seq_one = false;
        let mut after_seq = 0i64;
        while found.is_none() {
            let after = after_seq.to_string();
            let page = self.query_signed_chat_ds(
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("afterSeq", &after),
                    ("conversationId", cid),
                    ("limit", "100"),
                ],
                canonical_dev_id,
                signer,
            )?;
            let entries = page
                .get("entries")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            for entry in entries {
                let seq = entry["seq"].as_i64().unwrap_or(0);
                if seq <= after_seq || seq >= before_seq {
                    continue;
                }
                reads_seq_one |= seq == 1;
                if found.is_none() && invites(entry) {
                    found = Some(entry.clone());
                }
            }
            let last = entries
                .iter()
                .filter_map(|entry| entry["seq"].as_i64())
                .max()
                .unwrap_or(after_seq);
            if entries.len() < 100 || last <= after_seq || last >= before_seq {
                break;
            }
            after_seq = last;
        }
        let Some(invitation) = found else {
            return if reads_seq_one {
                Err(refused("no invitation in history that includes seq 1"))
            } else {
                Ok(())
            };
        };
        let kind = chat_wire::signed_entry_kind(&invitation)?;
        let body = &invitation["signedRequest"]["body"];
        let (inviter_did, inviter_device) = match provenance {
            Some(provenance) => (
                &provenance["invitedByDid"],
                &provenance["invitedByDeviceId"],
            ),
            None => (&body["actorDid"], &body["actorDeviceId"]),
        };
        let (Some(inviter_did), Some(inviter_device)) =
            (inviter_did.as_str(), inviter_device.as_str())
        else {
            return Err(refused("no inviter device"));
        };
        let verified = verify_signed_mutation_body(
            &invitation["signedRequest"],
            kind,
            &self.pds_device_key(inviter_did, inviter_device, keys_by_did)?,
        )?;
        match chat_wire::invitation_provenance(kind, &verified, cid, did) {
            Some(invited) if provenance.is_none_or(|provenance| *provenance == invited) => Ok(()),
            _ => Err(refused(
                "the verified invitation does not invite this participant",
            )),
        }
    }

    /// A sequenced `directRequestAcceptanceEntry` verifies before any effect: the exact entry for
    /// this conversation at `seq`; its signer a current leaf ([`Self::participant_leaf_key`]);
    /// its `Accept`-domain signature under that leaf key; a `next` that only advances
    /// `prior.stateVersion`; the local request's recipient accepting that request; and an
    /// attached coordinator receipt, if any, under the exact method it names. Returns the
    /// verified next coordinates.
    fn verify_direct_request_acceptance_entry(
        &self,
        convo: &ConversationRow,
        seq: i64,
        entry: &Value,
        keys: &[AuthorizedPeerDeviceKey],
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Value, MLSError> {
        let cid = convo.conversation_id.as_str();
        let refused = |what: &str| MLSError::Cryptography(format!("C33 acceptance entry: {what}"));
        let mut entry = entry.clone();
        let fields = entry
            .as_object_mut()
            .ok_or_else(|| refused("not an object"))?;
        if fields.remove("$type")
            != Some(json!("blue.catbird.chat.defs#directRequestAcceptanceEntry"))
        {
            return Err(refused("$type"));
        }
        let receipt = fields.remove("sequencerReceipt");
        let entry = dr_transcript::normalize_read_presentation(
            &serde_json::to_vec(&entry)?,
            "directRequestAcceptanceEntry",
            false,
        )
        .map_err(|e| refused(&e.to_string()))?;
        if entry["conversationId"].as_str() != Some(cid) || entry["seq"].as_i64() != Some(seq) {
            return Err(refused("not this conversation's entry at this seq"));
        }
        let signed_request = &entry["signedRequest"];
        let actor_key =
            self.participant_leaf_key(cid, signed_request, keys, canonical_dev_id, signer)?;
        let accepted = dr_transcript::verify_received_signed_request(
            DirectRequestKind::Accept,
            &serde_json::to_vec(signed_request)?,
            &actor_key,
        )
        .map_err(|e| refused(&e.to_string()))?;
        let body = accepted.body();
        let next_version = body["prior"]["stateVersion"]
            .as_u64()
            .and_then(|version| version.checked_add(1))
            .ok_or_else(|| refused("prior stateVersion"))?;
        let mut advanced = body["prior"].clone();
        advanced["stateVersion"] = json!(next_version);
        if body["prior"]["conversationId"].as_str() != Some(cid) || body["next"] != advanced {
            return Err(refused(
                "must only advance this conversation's stateVersion",
            ));
        }
        let requested = self.db.read_tx(|tx| {
            Ok(tx
                .list_requests(None)?
                .iter()
                .filter(|r| r.conversation_id == cid)
                .all(|r| {
                    body["actorDid"].as_str() == Some(r.recipient_did.as_str())
                        && body["requestId"].as_str() == Some(r.request_id.as_str())
                }))
        })?;
        if !requested {
            return Err(refused("not the local request's recipient accepting it"));
        }
        let next = match receipt {
            None => body["next"].clone(),
            Some(receipt) => {
                let authority = convo.sequencer_did.split('#').next().unwrap_or_default();
                let document = self
                    .resolve_did_document(authority)?
                    .ok_or_else(|| refused("coordinator document unavailable"))?;
                let method = receipt
                    .pointer("/body/keyId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| refused("receipt keyId"))?;
                let key = dr_transcript::resolve_direct_request_receipt_key_for_authority(
                    authority, &document, method,
                )
                .map_err(|e| refused(&e.to_string()))?;
                let proof =
                    dr_transcript::verify_received_direct_request_acceptance_proof_for_authority(
                        authority,
                        &serde_json::to_vec(&json!({ "entry": entry, "receipt": receipt }))?,
                        &key,
                        &actor_key,
                    )
                    .map_err(|e| refused(&e.to_string()))?;
                proof["receipt"]["body"]["next"].clone()
            }
        };
        chat_wire::canonicalize_wire_coordinate(&next, Some(cid))
    }

    /// Complete NSE-retained plaintext proof without replaying its consumed MLS ratchet.
    /// Payload pruning is safe here: the retained frame/nonce and signed I13 receipt suffice.
    fn finish_received_archive_evidence(
        &self,
        cid: &str,
        message_id: &str,
        entry_seq: i64,
        entry_id: &str,
        receipt: &Value,
    ) -> Result<(), MLSError> {
        let authority = self.db.read_tx(|tx| {
            tx.get_conversation(cid)?
                .map(|row| row.sequencer_did)
                .ok_or_else(|| MLSError::group_not_found(cid))
        })?;
        let kid = chat_wire::sequencer_receipt_kid(&authority, receipt)?;
        let key = self
            .resolve_sequencer_receipt_key(&authority, kid)?
            .ok_or_else(|| {
                MLSError::Cryptography("I13: cached message receipt authority unavailable".into())
            })?;
        let now_ms = self.hooks.now_ms();
        self.db.write_tx(|tx| {
            let mut convo = tx
                .get_conversation(cid)?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let message = tx.get_message(message_id)?.ok_or_else(|| {
                MLSError::Cryptography(
                    "cached message disappeared before receipt validation".into(),
                )
            })?;
            let state_key = format!("native.message:{cid}:{message_id}");
            let raw = tx.get_labyrinth_state(&state_key)?.ok_or_else(|| {
                MLSError::Cryptography(
                    "cached message has no retained authenticated archive frame".into(),
                )
            })?;
            let mut evidence: Value = serde_json::from_slice(&raw)?;
            let frame = evidence["labyrinth_frame_json"].as_str().ok_or_else(|| {
                MLSError::Cryptography("cached message archive frame missing".into())
            })?;
            serde_json::from_str::<crate::orchestrator::MLSMessagePayload>(frame)
                .map_err(|e| MLSError::Cryptography(format!("cached archive payload: {e}")))?;
            let nonce = STANDARD
                .decode(evidence["frame_nonce_b64"].as_str().ok_or_else(|| {
                    MLSError::Cryptography("cached message archive nonce missing".into())
                })?)
                .map_err(|e| MLSError::Cryptography(format!("cached archive nonce: {e}")))?;
            let nonce: [u8; 32] = nonce.try_into().map_err(|_| {
                MLSError::Cryptography("cached archive nonce must be 32 bytes".into())
            })?;
            let commitment =
                labyrinth_protocol::receipt::compute_archive_commitment(&nonce, frame.as_bytes());
            // Bind to the epoch the retained evidence authenticated, never the display row:
            // restored history (`import_conversation_history`) keeps historical rows at epoch 0.
            let bound_epoch = match evidence["sequencer_receipt_json"].as_str() {
                Some(prior) => {
                    serde_json::from_str::<chat_wire::StoredArchivedReceipt>(prior)
                        .map_err(|e| {
                            MLSError::Cryptography(format!("cached archive receipt: {e}"))
                        })?
                        .epoch
                }
                None => evidence["epoch"].as_u64().ok_or_else(|| {
                    MLSError::Cryptography("cached message archive epoch missing".into())
                })?,
            };
            let original_sender_attestation:
                crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope =
                serde_json::from_str(
                    evidence["original_sender_attestation_json"]
                        .as_str()
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "cached message missing original sender attestation".into(),
                            )
                        })?,
                )
                .map_err(|error| {
                    MLSError::Cryptography(format!(
                        "cached original sender attestation: {error}"
                    ))
                })?;
            if original_sender_attestation.sender_did != message.sender_did
                || original_sender_attestation.sender_device_id != message.sender_device_id
            {
                return Err(MLSError::Cryptography(
                    "cached original sender attestation attribution mismatch".into(),
                ));
            }
            let (seq, generation, stored_receipt) =
                chat_wire::parse_and_verify_i13_sequencer_receipt(
                    receipt,
                    &key,
                    &authority,
                    cid,
                    &message.group_id,
                    bound_epoch,
                    entry_id,
                    message_id,
                    &commitment,
                    Some(&original_sender_attestation),
                )?;
            if evidence["message_id"].as_str() != Some(message_id)
                // The display row must still be the plaintext this evidence authenticated:
                // an imported or replaced row never inherits another frame's receipt.
                || evidence["plaintext_json"].as_str() != Some(message.plaintext_json.as_str())
                || evidence["conversation_id"].as_str() != Some(cid)
                || message.conversation_id != cid
                || convo.sequencer_did != authority
                || message.group_id != convo.group_id
                || generation != convo.generation.max(0) as u64
                || i64::try_from(seq).ok() != Some(entry_seq)
                || receipt["senderDid"].as_str() != Some(message.sender_did.as_str())
                || receipt["senderDeviceId"].as_str() != Some(message.sender_device_id.as_str())
                || evidence["sequencer_receipt_json"]
                    .as_str()
                    .is_some_and(|prior| prior != stored_receipt.as_str())
            {
                return Err(MLSError::Cryptography(
                    "I13: cached archive proof binding mismatch".into(),
                ));
            }
            // NSE-retained evidence becomes archivable only once its I13 receipt verifies.
            let completes = evidence["sequencer_receipt_json"].is_null();
            evidence["sequencer_receipt_json"] = json!(stored_receipt);
            if completes {
                evidence["seq"] = json!(entry_seq);
            }
            tx.put_labyrinth_state(&state_key, &serde_json::to_vec(&evidence)?, now_ms)?;
            if completes && message.sender_did != self.normalized_did {
                let archive: QueuedLabyrinthArchivePayload = serde_json::from_value(evidence)
                    .map_err(|e| {
                        MLSError::Cryptography(format!("retained archive payload: {e}"))
                    })?;
                super::live_plane::enqueue_labyrinth_archive(tx, &archive)?;
            }
            tx.delete_pending_op(NATIVE_ARCHIVE_RECEIPT_OP, message_id)?;
            tx.conn()
                .execute(
                    "UPDATE messages SET seq = ?1 WHERE message_id = ?2",
                    rusqlite::params![entry_seq, message_id],
                )
                .map_err(|e| map_rusqlite_err("update authenticated cached message seq", &e))?;
            convo.last_seq = convo.last_seq.max(entry_seq);
            convo.updated_at_ms = now_ms;
            tx.upsert_conversation(&convo)
        })
    }

    /// Record a sequenced application entry this device can never decrypt: durable evidence and a
    /// system gap row at its seq, so the timeline shows the gap and sync moves on to later
    /// Commits. First, in the same transaction, the entry must authenticate without its
    /// plaintext: its signed sender is an active, PDS-authorized leaf of the group; the verified
    /// outer AAD carries that sender's archive commitment and original attestation; and the I13
    /// receipt (the method its `kid` names) sequenced exactly this entry at `seq`. An already
    /// stored message keeps its row. No archive or witness copy exists.
    fn record_undecryptable_entry(
        &self,
        evidence: &chat_wire::UndecryptableEntryEvidence,
        signed_aad: &Value,
        receipt: &Value,
        receipt_key: &[u8],
        keys: &[AuthorizedPeerDeviceKey],
    ) -> Result<(), MLSError> {
        let cid = evidence.conversation_id.as_str();
        let aad = canonical_application_aad_bytes(signed_aad).map_err(|error| {
            MLSError::Cryptography(format!("invalid signed application AAD: {error}"))
        })?;
        let (commitment, attestation) =
            verify_application_aad_archive_evidence(&aad, cid, &evidence.message_id)?;
        if attestation.sender_did != evidence.sender_did
            || attestation.sender_device_id != evidence.sender_device_id
        {
            return Err(MLSError::Cryptography(
                "undecryptable entry attestation differs from its signed sender".into(),
            ));
        }
        let epoch = u64::try_from(evidence.epoch)
            .map_err(|_| MLSError::Cryptography("undecryptable entry epoch is negative".into()))?;
        self.db.write_tx(|tx| {
            let mut convo = tx
                .get_conversation(cid)?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let mut sender_leaf = None;
            for member in group.members() {
                let (did, device) =
                    root_did_from_credential_bytes(member.credential.serialized_content())?;
                if did == evidence.sender_did && device == evidence.sender_device_id {
                    sender_leaf = Some(member);
                    break;
                }
            }
            let member = sender_leaf.ok_or_else(|| {
                MLSError::Cryptography(
                    "I4: undecryptable entry sender is not an active group leaf".into(),
                )
            })?;
            chat_wire::verify_leaf_slice_i4(
                member.credential.serialized_content(),
                member.signature_key.as_slice(),
                keys,
            )?;
            if attestation.sender_transport_public_key.as_slice() != member.signature_key.as_slice()
            {
                return Err(MLSError::Cryptography(
                    "original sender attestation differs from the sender's MLS leaf".into(),
                ));
            }
            let (seq, generation, _) = chat_wire::parse_and_verify_i13_sequencer_receipt(
                receipt,
                receipt_key,
                &convo.sequencer_did,
                cid,
                &convo.group_id,
                epoch,
                &evidence.entry_id,
                &evidence.message_id,
                &commitment,
                Some(&attestation),
            )?;
            if i64::try_from(seq).ok() != Some(evidence.seq) {
                return Err(MLSError::Cryptography(format!(
                    "I13: receipt seq {seq} != entry seq {}",
                    evidence.seq
                )));
            }
            if generation != convo.generation.max(0) as u64 {
                return Err(MLSError::Cryptography(
                    "I13: receipt generation mismatch".into(),
                ));
            }
            if tx.get_message(&evidence.message_id)?.is_none() {
                let is_own = evidence.sender_did == self.normalized_did;
                tx.insert_message(&evidence.gap_row(&convo.group_id, is_own)?)?;
                tx.put_labyrinth_state(
                    &chat_wire::undecryptable_evidence_key(cid, &evidence.message_id),
                    &serde_json::to_vec(evidence)?,
                    evidence.recorded_at_ms,
                )?;
                if !is_own {
                    convo.unread_count = convo.unread_count.saturating_add(1);
                }
            }
            convo.last_seq = convo.last_seq.max(evidence.seq);
            convo.updated_at_ms = evidence.recorded_at_ms;
            tx.upsert_conversation(&convo)
        })
    }

    /// Reconcile conversations, `C33` direct requests, pending `Welcome`s, leaf-recovery requests,
    /// and ordered `getEntries` deltas from the home `mls-ds` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`).
    pub fn sync(&self) -> Result<u32, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() else {
            return Ok(0);
        };
        let Ok((signer, auth_generation)) = self.load_enrolled_signer_and_auth_gen() else {
            return Ok(0);
        };

        let mut total_applied: u32 = 0;

        // Phase 1: `getConversations` -> C33 incoming direct requests + group invitation acceptance.
        let (conv_applied, inventory_session_id) =
            self.sync_conversations_list(&canonical_dev_id, &signer, auth_generation)?;
        total_applied = total_applied.saturating_add(conv_applied);

        // Phase 2: `getPendingWelcomes` -> StagedWelcome join + acknowledgeWelcome.
        total_applied = total_applied.saturating_add(self.sync_pending_welcomes(
            &canonical_dev_id,
            &signer,
            auth_generation,
            inventory_session_id.as_deref(),
        )?);

        // Phase 3: current leaves discover fulfillment work through `getConversationState`.
        total_applied = total_applied.saturating_add(self.fulfill_pending_leaf_recoveries(
            &canonical_dev_id,
            &signer,
            auth_generation,
        )?);

        // Journaled own closes whose answer was lost, refused or unverifiable: exact replay.
        total_applied = total_applied.saturating_add(self.complete_pending_closes()?);

        // Phase 4: `getEntries` for every known conversation -> decrypt + acknowledgeEntries.
        let convos = self.db.read_tx(|tx| tx.list_conversations(None, 200))?;
        for convo in convos {
            total_applied = total_applied.saturating_add(self.sync_conversation_entries(
                &canonical_dev_id,
                &signer,
                &convo,
            )?);
            // A leaf-removal Commit accepted without its response (and recovered from its
            // journal above) still owes the participant-removal policy transition.
            self.complete_participant_removals(&convo.conversation_id, &canonical_dev_id, &signer)?;
        }

        if total_applied > 0 {
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        }
        Ok(total_applied)
    }

    fn sync_conversations_list(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
    ) -> Result<(u32, Option<String>), MLSError> {
        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getConversations",
            &[
                ("actorDeviceId", canonical_dev_id),
                ("limit", "100"),
                ("supportedProtocolVersions", "1"),
                ("supportedProtocolVersions", "2"),
            ],
            canonical_dev_id,
            signer,
        )?;
        let inventory_session_id = resp
            .get("inventorySessionId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let Some(items) = resp
            .get("items")
            .or_else(|| resp.get("conversations"))
            .or_else(|| resp.get("states"))
            .and_then(|v| v.as_array())
        else {
            return Ok((0, inventory_session_id));
        };

        let mut count = 0u32;
        for item in items {
            let state = item.get("state").unwrap_or(item);
            let coords = state.get("coordinates").unwrap_or(&Value::Null);
            let Some(cid) = coords
                .get("conversationId")
                .or_else(|| state.get("conversationId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let kind = state
                .get("conversationKind")
                .or_else(|| state.get("kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("group");

            let local = self.db.read_tx(|tx| tx.get_conversation(cid))?;
            let has_local = local.is_some();
            // Direct rows take their authority from the request entry's own receipt.
            if let (Some(row), Some(authority), "group") =
                (&local, state_view_sequencer_did(state), kind)
            {
                if row.sequencer_did.is_empty() {
                    self.repair_conversation_authority(cid, authority)?;
                }
            }

            if kind == "direct" && !has_local {
                // A pruned opening's terminal state is recorded once; it is never re-fetched.
                let terminal = self.db.read_tx(|tx| {
                    Ok(tx
                        .list_requests(Some(C33_OPENING_UNAVAILABLE))?
                        .iter()
                        .any(|r| r.conversation_id == cid))
                })?;
                if terminal {
                    continue;
                }
                if self.import_incoming_c33_direct_request(canonical_dev_id, signer, cid)? {
                    count = count.saturating_add(1);
                }
                continue;
            }

            // If we have a pending group invitation in `participants`, accept it so the inviter
            // can discover our leaf recovery request through `getConversationState`.
            if kind == "group" {
                if let Some(participants) = state.get("participants").and_then(|v| v.as_array()) {
                    if let Some(me) = participants.iter().find(|p| {
                        p.get("userDid").and_then(|u| u.as_str()) == Some(&self.normalized_did)
                            && p.get("status").and_then(|s| s.as_str()) == Some("pending")
                    }) {
                        if let Some(prov) = me.get("invitationProvenance") {
                            if let Err(e) = self.accept_group_invitation(
                                canonical_dev_id,
                                signer,
                                auth_generation,
                                cid,
                                coords,
                                prov,
                            ) {
                                if !e.is_stale_coordinates() {
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok((count, inventory_session_id))
    }

    /// Pin an initially unknown authority. Inventory JSON is not a transfer proof and
    /// must never replace an existing `I13` trust anchor or its journaled sends.
    fn repair_conversation_authority(&self, cid: &str, authority: &str) -> Result<(), MLSError> {
        self.db.write_tx(|tx| {
            let Some(mut row) = tx.get_conversation(cid)? else {
                return Ok(());
            };
            if row.sequencer_did == authority {
                return Ok(());
            }
            if !row.sequencer_did.is_empty() {
                return Err(MLSError::Cryptography(
                    "unsigned conversation inventory cannot replace a pinned sequencer".into(),
                ));
            }
            let space_uri = row
                .space_uri
                .as_deref()
                .and_then(|uri| uri.strip_prefix("at://")?.split_once('/'))
                .map(|(_, path)| format!("at://{authority}/{path}"))
                .unwrap_or_else(|| conversation_space_uri(authority, cid, row.generation));
            tx.conn()
                .execute(
                    "UPDATE pending_ops SET payload_json = json_set(payload_json, \
                     '$.archive.sequencer_did', ?2, '$.archive.space_uri', ?3) \
                     WHERE op_kind = 'application_send' \
                     AND json_extract(payload_json, '$.archive.conversation_id') = ?1",
                    rusqlite::params![cid, authority, space_uri],
                )
                .map_err(|e| map_rusqlite_err("repair pending send authority", &e))?;
            row.sequencer_did = authority.to_owned();
            row.space_uri = Some(space_uri);
            tx.upsert_conversation(&row)
        })
    }

    fn accept_group_invitation(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        cid: &str,
        coords: &Value,
        invitation_provenance: &Value,
    ) -> Result<(), MLSError> {
        let prior = chat_wire::canonicalize_wire_coordinate(coords, Some(cid))?;
        let prior_sv = prior
            .get("stateVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let mut next = prior.clone();
        next["stateVersion"] = json!(prior_sv + 1);
        let transition_id = self.hooks.uuid_v4().to_string();
        let recovery_request_id = self.hooks.uuid_v4().to_string();
        let body = json!({
            "$type": "blue.catbird.chat.defs#participantAcceptanceBody",
            "signatureDomain": "CATBIRD-CHAT-ACCEPT\0",
            "transitionId": transition_id,
            "recoveryRequestId": recovery_request_id,
            "idempotencyKey": transition_id,
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_generation,
            "signedAt": self.hooks.now_rfc3339_millis(),
            "prior": prior,
            "next": next,
            "invitationProvenance": invitation_provenance,
        });
        let _ = self.submit_signed_chat_op(
            canonical_dev_id,
            Some(auth_generation),
            CanonicalOperation::AcceptConversation,
            &body,
            signer,
        )?;
        Ok(())
    }

    fn import_incoming_c33_direct_request(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        cid: &str,
    ) -> Result<bool, MLSError> {
        let entries_val = self.query_signed_chat_ds(
            "blue.catbird.chat.getEntries",
            &[
                ("actorDeviceId", canonical_dev_id),
                ("afterSeq", "0"),
                ("conversationId", cid),
                ("limit", "100"),
            ],
            canonical_dev_id,
            signer,
        )?;
        let Some(entries) = entries_val.get("entries").and_then(|v| v.as_array()) else {
            return Ok(false);
        };
        let Some(raw_dr_entry) = entries.iter().find(|e| {
            e.get("$type").and_then(|t| t.as_str())
                == Some("blue.catbird.chat.defs#directRequestEntry")
                || e.get("entryKind").and_then(|t| t.as_str()) == Some("directRequest")
                || e.get("directRequest").is_some()
        }) else {
            return Ok(false);
        };
        if raw_dr_entry["payloadPruned"] == true
            || (raw_dr_entry.get("directRequest").is_none()
                && raw_dr_entry["$type"] == "blue.catbird.chat.defs#directRequestEntry"
                && crate::orchestrator::direct_request_bootstrap::is_pruned_opening_entry(
                    raw_dr_entry,
                ))
        {
            return self.record_pruned_c33_opening(cid, raw_dr_entry);
        }

        let pub_wrapper = raw_dr_entry
            .get("signedRequest")
            .or_else(|| raw_dr_entry.get("directRequest"))
            .unwrap_or(raw_dr_entry);
        let p_body = pub_wrapper.get("body").unwrap_or(pub_wrapper);
        let sender_did = p_body
            .get("actorDid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing actorDid".to_string()))?;
        let sender_device_id = p_body
            .get("actorDeviceId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing actorDeviceId".to_string()))?;
        let request_id = p_body
            .get("requestId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing requestId".to_string()))?;
        let first_message_id = p_body
            .get("firstMessageId")
            .and_then(|v| v.as_str())
            .unwrap_or(request_id);

        // Enforce `I4` (`ADR-009`): verify sender device key in PDS `blue.catbird.chat.device` BEFORE Welcome join!
        let sender_pds_keys = self.fetch_and_cache_authorized_pds_device_keys(sender_did)?;
        let candidate_key = chat_wire::json_bytes(
            &p_body["artifacts"]["metadataSnapshot"]["authorProof"]["signaturePublicKey"],
        )?;
        let sender_scoped_id = format!("{sender_did}#{sender_device_id}");
        chat_wire::verify_leaf_slice_i4(
            sender_scoped_id.as_bytes(),
            &candidate_key,
            &sender_pds_keys,
        )?;

        let pub_norm = dr_transcript::normalize_read_presentation(
            &serde_json::to_vec(pub_wrapper).map_err(|e| MLSError::Internal(e.to_string()))?,
            "signedDirectRequestPublication",
            false,
        )
        .map_err(|e| MLSError::Cryptography(format!("normalize C33 publication: {e}")))?;
        let pub_norm_bytes =
            serde_json::to_vec(&pub_norm).map_err(|e| MLSError::Internal(e.to_string()))?;
        let verified_pub = dr_transcript::verify_received_signed_request(
            DirectRequestKind::Publish,
            &pub_norm_bytes,
            &candidate_key,
        )
        .map_err(|e| MLSError::Cryptography(format!("verify C33 publication signature: {e}")))?;

        let vp = verified_pub.body();
        if vp["conversationId"].as_str() != Some(cid)
            || vp["next"]["conversationId"].as_str() != Some(cid)
            || (vp["actorDid"].as_str() != Some(self.normalized_did.as_str())
                && vp["recipientDid"].as_str() != Some(self.normalized_did.as_str()))
        {
            return Err(MLSError::Cryptography(
                "C33 publication conversation/participant mismatch".into(),
            ));
        }
        let ctx_val = json!({
            "protocolVersion": "2",
            "requestId": vp["requestId"],
            "firstMessageId": vp["firstMessageId"],
            "conversationId": vp["conversationId"],
            "origin": vp["origin"],
            "actorDid": vp["actorDid"],
            "actorDeviceId": vp["actorDeviceId"],
            "actorKeyId": vp["keyId"],
            "recipientDid": vp["recipientDid"],
            "preparationDigest": vp["preparationDigest"],
        });
        let context_json =
            serde_json::to_vec(&ctx_val).map_err(|e| MLSError::Internal(e.to_string()))?;
        let context_hash = dr_transcript::direct_request_context_hash(&context_json)
            .map_err(|e| MLSError::Cryptography(format!("C33 context_hash: {e}")))?;
        let expected_ctx_hash = chat_wire::json_bytes(&vp["contextHash"])?;
        if expected_ctx_hash.as_slice() != context_hash {
            return Err(MLSError::Cryptography(
                "C33 contextHash mismatch".to_string(),
            ));
        }

        let artifact = &vp["artifacts"];
        let mut local_pkg_ref: Option<Vec<u8>> = None;
        let deliveries_arr = artifact["welcome"]["deliveries"]
            .as_array()
            .ok_or_else(|| MLSError::invalid_input("C33 welcome missing deliveries"))?;
        let mut refs: Vec<Vec<u8>> = Vec::with_capacity(deliveries_arr.len());
        for d in deliveries_arr {
            let r = chat_wire::json_bytes(&d["provenance"]["keyPackageRef"])?;
            if d.get("recipientDid").and_then(|v| v.as_str()) == Some(self.normalized_did.as_str())
                && d.get("recipientDeviceId").and_then(|v| v.as_str()) == Some(canonical_dev_id)
            {
                local_pkg_ref = Some(r.clone());
            }
            refs.push(r);
        }
        let import_until = chrono::DateTime::parse_from_rfc3339(
            vp["importUntil"]
                .as_str()
                .ok_or_else(|| MLSError::invalid_input("C33 missing importUntil"))?,
        )
        .map_err(|e| MLSError::invalid_input(format!("C33 importUntil: {e}")))?
        .timestamp()
        .max(0) as u64;

        let opening_commitment: [u8; 32] = chat_wire::json_bytes(&vp["archiveCommitment"])?
            .try_into()
            .map_err(|_| MLSError::Cryptography("C33 archiveCommitment must be 32 bytes".into()))?;
        let original_sender_attestation =
            crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope::from_aad_json(
                vp.get("originalSenderAttestation").ok_or_else(|| {
                    MLSError::Cryptography(
                        "C33 publication missing original sender attestation".into(),
                    )
                })?,
            )?;
        if original_sender_attestation.sender_did != sender_did
            || original_sender_attestation.sender_device_id != sender_device_id
        {
            return Err(MLSError::Cryptography(
                "C33 original sender attestation attribution mismatch".into(),
            ));
        }
        original_sender_attestation.verify(
            ctx_val["conversationId"].as_str().unwrap_or_default(),
            ctx_val["firstMessageId"].as_str().unwrap_or_default(),
            &opening_commitment,
        )?;

        let bootstrap = DirectRequestBootstrap {
            context_json,
            context_hash,
            coordinates: vp["next"].clone(),
            import_until,
            expected_package_refs: refs.clone(),
            genesis_group_info: chat_wire::json_bytes(&artifact["genesisGroupInfo"]["bytes"])?,
            add_commit: chat_wire::json_bytes(&artifact["addCommit"]["bytes"])?,
            final_group_info: chat_wire::json_bytes(&artifact["finalGroupInfo"]["bytes"])?,
            welcome: chat_wire::json_bytes(&artifact["welcome"]["opaqueWelcome"])?,
            metadata_nonce: chat_wire::json_bytes(&artifact["metadataSnapshot"]["nonce"])?,
            metadata_ciphertext: chat_wire::json_bytes(
                &artifact["metadataSnapshot"]["ciphertext"],
            )?,
            initial_ciphertext: chat_wire::json_bytes(&artifact["initialCiphertext"])?,
            archive_commitment: opening_commitment,
            original_sender_attestation,
            opening: None,
        };

        // An own opening, which another of this account's devices published, names the peer as
        // its recipient; an incoming one names this account. The group holds both accounts'
        // devices.
        let recipient_did = vp["recipientDid"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("C33 missing recipient".into()))?;
        let is_incoming = sender_did != self.normalized_did;
        let mut all_auth_keys = sender_pds_keys;
        all_auth_keys.extend(self.fetch_and_cache_authorized_pds_device_keys(recipient_did)?);

        let peer_did = if is_incoming {
            sender_did
        } else {
            recipient_did
        };
        let peer_ds = self.resolve_peer_home_ds_did(peer_did).ok_or_else(|| {
            MLSError::Cryptography("C33 peer home DS authority unavailable".into())
        })?;
        let effective_seq_did = dr_transcript::derive_deterministic_coordinator(
            self.config.home_ds_did.trim(),
            &peer_ds,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 coordinator: {e}")))?;
        let publication_receipt = raw_dr_entry.get("publicationReceipt").ok_or_else(|| {
            MLSError::Cryptography("C33 entry missing signed publicationReceipt".into())
        })?;
        // Closed single-variant union: `$type` is required and exact.
        let publication_receipt = dr_transcript::normalize_read_presentation(
            &serde_json::to_vec(publication_receipt)?,
            "signedDirectRequestReceipt",
            true,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 publication receipt: {e}")))?;
        let authority_doc = self
            .resolve_did_document(&effective_seq_did)?
            .ok_or_else(|| {
                MLSError::Cryptography("C33 receipt authority document unavailable".into())
            })?;
        let receipt_method = publication_receipt
            .pointer("/body/keyId")
            .and_then(Value::as_str)
            .ok_or_else(|| MLSError::Cryptography("C33 outcome missing receipt keyId".into()))?;
        let receipt_key = dr_transcript::resolve_direct_request_receipt_key_for_authority(
            &effective_seq_did,
            &authority_doc,
            receipt_method,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 receipt key: {e}")))?;
        let entry_receipt = raw_dr_entry.get("sequencerReceipt").ok_or_else(|| {
            MLSError::Cryptography("C33 entry missing I13 sequencerReceipt".into())
        })?;
        // The opening and the outcome carry one identical receipt: one exact method verifies both.
        let sequencer_receipt_key = chat_wire::decode_p256_sec1_from_did_doc(
            &authority_doc,
            &effective_seq_did,
            chat_wire::sequencer_receipt_kid(&effective_seq_did, entry_receipt)?,
        )?;
        let (entry_seq, _, dr_rcpt_json) =
            crate::orchestrator::direct_request_bootstrap::verify_opening_receipt(
                &bootstrap,
                entry_receipt,
                &effective_seq_did,
                &sequencer_receipt_key,
            )?;
        let (_, _, outcome_rcpt_json) =
            crate::orchestrator::direct_request_bootstrap::verify_opening_receipt(
                &bootstrap,
                &publication_receipt["body"]["receipt"]["sequencerReceipt"],
                &effective_seq_did,
                &sequencer_receipt_key,
            )?;
        let entry_seq = i64::try_from(entry_seq)
            .map_err(|_| MLSError::Cryptography("C33 entry sequence overflow".into()))?;
        if raw_dr_entry["seq"].as_i64() != Some(entry_seq)
            || dr_rcpt_json != outcome_rcpt_json
            || raw_dr_entry["entryId"].as_str() != Some(first_message_id)
        {
            return Err(MLSError::Cryptography(
                "C33 entry and outcome receipt mismatch".into(),
            ));
        }

        let welcome_input = DirectRequestWelcomeInput {
            bootstrap: bootstrap.clone(),
            publication_request: pub_norm_bytes.clone(),
            actor_signature_public_key: candidate_key,
            preparation_request_digest: chat_wire::json_bytes(&vp["preparationRequestDigest"])?
                .try_into()
                .map_err(|_| {
                    MLSError::Cryptography("C33 preparation digest must be 32 bytes".into())
                })?,
            local_identity: format!("{}#{}", self.normalized_did, canonical_dev_id).into_bytes(),
            local_package_ref: local_pkg_ref
                .or_else(|| refs.into_iter().next())
                .unwrap_or_default(),
            published_receipt: serde_json::to_vec(&publication_receipt)?,
            receipt_authority_did: effective_seq_did.clone(),
            receipt_authority_key: receipt_key,
            sequencer_receipt_authority_key: sequencer_receipt_key,
        };
        crate::orchestrator::direct_request_shared_crypto::validate_request_welcome_receipt(
            &welcome_input,
        )?;

        let now_ms = self.hooks.now_ms();
        let pub_norm_str = String::from_utf8(pub_norm_bytes)
            .map_err(|e| MLSError::Internal(format!("C33 pub UTF-8: {e}")))?;
        let coords_canon = chat_wire::canonicalize_wire_coordinate(&vp["next"], Some(cid))?;
        let coords_str =
            serde_json::to_string(&coords_canon).map_err(|e| MLSError::Internal(e.to_string()))?;

        self.db.write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let mls_welcome = MlsMessageIn::tls_deserialize_exact(&bootstrap.welcome)
                .map_err(|e| MLSError::Cryptography(format!("deserialize C33 Welcome: {e:?}")))?;
            let MlsMessageBodyIn::Welcome(welcome) = mls_welcome.extract() else {
                return Err(MLSError::Cryptography(
                    "C33 opaqueWelcome is not an MLS Welcome".to_string(),
                ));
            };
            let staged = crate::sim_hooks::build_staged_welcome_at(
                &provider,
                &build_join_config(),
                welcome,
                None,
                (now_ms.max(0) as u64) / 1_000,
            )
            .map_err(|e| MLSError::Cryptography(format!("stage C33 Welcome: {e:?}")))?;

            let sender_member = staged.welcome_sender().map_err(|e| {
                MLSError::Cryptography(format!("C33 welcome_sender lookup failed: {e:?}"))
            })?;
            chat_wire::verify_leaf_slice_i4(
                sender_member.credential().serialized_content(),
                sender_member.signature_key().as_slice(),
                &all_auth_keys,
            )?;

            let mut group = staged
                .into_group(&provider)
                .map_err(|e| MLSError::Cryptography(format!("into_group C33 Welcome: {e:?}")))?;
            self.clear_cached_groups();
            for m in group.members() {
                chat_wire::verify_leaf_slice_i4(
                    m.credential.serialized_content(),
                    m.signature_key.as_slice(),
                    &all_auth_keys,
                )?;
            }

            let group_id = group.group_id().as_slice().to_vec();
            let epoch = group.epoch().as_u64() as i64;
            let (intro_json, opening) =
                match decrypt_introduction_with_provider(&provider, &mut group, &welcome_input)? {
                    DirectRequestIntroductionResult::Ready { plaintext, opening } => {
                        let intro_val = dr_transcript::decode_direct_request_introduction(
                            &plaintext,
                        )
                        .map_err(|e| MLSError::Cryptography(format!("decode C33 intro: {e}")))?;
                        let txt = intro_val.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        (json!({ "text": txt }).to_string(), Some(opening))
                    }
                    DirectRequestIntroductionResult::Unavailable { code } => (
                        json!({ "text": format!("[unavailable:{code}]") }).to_string(),
                        None,
                    ),
                };

            let space_uri = Some(format!(
                "at://{effective_seq_did}/space/blue.catbird.labyrinth.conversation/{cid}-0"
            ));
            let convo_row = ConversationRow {
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                generation: 0,
                epoch,
                last_seq: entry_seq,
                sequencer_did: effective_seq_did.clone(),
                space_uri: space_uri.clone(),
                title: None,
                unread_count: i64::from(is_incoming),
                updated_at_ms: now_ms,
            };
            tx.upsert_conversation(&convo_row)?;
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, now_ms)?;
            tx.put_account_meta(
                &format!("c33_publication_json:{cid}"),
                &pub_norm_str,
                now_ms,
            )?;

            tx.upsert_request(&RequestRow {
                request_id: request_id.to_string(),
                conversation_id: cid.to_string(),
                sender_did: sender_did.to_string(),
                recipient_did: recipient_did.to_string(),
                consent: if is_incoming {
                    "incomingPending".to_string()
                } else {
                    "outgoingPending".to_string()
                },
                first_message_id: Some(first_message_id.to_string()),
                first_message_archived: false,
                payload_json: intro_json.clone(),
                expires_at_ms: (import_until as i64).saturating_mul(1000),
                updated_at_ms: now_ms,
            })?;
            tx.insert_message(&MessageRow {
                message_id: first_message_id.to_string(),
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                epoch,
                seq: entry_seq,
                sender_did: sender_did.to_string(),
                sender_device_id: sender_device_id.to_string(),
                plaintext_json: intro_json.clone(),
                created_at_ms: now_ms,
                is_own: !is_incoming,
            })?;

            // Stage an incoming C33 opening so `accept_direct_request` archives it ONLY after
            // consent. An own opening is the sending device's archive duty.
            if let Some(opening) = opening.filter(|_| is_incoming) {
                let staged_opening = QueuedLabyrinthArchivePayload {
                    expected_member_dids: group
                        .members()
                        .map(|member| {
                            root_did_from_credential_bytes(member.credential.serialized_content())
                                .map(|(did, _)| did)
                        })
                        .collect::<Result<std::collections::BTreeSet<_>, _>>()?
                        .into_iter()
                        .collect(),
                    version: 1,
                    message_id: first_message_id.to_string(),
                    conversation_id: cid.to_string(),
                    group_id_hex: hex::encode(&group_id),
                    epoch,
                    seq: entry_seq,
                    sender_did: sender_did.to_string(),
                    sender_device_id: sender_device_id.to_string(),
                    sequencer_did: effective_seq_did,
                    space_uri,
                    plaintext_json: intro_json.clone(),
                    labyrinth_frame_json: String::from_utf8(opening.canonical_payload_bytes)
                        .map_err(|e| {
                            MLSError::Cryptography(format!("C33 canonical opening frame: {e}"))
                        })?,
                    mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                    frame_nonce_b64: Some(STANDARD.encode(opening.frame_nonce)),
                    sequencer_receipt_json: Some(dr_rcpt_json),
                    original_sender_attestation_json: Some(
                        serde_json::to_string(&bootstrap.original_sender_attestation).map_err(
                            |error| {
                                MLSError::Internal(format!(
                                    "serialize C33 original sender attestation: {error}"
                                ))
                            },
                        )?,
                    ),
                    created_at_ms: now_ms,
                };
                tx.put_labyrinth_state(
                    &format!("native.message:{cid}:{first_message_id}"),
                    &serde_json::to_vec(&staged_opening)?,
                    now_ms,
                )?;
                tx.put_account_meta(
                    &format!("c33_pending_opening:{cid}"),
                    &serde_json::to_string(&staged_opening)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    now_ms,
                )?;
            }
            Ok(())
        })?;

        self.notify_change(PlatformChangeEvent::RequestsUpdated);
        self.notify_change(PlatformChangeEvent::MessagesUpdated {
            conversation_id: cid.to_string(),
        });
        Ok(true)
    }

    /// An opening pruned before this device imported it keeps only its receipts: no Welcome,
    /// preview or acceptance can follow. Its participants come from signed evidence alone: the
    /// coordinator's outcome names the sender, and this account, which never imported the
    /// opening, is the recipient. Their homes select the coordinator; no inventory field does.
    fn record_pruned_c33_opening(&self, cid: &str, entry: &Value) -> Result<bool, MLSError> {
        let missing = |what: &str| MLSError::Cryptography(format!("C33 pruned opening: {what}"));
        // Read unverified only to select the coordinator, whose verified outcome must then name
        // the same sender.
        let sender_did = entry
            .pointer("/publicationReceipt/body/receipt/actorDid")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("outcome actorDid"))?;
        if sender_did == self.normalized_did {
            // ponytail: re-read every sync. Nothing signed names the recipient of an own opening
            // another device published, so it is never recorded; keep a local skip marker if
            // such openings become common.
            return Ok(false);
        }
        let recipient_did = self.normalized_did.as_str();
        let sender_home = self
            .resolve_peer_home_ds_did(sender_did)
            .ok_or_else(|| missing("sender home DS authority"))?;
        let authority = dr_transcript::derive_deterministic_coordinator(
            &sender_home,
            self.config.home_ds_did.trim(),
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 coordinator: {e}")))?;
        let document = self
            .resolve_did_document(&authority)?
            .ok_or_else(|| missing("receipt authority document"))?;
        let receipt = crate::orchestrator::direct_request_bootstrap::verify_pruned_opening_entry(
            entry, cid, &authority, &document,
        )?;
        if receipt["actorDid"].as_str() != Some(sender_did) {
            return Err(missing("receipt sender binding"));
        }
        let row = RequestRow {
            request_id: receipt["requestId"]
                .as_str()
                .ok_or_else(|| missing("requestId"))?
                .to_string(),
            conversation_id: cid.to_string(),
            sender_did: sender_did.to_string(),
            recipient_did: recipient_did.to_string(),
            consent: C33_OPENING_UNAVAILABLE.to_string(),
            first_message_id: receipt["firstMessageId"].as_str().map(str::to_owned),
            first_message_archived: false,
            payload_json: json!({ "unavailable": "OpeningPruned" }).to_string(),
            expires_at_ms: 0,
            updated_at_ms: self.hooks.now_ms(),
        };
        self.db.write_tx(|tx| tx.upsert_request(&row))?;
        self.notify_change(PlatformChangeEvent::RequestsUpdated);
        Ok(false)
    }

    fn acquire_inventory_session_id(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Option<String>, MLSError> {
        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getConversations",
            &[
                ("actorDeviceId", canonical_dev_id),
                ("limit", "1"),
                ("supportedProtocolVersions", "1"),
                ("supportedProtocolVersions", "2"),
            ],
            canonical_dev_id,
            signer,
        )?;
        Ok(resp
            .get("inventorySessionId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned))
    }

    fn sync_pending_welcomes(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        inventory_session_id: Option<&str>,
    ) -> Result<u32, MLSError> {
        let owned_sid = if inventory_session_id.is_none() {
            self.acquire_inventory_session_id(canonical_dev_id, signer)?
        } else {
            None
        };
        let mut q_pairs: Vec<(&str, &str)> = vec![("actorDeviceId", canonical_dev_id)];
        if let Some(sid) = inventory_session_id.or(owned_sid.as_deref()) {
            q_pairs.push(("inventorySessionId", sid));
        }
        q_pairs.extend_from_slice(&[
            ("limit", "100"),
            ("supportedProtocolVersions", "1"),
            ("supportedProtocolVersions", "2"),
        ]);
        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getPendingWelcomes",
            &q_pairs,
            canonical_dev_id,
            signer,
        )?;
        let Some(welcomes) = resp
            .get("items")
            .or_else(|| resp.get("welcomes"))
            .or_else(|| resp.get("deliveries"))
            .and_then(|v| v.as_array())
        else {
            return Ok(0);
        };

        let mut joined = 0u32;
        for raw_item in welcomes {
            let w_env = raw_item
                .get("welcome")
                .filter(|v| v.is_object() && v.get("welcomeId").is_some())
                .unwrap_or(raw_item);
            let welcome_id = w_env
                .get("welcomeId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let coords = w_env.get("coordinates").unwrap_or(&Value::Null);
            let Some(cid) = coords
                .get("conversationId")
                .or_else(|| w_env.get("conversationId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let transition_seq = w_env
                .get("transitionSeq")
                .or_else(|| w_env.get("seq"))
                .and_then(|v| v.as_i64())
                .unwrap_or(1);
            let coords_canon = chat_wire::canonicalize_wire_coordinate(coords, Some(cid))?;
            let is_dr_welcome = w_env.get("$type").and_then(|t| t.as_str())
                == Some("blue.catbird.chat.defs#directRequestWelcomeView");

            let already_joined = self.db.read_tx(|tx| tx.get_conversation(cid))?.is_some();
            if already_joined {
                let has_pending_request = self.db.read_tx(|tx| {
                    Ok(tx
                        .list_requests(None)?
                        .iter()
                        .any(|r| r.conversation_id == cid && r.consent != "accepted"))
                })?;
                let status_str = w_env.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if !welcome_id.is_empty()
                    && status_str != "acknowledged"
                    && !is_dr_welcome
                    && !has_pending_request
                {
                    let ack_body = json!({
                        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
                        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
                        "welcomeId": welcome_id,
                        "transitionSeq": transition_seq,
                        "coordinates": coords_canon,
                        "actorDid": self.normalized_did,
                        "actorDeviceId": canonical_dev_id,
                        "keyId": derive_key_id(signer.public()),
                        "authGeneration": auth_generation,
                        "idempotencyKey": self.hooks.uuid_v4().to_string(),
                        "signedAt": self.hooks.now_rfc3339_millis(),
                    });
                    let _ = self.submit_signed_chat_op(
                        canonical_dev_id,
                        Some(auth_generation),
                        CanonicalOperation::AcknowledgeWelcome,
                        &ack_body,
                        signer,
                    )?;
                }
                continue;
            }

            let welcome_bytes_res = w_env
                .get("opaqueWelcome")
                .or_else(|| w_env.get("welcome").and_then(|w| w.get("opaqueWelcome")))
                .or_else(|| w_env.get("bytes"))
                .ok_or_else(|| MLSError::invalid_input("pending welcome missing opaqueWelcome"))
                .and_then(chat_wire::json_bytes);
            let Ok(welcome_bytes) = welcome_bytes_res else {
                continue;
            };
            // A direct-request Welcome joins only through the checked `C33` import (signed
            // publication, coordinator outcome and `I13` receipt), never here, and is never
            // acknowledged here.
            if is_dr_welcome {
                continue;
            }

            // The frozen `welcomeView` names no sequencer; the conversation state view does.
            let sequencer_did = self
                .query_signed_chat_ds(
                    "blue.catbird.chat.getConversationState",
                    &[("actorDeviceId", canonical_dev_id), ("conversationId", cid)],
                    canonical_dev_id,
                    signer,
                )?
                .get("state")
                .and_then(state_view_sequencer_did)
                .map(str::to_owned);
            let Some(sequencer_did) = sequencer_did else {
                // Joining without the authority would fail every `I13` receipt; the Welcome
                // stays pending until a later sync can read the state view.
                continue;
            };

            // A generic Welcome joins only as the Welcome of the signed
            // `leafRecoveryFulfillmentEntry` at its `transitionSeq`, which the added device can
            // read. A `C33` opening's Welcome has none. A missing or unverifiable one is neither
            // joined nor acknowledged, and is no sync error: a later sync retries it.
            let after_seq = transition_seq.saturating_sub(1).to_string();
            let fulfillment = self
                .query_signed_chat_ds(
                    "blue.catbird.chat.getEntries",
                    &[
                        ("actorDeviceId", canonical_dev_id),
                        ("afterSeq", &after_seq),
                        ("conversationId", cid),
                        ("limit", "1"),
                    ],
                    canonical_dev_id,
                    signer,
                )?
                .get("entries")
                .and_then(Value::as_array)
                .and_then(|entries| entries.first().cloned())
                .filter(|entry| {
                    entry["seq"].as_i64() == Some(transition_seq)
                        && chat_wire::signed_entry_kind(entry).ok()
                            == Some(SignedMutationKind::LeafRecoveryFulfillment)
                });
            let Some(fulfillment) = fulfillment else {
                continue;
            };
            let signed_fulfillment = &fulfillment["signedRequest"];
            let fulfiller_did = signed_fulfillment["body"]["actorDid"]
                .as_str()
                .unwrap_or_default();
            let fulfiller_device = signed_fulfillment["body"]["actorDeviceId"]
                .as_str()
                .unwrap_or_default();

            let mut candidate_dids = BTreeMap::new();
            chat_wire::collect_dids_from_json(w_env, &mut candidate_dids);
            candidate_dids.insert(self.normalized_did.clone(), ());
            candidate_dids.insert(fulfiller_did.to_owned(), ());
            let mut all_auth_keys: Vec<AuthorizedPeerDeviceKey> = Vec::new();
            for did in candidate_dids.keys() {
                let keys = self.fetch_and_cache_authorized_pds_device_keys(did)?;
                all_auth_keys.extend(keys);
            }

            let now_ms = self.hooks.now_ms();

            // Stage over KvWriteOverlay inside `read_tx`, so OpenMLS's one-time KeyPackageBundle
            // deletion never touches SQLite: the fulfiller must be a staged member under its
            // PDS-authorized key, its fulfillment must verify under that key and bind these
            // Welcome bytes to this device, and the joined group must be the state its signed
            // `next` names.
            let verified = self.db.read_tx(|tx| {
                let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
                let storage = OpenMlsKvStorage::new(overlay);
                let provider = self.hooks.openmls_provider(storage);
                let msg_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize Welcome: {e:?}")))?;
                let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
                    return Err(MLSError::Cryptography("not Welcome".to_string()));
                };
                let staged = crate::sim_hooks::build_staged_welcome_at(
                    &provider,
                    &build_join_config(),
                    welcome,
                    None,
                    (now_ms.max(0) as u64) / 1_000,
                )
                .map_err(|e| MLSError::Cryptography(format!("stage Welcome: {e:?}")))?;
                let mut member_dids = Vec::new();
                let mut fulfiller_key = None;
                for m in staged.members() {
                    let Ok((did, device)) =
                        root_did_from_credential_bytes(m.credential.serialized_content())
                    else {
                        continue;
                    };
                    if did == fulfiller_did && device == fulfiller_device {
                        fulfiller_key = Some(m.signature_key);
                    }
                    member_dids.push(did);
                }
                let Some(key) = fulfiller_key.filter(|key| {
                    all_auth_keys.iter().any(|authorized| {
                        authorized.did == fulfiller_did
                            && authorized.device_id == fulfiller_device
                            && authorized.signature_public_key == *key
                    })
                }) else {
                    return Ok(None);
                };
                let Ok(body) = verify_signed_mutation_body(
                    signed_fulfillment,
                    SignedMutationKind::LeafRecoveryFulfillment,
                    &key,
                ) else {
                    return Ok(None);
                };
                let Ok(next) = chat_wire::fulfillment_welcome_next(
                    &body,
                    cid,
                    &welcome_bytes,
                    &self.normalized_did,
                    canonical_dev_id,
                ) else {
                    return Ok(None);
                };
                let group = staged
                    .into_group(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("into_group: {e:?}")))?;
                if chat_wire::require_coordinate_names_group(&next, &group, &provider).is_err() {
                    return Ok(None);
                }
                Ok(Some((member_dids, body, next)))
            })?;
            let Some((member_dids, fulfillment_body, next)) = verified else {
                tracing::warn!(
                    cid,
                    transition_seq,
                    "Welcome is not its verified fulfillment's"
                );
                continue;
            };
            for d in member_dids {
                if candidate_dids.insert(d.clone(), ()).is_none() {
                    let keys = self.fetch_and_cache_authorized_pds_device_keys(&d)?;
                    all_auth_keys.extend(keys);
                }
            }
            let meta_snap_opt = fulfillment_body.get("metadataSnapshot");
            let next_str =
                serde_json::to_string(&next).map_err(|e| MLSError::Internal(e.to_string()))?;

            self.db.write_tx(|tx| {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                let msg_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize Welcome: {e:?}")))?;
                let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
                    return Err(MLSError::Cryptography("not Welcome".to_string()));
                };
                let staged = crate::sim_hooks::build_staged_welcome_at(
                    &provider,
                    &build_join_config(),
                    welcome,
                    None,
                    (now_ms.max(0) as u64) / 1_000,
                )
                .map_err(|e| MLSError::Cryptography(format!("stage Welcome: {e:?}")))?;
                let sender = staged
                    .welcome_sender()
                    .map_err(|e| MLSError::Cryptography(format!("welcome_sender: {e:?}")))?;
                chat_wire::verify_leaf_slice_i4(
                    sender.credential().serialized_content(),
                    sender.signature_key().as_slice(),
                    &all_auth_keys,
                )?;
                let mut group = staged
                    .into_group(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("into_group: {e:?}")))?;
                self.clear_cached_groups();
                for m in group.members() {
                    chat_wire::verify_leaf_slice_i4(
                        m.credential.serialized_content(),
                        m.signature_key.as_slice(),
                        &all_auth_keys,
                    )?;
                }
                chat_wire::require_coordinate_names_group(&next, &group, &provider)?;

                let mut decrypted_title: Option<String> = None;
                if let Some(snap) = meta_snap_opt {
                    if let Some((m_epoch, m_ver, meta)) =
                        chat_wire::try_decrypt_group_metadata_snapshot(&mut group, &provider, snap)
                    {
                        let meta_row = chat_wire::group_metadata_row_from_v1(
                            cid, m_ver, m_epoch, &meta, now_ms,
                        )?;
                        decrypted_title = meta_row.title.clone();
                        tx.upsert_group_metadata(&meta_row)?;
                    }
                    if let Ok(snap_s) = serde_json::to_string(snap) {
                        tx.put_account_meta(
                            &format!("metadata_snapshot_json:{cid}"),
                            &snap_s,
                            now_ms,
                        )?;
                    }
                }

                let gen_i64 = next["generation"].as_i64().unwrap_or(0);
                let row = ConversationRow {
                    conversation_id: cid.to_string(),
                    group_id: group.group_id().as_slice().to_vec(),
                    generation: gen_i64,
                    epoch: group.epoch().as_u64() as i64,
                    last_seq: transition_seq,
                    sequencer_did: sequencer_did.clone(),
                    space_uri: Some(conversation_space_uri(&sequencer_did, cid, gen_i64)),
                    title: decrypted_title,
                    unread_count: 0,
                    updated_at_ms: now_ms,
                };
                tx.upsert_conversation(&row)?;
                Self::prune_pending_commit_transitions(tx, cid, row.generation, row.epoch, false)?;
                tx.put_account_meta(&format!("conversation_coords:{cid}"), &next_str, now_ms)
            })?;

            if !welcome_id.is_empty() {
                let ack_body = json!({
                    "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
                    "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
                    "welcomeId": welcome_id,
                    "transitionSeq": transition_seq,
                    "coordinates": next,
                    "actorDid": self.normalized_did,
                    "actorDeviceId": canonical_dev_id,
                    "keyId": derive_key_id(signer.public()),
                    "authGeneration": auth_generation,
                    "idempotencyKey": self.hooks.uuid_v4().to_string(),
                    "signedAt": self.hooks.now_rfc3339_millis(),
                });
                let _ = self.submit_signed_chat_op(
                    canonical_dev_id,
                    Some(auth_generation),
                    CanonicalOperation::AcknowledgeWelcome,
                    &ack_body,
                    signer,
                )?;
            }
            joined = joined.saturating_add(1);
        }
        Ok(joined)
    }

    #[cfg_attr(not(feature = "sim"), allow(clippy::never_loop))]
    pub(crate) fn fulfill_pending_leaf_recoveries(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
    ) -> Result<u32, MLSError> {
        // The recovery inbox belongs to the requester, not the fulfiller. Scan
        // joined groups without the UI list limit, then ask for current-leaf work.
        let conversation_ids = self.db.read_tx(|tx| {
            let mut stmt = tx
                .conn()
                .prepare(
                    "SELECT conversation_id, group_id FROM conversations ORDER BY conversation_id",
                )
                .map_err(|e| map_rusqlite_err("leaf recovery discovery.prepare", &e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| map_rusqlite_err("leaf recovery discovery.query", &e))?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let mut joined = Vec::new();
            for row in rows {
                let (cid, group_id) =
                    row.map_err(|e| map_rusqlite_err("leaf recovery discovery.row", &e))?;
                if MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
                    .map_err(|e| MLSError::Internal(format!("load recovery group: {e:?}")))?
                    .is_some_and(|group| group.is_active())
                {
                    joined.push(cid);
                }
            }
            Ok(joined)
        })?;

        let mut fulfilled = 0u32;
        for conversation_id in conversation_ids {
            let cid = conversation_id.as_str();
            if self.is_conversation_closed(cid)? {
                continue;
            }
            let Ok(convo_uuid) = uuid::Uuid::parse_str(cid) else {
                continue;
            };
            let resp = match self.query_signed_chat_ds(
                "blue.catbird.chat.getConversationState",
                &[("actorDeviceId", canonical_dev_id), ("conversationId", cid)],
                canonical_dev_id,
                signer,
            ) {
                Ok(resp) => resp,
                // A removed device is no current leaf and owes no fulfillment; Phase 4
                // still delivers its removal (and the kick rescue) from `getEntries`.
                Err(MLSError::InvalidState(code))
                    if matches!(
                        code.as_str(),
                        "ConversationNotFound" | "NotEntitled" | "AccessOutsideMembershipInterval"
                    ) =>
                {
                    continue
                }
                Err(err) => return Err(err),
            };
            let Some(prior) = resp.pointer("/state/coordinates") else {
                continue;
            };
            let Some(req) = resp
                .get("pendingLeafRecoveryRequests")
                .and_then(|v| v.as_array())
                .and_then(|requests| {
                    requests.iter().find(|request| {
                        request["conversationId"].as_str() == Some(cid)
                            && request["recoveryKind"].as_str() == Some("add")
                            && request["status"].as_str() == Some("open")
                            && request.get("boundCoordinate") == Some(prior)
                            && !(request["requesterDid"].as_str()
                                == Some(self.normalized_did.as_str())
                                && request["requesterDeviceId"].as_str() == Some(canonical_dev_id))
                    })
                })
            else {
                continue;
            };
            // One accepted Commit invalidates the other reservations at this
            // coordinate. Discover fresh work on the next sync.
            let Some(recovery_request_id) = req["recoveryRequestId"].as_str() else {
                continue;
            };
            let Some(target_did) = req["requesterDid"].as_str() else {
                continue;
            };
            let Some(target_device_id) = req["requesterDeviceId"].as_str() else {
                continue;
            };
            let reservation = &req["reservation"];
            let Ok(kp_bytes) = chat_wire::json_bytes(&reservation["keyPackage"]["bytes"]) else {
                continue;
            };
            let Ok(kp_ref) = chat_wire::json_bytes(&reservation["keyPackageRef"]) else {
                continue;
            };
            // Enforce `I4` (`ADR-009`): verify target leaf's KeyPackage against PDS `blue.catbird.chat.device`!
            let target_pds_keys = self.fetch_and_cache_authorized_pds_device_keys(target_did)?;
            let MlsMessageBodyIn::KeyPackage(kp_in) =
                MlsMessageIn::tls_deserialize_exact(&kp_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize recovery KP: {e:?}")))?
                    .extract()
            else {
                continue;
            };
            let unverified_cred = kp_in.unverified_credential();
            chat_wire::verify_leaf_slice_i4(
                unverified_cred.credential.serialized_content(),
                unverified_cred.signature_key.as_slice(),
                &target_pds_keys,
            )?;

            let prior_coords = chat_wire::canonicalize_wire_coordinate(prior, Some(cid))?;
            let prior_sv = prior_coords
                .get("stateVersion")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let prior_epoch = prior_coords
                .get("epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let prior_gen = prior_coords
                .get("generation")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let prior_group_id = chat_wire::json_bytes(&prior_coords["groupId"])?;
            let prior_gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
            let prior_ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;

            // Only the sim-only P15 calibration retries; production submits each Commit once.
            #[cfg_attr(not(feature = "sim"), allow(unused_mut, unused_variables))]
            let mut first_attempt = true;
            loop {
                let transition_uuid = self.hooks.uuid_v4();
                let transition_id = transition_uuid.to_string();
                let welcome_id = self.hooks.uuid_v4().to_string();
                let now_ms = self.hooks.now_ms();

                // Stage without changing `openmls_kv`; retain the merged batch in the journal
                // across an uncertain response so sync can recover the accepted own Commit.
                let built = self.db.read_tx(|tx| {
                    let Some(convo) = tx.get_conversation(cid)? else {
                        return Ok(None);
                    };
                    let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
                    let storage = OpenMlsKvStorage::new(&overlay);
                    let provider = self.hooks.openmls_provider(storage);
                    let MlsMessageBodyIn::KeyPackage(kp_for_attempt) =
                        MlsMessageIn::tls_deserialize_exact(&kp_bytes)
                            .map_err(|e| {
                                MLSError::Cryptography(format!("deserialize recovery KP: {e:?}"))
                            })?
                            .extract()
                    else {
                        return Ok(None);
                    };
                    let validated_kp = crate::sim_hooks::validate_key_package_at(
                        kp_for_attempt,
                        provider.crypto(),
                        ProtocolVersion::Mls10,
                        (now_ms.max(0) as u64) / 1_000,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("validate recovery KP: {e:?}")))?;
                    let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    else {
                        return Ok(None);
                    };
                    // A newer peer Commit must be reconciled by getEntries before
                    // we can fulfill a request bound to its MLS coordinate.
                    if !group.is_active()
                        || convo.generation != prior_gen
                        || convo.group_id != prior_group_id
                        || group.epoch().as_u64() != prior_epoch
                    {
                        return Ok(None);
                    }
                    let (local_gch, local_ctag) =
                        chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                    if local_gch.as_slice() != prior_gch.as_slice()
                        || local_ctag.as_slice() != prior_ctag.as_slice()
                    {
                        return Ok(None);
                    }

                    let aad_prior = chat_wire::build_aad_prior_coordinate(
                        &convo_uuid,
                        &convo.group_id,
                        prior_gen,
                        prior_sv,
                        prior_epoch as i64,
                        &prior_gch,
                        &prior_ctag,
                    );
                    let commit_aad_val = json!({
                        "protocolVersion": "1",
                        "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                        "generation": prior_gen,
                        "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                        "prior": aad_prior,
                    });
                    let commit_aad_bytes =
                        canonical_commit_aad_bytes(&commit_aad_val).map_err(|e| {
                            MLSError::Cryptography(format!("canonical_commit_aad_bytes: {e}"))
                        })?;

                    group.set_aad(commit_aad_bytes);
                    let (commit_out, welcome_out, _) = group
                        .add_members(&provider, signer, &[validated_kp])
                        .map_err(|e| {
                            MLSError::Cryptography(format!("recovery add_members: {e:?}"))
                        })?;
                    let staged_pending_batch = overlay.clone_batch();
                    group.merge_pending_commit(&provider).map_err(|e| {
                        MLSError::Cryptography(format!("merge recovery commit: {e:?}"))
                    })?;
                    group.set_aad(Vec::new());

                    let commit_bytes = commit_out
                        .tls_serialize_detached()
                        .map_err(|e| MLSError::Internal(format!("serialize commit: {e:?}")))?;
                    let welcome_bytes = welcome_out
                        .tls_serialize_detached()
                        .map_err(|e| MLSError::Internal(format!("serialize welcome: {e:?}")))?;
                    let next_epoch = group.epoch().as_u64();
                    let (next_gch, next_ctag) =
                        chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                    let meta_row = tx.get_group_metadata(cid)?;
                    let meta_ver = meta_row
                        .as_ref()
                        .map(|m| m.metadata_version.max(1) as u64)
                        .unwrap_or(1);
                    let title_s = meta_row
                        .as_ref()
                        .and_then(|m| m.title.clone())
                        .unwrap_or_default();
                    let desc_s = meta_row
                        .as_ref()
                        .and_then(|m| m.description.clone())
                        .unwrap_or_default();
                    let avatar_opt = meta_row
                        .as_ref()
                        .and_then(chat_wire::space_avatar_from_metadata_row);
                    let meta_key = derive_metadata_key_from_group(
                        &mut group,
                        provider.crypto(),
                        provider.storage(),
                        &convo.group_id,
                        next_epoch,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                    let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                        tx,
                        cid,
                        &meta_key,
                        &convo.group_id,
                        &convo_uuid,
                        prior_gen,
                        next_epoch,
                        &next_gch,
                        &next_ctag,
                        &transition_id,
                        meta_ver,
                        canonical_dev_id,
                        auth_generation,
                        signer.public(),
                        &title_s,
                        &desc_s,
                        avatar_opt,
                    )?;
                    drop(provider);
                    let kv_batch = overlay.into_batch();
                    Ok(Some((
                        kv_batch,
                        staged_pending_batch,
                        convo.group_id,
                        commit_aad_val,
                        commit_bytes,
                        welcome_bytes,
                        next_epoch,
                        next_gch,
                        next_ctag,
                        carried_snap,
                    )))
                })?;

                let Some((
                    kv_batch,
                    staged_pending_batch,
                    group_id,
                    commit_aad_val,
                    commit_bytes,
                    welcome_bytes,
                    next_epoch,
                    next_gch,
                    next_ctag,
                    carried_snap,
                )) = built
                else {
                    break;
                };

                let next_coords = json!({
                    "conversationId": cid,
                    "generation": prior_gen,
                    "stateVersion": prior_sv + 1,
                    "groupId": { "$bytes": STANDARD.encode(&group_id) },
                    "epoch": next_epoch,
                    "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                    "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
                    "lifecycle": "active",
                });

                let commit_sha256: [u8; 32] = Sha256::digest(&commit_bytes).into();
                let fulfill_body = json!({
                    "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
                    "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
                    "transitionId": transition_id,
                    "recoveryRequestId": recovery_request_id,
                    "idempotencyKey": transition_id,
                    "actorDid": self.normalized_did,
                    "actorDeviceId": canonical_dev_id,
                    "keyId": derive_key_id(signer.public()),
                    "authGeneration": auth_generation,
                    "signedAt": self.hooks.now_rfc3339_millis(),
                    "prior": prior_coords,
                    "next": next_coords,
                    "aad": commit_aad_val,
                    "manifest": {
                        "participantChanges": [],
                        "leafChanges": [{
                            "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                            "userDid": target_did,
                            "deviceId": target_device_id,
                            "recoveryRequestId": recovery_request_id,
                            "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                        }],
                        "leafRecoveryRequestId": recovery_request_id,
                        "welcomeBundle": {
                            "welcomeId": welcome_id,
                            "framing": "mlsMessage",
                            "contentType": "welcome",
                            "opaqueWelcome": { "$bytes": STANDARD.encode(&welcome_bytes) },
                            "sha256": STANDARD.encode(Sha256::digest(&welcome_bytes)),
                            "deliveries": [{
                                "recipientDid": target_did,
                                "recipientDeviceId": target_device_id,
                                "provenance": {
                                    "recoveryRequestId": recovery_request_id,
                                    "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                                }
                            }]
                        }
                    },
                    "commit": {
                        "framing": "mlsMessage",
                        "contentType": "publicMessageCommit",
                        "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                        "sha256": STANDARD.encode(commit_sha256),
                    },
                    "metadataSnapshot": carried_snap.clone(),
                });
                let kv_batch = self.persist_pending_commit_transition(PendingCommitTransition {
                    conversation_id: cid.to_string(),
                    transition_id: transition_id.clone(),
                    commit_sha256,
                    prior: prior_coords.clone(),
                    next: next_coords.clone(),
                    kv_batch,
                    removed_participant_did: None,
                })?;

                if crate::planted::is_planted_bug_active(
                    crate::planted::PlantedBug::P2PrematureMergeBeforeServerAccept,
                ) {
                    self.db.write_tx(|tx| {
                        self.clear_cached_groups();
                        Ok(kv_batch.apply(&RusqliteKvBackend(tx.conn()))?)
                    })?;
                }
                let (resp_val, sent) = match self.submit_own_control(
                    canonical_dev_id,
                    auth_generation,
                    CanonicalOperation::SubmitTransition,
                    &fulfill_body,
                    signer,
                ) {
                    Ok(answered) => answered,
                    Err(e) if e.is_stale_coordinates() => {
                        self.db.write_tx(|tx| {
                            tx.delete_pending_op("commit_transition", &transition_id)?;
                            if crate::planted::is_planted_bug_active(
                                crate::planted::PlantedBug::P1KeepLoserStagedCommit,
                            ) {
                                staged_pending_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                                self.clear_cached_groups();
                            }
                            Ok(())
                        })?;
                        // Concurrent peer transition superseded `boundCoordinate`; discard overlay cleanly!
                        break;
                    }
                    Err(e) => {
                        #[cfg(feature = "sim")]
                        if first_attempt
                            && crate::planted::is_planted_bug_active(
                                crate::planted::PlantedBug::P15NonIdempotentCommitSubmitRetry,
                            )
                            && self
                                .db
                                .read_tx(|tx| {
                                    tx.get_pending_op("commit_transition", &transition_id)
                                })?
                                .is_some()
                        {
                            first_attempt = false;
                            self.db.write_tx(|tx| {
                                tx.delete_pending_op("commit_transition", &transition_id)?;
                                Ok(())
                            })?;
                            continue;
                        }
                        return Err(e);
                    }
                };

                // Only this device's own sequenced fulfillment moves anything. A foreign answer
                // keeps the journal unmerged, as a lost response does, for the own echo in sync.
                let authoritative_seq = verify_own_answer(
                    &resp_val,
                    &sent,
                    cid,
                    crate::chat_v2::wire::LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
                )?;
                let coords_str = serde_json::to_string(&next_coords)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let snap_str = serde_json::to_string(&carried_snap)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                if crate::buggify!("after_http_2xx_before_db_commit") {
                    return Err(MLSError::Internal(
                        "sim buggify: after_http_2xx_before_db_commit".to_string(),
                    ));
                }
                self.db.write_tx(|tx| {
                    let current = tx.get_conversation(cid)?;
                    if let Some(c) = &current {
                        if authoritative_seq > c.last_seq.saturating_add(1) {
                            // Preserve the prior epoch until ordered entries recover this Commit.
                            return Ok(());
                        }
                    }
                    kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                    self.clear_cached_groups();
                    if let Some(mut c) = current {
                        c.epoch = next_epoch as i64;
                        if authoritative_seq == c.last_seq + 1 {
                            c.last_seq = authoritative_seq;
                        }
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    tx.put_account_meta(
                        &format!("metadata_snapshot_json:{cid}"),
                        &snap_str,
                        now_ms,
                    )?;
                    tx.put_account_meta(
                        &format!("conversation_coords:{cid}"),
                        &coords_str,
                        now_ms,
                    )?;
                    Self::prune_pending_commit_transitions(
                        tx,
                        cid,
                        prior_gen,
                        next_epoch as i64,
                        false,
                    )?;
                    Ok(())
                })?;
                fulfilled = fulfilled.saturating_add(1);
                break;
            }
        }

        Ok(fulfilled)
    }

    pub(crate) fn sync_conversation_entries(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        convo: &ConversationRow,
    ) -> Result<u32, MLSError> {
        let cid = convo.conversation_id.as_str();
        if self.is_conversation_closed(cid)? {
            return Ok(0);
        }
        if uuid::Uuid::parse_str(cid)
            .ok()
            .filter(|u| u.get_version_num() == 4)
            .is_none()
        {
            return Ok(0);
        }

        let mut sorted_entries: Vec<Value> = Vec::new();
        let mut cursor_seq = convo.last_seq.max(0);
        let pending_receipts: BTreeMap<i64, (String, Option<String>)> = self.db.read_tx(|tx| {
            let mut stmt = tx
                .conn()
                .prepare(
                    "SELECT op_key, json_extract(payload_json, '$.seq'), \
                        json_extract(payload_json, '$.entry_id') FROM pending_ops \
                 WHERE op_kind = ?1 AND json_extract(payload_json, '$.conversation_id') = ?2",
                )
                .map_err(|e| map_rusqlite_err("pending archive receipts.prepare", &e))?;
            let rows = stmt
                .query_map(rusqlite::params![NATIVE_ARCHIVE_RECEIPT_OP, cid], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(|e| map_rusqlite_err("pending archive receipts.query", &e))?;
            let mut pending = BTreeMap::new();
            for row in rows {
                let (message_id, seq, entry_id) =
                    row.map_err(|e| map_rusqlite_err("pending archive receipts.row", &e))?;
                if seq < 1 || pending.insert(seq, (message_id, entry_id)).is_some() {
                    return Err(MLSError::Cryptography(
                        "ambiguous pending archive receipt sequence".into(),
                    ));
                }
            }
            Ok(pending)
        })?;
        if let Some((seq, _)) = pending_receipts.first_key_value() {
            cursor_seq = cursor_seq.min(seq.saturating_sub(1));
        }
        for _ in 0..50 {
            let after_seq_str = cursor_seq.to_string();
            let resp = match self.query_signed_chat_ds(
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("afterSeq", &after_seq_str),
                    ("conversationId", cid),
                    ("limit", "100"),
                ],
                canonical_dev_id,
                signer,
            ) {
                Ok(resp) => resp,
                Err(MLSError::InvalidState(code)) if code == "ConversationNotFound" => break,
                Err(err) => return Err(err),
            };
            let Some(page_entries) = resp.get("entries").and_then(|v| v.as_array()) else {
                break;
            };
            if page_entries.is_empty() {
                break;
            }
            let page_len = page_entries.len();
            let page_max_seq = page_entries
                .iter()
                .filter_map(|e| e.get("seq").and_then(|s| s.as_i64()))
                .max()
                .unwrap_or(cursor_seq);
            sorted_entries.extend(page_entries.iter().cloned());
            if page_len < 100 || page_max_seq <= cursor_seq {
                break;
            }
            cursor_seq = page_max_seq;
        }
        if sorted_entries.is_empty() {
            return Ok(0);
        }

        sorted_entries.sort_by_key(|e| e.get("seq").and_then(|s| s.as_i64()).unwrap_or(0));
        sorted_entries.dedup_by_key(|e| e.get("seq").and_then(|s| s.as_i64()).unwrap_or(0));

        // Pre-fetch PDS `blue.catbird.chat.device` keys (`I4`) for all DIDs referenced in batch
        // plus all current local `MlsGroup` members.
        let mut candidate_dids = BTreeMap::new();
        for entry in &sorted_entries {
            chat_wire::collect_dids_from_json(entry, &mut candidate_dids);
        }
        let existing_member_dids: Vec<String> = self.db.read_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let mut found = Vec::new();
            if let Some(group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group members: {e:?}")))?
            {
                for m in group.members() {
                    if let Ok((d, _)) =
                        root_did_from_credential_bytes(m.credential.serialized_content())
                    {
                        found.push(d);
                    }
                }
            }
            Ok(found)
        })?;
        for d in existing_member_dids {
            candidate_dids.insert(d, ());
        }
        let mut auth_keys_by_did: BTreeMap<String, Vec<AuthorizedPeerDeviceKey>> = BTreeMap::new();
        for did in candidate_dids.keys() {
            let keys = self.fetch_and_cache_authorized_pds_device_keys(did)?;
            auth_keys_by_did.insert(did.clone(), keys);
        }
        let flat_auth_keys: Vec<AuthorizedPeerDeviceKey> = auth_keys_by_did
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        let mut max_seq = convo.last_seq;
        let mut applied_count = 0u32;
        let mut saw_c33_accept = false;
        let mut was_kicked = false;
        let mut was_closed = false;

        const DIRECT_REQUEST_ENTRY: &str = "blue.catbird.chat.defs#directRequestEntry";
        const DIRECT_REQUEST_ACCEPTANCE_ENTRY: &str =
            "blue.catbird.chat.defs#directRequestAcceptanceEntry";
        const DIRECT_REQUEST_ACCEPTANCE_BODY: &str =
            "blue.catbird.chat.defs#directRequestAcceptanceBody";
        for (index, entry) in sorted_entries.iter().enumerate() {
            let entry_seq = entry.get("seq").and_then(|v| v.as_i64()).unwrap_or(max_seq);
            let label = entry.get("$type").and_then(Value::as_str);
            let signed_req = entry.get("signedRequest").unwrap_or(entry);
            let body = signed_req.get("body").unwrap_or(signed_req);
            let body_type = body.get("$type").and_then(|v| v.as_str()).unwrap_or("");
            let now_ms = self.hooks.now_ms();
            // The exact `$type` label classifies an entry; an unlabelled one, its signed body.
            let is_application = label.map_or(
                body_type == SignedMutationKind::ApplicationSend.type_id(),
                |label| label == crate::chat_v2::wire::APPLICATION_ENTRY_KIND,
            );
            if pending_receipts.contains_key(&entry_seq) && !is_application {
                return Err(MLSError::Cryptography(
                    "pending archive receipt was replaced by a non-application entry".into(),
                ));
            }
            if entry_seq <= convo.last_seq && !is_application {
                // Receipt-only replay must not reapply already accepted control effects.
                continue;
            }

            // Every entry below verifies before any effect. One that does not stops this
            // conversation's sync with the cursor below it: no later entry carries it past.
            if label == Some(crate::chat_v2::wire::ACCOUNT_DELETED_ENTRY_KIND) {
                let (deleted_did, seq) = self
                    .verify_account_deleted_entry(cid, &convo.sequencer_did, entry)?
                    .ok_or_else(|| {
                        MLSError::Cryptography(
                            "I13: account deletion authority does not verify".into(),
                        )
                    })?;
                self.apply_verified_account_deletion(cid, &deleted_did, seq)?;
                applied_count = applied_count.saturating_add(1);
                max_seq = max_seq.max(entry_seq);
                continue;
            }
            if label == Some(DIRECT_REQUEST_ENTRY) {
                return Err(MLSError::Cryptography(
                    "C33 opening: only the checked import consumes it".into(),
                ));
            }
            if label == Some(DIRECT_REQUEST_ACCEPTANCE_ENTRY)
                || body_type == DIRECT_REQUEST_ACCEPTANCE_BODY
            {
                // Only a verified direct-request acceptance touches the request, its pending
                // acceptance and the staged opening.
                let next = serde_json::to_string(&self.verify_direct_request_acceptance_entry(
                    convo,
                    entry_seq,
                    entry,
                    &flat_auth_keys,
                    canonical_dev_id,
                    signer,
                )?)?;
                self.db.write_tx(|tx| {
                    let mut reqs = tx.list_requests(None)?;
                    for r in &mut reqs {
                        if r.conversation_id == cid {
                            // The acceptance is sequenced; nothing remains to replay.
                            tx.delete_pending_op(
                                super::live_plane::DIRECT_REQUEST_ACCEPTANCE_OP,
                                &r.request_id,
                            )?;
                            r.consent = "accepted".to_string();
                            r.updated_at_ms = now_ms;
                            tx.upsert_request(r)?;
                        }
                    }
                    tx.put_account_meta(&format!("conversation_coords:{cid}"), &next, now_ms)?;
                    if let Some(mut c) = tx.get_conversation(cid)? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    Ok(())
                })?;
                saw_c33_accept = true;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            // Control kinds come from the signed body; a relabelled entry is refused. The actor
            // labels below only select the authority the body must then verify under.
            let kind = if is_application {
                None
            } else {
                Some(chat_wire::signed_entry_kind(entry)?)
            };
            let actor_did = body["actorDid"].as_str().unwrap_or_default();
            let actor_dev = body["actorDeviceId"].as_str().unwrap_or_default();
            let earlier = &sorted_entries[..index];

            if let Some(
                kind @ (SignedMutationKind::PolicyTransition
                | SignedMutationKind::MetadataTransition
                | SignedMutationKind::ParticipantAcceptance
                | SignedMutationKind::ZeroLeafLeave),
            ) = kind
            {
                // Policy and metadata are signed by a current leaf; an acceptance or a zero-leaf
                // leave by a participant device. An acceptance's invitation always verifies, a
                // leave's whenever its DID holds no current leaf. Each only steps `stateVersion`:
                // the verified `next`, and a metadata transition's verified snapshot, are all
                // that is written. An acceptance never touches a direct request.
                let leaf_signed = matches!(
                    kind,
                    SignedMutationKind::PolicyTransition | SignedMutationKind::MetadataTransition
                );
                let key = if leaf_signed {
                    self.participant_leaf_key(
                        cid,
                        signed_req,
                        &flat_auth_keys,
                        canonical_dev_id,
                        signer,
                    )?
                } else {
                    self.pds_device_key(actor_did, actor_dev, &auth_keys_by_did)?
                };
                let verified = verify_signed_mutation_body(signed_req, kind, &key)?;
                if !leaf_signed {
                    self.require_participant(
                        canonical_dev_id,
                        signer,
                        cid,
                        actor_did,
                        (kind == SignedMutationKind::ParticipantAcceptance)
                            .then(|| &verified["invitationProvenance"]),
                        entry_seq,
                        earlier,
                        &auth_keys_by_did,
                    )?;
                }
                let next =
                    serde_json::to_string(&chat_wire::verify_state_version_step(&verified, cid)?)?;
                let is_metadata = kind == SignedMutationKind::MetadataTransition;
                let snap_opt = verified.get("metadataSnapshot").filter(|_| is_metadata);
                self.db.write_tx(|tx| {
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(());
                    };
                    if let Some(snap) = snap_opt {
                        let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                        let provider = self.hooks.openmls_provider(storage);
                        if let Some(mut group) =
                            MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        {
                            if let Some((m_epoch, m_ver, meta)) =
                                chat_wire::try_decrypt_group_metadata_snapshot(
                                    &mut group, &provider, snap,
                                )
                            {
                                let meta_row = chat_wire::group_metadata_row_from_v1(
                                    cid, m_ver, m_epoch, &meta, now_ms,
                                )?;
                                c.title = meta_row.title.clone();
                                tx.upsert_group_metadata(&meta_row)?;
                            }
                        }
                        if let Ok(snap_s) = serde_json::to_string(snap) {
                            tx.put_account_meta(
                                &format!("metadata_snapshot_json:{cid}"),
                                &snap_s,
                                now_ms,
                            )?;
                        }
                    }
                    tx.put_account_meta(&format!("conversation_coords:{cid}"), &next, now_ms)?;
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)
                })?;
                if is_metadata {
                    self.notify_change(PlatformChangeEvent::GroupMetadataUpdated {
                        conversation_id: cid.to_string(),
                    });
                }
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if kind == Some(SignedMutationKind::ConversationClose) {
                // A current leaf closes. Otherwise only a direct conversation's participant
                // device does: its pending invitee may close it. The close retires exactly the
                // signed `prior` with `stateVersion + 1`.
                let is_leaf = self
                    .current_leaves(cid)?
                    .iter()
                    .any(|(did, device, _)| did == actor_did && device == actor_dev);
                let key = if is_leaf {
                    self.participant_leaf_key(
                        cid,
                        signed_req,
                        &flat_auth_keys,
                        canonical_dev_id,
                        signer,
                    )?
                } else if body["conversationKind"] == "direct" {
                    self.pds_device_key(actor_did, actor_dev, &auth_keys_by_did)?
                } else {
                    return Err(MLSError::Cryptography(
                        "I4: control entry signer is not an authorized active participant device"
                            .into(),
                    ));
                };
                let verified = verify_signed_mutation_body(
                    signed_req,
                    SignedMutationKind::ConversationClose,
                    &key,
                )?;
                if !is_leaf {
                    self.require_participant(
                        canonical_dev_id,
                        signer,
                        cid,
                        actor_did,
                        None,
                        entry_seq,
                        earlier,
                        &auth_keys_by_did,
                    )?;
                }
                let retired = chat_wire::verify_coordinate_step(
                    &verified["prior"],
                    &verified["retired"],
                    cid,
                    "superseded",
                )?;
                self.apply_terminal_close(cid, Some(&retired), Some(entry_seq))?;
                was_closed = true;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                break;
            }

            if let Some(
                kind @ (SignedMutationKind::ResetRequest
                | SignedMutationKind::ResetActivation
                | SignedMutationKind::LeaveCancellation
                | SignedMutationKind::Creation
                | SignedMutationKind::LeaveRequest),
            ) = kind
            {
                // Verified and bound to this conversation, these move only the cursor: a leave
                // request is signed by a current leaf, the others by a participant device. This
                // client does not apply a reset activation.
                let verified = if kind == SignedMutationKind::LeaveRequest {
                    let key = self.participant_leaf_key(
                        cid,
                        signed_req,
                        &flat_auth_keys,
                        canonical_dev_id,
                        signer,
                    )?;
                    verify_signed_mutation_body(signed_req, kind, &key)?
                } else {
                    let key = self.pds_device_key(actor_did, actor_dev, &auth_keys_by_did)?;
                    let verified = verify_signed_mutation_body(signed_req, kind, &key)?;
                    self.require_participant(
                        canonical_dev_id,
                        signer,
                        cid,
                        actor_did,
                        None,
                        entry_seq,
                        earlier,
                        &auth_keys_by_did,
                    )?;
                    verified
                };
                let conversation = match kind {
                    SignedMutationKind::Creation | SignedMutationKind::LeaveCancellation => {
                        &verified["conversationId"]
                    }
                    _ => &verified["prior"]["conversationId"],
                };
                if conversation.as_str() != Some(cid)
                    || ["next", "retired", "successor"].iter().any(|field| {
                        verified
                            .get(field)
                            .is_some_and(|coordinate| coordinate["conversationId"] != cid)
                    })
                {
                    return Err(MLSError::Cryptography(
                        "control entry is signed for a different conversation".into(),
                    ));
                }
                self.db.write_tx(|tx| {
                    if let Some(mut c) = tx.get_conversation(cid)? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    Ok(())
                })?;
                max_seq = max_seq.max(entry_seq);
                continue;
            }

            if let Some(
                kind @ (SignedMutationKind::CommitTransition
                | SignedMutationKind::LeafRecoveryFulfillment
                | SignedMutationKind::LeaveCommitFulfillment),
            ) = kind
            {
                let is_own_echo = actor_did == self.normalized_did && actor_dev == canonical_dev_id;
                // Actor labels are only a routing hint. The complete body, manifest and metadata
                // included, verifies first: an own echo under this device's signer, a peer's
                // under its signer's current leaf key. Nothing is read from the entry around it.
                let verified_body = if is_own_echo {
                    chat_wire::verify_own_commit_body(signed_req, signer.public())?
                } else {
                    let key = self.participant_leaf_key(
                        cid,
                        signed_req,
                        &flat_auth_keys,
                        canonical_dev_id,
                        signer,
                    )?;
                    verify_signed_mutation_body(signed_req, kind, &key)?
                };
                let body = &verified_body;
                if body["prior"]["conversationId"].as_str() != Some(cid)
                    || body["next"]["conversationId"].as_str() != Some(cid)
                {
                    return Err(MLSError::Cryptography(
                        "Commit is signed for a different conversation".into(),
                    ));
                }
                let commit_bytes_opt = body
                    .pointer("/commit/bytes")
                    .and_then(|b| chat_wire::json_bytes(b).ok());
                let snap_opt = body.get("metadataSnapshot");
                let next_opt = body
                    .get("next")
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok());

                let self_removed = self.db.write_tx(|tx| {
                    self.clear_cached_groups();
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(false);
                    };
                    let mut removed_self = false;
                    if is_own_echo {
                        let transition_id = body["transitionId"].as_str().unwrap_or("");
                        let next = next_opt.as_ref().ok_or_else(|| {
                            MLSError::Cryptography("own Commit missing next coordinate".into())
                        })?;
                        let next_epoch = next["epoch"].as_u64().ok_or_else(|| {
                            MLSError::Cryptography("own Commit has invalid next epoch".into())
                        })?;
                        let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                        let provider = self.hooks.openmls_provider(storage);
                        let mut group =
                            MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                                .map_err(|e| {
                                    MLSError::Internal(format!("load own Commit group: {e:?}"))
                                })?
                                .ok_or_else(|| MLSError::GroupNotFound {
                                    message: format!("own Commit group missing for {cid}"),
                                })?;
                        let next_generation = next["generation"].as_i64().ok_or_else(|| {
                            MLSError::Cryptography("own Commit has invalid next generation".into())
                        })?;
                        if next_generation < c.generation
                            || (next_generation == c.generation
                                && next_epoch < group.epoch().as_u64())
                        {
                            // A valid older echo may close a sequence gap after a later Commit
                            // is already durable. Retire its secrets without regressing state.
                            c.epoch = group.epoch().as_u64() as i64;
                            Self::prune_pending_commit_transitions(
                                tx,
                                cid,
                                c.generation,
                                c.epoch,
                                false,
                            )?;
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = now_ms;
                            tx.upsert_conversation(&c)?;
                            return Ok(false);
                        }
                        if next_generation != c.generation {
                            return Err(MLSError::Cryptography(
                                "own Commit does not match the local generation".into(),
                            ));
                        }
                        if let Some(raw) = tx.get_pending_op("commit_transition", transition_id)? {
                            let pending: PendingCommitTransition = serde_json::from_str(&raw)
                                .map_err(|e| {
                                    MLSError::Internal(format!("parse pending commit: {e}"))
                                })?;
                            let commit_bytes = commit_bytes_opt.as_ref().ok_or_else(|| {
                                MLSError::Cryptography("own Commit missing commit bytes".into())
                            })?;
                            let digest: [u8; 32] = Sha256::digest(commit_bytes).into();
                            if pending.conversation_id != cid
                                || pending.transition_id != transition_id
                                || pending.commit_sha256 != digest
                                || &pending.next != next
                            {
                                return Err(MLSError::Cryptography(
                                    "pending commit does not match sequenced own Commit".into(),
                                ));
                            }
                            if group.epoch().as_u64() < next_epoch {
                                let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(
                                    &group, &provider,
                                )?;
                                if pending.prior["epoch"].as_u64() != Some(group.epoch().as_u64())
                                    || pending.prior["generation"].as_i64() != Some(c.generation)
                                    || chat_wire::json_bytes(&pending.prior["groupId"])?
                                        != c.group_id
                                    || chat_wire::json_bytes(&pending.prior["groupContextHash"])?
                                        != gch
                                    || chat_wire::json_bytes(&pending.prior["confirmationTag"])?
                                        != ctag
                                {
                                    return Err(MLSError::Cryptography(
                                        "pending commit does not match local prior MLS state"
                                            .into(),
                                    ));
                                }
                                pending.kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                                group = MlsGroup::load(
                                    provider.storage(),
                                    &GroupId::from_slice(&c.group_id),
                                )
                                .map_err(|e| {
                                    MLSError::Internal(format!("reload recovered Commit: {e:?}"))
                                })?
                                .ok_or_else(|| {
                                    MLSError::GroupNotFound {
                                        message: format!(
                                            "recovered Commit group missing for {cid}"
                                        ),
                                    }
                                })?;
                                if group.epoch().as_u64() != next_epoch {
                                    return Err(MLSError::Cryptography(
                                        "pending commit batch did not restore its next epoch"
                                            .into(),
                                    ));
                                }
                                if let Some(target_did) = &pending.removed_participant_did {
                                    tx.put_account_meta(
                                        &format!("last_removed_member:{cid}"),
                                        target_did,
                                        now_ms,
                                    )?;
                                    tx.put_pending_op(
                                        super::live_plane::PARTICIPANT_REMOVAL_OP,
                                        &super::live_plane::participant_removal_key(
                                            cid, target_did,
                                        ),
                                        &super::live_plane::participant_removal_payload(
                                            cid, target_did,
                                        ),
                                        now_ms,
                                    )?;
                                }
                            }
                        } else if group.epoch().as_u64() < next_epoch {
                            return Err(MLSError::InvalidState(format!(
                                "unapplied own Commit {transition_id} has no recovery journal"
                            )));
                        }
                        if group.epoch().as_u64() == next_epoch {
                            let (gch, ctag) =
                                chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                            if next["generation"].as_i64() != Some(c.generation)
                                || chat_wire::json_bytes(&next["groupId"])? != c.group_id
                                || chat_wire::json_bytes(&next["groupContextHash"])? != gch
                                || chat_wire::json_bytes(&next["confirmationTag"])? != ctag
                            {
                                return Err(MLSError::Cryptography(
                                    "own Commit does not match recovered MLS state".into(),
                                ));
                            }
                        }
                        c.epoch = group.epoch().as_u64() as i64;
                    }
                    if !is_own_echo {
                        // A peer Commit applies only from its verified body: the MLS Commit for
                        // exactly the local epoch, sent by exactly the signed actor device, whose
                        // merged state the signed `next` names at `stateVersion + 1` in this
                        // generation.
                        let refused =
                            |what: &str| MLSError::Cryptography(format!("peer Commit: {what}"));
                        let commit_bytes = commit_bytes_opt
                            .as_ref()
                            .ok_or_else(|| refused("missing commit bytes"))?;
                        let next = next_opt
                            .as_ref()
                            .ok_or_else(|| refused("missing next coordinate"))?;
                        let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                        let provider = self.hooks.openmls_provider(storage);
                        let mut group =
                            MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                                .ok_or_else(|| MLSError::GroupNotFound {
                                    message: format!("peer Commit group missing for {cid}"),
                                })?;
                        let proto = MlsMessageIn::tls_deserialize_exact(commit_bytes)
                            .map_err(|e| {
                                MLSError::Cryptography(format!("deserialize Commit: {e:?}"))
                            })?
                            .try_into_protocol_message()
                            .map_err(|e| {
                                MLSError::Cryptography(format!("commit protocol msg: {e:?}"))
                            })?;
                        if proto.epoch() != group.epoch() {
                            return Err(refused("not for the local MLS epoch"));
                        }
                        let retain_loser = crate::planted::is_planted_bug_active(
                            crate::planted::PlantedBug::P1KeepLoserStagedCommit,
                        ) && group.pending_commit().is_some();
                        if !retain_loser {
                            let processed =
                                group.process_message(&provider, proto).map_err(|e| {
                                    MLSError::Cryptography(format!("process Commit: {e:?}"))
                                })?;
                            if processed.credential().serialized_content()
                                != format!("{actor_did}#{actor_dev}").as_bytes()
                            {
                                return Err(refused("MLS sender is not the signed actor device"));
                            }
                            let commit_sender = processed.sender().clone();
                            let ProcessedMessageContent::StagedCommitMessage(staged) =
                                processed.into_content()
                            else {
                                return Err(refused("not an MLS Commit"));
                            };
                            chat_wire::verify_staged_commit_slice_i4(
                                &group,
                                &commit_sender,
                                &staged,
                                &flat_auth_keys,
                            )?;
                            removed_self = staged.self_removed();
                            group.merge_staged_commit(&provider, *staged).map_err(|e| {
                                MLSError::Cryptography(format!("merge_staged_commit: {e:?}"))
                            })?;
                            // A Commit removing this device merges as public state only
                            // (OpenMLS): the removed device never derives the new epoch's
                            // transcript hash and confirmation tag, so it checks the group and
                            // epoch `next` names. Every other device checks the full MLS state.
                            if !removed_self {
                                chat_wire::require_coordinate_names_group(next, &group, &provider)?;
                            } else if chat_wire::json_bytes(&next["groupId"])?
                                != group.group_id().as_slice()
                                || next["epoch"].as_u64() != Some(group.epoch().as_u64())
                            {
                                return Err(refused("next does not name the merged group"));
                            }
                            let stepped = body["prior"]["stateVersion"]
                                .as_i64()
                                .and_then(|version| version.checked_add(1));
                            if stepped.is_none()
                                || next["stateVersion"].as_i64() != stepped
                                || next["generation"].as_i64() != Some(c.generation)
                            {
                                return Err(refused(
                                    "next does not step stateVersion in this generation",
                                ));
                            }
                            c.epoch = group.epoch().as_u64() as i64;
                        }
                        if let Some(snap) = snap_opt {
                            if let Some((m_epoch, m_ver, meta)) =
                                chat_wire::try_decrypt_group_metadata_snapshot(
                                    &mut group, &provider, snap,
                                )
                            {
                                let meta_row = chat_wire::group_metadata_row_from_v1(
                                    cid, m_ver, m_epoch, &meta, now_ms,
                                )?;
                                c.title = meta_row.title.clone();
                                tx.upsert_group_metadata(&meta_row)?;
                            }
                        }
                    }
                    let superseded = next_opt.as_ref().is_some_and(|next| {
                        next["generation"].as_i64().is_some_and(|generation| {
                            generation < c.generation
                                || (generation == c.generation
                                    && next["epoch"].as_i64().is_some_and(|epoch| epoch < c.epoch))
                        })
                    });
                    if !superseded {
                        if let Some(snap) = snap_opt {
                            if let Ok(snap_s) = serde_json::to_string(snap) {
                                tx.put_account_meta(
                                    &format!("metadata_snapshot_json:{cid}"),
                                    &snap_s,
                                    now_ms,
                                )?;
                            }
                        }
                        if let Some(nc) = &next_opt {
                            let s = serde_json::to_string(nc)
                                .map_err(|e| MLSError::Internal(e.to_string()))?;
                            tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, now_ms)?;
                        }
                    }
                    // Epoch-key erasure is atomic with accepted MLS state and its cursor.
                    Self::prune_pending_commit_transitions(
                        tx,
                        cid,
                        c.generation,
                        c.epoch,
                        removed_self,
                    )?;
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)?;
                    Ok(removed_self)
                })?;

                if self_removed {
                    was_kicked = true;
                }
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if is_application {
                let pending = pending_receipts.get(&entry_seq);
                let wire_message_id = body
                    .get("messageId")
                    .or_else(|| entry.get("messageId"))
                    .and_then(Value::as_str);
                if pending.is_some_and(|(mid, expected_entry_id)| {
                    wire_message_id.is_some_and(|wire| wire != mid.as_str())
                        || expected_entry_id.as_deref().is_some_and(|expected| {
                            entry.get("entryId").and_then(Value::as_str) != Some(expected)
                        })
                }) {
                    return Err(MLSError::Cryptography(
                        "entry differs from retained NSE message identity".into(),
                    ));
                }
                let msg_id = pending
                    .map(|(mid, _)| mid.as_str())
                    .or(wire_message_id)
                    .or_else(|| entry.get("entryId").and_then(Value::as_str))
                    .unwrap_or("");
                if msg_id.is_empty() {
                    return Err(MLSError::Cryptography(
                        "application entry has no message id".into(),
                    ));
                }

                let verified_application_body =
                    if entry.get("payloadPruned").and_then(Value::as_bool) == Some(true) {
                        None
                    } else {
                        let actor_did =
                            body.get("actorDid")
                                .and_then(Value::as_str)
                                .ok_or_else(|| {
                                    MLSError::Cryptography(
                                        "applicationSendBody missing actorDid".into(),
                                    )
                                })?;
                        let actor_device_id = body
                            .get("actorDeviceId")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                MLSError::Cryptography(
                                    "applicationSendBody missing actorDeviceId".into(),
                                )
                            })?;
                        let outer_key = flat_auth_keys
                            .iter()
                            .find(|key| key.did == actor_did && key.device_id == actor_device_id)
                            .ok_or_else(|| {
                                MLSError::Cryptography(
                                    "application outer sender key is not authorized".into(),
                                )
                            })?;
                        let verified = verify_signed_mutation_body(
                            signed_req,
                            SignedMutationKind::ApplicationSend,
                            &outer_key.signature_public_key,
                        );
                        // A tampered application entry is unreadable here, before decryption,
                        // so the P9 plant (forced rejoin on an unreadable entry) fires here too.
                        #[cfg(feature = "sim")]
                        if verified.is_err()
                            && crate::planted::is_planted_bug_active(
                                crate::planted::PlantedBug::P9AutomatedForcedRejoinOnDecryptFailure,
                            )
                        {
                            self.plant_p9_automated_forced_rejoin(cid, canonical_dev_id, signer)?;
                        }
                        let verified = verified?;
                        if verified["actorDid"].as_str() != Some(actor_did)
                            || verified["actorDeviceId"].as_str() != Some(actor_device_id)
                            || verified["messageId"].as_str() != Some(msg_id)
                            || verified["prior"]["conversationId"].as_str() != Some(cid)
                            || entry
                                .get("conversationId")
                                .and_then(Value::as_str)
                                .is_some_and(|conversation| conversation != cid)
                        {
                            return Err(MLSError::Cryptography(
                                "signed application coordinates or sender mismatch".into(),
                            ));
                        }
                        Some(verified)
                    };
                let body = verified_application_body.as_ref().unwrap_or(body);

                let already_have = self.db.read_tx(|tx| tx.get_message(msg_id))?.is_some();
                #[cfg(feature = "sim")]
                let already_have = already_have
                    && !(self.sim_reopened
                        && crate::planted::is_planted_bug_active(
                            crate::planted::PlantedBug::P12SkipMessageIdDedupeAfterCrashRestart,
                        ));
                let has_archive_evidence = self.db.read_tx(|tx| {
                    Ok(tx
                        .get_labyrinth_state(&format!("native.message:{cid}:{msg_id}"))?
                        .is_some())
                })?;
                if already_have && has_archive_evidence {
                    let receipt = entry
                        .get("sequencerReceipt")
                        .filter(|value| value.is_object())
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "I13: cached application entry missing sequencerReceipt".into(),
                            )
                        })?;
                    let entry_id = entry
                        .get("entryId")
                        .and_then(Value::as_str)
                        .unwrap_or(msg_id);
                    self.finish_received_archive_evidence(
                        cid, msg_id, entry_seq, entry_id, receipt,
                    )?;
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }
                // Enforce `I13` on every remaining path: the entry's own sequencer receipt.
                let rcpt_val = entry
                    .get("sequencerReceipt")
                    .filter(|v| v.is_object())
                    .ok_or_else(|| {
                        MLSError::Cryptography(format!(
                            "I13: applicationEntry {msg_id} at seq {entry_seq} missing sequencerReceipt"
                        ))
                    })?;
                let expected_rcpt_entry_id = entry
                    .get("entryId")
                    .and_then(|v| v.as_str())
                    .unwrap_or(msg_id);
                // The exact method the receipt's `kid` names, resolved outside `write_tx` (`I6`).
                let receipt_key = || -> Result<Vec<u8>, MLSError> {
                    let kid = chat_wire::sequencer_receipt_kid(&convo.sequencer_did, rcpt_val)?;
                    self.resolve_sequencer_receipt_key(&convo.sequencer_did, kid)?
                        .ok_or_else(|| {
                            MLSError::Cryptography(format!(
                                "I13: unable to resolve `{}` receipt method {kid}",
                                convo.sequencer_did
                            ))
                        })
                };
                if entry.get("payloadPruned").and_then(Value::as_bool) == Some(true) {
                    // Only the signed receipt remains: it must sequence exactly this entry.
                    let rcpt_sec1 = receipt_key()?;
                    self.db.write_tx(|tx| {
                        let mut c = tx
                            .get_conversation(cid)?
                            .ok_or_else(|| MLSError::group_not_found(cid))?;
                        chat_wire::verify_pruned_application_receipt(
                            rcpt_val,
                            &rcpt_sec1,
                            &c.sequencer_did,
                            cid,
                            &c.group_id,
                            expected_rcpt_entry_id,
                            entry_seq,
                        )?;
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)
                    })?;
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }

                let app_obj = body
                    .get("applicationMessage")
                    .or_else(|| entry.get("applicationMessage"))
                    .unwrap_or(entry);
                let ct_bytes = chat_wire::json_bytes(
                    app_obj
                        .get("bytes")
                        .or_else(|| entry.get("ciphertext"))
                        .ok_or_else(|| {
                            MLSError::invalid_input("applicationMessageEntry missing bytes")
                        })?,
                )?;

                if crate::planted::is_planted_bug_active(
                    crate::planted::PlantedBug::P13AdvanceSeqCursorBeforeDurableStore,
                ) {
                    self.db.write_tx(|tx| {
                        if let Some(mut c) = tx.get_conversation(cid)? {
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = now_ms;
                            tx.upsert_conversation(&c)?;
                        }
                        Ok(())
                    })?;
                    return Err(MLSError::Internal(
                        "sim planted P13: interrupted after durable cursor advance before message storage"
                            .to_string(),
                    ));
                }
                if let Some(raw) = self
                    .db
                    .read_tx(|tx| tx.get_pending_op("application_send", msg_id))?
                {
                    let pending: super::live_plane::PendingApplicationSend =
                        serde_json::from_str(&raw)
                            .map_err(|e| MLSError::Internal(format!("parse pending send: {e}")))?;
                    let reserved_ciphertext = STANDARD
                        .decode(&pending.archive.mls_ciphertext_b64)
                        .map_err(|e| MLSError::Internal(format!("pending send ciphertext: {e}")))?;
                    if pending.archive.conversation_id != cid
                        || pending.archive.sender_did != self.normalized_did
                        || pending.archive.sender_device_id != canonical_dev_id
                        || ct_bytes != reserved_ciphertext
                    {
                        return Err(MLSError::Cryptography(
                            "pending send does not match sequenced application ciphertext".into(),
                        ));
                    }
                    // Own MLS ciphertext is not decryptable. Recover only from the exact durable
                    // send journal, with the same I13 receipt verification as a successful send.
                    self.finish_application_send(
                        pending,
                        rcpt_val,
                        expected_rcpt_entry_id,
                        Some(entry_seq),
                        true,
                    )?;
                    self.notify_change(PlatformChangeEvent::MessagesUpdated {
                        conversation_id: cid.to_string(),
                    });
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }
                let rcpt_sec1 = receipt_key()?;
                // Set only when OpenMLS can never open this current-epoch entry for this device.
                let mut undecryptable = None;
                let decrypt_result = self.db.write_tx(|tx| {
                    self.clear_cached_groups();
                    let mut c = tx
                        .get_conversation(cid)?
                        .ok_or_else(|| MLSError::group_not_found(cid))?;
                    let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                    let provider = self.hooks.openmls_provider(storage);
                    // No group, no roster to authenticate against: never store, advance or ACK.
                    let mut group =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                            .ok_or_else(|| MLSError::group_not_found(cid))?;
                    let msg_in = MlsMessageIn::tls_deserialize_exact(&ct_bytes).map_err(|e| {
                        MLSError::Cryptography(format!("deserialize app msg: {e:?}"))
                    })?;
                    let proto = msg_in
                        .try_into_protocol_message()
                        .map_err(|e| MLSError::Cryptography(format!("app protocol msg: {e:?}")))?;
                    let msg_epoch = proto.epoch().as_u64() as i64;
                    let current_epoch = proto.epoch() == group.epoch();
                    let processed = group.process_message(&provider, proto).map_err(|e| {
                        if current_epoch {
                            undecryptable = chat_wire::permanent_decrypt_failure(&e)
                                .map(|reason| (reason, msg_epoch));
                        }
                        MLSError::Cryptography(format!("decrypt app msg: {e:?}"))
                    })?;
                    let sender_cred = processed.credential().clone();
                    let aad_bytes = processed.aad().to_vec();
                    let signed_aad =
                        canonical_application_aad_bytes(body.get("aad").ok_or_else(|| {
                            MLSError::Cryptography("signed application body missing MLS AAD".into())
                        })?)
                        .map_err(|error| {
                            MLSError::Cryptography(format!(
                                "invalid signed application AAD: {error}"
                            ))
                        })?;
                    if signed_aad != aad_bytes {
                        return Err(MLSError::Cryptography(
                            "decrypted MLS AAD differs from signed outer application AAD".into(),
                        ));
                    }

                    // Verify sender leaf binding against PDS `blue.catbird.chat.device` (`I4`)!
                    let sender_id_str = std::str::from_utf8(sender_cred.serialized_content())
                        .map_err(|_| MLSError::Cryptography("non-UTF8 credential".to_string()))?;
                    let (sender_did, sender_dev_id) = sender_id_str
                        .split_once('#')
                        .ok_or_else(|| MLSError::Cryptography("unscoped credential".to_string()))?;
                    if body["actorDid"].as_str() != Some(sender_did)
                        || body["actorDeviceId"].as_str() != Some(sender_dev_id)
                    {
                        return Err(MLSError::Cryptography(
                            "verified outer sender differs from decrypted MLS sender".into(),
                        ));
                    }
                    let member = group
                        .members()
                        .find(|m| {
                            m.credential.serialized_content() == sender_cred.serialized_content()
                        })
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "I4: applicationMessage sender leaf not in group roster"
                                    .to_string(),
                            )
                        })?;
                    chat_wire::verify_leaf_slice_i4(
                        member.credential.serialized_content(),
                        member.signature_key.as_slice(),
                        &flat_auth_keys,
                    )?;

                    let ProcessedMessageContent::ApplicationMessage(app_msg) =
                        processed.into_content()
                    else {
                        return Err(MLSError::Cryptography(
                            "expected ApplicationMessage".to_string(),
                        ));
                    };
                    let plaintext = app_msg.into_bytes();
                    let (
                        display_body,
                        json_str,
                        verified_commitment_opt,
                        original_sender_attestation,
                    ) = extract_plaintext_body_and_verify_aad(&plaintext, &aad_bytes)?;
                    let _ = display_body;
                    let verified_commitment = verified_commitment_opt.ok_or_else(|| {
                        MLSError::Cryptography(
                            "I13: applicationEntry missing verified AAD archiveCommitment"
                                .to_string(),
                        )
                    })?;
                    let original_sender_attestation =
                        original_sender_attestation.ok_or_else(|| {
                            MLSError::Cryptography(
                                "application message missing original sender archive attestation"
                                    .into(),
                            )
                        })?;
                    if original_sender_attestation.sender_did != sender_did
                        || original_sender_attestation.sender_device_id != sender_dev_id
                        || original_sender_attestation
                            .sender_transport_public_key
                            .as_slice()
                            != member.signature_key.as_slice()
                    {
                        return Err(MLSError::Cryptography(
                            "original sender attestation differs from decrypted MLS sender leaf"
                                .into(),
                        ));
                    }

                    let (rcpt_seq, rcpt_generation, archived_receipt_json) =
                        chat_wire::parse_and_verify_i13_sequencer_receipt(
                            rcpt_val,
                            &rcpt_sec1,
                            &c.sequencer_did,
                            cid,
                            &c.group_id,
                            msg_epoch.max(0) as u64,
                            expected_rcpt_entry_id,
                            msg_id,
                            &verified_commitment,
                            Some(&original_sender_attestation),
                        )?;
                    if rcpt_seq as i64 != entry_seq {
                        return Err(MLSError::Cryptography(format!(
                            "I13: receipt seq {rcpt_seq} != entry seq {entry_seq}"
                        )));
                    }
                    // The receipt's generation is not signed: bind it to the local conversation
                    // so retained evidence only ever carries an authenticated generation.
                    if rcpt_generation != c.generation.max(0) as u64 {
                        return Err(MLSError::Cryptography(
                            "I13: receipt generation mismatch".into(),
                        ));
                    }
                    let inner: crate::messaging::receive::PrivateMessagePlaintextEnvelope =
                        serde_json::from_slice(&plaintext).map_err(|e| {
                            MLSError::Cryptography(format!(
                                "missing authenticated archive frame: {e}"
                            ))
                        })?;
                    let canonical_frame = String::from_utf8(inner.canonical_payload_bytes)
                        .map_err(|e| MLSError::Cryptography(format!("archive frame UTF-8: {e}")))?;
                    serde_json::from_str::<crate::orchestrator::MLSMessagePayload>(
                        &canonical_frame,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("archive frame payload: {e}")))?;
                    let archive = QueuedLabyrinthArchivePayload {
                        version: 1,
                        message_id: msg_id.to_owned(),
                        conversation_id: cid.to_owned(),
                        group_id_hex: hex::encode(&c.group_id),
                        epoch: msg_epoch,
                        expected_member_dids: group
                            .members()
                            .map(|member| {
                                root_did_from_credential_bytes(
                                    member.credential.serialized_content(),
                                )
                                .map(|(did, _)| did)
                            })
                            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
                            .into_iter()
                            .collect(),
                        seq: entry_seq,
                        sender_did: sender_did.to_owned(),
                        sender_device_id: sender_dev_id.to_owned(),
                        sequencer_did: c.sequencer_did.clone(),
                        space_uri: c.space_uri.clone(),
                        plaintext_json: json_str.clone(),
                        labyrinth_frame_json: canonical_frame,
                        mls_ciphertext_b64: STANDARD.encode(&ct_bytes),
                        frame_nonce_b64: Some(STANDARD.encode(inner.frame_nonce)),
                        sequencer_receipt_json: Some(archived_receipt_json),
                        original_sender_attestation_json: Some(
                            serde_json::to_string(&original_sender_attestation).map_err(
                                |error| {
                                    MLSError::Internal(format!(
                                        "serialize original sender archive attestation: {error}"
                                    ))
                                },
                            )?,
                        ),
                        created_at_ms: now_ms,
                    };
                    tx.put_labyrinth_state(
                        &format!("native.message:{cid}:{msg_id}"),
                        &serde_json::to_vec(&archive)?,
                        now_ms,
                    )?;
                    // Witness copy: pre-removal history must not depend on its sender flushing.
                    // An own-account message stays the sending device's archive duty.
                    if sender_did != self.normalized_did {
                        super::live_plane::enqueue_labyrinth_archive(tx, &archive)?;
                    }

                    tx.insert_message(&MessageRow {
                        message_id: msg_id.to_string(),
                        conversation_id: cid.to_string(),
                        group_id: c.group_id.clone(),
                        epoch: msg_epoch,
                        seq: entry_seq,
                        sender_did: sender_did.to_string(),
                        sender_device_id: sender_dev_id.to_string(),
                        plaintext_json: json_str,
                        created_at_ms: now_ms,
                        is_own: sender_did == self.normalized_did,
                    })?;
                    c.last_seq = c.last_seq.max(entry_seq);
                    if sender_did != self.normalized_did {
                        c.unread_count = c.unread_count.saturating_add(1);
                    }
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)
                });
                #[cfg(feature = "sim")]
                if decrypt_result.is_err()
                    && crate::planted::is_planted_bug_active(
                        crate::planted::PlantedBug::P9AutomatedForcedRejoinOnDecryptFailure,
                    )
                {
                    self.plant_p9_automated_forced_rejoin(cid, canonical_dev_id, signer)?;
                }
                if let (Err(error), Some((reason, epoch))) = (&decrypt_result, undecryptable) {
                    // Never fail-stop or force a rejoin here: later entries, Commits above all,
                    // must still apply. The failed attempt rolled back; record the gap instead.
                    tracing::warn!(
                        conversation_id = cid,
                        seq = entry_seq,
                        reason,
                        %error,
                        "recording permanently undecryptable application entry"
                    );
                    self.record_undecryptable_entry(
                        &chat_wire::UndecryptableEntryEvidence {
                            version: 1,
                            conversation_id: cid.to_owned(),
                            message_id: msg_id.to_owned(),
                            entry_id: expected_rcpt_entry_id.to_owned(),
                            seq: entry_seq,
                            epoch,
                            sender_did: body["actorDid"].as_str().unwrap_or_default().to_owned(),
                            sender_device_id: body["actorDeviceId"]
                                .as_str()
                                .unwrap_or_default()
                                .to_owned(),
                            reason: reason.to_owned(),
                            recorded_at_ms: now_ms,
                        },
                        &body["aad"],
                        rcpt_val,
                        &rcpt_sec1,
                        &flat_auth_keys,
                    )?;
                    self.notify_change(PlatformChangeEvent::MessagesUpdated {
                        conversation_id: cid.to_string(),
                    });
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }
                decrypt_result?;

                self.notify_change(PlatformChangeEvent::MessagesUpdated {
                    conversation_id: cid.to_string(),
                });
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            return Err(MLSError::Cryptography(format!(
                "unexpected conversation entry kind {kind:?}"
            )));
        }

        if saw_c33_accept && !was_closed {
            self.archive_accepted_opening_messages(cid)?;
            self.notify_change(PlatformChangeEvent::RequestsUpdated);
        }
        if was_kicked && !was_closed {
            self.rescue_conversation_on_kick(cid)?;
        }
        if max_seq >= 1 && applied_count > 0 && !was_kicked && !was_closed {
            match self.acknowledge_entries_up_to(cid, max_seq) {
                Ok(()) => {}
                Err(MLSError::InvalidState(code)) if code == "ConversationNotFound" => {}
                Err(err) => return Err(err),
            }
        }

        Ok(applied_count)
    }

    #[cfg(feature = "sim")]
    fn plant_p9_automated_forced_rejoin(
        &self,
        cid: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<(), MLSError> {
        let convo_uuid = uuid::Uuid::parse_str(cid)
            .map_err(|e| MLSError::Internal(format!("invalid conversation UUID: {e}")))?;
        let prior_coords = self.load_or_build_conversation_coords(cid)?;
        let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
        let prior_epoch = prior_coords["epoch"].as_u64().unwrap_or(0);
        let prior_gen = prior_coords["generation"].as_i64().unwrap_or(0);
        let prior_gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
        let prior_ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;
        let transition_uuid = self.hooks.uuid_v4();
        let transition_id = transition_uuid.to_string();
        let (_, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let now_ms = self.hooks.now_ms();

        let maybe_rejoin = self.db.write_tx(|tx| {
            let Some(mut convo) = tx.get_conversation(cid)? else {
                return Ok(None);
            };
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let Some(mut old_group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group for P9: {e:?}")))?
            else {
                return Ok(None);
            };
            let group_info_bytes = old_group
                .export_group_info(provider.crypto(), signer, true)
                .map_err(|e| MLSError::Cryptography(format!("P9 export_group_info: {e:?}")))?
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("P9 serialize GroupInfo: {e:?}")))?;
            old_group
                .delete(provider.storage())
                .map_err(|e| MLSError::Internal(format!("P9 delete_group: {e:?}")))?;

            let MlsMessageBodyIn::GroupInfo(verifiable_group_info) =
                MlsMessageIn::tls_deserialize_exact(&group_info_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("P9 parse GroupInfo: {e:?}")))?
                    .extract()
            else {
                return Err(MLSError::Internal("P9 non-GroupInfo".into()));
            };
            let aad_prior = chat_wire::build_aad_prior_coordinate(
                &convo_uuid,
                &convo.group_id,
                prior_gen,
                prior_sv,
                prior_epoch as i64,
                &prior_gch,
                &prior_ctag,
            );
            let commit_aad_val = json!({
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": prior_gen,
                "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                "prior": aad_prior,
            });
            let commit_aad_bytes = canonical_commit_aad_bytes(&commit_aad_val)
                .map_err(|e| MLSError::Cryptography(format!("P9 commit AAD: {e}")))?;
            let scoped_id = format!("{}#{}", self.normalized_did, canonical_dev_id);
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let (mut group, bundle) = MlsGroup::external_commit_builder()
                .with_config(build_join_config())
                .with_aad(commit_aad_bytes)
                .skip_lifetime_validation()
                .build_group(
                    &provider,
                    verifiable_group_info,
                    CredentialWithKey {
                        credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                        signature_key: signer.public().into(),
                    },
                )
                .map_err(|e| MLSError::Cryptography(format!("P9 external build_group: {e:?}")))?
                .leaf_node_parameters(
                    LeafNodeParameters::builder()
                        .with_capabilities(caps)
                        .build(),
                )
                .load_psks(provider.storage())
                .map_err(|e| MLSError::Cryptography(format!("P9 external load_psks: {e:?}")))?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(|e| MLSError::Cryptography(format!("P9 external build: {e:?}")))?
                .finalize(&provider)
                .map_err(|e| MLSError::Cryptography(format!("P9 external finalize: {e:?}")))?;
            let commit_bytes = bundle
                .commit()
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("P9 serialize external commit: {e:?}")))?;
            let next_epoch = group.epoch().as_u64();
            let (next_gch, next_ctag) =
                chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
            let meta_row = tx.get_group_metadata(cid)?;
            let meta_ver = meta_row
                .as_ref()
                .map(|m| m.metadata_version.max(1) as u64)
                .unwrap_or(1);
            let title_s = meta_row
                .as_ref()
                .and_then(|m| m.title.clone())
                .unwrap_or_default();
            let desc_s = meta_row
                .as_ref()
                .and_then(|m| m.description.clone())
                .unwrap_or_default();
            let avatar_opt = meta_row
                .as_ref()
                .and_then(chat_wire::space_avatar_from_metadata_row);
            let meta_key = derive_metadata_key_from_group(
                &mut group,
                provider.crypto(),
                provider.storage(),
                &convo.group_id,
                next_epoch,
            )
            .map_err(|e| MLSError::Cryptography(format!("P9 metadata key: {e}")))?;
            let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                tx,
                cid,
                &meta_key,
                &convo.group_id,
                &convo_uuid,
                prior_gen,
                next_epoch,
                &next_gch,
                &next_ctag,
                &transition_id,
                meta_ver,
                canonical_dev_id,
                auth_gen,
                signer.public(),
                &title_s,
                &desc_s,
                avatar_opt,
            )?;
            convo.epoch = next_epoch as i64;
            convo.updated_at_ms = now_ms;
            tx.upsert_conversation(&convo)?;
            Ok(Some((
                convo.group_id,
                commit_aad_val,
                commit_bytes,
                next_epoch,
                next_gch,
                next_ctag,
                carried_snap,
            )))
        })?;

        if let Some((group_id, aad, commit_bytes, next_epoch, next_gch, next_ctag, snap)) =
            maybe_rejoin
        {
            let next_coords = json!({
                "conversationId": cid,
                "generation": prior_gen,
                "stateVersion": prior_sv + 1,
                "groupId": { "$bytes": STANDARD.encode(&group_id) },
                "epoch": next_epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(next_ctag) },
                "lifecycle": "active",
            });
            let commit_sha256: [u8; 32] = Sha256::digest(&commit_bytes).into();
            let body = json!({
                "$type": "blue.catbird.chat.defs#commitTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
                "transitionId": transition_id,
                "idempotencyKey": transition_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "signedAt": self.hooks.now_rfc3339_millis(),
                "prior": prior_coords,
                "next": next_coords,
                "aad": aad,
                "manifest": {
                    "participantChanges": [],
                    "leafChanges": [],
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                    "sha256": STANDARD.encode(commit_sha256),
                },
                "metadataSnapshot": snap,
            });
            let _ = self.submit_signed_chat_op(
                canonical_dev_id,
                Some(auth_gen),
                CanonicalOperation::SubmitTransition,
                &body,
                signer,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::record_account_deletion;
    use crate::storage::{LabyrinthQueueRow, MessageRow, MlsAccountDb, OpenMode};

    #[test]
    fn account_deletion_retains_queued_witness_copies_and_evidence() {
        const CID: &str = "conversation";
        let dir = tempfile::tempdir().unwrap();
        let db = MlsAccountDb::open_native(dir.path().join("witness.db"), &[7; 32], OpenMode::App)
            .unwrap();
        db.write_tx(|tx| {
            for (seq, (id, sender)) in [("m-alice", "did:plc:alice"), ("m-bob", "did:plc:bob")]
                .into_iter()
                .enumerate()
            {
                tx.insert_message(&MessageRow {
                    message_id: id.into(),
                    conversation_id: CID.into(),
                    group_id: vec![1; 32],
                    epoch: 1,
                    seq: seq as i64 + 1,
                    sender_did: sender.into(),
                    sender_device_id: "device".into(),
                    plaintext_json: "{}".into(),
                    created_at_ms: 1,
                    is_own: false,
                })?;
                tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                    item_id: id.into(),
                    conversation_id: CID.into(),
                    group_id_hex: "01".into(),
                    seq: seq as i64 + 1,
                    payload_bytes: b"{}".to_vec(),
                    created_at_ms: 1,
                })?;
                tx.put_labyrinth_state(&format!("native.message:{CID}:{id}"), b"{}", 1)?;
            }
            record_account_deletion(tx, CID, "did:plc:alice", 9, 1)
        })
        .unwrap();
        db.read_tx(|tx| {
            let queued: Vec<String> = tx
                .list_labyrinth_queue(None, 10)?
                .into_iter()
                .map(|row| row.item_id)
                .collect();
            assert_eq!(queued, ["m-alice", "m-bob"]);
            assert!(tx
                .get_labyrinth_state(&format!("native.message:{CID}:m-alice"))?
                .is_some());
            assert!(tx
                .get_labyrinth_state(&format!("native.message:{CID}:m-bob"))?
                .is_some());
            Ok(())
        })
        .unwrap();
    }
}
