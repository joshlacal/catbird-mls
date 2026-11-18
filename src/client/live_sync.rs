//! Live `sync()` reconciliation engine for `CatbirdMlsClient` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`, `C33`).
//!
//! Executes strictly outside `MlsAccountDb::write_tx` (`I6`) in three phases:
//! 1. `getConversations` -> `C33` direct-request Welcome/introduction import + pending group invite acceptance; an active
//!    participant's conversation this device holds nothing of owes its own `requestLeafRecovery`, sent after phase 2.
//! 2. `getPendingWelcomes` -> `StagedWelcome` join (a reset-retired row rejoins in place) as the
//!    receipt-verified `leafRecoveryFulfillmentEntry`'s Welcome, then `acknowledgeWelcome`.
//! 3. Per conversation: `getEntries` -> `I2`-ordered entries, each verified under its kind's authority before any effect +
//!    `I14` `acknowledge_entries_up_to`; then at most one leaf recovery this device authorizes itself (a verified
//!    acceptance's authorization or the requester's verified `signedRequest`), as
//!    `getConversationState.pendingLeafRecoveryRequests` lists it -> add (or remove + add) Commit + `#leafRecoveryFulfillmentBody`.
//!    A conversation a reset retired this device from instead owes its own `requestLeafRecovery`.
//!
//! Every conversation-scoped step is isolated: one conversation that fails never stops another.

use std::collections::{BTreeMap, BTreeSet};

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
use crate::error::{ConversationSyncFailure, MLSError};
use crate::messaging::receive::{
    extract_plaintext_body_and_verify_aad, verify_application_aad_archive_evidence,
};
use crate::orchestrator::canonical_transport::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use crate::orchestrator::direct_request_bootstrap::{
    DirectRequestBootstrap, DirectRequestIntroductionResult, DirectRequestWelcomeInput,
    C33_OPENING_UNAVAILABLE,
};
use crate::orchestrator::direct_request_shared_crypto::decrypt_introduction_with_provider;
use crate::push::processor::NATIVE_ARCHIVE_RECEIPT_OP;
use crate::push::{
    root_did_from_credential_bytes, AuthorizedPeerDeviceKey, NSE_DEFERRED_CONTROL_OP,
};
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

pub(crate) fn conversation_space_uri(sequencer_did: &str, cid: &str, generation: i64) -> String {
    let rkey = format!("{cid}-{generation}");
    atproto_spaces::SpaceUri::new(sequencer_did, "blue.catbird.labyrinth.conversation", &rkey)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| {
            format!("at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{rkey}")
        })
}

/// What one conversation's entry pass applied before it finished or stopped.
#[derive(Default)]
struct EntryPass {
    /// The seq of the last entry applied: the cursor the pass moved to.
    max_seq: i64,
    applied: u32,
    saw_c33_accept: bool,
    was_kicked: bool,
    was_closed: bool,
    /// A verified reset activation retired this device's leaf.
    was_retired: bool,
}

#[path = "live_integrity.rs"]
pub(crate) mod live_integrity;

/// Writes the earlier marker form, the deletion's seq alone, which readers still honour: archive
/// history loads and restores hide every copy of `deleted_did`'s messages ordered before it.
#[cfg(test)]
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

/// `cid`'s verified roster as `tx` holds it ([`chat_wire::conversation_roster_key`]); `None`
/// when this device never verified one.
pub(super) fn stored_roster(
    tx: &crate::storage::SqlReadTx<'_>,
    cid: &str,
) -> Result<Option<Value>, MLSError> {
    tx.get_account_meta(&chat_wire::conversation_roster_key(cid))?
        .map(|raw| serde_json::from_str(&raw).map_err(MLSError::from))
        .transpose()
}

fn clear_roster_baseline(tx: &crate::storage::SqlTx<'_>, cid: &str) -> Result<(), MLSError> {
    if let Some(previous) = stored_roster(tx, cid)? {
        for did in previous
            .as_object()
            .into_iter()
            .flatten()
            .map(|(did, _)| did)
        {
            tx.delete_account_meta(&chat_wire::verified_participant_admission_key(cid, did))?;
        }
    }
    tx.delete_account_meta(&chat_wire::conversation_roster_key(cid))
}

/// Records a member-authenticated roster baseline for `cid`, replacing any. Active rows carry
/// admission authority to this device; pending rows carry only their immutable invitation
/// provenance. Old baseline markers are removed before the replacement is installed.
pub(super) fn store_roster(
    tx: &crate::storage::SqlTx<'_>,
    cid: &str,
    roster: &Value,
    now_ms: i64,
) -> Result<(), MLSError> {
    clear_roster_baseline(tx, cid)?;
    tx.put_account_meta(
        &chat_wire::conversation_roster_key(cid),
        &roster.to_string(),
        now_ms,
    )?;
    for (did, row) in roster.as_object().into_iter().flatten() {
        if row["status"] == "active" {
            tx.put_account_meta(
                &chat_wire::verified_participant_admission_key(cid, did),
                "true",
                now_ms,
            )?;
        } else if row["status"] == "pending" {
            tx.delete_account_meta(&chat_wire::invitation_closed_key(cid, did))?;
        }
    }
    Ok(())
}

/// The participant effects of a verified `kind` body on `cid`'s verified roster
/// ([`chat_wire::apply_roster_effects`]), in the transaction that applies that body's
/// transition, once per transition. Without a verified roster there is nothing to keep current;
/// a body without participant effects writes nothing.
pub(crate) fn apply_verified_roster_effects(
    tx: &crate::storage::SqlTx<'_>,
    cid: &str,
    kind: SignedMutationKind,
    body: &Value,
    now_ms: i64,
) -> Result<(), MLSError> {
    let key = chat_wire::conversation_roster_key(cid);
    let acceptance_did = (kind == SignedMutationKind::ParticipantAcceptance)
        .then(|| body["actorDid"].as_str())
        .flatten();
    let Some(stored) = tx.get_account_meta(&key)? else {
        return if acceptance_did.is_some() {
            Err(MLSError::Cryptography(
                "invitation chain: no locally verified pending invitation".into(),
            ))
        } else {
            Ok(())
        };
    };
    let mut roster: Value = serde_json::from_str(&stored)?;
    if acceptance_did.is_some_and(|did| roster[did]["status"] != "pending") {
        return Err(MLSError::Cryptography(
            "invitation chain: actor has no locally verified pending invitation".into(),
        ));
    }
    let removed = chat_wire::removed_participants(kind, body);
    chat_wire::apply_roster_effects(&mut roster, kind, body);
    for (did, row) in roster.as_object().into_iter().flatten() {
        if row["status"] == "pending" {
            tx.delete_account_meta(&chat_wire::invitation_closed_key(cid, did))?;
        }
    }
    if let Some(did) = acceptance_did {
        tx.put_account_meta(
            &chat_wire::verified_participant_admission_key(cid, did),
            "true",
            now_ms,
        )?;
    }
    for did in removed {
        tx.delete_account_meta(&chat_wire::verified_participant_admission_key(cid, &did))?;
    }
    let updated = roster.to_string();
    if updated != stored {
        tx.put_account_meta(&key, &updated, now_ms)?;
    }
    Ok(())
}

/// Shared receipt check for an already authenticated control body. Foreground sync resolves the
/// key normally; the NSE supplies only the matching key retained in local account state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_control_entry_receipt_with_key(
    sequencer_did: &str,
    cid: &str,
    entry_id: &str,
    entry_seq: i64,
    receipt: &Value,
    verified_body: &Value,
    request_digest: &[u8; 32],
    receipt_key: &[u8],
    fallback_coordinate: Option<&Value>,
) -> Result<(), MLSError> {
    let coordinate = ["next", "successor", "retired", "prior"]
        .iter()
        .find_map(|field| verified_body.get(field))
        .or(fallback_coordinate)
        .ok_or_else(|| MLSError::Cryptography("control entry has no receipt coordinate".into()))?;
    let actor_did = verified_body["actorDid"]
        .as_str()
        .ok_or_else(|| MLSError::Cryptography("control body missing actorDid".into()))?;
    let actor_device_id = verified_body["actorDeviceId"]
        .as_str()
        .ok_or_else(|| MLSError::Cryptography("control body missing actorDeviceId".into()))?;
    chat_wire::verify_control_sequencer_receipt(
        receipt,
        receipt_key,
        sequencer_did,
        cid,
        entry_id,
        entry_seq,
        actor_did,
        actor_device_id,
        coordinate,
        request_digest,
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

    /// `cid`'s current coordinate as this device last verified and recorded it, canonical; `None`
    /// before any was recorded.
    pub(super) fn local_coordinates(&self, cid: &str) -> Result<Option<Value>, MLSError> {
        let raw = self
            .db
            .read_tx(|tx| tx.get_account_meta(&format!("conversation_coords:{cid}")))?;
        raw.map(|raw| {
            chat_wire::canonicalize_wire_coordinate(&serde_json::from_str(&raw)?, Some(cid))
        })
        .transpose()
    }

    /// A verified reset activation moves `cid` to its `successor` generation in one transaction
    /// (`CHAT_PROTOCOL` §6): the old MLS group, its epoch secrets, every staged Commit and own
    /// reset journal and any leaf-recovery authorization are erased; the conversation takes the
    /// successor's group, generation (and that generation's conversation Space) and coordinate at
    /// epoch 0, and `roster` (the activation manifest's) as its verified roster; the cursor moves
    /// to `cursor` when given.
    ///
    /// A peer's activation retires this device (`own` is `None`): every old leaf but the
    /// activator only closes and recovers later through its own signed request, so the
    /// conversation stays unsendable until a recovery Welcome of the successor adds this device.
    /// This device's own activation (`own`: its journaled successor group and the metadata
    /// snapshot it signed) installs that group, this device its only leaf, and that snapshot.
    pub(super) fn apply_reset_activation(
        &self,
        cid: &str,
        successor: &Value,
        roster: &Value,
        cursor: Option<i64>,
        own: Option<(&crate::storage::KvWriteBatch, &Value)>,
    ) -> Result<(), MLSError> {
        let successor_group = chat_wire::json_bytes(&successor["groupId"])?;
        let generation = successor["generation"]
            .as_i64()
            .ok_or_else(|| MLSError::Cryptography("reset successor generation".into()))?;
        let successor_str = serde_json::to_string(successor)?;
        let now_ms = self.hooks.now_ms();
        self.db.write_tx(|tx| {
            self.clear_cached_groups();
            let mut convo = tx
                .get_conversation(cid)?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            if let Some(mut group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load retired group: {e:?}")))?
            {
                group
                    .delete(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("delete retired group: {e:?}")))?;
            }
            tx.conn()
                .execute(
                    "DELETE FROM epoch_secrets WHERE group_id_hex = ?1",
                    [hex::encode(&convo.group_id)],
                )
                .map_err(|e| map_rusqlite_err("erase retired epoch secrets", &e))?;
            Self::prune_pending_commit_transitions(tx, cid, generation, 0, true)?;
            tx.conn()
                .execute(
                    "DELETE FROM pending_ops WHERE op_kind = ?1 \
                     AND json_extract(payload_json, '$.conversation_id') = ?2",
                    [super::live_plane::RESET_ACTIVATION_OP, cid],
                )
                .map_err(|e| map_rusqlite_err("erase reset journals", &e))?;
            if let Some((kv_batch, snapshot)) = own {
                kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                let mut group =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&successor_group))
                        .map_err(|e| MLSError::Internal(format!("load successor group: {e:?}")))?
                        .ok_or_else(|| MLSError::group_not_found(cid))?;
                if let Some((epoch, version, meta)) =
                    chat_wire::try_decrypt_group_metadata_snapshot(&mut group, &provider, snapshot)
                {
                    super::archive_policy::accept_snapshot(
                        tx,
                        cid,
                        cursor.unwrap_or(0),
                        &meta,
                        super::archive_policy::SnapshotPolicyAuthority::ExactCarry,
                        now_ms,
                    )?;
                    let row =
                        chat_wire::group_metadata_row_from_v1(cid, version, epoch, &meta, now_ms)?;
                    convo.title = row.title.clone();
                    tx.upsert_group_metadata(&row)?;
                }
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{cid}"),
                    &snapshot.to_string(),
                    now_ms,
                )?;
            }
            convo.group_id = successor_group;
            convo.generation = generation;
            convo.space_uri = Some(conversation_space_uri(
                &convo.sequencer_did,
                cid,
                generation,
            ));
            convo.epoch = 0;
            if let Some(seq) = cursor {
                convo.last_seq = convo.last_seq.max(seq);
            }
            convo.updated_at_ms = now_ms;
            tx.upsert_conversation(&convo)?;
            tx.put_account_meta(
                &format!("conversation_coords:{cid}"),
                &successor_str,
                now_ms,
            )?;
            store_roster(tx, cid, roster, now_ms)?;
            tx.delete_account_meta(&chat_wire::verified_reset_request_key(cid))?;
            tx.delete_account_meta(&chat_wire::leaf_recovery_authorization_key(cid))
        })
    }

    /// `did` takes part in `cid`. Without `provenance`, a DID holding a current leaf of the local
    /// group does; any other DID must be the invitee of a `creationEntry` or `policyEntry`. With
    /// `provenance` (a participant acceptance's signed `invitationProvenance`), the invitation is
    /// proven by either its signed, receipted entry in this device's contiguous post-join batch or
    /// the exact pending row in this device's member-authenticated roster baseline.
    ///
    /// Historical lookup is retained only for no-provenance participant controls. An acceptance
    /// never asks the sequencer for unreadable pre-join history. Its own entry still arrives at
    /// exactly `last_seq + 1`, and any post-join gap has already stopped the entry pass.
    ///
    /// Returns the verified invitation seq, `0` for a member-attested pending baseline, or `None`
    /// only for a current leaf or the no-provenance later-device case.
    #[allow(clippy::too_many_arguments)]
    fn require_participant(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        cid: &str,
        sequencer_did: &str,
        did: &str,
        provenance: Option<&Value>,
        before_seq: i64,
        earlier: &[Value],
        keys_by_did: &BTreeMap<String, Vec<AuthorizedPeerDeviceKey>>,
    ) -> Result<Option<i64>, MLSError> {
        let refused = |what: &str| MLSError::Cryptography(format!("invitation chain: {what}"));
        if let Some(provenance) = provenance {
            let roster = self.db.read_tx(|tx| stored_roster(tx, cid))?;
            if chat_wire::roster_has_pending_invitation(roster.as_ref(), did, provenance) {
                return Ok(Some(0));
            }
        }
        if provenance.is_none()
            && self
                .current_leaves(cid)?
                .iter()
                .any(|(leaf_did, _, _)| leaf_did == did)
        {
            return Ok(None);
        }
        if provenance.is_none() {
            let (roster, admission) = self.db.read_tx(|tx| {
                Ok((
                    stored_roster(tx, cid)?,
                    tx.get_account_meta(&chat_wire::verified_participant_admission_key(cid, did))?,
                ))
            })?;
            if admission.is_some() && chat_wire::roster_active(roster.as_ref(), did) {
                return Ok(None);
            }
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
        if provenance.is_some() && found.is_none() {
            return Err(refused(
                "no invitation in this device's contiguous history or member-attested baseline",
            ));
        }
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
            let mut prior: Vec<&Value> = entries
                .iter()
                .filter(|entry| {
                    entry["seq"]
                        .as_i64()
                        .is_some_and(|seq| seq > after_seq && seq < before_seq)
                })
                .collect();
            prior.sort_by_key(|entry| entry["seq"].as_i64().unwrap_or_default());
            for entry in prior {
                let seq = entry["seq"].as_i64().unwrap_or_default();
                reads_seq_one |= seq == 1;
                if found.is_none() && invites(entry) {
                    found = Some(entry.clone());
                }
            }
            if found.is_some() {
                break;
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
                Err(refused("no invitation in readable history"))
            } else {
                Ok(None)
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
        let (verified, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
            &invitation["signedRequest"],
            kind,
            &self.pds_device_key(inviter_did, inviter_device, keys_by_did)?,
        )?;
        let invitation_seq = invitation["seq"]
            .as_i64()
            .ok_or_else(|| refused("the verified invitation has no seq"))?;
        self.verify_control_entry_receipt(
            sequencer_did,
            cid,
            &invitation,
            invitation_seq,
            &verified,
            &request_digest,
        )?;
        match chat_wire::invitation_provenance(kind, &verified, cid, did) {
            Some(invited) if provenance.is_none_or(|provenance| *provenance == invited) => {
                Ok(Some(invitation_seq))
            }
            _ => Err(refused(
                "the verified invitation does not invite this participant",
            )),
        }
    }

    /// A sequenced `directRequestAcceptanceEntry` verifies before any effect: the exact entry for
    /// this conversation at `seq`; its signer a current leaf ([`Self::participant_leaf_key`]);
    /// its `Accept`-domain signature under that leaf key; a `next` that only advances
    /// `prior.stateVersion`; the local request's recipient accepting that request; and its required
    /// coordinator receipt under the exact method it names. Returns the verified next coordinates.
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
        let receipt = receipt
            .filter(Value::is_object)
            .ok_or_else(|| refused("missing I13 sequencerReceipt"))?;
        let mut receipt_entry = entry;
        receipt_entry["sequencerReceipt"] = receipt;
        self.verify_control_entry_receipt(
            &convo.sequencer_did,
            cid,
            &receipt_entry,
            seq,
            body,
            accepted.request_digest(),
        )?;
        chat_wire::canonicalize_wire_coordinate(&body["next"], Some(cid))
    }

    /// Complete NSE-retained plaintext proof without replaying its consumed MLS ratchet. The
    /// verified outer sender, retained frame/nonce and signed I13 receipt bind the completion.
    fn finish_received_archive_evidence(
        &self,
        cid: &str,
        message_id: &str,
        entry_seq: i64,
        entry_id: &str,
        receipt: &Value,
        outer_sender: Option<(&str, &str)>,
        send_counter: Option<u64>,
        canonical_device_id: &str,
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
            if outer_sender.is_some_and(|(did, device)| {
                message.sender_did != did || message.sender_device_id != device
            }) {
                return Err(MLSError::Cryptography(
                    "cached application outer sender mismatch".into(),
                ));
            }
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
            if completes
                && (message.sender_did != self.normalized_did
                    || message.sender_device_id != canonical_device_id)
            {
                // The extension records the counter in the transaction that stores the
                // message; completing that entry here must not count it a second time.
                if evidence[chat_wire::NSE_SEND_COUNTER_RECORDED].is_null() {
                    super::send_counter::record_peer_send_counter(
                        tx,
                        cid,
                        convo.generation,
                        bound_epoch as i64,
                        &message.sender_did,
                        &message.sender_device_id,
                        send_counter,
                        entry_seq,
                        now_ms,
                    )?;
                }
            }
            if crate::client::deletion_authority::suppress_local_frame(
                tx,
                cid,
                &message.sender_did,
                &message.sender_device_id,
                entry_seq,
                receipt["issuedAtMs"].as_i64(),
            )? {
                tx.conn()
                    .execute(
                        "DELETE FROM messages WHERE conversation_id=?1 AND message_id=?2",
                        rusqlite::params![cid, message_id],
                    )
                    .map_err(|e| map_rusqlite_err("clear deleted cached message", &e))?;
                tx.conn()
                    .execute(
                        "DELETE FROM labyrinth_state WHERE state_key=?1",
                        [&state_key],
                    )
                    .map_err(|e| map_rusqlite_err("clear deleted cached frame", &e))?;
                tx.dequeue_labyrinth_item(message_id)?;
                tx.delete_pending_op(NATIVE_ARCHIVE_RECEIPT_OP, message_id)?;
                convo.last_seq = convo.last_seq.max(entry_seq);
                convo.updated_at_ms = now_ms;
                return tx.upsert_conversation(&convo);
            }
            evidence["sequencer_receipt_json"] = json!(stored_receipt);
            if completes {
                evidence["seq"] = json!(entry_seq);
            }
            tx.put_labyrinth_state(&state_key, &serde_json::to_vec(&evidence)?, now_ms)?;
            if completes {
                let archive: QueuedLabyrinthArchivePayload = serde_json::from_value(evidence)
                    .map_err(|e| {
                        MLSError::Cryptography(format!("retained archive payload: {e}"))
                    })?;
                super::archive_policy::observe_frame(tx, &archive)?;
                if message.sender_did != self.normalized_did {
                    super::live_plane::enqueue_labyrinth_archive(tx, &archive)?;
                }
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
            if evidence.sender_did != self.normalized_did
                || evidence.sender_device_id != self.config.device_id
            {
                super::send_counter::record_peer_send_counter(
                    tx,
                    cid,
                    convo.generation,
                    evidence.epoch,
                    &evidence.sender_did,
                    &evidence.sender_device_id,
                    evidence.send_counter,
                    evidence.seq,
                    evidence.recorded_at_ms,
                )?;
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

    /// Reconcile conversations, `C33` direct requests, pending `Welcome`s, ordered `getEntries`
    /// deltas and authorized leaf-recovery work from the home `mls-ds` (`Spec §6.3`, `I2`, `I4`,
    /// `I6`, `I13`, `I14`).
    ///
    /// Every conversation-scoped step is isolated: a conversation that fails stops at its failing
    /// step, its cursor and acknowledgement still below a failing entry, and every other
    /// conversation still syncs. The failures are returned together as
    /// [`MLSError::SyncIncomplete`], never dropped; only a failure of the whole account's reads
    /// (no inventory, no Welcome list) stops `sync` outright.
    pub fn sync(&self) -> Result<u32, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() else {
            return Ok(0);
        };
        // Attempt each exact creation before inventory. Retained failures remain scoped to their
        // conversation, and suppress impossible leaf recovery while every healthy group proceeds.
        let (mut total_applied, pending_creations, creation_failures) =
            self.complete_pending_group_creations()?;
        let mut failures = creation_failures
            .into_iter()
            .map(|(conversation_id, error)| ConversationSyncFailure {
                conversation_id,
                error: Box::new(error),
            })
            .collect::<Vec<_>>();
        let Ok((signer, auth_generation)) = self.load_enrolled_signer_and_auth_gen() else {
            return if failures.is_empty() {
                Ok(total_applied)
            } else {
                Err(MLSError::SyncIncomplete {
                    applied: total_applied,
                    failures,
                })
            };
        };

        // Phase 1: `getConversations` -> C33 incoming direct requests + group invitation
        // acceptance, and the conversations whose leaf recovery this device owes.
        let mut owed = Vec::new();
        let (conv_applied, inventory_session_id) = match self.sync_conversations_list(
            &canonical_dev_id,
            &signer,
            auth_generation,
            &mut owed,
            &mut failures,
        ) {
            Ok(result) => result,
            Err(error) => {
                failures.push(ConversationSyncFailure {
                    conversation_id: "<conversation-inventory>".into(),
                    error: Box::new(error),
                });
                if total_applied > 0 || !failures.is_empty() {
                    self.notify_change(PlatformChangeEvent::ConversationsUpdated);
                }
                return Err(MLSError::SyncIncomplete {
                    applied: total_applied,
                    failures,
                });
            }
        };
        total_applied = total_applied.saturating_add(conv_applied);

        // Phase 2: `getPendingWelcomes` -> StagedWelcome join + acknowledgeWelcome.
        let mut welcomed = BTreeSet::new();
        total_applied = total_applied.saturating_add(self.sync_pending_welcomes(
            &canonical_dev_id,
            &signer,
            auth_generation,
            inventory_session_id.as_deref(),
            &mut welcomed,
            &mut failures,
        )?);

        // Owed leaf recoveries, once the Welcomes are in: a conversation with a Welcome pending
        // for this device requests nothing (a just-fulfilled device already holds a leaf).
        for (cid, state) in owed {
            if pending_creations.contains(&cid) || welcomed.contains(&cid) {
                continue;
            }
            if let Err(error) = self.ensure_own_leaf_recovery(
                &canonical_dev_id,
                &signer,
                auth_generation,
                &cid,
                &state,
            ) {
                failures.push(ConversationSyncFailure {
                    conversation_id: cid,
                    error: Box::new(error),
                });
            }
        }

        // Journaled own closes whose answer was lost, refused or unverifiable: exact replay.
        let (closed, close_failures) = self.complete_pending_closes()?;
        total_applied = total_applied.saturating_add(closed);
        failures.extend(close_failures.into_iter().map(|(conversation_id, error)| {
            ConversationSyncFailure {
                conversation_id,
                error: Box::new(error),
            }
        }));
        // Phase 3: every known conversation's entries, then its owed and authorized work.
        // Keyset pagination includes the conversation-id tiebreaker, so more than 200 rows
        // sharing one timestamp cannot disappear between pages.
        let mut local_cursor: Option<(i64, String)> = None;
        loop {
            let cursor = local_cursor
                .as_ref()
                .map(|(updated_at_ms, conversation_id)| (*updated_at_ms, conversation_id.as_str()));
            let convos = self
                .db
                .read_tx(|tx| tx.list_conversations_page(cursor, 200))?;
            if convos.is_empty() {
                break;
            }
            let Some(last) = convos.last() else {
                break;
            };
            let next_cursor = (last.updated_at_ms, last.conversation_id.clone());
            if local_cursor.as_ref().is_some_and(|previous| {
                next_cursor.0 > previous.0
                    || (next_cursor.0 == previous.0 && next_cursor.1 <= previous.1)
            }) {
                failures.push(ConversationSyncFailure {
                    conversation_id: "<local-conversation-inventory>".into(),
                    error: Box::new(MLSError::Cryptography(
                        "local conversation pagination made no progress".into(),
                    )),
                });
                break;
            }
            let has_more = convos.len() == 200;
            for convo in convos {
                let welcome_pending = welcomed.contains(&convo.conversation_id);
                match self.sync_one_conversation(
                    &canonical_dev_id,
                    &signer,
                    auth_generation,
                    &convo,
                    welcome_pending,
                ) {
                    Ok(applied) => total_applied = total_applied.saturating_add(applied),
                    Err(error) => failures.push(ConversationSyncFailure {
                        conversation_id: convo.conversation_id,
                        error: Box::new(error),
                    }),
                }
            }
            if !has_more {
                break;
            }
            local_cursor = Some(next_cursor);
        }

        // A failed conversation may still have applied the entries before its failing one.
        if total_applied > 0 || !failures.is_empty() {
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        }
        if failures.is_empty() {
            Ok(total_applied)
        } else {
            Err(MLSError::SyncIncomplete {
                applied: total_applied,
                failures,
            })
        }
    }

    /// `convo`'s ordered entries; then, once they all applied, the participant-removal policy a
    /// leaf-removal Commit accepted without its response still owes, and at most one leaf
    /// recovery this device authorizes ([`Self::fulfill_leaf_recovery`]).
    ///
    /// A conversation a reset retired this device from ([`Self::is_retired`]), before or by this
    /// pass, reads no entry past the reset: none verifies without its group, and mls-ds serves
    /// none to a device whose membership the reset closed. It owes only this device's own
    /// recovery request, unless a Welcome of it is pending ([`Self::ensure_own_leaf_recovery`]),
    /// from the state mls-ds presents; while this device may not read that state, nothing.
    fn sync_one_conversation(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        convo: &ConversationRow,
        welcome_pending: bool,
    ) -> Result<u32, MLSError> {
        let cid = convo.conversation_id.as_str();
        let mut applied = 0;
        if !self.is_retired(convo)? {
            applied = self.sync_conversation_entries(canonical_dev_id, signer, convo)?;
            // Within its entries only a verified reset moves the row to another group.
            let retired = match self.db.read_tx(|tx| tx.get_conversation(cid))? {
                Some(row) if row.group_id != convo.group_id => self.is_retired(&row)?,
                _ => false,
            };
            if !retired {
                self.complete_participant_removals(cid, canonical_dev_id, signer)?;
                let applied = applied.saturating_add(self.fulfill_leaf_recovery(
                    cid,
                    canonical_dev_id,
                    signer,
                    auth_generation,
                )?);
                self.maybe_auto_self_update(cid)?;
                return Ok(applied);
            }
        }
        if welcome_pending {
            return Ok(applied);
        }
        let state = match self.query_signed_chat_ds(
            "blue.catbird.chat.getConversationState",
            &[("actorDeviceId", canonical_dev_id), ("conversationId", cid)],
            canonical_dev_id,
            signer,
        ) {
            Ok(state) => state,
            Err(MLSError::InvalidState(code))
                if matches!(
                    code.as_str(),
                    "ConversationNotFound" | "NotEntitled" | "AccessOutsideMembershipInterval"
                ) =>
            {
                return Ok(applied)
            }
            Err(error) => return Err(error),
        };
        self.ensure_own_leaf_recovery(
            canonical_dev_id,
            signer,
            auth_generation,
            cid,
            &state["state"],
        )?;
        Ok(applied)
    }

    /// The inventory's conversations ([`Self::sync_inventory_item`]); `owed` collects each
    /// `(cid, state)` whose leaf recovery this device owes.
    fn sync_conversations_list(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        owed: &mut Vec<(String, Value)>,
        failures: &mut Vec<ConversationSyncFailure>,
    ) -> Result<(u32, Option<String>), MLSError> {
        let mut page_cursor: Option<String> = None;
        let mut inventory_session_id: Option<String> = None;
        let mut first_page = true;
        let mut pagination =
            crate::orchestrator::pagination::PaginationGuard::for_conversations(
                "live conversation inventory",
            );
        let mut inventory_items = Vec::new();
        loop {
            let mut params = vec![
                ("actorDeviceId", canonical_dev_id),
                ("limit", "100"),
                ("supportedProtocolVersions", "1"),
                ("supportedProtocolVersions", "2"),
            ];
            if let Some(cursor) = page_cursor.as_deref() {
                params.push(("pageCursor", cursor));
            }
            let mut resp = self.query_signed_chat_ds(
                "blue.catbird.chat.getConversations",
                &params,
                canonical_dev_id,
                signer,
            )?;
            let page_session_id = match resp.get("inventorySessionId") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
                _ => {
                    return Err(MLSError::Cryptography(
                        "conversation inventory has an invalid inventorySessionId".into(),
                    ));
                }
            };
            if first_page {
                inventory_session_id = page_session_id;
                first_page = false;
            } else if page_session_id != inventory_session_id {
                return Err(MLSError::Cryptography(
                    "conversation inventory changed its snapshot session between pages".into(),
                ));
            }
            let next_cursor = match resp.get("nextPageCursor") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
                _ => {
                    return Err(MLSError::Cryptography(
                        "conversation inventory has an invalid continuation cursor".into(),
                    ));
                }
            };
            if let Some(has_more) = resp.get("hasMore") {
                if has_more.as_bool() != Some(next_cursor.is_some()) {
                    return Err(MLSError::Cryptography(
                        "conversation inventory has inconsistent pagination".into(),
                    ));
                }
            }
            let object = resp.as_object_mut().ok_or_else(|| {
                MLSError::Cryptography("conversation inventory is not an object".into())
            })?;
            let page_items = if let Some(items) = object.remove("items") {
                items
            } else if let Some(items) = object.remove("conversations") {
                items
            } else if let Some(items) = object.remove("states") {
                items
            } else {
                return Err(MLSError::Cryptography(
                    "conversation inventory is missing items".into(),
                ));
            };
            let Value::Array(page_items) = page_items else {
                return Err(MLSError::Cryptography(
                    "conversation inventory items are malformed".into(),
                ));
            };
            pagination
                .observe_page(page_items.len(), next_cursor.as_deref())
                .map_err(|error| MLSError::Cryptography(error.to_string()))?;
            inventory_items.extend(page_items);
            match next_cursor {
                Some(next) => page_cursor = Some(next),
                None => break,
            }
        }

        let mut states = Vec::with_capacity(inventory_items.len());
        let mut seen = BTreeSet::new();
        for item in inventory_items {
            let state = match item {
                Value::Object(mut object) => object
                    .remove("state")
                    .unwrap_or_else(|| Value::Object(object)),
                value => value,
            };
            let cid = state
                .pointer("/coordinates/conversationId")
                .or_else(|| state.get("conversationId"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "conversation inventory item has no conversation id".into(),
                    )
                })?
                .to_owned();
            if !seen.insert(cid.clone()) {
                return Err(MLSError::Cryptography(format!(
                    "conversation inventory repeated conversation {cid}"
                )));
            }
            states.push((cid, state));
        }

        let mut count = 0u32;
        for (cid, state) in states {
            match self.sync_inventory_item(
                canonical_dev_id,
                signer,
                auth_generation,
                &cid,
                &state,
                owed,
            ) {
                Ok(applied) => count = count.saturating_add(applied),
                Err(error) => failures.push(ConversationSyncFailure {
                    conversation_id: cid,
                    error: Box::new(error),
                }),
            }
        }
        Ok((count, inventory_session_id))
    }

    /// One inventory conversation: pin an unknown group authority, import an incoming `C33`
    /// direct request, or act on this account's group participant row. A pending invitation is
    /// accepted, so the inviter can discover the acceptance's add request through
    /// `getConversationState`. An active row without a local conversation (a new or reinstalled
    /// device) owes this device's own recovery request: `owed` collects it, and `sync` sends it
    /// once that pass's Welcomes are in ([`Self::ensure_own_leaf_recovery`]).
    fn sync_inventory_item(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        cid: &str,
        state: &Value,
        owed: &mut Vec<(String, Value)>,
    ) -> Result<u32, MLSError> {
        let coords = state.get("coordinates").unwrap_or(&Value::Null);
        let kind = state
            .get("conversationKind")
            .or_else(|| state.get("kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("group");
        self.db.write_tx(|tx| {
            tx.put_account_meta(
                &format!("conversation_kind:{cid}"),
                kind,
                self.hooks.now_ms(),
            )
        })?;

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

        let me = state
            .get("participants")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|p| p["userDid"].as_str() == Some(self.normalized_did.as_str()));

        if kind == "direct" && !has_local {
            let active_in_direct = me.is_some_and(|p| p["status"].as_str() == Some("active"));
            // A pruned opening's terminal state is recorded once; it is never re-fetched.
            let terminal = self.db.read_tx(|tx| {
                Ok(tx
                    .list_requests(Some(C33_OPENING_UNAVAILABLE))?
                    .iter()
                    .any(|r| r.conversation_id == cid))
            })?;
            if terminal {
                if active_in_direct {
                    owed.push((cid.to_owned(), state.clone()));
                }
                return Ok(0);
            }
            return match self.import_incoming_c33_direct_request(canonical_dev_id, signer, cid) {
                Ok(true) => Ok(1),
                Ok(false) => {
                    if active_in_direct {
                        owed.push((cid.to_owned(), state.clone()));
                    }
                    Ok(0)
                }
                Err(MLSError::InvalidState(code))
                    if active_in_direct
                        && matches!(
                            code.as_str(),
                            "ConversationNotFound"
                                | "NotEntitled"
                                | "AccessOutsideMembershipInterval"
                        ) =>
                {
                    owed.push((cid.to_owned(), state.clone()));
                    Ok(0)
                }
                Err(err) => Err(err),
            };
        }

        if kind == "group" {
            match me.map(|me| (&me["status"], me.get("invitationProvenance"))) {
                Some((status, Some(prov))) if status == "pending" => {
                    if let Err(e) = self.accept_group_invitation(
                        canonical_dev_id,
                        signer,
                        auth_generation,
                        cid,
                        state_view_sequencer_did(state),
                        coords,
                        prov,
                    ) {
                        if !e.is_stale_coordinates() {
                            return Err(e);
                        }
                    }
                }
                Some((status, _)) if status == "active" && !has_local => {
                    owed.push((cid.to_owned(), state.clone()))
                }
                _ => {}
            }
        }
        Ok(0)
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

    /// Accepts this account's pending invitation to `cid` from this device. mls-ds opens the
    /// acceptance's add request with it: the answer's `recovery` view is recorded as this
    /// device's own open request ([`Self::own_request_record`]), so no duplicate is signed.
    fn accept_group_invitation(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        cid: &str,
        state_sequencer_did: Option<&str>,
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
        let sequencer_did = self
            .db
            .read_tx(|tx| tx.get_conversation(cid))?
            .map(|conversation| conversation.sequencer_did)
            .filter(|authority| !authority.is_empty())
            .or_else(|| state_sequencer_did.map(|authority| authority.to_owned()))
            .unwrap_or_else(|| self.config.home_ds_did.clone());
        let (answer, _) = self.submit_own_control_for_authority(
            canonical_dev_id,
            auth_generation,
            CanonicalOperation::AcceptConversation,
            &body,
            signer,
            Some(&sequencer_did),
        )?;
        let record = self.own_request_record(
            &answer["recovery"],
            cid,
            canonical_dev_id,
            &recovery_request_id,
            &next,
        )?;
        let now_ms = self.hooks.now_ms();
        self.db.write_tx(|tx| {
            tx.put_account_meta(
                &chat_wire::own_leaf_recovery_key(cid),
                &record.to_string(),
                now_ms,
            )
        })
    }

    /// This device's record of its own open request `recovery_request_id` bound to `bound`, from
    /// mls-ds's view of it in an answer ([`chat_wire::own_leaf_recovery_record`]); a view of any
    /// other request is refused.
    fn own_request_record(
        &self,
        view: &Value,
        cid: &str,
        canonical_dev_id: &str,
        recovery_request_id: &str,
        bound: &Value,
    ) -> Result<Value, MLSError> {
        let record =
            chat_wire::own_leaf_recovery_record(view, cid, &self.normalized_did, canonical_dev_id)?;
        if record["recoveryRequestId"] != recovery_request_id || record["boundCoordinate"] != *bound
        {
            return Err(MLSError::Cryptography(
                "leaf recovery: the answer is not this device's request".into(),
            ));
        }
        Ok(record)
    }

    /// `row` holds no MLS group and is not closed: a verified reset retired this device's leaf
    /// ([`Self::apply_reset_activation`]), or an archive restore brought back its history without
    /// one. Only a verified recovery Welcome joins it again ([`Self::join_pending_welcome`]);
    /// until then this device owes its own recovery request ([`Self::ensure_own_leaf_recovery`]).
    fn is_retired(&self, row: &ConversationRow) -> Result<bool, MLSError> {
        if self.is_conversation_closed(&row.conversation_id)? {
            return Ok(false);
        }
        self.db.read_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            Ok(
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&row.group_id))
                    .map_err(|e| MLSError::Internal(format!("load conversation group: {e:?}")))?
                    .is_none(),
            )
        })
    }

    /// This device's own leaf-recovery request in `cid`, which it owes (a reset retired it, or it
    /// is a new device of an active participant), from `state`: the conversation state as
    /// mls-ds presents it, active and with this account an active participant. A request still
    /// open at `state`'s coordinate is never repeated ([`chat_wire::own_leaf_recovery_open`]);
    /// otherwise this device signs one bound to that coordinate, a `replace` when `state` lists
    /// this exact device's leaf and an `add` otherwise, and records the answer's view of it.
    /// mls-ds refusing it as a duplicate (`LeafRecoveryAlreadyOpen`: one open request per exact
    /// device) records that coordinate for five minutes; a coordinate another transition took
    /// (`StaleCoordinates`) is left to a later sync.
    fn ensure_own_leaf_recovery(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        cid: &str,
        state: &Value,
    ) -> Result<(), MLSError> {
        let current = chat_wire::canonicalize_wire_coordinate(&state["coordinates"], Some(cid))?;
        let is_own = |row: &Value| row["userDid"].as_str() == Some(self.normalized_did.as_str());
        let active = state["participants"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|participant| is_own(participant) && participant["status"] == "active");
        if current["lifecycle"] != "active" || !active {
            return Ok(());
        }
        let key = chat_wire::own_leaf_recovery_key(cid);
        let now_ms = self.hooks.now_ms();
        let record = self
            .db
            .read_tx(|tx| tx.get_account_meta(&key))?
            .map(|raw| serde_json::from_str::<Value>(&raw))
            .transpose()?;
        if record
            .is_some_and(|record| chat_wire::own_leaf_recovery_open(&record, &current, cid, now_ms))
        {
            return Ok(());
        }
        let holds_leaf = state["leaves"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|leaf| is_own(leaf) && leaf["deviceId"] == canonical_dev_id);
        let recovery_request_id = self.hooks.uuid_v4().to_string();
        let body = chat_wire::leaf_recovery_request_body(
            &recovery_request_id,
            &self.normalized_did,
            canonical_dev_id,
            &derive_key_id(signer.public()),
            auth_generation,
            &current,
            if holds_leaf { "replace" } else { "add" },
            &self.hooks.now_rfc3339_millis(),
        )?;
        let record = match self.submit_signed_chat_op(
            canonical_dev_id,
            Some(auth_generation),
            CanonicalOperation::RequestLeafRecovery,
            &body,
            signer,
        ) {
            Ok(answer) => self.own_request_record(
                &answer["recovery"],
                cid,
                canonical_dev_id,
                &recovery_request_id,
                &current,
            )?,
            Err(MLSError::InvalidState(code)) if code == "LeafRecoveryAlreadyOpen" => {
                json!({ "boundCoordinate": current, "expiresAtMs": now_ms + 300_000 })
            }
            Err(error) if error.is_stale_coordinates() => return Ok(()),
            Err(error) => return Err(error),
        };
        self.db
            .write_tx(|tx| tx.put_account_meta(&key, &record.to_string(), now_ms))
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
        if local_pkg_ref.is_none() {
            return Ok(false);
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
        let peer_ds = self.resolve_peer_home_ds_did(peer_did)?.ok_or_else(|| {
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
        let metadata_snapshot_str = serde_json::to_string(&artifact["metadataSnapshot"])
            .map_err(|e| MLSError::Internal(format!("serialize C33 metadata snapshot: {e}")))?;

        let imported = self.db.write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let mls_welcome = MlsMessageIn::tls_deserialize_exact(&bootstrap.welcome)
                .map_err(|e| MLSError::Cryptography(format!("deserialize C33 Welcome: {e:?}")))?;
            let MlsMessageBodyIn::Welcome(welcome) = mls_welcome.extract() else {
                return Err(MLSError::Cryptography(
                    "C33 opaqueWelcome is not an MLS Welcome".to_string(),
                ));
            };
            let staged = match crate::sim_hooks::build_staged_welcome_at(
                &provider,
                &build_join_config(),
                welcome,
                None,
                (now_ms.max(0) as u64) / 1_000,
            ) {
                Ok(staged) => staged,
                Err(WelcomeError::NoMatchingKeyPackage) => return Ok(false),
                Err(e) => return Err(MLSError::Cryptography(format!("stage C33 Welcome: {e:?}"))),
            };

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

            let space_uri = Some(conversation_space_uri(&effective_seq_did, cid, 0));
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
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{cid}"),
                &metadata_snapshot_str,
                now_ms,
            )?;

            tx.put_labyrinth_state(
                &live_integrity::opening_receipt_key(cid, first_message_id),
                dr_rcpt_json.as_bytes(),
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
            live_integrity::reapply_opening_deletion(tx, cid, sender_did)?;
            Ok(true)
        })?;
        if !imported {
            return Ok(false);
        }

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
            .resolve_peer_home_ds_did(sender_did)?
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

    /// This device's pending Welcomes ([`Self::join_pending_welcome`]); `welcomed` collects the
    /// conversation of every one listed, joined or not.
    fn sync_pending_welcomes(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        inventory_session_id: Option<&str>,
        welcomed: &mut BTreeSet<String>,
        failures: &mut Vec<ConversationSyncFailure>,
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
            let Some(cid) = w_env
                .pointer("/coordinates/conversationId")
                .or_else(|| w_env.get("conversationId"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            welcomed.insert(cid.to_owned());
            match self.join_pending_welcome(canonical_dev_id, signer, auth_generation, w_env, cid) {
                Ok(joined_one) => joined = joined.saturating_add(u32::from(joined_one)),
                Err(error) => failures.push(ConversationSyncFailure {
                    conversation_id: cid.to_owned(),
                    error: Box::new(error),
                }),
            }
        }
        Ok(joined)
    }

    /// One pending Welcome `w_env` of `cid`: joined as the Welcome of its verified fulfillment
    /// and acknowledged (`true`), acknowledged only when this conversation is already joined, or
    /// left pending when it cannot be verified yet (`false`).
    fn join_pending_welcome(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        w_env: &Value,
        cid: &str,
    ) -> Result<bool, MLSError> {
        let welcome_id = w_env
            .get("welcomeId")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let coords = w_env.get("coordinates").unwrap_or(&Value::Null);
        let transition_seq = w_env
            .get("transitionSeq")
            .or_else(|| w_env.get("seq"))
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        let coords_canon = chat_wire::canonicalize_wire_coordinate(coords, Some(cid))?;
        let is_dr_welcome = w_env.get("$type").and_then(|t| t.as_str())
            == Some("blue.catbird.chat.defs#directRequestWelcomeView");

        // Already joined: the local row and its MLS group. A row whose group a verified reset
        // retired joins again like a new device, only through a verified recovery Welcome.
        let retired = match self.db.read_tx(|tx| tx.get_conversation(cid))? {
            Some(row) if self.is_retired(&row)? => Some(row),
            Some(_) => {
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
                return Ok(false);
            }
            None => None,
        };

        let welcome_bytes_res = w_env
            .get("opaqueWelcome")
            .or_else(|| w_env.get("welcome").and_then(|w| w.get("opaqueWelcome")))
            .or_else(|| w_env.get("bytes"))
            .ok_or_else(|| MLSError::invalid_input("pending welcome missing opaqueWelcome"))
            .and_then(chat_wire::json_bytes);
        let Ok(welcome_bytes) = welcome_bytes_res else {
            return Ok(false);
        };
        // A direct-request Welcome joins only through the checked `C33` import (signed
        // publication, coordinator outcome and `I13` receipt), never here, and is never
        // acknowledged here.
        if is_dr_welcome {
            return Ok(false);
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
            return Ok(false);
        };

        // A generic Welcome joins only as the Welcome of the receipt-verified, signed
        // `leafRecoveryFulfillmentEntry` at its `transitionSeq`, which the added device can read.
        // A `C33` opening's Welcome has none. A missing fulfillment stays pending; an invalid
        // fulfillment or receipt fails sync before installing or acknowledging the Welcome.
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
            return Ok(false);
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
        // Welcome bytes to this device, a retired row rejoins only at its generation or a later
        // one, and the joined group must be the state its signed `next` names.
        //
        // The recovery attestation in the Welcome's GroupInfo is covered by the staged GroupInfo
        // signature. Its roster and history-backup policy are accepted only when that sender is
        // exactly the verified fulfillment actor and the attestation names the joined coordinate.
        // An older, missing, or malformed policy is conservatively OFF: carried metadata may
        // predate an opt-out and is not evidence of the effective policy at this recovery.
        let verified = self.db.read_tx(|tx| {
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let storage = OpenMlsKvStorage::new(overlay);
            let provider = self.hooks.openmls_provider(storage);
            let msg_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                .map_err(|e| MLSError::Cryptography(format!("deserialize Welcome: {e:?}")))?;
            let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
                return Err(MLSError::Cryptography("not Welcome".to_string()));
            };
            let (staged, attestation) = crate::sim_hooks::build_staged_welcome_with_extension_at(
                &provider,
                &build_join_config(),
                welcome,
                None,
                (now_ms.max(0) as u64) / 1_000,
                Some(chat_wire::ROSTER_ATTESTATION_EXTENSION_TYPE),
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
            let Ok((body, request_digest)) = chat_wire::verify_signed_mutation_body_and_digest(
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
            let generation = next["generation"].as_i64().unwrap_or(0);
            if retired
                .as_ref()
                .is_some_and(|row| generation < row.generation)
            {
                return Ok(None);
            }
            let from_fulfiller = staged.welcome_sender().is_ok_and(|sender| {
                sender.credential().serialized_content()
                    == format!("{fulfiller_did}#{fulfiller_device}").as_bytes()
                    && sender.signature_key().as_slice() == key.as_slice()
            });
            let attestation = attestation.filter(|_| from_fulfiller);
            let history_backup = attestation.as_deref().and_then(|attestation| {
                chat_wire::attested_history_backup(attestation, cid, generation)
                    .ok()
                    .flatten()
            });
            let roster = attestation
                .as_deref()
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "roster attestation: none from the verified fulfiller".into(),
                    )
                })
                .and_then(|attestation| {
                    chat_wire::attested_roster(
                        attestation,
                        cid,
                        generation,
                        &self.normalized_did,
                        &member_dids,
                    )
                });
            let group = staged
                .into_group(&provider)
                .map_err(|e| MLSError::Cryptography(format!("into_group: {e:?}")))?;
            if chat_wire::require_coordinate_names_group(&next, &group, &provider).is_err() {
                return Ok(None);
            }
            Ok(Some((
                member_dids,
                body,
                request_digest,
                next,
                roster,
                history_backup,
            )))
        })?;
        let Some((
            member_dids,
            fulfillment_body,
            request_digest,
            next,
            roster,
            attested_history_backup,
        )) = verified
        else {
            tracing::warn!(
                cid,
                transition_seq,
                "Welcome is not its verified fulfillment's"
            );
            return Ok(false);
        };
        let recovery_history_backup = attested_history_backup.unwrap_or(false);
        let roster = roster
            .inspect_err(|error| tracing::warn!(cid, %error, "joining without a verified roster"))
            .ok();
        for d in member_dids {
            if candidate_dids.insert(d.clone(), ()).is_none() {
                let keys = self.fetch_and_cache_authorized_pds_device_keys(&d)?;
                all_auth_keys.extend(keys);
            }
        }
        // A retired row's pinned authority remains the I13 trust anchor; an unsigned inventory
        // view cannot replace it.
        let sequencer = retired
            .as_ref()
            .map(|row| row.sequencer_did.as_str())
            .filter(|pinned| !pinned.is_empty())
            .unwrap_or(&sequencer_did)
            .to_owned();
        self.verify_control_entry_receipt(
            &sequencer,
            cid,
            &fulfillment,
            transition_seq,
            &fulfillment_body,
            &request_digest,
        )?;
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
                    let meta_row =
                        chat_wire::group_metadata_row_from_v1(cid, m_ver, m_epoch, &meta, now_ms)?;
                    decrypted_title = meta_row.title.clone();
                    tx.upsert_group_metadata(&meta_row)?;
                }
                if let Ok(snap_s) = serde_json::to_string(snap) {
                    tx.put_account_meta(&format!("metadata_snapshot_json:{cid}"), &snap_s, now_ms)?;
                }
            }
            super::archive_policy::accept_recovery_attestation(
                tx,
                cid,
                transition_seq,
                recovery_history_backup,
                now_ms,
            )?;

            let generation = next["generation"].as_i64().unwrap_or(0);
            // A retired row keeps its history, title, unread count and pinned sequencer.
            let sequencer = sequencer.clone();
            let row = ConversationRow {
                conversation_id: cid.to_string(),
                group_id: group.group_id().as_slice().to_vec(),
                generation,
                epoch: group.epoch().as_u64() as i64,
                last_seq: transition_seq,
                space_uri: Some(conversation_space_uri(&sequencer, cid, generation)),
                sequencer_did: sequencer,
                title: decrypted_title,
                unread_count: retired.as_ref().map_or(0, |row| row.unread_count),
                updated_at_ms: now_ms,
            };
            tx.upsert_conversation(&row)?;
            Self::prune_pending_commit_transitions(tx, cid, row.generation, row.epoch, false)?;
            match &roster {
                Some(roster) => store_roster(tx, cid, roster, now_ms)?,
                None => clear_roster_baseline(tx, cid)?,
            }
            // The fulfillment answered this device's own request.
            tx.delete_account_meta(&chat_wire::own_leaf_recovery_key(cid))?;
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
        #[cfg(feature = "labyrinth")]
        if transition_seq > 1
            && self
                .labyrinth_status()
                .map(|st| st.backup_enabled)
                .unwrap_or(false)
        {
            let _ = self.restore_conversation_from_owner_mailbox(cid);
        }
        Ok(true)
    }

    /// Fulfills at most one leaf recovery of `cid` per pass: the oldest that
    /// `getConversationState.pendingLeafRecoveryRequests` lists and this device authorizes
    /// itself, and only while it is a current leaf of the active local group. A request is
    /// authorized by exactly one of:
    /// - the acceptance authorization this device stored for it
    ///   ([`chat_wire::leaf_recovery_authorization`]) when it verified that requester's
    ///   participant acceptance together with the invitation the acceptance names;
    /// - its `signedRequest`, verified under the PDS-authorized key of exactly the requester
    ///   device ([`chat_wire::leaf_recovery_request_authorization`]), signed at this device's
    ///   verified coordinate by a requester entitled to it there
    ///   ([`chat_wire::recovery_request_entitled`]).
    ///
    /// A request signed at another coordinate, an unsigned listing, or a valid request that this
    /// account is not eligible to fulfill is skipped. A valid, coordinate-bound `add` whose
    /// zero-leaf participant lacks member-authenticated admission proof returns
    /// [`MLSError::AdmissionProofUnavailable`].
    /// A `signedRequest` that does not verify, or a listed request, reservation or KeyPackage that
    /// is not exactly the authorized one ([`chat_wire::authorized_recovery_reservation`],
    /// [`chat_wire::require_recovery_key_package`]), is an error before any effect.
    ///
    /// An `add` commits an Add of the KeyPackage; a `replace` removes the requester device's
    /// exact leaf and adds the KeyPackage in one Commit. The Welcome's GroupInfo attests the
    /// effective history-backup policy and, when available, this device's verified roster
    /// ([`chat_wire::recovery_attestation_extension`]).
    ///
    /// Consume-once: a request is bound to exactly the coordinate it was signed (or accepted)
    /// at, and every transition, this fulfillment included, moves the conversation past that
    /// coordinate, so no request ever matches twice. An acceptance authorization bound to any
    /// other coordinate is dropped, and this device's verified answer consumes it.
    #[cfg_attr(not(feature = "sim"), allow(clippy::never_loop))]
    pub(crate) fn fulfill_leaf_recovery(
        &self,
        cid: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
    ) -> Result<u32, MLSError> {
        let refused = |what: &str| MLSError::Cryptography(format!("leaf recovery: {what}"));
        let authorization_key = chat_wire::leaf_recovery_authorization_key(cid);
        let closed = self.is_conversation_closed(cid)?;
        let local = self.local_coordinates(cid)?;
        let (stored, roster) = self.db.read_tx(|tx| {
            Ok((
                tx.get_account_meta(&authorization_key)?,
                stored_roster(tx, cid)?,
            ))
        })?;
        let mut acceptance = None;
        if let Some(stored) = stored {
            let authorization: Value = serde_json::from_str(&stored)?;
            let bound = chat_wire::canonicalize_wire_coordinate(
                &authorization["boundCoordinate"],
                Some(cid),
            )?;
            if closed || local.as_ref() != Some(&bound) {
                // A later step superseded it: it can never apply again.
                self.db
                    .write_tx(|tx| tx.delete_account_meta(&authorization_key))?;
            } else {
                acceptance = Some(authorization);
            }
        }
        let Some(prior_coords) = local.filter(|_| !closed) else {
            return Ok(0);
        };
        // `(did, device)` of every current leaf of the active local group; none without one.
        let leaves: Vec<(String, String)> = self.db.read_tx(|tx| {
            let Some(convo) = tx.get_conversation(cid)? else {
                return Ok(Vec::new());
            };
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let Some(group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load recovery group: {e:?}")))?
                    .filter(MlsGroup::is_active)
            else {
                return Ok(Vec::new());
            };
            group
                .members()
                .map(|member| {
                    root_did_from_credential_bytes(member.credential.serialized_content())
                })
                .collect()
        })?;
        if !leaves
            .iter()
            .any(|(did, device)| *did == self.normalized_did && device == canonical_dev_id)
        {
            return Ok(0);
        }
        let convo_uuid = uuid::Uuid::parse_str(cid)
            .map_err(|e| MLSError::invalid_input(format!("conversation id: {e}")))?;
        let resp = match self.query_signed_chat_ds(
            "blue.catbird.chat.getConversationState",
            &[("actorDeviceId", canonical_dev_id), ("conversationId", cid)],
            canonical_dev_id,
            signer,
        ) {
            Ok(resp) => resp,
            // A removed device is no current leaf and owes no fulfillment; its removal (and the
            // kick rescue) still arrives through `getEntries`.
            Err(MLSError::InvalidState(code))
                if matches!(
                    code.as_str(),
                    "ConversationNotFound" | "NotEntitled" | "AccessOutsideMembershipInterval"
                ) =>
            {
                return Ok(0)
            }
            Err(err) => return Err(err),
        };
        let mut requests: Vec<&Value> = resp["pendingLeafRecoveryRequests"]
            .as_array()
            .map(|requests| requests.iter().collect())
            .unwrap_or_default();
        requests.sort_by_key(|request| request["requestedAt"].as_str());
        let mut unentitled = None;
        let mut cached_own_devices: Option<Value> = None;
        let found = 'found: {
            for request in requests {
                if request["requesterDeviceStatus"].as_str() == Some("pending_approval")
                    || request["deviceStatus"].as_str() == Some("pending_approval")
                    || request["status"].as_str() == Some("pending_approval")
                {
                    tracing::info!(
                        cid,
                        "leaf recovery: refusing pending_approval target device"
                    );
                    continue;
                }
                let accepted = acceptance.as_ref().filter(|authorization| {
                    authorization["recoveryRequestId"] == request["recoveryRequestId"]
                });
                if accepted.is_none() && request["signedRequest"].is_null() {
                    tracing::info!(cid, "leaf recovery: skipping an unsigned request");
                    continue;
                }
                let (Some(did), Some(device)) = (
                    request["requesterDid"].as_str(),
                    request["requesterDeviceId"].as_str(),
                ) else {
                    return Err(refused("the request names no requester device"));
                };
                // Fetch current PDS authorization even for a previously accepted request. This
                // observes signing-key changes before any recovery Welcome can be produced.
                let requester_key = self.pds_device_key(did, device, &BTreeMap::new())?;
                if self
                    .db
                    .read_tx(|tx| {
                        tx.get_account_meta(&super::did_resolution::did_identity_changed_key(did))
                    })?
                    .is_some()
                {
                    return Err(refused("requester DID repository identity changed"));
                }
                if did == self.normalized_did {
                    if cached_own_devices.is_none() {
                        cached_own_devices = Some(self.query_signed_chat_ds(
                            "blue.catbird.chat.getOwnDevices",
                            &[("actorDeviceId", canonical_dev_id), ("limit", "100")],
                            canonical_dev_id,
                            signer,
                        )?);
                    }
                    let items = cached_own_devices
                        .as_ref()
                        .and_then(|response| response.get("items"))
                        .and_then(Value::as_array)
                        .ok_or_else(|| refused("getOwnDevices returned no device list"))?;
                    let own_device = items
                        .iter()
                        .map(|item| item.get("device").unwrap_or(item))
                        .find(|candidate| candidate["deviceId"].as_str() == Some(device))
                        .ok_or_else(|| refused("own requester absent from getOwnDevices"))?;
                    if own_device["status"].as_str() != Some("active") {
                        return Err(refused("own requester is not active"));
                    }
                    if chat_wire::json_bytes(&own_device["signaturePublicKey"])? != requester_key {
                        return Err(refused("own requester key differs between PDS and home DS"));
                    }
                }
                let (authorization, verified_key) = match accepted {
                    Some(authorization) => (authorization.clone(), None),
                    None => {
                        if resp["state"]["leaves"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|leaf| {
                                leaf["userDid"].as_str() == Some(did)
                                    && leaf["deviceId"].as_str() == Some(device)
                                    && leaf["status"].as_str() == Some("pending_approval")
                            })
                        {
                            tracing::info!(
                                cid,
                                "leaf recovery: refusing pending_approval leaf in state"
                            );
                            continue;
                        }
                        // `I4` (`ADR-009`): the PDS-authorized key of exactly that device.
                        let body = verify_signed_mutation_body(
                            &request["signedRequest"],
                            SignedMutationKind::LeafRecoveryRequest,
                            &requester_key,
                        )?;
                        let authorization =
                            chat_wire::leaf_recovery_request_authorization(&body, cid)?;
                        if authorization["boundCoordinate"] != prior_coords {
                            tracing::info!(
                                cid,
                                "leaf recovery: skipping a request signed at another coordinate"
                            );
                            continue;
                        }
                        let verified_admission = self.db.read_tx(|tx| {
                            tx.get_account_meta(&chat_wire::verified_participant_admission_key(
                                cid, did,
                            ))
                        })?;
                        if !chat_wire::recovery_request_entitled(
                            &authorization,
                            &leaves,
                            roster.as_ref(),
                            verified_admission.is_some(),
                            &self.normalized_did,
                            canonical_dev_id,
                        ) {
                            let has_account_leaf =
                                leaves.iter().any(|(leaf_did, _)| leaf_did == did);
                            if authorization["recoveryKind"] == "add"
                                && !has_account_leaf
                                && !(verified_admission.is_some()
                                    && chat_wire::roster_active(roster.as_ref(), did))
                            {
                                unentitled = Some(did.to_owned());
                            }
                            tracing::info!(cid, "leaf recovery: request is not eligible");
                            continue;
                        }
                        (authorization, Some(requester_key))
                    }
                };
                let (kp_bytes, kp_ref) = chat_wire::authorized_recovery_reservation(
                    &authorization,
                    request,
                    &resp["state"]["coordinates"],
                    &prior_coords,
                    cid,
                )?;
                break 'found Some((authorization, verified_key, kp_bytes, kp_ref));
            }
            None
        };
        let Some((authorization, verified_key, kp_bytes, kp_ref)) = found else {
            return match unentitled {
                Some(participant_did) => Err(MLSError::AdmissionProofUnavailable {
                    conversation_id: cid.to_owned(),
                    participant_did,
                }),
                None => {
                    let leave_fulfilled = self.fulfill_pending_group_leave_from_state(
                        cid,
                        canonical_dev_id,
                        &convo_uuid,
                        signer,
                        auth_generation,
                        &resp,
                    )?;
                    Ok(u32::from(leave_fulfilled))
                }
            };
        };
        let (Some(recovery_request_id), Some(target_did), Some(target_device_id)) = (
            authorization["recoveryRequestId"].as_str(),
            authorization["requesterDid"].as_str(),
            authorization["requesterDeviceId"].as_str(),
        ) else {
            return Err(refused("malformed authorization"));
        };
        // `I4` (`ADR-009`): the requester device's PDS-authorized key.
        let target_key = match verified_key {
            Some(key) => key,
            None => self.pds_device_key(target_did, target_device_id, &BTreeMap::new())?,
        };
        let target_identity = format!("{target_did}#{target_device_id}");
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
        let replace = authorization["recoveryKind"] == "replace";

        // Only the sim-only P15 calibration retries; production submits each Commit once.
        #[cfg_attr(not(feature = "sim"), allow(unused_mut, unused_variables))]
        let mut first_attempt = true;
        loop {
            let transition_uuid = self.hooks.uuid_v4();
            let transition_id = transition_uuid.to_string();
            let welcome_id = self.hooks.uuid_v4().to_string();
            let now_ms = self.hooks.now_ms();
            let now_secs = (now_ms.max(0) as u64) / 1_000;

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
                    return Err(MLSError::Cryptography(
                        "leaf recovery: reservation holds no KeyPackage".into(),
                    ));
                };
                let validated_kp = crate::sim_hooks::validate_key_package_at(
                    kp_for_attempt,
                    provider.crypto(),
                    ProtocolVersion::Mls10,
                    now_secs,
                )
                .map_err(|e| MLSError::Cryptography(format!("validate recovery KP: {e:?}")))?;
                chat_wire::require_recovery_key_package(
                    &authorization,
                    &validated_kp,
                    &kp_ref,
                    &target_key,
                    &provider,
                )?;
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
                // An add adds a device the tree does not hold; a replace removes the requester
                // device's one current leaf in the same Commit.
                let held: Vec<LeafNodeIndex> = group
                    .members()
                    .filter(|member| {
                        member.credential.serialized_content() == target_identity.as_bytes()
                    })
                    .map(|member| member.index)
                    .collect();
                if held.len() != usize::from(replace) {
                    return Err(refused(if replace {
                        "the requester device holds no leaf to replace"
                    } else {
                        "the requester device already holds a leaf"
                    }));
                }

                let metadata_carry = self
                    .metadata_snapshot_plaintext_for_carry_forward(
                        tx,
                        cid,
                        &convo.group_id,
                        &mut group,
                        &provider,
                    )?;

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

                // Policy controls do not move MLS coordinates. Read the effective value only
                // after all discovery I/O, in the same transaction that constructs GroupInfo,
                // so a completed concurrent control cannot be attested from a stale preflight.
                let attestation = chat_wire::recovery_attestation_extension(
                    cid,
                    prior_gen,
                    roster.as_ref(),
                    super::archive_policy::current_enabled(tx, cid)?,
                )?;
                group.set_aad(commit_aad_bytes);
                let mut builder = group
                    .commit_builder()
                    .propose_removals(held)
                    .propose_adds([validated_kp])
                    .force_self_update(true)
                    .leaf_node_lifetime_policy(LeafNodeLifetimePolicy::VerifyAt(now_secs))
                    .load_psks(provider.storage())
                    .map_err(|e| MLSError::Cryptography(format!("recovery commit: {e:?}")))?;
                builder = builder
                    .create_group_info_with_extensions([attestation])
                    .map_err(|e| {
                        MLSError::Cryptography(format!("recovery attestation: {e:?}"))
                    })?;
                let bundle = builder
                    .build(provider.rand(), provider.crypto(), signer, |_| true)
                    .map_err(|e| MLSError::Cryptography(format!("recovery commit: {e:?}")))?
                    .stage_commit(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("stage recovery commit: {e:?}")))?;
                let welcome_out = bundle
                    .to_welcome_msg()
                    .ok_or_else(|| refused("the Commit carries no Welcome"))?;
                let commit_out = bundle.into_commit();
                let staged_pending_batch = overlay.clone_batch();
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("merge recovery commit: {e:?}")))?;
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
                let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                    metadata_carry,
                    &mut group,
                    &provider,
                    &convo.group_id,
                    &convo_uuid,
                    prior_gen,
                    next_epoch,
                    &next_gch,
                    &next_ctag,
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
                    "leafChanges": chat_wire::recovery_leaf_changes(&authorization, &kp_ref),
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
                            .read_tx(|tx| tx.get_pending_op("commit_transition", &transition_id))?
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
                // Sequenced, the fulfillment consumed the authorization.
                tx.delete_account_meta(&authorization_key)?;
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
                    if (next_epoch as i64) > c.epoch {
                        let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                        let provider = self.hooks.openmls_provider(storage);
                        if let Some(group) =
                            MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        {
                            super::send_counter::advance_send_counter_epoch_chain(
                                tx,
                                cid,
                                c.generation,
                                c.epoch,
                                next_epoch as i64,
                                &super::send_counter::group_leaf_devices(&group),
                                now_ms,
                            )?;
                        }
                    }
                    c.epoch = next_epoch as i64;
                    if authoritative_seq == c.last_seq + 1 {
                        c.last_seq = authoritative_seq;
                    }
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)?;
                }
                tx.put_account_meta(&format!("metadata_snapshot_json:{cid}"), &snap_str, now_ms)?;
                tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, now_ms)?;
                Self::prune_pending_commit_transitions(
                    tx,
                    cid,
                    prior_gen,
                    next_epoch as i64,
                    false,
                )?;
                Ok(())
            })?;
            return Ok(1);
        }
        Ok(0)
    }

    /// Advance PCS after a deterministic age or durable-message threshold in one active group
    /// epoch. A missing epoch marker is initialized without treating pre-install wall time as age.
    fn maybe_auto_self_update(&self, cid: &str) -> Result<(), MLSError> {
        if self.hooks.pcs_max_age_ms == 0 && self.hooks.pcs_max_messages == 0 {
            return Ok(());
        }
        let Some(convo) = self.db.read_tx(|tx| tx.get_conversation(cid))? else {
            return Ok(());
        };
        let is_group = self.db.read_tx(|tx| {
            Ok(tx
                .get_account_meta(&format!("conversation_kind:{cid}"))?
                .is_some_and(|kind| kind == "group"))
        })?;
        if !is_group || self.is_retired(&convo)? || self.is_conversation_closed(cid)? {
            return Ok(());
        }
        let now_ms = self.hooks.now_ms();
        let marker = format!(
            "pcs_epoch_started_at:{cid}:{}:{}",
            convo.generation, convo.epoch
        );
        let (started_at, message_count) = self.db.write_tx(|tx| {
            let started = tx
                .get_account_meta(&marker)?
                .and_then(|raw| raw.parse::<i64>().ok());
            if started.is_none() {
                tx.put_account_meta(&marker, &now_ms.to_string(), now_ms)?;
            }
            let count: i64 = tx
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM messages \
                     WHERE conversation_id = ?1 AND group_id = ?2 AND epoch = ?3",
                    rusqlite::params![cid, &convo.group_id, convo.epoch],
                    |row| row.get(0),
                )
                .map_err(|e| map_rusqlite_err("count PCS epoch messages", &e))?;
            Ok((started.unwrap_or(now_ms), count.max(0) as u64))
        })?;
        let due_to_age = self.hooks.pcs_max_age_ms > 0
            && now_ms.saturating_sub(started_at) > self.hooks.pcs_max_age_ms;
        let due_to_messages =
            self.hooks.pcs_max_messages > 0 && message_count > self.hooks.pcs_max_messages;
        if due_to_age || due_to_messages {
            self.self_update(cid)?;
        }
        Ok(())
    }

    /// Verify a generic control entry's I13 receipt against its signed request and post-entry
    /// coordinate. This runs before every transition effect.
    pub(super) fn verify_control_entry_receipt(
        &self,
        sequencer_did: &str,
        cid: &str,
        entry: &Value,
        entry_seq: i64,
        verified_body: &Value,
        request_digest: &[u8; 32],
    ) -> Result<(), MLSError> {
        let receipt = entry
            .get("sequencerReceipt")
            .filter(|value| value.is_object())
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "I13: control entry at seq {entry_seq} missing sequencerReceipt"
                ))
            })?;
        let entry_id = entry
            .get("entryId")
            .and_then(Value::as_str)
            .ok_or_else(|| MLSError::Cryptography("control entry missing entryId".into()))?;
        let kid = chat_wire::sequencer_receipt_kid(sequencer_did, receipt)?;
        let key = self
            .resolve_sequencer_receipt_key(sequencer_did, kid)?
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "I13: unable to resolve `{sequencer_did}` receipt method {kid}"
                ))
            })?;
        let fallback_coordinate = self.local_coordinates(cid)?;
        verify_control_entry_receipt_with_key(
            sequencer_did,
            cid,
            entry_id,
            entry_seq,
            receipt,
            verified_body,
            request_digest,
            &key,
            fallback_coordinate.as_ref(),
        )
    }
    /// A valid current leaf signature over a different prior at our current epoch proves a fork,
    /// but durable evidence is written only after `authenticate` verifies this entry's exact I13
    /// receipt, sender and archive commitment. The application receipt does not currently sign the
    /// signed-request digest or prior hash/tag; this check deliberately does not claim otherwise.
    fn verify_application_prior_or_flag_fork(
        &self,
        cid: &str,
        entry_seq: i64,
        body: &Value,
        authenticate: impl FnOnce() -> Result<(), MLSError>,
    ) -> Result<(), MLSError> {
        let Some(local) = self.local_coordinates(cid)? else {
            return Ok(());
        };
        let prior = chat_wire::canonicalize_wire_coordinate(&body["prior"], Some(cid))?;
        let local_epoch = local["epoch"]
            .as_i64()
            .ok_or_else(|| MLSError::Internal("local coordinate missing epoch".into()))?;
        let prior_epoch = prior["epoch"]
            .as_i64()
            .ok_or_else(|| MLSError::Cryptography("application prior missing epoch".into()))?;
        if prior_epoch < local_epoch {
            // An own Commit answer can put MLS ahead of its still-unread application prefix.
            return Ok(());
        }
        if prior_epoch > local_epoch || prior["generation"] != local["generation"] {
            return Err(MLSError::Cryptography(format!(
                "WrongEpoch: signed application prior is generation {}, epoch {}, local is generation {}, epoch {}",
                prior["generation"], prior_epoch, local["generation"], local_epoch
            )));
        }
        let prior_hash = chat_wire::json_bytes(&prior["groupContextHash"])?;
        let local_hash = chat_wire::json_bytes(&local["groupContextHash"])?;
        let prior_tag = chat_wire::json_bytes(&prior["confirmationTag"])?;
        let local_tag = chat_wire::json_bytes(&local["confirmationTag"])?;
        if prior_hash == local_hash && prior_tag == local_tag {
            return Ok(());
        }
        authenticate()?;
        let generation = local["generation"].as_i64().unwrap_or_default();
        let evidence = json!({
            "entrySeq": entry_seq,
            "generation": generation,
            "epoch": local_epoch,
            "localGroupContextHash": local["groupContextHash"],
            "localConfirmationTag": local["confirmationTag"],
            "signedPrior": prior,
        });
        let now_ms = self.hooks.now_ms();
        self.db.write_tx(|tx| {
            tx.put_account_meta(
                &chat_wire::fork_detected_key(cid),
                &evidence.to_string(),
                now_ms,
            )
        })?;
        Err(MLSError::ForkDetected {
            conversation_id: cid.to_owned(),
            generation,
            epoch: local_epoch,
        })
    }

    /// Applies `convo`'s ordered entries past its cursor ([`Self::apply_conversation_entries`]).
    /// An entry that does not verify or apply stops the pass with its error after the applied
    /// prefix is finished as any pass is ([`Self::finish_entry_pass`]): the cursor and the
    /// acknowledgement both stay just below that entry.
    pub(crate) fn sync_conversation_entries(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        convo: &ConversationRow,
    ) -> Result<u32, MLSError> {
        let mut pass = EntryPass {
            max_seq: convo.last_seq,
            ..EntryPass::default()
        };
        let outcome = self.apply_conversation_entries(canonical_dev_id, signer, convo, &mut pass);
        let finished = self.finish_entry_pass(&convo.conversation_id, &pass);
        outcome.and(finished)?;

        // Only a completely successful foreground pass may retire the NSE's reason marker.
        // A missing/invalid receipt leaves both the cursor and marker below the control.
        self.db.write_tx(|tx| {
            let Some(raw_seq) =
                tx.get_pending_op(NSE_DEFERRED_CONTROL_OP, &convo.conversation_id)?
            else {
                return Ok(());
            };
            let deferred_seq = raw_seq.parse::<i64>().map_err(|error| {
                MLSError::InvalidState(format!(
                    "invalid NSE deferred-control marker for {}: {error}",
                    convo.conversation_id
                ))
            })?;
            if deferred_seq < 1 {
                return Err(MLSError::InvalidState(format!(
                    "invalid NSE deferred-control seq {deferred_seq} for {}",
                    convo.conversation_id
                )));
            }
            if pass.max_seq >= deferred_seq {
                tx.delete_pending_op(NSE_DEFERRED_CONTROL_OP, &convo.conversation_id)?;
            }
            Ok(())
        })?;
        Ok(pass.applied)
    }

    /// The end of an entry pass, over the entries it applied: the accepted opening's archive, the
    /// kick rescue, and the acknowledgement up to the last applied entry. Nothing is acknowledged
    /// once the pass ended this device's access: removed, closed, or retired by a reset.
    fn finish_entry_pass(&self, cid: &str, pass: &EntryPass) -> Result<(), MLSError> {
        let ended = pass.was_closed || pass.was_retired;
        if pass.saw_c33_accept && !ended {
            self.archive_accepted_opening_messages(cid)?;
            self.notify_change(PlatformChangeEvent::RequestsUpdated);
        }
        if pass.was_kicked && !ended {
            self.rescue_conversation_on_kick(cid)?;
        }
        if pass.max_seq >= 1 && pass.applied > 0 && !pass.was_kicked && !ended {
            match self.acknowledge_entries_up_to(cid, pass.max_seq) {
                Ok(()) => {}
                Err(MLSError::InvalidState(code)) if code == "ConversationNotFound" => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Every entry of `convo` past its cursor, in seq order, each verified before any effect and
    /// recorded in `pass` as it applies. Returns at the first that does not verify or apply.
    fn apply_conversation_entries(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        convo: &ConversationRow,
        pass: &mut EntryPass,
    ) -> Result<(), MLSError> {
        let cid = convo.conversation_id.as_str();
        if self.is_conversation_closed(cid)? {
            return Ok(());
        }
        if uuid::Uuid::parse_str(cid)
            .ok()
            .filter(|u| u.get_version_num() == 4)
            .is_none()
        {
            return Ok(());
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
        let mut pagination =
            crate::orchestrator::pagination::PaginationGuard::for_messages("live entry sync");
        loop {
            let after_seq_str = cursor_seq.to_string();
            let mut resp = match self.query_signed_chat_ds(
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
                Err(MLSError::InvalidState(code)) if code == "ConversationNotFound" => {
                    if sorted_entries.is_empty() {
                        break;
                    }
                    return Err(MLSError::Cryptography(
                        "conversation disappeared during entry pagination".into(),
                    ));
                }
                Err(err) => return Err(err),
            };
            let page_entries = resp
                .as_object_mut()
                .and_then(|object| object.remove("entries"))
                .ok_or_else(|| {
                    MLSError::Cryptography("entry page is missing entries".into())
                })?;
            let Value::Array(page_entries) = page_entries else {
                return Err(MLSError::Cryptography(
                    "entry page has malformed entries".into(),
                ));
            };
            if page_entries.len() > 100 {
                return Err(MLSError::Cryptography(
                    "entry page exceeds the requested limit".into(),
                ));
            }
            if page_entries.is_empty() {
                pagination
                    .observe_page(0, None)
                    .map_err(|error| MLSError::Cryptography(error.to_string()))?;
                break;
            }
            let mut page_max_seq = cursor_seq;
            for entry in &page_entries {
                let seq = entry.get("seq").and_then(Value::as_i64).ok_or_else(|| {
                    MLSError::Cryptography("entry page contains an invalid sequence".into())
                })?;
                if seq <= cursor_seq {
                    return Err(MLSError::Cryptography(
                        "entry pagination made no sequence progress".into(),
                    ));
                }
                page_max_seq = page_max_seq.max(seq);
            }
            let has_more = page_entries.len() == 100;
            let next_cursor = has_more.then(|| page_max_seq.to_string());
            pagination
                .observe_page(page_entries.len(), next_cursor.as_deref())
                .map_err(|error| MLSError::Cryptography(error.to_string()))?;
            sorted_entries.extend(page_entries);
            if !has_more {
                break;
            }
            cursor_seq = page_max_seq;
        }
        if sorted_entries.is_empty() {
            return Ok(());
        }

        sorted_entries.sort_by_key(|e| e.get("seq").and_then(|s| s.as_i64()).unwrap_or(0));

        let mut expected_next_seq = convo
            .last_seq
            .max(0)
            .checked_add(1)
            .ok_or_else(|| MLSError::Cryptography("conversation sequence exhausted".into()))?;

        // Pre-fetch PDS `blue.catbird.chat.device` keys (`I4`) for all DIDs referenced in batch
        // plus all current local `MlsGroup` members.
        let mut candidate_dids = BTreeMap::new();
        let deleting_dids: BTreeSet<String> = sorted_entries
            .iter()
            .filter(|entry| {
                entry.get("$type").and_then(Value::as_str)
                    == Some(crate::chat_v2::wire::ACCOUNT_DELETED_ENTRY_KIND)
            })
            .filter_map(|entry| entry["deletedDid"].as_str().map(str::to_owned))
            .collect();
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
            // Deletion can arrive after the actor's PDS repository is gone. Its actorWrite
            // verifies through the self-contained keyProof below; a prior application entry
            // still has to prove its own sender key and will fail without one.
            let keys = match self.fetch_and_cache_authorized_pds_device_keys(did) {
                Ok(keys) => keys,
                Err(error) if deleting_dids.contains(did) => {
                    tracing::warn!(%did, %error, "deleted account PDS keys unavailable; verifying deletion keyProof");
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            auth_keys_by_did.insert(did.clone(), keys);
        }
        let flat_auth_keys: Vec<AuthorizedPeerDeviceKey> = auth_keys_by_did
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        const DIRECT_REQUEST_ENTRY: &str = "blue.catbird.chat.defs#directRequestEntry";
        const DIRECT_REQUEST_ACCEPTANCE_ENTRY: &str =
            "blue.catbird.chat.defs#directRequestAcceptanceEntry";
        const DIRECT_REQUEST_ACCEPTANCE_BODY: &str =
            "blue.catbird.chat.defs#directRequestAcceptanceBody";
        for (index, entry) in sorted_entries.iter().enumerate() {
            let entry_seq = entry
                .get("seq")
                .and_then(|v| v.as_i64())
                .filter(|seq| *seq >= 1)
                .ok_or_else(|| {
                    MLSError::Cryptography("conversation entry missing a positive seq".into())
                })?;
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
            if entry_seq <= convo.last_seq {
                #[cfg(feature = "sim")]
                let sim_replay = self.sim_reopened
                    && crate::planted::is_planted_bug_active(
                        crate::planted::PlantedBug::P12SkipMessageIdDedupeAfterCrashRestart,
                    );
                #[cfg(not(feature = "sim"))]
                let sim_replay = false;
                if !is_application || (!pending_receipts.contains_key(&entry_seq) && !sim_replay) {
                    // Entries already at or below the durable cursor have already been applied;
                    // only a pending NSE archive receipt (or sim P12) re-inspects an application entry.
                    continue;
                }
            } else {
                if entry_seq != expected_next_seq {
                    return Err(MLSError::Cryptography(format!(
                        "non-contiguous conversation sequence: expected {expected_next_seq}, received {entry_seq}"
                    )));
                }
                // An own message the sequencer already receipted at this seq must be this entry.
                let entry_message_id = is_application
                    .then(|| {
                        body.get("messageId")
                            .or_else(|| entry.get("messageId"))
                            .or_else(|| entry.get("entryId"))
                            .and_then(Value::as_str)
                    })
                    .flatten();
                self.db.write_tx(|tx| {
                    super::send_counter::check_own_receipt_at_entry(
                        tx,
                        cid,
                        entry_seq,
                        entry_message_id,
                        now_ms,
                    )
                })?;
                expected_next_seq = expected_next_seq.checked_add(1).ok_or_else(|| {
                    MLSError::Cryptography("conversation sequence exhausted".into())
                })?;
            }
            if pending_receipts.contains_key(&entry_seq) && !is_application {
                return Err(MLSError::Cryptography(
                    "pending archive receipt was replaced by a non-application entry".into(),
                ));
            }

            // Every entry below verifies before any effect. One that does not stops this
            // conversation's sync with the cursor below it: no later entry carries it past.
            if label == Some(crate::chat_v2::wire::ACCOUNT_DELETED_ENTRY_KIND) {
                // A deletion takes effect only under its deleting device's own signature. Keep
                // any unverified entry as evidence, then leave the cursor below it so later
                // messages cannot make an unresolved deletion silently permanent.
                let decision = self.authorize_account_deletion(cid, &convo.sequencer_did, entry)?;
                if matches!(
                    &decision,
                    live_integrity::AccountDeletionDecision::Unverified {
                        reason: crate::client::deletion_authority::UnverifiedDeletionReason::SequencerUnverified,
                        ..
                    }
                ) {
                    return Err(MLSError::Cryptography(
                        "I13: account deletion authority does not verify".into(),
                    ));
                }
                self.apply_account_deletion_decision(cid, entry, &decision)?;
                if let live_integrity::AccountDeletionDecision::Unverified { reason, .. } = decision
                {
                    if !matches!(
                        reason,
                        crate::client::deletion_authority::UnverifiedDeletionReason::OtherConversation
                            | crate::client::deletion_authority::UnverifiedDeletionReason::Replayed
                    ) {
                        tracing::warn!(cid, entry_seq, ?reason, "account deletion remains unverified; sync will retry at this entry");
                        return Err(MLSError::InvalidState("AccountDeletionUnverified".into()));
                    }
                }
                let now_ms = self.hooks.now_ms();
                self.db.write_tx(|tx| {
                    if let Some(mut c) = tx.get_conversation(cid)? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    Ok(())
                })?;
                pass.applied = pass.applied.saturating_add(1);
                pass.max_seq = pass.max_seq.max(entry_seq);
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
                    if let Some(did) = body["actorDid"].as_str() {
                        tx.put_account_meta(
                            &chat_wire::verified_participant_admission_key(cid, did),
                            "true",
                            now_ms,
                        )?;
                    }
                    if let Some(mut c) = tx.get_conversation(cid)? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    Ok(())
                })?;
                pass.saw_c33_accept = true;
                pass.max_seq = pass.max_seq.max(entry_seq);
                pass.applied = pass.applied.saturating_add(1);
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
                // leave's whenever its DID holds no current leaf. Each steps `stateVersion` from
                // this device's current coordinate (`chat_wire::steps_from_local`; an own
                // transition its answer already recorded moves only the cursor): the verified
                // `next`, its participant effects on the verified roster
                // ([`apply_verified_roster_effects`]) and a metadata transition's verified
                // snapshot are all that is written. With a verified roster, a policy applies only
                // under an active admin by it (`chat_wire::require_active_admin`; mls-ds sequences
                // no other), so no member raises its own role. An acceptance never touches a
                // direct request.
                //
                // An acceptance or a removal ends its DID's pending invitation at this seq
                // (`chat_wire::invitation_closed_key`): an invitation is accepted once, and never
                // after its invitee's removal, so an acceptance of an invitation ended before is
                // refused. An acceptance whose invitation this device verified grants the
                // leaf-recovery authorization of its add request
                // ([`Self::fulfill_leaf_recovery`]); one whose invitation predates this
                // device's history grants nothing.
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
                let (verified, request_digest) =
                    chat_wire::verify_signed_mutation_body_and_digest(signed_req, kind, &key)?;
                self.verify_control_entry_receipt(
                    &convo.sequencer_did,
                    cid,
                    entry,
                    entry_seq,
                    &verified,
                    &request_digest,
                )?;
                let is_acceptance = kind == SignedMutationKind::ParticipantAcceptance;
                let invitation_seq = if leaf_signed {
                    None
                } else {
                    self.require_participant(
                        canonical_dev_id,
                        signer,
                        cid,
                        &convo.sequencer_did,
                        actor_did,
                        is_acceptance.then(|| &verified["invitationProvenance"]),
                        entry_seq,
                        earlier,
                        &auth_keys_by_did,
                    )?
                };
                let next = chat_wire::verify_state_version_step(&verified, cid)?;
                let steps = chat_wire::steps_from_local(
                    &verified["prior"],
                    &next,
                    self.local_coordinates(cid)?.as_ref(),
                    actor_did == self.normalized_did && actor_dev == canonical_dev_id,
                    cid,
                )?;
                if kind == SignedMutationKind::PolicyTransition && steps {
                    if let Some(roster) = self.db.read_tx(|tx| stored_roster(tx, cid))? {
                        chat_wire::require_active_admin(Some(&roster), actor_did, cid)?;
                    }
                }
                let authorization = match invitation_seq.filter(|_| is_acceptance) {
                    Some(invitation_seq) => {
                        let closed = self.db.read_tx(|tx| {
                            tx.get_account_meta(&chat_wire::invitation_closed_key(cid, actor_did))
                        })?;
                        if closed
                            .and_then(|seq| seq.parse::<i64>().ok())
                            .is_some_and(|closed| closed >= invitation_seq)
                        {
                            return Err(MLSError::Cryptography(
                                "invitation chain: the invitation is no longer pending".into(),
                            ));
                        }
                        Some(chat_wire::leaf_recovery_authorization(&verified, cid)?.to_string())
                    }
                    None => None,
                };
                let mut invitations_closed = chat_wire::removed_participants(kind, &verified);
                if is_acceptance {
                    invitations_closed.push(actor_did.to_owned());
                }
                let next = serde_json::to_string(&next)?;
                let is_metadata = kind == SignedMutationKind::MetadataTransition && steps;
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
                                super::archive_policy::accept_snapshot(
                                    tx,
                                    cid,
                                    entry_seq,
                                    &meta,
                                    super::archive_policy::SnapshotPolicyAuthority::AuthoredMetadataTransition,
                                    now_ms,
                                )?;
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
                    if steps {
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &next, now_ms)?;
                        apply_verified_roster_effects(tx, cid, kind, &verified, now_ms)?;
                    }
                    for did in &invitations_closed {
                        tx.put_account_meta(
                            &chat_wire::invitation_closed_key(cid, did),
                            &entry_seq.to_string(),
                            now_ms,
                        )?;
                    }
                    if is_acceptance {
                        let key = chat_wire::leaf_recovery_authorization_key(cid);
                        match &authorization {
                            Some(authorization) => {
                                tx.put_account_meta(&key, authorization, now_ms)?
                            }
                            None => tx.delete_account_meta(&key)?,
                        }
                    }
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)
                })?;
                if is_metadata {
                    self.notify_change(PlatformChangeEvent::GroupMetadataUpdated {
                        conversation_id: cid.to_string(),
                    });
                }
                pass.max_seq = pass.max_seq.max(entry_seq);
                pass.applied = pass.applied.saturating_add(1);
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
                let (verified, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    signed_req,
                    SignedMutationKind::ConversationClose,
                    &key,
                )?;
                self.verify_control_entry_receipt(
                    &convo.sequencer_did,
                    cid,
                    entry,
                    entry_seq,
                    &verified,
                    &request_digest,
                )?;
                if !is_leaf {
                    self.require_participant(
                        canonical_dev_id,
                        signer,
                        cid,
                        &convo.sequencer_did,
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
                // A close retires this device's current coordinate, never one it already left.
                chat_wire::steps_from_local(
                    &verified["prior"],
                    &retired,
                    self.local_coordinates(cid)?.as_ref(),
                    false,
                    cid,
                )?;
                self.apply_terminal_close(cid, Some(&retired), Some(entry_seq))?;
                pass.was_closed = true;
                pass.max_seq = pass.max_seq.max(entry_seq);
                pass.applied = pass.applied.saturating_add(1);
                break;
            }

            if kind == Some(SignedMutationKind::ResetActivation) {
                // A reset activation retires exactly this device's current state: its `prior` is
                // the recorded coordinate (a replayed or reordered activation names a state this
                // device already left and is refused), `retired` steps it to superseded and
                // `successor` opens the next generation on a fresh group
                // (`chat_wire::reset_successor`). Before any effect its activator must be an
                // active admin by this device's verified roster: without one nothing establishes
                // it (`MLSError::RosterUnverified`), and a participant's signature never does. The
                // manifest's roster then replaces this device's in the transaction that applies
                // the reset ([`Self::apply_reset_activation`]).
                //
                // This device's own activation verifies under its own key. Once its answer
                // applied (the local coordinate already is its `successor`) the echo moves only
                // the cursor; otherwise it applies exactly this device's journal of that
                // `transitionId` ([`super::live_plane::RESET_ACTIVATION_OP`]), and without one it
                // is refused. A peer device's activation, signed under its PDS-authorized key by
                // a participant, retires this device's old-generation leaf, which `prior` must
                // name: every old leaf but the activator only closes (`CHAT_PROTOCOL` §6), so
                // nothing past the reset is read.
                let is_own = actor_did == self.normalized_did && actor_dev == canonical_dev_id;
                let key = if is_own {
                    signer.public().to_vec()
                } else {
                    self.pds_device_key(actor_did, actor_dev, &auth_keys_by_did)?
                };
                let (verified, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    signed_req,
                    SignedMutationKind::ResetActivation,
                    &key,
                )?;
                self.verify_control_entry_receipt(
                    &convo.sequencer_did,
                    cid,
                    entry,
                    entry_seq,
                    &verified,
                    &request_digest,
                )?;
                let successor = chat_wire::reset_successor(&verified, cid)?;
                let roster = self.db.read_tx(|tx| stored_roster(tx, cid))?;
                chat_wire::require_active_admin(roster.as_ref(), actor_did, cid)?;
                let manifest_roster =
                    chat_wire::roster_from_participants(&verified["manifest"]["participants"])?;
                let local = self.local_coordinates(cid)?;
                if is_own && local.as_ref() == Some(&successor) {
                    self.db.write_tx(|tx| {
                        if let Some(mut c) = tx.get_conversation(cid)? {
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = now_ms;
                            tx.upsert_conversation(&c)?;
                        }
                        Ok(())
                    })?;
                    pass.max_seq = pass.max_seq.max(entry_seq);
                    continue;
                }
                chat_wire::steps_from_local(
                    &verified["prior"],
                    &verified["retired"],
                    local.as_ref(),
                    false,
                    cid,
                )?;
                if is_own {
                    let transition_id = verified["transitionId"].as_str().unwrap_or_default();
                    let journal: super::live_plane::PendingResetActivation = self
                        .db
                        .read_tx(|tx| {
                            tx.get_pending_op(super::live_plane::RESET_ACTIVATION_OP, transition_id)
                        })?
                        .map(|raw| serde_json::from_str(&raw))
                        .transpose()?
                        .ok_or_else(|| {
                            MLSError::InvalidState(format!(
                                "own reset activation {transition_id} has no journal"
                            ))
                        })?;
                    if journal.conversation_id != cid || journal.successor != successor {
                        return Err(MLSError::Cryptography(
                            "reset journal does not match the sequenced own activation".into(),
                        ));
                    }
                    self.apply_reset_activation(
                        cid,
                        &successor,
                        &manifest_roster,
                        Some(entry_seq),
                        Some((&journal.kv_batch, &verified["metadataSnapshot"])),
                    )?;
                    pass.max_seq = pass.max_seq.max(entry_seq);
                    pass.applied = pass.applied.saturating_add(1);
                    continue;
                }
                let prior = chat_wire::canonicalize_wire_coordinate(&verified["prior"], None)?;
                self.db.read_tx(|tx| {
                    let c = tx
                        .get_conversation(cid)?
                        .ok_or_else(|| MLSError::group_not_found(cid))?;
                    let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                    let provider = self.hooks.openmls_provider(storage);
                    let group =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                            .map_err(|e| MLSError::Internal(format!("load reset group: {e:?}")))?
                            .filter(|group| group.is_active())
                            .ok_or_else(|| {
                                MLSError::Cryptography(
                                    "reset activation: no old-generation leaf here to retire"
                                        .into(),
                                )
                            })?;
                    if prior["generation"].as_i64() != Some(c.generation) {
                        return Err(MLSError::Cryptography(
                            "reset activation: prior is not the local generation".into(),
                        ));
                    }
                    chat_wire::require_coordinate_names_group(&prior, &group, &provider)
                })?;
                self.require_participant(
                    canonical_dev_id,
                    signer,
                    cid,
                    &convo.sequencer_did,
                    actor_did,
                    None,
                    entry_seq,
                    earlier,
                    &auth_keys_by_did,
                )?;
                self.apply_reset_activation(
                    cid,
                    &successor,
                    &manifest_roster,
                    Some(entry_seq),
                    None,
                )?;
                pass.was_retired = true;
                pass.max_seq = pass.max_seq.max(entry_seq);
                pass.applied = pass.applied.saturating_add(1);
                break;
            }

            if let Some(
                kind @ (SignedMutationKind::ResetRequest
                | SignedMutationKind::LeaveCancellation
                | SignedMutationKind::Creation
                | SignedMutationKind::LeaveRequest),
            ) = kind
            {
                // Verified and bound to this conversation, these move only the cursor: a leave
                // request is signed by a current leaf, the others by a participant device.
                let (verified, request_digest) = if kind == SignedMutationKind::LeaveRequest {
                    let key = self.participant_leaf_key(
                        cid,
                        signed_req,
                        &flat_auth_keys,
                        canonical_dev_id,
                        signer,
                    )?;
                    chat_wire::verify_signed_mutation_body_and_digest(signed_req, kind, &key)?
                } else {
                    let key = self.pds_device_key(actor_did, actor_dev, &auth_keys_by_did)?;
                    let verified =
                        chat_wire::verify_signed_mutation_body_and_digest(signed_req, kind, &key)?;
                    self.require_participant(
                        canonical_dev_id,
                        signer,
                        cid,
                        &convo.sequencer_did,
                        actor_did,
                        None,
                        entry_seq,
                        earlier,
                        &auth_keys_by_did,
                    )?;
                    verified
                };
                self.verify_control_entry_receipt(
                    &convo.sequencer_did,
                    cid,
                    entry,
                    entry_seq,
                    &verified,
                    &request_digest,
                )?;
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
                    if kind == SignedMutationKind::ResetRequest
                        && actor_did == self.normalized_did
                        && actor_dev == canonical_dev_id
                    {
                        tx.put_account_meta(
                            &chat_wire::verified_reset_request_key(cid),
                            &verified.to_string(),
                            now_ms,
                        )?;
                    }
                    if let Some(mut c) = tx.get_conversation(cid)? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    Ok(())
                })?;
                pass.max_seq = pass.max_seq.max(entry_seq);
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
                let (verified_body, request_digest) = if is_own_echo {
                    chat_wire::verify_own_commit_body_and_digest(signed_req, signer.public())?
                } else {
                    let key = self.participant_leaf_key(
                        cid,
                        signed_req,
                        &flat_auth_keys,
                        canonical_dev_id,
                        signer,
                    )?;
                    chat_wire::verify_signed_mutation_body_and_digest(signed_req, kind, &key)?
                };
                self.verify_control_entry_receipt(
                    &convo.sequencer_did,
                    cid,
                    entry,
                    entry_seq,
                    &verified_body,
                    &request_digest,
                )?;
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
                    let epoch_before_commit = c.epoch;
                    // This sync merges the Commit: a peer's, or an own one from its journal.
                    let mut merged = false;
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
                                merged = true;
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
                        let mut metadata_carry = None;
                        if !retain_loser {
                            let processed = group
                                .process_message_with_lifetime_policy(
                                    &provider,
                                    proto,
                                    LeafNodeLifetimePolicy::VerifyAt(
                                        (now_ms.max(0) as u64) / 1_000,
                                    ),
                                )
                                .map_err(|e| {
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
                            if !removed_self {
                                metadata_carry = snap_opt
                                    .map(|_| {
                                        self.metadata_snapshot_plaintext_for_carry_forward(
                                            tx,
                                            cid,
                                            &c.group_id,
                                            &mut group,
                                            &provider,
                                        )
                                    })
                                    .transpose()?;
                            }
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
                            merged = true;
                        }
                        if merged && !removed_self {
                            if let (Some(snap), Some(carry)) = (snap_opt, metadata_carry) {
                                let (m_epoch, m_ver, meta) = self
                                    .decrypt_verified_metadata_carry_for_epoch(
                                        carry,
                                        snap,
                                        &mut group,
                                        &provider,
                                    )?;
                                super::archive_policy::accept_snapshot(
                                    tx,
                                    cid,
                                    entry_seq,
                                    &meta,
                                    super::archive_policy::SnapshotPolicyAuthority::ExactCarry,
                                    now_ms,
                                )?;
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
                        // The Commit moved the coordinate: it consumed or superseded any
                        // leaf-recovery authorization, and ends the invitations of the
                        // participants it removes. Its verified manifest's participant effects
                        // reach the verified roster where this sync merges it.
                        tx.delete_account_meta(&chat_wire::leaf_recovery_authorization_key(cid))?;
                        for did in chat_wire::removed_participants(kind, body) {
                            tx.put_account_meta(
                                &chat_wire::invitation_closed_key(cid, &did),
                                &entry_seq.to_string(),
                                now_ms,
                            )?;
                        }
                        if merged {
                            apply_verified_roster_effects(tx, cid, kind, body, now_ms)?;
                        }
                    }
                    if c.epoch > epoch_before_commit && !removed_self {
                        // This device applied the Commit itself: counters of the leaves that
                        // stay remain comparable across it.
                        let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                        let provider = self.hooks.openmls_provider(storage);
                        if let Some(group) =
                            MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        {
                            super::send_counter::advance_send_counter_epoch_chain(
                                tx,
                                cid,
                                c.generation,
                                epoch_before_commit,
                                c.epoch,
                                &super::send_counter::group_leaf_devices(&group),
                                now_ms,
                            )?;
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
                    pass.was_kicked = true;
                }
                pass.max_seq = pass.max_seq.max(entry_seq);
                pass.applied = pass.applied.saturating_add(1);
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
                let outer_sender = verified_application_body.as_ref().and_then(|verified| {
                    Some((
                        verified["actorDid"].as_str()?,
                        verified["actorDeviceId"].as_str()?,
                    ))
                });
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
                    // A verified signed body always names its counter; only a pruned entry,
                    // whose body is gone, completes without one.
                    let send_counter = body.get("sendCounter").and_then(Value::as_u64);
                    if verified_application_body.is_some() && send_counter.is_none() {
                        return Err(MLSError::Cryptography(
                            "applicationSendBody missing sendCounter".into(),
                        ));
                    }
                    self.finish_received_archive_evidence(
                        cid,
                        msg_id,
                        entry_seq,
                        entry_id,
                        receipt,
                        outer_sender,
                        send_counter,
                        canonical_dev_id,
                    )?;
                    pass.max_seq = pass.max_seq.max(entry_seq);
                    pass.applied = pass.applied.saturating_add(1);
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
                        let pruned = chat_wire::verify_pruned_application_receipt(
                            rcpt_val,
                            &rcpt_sec1,
                            &c.sequencer_did,
                            cid,
                            &c.group_id,
                            expected_rcpt_entry_id,
                            entry_seq,
                        )?;
                        if pruned.generation != c.generation {
                            return Err(MLSError::Cryptography(
                                "I13: pruned receipt generation mismatch".into(),
                            ));
                        }
                        let own_device = pruned.sender_did == self.normalized_did
                            && pruned.sender_device_id == canonical_dev_id;
                        if tx.get_message(msg_id)?.is_none() {
                            // Pruned before this device ever held it: keep the signed receipt as
                            // durable evidence and show a neutral placeholder at its seq.
                            let evidence = chat_wire::UnavailableEntryEvidence {
                                version: 1,
                                conversation_id: cid.to_owned(),
                                message_id: msg_id.to_owned(),
                                entry_id: expected_rcpt_entry_id.to_owned(),
                                seq: entry_seq,
                                generation: pruned.generation,
                                epoch: pruned.epoch,
                                sender_did: pruned.sender_did.clone(),
                                sender_device_id: pruned.sender_device_id.clone(),
                                reason: chat_wire::PAYLOAD_PRUNED_REASON.to_owned(),
                                receipt: rcpt_val.clone(),
                                recorded_at_ms: now_ms,
                            };
                            tx.insert_message(&evidence.placeholder_row(&c.group_id, own_device)?)?;
                            tx.put_labyrinth_state(
                                &chat_wire::unavailable_message_key(cid, msg_id),
                                &serde_json::to_vec(&evidence)?,
                                now_ms,
                            )?;
                        }
                        if !own_device {
                            // Its counter is unknowable here: count the entry so the sender's
                            // next counter is still compared exactly, without inventing one.
                            super::send_counter::record_peer_send_counter(
                                tx,
                                cid,
                                pruned.generation,
                                pruned.epoch,
                                &pruned.sender_did,
                                &pruned.sender_device_id,
                                None,
                                entry_seq,
                                now_ms,
                            )?;
                        }
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)
                    })?;
                    pass.max_seq = pass.max_seq.max(entry_seq);
                    pass.applied = pass.applied.saturating_add(1);
                    continue;
                }

                let current = self
                    .db
                    .read_tx(|tx| tx.get_conversation(cid))?
                    .ok_or_else(|| MLSError::group_not_found(cid))?;
                let peer_counter = if entry_seq > current.last_seq {
                    self.verify_application_prior_or_flag_fork(cid, entry_seq, body, || {
                        let leaf_key = self.participant_leaf_key(
                            cid,
                            signed_req,
                            &flat_auth_keys,
                            canonical_dev_id,
                            signer,
                        )?;
                        let aad =
                            canonical_application_aad_bytes(body.get("aad").ok_or_else(|| {
                                MLSError::Cryptography(
                                    "signed application body missing MLS AAD".into(),
                                )
                            })?)
                            .map_err(|error| {
                                MLSError::Cryptography(format!(
                                    "invalid signed application AAD: {error}"
                                ))
                            })?;
                        let (commitment, attestation) =
                            verify_application_aad_archive_evidence(&aad, cid, msg_id)?;
                        let sender_did = body["actorDid"].as_str().ok_or_else(|| {
                            MLSError::Cryptography("applicationSendBody missing actorDid".into())
                        })?;
                        let sender_device_id = body["actorDeviceId"].as_str().ok_or_else(|| {
                            MLSError::Cryptography(
                                "applicationSendBody missing actorDeviceId".into(),
                            )
                        })?;
                        if attestation.sender_did != sender_did
                            || attestation.sender_device_id != sender_device_id
                            || attestation.sender_transport_public_key.as_slice()
                                != leaf_key.as_slice()
                        {
                            return Err(MLSError::Cryptography(
                                "fork evidence sender is not the signed current leaf".into(),
                            ));
                        }
                        let epoch = body["prior"]["epoch"]
                            .as_i64()
                            .and_then(|epoch| u64::try_from(epoch).ok())
                            .ok_or_else(|| {
                                MLSError::Cryptography(
                                    "applicationSendBody prior epoch is invalid".into(),
                                )
                            })?;
                        let rcpt_sec1 = receipt_key()?;
                        let (receipt_seq, receipt_generation, _) =
                            chat_wire::parse_and_verify_i13_sequencer_receipt(
                                rcpt_val,
                                &rcpt_sec1,
                                &current.sequencer_did,
                                cid,
                                &current.group_id,
                                epoch,
                                expected_rcpt_entry_id,
                                msg_id,
                                &commitment,
                                Some(&attestation),
                            )?;
                        if i64::try_from(receipt_seq).ok() != Some(entry_seq) {
                            return Err(MLSError::Cryptography(format!(
                                "I13: receipt seq {receipt_seq} != entry seq {entry_seq}"
                            )));
                        }
                        if receipt_generation != current.generation.max(0) as u64 {
                            return Err(MLSError::Cryptography(
                                "I13: receipt generation mismatch".into(),
                            ));
                        }
                        Ok(())
                    })?;
                    let sender_did = body["actorDid"].as_str().unwrap_or_default();
                    let sender_device_id = body["actorDeviceId"].as_str().unwrap_or_default();
                    if sender_did == self.normalized_did && sender_device_id == canonical_dev_id {
                        None
                    } else {
                        let send_counter = body["sendCounter"].as_u64().ok_or_else(|| {
                            MLSError::Cryptography("applicationSendBody missing sendCounter".into())
                        })?;
                        let generation = body["prior"]["generation"].as_i64().ok_or_else(|| {
                            MLSError::Cryptography(
                                "applicationSendBody prior missing generation".into(),
                            )
                        })?;
                        let epoch = body["prior"]["epoch"].as_i64().ok_or_else(|| {
                            MLSError::Cryptography("applicationSendBody prior missing epoch".into())
                        })?;
                        self.db.read_tx(|tx| {
                            super::send_counter::check_peer_send_counter(
                                tx,
                                cid,
                                generation,
                                epoch,
                                sender_did,
                                sender_device_id,
                                send_counter,
                            )
                        })?;
                        Some((
                            generation,
                            epoch,
                            sender_did.to_owned(),
                            sender_device_id.to_owned(),
                            send_counter,
                        ))
                    }
                } else {
                    None
                };

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
                    pass.max_seq = pass.max_seq.max(entry_seq);
                    pass.applied = pass.applied.saturating_add(1);
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
                    if let Some((generation, epoch, sender_did, sender_device_id, send_counter)) =
                        &peer_counter
                    {
                        super::send_counter::record_peer_send_counter(
                            tx,
                            cid,
                            *generation,
                            *epoch,
                            sender_did,
                            sender_device_id,
                            Some(*send_counter),
                            entry_seq,
                            now_ms,
                        )?;
                    }
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
                    let eligible_for_gap = current_epoch
                        && entry_seq > c.last_seq
                        && tx.get_message(msg_id)?.is_none();
                    let processed = group.process_message(&provider, proto).map_err(|e| {
                        if eligible_for_gap {
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
                    if crate::client::deletion_authority::suppress_local_frame(
                        tx,
                        cid,
                        sender_did,
                        sender_dev_id,
                        entry_seq,
                        rcpt_val["issuedAtMs"].as_i64(),
                    )? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        return tx.upsert_conversation(&c);
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
                    super::archive_policy::observe_frame(tx, &archive)?;
                    tx.put_labyrinth_state(
                        &format!("push.verified_receipt:{cid}:{msg_id}"),
                        b"1",
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
                            send_counter: peer_counter
                                .as_ref()
                                .map(|(_, _, _, _, send_counter)| *send_counter),
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
                    pass.max_seq = pass.max_seq.max(entry_seq);
                    pass.applied = pass.applied.saturating_add(1);
                    continue;
                }
                decrypt_result?;

                self.notify_change(PlatformChangeEvent::MessagesUpdated {
                    conversation_id: cid.to_string(),
                });
                pass.max_seq = pass.max_seq.max(entry_seq);
                pass.applied = pass.applied.saturating_add(1);
                continue;
            }

            return Err(MLSError::Cryptography(format!(
                "unexpected conversation entry kind {kind:?}"
            )));
        }

        Ok(())
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
            let metadata_carry = self
                .metadata_snapshot_plaintext_for_carry_forward(
                    tx,
                    cid,
                    &convo.group_id,
                    &mut old_group,
                    &provider,
                )?;

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
            let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                metadata_carry,
                &mut group,
                &provider,
                &convo.group_id,
                &convo_uuid,
                prior_gen,
                next_epoch,
                &next_gch,
                &next_ctag,
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
    use super::{
        apply_verified_roster_effects, clear_roster_baseline, record_account_deletion, store_roster,
    };
    use crate::chat_v2::transcript::SignedMutationKind;
    use crate::client::chat_wire;
    use crate::storage::{LabyrinthQueueRow, MessageRow, MlsAccountDb, OpenMode};
    use serde_json::json;

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

    #[test]
    fn replacing_roster_baseline_clears_stale_admission_markers() {
        const CID: &str = "baseline-replacement";
        const ALICE: &str = "did:plc:alice";
        const BOB: &str = "did:plc:bob";
        let dir = tempfile::tempdir().unwrap();
        let db = MlsAccountDb::open_native(dir.path().join("roster.db"), &[8; 32], OpenMode::App)
            .unwrap();
        db.write_tx(|tx| {
            store_roster(
                tx,
                CID,
                &json!({
                    "did:plc:alice": {"role": "admin", "status": "active"},
                    "did:plc:bob": {"role": "member", "status": "active"},
                }),
                1,
            )?;
            store_roster(
                tx,
                CID,
                &json!({"did:plc:alice": {"role": "admin", "status": "active"}}),
                2,
            )
        })
        .unwrap();
        db.read_tx(|tx| {
            assert!(tx
                .get_account_meta(&chat_wire::verified_participant_admission_key(CID, ALICE))?
                .is_some());
            assert!(tx
                .get_account_meta(&chat_wire::verified_participant_admission_key(CID, BOB))?
                .is_none());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn clearing_roster_baseline_clears_admission_markers() {
        const CID: &str = "baseline-cleared";
        const ALICE: &str = "did:plc:alice";
        let dir = tempfile::tempdir().unwrap();
        let db = MlsAccountDb::open_native(dir.path().join("clear.db"), &[7; 32], OpenMode::App)
            .unwrap();
        db.write_tx(|tx| {
            store_roster(
                tx,
                CID,
                &json!({"did:plc:alice": {"role": "admin", "status": "active"}}),
                1,
            )?;
            clear_roster_baseline(tx, CID)
        })
        .unwrap();
        db.read_tx(|tx| {
            assert!(tx
                .get_account_meta(&chat_wire::conversation_roster_key(CID))?
                .is_none());
            assert!(tx
                .get_account_meta(&chat_wire::verified_participant_admission_key(CID, ALICE))?
                .is_none());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn verified_removal_clears_participant_admission_marker() {
        const CID: &str = "participant-removal";
        const ALICE: &str = "did:plc:alice";
        const BOB: &str = "did:plc:bob";
        let dir = tempfile::tempdir().unwrap();
        let db = MlsAccountDb::open_native(dir.path().join("removal.db"), &[9; 32], OpenMode::App)
            .unwrap();
        db.write_tx(|tx| {
            store_roster(
                tx,
                CID,
                &json!({
                    "did:plc:alice": {"role": "admin", "status": "active"},
                    "did:plc:bob": {"role": "member", "status": "active"},
                }),
                1,
            )?;
            apply_verified_roster_effects(
                tx,
                CID,
                SignedMutationKind::PolicyTransition,
                &json!({"participantChanges": [{
                    "$type": "blue.catbird.chat.defs#removeParticipant",
                    "userDid": BOB,
                }]}),
                2,
            )
        })
        .unwrap();
        db.read_tx(|tx| {
            let roster = tx
                .get_account_meta(&chat_wire::conversation_roster_key(CID))?
                .unwrap();
            let roster: serde_json::Value = serde_json::from_str(&roster)?;
            assert!(roster.get(BOB).is_none());
            assert!(tx
                .get_account_meta(&chat_wire::verified_participant_admission_key(CID, BOB))?
                .is_none());
            Ok(())
        })
        .unwrap();
    }
}

#[cfg(test)]
#[path = "live_sync_unit_tests.rs"]
mod live_sync_unit_tests;
