//! Device authority and bounded effects of sequenced account deletions.

use rusqlite::OptionalExtension;
use serde_json::Value;

use super::{chat_wire, CatbirdMlsClient};
use crate::client::deletion_authority::{
    self as authority, AppliedAccountDeletion, DeletionActorWrite, StoredAccountDeletion,
    UnverifiedAccountDeletion, UnverifiedDeletionReason,
};
use crate::client::QueuedLabyrinthArchivePayload;
use crate::error::MLSError;
use crate::storage::SqlTx;

/// What one sequenced `accountDeletedEntry` does on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AccountDeletionDecision {
    /// Device-signed and verified: purge `deleted_did`'s messages up to the signed instant.
    Apply {
        deleted_did: String,
        seq: i64,
        write: DeletionActorWrite,
    },
    /// Already applied at this seq: nothing more to do.
    AlreadyApplied,
    /// Not applied: kept as evidence and shown as an unverified deletion.
    Unverified {
        deleted_did: String,
        seq: i64,
        reason: UnverifiedDeletionReason,
        write: Option<DeletionActorWrite>,
    },
}

fn delete_state(tx: &SqlTx<'_>, key: &str) -> Result<(), MLSError> {
    tx.conn()
        .execute("DELETE FROM labyrinth_state WHERE state_key = ?1", [key])
        .map_err(|e| MLSError::Internal(format!("delete labyrinth state: {e}")))?;
    Ok(())
}

/// Every `labyrinth_state` row whose key starts with `prefix`, in key order.
pub(crate) fn list_state_prefix(
    tx: &crate::storage::SqlReadTx<'_>,
    prefix: &str,
) -> Result<Vec<(String, Vec<u8>)>, MLSError> {
    let mut statement = tx
        .conn()
        .prepare(
            "SELECT state_key, value_bytes FROM labyrinth_state \
             WHERE substr(state_key, 1, length(?1)) = ?1 ORDER BY state_key",
        )
        .map_err(|e| MLSError::Internal(format!("list labyrinth state: {e}")))?;
    let rows = statement
        .query_map([prefix], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| MLSError::Internal(format!("list labyrinth state: {e}")))?;
    rows.collect::<Result<_, _>>()
        .map_err(|e| MLSError::Internal(format!("read labyrinth state: {e}")))
}

/// A retained I13 receipt is serialized from `StoredArchivedReceipt`, whose persisted field is
/// `issued_at_ms` (the wire receipt instead uses `issuedAtMs`).
fn stored_receipt_issued_at_ms(raw: &str) -> Option<i64> {
    serde_json::from_str::<chat_wire::StoredArchivedReceipt>(raw)
        .ok()
        .map(|receipt| receipt.issued_at_ms)
}

/// Keep the authenticated issue coordinates even when a sibling device has no archive duty.
pub(crate) fn opening_receipt_key(cid: &str, message_id: &str) -> String {
    format!("c33_opening_receipt:{cid}:{message_id}")
}

fn opening_receipt(
    raw: &[u8],
    cid: &str,
    message_id: &str,
    sender: &str,
) -> Option<chat_wire::StoredArchivedReceipt> {
    let receipt: chat_wire::StoredArchivedReceipt = serde_json::from_slice(raw).ok()?;
    (receipt.conversation_id == cid
        && receipt.entry_id == message_id
        && receipt.sender_device_did_url.split_once('#')?.0 == sender)
        .then_some(receipt)
}

fn opening_covered(
    tx: &SqlTx<'_>,
    cid: &str,
    did: &str,
    mid: &str,
    staged: Option<&QueuedLabyrinthArchivePayload>,
    marker: &StoredAccountDeletion,
) -> Result<bool, MLSError> {
    let blocked = |seq, issued, device: &str| {
        marker.covers(seq, issued) || marker.self_deleted_device_post_entry(seq, device)
    };
    let from_receipt = |raw: &[u8]| {
        let receipt = opening_receipt(raw, cid, mid, did)?;
        let seq = i64::try_from(receipt.seq).ok()?;
        Some(blocked(
            seq,
            Some(receipt.issued_at_ms),
            receipt.sender_device_did_url.split_once('#')?.1,
        ))
    };
    if let Some(result) = tx
        .get_labyrinth_state(&opening_receipt_key(cid, mid))?
        .as_deref()
        .and_then(from_receipt)
    {
        return Ok(result);
    }
    let from_frame = |frame: &QueuedLabyrinthArchivePayload| {
        if frame.conversation_id != cid || frame.sender_did != did || frame.message_id != mid {
            return None;
        }
        Some(
            frame
                .sequencer_receipt_json
                .as_deref()
                .and_then(|s| from_receipt(s.as_bytes()))
                .unwrap_or_else(|| blocked(frame.seq, None, &frame.sender_device_id)),
        )
    };
    if let Some(result) = staged.and_then(from_frame) {
        return Ok(result);
    }
    let frame = |raw: &[u8]| {
        serde_json::from_slice(raw)
            .ok()
            .as_ref()
            .and_then(from_frame)
    };
    if let Some(result) = tx
        .get_labyrinth_state(&format!("native.message:{cid}:{mid}"))?
        .as_deref()
        .and_then(frame)
    {
        return Ok(result);
    }
    let queued: Option<Vec<u8>> = tx
        .conn()
        .query_row(
            "SELECT payload_bytes FROM labyrinth_queue WHERE conversation_id = ?1 AND item_id = ?2",
            rusqlite::params![cid, mid],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MLSError::Internal(format!("read queued request opening: {e}")))?;
    if let Some(result) = queued.as_deref().and_then(frame) {
        return Ok(result);
    }
    if let Some(row) = tx
        .get_message(mid)?
        .filter(|row| row.conversation_id == cid && row.sender_did == did)
    {
        // Legacy sibling imports only kept their receive time, which can follow the deletion.
        return Ok(blocked(row.seq, None, &row.sender_device_id));
    }
    // Older clients could erase all signed coordinates and leave only the preview.
    Ok(true)
}

fn scrub_request_openings(
    tx: &SqlTx<'_>,
    cid: &str,
    did: &str,
    marker: &StoredAccountDeletion,
) -> Result<(), MLSError> {
    let key = format!("c33_pending_opening:{cid}");
    let staged: Option<QueuedLabyrinthArchivePayload> = tx
        .get_account_meta(&key)?
        .and_then(|raw| serde_json::from_str(&raw).ok());
    let staged = staged
        .as_ref()
        .filter(|frame| frame.conversation_id == cid && frame.sender_did == did);
    let opening_ids: Vec<String> = {
        let mut query = tx
            .conn()
            .prepare(
                "SELECT DISTINCT first_message_id FROM requests
            WHERE conversation_id = ?1 AND sender_did = ?2 AND first_message_id IS NOT NULL",
            )
            .map_err(|e| MLSError::Internal(format!("select request openings: {e}")))?;
        let rows = query
            .query_map(rusqlite::params![cid, did], |row| row.get(0))
            .map_err(|e| MLSError::Internal(format!("select request openings: {e}")))?;
        rows.collect::<Result<_, _>>()
            .map_err(|e| MLSError::Internal(format!("read request openings: {e}")))?
    };
    let mut opening_ids: std::collections::BTreeSet<_> = opening_ids.into_iter().collect();
    if let Some(stage) = staged {
        opening_ids.insert(stage.message_id.clone());
    }
    for mid in opening_ids {
        if !opening_covered(tx, cid, did, &mid, staged, marker)? {
            continue;
        }
        tx.conn()
            .execute(
                "UPDATE requests SET payload_json = '{}' WHERE conversation_id = ?1
            AND sender_did = ?2 AND first_message_id = ?3",
                rusqlite::params![cid, did, mid],
            )
            .map_err(|e| MLSError::Internal(format!("clear request opening preview: {e}")))?;
        if staged.is_some_and(|stage| stage.message_id == mid) {
            tx.delete_account_meta(&key)?;
        }
        tx.conn().execute("DELETE FROM messages WHERE conversation_id = ?1 AND sender_did = ?2 AND message_id = ?3",
            rusqlite::params![cid, did, mid]).map_err(|e| MLSError::Internal(format!("clear request opening message: {e}")))?;
        let evidence_key = format!("native.message:{cid}:{mid}");
        if let Some(raw) = tx.get_labyrinth_state(&evidence_key)? {
            if serde_json::from_slice::<Value>(&raw)
                .ok()
                .is_some_and(|evidence| {
                    evidence["sender_did"].as_str() == Some(did)
                        || evidence["sequencer_receipt_json"]
                            .as_str()
                            .and_then(|receipt| opening_receipt(receipt.as_bytes(), cid, &mid, did))
                            .is_some()
                })
            {
                delete_state(tx, &evidence_key)?;
            }
        }
        tx.conn()
            .execute(
                "DELETE FROM labyrinth_queue WHERE conversation_id = ?1 AND item_id = ?2
            AND json_extract(CAST(payload_bytes AS TEXT), '$.sender_did') = ?3",
                rusqlite::params![cid, mid, did],
            )
            .map_err(|e| MLSError::Internal(format!("clear queued request opening: {e}")))?;
    }
    Ok(())
}

pub(crate) fn reapply_opening_deletion(
    tx: &SqlTx<'_>,
    cid: &str,
    did: &str,
) -> Result<(), MLSError> {
    if let Some(raw) = tx.get_labyrinth_state(&chat_wire::account_deletion_key(cid, did))? {
        let marker = AppliedAccountDeletion::decode(&raw)
            .ok_or_else(|| MLSError::InvalidState("UnreadableAccountDeletionMarker".into()))?;
        scrub_request_openings(tx, cid, did, &marker)?;
    }
    Ok(())
}

/// Repair persisted previews on first open after upgrade even if the sync cursor already advanced.
pub(crate) fn migrate_opening_deletions(tx: &SqlTx<'_>, now_ms: i64) -> Result<(), MLSError> {
    const MIGRATION: &str = "c33_opening_erasure_v1";
    if tx.get_account_meta(MIGRATION)?.is_some() {
        return Ok(());
    }
    const PREFIX: &str = "native.account_deleted:";
    for (key, raw) in list_state_prefix(tx, PREFIX)? {
        if let Some((cid, did)) = key[PREFIX.len()..].split_once(":did:") {
            let marker = AppliedAccountDeletion::decode(&raw)
                .ok_or_else(|| MLSError::InvalidState("UnreadableAccountDeletionMarker".into()))?;
            scrub_request_openings(tx, cid, &format!("did:{did}"), &marker)?;
        }
    }
    tx.put_account_meta(MIGRATION, "1", now_ms)
}

/// Issue time of a stored message: its sequencer receipt when this device holds one, else the
/// local receive time.
fn message_issued_at_ms(
    tx: &SqlTx<'_>,
    cid: &str,
    message_id: &str,
    created_at_ms: i64,
) -> Result<i64, MLSError> {
    let native = tx
        .get_labyrinth_state(&format!("native.message:{cid}:{message_id}"))?
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|evidence| {
            evidence["sequencer_receipt_json"]
                .as_str()
                .and_then(stored_receipt_issued_at_ms)
                .or_else(|| evidence["nse_verified_issued_at_ms"].as_i64())
        });
    let unavailable = tx
        .get_labyrinth_state(&chat_wire::unavailable_message_key(cid, message_id))?
        .and_then(|raw| serde_json::from_slice::<chat_wire::UnavailableEntryEvidence>(&raw).ok())
        .and_then(|evidence| evidence.receipt["issuedAtMs"].as_i64());
    let issued = native.or(unavailable);
    Ok(issued.unwrap_or(created_at_ms))
}

/// Remove `deleted_did`'s local messages and queued archive copies in `cid` that the deletion
/// covers: sequenced before it and issued no later than its device-signed instant (plus skew).
pub(crate) fn purge_covered_messages(
    tx: &SqlTx<'_>,
    cid: &str,
    deleted_did: &str,
    marker: &StoredAccountDeletion,
) -> Result<usize, MLSError> {
    scrub_request_openings(tx, cid, deleted_did, marker)?;
    let rows: Vec<(String, i64, i64)> = {
        let mut statement = tx
            .conn()
            .prepare(
                "SELECT message_id, seq, created_at_ms FROM messages \
                 WHERE conversation_id = ?1 AND sender_did = ?2",
            )
            .map_err(|e| MLSError::Internal(format!("select deleted sender messages: {e}")))?;
        let mapped = statement
            .query_map(rusqlite::params![cid, deleted_did], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| MLSError::Internal(format!("select deleted sender messages: {e}")))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| MLSError::Internal(format!("read deleted sender messages: {e}")))?
    };
    let mut purged = 0;
    for (message_id, seq, created_at_ms) in rows {
        let issued = message_issued_at_ms(tx, cid, &message_id, created_at_ms)?;
        if marker.covers(seq, Some(issued)) {
            purged += tx
                .conn()
                .execute(
                    "DELETE FROM messages WHERE message_id = ?1 AND conversation_id = ?2",
                    rusqlite::params![message_id, cid],
                )
                .map_err(|e| MLSError::Internal(format!("purge deleted sender message: {e}")))?;
            tx.delete_pending_op(
                crate::push::processor::NATIVE_ARCHIVE_RECEIPT_OP,
                &message_id,
            )?;
            delete_state(tx, &chat_wire::unavailable_message_key(cid, &message_id))?;
            // The retained native archive evidence carries the same canonical plaintext frame.
            // A verified deletion must erase it with the display row, not leave a restorable copy.
            delete_state(tx, &format!("native.message:{cid}:{message_id}"))?;
        }
    }
    // A restore or local cleanup can remove a display row while retaining its authenticated
    // archive frame. Scan that evidence independently so a later applied deletion cannot leave
    // an orphan plaintext copy behind.
    let native_prefix = format!("native.message:{cid}:");
    let native_rows: Vec<(String, Vec<u8>)> = {
        let mut statement = tx
            .conn()
            .prepare(
                "SELECT state_key, value_bytes FROM labyrinth_state \
                 WHERE substr(state_key, 1, length(?1)) = ?1 ORDER BY state_key",
            )
            .map_err(|e| MLSError::Internal(format!("select archived message evidence: {e}")))?;
        let mapped = statement
            .query_map([&native_prefix], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| MLSError::Internal(format!("select archived message evidence: {e}")))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| MLSError::Internal(format!("read archived message evidence: {e}")))?
    };
    for (key, raw) in native_rows {
        let receipt = serde_json::from_slice::<Value>(&raw)
            .ok()
            .and_then(|evidence| {
                evidence["sequencer_receipt_json"].as_str().and_then(|raw| {
                    serde_json::from_str::<chat_wire::StoredArchivedReceipt>(raw).ok()
                })
            });
        let Some(receipt) = receipt else { continue };
        if receipt
            .sender_device_did_url
            .split_once('#')
            .is_some_and(|(did, _)| did == deleted_did)
            && marker.covers(
                i64::try_from(receipt.seq).unwrap_or(i64::MAX),
                Some(receipt.issued_at_ms),
            )
        {
            delete_state(tx, &key)?;
        }
    }
    let queued: Vec<(String, i64, Vec<u8>)> = {
        let mut statement = tx
            .conn()
            .prepare(
                "SELECT item_id, seq, payload_bytes FROM labyrinth_queue WHERE conversation_id = ?1 \
                 AND json_extract(CAST(payload_bytes AS TEXT), '$.sender_did') = ?2",
            )
            .map_err(|e| MLSError::Internal(format!("select deleted sender queue: {e}")))?;
        let mapped = statement
            .query_map(rusqlite::params![cid, deleted_did], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| MLSError::Internal(format!("select deleted sender queue: {e}")))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| MLSError::Internal(format!("read deleted sender queue: {e}")))?
    };
    for (item_id, seq, payload) in queued {
        let payload: Value = serde_json::from_slice(&payload).unwrap_or(Value::Null);
        let issued = payload["sequencer_receipt_json"]
            .as_str()
            .and_then(stored_receipt_issued_at_ms)
            .or(payload["created_at_ms"].as_i64());
        if marker.covers(seq, issued) {
            tx.dequeue_labyrinth_item(&item_id)?;
        }
    }
    Ok(purged)
}

impl CatbirdMlsClient {
    /// Ed25519 keys this device holds for `(did, device_id)`: its leaf in `cid`, then its leaf
    /// in any other local conversation.
    fn local_device_keys(&self, cid: &str, did: &str, device_id: &str) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        let mut push = |leaves: Vec<(String, String, Vec<u8>)>| {
            for (leaf_did, leaf_device, key) in leaves {
                if leaf_did == did && leaf_device == device_id && !keys.contains(&key) {
                    keys.push(key);
                }
            }
        };
        if let Ok(leaves) = self.current_leaves(cid) {
            push(leaves);
        }
        let others = crate::client::all_local_conversation_ids(&self.db).unwrap_or_default();
        for other in others {
            if other != cid {
                if let Ok(leaves) = self.current_leaves(&other) {
                    push(leaves);
                }
            }
        }
        keys
    }

    /// A retired signing key cannot authenticate a newly encountered historical
    /// record by itself. Ask today's repository to attest to the same bytes.
    #[cfg(feature = "labyrinth")]
    fn reanchor_deletion_record(
        &self,
        historical: &[u8],
        document: &[u8],
        did: &str,
        collection: &str,
        rkey: &str,
    ) -> Option<Vec<u8>> {
        let pds = chat_wire::extract_pds_endpoint_from_did_doc(document, did)?;
        let key = atproto_spaces::did_resolver::DidDocument::parse_json(did, document)
            .ok()?
            .atproto_key?;
        let current = self
            .fetch_pds_record_car(&pds, did, collection, rkey)
            .ok()?;
        let rev = crate::labyrinth::repo_proof::verify_reanchored_record(
            historical, &current, did, collection, rkey, &key,
        )
        .ok()?;
        crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
            &self.db,
            did,
            &rev,
            self.hooks.now_ms(),
        )
        .ok()?;
        Some(current)
    }

    /// The device key `keyProof` proves, verified under `did`'s DID document. `Err` only when
    /// the DID document cannot be fetched now (retryable).
    fn key_proof_device_key(
        &self,
        entry: &Value,
        did: &str,
        device_id: &str,
        signed_at_ms: i64,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        let Some(proof) = authority::key_proof_bytes(entry) else {
            return Ok(None);
        };
        let Some(document) = self.resolve_did_document(did)? else {
            return Ok(None);
        };
        let verify = |car: &[u8]| {
            authority::device_key_from_key_proof(car, did, device_id, signed_at_ms, &document)
        };
        let key = verify(&proof);
        #[cfg(feature = "labyrinth")]
        let key = key.or_else(|| {
            self.reanchor_deletion_record(
                &proof,
                &document,
                did,
                authority::DEVICE_RECORD_COLLECTION,
                device_id,
            )
            .and_then(|current| verify(&current))
        });
        Ok(key)
    }

    /// Decide what a sequenced `accountDeletedEntry` does here: verify the sequencer's
    /// signature for this conversation, then the deleting device's own signed request under a
    /// key of that device, then that this signed request was not already applied at another
    /// seq of this conversation. A new deletion remains unverified until signed historical
    /// non-revocation evidence is available.
    pub(crate) fn authorize_account_deletion(
        &self,
        cid: &str,
        sequencer_did: &str,
        entry: &Value,
    ) -> Result<AccountDeletionDecision, MLSError> {
        let Some((deleted_did, seq)) =
            self.verify_account_deleted_entry(cid, sequencer_did, entry)?
        else {
            // A deletion the sequencer signed for the conversation it names, served here under
            // another conversation, is kept as evidence; any other is not this sequencer's.
            let named = entry["conversationId"].as_str().unwrap_or_default();
            let elsewhere = !named.is_empty()
                && named != cid
                && matches!(
                    self.verify_account_deleted_entry(named, sequencer_did, entry),
                    Ok(Some(_))
                );
            return Ok(AccountDeletionDecision::Unverified {
                deleted_did: entry["deletedDid"].as_str().unwrap_or_default().to_owned(),
                seq: entry["seq"].as_i64().unwrap_or_default(),
                reason: if elsewhere {
                    UnverifiedDeletionReason::OtherConversation
                } else {
                    UnverifiedDeletionReason::SequencerUnverified
                },
                write: authority::parse_actor_write(entry).ok(),
            });
        };
        let unverified = |reason, write: Option<&DeletionActorWrite>| {
            Ok(AccountDeletionDecision::Unverified {
                deleted_did: deleted_did.clone(),
                seq,
                reason,
                write: write.cloned(),
            })
        };
        let write = match authority::parse_actor_write(entry) {
            Ok(write) => write,
            Err(reason) => return unverified(reason, None),
        };
        let sequenced_at = authority::sequenced_at_ms(entry).unwrap_or(i64::MIN);
        if !authority::signed_before_sequenced(&write, sequenced_at) {
            return unverified(UnverifiedDeletionReason::SignedAfterSequenced, Some(&write));
        }
        let mut keys = self.local_device_keys(cid, &deleted_did, &write.actor_device_id);
        let mut verified_key = keys.iter().find_map(|key| {
            if authority::actor_write_signature_valid(&write, key) {
                <[u8; 32]>::try_from(key.as_slice()).ok()
            } else {
                None
            }
        });
        if verified_key.is_none() {
            match self.key_proof_device_key(
                entry,
                &deleted_did,
                &write.actor_device_id,
                write.signed_at_ms,
            ) {
                Ok(Some(key)) => {
                    if authority::actor_write_signature_valid(&write, &key) {
                        verified_key = <[u8; 32]>::try_from(key.as_slice()).ok();
                    }
                    keys.push(key);
                }
                Ok(None) => {}
                // A sequencer-verified deletion cannot be treated as permanently unverified
                // merely because the deleting DID is temporarily unreachable. Let live sync
                // retry at the same entry and abort archive restore before importing copies.
                Err(error) => return Err(error),
            }
        }
        let Some(verified_key) = verified_key else {
            let reason = if keys.is_empty() {
                UnverifiedDeletionReason::DeviceKeyUnavailable
            } else {
                UnverifiedDeletionReason::BadSignature
            };
            return unverified(reason, Some(&write));
        };
        let (revoked_at, self_op) = self.db.read_tx(|tx| {
            let revoked_at = tx
                .get_account_meta(&authority::verified_device_revocation_key(
                    &deleted_did,
                    &write.actor_device_id,
                ))?
                .and_then(|raw| raw.parse::<i64>().ok());
            let self_op =
                tx.get_account_meta(&authority::verified_device_revocation_self_op_key(
                    &deleted_did,
                    &write.actor_device_id,
                ))?;
            Ok((revoked_at, self_op))
        })?;
        if self_op.as_deref() != Some(write.operation_id.as_str())
            && authority::revoked_at_signed_instant(revoked_at, write.signed_at_ms)
        {
            return unverified(
                UnverifiedDeletionReason::DeviceRevokedAtSignedAt,
                Some(&write),
            );
        }
        let existing = self
            .db
            .read_tx(|tx| {
                tx.get_labyrinth_state(&chat_wire::account_deletion_key(cid, &deleted_did))
            })?
            .map(|raw| {
                AppliedAccountDeletion::decode(&raw)
                    .ok_or_else(|| MLSError::InvalidState("UnreadableAccountDeletionMarker".into()))
            })
            .transpose()?;
        if let Some(previous) = existing
            .as_ref()
            .and_then(|marker| marker.operation(&write.operation_id))
        {
            if previous.seq != seq {
                return unverified(UnverifiedDeletionReason::Replayed, Some(&write));
            }
            if previous.signed_at_ms == write.signed_at_ms
                && previous.actor_device_id.as_deref() == Some(write.actor_device_id.as_str())
            {
                return Ok(AccountDeletionDecision::AlreadyApplied);
            }
        }
        let rev_proof = match authority::revocation_proof_bytes(entry) {
            Ok(Some(proof)) => proof,
            Ok(None) => {
                return unverified(
                    UnverifiedDeletionReason::RevocationStatusUnproven,
                    Some(&write),
                )
            }
            Err(reason) => return unverified(reason, Some(&write)),
        };
        let Some(document) = self.resolve_did_document(&deleted_did)? else {
            return unverified(
                UnverifiedDeletionReason::RevocationStatusUnproven,
                Some(&write),
            );
        };
        let verify = |car: &[u8]| {
            authority::verify_self_deletion_revocation_proof(
                car,
                &deleted_did,
                &write,
                &verified_key,
                &document,
            )
        };
        let verified = verify(&rev_proof);
        #[cfg(feature = "labyrinth")]
        let verified = verified.or_else(|reason| {
            self.reanchor_deletion_record(
                &rev_proof,
                &document,
                &deleted_did,
                authority::DEVICE_REVOCATION_COLLECTION,
                &write.actor_device_id,
            )
            .map_or(Err(reason), |current| verify(&current))
        });
        match verified {
            Ok(()) => Ok(AccountDeletionDecision::Apply {
                deleted_did,
                seq,
                write,
            }),
            Err(reason) => unverified(reason, Some(&write)),
        }
    }

    /// Carry out a decision. An applied deletion records its marker and operation and purges
    /// what it covers in one transaction; an unverified one only records evidence.
    pub(crate) fn apply_account_deletion_decision(
        &self,
        cid: &str,
        entry: &Value,
        decision: &AccountDeletionDecision,
    ) -> Result<(), MLSError> {
        let now_ms = self.hooks.now_ms();
        match decision {
            AccountDeletionDecision::Apply {
                deleted_did,
                seq,
                write,
            } => {
                let applied = AppliedAccountDeletion {
                    seq: *seq,
                    signed_at_ms: write.signed_at_ms,
                    operation_id: write.operation_id.clone(),
                    actor_device_id: Some(write.actor_device_id.clone()),
                };
                self.db.write_tx(|tx| {
                    // Recheck the operation inside the transaction. Independent
                    // erasures retain independent sequence and signed-time bounds.
                    let marker_key = chat_wire::account_deletion_key(cid, deleted_did);
                    let op_key =
                        authority::deletion_operation_key(cid, deleted_did, &write.operation_id);
                    let existing = tx
                        .get_labyrinth_state(&marker_key)?
                        .map(|raw| {
                            AppliedAccountDeletion::decode(&raw).ok_or_else(|| {
                                MLSError::InvalidState("UnreadableAccountDeletionMarker".into())
                            })
                        })
                        .transpose()?;
                    let previous_seq = tx.get_labyrinth_state(&op_key)?;
                    if previous_seq
                        .as_ref()
                        .is_some_and(|old| old != seq.to_string().as_bytes())
                    {
                        let evidence = UnverifiedAccountDeletion {
                            conversation_id: cid.to_owned(),
                            deleted_did: deleted_did.clone(),
                            seq: *seq,
                            entry_id: entry["entryId"].as_str().unwrap_or_default().to_owned(),
                            reason: UnverifiedDeletionReason::Replayed,
                            operation_id: Some(write.operation_id.clone()),
                            actor_device_id: Some(write.actor_device_id.clone()),
                            entry: entry.clone(),
                            recorded_at_ms: now_ms,
                        };
                        return tx.put_labyrinth_state(
                            &authority::unverified_deletion_key(cid, deleted_did, *seq),
                            &serde_json::to_vec(&evidence)?,
                            now_ms,
                        );
                    }
                    let merged =
                        StoredAccountDeletion::merge_verified(existing.as_ref(), applied.clone())
                            .map_err(MLSError::Cryptography)?;
                    tx.put_labyrinth_state(
                        &marker_key,
                        &merged.encode().map_err(MLSError::Internal)?,
                        now_ms,
                    )?;
                    tx.put_labyrinth_state(&op_key, seq.to_string().as_bytes(), now_ms)?;
                    let del_meta_key = authority::verified_deleted_account_key(deleted_did);
                    let del_ms = applied.signed_at_ms.max(0);
                    let earliest_del_ms = tx
                        .get_account_meta(&del_meta_key)?
                        .and_then(|raw| raw.parse::<i64>().ok())
                        .map_or(del_ms, |old| old.min(del_ms));
                    tx.put_account_meta(&del_meta_key, &earliest_del_ms.to_string(), now_ms)?;
                    delete_state(
                        tx,
                        &authority::unverified_deletion_key(cid, deleted_did, *seq),
                    )?;
                    purge_covered_messages(
                        tx,
                        cid,
                        deleted_did,
                        &StoredAccountDeletion::Signed(applied.clone()),
                    )
                    .map(|_| ())
                })?;
                self.clear_cached_groups();
                self.notify_change(super::PlatformChangeEvent::MessagesUpdated {
                    conversation_id: cid.to_owned(),
                });
                self.notify_change(super::PlatformChangeEvent::RequestsUpdated);
                Ok(())
            }
            AccountDeletionDecision::Unverified {
                deleted_did,
                seq,
                reason,
                write,
            } => {
                tracing::warn!(cid, seq, ?reason, "keeping an unverified account deletion");
                let evidence = UnverifiedAccountDeletion {
                    conversation_id: cid.to_owned(),
                    deleted_did: deleted_did.clone(),
                    seq: *seq,
                    entry_id: entry["entryId"].as_str().unwrap_or_default().to_owned(),
                    reason: *reason,
                    operation_id: write.as_ref().map(|w| w.operation_id.clone()),
                    actor_device_id: write.as_ref().map(|w| w.actor_device_id.clone()),
                    entry: entry.clone(),
                    recorded_at_ms: now_ms,
                };
                self.db.write_tx(|tx| {
                    tx.put_labyrinth_state(
                        &authority::unverified_deletion_key(cid, deleted_did, *seq),
                        &serde_json::to_vec(&evidence)?,
                        now_ms,
                    )
                })
            }
            AccountDeletionDecision::AlreadyApplied => Ok(()),
        }
    }

    /// Every unverified deletion this device kept for `cid`, in seq order.
    pub(crate) fn unverified_account_deletions(
        &self,
        cid: &str,
    ) -> Result<Vec<UnverifiedAccountDeletion>, MLSError> {
        let prefix = authority::unverified_deletion_prefix(cid);
        self.db.read_tx(|tx| {
            Ok(list_state_prefix(tx, &prefix)?
                .into_iter()
                .filter_map(|(_, raw)| serde_json::from_slice(&raw).ok())
                .collect())
        })
    }

    /// Export stored ordering and deletion evidence for a conversation as JSON. This is a
    /// diagnostic read: evidence never blocks message delivery or raises an in-app alarm.
    pub fn export_conversation_integrity_evidence_json(
        &self,
        cid: &str,
    ) -> Result<String, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let (counters, own_receipts) = self.db.read_tx(|tx| {
            Ok((
                super::super::send_counter::list_send_counter_evidence(tx, cid)?,
                super::super::send_counter::list_own_receipt_mismatches(tx, cid)?,
            ))
        })?;
        let deletions = self.unverified_account_deletions(cid)?;
        serde_json::to_string(&serde_json::json!({
            "conversationId": cid,
            "sendCounterEvidence": counters,
            "ownReceiptMismatches": own_receipts,
            "unverifiedAccountDeletions": deletions,
        }))
        .map_err(MLSError::from)
    }
}
