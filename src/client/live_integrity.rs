//! Device authority and bounded effects of sequenced account deletions.

use serde_json::Value;

use super::{chat_wire, CatbirdMlsClient};
use crate::client::deletion_authority::{
    self as authority, AppliedAccountDeletion, DeletionActorWrite, StoredAccountDeletion,
    UnverifiedAccountDeletion, UnverifiedDeletionReason,
};
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
        let others = self
            .db
            .read_tx(|tx| tx.list_conversations(None, 500))
            .unwrap_or_default();
        for other in others {
            if other.conversation_id != cid {
                if let Ok(leaves) = self.current_leaves(&other.conversation_id) {
                    push(leaves);
                }
            }
        }
        keys
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
        Ok(authority::device_key_from_key_proof(
            &proof,
            did,
            device_id,
            signed_at_ms,
            &document,
        ))
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
        let revoked_at = self
            .db
            .read_tx(|tx| {
                tx.get_account_meta(&authority::verified_device_revocation_key(
                    &deleted_did,
                    &write.actor_device_id,
                ))
            })?
            .and_then(|raw| raw.parse::<i64>().ok());
        if authority::revoked_at_signed_instant(revoked_at, write.signed_at_ms) {
            return unverified(
                UnverifiedDeletionReason::DeviceRevokedAtSignedAt,
                Some(&write),
            );
        }
        let applied_at = self.db.read_tx(|tx| {
            tx.get_labyrinth_state(&authority::deletion_operation_key(
                cid,
                &deleted_did,
                &write.operation_id,
            ))
        })?;
        match applied_at
            .as_deref()
            .and_then(|raw| std::str::from_utf8(raw).ok()?.parse::<i64>().ok())
        {
            Some(applied) if applied == seq => Ok(AccountDeletionDecision::AlreadyApplied),
            Some(_) => unverified(UnverifiedDeletionReason::Replayed, Some(&write)),
            None => {
                // The account's deletion is terminal. A new operation ID cannot replace an
                // earlier marker with a narrower signed time and resurrect archived messages.
                let existing = self
                    .db
                    .read_tx(|tx| {
                        tx.get_labyrinth_state(&chat_wire::account_deletion_key(cid, &deleted_did))
                    })?
                    .and_then(|raw| AppliedAccountDeletion::decode(&raw));
                match existing {
                    Some(marker) if marker.seq() == seq => {
                        Ok(AccountDeletionDecision::AlreadyApplied)
                    }
                    Some(_) => unverified(UnverifiedDeletionReason::Replayed, Some(&write)),
                    // When an entry omits `revocationProof`, neither a local MLS leaf nor a
                    // `chat.device` CAR proves the signer was unrevoked at the signed instant,
                    // so quarantine it. When `revocationProof` IS attached, verify the PDS
                    // self-deletion CARv1 against `deletedDid`'s `#atproto` key.
                    None => match authority::revocation_proof_bytes(entry) {
                        Ok(None) => unverified(
                            UnverifiedDeletionReason::RevocationStatusUnproven,
                            Some(&write),
                        ),
                        Err(reason) => unverified(reason, Some(&write)),
                        Ok(Some(rev_proof)) => {
                            let Some(document) = self.resolve_did_document(&deleted_did)? else {
                                return unverified(
                                    UnverifiedDeletionReason::RevocationStatusUnproven,
                                    Some(&write),
                                );
                            };
                            match authority::verify_self_deletion_revocation_proof(
                                &rev_proof,
                                &deleted_did,
                                &write,
                                &verified_key,
                                &document,
                            ) {
                                Ok(()) => Ok(AccountDeletionDecision::Apply {
                                    deleted_did,
                                    seq,
                                    write,
                                }),
                                Err(reason) => unverified(reason, Some(&write)),
                            }
                        }
                    },
                }
            }
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
                };
                self.db.write_tx(|tx| {
                    // Authorization reads happen outside this transaction. Re-check the terminal
                    // marker and operation here so two concurrent sync calls cannot each replace
                    // it with a different signed instant.
                    let marker_key = chat_wire::account_deletion_key(cid, deleted_did);
                    let op_key =
                        authority::deletion_operation_key(cid, deleted_did, &write.operation_id);
                    let existing = tx.get_labyrinth_state(&marker_key)?;
                    let prior_op = tx.get_labyrinth_state(&op_key)?;
                    if existing.is_some() || prior_op.is_some() {
                        if existing
                            .as_deref()
                            .and_then(AppliedAccountDeletion::decode)
                            .is_none_or(|marker| marker.seq() != *seq)
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
                            tx.put_labyrinth_state(
                                &authority::unverified_deletion_key(cid, deleted_did, *seq),
                                &serde_json::to_vec(&evidence)?,
                                now_ms,
                            )?;
                        }
                        return Ok(());
                    }
                    tx.put_labyrinth_state(&marker_key, &serde_json::to_vec(&applied)?, now_ms)?;
                    tx.put_labyrinth_state(&op_key, seq.to_string().as_bytes(), now_ms)?;
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
