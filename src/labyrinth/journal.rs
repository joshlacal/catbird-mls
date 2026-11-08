//! Gate 4 crash-safe `mutation_journal` roll-forward for Labyrinth epoch rotations:
//! atomically tracks `(mailboxKeys/self swapRecord CAS -> mls-ds publishEpochHead(E+1))`
//! so a process crash between the PDS Space write and the `mls-ds` head announcement
//! rolls forward cleanly on next `<did_hash>.db` open without losing CAS coherence.

use labyrinth::store::{MaybeSend, MaybeSync};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use crate::storage::{MlsAccountDb, MutationJournalRow};
use crate::MLSError;

pub const LABYRINTH_ROTATION_OP_TYPE: &str = "labyrinth_epoch_rotation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationJournalStage {
    PendingMailboxSwap,
    MailboxSwapped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationJournalPayload {
    pub did: String,
    pub epoch_seq: u64,
    pub epoch_head: [u8; 32],
    pub expected_swap_cid: Option<String>,
    pub committed_swap_cid: Option<String>,
    pub mailbox_keys_cbor: Vec<u8>,
    pub stage: RotationJournalStage,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait RotationCommitTransport: MaybeSend + MaybeSync {
    async fn swap_mailbox_keys_cas(
        &self,
        expected_swap_cid: Option<&str>,
        next_epoch_seq: u64,
        record_cbor: &[u8],
    ) -> Result<String, MLSError>;

    async fn publish_epoch_head_on_ds(
        &self,
        epoch_seq: u64,
        epoch_head: &[u8; 32],
    ) -> Result<(), MLSError>;
}

/// Replay any incomplete Gate 4 Labyrinth epoch-rotation journal entries in `<did_hash>.db`,
/// persisting intermediate `MailboxSwapped` state immediately after `swapRecord` succeeds and
/// deleting the journal entry once `mls-ds` `publishEpochHead(E+1)` acknowledges.
#[cfg(not(target_arch = "wasm32"))]
pub async fn recover_pending_labyrinth_rotations(
    db: &MlsAccountDb,
    transport: &dyn RotationCommitTransport,
) -> Result<usize, MLSError> {
    if crate::planted::is_planted_bug_active(crate::planted::PlantedBug::MutationJournalRollForward)
    {
        return Ok(0);
    }
    let pending: Vec<MutationJournalRow> = db
        .read_tx(|rx| rx.list_mutation_journal_pending())?
        .into_iter()
        .filter(|row| row.op_type == LABYRINTH_ROTATION_OP_TYPE)
        .collect();

    let mut completed = 0usize;
    for row in pending {
        let mut payload: RotationJournalPayload =
            serde_json::from_str(&row.state_json).map_err(|e| {
                MLSError::Internal(format!(
                    "Gate 4: malformed RotationJournalPayload in {}: {e}",
                    row.journal_id
                ))
            })?;

        if payload.stage == RotationJournalStage::PendingMailboxSwap {
            let committed_cid = transport
                .swap_mailbox_keys_cas(
                    payload.expected_swap_cid.as_deref(),
                    payload.epoch_seq,
                    &payload.mailbox_keys_cbor,
                )
                .await?;
            payload.stage = RotationJournalStage::MailboxSwapped;
            payload.committed_swap_cid = Some(committed_cid);
            let updated_json = serde_json::to_string(&payload).map_err(|e| {
                MLSError::Internal(format!("serialize RotationJournalPayload: {e}"))
            })?;
            let updated_row = MutationJournalRow {
                journal_id: row.journal_id.clone(),
                op_type: row.op_type.clone(),
                epoch_seq: row.epoch_seq,
                state_json: updated_json,
                status: "pending".into(),
                created_at_ms: row.created_at_ms,
                updated_at_ms: row.updated_at_ms.saturating_add(1),
            };
            db.write_tx(|tx| tx.upsert_mutation_journal(&updated_row))?;
        }

        transport
            .publish_epoch_head_on_ds(payload.epoch_seq, &payload.epoch_head)
            .await?;

        db.write_tx(|tx| tx.delete_mutation_journal(&row.journal_id))?;
        completed += 1;
    }

    Ok(completed)
}
