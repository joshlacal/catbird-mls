//! Gate 5 `.staged` -> `.space` attachment promotion BEFORE MLS `sendMessage`, and
//! `[CB-22]` `rearchive_before_leave` copying readable batches + encrypted attachment blobs
//! into the leaving member's personal mailbox Space before `clearRecords` and MLS leave.

use std::future::Future;

use labyrinth::attachment::AttachmentCiphertextMeta;
use serde::{Deserialize, Serialize};

use crate::MLSError;

/// Locally encrypted attachment staged via `com.atproto.repo.uploadBlob` awaiting
/// `blue.catbird.labyrinth.attachmentManifest` commit in the conversation Space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedAttachmentInput {
    pub rkey: String,
    pub ciphertext: Vec<u8>,
    pub mime_type_hint: Option<String>,
    pub created_at: String,
}

/// Lifecycle state of an encrypted Space attachment (`Gate 5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentUploadStage {
    Staged {
        rkey: String,
    },
    PromotedToSpace {
        rkey: String,
        blob_cid: String,
        sha256: [u8; 32],
    },
}

/// Promoted Space attachment reference ready to embed in the MLS `PrivateMessage` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedSpaceAttachment {
    pub rkey: String,
    pub blob_cid: String,
    pub sha256: [u8; 32],
    pub ciphertext_size: u64,
}

/// Outcome of `[CB-22]` `execute_leave_with_rearchive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaveRearchiveReport {
    pub conversation_id: String,
    pub messages_rearchived: usize,
    pub rearchived_blob_cids: Vec<String>,
}

/// Enforce Gate 5: every encrypted attachment MUST be promoted from `.staged` to `.space`
/// (committing `blue.catbird.labyrinth.attachmentManifest` via `com.atproto.space.applyWrites`
/// so the blob is never orphaned or `404` for recipients) **strictly before** invoking
/// `send_mls_message`. If any promotion fails, `send_mls_message` is never called.
pub async fn send_message_with_promoted_attachments<PromoteFn, PromoteFut, SendFn, SendFut, Out>(
    staged_attachments: Vec<StagedAttachmentInput>,
    mut promote_to_space: PromoteFn,
    send_mls_message: SendFn,
) -> Result<Out, MLSError>
where
    PromoteFn: FnMut(StagedAttachmentInput, AttachmentCiphertextMeta) -> PromoteFut,
    PromoteFut: Future<Output = Result<AttachmentUploadStage, MLSError>>,
    SendFn: FnOnce(Vec<PromotedSpaceAttachment>) -> SendFut,
    SendFut: Future<Output = Result<Out, MLSError>>,
{
    let mut promoted = Vec::with_capacity(staged_attachments.len());
    for att in staged_attachments {
        if att.rkey.trim().is_empty() {
            return Err(MLSError::invalid_input("attachment rkey must not be empty"));
        }
        let meta =
            AttachmentCiphertextMeta::from_ciphertext(&att.ciphertext, att.mime_type_hint.clone())
                .map_err(|e| MLSError::Internal(format!("attachment ciphertext metadata: {e}")))?;
        let ciphertext_size = meta.ciphertext_size;
        match promote_to_space(att, meta).await? {
            AttachmentUploadStage::PromotedToSpace {
                rkey,
                blob_cid,
                sha256,
            } => {
                if blob_cid.trim().is_empty() {
                    return Err(MLSError::invalid_input(
                        "promoted Space attachment blob_cid must not be empty",
                    ));
                }
                promoted.push(PromotedSpaceAttachment {
                    rkey,
                    blob_cid,
                    sha256,
                    ciphertext_size,
                });
            }
            AttachmentUploadStage::Staged { rkey } => {
                return Err(MLSError::InvalidState(format!(
                    "Gate 5 violation: attachment {rkey} remained in .staged state; refusing MLS sendMessage"
                )));
            }
        }
    }

    send_mls_message(promoted).await
}

/// Enforce `[CB-22]`: before clearing our repo inside a conversation Space or submitting an
/// MLS leave/self-remove commit, copy readable message batches and encrypted attachment blobs
/// into our personal mailbox Space (`rearchive_step`), then clear our conversation Space
/// records (`clear_records_step`), and finally submit the MLS leave (`leave_commit_step`).
pub async fn execute_leave_with_rearchive<
    RearchiveFn,
    RearchiveFut,
    ClearFn,
    ClearFut,
    LeaveFn,
    LeaveFut,
>(
    conversation_id: &str,
    rearchive_step: RearchiveFn,
    clear_records_step: ClearFn,
    leave_commit_step: LeaveFn,
) -> Result<LeaveRearchiveReport, MLSError>
where
    RearchiveFn: FnOnce(String) -> RearchiveFut,
    RearchiveFut: Future<Output = Result<(usize, Vec<String>), MLSError>>,
    ClearFn: FnOnce(String) -> ClearFut,
    ClearFut: Future<Output = Result<(), MLSError>>,
    LeaveFn: FnOnce(String) -> LeaveFut,
    LeaveFut: Future<Output = Result<(), MLSError>>,
{
    if conversation_id.trim().is_empty() {
        return Err(MLSError::invalid_input("conversation_id must not be empty"));
    }
    let cid = conversation_id.to_owned();
    let (messages_rearchived, rearchived_blob_cids) = rearchive_step(cid.clone()).await?;
    clear_records_step(cid.clone()).await?;
    leave_commit_step(cid.clone()).await?;

    Ok(LeaveRearchiveReport {
        conversation_id: cid,
        messages_rearchived,
        rearchived_blob_cids,
    })
}
