//! `1A` encrypted `GroupMetadataV1` snapshot validation (`<= 16 KiB`) and Space-backed
//! encrypted avatar pointer (`{setter_did, space_blob_cid, sym_key, sha256}`) with
//! automatic active-admin re-hosting when `setter_did` leaves (`Spec §6.5`).

use std::future::Future;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::lifecycle::MemberRole;
use crate::metadata::GroupMetadataV1;
use crate::MLSError;

/// Maximum serialized ciphertext byte length for a `chat.metadata_snapshots` blob (`16 KiB`).
pub const MAX_METADATA_SNAPSHOT_BYTES: usize = 16 * 1024;

/// Pointer inside `GroupMetadataV1` to an encrypted group avatar blob stored in
/// `setter_did`'s repo inside the conversation's ATProto Space (`1A`, zero `mls-ds` blobs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpaceAvatarPointer {
    pub setter_did: String,
    pub space_blob_cid: String,
    pub sym_key: Vec<u8>,
    pub sha256: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Result of re-hosting a group avatar blob when the previous `setter_did` leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehostedMetadataResult {
    pub next_metadata_version: u64,
    pub metadata: GroupMetadataV1,
}

/// Validate that an encrypted `GroupMetadataV1` snapshot fits within `16 KiB` (`1A`).
pub fn validate_metadata_snapshot_size(ciphertext: &[u8]) -> Result<(), MLSError> {
    if ciphertext.is_empty() {
        return Err(MLSError::invalid_input(
            "metadata snapshot ciphertext must not be empty",
        ));
    }
    if ciphertext.len() > MAX_METADATA_SNAPSHOT_BYTES {
        return Err(MLSError::invalid_input(format!(
            "metadata snapshot ciphertext ({} bytes) exceeds 16 KiB cap ({MAX_METADATA_SNAPSHOT_BYTES} bytes)",
            ciphertext.len()
        )));
    }
    Ok(())
}

/// When `departing_did` matches `current_metadata.space_avatar.setter_did` and the local
/// actor is an active `MemberRole::Admin` (`local_did != departing_did`), fetch the
/// encrypted avatar ciphertext from `departing_did`'s Space repo, verify its SHA-256,
/// upload it to `local_did`'s Space repo, and return an updated `GroupMetadataV1` at
/// `current_metadata_version + 1`.
pub async fn maybe_rehost_avatar_on_setter_leave<FetchFn, FetchFut, UploadFn, UploadFut>(
    current_metadata: &GroupMetadataV1,
    current_metadata_version: u64,
    departing_did: &str,
    local_did: &str,
    local_role: MemberRole,
    fetch_encrypted_avatar: FetchFn,
    upload_encrypted_avatar: UploadFn,
) -> Result<Option<RehostedMetadataResult>, MLSError>
where
    FetchFn: FnOnce(String, String) -> FetchFut,
    FetchFut: Future<Output = Result<Vec<u8>, MLSError>>,
    UploadFn: FnOnce(String, Vec<u8>, Option<String>) -> UploadFut,
    UploadFut: Future<Output = Result<String, MLSError>>,
{
    let Some(pointer) = current_metadata.space_avatar.as_ref() else {
        return Ok(None);
    };
    if pointer.setter_did != departing_did {
        return Ok(None);
    }
    if local_role != MemberRole::Admin || local_did == departing_did {
        return Ok(None);
    }

    let ciphertext = fetch_encrypted_avatar(
        pointer.setter_did.clone(),
        pointer.space_blob_cid.clone(),
    )
    .await?;

    let computed_sha256: [u8; 32] = Sha256::digest(&ciphertext).into();
    if pointer.sha256.as_slice() != computed_sha256.as_slice() {
        return Err(MLSError::Cryptography(
            "avatar ciphertext SHA-256 mismatch during admin re-host".into(),
        ));
    }

    let mime = pointer
        .mime_type
        .clone()
        .or_else(|| current_metadata.avatar_content_type.clone());
    let new_cid = upload_encrypted_avatar(local_did.to_owned(), ciphertext, mime.clone()).await?;
    if new_cid.trim().is_empty() {
        return Err(MLSError::invalid_input(
            "re-hosted Space avatar CID must not be empty",
        ));
    }

    let mut next_metadata = current_metadata.clone();
    next_metadata.space_avatar = Some(SpaceAvatarPointer {
        setter_did: local_did.to_owned(),
        space_blob_cid: new_cid,
        sym_key: pointer.sym_key.clone(),
        sha256: pointer.sha256.clone(),
        mime_type: mime,
    });

    Ok(Some(RehostedMetadataResult {
        next_metadata_version: current_metadata_version.saturating_add(1),
        metadata: next_metadata,
    }))
}
