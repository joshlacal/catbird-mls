//! `C33` direct requests (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` KeyPackages with
//! `not_after >= 35 days`, plus automatic Space archival of `first_message_id` once the sender
//! observes `consent == 'accepted'`).

#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;

#[cfg(not(target_arch = "wasm32"))]
use crate::storage::{MessageRow, MlsAccountDb};
use crate::MLSError;

/// Minimum lifetime in seconds for a `direct-request` KeyPackage (`35 days`, `Spec §6.5`).
pub const DIRECT_REQUEST_KP_MIN_LIFETIME_SECS: u64 = 35 * 86_400;

/// Maximum lifetime in seconds for a `recovery` KeyPackage (`30 days`, `Spec §6.5`).
pub const RECOVERY_KP_MAX_LIFETIME_SECS: u64 = 30 * 86_400;

/// Maximum lifetime in seconds for a `direct-request` KeyPackage (`45 days + 1h`, `mls-ds` bound).
pub const DIRECT_REQUEST_KP_MAX_LIFETIME_SECS: u64 = 45 * 86_400 + 3_600;

/// Validate that a `direct-request` KeyPackage satisfies `not_after - not_before >= 35 days`
/// (and does not exceed the server's `45d + 1h` ceiling).
pub fn validate_direct_request_key_package_lifetime(
    not_before_sec: u64,
    not_after_sec: u64,
) -> Result<(), MLSError> {
    if not_after_sec <= not_before_sec {
        return Err(MLSError::invalid_input(
            "KeyPackage not_after must be strictly greater than not_before",
        ));
    }
    let span = not_after_sec - not_before_sec;
    if span < DIRECT_REQUEST_KP_MIN_LIFETIME_SECS {
        return Err(MLSError::invalid_input(format!(
            "C33 direct-request KeyPackage lifetime ({span}s) is shorter than minimum 35 days ({DIRECT_REQUEST_KP_MIN_LIFETIME_SECS}s)"
        )));
    }
    if span > DIRECT_REQUEST_KP_MAX_LIFETIME_SECS {
        return Err(MLSError::invalid_input(format!(
            "C33 direct-request KeyPackage lifetime ({span}s) exceeds maximum 45d+1h ({DIRECT_REQUEST_KP_MAX_LIFETIME_SECS}s)"
        )));
    }
    Ok(())
}

/// Validate that a `recovery` KeyPackage satisfies `not_after - not_before <= 30 days + 1h`.
pub fn validate_recovery_key_package_lifetime(
    not_before_sec: u64,
    not_after_sec: u64,
) -> Result<(), MLSError> {
    if not_after_sec <= not_before_sec {
        return Err(MLSError::invalid_input(
            "KeyPackage not_after must be strictly greater than not_before",
        ));
    }
    let span = not_after_sec - not_before_sec;
    if span > RECOVERY_KP_MAX_LIFETIME_SECS + 3_600 {
        return Err(MLSError::invalid_input(format!(
            "recovery KeyPackage lifetime ({span}s) exceeds 30d+1h ceiling"
        )));
    }
    Ok(())
}

/// Scan accepted `C33` direct requests whose opening message (`first_message_id`) has not yet
/// been archived to the conversation's ATProto Space, invoke `archive_to_space` for each, and
/// durably mark `first_message_archived = true` in `<did_hash>.db` (`Spec §6.5`).
#[cfg(not(target_arch = "wasm32"))]
pub async fn archive_accepted_opening_messages<ArchiveFn, ArchiveFut>(
    db: &MlsAccountDb,
    mut archive_to_space: ArchiveFn,
) -> Result<usize, MLSError>
where
    ArchiveFn: FnMut(String, MessageRow) -> ArchiveFut,
    ArchiveFut: Future<Output = Result<(), MLSError>>,
{
    let candidates: Vec<(String, String, MessageRow, i64)> = db.read_tx(|rx| {
        let accepted = rx.list_requests(Some("accepted"))?;
        let mut out = Vec::new();
        for req in accepted {
            if req.first_message_archived {
                continue;
            }
            if let Some(first_msg_id) = req.first_message_id.as_deref() {
                if let Some(msg) = rx.get_message(first_msg_id)? {
                    out.push((
                        req.request_id.clone(),
                        req.conversation_id.clone(),
                        msg,
                        req.updated_at_ms.saturating_add(1),
                    ));
                }
            }
        }
        Ok(out)
    })?;

    let mut archived_count = 0usize;
    for (request_id, conversation_id, message, next_updated_ms) in candidates {
        archive_to_space(conversation_id, message).await?;
        db.write_tx(|tx| tx.mark_request_first_message_archived(&request_id, next_updated_ms))?;
        archived_count += 1;
    }

    Ok(archived_count)
}
