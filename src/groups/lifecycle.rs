//! Group membership lifecycle and `D3` (`M-F01`) admin-only removal policy.

use serde::{Deserialize, Serialize};

use crate::MLSError;

/// Conversation membership role (`Spec §3.1 D3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Admin,
    Member,
}

/// Enforce `D3` (`M-F01`): only a conversation admin may remove another member.
/// Self-leave (`target_dids == [actor_did]`) is always permitted for any active member.
pub fn enforce_admin_removal_policy(
    actor_did: &str,
    actor_role: MemberRole,
    target_dids: &[String],
) -> Result<(), MLSError> {
    if actor_did.trim().is_empty() {
        return Err(MLSError::invalid_input("actor_did must not be empty"));
    }
    if target_dids.is_empty() {
        return Err(MLSError::invalid_input("target_dids must not be empty"));
    }

    let is_self_leave_only = target_dids.iter().all(|did| did == actor_did);
    if is_self_leave_only {
        return Ok(());
    }

    match actor_role {
        MemberRole::Admin => Ok(()),
        MemberRole::Member => Err(MLSError::insufficient_permissions(
            "D3/M-F01: non-admin member cannot remove another member",
        )),
    }
}
