//! Shared notification push processor (`Spec §6.2`, `G1`, `I4`, `I6`, `I7`, `I10`, `I11`, `I12`, `I13`).
//!
//! Designed for iOS `NotificationServiceExtension` (`<= 15 MB` peak RSS, zero Tokio worker pool)
//! and Android `FirebaseMessagingService`.

#[cfg(not(target_arch = "wasm32"))]
pub mod processor;

/// Maximum inline MLS `PrivateMessage` ciphertext bytes allowed inside a push wake (`Spec §5 I12`).
/// Larger messages and `X-Wing` `Commit`s set `fetch_required = true` so outer APNs JSON stays well under 4 KB.
pub const INLINE_CIPHERTEXT_MAX_BYTES: usize = 2200;

/// Darwin notification posted after NSE commits decrypted messages to `<did_hash>.db` (`Spec §5 I11`).
pub const DARWIN_NSE_DID_COMMIT_NOTIFICATION: &str = "blue.catbird.mls.nseDidCommit";
/// Durable pending-op kind written when the NSE cannot verify and apply a Commit/control locally.
pub(crate) const NSE_DEFERRED_CONTROL_OP: &str = "nse_deferred_control";

/// Returns `true` iff `ciphertext` fits within the `I12` 2,200-byte inline push ceiling.
pub fn should_inline_push_ciphertext(ciphertext: &[u8]) -> bool {
    ciphertext.len() <= INLINE_CIPHERTEXT_MAX_BYTES
        || crate::planted::is_planted_bug_active(crate::planted::PlantedBug::OversizedInlinePush)
}

#[cfg(not(target_arch = "wasm32"))]
pub use processor::{
    process_push_notification, process_push_notification_with_hooks, AuthorizedPeerDeviceKey,
    FetchedMetadataSnapshot, FetchedPushEntry, NotificationPreview, PushFetchBundle,
    PushFetchTransport, PushKeystore, PushWakePayload,
};
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use processor::{
    root_did_from_credential_bytes, verify_leaf_binding_i4, verify_staged_commit_i4,
};
