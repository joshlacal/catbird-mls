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

/// Returns `true` iff `ciphertext` fits within the `I12` 2,200-byte inline push ceiling.
pub fn should_inline_push_ciphertext(ciphertext: &[u8]) -> bool {
    ciphertext.len() <= INLINE_CIPHERTEXT_MAX_BYTES
}

#[cfg(not(target_arch = "wasm32"))]
pub use processor::{
    process_push_notification, AuthorizedPeerDeviceKey, FetchedMetadataSnapshot, FetchedPushEntry,
    NotificationPreview, PushFetchBundle, PushFetchTransport, PushKeystore, PushWakePayload,
};
