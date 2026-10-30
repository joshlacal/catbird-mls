//! What background Labyrinth work could not do, kept so the platform can
//! show it (labyrinth review 2). Nothing here is ever dropped silently:
//!
//! - **Excluded members.** A conversation member whose epoch failed a
//!   trust check ([CB-18], [CB-28], [CB-29]) gets no MEK for the messages
//!   archived while it is excluded, so it cannot read them from history.
//!   `needs_repin` marks a pin conflict ([CB-29]): the peer reset its
//!   mailbox (or someone is replaying an old one). The user resolves it
//!   with `labyrinth_propose_repin` / `labyrinth_repin_peer`, like a
//!   Signal safety-number change.
//! - **Dropped rows.** Queued messages that left the queue unarchived, with
//!   the reason: the conversation is gone, or the queue was full.
//! - **Quarantined rows** live in the queue itself
//!   ([`super::queue::PendingArchive::quarantined`]).
//! - **A pending remote deletion.** Account deletion erased this device's
//!   state, but mls-ds `deleteAccountData` (or the PDS retract) failed; it
//!   is retried before Labyrinth can be enabled again.
//!
//! Stored per account as one JSON value in the encrypted MLS database
//! (request-value namespace [`STATUS_NAMESPACE`]).

use serde::{Deserialize, Serialize};

/// Request-value namespace of the per-account status.
pub const STATUS_NAMESPACE: &str = "labyrinthArchiveStatus";

/// Most entries kept per list; the oldest go first.
pub const MAX_REPORTS: usize = 100;

/// A member left out of a conversation's MEK distribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberExclusion {
    pub conversation_id: String,
    pub did: String,
    /// The crate error, as text.
    pub reason: String,
    /// A [CB-29] pin conflict: resolve with a user-confirmed re-pin.
    pub needs_repin: bool,
    pub at_ms: u64,
}

/// A queued message that left the queue without being archived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DroppedArchive {
    pub conversation_id: String,
    pub message_id: String,
    pub reason: String,
    pub at_ms: u64,
}

/// Account deletion finished locally; the remote half is still to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDeletion {
    pub attempts: u32,
    pub last_error: String,
    pub since_ms: u64,
    /// Captured before erasing local state. An unavailable Space must not
    /// turn a partial deletion into a reported success on another platform.
    #[serde(default)]
    pub mailbox_placement: Option<String>,
    /// Owner ciphertext cleanup targets retained after local pin erasure.
    #[serde(default)]
    pub conversation_spaces: Vec<String>,
    /// Discovery on the owner PDS is still required even if this device
    /// never opened the conversations written by another account device.
    #[serde(default)]
    pub space_cleanup_required: bool,
}

/// One account's status.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveStatus {
    #[serde(default)]
    pub excluded_members: Vec<MemberExclusion>,
    #[serde(default)]
    pub dropped: Vec<DroppedArchive>,
    #[serde(default)]
    pub pending_remote_deletion: Option<PendingDeletion>,
}

fn trim<T>(v: &mut Vec<T>) {
    if v.len() > MAX_REPORTS {
        v.drain(..v.len() - MAX_REPORTS);
    }
}

impl ArchiveStatus {
    /// Records (or refreshes) that `did` is excluded in `conversation_id`.
    pub fn exclude(&mut self, x: MemberExclusion) {
        self.excluded_members
            .retain(|e| !(e.conversation_id == x.conversation_id && e.did == x.did));
        self.excluded_members.push(x);
        trim(&mut self.excluded_members);
    }

    /// `did` was addressed again in `conversation_id`: its exclusion there
    /// is over. Returns whether one was recorded.
    pub fn readmit(&mut self, conversation_id: &str, did: &str) -> bool {
        let before = self.excluded_members.len();
        self.excluded_members
            .retain(|e| !(e.conversation_id == conversation_id && e.did == did));
        before != self.excluded_members.len()
    }

    pub fn drop_row(&mut self, d: DroppedArchive) {
        self.dropped.push(d);
        trim(&mut self.dropped);
    }

    /// DIDs with a pin conflict in any conversation.
    pub fn needs_repin(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .excluded_members
            .iter()
            .filter(|e| e.needs_repin)
            .map(|e| e.did.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Milliseconds since the Unix epoch, now.
pub(crate) fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x(c: &str, d: &str, repin: bool) -> MemberExclusion {
        MemberExclusion {
            conversation_id: c.into(),
            did: d.into(),
            reason: "r".into(),
            needs_repin: repin,
            at_ms: 1,
        }
    }

    #[test]
    fn exclusions_are_per_conversation_and_bounded() {
        let mut s = ArchiveStatus::default();
        s.exclude(x("c1", "did:b", true));
        s.exclude(x("c1", "did:b", true));
        s.exclude(x("c2", "did:b", false));
        assert_eq!(s.excluded_members.len(), 2);
        assert_eq!(s.needs_repin(), ["did:b"]);
        assert!(s.readmit("c1", "did:b"));
        assert!(!s.readmit("c1", "did:b"));
        assert!(s.needs_repin().is_empty());
        for n in 0..(MAX_REPORTS + 5) {
            s.exclude(x(&format!("c{n}"), "did:z", false));
        }
        assert_eq!(s.excluded_members.len(), MAX_REPORTS);
        assert_eq!(
            s.excluded_members.last().unwrap().conversation_id,
            format!("c{}", MAX_REPORTS + 4)
        );
    }
}
