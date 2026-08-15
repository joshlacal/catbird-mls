//! The atomic unit of durable progress.
//!
//! CHAT_PROTOCOL.md §9 states the requirement twice, in two different sections,
//! which is a fair indication of how it is usually got wrong:
//!
//! > Clients atomically persist all returned state/content/rejection and ratchet
//! > effects before advancing to `nextAfterSeq`.
//!
//! and
//!
//! > Ratchet state, frame/rejection, and `afterSeq` persist atomically.
//!
//! # Why this is one value rather than several calls
//!
//! A storage seam offering `store_entry`, `store_ratchet`, and `set_cursor` as
//! separate operations satisfies the sentence above only if every caller
//! remembers to wrap them, and only if the wrapping is genuinely transactional
//! on every platform. Neither is checkable, and the failure is silent: a cursor
//! that advanced past entries whose writes did not land skips those entries
//! **permanently**, because `afterSeq` is exclusive and nothing will ever return
//! them again. The client is then missing messages it will never re-request, and
//! there is no error anywhere.
//!
//! So the cursor advance is not separately expressible. [`PageCommit`] carries
//! the entries, the ratchet checkpoint, and the new position as one value, and
//! [`super::ChatV2Store`] deliberately has **no cursor setter** — the only way
//! the position moves is by committing the effects that justify it.
//!
//! This is the shape used throughout this tree for the same reason:
//! `CloseProof` is all-or-none so a partial close cannot be stated,
//! `TouchingBoundary` is one object so one row cannot advance a context twice,
//! and `Containment` is one value so a caller cannot freeze half. In each case
//! the invariant is carried by what the types make impossible to say, not by
//! what a reviewer remembers to check.
//!
//! # What this module does not validate
//!
//! Page well-formedness is [`super::super::append_log`]'s, and it has already
//! run by the time a page reaches storage: whether `nextAfterSeq` equals the
//! greatest returned seq, whether entries lie above the scan position, whether
//! `hasMore` is coherent. Re-deriving any of it here would create a second
//! source of truth for rules that were ratified once.

use super::super::cursor::AfterSeq;
use super::super::ids::{EntryId, Seq};
use super::super::interval::RecipientBinding;
use super::super::provenance::OuterEntryFingerprint;

/// The MLS ratchet state accompanying a page, as opaque bytes.
///
/// Storage never interprets these. The MLS crypto layer owns the format, and
/// this type exists only so ratchet state can travel in the same atomic unit as
/// the entries it was derived from — advancing the cursor without the matching
/// ratchet state, or the reverse, leaves a client unable to process what comes
/// next.
///
/// Deliberately not `Debug`-printed in full and deliberately without a parser:
/// nothing in this crate may make a decision from these bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct RatchetCheckpoint(Vec<u8>);

impl RatchetCheckpoint {
    /// Adopts a checkpoint produced by the MLS crypto layer.
    pub fn from_crypto_layer(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The exact bytes, for durable write and for handing back unchanged.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// How many bytes the checkpoint occupies.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the checkpoint carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for RatchetCheckpoint {
    /// Prints the length only.
    ///
    /// Ratchet state is key material adjacent, and a log line is the last place
    /// it should be reconstructible from.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RatchetCheckpoint({} bytes)", self.0.len())
    }
}

/// What durably became of one append-log entry.
///
/// §4: a semantic-invalid decrypted frame "produces a durable terminal
/// rejection after MLS ratchet handling". A rejection is therefore a stored
/// outcome in its own right, not the absence of one — the ratchet has already
/// advanced past it, so a client that stored nothing would retry an entry whose
/// key material is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryOutcome {
    /// A verified frame, retained as the exact bytes that were authenticated.
    Frame {
        /// The canonical body, byte-identical to what was verified.
        canonical_body: Vec<u8>,
    },
    /// A durable terminal rejection.
    Rejection {
        /// The rejecting layer's own rendered reason, stored verbatim.
        ///
        /// **Never a policy input.** Storage does not parse it, and nothing
        /// decides anything from it; it is retained so an operator can see why
        /// an entry was refused. The classification that produced it belongs to
        /// the layer that rejected the frame.
        detail: String,
    },
}

impl EntryOutcome {
    /// Whether this entry was rejected rather than accepted.
    pub fn is_rejection(&self) -> bool {
        matches!(self, Self::Rejection { .. })
    }
}

/// One durably recorded append-log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedEntry {
    /// The entry's append sequence within its conversation.
    pub seq: Seq,
    /// The row's replay identity.
    ///
    /// Kept alongside, never in place of, the fingerprint: §9 is explicit that
    /// an append `entryId` is separate from signed provenance.
    pub entry_id: EntryId,
    /// The authenticated outer fingerprint.
    ///
    /// Constructible only by the envelope-verification layer, so an entry
    /// cannot reach storage without having been verified first.
    pub fingerprint: OuterEntryFingerprint,
    /// What became of it.
    pub outcome: EntryOutcome,
}

/// A page's entire durable effect, including the position it justifies.
///
/// Every field lands together or nothing does. There is no constructor that
/// produces a cursor advance alone, and no accessor that hands one out
/// separately for a caller to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCommit {
    binding: RecipientBinding,
    previous_after_seq: AfterSeq,
    next_after_seq: AfterSeq,
    entries: Vec<PersistedEntry>,
    ratchet: Option<RatchetCheckpoint>,
}

impl PageCommit {
    /// Assembles a page's effects and the position they justify.
    ///
    /// `previous_after_seq` is the position the page was fetched against. It is
    /// compared against the stored cursor at commit time, so two commits racing
    /// on one device cannot silently lose one another's effects — the same
    /// compare-and-set discipline the delivery service applies to a coordinate.
    ///
    /// `ratchet` is absent when the page moved no ratchet state, which is the
    /// ordinary case for a page of control entries.
    pub fn new(
        binding: RecipientBinding,
        previous_after_seq: AfterSeq,
        next_after_seq: AfterSeq,
        entries: Vec<PersistedEntry>,
        ratchet: Option<RatchetCheckpoint>,
    ) -> Self {
        Self {
            binding,
            previous_after_seq,
            next_after_seq,
            entries,
            ratchet,
        }
    }

    /// The exact device whose scan position and entries this commit moves.
    pub fn binding(&self) -> &RecipientBinding {
        &self.binding
    }

    /// The position this page was fetched against.
    pub fn previous_after_seq(&self) -> AfterSeq {
        self.previous_after_seq
    }

    /// The position this page justifies advancing to.
    ///
    /// Reading it is fine; there is simply nothing that will *store* it on its
    /// own. [`super::ChatV2Store`] has no cursor setter, so this value only ever
    /// reaches durable state through the commit that carries its entries.
    pub fn next_after_seq(&self) -> AfterSeq {
        self.next_after_seq
    }

    /// The entries this page durably records.
    pub fn entries(&self) -> &[PersistedEntry] {
        &self.entries
    }

    /// The ratchet checkpoint this page moved, if any.
    pub fn ratchet(&self) -> Option<&RatchetCheckpoint> {
        self.ratchet.as_ref()
    }

    /// Whether this commit records no entries and no ratchet movement.
    ///
    /// An empty page still commits: §9 defines `nextAfterSeq` as equal to the
    /// input when the returned array is empty, so committing one is a no-op that
    /// legitimately confirms the position rather than advancing it.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.ratchet.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId};

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const ENTRY: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";

    fn binding() -> RecipientBinding {
        RecipientBinding::new(
            ConversationId::parse(CONVERSATION).unwrap(),
            BareDid::parse(DID).unwrap(),
            DeviceId::parse(DEVICE).unwrap(),
        )
    }

    fn entry(seq_value: i64, outcome: EntryOutcome) -> PersistedEntry {
        PersistedEntry {
            seq: Seq::new(seq_value).unwrap(),
            entry_id: EntryId::parse(ENTRY).unwrap(),
            fingerprint: OuterEntryFingerprint::for_tests([0x11; 32]),
            outcome,
        }
    }

    fn frame(seq_value: i64) -> PersistedEntry {
        entry(
            seq_value,
            EntryOutcome::Frame {
                canonical_body: b"frame-bytes".to_vec(),
            },
        )
    }

    #[test]
    fn a_page_carries_its_effects_and_its_position_as_one_value() {
        let page = PageCommit::new(
            binding(),
            AfterSeq::START,
            AfterSeq::new(2).unwrap(),
            vec![frame(1), frame(2)],
            Some(RatchetCheckpoint::from_crypto_layer(vec![0xaa; 48])),
        );
        assert_eq!(page.previous_after_seq(), AfterSeq::START);
        assert_eq!(page.next_after_seq().get(), 2);
        assert_eq!(page.entries().len(), 2);
        assert_eq!(page.ratchet().unwrap().len(), 48);
        assert!(!page.is_empty());
    }

    #[test]
    fn an_empty_page_confirms_a_position_rather_than_advancing_it() {
        // §9: nextAfterSeq equals the input when the returned array is empty.
        // Committing that is a legitimate no-op, not a degenerate case to
        // refuse — refusing it would leave a caller with nothing to call.
        let position = AfterSeq::new(40).unwrap();
        let page = PageCommit::new(binding(), position, position, Vec::new(), None);
        assert!(page.is_empty());
        assert_eq!(page.previous_after_seq(), page.next_after_seq());
    }

    #[test]
    fn a_rejection_is_a_stored_outcome_not_an_absent_one() {
        // The ratchet has already advanced past a rejected frame, so storing
        // nothing would have the client retry an entry whose key material is
        // gone. A rejection therefore occupies a row like any other entry.
        let page = PageCommit::new(
            binding(),
            AfterSeq::START,
            AfterSeq::new(1).unwrap(),
            vec![entry(
                1,
                EntryOutcome::Rejection {
                    detail: "semantic-invalid frame".to_owned(),
                },
            )],
            Some(RatchetCheckpoint::from_crypto_layer(vec![0xbb; 16])),
        );
        assert_eq!(page.entries().len(), 1);
        assert!(page.entries()[0].outcome.is_rejection());
        assert!(
            !page.is_empty(),
            "a page of rejections still has durable effect"
        );
    }

    #[test]
    fn a_ratchet_checkpoint_is_opaque_and_does_not_print_its_bytes() {
        // These bytes are key-material adjacent. A Debug impl that rendered
        // them would put them in every log line that formats a page.
        let checkpoint = RatchetCheckpoint::from_crypto_layer(vec![0xde, 0xad, 0xbe, 0xef]);
        let rendered = format!("{checkpoint:?}");
        assert_eq!(rendered, "RatchetCheckpoint(4 bytes)");
        assert!(!rendered.contains("222"), "{rendered}");
        assert!(!rendered.contains("de"), "{rendered}");
        // The exact bytes are still available to the layer that must write them.
        assert_eq!(checkpoint.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn a_frame_retains_the_exact_bytes_that_were_authenticated() {
        let bytes = vec![0x00, 0xff, 0x7f, 0x80];
        let stored = frame(1);
        assert!(matches!(stored.outcome, EntryOutcome::Frame { .. }));
        let page = PageCommit::new(
            binding(),
            AfterSeq::START,
            AfterSeq::new(1).unwrap(),
            vec![entry(
                1,
                EntryOutcome::Frame {
                    canonical_body: bytes.clone(),
                },
            )],
            None,
        );
        let EntryOutcome::Frame { canonical_body } = &page.entries()[0].outcome else {
            panic!("expected a frame");
        };
        assert_eq!(canonical_body, &bytes);
    }

    #[test]
    fn the_replay_identity_and_the_fingerprint_are_both_retained() {
        // §9 keeps them separate on purpose: an append entryId is a replay
        // identity and never signed provenance. Storing one in place of the
        // other would lose the ability to tell them apart later.
        let stored = frame(7);
        assert_eq!(stored.entry_id, EntryId::parse(ENTRY).unwrap());
        assert_eq!(
            stored.fingerprint,
            OuterEntryFingerprint::for_tests([0x11; 32])
        );
    }
}
