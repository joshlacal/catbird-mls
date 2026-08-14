//! Ordered unified append-log pull for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §9: conversation seq is globally contiguous across
//! application and control entries, but `getEntries.afterSeq` is only a scan
//! position for one authenticated device. The server returns that device's
//! application entries plus separately entitled control entries, skips
//! inaccessible gaps, and never reveals gap content. `nextAfterSeq` equals the
//! input when the returned array is empty and otherwise the greatest returned
//! seq; `hasMore` is true exactly when another caller-visible entry exists
//! above it.
//!
//! Realtime is a hint and nothing more. There is deliberately no path in this
//! module by which an event can advance a cursor or contribute an entry: an
//! event may only cause a pull to be scheduled, and the pull is what is
//! authoritative. That is the one v1 policy worth carrying forward — v1's
//! realtime handlers were already persist-only, with external commits confined
//! to deferred recovery — and here it is structural rather than conventional.
//!
//! The server's `nextAfterSeq` is verified against the returned entries rather
//! than trusted. An unchecked advance value lets a server move a client past
//! entries it is entitled to, which would silently lose messages.
//!
//! # The advance rule is strict equality, and why
//!
//! `blue.catbird.chat.getEntries` states it verbatim:
//!
//! > The server skips inaccessible gaps and never returns their entries.
//! > `nextAfterSeq` is `afterSeq` when entries is empty, otherwise the greatest
//! > returned seq; `hasMore` is true exactly when another caller-visible
//! > application or separately entitled control entry has seq greater than
//! > `nextAfterSeq`.
//!
//! Per-device visibility gaps do **not** loosen this into `nextAfterSeq >=
//! max(returned)`. A gap is skipped by the *entries* — a page may legitimately
//! return seq 5 then seq 900 — and the cursor lands on the greatest entry that
//! was actually delivered. Nothing needs to advance past an invisible row,
//! because an invisible row is never a thing the cursor must step over; it is
//! simply never returned.
//!
//! Relaxing to `>=` would give up the only property this check buys. A server
//! could return seq 5 and set `nextAfterSeq` to 100000, and the client would
//! resume above every entitled entry in between and never learn it had lost
//! them. Equality is what makes that unrepresentable.
//!
//! # Recorded for the mls-ds lane
//!
//! `getEntries` is **not implemented** server-side. On `mls-ds` main the chat
//! router registers all 32 routes but only device lifecycle, Reset, G6,
//! Welcome, and Recovery have real handlers; the rest, including this one, sit
//! on the shared cutover-gated stub. So the reading above is recorded here to
//! be implemented against rather than diverged from.
//!
//! One genuine gap in the frozen contract, surfaced rather than papered over:
//! it gives a server no way to say "I scanned a large inaccessible region,
//! found nothing visible, and have not reached the end". Empty forces
//! `nextAfterSeq == afterSeq`, and `hasMore` is defined by whether a visible
//! entry exists above rather than by how far the server looked — so a device
//! resuming beneath a very large gap implies an unbounded scan. That needs a
//! contract answer before `getEntries` is built, not a client-side workaround:
//! accepting a bare `>=` here would trade a real security property for it.

use super::cursor::AfterSeq;
use super::endpoint_error::EndpointError;
use super::ids::seq::{IntegerError, Seq};
use super::ids::ConversationId;
use core::fmt;

/// The protocol caps every transport array at 100 elements.
pub const MAX_PAGE_LIMIT: u16 = 100;
/// The generated `getEntries.limit` default.
pub const DEFAULT_PAGE_LIMIT: u16 = 100;

/// An entry as returned by the unified append log.
///
/// Only the two fields the pull layer needs are exposed. Everything else about
/// an entry — its shape, signature, transcript, and fingerprint — is the
/// verification layer's business, and this module deliberately cannot see it,
/// so it cannot be tempted to act on an unverified entry.
pub trait AppendLogEntry {
    /// The row's sequence number, exactly as received.
    fn raw_seq(&self) -> i64;
    /// The row's conversation, exactly as received.
    fn raw_conversation_id(&self) -> &str;
}

/// Why an append-log page or pull was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendLogError {
    /// An entry carried a sequence outside the positive-safe-integer range.
    InvalidSeq {
        position: usize,
        source: IntegerError,
    },
    /// An entry was at or below the requested scan position, i.e. a
    /// redelivery the client has already processed.
    EntryNotAboveScanPosition {
        position: usize,
        requested_after: AfterSeq,
        found: Seq,
    },
    /// Entries were not strictly increasing by sequence.
    NonIncreasingSeq {
        position: usize,
        previous: Seq,
        found: Seq,
    },
    /// An entry belonged to a different conversation.
    ConversationMismatch {
        position: usize,
        expected: ConversationId,
        found: String,
    },
    /// The server returned more entries than the requested limit.
    LimitExceeded { limit: u16, returned: usize },
    /// The server's `nextAfterSeq` disagreed with the entries it returned.
    ///
    /// Trusting it would let a server advance the client past entries it is
    /// entitled to receive.
    NextAfterSeqMismatch { expected: i64, server_sent: i64 },
    /// An empty page claimed more entries exist above the unchanged position.
    ///
    /// The two rules together — `nextAfterSeq` equals the input when empty, and
    /// `hasMore` is true exactly when a caller-visible entry exists above it —
    /// make this self-contradictory. It is also a liveness trap: a client that
    /// honours it re-requests the same position forever.
    EmptyPageClaimsMore { requested_after: AfterSeq },
    /// A page advanced nothing yet asked to be followed.
    NonAdvancingPage { stuck_at: AfterSeq },
    /// The pull exceeded its page budget without draining the log.
    PageBudgetExhausted { budget: usize, stopped_at: AfterSeq },
    /// The endpoint returned a typed error.
    Endpoint(EndpointError),
    /// The sink refused to persist a page.
    Sink(String),
}

impl fmt::Display for AppendLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeq { position, source } => {
                write!(f, "entry {position} has an invalid seq: {source}")
            }
            Self::EntryNotAboveScanPosition {
                position,
                requested_after,
                found,
            } => write!(
                f,
                "entry {position} has seq {found}, at or below the requested afterSeq {requested_after}"
            ),
            Self::NonIncreasingSeq {
                position,
                previous,
                found,
            } => write!(
                f,
                "entry {position} has seq {found} after {previous}; entries must strictly increase"
            ),
            Self::ConversationMismatch {
                position,
                expected,
                found,
            } => write!(
                f,
                "entry {position} belongs to conversation {found}, expected {expected}"
            ),
            Self::LimitExceeded { limit, returned } => {
                write!(f, "server returned {returned} entries for a limit of {limit}")
            }
            Self::NextAfterSeqMismatch {
                expected,
                server_sent,
            } => write!(
                f,
                "server sent nextAfterSeq {server_sent}; the returned entries require {expected}"
            ),
            Self::EmptyPageClaimsMore { requested_after } => write!(
                f,
                "empty page at afterSeq {requested_after} claims hasMore, which cannot advance"
            ),
            Self::NonAdvancingPage { stuck_at } => {
                write!(f, "page did not advance past afterSeq {stuck_at}")
            }
            Self::PageBudgetExhausted { budget, stopped_at } => write!(
                f,
                "pull exhausted its {budget}-page budget at afterSeq {stopped_at}"
            ),
            Self::Endpoint(err) => write!(f, "{err}"),
            Self::Sink(detail) => write!(f, "sink refused the page: {detail}"),
        }
    }
}

impl core::error::Error for AppendLogError {}

impl From<EndpointError> for AppendLogError {
    fn from(err: EndpointError) -> Self {
        Self::Endpoint(err)
    }
}

/// A page exactly as the server sent it, before validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEntryPage<E> {
    /// Entries in server order.
    pub entries: Vec<E>,
    /// The server's claimed next scan position.
    pub next_after_seq: i64,
    /// The server's claim that more caller-visible entries exist above it.
    pub has_more: bool,
}

/// A page whose ordering, conversation binding, and advance value have all been
/// checked against the protocol's stated rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPage<E> {
    entries: Vec<E>,
    next_after_seq: AfterSeq,
    has_more: bool,
}

impl<E: AppendLogEntry> EntryPage<E> {
    /// Validates a raw server page against the request that produced it.
    pub fn validate(
        conversation_id: ConversationId,
        requested_after: AfterSeq,
        limit: u16,
        raw: RawEntryPage<E>,
    ) -> Result<Self, AppendLogError> {
        if raw.entries.len() > usize::from(limit) {
            return Err(AppendLogError::LimitExceeded {
                limit,
                returned: raw.entries.len(),
            });
        }

        let expected_conversation = conversation_id.to_string();
        let mut previous: Option<Seq> = None;

        for (position, entry) in raw.entries.iter().enumerate() {
            if entry.raw_conversation_id() != expected_conversation {
                return Err(AppendLogError::ConversationMismatch {
                    position,
                    expected: conversation_id,
                    found: entry.raw_conversation_id().to_owned(),
                });
            }

            let seq = Seq::new(entry.raw_seq())
                .map_err(|source| AppendLogError::InvalidSeq { position, source })?;

            if !requested_after.admits(seq) {
                return Err(AppendLogError::EntryNotAboveScanPosition {
                    position,
                    requested_after,
                    found: seq,
                });
            }

            if let Some(previous) = previous {
                if !seq.is_strictly_after(previous) {
                    return Err(AppendLogError::NonIncreasingSeq {
                        position,
                        previous,
                        found: seq,
                    });
                }
            }
            previous = Some(seq);
        }

        // The advance rule: unchanged when empty, otherwise the greatest
        // returned seq. Entries are strictly increasing by the loop above, so
        // the greatest is the last.
        let expected_next = match previous {
            Some(greatest) => greatest.get(),
            None => requested_after.get(),
        };
        if raw.next_after_seq != expected_next {
            return Err(AppendLogError::NextAfterSeqMismatch {
                expected: expected_next,
                server_sent: raw.next_after_seq,
            });
        }

        if raw.entries.is_empty() && raw.has_more {
            return Err(AppendLogError::EmptyPageClaimsMore { requested_after });
        }

        Ok(Self {
            // `expected_next` came from a validated Seq or from an existing
            // AfterSeq, so it is within range by construction.
            next_after_seq: AfterSeq::new(expected_next)
                .expect("advance value derives from an already-validated position"),
            entries: raw.entries,
            has_more: raw.has_more,
        })
    }

    /// The validated entries, in ascending sequence order.
    pub fn entries(&self) -> &[E] {
        &self.entries
    }

    /// Consumes the page and yields its entries.
    pub fn into_entries(self) -> Vec<E> {
        self.entries
    }

    /// The scan position to persist once every entry effect is durable.
    pub fn next_after_seq(&self) -> AfterSeq {
        self.next_after_seq
    }

    /// Whether the server reports further caller-visible entries above.
    pub fn has_more(&self) -> bool {
        self.has_more
    }

    /// Whether following this page would move the scan position.
    pub fn advances(&self, from: AfterSeq) -> bool {
        self.next_after_seq.get() > from.get()
    }
}

/// Why an ordered pull stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullStop {
    /// The server reported no further caller-visible entries.
    Drained,
    /// The page budget was reached with entries still outstanding.
    BudgetExhausted,
}

/// The outcome of one ordered pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullReport {
    /// Pages fetched and applied.
    pub pages: usize,
    /// Entries delivered to the sink.
    pub entries: usize,
    /// The scan position after the last successfully applied page.
    pub after_seq: AfterSeq,
    /// Why the pull stopped.
    pub stop: PullStop,
}

/// Thread-safety bound that relaxes on wasm32.
///
/// The web target is single-threaded and its futures are `?Send`, so requiring
/// `Send + Sync` there would make the traits below unimplementable. This is the
/// same conditional-bound shape the v1 platform traits use, and it is the
/// reason the WASM client can consume these traits without a parallel facade.
/// It is blanket-implemented, so implementors never name it.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MaybeSend for T {}

/// Thread-safety bound that relaxes on wasm32. See the non-wasm definition.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// Fetches pages of the unified append log.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AppendLogSource<E>: MaybeSend {
    /// Issues one `getEntries` call.
    async fn fetch_entries(
        &self,
        conversation_id: ConversationId,
        after: AfterSeq,
        limit: u16,
    ) -> Result<RawEntryPage<E>, EndpointError>;
}

/// Consumes validated pages.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait EntryPageSink<E>: MaybeSend {
    /// Persists every effect of `entries` **and** the new scan position in one
    /// atomic unit.
    ///
    /// CHAT_PROTOCOL.md §6 and §9 both require this: state, content,
    /// rejections, ratchet effects, and `afterSeq` persist together. A sink
    /// that commits entry effects and the cursor separately can lose entries
    /// on a crash between the two, or reprocess them, and MLS ratchet state
    /// does not tolerate either. Implementations must use a single
    /// transaction; the driver cannot enforce this for them.
    async fn apply_page(
        &self,
        conversation_id: ConversationId,
        entries: &[E],
        advance_to: AfterSeq,
    ) -> Result<(), String>;
}

/// Pulls a conversation's append log in order from `from`, applying each page
/// before requesting the next.
///
/// Pages are never fetched ahead: each is applied — and therefore durable —
/// before the next request goes out, so a crash resumes from the last
/// persisted position rather than losing a window.
pub async fn pull_conversation<E, S, K>(
    source: &S,
    sink: &K,
    conversation_id: ConversationId,
    from: AfterSeq,
    limit: u16,
    page_budget: usize,
) -> Result<PullReport, AppendLogError>
where
    E: AppendLogEntry,
    S: AppendLogSource<E> + ?Sized,
    K: EntryPageSink<E> + ?Sized,
{
    let limit = limit.clamp(1, MAX_PAGE_LIMIT);
    let mut position = from;
    let mut pages = 0usize;
    let mut entries = 0usize;

    while pages < page_budget {
        let raw = source
            .fetch_entries(conversation_id, position, limit)
            .await?;
        let page = EntryPage::validate(conversation_id, position, limit, raw)?;

        // A page that neither advances nor drains would spin forever. Empty
        // pages claiming `hasMore` are already rejected during validation; this
        // catches any other non-advancing shape before it becomes a hot loop.
        if page.has_more() && !page.advances(position) {
            return Err(AppendLogError::NonAdvancingPage { stuck_at: position });
        }

        let has_more = page.has_more();
        let advance_to = page.next_after_seq();
        let batch = page.into_entries();
        let delivered = batch.len();

        if !batch.is_empty() || advance_to != position {
            sink.apply_page(conversation_id, &batch, advance_to)
                .await
                .map_err(AppendLogError::Sink)?;
        }

        position = advance_to;
        entries += delivered;
        pages += 1;

        if !has_more {
            return Ok(PullReport {
                pages,
                entries,
                after_seq: position,
                stop: PullStop::Drained,
            });
        }
    }

    Err(AppendLogError::PageBudgetExhausted {
        budget: page_budget,
        stopped_at: position,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::endpoint_error::ChatErrorCode;
    use std::sync::Mutex;

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_CONVERSATION: &str = "22222222-2222-4222-8222-222222222222";

    fn conversation() -> ConversationId {
        ConversationId::parse(CONVERSATION).expect("fixture conversation must parse")
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEntry {
        seq: i64,
        conversation: String,
    }

    impl TestEntry {
        fn at(seq: i64) -> Self {
            Self {
                seq,
                conversation: CONVERSATION.to_owned(),
            }
        }

        fn in_other_conversation(seq: i64) -> Self {
            Self {
                seq,
                conversation: OTHER_CONVERSATION.to_owned(),
            }
        }
    }

    impl AppendLogEntry for TestEntry {
        fn raw_seq(&self) -> i64 {
            self.seq
        }
        fn raw_conversation_id(&self) -> &str {
            &self.conversation
        }
    }

    fn page(
        entries: Vec<TestEntry>,
        next_after_seq: i64,
        has_more: bool,
    ) -> RawEntryPage<TestEntry> {
        RawEntryPage {
            entries,
            next_after_seq,
            has_more,
        }
    }

    fn validate(
        requested_after: i64,
        raw: RawEntryPage<TestEntry>,
    ) -> Result<EntryPage<TestEntry>, AppendLogError> {
        EntryPage::validate(
            conversation(),
            AfterSeq::new(requested_after).unwrap(),
            MAX_PAGE_LIMIT,
            raw,
        )
    }

    // ---- page validation -------------------------------------------------

    #[test]
    fn accepts_a_well_formed_page() {
        let validated = validate(
            0,
            page(
                vec![TestEntry::at(1), TestEntry::at(2), TestEntry::at(5)],
                5,
                true,
            ),
        )
        .expect("a well-formed page must validate");

        assert_eq!(validated.entries().len(), 3);
        assert_eq!(validated.next_after_seq().get(), 5);
        assert!(validated.has_more());
        assert!(validated.advances(AfterSeq::START));
    }

    #[test]
    fn accepts_a_sequence_gap_because_gaps_are_normal() {
        // The server skips inaccessible entries, so a caller-visible page is
        // routinely non-contiguous. Requiring contiguity would break every
        // client that has ever been removed and re-added.
        let validated = validate(
            0,
            page(vec![TestEntry::at(1), TestEntry::at(900)], 900, false),
        )
        .expect("a gapped page is legitimate");
        assert_eq!(validated.next_after_seq().get(), 900);
    }

    #[test]
    fn a_visibility_gap_does_not_loosen_the_advance_rule() {
        // Gaps are handled by the entries, not by the cursor: the page above
        // steps 1 -> 900 and the cursor lands on 900, the greatest entry
        // actually delivered. An invisible row is never something the cursor
        // must step over, so relaxing to `nextAfterSeq >= max(returned)` buys
        // nothing and costs the anti-skip property. Concretely, this page
        // returns only seq 1 while claiming 900; under a `>=` rule it would be
        // accepted and 899 entitled entries would be lost silently, and it
        // would be indistinguishable from the legitimate gapped page above.
        let err = validate(0, page(vec![TestEntry::at(1)], 900, true)).unwrap_err();
        assert_eq!(
            err,
            AppendLogError::NextAfterSeqMismatch {
                expected: 1,
                server_sent: 900
            }
        );
    }

    #[test]
    fn accepts_a_drained_empty_page() {
        let validated = validate(42, page(vec![], 42, false)).expect("an empty tail is normal");
        assert!(validated.entries().is_empty());
        assert_eq!(validated.next_after_seq().get(), 42);
        assert!(!validated.has_more());
        assert!(!validated.advances(AfterSeq::new(42).unwrap()));
    }

    #[test]
    fn rejects_a_redelivered_entry() {
        let err = validate(10, page(vec![TestEntry::at(10)], 10, false)).unwrap_err();
        assert!(
            matches!(
                err,
                AppendLogError::EntryNotAboveScanPosition { position: 0, .. }
            ),
            "afterSeq is exclusive, so entry 10 was already processed: {err}"
        );
    }

    #[test]
    fn rejects_non_increasing_entries() {
        let err =
            validate(0, page(vec![TestEntry::at(3), TestEntry::at(2)], 3, false)).unwrap_err();
        assert!(matches!(
            err,
            AppendLogError::NonIncreasingSeq { position: 1, .. }
        ));
    }

    #[test]
    fn rejects_a_duplicated_seq() {
        let err =
            validate(0, page(vec![TestEntry::at(3), TestEntry::at(3)], 3, false)).unwrap_err();
        assert!(
            matches!(err, AppendLogError::NonIncreasingSeq { position: 1, .. }),
            "a repeated seq would double-apply an entry's effects"
        );
    }

    #[test]
    fn rejects_an_entry_from_another_conversation() {
        let err = validate(
            0,
            page(
                vec![TestEntry::at(1), TestEntry::in_other_conversation(2)],
                2,
                false,
            ),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AppendLogError::ConversationMismatch { position: 1, .. }
        ));
    }

    #[test]
    fn rejects_a_next_after_seq_that_skips_past_undelivered_entries() {
        // The security case. If the client trusted this, it would resume at 500
        // and permanently lose every entry between 2 and 500 that it is
        // entitled to receive.
        let err =
            validate(0, page(vec![TestEntry::at(1), TestEntry::at(2)], 500, true)).unwrap_err();
        assert_eq!(
            err,
            AppendLogError::NextAfterSeqMismatch {
                expected: 2,
                server_sent: 500
            }
        );
    }

    #[test]
    fn rejects_a_next_after_seq_that_rewinds() {
        let err = validate(0, page(vec![TestEntry::at(1), TestEntry::at(9)], 1, true)).unwrap_err();
        assert_eq!(
            err,
            AppendLogError::NextAfterSeqMismatch {
                expected: 9,
                server_sent: 1
            }
        );
    }

    #[test]
    fn rejects_an_empty_page_that_claims_more() {
        // Self-contradictory per the spec's "exactly when", and a liveness trap:
        // honouring it re-requests the same position forever.
        let err = validate(7, page(vec![], 7, true)).unwrap_err();
        assert_eq!(
            err,
            AppendLogError::EmptyPageClaimsMore {
                requested_after: AfterSeq::new(7).unwrap()
            }
        );
    }

    #[test]
    fn rejects_an_oversized_page() {
        let entries: Vec<TestEntry> = (1..=5).map(TestEntry::at).collect();
        let err = EntryPage::validate(conversation(), AfterSeq::START, 3, page(entries, 5, false))
            .unwrap_err();
        assert_eq!(
            err,
            AppendLogError::LimitExceeded {
                limit: 3,
                returned: 5
            }
        );
    }

    #[test]
    fn rejects_a_non_positive_seq() {
        let err = validate(0, page(vec![TestEntry::at(0)], 0, false)).unwrap_err();
        assert!(
            matches!(err, AppendLogError::InvalidSeq { position: 0, .. }),
            "entry sequences are positive-safe-integers: {err}"
        );
    }

    // ---- ordered pull ----------------------------------------------------

    #[derive(Debug)]
    struct ScriptedSource {
        pages: Mutex<Vec<Result<RawEntryPage<TestEntry>, EndpointError>>>,
        requests: Mutex<Vec<(i64, u16)>>,
    }

    impl ScriptedSource {
        fn new(pages: Vec<Result<RawEntryPage<TestEntry>, EndpointError>>) -> Self {
            Self {
                pages: Mutex::new(pages),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requested_positions(&self) -> Vec<i64> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|(after, _)| *after)
                .collect()
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl AppendLogSource<TestEntry> for ScriptedSource {
        async fn fetch_entries(
            &self,
            _conversation_id: ConversationId,
            after: AfterSeq,
            limit: u16,
        ) -> Result<RawEntryPage<TestEntry>, EndpointError> {
            self.requests.lock().unwrap().push((after.get(), limit));
            let mut pages = self.pages.lock().unwrap();
            assert!(
                !pages.is_empty(),
                "source was polled more times than scripted"
            );
            pages.remove(0)
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSink {
        applied: Mutex<Vec<(Vec<i64>, i64)>>,
        fail_on_call: Option<usize>,
    }

    impl RecordingSink {
        fn failing_on(call: usize) -> Self {
            Self {
                applied: Mutex::new(Vec::new()),
                fail_on_call: Some(call),
            }
        }

        fn applied(&self) -> Vec<(Vec<i64>, i64)> {
            self.applied.lock().unwrap().clone()
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl EntryPageSink<TestEntry> for RecordingSink {
        async fn apply_page(
            &self,
            _conversation_id: ConversationId,
            entries: &[TestEntry],
            advance_to: AfterSeq,
        ) -> Result<(), String> {
            let mut applied = self.applied.lock().unwrap();
            if self.fail_on_call == Some(applied.len()) {
                return Err("storage transaction rolled back".to_owned());
            }
            applied.push((
                entries.iter().map(TestEntry::raw_seq).collect(),
                advance_to.get(),
            ));
            Ok(())
        }
    }

    #[tokio::test]
    async fn drains_pages_in_order_resuming_from_each_advance() {
        let source = ScriptedSource::new(vec![
            Ok(page(vec![TestEntry::at(1), TestEntry::at(2)], 2, true)),
            Ok(page(vec![TestEntry::at(7)], 7, true)),
            Ok(page(vec![], 7, false)),
        ]);
        let sink = RecordingSink::default();

        let report = pull_conversation(&source, &sink, conversation(), AfterSeq::START, 100, 10)
            .await
            .expect("pull must drain");

        assert_eq!(report.stop, PullStop::Drained);
        assert_eq!(report.pages, 3);
        assert_eq!(report.entries, 3);
        assert_eq!(report.after_seq.get(), 7);

        // Each request resumes from the previous page's validated advance, so
        // no window is skipped and none is re-fetched.
        assert_eq!(source.requested_positions(), vec![0, 2, 7]);
        assert_eq!(sink.applied(), vec![(vec![1, 2], 2), (vec![7], 7)]);
    }

    #[tokio::test]
    async fn applies_each_page_before_fetching_the_next() {
        // Pages are never fetched ahead: a crash resumes from the last durable
        // position instead of losing an in-flight window.
        let source = ScriptedSource::new(vec![
            Ok(page(vec![TestEntry::at(1)], 1, true)),
            Ok(page(vec![TestEntry::at(2)], 2, false)),
        ]);
        let sink = RecordingSink::default();

        pull_conversation(&source, &sink, conversation(), AfterSeq::START, 100, 10)
            .await
            .unwrap();

        let applied = sink.applied();
        assert_eq!(applied.len(), 2);
        assert_eq!(
            source.requested_positions()[1],
            applied[0].1,
            "the second fetch must start from the first page's persisted advance"
        );
    }

    #[tokio::test]
    async fn a_sink_failure_stops_the_pull_without_advancing() {
        let source = ScriptedSource::new(vec![
            Ok(page(vec![TestEntry::at(1)], 1, true)),
            Ok(page(vec![TestEntry::at(2)], 2, true)),
        ]);
        let sink = RecordingSink::failing_on(1);

        let err = pull_conversation(&source, &sink, conversation(), AfterSeq::START, 100, 10)
            .await
            .unwrap_err();

        assert_eq!(
            err,
            AppendLogError::Sink("storage transaction rolled back".to_owned())
        );
        // Only the first page was persisted; the pull must not have advanced
        // past a page whose effects did not commit.
        assert_eq!(sink.applied(), vec![(vec![1], 1)]);
    }

    #[tokio::test]
    async fn surfaces_endpoint_errors_with_their_type_intact() {
        let source = ScriptedSource::new(vec![Err(EndpointError::new(
            "blue.catbird.chat.getEntries",
            ChatErrorCode::DeviceRevoked,
            None,
        ))]);
        let sink = RecordingSink::default();

        let err = pull_conversation(&source, &sink, conversation(), AfterSeq::START, 100, 10)
            .await
            .unwrap_err();

        match err {
            AppendLogError::Endpoint(endpoint) => {
                assert_eq!(endpoint.code, ChatErrorCode::DeviceRevoked);
                assert!(
                    endpoint.requires_reauthentication(),
                    "the ladder must see the typed classification, not a string"
                );
            }
            other => panic!("expected a typed endpoint error, got {other}"),
        }
        assert!(sink.applied().is_empty());
    }

    #[tokio::test]
    async fn rejects_a_page_that_would_spin_forever() {
        // A page that advances nothing yet claims more entries exist would make
        // the loop re-request the same position indefinitely.
        let source = ScriptedSource::new(vec![Ok(page(vec![], 5, true))]);
        let sink = RecordingSink::default();

        let err = pull_conversation(
            &source,
            &sink,
            conversation(),
            AfterSeq::new(5).unwrap(),
            100,
            10,
        )
        .await
        .unwrap_err();

        assert_eq!(
            err,
            AppendLogError::EmptyPageClaimsMore {
                requested_after: AfterSeq::new(5).unwrap()
            }
        );
    }

    #[tokio::test]
    async fn stops_at_the_page_budget_rather_than_pulling_unboundedly() {
        let source = ScriptedSource::new(vec![
            Ok(page(vec![TestEntry::at(1)], 1, true)),
            Ok(page(vec![TestEntry::at(2)], 2, true)),
        ]);
        let sink = RecordingSink::default();

        let err = pull_conversation(&source, &sink, conversation(), AfterSeq::START, 100, 2)
            .await
            .unwrap_err();

        assert_eq!(
            err,
            AppendLogError::PageBudgetExhausted {
                budget: 2,
                stopped_at: AfterSeq::new(2).unwrap()
            },
            "the two applied pages remain durable; only the pull stops"
        );
        assert_eq!(sink.applied().len(), 2);
    }

    #[tokio::test]
    async fn clamps_the_requested_limit_to_the_protocol_cap() {
        let source = ScriptedSource::new(vec![Ok(page(vec![], 0, false))]);
        let sink = RecordingSink::default();

        pull_conversation(&source, &sink, conversation(), AfterSeq::START, 5_000, 10)
            .await
            .unwrap();

        assert_eq!(
            source.requests.lock().unwrap()[0].1,
            MAX_PAGE_LIMIT,
            "every transport array is capped at 100"
        );
    }

    #[tokio::test]
    async fn a_drained_empty_first_page_applies_nothing() {
        let source = ScriptedSource::new(vec![Ok(page(vec![], 12, false))]);
        let sink = RecordingSink::default();

        let report = pull_conversation(
            &source,
            &sink,
            conversation(),
            AfterSeq::new(12).unwrap(),
            100,
            10,
        )
        .await
        .unwrap();

        assert_eq!(report.entries, 0);
        assert_eq!(report.after_seq.get(), 12);
        assert!(
            sink.applied().is_empty(),
            "a no-op page must not open a storage transaction"
        );
    }
}
