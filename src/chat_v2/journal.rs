//! Durable journal of submitted protocol mutations.
//!
//! CHAT_PROTOCOL.md §5: idempotency identity is
//! `(endpoint NSID, authenticated principal DID, operation ID)`, and an exact
//! completed replay returns the stored result **only when both the transcript
//! digest and the signature are byte-identical**; either mismatch is an
//! idempotency conflict.
//!
//! That sentence is the whole reason this module exists, and it dictates a
//! design that is easy to get backwards.
//!
//! # The journal stores bytes, not intent
//!
//! A journal that recorded "I intended to send message X" and rebuilt the
//! request on retry would be worse than no journal at all. Rebuilding produces
//! a fresh `signedAt`, which changes the canonical transcript, which changes
//! the request digest and the signature — so the retry no longer matches the
//! stored operation and earns `IdempotencyConflict` **permanently**. The
//! operation ID can then never succeed, and the client cannot tell whether the
//! original landed.
//!
//! So [`JournalEntry`] retains the exact canonical body bytes, digest, and
//! signature, and exposes them for resubmission. There is deliberately no API
//! here that regenerates a request.
//!
//! # The body is replayed; the authentication is not
//!
//! The same section requires that a replay "remains fully authenticated and
//! still requires a fresh valid DPoP proof and unconsumed JTI". These pull in
//! opposite directions and both are mandatory:
//!
//! - the signed **body** must be byte-identical to the original, or the server
//!   reports a conflict;
//! - the **token and proof** must be freshly minted with new JTIs, or the
//!   server rejects the replay as a consumed JTI.
//!
//! Getting either backwards fails, and the two failures look nothing alike. The
//! journal therefore owns only the body half and holds no credential material.

use super::ids::{BareDid, CanonicalTimestamp, IdempotencyKey, MessageId};
use core::fmt;

/// The operation-identity component of an idempotency key.
///
/// `sendMessage` is the documented special case: its operation ID is the
/// signed `messageId` rather than an `idempotencyKey`. Modelling that as a
/// closed enum keeps the special case visible instead of hiding it behind a
/// bare string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationId {
    /// The signed `idempotencyKey` of an ordinary mutation.
    IdempotencyKey(IdempotencyKey),
    /// The signed `messageId`, which is `sendMessage`'s only idempotency
    /// identity and is unique by `(conversationId, messageId)`.
    MessageId(MessageId),
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdempotencyKey(key) => write!(f, "{key}"),
            Self::MessageId(id) => write!(f, "{id}"),
        }
    }
}

/// The exact triple the server deduplicates on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperationIdentity {
    /// The endpoint NSID.
    pub endpoint: String,
    /// The authenticated principal.
    pub actor_did: BareDid,
    /// The operation ID.
    pub operation_id: OperationId,
}

impl fmt::Display for OperationIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.endpoint, self.actor_did, self.operation_id
        )
    }
}

/// How far a journalled mutation has progressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalState {
    /// Recorded durably but not yet transmitted.
    ///
    /// A crash here is the safe case: the server has not seen the operation, so
    /// it can be sent normally.
    Prepared,
    /// Transmitted with no conclusive response.
    ///
    /// This is the state that makes the journal worth having. The operation may
    /// or may not have committed, and the only way to find out is to resubmit
    /// the identical bytes and read the stored result.
    InFlight {
        /// How many times the identical bytes have been transmitted.
        attempts: u32,
    },
    /// The server confirmed the operation. Terminal.
    Completed,
    /// The server reported that this identity already carries different bytes.
    ///
    /// Terminal, and never recoverable by retrying: some other request won the
    /// identity. A new operation ID is required.
    Conflicted,
    /// `sendMessage` only: the server durably recorded a stale tombstone.
    ///
    /// Terminal. CHAT_PROTOCOL.md §4: the ID "can never later succeed", and a
    /// fresh frame, ciphertext, and message ID are required.
    StaleTombstoned,
}

impl JournalState {
    /// Whether no further submission of these bytes can change the outcome.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Conflicted | Self::StaleTombstoned
        )
    }

    /// Whether the identical bytes should be transmitted.
    pub fn should_submit(&self) -> bool {
        matches!(self, Self::Prepared | Self::InFlight { .. })
    }
}

/// Why a journal operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// An attempt to move out of a terminal state.
    AlreadyTerminal {
        identity: OperationIdentity,
        state: JournalState,
    },
    /// An attempt to record different bytes under an identity already in use.
    ///
    /// Caught locally rather than being sent, because transmitting it would
    /// burn the identity server-side with a permanent conflict.
    IdentityReused { identity: OperationIdentity },
    /// A stale tombstone was reported for something other than `sendMessage`.
    StaleTombstoneNotApplicable { identity: OperationIdentity },
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyTerminal { identity, state } => {
                write!(f, "{identity} is already terminal ({state:?})")
            }
            Self::IdentityReused { identity } => write!(
                f,
                "{identity} already holds different bytes; reusing it would earn a permanent conflict"
            ),
            Self::StaleTombstoneNotApplicable { identity } => write!(
                f,
                "{identity} is not a sendMessage operation, so it has no stale tombstone"
            ),
        }
    }
}

impl core::error::Error for JournalError {}

/// One journalled mutation, retaining exactly what a replay needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    identity: OperationIdentity,
    request_digest: [u8; 32],
    signature: [u8; 64],
    signed_at: CanonicalTimestamp,
    canonical_body: Vec<u8>,
    state: JournalState,
}

impl JournalEntry {
    /// Records a prepared mutation before it is transmitted.
    ///
    /// `canonical_body`, `request_digest`, and `signature` must be the exact
    /// bytes that were signed. They are retained verbatim and are what a replay
    /// resends.
    pub fn prepare(
        identity: OperationIdentity,
        canonical_body: Vec<u8>,
        request_digest: [u8; 32],
        signature: [u8; 64],
        signed_at: CanonicalTimestamp,
    ) -> Self {
        Self {
            identity,
            request_digest,
            signature,
            signed_at,
            canonical_body,
            state: JournalState::Prepared,
        }
    }

    /// The idempotency triple.
    pub fn identity(&self) -> &OperationIdentity {
        &self.identity
    }

    /// The current state.
    pub fn state(&self) -> &JournalState {
        &self.state
    }

    /// The exact canonical body to resend.
    ///
    /// This is the only way to obtain a payload for retry, and it returns
    /// stored bytes. There is no counterpart that rebuilds a request, because
    /// rebuilding changes `signedAt` and therefore the digest, which converts a
    /// recoverable ambiguous outcome into a permanent conflict.
    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }

    /// The frozen request digest, i.e. SHA-256 of the signing transcript.
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// The exact 64-byte signature, compared separately from the digest.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The signed timestamp, retained so a replay can be recognized as one.
    ///
    /// A completed replay may bypass only the `signedAt` age check; it does not
    /// get a fresh `signedAt`, because that would change the transcript.
    pub fn signed_at(&self) -> &CanonicalTimestamp {
        &self.signed_at
    }

    /// Whether the identical bytes should be transmitted now.
    pub fn should_submit(&self) -> bool {
        self.state.should_submit()
    }

    /// Records that the identical bytes were transmitted without a conclusive
    /// response.
    pub fn record_transmission(&mut self) -> Result<(), JournalError> {
        match &self.state {
            JournalState::Prepared => {
                self.state = JournalState::InFlight { attempts: 1 };
                Ok(())
            }
            JournalState::InFlight { attempts } => {
                self.state = JournalState::InFlight {
                    attempts: attempts.saturating_add(1),
                };
                Ok(())
            }
            terminal => Err(JournalError::AlreadyTerminal {
                identity: self.identity.clone(),
                state: terminal.clone(),
            }),
        }
    }

    /// Records a confirmed outcome.
    pub fn record_completed(&mut self) -> Result<(), JournalError> {
        self.enter_terminal(JournalState::Completed)
    }

    /// Records that the server reported an idempotency conflict.
    pub fn record_conflict(&mut self) -> Result<(), JournalError> {
        self.enter_terminal(JournalState::Conflicted)
    }

    /// Records a `sendMessage` stale tombstone.
    ///
    /// Rejected for any other endpoint: only `sendMessage` has this outcome,
    /// and accepting it elsewhere would silently retire an operation ID that
    /// the server had not actually retired.
    pub fn record_stale_tombstone(&mut self) -> Result<(), JournalError> {
        if !matches!(self.identity.operation_id, OperationId::MessageId(_)) {
            return Err(JournalError::StaleTombstoneNotApplicable {
                identity: self.identity.clone(),
            });
        }
        self.enter_terminal(JournalState::StaleTombstoned)
    }

    fn enter_terminal(&mut self, next: JournalState) -> Result<(), JournalError> {
        if self.state.is_terminal() {
            return Err(JournalError::AlreadyTerminal {
                identity: self.identity.clone(),
                state: self.state.clone(),
            });
        }
        self.state = next;
        Ok(())
    }

    /// Whether `digest` and `signature` are the exact stored pair.
    ///
    /// Both must match. The protocol compares them separately and treats either
    /// mismatch as a conflict, so checking only the digest would accept a
    /// re-signed body.
    pub fn matches_stored_bytes(&self, digest: &[u8; 32], signature: &[u8; 64]) -> bool {
        &self.request_digest == digest && &self.signature == signature
    }
}

/// An in-memory index of journalled mutations, keyed by idempotency identity.
///
/// The uniqueness rule this enforces is not bookkeeping. Because the server
/// deduplicates on `(endpoint, DID, operation ID)` and compares the stored
/// digest and signature byte-for-byte, transmitting *different* bytes under an
/// identity that is already in use earns a permanent `IdempotencyConflict` and
/// burns that identity forever. Catching the reuse locally, before anything is
/// sent, is the difference between a recoverable local error and an operation
/// ID that can never succeed.
///
/// Durability is the platform storage layer's job; this type owns the
/// invariant, not the persistence.
#[derive(Debug, Default)]
pub struct TransitionJournal {
    entries: std::collections::HashMap<OperationIdentity, JournalEntry>,
}

impl TransitionJournal {
    /// Creates an empty journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a prepared mutation.
    ///
    /// Re-recording an identity is allowed only when the bytes are identical,
    /// which is the crash-recovery case: the entry was already durable and is
    /// being reloaded. Different bytes under the same identity are refused.
    pub fn prepare(&mut self, entry: JournalEntry) -> Result<&mut JournalEntry, JournalError> {
        let identity = entry.identity().clone();
        if let Some(existing) = self.entries.get(&identity) {
            if !existing.matches_stored_bytes(entry.request_digest(), entry.signature()) {
                return Err(JournalError::IdentityReused { identity });
            }
        }
        Ok(self.entries.entry(identity).or_insert(entry))
    }

    /// Looks up a journalled mutation.
    pub fn get(&self, identity: &OperationIdentity) -> Option<&JournalEntry> {
        self.entries.get(identity)
    }

    /// Looks up a journalled mutation for update.
    pub fn get_mut(&mut self, identity: &OperationIdentity) -> Option<&mut JournalEntry> {
        self.entries.get_mut(identity)
    }

    /// Every entry whose identical bytes still need transmitting.
    ///
    /// This is the restart path: after a crash, these are the operations whose
    /// outcome is unknown and which must be resubmitted verbatim to discover
    /// what the server recorded.
    pub fn outstanding(&self) -> impl Iterator<Item = &JournalEntry> {
        self.entries.values().filter(|entry| entry.should_submit())
    }

    /// How many mutations are journalled.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const KEY: &str = "70707070-7070-4070-b070-707070707070";
    const SIGNED_AT: &str = "2026-08-14T12:34:56.789Z";

    fn did() -> BareDid {
        BareDid::parse(DID).unwrap()
    }

    fn timestamp() -> CanonicalTimestamp {
        CanonicalTimestamp::parse(SIGNED_AT).unwrap()
    }

    fn message_identity() -> OperationIdentity {
        OperationIdentity {
            endpoint: "blue.catbird.chat.sendMessage".to_owned(),
            actor_did: did(),
            operation_id: OperationId::MessageId(MessageId::parse(KEY).unwrap()),
        }
    }

    fn transition_identity() -> OperationIdentity {
        OperationIdentity {
            endpoint: "blue.catbird.chat.submitTransition".to_owned(),
            actor_did: did(),
            operation_id: OperationId::IdempotencyKey(IdempotencyKey::parse(KEY).unwrap()),
        }
    }

    fn entry(identity: OperationIdentity) -> JournalEntry {
        JournalEntry::prepare(
            identity,
            b"canonical-body".to_vec(),
            [0xab; 32],
            [0xcd; 64],
            timestamp(),
        )
    }

    #[test]
    fn a_prepared_entry_is_submittable_and_retains_its_bytes() {
        let journalled = entry(transition_identity());
        assert_eq!(journalled.state(), &JournalState::Prepared);
        assert!(journalled.should_submit());
        assert_eq!(journalled.canonical_body(), b"canonical-body");
        assert_eq!(journalled.request_digest(), &[0xab; 32]);
        assert_eq!(journalled.signature(), &[0xcd; 64]);
    }

    #[test]
    fn a_retry_resends_the_identical_bytes() {
        // The central invariant. Every retry reads the same stored payload, so
        // the digest the server recomputes is the one it already has. There is
        // no API here that could produce different bytes.
        let mut journalled = entry(transition_identity());
        let original_body = journalled.canonical_body().to_vec();
        let original_digest = *journalled.request_digest();
        let original_signature = *journalled.signature();
        let original_signed_at = journalled.signed_at().clone();

        journalled.record_transmission().unwrap();
        journalled.record_transmission().unwrap();
        journalled.record_transmission().unwrap();

        assert_eq!(journalled.state(), &JournalState::InFlight { attempts: 3 });
        assert_eq!(journalled.canonical_body(), original_body.as_slice());
        assert_eq!(journalled.request_digest(), &original_digest);
        assert_eq!(journalled.signature(), &original_signature);
        assert_eq!(
            journalled.signed_at(),
            &original_signed_at,
            "signedAt must not be refreshed; doing so would change the transcript"
        );
    }

    #[test]
    fn matching_stored_bytes_requires_both_digest_and_signature() {
        let journalled = entry(transition_identity());
        assert!(journalled.matches_stored_bytes(&[0xab; 32], &[0xcd; 64]));
        assert!(
            !journalled.matches_stored_bytes(&[0xab; 32], &[0x00; 64]),
            "a re-signed body with the same digest must not be accepted"
        );
        assert!(!journalled.matches_stored_bytes(&[0x00; 32], &[0xcd; 64]));
    }

    #[test]
    fn in_flight_is_the_state_that_needs_resubmission() {
        let mut journalled = entry(transition_identity());
        journalled.record_transmission().unwrap();
        assert!(
            journalled.should_submit(),
            "an ambiguous outcome is resolved by resubmitting, not by giving up"
        );
    }

    #[test]
    fn terminal_states_stop_submission() {
        for mut journalled in [entry(transition_identity()), entry(transition_identity())] {
            journalled.record_transmission().unwrap();
            journalled.record_completed().unwrap();
            assert!(journalled.state().is_terminal());
            assert!(!journalled.should_submit());
        }

        let mut conflicted = entry(transition_identity());
        conflicted.record_conflict().unwrap();
        assert!(!conflicted.should_submit());
    }

    #[test]
    fn a_terminal_entry_refuses_further_transitions() {
        let mut journalled = entry(transition_identity());
        journalled.record_completed().unwrap();

        assert!(matches!(
            journalled.record_transmission(),
            Err(JournalError::AlreadyTerminal { .. })
        ));
        assert!(matches!(
            journalled.record_conflict(),
            Err(JournalError::AlreadyTerminal { .. })
        ));
        assert_eq!(
            journalled.state(),
            &JournalState::Completed,
            "a refused transition must not corrupt the recorded outcome"
        );
    }

    #[test]
    fn a_conflict_is_terminal_and_not_retryable() {
        // Some other request won this identity. Retrying cannot take it back;
        // a new operation ID is required.
        let mut journalled = entry(transition_identity());
        journalled.record_transmission().unwrap();
        journalled.record_conflict().unwrap();
        assert_eq!(journalled.state(), &JournalState::Conflicted);
        assert!(journalled.state().is_terminal());
        assert!(!journalled.should_submit());
    }

    #[test]
    fn stale_tombstones_apply_only_to_send_message() {
        let mut message = entry(message_identity());
        message.record_transmission().unwrap();
        message.record_stale_tombstone().unwrap();
        assert_eq!(message.state(), &JournalState::StaleTombstoned);
        assert!(
            !message.should_submit(),
            "the message ID can never later succeed"
        );

        // An idempotencyKey-identified mutation has no stale-tombstone outcome.
        // Accepting one would retire an operation ID the server had not.
        let mut transition = entry(transition_identity());
        assert!(matches!(
            transition.record_stale_tombstone(),
            Err(JournalError::StaleTombstoneNotApplicable { .. })
        ));
        assert_eq!(
            transition.state(),
            &JournalState::Prepared,
            "the rejected call must leave the state untouched"
        );
    }

    #[test]
    fn operation_identity_separates_the_two_id_kinds() {
        // Both wrap the same UUID here. They must not compare equal, because
        // sendMessage deduplicates on messageId while every other mutation
        // deduplicates on idempotencyKey, and they occupy different namespaces.
        let message = message_identity();
        let transition = transition_identity();
        assert_ne!(message.operation_id, transition.operation_id);
        assert_ne!(message, transition);
        assert_eq!(message.operation_id.to_string(), KEY);
        assert_eq!(transition.operation_id.to_string(), KEY);
    }

    // ---- the journal collection ----------------------------------------

    fn entry_with_bytes(identity: OperationIdentity, marker: u8) -> JournalEntry {
        JournalEntry::prepare(
            identity,
            vec![marker; 8],
            [marker; 32],
            [marker; 64],
            timestamp(),
        )
    }

    #[test]
    fn the_journal_refuses_different_bytes_under_a_used_identity() {
        // The whole point of catching this locally: transmitting it would earn
        // a permanent IdempotencyConflict and burn the operation ID forever.
        let mut journal = TransitionJournal::new();
        journal
            .prepare(entry_with_bytes(transition_identity(), 0x11))
            .expect("first record must succeed");

        let err = journal
            .prepare(entry_with_bytes(transition_identity(), 0x22))
            .unwrap_err();
        assert!(matches!(err, JournalError::IdentityReused { .. }));
        assert_eq!(journal.len(), 1, "the refused record must not be stored");
        assert_eq!(
            journal
                .get(&transition_identity())
                .unwrap()
                .request_digest(),
            &[0x11; 32],
            "the original bytes must be untouched"
        );
    }

    #[test]
    fn re_recording_identical_bytes_is_the_crash_recovery_case() {
        // Reloading a durable entry after a restart must not be mistaken for
        // reuse, so identical bytes are accepted idempotently.
        let mut journal = TransitionJournal::new();
        journal
            .prepare(entry_with_bytes(transition_identity(), 0x11))
            .unwrap();
        journal
            .get_mut(&transition_identity())
            .unwrap()
            .record_transmission()
            .unwrap();

        journal
            .prepare(entry_with_bytes(transition_identity(), 0x11))
            .expect("identical bytes must be accepted");

        assert_eq!(journal.len(), 1);
        assert_eq!(
            journal.get(&transition_identity()).unwrap().state(),
            &JournalState::InFlight { attempts: 1 },
            "re-recording must not reset progress"
        );
    }

    #[test]
    fn outstanding_lists_exactly_what_restart_must_resubmit() {
        let mut journal = TransitionJournal::new();
        journal.prepare(entry(transition_identity())).unwrap();
        journal.prepare(entry(message_identity())).unwrap();
        assert_eq!(journal.outstanding().count(), 2);

        // A completed operation drops out; an in-flight one stays, because its
        // outcome is still unknown.
        journal
            .get_mut(&transition_identity())
            .unwrap()
            .record_completed()
            .unwrap();
        journal
            .get_mut(&message_identity())
            .unwrap()
            .record_transmission()
            .unwrap();

        let outstanding: Vec<&OperationIdentity> =
            journal.outstanding().map(JournalEntry::identity).collect();
        assert_eq!(outstanding, vec![&message_identity()]);
    }

    #[test]
    fn the_two_id_kinds_do_not_collide_in_the_journal() {
        // Same UUID, same DID, different endpoint and different ID kind. These
        // are distinct server-side identities and must be distinct keys here.
        let mut journal = TransitionJournal::new();
        journal.prepare(entry(transition_identity())).unwrap();
        journal
            .prepare(entry(message_identity()))
            .expect("a messageId identity must not collide with an idempotencyKey");
        assert_eq!(journal.len(), 2);
    }

    #[test]
    fn a_fresh_journal_is_empty() {
        let journal = TransitionJournal::new();
        assert!(journal.is_empty());
        assert_eq!(journal.len(), 0);
        assert_eq!(journal.outstanding().count(), 0);
    }

    #[test]
    fn identity_display_names_all_three_components() {
        assert_eq!(
            transition_identity().to_string(),
            format!("blue.catbird.chat.submitTransition/{DID}/{KEY}")
        );
    }
}
