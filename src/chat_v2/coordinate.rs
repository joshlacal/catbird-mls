//! The full conversation coordinate and its transition relations.
//!
//! CHAT_PROTOCOL.md §4 defines the coordinate as
//! `{conversationId, generation, stateVersion, groupId, epoch, groupContextHash,
//! confirmationTag, lifecycle}` and then fixes exactly how each kind of
//! transition may move it. Those relations are not advisory: the reducer
//! compares a control row's `previous` against its expected context and
//! installs the row's `next`, so a coordinate that moved illegally is how a
//! client silently forks from the group.
//!
//! Every relation here is expressed as a check rather than a constructor. The
//! client never *derives* the next coordinate — the server and the MLS state
//! are authoritative for that — it only ever confirms that a coordinate it was
//! handed moved the way its transition kind permits.

use super::ids::{ConversationId, IntegerError, SafeInteger};
use core::fmt;

/// Whether a coordinate is the conversation's live state or has been retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lifecycle {
    /// The live coordinate.
    Active,
    /// Retired by reset or terminal close.
    Superseded,
}

/// The exact 32-byte cryptographic fields of a coordinate.
pub const CRYPTO_FIELD_LEN: usize = 32;

/// The complete conversation coordinate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Coordinate {
    /// Stable across generations, resets, and terminal close.
    pub conversation_id: ConversationId,
    /// Incremented only by a reset successor.
    pub generation: SafeInteger,
    /// Incremented by every transition, including policy-only ones.
    pub state_version: SafeInteger,
    /// Random 32 bytes; changes only on a reset successor.
    pub group_id: [u8; CRYPTO_FIELD_LEN],
    /// The MLS epoch.
    pub epoch: SafeInteger,
    /// SHA-256 of the authoritative MLS GroupContext TLS serialization.
    pub group_context_hash: [u8; CRYPTO_FIELD_LEN],
    /// The MLS confirmation tag.
    pub confirmation_tag: [u8; CRYPTO_FIELD_LEN],
    /// Active or superseded.
    pub lifecycle: Lifecycle,
}

/// Which kind of transition is claimed to connect two coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionKind {
    /// An epoch-changing MLS Commit, including recovery and leave fulfillment.
    Commit,
    /// A group policy change. Increments only state version.
    Policy,
    /// A metadata update. Increments only state version.
    Metadata,
    /// The old generation being retired by a reset.
    ResetRetirement,
    /// The new generation created by a reset activation.
    ResetSuccessor,
    /// Terminal conversation close.
    TerminalClose,
}

/// Why a claimed coordinate transition was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinateError {
    /// The conversation identity changed. It never may.
    ConversationChanged,
    /// A field moved in a way this transition kind forbids.
    FieldMustNotChange {
        kind: TransitionKind,
        field: &'static str,
    },
    /// A field that had to change did not.
    FieldMustChange {
        kind: TransitionKind,
        field: &'static str,
    },
    /// A counter did not increment by exactly one.
    NotIncrementedByOne {
        kind: TransitionKind,
        field: &'static str,
        prior: i64,
        next: i64,
    },
    /// A counter that had to reset to zero did not.
    MustBeZero {
        kind: TransitionKind,
        field: &'static str,
        found: i64,
    },
    /// The lifecycle was not the one this transition kind requires.
    Lifecycle {
        kind: TransitionKind,
        expected: Lifecycle,
        found: Lifecycle,
    },
    /// A checked increment would pass the safe-integer ceiling.
    ///
    /// This is the `CoordinateOverflow` boundary; it rejects atomically and
    /// never wraps.
    Overflow {
        field: &'static str,
        source: IntegerError,
    },
}

impl fmt::Display for CoordinateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversationChanged => f.write_str("conversationId is immutable"),
            Self::FieldMustNotChange { kind, field } => {
                write!(f, "{kind:?} must not change {field}")
            }
            Self::FieldMustChange { kind, field } => write!(f, "{kind:?} must change {field}"),
            Self::NotIncrementedByOne {
                kind,
                field,
                prior,
                next,
            } => write!(
                f,
                "{kind:?} must increment {field} by exactly one, got {prior} -> {next}"
            ),
            Self::MustBeZero { kind, field, found } => {
                write!(f, "{kind:?} requires {field} to be zero, got {found}")
            }
            Self::Lifecycle {
                kind,
                expected,
                found,
            } => write!(f, "{kind:?} requires {expected:?} lifecycle, got {found:?}"),
            Self::Overflow { field, source } => write!(f, "{field}: {source}"),
        }
    }
}

impl core::error::Error for CoordinateError {}

impl Coordinate {
    /// Whether this coordinate is a legal creation coordinate.
    ///
    /// §4: creation is `(generation=0, stateVersion=0, epoch=0,
    /// lifecycle=active)`.
    pub fn is_creation(&self) -> bool {
        self.generation == SafeInteger::ZERO
            && self.state_version == SafeInteger::ZERO
            && self.epoch == SafeInteger::ZERO
            && self.lifecycle == Lifecycle::Active
    }

    /// Confirms that `next` is a legal successor of `self` under `kind`.
    ///
    /// The client never derives a coordinate; it only checks one it was given.
    pub fn validate_transition(
        &self,
        next: &Coordinate,
        kind: TransitionKind,
    ) -> Result<(), CoordinateError> {
        if self.conversation_id != next.conversation_id {
            return Err(CoordinateError::ConversationChanged);
        }

        match kind {
            TransitionKind::Commit => {
                self.require_same(next, kind, Field::Generation)?;
                self.require_same(next, kind, Field::GroupId)?;
                self.require_lifecycle(next, kind, Lifecycle::Active)?;
                self.require_increment(next, kind, Field::StateVersion)?;
                self.require_increment(next, kind, Field::Epoch)?;
                // An epoch change must derive a different GroupContext hash and
                // a different confirmation tag. Equality here would mean the
                // epoch advanced without the group state actually moving.
                self.require_changed(next, kind, Field::GroupContextHash)?;
                self.require_changed(next, kind, Field::ConfirmationTag)?;
            }
            TransitionKind::Policy | TransitionKind::Metadata => {
                // Every cryptographic field is preserved: these do not touch
                // the MLS epoch at all.
                self.require_same(next, kind, Field::Generation)?;
                self.require_same(next, kind, Field::GroupId)?;
                self.require_same(next, kind, Field::Epoch)?;
                self.require_same(next, kind, Field::GroupContextHash)?;
                self.require_same(next, kind, Field::ConfirmationTag)?;
                self.require_lifecycle(next, kind, Lifecycle::Active)?;
                self.require_increment(next, kind, Field::StateVersion)?;
            }
            TransitionKind::ResetRetirement | TransitionKind::TerminalClose => {
                // Both retire the current coordinate in place: every
                // cryptographic field is preserved, state version advances once,
                // and the lifecycle becomes superseded. They differ only in
                // whether a successor generation follows, which is not
                // observable from the coordinate pair alone.
                self.require_same(next, kind, Field::Generation)?;
                self.require_same(next, kind, Field::GroupId)?;
                self.require_same(next, kind, Field::Epoch)?;
                self.require_same(next, kind, Field::GroupContextHash)?;
                self.require_same(next, kind, Field::ConfirmationTag)?;
                self.require_increment(next, kind, Field::StateVersion)?;
                self.require_lifecycle(next, kind, Lifecycle::Superseded)?;
            }
            TransitionKind::ResetSuccessor => {
                self.require_increment(next, kind, Field::Generation)?;
                self.require_zero(next, kind, Field::StateVersion)?;
                self.require_zero(next, kind, Field::Epoch)?;
                self.require_lifecycle(next, kind, Lifecycle::Active)?;
                // A fresh generation gets a fresh random group ID and a derived
                // context hash. Reusing either would let a reset silently
                // continue the retired group.
                self.require_changed(next, kind, Field::GroupId)?;
                self.require_changed(next, kind, Field::GroupContextHash)?;
            }
        }
        Ok(())
    }

    fn require_same(
        &self,
        next: &Coordinate,
        kind: TransitionKind,
        field: Field,
    ) -> Result<(), CoordinateError> {
        if field.differs(self, next) {
            return Err(CoordinateError::FieldMustNotChange {
                kind,
                field: field.name(),
            });
        }
        Ok(())
    }

    fn require_changed(
        &self,
        next: &Coordinate,
        kind: TransitionKind,
        field: Field,
    ) -> Result<(), CoordinateError> {
        if !field.differs(self, next) {
            return Err(CoordinateError::FieldMustChange {
                kind,
                field: field.name(),
            });
        }
        Ok(())
    }

    fn require_increment(
        &self,
        next: &Coordinate,
        kind: TransitionKind,
        field: Field,
    ) -> Result<(), CoordinateError> {
        let prior = field.counter(self);
        let expected = prior
            .checked_increment()
            .map_err(|source| CoordinateError::Overflow {
                field: field.name(),
                source,
            })?;
        let found = field.counter(next);
        if found != expected {
            return Err(CoordinateError::NotIncrementedByOne {
                kind,
                field: field.name(),
                prior: prior.get(),
                next: found.get(),
            });
        }
        Ok(())
    }

    fn require_zero(
        &self,
        next: &Coordinate,
        kind: TransitionKind,
        field: Field,
    ) -> Result<(), CoordinateError> {
        let found = field.counter(next);
        if found != SafeInteger::ZERO {
            return Err(CoordinateError::MustBeZero {
                kind,
                field: field.name(),
                found: found.get(),
            });
        }
        Ok(())
    }

    fn require_lifecycle(
        &self,
        next: &Coordinate,
        kind: TransitionKind,
        expected: Lifecycle,
    ) -> Result<(), CoordinateError> {
        if next.lifecycle != expected {
            return Err(CoordinateError::Lifecycle {
                kind,
                expected,
                found: next.lifecycle,
            });
        }
        Ok(())
    }
}

/// Names a coordinate field so the relation checks read as rules rather than
/// as repeated field access.
#[derive(Debug, Clone, Copy)]
enum Field {
    Generation,
    StateVersion,
    Epoch,
    GroupId,
    GroupContextHash,
    ConfirmationTag,
}

impl Field {
    fn name(self) -> &'static str {
        match self {
            Self::Generation => "generation",
            Self::StateVersion => "stateVersion",
            Self::Epoch => "epoch",
            Self::GroupId => "groupId",
            Self::GroupContextHash => "groupContextHash",
            Self::ConfirmationTag => "confirmationTag",
        }
    }

    fn counter(self, coordinate: &Coordinate) -> SafeInteger {
        match self {
            Self::Generation => coordinate.generation,
            Self::StateVersion => coordinate.state_version,
            Self::Epoch => coordinate.epoch,
            Self::GroupId | Self::GroupContextHash | Self::ConfirmationTag => {
                unreachable!("{} is not a counter", self.name())
            }
        }
    }

    fn differs(self, prior: &Coordinate, next: &Coordinate) -> bool {
        match self {
            Self::Generation => prior.generation != next.generation,
            Self::StateVersion => prior.state_version != next.state_version,
            Self::Epoch => prior.epoch != next.epoch,
            Self::GroupId => prior.group_id != next.group_id,
            Self::GroupContextHash => prior.group_context_hash != next.group_context_hash,
            Self::ConfirmationTag => prior.confirmation_tag != next.confirmation_tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_CONVERSATION: &str = "22222222-2222-4222-8222-222222222222";

    fn integer(value: i64) -> SafeInteger {
        SafeInteger::new(value).unwrap()
    }

    fn creation() -> Coordinate {
        Coordinate {
            conversation_id: ConversationId::parse(CONVERSATION).unwrap(),
            generation: SafeInteger::ZERO,
            state_version: SafeInteger::ZERO,
            group_id: [0x01; 32],
            epoch: SafeInteger::ZERO,
            group_context_hash: [0x02; 32],
            confirmation_tag: [0x03; 32],
            lifecycle: Lifecycle::Active,
        }
    }

    #[test]
    fn a_creation_coordinate_is_recognized() {
        assert!(creation().is_creation());

        let mut advanced = creation();
        advanced.epoch = integer(1);
        assert!(!advanced.is_creation());

        let mut superseded = creation();
        superseded.lifecycle = Lifecycle::Superseded;
        assert!(!superseded.is_creation());
    }

    #[test]
    fn conversation_identity_is_immutable_under_every_kind() {
        let prior = creation();
        let mut next = creation();
        next.conversation_id = ConversationId::parse(OTHER_CONVERSATION).unwrap();
        for kind in [
            TransitionKind::Commit,
            TransitionKind::Policy,
            TransitionKind::Metadata,
            TransitionKind::ResetRetirement,
            TransitionKind::ResetSuccessor,
            TransitionKind::TerminalClose,
        ] {
            assert_eq!(
                prior.validate_transition(&next, kind).unwrap_err(),
                CoordinateError::ConversationChanged,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_commit_advances_state_version_and_epoch_together() {
        let prior = creation();
        let mut next = creation();
        next.state_version = integer(1);
        next.epoch = integer(1);
        next.group_context_hash = [0x22; 32];
        next.confirmation_tag = [0x33; 32];

        prior
            .validate_transition(&next, TransitionKind::Commit)
            .expect("a well-formed commit must validate");
    }

    #[test]
    fn a_commit_that_does_not_move_the_group_state_is_rejected() {
        // An epoch change with an unchanged context hash or confirmation tag
        // means the epoch advanced without the group actually moving.
        let prior = creation();
        let mut stale_hash = creation();
        stale_hash.state_version = integer(1);
        stale_hash.epoch = integer(1);
        stale_hash.confirmation_tag = [0x33; 32];
        assert_eq!(
            prior
                .validate_transition(&stale_hash, TransitionKind::Commit)
                .unwrap_err(),
            CoordinateError::FieldMustChange {
                kind: TransitionKind::Commit,
                field: "groupContextHash"
            }
        );

        let mut stale_tag = creation();
        stale_tag.state_version = integer(1);
        stale_tag.epoch = integer(1);
        stale_tag.group_context_hash = [0x22; 32];
        assert_eq!(
            prior
                .validate_transition(&stale_tag, TransitionKind::Commit)
                .unwrap_err(),
            CoordinateError::FieldMustChange {
                kind: TransitionKind::Commit,
                field: "confirmationTag"
            }
        );
    }

    #[test]
    fn a_commit_must_not_skip_an_epoch() {
        let prior = creation();
        let mut next = creation();
        next.state_version = integer(1);
        next.epoch = integer(2);
        next.group_context_hash = [0x22; 32];
        next.confirmation_tag = [0x33; 32];
        assert_eq!(
            prior
                .validate_transition(&next, TransitionKind::Commit)
                .unwrap_err(),
            CoordinateError::NotIncrementedByOne {
                kind: TransitionKind::Commit,
                field: "epoch",
                prior: 0,
                next: 2
            }
        );
    }

    #[test]
    fn policy_and_metadata_leave_every_cryptographic_field_alone() {
        let prior = creation();
        let mut next = creation();
        next.state_version = integer(1);

        for kind in [TransitionKind::Policy, TransitionKind::Metadata] {
            prior
                .validate_transition(&next, kind)
                .unwrap_or_else(|err| panic!("{kind:?} must validate: {err}"));
        }

        // Touching the epoch makes it a Commit, not a policy change.
        let mut moved_epoch = next.clone();
        moved_epoch.epoch = integer(1);
        assert_eq!(
            prior
                .validate_transition(&moved_epoch, TransitionKind::Policy)
                .unwrap_err(),
            CoordinateError::FieldMustNotChange {
                kind: TransitionKind::Policy,
                field: "epoch"
            }
        );
    }

    #[test]
    fn retirement_and_close_preserve_the_crypto_state_and_supersede() {
        let prior = creation();
        let mut next = creation();
        next.state_version = integer(1);
        next.lifecycle = Lifecycle::Superseded;

        for kind in [
            TransitionKind::ResetRetirement,
            TransitionKind::TerminalClose,
        ] {
            prior
                .validate_transition(&next, kind)
                .unwrap_or_else(|err| panic!("{kind:?} must validate: {err}"));
        }

        // Staying active is the error that would let a closed conversation
        // keep accepting writes.
        let mut still_active = next.clone();
        still_active.lifecycle = Lifecycle::Active;
        assert_eq!(
            prior
                .validate_transition(&still_active, TransitionKind::TerminalClose)
                .unwrap_err(),
            CoordinateError::Lifecycle {
                kind: TransitionKind::TerminalClose,
                expected: Lifecycle::Superseded,
                found: Lifecycle::Active
            }
        );
    }

    #[test]
    fn a_reset_successor_starts_a_fresh_generation_from_zero() {
        let prior = creation();
        let mut next = creation();
        next.generation = integer(1);
        next.group_id = [0xaa; 32];
        next.group_context_hash = [0xbb; 32];

        prior
            .validate_transition(&next, TransitionKind::ResetSuccessor)
            .expect("a well-formed reset successor must validate");
    }

    #[test]
    fn a_reset_successor_may_not_reuse_the_retired_group_id() {
        // Reusing it would let a reset silently continue the retired group
        // rather than replace it.
        let prior = creation();
        let mut next = creation();
        next.generation = integer(1);
        next.group_context_hash = [0xbb; 32];
        assert_eq!(
            prior
                .validate_transition(&next, TransitionKind::ResetSuccessor)
                .unwrap_err(),
            CoordinateError::FieldMustChange {
                kind: TransitionKind::ResetSuccessor,
                field: "groupId"
            }
        );
    }

    #[test]
    fn a_reset_successor_must_restart_state_version_and_epoch() {
        let prior = creation();
        let mut next = creation();
        next.generation = integer(1);
        next.state_version = integer(4);
        next.group_id = [0xaa; 32];
        next.group_context_hash = [0xbb; 32];
        assert_eq!(
            prior
                .validate_transition(&next, TransitionKind::ResetSuccessor)
                .unwrap_err(),
            CoordinateError::MustBeZero {
                kind: TransitionKind::ResetSuccessor,
                field: "stateVersion",
                found: 4
            }
        );
    }

    #[test]
    fn an_increment_at_the_ceiling_rejects_rather_than_wraps() {
        // The CoordinateOverflow boundary.
        let mut prior = creation();
        prior.state_version = integer(super::super::ids::MAX_SAFE_INTEGER);
        let mut next = creation();
        next.state_version = SafeInteger::ZERO;
        next.lifecycle = Lifecycle::Superseded;

        let err = prior
            .validate_transition(&next, TransitionKind::TerminalClose)
            .unwrap_err();
        assert!(
            matches!(
                err,
                CoordinateError::Overflow {
                    field: "stateVersion",
                    ..
                }
            ),
            "expected an overflow rejection, got {err}"
        );
    }

    #[test]
    fn a_commit_may_not_change_generation_or_group_id() {
        let prior = creation();
        let mut next = creation();
        next.state_version = integer(1);
        next.epoch = integer(1);
        next.group_context_hash = [0x22; 32];
        next.confirmation_tag = [0x33; 32];
        next.generation = integer(1);
        assert_eq!(
            prior
                .validate_transition(&next, TransitionKind::Commit)
                .unwrap_err(),
            CoordinateError::FieldMustNotChange {
                kind: TransitionKind::Commit,
                field: "generation"
            }
        );
    }
}
