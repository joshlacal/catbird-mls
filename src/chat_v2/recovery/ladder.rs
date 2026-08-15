//! The bounded recovery ladder.
//!
//! §1 and §5 give recovery exactly four rungs, in one order, and nothing else:
//!
//! 1. **Catch-up** — fetch and apply what is already entitled. Costs nothing and
//!    fixes the common case.
//! 2. **Pending Welcome** — a Welcome is already waiting; process it.
//! 3. **Target-device recovery request** — the device signs
//!    `requestLeafRecovery` itself and waits for a healthy different-DID leaf to
//!    fulfil it.
//! 4. **Reset request** — a durable signed intent that an active admin may
//!    later activate.
//!
//! The ladder is **bounded** in both directions. It never skips a rung, because
//! each rung is cheaper and less destructive than the next and skipping one
//! escalates a problem that a cheaper step would have solved. And it never grows
//! a fifth, because every escalation past reset is either destructive or
//! unauthorized.
//!
//! # The deliberate absences
//!
//! These are the reason this module is written as a closed enum rather than a
//! set of functions a caller composes. What is *not* here matters more than what
//! is:
//!
//! - **No external commit, at any rung.** §1: "Proposal references, standalone
//!   proposals, external commits, private handshakes, PSKs, ReInit,
//!   GroupContextExtensions, and draft application-data updates are forbidden."
//!   OpenMLS emits `external_pub` because the format has the field; protocol
//!   policy forbids using it. v1's `force_rejoin_unlocked` does `delete_group`
//!   then `create_external_commit`, which is precisely the shape that must never
//!   reappear here — an external commit inflates the epoch and isolates the
//!   sender, and observed epochs of 700-800 in v1 are what that looks like in
//!   production. A test walks this tree and fails on any reference to one.
//! - **No autonomous destructive reset.** Reset activation is an explicit
//!   authorized act, never a fallback a client reaches on its own. This module
//!   can produce a reset *request* — a signed durable intent — and nothing more.
//!   [`RecoveryRung::ResetRequest`] is the top rung precisely so that the
//!   destructive step sits outside the ladder entirely.
//! - **No self-authorized recovery.** §9: "Neither a locally observed poisoned
//!   state nor a deterministic join failure is server-authored recovery work …
//!   Recovery work never authorizes recovery." A recovery-work item is advisory
//!   only; the device must still submit its own signed request. That is the same
//!   hint-versus-authority split the close path uses, and it is enforced the
//!   same way — by separate types with no conversion between them.

use core::fmt;

/// One rung of the bounded recovery ladder.
///
/// Ordered from cheapest to most disruptive. The ordering is not cosmetic:
/// [`RecoveryLadder`] uses it to refuse a step that skips ahead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryRung {
    /// Fetch and apply already-entitled entries. Non-mutating and always tried
    /// first.
    CatchUp,
    /// Process a Welcome that is already waiting for this device.
    PendingWelcome,
    /// Sign `requestLeafRecovery` and wait for a healthy different-DID leaf.
    TargetDeviceRecoveryRequest,
    /// Sign a durable reset intent. The top rung; activation is a separate
    /// authorized act by an active admin, not part of this ladder.
    ResetRequest,
}

impl RecoveryRung {
    /// Every rung, cheapest first. Exactly four, forever.
    pub const ALL: [Self; 4] = [
        Self::CatchUp,
        Self::PendingWelcome,
        Self::TargetDeviceRecoveryRequest,
        Self::ResetRequest,
    ];

    /// The next rung, or `None` at the top.
    ///
    /// Returning `None` rather than wrapping or escalating is the bound: there
    /// is nothing above a reset request that a client may reach for on its own.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::CatchUp => Some(Self::PendingWelcome),
            Self::PendingWelcome => Some(Self::TargetDeviceRecoveryRequest),
            Self::TargetDeviceRecoveryRequest => Some(Self::ResetRequest),
            Self::ResetRequest => None,
        }
    }

    /// Whether this rung mutates conversation state.
    ///
    /// Catch-up does not; the rest submit something signed. Useful for deciding
    /// what may be retried freely.
    pub fn is_mutating(self) -> bool {
        match self {
            Self::CatchUp => false,
            Self::PendingWelcome | Self::TargetDeviceRecoveryRequest | Self::ResetRequest => true,
        }
    }
}

impl fmt::Display for RecoveryRung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CatchUp => "catch-up",
            Self::PendingWelcome => "pending Welcome",
            Self::TargetDeviceRecoveryRequest => "target-device recovery request",
            Self::ResetRequest => "reset request",
        })
    }
}

/// Why a ladder step was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderError {
    /// A step skipped one or more rungs.
    ///
    /// Each rung is cheaper and less destructive than the next, so skipping
    /// escalates a problem a cheaper step would have solved.
    SkippedRung {
        attempted: RecoveryRung,
        expected: RecoveryRung,
    },
    /// A step went back down the ladder.
    ///
    /// The ladder is monotonic within one episode. Descending would let a
    /// client loop between rungs indefinitely.
    Descended {
        attempted: RecoveryRung,
        current: RecoveryRung,
    },
    /// The ladder was already at the top and something tried to escalate.
    ///
    /// There is deliberately nothing above a reset request. Escalating further
    /// would mean either a destructive act the client is not authorized to take
    /// or an external commit, and both are forbidden.
    Exhausted,
}

impl fmt::Display for LadderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SkippedRung {
                attempted,
                expected,
            } => write!(f, "recovery attempted {attempted} before trying {expected}"),
            Self::Descended { attempted, current } => write!(
                f,
                "recovery attempted {attempted} after already reaching {current}"
            ),
            Self::Exhausted => f.write_str(
                "the recovery ladder is exhausted; nothing above a reset request is available",
            ),
        }
    }
}

impl core::error::Error for LadderError {}

/// One device's position on the bounded ladder for one recovery episode.
///
/// Deliberately has no "force" or "restart at" constructor. An episode begins at
/// the bottom and climbs one rung at a time; a caller that wants to start over
/// begins a new episode, which makes the restart visible instead of hiding it
/// inside a jump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryLadder {
    reached: Option<RecoveryRung>,
}

impl RecoveryLadder {
    /// A fresh episode, below the first rung.
    pub fn new() -> Self {
        Self { reached: None }
    }

    /// The highest rung reached so far, if the episode has begun.
    pub fn reached(&self) -> Option<RecoveryRung> {
        self.reached
    }

    /// The rung this episode must take next, or `None` when exhausted.
    pub fn next_rung(&self) -> Option<RecoveryRung> {
        match self.reached {
            None => Some(RecoveryRung::CatchUp),
            Some(rung) => rung.next(),
        }
    }

    /// Whether every rung has been tried.
    pub fn is_exhausted(&self) -> bool {
        self.reached == Some(RecoveryRung::ResetRequest)
    }

    /// Advances to `rung`, which must be exactly the next one.
    ///
    /// Refuses a skip, a descent, and an escalation past the top — each by name,
    /// because they mean different things and a caller should be told which
    /// mistake it made.
    pub fn advance_to(&mut self, rung: RecoveryRung) -> Result<(), LadderError> {
        let Some(expected) = self.next_rung() else {
            return Err(LadderError::Exhausted);
        };
        if rung == expected {
            self.reached = Some(rung);
            return Ok(());
        }
        if let Some(current) = self.reached.filter(|current| rung <= *current) {
            return Err(LadderError::Descended {
                attempted: rung,
                current,
            });
        }
        Err(LadderError::SkippedRung {
            attempted: rung,
            expected,
        })
    }
}

impl Default for RecoveryLadder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_has_exactly_four_rungs_in_one_order() {
        assert_eq!(RecoveryRung::ALL.len(), 4);
        assert_eq!(
            RecoveryRung::ALL,
            [
                RecoveryRung::CatchUp,
                RecoveryRung::PendingWelcome,
                RecoveryRung::TargetDeviceRecoveryRequest,
                RecoveryRung::ResetRequest,
            ]
        );
        // The declared order and the `next` chain must agree, or one of them is
        // lying about the ladder.
        let mut walked = vec![RecoveryRung::CatchUp];
        while let Some(next) = walked.last().unwrap().next() {
            walked.push(next);
        }
        assert_eq!(walked, RecoveryRung::ALL.to_vec());
    }

    #[test]
    fn the_ladder_is_bounded_at_the_top() {
        // There is deliberately nothing above a reset request. Anything a
        // client could reach for past this point is either destructive without
        // authorization or an external commit.
        assert_eq!(RecoveryRung::ResetRequest.next(), None);

        let mut ladder = RecoveryLadder::new();
        for rung in RecoveryRung::ALL {
            ladder.advance_to(rung).expect("each rung in turn");
        }
        assert!(ladder.is_exhausted());
        assert_eq!(ladder.next_rung(), None);
        for rung in RecoveryRung::ALL {
            assert_eq!(
                ladder.advance_to(rung),
                Err(LadderError::Exhausted),
                "{rung}"
            );
        }
    }

    #[test]
    fn a_full_climb_visits_every_rung_in_order() {
        let mut ladder = RecoveryLadder::new();
        assert_eq!(ladder.reached(), None);
        assert_eq!(ladder.next_rung(), Some(RecoveryRung::CatchUp));

        for rung in RecoveryRung::ALL {
            assert_eq!(ladder.next_rung(), Some(rung));
            ladder.advance_to(rung).unwrap();
            assert_eq!(ladder.reached(), Some(rung));
        }
    }

    #[test]
    fn skipping_a_rung_is_refused_by_name() {
        // The whole point of the ordering. Jumping to a reset request without
        // trying catch-up escalates a problem the cheapest step would have
        // solved.
        let mut ladder = RecoveryLadder::new();
        assert_eq!(
            ladder.advance_to(RecoveryRung::ResetRequest),
            Err(LadderError::SkippedRung {
                attempted: RecoveryRung::ResetRequest,
                expected: RecoveryRung::CatchUp
            })
        );
        assert_eq!(
            ladder.advance_to(RecoveryRung::TargetDeviceRecoveryRequest),
            Err(LadderError::SkippedRung {
                attempted: RecoveryRung::TargetDeviceRecoveryRequest,
                expected: RecoveryRung::CatchUp
            })
        );
        assert_eq!(ladder.reached(), None, "a refused step must not advance");

        ladder.advance_to(RecoveryRung::CatchUp).unwrap();
        assert_eq!(
            ladder.advance_to(RecoveryRung::ResetRequest),
            Err(LadderError::SkippedRung {
                attempted: RecoveryRung::ResetRequest,
                expected: RecoveryRung::PendingWelcome
            })
        );
    }

    #[test]
    fn descending_the_ladder_is_refused_by_name() {
        // Monotonic within an episode; descending would let a client loop
        // between rungs forever.
        let mut ladder = RecoveryLadder::new();
        ladder.advance_to(RecoveryRung::CatchUp).unwrap();
        ladder.advance_to(RecoveryRung::PendingWelcome).unwrap();

        for rung in [RecoveryRung::CatchUp, RecoveryRung::PendingWelcome] {
            assert_eq!(
                ladder.advance_to(rung),
                Err(LadderError::Descended {
                    attempted: rung,
                    current: RecoveryRung::PendingWelcome
                }),
                "{rung}"
            );
        }
        assert_eq!(ladder.reached(), Some(RecoveryRung::PendingWelcome));
    }

    #[test]
    fn a_restart_is_a_new_episode_rather_than_a_jump() {
        // There is no force or restart-at constructor, so starting over is
        // visible in the caller rather than hidden inside a jump.
        let mut ladder = RecoveryLadder::new();
        ladder.advance_to(RecoveryRung::CatchUp).unwrap();
        ladder.advance_to(RecoveryRung::PendingWelcome).unwrap();

        let fresh = RecoveryLadder::new();
        assert_eq!(fresh.reached(), None);
        assert_eq!(fresh.next_rung(), Some(RecoveryRung::CatchUp));
        assert_ne!(fresh, ladder);
    }

    #[test]
    fn only_catch_up_is_non_mutating() {
        assert!(!RecoveryRung::CatchUp.is_mutating());
        for rung in [
            RecoveryRung::PendingWelcome,
            RecoveryRung::TargetDeviceRecoveryRequest,
            RecoveryRung::ResetRequest,
        ] {
            assert!(rung.is_mutating(), "{rung}");
        }
    }

    #[test]
    fn the_cheapest_rung_is_the_one_tried_first() {
        // Stated as an executable property rather than a comment: the first
        // rung must be the non-mutating one.
        let first = RecoveryLadder::new().next_rung().unwrap();
        assert_eq!(first, RecoveryRung::CatchUp);
        assert!(!first.is_mutating());
    }
}
