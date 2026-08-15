//! Poisoned-state containment.
//!
//! §1 states the whole containment story in one paragraph, and every rule below
//! is a sentence from it:
//!
//! > A poisoned victim authenticates outside MLS and signs `requestLeafRecovery`
//! > with `recoveryKind=replace`, selecting a fresh target-device KeyPackage. A
//! > healthy different-DID current leaf fulfills by removing and re-adding that
//! > exact victim device and emits the sole request-bound Welcome; the victim
//! > resumes only from the replacement interval and receives no history
//! > backfill. If all usable leaves are poisoned, an active admin uses reset
//! > activation; either direct participant may instead close the direct.
//!
//! # Poison is a local observation, never an authority
//!
//! §9 is explicit: "Neither a locally observed poisoned state nor a
//! deterministic join failure is server-authored recovery work … `poisonedState`
//! remains only a client-selected reset reason. Recovery work never authorizes
//! recovery."
//!
//! The server cannot prove MLS decryptability, so it cannot detect poison at
//! all. That makes [`PoisonObservation`] a *hint* in the same sense
//! `CloseHint` is one, and it is typed the same way: it can select a reason and
//! drive a request, and it can never be the reason a peer accepts anything. The
//! device must still submit its own signed `requestLeafRecovery`.
//!
//! # Deterministic, not transient
//!
//! Only a **deterministic** processing failure is poison. A transient failure —
//! a truncated response, a network fault — must not freeze a conversation,
//! because freezing is disruptive and the retry would have worked.
//! [`ProcessingFailure::is_deterministic`] is what separates them, and the
//! distinction is the caller's to establish honestly; the type exists so it has
//! to be stated rather than assumed.
//!
//! # Freezing is the containment
//!
//! On deterministic failure the device freezes **both** sending and ratchet
//! advancement. Freezing only one is worse than freezing neither: advancing the
//! ratchet past a message that cannot be processed destroys the key material
//! needed to ever process it, and sending from a state the group may not share
//! propagates the damage outward.

use super::ladder::RecoveryRung;
use crate::chat_v2::ids::{BareDid, DeviceId};
use core::fmt;

/// What kind of MLS processing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoisonSource {
    /// A Commit could not be processed.
    Commit,
    /// A Welcome could not be processed, so the join never completed.
    Welcome,
}

/// An observed MLS processing failure.
///
/// Carries whether the failure is deterministic because that is the only thing
/// that distinguishes poison from an ordinary fault, and a caller must state it
/// rather than leave it implied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingFailure {
    /// Which operation failed.
    pub source: PoisonSource,
    /// Whether the same input fails the same way on every attempt.
    ///
    /// A transient failure must never freeze a conversation: freezing is
    /// disruptive, and the retry would have succeeded.
    pub is_deterministic: bool,
}

/// A locally observed poisoned state.
///
/// **A hint, never an authority.** The server cannot prove MLS decryptability,
/// so nothing here authorizes recovery — it selects a reason and drives the
/// device's own signed request. There is deliberately no conversion from this
/// type into anything a peer would accept, which is the same shape the
/// hint-versus-authority split uses everywhere else in this tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoisonObservation {
    failure: ProcessingFailure,
}

impl PoisonObservation {
    /// Records a deterministic failure as poison.
    ///
    /// Returns `None` for a transient failure, so a caller cannot obtain an
    /// observation without having asserted determinism.
    pub fn from_failure(failure: ProcessingFailure) -> Option<Self> {
        failure.is_deterministic.then_some(Self { failure })
    }

    /// The failure this observation was derived from.
    pub fn failure(&self) -> &ProcessingFailure {
        &self.failure
    }

    /// What the device must freeze immediately.
    ///
    /// Always both. Exposed as a value rather than two booleans so a caller
    /// cannot apply half of it.
    pub fn containment(&self) -> Containment {
        Containment
    }
}

/// The freeze a poisoned device applies: sending **and** ratchet advancement.
///
/// A single unit type rather than a pair of flags, because the two must move
/// together. Advancing the ratchet past an unprocessable message destroys the
/// key material needed to ever process it; sending from a state the group may
/// not share propagates the damage. Half of this containment is worse than none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Containment;

impl Containment {
    /// Sending is frozen.
    pub fn freezes_sending(self) -> bool {
        true
    }

    /// Ratchet advancement is frozen.
    pub fn freezes_ratchet_advancement(self) -> bool {
        true
    }
}

/// A candidate leaf considered as a recovery fulfiller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillerCandidate {
    /// The candidate's DID.
    pub did: BareDid,
    /// The candidate's device.
    pub device_id: DeviceId,
    /// Whether the candidate is itself poisoned.
    pub is_poisoned: bool,
    /// Whether the candidate is a current leaf.
    ///
    /// A non-leaf cannot commit the remove-and-re-add, so it cannot fulfil.
    pub is_current_leaf: bool,
}

/// Why no fulfiller could be selected, or what to do instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoisonEscalation {
    /// Every usable leaf is poisoned.
    ///
    /// §1: an active admin uses reset activation, or either direct participant
    /// closes the direct. Both are **authorized acts by someone else** — the
    /// poisoned device's own next step is a reset *request*, never an
    /// activation, and never a local destructive act.
    AllUsableLeavesPoisoned,
    /// There are no current leaves other than the victim's own DID.
    NoDifferentDidLeaf,
}

impl fmt::Display for PoisonEscalation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllUsableLeavesPoisoned => f.write_str(
                "every usable leaf is poisoned; escalation is an authorized reset activation \
                 or a direct close by another party, never a local act",
            ),
            Self::NoDifferentDidLeaf => {
                f.write_str("no current leaf of a different DID is available to fulfil")
            }
        }
    }
}

impl core::error::Error for PoisonEscalation {}

/// The recovery a poisoned victim requests.
///
/// `recoveryKind=replace`, signed **outside MLS**. That is the point: the
/// victim's MLS state is exactly what cannot be trusted, so the request is
/// authenticated by the device's own signing key rather than by group
/// membership. A poisoned device that could only speak through MLS could not
/// ask for help at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryKind {
    /// Replace this exact device's leaf: remove and re-add it.
    Replace,
}

impl RecoveryKind {
    /// The wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replace => "replace",
        }
    }

    /// Whether the request is authenticated outside MLS.
    ///
    /// Always true for a poison replacement, and stated as a method so the
    /// reason travels with the value.
    pub const fn is_signed_outside_mls(self) -> bool {
        true
    }
}

/// Selects the leaf that may fulfil a poisoned device's replacement request.
///
/// The rule is **different DID**, not merely different device. §1 says "a
/// healthy different-DID current leaf", and the reason is that poison plausibly
/// affects every device of one principal — a sibling device of the victim is the
/// least trustworthy candidate available, not the most convenient one.
///
/// Returns the first eligible candidate in the caller's order; the caller is
/// responsible for whatever ordering it wants among equally eligible leaves.
pub fn select_fulfiller<'a>(
    victim_did: &BareDid,
    candidates: &'a [FulfillerCandidate],
) -> Result<&'a FulfillerCandidate, PoisonEscalation> {
    let usable: Vec<&FulfillerCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.is_current_leaf)
        .collect();

    if let Some(healthy) = usable
        .iter()
        .find(|candidate| !candidate.is_poisoned && &candidate.did != victim_did)
    {
        return Ok(healthy);
    }

    // Distinguish the two dead ends, because they call for different responses.
    // "Everyone is poisoned" escalates to an authorized reset or a direct close;
    // "there is nobody else here" is a different situation entirely.
    if usable.iter().any(|candidate| &candidate.did != victim_did) {
        Err(PoisonEscalation::AllUsableLeavesPoisoned)
    } else {
        Err(PoisonEscalation::NoDifferentDidLeaf)
    }
}

/// The ladder rung a poisoned device takes next.
///
/// Always the target-device recovery request — the victim signs for itself.
/// Never a reset activation: activation is an authorized act by an active admin,
/// and a poisoned device escalating itself to a destructive act is exactly what
/// "no autonomous destructive reset" forbids.
pub fn poisoned_device_next_rung(_observation: &PoisonObservation) -> RecoveryRung {
    RecoveryRung::TargetDeviceRecoveryRequest
}

#[cfg(test)]
mod tests {
    use super::*;

    const VICTIM_DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const PEER_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const DEVICE_A: &str = "70707070-7070-4070-b070-707070707070";
    const DEVICE_B: &str = "72727272-7272-4272-b272-727272727272";

    fn did(value: &str) -> BareDid {
        BareDid::parse(value).unwrap()
    }

    fn candidate(
        did_text: &str,
        device: &str,
        is_poisoned: bool,
        is_current_leaf: bool,
    ) -> FulfillerCandidate {
        FulfillerCandidate {
            did: did(did_text),
            device_id: DeviceId::parse(device).unwrap(),
            is_poisoned,
            is_current_leaf,
        }
    }

    fn deterministic(source: PoisonSource) -> ProcessingFailure {
        ProcessingFailure {
            source,
            is_deterministic: true,
        }
    }

    // ---- deterministic vs transient ----------------------------------------

    #[test]
    fn only_a_deterministic_failure_is_poison() {
        for source in [PoisonSource::Commit, PoisonSource::Welcome] {
            assert!(PoisonObservation::from_failure(deterministic(source)).is_some());
            assert!(
                PoisonObservation::from_failure(ProcessingFailure {
                    source,
                    is_deterministic: false,
                })
                .is_none(),
                "a transient {source:?} failure must not freeze a conversation"
            );
        }
    }

    #[test]
    fn an_observation_cannot_be_built_without_asserting_determinism() {
        // There is no constructor that skips the check, so a caller cannot end
        // up holding an observation for a failure it never classified.
        let transient = ProcessingFailure {
            source: PoisonSource::Commit,
            is_deterministic: false,
        };
        assert_eq!(PoisonObservation::from_failure(transient), None);
    }

    // ---- containment ---------------------------------------------------------

    #[test]
    fn containment_freezes_both_sending_and_ratchet_advancement() {
        // Half of this is worse than none: advancing the ratchet past an
        // unprocessable message destroys the key material needed to ever
        // process it, and sending from an unshared state spreads the damage.
        let observation =
            PoisonObservation::from_failure(deterministic(PoisonSource::Commit)).unwrap();
        let containment = observation.containment();
        assert!(containment.freezes_sending());
        assert!(containment.freezes_ratchet_advancement());
    }

    // ---- fulfiller selection --------------------------------------------------

    #[test]
    fn a_healthy_different_did_leaf_is_selected() {
        let candidates = [
            candidate(VICTIM_DID, DEVICE_A, true, true),
            candidate(PEER_DID, DEVICE_B, false, true),
        ];
        let chosen = select_fulfiller(&did(VICTIM_DID), &candidates).unwrap();
        assert_eq!(chosen.did, did(PEER_DID));
    }

    #[test]
    fn a_sibling_device_of_the_victim_is_never_selected() {
        // The rule is different DID, not different device. Poison plausibly
        // affects every device of one principal, so the victim's own sibling is
        // the least trustworthy candidate available.
        let candidates = [
            candidate(VICTIM_DID, DEVICE_A, true, true),
            candidate(VICTIM_DID, DEVICE_B, false, true),
        ];
        assert_eq!(
            select_fulfiller(&did(VICTIM_DID), &candidates),
            Err(PoisonEscalation::NoDifferentDidLeaf),
            "a healthy sibling of the same DID must not qualify"
        );
    }

    #[test]
    fn a_poisoned_different_did_leaf_is_not_selected() {
        let candidates = [
            candidate(VICTIM_DID, DEVICE_A, true, true),
            candidate(PEER_DID, DEVICE_B, true, true),
        ];
        assert_eq!(
            select_fulfiller(&did(VICTIM_DID), &candidates),
            Err(PoisonEscalation::AllUsableLeavesPoisoned)
        );
    }

    #[test]
    fn a_non_leaf_cannot_fulfil_however_healthy() {
        // Fulfilment is a remove-and-re-add Commit, which only a current leaf
        // can make.
        let candidates = [
            candidate(VICTIM_DID, DEVICE_A, true, true),
            candidate(PEER_DID, DEVICE_B, false, false),
        ];
        assert_eq!(
            select_fulfiller(&did(VICTIM_DID), &candidates),
            Err(PoisonEscalation::NoDifferentDidLeaf)
        );
    }

    #[test]
    fn the_two_dead_ends_are_distinguished() {
        // They call for different responses: "everyone is poisoned" escalates
        // to an authorized reset or a direct close, while "nobody else is here"
        // is a different situation. Collapsing them would misroute the answer.
        let all_poisoned = [
            candidate(VICTIM_DID, DEVICE_A, true, true),
            candidate(PEER_DID, DEVICE_B, true, true),
        ];
        let alone = [candidate(VICTIM_DID, DEVICE_A, true, true)];

        assert_eq!(
            select_fulfiller(&did(VICTIM_DID), &all_poisoned),
            Err(PoisonEscalation::AllUsableLeavesPoisoned)
        );
        assert_eq!(
            select_fulfiller(&did(VICTIM_DID), &alone),
            Err(PoisonEscalation::NoDifferentDidLeaf)
        );
        assert_ne!(
            PoisonEscalation::AllUsableLeavesPoisoned,
            PoisonEscalation::NoDifferentDidLeaf
        );
    }

    #[test]
    fn an_empty_candidate_set_is_not_a_fulfiller() {
        assert_eq!(
            select_fulfiller(&did(VICTIM_DID), &[]),
            Err(PoisonEscalation::NoDifferentDidLeaf)
        );
    }

    // ---- the request ----------------------------------------------------------

    #[test]
    fn the_replacement_request_is_signed_outside_mls() {
        // The victim's MLS state is exactly what cannot be trusted. A poisoned
        // device that could only speak through MLS could not ask for help.
        assert!(RecoveryKind::Replace.is_signed_outside_mls());
        assert_eq!(RecoveryKind::Replace.as_str(), "replace");
    }

    #[test]
    fn a_poisoned_device_requests_rather_than_activates() {
        // The single most important property here. A poisoned device escalating
        // itself to a reset activation is precisely the autonomous destructive
        // act the protocol forbids; its next step is its own signed request.
        let observation =
            PoisonObservation::from_failure(deterministic(PoisonSource::Welcome)).unwrap();
        let rung = poisoned_device_next_rung(&observation);
        assert_eq!(rung, RecoveryRung::TargetDeviceRecoveryRequest);
        assert_ne!(
            rung,
            RecoveryRung::ResetRequest,
            "poison does not skip the ladder to the top either"
        );
    }

    #[test]
    fn escalation_after_all_peers_poisoned_is_someone_elses_authorized_act() {
        // Recorded as an executable statement of the boundary: this module
        // reports the situation and stops. It has no function that activates a
        // reset or closes a conversation, because neither is the poisoned
        // device's to perform.
        let escalation = PoisonEscalation::AllUsableLeavesPoisoned;
        let message = escalation.to_string();
        assert!(
            message.contains("authorized") && message.contains("never a local act"),
            "the refusal must say whose act this is: {message}"
        );
    }

    #[test]
    fn a_poison_observation_carries_no_path_to_authority() {
        // The hint-versus-authority split, recorded the same way the close path
        // records it. The server cannot prove MLS decryptability, so nothing
        // here can authorize anything; the device must still submit its own
        // signed request. There is no From/Into to any authority type, and this
        // test states the intent the compiler enforces.
        let observation =
            PoisonObservation::from_failure(deterministic(PoisonSource::Commit)).unwrap();
        assert_eq!(observation.failure().source, PoisonSource::Commit);
        assert!(observation.failure().is_deterministic);
    }
}
