//! Participation status and the direct-traffic gate.
//!
//! §9 states the send precondition exactly, and the sentence is doing more work
//! than it looks:
//!
//! > Direct additionally requires both exact participants active and each
//! > currently represented by at least one MLS leaf: pending returns
//! > `ConversationNotAccepted`, while an active zero-leaf acceptance/Welcome,
//! > recovery, or reset gap returns `RecipientNotReady`. The server never stores
//! > misleading direct ciphertext during those gaps. **Group traffic may
//! > continue for remaining current leaves.**
//!
//! # "Both exact participants" is a cardinality rule first
//!
//! The sentence names *both* participants, so a direct is only evaluable
//! against a roster that has exactly two of them, distinct, one of which is the
//! sender. That part is easy to lose: a readiness check written as "no
//! participant is unready" answers `Ok` for an **empty** roster, for a roster
//! holding only the sender, and for a five-member roster that is not a direct at
//! all. Each of those is a caller assembling the wrong roster, and each would
//! have sent direct traffic the protocol forbids — the empty case most plainly,
//! since it permits sending to nobody.
//!
//! So the cardinality is checked before readiness, and refused by its own names.
//! The group arm has no equivalent rule on purpose: a group is one creator plus
//! zero or more invitees, so no member count is wrong there.
//!
//! # Two conditions, two different refusals
//!
//! "Active" and "has a leaf" are separate facts, and conflating them loses the
//! distinction the protocol draws:
//!
//! - **Pending** means the invitee has not accepted. Nothing is broken; the
//!   conversation simply is not consented to yet, and the answer is
//!   [`TrafficRefusal::ConversationNotAccepted`].
//! - **Active with zero leaves** means consent exists but the cryptographic
//!   state does not — an acceptance or Welcome still in flight, or a recovery or
//!   reset gap. That is [`TrafficRefusal::RecipientNotReady`], and it is
//!   *temporary in a way the first is not*.
//!
//! A client that reported "not accepted" for a recovery gap would tell a user
//! their peer had ignored them, which is both wrong and unkind.
//!
//! # Direct and group are gated differently, on purpose
//!
//! A direct requires **both** participants ready. A group does **not** — traffic
//! continues for whichever leaves remain. Applying the direct rule to groups
//! would silence an entire conversation because one member is mid-recovery,
//! which is exactly the availability failure the asymmetry exists to avoid.
//!
//! # Pending status grants no authority at all
//!
//! §4: "Both roles are admin, but pending status grants the invitee no
//! authority; acceptance changes only status to active." A pending invitee
//! cannot be Added to the MLS group either — §5 has acceptance atomically create
//! the add-kind request, so acceptance is what makes an Add possible rather than
//! something that happens alongside it.
//!
//! The one thing a pending invitee *may* do is close the direct (§7), which is
//! deliberate: consent to receive is exactly what they are withholding.

use crate::chat_v2::endpoint_error::ChatErrorCode;
use crate::chat_v2::ids::BareDid;
use core::fmt;

/// Whether a participant has accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParticipantStatus {
    /// Invited but not yet accepted. Grants no authority.
    Pending,
    /// Accepted. The only status change acceptance makes.
    Active,
}

/// Whether a conversation is a direct or a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationKind {
    /// Exactly two logical participants. Both must be ready to send.
    Direct,
    /// One creator plus zero or more invitees. Traffic continues for remaining
    /// current leaves.
    Group,
}

/// One participant's readiness for traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantPresence {
    /// Which participant this is.
    pub did: BareDid,
    /// Whether they have accepted.
    pub status: ParticipantStatus,
    /// How many current MLS leaves represent them.
    ///
    /// Separate from `status` because active-with-zero-leaves is a real and
    /// distinct state: an acceptance or Welcome in flight, or a recovery or
    /// reset gap.
    pub leaf_count: usize,
}

impl ParticipantPresence {
    /// Whether this participant can currently receive.
    pub fn is_ready(&self) -> bool {
        self.status == ParticipantStatus::Active && self.leaf_count > 0
    }
}

/// Why traffic was refused.
///
/// Each variant maps to the exact endpoint code the protocol names, so a client
/// reports what a server would and the two cannot drift into different
/// vocabularies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficRefusal {
    /// A direct participant has not accepted.
    ///
    /// Nothing is broken; consent has not been given.
    ConversationNotAccepted { did: BareDid },
    /// A direct participant is active but currently has no MLS leaf.
    ///
    /// An acceptance or Welcome in flight, or a recovery or reset gap. Distinct
    /// from not-accepted because it is temporary in a way that is not.
    RecipientNotReady { did: BareDid },
    /// A group has no current leaves at all.
    ///
    /// Group traffic continues for *remaining* leaves, but there must be at
    /// least one; sending into a group nobody can decrypt stores ciphertext no
    /// one will ever read.
    NoCurrentLeaves,
    /// A direct's roster was not exactly two participants.
    ///
    /// §9 requires *both* exact participants, so a roster of nought, one, or
    /// five is not a direct whose precondition can be evaluated. Refusing is
    /// the only safe answer: the alternative permits sending to nobody.
    DirectNotTwoParticipants { found: usize },
    /// A direct's roster named one participant twice.
    ///
    /// Two entries for one DID are one participant, not both of them. Left
    /// unchecked, a roster holding a device's own two rows would satisfy a
    /// count of two while the peer was never present.
    DirectParticipantsNotDistinct { did: BareDid },
    /// The sender was neither of the direct's two participants.
    ///
    /// A direct is between the sender and exactly one other. A pair that does
    /// not include the sender is a roster assembled for a different
    /// conversation, and readiness would answer about the wrong two people.
    ///
    /// Unlike its two roster siblings, this one **does** carry an endpoint
    /// code. It is not a local bookkeeping mistake the server cannot see: a
    /// send from a principal who is not a participant is refused server-side as
    /// [`ChatErrorCode::NotParticipant`], which the delivery service classifies
    /// as authorization — authenticated, but not permitted here. So the local
    /// pre-check and the server's answer stay one vocabulary, which is this
    /// module's standing rule.
    SenderNotAParticipant { sender: BareDid },
}

impl TrafficRefusal {
    /// The endpoint code a server would return for this refusal.
    ///
    /// Exposed so a client's local pre-check and the server's answer are the
    /// same vocabulary rather than two descriptions of one condition.
    pub fn endpoint_code(&self) -> Option<ChatErrorCode> {
        match self {
            Self::ConversationNotAccepted { .. } => Some(ChatErrorCode::ConversationNotAccepted),
            Self::RecipientNotReady { .. } => Some(ChatErrorCode::RecipientNotReady),
            // A send from a non-participant is refused server-side too, so it
            // reports what the server would rather than inventing a local-only
            // vocabulary for a condition the protocol already names.
            Self::SenderNotAParticipant { .. } => Some(ChatErrorCode::NotParticipant),
            // Genuinely local preconditions: the server never sees the roster,
            // so a roster this client assembled wrongly is not an answer a
            // server would ever give, and claiming one would put words in its
            // mouth.
            Self::NoCurrentLeaves
            | Self::DirectNotTwoParticipants { .. }
            | Self::DirectParticipantsNotDistinct { .. } => None,
        }
    }
}

impl fmt::Display for TrafficRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversationNotAccepted { did } => {
                write!(f, "{did} has not accepted this conversation")
            }
            Self::RecipientNotReady { did } => write!(
                f,
                "{did} is active but currently has no MLS leaf; the gap is temporary"
            ),
            Self::NoCurrentLeaves => f.write_str("no current leaf could receive this"),
            Self::DirectNotTwoParticipants { found } => write!(
                f,
                "a direct has exactly two participants, this roster has {found}"
            ),
            Self::DirectParticipantsNotDistinct { did } => write!(
                f,
                "{did} appears twice; two entries for one DID are one participant"
            ),
            Self::SenderNotAParticipant { sender } => {
                write!(f, "{sender} is not one of this direct's two participants")
            }
        }
    }
}

impl core::error::Error for TrafficRefusal {}

/// Whether application traffic may be sent.
///
/// Direct requires the roster to be exactly the sender and one distinct other,
/// **both** active and leafed. Group requires only that some current leaf
/// remains — silencing a whole group because one member is mid-recovery is the
/// availability failure the asymmetry avoids.
///
/// `sender` is this device's own principal. It is read only on the direct path,
/// where "both exact participants" cannot be checked without knowing who one of
/// them is meant to be.
pub fn require_traffic_allowed(
    kind: ConversationKind,
    sender: &BareDid,
    participants: &[ParticipantPresence],
) -> Result<(), TrafficRefusal> {
    match kind {
        ConversationKind::Direct => {
            // Cardinality before readiness. "No participant is unready" is
            // vacuously true of an empty roster, so a readiness-first check
            // permits sending a direct to nobody.
            require_direct_roster(sender, participants)?;
            // Pending is reported ahead of zero-leaf when both apply: "they
            // have not accepted" is the more accurate and more actionable
            // answer, and a pending participant has no leaf by construction.
            if let Some(pending) = participants
                .iter()
                .find(|participant| participant.status == ParticipantStatus::Pending)
            {
                return Err(TrafficRefusal::ConversationNotAccepted {
                    did: pending.did.clone(),
                });
            }
            if let Some(unleafed) = participants
                .iter()
                .find(|participant| participant.leaf_count == 0)
            {
                return Err(TrafficRefusal::RecipientNotReady {
                    did: unleafed.did.clone(),
                });
            }
            Ok(())
        }
        ConversationKind::Group => {
            if participants.iter().any(ParticipantPresence::is_ready) {
                Ok(())
            } else {
                Err(TrafficRefusal::NoCurrentLeaves)
            }
        }
    }
}

/// Confirms a direct's roster really is this sender and one distinct other.
///
/// Separate from the readiness checks because it answers a different question:
/// readiness asks whether the two participants can receive, and this asks
/// whether there are two participants at all and whether they are the right
/// two. A roster failing here is a caller mistake, not a peer's state.
fn require_direct_roster(
    sender: &BareDid,
    participants: &[ParticipantPresence],
) -> Result<(), TrafficRefusal> {
    if participants.len() != 2 {
        return Err(TrafficRefusal::DirectNotTwoParticipants {
            found: participants.len(),
        });
    }
    if participants[0].did == participants[1].did {
        return Err(TrafficRefusal::DirectParticipantsNotDistinct {
            did: participants[0].did.clone(),
        });
    }
    if !participants
        .iter()
        .any(|participant| &participant.did == sender)
    {
        return Err(TrafficRefusal::SenderNotAParticipant {
            sender: sender.clone(),
        });
    }
    Ok(())
}

/// Why an Add was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddRefusal {
    /// The target has not accepted.
    ///
    /// Acceptance is what *creates* the add-kind request, so an Add before
    /// acceptance is not merely early — it has nothing to refine.
    NotAccepted { did: BareDid },
}

impl fmt::Display for AddRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAccepted { did } => write!(
                f,
                "{did} must accept before being added; acceptance is what creates the add request"
            ),
        }
    }
}

impl core::error::Error for AddRefusal {}

/// Confirms a participant may be Added to the MLS group.
///
/// §5: initial invitation acceptance atomically creates an add-kind request, and
/// every Add refines exactly one open request signed by the target device
/// itself. So acceptance is not a step that happens near an Add — it is the
/// thing that makes an Add possible, and an Add before it has no request to
/// refine.
pub fn require_accepted_before_add(participant: &ParticipantPresence) -> Result<(), AddRefusal> {
    match participant.status {
        ParticipantStatus::Active => Ok(()),
        ParticipantStatus::Pending => Err(AddRefusal::NotAccepted {
            did: participant.did.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const BOB: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const CAROL: &str = "did:plc:44ybard66vv44zksje25o7dz";

    fn did(value: &str) -> BareDid {
        BareDid::parse(value).unwrap()
    }

    fn presence(value: &str, status: ParticipantStatus, leaf_count: usize) -> ParticipantPresence {
        ParticipantPresence {
            did: did(value),
            status,
            leaf_count,
        }
    }

    fn ready(value: &str) -> ParticipantPresence {
        presence(value, ParticipantStatus::Active, 1)
    }

    /// Every direct below sends as Alice, so the sender is spelled once.
    fn direct(participants: &[ParticipantPresence]) -> Result<(), TrafficRefusal> {
        require_traffic_allowed(ConversationKind::Direct, &did(ALICE), participants)
    }

    fn group(participants: &[ParticipantPresence]) -> Result<(), TrafficRefusal> {
        require_traffic_allowed(ConversationKind::Group, &did(ALICE), participants)
    }

    // ---- direct ------------------------------------------------------------

    #[test]
    fn a_direct_with_both_participants_ready_permits_traffic() {
        assert_eq!(direct(&[ready(ALICE), ready(BOB)]), Ok(()));
    }

    #[test]
    fn a_pending_invitee_blocks_direct_traffic_as_not_accepted() {
        let participants = [ready(ALICE), presence(BOB, ParticipantStatus::Pending, 0)];
        assert_eq!(
            direct(&participants),
            Err(TrafficRefusal::ConversationNotAccepted { did: did(BOB) })
        );
    }

    // ---- direct cardinality ---------------------------------------------------

    #[test]
    fn a_direct_roster_that_is_not_two_participants_is_refused_by_name() {
        // The four rosters a readiness-only check answers `Ok` for. The empty
        // one is the plainest: "no participant is unready" is vacuously true,
        // so the gate would permit sending a direct to nobody.
        for participants in [
            vec![],
            vec![ready(ALICE)],
            vec![ready(ALICE), ready(BOB), ready(CAROL)],
            vec![
                ready(ALICE),
                ready(BOB),
                ready(CAROL),
                presence(BOB, ParticipantStatus::Active, 2),
                presence(CAROL, ParticipantStatus::Active, 3),
            ],
        ] {
            let found = participants.len();
            assert_eq!(
                direct(&participants),
                Err(TrafficRefusal::DirectNotTwoParticipants { found }),
                "a roster of {found} is not a direct"
            );
        }
    }

    #[test]
    fn one_participant_named_twice_is_not_two_participants() {
        // A count of two is not the rule; §9 names *both exact participants*.
        // Two rows for one DID satisfy the count while the peer is absent.
        assert_eq!(
            direct(&[ready(ALICE), presence(ALICE, ParticipantStatus::Active, 2)]),
            Err(TrafficRefusal::DirectParticipantsNotDistinct { did: did(ALICE) })
        );
    }

    #[test]
    fn a_direct_the_sender_is_not_part_of_is_refused() {
        // Two ready, distinct participants — and neither of them is us. The
        // roster belongs to a different conversation, so readiness would be
        // answering about the wrong two people.
        assert_eq!(
            direct(&[ready(BOB), ready(CAROL)]),
            Err(TrafficRefusal::SenderNotAParticipant { sender: did(ALICE) })
        );
    }

    #[test]
    fn the_roster_refusals_are_local_and_carry_no_endpoint_code() {
        // A server never answers "your roster is malformed" — it never sees the
        // roster. Handing these an endpoint code would put words in its mouth.
        for refusal in [
            TrafficRefusal::DirectNotTwoParticipants { found: 5 },
            TrafficRefusal::DirectParticipantsNotDistinct { did: did(ALICE) },
        ] {
            assert_eq!(refusal.endpoint_code(), None, "{refusal}");
        }
    }

    #[test]
    fn a_non_participant_sender_reports_what_the_server_would() {
        // The one roster refusal that is not local-only. A send from a
        // principal who is not a participant is refused server-side as
        // NotParticipant, so the pre-check speaks the same vocabulary rather
        // than inventing a second description of one condition — this module's
        // standing rule, applied to the case where it actually applies.
        assert_eq!(
            TrafficRefusal::SenderNotAParticipant { sender: did(ALICE) }.endpoint_code(),
            Some(ChatErrorCode::NotParticipant)
        );
    }

    #[test]
    fn an_active_zero_leaf_peer_is_not_ready_rather_than_not_accepted() {
        // The distinction that matters to a user. Reporting "not accepted" for
        // a recovery gap would say their peer ignored them, which is wrong and
        // unkind.
        let participants = [ready(ALICE), presence(BOB, ParticipantStatus::Active, 0)];
        assert_eq!(
            direct(&participants),
            Err(TrafficRefusal::RecipientNotReady { did: did(BOB) })
        );
    }

    #[test]
    fn the_two_direct_refusals_carry_the_endpoint_codes_the_server_uses() {
        // A local pre-check and the server's answer must speak one vocabulary,
        // or the two drift into different descriptions of one condition.
        assert_eq!(
            TrafficRefusal::ConversationNotAccepted { did: did(BOB) }.endpoint_code(),
            Some(ChatErrorCode::ConversationNotAccepted)
        );
        assert_eq!(
            TrafficRefusal::RecipientNotReady { did: did(BOB) }.endpoint_code(),
            Some(ChatErrorCode::RecipientNotReady)
        );
    }

    #[test]
    fn pending_is_reported_ahead_of_zero_leaf() {
        // Both apply to a pending invitee, since pending implies no leaf. The
        // more accurate and more actionable answer wins.
        let participants = [
            presence(ALICE, ParticipantStatus::Active, 0),
            presence(BOB, ParticipantStatus::Pending, 0),
        ];
        assert_eq!(
            direct(&participants),
            Err(TrafficRefusal::ConversationNotAccepted { did: did(BOB) })
        );
    }

    #[test]
    fn a_direct_needs_both_sides_not_just_the_sender() {
        // Being ready oneself is not the condition.
        for unready in [
            presence(BOB, ParticipantStatus::Pending, 0),
            presence(BOB, ParticipantStatus::Active, 0),
        ] {
            assert!(direct(&[ready(ALICE), unready]).is_err());
        }
    }

    // ---- group -------------------------------------------------------------

    #[test]
    fn group_traffic_continues_for_remaining_leaves() {
        // The asymmetry, and the reason for it: applying the direct rule here
        // would silence a whole conversation because one member is mid-recovery.
        // The roster is a legal direct roster — two distinct participants, one
        // of them the sender — so the two answers differ on *readiness* and not
        // on cardinality, which is what makes this a genuine asymmetry.
        let participants = [ready(ALICE), presence(BOB, ParticipantStatus::Active, 0)];
        assert_eq!(
            group(&participants),
            Ok(()),
            "a group tolerates unready members that a direct does not"
        );
        assert_eq!(
            direct(&participants),
            Err(TrafficRefusal::RecipientNotReady { did: did(BOB) }),
            "the identical roster, refused as a direct, and for the readiness reason"
        );

        // A group is also unbothered by a member count no direct could have.
        assert_eq!(
            group(&[
                ready(ALICE),
                presence(BOB, ParticipantStatus::Active, 0),
                presence(CAROL, ParticipantStatus::Pending, 0),
            ]),
            Ok(())
        );
    }

    #[test]
    fn a_group_with_no_current_leaves_is_refused() {
        // "Remaining leaves" needs at least one. Sending into a group nobody
        // can decrypt stores ciphertext no one will ever read.
        let participants = [
            presence(ALICE, ParticipantStatus::Active, 0),
            presence(BOB, ParticipantStatus::Pending, 0),
        ];
        assert_eq!(group(&participants), Err(TrafficRefusal::NoCurrentLeaves));
        assert_eq!(group(&[]), Err(TrafficRefusal::NoCurrentLeaves));
    }

    #[test]
    fn a_pending_member_alone_does_not_make_a_group_sendable() {
        assert_eq!(
            group(&[presence(ALICE, ParticipantStatus::Pending, 1)]),
            Err(TrafficRefusal::NoCurrentLeaves),
            "a leaf without acceptance is not a ready participant"
        );
    }

    // ---- pending invite before Add --------------------------------------------

    #[test]
    fn a_pending_invitee_may_not_be_added() {
        // Acceptance is what CREATES the add-kind request, so an Add before it
        // has nothing to refine — this is not merely an ordering preference.
        let pending = presence(BOB, ParticipantStatus::Pending, 0);
        assert_eq!(
            require_accepted_before_add(&pending),
            Err(AddRefusal::NotAccepted { did: did(BOB) })
        );
        assert!(
            require_accepted_before_add(&pending)
                .unwrap_err()
                .to_string()
                .contains("acceptance is what creates the add request"),
            "the refusal must say why, not just that"
        );
    }

    #[test]
    fn an_accepted_participant_may_be_added() {
        assert_eq!(
            require_accepted_before_add(&presence(BOB, ParticipantStatus::Active, 0)),
            Ok(()),
            "an active participant with no leaf yet is exactly who an Add is for"
        );
    }

    #[test]
    fn acceptance_changes_only_status_not_readiness() {
        // §4: "acceptance changes only status to active". A freshly accepted
        // participant still has no leaf, which is precisely the active
        // zero-leaf state that reports RecipientNotReady rather than
        // ConversationNotAccepted.
        let freshly_accepted = presence(BOB, ParticipantStatus::Active, 0);
        assert!(!freshly_accepted.is_ready());
        assert_eq!(
            require_accepted_before_add(&freshly_accepted),
            Ok(()),
            "accepted, so addable"
        );
        assert_eq!(
            direct(&[ready(ALICE), freshly_accepted]),
            Err(TrafficRefusal::RecipientNotReady { did: did(BOB) }),
            "but not yet sendable, and for the leaf reason"
        );
    }

    #[test]
    fn readiness_requires_both_facts() {
        assert!(ready(ALICE).is_ready());
        assert!(!presence(ALICE, ParticipantStatus::Active, 0).is_ready());
        assert!(!presence(ALICE, ParticipantStatus::Pending, 1).is_ready());
        assert!(!presence(ALICE, ParticipantStatus::Pending, 0).is_ready());
    }
}
