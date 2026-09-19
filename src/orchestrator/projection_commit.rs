//! Host projection claims for an atomic, account-scoped alias retirement.
//!
//! These records capture a caller's observed coordinates. They do not establish
//! cryptographic authority. The storage adapter must recheck every owner,
//! identity, incarnation and lifecycle fence in the same transaction as its
//! writes, preserve message history, and reject unsupported fence dimensions.

use super::error::{OrchestratorError, Result};
use super::types::ConversationView;
use crate::chat_v2::ids::uuid::CanonicalUuid;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionLifecycleFence {
    /// Canonical protocol generation, never MLS epoch or a reset counter.
    pub generation: Option<i64>,
    pub state_version: Option<i64>,
    pub reset_generation: Option<i32>,
    pub reset_pending_target_group_id: Option<String>,
}

impl ProjectionLifecycleFence {
    pub fn is_unknown(&self) -> bool {
        self.generation.is_none()
            && self.state_version.is_none()
            && self.reset_generation.is_none()
            && self.reset_pending_target_group_id.is_none()
    }

    fn from_view(view: &ConversationView) -> Self {
        match &view.canonical_state {
            Some(state) => Self {
                generation: Some(state.coordinates.generation),
                state_version: Some(state.coordinates.state_version),
                // ConversationView has no host reset-counter/target fields.
                // Their absence must not be filled from a different coordinate.
                ..Self::default()
            },
            None => Self::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationProjectionCommitMode {
    Live,
    Replay,
}

/// Exact alias-retirement claim. Storage must validate it against durable rows;
/// constructing this value alone cannot authorize retiring an alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRetirementAuthority {
    pub owner_user_did: String,
    pub canonical_conversation_id: String,
    pub canonical_group_id: String,
    pub alias_conversation_id: String,
    pub alias_group_id: String,
    /// Observed native group incarnation used by the existing browser adapter.
    pub canonical_incarnation: u64,
    pub alias_incarnation: u64,
    pub canonical_lifecycle: ProjectionLifecycleFence,
    pub alias_lifecycle: ProjectionLifecycleFence,
}

impl AliasRetirementAuthority {
    pub fn from_views(
        owner: &str,
        canonical: &ConversationView,
        alias: &ConversationView,
    ) -> Result<Self> {
        if owner.is_empty()
            || CanonicalUuid::parse(&canonical.conversation_id).is_err()
            || canonical.group_id.is_empty()
            || canonical.group_id != alias.group_id
            || alias.conversation_id != alias.group_id
            || canonical.conversation_id == alias.conversation_id
            || CanonicalUuid::parse(&alias.conversation_id).is_ok()
        {
            return Err(OrchestratorError::InvalidInput(
                "alias retirement requires one owner and an exact canonical/alias identity pair"
                    .into(),
            ));
        }
        Ok(Self {
            owner_user_did: owner.into(),
            canonical_conversation_id: canonical.conversation_id.clone(),
            canonical_group_id: canonical.group_id.clone(),
            alias_conversation_id: alias.conversation_id.clone(),
            alias_group_id: alias.group_id.clone(),
            canonical_incarnation: canonical.epoch,
            alias_incarnation: alias.epoch,
            canonical_lifecycle: ProjectionLifecycleFence::from_view(canonical),
            alias_lifecycle: ProjectionLifecycleFence::from_view(alias),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConversationProjectionCommitRequest {
    pub owner_user_did: String,
    pub mode: ConversationProjectionCommitMode,
    pub canonical: Option<ConversationView>,
    pub aliases: Vec<AliasRetirementAuthority>,
    pub canonical_lifecycle: ProjectionLifecycleFence,
}

impl ConversationProjectionCommitRequest {
    pub fn live(
        owner: &str,
        canonical: ConversationView,
        aliases: Vec<AliasRetirementAuthority>,
    ) -> Self {
        Self {
            owner_user_did: owner.into(),
            mode: ConversationProjectionCommitMode::Live,
            canonical_lifecycle: ProjectionLifecycleFence::from_view(&canonical),
            canonical: Some(canonical),
            aliases,
        }
    }

    pub fn replay(authority: AliasRetirementAuthority) -> Self {
        Self {
            owner_user_did: authority.owner_user_did.clone(),
            mode: ConversationProjectionCommitMode::Replay,
            canonical: None,
            canonical_lifecycle: authority.canonical_lifecycle.clone(),
            aliases: vec![authority],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationProjectionCommitOutcome {
    Retired {
        affected_rows: u32,
    },
    AlreadyAbsent {
        affected_rows: u32,
    },
    FenceMismatch {
        affected_rows: u32,
    },
    Ambiguous {
        canonical_ids: Vec<String>,
        affected_rows: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> ConversationView {
        ConversationView {
            conversation_id: "018f3f6a-7b2c-4d91-8a5e-0f123456789a".into(),
            group_id: "00112233445566778899aabbccddeeff".into(),
            epoch: 7,
            members: vec![],
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
            canonical_state: None,
        }
    }

    #[test]
    fn retirement_cannot_capture_a_different_group_or_stable_conversation() {
        let canonical = view();
        let mut alias = canonical.clone();
        alias.conversation_id = canonical.group_id.clone();
        assert!(AliasRetirementAuthority::from_views("did:plc:owner", &canonical, &alias).is_ok());
        alias.group_id = "ffeeddccbbaa99887766554433221100".into();
        assert!(AliasRetirementAuthority::from_views("did:plc:owner", &canonical, &alias).is_err());
        assert!(
            AliasRetirementAuthority::from_views("did:plc:owner", &canonical, &canonical).is_err()
        );
        alias.group_id = canonical.group_id.clone();
        assert!(AliasRetirementAuthority::from_views("", &canonical, &alias).is_err());
    }

    #[test]
    fn replay_keeps_exact_owner_incarnations_and_lifecycle_without_recreating_view() {
        let canonical = view();
        let mut alias = canonical.clone();
        alias.conversation_id = canonical.group_id.clone();
        alias.epoch = 6;
        let mut authority =
            AliasRetirementAuthority::from_views("did:plc:owner", &canonical, &alias).unwrap();
        authority.canonical_lifecycle.state_version = Some(9);
        authority.alias_lifecycle.reset_generation = Some(4);
        let replay = ConversationProjectionCommitRequest::replay(authority.clone());
        assert_eq!(replay.owner_user_did, "did:plc:owner");
        assert_eq!(replay.mode, ConversationProjectionCommitMode::Replay);
        assert!(replay.canonical.is_none());
        assert_eq!(replay.aliases, vec![authority]);
        assert_eq!(replay.canonical_lifecycle.state_version, Some(9));
        assert_eq!(replay.canonical_lifecycle.generation, None);
    }

    #[test]
    fn zero_coordinates_are_known_and_are_not_replaced_with_epoch() {
        let mut fence = ProjectionLifecycleFence::default();
        assert!(fence.is_unknown());
        fence.state_version = Some(0);
        assert!(!fence.is_unknown());
        let live = ConversationProjectionCommitRequest::live("did:plc:owner", view(), vec![]);
        assert!(live.canonical_lifecycle.is_unknown());
        assert_eq!(live.canonical.as_ref().unwrap().epoch, 7);
        assert_eq!(live.canonical_lifecycle.generation, None);
        assert_eq!(live.canonical_lifecycle.reset_generation, None);
    }
}
