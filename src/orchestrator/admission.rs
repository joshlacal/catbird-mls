//! Authenticated admission policy is distinct from cryptographic MLS access.
use catbird_atproto::blue_catbird::chat::ConversationState as CanonicalState;
use serde::{Deserialize, Serialize};

use super::{
    ConversationView, CredentialStore, MLSAPIClient, MLSOrchestrator, MLSStorageBackend,
    MlsCryptoContext, OrchestratorError, Result,
};

fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(format!("Invalid conversation policy: {message}"))
}

/// Validate policy semantics after the schema codec has preserved its fields.
/// No value here establishes cryptographic group membership.
pub fn validate_conversation_policy(state: &CanonicalState) -> Result<()> {
    use crate::chat_v2::ids::{BareDid, CanonicalUuid, MAX_SAFE_INTEGER};
    let coordinate = &state.coordinates;
    CanonicalUuid::parse(coordinate.conversation_id.as_str())
        .map_err(|_| invalid("conversation ID"))?;
    for number in [
        coordinate.epoch,
        coordinate.generation,
        coordinate.state_version,
        state.snapshot_seq,
    ] {
        if number < 0 || number > MAX_SAFE_INTEGER {
            return Err(invalid("coordinate range"));
        }
    }
    if coordinate.group_id.len() != 32
        || coordinate.group_context_hash.len() != 32
        || coordinate.confirmation_tag.len() != 32
        || !matches!(coordinate.lifecycle.as_str(), "active" | "superseded")
        || !matches!(state.conversation_kind.as_str(), "direct" | "group")
    {
        return Err(invalid("coordinate or conversation kind"));
    }
    let mut participants = std::collections::HashSet::new();
    for participant in &state.participants {
        BareDid::parse(participant.user_did.as_str()).map_err(|_| invalid("participant DID"))?;
        if !participants.insert(participant.user_did.to_string())
            || !matches!(participant.role.as_str(), "admin" | "member")
            || !matches!(participant.status.as_str(), "active" | "pending")
            || !(0..=20).contains(&participant.leaf_count)
        {
            return Err(invalid("participant status, role, or duplicate"));
        }
        if participant.status.as_str() == "pending"
            && (participant.leaf_count != 0 || participant.invitation_provenance.is_none())
        {
            return Err(invalid("pending participant lacks invitation provenance"));
        }
        if let Some(provenance) = &participant.invitation_provenance {
            CanonicalUuid::parse(provenance.invitation_transition_id.as_str())
                .map_err(|_| invalid("invitation transition"))?;
            CanonicalUuid::parse(provenance.invited_by_device_id.as_str())
                .map_err(|_| invalid("inviter device"))?;
            BareDid::parse(provenance.invited_by_did.as_str())
                .map_err(|_| invalid("inviter DID"))?;
        }
    }
    Ok(())
}

pub fn validate_conversation_view(view: &ConversationView) -> Result<()> {
    if let Some(state) = &view.canonical_state {
        super::canonical_transport::encode_conversation_state(state)
            .map_err(|error| invalid(&error.to_string()))?;
        if state.coordinates.conversation_id.as_str() != view.conversation_id
            || hex::encode(&state.coordinates.group_id) != view.group_id
            || state.coordinates.epoch as u64 > view.epoch
        {
            return Err(invalid(
                "snapshot does not match conversation identity/epoch",
            ));
        }
    }
    Ok(())
}

/// Compare complete policies. Snapshot sequence alone can advance when an
/// application entry is appended without changing the policy coordinate.
fn incoming_is_newer(previous: &CanonicalState, incoming: &CanonicalState) -> Result<bool> {
    let old = &previous.coordinates;
    let new = &incoming.coordinates;
    if old.conversation_id != new.conversation_id {
        return Err(invalid("different conversation"));
    }
    let old_version = (old.generation, old.state_version);
    let new_version = (new.generation, new.state_version);
    if new_version < old_version {
        return Ok(false);
    }
    if new.generation == old.generation && new.group_id != old.group_id {
        return Err(invalid("group changed within a generation"));
    }
    if new_version == old_version {
        let mut comparable = incoming.clone();
        comparable.snapshot_seq = previous.snapshot_seq;
        let mut revoked_overlay = false;
        for (old_leaf, new_leaf) in previous.leaves.iter().zip(&mut comparable.leaves) {
            if old_leaf.device_status.as_str() == "active"
                && new_leaf.device_status.as_str() == "revoked"
            {
                new_leaf.device_status = old_leaf.device_status.clone();
                revoked_overlay = true;
            }
        }
        if &comparable != previous {
            return Err(invalid("conflicting policy at the same coordinate"));
        }
        return Ok(incoming.snapshot_seq > previous.snapshot_seq || revoked_overlay);
    }
    if new.generation == old.generation && new.epoch < old.epoch {
        return Err(invalid("epoch regressed within a generation"));
    }
    if incoming.snapshot_seq < previous.snapshot_seq {
        return Err(invalid("snapshot sequence regressed"));
    }
    Ok(true)
}

fn retain_revoked_leaf_status(previous: &CanonicalState, incoming: &mut CanonicalState) {
    for leaf in &mut incoming.leaves {
        if previous.leaves.iter().any(|old| {
            old.user_did == leaf.user_did
                && old.device_id == leaf.device_id
                && old.key_id == leaf.key_id
                && old.device_status.as_str() == "revoked"
        }) {
            leaf.device_status = "revoked".into();
        }
    }
    if previous.coordinates == incoming.coordinates {
        incoming.snapshot_seq = incoming.snapshot_seq.max(previous.snapshot_seq);
    }
}

/// Merge policy-bearing rows without inventing admission for legacy None.
pub fn merge_conversation_view(
    previous: Option<&ConversationView>,
    mut incoming: ConversationView,
) -> Result<ConversationView> {
    validate_conversation_view(&incoming)?;
    let Some(previous) = previous else {
        return Ok(incoming);
    };
    validate_conversation_view(previous)?;
    if previous.conversation_id != incoming.conversation_id {
        return Err(invalid("different view identity"));
    }
    if let (Some(old), Some(new)) = (&previous.canonical_state, &mut incoming.canonical_state) {
        retain_revoked_leaf_status(old, new);
    }
    match (&previous.canonical_state, &incoming.canonical_state) {
        (Some(old), Some(new)) if !incoming_is_newer(old, new)? => {
            let mut retained = previous.clone();
            if incoming.group_id == retained.group_id {
                retained.epoch = retained.epoch.max(incoming.epoch);
            }
            Ok(retained)
        }
        (Some(old), None) => {
            if previous.group_id != incoming.group_id {
                return Ok(previous.clone());
            }
            incoming.canonical_state = Some(old.clone());
            incoming.epoch = incoming.epoch.max(previous.epoch);
            Ok(incoming)
        }
        _ => Ok(incoming),
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Merge the native durable policy before any recovery/display decision.
    pub(crate) fn restore_conversation_policy(
        &self,
        user_did: &str,
        mut view: ConversationView,
    ) -> Result<ConversationView> {
        validate_conversation_view(&view)?;
        // Legacy host-only rows have no canonical policy namespace. A typed
        // snapshot always takes the strict path above and cannot use this.
        if view.canonical_state.is_none()
            && (crate::chat_v2::ids::BareDid::parse(user_did).is_err()
                || crate::chat_v2::ids::CanonicalUuid::parse(&view.conversation_id).is_err())
        {
            return Ok(view);
        }
        if let Some(incoming) = &view.canonical_state {
            self.mls_context()
                .put_conversation_policy(user_did, incoming)?;
        }
        if let Some(retained) = self
            .mls_context()
            .get_conversation_policy(user_did, &view.conversation_id)?
        {
            // A policy from a different group must not overwrite a verified
            // local successor. Its generation fence remains in native storage.
            if hex::encode(&retained.coordinates.group_id) == view.group_id {
                view.epoch = view.epoch.max(retained.coordinates.epoch as u64);
                view.members = retained
                    .participants
                    .iter()
                    .map(|member| super::MemberView {
                        did: member.user_did.to_string(),
                        role: if member.role.as_str() == "admin" {
                            super::MemberRole::Admin
                        } else {
                            super::MemberRole::Member
                        },
                    })
                    .collect();
                view.canonical_state = Some(retained);
            } else if view.canonical_state.is_some() {
                // An old inventory generation must not revive its old group
                // after a newer authenticated generation was retained.
                view.group_id = hex::encode(&retained.coordinates.group_id);
                view.epoch = retained.coordinates.epoch as u64;
                view.members = retained
                    .participants
                    .iter()
                    .map(|member| super::MemberView {
                        did: member.user_did.to_string(),
                        role: if member.role.as_str() == "admin" {
                            super::MemberRole::Admin
                        } else {
                            super::MemberRole::Member
                        },
                    })
                    .collect();
                view.canonical_state = Some(retained);
            }
        }
        Ok(view)
    }

    /// Retain a complete authenticated point-read, never synthetic coordinates.
    pub(crate) async fn retain_conversation_policy_json(
        &self,
        conversation_id: &str,
        value: &serde_json::Value,
    ) -> Result<()> {
        let raw = serde_json::to_vec(value).map_err(|error| invalid(&error.to_string()))?;
        let state = super::canonical_transport::decode_conversation_state(&raw)
            .map_err(|error| invalid(&error.to_string()))?;
        if state.coordinates.conversation_id.as_str() != conversation_id {
            return Err(invalid("point-read conversation mismatch"));
        }
        let did = self.require_user_did().await?;
        self.mls_context().put_conversation_policy(&did, &state)?;
        let previous = self
            .conversations()
            .lock()
            .await
            .get(conversation_id)
            .cloned();
        if let Some(mut view) = previous {
            if hex::encode(&state.coordinates.group_id) == view.group_id {
                view.epoch = view.epoch.max(state.coordinates.epoch as u64);
                view.canonical_state = Some(state);
                let view = self.restore_conversation_policy(&did, view)?;
                self.conversations()
                    .lock()
                    .await
                    .insert(conversation_id.into(), view);
            }
        }
        Ok(())
    }

    pub(crate) async fn refresh_conversation_policy(&self, conversation_id: &str) -> Result<()> {
        let response = self.fetch_conversation_lifecycle(conversation_id).await?;
        self.retain_conversation_policy_json(conversation_id, &response["state"])
            .await
    }

    /// The caller has authenticated the exact terminal signed entry and its
    /// native removal (or retained exact accepted account-exit response).
    pub(crate) async fn retain_verified_departure_coordinate(
        &self,
        conversation_id: &str,
        value: &serde_json::Value,
    ) -> Result<()> {
        let coordinate = super::canonical_transport::decode_conversation_coordinates(
            &serde_json::to_vec(value).map_err(|error| invalid(&error.to_string()))?,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        if coordinate.conversation_id.as_str() != conversation_id {
            return Err(invalid("departure conversation mismatch"));
        }
        let did = self.require_user_did().await?;
        self.mls_context()
            .put_conversation_departure(&did, &coordinate)?;
        Ok(())
    }

    pub(crate) async fn is_pending_invitation_after_departure(
        &self,
        user_did: &str,
        view: &ConversationView,
    ) -> Result<bool> {
        validate_conversation_view(view)?;
        let Some(state) = &view.canonical_state else {
            return Ok(false);
        };
        if state.coordinates.lifecycle.as_str() != "active"
            || !state
                .participants
                .iter()
                .any(|p| p.user_did.as_str() == user_did && p.status.as_str() == "pending")
        {
            return Ok(false);
        }
        // V3 already retains exact accepted exit proof. Hydrate its anchor on
        // first V4 display, even when the old exit was locally completed.
        let actor_device = self.require_actor_device_id().await?;
        for record in self.mls_context().list_account_exits()? {
            if record.accepted_response.is_none() {
                continue;
            }
            record.validate()?;
            let wrapper = record.wrapper()?;
            let body = &wrapper["signedRequest"]["body"];
            if body["actorDid"] != user_did
                || body["actorDeviceId"] != actor_device
                || body["prior"]["conversationId"] != view.conversation_id
            {
                continue;
            }
            let key = if body["$type"] == "blue.catbird.chat.defs#conversationCloseBody" {
                "retired"
            } else {
                "next"
            };
            self.retain_verified_departure_coordinate(&view.conversation_id, &body[key])
                .await?;
        }
        let Some(departure) = self
            .mls_context()
            .get_conversation_departure(user_did, &view.conversation_id)?
        else {
            return Ok(false);
        };
        let current = &state.coordinates;
        Ok(departure.lifecycle.as_str() == "active"
            && departure.group_id == current.group_id
            && departure.generation == current.generation
            && current.epoch >= departure.epoch
            && current.state_version > departure.state_version)
    }

    pub(crate) async fn pending_conversation_admission(
        &self,
        conversation_id: &str,
    ) -> Result<bool> {
        let did = self.require_user_did().await?;
        let runtime = self
            .conversations()
            .lock()
            .await
            .get(conversation_id)
            .cloned();
        let stored = self
            .storage()
            .get_conversation(&did, conversation_id)
            .await?;
        let Some(view) = runtime.or(stored) else {
            return Ok(false);
        };
        let view = self.restore_conversation_policy(&did, view)?;
        // An unknown host group mapping cannot erase retained pending consent.
        // Keep the immutable old policy separate from a possible successor
        // view until native membership or a new canonical policy proves it.
        let retained = if view.canonical_state.is_none()
            && crate::chat_v2::ids::CanonicalUuid::parse(conversation_id).is_ok()
            && crate::chat_v2::ids::BareDid::parse(&did).is_ok()
        {
            self.mls_context()
                .get_conversation_policy(&did, conversation_id)?
        } else {
            None
        };
        let Some(state) = view.canonical_state.as_ref().or(retained.as_ref()) else {
            return Ok(false);
        };
        let pending = state.participants.iter().any(|participant| {
            participant.user_did.as_str() == did && participant.status.as_str() == "pending"
        });
        if !pending {
            return Ok(false);
        }
        let group = state.coordinates.group_id.to_vec();
        let native_admitted = match self.mls_context().group_is_active(group.clone()) {
            Ok(true)
                if self.mls_context().get_epoch(group.clone())?
                    > state.coordinates.epoch as u64 =>
            {
                let own = self.require_scoped_identity().await?;
                self.mls_context()
                    .group_member_identities(group.clone())?
                    .iter()
                    .any(|identity| identity == own.as_bytes())
            }
            Ok(_) | Err(crate::error::MLSError::GroupNotFound { .. }) => false,
            Err(error) => return Err(error.into()),
        };
        if !native_admitted && view.group_id != hex::encode(&group) {
            let identity = self.require_scoped_identity().await?;
            let successor =
                hex::decode(&view.group_id).map_err(|_| invalid("successor group encoding"))?;
            // Only a native atomic Welcome receipt binds an otherwise unknown
            // successor group to this exact CID/device; cosmetic host mapping
            // or an unrelated active group cannot establish that relation.
            let receipt = self
                .mls_context()
                .list_welcome_acceptances()?
                .into_iter()
                .any(|receipt| {
                    receipt.delivery.conversation_id() == conversation_id
                        && receipt.delivery.recipient_identity() == identity
                        && receipt.delivery.group_id().ok().as_ref() == Some(&successor)
                });
            if receipt
                && self.mls_context().group_is_active(successor.clone())?
                && self
                    .mls_context()
                    .group_member_identities(successor)?
                    .iter()
                    .any(|member| member.as_slice() == identity.as_bytes())
            {
                return Ok(false);
            }
        }
        Ok(!native_admitted)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native {
    use super::*;
    use crate::{error::MLSError, mls_context::ManifestStorage};
    use rusqlite::{OptionalExtension, TransactionBehavior};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PolicyRecord {
        user_did: String,
        state: CanonicalState,
    }
    fn failed<E>(_: E) -> MLSError {
        MLSError::StorageFailed
    }
    fn key(user_did: &str, cid: &str) -> std::result::Result<String, MLSError> {
        crate::chat_v2::ids::BareDid::parse(user_did).map_err(failed)?;
        crate::chat_v2::ids::CanonicalUuid::parse(cid).map_err(failed)?;
        Ok(format!("conversation_policy_v1:{user_did}:{cid}"))
    }
    fn decode(
        raw: &str,
        user_did: &str,
        cid: &str,
    ) -> std::result::Result<CanonicalState, MLSError> {
        let record: PolicyRecord = serde_json::from_str(raw).map_err(failed)?;
        if record.user_did != user_did || record.state.coordinates.conversation_id.as_str() != cid {
            return Err(MLSError::StorageFailed);
        }
        validate_conversation_policy(&record.state).map_err(failed)?;
        Ok(record.state)
    }
    pub(crate) fn get(
        storage: &ManifestStorage,
        user_did: &str,
        cid: &str,
    ) -> std::result::Result<Option<CanonicalState>, MLSError> {
        let key = key(user_did, cid)?;
        let raw: Option<String> = storage
            .welcome_ack_connection()
            .query_row(
                "SELECT value FROM mls_manifests WHERE key = ?1",
                [&key],
                |row| row.get(0),
            )
            .optional()
            .map_err(failed)?;
        raw.map(|raw| decode(&raw, user_did, cid)).transpose()
    }
    pub(crate) fn put(
        storage: &ManifestStorage,
        user_did: &str,
        state: &CanonicalState,
    ) -> std::result::Result<bool, MLSError> {
        let canonical =
            super::super::canonical_transport::encode_conversation_state(state).map_err(failed)?;
        let mut normalized =
            super::super::canonical_transport::decode_conversation_state(&canonical)
                .map_err(failed)?;
        let state = &mut normalized;
        let cid = state.coordinates.conversation_id.to_string();
        let key = key(user_did, &cid)?;
        let tx = rusqlite::Transaction::new_unchecked(
            storage.welcome_ack_connection(),
            TransactionBehavior::Immediate,
        )
        .map_err(failed)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM mls_manifests WHERE key = ?1",
                [&key],
                |row| row.get(0),
            )
            .optional()
            .map_err(failed)?;
        if let Some(raw) = raw {
            let previous = decode(&raw, user_did, &cid)?;
            retain_revoked_leaf_status(&previous, state);
            if !incoming_is_newer(&previous, state).map_err(failed)? {
                return Ok(false);
            }
        }
        let raw = serde_json::to_string(&PolicyRecord {
            user_did: user_did.into(),
            state: state.clone(),
        })
        .map_err(failed)?;
        tx.execute("INSERT INTO mls_manifests (key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", rusqlite::params![key,raw]).map_err(failed)?;
        tx.commit().map_err(failed)?;
        storage.flush_database()?;
        Ok(true)
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DepartureRecord {
        user_did: String,
        coordinate: catbird_atproto::blue_catbird::chat::ConversationCoordinates,
    }
    fn departure_key(user_did: &str, cid: &str) -> std::result::Result<String, MLSError> {
        Ok(format!("{}:departure", key(user_did, cid)?))
    }
    fn departure_record(
        raw: &str,
        user_did: &str,
        cid: &str,
    ) -> std::result::Result<catbird_atproto::blue_catbird::chat::ConversationCoordinates, MLSError>
    {
        let record: DepartureRecord = serde_json::from_str(raw).map_err(failed)?;
        if record.user_did != user_did || record.coordinate.conversation_id.as_str() != cid {
            return Err(MLSError::StorageFailed);
        }
        super::super::canonical_transport::decode_conversation_coordinates(
            &serde_json::to_vec(&record.coordinate).map_err(failed)?,
        )
        .map_err(failed)
    }
    pub(crate) fn get_departure(
        storage: &ManifestStorage,
        user_did: &str,
        cid: &str,
    ) -> std::result::Result<
        Option<catbird_atproto::blue_catbird::chat::ConversationCoordinates>,
        MLSError,
    > {
        let key = departure_key(user_did, cid)?;
        let raw: Option<String> = storage
            .welcome_ack_connection()
            .query_row(
                "SELECT value FROM mls_manifests WHERE key=?1",
                [&key],
                |row| row.get(0),
            )
            .optional()
            .map_err(failed)?;
        raw.map(|raw| departure_record(&raw, user_did, cid))
            .transpose()
    }
    pub(crate) fn put_departure(
        storage: &ManifestStorage,
        user_did: &str,
        coordinate: &catbird_atproto::blue_catbird::chat::ConversationCoordinates,
    ) -> std::result::Result<bool, MLSError> {
        let coordinate = super::super::canonical_transport::decode_conversation_coordinates(
            &serde_json::to_vec(coordinate).map_err(failed)?,
        )
        .map_err(failed)?;
        let cid = coordinate.conversation_id.as_str();
        let key = departure_key(user_did, cid)?;
        let tx = rusqlite::Transaction::new_unchecked(
            storage.welcome_ack_connection(),
            TransactionBehavior::Immediate,
        )
        .map_err(failed)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT value FROM mls_manifests WHERE key=?1",
                [&key],
                |row| row.get(0),
            )
            .optional()
            .map_err(failed)?;
        if let Some(old) = old {
            let old = departure_record(&old, user_did, cid)?;
            let old_version = (old.generation, old.state_version);
            let new_version = (coordinate.generation, coordinate.state_version);
            if new_version < old_version {
                return Ok(false);
            }
            if new_version == old_version {
                return if old == coordinate {
                    Ok(false)
                } else {
                    Err(MLSError::StorageFailed)
                };
            }
            if old.lifecycle.as_str() == "superseded"
                || (old.generation == coordinate.generation
                    && (old.group_id != coordinate.group_id || coordinate.epoch < old.epoch))
            {
                return Err(MLSError::StorageFailed);
            }
        }
        let raw = serde_json::to_string(&DepartureRecord {
            user_did: user_did.into(),
            coordinate,
        })
        .map_err(failed)?;
        tx.execute("INSERT INTO mls_manifests(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", rusqlite::params![key,raw]).map_err(failed)?;
        tx.commit().map_err(failed)?;
        storage.flush_database()?;
        Ok(true)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::super::canonical_transport::{
        decode_conversation_state, decode_conversations_inventory, encode_conversation_state,
    };
    use super::*;
    const SWIFT: &[u8] =
        include_bytes!("../../tests/fixtures/swift_pending_conversation_state.json");
    struct Keys;
    #[async_trait::async_trait]
    impl crate::KeychainAccess for Keys {
        async fn read(&self, _: String) -> std::result::Result<Option<Vec<u8>>, crate::MLSError> {
            Ok(None)
        }
        async fn write(&self, _: String, _: Vec<u8>) -> std::result::Result<(), crate::MLSError> {
            Ok(())
        }
        async fn delete(&self, _: String) -> std::result::Result<(), crate::MLSError> {
            Ok(())
        }
    }
    fn policy() -> CanonicalState {
        decode_conversation_state(SWIFT)
            .expect("actual Swift generated DTO must satisfy canonical schema")
    }

    #[test]
    fn actual_swift_policy_round_trips_through_canonical_codec() {
        let state = policy();
        assert_eq!(state.participants[1].status.as_str(), "pending");
        let encoded = encode_conversation_state(&state).unwrap();
        assert_eq!(decode_conversation_state(&encoded).unwrap(), state);
        // Export for the independent Swift generated-type decode proof.
        if let Ok(path) = std::env::var("CATBIRD_POLICY_ROUNDTRIP_OUTPUT") {
            std::fs::write(path, encoded).unwrap();
        }
        let mut wrong: serde_json::Value = serde_json::from_slice(SWIFT).unwrap();
        wrong["participants"][1]["$type"] =
            serde_json::json!("blue.catbird.chat.defs#deviceLeafView");
        assert!(decode_conversation_state(&serde_json::to_vec(&wrong).unwrap()).is_err());
    }

    #[test]
    fn inventory_codec_preserves_policy_and_all_snapshot_fields() {
        let state = policy();
        let wire: serde_json::Value = serde_json::from_slice(SWIFT).unwrap();
        let value = serde_json::json!({
            "items":[{"$type":"blue.catbird.chat.defs#conversationInventoryState","state":wire}],
            "hasMore":false,"inventorySessionId":"650e8400-e29b-41d4-a716-446655440000",
            "snapshotEventCursor":"opaque-event-cursor", "snapshotExpiresAt":"2026-09-05T12:00:00.000Z"
        });
        let output = decode_conversations_inventory(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!output.has_more);
        assert_eq!(output.snapshot_event_cursor.as_str(), "opaque-event-cursor");
        let catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(item) = &output.items[0] else { panic!("state variant changed"); };
        assert_eq!(item.state, state);
    }

    #[test]
    fn native_policy_is_monotonic_account_scoped_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("policy.sqlite")
            .to_string_lossy()
            .into_owned();
        let state = policy();
        let did = state.participants[1].user_did.as_str();
        let cid = state.coordinates.conversation_id.as_str();
        let context =
            crate::MLSContext::new(path.clone(), "policy-test-key".into(), Box::new(Keys)).unwrap();
        assert!(context.put_conversation_policy(did, &state).unwrap());
        let mut snapshot = state.clone();
        snapshot.snapshot_seq += 1;
        assert!(context.put_conversation_policy(did, &snapshot).unwrap());
        assert!(!context.put_conversation_policy(did, &state).unwrap());
        let mut conflict = snapshot.clone();
        conflict.participants[1].status = "active".into();
        assert!(context.put_conversation_policy(did, &conflict).is_err());
        conflict.coordinates.state_version += 1;
        assert!(context.put_conversation_policy(did, &conflict).unwrap());
        assert!(!context.put_conversation_policy(did, &snapshot).unwrap());
        let mut revoked = conflict.clone();
        revoked.leaves[0].device_status = "revoked".into();
        assert!(context.put_conversation_policy(did, &revoked).unwrap());
        let mut stale_active = conflict.clone();
        stale_active.snapshot_seq += 1;
        assert!(context.put_conversation_policy(did, &stale_active).unwrap());
        revoked.snapshot_seq = stale_active.snapshot_seq;
        assert_eq!(
            context.get_conversation_policy(did, cid).unwrap(),
            Some(revoked.clone())
        );
        assert!(!context.put_conversation_policy(did, &conflict).unwrap());
        conflict.snapshot_seq = stale_active.snapshot_seq;
        assert!(!context.put_conversation_policy(did, &conflict).unwrap());
        assert!(context
            .get_conversation_policy(state.participants[0].user_did.as_str(), cid)
            .unwrap()
            .is_none());
        drop(context);
        let context =
            crate::MLSContext::new(path, "policy-test-key".into(), Box::new(Keys)).unwrap();
        assert_eq!(
            context.get_conversation_policy(did, cid).unwrap(),
            Some(revoked)
        );
    }

    #[test]
    fn departure_anchor_is_exact_monotonic_account_scoped_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("departure.sqlite")
            .to_string_lossy()
            .into_owned();
        let policy = policy();
        let did = policy.participants[1].user_did.as_str();
        let cid = policy.coordinates.conversation_id.as_str();
        let context =
            crate::MLSContext::new(path.clone(), "departure-test-key".into(), Box::new(Keys))
                .unwrap();
        let mut coordinate = policy.coordinates.clone();
        assert!(context
            .put_conversation_departure(did, &coordinate)
            .unwrap());
        assert!(!context
            .put_conversation_departure(did, &coordinate)
            .unwrap());
        let old = coordinate.clone();
        coordinate.state_version += 1;
        assert!(context
            .put_conversation_departure(did, &coordinate)
            .unwrap());
        assert!(!context.put_conversation_departure(did, &old).unwrap());
        let mut conflict = coordinate.clone();
        conflict.confirmation_tag = vec![9; 32].into();
        assert!(context.put_conversation_departure(did, &conflict).is_err());
        conflict = coordinate.clone();
        conflict.state_version += 1;
        conflict.group_id = vec![8; 32].into();
        assert!(context.put_conversation_departure(did, &conflict).is_err());
        assert!(context
            .get_conversation_departure(policy.participants[0].user_did.as_str(), cid)
            .unwrap()
            .is_none());
        drop(context);
        let context =
            crate::MLSContext::new(path, "departure-test-key".into(), Box::new(Keys)).unwrap();
        assert_eq!(
            context.get_conversation_departure(did, cid).unwrap(),
            Some(coordinate.clone())
        );
        coordinate.lifecycle = "superseded".into();
        coordinate.state_version += 1;
        assert!(context
            .put_conversation_departure(did, &coordinate)
            .unwrap());
        coordinate.lifecycle = "active".into();
        coordinate.state_version += 1;
        assert!(context
            .put_conversation_departure(did, &coordinate)
            .is_err());
    }
}
