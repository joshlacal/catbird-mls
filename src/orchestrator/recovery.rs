use std::collections::{BTreeSet, HashMap};
use std::time::Duration;
use web_time::Instant;

use crate::error::MLSError;
use base64::Engine;
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
use sha2::{Digest, Sha256};
use tls_codec::DeserializeBytes;

use super::api_client::MLSAPIClient;
use super::constants;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::{MLSOrchestrator, OwnCommitExpectation};
use super::pagination::PaginationGuard;
use super::storage::MLSStorageBackend;
use super::types::*;
use super::welcome_recovery::{
    classify_server_error, classify_welcome_processing_error, LastRecoveryError,
};

pub(crate) enum DeferredRecoveryOutcome {
    ClearedStale,
    Skipped,
    Recovered(u64),
}

fn credential_root_matches_exact(identity: &str, expected_root: &str) -> bool {
    super::credential_binding::credential_root_did(identity) == expected_root
}

pub(crate) fn advertised_group_id_from_group_info(group_info: &[u8]) -> Result<Vec<u8>> {
    crate::message_limits::validate_inbound_mls_message_len(group_info.len(), "group_info")?;
    let (message, remaining) = MlsMessageIn::tls_deserialize_bytes(group_info).map_err(|_| {
        OrchestratorError::InvalidInput("recovery GroupInfo is malformed".to_string())
    })?;
    if !remaining.is_empty() {
        return Err(OrchestratorError::InvalidInput(
            "recovery GroupInfo has trailing bytes".to_string(),
        ));
    }
    match message.extract() {
        MlsMessageBodyIn::GroupInfo(info) => Ok(info.group_id().as_slice().to_vec()),
        _ => Err(OrchestratorError::InvalidInput(
            "recovery payload is not GroupInfo".to_string(),
        )),
    }
}

/// Snapshot of a conversation's `ResetPending` payload for use inside the
/// recovery loop. Mirrors the variant on `ConversationState::ResetPending`
/// without dragging the full enum into call sites that only need to inspect
/// "are we mid-reset and what's the new id?". Read via
/// `MLSOrchestrator::reset_pending_payload`.
#[derive(Debug, Clone)]
pub(crate) struct ResetPendingPayload {
    pub new_group_id: String,
    pub reset_generation: i32,
    #[allow(dead_code)]
    pub notified_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LocalDeleteGroupFence {
    pub group_id_hex: String,
    pub epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LocalDeleteConversationFence {
    pub group_id: String,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LocalDeleteResetFence {
    pub new_group_id: String,
    pub reset_generation: i32,
}

#[derive(Debug, Clone)]
pub(crate) struct LocalDeleteSnapshot {
    pub groups: Vec<LocalDeleteGroupFence>,
    pub group_state_keys: Vec<String>,
    pub conversation: Option<LocalDeleteConversationFence>,
    pub reset: Option<LocalDeleteResetFence>,
}

const LOCAL_DELETE_AUTHORITY_MAGIC_V1: &[u8] = b"CBLD\x01";
const LOCAL_DELETE_AUTHORITY_MAGIC_V2: &[u8] = b"CBLD\x02";

/// Original owner-bound authority format. It did not carry enough lifecycle
/// state to distinguish an interrupted delete from a subsequently re-created
/// conversation that reused the same stable id.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PersistedLocalDeleteAuthorityV1 {
    owner_user_did: String,
    group_ids_hex: Vec<String>,
    group_state_keys: Vec<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PersistedLocalDeleteAuthorityV2 {
    owner_user_did: String,
    groups: Vec<LocalDeleteGroupFence>,
    group_state_keys: Vec<String>,
    conversation: Option<LocalDeleteConversationFence>,
    reset: Option<LocalDeleteResetFence>,
}

pub(crate) enum LocalDeleteAuthority {
    Versioned {
        owner_user_did: String,
        snapshot: LocalDeleteSnapshot,
    },
    /// Compatibility decoder for owner-bound intents written before lifecycle
    /// fences were added. Callers may perform only narrow orphan cleanup; this
    /// format cannot authorize deleting a live conversation mapping.
    VersionedV1 {
        owner_user_did: String,
        group_ids_hex: Vec<String>,
        group_state_keys: Vec<String>,
    },
    LegacyGroupId(String),
    LegacyUnbound,
}

impl LocalDeleteSnapshot {
    pub(crate) fn encode_authority(&self, owner_user_did: &str) -> Result<String> {
        let payload = PersistedLocalDeleteAuthorityV2 {
            owner_user_did: owner_user_did.to_string(),
            groups: self.groups.clone(),
            group_state_keys: self.group_state_keys.clone(),
            conversation: self.conversation.clone(),
            reset: self.reset.clone(),
        };
        let mut encoded = LOCAL_DELETE_AUTHORITY_MAGIC_V2.to_vec();
        encoded.extend(serde_json::to_vec(&payload).map_err(|error| {
            OrchestratorError::InvalidInput(format!(
                "failed to serialize local-delete authority: {error}"
            ))
        })?);
        Ok(hex::encode(encoded))
    }
}

pub(crate) fn decode_local_delete_authority(encoded: Option<&str>) -> Result<LocalDeleteAuthority> {
    let Some(encoded) = encoded else {
        return Ok(LocalDeleteAuthority::LegacyUnbound);
    };
    let bytes = hex::decode(encoded).map_err(|error| {
        OrchestratorError::InvalidInput(format!(
            "pending local-delete authority is not valid hex: {error}"
        ))
    })?;
    if bytes.starts_with(LOCAL_DELETE_AUTHORITY_MAGIC_V2) {
        let payload: PersistedLocalDeleteAuthorityV2 = serde_json::from_slice(
            &bytes[LOCAL_DELETE_AUTHORITY_MAGIC_V2.len()..],
        )
        .map_err(|error| {
            OrchestratorError::InvalidInput(format!(
                "pending local-delete authority is malformed: {error}"
            ))
        })?;
        if payload.owner_user_did.is_empty() {
            return Err(OrchestratorError::InvalidInput(
                "pending local-delete authority has no owner".to_string(),
            ));
        }
        for group in &payload.groups {
            hex::decode(&group.group_id_hex).map_err(|error| {
                OrchestratorError::InvalidInput(format!(
                    "pending local-delete authority contains malformed group id {}: {error}",
                    group.group_id_hex
                ))
            })?;
        }
        if let Some(conversation) = payload.conversation.as_ref() {
            hex::decode(&conversation.group_id).map_err(|error| {
                OrchestratorError::InvalidInput(format!(
                    "pending local-delete authority contains malformed conversation group id {}: {error}",
                    conversation.group_id
                ))
            })?;
        }
        if let Some(reset) = payload.reset.as_ref() {
            hex::decode(&reset.new_group_id).map_err(|error| {
                OrchestratorError::InvalidInput(format!(
                    "pending local-delete authority contains malformed reset group id {}: {error}",
                    reset.new_group_id
                ))
            })?;
        }
        return Ok(LocalDeleteAuthority::Versioned {
            owner_user_did: payload.owner_user_did,
            snapshot: LocalDeleteSnapshot {
                groups: payload.groups,
                group_state_keys: payload.group_state_keys,
                conversation: payload.conversation,
                reset: payload.reset,
            },
        });
    }
    if !bytes.starts_with(LOCAL_DELETE_AUTHORITY_MAGIC_V1) {
        return Ok(LocalDeleteAuthority::LegacyGroupId(encoded.to_string()));
    }
    let payload: PersistedLocalDeleteAuthorityV1 = serde_json::from_slice(
        &bytes[LOCAL_DELETE_AUTHORITY_MAGIC_V1.len()..],
    )
    .map_err(|error| {
        OrchestratorError::InvalidInput(format!(
            "pending local-delete authority is malformed: {error}"
        ))
    })?;
    if payload.owner_user_did.is_empty() {
        return Err(OrchestratorError::InvalidInput(
            "pending local-delete authority has no owner".to_string(),
        ));
    }
    for group_id in &payload.group_ids_hex {
        hex::decode(group_id).map_err(|error| {
            OrchestratorError::InvalidInput(format!(
                "pending local-delete authority contains malformed group id {group_id}: {error}"
            ))
        })?;
    }
    Ok(LocalDeleteAuthority::VersionedV1 {
        owner_user_did: payload.owner_user_did,
        group_ids_hex: payload.group_ids_hex,
        group_state_keys: payload.group_state_keys,
    })
}

fn delete_materialized_force_rejoin_groups<F>(
    group_ids: Vec<Vec<u8>>,
    mut delete_group: F,
) -> Result<()>
where
    F: FnMut(Vec<u8>) -> std::result::Result<(), crate::MLSError>,
{
    for group_id in group_ids {
        let group_id_hex = hex::encode(&group_id);
        match delete_group(group_id) {
            Ok(()) | Err(crate::MLSError::GroupNotFound { .. }) => {}
            Err(error) => {
                return Err(OrchestratorError::RecoveryFailed(format!(
                "Failed to delete locally materialized group {group_id_hex} before force rejoin: {error}"
            )))
            }
        }
    }
    Ok(())
}

pub(crate) fn delete_materialized_reset_predecessors<F>(
    group_ids: Vec<Vec<u8>>,
    mut delete_group: F,
) -> Result<()>
where
    F: FnMut(Vec<u8>) -> std::result::Result<(), crate::MLSError>,
{
    for group_id in group_ids {
        match delete_group(group_id) {
            Ok(()) | Err(crate::MLSError::GroupNotFound { .. }) => {}
            Err(error) => return Err(OrchestratorError::Mls(error)),
        }
    }
    Ok(())
}

/// Witness that a destructive reset's target group-id hex was validated for
/// shape/hex/length at record time, before any state transition referenced it.
///
/// ADR-021 Part A (ledger residual `csf_d0d5fab7fefe6dd96602ebe7`): a
/// destructive reset must never delete the pre-reset MLS group on the strength
/// of an unvalidated, server-asserted target id. The only constructor is
/// [`ValidatedResetTarget::parse`], which fails closed with
/// [`OrchestratorError::InvalidInput`]. Because `persist_reset_pending_state`
/// takes this witness by reference — and it is the only path that reaches
/// `delete_group` for a reset — the destructive delete is unreachable unless
/// target validation has already succeeded. Threading the witness (rather than
/// a bare `&str`) makes that ordering a property of the type, not of call-site
/// discipline.
#[derive(Debug, Clone)]
struct ValidatedResetTarget {
    hex: String,
}

impl ValidatedResetTarget {
    /// Smallest MLS group id this stack produces: a client-minted UUIDv4
    /// candidate (`format!("{:032x}", ..)`) and an OpenMLS random group id are
    /// both 16 bytes.
    const MIN_GROUP_ID_BYTES: usize = 16;
    /// Generous upper bound. Admin/legacy targets have been observed at 32
    /// bytes; anything beyond this band signals a malformed assertion rather
    /// than a real group id.
    const MAX_GROUP_ID_BYTES: usize = 64;

    /// Validate a reset target's hex identifier at record time. Fails closed —
    /// the caller must abort the reset and leave the pre-reset group intact.
    fn parse(new_group_id_hex: &str) -> Result<Self> {
        if new_group_id_hex.is_empty() {
            return Err(OrchestratorError::InvalidInput(
                "reset target group id is empty".to_string(),
            ));
        }
        let bytes = hex::decode(new_group_id_hex).map_err(|error| {
            OrchestratorError::InvalidInput(format!(
                "reset target group id {new_group_id_hex} is not valid hex: {error}"
            ))
        })?;
        if !(Self::MIN_GROUP_ID_BYTES..=Self::MAX_GROUP_ID_BYTES).contains(&bytes.len()) {
            return Err(OrchestratorError::InvalidInput(format!(
                "reset target group id length {} bytes is outside the valid MLS group-id range [{}, {}]",
                bytes.len(),
                Self::MIN_GROUP_ID_BYTES,
                Self::MAX_GROUP_ID_BYTES,
            )));
        }
        Ok(Self {
            hex: new_group_id_hex.to_string(),
        })
    }

    /// The validated target's hex identifier.
    fn hex(&self) -> &str {
        &self.hex
    }
}

/// One conversation's failed-rejoin bookkeeping (in-memory side of the
/// persisted `PersistedRecoveryBackoff` schema, WS-5.4 / invariant E7).
#[derive(Debug, Clone)]
struct FailedRejoinEntry {
    /// Consecutive failed rejoin attempts.
    count: u32,
    /// When the most recent attempt happened.
    last_attempt: Instant,
    /// When the maxed-out lockout expires. Set when `count` reaches
    /// `max_attempts`; mirrors the persisted `quarantined_until_ms`. `None`
    /// for non-maxed entries.
    lockout_until: Option<Instant>,
}

/// Tracks recovery state per conversation.
pub struct RecoveryTracker {
    /// Failed rejoin attempts per conversation.
    failed_rejoins: HashMap<String, FailedRejoinEntry>,
    /// Last successful rejoin per conversation. Used to gate sync-triggered
    /// rejoins via SUCCESSFUL_REJOIN_COOLDOWN.
    successful_rejoins: HashMap<String, Instant>,
    /// Last rejoin attempt on ANY conversation.
    pub(crate) last_global_rejoin_at: Option<Instant>,
    /// Maximum rejoin attempts before giving up.
    max_attempts: u32,
    /// Layer 3: per-conversation rolling window of recent peer-bad commit
    /// observations. Each entry is (message_id, observed_at, sender_did).
    /// sender_did is None when StagedCommitInfo wasnt available (Signal D).
    /// Cleared on healthy peer commit and on quarantine entry.
    peer_bad_commits:
        HashMap<String, std::collections::VecDeque<(String, Instant, Option<String>)>>,
    /// Layer 3: in-memory quarantine state per conversation. Mirrors what
    /// is persisted via MLSStorageBackend::mark_quarantined; the in-memory
    /// copy lets the orchestrator gate sends/rejoins without an async DB hop.
    quarantined: HashMap<String, QuarantineSnapshot>,
    /// When this device last opened an `add` leaf-recovery request per
    /// conversation. Re-requesting before the server TTL lapses only earns a
    /// `LeafRecoveryAlreadyOpen`; once it has lapsed unfulfilled, nobody is
    /// coming and the caller escalates to a reset.
    leaf_recovery_requested_at: HashMap<String, Instant>,
}

/// In-memory quarantine snapshot, mirroring ConversationState::Quarantined.
#[derive(Debug, Clone)]
pub(crate) struct QuarantineSnapshot {
    pub reason: crate::orchestrator::types::QuarantineReason,
    pub since_ms: i64,
    pub suspected_dids: Vec<String>,
}
impl RecoveryTracker {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            failed_rejoins: HashMap::new(),
            successful_rejoins: HashMap::new(),
            last_global_rejoin_at: None,
            max_attempts,
            peer_bad_commits: HashMap::new(),
            quarantined: HashMap::new(),
            leaf_recovery_requested_at: HashMap::new(),
        }
    }

    pub(crate) fn note_leaf_recovery_requested(&mut self, convo_id: &str) {
        self.note_leaf_recovery_requested_at(convo_id, Instant::now());
    }

    /// Test hook: pretend the request was opened at `at`.
    pub fn note_leaf_recovery_requested_at(&mut self, convo_id: &str, at: Instant) {
        self.leaf_recovery_requested_at
            .insert(convo_id.to_string(), at);
    }

    /// `Some(elapsed)` while a leaf-recovery request opened by this device
    /// is still being waited on; `None` when none was recorded.
    pub(crate) fn leaf_recovery_wait(&self, convo_id: &str) -> Option<Duration> {
        self.leaf_recovery_requested_at
            .get(convo_id)
            .map(|at| at.elapsed())
    }

    pub(crate) fn clear_leaf_recovery_wait(&mut self, convo_id: &str) {
        self.leaf_recovery_requested_at.remove(convo_id);
    }

    pub fn cooldown_for_attempts(&self, attempts: u32) -> Duration {
        if attempts == 0 {
            return Duration::from_secs(0);
        }
        // Spec §10: REJOIN_BACKOFF = [30s, 2m, 10m] indexed by attempt (1-based)
        let index = (attempts as usize).saturating_sub(1);
        if index < constants::REJOIN_BACKOFF.len() {
            constants::REJOIN_BACKOFF[index]
        } else {
            // Beyond defined backoff: use the last value
            *constants::REJOIN_BACKOFF.last().unwrap()
        }
    }

    /// Number of consecutive failed rejoin attempts recorded for this convo.
    /// Returns 0 if the convo has no failure record (cleared after success or
    /// never attempted). Used for diagnostic logging at the eligibility gate.
    pub fn failed_attempts(&self, convo_id: &str) -> u32 {
        self.failed_rejoins
            .get(convo_id)
            .map(|e| e.count)
            .unwrap_or(0)
    }

    /// Whether the entry's maxed-out lockout has lapsed (E7 runtime expiry).
    /// Entries written by `record_failure` always carry a `lockout_until`;
    /// for defensive completeness a maxed entry without one falls back to
    /// `last_attempt + RECOVERY_BACKOFF_TTL` (the same value
    /// `record_rejoin_failure` persists).
    fn lockout_lapsed(&self, entry: &FailedRejoinEntry) -> bool {
        let until = entry
            .lockout_until
            .unwrap_or_else(|| entry.last_attempt + constants::RECOVERY_BACKOFF_TTL);
        Instant::now() >= until
    }

    /// Whether max attempts have been reached AND the lockout is still
    /// active. E7 runtime expiry: a lapsed lockout no longer gates — the
    /// mutating clamp (count → max-1 + persisted-row update) happens at the
    /// rejoin gate via [`expire_lapsed_lockout`]; this read-only view simply
    /// stops closing the gate the moment the lockout lapses (mirrors the
    /// Swift twin `MLSRecoveryManager.shouldSkipRejoin`, which removes
    /// expired quarantine at runtime).
    ///
    /// [`expire_lapsed_lockout`]: RecoveryTracker::expire_lapsed_lockout
    pub fn is_maxed_out(&self, convo_id: &str) -> bool {
        let Some(entry) = self.failed_rejoins.get(convo_id) else {
            return false;
        };
        if entry.count < self.max_attempts {
            return false;
        }
        !self.lockout_lapsed(entry)
    }

    /// Remaining cooldown before the next rejoin attempt is eligible.
    pub fn cooldown_remaining(&self, convo_id: &str) -> Option<Duration> {
        let entry = self.failed_rejoins.get(convo_id)?;
        // E7 runtime expiry: a maxed entry whose lockout lapsed behaves as
        // count = max-1 (one fresh attempt re-opens). Its last_attempt is at
        // least RECOVERY_BACKOFF_TTL old by then — beyond every
        // REJOIN_BACKOFF step — so this computes to None in practice.
        let attempts = if entry.count >= self.max_attempts && self.lockout_lapsed(entry) {
            self.max_attempts.saturating_sub(1)
        } else {
            entry.count
        };
        if attempts == 0 || attempts >= self.max_attempts {
            return None;
        }

        let cooldown = self.cooldown_for_attempts(attempts);
        let elapsed = entry.last_attempt.elapsed();
        if elapsed >= cooldown {
            None
        } else {
            Some(cooldown - elapsed)
        }
    }

    /// Runtime twin of the hydration clamp (E7): when a maxed-out entry's
    /// lockout lapses while the process is running, clamp the count to
    /// `max_attempts - 1` so exactly one fresh attempt re-opens, and clear
    /// the in-memory lockout. Long-running processes (BIRDaemon, catmos
    /// desktop) otherwise carry a hydrated lockout for the whole process
    /// lifetime.
    ///
    /// Returns `Some((clamped_count, last_attempt_at_ms))` when a clamp
    /// happened so the caller can write the persisted row through (a
    /// `clamped_count` of 0 means the entry was dropped entirely and the
    /// persisted row should be cleared). `None` when nothing changed.
    pub fn expire_lapsed_lockout(&mut self, convo_id: &str) -> Option<(u32, i64)> {
        let lapsed = {
            let entry = self.failed_rejoins.get(convo_id)?;
            entry.count >= self.max_attempts && self.lockout_lapsed(entry)
        };
        if !lapsed {
            return None;
        }
        let clamped = self.max_attempts.saturating_sub(1);
        if clamped == 0 {
            // max_attempts == 1: mirroring hydration, a zero count is not
            // tracked at all.
            self.failed_rejoins.remove(convo_id);
            return Some((0, chrono::Utc::now().timestamp_millis()));
        }
        let entry = self.failed_rejoins.get_mut(convo_id)?;
        entry.count = clamped;
        entry.lockout_until = None;
        let last_attempt_at_ms =
            chrono::Utc::now().timestamp_millis() - entry.last_attempt.elapsed().as_millis() as i64;
        Some((clamped, last_attempt_at_ms))
    }

    /// Whether a conversation should skip rejoin (max attempts, cooldown, min
    /// interval, or Layer 3 quarantine).
    pub fn should_skip(&self, convo_id: &str) -> bool {
        // Layer 3: quarantine is the strongest gate --- the orchestrator must
        // never auto-rejoin a quarantined conversation. Exit only via server
        // reset, healthy peer commit, or user-confirmed manual reset.
        if self.quarantined.contains_key(convo_id) {
            return true;
        }
        if self.is_maxed_out(convo_id) || self.cooldown_remaining(convo_id).is_some() {
            return true;
        }
        // Global minimum interval: no rejoin on ANY conversation within MIN_REJOIN_INTERVAL
        if let Some(last) = self.last_global_rejoin_at {
            if last.elapsed() < constants::MIN_REJOIN_INTERVAL {
                return true;
            }
        }
        false
    }

    /// Record a failed rejoin attempt.
    pub fn record_failure(&mut self, convo_id: &str) {
        let now = Instant::now();
        let max_attempts = self.max_attempts;
        let entry = self
            .failed_rejoins
            .entry(convo_id.to_string())
            .or_insert(FailedRejoinEntry {
                count: 0,
                last_attempt: now,
                lockout_until: None,
            });
        entry.count += 1;
        entry.last_attempt = now;
        // Maxed-out lockout: mirrors the persisted `quarantined_until_ms`
        // written by `record_rejoin_failure` (RECOVERY_BACKOFF_TTL lockout
        // duration, Swift parity) so runtime expiry can fire in-process.
        entry.lockout_until =
            (entry.count >= max_attempts).then(|| now + constants::RECOVERY_BACKOFF_TTL);
        self.last_global_rejoin_at = Some(now);
    }

    /// Clear failure tracking on success.
    /// Note: does NOT clear `last_global_rejoin_at` — the minimum interval still applies
    /// to prevent rapid successive rejoins even when they succeed. Also records
    /// per-convo success time so sync-triggered rejoins are suppressed for
    /// `SUCCESSFUL_REJOIN_COOLDOWN` on this conversation.
    pub fn clear(&mut self, convo_id: &str) {
        let now = Instant::now();
        self.failed_rejoins.remove(convo_id);
        self.successful_rejoins.insert(convo_id.to_string(), now);
        // Record the current time globally so the MIN_REJOIN_INTERVAL applies across all convos
        self.last_global_rejoin_at = Some(now);
    }

    /// Clear per-conversation rejoin failure tracking for a server-initiated
    /// reset. Unlike [`clear`], this does NOT arm `last_global_rejoin_at` and
    /// does NOT insert into `successful_rejoins` — a server-pushed reset is
    /// not an attempt by THIS client and must not gate the imminent
    /// first-responder bootstrap that follows.
    ///
    /// The 30 s `MIN_REJOIN_INTERVAL` and 5 m `SUCCESSFUL_REJOIN_COOLDOWN`
    /// gates exist to prevent epoch-inflation spirals from this device's own
    /// rejoin loop. They are the wrong gate for a fresh `groupResetEvent`,
    /// where the server has just told us the prior group is dead and we need
    /// to either fetch a new Welcome or bootstrap immediately.
    ///
    /// Call site: [`persist_reset_pending_state`]. Previously called `clear`,
    /// which armed the global gate on every server reset and blocked
    /// `try_first_responder_bootstrap` for ≥30 s — the deadlock observed in
    /// the 2026-05-02 prod incident where two clients sat behind their own
    /// gates waiting for the other to bootstrap, sometimes for 24+ minutes.
    pub fn clear_for_fresh_reset(&mut self, convo_id: &str) {
        // Server-driven reset is the strongest possible "start from scratch"
        // signal; wipe any in-flight client-side failure history. If a
        // per-convo backoff was running for an unrelated reason (e.g., epoch
        // divergence retries), the prior failure count would otherwise stack
        // on top of the fresh reset's bootstrap attempt.
        if let Some(entry) = self.failed_rejoins.get(convo_id) {
            if entry.count > 0 {
                tracing::info!(
                    convo_id,
                    wiped_attempts = entry.count,
                    "clear_for_fresh_reset: wiping prior per-convo failure history (server reset trumps client retry counter)"
                );
            }
        }
        self.failed_rejoins.remove(convo_id);
        // Intentionally do NOT touch `successful_rejoins` or
        // `last_global_rejoin_at`. See doc comment above for rationale.
    }

    /// Clear per-conversation failure tracking when sync clears a STALE
    /// `needs_rejoin` flag (the local group turned out to be already caught
    /// up — NO rejoin was attempted). Modeled on [`clear_for_fresh_reset`]:
    /// this does NOT arm `last_global_rejoin_at` and does NOT insert into
    /// `successful_rejoins`.
    ///
    /// The stale-flag branch in `sync_with_server` can re-fire every
    /// `SYNC_INTERVAL_SECS` (5 s) pass. Routing it through [`clear`] would
    /// re-arm the 30 s global `MIN_REJOIN_INTERVAL` gate continuously —
    /// blocking rejoins on EVERY conversation indefinitely (the same gate
    /// deadlock class as the 2026-05-02 prod incident, see
    /// [`clear_for_fresh_reset`]) — and the WS-5.4 write-through would
    /// persist that spurious gate across restart.
    ///
    /// [`clear`]: RecoveryTracker::clear
    pub fn clear_stale_flag(&mut self, convo_id: &str) {
        self.failed_rejoins.remove(convo_id);
        // Intentionally do NOT touch `successful_rejoins` or
        // `last_global_rejoin_at` — no rejoin happened here.
    }

    /// Drop ALL in-memory recovery bookkeeping for a conversation that is
    /// being locally deleted (WS-5.3 `force_delete_local`). Leaves the
    /// global gate untouched — deleting one conversation says nothing about
    /// rejoin pressure on others.
    pub fn forget_conversation(&mut self, convo_id: &str) {
        self.failed_rejoins.remove(convo_id);
        self.successful_rejoins.remove(convo_id);
        self.peer_bad_commits.remove(convo_id);
        self.quarantined.remove(convo_id);
        self.leaf_recovery_requested_at.remove(convo_id);
    }

    /// Hydrate backoff state from storage on startup (WS-5.4, invariant E7).
    ///
    /// Rules (coordinated with the Swift twin, WS-6.4):
    /// - Entries whose `last_attempt_at_ms` is older than
    ///   `RECOVERY_BACKOFF_TTL` (24 h) are ignored.
    /// - Remaining cooldown/quarantine is honored but never extended: the
    ///   in-memory attempt timestamp is back-dated by the real elapsed time,
    ///   and an expired `quarantined_until_ms` clamps the failure count below
    ///   `max_attempts` so the maxed-out gate cannot outlive its lockout.
    /// - `last_global_rejoin_attempt_at_ms` re-arms `MIN_REJOIN_INTERVAL` for
    ///   whatever window remains.
    ///
    /// Returns the conversation ids of entries hydration REJECTED
    /// (TTL-expired, future-dated, zero-count, or undatable on this clock).
    /// The caller must delete the corresponding persisted rows
    /// (`clear_recovery_backoff`) — Swift twin parity:
    /// `MLSRecoveryManager.hydrateFromDatabase` ignores AND deletes. A kept
    /// row could resurrect later (e.g. a TTL-expired row becomes "valid"
    /// again if the wall clock regresses), and a kept future-dated row
    /// re-logs its drop warning on every restart. This is a pure tracker
    /// function; storage I/O stays with the caller.
    #[must_use = "rejected entries must be deleted from storage (clear_recovery_backoff)"]
    pub fn hydrate_from_persisted(
        &mut self,
        state: &PersistedRecoveryState,
        now_ms: i64,
    ) -> Vec<String> {
        let ttl_ms = constants::RECOVERY_BACKOFF_TTL.as_millis() as i64;
        let now = Instant::now();
        let mut rejected: Vec<String> = Vec::new();

        for entry in &state.entries {
            let elapsed_ms = now_ms.saturating_sub(entry.last_attempt_at_ms);
            if elapsed_ms < 0 {
                // Future-dated entry: the wall clock moved backwards since the
                // write (clock correction). Negative elapsed would dodge the
                // TTL gate, restart the full cooldown (violating
                // honor-never-extend), and pin a future quarantined_until far
                // past 24 h of real time. Treat it as invalid persisted state
                // and drop it (same policy as the monotonic-underflow drop
                // below) — under-gating never extends backoff.
                tracing::warn!(
                    convo_id = %entry.conversation_id,
                    last_attempt_at_ms = entry.last_attempt_at_ms,
                    now_ms,
                    "Persisted rejoin backoff is future-dated (wall clock moved backwards) — dropping entry"
                );
                rejected.push(entry.conversation_id.clone());
                continue;
            }
            if elapsed_ms >= ttl_ms {
                tracing::info!(
                    convo_id = %entry.conversation_id,
                    last_attempt_at_ms = entry.last_attempt_at_ms,
                    "Persisted rejoin backoff older than TTL — ignoring on hydration"
                );
                rejected.push(entry.conversation_id.clone());
                continue;
            }
            let mut count = entry.failed_rejoin_count;
            if count == 0 {
                // No failure state to carry — a dead row (e.g. a runtime
                // lockout expiry written through with max_attempts == 1).
                rejected.push(entry.conversation_id.clone());
                continue;
            }
            let mut lockout_until = None;
            if count >= self.max_attempts {
                let quarantine_active = entry
                    .quarantined_until_ms
                    .is_some_and(|until| until > now_ms);
                if quarantine_active {
                    // Carry the remaining lockout into memory so runtime
                    // expiry (`expire_lapsed_lockout` / `is_maxed_out`) can
                    // fire in-process for long-running clients.
                    let remaining_ms = entry
                        .quarantined_until_ms
                        .expect("quarantine_active implies Some")
                        .saturating_sub(now_ms);
                    lockout_until = Some(now + Duration::from_millis(remaining_ms.max(0) as u64));
                } else {
                    // Lockout expired: honor it, don't extend. Clamping below
                    // max_attempts re-opens exactly one attempt (after the
                    // normal per-attempt cooldown) instead of re-arming the
                    // indefinite maxed-out gate.
                    count = self.max_attempts.saturating_sub(1);
                    if count == 0 {
                        rejected.push(entry.conversation_id.clone());
                        continue;
                    }
                }
            }
            // Back-date the in-memory timestamp by the real elapsed time so
            // cooldown_remaining computes the true remainder. If the monotonic
            // clock can't represent that far back (process older than boot
            // window), drop the entry — under-gating never extends backoff.
            let Some(at) = now.checked_sub(Duration::from_millis(elapsed_ms as u64)) else {
                tracing::warn!(
                    convo_id = %entry.conversation_id,
                    elapsed_ms,
                    "Cannot back-date persisted rejoin backoff on this clock — dropping entry"
                );
                // Elapsed only grows (a regressed clock hits the future-dated
                // drop instead), so this entry can never hydrate on this
                // device again — reject so the row is deleted rather than
                // re-warning every restart until the TTL drop.
                rejected.push(entry.conversation_id.clone());
                continue;
            };
            self.failed_rejoins.insert(
                entry.conversation_id.clone(),
                FailedRejoinEntry {
                    count,
                    last_attempt: at,
                    lockout_until,
                },
            );
        }

        if let Some(global_ms) = state.last_global_rejoin_attempt_at_ms {
            let elapsed_ms = now_ms.saturating_sub(global_ms);
            if elapsed_ms < 0 {
                // Same backward-clock policy as per-convo entries above.
                // (Not in `rejected`: the global stamp has no per-convo row,
                // and the storage trait has no clear API for it — the next
                // rejoin attempt overwrites it via
                // set_last_global_rejoin_attempt_at.)
                tracing::warn!(
                    global_ms,
                    now_ms,
                    "Persisted global rejoin stamp is future-dated (wall clock moved backwards) — dropping"
                );
            } else if elapsed_ms < ttl_ms {
                if let Some(at) = now.checked_sub(Duration::from_millis(elapsed_ms as u64)) {
                    self.last_global_rejoin_at = Some(at);
                } else {
                    tracing::warn!(
                        global_ms,
                        elapsed_ms,
                        "Cannot back-date persisted global rejoin stamp on this clock — dropping"
                    );
                }
            }
        }

        rejected
    }

    /// Remaining cooldown imposed by a recent SUCCESSFUL rejoin on this
    /// conversation. Applies to sync-triggered rejoins only (see
    /// `should_attempt_sync_rejoin`). `None` means no cooldown active.
    pub fn success_cooldown_remaining(&self, convo_id: &str) -> Option<Duration> {
        let last = self.successful_rejoins.get(convo_id)?;
        let elapsed = last.elapsed();
        if elapsed >= constants::SUCCESSFUL_REJOIN_COOLDOWN {
            None
        } else {
            Some(constants::SUCCESSFUL_REJOIN_COOLDOWN - elapsed)
        }
    }

    // ----- Layer 3 Quarantine -----

    /// Snapshot of the current quarantine state for convo_id, if any.
    pub fn quarantine_snapshot(&self, convo_id: &str) -> Option<super::types::QuarantineState> {
        self.quarantined
            .get(convo_id)
            .map(|q| super::types::QuarantineState {
                reason: q.reason,
                since_ms: q.since_ms,
                suspected_dids: q.suspected_dids.clone(),
            })
    }

    /// Whether convo_id is currently quarantined.
    pub fn is_quarantined(&self, convo_id: &str) -> bool {
        self.quarantined.contains_key(convo_id)
    }

    /// Record a peer-bad commit observation. Returns Some(reason) when the
    /// thresholds are crossed and the caller should mark the conversation
    /// quarantined; returns None when below threshold.
    pub fn record_peer_bad_commit(
        &mut self,
        convo_id: &str,
        message_id: &str,
        sender_did: Option<String>,
    ) -> Option<crate::orchestrator::types::QuarantineReason> {
        if self.is_quarantined(convo_id) {
            return None;
        }
        let now = Instant::now();
        let buf = self
            .peer_bad_commits
            .entry(convo_id.to_string())
            .or_default();
        let max_window = constants::QUARANTINE_FRAMING_WINDOW;
        while let Some((_, ts, _)) = buf.front() {
            if now.duration_since(*ts) > max_window {
                buf.pop_front();
            } else {
                break;
            }
        }
        while buf.len() >= constants::QUARANTINE_RING_CAPACITY {
            buf.pop_front();
        }
        buf.push_back((message_id.to_string(), now, sender_did.clone()));

        if let Some(ref did) = sender_did {
            let count = buf
                .iter()
                .filter(|(_, _, s)| s.as_deref() == Some(did))
                .count() as u32;
            if count >= constants::QUARANTINE_SINGLE_PEER_HITS {
                return Some(crate::orchestrator::types::QuarantineReason::PeerBadCommit);
            }
        }

        let multi_window = constants::QUARANTINE_MULTI_PEER_WINDOW;
        let mut distinct_peers = std::collections::HashSet::new();
        for (_, ts, s) in buf.iter() {
            if now.duration_since(*ts) > multi_window {
                continue;
            }
            if let Some(did) = s {
                distinct_peers.insert(did.clone());
            }
        }
        if distinct_peers.len() >= constants::QUARANTINE_MULTI_PEER_DISTINCT {
            return Some(crate::orchestrator::types::QuarantineReason::MultiPeerBadCommits);
        }

        let framing_window = constants::QUARANTINE_FRAMING_WINDOW;
        let mut distinct_msgs = std::collections::HashSet::new();
        for (mid, ts, _) in buf.iter() {
            if now.duration_since(*ts) > framing_window {
                continue;
            }
            distinct_msgs.insert(mid.clone());
        }
        if distinct_msgs.len() >= constants::QUARANTINE_FRAMING_DISTINCT_MSGS {
            return Some(crate::orchestrator::types::QuarantineReason::RepeatedFramingFailures);
        }

        None
    }

    /// A healthy peer commit merged successfully. Clears rolling buffer.
    pub fn record_healthy_peer_commit(&mut self, convo_id: &str) {
        self.peer_bad_commits.remove(convo_id);
    }

    /// Mark the conversation quarantined.
    pub fn mark_quarantined(
        &mut self,
        convo_id: &str,
        reason: crate::orchestrator::types::QuarantineReason,
        since_ms: i64,
        suspected_dids: Vec<String>,
    ) {
        self.quarantined.insert(
            convo_id.to_string(),
            QuarantineSnapshot {
                reason,
                since_ms,
                suspected_dids,
            },
        );
        self.peer_bad_commits.remove(convo_id);
        self.failed_rejoins.remove(convo_id);
    }

    /// Clear quarantine. Returns true if there was a snapshot to clear.
    pub fn clear_quarantine(&mut self, convo_id: &str) -> bool {
        self.quarantined.remove(convo_id).is_some()
    }

    /// Distinct DIDs in the rolling buffer (for entry events).
    pub fn suspected_dids_for(&self, convo_id: &str) -> Vec<String> {
        let Some(buf) = self.peer_bad_commits.get(convo_id) else {
            return Vec::new();
        };
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for (_, _, s) in buf.iter() {
            if let Some(did) = s {
                if seen.insert(did.clone()) {
                    out.push(did.clone());
                }
            }
        }
        out
    }
}

/// Diagnostic status of a conversation's sequencer connectivity.
#[derive(Debug, Clone)]
pub enum FailoverStatus {
    /// No failures recorded — sequencer is reachable.
    Healthy,
    /// Some failures but below the failover threshold.
    Degraded {
        consecutive_failures: u32,
        since: Instant,
    },
    /// Threshold exceeded — the caller should switch to a backup sequencer.
    FailoverRecommended {
        consecutive_failures: u32,
        since: Instant,
    },
}

/// Internal per-conversation failure tracking state.
struct FailoverState {
    consecutive_failures: u32,
    first_failure_at: Instant,
    last_failure_at: Instant,
}

/// Tracks consecutive sequencer failures per conversation to detect when
/// failover should be triggered.
///
/// This is a pure state tracker — it does not perform network calls or async
/// work. The caller is responsible for calling [`record_failure`] only for
/// connection/timeout errors (not business-logic errors like 409 Conflict).
pub struct SequencerFailoverTracker {
    failures: HashMap<String, FailoverState>,
}

impl SequencerFailoverTracker {
    pub fn new() -> Self {
        Self {
            failures: HashMap::new(),
        }
    }

    /// Record a connection/timeout failure for a conversation's sequencer.
    pub fn record_failure(&mut self, convo_id: &str) {
        let now = Instant::now();
        let state = self
            .failures
            .entry(convo_id.to_string())
            .and_modify(|s| {
                s.consecutive_failures += 1;
                s.last_failure_at = now;
            })
            .or_insert(FailoverState {
                consecutive_failures: 1,
                first_failure_at: now,
                last_failure_at: now,
            });
        tracing::debug!(
            convo_id,
            consecutive_failures = state.consecutive_failures,
            "Sequencer failure recorded"
        );
    }

    /// Record a successful sequencer interaction, clearing failure state.
    pub fn record_success(&mut self, convo_id: &str) {
        if self.failures.remove(convo_id).is_some() {
            tracing::debug!(convo_id, "Sequencer failure state cleared on success");
        }
    }

    /// Whether failover is recommended for this conversation.
    ///
    /// Returns `true` when both conditions are met:
    /// - At least [`FAILOVER_MIN_FAILURES`] consecutive failures
    /// - The first failure occurred at least [`FAILOVER_MIN_DURATION`] ago
    pub fn should_failover(&self, convo_id: &str) -> bool {
        let Some(state) = self.failures.get(convo_id) else {
            return false;
        };
        state.consecutive_failures >= constants::FAILOVER_MIN_FAILURES
            && state.first_failure_at.elapsed() >= constants::FAILOVER_MIN_DURATION
    }

    /// Reset failure tracking after a successful failover.
    pub fn clear(&mut self, convo_id: &str) {
        self.failures.remove(convo_id);
    }

    /// Get the current failover diagnostic status for a conversation.
    pub fn get_status(&self, convo_id: &str) -> Option<FailoverStatus> {
        let state = self.failures.get(convo_id)?;
        if self.should_failover(convo_id) {
            Some(FailoverStatus::FailoverRecommended {
                consecutive_failures: state.consecutive_failures,
                since: state.first_failure_at,
            })
        } else {
            Some(FailoverStatus::Degraded {
                consecutive_failures: state.consecutive_failures,
                since: state.first_failure_at,
            })
        }
    }
}

/// Tracks consecutive GroupInfo 404 responses per conversation.
/// After GROUPINFO_404_CIRCUIT_BREAKER (3) consecutive 404s, the circuit
/// trips and External Commit attempts should be skipped for that conversation.
pub struct GroupInfo404Tracker {
    counts: HashMap<String, u32>,
}

impl GroupInfo404Tracker {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn record_404(&mut self, convo_id: &str) {
        let count = self.counts.entry(convo_id.to_string()).or_insert(0);
        *count += 1;
    }

    pub fn is_tripped(&self, convo_id: &str) -> bool {
        self.counts
            .get(convo_id)
            .is_some_and(|c| *c >= constants::GROUPINFO_404_CIRCUIT_BREAKER)
    }

    pub fn clear(&mut self, convo_id: &str) {
        self.counts.remove(convo_id);
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(crate) async fn attempt_fork_readd(&self, convo_id: &str) -> Result<()> {
        let user_did = self.require_user_did().await?;
        let lock = self.rejoin_lock(convo_id).await;
        let _g = match lock.try_lock() {
            Ok(g) => g,
            Err(_) => {
                return Ok(());
            }
        };
        if self
            .reset_blocks_non_reset_transition_locked(convo_id)
            .await?
        {
            return Err(OrchestratorError::RecoveryFailed(format!(
                "durable reset authority blocks fork readd for {convo_id}"
            )));
        }
        let ok = {
            let fds = self
                .fork_detection_states()
                .lock()
                .map_err(|_| OrchestratorError::RecoveryFailed("lock".into()))?;
            fds.get(convo_id)
                .is_some_and(|s| s.readd_attempts < constants::FORK_READD_MAX_ATTEMPTS)
        };
        if !ok {
            return Ok(());
        }
        {
            let mut fds = self
                .fork_detection_states()
                .lock()
                .map_err(|_| OrchestratorError::RecoveryFailed("lock".into()))?;
            if let Some(s) = fds.get_mut(convo_id) {
                s.readd_attempts += 1;
            }
        }
        let resolved = match self.resolve_legacy_group_identifier(convo_id).await {
            Ok(resolved) => resolved,
            Err(error) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(error);
            }
        };
        let gid = resolved.group_id_bytes()?;
        let group_state_projection = {
            let st = self.group_states().lock().await;
            resolved.group_state(&st).cloned()
        };
        let mut group_state_projection = match group_state_projection {
            Some(state) => state,
            None => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "missing group state for fork readd: {}",
                    resolved.conversation_id
                )));
            }
        };
        let mems = group_state_projection.members.clone();
        if mems.is_empty() {
            self.escalate_fork_to_rejoin(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed("no members".into()));
        }
        let actor_device_id = match self.require_actor_device_id().await {
            Ok(id) => id,
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(e);
            }
        };
        let kp_refs = match self
            .api_client()
            .get_key_packages(&actor_device_id, &mems)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
            }
        };

        // WS-3 stage 1 (ADR-009 D3): warn-and-allow credential binding check
        // before the fetched packages are consumed by the fork-readd commit
        // (`recover_fork_by_readding` → `commit_group_change("forkReadd")`).
        // This is an automated Add path a malicious DS can steer clients into
        // via decrypt failures, so it must hit the same verify-on-fetch
        // chokepoint as create_group / add_members / swap_members.
        if let Err(error) = self
            .verify_fetched_key_packages(
                &mems,
                &kp_refs,
                "fork_readd",
                Some(&resolved.conversation_id),
            )
            .await
        {
            self.escalate_fork_to_rejoin(convo_id).await;
            return Err(error);
        }
        let (metadata_plaintext, metadata_version) = match self
            .decrypt_current_metadata_snapshot(&resolved.conversation_id, &gid)
            .await
        {
            Ok(metadata) => metadata,
            Err(error) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(error);
            }
        };

        let kps: Vec<Vec<u8>> = kp_refs.iter().map(|r| r.key_package_data.clone()).collect();
        let (commit, _) = match self
            .mls_context()
            .recover_fork_by_readding(gid.clone(), kps)
        {
            Ok(r) => r,
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
            }
        };
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential(
                "auth_generation must be >= 1".into(),
            ));
        }
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);
        let target_epoch = self.mls_context().get_epoch(gid.clone())? + 1;
        let tag_bytes = self.mls_context().get_confirmation_tag(gid.clone())?;
        if tag_bytes.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "confirmation tag must be exactly 32 bytes, got {}",
                tag_bytes.len()
            ))));
        }
        let gc_hash = self.mls_context().get_group_context_hash(gid.clone())?;
        if gc_hash.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "group context hash must be exactly 32 bytes, got {}",
                gc_hash.len()
            ))));
        }
        let convo_uuid = uuid::Uuid::parse_str(&resolved.conversation_id).map_err(|e| {
            OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}"))
        })?;

        let metadata = (|| -> Result<([u8; 12], Vec<u8>)> {
            use rand::RngCore;
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            let metadata_key: [u8; 32] = self
                .mls_context()
                .export_metadata_key_from_pending(gid.clone(), target_epoch)?
                .try_into()
                .map_err(|_| {
                    OrchestratorError::Mls(MLSError::Internal(
                        "pending metadata key length mismatch".into(),
                    ))
                })?;
            let ciphertext = crate::metadata::encrypt_metadata_snapshot_with_nonce(
                &metadata_key,
                &gid,
                target_epoch,
                metadata_version,
                &nonce,
                &metadata_plaintext,
            )
            .map_err(|error| {
                OrchestratorError::Mls(MLSError::Internal(format!(
                    "encrypt metadata snapshot: {error:?}"
                )))
            })?;
            Ok((nonce, ciphertext))
        })();
        let (nonce, ciphertext) = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                let _ = self.mls_context().clear_pending_commit(gid.clone());
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(error);
            }
        };
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use sha2::{Digest, Sha256};

        let transition_id = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "aad": {
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": 0,
                "prior": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": target_epoch.saturating_sub(1),
                    "generation": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                    "groupId": { "$bytes": STANDARD.encode(&gid) },
                    "lifecycle": "active",
                    "stateVersion": 0
                },
                "protocolVersion": "1",
                "transitionId": STANDARD.encode(uuid::Uuid::parse_str(&transition_id).map_err(|e| OrchestratorError::InvalidInput(e.to_string()))?.as_bytes())
            },
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "commit": {
                "bytes": { "$bytes": STANDARD.encode(&commit) },
                "contentType": "publicMessageCommit",
                "framing": "mlsMessage",
                "sha256": STANDARD.encode(Sha256::digest(&commit))
            },
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "keyId": key_id,
            "manifest": {
                "leafChanges": [],
                "participantChanges": []
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": auth_generation,
                    "authorDeviceId": actor_device_id,
                    "authorDid": user_did,
                    "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active",
                    "originSeq": 1,
                    "originTransitionId": transition_id,
                    "roleAtOrigin": "admin",
                    "signaturePublicKey": { "$bytes": STANDARD.encode(&public_key) }
                },
                "ciphertext": { "$bytes": STANDARD.encode(&ciphertext) },
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": target_epoch,
                    "generation": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                    "groupId": { "$bytes": STANDARD.encode(&gid) }
                },
                "metadataVersion": metadata_version,
                "nonce": { "$bytes": STANDARD.encode(&nonce) },
                "originTransitionId": transition_id
            },
            "next": {
                "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                "conversationId": resolved.conversation_id.clone(),
                "epoch": target_epoch,
                "generation": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                "groupId": { "$bytes": STANDARD.encode(&gid) },
                "lifecycle": "active",
                "stateVersion": 0
            },
            "prior": {
                "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                "conversationId": resolved.conversation_id.clone(),
                "epoch": target_epoch.saturating_sub(1),
                "generation": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                "groupId": { "$bytes": STANDARD.encode(&gid) },
                "lifecycle": "active",
                "stateVersion": 0
            },
            "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "transitionId": transition_id
        });

        let send_res = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::SubmitTransition,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await;

        if let Err(e) = send_res {
            let _ = self.mls_context().clear_pending_commit(gid);
            self.escalate_fork_to_rejoin(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
        }
        match self.mls_context().merge_pending_commit(gid.clone()) {
            Ok(ep) => {
                // The server has accepted the commit and the local MLS group
                // has advanced, but fork recovery is not complete until the
                // stable conversation -> group projection is durable. Publish
                // none of the success side effects before that boundary.
                group_state_projection.epoch = ep;
                if let Err(error) = self
                    .storage()
                    .set_group_state(&group_state_projection)
                    .await
                {
                    self.report_recovery_storage_failure(
                        convo_id,
                        "set_group_state:fork_readd",
                        &error,
                    )
                    .await;
                    self.escalate_fork_to_rejoin(convo_id).await;
                    return Err(error);
                }

                {
                    let mut st = self.group_states().lock().await;
                    normalize_group_state(&mut st, group_state_projection);
                }

                match self
                    .project_non_reset_cache_locked(convo_id, ConversationState::Active)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(OrchestratorError::RecoveryFailed(format!(
                            "durable reset authority blocked fork readd completion for {convo_id}"
                        )));
                    }
                    Err(error) => {
                        self.report_recovery_storage_failure(
                            convo_id,
                            "fork_readd:active_projection_authority_read",
                            &error,
                        )
                        .await;
                        return Err(error);
                    }
                }

                // Cleanup old epoch secrets only after the durable projection
                // and in-memory Active transition have both succeeded.
                self.cleanup_epoch_secrets_if_needed(
                    &resolved.conversation_id,
                    &resolved.group_id,
                    ep,
                )
                .await;

                {
                    let mut fds = self
                        .fork_detection_states()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    fds.remove(convo_id);
                }
                self.decrypt_fail_counts().lock().await.remove(convo_id);
                let scoped_identity = self.require_scoped_identity().await?;
                let _ = self
                    .mls_context()
                    .export_group_info(gid, scoped_identity.as_bytes().to_vec());
                tracing::info!(convo_id, "Fork readd succeeded");
                Ok(())
            }
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                Err(OrchestratorError::RecoveryFailed(format!("{e}")))
            }
        }
    }
    async fn escalate_fork_to_rejoin(&self, convo_id: &str) {
        {
            let mut fds = self
                .fork_detection_states()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            fds.remove(convo_id);
        }
        if self
            .project_non_reset_cache_locked(convo_id, ConversationState::NeedsRejoin)
            .await
            .unwrap_or(false)
        {
            self.mark_needs_rejoin_critical(convo_id).await;
        }
        tracing::info!(convo_id, "Fork escalated to NeedsRejoin");
    }

    pub(crate) async fn project_startup_needs_rejoin(&self, convo_id: &str) {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        match self
            .project_non_reset_state_locked(convo_id, ConversationState::NeedsRejoin)
            .await
        {
            Ok(true) => self.mark_needs_rejoin_critical(convo_id).await,
            Ok(false) => {
                tracing::info!(
                    convo_id,
                    "ResetPending suppressed startup NeedsRejoin projection"
                )
            }
            Err(e) => {
                self.report_recovery_storage_failure(
                    convo_id,
                    "set_conversation_state:needs_rejoin",
                    &e,
                )
                .await;
            }
        }
    }

    pub(crate) async fn should_attempt_sync_rejoin(&self, convo_id: &str) -> bool {
        // Layer 3: quarantined conversations never participate in sync-driven
        // rejoins. This must run before the rejoin_lock check so that a
        // background task holding the lock for a quarantine bookkeeping op
        // does not mask the gate.
        if self
            .recovery_tracker()
            .lock()
            .await
            .is_quarantined(convo_id)
        {
            tracing::debug!(
                convo_id,
                "Skipping sync rejoin: conversation quarantined (Layer 3)"
            );
            crate::info_log!("[gate] convo={} REJECT: quarantined (Layer 3)", convo_id);
            return false;
        }
        let rejoin_lock = self.rejoin_lock(convo_id).await;
        let lock_guard = match rejoin_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::debug!(
                    convo_id,
                    "Skipping sync-triggered join/rejoin: attempt already in-flight"
                );
                crate::info_log!(
                    "[gate] convo={} REJECT: attempt already in-flight (rejoin_lock held)",
                    convo_id
                );
                return false;
            }
        };
        drop(lock_guard);

        // Epoch-inflation spiral guard: if we SUCCESSFULLY rejoined this
        // conversation recently and sync still thinks we need to rejoin
        // (e.g. `ffi_has_group=false`), something is dropping our MLS state
        // after a successful external commit. Each re-rejoin advances the
        // server epoch, 409-ing every other device's `sendMessage`. Suppress
        // sync-path rejoins until the cooldown elapses. Decrypt-triggered
        // rejoins in `process_incoming_message` still go through — those have
        // a real incoming message and a real epoch gap to close.
        if let Some(remaining) = self
            .recovery_tracker()
            .lock()
            .await
            .success_cooldown_remaining(convo_id)
        {
            tracing::info!(
                convo_id,
                remaining_secs = remaining.as_secs(),
                "Skipping sync-triggered join/rejoin: recently succeeded (spiral protection)"
            );
            crate::info_log!(
                "[gate] convo={} REJECT: success cooldown ({}s remaining, spiral protection)",
                convo_id,
                remaining.as_secs()
            );
            return false;
        }

        if let Err(err) = self.enforce_rejoin_backoff(convo_id).await {
            tracing::debug!(
                convo_id,
                error = %err,
                "Skipping sync-triggered join/rejoin: recovery backoff active"
            );
            crate::info_log!("[gate] convo={} REJECT: backoff active ({})", convo_id, err);
            return false;
        }

        crate::info_log!("[gate] convo={} ACCEPT: proceeding with rejoin", convo_id);

        true
    }

    fn state_requires_deferred_recovery(state: &ConversationState) -> bool {
        matches!(
            state,
            ConversationState::NeedsRejoin | ConversationState::ResetPending { .. }
        )
    }

    pub(crate) async fn consume_deferred_recovery_for_conversation(
        &self,
        convo_id: &str,
        server_epoch: Option<u64>,
        server_group_id: Option<&str>,
    ) -> Result<DeferredRecoveryOutcome> {
        {
            // Serialize the authority check, context/epoch decision, and flag
            // clear with reset recording. Otherwise an SSE reset can commit
            // ResetPending between the check and clear and lose its durable
            // recovery route.
            let transition_lock = self.rejoin_lock(convo_id).await;
            let _transition_guard = transition_lock.lock().await;

            // ResetPending is authoritative even when the accepted bootstrap
            // candidate is already at the server epoch. Only the generation-bound
            // completion transaction may clear its durable rejoin route. A read
            // failure is fail-closed and must not fall through to stale clearing.
            let reset_authority = self.reset_pending_payload_result(convo_id).await?;
            if let (None, Some(server_epoch)) = (reset_authority.as_ref(), server_epoch) {
                let candidate_group_id = self
                    .resolve_conversation_context(convo_id)
                    .await
                    .ok()
                    .and_then(|resolved| match server_group_id {
                        Some(server_group_id) if server_group_id != resolved.group_id => None,
                        _ => Some(resolved.group_id),
                    });
                let current_epoch = {
                    candidate_group_id
                        .and_then(|group_id| hex::decode(group_id).ok())
                        .and_then(|gid_bytes| self.mls_context().get_epoch(gid_bytes).ok())
                };

                if current_epoch.is_some_and(|epoch| epoch >= server_epoch) {
                    tracing::info!(
                        conversation_id = %convo_id,
                        local_epoch = current_epoch.unwrap_or_default(),
                        server_epoch,
                        "Clearing stale needs_rejoin flag; local MLS group is already caught up"
                    );
                    if let Err(e) = self.storage().clear_rejoin_flag(convo_id).await {
                        self.report_recovery_storage_failure(convo_id, "clear_rejoin_flag", &e)
                            .await;
                    } else {
                        self.clear_stale_rejoin_state(convo_id).await;
                    }
                    return Ok(DeferredRecoveryOutcome::ClearedStale);
                }
            }
        }

        if !self.should_attempt_sync_rejoin(convo_id).await {
            return Ok(DeferredRecoveryOutcome::Skipped);
        }

        let epoch = self.join_or_rejoin(convo_id).await?;
        Ok(DeferredRecoveryOutcome::Recovered(epoch))
    }

    pub async fn run_deferred_recovery(&self, reason: &str) -> Result<DeferredRecoveryReport> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let conversations = self.storage().list_conversations(&user_did).await?;
        let mut report = DeferredRecoveryReport {
            scanned: conversations.len() as u32,
            ..DeferredRecoveryReport::default()
        };

        tracing::info!(
            reason,
            scanned = report.scanned,
            "Starting Rust-owned deferred recovery sweep"
        );

        for convo in conversations {
            let convo_id = convo.conversation_id;
            let persisted_state = match self.storage().get_conversation_state(&convo_id).await {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!(
                        conversation_id = %convo_id,
                        error = %e,
                        "Failed to read persisted conversation state during deferred recovery sweep"
                    );
                    self.conversation_states()
                        .lock()
                        .await
                        .get(&convo_id)
                        .cloned()
                }
            };

            let needs_rejoin = match self.storage().needs_rejoin(&convo_id).await {
                Ok(flag) => flag,
                Err(e) => {
                    tracing::warn!(
                        conversation_id = %convo_id,
                        error = %e,
                        "needs_rejoin read failed during deferred recovery sweep"
                    );
                    false
                }
            };

            let in_memory_state = if persisted_state.is_none() {
                self.conversation_states()
                    .lock()
                    .await
                    .get(&convo_id)
                    .cloned()
            } else {
                None
            };

            let state_requires_recovery = persisted_state
                .as_ref()
                .is_some_and(Self::state_requires_deferred_recovery)
                || in_memory_state
                    .as_ref()
                    .is_some_and(Self::state_requires_deferred_recovery);

            if !needs_rejoin && !state_requires_recovery {
                continue;
            }

            match self
                .consume_deferred_recovery_for_conversation(&convo_id, None, None)
                .await
            {
                Ok(DeferredRecoveryOutcome::ClearedStale | DeferredRecoveryOutcome::Skipped) => {
                    report.skipped += 1;
                }
                Ok(DeferredRecoveryOutcome::Recovered(epoch)) => {
                    report.attempted += 1;
                    report.recovered += 1;
                    tracing::info!(
                        conversation_id = %convo_id,
                        epoch,
                        reason,
                        "Deferred recovery succeeded"
                    );
                }
                Err(err) => {
                    report.attempted += 1;
                    report.failed += 1;
                    tracing::warn!(
                        conversation_id = %convo_id,
                        error = %err,
                        reason,
                        "Deferred recovery attempt failed"
                    );
                }
            }
        }

        Ok(report)
    }

    async fn enforce_rejoin_backoff(&self, convo_id: &str) -> Result<()> {
        // E7 runtime expiry: a maxed-out lockout that lapsed while this
        // process was running re-opens exactly one attempt (clamp to
        // max-1), mirroring the hydration clamp and the Swift twin's
        // runtime quarantine removal. Update the persisted row to match so
        // a restart sees the same clamped state.
        let (clamp, pre_clamp_entry) = {
            let mut tracker = self.recovery_tracker().lock().await;
            let prior = tracker.failed_rejoins.get(convo_id).cloned();
            (tracker.expire_lapsed_lockout(convo_id), prior)
        };
        if let Some((clamped_count, last_attempt_at_ms)) = clamp {
            tracing::info!(
                convo_id,
                clamped_count,
                "Maxed-out rejoin lockout lapsed at runtime — clamping below max (one fresh attempt re-opens)"
            );
            if clamped_count == 0 {
                if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
                    let mut tracker = self.recovery_tracker().lock().await;
                    if let Some(prior) = pre_clamp_entry.clone() {
                        tracker.failed_rejoins.insert(convo_id.to_string(), prior);
                    }
                    drop(tracker);
                    self.report_recovery_storage_failure(convo_id, "clear_recovery_backoff", &e)
                        .await;
                    return Err(e);
                }
            } else {
                let entry = PersistedRecoveryBackoff {
                    conversation_id: convo_id.to_string(),
                    failed_rejoin_count: clamped_count,
                    last_attempt_at_ms,
                    quarantined_until_ms: None,
                };
                if let Err(e) = self.storage().set_recovery_backoff(&entry).await {
                    let mut tracker = self.recovery_tracker().lock().await;
                    if let Some(prior) = pre_clamp_entry.clone() {
                        tracker.failed_rejoins.insert(convo_id.to_string(), prior);
                    }
                    drop(tracker);
                    self.report_recovery_storage_failure(convo_id, "set_recovery_backoff", &e)
                        .await;
                    return Err(e);
                }
            }
        }

        let tracker = self.recovery_tracker().lock().await;
        if tracker.is_maxed_out(convo_id) {
            tracing::warn!(
                convo_id,
                max_attempts = self.config().max_rejoin_attempts,
                "Rejoin suppressed: max attempts reached, reporting recovery failure"
            );
            crate::info_log!(
                "[gate] convo={} REJECT: max attempts ({}) reached, reporting recovery failure",
                convo_id,
                self.config().max_rejoin_attempts
            );
            // Drop lock before async call
            drop(tracker);
            // Report failure to server for quorum-based auto-reset. Bind the
            // report to the local epoch_authenticator (ADR-002 / §8.6) so
            // stale clients can't forge quorum votes. `None` retains pre-A7
            // behavior; servers that accept the hint will reject mismatched
            // authenticators.
            //
            // ADR-008 D1 (spec §8.6.1): classify as `local_state_loss`. By
            // the time we reach `external_commit_exhausted`, malformed
            // GroupInfo (Mode B) has already short-circuited via
            // `is_remote_data_error` below; remaining failures are typically
            // network / OpenMLS storage issues that should self-heal via
            // §6.6 / §8.4 instead of triggering a global reset.
            let authenticator = self.epoch_authenticator_hex(convo_id).await;
            let _ = self
                .submit_reset_request_prepared(convo_id, "external_commit_exhausted")
                .await;
            return Err(OrchestratorError::RecoveryFailed(format!(
                "Rejoin suppressed for {convo_id}: max attempts reached"
            )));
        }

        if let Some(remaining) = tracker.cooldown_remaining(convo_id) {
            tracing::info!(
                convo_id,
                remaining_secs = remaining.as_secs(),
                "Rejoin suppressed: cooldown active"
            );
            crate::info_log!(
                "[gate] convo={} REJECT: per-convo backoff active ({}s remaining, after {} failures)",
                convo_id,
                remaining.as_secs(),
                tracker.failed_attempts(convo_id)
            );
            return Err(OrchestratorError::RecoveryFailed(format!(
                "Rejoin suppressed for {convo_id}: cooldown active ({}s remaining)",
                remaining.as_secs()
            )));
        }

        // Hard minimum interval between any rejoin attempts (even successful ones)
        if let Some(last) = tracker.last_global_rejoin_at {
            let elapsed = last.elapsed();
            if elapsed < constants::MIN_REJOIN_INTERVAL {
                let remaining = constants::MIN_REJOIN_INTERVAL - elapsed;
                tracing::info!(
                    convo_id,
                    remaining_secs = remaining.as_secs(),
                    "Rejoin suppressed: minimum interval not elapsed"
                );
                crate::info_log!(
                    "[gate] convo={} REJECT: global MIN_REJOIN_INTERVAL ({}s remaining)",
                    convo_id,
                    remaining.as_secs()
                );
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Rejoin suppressed for {convo_id}: minimum interval ({}s remaining)",
                    remaining.as_secs()
                )));
            }
        }

        Ok(())
    }

    /// Log a recovery-critical storage-write failure and surface it through
    /// the platform event observer (WS-5.2). Never silent: losing one of
    /// these writes cancels deferred recovery across restart.
    pub(crate) async fn report_recovery_storage_failure(
        &self,
        convo_id: &str,
        operation: &str,
        error: &OrchestratorError,
    ) {
        tracing::error!(
            convo_id,
            operation,
            error = %error,
            "Recovery-critical storage write failed — deferred recovery state may be lost"
        );
        // Also route through the platform logging facility (MLSLogger):
        // Android/iOS never see `tracing` output (no subscriber outside the
        // echo-bot feature), so without this the failure is invisible on
        // platforms that haven't wired the event observer yet.
        crate::error_log!(
            "[recovery-storage] convo={} op={} CRITICAL: storage write failed ({}) — deferred recovery state may be lost",
            convo_id,
            operation,
            error
        );
        if let Some(obs) = self.current_event_observer().await {
            obs.on_recovery_storage_write_failed(convo_id, operation, &error.to_string());
        }
    }

    /// Check the reset authority while the caller owns the per-conversation
    /// transition lock. A cached ResetPending projection is monotonic: only an
    /// exact completion CAS or explicit delete may clear it.
    pub(crate) async fn reset_blocks_non_reset_transition_locked(
        &self,
        convo_id: &str,
    ) -> Result<bool> {
        if self.reset_pending_payload_result(convo_id).await?.is_some() {
            return Ok(true);
        }
        Ok(matches!(
            self.conversation_states().lock().await.get(convo_id),
            Some(ConversationState::ResetPending { .. })
        ))
    }

    /// Persist and cache a non-reset state while the caller owns the
    /// transition lock. ResetPending always wins and read failures fail closed.
    pub(crate) async fn project_non_reset_state_locked(
        &self,
        convo_id: &str,
        state: ConversationState,
    ) -> Result<bool> {
        debug_assert!(!matches!(state, ConversationState::ResetPending { .. }));
        if self
            .reset_blocks_non_reset_transition_locked(convo_id)
            .await?
        {
            return Ok(false);
        }
        self.storage()
            .set_conversation_state(convo_id, state.clone())
            .await?;
        self.conversation_states()
            .lock()
            .await
            .insert(convo_id.to_string(), state);
        Ok(true)
    }

    pub(crate) async fn project_non_reset_cache_locked(
        &self,
        convo_id: &str,
        state: ConversationState,
    ) -> Result<bool> {
        debug_assert!(!matches!(state, ConversationState::ResetPending { .. }));
        if self
            .reset_blocks_non_reset_transition_locked(convo_id)
            .await?
        {
            return Ok(false);
        }
        self.conversation_states()
            .lock()
            .await
            .insert(convo_id.to_string(), state);
        Ok(true)
    }

    pub(crate) async fn project_runtime_needs_rejoin(&self, convo_id: &str) {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        match self
            .project_non_reset_cache_locked(convo_id, ConversationState::NeedsRejoin)
            .await
        {
            Ok(true) => self.mark_needs_rejoin_critical(convo_id).await,
            Ok(false) => {}
            Err(e) => {
                self.report_recovery_storage_failure(
                    convo_id,
                    "project_runtime_needs_rejoin:reset_authority_read",
                    &e,
                )
                .await;
            }
        }
    }

    pub(crate) async fn project_runtime_active(&self, convo_id: &str) {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        if let Err(e) = self
            .project_non_reset_cache_locked(convo_id, ConversationState::Active)
            .await
        {
            self.report_recovery_storage_failure(
                convo_id,
                "project_runtime_active:reset_authority_read",
                &e,
            )
            .await;
        }
    }

    pub(crate) async fn project_fork_detected_if_active(&self, convo_id: &str, epoch: u64) -> bool {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        if self
            .reset_blocks_non_reset_transition_locked(convo_id)
            .await
            .unwrap_or(true)
        {
            return false;
        }
        let mut states = self.conversation_states().lock().await;
        if !matches!(states.get(convo_id), Some(ConversationState::Active) | None) {
            return false;
        }
        states.insert(convo_id.to_string(), ConversationState::ForkDetected);
        drop(states);
        if let Ok(mut fds) = self.fork_detection_states().lock() {
            fds.insert(
                convo_id.to_string(),
                ForkDetectionState {
                    detected_at_epoch: epoch,
                    readd_attempts: 0,
                },
            );
        }
        true
    }

    /// `mark_needs_rejoin` with WS-5.2 escalation: the rejoin flag is what the
    /// deferred-recovery loop consumes, so a dropped write here silently
    /// cancels recovery.
    pub(crate) async fn mark_needs_rejoin_critical(&self, convo_id: &str) {
        if let Err(e) = self.storage().mark_needs_rejoin(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "mark_needs_rejoin", &e)
                .await;
        }
    }

    pub(crate) async fn clear_rejoin_failures(&self, convo_id: &str) -> Result<()> {
        // Successful recovery also resets the session-scoped reissue attempt
        // log so a future (unrelated) welcome failure starts a fresh ladder.
        self.reissue_attempts_mem().lock().await.remove(convo_id);
        // WS-5.4 write-through: successful rejoin clears the persisted entry;
        // `clear` arms the global gate, so persist that too. Do not publish the
        // in-memory success until both durable mutations complete.
        let now_ms = chrono::Utc::now().timestamp_millis();
        self.recovery_tracker().lock().await.last_global_rejoin_at = Some(Instant::now());
        if let Err(e) = self
            .storage()
            .set_last_global_rejoin_attempt_at(now_ms)
            .await
        {
            self.report_recovery_storage_failure(convo_id, "set_last_global_rejoin_attempt_at", &e)
                .await;
            return Err(e);
        }
        if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_recovery_backoff", &e)
                .await;
            return Err(e);
        }
        self.recovery_tracker().lock().await.clear(convo_id);
        Ok(())
    }

    /// Stale-flag housekeeping twin of [`clear_rejoin_failures`]
    /// (`Self::clear_rejoin_failures`). Used by the sync loop when a
    /// persisted `needs_rejoin` flag turns out to be stale (local epoch
    /// already caught up): NO rejoin attempt happened, so this must not arm
    /// the global rejoin gate, must not record a per-convo success, and must
    /// not persist a global-attempt stamp (precedent: the
    /// `record_group_reset` write-through, which deliberately skips the
    /// global-gate write because a non-attempt is not an attempt by this
    /// client).
    pub(crate) async fn clear_stale_rejoin_state(&self, convo_id: &str) {
        self.recovery_tracker()
            .lock()
            .await
            .clear_stale_flag(convo_id);
        // WS-5.4 write-through: drop the persisted backoff row to match the
        // in-memory clear. Escalate failures — a surviving row re-imports a
        // ghost cooldown on the next restart.
        if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_recovery_backoff", &e)
                .await;
        }
        // Intentionally NO set_last_global_rejoin_attempt_at here.
    }

    /// P0.2 (epoch-inflation remediation): a persisted `NeedsRejoin` enum or
    /// `needs_rejoin` boolean MUST NOT force a rejoin when the LOCAL group is
    /// already cryptographically healthy.
    ///
    /// Root cause: a sticky `needs_rejoin` flag is re-projected to NeedsRejoin
    /// at startup with no health probe, dragging a healthy local group through
    /// `ensure_conversation_ready -> join_or_rejoin -> force_rejoin` (delete_group
    /// + External Commit) — the ADR-001 anti-pattern. Each no-op EC + GroupInfo
    /// upload bumps the server's cosmetic `group_info_epoch` counter, producing
    /// the visible "epoch inflation" with no underlying crypto advance.
    ///
    /// "Locally healthy" is gated on both durable state and a CRYPTOGRAPHIC
    /// self-membership check (I4 safety), not merely "an epoch exists": the
    /// durable GroupState must bind the resolved mutable group to this stable
    /// conversation at exactly the crypto epoch, and the group must have a
    /// populated ratchet tree in which THIS device's identity is a current
    /// leaf. A post-merge persistence failure, locally forked/emptied group, or
    /// self-evicted group fails this and still routes to recovery, so we never
    /// erase recovery intent or unblock sends peers cannot decrypt.
    ///
    /// Returns `true` (and clears the stale enum/boolean/counters, projecting
    /// `Active`) when the group is healthy; `false` when the caller should
    /// proceed to project `NeedsRejoin`.
    pub(crate) async fn clear_needs_rejoin_if_locally_healthy(&self, convo_id: &str) -> bool {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        self.clear_needs_rejoin_if_locally_healthy_unlocked(convo_id)
            .await
    }

    /// Same health check while the caller already owns the transition lock.
    async fn clear_needs_rejoin_if_locally_healthy_unlocked(&self, convo_id: &str) -> bool {
        match self.reset_pending_payload_result(convo_id).await {
            Ok(Some(_)) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} reset authority present -> keeping NeedsRejoin",
                    convo_id
                );
                return false;
            }
            Ok(None) => {}
            Err(err) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} reset authority read FAILED ({}) -> keeping NeedsRejoin",
                    convo_id,
                    err
                );
                return false;
            }
        }

        let resolved = match self.resolve_conversation_context(convo_id).await {
            Ok(resolved) => resolved,
            Err(err) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin group resolution FAILED ({}) -> keeping NeedsRejoin",
                    convo_id, err
                );
                return false;
            }
        };
        let group_id_bytes = match resolved.group_id_bytes() {
            Err(err) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin group id invalid ({}) -> keeping NeedsRejoin",
                    convo_id, err
                );
                return false;
            }
            Ok(group_id) => group_id,
        };
        let local_epoch = match self.mls_context().get_epoch(group_id_bytes.clone()) {
            Ok(epoch) => epoch,
            Err(crate::MLSError::GroupNotFound { .. }) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin local_group=ABSENT -> keeping NeedsRejoin",
                    convo_id
                );
                return false;
            }
            Err(err) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin local epoch probe FAILED ({}) -> keeping NeedsRejoin",
                    convo_id, err
                );
                return false;
            }
        };

        let durable_group_state = match self.storage().get_group_state(&resolved.group_id).await {
            Ok(Some(state)) => state,
            Ok(None) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin durable group projection=ABSENT -> keeping NeedsRejoin",
                    convo_id
                );
                return false;
            }
            Err(err) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin durable group projection read FAILED ({}) -> keeping NeedsRejoin",
                    convo_id, err
                );
                return false;
            }
        };
        if durable_group_state.group_id != resolved.group_id
            || durable_group_state.conversation_id != resolved.conversation_id
            || durable_group_state.epoch != local_epoch
        {
            crate::warn_log!(
                "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin durable projection does not match resolved crypto state (durable_epoch={} crypto_epoch={}) -> keeping NeedsRejoin",
                convo_id,
                durable_group_state.epoch,
                local_epoch
            );
            return false;
        }

        let members = match self.mls_context().group_member_identities(group_id_bytes) {
            Ok(members) => members,
            Err(err) => {
                crate::warn_log!(
                    "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin epoch={} member probe FAILED ({}) -> keeping NeedsRejoin",
                    convo_id, local_epoch, err
                );
                return false;
            }
        };

        let self_is_member = match self.require_user_did().await {
            Ok(user_did) => members.iter().any(|identity| {
                std::str::from_utf8(identity)
                    .is_ok_and(|text| credential_root_matches_exact(text, &user_did))
            }),
            Err(_) => false,
        };

        if members.is_empty() || !self_is_member {
            crate::warn_log!(
                "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin epoch={} members={} self_is_member={} -> NOT locally healthy, keeping NeedsRejoin",
                convo_id, local_epoch, members.len(), self_is_member
            );
            return false;
        }

        // Healthy local group carrying a stale flag. Clear enum + boolean +
        // counters together (the in-session path messaging.rs cleared only the
        // enum, leaving the boolean to re-arm across restart) and project
        // Active so the startup scan does NOT drive a force_rejoin.
        match self
            .project_non_reset_state_locked(convo_id, ConversationState::Active)
            .await
        {
            Ok(true) => {}
            Ok(false) => return false,
            Err(e) => {
                self.report_recovery_storage_failure(
                    convo_id,
                    "set_conversation_state:active_stale_clear",
                    &e,
                )
                .await;
                return false;
            }
        }
        if let Err(e) = self.storage().clear_rejoin_flag(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_rejoin_flag:stale", &e)
                .await;
        }
        self.clear_stale_rejoin_state(convo_id).await;

        crate::warn_log!(
            "[NEEDSREJOIN-DIAG] convo={} stored=NeedsRejoin but LOCAL HEALTHY (epoch={} members={} self_is_member=true) -> cleared stale flag, projected Active (NO force_rejoin)",
            convo_id, local_epoch, members.len()
        );
        true
    }

    async fn record_rejoin_failure(&self, convo_id: &str) -> Result<()> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let (count, max_attempts) = {
            let mut tracker = self.recovery_tracker().lock().await;
            tracker.record_failure(convo_id);
            (
                tracker.failed_attempts(convo_id),
                self.config().max_rejoin_attempts,
            )
        };
        // WS-5.4 write-through (E7 schema): persist on every state change so
        // restart cannot reset backoff. Maxed-out conversations carry a
        // quarantined_until lockout matching the hydration TTL.
        let entry = PersistedRecoveryBackoff {
            conversation_id: convo_id.to_string(),
            failed_rejoin_count: count,
            last_attempt_at_ms: now_ms,
            quarantined_until_ms: (count >= max_attempts)
                .then(|| now_ms + constants::RECOVERY_BACKOFF_TTL.as_millis() as i64),
        };
        if let Err(e) = self.storage().set_recovery_backoff(&entry).await {
            self.report_recovery_storage_failure(convo_id, "set_recovery_backoff", &e)
                .await;
            return Err(e);
        }
        if let Err(e) = self
            .storage()
            .set_last_global_rejoin_attempt_at(now_ms)
            .await
        {
            self.report_recovery_storage_failure(convo_id, "set_last_global_rejoin_attempt_at", &e)
                .await;
            return Err(e);
        }
        Ok(())
    }

    pub(crate) async fn group_id_hex_for_conversation(&self, convo_id: &str) -> Option<String> {
        self.resolve_conversation_context(convo_id)
            .await
            .ok()
            .map(|resolved| resolved.group_id)
    }

    /// Resolve a stable conversation identifier to its current MLS group.
    ///
    /// Unlike `group_id_hex_for_conversation`, this security boundary never
    /// treats a hex-looking conversation id as a group id. Callers receive a
    /// context only when a server-backed cache, durable conversation record,
    /// or explicit group state binds both identifiers.
    pub(crate) async fn resolve_conversation_context(
        &self,
        conversation_id: &str,
    ) -> Result<ResolvedConversationContext> {
        // A persisted ResetPending payload is the transition authority for a
        // server-directed group rotation. It must precede both ConversationView
        // projections: those rows are refreshed by sync and can legitimately
        // retain the deleted pre-reset group until that refresh completes.
        // This is deliberately narrow; arbitrary group-state cache entries do
        // not gain precedence over server-backed conversation mappings.
        if let Some(pending) = self.reset_pending_payload_result(conversation_id).await? {
            return Ok(ResolvedConversationContext {
                conversation_id: conversation_id.to_string(),
                group_id: pending.new_group_id,
            });
        }

        // The server-refreshed conversation cache is the authoritative O(1)
        // mapping during a live session. It must precede legacy group-state
        // entries, which may survive a group rotation under the stable key.
        {
            let conversations = self.conversations().lock().await;
            if let Some(view) = conversations
                .get(conversation_id)
                .filter(|view| view.conversation_id == conversation_id)
            {
                return Ok(ResolvedConversationContext {
                    conversation_id: view.conversation_id.clone(),
                    group_id: view.group_id.clone(),
                });
            }
        }

        let user_did = self.require_user_did().await?;
        if let Some(view) = self
            .storage()
            .get_conversation(&user_did, conversation_id)
            .await?
            .filter(|view| view.conversation_id == conversation_id)
        {
            return Ok(ResolvedConversationContext {
                conversation_id: view.conversation_id,
                group_id: view.group_id,
            });
        }

        // Compatibility fallback for pre-normalization in-memory state. New
        // group-state entries are keyed by mutable GroupId, so a direct stable
        // key hit is legacy data and is consulted only when neither current
        // cache nor durable storage has an authoritative mapping.
        {
            let states = self.group_states().lock().await;
            if let Some(state) = states
                .get(conversation_id)
                .filter(|state| state.conversation_id == conversation_id)
            {
                return Ok(ResolvedConversationContext {
                    conversation_id: state.conversation_id.clone(),
                    group_id: state.group_id.clone(),
                });
            }
        }

        Err(OrchestratorError::ConversationNotFound(
            conversation_id.to_string(),
        ))
    }

    /// Translate a legacy public bridge identifier documented as `group_id`
    /// into the stable conversation context required by orchestrator member
    /// mutations.
    ///
    /// New callers pass the stable conversation id directly and take the fast
    /// path above. Legacy callers may pass the current mutable MLS group id;
    /// this compatibility path accepts it only when current authoritative
    /// state resolves exactly one stable conversation back to that same group.
    /// Ambiguous or stale group ids fail closed rather than selecting a
    /// conversation by iteration order.
    pub(crate) async fn resolve_legacy_group_identifier(
        &self,
        identifier: &str,
    ) -> Result<ResolvedConversationContext> {
        let mut candidate_conversation_ids = BTreeSet::new();
        candidate_conversation_ids.insert(identifier.to_string());
        {
            let conversations = self.conversations().lock().await;
            candidate_conversation_ids.extend(conversations.keys().cloned());
        }
        {
            let states = self.group_states().lock().await;
            candidate_conversation_ids
                .extend(states.values().map(|state| state.conversation_id.clone()));
        }
        {
            let states = self.conversation_states().lock().await;
            candidate_conversation_ids.extend(states.keys().cloned());
        }

        let user_did = self.require_user_did().await?;
        candidate_conversation_ids.extend(
            self.storage()
                .list_conversations(&user_did)
                .await?
                .into_iter()
                .map(|view| view.conversation_id),
        );

        let mut matches = std::collections::BTreeMap::new();
        for conversation_id in candidate_conversation_ids {
            match self.resolve_conversation_context(&conversation_id).await {
                Ok(resolved)
                    if resolved.conversation_id == identifier
                        || resolved.group_id == identifier =>
                {
                    matches.insert(resolved.conversation_id.clone(), resolved);
                }
                Ok(_) | Err(OrchestratorError::ConversationNotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }

        match matches.len() {
            0 => Err(OrchestratorError::ConversationNotFound(
                identifier.to_string(),
            )),
            1 => Ok(matches.into_values().next().expect("one legacy id match")),
            count => Err(OrchestratorError::InvalidInput(format!(
                "mutable MLS group id {identifier} resolves to {count} stable conversations"
            ))),
        }
    }

    pub(crate) async fn group_id_bytes_for_conversation(&self, convo_id: &str) -> Option<Vec<u8>> {
        let group_id_hex = self.group_id_hex_for_conversation(convo_id).await?;
        hex::decode(group_id_hex).ok()
    }

    /// Snapshot the locally materialized group bound to a stable conversation
    /// before destructive force-rejoin cleanup.
    ///
    /// The server-authoritative conversation mapping can legitimately advance
    /// to a reset target that this device has not joined yet. Deleting that
    /// absent target would leave the old local group (and its epoch secrets)
    /// behind. Prefer a group-state entry explicitly bound to this stable
    /// conversation only when its decoded group is still present in the MLS
    /// context; otherwise retain the normal authoritative-resolution fallback.
    async fn group_ids_for_force_rejoin_cleanup(&self, convo_id: &str) -> Vec<Vec<u8>> {
        let local_candidates = {
            let states = self.group_states().lock().await;
            states
                .values()
                .filter(|state| state.conversation_id == convo_id)
                .map(|state| state.group_id.clone())
                .collect::<Vec<_>>()
        };

        // Distinct MLS groups do not share an epoch space, so no single
        // candidate can be selected by comparing epochs. Snapshot every
        // context-resident group explicitly bound to this conversation.
        let mut materialized = Vec::new();
        for group_id_hex in local_candidates {
            let Ok(group_id_bytes) = hex::decode(group_id_hex) else {
                continue;
            };
            if self.mls_context().group_exists(group_id_bytes.clone())
                && !materialized.contains(&group_id_bytes)
            {
                materialized.push(group_id_bytes);
            }
        }
        if let Some(authoritative) = self.group_id_bytes_for_conversation(convo_id).await {
            if self.mls_context().group_exists(authoritative.clone())
                && !materialized.contains(&authoritative)
            {
                materialized.push(authoritative);
            }
        }
        materialized
    }

    /// Snapshot every MLS group whose local secrets must be gone before a
    /// local conversation delete may clear reset authority or its durable
    /// conversation mapping.
    pub(crate) async fn snapshot_local_delete_groups(
        &self,
        convo_id: &str,
        captured_group_ids: &[String],
        captured_group_state_keys: &[String],
    ) -> Result<LocalDeleteSnapshot> {
        let reset_pending = self.reset_pending_payload_result(convo_id).await?;
        let mut group_ids = BTreeSet::new();
        let mut group_state_keys = BTreeSet::new();

        group_ids.extend(captured_group_ids.iter().cloned());
        group_state_keys.extend(captured_group_state_keys.iter().cloned());
        if let Some(pending) = reset_pending.as_ref() {
            group_ids.insert(pending.new_group_id.clone());
        }
        let cached_conversation = self.conversations().lock().await.get(convo_id).cloned();
        if let Some(view) = cached_conversation.as_ref() {
            group_ids.insert(view.group_id.clone());
        }

        let user_did = self.cleanup_user_did().await?;
        let durable_conversation = self.storage().get_conversation(&user_did, convo_id).await?;
        if let Some(view) = durable_conversation.as_ref() {
            group_ids.insert(view.group_id.clone());
        }

        // On startup the in-memory group-state cache is intentionally empty.
        // Enumerate the reopened MLS database and re-associate each group via
        // its durable GroupState so every predecessor captured before the
        // crash remains discoverable. Enumeration failure is security
        // relevant and propagates closed.
        for local_group_id in self.mls_context().list_local_group_ids()? {
            let local_group_id_hex = hex::encode(&local_group_id);
            if let Some(state) = self.storage().get_group_state(&local_group_id_hex).await? {
                if state.conversation_id == convo_id {
                    group_state_keys.insert(local_group_id_hex);
                    group_ids.insert(state.group_id);
                }
            }
        }

        {
            let states = self.group_states().lock().await;
            for (key, state) in states
                .iter()
                .filter(|(_, state)| state.conversation_id == convo_id)
            {
                group_state_keys.insert(key.clone());
                group_ids.insert(state.group_id.clone());
            }
        }

        let mut groups = Vec::with_capacity(group_ids.len());
        for group_id in group_ids {
            let decoded = hex::decode(&group_id).map_err(|error| {
                OrchestratorError::InvalidInput(format!(
                    "local delete discovered malformed MLS group id {group_id}: {error}"
                ))
            })?;
            let epoch = match self.mls_context().get_epoch(decoded) {
                Ok(epoch) => Some(epoch),
                Err(crate::MLSError::GroupNotFound { .. }) => None,
                Err(error) => return Err(error.into()),
            };
            groups.push(LocalDeleteGroupFence {
                group_id_hex: group_id,
                epoch,
            });
        }

        Ok(LocalDeleteSnapshot {
            groups,
            group_state_keys: group_state_keys.into_iter().collect(),
            // Durable application state is the restart fence. The cache is a
            // fallback only during the narrow pre-persistence creation window.
            conversation: durable_conversation.or(cached_conversation).map(|view| {
                LocalDeleteConversationFence {
                    group_id: view.group_id,
                    epoch: view.epoch,
                }
            }),
            reset: reset_pending.map(|pending| LocalDeleteResetFence {
                new_group_id: pending.new_group_id,
                reset_generation: pending.reset_generation,
            }),
        })
    }

    pub(crate) async fn local_group_epoch(&self, convo_id: &str) -> Option<u64> {
        let group_id_bytes = self.group_id_bytes_for_conversation(convo_id).await?;
        self.mls_context().get_epoch(group_id_bytes).ok()
    }

    pub(crate) async fn local_group_epoch_result(
        &self,
        convo_id: &str,
    ) -> std::result::Result<Option<u64>, crate::MLSError> {
        let Some(group_id_bytes) = self.group_id_bytes_for_conversation(convo_id).await else {
            return Ok(None);
        };

        match self.mls_context().get_epoch(group_id_bytes) {
            Ok(epoch) => Ok(Some(epoch)),
            Err(crate::MLSError::GroupNotFound { .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Fulfill a Welcome-reissue request as an admin member, in rustFull mode.
    ///
    /// Mirrors [`swap_members`](Self::swap_members) (no external commit) but
    /// resolves the recipient's stale leaf internally and threads `request_id`
    /// as the server idempotency key so the delivery service marks the request
    /// answered (`mark_reissue_request_answered_tx`). Only a current group
    /// member with the group secrets can seal a Welcome, so this is necessarily
    /// an admin-client duty — in rustFull the admin's crypto lives here.
    ///
    /// Idempotent against the wire: a repeat call with the same `request_id` is
    /// absorbed by the server idempotency key + the epoch fence (the DS replays
    /// the answered request without advancing the epoch, so the fence discards
    /// the duplicate staged commit and the local epoch does not advance again).
    ///
    /// Returns a typed [`OrchestratorError::RecoveryFailed`] — which the Swift
    /// layer classifies as "unfulfillable here" so the requester stops
    /// retrying — when this device has no local state for the group or the
    /// recipient has no leaf to swap.
    pub async fn respond_to_welcome_reissue(
        &self,
        convo_id: &str,
        recipient_device_did: &str,
        request_id: &str,
    ) -> Result<()> {
        self.check_shutdown().await?;

        let resolved = match self.resolve_conversation_context(convo_id).await {
            Ok(resolved) => resolved,
            Err(_) => {
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "convo {convo_id} not present in local MLS group state"
                )))
            }
        };
        let group_id = resolved.group_id.clone();

        let recipient_user_did =
            super::credential_binding::credential_root_did(recipient_device_did).to_string();

        tracing::info!(
            convo_id,
            group_id = %group_id,
            request_id,
            "respond_to_welcome_reissue"
        );

        // Compute remove_dids: every local leaf whose credential identity maps
        // to the recipient user (mirror Swift `removeIdentities` — split the
        // device-qualified DID at `#`, and compare the method-specific
        // identifier exactly. DID roots are not globally case-insensitive.
        let group_id_bytes = hex::decode(&group_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;
        let identities = self.mls_context().group_member_identities(group_id_bytes)?;
        let remove_dids: Vec<String> = identities
            .iter()
            .filter_map(|raw| String::from_utf8(raw.clone()).ok())
            .filter(|id| credential_root_matches_exact(id, &recipient_user_did))
            .collect();
        if remove_dids.is_empty() {
            // No leaf for the recipient locally — this device is not a current
            // member of the group (or the recipient is already gone), so it
            // cannot fulfill the reissue. Surface the typed unfulfillable error.
            return Err(OrchestratorError::RecoveryFailed(format!(
                "recipient {recipient_user_did} not present in local MLS group state"
            )));
        }
        let current_group_id = resolved.group_id_bytes()?;
        let (metadata_plaintext, metadata_version) = self
            .decrypt_current_metadata_snapshot(&resolved.conversation_id, &current_group_id)
            .await?;

        // Fetch a fresh key package for the recipient and stage the swap. Same
        // body shape as `swap_members`, but ships through
        // `add_members_with_idempotency` so the DS answers the reissue request.
        let key_packages = self
            .api_client()
            .get_key_packages(
                &self.require_actor_device_id().await?,
                &[recipient_user_did.clone()],
            )
            .await?;
        self.verify_fetched_key_packages(
            &[recipient_user_did.clone()],
            &key_packages,
            "respond_to_welcome_reissue",
            Some(&resolved.conversation_id),
        )
        .await?;
        let kp_data: Vec<crate::KeyPackageData> = key_packages
            .iter()
            .map(|kp| crate::KeyPackageData {
                data: kp.key_package_data.clone(),
            })
            .collect();

        let plan = self
            .stage_commit_for_group(
                &resolved.conversation_id,
                &resolved.group_id,
                CommitKind::SwapMembers {
                    remove_dids: remove_dids.clone(),
                    add_dids: vec![recipient_user_did.clone()],
                    add_key_packages: kp_data,
                },
            )
            .await?;

        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential(
                "auth_generation must be >= 1".into(),
            ));
        }
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);
        let group_id_bytes = resolved.group_id_bytes()?;
        let tag_bytes = self
            .mls_context()
            .get_confirmation_tag(group_id_bytes.clone())?;
        if tag_bytes.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "confirmation tag must be exactly 32 bytes, got {}",
                tag_bytes.len()
            ))));
        }
        let gc_hash = self
            .mls_context()
            .get_group_context_hash(group_id_bytes.clone())?;
        if gc_hash.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "group context hash must be exactly 32 bytes, got {}",
                gc_hash.len()
            ))));
        }
        let convo_uuid = uuid::Uuid::parse_str(&resolved.conversation_id).map_err(|e| {
            OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}"))
        })?;

        let metadata = (|| -> Result<([u8; 12], Vec<u8>)> {
            use rand::RngCore;
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            let metadata_key: [u8; 32] = self
                .mls_context()
                .export_metadata_key_from_pending(group_id_bytes.clone(), plan.target_epoch)?
                .try_into()
                .map_err(|_| {
                    OrchestratorError::Mls(MLSError::Internal(
                        "pending metadata key length mismatch".into(),
                    ))
                })?;
            let ciphertext = crate::metadata::encrypt_metadata_snapshot_with_nonce(
                &metadata_key,
                &group_id_bytes,
                plan.target_epoch,
                metadata_version,
                &nonce,
                &metadata_plaintext,
            )
            .map_err(|error| {
                OrchestratorError::Mls(MLSError::Internal(format!(
                    "encrypt metadata snapshot: {error:?}"
                )))
            })?;
            Ok((nonce, ciphertext))
        })();
        let (nonce, ciphertext) = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                self.discard_pending_after_failed_operation(
                    plan.handle,
                    "respond_to_welcome_reissue metadata",
                    &error.to_string(),
                )
                .await?;
                return Err(error);
            }
        };
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use sha2::{Digest, Sha256};

        let transition_id = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
            "aad": {
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": 0,
                "prior": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": plan.target_epoch.saturating_sub(1),
                    "generation": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                    "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                    "lifecycle": "active",
                    "stateVersion": 0
                },
                "protocolVersion": "1",
                "transitionId": STANDARD.encode(uuid::Uuid::parse_str(&transition_id).map_err(|e| OrchestratorError::InvalidInput(e.to_string()))?.as_bytes())
            },
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "commit": {
                "bytes": { "$bytes": STANDARD.encode(&plan.commit_bytes) },
                "contentType": "publicMessageCommit",
                "framing": "mlsMessage",
                "sha256": STANDARD.encode(Sha256::digest(&plan.commit_bytes))
            },
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "keyId": key_id,
            "manifest": {
                "leafChanges": [],
                "participantChanges": []
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": auth_generation,
                    "authorDeviceId": actor_device_id,
                    "authorDid": user_did,
                    "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active",
                    "originSeq": 1,
                    "originTransitionId": transition_id,
                    "roleAtOrigin": "admin",
                    "signaturePublicKey": { "$bytes": STANDARD.encode(&public_key) }
                },
                "ciphertext": { "$bytes": STANDARD.encode(&ciphertext) },
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": plan.target_epoch,
                    "generation": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                    "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) }
                },
                "metadataVersion": metadata_version,
                "nonce": { "$bytes": STANDARD.encode(&nonce) },
                "originTransitionId": transition_id
            },
            "next": {
                "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                "conversationId": resolved.conversation_id.clone(),
                "epoch": plan.target_epoch,
                "generation": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                "lifecycle": "active",
                "stateVersion": 0
            },
            "prior": {
                "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                "conversationId": resolved.conversation_id.clone(),
                "epoch": plan.target_epoch.saturating_sub(1),
                "generation": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                "lifecycle": "active",
                "stateVersion": 0
            },
            "recoveryRequestId": request_id,
            "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "transitionId": transition_id
        });

        let server_resp = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::SubmitTransition,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await;

        let server_result: std::result::Result<AddMembersServerResult, OrchestratorError> =
            match server_resp {
                Ok(resp) if resp.status == 200 => {
                    let resp_json: serde_json::Value =
                        serde_json::from_slice(&resp.body).map_err(|e| {
                            OrchestratorError::Serialization(format!(
                                "SubmitTransition response: {e}"
                            ))
                        })?;
                    let epoch = resp_json
                        .get("result")
                        .and_then(|r| r.get("epoch"))
                        .and_then(|e| e.as_u64())
                        .unwrap_or(plan.target_epoch);
                    Ok(AddMembersServerResult {
                        success: true,
                        new_epoch: epoch,
                        receipt: None,
                    })
                }
                Ok(resp) => Err(OrchestratorError::Api(format!(
                    "respond_to_welcome_reissue failed with status {}",
                    resp.status
                ))),
                Err(e) => Err(e),
            };
        match server_result {
            Ok(result) => {
                if !result.success {
                    self.discard_pending_after_failed_operation(
                        plan.handle,
                        "respond_to_welcome_reissue",
                        "server returned success=false",
                    )
                    .await?;
                    return Err(OrchestratorError::MemberSyncFailed);
                }
                if let Some(ref receipt) = result.receipt {
                    self.record_and_check_sequencer_receipt(receipt, "respond_to_welcome_reissue")
                        .await;
                }
                // An idempotent replay returns the prior accepted epoch. Only
                // the exact staged target may authorize this local merge.
                if result.new_epoch == plan.target_epoch {
                    self.confirm_commit(plan.handle, result.new_epoch).await?;
                } else {
                    self.discard_pending_after_failed_operation(
                        plan.handle,
                        "respond_to_welcome_reissue idempotent response",
                        "server epoch did not equal staged target",
                    )
                    .await?;
                }
                tracing::info!(convo_id, request_id, "respond_to_welcome_reissue complete");
                Ok(())
            }
            Err(e) => {
                self.discard_pending_after_failed_operation(
                    plan.handle,
                    "respond_to_welcome_reissue",
                    &e.to_string(),
                )
                .await?;
                Err(e)
            }
        }
    }

    /// Best-effort helper that returns the hex-encoded epoch_authenticator for
    /// the group currently bound to `convo_id`.
    ///
    /// Resolves through the authoritative stable-conversation mapping before
    /// asking the MLS context for the active group's authenticator.
    /// Returns `None` if the context can't produce an authenticator (platform
    /// default stub, missing group, or remote-data error) so the caller can
    /// pass the original pre-A7 `None` payload.
    pub(crate) async fn epoch_authenticator_hex(&self, convo_id: &str) -> Option<String> {
        let group_id_bytes = self
            .resolve_conversation_context(convo_id)
            .await
            .ok()?
            .group_id_bytes()
            .ok()?;

        self.mls_context()
            .epoch_authenticator(group_id_bytes)
            .ok()
            .map(hex::encode)
    }

    async fn force_rejoin_unlocked(&self, convo_id: &str, user_did: &str) -> Result<()> {
        tracing::info!(convo_id, "Attempting force rejoin via External Commit");

        // Layer 3: refuse force_rejoin entry on a quarantined conversation.
        // Quarantine means we have classified recent failures as peer-bad; an
        // External Commit here would just feed the epoch storm we are trying
        // to break. Caller must clear quarantine via server reset, healthy
        // peer commit, or user_confirmed_manual_reset.
        if let Some(q) = self
            .recovery_tracker()
            .lock()
            .await
            .quarantine_snapshot(convo_id)
        {
            tracing::warn!(
                convo_id,
                reason = q.reason.tag(),
                "force_rejoin refused: conversation is quarantined (Layer 3)"
            );
            return Err(OrchestratorError::ConversationQuarantined {
                convo_id: convo_id.to_string(),
                reason: q.reason.tag().to_string(),
            });
        }

        // Check GroupInfo 404 circuit breaker
        {
            let tracker = self.groupinfo_404_tracker().lock().await;
            if tracker.is_tripped(convo_id) {
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "GroupInfo 404 circuit breaker tripped for {convo_id}"
                )));
            }
        }

        // Fetch GroupInfo from server FIRST — only delete local state after success
        // (spec: preserve local state if fetch fails so we can still decrypt)
        let group_info = match self.api_client().get_group_info(convo_id).await {
            Ok(gi) => {
                // Success: clear 404 counter
                self.groupinfo_404_tracker().lock().await.clear(convo_id);
                gi
            }
            Err(e) => {
                // Check if this is a 404-like error
                let err_str = e.to_string().to_lowercase();
                let is_404 = err_str.contains("404")
                    || err_str.contains("not found")
                    || err_str.contains("notfound");
                if is_404 {
                    self.groupinfo_404_tracker()
                        .lock()
                        .await
                        .record_404(convo_id);
                }
                tracing::error!(error = %e, "Failed to fetch GroupInfo for rejoin");
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Failed to fetch GroupInfo: {e}"
                )));
            }
        };

        // Parse and bind the DS-controlled GroupInfo before deleting any local
        // MLS state. The stable conversation mapping is authoritative for the
        // current mutable group ID; a valid GroupInfo from another conversation
        // must not gain destructive authority merely because it was routed
        // under this conversation ID.
        let advertised_group_id = advertised_group_id_from_group_info(&group_info)?;
        let resolved = self.resolve_conversation_context(convo_id).await?;
        let authoritative_group_id = resolved.group_id_bytes()?;
        if advertised_group_id != authoritative_group_id {
            return Err(OrchestratorError::RecoveryFailed(format!(
                "GroupInfo group binding mismatch for conversation {convo_id}"
            )));
        }

        // GroupInfo fetched successfully — now delete old local group state.
        // Prefer a locally materialized group bound to this stable conversation;
        // the authoritative mapping may already name an as-yet-unjoined reset
        // target. Fall back to authoritative resolution without interpreting
        // the stable ID as MLS group bytes.
        delete_materialized_force_rejoin_groups(
            self.group_ids_for_force_rejoin_cleanup(convo_id).await,
            |group_id| self.mls_context().delete_group(group_id),
        )?;

        // Create External Commit
        let scoped_identity = self.require_scoped_identity().await?;
        let identity_bytes = scoped_identity.into_bytes();
        let ext_commit_result = match self
            .mls_context()
            .create_external_commit(group_info, identity_bytes)
        {
            Ok(result) => result,
            Err(e) => {
                let err = OrchestratorError::RecoveryFailed(format!("External Commit failed: {e}"));
                // Remote data errors (malformed GroupInfo) are unrecoverable —
                // don't burn retries or delete local state further.
                if err.is_remote_data_error() {
                    tracing::error!(
                        convo_id,
                        error = %e,
                        "External Commit failed due to malformed remote data — marking unrecoverable"
                    );
                    // Transition to Failed state without incrementing failure counter.
                    // ADR-008 D1: classify as `group_state_unrecoverable` —
                    // a `remote_data_error` is by definition Mode B (the
                    // server-side ratchet/GroupInfo is malformed), so this
                    // report SHOULD count toward server-side quorum auto-reset.
                    let authenticator = self.epoch_authenticator_hex(convo_id).await;
                    let _ = self
                        .submit_reset_request_prepared(convo_id, "remote_data_error")
                        .await;
                    return Err(err);
                }
                tracing::error!(error = %e, "External Commit creation failed");
                return Err(err);
            }
        };

        // group_id_hex used below when updating group state

        // Track our own External Commit so that when the server fans it back
        // through `process_incoming` (`messaging.rs:489-503`), the inbound
        // pipeline recognizes the ciphertext hash as ours and short-circuits
        // before invoking `decrypt_message`. Mirrors the pattern used by
        // `groups.rs:151`, `groups.rs:668`, `staged_commit.rs:156`, and
        // `messaging.rs:181, 371` for all other commit producers. The dedup
        // key is `sha2::Sha256::digest(ciphertext)`; the entry is evicted
        // after `OWN_COMMIT_TTL` (`constants.rs`, 300s) by `evict_stale_commits`.
        let commit_hash = Sha256::digest(&ext_commit_result.commit_data).to_vec();
        let target_epoch = self
            .mls_context()
            .get_epoch(ext_commit_result.group_id.clone())?;
        self.track_epoch_changing_own_commit(
            commit_hash.clone(),
            OwnCommitExpectation {
                conversation_id: convo_id.to_string(),
                group_id: hex::encode(&ext_commit_result.group_id),
                target_epoch,
            },
        )
        .await;

        // Get confirmation tag from the new local group state
        let tag_b64 = self
            .mls_context()
            .get_confirmation_tag(ext_commit_result.group_id.clone())
            .map(|tag| base64::engine::general_purpose::STANDARD.encode(&tag))
            .ok();

        // Send commit to server via the processExternalCommit endpoint
        // (NOT sendMessage — that endpoint validates padding/epoch/membership which don't apply)
        let ext_commit_server_result = match self
            .submit_external_commit_prepared(convo_id, &ext_commit_result.commit_data, target_epoch)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                // A rejected/ambiguous External Commit must not strand a
                // materialized candidate group. Surface cleanup failure and
                // retain durable recovery authority instead of returning only
                // the network error.
                if let Err(cleanup_error) = self
                    .mls_context()
                    .discard_pending_external_join(ext_commit_result.group_id.clone())
                {
                    self.mark_needs_rejoin_critical(convo_id).await;
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "Failed to send external commit ({e}); candidate cleanup also failed: {cleanup_error}"
                    )));
                }
                self.remove_own_commit_tracking(&commit_hash).await;
                if matches!(e, OrchestratorError::EpochMismatch { .. }) {
                    return Err(e);
                }
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Failed to send external commit: {e}"
                )));
            }
        };

        // The callback is attacker-controlled DS evidence. Advancing merely
        // "past" the local epoch could acknowledge a different commit or a
        // different history; require the exact locally staged target before
        // merging the candidate group.
        if ext_commit_server_result.epoch != target_epoch {
            let cleanup = self
                .mls_context()
                .discard_pending_external_join(ext_commit_result.group_id.clone());
            self.remove_own_commit_tracking(&commit_hash).await;
            self.mark_needs_rejoin_critical(convo_id).await;
            if let Err(cleanup_error) = cleanup {
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "External Commit epoch mismatch (local target {target_epoch}, server {}); candidate cleanup failed: {cleanup_error}",
                    ext_commit_server_result.epoch
                )));
            }
            return Err(OrchestratorError::EpochMismatch {
                local: target_epoch,
                remote: ext_commit_server_result.epoch,
            });
        }

        // Best-effort receipt storage, preceded by sequencer-equivocation
        // detection against previously stored receipts for this conversation
        // (WS-3 stage 1, ADR-009 D8 / backlog E3). Stage 1 is detection-only:
        // on conflict this logs loudly and escalates via the event observer,
        // then the rejoin proceeds unchanged.
        if let Some(ref receipt) = ext_commit_server_result.receipt {
            self.record_and_check_sequencer_receipt(receipt, "external_commit")
                .await;
        }

        // Merge the external join locally
        let merged = self
            .mls_context()
            .merge_pending_commit(ext_commit_result.group_id.clone())
            .map_err(|e| {
                OrchestratorError::RecoveryFailed(format!("Failed to merge external commit: {e}"))
            })?;

        // Persist the new group projection before publishing it in memory or
        // clearing any recovery state. A merged External Commit without this
        // durable conversation -> group binding is not a completed recovery:
        // restart would lose the mapping while the server has already advanced.
        let new_group_id_hex = hex::encode(&ext_commit_result.group_id);
        let state = {
            let states = self.group_states().lock().await;
            let mut state = states
                .get(&new_group_id_hex)
                .cloned()
                .unwrap_or_else(|| GroupState {
                    group_id: new_group_id_hex.clone(),
                    conversation_id: convo_id.to_string(),
                    epoch: 0,
                    members: vec![],
                });
            state.group_id = new_group_id_hex.clone();
            state.conversation_id = convo_id.to_string();
            state.epoch = merged;
            state
        };
        if let Err(error) = self.storage().set_group_state(&state).await {
            self.report_recovery_storage_failure(convo_id, "set_group_state:force_rejoin", &error)
                .await;
            // The cryptographic merge succeeded, but without the durable
            // stable-conversation mapping a subsequent health probe could
            // mistake this half-completed recovery for a healthy group and
            // clear NeedsRejoin. Remove the uncommitted local projection so a
            // retry must traverse recovery again instead of bypassing the
            // failed durability boundary.
            let cleanup_error = match self
                .mls_context()
                .delete_group(ext_commit_result.group_id.clone())
            {
                Ok(()) | Err(crate::MLSError::GroupNotFound { .. }) => None,
                Err(cleanup_error) => Some(cleanup_error),
            };
            match self
                .project_non_reset_state_locked(convo_id, ConversationState::NeedsRejoin)
                .await
            {
                Ok(true) | Ok(false) => {}
                Err(state_error) => {
                    self.report_recovery_storage_failure(
                        convo_id,
                        "set_conversation_state:force_rejoin_persistence_failure",
                        &state_error,
                    )
                    .await;
                }
            }
            self.mark_needs_rejoin_critical(convo_id).await;
            if let Some(cleanup_error) = cleanup_error {
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "group-state persistence failed ({error}); failed to remove the undurable rejoin group ({cleanup_error})"
                )));
            }
            return Err(error);
        }
        {
            let mut states = self.group_states().lock().await;
            states.retain(|key, existing| {
                key == &new_group_id_hex || existing.conversation_id != convo_id
            });
            states.insert(new_group_id_hex, state);
        }

        // Secret pruning is post-commit bookkeeping. Do not run it until the
        // new stable-conversation projection is durable and installed in the
        // in-memory cache; otherwise a failed persistence boundary could both
        // remove the recovery group and prune the only remaining epoch data.
        let merged_group_id = hex::encode(&ext_commit_result.group_id);
        self.cleanup_epoch_secrets_if_needed(convo_id, &merged_group_id, merged)
            .await;

        // Clear rejoin flag
        if let Err(e) = self.storage().clear_rejoin_flag(convo_id).await {
            tracing::warn!(error = %e, convo_id, "Failed to clear rejoin flag after force rejoin");
        }

        // Insert history boundary marker for device rejoin.
        // On iOS, Swift inserts first with the correct content key — the message_exists
        // check below prevents duplicates. On catmos/WASM, this is the only inserter.
        let marker_id = format!("hb-{}-{}", convo_id, merged);
        if !self
            .storage()
            .message_exists(&marker_id)
            .await
            .unwrap_or(true)
        {
            let payload = MLSMessagePayload::system("history_boundary.device_rejoined");
            let marker = Message {
                id: marker_id,
                conversation_id: convo_id.to_string(),
                sender_did: user_did.to_string(),
                text: "history_boundary.device_rejoined".to_string(),
                timestamp: chrono::Utc::now(),
                epoch: merged,
                sequence_number: 0,
                is_own: true,
                delivery_status: None,
                payload_json: serde_json::to_string(&payload).ok(),
            };
            if let Err(e) = self.storage().store_message(&marker).await {
                tracing::warn!(error = %e, convo_id, "Failed to store history boundary marker");
            }
        }

        // Do not manufacture a global message high-water mark from a one-row
        // per-conversation fetch. Such a fetch both discarded an envelope and
        // overwrote the independent conversations cursor. The normal sync path
        // will process every envelope durably before advancing either field;
        // recovery deliberately leaves the complete existing cursor unchanged.

        let scoped_identity = self.require_scoped_identity().await?;
        let _ = self.mls_context().export_group_info(
            ext_commit_result.group_id,
            scoped_identity.as_bytes().to_vec(),
        );

        tracing::info!(convo_id, new_epoch = merged, "Force rejoin successful");
        Ok(())
    }

    /// Attempt to rejoin a conversation via External Commit.
    ///
    /// This is the recovery path when the local MLS state is desynced
    /// from the server (epoch mismatch, decryption failures, etc.).
    ///
    /// Task #43: Report to the server that the local client has reached an
    /// unrecoverable state for `convo_id` (e.g. missing group, fork detected,
    /// decryption permanently failing). This is the public escalation path that
    /// replaces client-initiated External Commits.
    ///
    /// The server (mls-ds) handles this via the A7 reset pyramid: it will
    /// eventually issue a `GroupResetEvent` to move all clients to a new group.
    ///
    /// This method does **not** touch local MLS state and does **not** create
    /// External Commits. It's a pure report call. Any callback errors from
    /// `api_client().report_recovery_failure` are logged and swallowed — the
    /// whole point is that the client has already given up locally, so failing
    /// the report call serves no recovery purpose.
    pub async fn report_unrecoverable_local(&self, convo_id: &str, reason: &str) {
        let authenticator = self.epoch_authenticator_hex(convo_id).await;
        // ADR-008 D1 (spec §8.6.1): default classification by failureType.
        // Callers with richer context can use a more specific path below.
        let failure_mode = match reason {
            "remote_data_error" => Some("group_state_unrecoverable"),
            "external_commit_exhausted" => Some("local_state_loss"),
            _ => None,
        };
        tracing::warn!(
            convo_id,
            reason,
            failure_mode = ?failure_mode,
            has_authenticator = authenticator.is_some(),
            "Reporting unrecoverable-local state to server (A7 reset path)",
        );
        let _ = self.submit_reset_request_prepared(convo_id, reason).await;
    }

    /// 1. Fetches GroupInfo from server
    /// 2. Creates an External Commit
    /// 3. Sends the commit to the server
    /// 4. Merges the pending external join
    ///
    /// Task #43 / #49: **Not part of the public API.** External Commits
    /// driven by a client whenever it observes desync are the root cause of
    /// production epoch inflation (observed epochs 800+). Recovery belongs to
    /// the server's A7 reset pyramid now. This method is hidden from rustdoc
    /// and removed from UniFFI exports; it remains accessible at Rust
    /// visibility `pub` strictly so that:
    ///   - the legitimate `join_or_rejoin` deferred-recovery caller in this file
    ///     works across the impl boundary
    ///   - `tests/state_machine_tests.rs` (integration tests documenting
    ///     internal recovery semantics) can still exercise it
    ///
    /// `convo_id` is the stable server conversation id. It is not the mutable
    /// MLS group id; local MLS operations resolve the current group id from
    /// conversation state before touching the crypto context.
    ///
    /// Task #49 deleted the transitional `rejoin_conversation` shim on
    /// `CatbirdClient`/`WasmClient` and rewired
    /// `HighLevelSyncRecoveryContract::recover_conversation` to call
    /// `report_unrecoverable_local` instead — closing the back-door that
    /// undermined Task #43's surface reduction.
    ///
    /// **No new callers.** Prefer `report_unrecoverable_local` for any
    /// client-observed unrecoverable state.
    #[doc(hidden)]
    pub async fn force_rejoin(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let resolved = self.resolve_legacy_group_identifier(convo_id).await?;
        let convo_id = &resolved.conversation_id;
        let rejoin_lock = self.rejoin_lock(convo_id).await;
        let _rejoin_guard = match rejoin_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::info!(convo_id, "Force rejoin already in-flight, waiting");
                let _wait_guard = rejoin_lock.lock().await;
                match self.reset_pending_payload_result(convo_id).await {
                    Ok(Some(_)) => {
                        return Err(OrchestratorError::RecoveryFailed(format!(
                            "ResetPending is authoritative for {convo_id}; use join_or_rejoin"
                        )));
                    }
                    Ok(None) => {}
                    Err(err) => return Err(err),
                }
                return if self.local_group_epoch(convo_id).await.is_some() {
                    Ok(())
                } else {
                    Err(OrchestratorError::RecoveryFailed(format!(
                        "Concurrent force rejoin did not restore group {convo_id}"
                    )))
                };
            }
        };

        // A server-directed reset owns recovery while ResetPending is durable.
        // Direct Rust callers must not bypass join_or_rejoin's reset-aware
        // completion path and clear the reset's rejoin route via External Commit.
        if self.reset_pending_payload_result(convo_id).await?.is_some() {
            return Err(OrchestratorError::RecoveryFailed(format!(
                "ResetPending is authoritative for {convo_id}; use join_or_rejoin"
            )));
        }

        self.enforce_rejoin_backoff(convo_id).await?;

        let result = self.force_rejoin_unlocked(convo_id, &user_did).await;
        match result {
            Ok(()) => {
                if !self
                    .project_non_reset_state_locked(convo_id, ConversationState::Active)
                    .await?
                {
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "ResetPending remains authoritative after force rejoin for {convo_id}"
                    )));
                }
                self.clear_rejoin_failures(convo_id).await?;
                Ok(())
            }
            Err(ref err) if err.is_rate_limited() => {
                // 429 Too Many Requests: don't burn a rejoin attempt slot.
                // Just return the error so the caller can retry later.
                tracing::warn!(
                    convo_id,
                    "Force rejoin got 429 — not counting as failed attempt"
                );
                result
            }
            Err(ref err) if err.is_remote_data_error() => {
                // Remote data errors are already handled in force_rejoin_unlocked
                // (reported to server, marked unrecoverable). Don't record as
                // normal failure — the error is on the server side.
                tracing::warn!(
                    convo_id,
                    "Force rejoin failed due to remote data error — not counting as attempt"
                );
                result
            }
            Err(_) => {
                self.record_rejoin_failure(convo_id).await?;
                result
            }
        }
    }

    /// Join a conversation, trying Welcome first and falling back to External Commit.
    ///
    /// This is the correct join path for conversations where the user was added
    /// by another client. Welcome provides key continuity (can decrypt current
    /// epoch messages), while External Commit is a fallback for device-sync
    /// scenarios where the Welcome was already consumed.
    ///
    /// 1. Try fetching Welcome message from server
    /// 2. If Welcome found → process it to join the group
    /// 3. If Welcome unavailable (404/410) → fall back to External Commit
    ///
    /// `convo_id` is the stable server conversation id. It is not the mutable
    /// MLS group id; server calls and recovery gates are keyed by this stable
    /// id, while local MLS context calls resolve the current group id first.
    pub async fn join_or_rejoin(&self, convo_id: &str) -> Result<u64> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let rejoin_lock = self.rejoin_lock(convo_id).await;
        let _rejoin_guard = match rejoin_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::info!(convo_id, "Join/rejoin already in-flight, waiting");
                let _wait_guard = rejoin_lock.lock().await;
                if self.reset_pending_payload_result(convo_id).await?.is_some() {
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "ResetPending remains authoritative for {convo_id}"
                    )));
                }
                return self.local_group_epoch(convo_id).await.ok_or_else(|| {
                    OrchestratorError::RecoveryFailed(format!(
                        "Concurrent join/rejoin did not restore group {convo_id}"
                    ))
                });
            }
        };

        let epoch = self.join_or_rejoin_locked(convo_id, user_did).await?;
        match self
            .project_non_reset_state_locked(convo_id, ConversationState::Active)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "ResetPending remains authoritative after recovery for {convo_id}"
                )));
            }
            Err(error) => {
                self.mark_needs_rejoin_critical(convo_id).await;
                return Err(error);
            }
        }
        Ok(epoch)
    }

    /// Recovery body for callers that already own the transition lock.
    async fn join_or_rejoin_locked(&self, convo_id: &str, user_did: String) -> Result<u64> {
        // Durable reset state is the first recovery authority consulted. A
        // locally materialized group can be a bootstrap candidate whose
        // completion response was ambiguous, so local health alone must never
        // clear Active/rejoin state while ResetPending exists or cannot be
        // read.
        let reset_authority_at_start = self.reset_pending_payload_result(convo_id).await?;

        // P0.1 (epoch-inflation remediation): authorization-layer chokepoint.
        // EVERY recovery surface funnels through join_or_rejoin — convo-open
        // (ensure_conversation_ready), the deferred-recovery loop (which passes
        // server_epoch=None, bypassing the caught-up clear), the sync-loop init
        // path, and bootstrap retry. Before attempting any Welcome / External
        // Commit, refuse to "rejoin" a group that is already LOCALLY healthy
        // (present, valid epoch, self is a current member of the ratchet tree).
        // Such a rejoin heals nothing and only inflates the server's cosmetic
        // group_info_epoch counter — the ADR-001 force_rejoin anti-pattern that
        // drove the year-long inflation spiral. Closing the door HERE, not
        // surface-by-surface, is the durable fix. The self-membership gate means
        // a genuinely leaf-lost / absent-local member still falls through to the
        // real Welcome/EC recovery below, so this cannot strand anyone.
        if reset_authority_at_start.is_none()
            && self
                .clear_needs_rejoin_if_locally_healthy_unlocked(convo_id)
                .await
        {
            let epoch = self.local_group_epoch(convo_id).await.unwrap_or(0);
            crate::warn_log!(
                "[REJOIN-DIAG] convo={} join_or_rejoin SHORT-CIRCUIT: local group already healthy (epoch={}) — NO Welcome/ExternalCommit",
                convo_id,
                epoch
            );
            return Ok(epoch);
        }

        // Welcome should be tried unconditionally — backoff only applies to
        // External Commit fallback (spec: Welcome is the preferred join path).
        tracing::info!(
            convo_id,
            "Attempting to join group (Welcome first, External Commit fallback)"
        );
        crate::warn_log!(
            "[REJOIN-DIAG] convo={} START join_or_rejoin (Welcome first, EC fallback)",
            convo_id
        );

        // Step 1: Try Welcome.
        //
        // Track the outcome so the next steps can decide whether to attempt
        // first-responder bootstrap. We only try bootstrap when Welcome was
        // unavailable in an "expected" way (404/410/processing-fail) — a
        // real network error means we can't trust that the welcome isn't
        // sitting on the server, and we shouldn't race-bootstrap blind.
        let mut welcome_recovery_error: Option<LastRecoveryError> = None;
        let welcome_unavailable_expected: bool = match self.api_client().get_welcome(convo_id).await
        {
            Ok(welcome_data) => {
                tracing::info!(
                    convo_id,
                    welcome_len = welcome_data.len(),
                    "Welcome message found, joining via Welcome"
                );
                crate::warn_log!(
                    "[REJOIN-DIAG] convo={} Welcome FOUND len={} — calling process_welcome",
                    convo_id,
                    welcome_data.len()
                );

                let scoped_identity = self.require_scoped_identity().await?;
                let identity_bytes = scoped_identity.into_bytes();
                let welcome_result = self.mls_context().process_welcome(
                    welcome_data,
                    identity_bytes,
                    Some(self.config().group_config.clone()),
                ).map_err(|e| {
                    tracing::warn!(convo_id, error = %e, "Welcome processing failed, will try first-responder bootstrap or External Commit");
                    e
                });

                match welcome_result {
                    Ok(result) => {
                        let current_reset_authority =
                            self.reset_pending_payload_result(convo_id).await?;
                        let epoch = if let Some(payload) = current_reset_authority.as_ref() {
                            let expected_group =
                                hex::decode(&payload.new_group_id).map_err(|e| {
                                    OrchestratorError::InvalidInput(format!(
                                        "ResetPending target is invalid hex: {e}"
                                    ))
                                })?;
                            if result.group_id != expected_group {
                                let welcome_group_id = hex::encode(&result.group_id);
                                let authoritative =
                                    self.fetch_conversation_for_convo(convo_id).await;
                                match authoritative {
                                    Ok(conversation)
                                        if conversation.conversation_id == convo_id
                                            && conversation.group_id == welcome_group_id => {}
                                    Ok(conversation) => {
                                        let _ = self
                                            .mls_context()
                                            .delete_group(result.group_id.clone());
                                        return Err(
                                            OrchestratorError::ResetCompletionNotCommitted {
                                                convo_id: convo_id.to_string(),
                                                reset_generation: payload.reset_generation,
                                                reason: format!(
                                                    "processed Welcome group {welcome_group_id} does not match authoritative server mapping {}",
                                                    conversation.group_id
                                                ),
                                            },
                                        );
                                    }
                                    Err(error) => {
                                        let _ = self
                                            .mls_context()
                                            .delete_group(result.group_id.clone());
                                        return Err(
                                            OrchestratorError::ResetCompletionNotCommitted {
                                                convo_id: convo_id.to_string(),
                                                reset_generation: payload.reset_generation,
                                                reason: format!(
                                                    "processed Welcome winner could not be verified against the server mapping: {error}"
                                                ),
                                            },
                                        );
                                    }
                                }
                                let adopted_payload = self
                                    .adopt_verified_welcome_reset_target(
                                        convo_id,
                                        payload,
                                        &welcome_group_id,
                                    )
                                    .await?;
                                self.complete_reset_recovery(
                                    convo_id,
                                    &adopted_payload,
                                    result.group_id.clone(),
                                    false,
                                )
                                .await?
                            } else {
                                self.complete_reset_recovery(
                                    convo_id,
                                    payload,
                                    result.group_id.clone(),
                                    true,
                                )
                                .await?
                            }
                        } else {
                            // A processed Welcome without a readable epoch is
                            // not a usable recovery result. Epoch zero fallback
                            // used to publish a half-joined group and clear its
                            // recovery flag.
                            self.mls_context()
                                .get_epoch(result.group_id.clone())
                                .map_err(|error| {
                                    OrchestratorError::RecoveryFailed(format!(
                                        "processed Welcome epoch is unavailable for {convo_id}: {error}"
                                    ))
                                })?
                        };

                        // The durable stable-conversation projection is the
                        // application-level commit point. Construct it without
                        // mutating the cache, persist it first, and publish it
                        // only after the write succeeds.
                        let welcome_group_id_hex = hex::encode(&result.group_id);
                        let mut state = {
                            let states = self.group_states().lock().await;
                            states
                                .get(&welcome_group_id_hex)
                                .cloned()
                                .or_else(|| {
                                    states
                                        .values()
                                        .find(|state| state.conversation_id == convo_id)
                                        .cloned()
                                })
                                .unwrap_or_else(|| GroupState {
                                    group_id: welcome_group_id_hex.clone(),
                                    conversation_id: convo_id.to_string(),
                                    epoch: 0,
                                    members: vec![],
                                })
                        };
                        state.group_id = welcome_group_id_hex.clone();
                        state.conversation_id = convo_id.to_string();
                        state.epoch = epoch;
                        // Materialize the stable conversation row before the
                        // GroupState projection. Apart from binding the stable
                        // conversation id to the mutable MLS group, this gives
                        // recovery-flag storage a durable row to update if a
                        // later commit-point write fails.
                        if let Err(error) = self
                            .storage()
                            .ensure_conversation_exists(&user_did, convo_id, &welcome_group_id_hex)
                            .await
                        {
                            self.report_recovery_storage_failure(
                                convo_id,
                                "ensure_conversation_exists:welcome_recovery",
                                &error,
                            )
                            .await;
                            return Err(error);
                        }
                        if let Err(error) = self.storage().set_group_state(&state).await {
                            self.mark_needs_rejoin_critical(convo_id).await;
                            return Err(error);
                        }
                        if let Err(error) = self
                            .storage()
                            .update_join_info(convo_id, &user_did, JoinMethod::Welcome, epoch)
                            .await
                        {
                            self.mark_needs_rejoin_critical(convo_id).await;
                            return Err(error);
                        }

                        // Outside reset recovery there is no generation-bound
                        // completion transaction, so retain the legacy clear.
                        if let Err(error) = self.clear_rejoin_failures(convo_id).await {
                            self.mark_needs_rejoin_critical(convo_id).await;
                            return Err(error);
                        }
                        if current_reset_authority.is_none() {
                            if let Err(error) = self.storage().clear_rejoin_flag(convo_id).await {
                                self.mark_needs_rejoin_critical(convo_id).await;
                                return Err(error);
                            }
                        }
                        {
                            let mut states = self.group_states().lock().await;
                            normalize_group_state(&mut states, state);
                        }

                        self.cleanup_epoch_secrets_if_needed(
                            convo_id,
                            &welcome_group_id_hex,
                            epoch,
                        )
                        .await;

                        // Insert history boundary marker for Welcome join.
                        // On iOS, Swift inserts first — message_exists prevents duplicates.
                        let marker_id = format!("hb-{}-{}", convo_id, epoch);
                        if !self
                            .storage()
                            .message_exists(&marker_id)
                            .await
                            .unwrap_or(true)
                        {
                            let user_did_ref = &user_did;
                            let payload = MLSMessagePayload::system("history_boundary.new_member");
                            let marker = Message {
                                id: marker_id,
                                conversation_id: convo_id.to_string(),
                                sender_did: user_did_ref.clone(),
                                text: "history_boundary.new_member".to_string(),
                                timestamp: chrono::Utc::now(),
                                epoch,
                                sequence_number: 0,
                                is_own: true,
                                delivery_status: None,
                                payload_json: serde_json::to_string(&payload).ok(),
                            };
                            if let Err(e) = self.storage().store_message(&marker).await {
                                tracing::warn!(error = %e, convo_id, "Failed to store history boundary marker");
                            }
                        }

                        tracing::info!(convo_id, epoch, "Successfully joined via Welcome");
                        crate::warn_log!(
                            "[REJOIN-DIAG] convo={} Welcome JOIN OK epoch={}",
                            convo_id,
                            epoch
                        );
                        // Newly-joined members can't derive a past epoch's
                        // exporter, so fetch + decrypt the encrypted metadata
                        // blob now to surface the group name/description. The
                        // enclosing sync builds its snapshot from the cache this
                        // populates. Best-effort — never fails the join.
                        self.hydrate_conversation_metadata(convo_id).await;
                        return Ok(epoch);
                    }
                    Err(err) => {
                        crate::warn_log!(
                            "[REJOIN-DIAG] convo={} Welcome process_welcome FAILED: {}",
                            convo_id,
                            err
                        );
                        welcome_recovery_error = classify_welcome_processing_error(&err);
                        // Welcome bytes returned but processing failed — treat
                        // as "expected" for bootstrap eligibility (the welcome
                        // is malformed for us; bootstrapping into a fresh
                        // group is the right next step if state is ResetPending).
                        tracing::info!(
                            convo_id,
                            "Welcome processing failed, will try first-responder bootstrap (if ResetPending) before External Commit"
                        );
                        true
                    }
                }
            }
            Err(e) => {
                // Check if this is a 404/410 (Welcome not available) vs a real error.
                let is_expected = match &e {
                    OrchestratorError::ServerError { status, .. } => {
                        *status == 404 || *status == 410
                    }
                    _ => false,
                };
                if is_expected {
                    welcome_recovery_error = Some(classify_server_error(&e));
                    tracing::info!(
                        convo_id,
                        "No Welcome available — will try first-responder bootstrap (if ResetPending) before External Commit"
                    );
                    crate::warn_log!(
                        "[REJOIN-DIAG] convo={} Welcome fetch 404/410 (unavailable/expired): {}",
                        convo_id,
                        e
                    );
                    true
                } else {
                    tracing::warn!(convo_id, error = %e, "Welcome fetch failed with non-404/410 error; skipping bootstrap, falling back to External Commit");
                    crate::warn_log!(
                        "[REJOIN-DIAG] convo={} Welcome fetch FAILED (non-404/410, skipping bootstrap): {}",
                        convo_id,
                        e
                    );
                    false
                }
            }
        };

        // Step 2: First-responder bootstrap (spec §8.5 Phase 1) — try BEFORE
        // External Commit when state is `ResetPending` and Welcome was
        // unavailable in the expected shape.
        //
        // Pre-fix this lived AFTER External Commit failed. That ordering was
        // wrong for two reasons:
        //   (i)  EC against a freshly-emptied group (which is exactly the
        //        post-reset shape) cannot succeed — the server has wiped the
        //        membership/epoch state atomically with the reset transaction.
        //        Running EC first burned a network round-trip + a per-convo
        //        failure counter increment for no benefit.
        //   (ii) The 30s MIN_REJOIN_INTERVAL gate sits in front of
        //        `enforce_rejoin_backoff`. Combined with the fact that
        //        `record_group_reset` USED to arm that gate (fixed; see
        //        `clear_for_fresh_reset`), bootstrap was effectively
        //        unreachable for ≥30 s after every reset, and could remain
        //        unreachable indefinitely if the gate kept re-arming.
        //
        // Gating strictly on `ResetPending` — NOT on the welcome failure shape
        // alone — is deliberate: never-joined conversations also produce "no
        // Welcome + no GroupInfo" but must not trigger bootstrap (they belong
        // to External Commit / standard join).
        //
        // Bootstrap itself is NOT gated by `enforce_rejoin_backoff`:
        //   - bootstrap is a server-serialized CREATE keyed by
        //     `crypto_sessions UNIQUE (conversation_id, generation)`, not a
        //     competitive External Commit, so the gate's epoch-inflation
        //     concern doesn't apply.
        //   - the race-loser path inside `try_first_responder_bootstrap`
        //     (409 AlreadyBootstrapped) cleanly drops local pre-bootstrap
        //     state and lets the next sync tick consume the winner's Welcome.
        //
        // With ≤8-device groups the first-responder race resolves within one
        // or two sync cycles (one winner, others see AlreadyBootstrapped 409 →
        // Welcome on the next pass).
        if welcome_unavailable_expected {
            // Reset persistence is the recovery authority. If it cannot be
            // read, fail closed instead of treating that failure as “not
            // pending” and falling through to an unauthorized External Commit.
            if let Some(payload) = self.reset_pending_payload_result(convo_id).await? {
                tracing::info!(
                    convo_id,
                    new_group_id = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "join_or_rejoin: Welcome unavailable + ResetPending; attempting first-responder bootstrap before External Commit"
                );
                match self
                    .try_first_responder_bootstrap(convo_id, &payload, &user_did)
                    .await
                {
                    Ok(epoch) => {
                        // Bootstrap winner. State already transitioned to
                        // Active inside try_first_responder_bootstrap; just
                        // clear the rejoin failure tracker (idempotent if no
                        // prior failures).
                        self.clear_rejoin_failures(convo_id).await?;
                        return Ok(epoch);
                    }
                    Err(boot_err) if boot_err.is_bootstrap_already_bootstrapped() => {
                        // Race loser. try_first_responder_bootstrap already
                        // dropped the local pre-bootstrap group and KEPT
                        // reset_pending so the deferred-recovery loop will
                        // retry Welcome on the next sync tick and pick up
                        // the winner's published Welcome. Do NOT fall through
                        // to External Commit — EC against the freshly-bootstrapped
                        // empty group can't succeed, and we'd burn the global
                        // gate for nothing. Returning the 409 propagates to the
                        // sync loop, which schedules the next tick.
                        tracing::info!(
                            convo_id,
                            "first-responder bootstrap race lost; awaiting winner's Welcome on next sync tick (no External Commit fallback)"
                        );
                        return Err(boot_err);
                    }
                    Err(boot_err) if boot_err.is_reset_completion_not_committed() => {
                        // The server accepted this bootstrap, but a newer
                        // ResetPending generation won the local storage CAS.
                        // Retry that authority on the next sync pass; never
                        // fall through to External Commit for the stale one.
                        return Err(boot_err);
                    }
                    Err(boot_err) => {
                        // ResetPending is durable authority. Any bootstrap
                        // uncertainty must remain on this path; treating it as
                        // authorization for legacy External Commit can mutate
                        // the wrong reset generation.
                        tracing::warn!(
                            convo_id,
                            bootstrap_error = %boot_err,
                            "first-responder bootstrap failed; preserving ResetPending (no External Commit fallback)"
                        );
                        return Err(boot_err);
                    }
                }
            }
        }

        // Step 3: External Commit fallback (gated by enforce_rejoin_backoff).
        // Re-read immediately before authorizing EC: a non-404 Welcome error
        // skips bootstrap, and another process may also have published reset
        // authority since the entry snapshot. Either case must fail closed.
        if let Some(pending) = self.reset_pending_payload_result(convo_id).await? {
            return Err(OrchestratorError::ResetCompletionNotCommitted {
                convo_id: convo_id.to_string(),
                reset_generation: pending.reset_generation,
                reason: "ResetPending authority prohibits External Commit fallback".to_string(),
            });
        }
        //
        // Bootstrap was tried above when applicable; this path is for:
        //   - never-joined convos (state != ResetPending)
        //   - convos where bootstrap failed for a non-409 reason
        //   - convos where Welcome failed with a non-404/410 error and we
        //     skipped bootstrap defensively
        if welcome_recovery_error.is_some() {
            // Clean-chat exposes no GroupInfo, so External Commit can never
            // succeed here. A live leaf of another participant must re-add
            // us, or an admin resets; both bind the server's coordinate.
            let state = self.fetch_server_conversation_state(convo_id).await?;
            let outcome = self.recover_leaf_or_reset(&state, &user_did).await?;
            if let Some(epoch) = outcome.get("epoch").and_then(|v| v.as_u64()) {
                self.clear_rejoin_failures(convo_id).await?;
                crate::warn_log!("[REJOIN-DIAG] convo={} reset activated epoch={}", convo_id, epoch);
                return Ok(epoch);
            }
            self.storage().mark_needs_rejoin(convo_id).await?;
            crate::warn_log!("[REJOIN-DIAG] convo={} leaf recovery pending: {}", convo_id, outcome);
            return Err(OrchestratorError::RecoveryFailed(format!(
                "leaf recovery pending for {convo_id}: {outcome}"
            )));
        }
        if let Err(err) = self.enforce_rejoin_backoff(convo_id).await {
            crate::warn_log!(
                "[REJOIN-DIAG] convo={} External Commit BLOCKED by rejoin backoff/circuit-breaker — staying NeedsRejoin: {}",
                convo_id,
                err
            );
            return Err(err);
        }
        crate::warn_log!(
            "[REJOIN-DIAG] convo={} attempting External Commit (force_rejoin)",
            convo_id
        );
        let rejoin_result = self.force_rejoin_unlocked(convo_id, &user_did).await;
        match rejoin_result {
            Ok(()) => {
                self.clear_rejoin_failures(convo_id).await?;
                let epoch = self.local_group_epoch(convo_id).await.unwrap_or(0);
                crate::warn_log!(
                    "[REJOIN-DIAG] convo={} External Commit OK epoch={}",
                    convo_id,
                    epoch
                );
                Ok(epoch)
            }
            Err(err) => {
                self.record_rejoin_failure(convo_id).await?;
                crate::warn_log!(
                    "[REJOIN-DIAG] convo={} External Commit FAILED: {}",
                    convo_id,
                    err
                );
                Err(err)
            }
        }
    }

    /// Perform full silent recovery for a user.
    ///
    /// Nuclear option: deletes device, clears local state, re-registers,
    /// and marks all conversations for rejoin.
    pub async fn perform_silent_recovery(&self, conversation_ids: &[String]) -> Result<()> {
        let user_did = self.require_user_did().await?;

        tracing::info!(
            user_did = %user_did,
            conversations = conversation_ids.len(),
            "Starting silent recovery"
        );

        // 1. Delete current device from server
        let device_uuid = self
            .credentials()
            .get_device_uuid(&user_did)
            .await?
            .unwrap_or_default();
        if !device_uuid.is_empty() {
            if let Ok(devices) = self.api_client().list_devices(&device_uuid).await {
                for device in &devices {
                    if device.device_uuid == device_uuid {
                        let _ = self.remove_device(&device.device_id).await;
                    }
                }
            }
        }

        // 2. Clear local credentials
        self.credentials().clear_all(&user_did).await?;

        // 3. Re-register device
        let _new_mls_did = self.ensure_device_registered().await?;

        // 4. Mark conversations for rejoin
        for convo_id in conversation_ids {
            self.mark_needs_rejoin_critical(convo_id).await;
        }

        // 5. Process rejoins
        for convo_id in conversation_ids {
            let needs_rejoin = match self.storage().needs_rejoin(convo_id).await {
                Ok(flag) => flag,
                Err(e) => {
                    // A storage READ failure must not silently read as
                    // "no rejoin needed" without a trace.
                    tracing::warn!(
                        convo_id = %convo_id,
                        error = %e,
                        "needs_rejoin read failed during silent recovery — defaulting to false (rejoin skipped this pass)"
                    );
                    false
                }
            };
            if needs_rejoin {
                match self.join_or_rejoin(convo_id).await {
                    Ok(epoch) => {
                        tracing::info!(convo_id = %convo_id, epoch, "Rejoin successful during recovery");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            convo_id = %convo_id,
                            "Rejoin failed during recovery"
                        );
                    }
                }
            }
        }

        tracing::info!("Silent recovery complete");
        Ok(())
    }

    /// Persist a server-initiated GroupReset event WITHOUT performing any
    /// network recovery (spec §8.5 Phase 1 / §8.6).
    ///
    /// Called by the platform SSE/WS event handler when a `groupResetEvent`
    /// arrives. Splits the persist-only steps out of the legacy
    /// `handle_group_reset` so event handlers don't trigger an inline
    /// External Commit (catmos's `websocket.rs:494` enforces "External Commits
    /// only in deferred recovery, never inline in event handlers" — see the
    /// April 2026 epoch-inflation incident class). The deferred-recovery
    /// sync loop subsequently picks the conversation up via the
    /// `needs_rejoin` flag and routes through `join_or_rejoin`, which now
    /// includes a first-responder bootstrap step gated on
    /// `ConversationState::ResetPending`.
    ///
    /// Steps:
    /// 1. Transition the conversation to `ResetPending { new_group_id,
    ///    reset_generation, notified_at_ms }` and persist it so the payload
    ///    survives orchestrator restart.
    /// 2. Delete the old local MLS group (looked up via `group_states` so we
    ///    drop the *pre-reset* group, not whatever `hex::decode(convo_id)`
    ///    happens to yield).
    /// 3. Reset the per-conversation `RecoveryTracker` counter to 0 via
    ///    `clear_for_fresh_reset` — this is a fresh start from the server,
    ///    not a continuation of a client-side retry loop. **Critically**,
    ///    this does NOT arm `last_global_rejoin_at`; the global gate is for
    ///    our own rejoin attempts, and a server-pushed reset is not such an
    ///    attempt. (Pre-fix this used `clear`, which armed the gate and
    ///    blocked the imminent first-responder bootstrap for ≥30 s — see
    ///    `RecoveryTracker::clear_for_fresh_reset` doc.)
    /// 4. Update `group_states[convo_id].group_id = new_group_id_hex` and
    ///    `mark_needs_rejoin` so the next sync-loop pass routes this convo
    ///    through `join_or_rejoin` (Welcome → bootstrap → ExternalCommit).
    ///
    /// `new_group_id` is the raw bytes of the new MLS group id (not hex).
    pub async fn record_group_reset(
        &self,
        convo_id: &str,
        new_group_id: Vec<u8>,
        reset_generation: i32,
    ) -> Result<()> {
        self.record_group_reset_with_outcome(convo_id, new_group_id, reset_generation)
            .await?;
        Ok(())
    }

    pub async fn record_group_reset_with_outcome(
        &self,
        convo_id: &str,
        new_group_id: Vec<u8>,
        reset_generation: i32,
    ) -> Result<ResetRecordOutcome> {
        self.check_shutdown().await?;
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        let new_group_id_hex = hex::encode(&new_group_id);
        // ADR-021 Part A: validate the reset target's shape/hex at record time,
        // before any idempotency/self-echo check or state transition references
        // it. A malformed target fails closed here and never reaches the
        // destructive delete in `persist_reset_pending_state`.
        let validated_target = ValidatedResetTarget::parse(&new_group_id_hex)?;
        tracing::info!(
            convo_id,
            new_group_id = %new_group_id_hex,
            reset_generation,
            "Recording server-initiated GroupReset (deferred adoption)"
        );
        let existing_pending = self.reset_pending_payload_result(convo_id).await?;
        if let Some(existing) = existing_pending.as_ref() {
            if existing.reset_generation > reset_generation
                || (existing.reset_generation == reset_generation
                    && existing.new_group_id != new_group_id_hex)
            {
                tracing::info!(
                    convo_id,
                    existing_reset_generation = existing.reset_generation,
                    incoming_reset_generation = reset_generation,
                    existing_new_group_id = %existing.new_group_id,
                    incoming_new_group_id = %new_group_id_hex,
                    "GroupResetEvent: stale or duplicate generation, no-op"
                );
                return Ok(ResetRecordOutcome::StaleOrDuplicate);
            }
            if existing.reset_generation == reset_generation {
                self.persist_reset_pending_state(
                    convo_id,
                    &validated_target,
                    reset_generation,
                    Some(existing.clone()),
                )
                .await?;
                return Ok(ResetRecordOutcome::StaleOrDuplicate);
            }
            tracing::info!(
                convo_id,
                old_reset_generation = existing.reset_generation,
                new_reset_generation = reset_generation,
                "GroupResetEvent: superseding existing ResetPending at newer generation"
            );
        }
        if existing_pending.is_none()
            && self
                .reset_target_is_current_existing_group(convo_id, &new_group_id_hex)
                .await
        {
            tracing::info!(
                convo_id,
                new_group_id = %new_group_id_hex,
                reset_generation,
                "GroupResetEvent: target already matches an existing local group, self-echo no-op"
            );
            return Ok(ResetRecordOutcome::SelfEchoNoOp);
        }
        self.persist_reset_pending_state(convo_id, &validated_target, reset_generation, None)
            .await?;
        Ok(ResetRecordOutcome::Recorded)
    }

    /// Phase 2.5 (`docs/plans/phase-2-5-indirect-funneling.md` §3, §5 Stage 1):
    /// record an indirect-trigger `resetRequestedEvent` from the DS where the
    /// server has NOT minted a new MLS group id and is asking subscribed
    /// clients to elect a first responder.
    ///
    /// The `resetRequestedEvent` lexicon (parallel agent's scope) carries:
    /// - `cryptoSessionId` (prior session id, now in `reset_requested` server-side),
    /// - `generation` (monotonic per conversation; `i32` here to match the
    ///   existing `reset_generation` field — see `storage.rs:106`),
    /// - `trigger` (`quorumVote | systemSweep | inlineCommit409 |
    ///   inlineGroupInfo404 | adminRequest`),
    /// - `requestEventId` (deterministic dedup key — see plan §3 idempotency
    ///   scheme: `req-quorum:..`, `req-sweep:..`, `req-inline-409:..`,
    ///   `req-inline-404:..`),
    /// - `expectedNewMlsGroupId` (`Option<String>`; usually `None`, set only
    ///   when an admin or legacy direct flow knows the target id).
    ///
    /// Resolution policy in this client:
    ///
    /// **Idempotency** is by current state: if the conversation is already
    /// `ResetPending { reset_generation: g, .. }` and the incoming
    /// `reset_generation` matches `g`, return `Ok(())` without doing duplicate
    /// work. The same `request_event_id` arriving twice through different SSE
    /// reconnects (or replayed via `event_stream` cursor) collapses to a single
    /// persisted reset_pending row + single bootstrap attempt. We don't carry
    /// `request_event_id` into `ResetPending` itself — the conversation state
    /// only needs the new group id and generation, and the payload should not
    /// keep growing per Phase 2.5 — but we do log it for observability.
    ///
    /// **Eager group_id resolution.** When `expected_new_mls_group_id` is
    /// `None`, we generate a fresh random UUIDv4-style hex id and persist it
    /// into `ResetPending.new_group_id`. This is cleaner than threading
    /// `Option<String>` through `ConversationState::ResetPending`,
    /// `try_first_responder_bootstrap`, and every storage backend's
    /// `mark_reset_pending` schema. The MLS-protocol-visible behavior is
    /// identical: clients race-bootstrap with their own pre-generated id, the
    /// server's `crypto_sessions UNIQUE (conversation_id, generation)`
    /// chokepoint constraint serializes the winner, race losers see HTTP 409
    /// `AlreadyBootstrapped` and drop their pre-bootstrap MLS group cleanly
    /// (see the existing logic at `try_first_responder_bootstrap` race-loser
    /// branch). The client-generated id never appears on the wire until
    /// `bootstrap_reset_group` submits it, so this is functionally equivalent
    /// to bootstrap-time generation.
    ///
    /// When `expected_new_mls_group_id` is `Some(g)`, we use `g` directly —
    /// matching the legacy `record_group_reset` behavior (admin-driven reset,
    /// plan §5 Stage 1 Catbird/Android dual-path period).
    ///
    /// `trigger` is logged (and surfaced in structured logs) but not parsed
    /// into an internal enum — the lexicon owns the canonical string set, and
    /// keeping this layer string-typed avoids cross-repo enum drift. The
    /// security boundary (only quorum/sweep/inline triggers may pass `None`,
    /// admin must always pass `Some`) is enforced by the server (plan §7 R1
    /// mitigation 1: `request_crypto_session_reset_tx` debug assertion) — not
    /// here. Clients receive whatever the server sent.
    ///
    /// Wires into the same internal `persist_reset_pending_state` helper as
    /// `record_group_reset`, so the resulting in-memory state, storage rows,
    /// and `needs_rejoin` flag are identical to the legacy path. The deferred-
    /// recovery loop in `sync_with_server` then picks up the conversation and
    /// drives `join_or_rejoin`, which already includes the first-responder
    /// bootstrap branch gated on `ResetPending` (see `recovery.rs:1173-1215`).
    pub async fn record_reset_requested(
        &self,
        convo_id: &str,
        crypto_session_id: &str,
        reset_generation: i32,
        trigger: &str,
        request_event_id: &str,
        expected_new_mls_group_id: Option<String>,
    ) -> Result<()> {
        self.record_reset_requested_with_outcome(
            convo_id,
            crypto_session_id,
            reset_generation,
            trigger,
            request_event_id,
            expected_new_mls_group_id,
        )
        .await?;
        Ok(())
    }

    pub async fn record_reset_requested_with_outcome(
        &self,
        convo_id: &str,
        crypto_session_id: &str,
        reset_generation: i32,
        trigger: &str,
        request_event_id: &str,
        expected_new_mls_group_id: Option<String>,
    ) -> Result<ResetRecordOutcome> {
        self.check_shutdown().await?;
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;

        // Idempotency/stale check: if we're already in ResetPending at this
        // generation or newer, drop the duplicate/stale replay before it can
        // overwrite the current target group or delete the current local group.
        let existing_pending = self.reset_pending_payload_result(convo_id).await?;
        if let Some(existing) = existing_pending.as_ref() {
            if existing.reset_generation > reset_generation {
                tracing::info!(
                    convo_id,
                    crypto_session_id,
                    existing_reset_generation = existing.reset_generation,
                    incoming_reset_generation = reset_generation,
                    trigger,
                    request_event_id,
                    existing_new_group_id = %existing.new_group_id,
                    "resetRequestedEvent: stale or duplicate generation, no-op"
                );
                return Ok(ResetRecordOutcome::StaleOrDuplicate);
            }
            if existing.reset_generation == reset_generation {
                // Resume of an already-committed target. It was validated when
                // first recorded; re-validate at record time so the delete path
                // is never reachable with an unvalidated target (ADR-021 Part A).
                let validated_existing = ValidatedResetTarget::parse(&existing.new_group_id)?;
                self.persist_reset_pending_state(
                    convo_id,
                    &validated_existing,
                    reset_generation,
                    Some(existing.clone()),
                )
                .await?;
                return Ok(ResetRecordOutcome::StaleOrDuplicate);
            }
            tracing::info!(
                convo_id,
                crypto_session_id,
                old_reset_generation = existing.reset_generation,
                new_reset_generation = reset_generation,
                trigger,
                request_event_id,
                "resetRequestedEvent: superseding existing ResetPending at newer generation"
            );
        }

        // Resolve new_group_id eagerly. When the server hands us one (admin
        // path / legacy direct flow), use it; otherwise mint a fresh
        // UUIDv4-style 32-hex-char id locally for our race-bootstrap candidate.
        let new_group_id_hex = match expected_new_mls_group_id {
            Some(hex_id) if !hex_id.is_empty() => {
                tracing::info!(
                    convo_id,
                    crypto_session_id,
                    reset_generation,
                    trigger,
                    request_event_id,
                    new_group_id = %hex_id,
                    "resetRequestedEvent: server-supplied expected_new_mls_group_id, using it directly"
                );
                hex_id
            }
            _ => {
                let minted = format!("{:032x}", uuid::Uuid::new_v4().as_u128());
                tracing::info!(
                    convo_id,
                    crypto_session_id,
                    reset_generation,
                    trigger,
                    request_event_id,
                    new_group_id = %minted,
                    "resetRequestedEvent: no expected_new_mls_group_id from server, minting client-side candidate for first-responder bootstrap"
                );
                minted
            }
        };

        // ADR-021 Part A: validate the resolved target's shape/hex at record
        // time, before the self-echo check or any state transition references
        // it. A malformed server-supplied `expectedNewMlsGroupId` fails closed
        // here and never reaches the destructive delete.
        let validated_target = ValidatedResetTarget::parse(&new_group_id_hex)?;

        if existing_pending.is_none()
            && self
                .reset_target_is_current_existing_group(convo_id, &new_group_id_hex)
                .await
        {
            tracing::info!(
                convo_id,
                crypto_session_id,
                reset_generation,
                trigger,
                request_event_id,
                new_group_id = %new_group_id_hex,
                "resetRequestedEvent: target already matches an existing local group, self-echo no-op"
            );
            return Ok(ResetRecordOutcome::SelfEchoNoOp);
        }

        self.persist_reset_pending_state(convo_id, &validated_target, reset_generation, None)
            .await?;
        Ok(ResetRecordOutcome::Recorded)
    }

    /// Internal helper shared by `record_group_reset` (legacy direct path) and
    /// `record_reset_requested` (Phase 2.5 indirect path).
    ///
    /// Steps mirror the original `record_group_reset` body — extracted so the
    /// two public entry points produce identical in-memory + storage state
    /// without code duplication.
    ///
    /// Steps:
    /// 1. Transition the conversation to `ResetPending { new_group_id,
    ///    reset_generation, notified_at_ms }` and persist it so the payload
    ///    survives orchestrator restart.
    /// 2. Delete the old local MLS group (looked up via `group_states` so we
    ///    drop the *pre-reset* group, not whatever `hex::decode(convo_id)`
    ///    happens to yield).
    /// 3. Reset the per-conversation `RecoveryTracker` counter to 0 via
    ///    `clear_for_fresh_reset` — this is a fresh start from the server,
    ///    not a continuation of a client-side retry loop. Crucially, this
    ///    does NOT arm `last_global_rejoin_at`; that gate is for our own
    ///    rejoin attempts, and a server-pushed reset is not such an attempt.
    /// 4. Update `group_states[convo_id].group_id = new_group_id_hex` and
    ///    `mark_needs_rejoin` so the next sync-loop pass routes this convo
    ///    through `join_or_rejoin` (Welcome → bootstrap → ExternalCommit).
    async fn persist_reset_pending_state(
        &self,
        convo_id: &str,
        target: &ValidatedResetTarget,
        reset_generation: i32,
        committed: Option<ResetPendingPayload>,
    ) -> Result<()> {
        // `target` is a `ValidatedResetTarget`, so its shape/hex/length were
        // checked at record time (ADR-021 Part A). The destructive delete
        // below (`delete_materialized_reset_predecessors`) is therefore
        // unreachable for an unvalidated target — the type is the gate — and it
        // additionally runs only after the durable `mark_reset_pending`
        // publication succeeds, so `delete_group` cannot precede durable intent.
        let new_group_id_hex = target.hex();
        let resuming_committed_generation = committed.is_some();
        let notified_at_ms = committed
            .as_ref()
            .map(|payload| payload.notified_at_ms)
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        // Resolve the pre-transition authority before publishing ResetPending.
        // Once the pending payload is visible, normal resolution intentionally
        // selects the new target and must never be used to choose the group to
        // delete.
        let mut old_group_ids: Vec<Vec<u8>> = {
            let states = self.group_states().lock().await;
            states
                .values()
                .filter(|state| {
                    state.conversation_id == convo_id
                        && (!resuming_committed_generation || state.group_id != new_group_id_hex)
                })
                .filter_map(|state| hex::decode(&state.group_id).ok())
                .filter(|group_id| self.mls_context().group_exists(group_id.clone()))
                .collect()
        };
        if committed.is_none() {
            let old_context = self.resolve_conversation_context(convo_id).await?;
            if old_context.group_id != new_group_id_hex || !resuming_committed_generation {
                if let Ok(group_id) = old_context.group_id_bytes() {
                    if self.mls_context().group_exists(group_id.clone()) {
                        old_group_ids.push(group_id);
                    }
                }
            }
        } else {
            let user_did = self.require_user_did().await?;
            if let Some(view) = self.storage().get_conversation(&user_did, convo_id).await? {
                if view.group_id != new_group_id_hex {
                    if let Ok(group_id) = hex::decode(&view.group_id) {
                        if self.mls_context().group_exists(group_id.clone()) {
                            old_group_ids.push(group_id);
                        }
                    }
                }
            }
        }
        old_group_ids.sort();
        old_group_ids.dedup();
        let reset_state = ConversationState::ResetPending {
            new_group_id: new_group_id_hex.to_string(),
            reset_generation,
            notified_at_ms,
        };

        // 1. `mark_reset_pending` is the sole atomic authority-publication
        // operation: backends commit tag + complete payload together and
        // reject stale generations. There is deliberately no preparatory tag
        // write and no rollback. A callback error is ambiguous (the commit may
        // have succeeded before its response was lost), so re-read durable
        // authority and continue only when the exact tuple is observable.
        let durable_state = if let Some(committed) = committed {
            ConversationState::ResetPending {
                new_group_id: committed.new_group_id,
                reset_generation: committed.reset_generation,
                notified_at_ms: committed.notified_at_ms,
            }
        } else {
            match self
                .storage()
                .mark_reset_pending(convo_id, new_group_id_hex, reset_generation, notified_at_ms)
                .await
            {
                Ok(()) => reset_state.clone(),
                Err(mark_error) => match self.storage().get_conversation_state(convo_id).await {
                    Ok(Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation: durable_generation,
                        notified_at_ms: durable_notified_at_ms,
                    })) if durable_generation == reset_generation
                        && new_group_id == new_group_id_hex
                        && durable_notified_at_ms == notified_at_ms =>
                    {
                        ConversationState::ResetPending {
                            new_group_id,
                            reset_generation: durable_generation,
                            notified_at_ms: durable_notified_at_ms,
                        }
                    }
                    Ok(Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation: durable_generation,
                        notified_at_ms: durable_notified_at_ms,
                    })) if durable_generation > reset_generation => {
                        self.conversation_states().lock().await.insert(
                            convo_id.to_string(),
                            ConversationState::ResetPending {
                                new_group_id,
                                reset_generation: durable_generation,
                                notified_at_ms: durable_notified_at_ms,
                            },
                        );
                        return Err(OrchestratorError::ResetCompletionNotCommitted {
                        convo_id: convo_id.to_string(),
                        reset_generation,
                        reason: format!(
                            "mark response failed and newer durable generation {durable_generation} owns authority"
                        ),
                    });
                    }
                    Ok(_) => {
                        self.report_recovery_storage_failure(
                            convo_id,
                            "mark_reset_pending",
                            &mark_error,
                        )
                        .await;
                        return Err(mark_error);
                    }
                    Err(read_error) => {
                        self.report_recovery_storage_failure(
                            convo_id,
                            "mark_reset_pending:ambiguous_read",
                            &read_error,
                        )
                        .await;
                        return Err(OrchestratorError::Storage(format!(
                        "mark_reset_pending response failed ({mark_error}); durable authority reread failed ({read_error})"
                    )));
                    }
                },
            }
        };
        self.conversation_states()
            .lock()
            .await
            .insert(convo_id.to_string(), durable_state);
        if let Some(view) = self.conversations().lock().await.get_mut(convo_id) {
            view.group_id = new_group_id_hex.to_string();
            view.epoch = 0;
        }

        // 2. Delete the old local MLS group through the authoritative mapping.
        delete_materialized_reset_predecessors(old_group_ids, |group_id| {
            self.mls_context().delete_group(group_id)
        })?;

        // 3. Clear any in-flight rejoin bookkeeping — server reset is a fresh
        // start, not a continuation of our attempt counter. Crucially, this
        // does NOT arm `last_global_rejoin_at`: that gate gates OUR rejoin
        // attempts, and a server-pushed reset is not such an attempt. See
        // `RecoveryTracker::clear_for_fresh_reset` for the bug history.
        let was_quarantined = {
            let mut tracker = self.recovery_tracker().lock().await;
            tracker.clear_for_fresh_reset(convo_id);
            tracker.clear_quarantine(convo_id)
        };
        // WS-5.4 write-through: a server reset wipes the persisted backoff
        // entry too, mirroring `clear_for_fresh_reset` (no global-gate write —
        // a server-pushed reset is not an attempt by this client).
        if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_recovery_backoff", &e)
                .await;
        }
        // WS-3 stage 2 (backlog N44a): a server reset also wipes stored
        // sequencer receipts for this conversation. The reset rebuilds the
        // MLS group — epochs restart — so comparing receipts across the reset
        // boundary is meaningless and would false-positive the ADR-009 D8
        // equivocation check (stale pre-reset receipt at epoch N vs genuine
        // post-reset receipt at the same N). A failed clear leaves those
        // false-positive-producing rows behind, so escalate like the
        // recovery-critical writes above.
        if let Err(e) = self.storage().clear_sequencer_receipts(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_sequencer_receipts", &e)
                .await;
        }
        if was_quarantined {
            // Server reset trumps client-side quarantine (ruling 2a). The
            // authority commit in `mark_reset_pending` is now contractually
            // required to clear the persisted quarantine itself; this call
            // remains as a backstop for backends written before that
            // amendment. Warn-only here used to mint the both-set row on its
            // own — a plain failed clear, no crash needed — and such a row
            // rehydrates quarantined forever because the replayed reset takes
            // the same-generation dedupe path above and never returns here.
            // Escalate like the other recovery-critical writes in this
            // function.
            if let Err(e) = self.storage().clear_quarantine(convo_id).await {
                self.report_recovery_storage_failure(convo_id, "clear_quarantine", &e)
                    .await;
            }
            tracing::info!(convo_id, "[QUARANTINE-CLEAR] via server reset");
        }
        self.groupinfo_404_tracker().lock().await.clear(convo_id);

        // 4. Update group_states to point at the new group id so that any
        // group-id-derived lookups see the new target. `mark_reset_pending`
        // already armed durable `needs_rejoin` in the authority transaction,
        // so a crash at any point after publication remains restart-routable.
        {
            let mut states = self.group_states().lock().await;
            states
                .retain(|key, state| key == new_group_id_hex || state.conversation_id != convo_id);
            let entry = states
                .entry(new_group_id_hex.to_string())
                .or_insert_with(|| GroupState {
                    group_id: new_group_id_hex.to_string(),
                    conversation_id: convo_id.to_string(),
                    epoch: 0,
                    members: vec![],
                });
            entry.group_id = new_group_id_hex.to_string();
            entry.epoch = 0;
            let snap = entry.clone();
            drop(states);
            if let Err(e) = self.storage().set_group_state(&snap).await {
                tracing::warn!(
                    convo_id,
                    error = %e,
                    "Failed to persist group state rebinding on reset"
                );
            }
        }
        Ok(())
    }

    async fn reset_target_is_current_existing_group(
        &self,
        convo_id: &str,
        new_group_id_hex: &str,
    ) -> bool {
        let Some(current_group_id_bytes) = self.group_id_bytes_for_conversation(convo_id).await
        else {
            return false;
        };
        let current_group_id_hex = hex::encode(&current_group_id_bytes);
        current_group_id_hex.eq_ignore_ascii_case(new_group_id_hex)
            && self.mls_context().group_exists(current_group_id_bytes)
    }

    /// Handle a server-initiated group reset (spec §8.5 Phase 1 / §8.6).
    ///
    /// **Deprecated:** prefer `record_group_reset` from event handlers and
    /// let the deferred-recovery sync loop drive `join_or_rejoin`.
    ///
    /// WS-5.1 (invariant S1, spec §8.5): this method no longer performs the
    /// inline `join_or_rejoin` it historically ran. The auto-External-Commit
    /// pattern it embodied is exactly what caused production epoch inflation
    /// (March 2026 incident class; see
    /// `project_handle_group_reset_design_gaps.md`). The body now delegates
    /// to `record_group_reset` — persist `RESET_PENDING`, drop the old local
    /// group, clear recovery counters, flag `needs_rejoin` — and returns. The
    /// deferred-recovery loop in `sync_with_server` drives `join_or_rejoin`
    /// (Welcome → first-responder bootstrap → External Commit) on the next
    /// cycle.
    ///
    /// The signature is retained (and stays reachable via the UniFFI bridge)
    /// so out-of-tree callers keep compiling — removing it would be an ABI
    /// break for android/catmos/catmos-cli/web bindings.
    #[deprecated(
        since = "0.2.0",
        note = "Call `record_group_reset` from event handlers; deferred-recovery loop will drive `join_or_rejoin` (which now includes first-responder bootstrap). See spec §8.5 Phase 1."
    )]
    pub async fn handle_group_reset(
        &self,
        convo_id: &str,
        new_group_id: Vec<u8>,
        reset_generation: i32,
    ) -> Result<()> {
        tracing::warn!(
            convo_id,
            reset_generation,
            "handle_group_reset is deprecated and no longer rejoins inline; \
             delegating to record_group_reset (deferred recovery, invariant S1 / spec §8.5). \
             Callers should migrate to record_group_reset and rely on the sync loop."
        );
        self.record_group_reset(convo_id, new_group_id, reset_generation)
            .await
    }

    /// Read the durable ResetPending authority and refresh its in-memory
    /// projection. Callers must propagate read failures; collapsing them to
    /// `None` can authorize a stale recovery or delete path.
    pub(crate) async fn reset_pending_payload_result(
        &self,
        convo_id: &str,
    ) -> Result<Option<ResetPendingPayload>> {
        match self.storage().get_conversation_state(convo_id).await? {
            Some(ConversationState::ResetPending {
                new_group_id,
                reset_generation,
                notified_at_ms,
            }) => {
                let mut states = self.conversation_states().lock().await;
                if let Some(ConversationState::ResetPending {
                    new_group_id: cached_group_id,
                    reset_generation: cached_generation,
                    notified_at_ms: cached_notified_at_ms,
                }) = states.get(convo_id)
                {
                    if *cached_generation > reset_generation
                        || (*cached_generation == reset_generation
                            && cached_group_id != &new_group_id)
                    {
                        return Ok(Some(ResetPendingPayload {
                            new_group_id: cached_group_id.clone(),
                            reset_generation: *cached_generation,
                            notified_at_ms: *cached_notified_at_ms,
                        }));
                    }
                }
                let payload = ResetPendingPayload {
                    new_group_id: new_group_id.clone(),
                    reset_generation,
                    notified_at_ms,
                };
                states.insert(
                    convo_id.to_string(),
                    ConversationState::ResetPending {
                        new_group_id,
                        reset_generation,
                        notified_at_ms,
                    },
                );
                Ok(Some(payload))
            }
            // ResetPending is monotonic in memory. A stale None/non-reset read
            // must never downgrade it; only exact completion CAS or explicit
            // delete authority clears the projection.
            Some(_) | None => {
                let states = self.conversation_states().lock().await;
                Ok(match states.get(convo_id) {
                    Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation,
                        notified_at_ms,
                    }) => Some(ResetPendingPayload {
                        new_group_id: new_group_id.clone(),
                        reset_generation: *reset_generation,
                        notified_at_ms: *notified_at_ms,
                    }),
                    _ => None,
                })
            }
        }
    }

    /// Commit one reset recovery result against the exact durable generation.
    /// On a mismatch, refresh the newer authority and remove only the stale
    /// materialized candidate. Callback errors remain ambiguous and therefore
    /// preserve local material for a later durable reread.
    async fn complete_reset_recovery(
        &self,
        convo_id: &str,
        payload: &ResetPendingPayload,
        completed_group_id: Vec<u8>,
        delete_completed_group_on_mismatch: bool,
    ) -> Result<u64> {
        let landed_epoch = self
            .mls_context()
            .get_epoch(completed_group_id.clone())
            .map_err(|error| OrchestratorError::ResetCompletionNotCommitted {
                convo_id: convo_id.to_string(),
                reset_generation: payload.reset_generation,
                reason: format!("completed reset target epoch is unavailable: {error}"),
            })?;
        let cleared = match self
            .storage()
            .complete_reset_pending(
                convo_id,
                payload.reset_generation,
                &payload.new_group_id,
                landed_epoch,
            )
            .await
        {
            Ok(cleared) => cleared,
            Err(error) => {
                self.report_recovery_storage_failure(convo_id, "complete_reset_pending", &error)
                    .await;
                return Err(OrchestratorError::ResetCompletionNotCommitted {
                    convo_id: convo_id.to_string(),
                    reset_generation: payload.reset_generation,
                    reason: error.to_string(),
                });
            }
        };
        if cleared {
            // No I/O await is permitted between the durable CAS and these
            // cache projections. A newer in-process reset projection must
            // remain intact.
            let project_completed_target = {
                let mut states = self.conversation_states().lock().await;
                if matches!(
                    states.get(convo_id),
                    Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation,
                        ..
                    }) if *reset_generation == payload.reset_generation
                        && new_group_id == &payload.new_group_id
                ) {
                    states.insert(convo_id.to_string(), ConversationState::Active);
                    true
                } else {
                    false
                }
            };
            if project_completed_target {
                if let Some(view) = self.conversations().lock().await.get_mut(convo_id) {
                    view.group_id = payload.new_group_id.clone();
                    view.epoch = landed_epoch;
                }
            }
            return Ok(landed_epoch);
        }

        let _latest_reset_authority =
            self.reset_pending_payload_result(convo_id)
                .await
                .map_err(|error| OrchestratorError::ResetCompletionNotCommitted {
                    convo_id: convo_id.to_string(),
                    reset_generation: payload.reset_generation,
                    reason: format!("generation mismatch and authority reload failed: {error}"),
                })?;
        if delete_completed_group_on_mismatch
            && self.mls_context().group_exists(completed_group_id.clone())
        {
            self.mls_context()
                .delete_group(completed_group_id)
                .map_err(|error| OrchestratorError::ResetCompletionNotCommitted {
                    convo_id: convo_id.to_string(),
                    reset_generation: payload.reset_generation,
                    reason: format!("stale completed group cleanup failed: {error}"),
                })?;
        }
        Err(OrchestratorError::ResetCompletionNotCommitted {
            convo_id: convo_id.to_string(),
            reset_generation: payload.reset_generation,
            reason: "a newer reset generation owns recovery authority".to_string(),
        })
    }

    /// Adopt a server-verified reset winner without weakening ResetPending.
    /// The caller owns the transition lock and has already bound the processed
    /// Welcome group to the exact stable server conversation.
    async fn adopt_verified_welcome_reset_target(
        &self,
        convo_id: &str,
        payload: &ResetPendingPayload,
        authoritative_new_target: &str,
    ) -> Result<ResetPendingPayload> {
        let adopt_result = self
            .storage()
            .adopt_reset_pending_target(
                convo_id,
                payload.reset_generation,
                &payload.new_group_id,
                authoritative_new_target,
            )
            .await;

        let adopted = match adopt_result {
            Ok(true) => true,
            Ok(false) => false,
            Err(error) => {
                self.report_recovery_storage_failure(
                    convo_id,
                    "adopt_reset_pending_target",
                    &error,
                )
                .await;
                false
            }
        };

        // False and errors are commit-ambiguous: only an exact durable reread
        // of the adopted generation/target may authorize loser cleanup and
        // exact completion.
        if !adopted {
            let durable = self.storage().get_conversation_state(convo_id).await.map_err(
                |error| OrchestratorError::ResetCompletionNotCommitted {
                    convo_id: convo_id.to_string(),
                    reset_generation: payload.reset_generation,
                    reason: format!(
                        "winner-target adoption was not confirmed and authority reread failed: {error}"
                    ),
                },
            )?;
            if !matches!(
                durable,
                Some(ConversationState::ResetPending {
                    ref new_group_id,
                    reset_generation,
                    ..
                }) if reset_generation == payload.reset_generation
                    && new_group_id == authoritative_new_target
            ) {
                return Err(OrchestratorError::ResetCompletionNotCommitted {
                    convo_id: convo_id.to_string(),
                    reset_generation: payload.reset_generation,
                    reason: "winner-target adoption lost to newer or competing reset authority"
                        .to_string(),
                });
            }
        }

        let adopted_payload = ResetPendingPayload {
            new_group_id: authoritative_new_target.to_string(),
            reset_generation: payload.reset_generation,
            notified_at_ms: payload.notified_at_ms,
        };
        {
            let mut states = self.conversation_states().lock().await;
            match states.get(convo_id) {
                Some(ConversationState::ResetPending {
                    reset_generation,
                    new_group_id,
                    ..
                }) if *reset_generation == payload.reset_generation
                    && (new_group_id == &payload.new_group_id
                        || new_group_id == authoritative_new_target) =>
                {
                    states.insert(
                        convo_id.to_string(),
                        ConversationState::ResetPending {
                            new_group_id: authoritative_new_target.to_string(),
                            reset_generation: payload.reset_generation,
                            notified_at_ms: payload.notified_at_ms,
                        },
                    );
                }
                _ => {
                    return Err(OrchestratorError::ResetCompletionNotCommitted {
                        convo_id: convo_id.to_string(),
                        reset_generation: payload.reset_generation,
                        reason: "in-memory reset authority changed during winner adoption"
                            .to_string(),
                    });
                }
            }
        }

        if payload.new_group_id != authoritative_new_target {
            let loser_group = hex::decode(&payload.new_group_id).map_err(|error| {
                OrchestratorError::ResetCompletionNotCommitted {
                    convo_id: convo_id.to_string(),
                    reset_generation: payload.reset_generation,
                    reason: format!("loser reset target is malformed: {error}"),
                }
            })?;
            match self.mls_context().delete_group(loser_group) {
                Ok(()) | Err(crate::MLSError::GroupNotFound { .. }) => {}
                Err(error) => {
                    return Err(OrchestratorError::ResetCompletionNotCommitted {
                        convo_id: convo_id.to_string(),
                        reset_generation: payload.reset_generation,
                        reason: format!("failed to delete proven loser reset target: {error}"),
                    });
                }
            }
        }

        Ok(adopted_payload)
    }

    /// First-responder bootstrap (spec §8.5 Phase 1).
    ///
    /// Builds a local MLS group at the predetermined `new_group_id`,
    /// exports its `GroupInfo`, and submits via `bootstrapResetGroup`
    /// (mls-ds task #17). The server holds an empty post-reset row at
    /// `(id=originalConvoId, group_id=newGroupId, group_info IS NULL)`
    /// from the auto-reset that emitted the `groupResetEvent`; the
    /// endpoint UPDATEs that row in place, so race losers see HTTP 409
    /// `AlreadyBootstrapped` and drop their pre-bootstrap MLS group
    /// cleanly. (Pre-task #18 this used `createConvo`, which would
    /// orphan the post-reset row by INSERTing a new row at id=newGroupId —
    /// see ios-impl flag on task #13.)
    ///
    /// Race-loser semantics: do NOT clear `reset_pending` — the deferred-
    /// recovery loop will retry Welcome on the next sync cycle and pick
    /// up the winner's published Welcome.
    ///
    /// Race-winner semantics: clear `reset_pending`, transition to Active.
    ///
    /// Roster source: `group_states[convo_id].members` is unreliable post-
    /// reset (the server clears membership rosters atomically with the
    /// reset transaction), so we fetch fresh via `get_conversations`
    /// pagination per Phase 0 Q3. Spec design accepts this network cost
    /// because bootstrap is rare (post-quorum-reset only).
    async fn try_first_responder_bootstrap(
        &self,
        convo_id: &str,
        payload: &ResetPendingPayload,
        user_did: &str,
    ) -> Result<u64> {
        let new_group_id_bytes = hex::decode(&payload.new_group_id).map_err(|e| {
            OrchestratorError::InvalidInput(format!(
                "ResetPending.new_group_id is not valid hex ({}): {e}",
                payload.new_group_id
            ))
        })?;

        // Fetch fresh roster — post-reset, the server clears the membership
        // table atomically with the reset transaction (per Phase 0 Q3 / Q2
        // findings). Cached `group_states[convo_id].members` would be the
        // pre-reset roster.
        let roster = self.fetch_roster_for_convo(convo_id).await?;
        if roster.is_empty() {
            return Err(OrchestratorError::RecoveryFailed(format!(
                "Cannot bootstrap convo {convo_id}: server roster is empty"
            )));
        }

        tracing::info!(
            convo_id,
            new_group_id = %payload.new_group_id,
            roster_size = roster.len(),
            "first-responder bootstrap: creating local MLS group at predetermined id"
        );

        // 1. Create local MLS group AT the predetermined id.
        let scoped_identity = self.require_scoped_identity().await?;
        let identity_bytes = scoped_identity.into_bytes();
        let group_config = self.config().group_config.clone();
        let resumed_existing_candidate =
            self.mls_context().group_exists(new_group_id_bytes.clone());
        if !resumed_existing_candidate {
            let _creation_result = self.mls_context().create_group_with_id(
                identity_bytes.clone(),
                new_group_id_bytes.clone(),
                Some(group_config),
            )?;
        } else {
            tracing::info!(
                convo_id,
                reset_generation = payload.reset_generation,
                "first-responder bootstrap: resuming existing local candidate"
            );
        }

        // 2. Export GroupInfo from the freshly-created group — required by
        // bootstrapResetGroup's lexicon `groupInfo` field. On failure, drop
        // the local pre-bootstrap group so the next deferred-recovery cycle
        // starts clean (keep `reset_pending` so the loop retries).
        let group_info = match self
            .mls_context()
            .export_group_info(new_group_id_bytes.clone(), identity_bytes.clone())
        {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    convo_id,
                    error = %e,
                    "first-responder bootstrap: export_group_info failed; dropping local pre-bootstrap group"
                );
                if !resumed_existing_candidate {
                    let _ = self.mls_context().delete_group(new_group_id_bytes);
                }
                return Err(OrchestratorError::Mls(e));
            }
        };

        // 3. Submit to server via bootstrapResetGroup (NOT createConvo —
        // post-reset rows have id=originalConvoId, group_id=newGroupId, so
        // createConvo would orphan the row by inserting a new id=newGroupId
        // row. bootstrapResetGroup UPDATEs the existing post-reset row in
        // place. Per spec §8.5 / mls-ds task #17.) Members roster is
        // diagnostic-only on the server (lexicon docs); the persisted
        // members table preserved across reset is authoritative — we ship
        // the FULL roster including the caller, matching the catmos-cli
        // precedent at recovery_ops::bootstrap_reset_group.
        //
        // TODO: cipher_suite isn't tracked on ResetPendingPayload or
        // ConversationView yet. Use the catmos default to match the
        // existing create_conversation hardcoding (catmos
        // src-tauri/src/api_client.rs:776). When per-convo cipher_suite
        // plumbing lands, swap to derive from convo state.
        let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
        let result = self
            .submit_activate_reset_prepared(convo_id, payload, &group_info)
            .await;
        match result {
            Ok(_create_result) => {
                tracing::info!(
                    convo_id,
                    new_group_id = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "first-responder bootstrap won — clearing reset_pending"
                );
                let epoch = self
                    .complete_reset_recovery(convo_id, payload, new_group_id_bytes.clone(), true)
                    .await?;
                Ok(epoch)
            }
            Err(err) if err.is_bootstrap_already_bootstrapped() => {
                let authoritative = self.fetch_conversation_for_convo(convo_id).await;
                let authoritative_group_info = self.api_client().get_group_info(convo_id).await;
                match (authoritative, authoritative_group_info) {
                    (Ok(conversation), Ok(server_group_info))
                        if conversation.group_id == payload.new_group_id
                            && server_group_info == group_info =>
                    {
                        tracing::info!(
                            convo_id,
                            new_group_id = %payload.new_group_id,
                            reset_generation = payload.reset_generation,
                            resumed_existing_candidate,
                            "AlreadyBootstrapped is bound to this accepted local candidate; resuming local reset completion"
                        );
                        let epoch = self
                            .complete_reset_recovery(
                                convo_id,
                                payload,
                                new_group_id_bytes.clone(),
                                true,
                            )
                            .await?;
                        return Ok(epoch);
                    }
                    (Ok(conversation), Ok(server_group_info)) => {
                        tracing::info!(
                            convo_id,
                            local_group_id = %payload.new_group_id,
                            authoritative_group_id = %conversation.group_id,
                            group_info_matches = server_group_info == group_info,
                            resumed_existing_candidate,
                            "AlreadyBootstrapped is authoritatively bound to a different winner"
                        );
                    }
                    (conversation_result, group_info_result) => {
                        tracing::warn!(
                            convo_id,
                            conversation_error = ?conversation_result.err(),
                            group_info_error = ?group_info_result.err(),
                            resumed_existing_candidate,
                            "Could not bind AlreadyBootstrapped to an authoritative winner; preserving local candidate"
                        );
                        return Err(OrchestratorError::ResetCompletionNotCommitted {
                            convo_id: convo_id.to_string(),
                            reset_generation: payload.reset_generation,
                            reason: "AlreadyBootstrapped authority could not be verified"
                                .to_string(),
                        });
                    }
                }
                tracing::info!(
                    convo_id,
                    new_group_id = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "first-responder bootstrap race lost (AlreadyBootstrapped) — dropping local pre-bootstrap group"
                );
                if let Err(e) = self.mls_context().delete_group(new_group_id_bytes) {
                    tracing::warn!(
                        convo_id,
                        error = %e,
                        "delete_group for race-lost bootstrap failed (non-fatal)"
                    );
                }
                // Do NOT clear reset_pending — the deferred-recovery loop will
                // retry Welcome on the next sync cycle and pick up the
                // winner's published Welcome.
                Err(err)
            }
            Err(err) => {
                // Other error (network, auth, etc.) — drop the local group so
                // the next bootstrap attempt starts clean. Keep reset_pending.
                tracing::warn!(
                    convo_id,
                    "first-responder bootstrap bootstrapResetGroup failed; dropping local group, will retry"
                );
                if resumed_existing_candidate {
                    tracing::warn!(
                        convo_id,
                        "preserving resumed bootstrap candidate after uncertain server error"
                    );
                } else if let Err(e) = self.mls_context().delete_group(new_group_id_bytes) {
                    tracing::warn!(
                        convo_id,
                        error = %e,
                        "delete_group for failed bootstrap failed (non-fatal)"
                    );
                }
                Err(err)
            }
        }
    }

    /// Page through `get_conversations` to find the roster for a single
    /// conversation. Phase 0 Q3 confirms `groupResetEvent` does NOT carry
    /// a roster, and the cached `group_states` membership is wiped by the
    /// server's reset transaction. Bootstrap rarity (post-quorum-reset
    /// only) makes the network cost acceptable.
    async fn fetch_roster_for_convo(&self, convo_id: &str) -> Result<Vec<String>> {
        let conversation = self.fetch_conversation_for_convo(convo_id).await?;
        Ok(conversation.members.iter().map(|m| m.did.clone()).collect())
    }

    pub(crate) async fn fetch_conversation_for_convo(
        &self,
        convo_id: &str,
    ) -> Result<ConversationView> {
        let mut cursor: Option<String> = None;
        let mut pagination = PaginationGuard::for_conversations("reset conversation lookup");
        loop {
            let page = self
                .api_client()
                .get_conversations(50, cursor.as_deref())
                .await?;
            pagination.observe_page(page.conversations.len(), page.cursor.as_deref())?;
            for cv in &page.conversations {
                if cv.conversation_id == convo_id {
                    return Ok(cv.clone());
                }
            }
            cursor = page.cursor;
            if cursor.is_none() {
                return Err(OrchestratorError::ConversationNotFound(format!(
                    "Server did not return convo {convo_id} in pagination — cannot bootstrap"
                )));
            }
        }
    }

    /// Check desync severity between local and server key packages.
    pub async fn check_desync_severity(&self) -> Result<DesyncSeverity> {
        let stats = self.api_client().get_key_package_stats().await?;

        // If no key packages on server and we think we're registered, it's severe
        if stats.available == 0 {
            let user_did = self.require_user_did().await?;
            if self.credentials().has_credentials(&user_did).await? {
                return Ok(DesyncSeverity::Severe {
                    local_count: 0,
                    server_count: 0,
                    difference: 0,
                });
            }
            return Ok(DesyncSeverity::None);
        }

        Ok(DesyncSeverity::None)
    }

    /// Classify whether an incoming-message processing failure looks peer-bad.
    /// Used by Layer 3 quarantine to drive .
    ///
    /// Signal A (error class) is the primary input. Signal B (epoch context)
    /// gates Signal A: if the local epoch is BEHIND the message epoch we lean
    /// self-bad regardless of the error class, because we may simply be missing
    /// commits and decrypt failures here are normal catch-up.
    pub(crate) fn classify_peer_bad(
        err: &crate::MLSError,
        local_epoch: Option<u64>,
        message_epoch: u64,
    ) -> bool {
        // Signal B: if we are behind the message, we are catching up; not peer-bad.
        if let Some(local) = local_epoch {
            if local < message_epoch {
                return false;
            }
        }
        // Wrong-epoch is the canonical self-bad signal.
        // Wrong-epoch or wrong-group (superseded generation) is not peer-bad.
        if err.is_wrong_epoch() || err.is_wrong_group_id() {
            return false;
        }
        match err {
            crate::MLSError::InvalidCommit
            | crate::MLSError::WireFormatPolicyViolation { .. }
            | crate::MLSError::InvalidProposalRef
            | crate::MLSError::TlsCodec(_) => true,
            crate::MLSError::CommitProcessingFailed { message } => {
                let m = message.to_lowercase();
                m.contains("leafnodevalidation")
                    || m.contains("invalidgroupinfo")
                    || m.contains("authenticationfailed")
                    || m.contains("invalidcredential")
                    || m.contains("proposalvalidationerror")
            }
            crate::MLSError::OpenMLS(message) => {
                let m = message.to_lowercase();
                m.contains("leafnodevalidation")
                    || m.contains("invalidgroupinfo")
                    || m.contains("authenticationfailed")
                    || m.contains("invalidcredential")
                    || m.contains("proposalvalidationerror")
            }
            // Self-bad / ambiguous classes: treat as not peer-bad so we do not
            // tip the classifier.
            _ => false,
        }
    }

    /// Public API: snapshot of a conversation quarantine state, if any.
    pub async fn get_conversation_quarantine_state(
        &self,
        convo_id: &str,
    ) -> Option<crate::orchestrator::types::QuarantineState> {
        let tracker = self.recovery_tracker().lock().await;
        if let Some(state) = tracker.quarantine_snapshot(convo_id) {
            return Some(state);
        }
        if let Ok(resolved) = self.resolve_legacy_group_identifier(convo_id).await {
            if let Some(state) = tracker.quarantine_snapshot(&resolved.conversation_id) {
                return Some(state);
            }
        }
        None
    }

    /// Internal: mark a conversation quarantined and persist the transition.
    /// Emits the on_conversation_quarantined event when an event callback is
    /// installed.
    pub(crate) async fn enter_quarantine(
        &self,
        convo_id: &str,
        reason: crate::orchestrator::types::QuarantineReason,
    ) {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let transition_guard = transition_lock.lock().await;
        match self
            .reset_blocks_non_reset_transition_locked(convo_id)
            .await
        {
            Ok(false) => {}
            Ok(true) => return,
            Err(e) => {
                self.report_recovery_storage_failure(
                    convo_id,
                    "enter_quarantine:reset_authority_read",
                    &e,
                )
                .await;
                return;
            }
        }
        let since_ms = chrono::Utc::now().timestamp_millis();
        let suspected_dids = {
            let tracker = self.recovery_tracker().lock().await;
            tracker.suspected_dids_for(convo_id)
        };
        {
            let mut tracker = self.recovery_tracker().lock().await;
            tracker.mark_quarantined(convo_id, reason, since_ms, suspected_dids.clone());
        }
        // WS-5.4 write-through: `mark_quarantined` dropped the in-memory
        // failed_rejoins entry; mirror that to the persisted backoff row.
        // Quarantine has its own persisted lifecycle — leaving a maxed-out
        // backoff row behind would let hydration re-import the lockout
        // within the 24 h TTL and gate a conversation that already exited
        // quarantine. Mirrors the server-reset clear in
        // `persist_reset_pending_state`.
        if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_recovery_backoff", &e)
                .await;
        }
        // WS-5.2: quarantine state is recovery-critical — a dropped write
        // here means the quarantine silently does not survive restart and
        // the conversation re-enters the message flow until Layer 3 trips
        // again. Escalate like the backoff-row clear above.
        let quarantine_state = ConversationState::Quarantined { reason, since_ms };
        if let Err(e) = self
            .storage()
            .set_conversation_state(convo_id, quarantine_state.clone())
            .await
        {
            self.report_recovery_storage_failure(
                convo_id,
                "set_conversation_state:quarantined",
                &e,
            )
            .await;
        } else {
            self.conversation_states()
                .lock()
                .await
                .insert(convo_id.to_string(), quarantine_state);
        }
        if let Err(e) = self
            .storage()
            .mark_quarantined(convo_id, reason.tag(), since_ms)
            .await
        {
            self.report_recovery_storage_failure(convo_id, "mark_quarantined", &e)
                .await;
        }
        tracing::warn!(
            convo_id,
            reason = reason.tag(),
            suspected_count = suspected_dids.len(),
            "[QUARANTINE-ENTER] conversation quarantined"
        );
        drop(transition_guard);
        self.notify_quarantined(convo_id, reason, suspected_dids)
            .await;
    }

    /// Internal: clear quarantine, transition to Active, persist, and emit event.
    pub(crate) async fn exit_quarantine(
        &self,
        convo_id: &str,
        via: crate::orchestrator::types::QuarantineExitReason,
    ) {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let transition_guard = transition_lock.lock().await;
        let reset_blocks_active = match self
            .reset_blocks_non_reset_transition_locked(convo_id)
            .await
        {
            Ok(blocked) => blocked,
            Err(e) => {
                self.report_recovery_storage_failure(
                    convo_id,
                    "exit_quarantine:reset_authority_read",
                    &e,
                )
                .await;
                return;
            }
        };
        let was = {
            let mut tracker = self.recovery_tracker().lock().await;
            tracker.clear_quarantine(convo_id)
        };
        if !was {
            return;
        }
        // Conversation state transitions to Active here for PeerCommitSucceeded
        // and UserConfirmedReset; ServerReset path handles its own transition
        // (ResetPending) before calling exit_quarantine.
        if !matches!(
            via,
            crate::orchestrator::types::QuarantineExitReason::ServerReset
        ) && !reset_blocks_active
        {
            // WS-5.2: a dropped write here leaves the persisted state
            // Quarantined, so restart rehydration re-quarantines a
            // conversation the user/peer already cleared. Escalate.
            match self
                .project_non_reset_state_locked(convo_id, ConversationState::Active)
                .await
            {
                Ok(true) => {}
                Ok(false) => {}
                Err(e) => {
                    self.report_recovery_storage_failure(
                        convo_id,
                        "set_conversation_state:active_quarantine_exit",
                        &e,
                    )
                    .await;
                }
            }
        }
        // WS-5.2: a surviving quarantine payload row resurrects the
        // quarantine on restart. Escalate like the state write above.
        if let Err(e) = self.storage().clear_quarantine(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_quarantine", &e)
                .await;
        }
        tracing::info!(
            convo_id,
            via = via.tag(),
            "[QUARANTINE-CLEAR] conversation quarantine cleared"
        );
        drop(transition_guard);
        self.notify_quarantine_cleared(convo_id, via).await;
    }

    /// Public API: user-confirmed manual reset. Requests and (as an admin)
    /// activates a clean-chat reset from server state, then clears local
    /// quarantine so the successor generation is not gated by the dead one.
    pub async fn user_confirmed_manual_reset(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let auth = self.epoch_authenticator_hex(convo_id).await;
        tracing::info!(convo_id, auth = ?auth, "user_confirmed_manual_reset: manual reset confirmed by user");
        let outcome = self.reset_conversation(convo_id, "manualRecovery").await?;
        tracing::info!(convo_id, ?outcome, "user_confirmed_manual_reset: reset outcome");
        self.exit_quarantine(
            convo_id,
            crate::orchestrator::types::QuarantineExitReason::UserConfirmedReset,
        )
        .await;
        Ok(())
    }

    pub(crate) async fn notify_quarantined(
        &self,
        convo_id: &str,
        reason: crate::orchestrator::types::QuarantineReason,
        suspected_dids: Vec<String>,
    ) {
        if let Some(obs) = self.current_event_observer().await {
            obs.on_conversation_quarantined(convo_id, reason, suspected_dids);
        }
    }

    pub(crate) async fn notify_quarantine_cleared(
        &self,
        convo_id: &str,
        via: crate::orchestrator::types::QuarantineExitReason,
    ) {
        if let Some(obs) = self.current_event_observer().await {
            obs.on_conversation_quarantine_cleared(convo_id, via);
        }
    }

    async fn locally_known_metadata(
        &self,
        convo_id: &str,
    ) -> Result<crate::metadata::GroupMetadataV1> {
        let cached = self
            .conversations()
            .lock()
            .await
            .get(convo_id)
            .and_then(|conversation| conversation.metadata.clone());
        let metadata = match cached {
            Some(metadata) => Some(metadata),
            None => {
                let user_did = self.require_user_did().await?;
                self.storage()
                    .get_conversation(&user_did, convo_id)
                    .await?
                    .and_then(|conversation| conversation.metadata)
            }
        };
        let (title, description, avatar_blob_locator) = match metadata {
            Some(metadata) => (
                metadata.name.unwrap_or_default(),
                metadata.description.unwrap_or_default(),
                metadata.avatar_url,
            ),
            None => {
                tracing::warn!(
                    convo_id,
                    "no locally cached conversation metadata available; sealing an empty snapshot"
                );
                (String::new(), String::new(), None)
            }
        };
        Ok(crate::metadata::GroupMetadataV1 {
            version: 1,
            title,
            description,
            avatar_blob_locator,
            avatar_content_type: None,
        })
    }

    async fn submit_external_commit_prepared(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        target_epoch: u64,
    ) -> Result<ProcessExternalCommitResult> {
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential(
                "auth_generation must be >= 1".into(),
            ));
        }
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);

        let resolved = self.resolve_conversation_context(convo_id).await?;
        let group_id_bytes = resolved.group_id_bytes()?;
        let tag_bytes = self
            .mls_context()
            .get_confirmation_tag(group_id_bytes.clone())?;
        if tag_bytes.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "confirmation tag must be exactly 32 bytes, got {}",
                tag_bytes.len()
            ))));
        }
        let gc_hash = self
            .mls_context()
            .get_group_context_hash(group_id_bytes.clone())?;
        if gc_hash.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "group context hash must be exactly 32 bytes, got {}",
                gc_hash.len()
            ))));
        }
        let convo_uuid = uuid::Uuid::parse_str(convo_id).map_err(|e| {
            OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}"))
        })?;

        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let metadata_plaintext = self.locally_known_metadata(convo_id).await?;
        let metadata_key: [u8; 32] = self
            .mls_context()
            .export_metadata_key(group_id_bytes.clone(), target_epoch)?
            .try_into()
            .map_err(|_| {
                OrchestratorError::Mls(MLSError::Internal("metadata key length mismatch".into()))
            })?;
        let ciphertext = crate::metadata::encrypt_metadata_snapshot_with_nonce(
            &metadata_key,
            &group_id_bytes,
            target_epoch,
            u64::from(metadata_plaintext.version),
            &nonce,
            &metadata_plaintext,
        )
        .map_err(|error| {
            OrchestratorError::Mls(MLSError::Internal(format!(
                "encrypt metadata snapshot: {error:?}"
            )))
        })?;

        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use sha2::{Digest, Sha256};

        let transition_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = uuid::Uuid::new_v4().to_string();

        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "aad": {
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": 0,
                "prior": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": target_epoch.saturating_sub(1),
                    "generation": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                    "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                    "lifecycle": "active",
                    "stateVersion": 0
                },
                "protocolVersion": "1",
                "transitionId": STANDARD.encode(uuid::Uuid::parse_str(&transition_id).map_err(|e| OrchestratorError::InvalidInput(e.to_string()))?.as_bytes())
            },
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "commit": {
                "bytes": { "$bytes": STANDARD.encode(commit_data) },
                "contentType": "publicMessageCommit",
                "framing": "mlsMessage",
                "sha256": STANDARD.encode(Sha256::digest(commit_data))
            },
            "idempotencyKey": idempotency_key,
            "keyId": key_id,
            "manifest": {
                "leafChanges": [],
                "participantChanges": []
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": auth_generation,
                    "authorDeviceId": actor_device_id,
                    "authorDid": user_did,
                    "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active",
                    "originSeq": 1,
                    "originTransitionId": transition_id,
                    "roleAtOrigin": "admin",
                    "signaturePublicKey": { "$bytes": STANDARD.encode(&public_key) }
                },
                "ciphertext": { "$bytes": STANDARD.encode(&ciphertext) },
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": target_epoch,
                    "generation": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                    "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) }
                },
                "metadataVersion": metadata_plaintext.version,
                "nonce": { "$bytes": STANDARD.encode(&nonce) },
                "originTransitionId": transition_id
            },
            "next": {
                "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                "conversationId": convo_id,
                "epoch": target_epoch,
                "generation": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                "lifecycle": "active",
                "stateVersion": 0
            },
            "prior": {
                "confirmationTag": { "$bytes": STANDARD.encode(&tag_bytes) },
                "conversationId": convo_id,
                "epoch": target_epoch.saturating_sub(1),
                "generation": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&gc_hash) },
                "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                "lifecycle": "active",
                "stateVersion": 0
            },
            "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "transitionId": transition_id
        });

        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::SubmitTransition,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;

        if response.status != 200 {
            if response.status == 409 {
                return Err(OrchestratorError::EpochMismatch {
                    local: target_epoch,
                    remote: target_epoch + 1,
                });
            }
            return Err(OrchestratorError::Api(format!(
                "process_external_commit failed with status {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }

        let resp_json: serde_json::Value =
            serde_json::from_slice(&response.body).unwrap_or_default();
        let server_epoch = resp_json
            .get("result")
            .and_then(|r| r.get("epoch"))
            .and_then(|e| e.as_u64())
            .unwrap_or(target_epoch);
        if server_epoch != target_epoch {
            return Err(OrchestratorError::EpochMismatch {
                local: target_epoch,
                remote: server_epoch,
            });
        }
        let receipt: Option<crate::orchestrator::types::SequencerReceipt> = resp_json
            .get("result")
            .and_then(|r| r.get("receipt"))
            .and_then(|rc| serde_json::from_value(rc.clone()).ok());

        Ok(ProcessExternalCommitResult {
            epoch: target_epoch,
            rejoined_at: chrono::Utc::now().to_rfc3339(),
            receipt,
        })
    }

    /// Record a `requestReset` bound to the server's *current* coordinate.
    /// Reads nothing from local MLS state, so it works from a device whose
    /// group is gone — the situation a reset exists for.
    async fn submit_reset_request_prepared(&self, convo_id: &str, reason: &str) -> Result<()> {
        let state = self.fetch_server_conversation_state(convo_id).await?;
        self.ensure_reset_request(&state, reason).await.map(|_| ())
    }

    async fn submit_activate_reset_prepared(
        &self,
        convo_id: &str,
        payload: &ResetPendingPayload,
        group_info: &[u8],
    ) -> Result<CreateConversationResult> {
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential(
                "auth_generation must be >= 1".into(),
            ));
        }
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);
        let transition_id = uuid::Uuid::new_v4().to_string();
        let new_group_id_bytes = hex::decode(&payload.new_group_id)
            .map_err(|_| OrchestratorError::InvalidInput("invalid new_group_id hex".into()))?;
        let (group_info_group_id, successor_epoch) = {
            let (gid, epoch) = {
                crate::message_limits::validate_inbound_mls_message_len(
                    group_info.len(),
                    "group_info",
                )?;
                let (message, remaining) = MlsMessageIn::tls_deserialize_bytes(group_info)
                    .map_err(|_| OrchestratorError::InvalidInput("malformed GroupInfo".into()))?;
                if !remaining.is_empty() {
                    return Err(OrchestratorError::InvalidInput(
                        "GroupInfo trailing bytes".into(),
                    ));
                }
                match message.extract() {
                    MlsMessageBodyIn::GroupInfo(info) => {
                        (info.group_id().as_slice().to_vec(), info.epoch().as_u64())
                    }
                    _ => return Err(OrchestratorError::InvalidInput("not GroupInfo".into())),
                }
            };
            (gid, epoch)
        };
        if group_info_group_id != new_group_id_bytes || successor_epoch != 0 {
            return Err(OrchestratorError::InvalidInput(
                "exported reset GroupInfo coordinate mismatch".into(),
            ));
        }
        let prior_context = self.resolve_conversation_context(convo_id).await?;
        let prior_group_id = prior_context.group_id_bytes()?;
        let prior_epoch = self.mls_context().get_epoch(prior_group_id.clone())?;
        let prior_tag: [u8; 32] = self
            .mls_context()
            .get_confirmation_tag(prior_group_id.clone())?
            .try_into()
            .map_err(|_| {
                OrchestratorError::Mls(MLSError::Internal(
                    "prior confirmation tag length mismatch".into(),
                ))
            })?;
        let prior_gc_hash: [u8; 32] = self
            .mls_context()
            .get_group_context_hash(prior_group_id.clone())?
            .try_into()
            .map_err(|_| {
                OrchestratorError::Mls(MLSError::Internal(
                    "prior group context hash length mismatch".into(),
                ))
            })?;
        let successor_tag: [u8; 32] = self
            .mls_context()
            .get_confirmation_tag(new_group_id_bytes.clone())?
            .try_into()
            .map_err(|_| {
                OrchestratorError::Mls(MLSError::Internal(
                    "successor confirmation tag length mismatch".into(),
                ))
            })?;
        let successor_gc_hash: [u8; 32] = self
            .mls_context()
            .get_group_context_hash(new_group_id_bytes.clone())?
            .try_into()
            .map_err(|_| {
                OrchestratorError::Mls(MLSError::Internal(
                    "successor group context hash length mismatch".into(),
                ))
            })?;
        let convo_uuid = uuid::Uuid::parse_str(convo_id).map_err(|e| {
            OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}"))
        })?;
        let prior_generation = payload.reset_generation;

        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let metadata_plaintext = self.locally_known_metadata(convo_id).await?;
        let metadata_key: [u8; 32] = self
            .mls_context()
            .export_metadata_key(new_group_id_bytes.clone(), successor_epoch)?
            .try_into()
            .map_err(|_| {
                OrchestratorError::Mls(MLSError::Internal("metadata key length mismatch".into()))
            })?;
        let ciphertext = crate::metadata::encrypt_metadata_snapshot_with_nonce(
            &metadata_key,
            &new_group_id_bytes,
            successor_epoch,
            u64::from(metadata_plaintext.version),
            &nonce,
            &metadata_plaintext,
        )
        .map_err(|error| {
            OrchestratorError::Mls(MLSError::Internal(format!(
                "encrypt metadata snapshot: {error:?}"
            )))
        })?;

        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#resetActivationBody",
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "conversationKind": "group",
            "genesisGroupInfo": {
                "bytes": base64::engine::general_purpose::STANDARD.encode(group_info),
                "contentType": "groupInfo",
                "framing": "mlsMessage",
                "sha256": base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(group_info))
            },
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "keyId": key_id,
            "manifest": {
                "actorLeaf": {
                    "deviceId": actor_device_id,
                    "leafOrigin": "genesis",
                    "userDid": user_did
                },
                "participants": [{
                    "userDid": user_did,
                    "role": "admin",
                    "status": "active"
                }]
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": auth_generation,
                    "authorDeviceId": actor_device_id,
                    "authorDid": user_did,
                    "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active",
                    "originSeq": 1,
                    "originTransitionId": transition_id,
                    "roleAtOrigin": "admin",
                    "signaturePublicKey": base64::engine::general_purpose::STANDARD.encode(&public_key)
                },
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
                "ciphertextSha256": base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "confirmationTag": base64::engine::general_purpose::STANDARD.encode(successor_tag),
                    "conversationId": base64::engine::general_purpose::STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": successor_epoch,
                    "generation": prior_generation + 1,
                    "groupContextHash": base64::engine::general_purpose::STANDARD.encode(successor_gc_hash),
                    "groupId": base64::engine::general_purpose::STANDARD.encode(&new_group_id_bytes)
                },
                "metadataVersion": metadata_plaintext.version,
                "nonce": base64::engine::general_purpose::STANDARD.encode(&nonce),
                "originTransitionId": transition_id
            },
            "prior": {
                "confirmationTag": base64::engine::general_purpose::STANDARD.encode(prior_tag),
                "conversationId": convo_id,
                "epoch": prior_epoch,
                "generation": prior_generation,
                "groupContextHash": base64::engine::general_purpose::STANDARD.encode(prior_gc_hash),
                "groupId": base64::engine::general_purpose::STANDARD.encode(&prior_group_id),
                "lifecycle": "active",
                "stateVersion": 0
            },
            "resetRequestId": uuid::Uuid::new_v4().to_string(),
            "retired": {
                "confirmationTag": base64::engine::general_purpose::STANDARD.encode(prior_tag),
                "conversationId": convo_id,
                "epoch": prior_epoch,
                "generation": prior_generation,
                "groupContextHash": base64::engine::general_purpose::STANDARD.encode(prior_gc_hash),
                "groupId": base64::engine::general_purpose::STANDARD.encode(&prior_group_id),
                "lifecycle": "superseded",
                "stateVersion": 1
            },
            "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
            "successor": {
                "confirmationTag": base64::engine::general_purpose::STANDARD.encode(successor_tag),
                "conversationId": convo_id,
                "epoch": successor_epoch,
                "generation": prior_generation + 1,
                "groupContextHash": base64::engine::general_purpose::STANDARD.encode(successor_gc_hash),
                "groupId": base64::engine::general_purpose::STANDARD.encode(&new_group_id_bytes),
                "lifecycle": "active",
                "stateVersion": 0
            },
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "transitionId": transition_id
        });
        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::ActivateReset,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status as u16,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        Ok(CreateConversationResult {
            conversation: ConversationView {
                group_id: payload.new_group_id.clone(),
                conversation_id: convo_id.to_string(),
                epoch: 0,
                members: vec![MemberView {
                    did: user_did,
                    role: MemberRole::Admin,
                }],
                metadata: None,
                created_at: Some(chrono::Utc::now()),
                updated_at: Some(chrono::Utc::now()),
                sequencer_did: None,
            },
            commit_data: None,
            welcome_data: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welcome_reissue_root_matching_preserves_method_specific_case() {
        assert!(credential_root_matches_exact(
            "did:web:Example.com#device-a",
            "did:web:Example.com"
        ));
        assert!(!credential_root_matches_exact(
            "did:web:example.com#device-b",
            "did:web:Example.com"
        ));
    }

    struct DurableEpochSecretStorage {
        cleanup_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::types::EpochSecretStorage for DurableEpochSecretStorage {
        async fn store_epoch_secret(
            &self,
            _conversation_id: String,
            _epoch: u64,
            _secret_data: Vec<u8>,
        ) -> bool {
            true
        }

        async fn get_epoch_secret(&self, _conversation_id: String, _epoch: u64) -> Option<Vec<u8>> {
            None
        }

        async fn delete_epoch_secret(&self, _conversation_id: String, _epoch: u64) -> bool {
            true
        }

        async fn delete_epochs_before(&self, _conversation_id: String, _cutoff_epoch: u64) -> u32 {
            self.cleanup_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            0
        }
    }

    #[cfg(feature = "fork-resolution")]
    async fn fork_readd_fixture(
        label: &str,
    ) -> (crate::recovery_e2e_harness::TestWorld, String, String, u64) {
        let mut world = crate::recovery_e2e_harness::TestWorld::new();
        world.add_client("Alice").await;
        world.add_client("Bob").await;
        world.register_device("Alice").await.unwrap();
        let bob_did = world.register_device("Bob").await.unwrap();
        let alice = world.client("Alice");
        let bob = world.client("Bob");
        let group = alice
            .orchestrator
            .create_group(label, Some(std::slice::from_ref(&bob_did)), None)
            .await
            .expect("create fork fixture");

        let bob_device_id = bob
            .orchestrator
            .require_actor_device_id()
            .await
            .expect("bob device id");
        let key_package = bob
            .orchestrator
            .mls_context()
            .create_key_package(format!("{bob_did}#{bob_device_id}").into_bytes())
            .expect("create Bob fork fixture key package");
        world
            .delivery_service()
            .add_leaf_recovery_inbox_item(serde_json::json!({
                "recovery": {
                    "recoveryRequestId": uuid::Uuid::new_v4().to_string(),
                    "conversationId": group.conversation_id,
                    "requesterDid": bob_did,
                    "requesterDeviceId": bob_device_id,
                    "recoveryKind": "add",
                    "status": "open",
                    "reservation": {
                        "keyPackageRef": STANDARD.encode(&key_package.hash_ref),
                        "keyPackage": {
                            "bytes": STANDARD.encode(&key_package.key_package_data)
                        }
                    }
                }
            }));
        assert_eq!(
            alice
                .orchestrator
                .fulfill_pending_leaf_recoveries()
                .await
                .expect("add Bob to fork fixture"),
            1,
            "fork fixture must contain a complement member"
        );

        let epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&group.group_id).expect("group id hex"))
            .expect("source epoch");
        assert_eq!(epoch, 1, "Bob add commit must advance the fixture");
        let mut durable_state = alice
            .storage
            .get_group_state(&group.group_id)
            .await
            .expect("read fork fixture group state")
            .expect("fork fixture group state exists");
        durable_state.epoch = epoch;
        alice
            .storage
            .set_group_state(&durable_state)
            .await
            .expect("persist fork fixture add epoch");
        alice
            .orchestrator
            .group_states()
            .lock()
            .await
            .insert(group.group_id.clone(), durable_state);
        (world, group.conversation_id, group.group_id, epoch)
    }

    #[cfg(feature = "fork-resolution")]
    fn canonical_transition_submission_count(
        world: &crate::recovery_e2e_harness::TestWorld,
    ) -> usize {
        world
            .delivery_service()
            .submitted_prepared_requests()
            .iter()
            .filter(|request| {
                request.operation
                    == crate::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition
            })
            .count()
    }

    fn submitted_inner_body(
        request: &crate::orchestrator::canonical_transport::PreparedRequest,
    ) -> serde_json::Value {
        let value: serde_json::Value =
            serde_json::from_slice(request.body.as_deref().unwrap_or_default())
                .expect("parse submitted request body");
        value
            .pointer("/signedRequest/body")
            .cloned()
            .unwrap_or(value)
    }

    fn metadata_snapshot_bytes(snapshot: &serde_json::Value, field: &str) -> Vec<u8> {
        use base64::Engine as _;
        let value = snapshot.get(field).expect("metadata snapshot field");
        let encoded = value
            .get("$bytes")
            .and_then(|bytes| bytes.as_str())
            .or_else(|| value.as_str())
            .expect("metadata snapshot bytes");
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid metadata snapshot base64")
    }

    #[cfg(feature = "fork-resolution")]
    #[tokio::test(flavor = "multi_thread")]
    async fn fork_readd_entry_refuses_reset_recorded_after_fork_projection() {
        let (world, conversation_id, group_id, source_epoch) =
            fork_readd_fixture("fork reset inter-call").await;
        let alice = world.client("Alice");
        let target = alice
            .orchestrator
            .create_group("fork reset target", None, None)
            .await
            .expect("materialize reset target");
        let target_epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&target.group_id).expect("target group id hex"))
            .expect("target epoch");
        let submissions_before = canonical_transition_submission_count(&world);

        assert!(
            alice
                .orchestrator
                .project_fork_detected_if_active(&conversation_id, source_epoch)
                .await
        );
        alice
            .orchestrator
            .record_group_reset_with_outcome(
                &conversation_id,
                hex::decode(&target.group_id).expect("target group id hex"),
                7,
            )
            .await
            .expect("record reset in the inter-call gap");

        assert!(
            alice
                .orchestrator
                .attempt_fork_readd(&conversation_id)
                .await
                .is_err(),
            "ResetPending must reject fork readd at entry"
        );
        assert_eq!(
            canonical_transition_submission_count(&world),
            submissions_before,
            "rejected fork readd must not submit a transition"
        );
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(hex::decode(&target.group_id).expect("target group id hex"))
                .expect("target remains materialized"),
            target_epoch,
            "rejected fork readd must not merge against the reset target"
        );
        let pending = alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .expect("reset remains durable");
        assert_eq!(pending.reset_generation, 7);
        assert_eq!(pending.new_group_id_hex, target.group_id);
        assert!(alice.storage.has_rejoin_flag(&conversation_id));
        let _ = group_id;
    }

    #[cfg(feature = "fork-resolution")]
    #[tokio::test(flavor = "multi_thread")]
    async fn fork_readd_entry_fails_closed_when_reset_authority_is_unreadable() {
        let (world, conversation_id, group_id, source_epoch) =
            fork_readd_fixture("fork reset unreadable").await;
        let alice = world.client("Alice");
        let submissions_before = canonical_transition_submission_count(&world);
        assert!(
            alice
                .orchestrator
                .project_fork_detected_if_active(&conversation_id, source_epoch)
                .await
        );
        alice
            .storage
            .fail_next_get_conversation_state_for(&conversation_id);

        assert!(
            alice
                .orchestrator
                .attempt_fork_readd(&conversation_id)
                .await
                .is_err(),
            "unreadable reset authority must reject fork readd"
        );
        assert_eq!(
            canonical_transition_submission_count(&world),
            submissions_before,
            "failed-closed authority read must not submit a transition"
        );
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(hex::decode(&group_id).expect("group id hex"))
                .expect("group epoch remains readable"),
            source_epoch,
            "failed-closed authority read must not merge a pending commit"
        );
    }

    #[cfg(feature = "fork-resolution")]
    #[tokio::test(flavor = "multi_thread")]
    async fn fork_readd_missing_group_projection_escalates_without_submitting() {
        let (world, conversation_id, _group_id, source_epoch) =
            fork_readd_fixture("fork missing projection").await;
        let alice = world.client("Alice");
        let submissions_before = canonical_transition_submission_count(&world);
        assert!(
            alice
                .orchestrator
                .project_fork_detected_if_active(&conversation_id, source_epoch)
                .await,
            "fixture must enter ForkDetected before attempting repair"
        );
        alice
            .orchestrator
            .group_states()
            .lock()
            .await
            .retain(|_, state| state.conversation_id != conversation_id);

        let result = alice
            .orchestrator
            .attempt_fork_readd(&conversation_id)
            .await;

        assert!(
            matches!(&result, Err(OrchestratorError::RecoveryFailed(message)) if message.contains("missing group state")),
            "missing durable-projection source must fail closed, got {result:?}"
        );
        assert_eq!(
            canonical_transition_submission_count(&world),
            submissions_before,
            "missing projection must be detected before server submission"
        );
        assert_eq!(
            alice
                .orchestrator
                .conversation_states()
                .lock()
                .await
                .get(&conversation_id),
            Some(&ConversationState::NeedsRejoin)
        );
        assert!(alice.storage.has_rejoin_flag(&conversation_id));
    }

    #[cfg(feature = "fork-resolution")]
    #[tokio::test(flavor = "multi_thread")]
    async fn fork_readd_group_state_write_failure_does_not_publish_success() {
        let (world, conversation_id, group_id, source_epoch) =
            fork_readd_fixture("fork durable projection failure").await;
        let alice = world.client("Alice");
        let submissions_before = canonical_transition_submission_count(&world);
        assert!(
            alice
                .orchestrator
                .project_fork_detected_if_active(&conversation_id, source_epoch)
                .await,
            "fixture must enter ForkDetected before attempting repair"
        );
        alice
            .orchestrator
            .decrypt_fail_counts()
            .lock()
            .await
            .insert(conversation_id.clone(), constants::FORK_DETECTION_THRESHOLD);

        let group_info_before = alice
            .orchestrator
            .api_client()
            .get_group_info(&conversation_id)
            .await
            .expect("fixture GroupInfo");
        let cleanup_calls_before = alice.storage.epoch_cleanup_calls();
        let durable_before = alice
            .storage
            .get_group_state(&group_id)
            .await
            .expect("read durable group state")
            .expect("durable group state exists");
        assert_eq!(durable_before.epoch, source_epoch);
        alice.storage.fail_next_set_group_state();

        let result = alice
            .orchestrator
            .attempt_fork_readd(&conversation_id)
            .await;

        assert!(
            matches!(&result, Err(OrchestratorError::Storage(message)) if message.contains("set_group_state")),
            "durable projection failure must abort fork readd, got {result:?}"
        );
        assert_eq!(
            canonical_transition_submission_count(&world),
            submissions_before + 1,
            "failure injection must occur after canonical server acceptance and local merge"
        );
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(hex::decode(&group_id).expect("group id hex"))
                .expect("merged crypto epoch remains readable"),
            source_epoch + 1,
            "regression must exercise failure after the local crypto merge"
        );
        let transition = world
            .delivery_service()
            .submitted_prepared_requests()
            .into_iter()
            .rfind(|request| {
                request.operation
                    == crate::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition
            })
            .expect("fork readd transition");
        let body = submitted_inner_body(&transition);
        let snapshot = body
            .get("metadataSnapshot")
            .expect("fork readd metadata snapshot");
        let nonce: [u8; 12] = metadata_snapshot_bytes(snapshot, "nonce")
            .try_into()
            .expect("canonical metadata nonce");
        let ciphertext = metadata_snapshot_bytes(snapshot, "ciphertext");
        let group_id_bytes = hex::decode(&group_id).expect("group id hex");
        let metadata_key: [u8; 32] = alice
            .orchestrator
            .mls_context()
            .export_metadata_key(group_id_bytes.clone(), source_epoch + 1)
            .expect("fork readd metadata key")
            .try_into()
            .expect("metadata key length");
        let metadata = crate::metadata::decrypt_metadata_snapshot(
            &metadata_key,
            &group_id_bytes,
            source_epoch + 1,
            snapshot
                .get("metadataVersion")
                .and_then(|value| value.as_u64())
                .expect("metadata version"),
            &nonce,
            &ciphertext,
        )
        .expect("fork readd metadata must decrypt canonically");
        assert_eq!(metadata.title, "fork durable projection failure");
        assert_eq!(
            alice
                .orchestrator
                .conversation_states()
                .lock()
                .await
                .get(&conversation_id),
            Some(&ConversationState::NeedsRejoin),
            "failed durability must escalate instead of publishing Active"
        );
        assert!(
            alice.storage.has_rejoin_flag(&conversation_id),
            "failed durability must leave a durable recovery trigger"
        );
        assert_eq!(
            alice
                .orchestrator
                .group_states()
                .lock()
                .await
                .get(&group_id)
                .expect("cached group state remains present")
                .epoch,
            source_epoch,
            "undurable merged epoch must not be published to the group-state cache"
        );
        assert_eq!(
            alice
                .storage
                .get_group_state(&group_id)
                .await
                .expect("read durable group state after failure")
                .expect("prior durable group state remains present")
                .epoch,
            source_epoch,
            "failed write must leave the prior durable projection intact"
        );
        assert_eq!(
            alice.storage.epoch_cleanup_calls(),
            cleanup_calls_before,
            "platform epoch cleanup must not run before group-state durability"
        );
        assert_eq!(
            alice
                .orchestrator
                .decrypt_fail_counts()
                .lock()
                .await
                .get(&conversation_id),
            Some(&constants::FORK_DETECTION_THRESHOLD),
            "durability failure must not clear decrypt-failure evidence"
        );
        assert!(
            !alice
                .orchestrator
                .fork_detection_states()
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains_key(&conversation_id),
            "NeedsRejoin escalation must retire the fork-readd attempt state"
        );
        assert_eq!(
            alice
                .orchestrator
                .api_client()
                .get_group_info(&conversation_id)
                .await
                .expect("GroupInfo remains readable"),
            group_info_before,
            "durability failure must not publish advanced GroupInfo"
        );
        assert!(
            !alice
                .orchestrator
                .clear_needs_rejoin_if_locally_healthy(&conversation_id)
                .await,
            "crypto membership must not clear recovery intent while durable GroupState is stale"
        );
        assert_eq!(
            alice
                .orchestrator
                .conversation_states()
                .lock()
                .await
                .get(&conversation_id),
            Some(&ConversationState::NeedsRejoin),
            "stale durable projection must remain NeedsRejoin"
        );
        assert!(
            alice.storage.has_rejoin_flag(&conversation_id),
            "stale durable projection must retain the durable recovery trigger"
        );
    }

    #[test]
    fn materialized_cleanup_propagates_first_delete_failure() {
        let groups = vec![vec![1], vec![2]];
        let mut attempted = Vec::new();
        let result = delete_materialized_force_rejoin_groups(groups, |group_id| {
            attempted.push(group_id.clone());
            Err(crate::MLSError::Internal(format!(
                "injected delete failure for {}",
                hex::encode(group_id)
            )))
        });

        assert!(
            result.is_err(),
            "known-present deletion failure must fail closed"
        );
        assert_eq!(
            attempted,
            vec![vec![1]],
            "cleanup must stop at first failure"
        );
    }

    #[test]
    fn materialized_cleanup_treats_missing_group_as_idempotent_and_continues() {
        let groups = vec![vec![1], vec![2]];
        let mut attempted = Vec::new();
        let result = delete_materialized_force_rejoin_groups(groups, |group_id| {
            attempted.push(group_id.clone());
            if group_id == vec![1] {
                Err(crate::MLSError::GroupNotFound {
                    message: "already removed".into(),
                })
            } else {
                Ok(())
            }
        });

        assert!(result.is_ok(), "already-absent cleanup is idempotent");
        assert_eq!(
            attempted,
            vec![vec![1], vec![2]],
            "cleanup must continue after an already-absent group"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn force_rejoin_group_state_write_failure_preserves_recovery_state() {
        let mut world = crate::recovery_e2e_harness::TestWorld::new();
        world.add_client("Alice").await;
        world.register_device("Alice").await.unwrap();

        let alice = world.client("Alice");
        let epoch_cleanup_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        alice
            .orchestrator
            .mls_context()
            .set_epoch_secret_storage(Box::new(DurableEpochSecretStorage {
                cleanup_calls: std::sync::Arc::clone(&epoch_cleanup_calls),
            }))
            .expect("install durable epoch-secret storage");
        let conversation = alice
            .orchestrator
            .create_group("durable rejoin projection", None, None)
            .await
            .expect("create group");
        let conversation_id = conversation.conversation_id.clone();
        let local_epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&conversation.group_id).expect("group id is hex"))
            .expect("local epoch");
        world
            .delivery_service()
            .set_conversation_epoch_for_test(&conversation_id, local_epoch);
        alice
            .storage
            .mark_needs_rejoin(&conversation_id)
            .await
            .expect("seed durable rejoin flag");
        alice.storage.fail_next_set_group_state();

        let result = alice.orchestrator.force_rejoin(&conversation_id).await;
        assert!(
            matches!(&result, Err(OrchestratorError::Storage(message)) if message.contains("set_group_state")),
            "durable group-state failure must abort force rejoin, got {result:?}"
        );
        let transition = world
            .delivery_service()
            .submitted_prepared_requests()
            .into_iter()
            .rfind(|request| {
                request.operation
                    == crate::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition
            })
            .expect("external commit transition");
        let body = submitted_inner_body(&transition);
        let snapshot = body
            .get("metadataSnapshot")
            .expect("external commit metadata snapshot");
        assert_eq!(
            metadata_snapshot_bytes(snapshot, "nonce").len(),
            12,
            "metadata nonce must be carried separately"
        );
        let ciphertext = metadata_snapshot_bytes(snapshot, "ciphertext");
        let expected_plaintext = crate::metadata::GroupMetadataV1 {
            version: 1,
            title: "durable rejoin projection".into(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        };
        assert_eq!(
            ciphertext.len(),
            serde_json::to_vec(&expected_plaintext)
                .expect("serialize expected metadata")
                .len()
                + 16,
            "external commit must preserve cached metadata and carry only ciphertext plus tag"
        );
        assert_eq!(
            snapshot
                .get("ciphertextSize")
                .and_then(|value| value.as_u64()),
            Some(ciphertext.len() as u64)
        );
        assert!(
            alice.storage.has_rejoin_flag(&conversation_id),
            "failed durable projection must not clear the recovery flag"
        );
        assert!(matches!(
            alice
                .storage
                .get_conversation_state(&conversation_id)
                .await
                .expect("read durable recovery state"),
            Some(ConversationState::NeedsRejoin)
        ));
        assert!(matches!(
            alice
                .orchestrator
                .conversation_states()
                .lock()
                .await
                .get(&conversation_id),
            Some(ConversationState::NeedsRejoin)
        ));
        assert!(
            !alice.orchestrator.mls_context().group_exists(
                hex::decode(&conversation.group_id).expect("conversation group id is hex")
            ),
            "an undurable merged group must not satisfy the next healthy-group probe"
        );
        assert!(
            alice
                .storage
                .get_conversation_messages(&conversation_id)
                .iter()
                .all(|message| !message.id.starts_with("hb-")),
            "history-boundary bookkeeping must not run after failed persistence"
        );
        assert!(
            alice
                .storage
                .get_sync_cursor(&alice.did)
                .await
                .expect("read sync cursor")
                .messages_cursor
                .is_none(),
            "cursor seeding must not run after failed persistence"
        );
        assert_eq!(
            epoch_cleanup_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "epoch-secret cleanup must not run before the group-state durability boundary"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn force_rejoin_rejects_wrong_callback_epoch_without_merging_candidate() {
        let mut world = crate::recovery_e2e_harness::TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let conversation = alice
            .orchestrator
            .create_group("external callback epoch fence", None, None)
            .await
            .expect("create group");
        let old_group_id = hex::decode(&conversation.group_id).expect("group id is hex");
        let local_epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(old_group_id.clone())
            .expect("local epoch");
        alice
            .storage
            .mark_needs_rejoin(&conversation.conversation_id)
            .await
            .expect("seed recovery state");
        world
            .delivery_service()
            .set_conversation_epoch_for_test(&conversation.conversation_id, local_epoch + 7);

        let error = alice
            .orchestrator
            .force_rejoin(&conversation.conversation_id)
            .await
            .expect_err("wrong DS callback epoch must not merge candidate");
        assert!(matches!(error, OrchestratorError::EpochMismatch { .. }));
        assert!(
            !alice.orchestrator.mls_context().group_exists(old_group_id),
            "the rejected external-join candidate must be discarded"
        );
        assert!(alice.storage.has_rejoin_flag(&conversation.conversation_id));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn force_rejoin_preserves_both_sync_cursor_fields_and_fetches_no_seed_envelope() {
        let mut world = crate::recovery_e2e_harness::TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let conversation = alice
            .orchestrator
            .create_group("cursor preservation", None, None)
            .await
            .expect("create group");
        let local_epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&conversation.group_id).expect("group id is hex"))
            .expect("local epoch");
        world
            .delivery_service()
            .set_conversation_epoch_for_test(&conversation.conversation_id, local_epoch);
        alice
            .storage
            .mark_needs_rejoin(&conversation.conversation_id)
            .await
            .expect("seed recovery state");
        let original_cursor = SyncCursor {
            conversations_cursor: Some("conversation-high-water".to_string()),
            messages_cursor: Some("message-high-water".to_string()),
        };
        alice
            .storage
            .set_sync_cursor(&alice.did, &original_cursor)
            .await
            .expect("seed cursor");
        let unexpected_fetch = world.delivery_service().pause_next_get_messages();
        let mut recovery = Box::pin(
            alice
                .orchestrator
                .force_rejoin(&conversation.conversation_id),
        );

        tokio::select! {
            result = &mut recovery => result.expect("force rejoin"),
            _ = unexpected_fetch.wait_until_reached() => {
                unexpected_fetch.release();
                panic!("recovery must not fetch and discard an envelope solely to seed a cursor");
            }
        }

        let persisted_cursor = alice
            .storage
            .get_sync_cursor(&alice.did)
            .await
            .expect("read cursor");
        assert_eq!(
            persisted_cursor.conversations_cursor, original_cursor.conversations_cursor,
            "recovery must preserve the independent conversation cursor"
        );
        assert_eq!(
            persisted_cursor.messages_cursor, original_cursor.messages_cursor,
            "recovery must preserve the message cursor"
        );
    }

    #[test]
    fn reset_predecessor_cleanup_propagates_delete_failure_and_stops() {
        let groups = vec![vec![1], vec![2]];
        let mut attempted = Vec::new();
        let result = delete_materialized_reset_predecessors(groups, |group_id| {
            attempted.push(group_id.clone());
            Err(crate::MLSError::Internal(
                "injected reset cleanup failure".into(),
            ))
        });
        assert!(result.is_err());
        assert_eq!(attempted, vec![vec![1]]);
    }

    #[test]
    fn clear_records_success_time_so_cooldown_applies() {
        let mut t = RecoveryTracker::new(3);
        // No prior success → no cooldown
        assert!(t.success_cooldown_remaining("convo-a").is_none());

        t.clear("convo-a");

        // Just-cleared → cooldown active, within configured window
        let remaining = t
            .success_cooldown_remaining("convo-a")
            .expect("cooldown should be active immediately after clear");
        assert!(
            remaining <= constants::SUCCESSFUL_REJOIN_COOLDOWN,
            "remaining ({remaining:?}) must not exceed configured cooldown"
        );
    }

    #[test]
    fn success_cooldown_is_per_convo() {
        let mut t = RecoveryTracker::new(3);
        t.clear("convo-a");
        // Different convo — no cooldown
        assert!(t.success_cooldown_remaining("convo-b").is_none());
        // Same convo — cooldown active
        assert!(t.success_cooldown_remaining("convo-a").is_some());
    }

    #[test]
    fn wrong_epoch_error_classified_correctly() {
        use crate::MLSError;
        let we = MLSError::OpenMLS("unprotect_message failed: ValidationError(WrongEpoch)".into());
        assert!(
            we.is_wrong_epoch(),
            "ValidationError(WrongEpoch) must classify"
        );

        let other = MLSError::OpenMLS("some other openmls error".into());
        assert!(
            !other.is_wrong_epoch(),
            "non-WrongEpoch OpenMLS must not classify"
        );

        let decrypt = MLSError::DecryptionFailed;
        assert!(
            !decrypt.is_wrong_epoch(),
            "non-OpenMLS variants must not classify"
        );
    }

    #[test]
    fn clear_also_updates_global_interval_and_removes_failures() {
        let mut t = RecoveryTracker::new(3);
        t.record_failure("convo-a");
        assert_eq!(
            t.failed_rejoins.get("convo-a").map(|e| e.count),
            Some(1),
            "record_failure should insert failure count"
        );

        t.clear("convo-a");
        assert!(
            t.failed_rejoins.get("convo-a").is_none(),
            "clear must remove failure tracking for the convo"
        );
        assert!(
            t.last_global_rejoin_at.is_some(),
            "clear must bump last_global_rejoin_at so MIN_REJOIN_INTERVAL applies"
        );
    }

    // ----- Layer 3 quarantine classifier tests -----

    #[test]
    fn quarantine_two_hits_from_one_peer_does_not_trigger() {
        let mut t = RecoveryTracker::new(3);
        let peer = Some("did:plc:abc".to_string());
        let r1 = t.record_peer_bad_commit("convo", "m1", peer.clone());
        let r2 = t.record_peer_bad_commit("convo", "m2", peer);
        assert!(r1.is_none(), "single hit should not trigger");
        assert!(r2.is_none(), "two hits should not trigger");
        assert!(!t.is_quarantined("convo"));
    }

    #[test]
    fn quarantine_three_hits_from_one_peer_triggers_peer_bad() {
        let mut t = RecoveryTracker::new(3);
        let peer = Some("did:plc:abc".to_string());
        let _ = t.record_peer_bad_commit("convo", "m1", peer.clone());
        let _ = t.record_peer_bad_commit("convo", "m2", peer.clone());
        let r3 = t.record_peer_bad_commit("convo", "m3", peer);
        assert!(
            matches!(
                r3,
                Some(crate::orchestrator::types::QuarantineReason::PeerBadCommit)
            ),
            "three hits from one peer must trigger PeerBadCommit, got {:?}",
            r3
        );
    }

    #[test]
    fn quarantine_two_distinct_peers_triggers_multi_peer() {
        let mut t = RecoveryTracker::new(3);
        let r1 = t.record_peer_bad_commit("convo", "m1", Some("did:plc:alpha".to_string()));
        assert!(r1.is_none());
        let r2 = t.record_peer_bad_commit("convo", "m2", Some("did:plc:beta".to_string()));
        assert!(
            matches!(
                r2,
                Some(crate::orchestrator::types::QuarantineReason::MultiPeerBadCommits)
            ),
            "two distinct peers within window must trigger MultiPeerBadCommits, got {:?}",
            r2
        );
    }

    #[test]
    fn quarantine_three_distinct_msgs_no_sender_triggers_framing() {
        let mut t = RecoveryTracker::new(3);
        let r1 = t.record_peer_bad_commit("convo", "m1", None);
        let r2 = t.record_peer_bad_commit("convo", "m2", None);
        let r3 = t.record_peer_bad_commit("convo", "m3", None);
        assert!(r1.is_none());
        assert!(r2.is_none());
        assert!(
            matches!(
                r3,
                Some(crate::orchestrator::types::QuarantineReason::RepeatedFramingFailures)
            ),
            "three distinct messages without sender attribution must trigger framing, got {:?}",
            r3
        );
    }

    #[test]
    fn healthy_peer_commit_clears_buffer_and_quarantine() {
        let mut t = RecoveryTracker::new(3);
        let peer = Some("did:plc:abc".to_string());
        let _ = t.record_peer_bad_commit("convo", "m1", peer.clone());
        let _ = t.record_peer_bad_commit("convo", "m2", peer.clone());
        let r = t.record_peer_bad_commit("convo", "m3", peer);
        assert!(r.is_some());
        t.mark_quarantined(
            "convo",
            crate::orchestrator::types::QuarantineReason::PeerBadCommit,
            0,
            vec!["did:plc:abc".to_string()],
        );
        assert!(t.is_quarantined("convo"));
        t.record_healthy_peer_commit("convo");
        let cleared = t.clear_quarantine("convo");
        assert!(cleared);
        assert!(!t.is_quarantined("convo"));
    }

    #[test]
    fn quarantine_blocks_should_skip() {
        let mut t = RecoveryTracker::new(3);
        assert!(!t.should_skip("convo"));
        t.mark_quarantined(
            "convo",
            crate::orchestrator::types::QuarantineReason::PeerBadCommit,
            0,
            vec![],
        );
        assert!(t.should_skip("convo"));
    }

    #[test]
    fn record_peer_bad_no_op_when_already_quarantined() {
        let mut t = RecoveryTracker::new(3);
        t.mark_quarantined(
            "convo",
            crate::orchestrator::types::QuarantineReason::PeerBadCommit,
            0,
            vec![],
        );
        let r = t.record_peer_bad_commit("convo", "m", Some("did:plc:x".to_string()));
        assert!(r.is_none());
    }

    #[test]
    fn quarantine_state_persists_across_mark() {
        let mut t = RecoveryTracker::new(3);
        t.mark_quarantined(
            "convo",
            crate::orchestrator::types::QuarantineReason::MultiPeerBadCommits,
            123,
            vec!["did:plc:a".to_string(), "did:plc:b".to_string()],
        );
        let snap = t.quarantine_snapshot("convo").expect("snapshot");
        assert_eq!(
            snap.reason,
            crate::orchestrator::types::QuarantineReason::MultiPeerBadCommits
        );
        assert_eq!(snap.since_ms, 123);
        assert_eq!(snap.suspected_dids.len(), 2);
    }

    #[test]
    fn mark_quarantined_clears_failed_rejoins() {
        let mut t = RecoveryTracker::new(3);
        t.record_failure("convo");
        assert_eq!(t.failed_attempts("convo"), 1);
        t.mark_quarantined(
            "convo",
            crate::orchestrator::types::QuarantineReason::PeerBadCommit,
            0,
            vec!["did:plc:bad".into()],
        );
        assert_eq!(
            t.failed_attempts("convo"),
            0,
            "failed_rejoins must be cleared on quarantine"
        );
    }
}
