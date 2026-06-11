use std::collections::HashMap;
use std::time::Duration;
use web_time::Instant;

use base64::Engine;

use super::api_client::MLSAPIClient;
use super::constants;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;
use super::welcome_recovery::{
    classify_server_error, classify_welcome_processing_error, decide_welcome_recovery,
    LastRecoveryError, WelcomeRecoveryDecision, WelcomeRecoveryInput,
};

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
        }
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
        let gid =
            hex::decode(convo_id).map_err(|_| OrchestratorError::InvalidInput("bad hex".into()))?;
        let mems: Vec<String> = {
            let st = self.group_states().lock().await;
            st.get(convo_id)
                .map(|g| g.members.clone())
                .unwrap_or_default()
        };
        if mems.is_empty() {
            self.escalate_fork_to_rejoin(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed("no members".into()));
        }
        let kp_refs = match self.api_client().get_key_packages(&mems).await {
            Ok(r) => r,
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
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
        let tag = self
            .mls_context()
            .get_confirmation_tag(gid.clone())
            .map(|t| base64::engine::general_purpose::STANDARD.encode(&t))
            .ok();
        if let Err(e) = self
            .api_client()
            .commit_group_change(convo_id, &commit, "forkReadd", tag.as_deref())
            .await
        {
            let _ = self.mls_context().clear_pending_commit(gid);
            self.escalate_fork_to_rejoin(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
        }
        match self.mls_context().merge_pending_commit(gid.clone()) {
            Ok(ep) => {
                // Cleanup old epoch secrets after fork readd
                self.cleanup_epoch_secrets_if_needed(convo_id, ep).await;

                {
                    let mut st = self.group_states().lock().await;
                    if let Some(gs) = st.get_mut(convo_id) {
                        gs.epoch = ep;
                        let sc = gs.clone();
                        drop(st);
                        if let Err(e) = self.storage().set_group_state(&sc).await {
                            tracing::warn!(error = %e, convo_id, "Failed to persist group state after fork readd");
                        }
                    }
                }
                {
                    let mut fds = self
                        .fork_detection_states()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    fds.remove(convo_id);
                }
                self.decrypt_fail_counts().lock().await.remove(convo_id);
                self.conversation_states()
                    .lock()
                    .await
                    .insert(convo_id.to_string(), ConversationState::Active);
                if let Ok(gi) = self
                    .mls_context()
                    .export_group_info(gid, user_did.as_bytes().to_vec())
                {
                    let _ = self.api_client().publish_group_info(convo_id, &gi).await;
                }
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
        self.conversation_states()
            .lock()
            .await
            .insert(convo_id.to_string(), ConversationState::NeedsRejoin);
        self.mark_needs_rejoin_critical(convo_id).await;
        tracing::info!(convo_id, "Fork escalated to NeedsRejoin");
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

    async fn enforce_rejoin_backoff(&self, convo_id: &str) -> Result<()> {
        // E7 runtime expiry: a maxed-out lockout that lapsed while this
        // process was running re-opens exactly one attempt (clamp to
        // max-1), mirroring the hydration clamp and the Swift twin's
        // runtime quarantine removal. Update the persisted row to match so
        // a restart sees the same clamped state.
        let clamp = {
            let mut tracker = self.recovery_tracker().lock().await;
            tracker.expire_lapsed_lockout(convo_id)
        };
        if let Some((clamped_count, last_attempt_at_ms)) = clamp {
            tracing::info!(
                convo_id,
                clamped_count,
                "Maxed-out rejoin lockout lapsed at runtime — clamping below max (one fresh attempt re-opens)"
            );
            if clamped_count == 0 {
                if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
                    self.report_recovery_storage_failure(convo_id, "clear_recovery_backoff", &e)
                        .await;
                }
            } else {
                let entry = PersistedRecoveryBackoff {
                    conversation_id: convo_id.to_string(),
                    failed_rejoin_count: clamped_count,
                    last_attempt_at_ms,
                    quarantined_until_ms: None,
                };
                if let Err(e) = self.storage().set_recovery_backoff(&entry).await {
                    self.report_recovery_storage_failure(convo_id, "set_recovery_backoff", &e)
                        .await;
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
            let authenticator = self.epoch_authenticator_hex(convo_id);
            if let Err(e) = self
                .api_client()
                .report_recovery_failure(
                    convo_id,
                    "external_commit_exhausted",
                    authenticator.as_deref(),
                    Some("local_state_loss"),
                )
                .await
            {
                tracing::warn!(
                    convo_id,
                    error = %e,
                    "Failed to report recovery failure to server"
                );
            }
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

    /// `mark_needs_rejoin` with WS-5.2 escalation: the rejoin flag is what the
    /// deferred-recovery loop consumes, so a dropped write here silently
    /// cancels recovery.
    pub(crate) async fn mark_needs_rejoin_critical(&self, convo_id: &str) {
        if let Err(e) = self.storage().mark_needs_rejoin(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "mark_needs_rejoin", &e)
                .await;
        }
    }

    pub(crate) async fn clear_rejoin_failures(&self, convo_id: &str) {
        self.recovery_tracker().lock().await.clear(convo_id);
        // WS-5.4 write-through: successful rejoin clears the persisted entry;
        // `clear` arms the global gate, so persist that too.
        let now_ms = chrono::Utc::now().timestamp_millis();
        if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
            self.report_recovery_storage_failure(convo_id, "clear_recovery_backoff", &e)
                .await;
        }
        if let Err(e) = self
            .storage()
            .set_last_global_rejoin_attempt_at(now_ms)
            .await
        {
            self.report_recovery_storage_failure(convo_id, "set_last_global_rejoin_attempt_at", &e)
                .await;
        }
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

    async fn record_rejoin_failure(&self, convo_id: &str) {
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
        }
        if let Err(e) = self
            .storage()
            .set_last_global_rejoin_attempt_at(now_ms)
            .await
        {
            self.report_recovery_storage_failure(convo_id, "set_last_global_rejoin_attempt_at", &e)
                .await;
        }
    }

    async fn route_welcome_recovery_decision(
        &self,
        convo_id: &str,
        user_did: &str,
        last_error: LastRecoveryError,
    ) -> Result<bool> {
        let attempts = self
            .storage()
            .get_welcome_reissue_attempt_log(convo_id)
            .await?;

        let has_groupinfo = self.api_client().get_group_info(convo_id).await.is_ok();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let decision = decide_welcome_recovery(WelcomeRecoveryInput {
            attempts,
            last_error,
            has_groupinfo,
            last_seen_epoch: self.local_group_epoch(convo_id).await.unwrap_or(0),
            now_ms,
        });

        match decision {
            WelcomeRecoveryDecision::RequestReissue {
                reason,
                retry_after,
            } => {
                if !retry_after.is_zero() {
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "Welcome reissue suppressed for {convo_id}: retry after {}s",
                        retry_after.as_secs()
                    )));
                }

                let recipient_device_did = self
                    .credentials()
                    .get_mls_did(user_did)
                    .await?
                    .unwrap_or_else(|| user_did.to_string());
                self.api_client()
                    .request_welcome_reissue(convo_id, &recipient_device_did, &reason)
                    .await?;
                self.storage()
                    .record_welcome_reissue_attempt(convo_id, now_ms)
                    .await?;
                self.storage().mark_needs_rejoin(convo_id).await?;
                Err(OrchestratorError::RecoveryFailed(format!(
                    "Welcome reissue requested for {convo_id}"
                )))
            }
            WelcomeRecoveryDecision::ExternalCommitWithHistoryGap { last_seen_epoch } => {
                tracing::warn!(
                    convo_id,
                    last_seen_epoch,
                    "Welcome recovery exhausted reissue path; authorizing External Commit with history gap"
                );
                Ok(true)
            }
            WelcomeRecoveryDecision::Surrender {
                reason,
                retry_after,
            } => {
                self.conversation_states()
                    .lock()
                    .await
                    .insert(convo_id.to_string(), ConversationState::Failed);
                if let Err(e) = self
                    .storage()
                    .set_conversation_state(convo_id, ConversationState::Failed)
                    .await
                {
                    tracing::warn!(error = %e, convo_id, "Failed to persist Failed state after Welcome recovery surrender");
                }
                Err(OrchestratorError::RecoveryFailed(match retry_after {
                    Some(delay) => format!(
                        "Welcome recovery surrendered for {convo_id}: {reason}; retry after {}s",
                        delay.as_secs()
                    ),
                    None => format!("Welcome recovery surrendered for {convo_id}: {reason}"),
                }))
            }
            WelcomeRecoveryDecision::Accept { .. } => Ok(false),
        }
    }

    fn cached_group_id_hex_for_conversation(&self, convo_id: &str) -> Option<String> {
        let states = self.group_states().try_lock().ok()?;
        states
            .get(convo_id)
            .map(|gs| gs.group_id.clone())
            .or_else(|| {
                states
                    .values()
                    .find(|gs| gs.conversation_id == convo_id)
                    .map(|gs| gs.group_id.clone())
            })
    }

    pub(crate) async fn group_id_hex_for_conversation(&self, convo_id: &str) -> Option<String> {
        {
            let states = self.group_states().lock().await;
            if let Some(group_id) = states.get(convo_id).map(|gs| gs.group_id.clone()) {
                return Some(group_id);
            }
            if let Some(group_id) = states
                .values()
                .find(|gs| gs.conversation_id == convo_id)
                .map(|gs| gs.group_id.clone())
            {
                return Some(group_id);
            }
        }

        {
            let conversations = self.conversations().lock().await;
            if let Some(group_id) = conversations.get(convo_id).map(|c| c.group_id.clone()) {
                return Some(group_id);
            }
            if let Some(group_id) = conversations
                .values()
                .find(|c| c.conversation_id == convo_id)
                .map(|c| c.group_id.clone())
            {
                return Some(group_id);
            }
        }

        if let Ok(user_did) = self.require_user_did().await {
            if let Ok(Some(convo)) = self.storage().get_conversation(&user_did, convo_id).await {
                return Some(convo.group_id);
            }
        }

        if hex::decode(convo_id).is_ok() {
            Some(convo_id.to_string())
        } else {
            None
        }
    }

    pub(crate) async fn group_id_bytes_for_conversation(&self, convo_id: &str) -> Option<Vec<u8>> {
        let group_id_hex = self.group_id_hex_for_conversation(convo_id).await?;
        hex::decode(group_id_hex).ok()
    }

    async fn local_group_epoch(&self, convo_id: &str) -> Option<u64> {
        let group_id_bytes = self.group_id_bytes_for_conversation(convo_id).await?;
        self.mls_context().get_epoch(group_id_bytes).ok()
    }

    /// Best-effort helper that returns the hex-encoded epoch_authenticator for
    /// the group currently bound to `convo_id`.
    ///
    /// Walks the orchestrator's `group_states` cache first so that post-reset
    /// conversations (where `convo_id != group_id_hex`) resolve correctly;
    /// falls back to `hex::decode(convo_id)` for never-reset groups.
    /// Returns `None` if the context can't produce an authenticator (platform
    /// default stub, missing group, or remote-data error) so the caller can
    /// pass the original pre-A7 `None` payload.
    pub(crate) fn epoch_authenticator_hex(&self, convo_id: &str) -> Option<String> {
        let group_id_bytes = self
            .cached_group_id_hex_for_conversation(convo_id)
            .and_then(|group_id| hex::decode(group_id).ok())
            .or_else(|| hex::decode(convo_id).ok())?;

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

        // GroupInfo fetched successfully — now delete old local group state.
        // Prefer the currently-bound group id from `group_states` so that
        // post-reset conversations (convo_id != group_id_hex) delete the
        // *old* local group rather than whatever hex::decode(convo_id)
        // happens to produce. Fall back to the convo_id bytes for never-
        // reset groups where the two are identical.
        let old_group_id_bytes = self.group_id_bytes_for_conversation(convo_id).await;
        if let Some(bytes) = old_group_id_bytes {
            let _ = self.mls_context().delete_group(bytes);
        }

        // Create External Commit
        let identity_bytes = user_did.as_bytes().to_vec();
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
                    let authenticator = self.epoch_authenticator_hex(convo_id);
                    if let Err(report_err) = self
                        .api_client()
                        .report_recovery_failure(
                            convo_id,
                            "remote_data_error",
                            authenticator.as_deref(),
                            Some("group_state_unrecoverable"),
                        )
                        .await
                    {
                        tracing::warn!(
                            convo_id,
                            error = %report_err,
                            "Failed to report remote data recovery failure"
                        );
                    }
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
        {
            use sha2::{Digest, Sha256};
            self.evict_stale_commits().await;
            let commit_hash = Sha256::digest(&ext_commit_result.commit_data).to_vec();
            self.own_commits()
                .lock()
                .await
                .insert(commit_hash, Instant::now());
        }

        // Get confirmation tag from the new local group state
        let tag_b64 = self
            .mls_context()
            .get_confirmation_tag(ext_commit_result.group_id.clone())
            .map(|tag| base64::engine::general_purpose::STANDARD.encode(&tag))
            .ok();

        // Send commit to server via the processExternalCommit endpoint
        // (NOT sendMessage — that endpoint validates padding/epoch/membership which don't apply)
        let ext_commit_server_result = match self
            .api_client()
            .process_external_commit(
                convo_id,
                &ext_commit_result.commit_data,
                ext_commit_result.group_info.as_deref(),
                tag_b64.as_deref(),
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                // Discard the pending external join on failure
                let _ = self
                    .mls_context()
                    .discard_pending_external_join(ext_commit_result.group_id.clone());
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Failed to send external commit: {e}"
                )));
            }
        };

        // Best-effort receipt storage
        if let Some(ref receipt) = ext_commit_server_result.receipt {
            if let Err(e) = self.storage().store_sequencer_receipt(receipt).await {
                tracing::warn!(error = %e, convo_id, "Failed to store sequencer receipt");
            }
        }

        // Merge the external join locally
        let merged = self
            .mls_context()
            .merge_pending_commit(ext_commit_result.group_id.clone())
            .map_err(|e| {
                OrchestratorError::RecoveryFailed(format!("Failed to merge external commit: {e}"))
            })?;

        // Cleanup old epoch secrets after External Commit rejoin
        self.cleanup_epoch_secrets_if_needed(convo_id, merged).await;

        // Update group state (insert if missing, persist to storage)
        let new_group_id_hex = hex::encode(&ext_commit_result.group_id);
        {
            let mut states = self.group_states().lock().await;
            let state = states
                .entry(convo_id.to_string())
                .or_insert_with(|| GroupState {
                    group_id: new_group_id_hex.clone(),
                    conversation_id: convo_id.to_string(),
                    epoch: 0,
                    members: vec![],
                });
            state.group_id = new_group_id_hex;
            state.epoch = merged;
            let state_clone = state.clone();
            drop(states);
            if let Err(e) = self.storage().set_group_state(&state_clone).await {
                tracing::warn!(error = %e, convo_id, "Failed to persist group state after force rejoin");
            }
        }

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

        // Seed lastSyncedSeq: fetch the latest message to get the current
        // server sequence number so the next sync cycle doesn't re-process
        // the entire backlog (spec: seed cursor after External Commit rejoin).
        match self
            .api_client()
            .get_messages(convo_id, None, 1, None, None, None)
            .await
        {
            Ok((_msgs, new_cursor)) => {
                if let Some(cursor_val) = new_cursor {
                    let user_did_for_cursor = user_did.to_string();
                    let sync_cursor = SyncCursor {
                        conversations_cursor: None,
                        messages_cursor: Some(cursor_val.clone()),
                    };
                    if let Err(e) = self
                        .storage()
                        .set_sync_cursor(&user_did_for_cursor, &sync_cursor)
                        .await
                    {
                        tracing::warn!(
                            error = %e,
                            convo_id,
                            "Failed to seed sync cursor after rejoin"
                        );
                    } else {
                        tracing::info!(
                            convo_id,
                            cursor = %cursor_val,
                            "Seeded sync cursor after External Commit rejoin"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    convo_id,
                    "Failed to fetch latest seq for sync cursor seeding"
                );
            }
        }

        // Publish updated GroupInfo
        let group_info = self
            .mls_context()
            .export_group_info(ext_commit_result.group_id, user_did.as_bytes().to_vec())?;
        if let Err(e) = self
            .api_client()
            .publish_group_info(convo_id, &group_info)
            .await
        {
            tracing::warn!(error = %e, convo_id, "Failed to publish GroupInfo (external joins may fail)");
        }

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
        let authenticator = self.epoch_authenticator_hex(convo_id);
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
        if let Err(e) = self
            .api_client()
            .report_recovery_failure(convo_id, reason, authenticator.as_deref(), failure_mode)
            .await
        {
            tracing::warn!(
                convo_id,
                error = %e,
                "report_unrecoverable_local: API call failed (best-effort, swallowed)",
            );
        }
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
        let rejoin_lock = self.rejoin_lock(convo_id).await;
        let _rejoin_guard = match rejoin_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::info!(convo_id, "Force rejoin already in-flight, waiting");
                let _wait_guard = rejoin_lock.lock().await;
                return if self.local_group_epoch(convo_id).await.is_some() {
                    Ok(())
                } else {
                    Err(OrchestratorError::RecoveryFailed(format!(
                        "Concurrent force rejoin did not restore group {convo_id}"
                    )))
                };
            }
        };

        self.enforce_rejoin_backoff(convo_id).await?;

        let result = self.force_rejoin_unlocked(convo_id, &user_did).await;
        match result {
            Ok(()) => {
                self.clear_rejoin_failures(convo_id).await;
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
                self.record_rejoin_failure(convo_id).await;
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
                return self.local_group_epoch(convo_id).await.ok_or_else(|| {
                    OrchestratorError::RecoveryFailed(format!(
                        "Concurrent join/rejoin did not restore group {convo_id}"
                    ))
                });
            }
        };

        // Welcome should be tried unconditionally — backoff only applies to
        // External Commit fallback (spec: Welcome is the preferred join path).
        tracing::info!(
            convo_id,
            "Attempting to join group (Welcome first, External Commit fallback)"
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

                let identity_bytes = user_did.as_bytes().to_vec();
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
                        let epoch = self
                            .mls_context()
                            .get_epoch(result.group_id.clone())
                            .unwrap_or(0);

                        // Update group state
                        let welcome_group_id_hex = hex::encode(&result.group_id);
                        {
                            let mut states = self.group_states().lock().await;
                            let state =
                                states
                                    .entry(convo_id.to_string())
                                    .or_insert_with(|| GroupState {
                                        group_id: welcome_group_id_hex.clone(),
                                        conversation_id: convo_id.to_string(),
                                        epoch: 0,
                                        members: vec![],
                                    });
                            state.group_id = welcome_group_id_hex;
                            state.epoch = epoch;
                            let state_clone = state.clone();
                            drop(states);
                            if let Err(e) = self.storage().set_group_state(&state_clone).await {
                                tracing::warn!(error = %e, convo_id, "Failed to persist group state after Welcome join");
                            }
                        }

                        // Clear rejoin flag
                        if let Err(e) = self.storage().clear_rejoin_flag(convo_id).await {
                            tracing::warn!(error = %e, convo_id, "Failed to clear rejoin flag after Welcome join");
                        }
                        self.clear_rejoin_failures(convo_id).await;

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
                        return Ok(epoch);
                    }
                    Err(err) => {
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
                    true
                } else {
                    tracing::warn!(convo_id, error = %e, "Welcome fetch failed with non-404/410 error; skipping bootstrap, falling back to External Commit");
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
            if let Some(payload) = self.reset_pending_payload(convo_id).await {
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
                        self.clear_rejoin_failures(convo_id).await;
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
                    Err(boot_err) => {
                        // Other bootstrap error (network, auth, malformed
                        // GroupInfo export, etc.). Local pre-bootstrap group
                        // was already dropped inside try_first_responder_bootstrap.
                        // Fall through to External Commit so we still get a
                        // chance to recover via the legacy path.
                        tracing::warn!(
                            convo_id,
                            bootstrap_error = %boot_err,
                            "first-responder bootstrap failed (non-409); falling back to External Commit"
                        );
                    }
                }
            }
        }

        // Step 3: External Commit fallback (gated by enforce_rejoin_backoff).
        //
        // Bootstrap was tried above when applicable; this path is for:
        //   - never-joined convos (state != ResetPending)
        //   - convos where bootstrap failed for a non-409 reason
        //   - convos where Welcome failed with a non-404/410 error and we
        //     skipped bootstrap defensively
        if let Some(last_error) = welcome_recovery_error {
            let allow_external_commit = self
                .route_welcome_recovery_decision(convo_id, &user_did, last_error)
                .await?;
            if !allow_external_commit {
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Welcome recovery did not authorize External Commit for {convo_id}"
                )));
            }
        }
        self.enforce_rejoin_backoff(convo_id).await?;
        let rejoin_result = self.force_rejoin_unlocked(convo_id, &user_did).await;
        match rejoin_result {
            Ok(()) => {
                self.clear_rejoin_failures(convo_id).await;
                Ok(self.local_group_epoch(convo_id).await.unwrap_or(0))
            }
            Err(err) => {
                self.record_rejoin_failure(convo_id).await;
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
        if let Ok(devices) = self.api_client().list_devices().await {
            let device_uuid = self
                .credentials()
                .get_device_uuid(&user_did)
                .await?
                .unwrap_or_default();

            for device in &devices {
                if device.device_uuid == device_uuid {
                    let _ = self.api_client().remove_device(&device.device_id).await;
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
        self.check_shutdown().await?;
        let new_group_id_hex = hex::encode(&new_group_id);
        tracing::info!(
            convo_id,
            new_group_id = %new_group_id_hex,
            reset_generation,
            "Recording server-initiated GroupReset (deferred adoption)"
        );
        self.persist_reset_pending_state(convo_id, &new_group_id_hex, reset_generation)
            .await
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
        self.check_shutdown().await?;

        // Idempotency check: if we're already in ResetPending at this
        // generation, drop the duplicate.
        if let Some(existing) = self.reset_pending_payload(convo_id).await {
            if existing.reset_generation == reset_generation {
                tracing::info!(
                    convo_id,
                    crypto_session_id,
                    reset_generation,
                    trigger,
                    request_event_id,
                    existing_new_group_id = %existing.new_group_id,
                    "resetRequestedEvent: already in ResetPending at this generation, idempotent no-op"
                );
                return Ok(());
            }
            // Different generation arriving — fall through and overwrite.
            // Higher generation supersedes; lower would be a stale replay but
            // we still re-persist (the server is authoritative).
            tracing::info!(
                convo_id,
                crypto_session_id,
                old_reset_generation = existing.reset_generation,
                new_reset_generation = reset_generation,
                trigger,
                request_event_id,
                "resetRequestedEvent: superseding existing ResetPending at different generation"
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

        self.persist_reset_pending_state(convo_id, &new_group_id_hex, reset_generation)
            .await
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
        new_group_id_hex: &str,
        reset_generation: i32,
    ) -> Result<()> {
        let notified_at_ms = chrono::Utc::now().timestamp_millis();

        // 1. Transition to ResetPending + persist the payload.
        {
            let mut states = self.conversation_states().lock().await;
            states.insert(
                convo_id.to_string(),
                ConversationState::ResetPending {
                    new_group_id: new_group_id_hex.to_string(),
                    reset_generation,
                    notified_at_ms,
                },
            );
        }
        if let Err(e) = self
            .storage()
            .set_conversation_state(
                convo_id,
                ConversationState::ResetPending {
                    new_group_id: new_group_id_hex.to_string(),
                    reset_generation,
                    notified_at_ms,
                },
            )
            .await
        {
            // WS-5.2: the persisted ResetPending payload is the sole
            // cross-restart carrier of the first-responder bootstrap gate —
            // a dropped write here silently cancels Phase 1 recovery after
            // restart. Escalate like the matching `clear_reset_pending`.
            self.report_recovery_storage_failure(
                convo_id,
                "set_conversation_state:reset_pending",
                &e,
            )
            .await;
        }
        if let Err(e) = self
            .storage()
            .mark_reset_pending(convo_id, new_group_id_hex, reset_generation, notified_at_ms)
            .await
        {
            self.report_recovery_storage_failure(convo_id, "mark_reset_pending", &e)
                .await;
        }

        // 2. Delete the old local MLS group. Prefer group_states lookup; fall
        // back to hex::decode(convo_id) for never-reset groups.
        let old_group_id_bytes = self.group_id_bytes_for_conversation(convo_id).await;
        if let Some(bytes) = old_group_id_bytes {
            if let Err(e) = self.mls_context().delete_group(bytes) {
                // Non-fatal: the group may already be gone if a previous reset
                // attempt partially completed.
                tracing::warn!(
                    convo_id,
                    error = %e,
                    "delete_group for pre-reset group failed (non-fatal)"
                );
            }
        }

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
        if was_quarantined {
            // Server reset trumps client-side quarantine; persist the cleared
            // quarantine row alongside the new ResetPending payload.
            if let Err(e) = self.storage().clear_quarantine(convo_id).await {
                tracing::warn!(convo_id, error = %e, "Failed to clear persisted quarantine on server reset");
            }
            tracing::info!(convo_id, "[QUARANTINE-CLEAR] via server reset");
        }
        self.groupinfo_404_tracker().lock().await.clear(convo_id);

        // 4. Update group_states to point at the new group id so that any
        // group-id-derived lookups (including the one inside
        // force_rejoin_unlocked) see the new target. Also flag `needs_rejoin`
        // so the deferred-recovery loop in `sync_with_server` picks the
        // conversation up on the next pass.
        {
            let mut states = self.group_states().lock().await;
            let entry = states
                .entry(convo_id.to_string())
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
        // WS-5.2: the needs_rejoin flag is what routes this conversation into
        // the deferred-recovery loop — escalate a dropped write.
        self.mark_needs_rejoin_critical(convo_id).await;

        Ok(())
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

    /// Snapshot of the `ResetPending` payload for a conversation, or `None`
    /// if the conversation is not in that state. Used by `join_or_rejoin`'s
    /// bootstrap gate.
    ///
    /// Reads the in-memory `conversation_states` map first, then falls back
    /// to storage. The fallback covers two production scenarios:
    ///
    /// 1. **Cold-start race.** `MLSOrchestrator::initialize` rehydrates
    ///    persisted state into the in-memory map at startup, but a
    ///    `groupResetEvent` arriving during that window can land in storage
    ///    before the in-memory map is rehydrated.
    /// 2. **Platform WS/SSE handlers that persist without updating the
    ///    in-memory map.** catmos's `websocket.rs` writes
    ///    `set_conversation_state(ResetPending{..})` + `mark_reset_pending`
    ///    on a `groupResetEvent` but cannot reach into the orchestrator's
    ///    `conversation_states` mutex (workspace-internal surface). Storage
    ///    fallback closes the gap without forcing every platform to migrate
    ///    to `record_group_reset` simultaneously.
    pub(crate) async fn reset_pending_payload(
        &self,
        convo_id: &str,
    ) -> Option<ResetPendingPayload> {
        {
            let states = self.conversation_states().lock().await;
            if let Some(ConversationState::ResetPending {
                new_group_id,
                reset_generation,
                notified_at_ms,
            }) = states.get(convo_id)
            {
                return Some(ResetPendingPayload {
                    new_group_id: new_group_id.clone(),
                    reset_generation: *reset_generation,
                    notified_at_ms: *notified_at_ms,
                });
            }
        }
        match self.storage().get_conversation_state(convo_id).await {
            Ok(Some(ConversationState::ResetPending {
                new_group_id,
                reset_generation,
                notified_at_ms,
            })) => Some(ResetPendingPayload {
                new_group_id,
                reset_generation,
                notified_at_ms,
            }),
            _ => None,
        }
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
        let identity_bytes = user_did.as_bytes().to_vec();
        let group_config = self.config().group_config.clone();
        let _creation_result = self.mls_context().create_group_with_id(
            identity_bytes.clone(),
            new_group_id_bytes.clone(),
            Some(group_config),
        )?;

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
                let _ = self.mls_context().delete_group(new_group_id_bytes);
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
            .api_client()
            .bootstrap_reset_group(
                convo_id,
                &payload.new_group_id,
                cipher_suite,
                &group_info,
                &roster,
                None, // welcome_message: race-winner publishes Welcomes via the standard add-members commit path; not bootstrapped inline
            )
            .await;

        match result {
            Ok(_create_result) => {
                tracing::info!(
                    convo_id,
                    new_group_id = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "first-responder bootstrap won — clearing reset_pending"
                );
                self.conversation_states()
                    .lock()
                    .await
                    .insert(convo_id.to_string(), ConversationState::Active);
                if let Err(e) = self
                    .storage()
                    .set_conversation_state(convo_id, ConversationState::Active)
                    .await
                {
                    tracing::warn!(error = %e, convo_id, "Failed to persist Active state after bootstrap win");
                }
                // A stale reset_pending row would re-trigger bootstrap on a
                // later restart — escalate a dropped clear.
                if let Err(e) = self.storage().clear_reset_pending(convo_id).await {
                    self.report_recovery_storage_failure(convo_id, "clear_reset_pending", &e)
                        .await;
                }
                if let Err(e) = self.storage().clear_rejoin_flag(convo_id).await {
                    tracing::warn!(error = %e, convo_id, "Failed to clear rejoin flag after bootstrap win");
                }
                let epoch = self
                    .mls_context()
                    .get_epoch(new_group_id_bytes)
                    .unwrap_or(0);
                Ok(epoch)
            }
            Err(err) if err.is_bootstrap_already_bootstrapped() => {
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
                    error = %err,
                    "first-responder bootstrap bootstrapResetGroup failed; dropping local group, will retry"
                );
                if let Err(e) = self.mls_context().delete_group(new_group_id_bytes) {
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
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .api_client()
                .get_conversations(50, cursor.as_deref())
                .await?;
            for cv in &page.conversations {
                if cv.conversation_id == convo_id {
                    return Ok(cv.members.iter().map(|m| m.did.clone()).collect());
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
        if err.is_wrong_epoch() {
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
        self.recovery_tracker()
            .lock()
            .await
            .quarantine_snapshot(convo_id)
    }

    /// Internal: mark a conversation quarantined and persist the transition.
    /// Emits the on_conversation_quarantined event when an event callback is
    /// installed.
    pub(crate) async fn enter_quarantine(
        &self,
        convo_id: &str,
        reason: crate::orchestrator::types::QuarantineReason,
    ) {
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
        {
            let mut states = self.conversation_states().lock().await;
            states.insert(
                convo_id.to_string(),
                ConversationState::Quarantined { reason, since_ms },
            );
        }
        // WS-5.2: quarantine state is recovery-critical — a dropped write
        // here means the quarantine silently does not survive restart and
        // the conversation re-enters the message flow until Layer 3 trips
        // again. Escalate like the backoff-row clear above.
        if let Err(e) = self
            .storage()
            .set_conversation_state(
                convo_id,
                ConversationState::Quarantined { reason, since_ms },
            )
            .await
        {
            self.report_recovery_storage_failure(
                convo_id,
                "set_conversation_state:quarantined",
                &e,
            )
            .await;
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
        self.notify_quarantined(convo_id, reason, suspected_dids)
            .await;
    }

    /// Internal: clear quarantine, transition to Active, persist, and emit event.
    pub(crate) async fn exit_quarantine(
        &self,
        convo_id: &str,
        via: crate::orchestrator::types::QuarantineExitReason,
    ) {
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
        ) {
            let mut states = self.conversation_states().lock().await;
            states.insert(convo_id.to_string(), ConversationState::Active);
            drop(states);
            // WS-5.2: a dropped write here leaves the persisted state
            // Quarantined, so restart rehydration re-quarantines a
            // conversation the user/peer already cleared. Escalate.
            if let Err(e) = self
                .storage()
                .set_conversation_state(convo_id, ConversationState::Active)
                .await
            {
                self.report_recovery_storage_failure(
                    convo_id,
                    "set_conversation_state:active_quarantine_exit",
                    &e,
                )
                .await;
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
        self.notify_quarantine_cleared(convo_id, via).await;
    }

    /// Public API: user-confirmed manual reset. Reports failure to the server
    /// (so the A7 reset pyramid counts the user vote) and clears local quarantine.
    pub async fn user_confirmed_manual_reset(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        // Report deliberate user vote so server quorum (spec section 8.6) can
        // include this client. Reason is logged in the structured tracing log.
        let auth = self.epoch_authenticator_hex(convo_id);
        if let Err(e) = self
            .api_client()
            .report_recovery_failure(
                convo_id,
                "user_initiated_quarantine",
                auth.as_deref(),
                Some("group_state_unrecoverable"),
            )
            .await
        {
            tracing::warn!(convo_id, error = %e, "user_confirmed_manual_reset: report_recovery_failure failed (best-effort)");
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            vec![],
        );
        assert_eq!(
            t.failed_attempts("convo"),
            0,
            "failed_rejoins must be cleared on quarantine"
        );
    }
}
