//! Native [`MLSStorageBackend`] implementation on [`MlsAccountDb`] (`Spec §6.1`).
//!
//! Executes all conversation projections, reset-pending CAS transitions,
//! message writes/reads, sync cursors, group state projections, sequencer
//! receipts, recovery rate-limiting state, and pending local-delete intents
//! inside [`MlsAccountDb`]'s single SQLCipher connection (`read_tx` / `write_tx`).

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::error::MLSError;
use crate::orchestrator::error::{OrchestratorError, Result as OrchResult};
use crate::orchestrator::storage::{MLSStorageBackend, OPTIONAL_STORAGE_METHODS};
use crate::orchestrator::types::*;
use crate::orchestrator::welcome_recovery::{ReissueAttempt, ReissueAttemptLog};

use super::driver_native::{map_rusqlite_err, MlsAccountDb, SqlReadTx};

const OP_RESET_PENDING: &str = "reset_pending";
const OP_RESET_HIGH_WATER: &str = "reset_high_water";
const OP_QUARANTINE: &str = "quarantine";
const OP_WELCOME_REISSUE: &str = "welcome_reissue";
const OP_PENDING_MESSAGE: &str = "pending_message";
const OP_PENDING_LOCAL_DELETE: &str = "pending_local_delete";
const GLOBAL_RECOVERY_SCOPE_KEY: &str = "__global__";
const CONVO_RECOVERY_PREFIX: &str = "convo:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedResetPendingPayload {
    new_group_id_hex: String,
    reset_generation: i32,
    notified_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedQuarantinePayload {
    reason_tag: String,
    since_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredConversationEnvelope {
    user_did: String,
    group_id_str: String,
    is_active: bool,
    state: ConversationState,
    needs_rejoin: bool,
    join_method: Option<JoinMethod>,
    join_epoch: Option<u64>,
    view: ConversationView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessageEnvelope {
    text: String,
    payload_json: Option<String>,
    delivery_status: Option<crate::orchestrator::types::DeliveryStatus>,
    timestamp_rfc3339: String,
}

fn mls_to_orch_err(err: MLSError) -> OrchestratorError {
    OrchestratorError::Storage(err.to_string())
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn encode_group_id_blob(group_id_str: &str) -> Vec<u8> {
    if !group_id_str.is_empty()
        && group_id_str.len().is_multiple_of(2)
        && group_id_str.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if let Ok(decoded) = hex::decode(group_id_str) {
            return decoded;
        }
    }
    group_id_str.as_bytes().to_vec()
}

fn state_tag_for(state: &ConversationState) -> &'static str {
    state.tag()
}

fn join_method_str(method: Option<JoinMethod>) -> &'static str {
    match method {
        Some(JoinMethod::Creator) | None => "created",
        Some(JoinMethod::Welcome) => "welcome",
        Some(JoinMethod::ExternalCommit) => "external_commit",
    }
}

fn parse_state_tag_fallback(tag: &str) -> ConversationState {
    match tag {
        "initializing" => ConversationState::Initializing,
        "active" => ConversationState::Active,
        "fork_detected" => ConversationState::ForkDetected,
        "needs_rejoin" => ConversationState::NeedsRejoin,
        "quarantined" => ConversationState::Quarantined {
            reason: crate::orchestrator::types::QuarantineReason::PeerBadCommit,
            since_ms: 0,
        },
        "device_removed" => ConversationState::DeviceRemoved,
        "closed" => ConversationState::Closed,
        "failed" => ConversationState::Failed,
        _ => ConversationState::Active,
    }
}

fn load_conversation_envelope(
    rx: &SqlReadTx<'_>,
    conversation_id: &str,
) -> Result<Option<StoredConversationEnvelope>, MLSError> {
    let row: Option<(
        Vec<u8>,
        i64,
        i64,
        String,
        i64,
        String,
        Option<String>,
        i64,
        String,
        Option<String>,
        Option<String>,
        i64,
    )> = rx
        .conn()
        .query_row(
            "SELECT group_id, generation, epoch, join_method, join_epoch, state_tag, state_json, \
                    needs_rejoin, sequencer_did, title, description, updated_at_ms \
             FROM conversations WHERE conversation_id = ?1",
            [conversation_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                ))
            },
        )
        .optional()
        .map_err(|e| map_rusqlite_err("load_conversation_envelope", &e))?;

    let Some((
        group_id_blob,
        _generation,
        epoch,
        join_method_col,
        join_epoch_col,
        state_tag,
        state_json,
        needs_rejoin_col,
        sequencer_did_col,
        title_col,
        description_col,
        updated_at_ms,
    )) = row
    else {
        return Ok(None);
    };

    if let Some(json) = state_json {
        if !json.is_empty() {
            let mut env: StoredConversationEnvelope = serde_json::from_str(&json).map_err(|e| {
                MLSError::invalid_input(format!("corrupt state_json for {conversation_id}: {e}"))
            })?;
            env.needs_rejoin = needs_rejoin_col != 0;
            return Ok(Some(env));
        }
    }

    let group_id_str = hex::encode(&group_id_blob);
    let updated_dt = Utc
        .timestamp_millis_opt(updated_at_ms)
        .single()
        .unwrap_or_else(Utc::now);
    let join_method = match join_method_col.as_str() {
        "welcome" => Some(JoinMethod::Welcome),
        "external_commit" => Some(JoinMethod::ExternalCommit),
        _ => Some(JoinMethod::Creator),
    };
    let metadata = if title_col.is_some() || description_col.is_some() {
        Some(ConversationMetadata {
            name: title_col,
            description: description_col,
            avatar_url: None,
        })
    } else {
        None
    };
    Ok(Some(StoredConversationEnvelope {
        user_did: String::new(),
        group_id_str: group_id_str.clone(),
        is_active: state_tag != "failed",
        state: parse_state_tag_fallback(&state_tag),
        needs_rejoin: needs_rejoin_col != 0,
        join_method,
        join_epoch: Some(join_epoch_col.max(0) as u64),
        view: ConversationView {
            group_id: group_id_str,
            conversation_id: conversation_id.to_string(),
            epoch: epoch.max(0) as u64,
            members: Vec::new(),
            metadata,
            created_at: Some(updated_dt),
            updated_at: Some(updated_dt),
            sequencer_did: (!sequencer_did_col.is_empty()).then_some(sequencer_did_col),
            canonical_state: None,
        },
    }))
}

fn load_all_conversation_envelopes(
    rx: &SqlReadTx<'_>,
) -> Result<Vec<(String, StoredConversationEnvelope)>, MLSError> {
    let mut stmt = rx
        .conn()
        .prepare(
            "SELECT conversation_id FROM conversations \
             ORDER BY updated_at_ms DESC, conversation_id ASC",
        )
        .map_err(|e| map_rusqlite_err("load_all_conversation_envelopes.prepare", &e))?;
    let ids: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .map_err(|e| map_rusqlite_err("load_all_conversation_envelopes.query", &e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| map_rusqlite_err("load_all_conversation_envelopes.collect", &e))?;

    let mut out = Vec::with_capacity(ids.len());
    for cid in ids {
        if let Some(env) = load_conversation_envelope(rx, &cid)? {
            out.push((cid, env));
        }
    }
    Ok(out)
}

fn save_conversation_envelope(
    conn: &rusqlite::Connection,
    conversation_id: &str,
    env: &StoredConversationEnvelope,
) -> Result<(), MLSError> {
    let state_json = serde_json::to_string(env)
        .map_err(|e| MLSError::invalid_input(format!("serialize state_json: {e}")))?;
    let group_id_blob = encode_group_id_blob(&env.group_id_str);
    let generation = env
        .view
        .canonical_state
        .as_ref()
        .map(|s| s.coordinates.generation)
        .unwrap_or(0);
    let epoch = env.view.epoch as i64;
    let join_method = join_method_str(env.join_method);
    let join_epoch = env.join_epoch.unwrap_or(0) as i64;
    let state_tag = state_tag_for(&env.state);
    let needs_rejoin = i64::from(env.needs_rejoin);
    let sequencer_did = env.view.sequencer_did.as_deref().unwrap_or("");
    let title = env.view.metadata.as_ref().and_then(|m| m.name.as_deref());
    let description = env
        .view
        .metadata
        .as_ref()
        .and_then(|m| m.description.as_deref());
    let updated_at_ms = env
        .view
        .updated_at
        .map(|dt| dt.timestamp_millis())
        .unwrap_or_else(now_ms);

    conn.execute(
        "INSERT INTO conversations (\
            conversation_id, group_id, generation, epoch, join_method, join_epoch, \
            state_tag, state_json, needs_rejoin, sequencer_did, title, description, updated_at_ms\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
         ON CONFLICT(conversation_id) DO UPDATE SET \
            group_id = excluded.group_id, \
            generation = excluded.generation, \
            epoch = excluded.epoch, \
            join_method = excluded.join_method, \
            join_epoch = excluded.join_epoch, \
            state_tag = excluded.state_tag, \
            state_json = excluded.state_json, \
            needs_rejoin = excluded.needs_rejoin, \
            sequencer_did = CASE WHEN excluded.sequencer_did != '' THEN excluded.sequencer_did ELSE conversations.sequencer_did END, \
            title = COALESCE(excluded.title, conversations.title), \
            description = COALESCE(excluded.description, conversations.description), \
            updated_at_ms = excluded.updated_at_ms",
        rusqlite::params![
            conversation_id,
            group_id_blob,
            generation,
            epoch,
            join_method,
            join_epoch,
            state_tag,
            state_json,
            needs_rejoin,
            sequencer_did,
            title,
            description,
            updated_at_ms,
        ],
    )
    .map_err(|e| map_rusqlite_err("save_conversation_envelope", &e))?;
    Ok(())
}

fn load_pending_op(
    conn: &rusqlite::Connection,
    op_kind: &str,
    op_key: &str,
) -> Result<Option<String>, MLSError> {
    conn.query_row(
        "SELECT payload_json FROM pending_ops WHERE op_kind = ?1 AND op_key = ?2",
        rusqlite::params![op_kind, op_key],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| map_rusqlite_err("load_pending_op", &e))
}

fn load_reset_pending(
    conn: &rusqlite::Connection,
    conversation_id: &str,
) -> Result<Option<PersistedResetPendingPayload>, MLSError> {
    let Some(raw) = load_pending_op(conn, OP_RESET_PENDING, conversation_id)? else {
        return Ok(None);
    };
    let parsed: PersistedResetPendingPayload = serde_json::from_str(&raw).map_err(|e| {
        MLSError::invalid_input(format!(
            "malformed persisted reset_pending payload for {conversation_id}: {e}"
        ))
    })?;
    Ok(Some(parsed))
}

fn load_reset_high_water(
    conn: &rusqlite::Connection,
    conversation_id: &str,
) -> Result<Option<i32>, MLSError> {
    let Some(raw) = load_pending_op(conn, OP_RESET_HIGH_WATER, conversation_id)? else {
        return Ok(None);
    };
    let parsed: i32 = serde_json::from_str(&raw).map_err(|e| {
        MLSError::invalid_input(format!(
            "malformed reset_high_water for {conversation_id}: {e}"
        ))
    })?;
    Ok(Some(parsed))
}

#[async_trait]
impl MLSStorageBackend for MlsAccountDb {
    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        OPTIONAL_STORAGE_METHODS
    }

    async fn commit_conversation_projection(
        &self,
        request: &ConversationProjectionCommitRequest,
    ) -> OrchResult<ConversationProjectionCommitOutcome> {
        use ConversationProjectionCommitOutcome as Outcome;

        let view = request.canonical.as_ref().ok_or_else(|| {
            OrchestratorError::Storage(
                "conversation projection commit requires canonical ConversationView".into(),
            )
        })?;
        if request.mode != ConversationProjectionCommitMode::Live
            || request.owner_user_did.is_empty()
        {
            return Err(OrchestratorError::Storage(
                "invalid conversation projection mode or empty owner DID".into(),
            ));
        }

        self.write_tx(|tx| {
            let existing = load_conversation_envelope(tx, &view.conversation_id)?;
            let reset_pending = load_reset_pending(tx.conn(), &view.conversation_id)?;

            if let Some(old) = &existing {
                let effective_state = if let Some(p) = &reset_pending {
                    ConversationState::ResetPending {
                        new_group_id: p.new_group_id_hex.clone(),
                        reset_generation: p.reset_generation,
                        notified_at_ms: p.notified_at_ms,
                    }
                } else {
                    old.state.clone()
                };

                let reset_authorized = match &effective_state {
                    ConversationState::ResetPending {
                        new_group_id,
                        reset_generation,
                        ..
                    } => {
                        request.canonical_lifecycle.reset_generation == Some(*reset_generation)
                            && request
                                .canonical_lifecycle
                                .reset_pending_target_group_id
                                .as_deref()
                                == Some(new_group_id.as_str())
                            && &view.group_id == new_group_id
                    }
                    _ => false,
                };

                if (!old.user_did.is_empty() && old.user_did != request.owner_user_did)
                    || matches!(
                        effective_state,
                        ConversationState::Closed | ConversationState::DeviceRemoved
                    )
                    || (matches!(effective_state, ConversationState::ResetPending { .. })
                        && !reset_authorized)
                {
                    return Ok(Outcome::FenceMismatch { affected_rows: 0 });
                }

                if let (Some(a), Some(b)) = (&old.view.canonical_state, &view.canonical_state) {
                    if (a.coordinates.generation, a.coordinates.state_version)
                        > (b.coordinates.generation, b.coordinates.state_version)
                    {
                        return Ok(Outcome::FenceMismatch { affected_rows: 0 });
                    }
                }
            }

            let mut loaded_aliases = Vec::with_capacity(request.aliases.len());
            for claim in &request.aliases {
                let Some(alias) = load_conversation_envelope(tx, &claim.alias_conversation_id)?
                else {
                    return Ok(Outcome::FenceMismatch { affected_rows: 0 });
                };
                let alias_reset = load_reset_pending(tx.conn(), &claim.alias_conversation_id)?;
                if alias_reset.is_some()
                    || matches!(
                        alias.state,
                        ConversationState::Closed
                            | ConversationState::DeviceRemoved
                            | ConversationState::ResetPending { .. }
                    )
                    || claim.alias_incarnation > claim.canonical_incarnation
                    || (!alias.user_did.is_empty() && alias.user_did != request.owner_user_did)
                    || claim.owner_user_did != request.owner_user_did
                    || alias.group_id_str != view.group_id
                    || claim.alias_group_id != view.group_id
                    || claim.alias_conversation_id != view.group_id
                    || claim.canonical_conversation_id != view.conversation_id
                    || claim.canonical_incarnation != view.epoch
                    || claim.alias_incarnation != alias.view.epoch
                {
                    return Ok(Outcome::FenceMismatch { affected_rows: 0 });
                }
                loaded_aliases.push((claim.alias_conversation_id.clone(), alias));
            }

            let all_rows = load_all_conversation_envelopes(tx)?;
            let ambiguous_ids: Vec<String> = all_rows
                .into_iter()
                .filter(|(cid, env)| {
                    env.is_active
                        && (env.user_did.is_empty() || env.user_did == request.owner_user_did)
                        && env.group_id_str == view.group_id
                        && cid != &view.conversation_id
                        && cid != &view.group_id
                })
                .map(|(cid, _)| cid)
                .collect();
            if !ambiguous_ids.is_empty() {
                return Ok(Outcome::Ambiguous {
                    canonical_ids: ambiguous_ids,
                    affected_rows: 0,
                });
            }

            let updated_env = if let Some(mut old) = existing {
                old.user_did = request.owner_user_did.clone();
                old.group_id_str = view.group_id.clone();
                old.view = view.clone();
                old.is_active = true;
                old
            } else {
                StoredConversationEnvelope {
                    user_did: request.owner_user_did.clone(),
                    group_id_str: view.group_id.clone(),
                    is_active: true,
                    state: ConversationState::Initializing,
                    needs_rejoin: false,
                    join_method: None,
                    join_epoch: None,
                    view: view.clone(),
                }
            };
            save_conversation_envelope(tx.conn(), &view.conversation_id, &updated_env)?;

            for (alias_id, mut alias_env) in loaded_aliases {
                alias_env.is_active = false;
                save_conversation_envelope(tx.conn(), &alias_id, &alias_env)?;
            }

            Ok(if request.aliases.is_empty() {
                Outcome::AlreadyAbsent { affected_rows: 1 }
            } else {
                Outcome::Retired {
                    affected_rows: request.aliases.len() as u32 + 1,
                }
            })
        })
        .map_err(mls_to_orch_err)
    }

    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            let env = if let Some(mut existing) = load_conversation_envelope(tx, conversation_id)? {
                existing.user_did = user_did.to_string();
                existing.group_id_str = group_id.to_string();
                existing.is_active = true;
                existing.view.group_id = group_id.to_string();
                existing
            } else {
                let now = Utc::now();
                StoredConversationEnvelope {
                    user_did: user_did.to_string(),
                    group_id_str: group_id.to_string(),
                    is_active: true,
                    state: ConversationState::Initializing,
                    needs_rejoin: false,
                    join_method: None,
                    join_epoch: None,
                    view: ConversationView {
                        group_id: group_id.to_string(),
                        conversation_id: conversation_id.to_string(),
                        epoch: 0,
                        members: Vec::new(),
                        metadata: None,
                        created_at: Some(now),
                        updated_at: Some(now),
                        sequencer_did: None,
                        canonical_state: None,
                    },
                }
            };
            save_conversation_envelope(tx.conn(), conversation_id, &env)
        })
        .map_err(mls_to_orch_err)
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        _user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> OrchResult<()> {
        let found = self
            .write_tx(|tx| {
                let Some(mut env) = load_conversation_envelope(tx, conversation_id)? else {
                    return Ok(false);
                };
                env.join_method = Some(join_method);
                env.join_epoch = Some(join_epoch);
                env.view.epoch = join_epoch;
                env.view.updated_at = Some(Utc::now());
                save_conversation_envelope(tx.conn(), conversation_id, &env)?;
                Ok(true)
            })
            .map_err(mls_to_orch_err)?;

        if !found {
            return Err(OrchestratorError::ConversationNotFound(
                conversation_id.to_string(),
            ));
        }
        Ok(())
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> OrchResult<Option<ConversationView>> {
        self.read_tx(|rx| {
            let Some(env) = load_conversation_envelope(rx, conversation_id)? else {
                return Ok(None);
            };
            if !env.is_active || (!env.user_did.is_empty() && env.user_did != user_did) {
                return Ok(None);
            }
            Ok(Some(env.view))
        })
        .map_err(mls_to_orch_err)
    }

    async fn list_conversations(&self, user_did: &str) -> OrchResult<Vec<ConversationView>> {
        self.read_tx(|rx| {
            let rows = load_all_conversation_envelopes(rx)?;
            Ok(rows
                .into_iter()
                .filter(|(_, env)| {
                    env.is_active && (env.user_did.is_empty() || env.user_did == user_did)
                })
                .map(|(_, env)| env.view)
                .collect())
        })
        .map_err(mls_to_orch_err)
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> OrchResult<()> {
        self.write_tx(|tx| {
            for id in ids {
                if let Some(mut env) = load_conversation_envelope(tx, id)? {
                    if env.user_did.is_empty() || env.user_did == user_did {
                        env.is_active = false;
                        env.state = ConversationState::Failed;
                        save_conversation_envelope(tx.conn(), id, &env)?;
                    }
                }
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            if let Some(mut env) = load_conversation_envelope(tx, conversation_id)? {
                if matches!(state, ConversationState::Active) {
                    env.is_active = true;
                    env.needs_rejoin = false;
                }
                env.state = state;
                env.view.updated_at = Some(Utc::now());
                save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> OrchResult<Option<ConversationState>> {
        self.read_tx(|rx| {
            if let Some(pending) = load_reset_pending(rx.conn(), conversation_id)? {
                return Ok(Some(ConversationState::ResetPending {
                    new_group_id: pending.new_group_id_hex,
                    reset_generation: pending.reset_generation,
                    notified_at_ms: pending.notified_at_ms,
                }));
            }
            let Some(env) = load_conversation_envelope(rx, conversation_id)? else {
                return Ok(None);
            };
            if matches!(env.state, ConversationState::ResetPending { .. }) {
                return Err(MLSError::invalid_input(format!(
                    "incomplete reset_pending state for {conversation_id}: payload not committed"
                )));
            }
            Ok(Some(env.state))
        })
        .map_err(mls_to_orch_err)
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> OrchResult<()> {
        self.write_tx(|tx| {
            if let Some(mut env) = load_conversation_envelope(tx, conversation_id)? {
                env.needs_rejoin = true;
                save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> OrchResult<bool> {
        self.read_tx(|rx| {
            Ok(load_conversation_envelope(rx, conversation_id)?
                .map(|env| env.needs_rejoin)
                .unwrap_or(false))
        })
        .map_err(mls_to_orch_err)
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> OrchResult<()> {
        self.write_tx(|tx| {
            if let Some(mut env) = load_conversation_envelope(tx, conversation_id)? {
                env.needs_rejoin = false;
                save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn get_welcome_reissue_attempt_log(
        &self,
        conversation_id: &str,
    ) -> OrchResult<ReissueAttemptLog> {
        self.read_tx(|rx| {
            let Some(raw) = load_pending_op(rx.conn(), OP_WELCOME_REISSUE, conversation_id)? else {
                return Ok(ReissueAttemptLog::default());
            };
            let ts_list: Vec<i64> = serde_json::from_str(&raw).map_err(|e| {
                MLSError::invalid_input(format!("corrupt welcome_reissue log: {e}"))
            })?;
            Ok(ReissueAttemptLog {
                attempts: ts_list
                    .into_iter()
                    .map(|attempted_at_ms| ReissueAttempt { attempted_at_ms })
                    .collect(),
            })
        })
        .map_err(mls_to_orch_err)
    }

    async fn record_welcome_reissue_attempt(
        &self,
        conversation_id: &str,
        attempted_at_ms: i64,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            let mut ts_list: Vec<i64> = if let Some(raw) =
                load_pending_op(tx.conn(), OP_WELCOME_REISSUE, conversation_id)?
            {
                serde_json::from_str(&raw).unwrap_or_default()
            } else {
                Vec::new()
            };
            ts_list.push(attempted_at_ms);
            let json = serde_json::to_string(&ts_list)
                .map_err(|e| MLSError::invalid_input(format!("serialize welcome_reissue: {e}")))?;
            tx.put_pending_op(OP_WELCOME_REISSUE, conversation_id, &json, attempted_at_ms)
        })
        .map_err(mls_to_orch_err)
    }

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            if let Some(existing) = load_reset_pending(tx.conn(), conversation_id)? {
                if existing.reset_generation >= reset_generation {
                    return Err(MLSError::invalid_input(format!(
                        "stale reset generation {reset_generation}"
                    )));
                }
            }
            let payload = PersistedResetPendingPayload {
                new_group_id_hex: new_group_id_hex.to_string(),
                reset_generation,
                notified_at_ms,
            };
            let payload_json = serde_json::to_string(&payload)
                .map_err(|e| MLSError::invalid_input(format!("serialize reset_pending: {e}")))?;
            tx.put_pending_op(
                OP_RESET_PENDING,
                conversation_id,
                &payload_json,
                notified_at_ms,
            )?;

            let prev_high = load_reset_high_water(tx.conn(), conversation_id)?.unwrap_or(0);
            let next_high = prev_high.max(reset_generation);
            tx.put_pending_op(
                OP_RESET_HIGH_WATER,
                conversation_id,
                &next_high.to_string(),
                notified_at_ms,
            )?;

            if let Some(mut env) = load_conversation_envelope(tx, conversation_id)? {
                env.state = ConversationState::ResetPending {
                    new_group_id: new_group_id_hex.to_string(),
                    reset_generation,
                    notified_at_ms,
                };
                env.needs_rejoin = true;
                save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> OrchResult<bool> {
        let canonical_hex = |value: &str| {
            !value.is_empty()
                && value.len().is_multiple_of(2)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !canonical_hex(expected_old_target) || !canonical_hex(authoritative_new_target) {
            return Err(OrchestratorError::Storage(
                "reset target must be non-empty canonical hex".to_string(),
            ));
        }

        self.write_tx(|tx| {
            let Some(pending) = load_reset_pending(tx.conn(), conversation_id)? else {
                return Ok(false);
            };
            if pending.reset_generation != expected_generation
                || pending.new_group_id_hex != expected_old_target
            {
                return Ok(false);
            }
            let updated = PersistedResetPendingPayload {
                new_group_id_hex: authoritative_new_target.to_string(),
                reset_generation: expected_generation,
                notified_at_ms: pending.notified_at_ms,
            };
            let json = serde_json::to_string(&updated)
                .map_err(|e| MLSError::invalid_input(format!("serialize reset_pending: {e}")))?;
            tx.put_pending_op(
                OP_RESET_PENDING,
                conversation_id,
                &json,
                pending.notified_at_ms,
            )?;
            if let Some(mut env) = load_conversation_envelope(tx, conversation_id)? {
                env.state = ConversationState::ResetPending {
                    new_group_id: authoritative_new_target.to_string(),
                    reset_generation: expected_generation,
                    notified_at_ms: pending.notified_at_ms,
                };
                env.needs_rejoin = true;
                save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            }
            Ok(true)
        })
        .map_err(mls_to_orch_err)
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> OrchResult<bool> {
        self.write_tx(|tx| {
            let Some(mut env) = load_conversation_envelope(tx, conversation_id)? else {
                return Ok(false);
            };
            let Some(pending) = load_reset_pending(tx.conn(), conversation_id)? else {
                return Ok(false);
            };
            if pending.reset_generation != expected_generation
                || pending.new_group_id_hex != expected_new_group_id_hex
            {
                return Ok(false);
            }
            tx.delete_pending_op(OP_RESET_PENDING, conversation_id)?;
            env.group_id_str = expected_new_group_id_hex.to_string();
            env.view.group_id = expected_new_group_id_hex.to_string();
            env.view.epoch = landed_epoch;
            env.join_epoch = Some(landed_epoch);
            env.state = ConversationState::Active;
            env.is_active = true;
            env.needs_rejoin = false;
            env.view.updated_at = Some(Utc::now());
            save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            Ok(true)
        })
        .map_err(mls_to_orch_err)
    }

    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> OrchResult<bool> {
        if !matches!(
            terminal_state,
            ConversationState::Closed | ConversationState::DeviceRemoved
        ) || expected_group_id_hex.len() != 64
            || !expected_group_id_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || terminal_epoch > 9_007_199_254_740_991
            || expected_reset_generation.is_some_and(|g| g <= 0)
        {
            return Err(OrchestratorError::Storage(
                "invalid account exit tuple".into(),
            ));
        }

        self.write_tx(|tx| {
            let Some(mut env) = load_conversation_envelope(tx, conversation_id)? else {
                return Ok(false);
            };
            let pending = load_reset_pending(tx.conn(), conversation_id)?;
            let high_water = load_reset_high_water(tx.conn(), conversation_id)?;

            let same_terminal = env.state == terminal_state
                && env.group_id_str == expected_group_id_hex
                && env.view.epoch == terminal_epoch;
            if env.state == ConversationState::Closed && (!same_terminal || pending.is_some()) {
                return Ok(false);
            }

            let allowed = match (expected_reset_generation, pending.as_ref()) {
                (Some(expected), Some(p)) => {
                    expected == p.reset_generation && p.new_group_id_hex == expected_group_id_hex
                }
                (Some(expected), None) => same_terminal && high_water == Some(expected),
                (None, None) => {
                    !matches!(env.state, ConversationState::ResetPending { .. })
                        && env.group_id_str == expected_group_id_hex
                }
                (None, Some(_)) => false,
            };

            if !allowed
                || (env.group_id_str == expected_group_id_hex && env.view.epoch > terminal_epoch)
            {
                return Ok(false);
            }

            if let Some(gen) = expected_reset_generation {
                tx.put_pending_op(
                    OP_RESET_HIGH_WATER,
                    conversation_id,
                    &gen.to_string(),
                    now_ms(),
                )?;
            }
            tx.delete_pending_op(OP_RESET_PENDING, conversation_id)?;
            env.group_id_str = expected_group_id_hex.to_string();
            env.view.group_id = expected_group_id_hex.to_string();
            env.view.epoch = terminal_epoch;
            env.state = terminal_state;
            env.needs_rejoin = false;
            env.view.updated_at = Some(Utc::now());
            save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            Ok(true)
        })
        .map_err(mls_to_orch_err)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> OrchResult<bool> {
        self.write_tx(|tx| {
            let Some(pending) = load_reset_pending(tx.conn(), conversation_id)? else {
                return Ok(false);
            };
            if pending.reset_generation != expected_generation {
                return Ok(false);
            }
            tx.delete_pending_op(OP_RESET_PENDING, conversation_id)?;
            Ok(true)
        })
        .map_err(mls_to_orch_err)
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            if let Some(mut env) = load_conversation_envelope(tx, conversation_id)? {
                env.view.sequencer_did = Some(sequencer_did.to_string());
                save_conversation_envelope(tx.conn(), conversation_id, &env)?;
            } else {
                tx.conn()
                    .execute(
                        "UPDATE conversations SET sequencer_did = ?2 WHERE conversation_id = ?1",
                        rusqlite::params![conversation_id, sequencer_did],
                    )
                    .map_err(|e| map_rusqlite_err("set_conversation_sequencer", &e))?;
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            let payload = PersistedQuarantinePayload {
                reason_tag: reason_tag.to_string(),
                since_ms,
            };
            let json = serde_json::to_string(&payload)
                .map_err(|e| MLSError::invalid_input(format!("serialize quarantine: {e}")))?;
            tx.put_pending_op(OP_QUARANTINE, conversation_id, &json, since_ms)
        })
        .map_err(mls_to_orch_err)
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> OrchResult<()> {
        self.write_tx(|tx| {
            tx.delete_pending_op(OP_QUARANTINE, conversation_id)?;
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn store_message(&self, message: &Message) -> OrchResult<()> {
        self.write_tx(|tx| {
            let group_id_blob = load_conversation_envelope(tx, &message.conversation_id)?
                .map(|env| encode_group_id_blob(&env.group_id_str))
                .unwrap_or_default();
            let envelope = StoredMessageEnvelope {
                text: message.text.clone(),
                payload_json: message.payload_json.clone(),
                delivery_status: message.delivery_status.clone(),
                timestamp_rfc3339: message.timestamp.to_rfc3339(),
            };
            let plaintext_json = serde_json::to_string(&envelope)
                .map_err(|e| MLSError::invalid_input(format!("serialize message: {e}")))?;
            let created_at_ms = message.timestamp.timestamp_millis();

            tx.conn()
                .execute(
                    "INSERT OR REPLACE INTO messages (\
                        message_id, conversation_id, group_id, epoch, seq, \
                        sender_did, sender_device_id, plaintext_json, created_at_ms, is_own\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    rusqlite::params![
                        message.id,
                        message.conversation_id,
                        group_id_blob,
                        message.epoch as i64,
                        message.sequence_number as i64,
                        message.sender_did,
                        "",
                        plaintext_json,
                        created_at_ms,
                        i64::from(message.is_own),
                    ],
                )
                .map_err(|e| map_rusqlite_err("MLSStorageBackend::store_message", &e))?;

            tx.conn()
                .execute(
                    "UPDATE conversations SET last_seq = MAX(last_seq, ?2), updated_at_ms = MAX(updated_at_ms, ?3) \
                     WHERE conversation_id = ?1",
                    rusqlite::params![
                        message.conversation_id,
                        message.sequence_number as i64,
                        created_at_ms,
                    ],
                )
                .map_err(|e| map_rusqlite_err("MLSStorageBackend::store_message.last_seq", &e))?;
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> OrchResult<Vec<Message>> {
        self.read_tx(|rx| {
            let rows = rx.list_messages(
                conversation_id,
                before_sequence.map(|s| s as i64),
                limit as usize,
            )?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows.into_iter().rev() {
                let (text, payload_json, delivery_status, timestamp) = if let Ok(env) =
                    serde_json::from_str::<StoredMessageEnvelope>(&row.plaintext_json)
                {
                    let ts = DateTime::parse_from_rfc3339(&env.timestamp_rfc3339)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| {
                            Utc.timestamp_millis_opt(row.created_at_ms)
                                .single()
                                .unwrap_or_else(Utc::now)
                        });
                    (env.text, env.payload_json, env.delivery_status, ts)
                } else {
                    let ts = Utc
                        .timestamp_millis_opt(row.created_at_ms)
                        .single()
                        .unwrap_or_else(Utc::now);
                    (row.plaintext_json, None, None, ts)
                };
                out.push(Message {
                    id: row.message_id,
                    conversation_id: row.conversation_id,
                    sender_did: row.sender_did,
                    text,
                    timestamp,
                    epoch: row.epoch.max(0) as u64,
                    sequence_number: row.seq.max(0) as u64,
                    is_own: row.is_own,
                    delivery_status,
                    payload_json,
                });
            }
            Ok(out)
        })
        .map_err(mls_to_orch_err)
    }

    async fn message_exists(&self, message_id: &str) -> OrchResult<bool> {
        self.read_tx(|rx| {
            let found: Option<i64> = rx
                .conn()
                .query_row(
                    "SELECT 1 FROM messages WHERE message_id = ?1 LIMIT 1",
                    [message_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| map_rusqlite_err("message_exists", &e))?;
            Ok(found.is_some())
        })
        .map_err(mls_to_orch_err)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> OrchResult<SyncCursor> {
        let key = format!("sync_cursor:{user_did}");
        self.read_tx(|rx| {
            let Some(json) = rx.get_account_meta(&key)? else {
                return Ok(SyncCursor::default());
            };
            serde_json::from_str(&json)
                .map_err(|e| MLSError::invalid_input(format!("corrupt sync_cursor: {e}")))
        })
        .map_err(mls_to_orch_err)
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> OrchResult<()> {
        let key = format!("sync_cursor:{user_did}");
        let json = serde_json::to_string(cursor)
            .map_err(|e| OrchestratorError::Storage(format!("serialize sync_cursor: {e}")))?;
        self.write_tx(|tx| tx.put_account_meta(&key, &json, now_ms()))
            .map_err(mls_to_orch_err)
    }

    async fn set_group_state(&self, state: &GroupState) -> OrchResult<()> {
        let key = format!("group_state:{}", state.group_id);
        let json = serde_json::to_string(state)
            .map_err(|e| OrchestratorError::Storage(format!("serialize group_state: {e}")))?;
        self.write_tx(|tx| tx.put_account_meta(&key, &json, now_ms()))
            .map_err(mls_to_orch_err)
    }

    async fn get_group_state(&self, group_id: &str) -> OrchResult<Option<GroupState>> {
        let exact_key = format!("group_state:{group_id}");
        self.read_tx(|rx| {
            if let Some(json) = rx.get_account_meta(&exact_key)? {
                let parsed: GroupState = serde_json::from_str(&json)
                    .map_err(|e| MLSError::invalid_input(format!("corrupt group_state: {e}")))?;
                return Ok(Some(parsed));
            }
            let mut stmt = rx
                .conn()
                .prepare("SELECT value_json FROM account_meta WHERE key LIKE 'group_state:%'")
                .map_err(|e| map_rusqlite_err("get_group_state.scan", &e))?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| map_rusqlite_err("get_group_state.rows", &e))?;
            for row in rows {
                let json = row.map_err(|e| map_rusqlite_err("get_group_state.row", &e))?;
                if let Ok(state) = serde_json::from_str::<GroupState>(&json) {
                    if state.conversation_id == group_id || state.group_id == group_id {
                        return Ok(Some(state));
                    }
                }
            }
            Ok(None)
        })
        .map_err(mls_to_orch_err)
    }

    async fn delete_group_state(&self, group_id: &str) -> OrchResult<()> {
        let key = format!("group_state:{group_id}");
        self.write_tx(|tx| tx.delete_account_meta(&key))
            .map_err(mls_to_orch_err)
    }

    async fn store_pending_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            tx.put_pending_op(OP_PENDING_MESSAGE, message_id, conversation_id, now_ms())
        })
        .map_err(mls_to_orch_err)
    }

    async fn remove_pending_message(&self, message_id: &str) -> OrchResult<bool> {
        self.write_tx(|tx| Ok(tx.delete_pending_op(OP_PENDING_MESSAGE, message_id)? > 0))
            .map_err(mls_to_orch_err)
    }

    async fn reserve_send_counter(&self, conversation_id: &str) -> OrchResult<u64> {
        let key = crate::client::chat_wire::send_counter_key(conversation_id);
        self.write_tx(|tx| {
            let next =
                crate::client::chat_wire::next_send_counter(tx.get_account_meta(&key)?.as_deref())?;
            tx.put_account_meta(&key, &next.to_string(), now_ms())?;
            Ok(next)
        })
        .map_err(mls_to_orch_err)
    }

    async fn store_sequencer_receipt(&self, receipt: &SequencerReceipt) -> OrchResult<()> {
        let entry_id = hex::encode(&receipt.commit_hash);
        let json = serde_json::to_string(receipt)
            .map_err(|e| OrchestratorError::Storage(format!("serialize receipt: {e}")))?;
        self.write_tx(|tx| {
            tx.put_sequencer_receipt(
                &receipt.convo_id,
                i64::from(receipt.epoch),
                0,
                &entry_id,
                &json,
            )
        })
        .map_err(mls_to_orch_err)
    }

    async fn get_sequencer_receipts(
        &self,
        convo_id: &str,
        since_epoch: Option<i32>,
    ) -> OrchResult<Vec<SequencerReceipt>> {
        self.read_tx(|rx| {
            let mut candidate_ids = vec![convo_id.to_string()];
            if let Some(env) = load_conversation_envelope(rx, convo_id)? {
                if !env.group_id_str.is_empty() && env.group_id_str != convo_id {
                    candidate_ids.push(env.group_id_str);
                }
            } else {
                for (cid, env) in load_all_conversation_envelopes(rx)? {
                    if env.group_id_str == convo_id && cid != convo_id {
                        candidate_ids.push(cid);
                    }
                }
            }

            let min_epoch = i64::from(since_epoch.unwrap_or(i32::MIN));
            let mut out = Vec::new();
            for cid in candidate_ids {
                let mut stmt = rx
                    .conn()
                    .prepare(
                        "SELECT receipt_json FROM sequencer_receipts \
                         WHERE conversation_id = ?1 AND epoch >= ?2 \
                         ORDER BY epoch ASC, entry_id ASC",
                    )
                    .map_err(|e| map_rusqlite_err("get_sequencer_receipts", &e))?;
                let rows = stmt
                    .query_map(rusqlite::params![cid, min_epoch], |r| r.get::<_, String>(0))
                    .map_err(|e| map_rusqlite_err("get_sequencer_receipts.rows", &e))?;
                for row in rows {
                    let json =
                        row.map_err(|e| map_rusqlite_err("get_sequencer_receipts.row", &e))?;
                    let parsed: SequencerReceipt = serde_json::from_str(&json).map_err(|e| {
                        MLSError::invalid_input(format!("corrupt sequencer_receipt: {e}"))
                    })?;
                    out.push(parsed);
                }
            }
            Ok(out)
        })
        .map_err(mls_to_orch_err)
    }

    async fn clear_sequencer_receipts(&self, conversation_id: &str) -> OrchResult<()> {
        self.write_tx(|tx| {
            let mut candidate_ids = vec![conversation_id.to_string()];
            if let Some(env) = load_conversation_envelope(tx, conversation_id)? {
                if !env.group_id_str.is_empty() && env.group_id_str != conversation_id {
                    candidate_ids.push(env.group_id_str);
                }
            } else {
                for (cid, env) in load_all_conversation_envelopes(tx)? {
                    if env.group_id_str == conversation_id && cid != conversation_id {
                        candidate_ids.push(cid);
                    }
                }
            }
            for cid in candidate_ids {
                tx.clear_sequencer_receipts(&cid)?;
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn cleanup_old_epoch_data(
        &self,
        conversation_id: &str,
        retain_from_epoch: u64,
    ) -> OrchResult<()> {
        self.write_tx(|tx| {
            tx.delete_epoch_secrets_before(conversation_id, retain_from_epoch)?;
            if let Some(env) = load_conversation_envelope(tx, conversation_id)? {
                if env.group_id_str != conversation_id {
                    tx.delete_epoch_secrets_before(&env.group_id_str, retain_from_epoch)?;
                }
            }
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn get_recovery_state(&self) -> OrchResult<PersistedRecoveryState> {
        self.read_tx(|rx| {
            let last_global_rejoin_attempt_at_ms: Option<i64> = rx
                .conn()
                .query_row(
                    "SELECT last_attempt_at_ms FROM recovery_state WHERE scope_key = ?1",
                    [GLOBAL_RECOVERY_SCOPE_KEY],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| map_rusqlite_err("get_recovery_state.global", &e))?;

            let mut stmt = rx
                .conn()
                .prepare(
                    "SELECT scope_key, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms, extra_json \
                     FROM recovery_state WHERE scope_key LIKE 'convo:%'",
                )
                .map_err(|e| map_rusqlite_err("get_recovery_state.entries", &e))?;
            let rows = stmt
                .query_map([], |r| {
                    let scope_key: String = r.get(0)?;
                    let failed_rejoin_count: i64 = r.get(1)?;
                    let last_attempt_at_ms: i64 = r.get(2)?;
                    let quarantined_until_ms: Option<i64> = r.get(3)?;
                    let extra_json: Option<String> = r.get(4)?;
                    let conversation_id = extra_json.unwrap_or_else(|| {
                        scope_key
                            .strip_prefix(CONVO_RECOVERY_PREFIX)
                            .unwrap_or(&scope_key)
                            .to_string()
                    });
                    Ok(PersistedRecoveryBackoff {
                        conversation_id,
                        failed_rejoin_count: failed_rejoin_count.max(0) as u32,
                        last_attempt_at_ms,
                        quarantined_until_ms,
                    })
                })
                .map_err(|e| map_rusqlite_err("get_recovery_state.rows", &e))?;
            let entries = rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("get_recovery_state.collect", &e))?;

            Ok(PersistedRecoveryState {
                entries,
                last_global_rejoin_attempt_at_ms,
            })
        })
        .map_err(mls_to_orch_err)
    }

    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> OrchResult<()> {
        let scope_key = format!("{CONVO_RECOVERY_PREFIX}{}", entry.conversation_id);
        self.write_tx(|tx| {
            tx.conn()
                .execute(
                    "INSERT OR REPLACE INTO recovery_state \
                     (scope_key, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms, extra_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        scope_key,
                        i64::from(entry.failed_rejoin_count),
                        entry.last_attempt_at_ms,
                        entry.quarantined_until_ms,
                        entry.conversation_id,
                    ],
                )
                .map_err(|e| map_rusqlite_err("set_recovery_backoff", &e))?;
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn clear_recovery_backoff(&self, conversation_id: &str) -> OrchResult<()> {
        let scope_key = format!("{CONVO_RECOVERY_PREFIX}{conversation_id}");
        self.write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM recovery_state WHERE scope_key = ?1",
                    [scope_key],
                )
                .map_err(|e| map_rusqlite_err("clear_recovery_backoff", &e))?;
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> OrchResult<()> {
        self.write_tx(|tx| {
            tx.conn()
                .execute(
                    "INSERT OR REPLACE INTO recovery_state \
                     (scope_key, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms, extra_json) \
                     VALUES (?1, 0, ?2, NULL, NULL)",
                    rusqlite::params![GLOBAL_RECOVERY_SCOPE_KEY, at_ms],
                )
                .map_err(|e| map_rusqlite_err("set_last_global_rejoin_attempt_at", &e))?;
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> OrchResult<()> {
        let intent = PendingLocalDelete {
            conversation_id: conversation_id.to_string(),
            group_id_hex: group_id_hex.map(ToString::to_string),
        };
        let json = serde_json::to_string(&intent).map_err(|e| {
            OrchestratorError::Storage(format!("serialize pending_local_delete: {e}"))
        })?;
        self.write_tx(|tx| {
            tx.put_pending_op(OP_PENDING_LOCAL_DELETE, conversation_id, &json, now_ms())
        })
        .map_err(mls_to_orch_err)
    }

    async fn clear_pending_local_delete(&self, conversation_id: &str) -> OrchResult<()> {
        self.write_tx(|tx| {
            tx.delete_pending_op(OP_PENDING_LOCAL_DELETE, conversation_id)?;
            Ok(())
        })
        .map_err(mls_to_orch_err)
    }

    async fn list_pending_local_deletes(&self) -> OrchResult<Vec<PendingLocalDelete>> {
        self.read_tx(|rx| {
            let mut stmt = rx
                .conn()
                .prepare(
                    "SELECT payload_json FROM pending_ops \
                     WHERE op_kind = ?1 ORDER BY created_at_ms ASC",
                )
                .map_err(|e| map_rusqlite_err("list_pending_local_deletes", &e))?;
            let rows = stmt
                .query_map([OP_PENDING_LOCAL_DELETE], |r| r.get::<_, String>(0))
                .map_err(|e| map_rusqlite_err("list_pending_local_deletes.rows", &e))?;
            let mut out = Vec::new();
            for row in rows {
                let json =
                    row.map_err(|e| map_rusqlite_err("list_pending_local_deletes.row", &e))?;
                let parsed: PendingLocalDelete = serde_json::from_str(&json).map_err(|e| {
                    MLSError::invalid_input(format!("corrupt pending_local_delete: {e}"))
                })?;
                out.push(parsed);
            }
            Ok(out)
        })
        .map_err(mls_to_orch_err)
    }
}
