//! One async flush of the archive queue, conversation by conversation.

use std::collections::{BTreeMap, BTreeSet};

use super::hooks::roster_members;
use super::queue::{ArchiveQueueStore, PendingArchive, MAX_FAILURES};
use super::session::{LabyrinthSession, SessionDeps};
use super::status::{now_ms, MemberExclusion};
use super::transport::map_xrpc_error;
use crate::orchestrator::error::Result;

/// What one flush did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Rows archived (or found already archived) and removed.
    pub archived: usize,
    /// Rows removed unarchived because their conversation is gone.
    pub dropped: usize,
    /// Conversations that failed this time; their rows stay queued.
    pub failed_conversations: usize,
    /// Rows newly quarantined by this flush.
    pub quarantined: usize,
    /// Member exclusions recorded by this flush.
    pub excluded_members: usize,
}

impl FlushReport {
    /// Rows that left the queue.
    pub fn left_queue(&self) -> usize {
        self.archived + self.dropped
    }
}

pub(crate) fn is_transient(e: &labyrinth::Error) -> bool {
    match e {
        labyrinth::Error::Backend(m) => [
            "xrpc 0:",
            "xrpc 5",
            "xrpc 429",
            "xrpc 408",
            "space 0:",
            "space 5",
            "space 429",
            "space 408",
        ]
        .iter()
        .any(|p| m.starts_with(p)),
        labyrinth::Error::Rng => true,
        _ => false,
    }
}

/// Archives every pending, unquarantined row of the session's account.
pub async fn flush_queue(
    session: &mut LabyrinthSession,
    deps: &SessionDeps,
    store: &dyn ArchiveQueueStore,
) -> Result<FlushReport> {
    let did = session.did().to_owned();
    let mut todo: BTreeMap<String, Vec<PendingArchive>> = BTreeMap::new();
    for row in store.list(&did)?.into_iter().filter(|r| !r.quarantined) {
        todo.entry(row.conversation_id.clone())
            .or_default()
            .push(row);
    }
    let mut report = FlushReport::default();
    for (conversation, rows) in todo {
        if let Err(error) = flush_conversation(
            session,
            deps,
            store,
            &conversation,
            rows.clone(),
            &mut report,
        )
        .await?
        {
            session.discard_pending(&conversation);
            report.failed_conversations += 1;
            fail_rows(store, rows, &error, &mut report)?;
        }
    }
    Ok(report)
}

async fn flush_conversation(
    session: &mut LabyrinthSession,
    deps: &SessionDeps,
    store: &dyn ArchiveQueueStore,
    conversation: &str,
    rows: Vec<PendingArchive>,
    report: &mut FlushReport,
) -> Result<labyrinth::Result<()>> {
    let did = session.did().to_owned();
    let mut todo = Vec::with_capacity(rows.len());
    let mut quarantined_legacy = false;
    for mut row in rows {
        let has_snapshot = row
            .expected_member_dids
            .as_ref()
            .is_some_and(|members| !members.is_empty());
        if !has_snapshot {
            row.last_error =
                Some("labyrinth: missing local MLS roster snapshot on queued archive".to_owned());
            row.failures = MAX_FAILURES.max(row.failures.saturating_add(1));
            if !row.quarantined {
                row.quarantined = true;
                report.quarantined += 1;
            }
            store.put(&row)?;
            quarantined_legacy = true;
            continue;
        }
        if row.inflight {
            match session.has_archived(conversation, &row.message_id).await? {
                Ok(true) => {
                    store.remove(&did, &row.message_id)?;
                    report.archived += 1;
                    continue;
                }
                // A deleted conversation holds no copy; the rescue below archives the row.
                Ok(false) | Err(labyrinth::Error::NotFound("space" | "conversation")) => {}
                Err(e) => return Ok(Err(e)),
            }
        } else {
            row.inflight = true;
            store.put(&row)?;
        }
        todo.push(row);
    }
    if todo.is_empty() {
        if quarantined_legacy {
            report.failed_conversations += 1;
        }
        return Ok(Ok(()));
    }

    let first_group_id_hex = todo.first().and_then(|r| r.group_id_hex.as_deref());
    let local_snapshot = match &deps.local_authority {
        Some(auth) => {
            auth.current_group_snapshot(conversation, first_group_id_hex)
                .await?
        }
        None => None,
    };

    let ds_members = match conversation_roster(deps, conversation).await {
        Ok(m) => m,
        Err(labyrinth::Error::Forbidden) => {
            tracing::info!(
                conversation,
                count = todo.len(),
                "labyrinth: kicked/forbidden on conversation state; rescuing queued messages into personal mailbox Space"
            );
            return rescue_as_owner(session, store, report, &did, conversation, &todo).await;
        }
        Err(labyrinth::Error::NotFound("conversation")) => {
            let local_has_self = local_snapshot
                .as_ref()
                .is_some_and(|snap| snap.member_dids.iter().any(|m| m == &did));
            if local_has_self {
                return Ok(Err(labyrinth::Error::Backend(
                    "xrpc 503: conversation missing on mls-ds while local MLS group exists".into(),
                )));
            }
            tracing::info!(
                conversation,
                count = todo.len(),
                "labyrinth: conversation deleted on mls-ds; rescuing queued messages into personal mailbox Space"
            );
            return rescue_as_owner(session, store, report, &did, conversation, &todo).await;
        }
        Err(e) => return Ok(Err(e)),
    };
    let ds_set: BTreeSet<&str> = ds_members.iter().map(String::as_str).collect();
    if !ds_set.contains(did.as_str()) {
        tracing::info!(
            conversation,
            count = todo.len(),
            "labyrinth: local DID removed from conversation roster; rescuing queued messages into personal mailbox Space"
        );
        return rescue_as_owner(session, store, report, &did, conversation, &todo).await;
    }

    type ChunkKey = (Option<String>, Option<u64>, Vec<String>);
    let mut chunks: Vec<(ChunkKey, Vec<PendingArchive>)> = Vec::new();
    for row in todo {
        let mut expected = row.expected_member_dids.clone().unwrap_or_default();
        expected.sort();
        expected.dedup();
        let key: ChunkKey = (row.group_id_hex.clone(), row.mls_epoch, expected);
        match chunks.last_mut() {
            Some((last_key, batch)) if *last_key == key => batch.push(row),
            _ => chunks.push((key, vec![row])),
        }
    }

    for ((chunk_group_id_hex, chunk_epoch, expected_members), chunk_rows) in chunks {
        let expected_set: BTreeSet<&str> = expected_members.iter().map(String::as_str).collect();
        let authoritative_ds_set: BTreeSet<&str> = match (&local_snapshot, chunk_epoch) {
            (Some(snap), Some(row_epoch))
                if chunk_group_id_hex
                    .as_deref()
                    .is_none_or(|gid| gid == snap.group_id_hex)
                    && snap.epoch > row_epoch
                    && !snap.member_dids.is_empty() =>
            {
                snap.member_dids.iter().map(String::as_str).collect()
            }
            _ => expected_set.clone(),
        };

        if ds_set.iter().any(|d| !authoritative_ds_set.contains(*d)) {
            return Ok(Err(labyrinth::Error::Malformed(
                "ds roster contains non-mls participant",
            )));
        }
        if authoritative_ds_set.iter().any(|d| !ds_set.contains(*d)) {
            return Ok(Err(labyrinth::Error::Malformed(
                "ds roster omits mls participant",
            )));
        }

        let items = chunk_rows
            .iter()
            .map(|r| Ok((r.message_id.clone(), r.timestamp_ms, r.frame_bytes()?)))
            .collect::<Result<Vec<_>>>()?;
        let excluded = match session
            .archive_conversation(conversation, &expected_members, &items)
            .await?
        {
            Ok(x) => x,
            Err(
                labyrinth::Error::Forbidden | labyrinth::Error::NotFound("space" | "conversation"),
            ) => {
                tracing::info!(
                    conversation,
                    count = chunk_rows.len(),
                    "labyrinth: Space write forbidden/missing (kicked or deleted mid-flush); rescuing chunk into personal mailbox Space"
                );
                let owner_items = chunk_rows
                    .iter()
                    .map(|r| {
                        Ok((
                            r.message_id.clone(),
                            r.timestamp_ms,
                            did.clone(),
                            r.frame_bytes()?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                match session
                    .archive_owner_fallback(conversation, &owner_items)
                    .await?
                {
                    Ok(_) => {
                        for row in &chunk_rows {
                            store.remove(&did, &row.message_id)?;
                            report.archived += 1;
                        }
                        continue;
                    }
                    Err(e) => return Ok(Err(e)),
                }
            }
            Err(e) => return Ok(Err(e)),
        };
        for row in &chunk_rows {
            store.remove(&did, &row.message_id)?;
            report.archived += 1;
        }
        report.excluded_members += excluded.len();
        let at_ms = now_ms();
        store.update_status(&did, &mut |s| {
            for m in expected_members
                .iter()
                .filter(|m| !excluded.iter().any(|x| x.did == **m))
            {
                s.readmit(conversation, m);
            }
            for x in &excluded {
                s.exclude(MemberExclusion {
                    conversation_id: conversation.to_owned(),
                    did: x.did.clone(),
                    reason: x.error.to_string(),
                    needs_repin: matches!(x.error, labyrinth::Error::EpochRollback { .. }),
                    at_ms,
                });
            }
        })?;
        for x in &excluded {
            tracing::warn!(
                conversation,
                did = %x.did,
                error = %x.error,
                "labyrinth: member excluded from the archive roster"
            );
        }
    }
    Ok(Ok(()))
}

async fn rescue_as_owner(
    session: &mut LabyrinthSession,
    store: &dyn ArchiveQueueStore,
    report: &mut FlushReport,
    did: &str,
    conversation: &str,
    rows_to_rescue: &[PendingArchive],
) -> Result<labyrinth::Result<()>> {
    let owner_items = rows_to_rescue
        .iter()
        .map(|r| {
            Ok((
                r.message_id.clone(),
                r.timestamp_ms,
                did.to_owned(),
                r.frame_bytes()?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    match session
        .archive_owner_fallback(conversation, &owner_items)
        .await?
    {
        Ok(_) => {
            for row in rows_to_rescue {
                store.remove(did, &row.message_id)?;
                report.archived += 1;
            }
            Ok(Ok(()))
        }
        Err(e) => Ok(Err(e)),
    }
}

fn fail_rows(
    store: &dyn ArchiveQueueStore,
    rows: Vec<PendingArchive>,
    error: &labyrinth::Error,
    report: &mut FlushReport,
) -> Result<()> {
    let transient = is_transient(error);
    tracing::warn!(%error, transient, "labyrinth: conversation archive failed");
    let Some(did) = rows.first().map(|r| r.did.clone()) else {
        return Ok(());
    };
    let stored: BTreeMap<String, PendingArchive> = store
        .list(&did)?
        .into_iter()
        .map(|r| (r.message_id.clone(), r))
        .collect();
    for mut row in rows {
        let Some(current) = stored.get(&row.message_id) else {
            continue;
        };
        row.inflight = current.inflight;
        row.last_error = Some(error.to_string());
        if !transient {
            row.failures = current.failures + 1;
            if row.failures >= MAX_FAILURES && !current.quarantined {
                row.quarantined = true;
                report.quarantined += 1;
            }
        }
        store.put(&row)?;
    }
    Ok(())
}

async fn conversation_roster(
    deps: &SessionDeps,
    conversation: &str,
) -> labyrinth::Result<Vec<String>> {
    let body = deps
        .transport
        .query(
            "blue.catbird.chat.getConversationState",
            &[("conversationId", conversation.to_owned())],
        )
        .await
        .map_err(map_xrpc_error)?;
    let state: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| labyrinth::Error::Backend(format!("conversation state: {e}")))?;
    roster_members(&state)
}
