//! Strict per-sender `sendCounter` continuity, recorded as evidence only.
//!
//! A sending device reserves `confirmed + 1` for each send and reuses a counter only after a
//! definitive refusal, so the counters one device gets sequenced in a conversation have no holes,
//! and its sends are sequenced in counter order. A receiver that applied every entry between two
//! of that device's messages therefore expects the second counter to be exactly the first plus
//! one, plus the number of that device's entries it applied without learning their counter
//! (payload-pruned or legacy evidence).
//!
//! Within one MLS epoch every member applies every sequenced entry, so the comparison holds from
//! the first message a receiver sees. Across epochs it holds only while the receiver applied every
//! Commit between the two messages itself ([`EpochChain`]) and the sender stayed a leaf throughout
//! (its continuity is dropped when a Commit leaves it out of the group). Anything else is a fresh
//! baseline.
//!
//! A mismatch never blocks delivery and never reaches the user as an error: it is stored as
//! evidence ([`send_counter_gap_key`]) and exported for diagnosis. Even a non-increasing counter
//! is evidence only; the last verified high-water mark stays put so one anomaly does not cause a
//! cascade of false gaps.

use serde::{Deserialize, Serialize};

use crate::error::MLSError;

/// Largest counter the canonical JSON wire can carry exactly.
pub const MAX_SAFE_SEND_COUNTER: u64 = 9_007_199_254_740_991;

/// What the receiver last knew about one sender device before its next counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCounterPrior {
    /// The last counter this receiver verified from the device.
    pub last: u64,
    /// Entries from the device applied since `last` whose counter this receiver never learned.
    pub skipped: u64,
    /// `last` was verified in the same MLS epoch as the next counter.
    pub same_epoch: bool,
}

/// How a verified counter relates to what the receiver expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCounterVerdict {
    /// Nothing to compare against: the first counter this receiver can anchor.
    Baseline,
    /// Exactly the expected successor.
    Contiguous,
    /// Anything other than the expected successor while the counter still increased.
    Gap { expected: u64, received: u64 },
    /// A counter at or below the last one seen, in this epoch or across an epoch boundary.
    Regressed { last: u64, received: u64 },
}

impl PeerCounterVerdict {
    /// The verdict is evidence worth storing.
    pub fn is_anomaly(&self) -> bool {
        matches!(self, Self::Gap { .. } | Self::Regressed { .. })
    }
}

/// Classify the next verified counter of a sender device against what the receiver knew.
///
/// `Err` only for a counter outside the lexicon's 1..=safe-integer range. Every valid counter is delivered;
/// non-increasing counters are stored as evidence.
pub fn classify_peer_send_counter(
    prior: Option<PeerCounterPrior>,
    next: u64,
) -> Result<PeerCounterVerdict, MLSError> {
    if next == 0 || next > MAX_SAFE_SEND_COUNTER {
        return Err(MLSError::Cryptography(
            "peer sendCounter is outside the canonical positive safe-integer range".into(),
        ));
    }
    let Some(prior) = prior else {
        return Ok(PeerCounterVerdict::Baseline);
    };
    if next <= prior.last {
        return Ok(PeerCounterVerdict::Regressed {
            last: prior.last,
            received: next,
        });
    }
    let expected = prior.last.saturating_add(1).saturating_add(prior.skipped);
    Ok(if next == expected {
        PeerCounterVerdict::Contiguous
    } else {
        PeerCounterVerdict::Gap {
            expected,
            received: next,
        }
    })
}

/// The epochs of one conversation generation this receiver moved through by applying each
/// sequenced Commit itself, from `start` to `current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochChain {
    pub start: u64,
    pub current: u64,
}

impl EpochChain {
    /// `from..=to` lies inside the chain.
    pub fn covers(&self, from: u64, to: u64) -> bool {
        self.start <= from && from <= to && to <= self.current
    }

    pub fn encode(&self) -> String {
        format!("{}:{}", self.start, self.current)
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let (start, current) = raw.split_once(':')?;
        let chain = Self {
            start: start.parse().ok()?,
            current: current.parse().ok()?,
        };
        (chain.start <= chain.current).then_some(chain)
    }
}

/// The chain after this receiver applied a Commit from `prior_epoch` to `next_epoch`. A Commit
/// that does not continue the chain starts a new one at the epoch it left: the receiver saw every
/// entry of that epoch after its own last observation of it, because the cursor never skips.
pub fn advance_epoch_chain(
    chain: Option<EpochChain>,
    prior_epoch: u64,
    next_epoch: u64,
) -> EpochChain {
    match prior_epoch.checked_add(1) {
        Some(step) if step == next_epoch => match chain {
            Some(chain) if chain.current == prior_epoch => EpochChain {
                start: chain.start,
                current: next_epoch,
            },
            _ => EpochChain {
                start: prior_epoch,
                current: next_epoch,
            },
        },
        _ => EpochChain {
            start: next_epoch,
            current: next_epoch,
        },
    }
}

/// The last verified state of one sender device, kept across epochs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerCounterContinuity {
    pub sender_did: String,
    pub sender_device_id: String,
    pub counter: u64,
    pub skipped: u64,
    pub epoch: u64,
    pub seq: i64,
}

/// What to compare the next counter of a device in `epoch` against: the same-epoch counter when
/// one exists, otherwise the device's last counter from an earlier epoch when the chain covers
/// both epochs, otherwise nothing.
pub fn select_peer_counter_prior(
    epoch_last: Option<u64>,
    continuity: Option<(u64, u64, u64)>,
    chain: Option<EpochChain>,
    epoch: u64,
) -> Option<PeerCounterPrior> {
    if let Some(last) = epoch_last {
        let skipped = continuity
            .filter(|(counter, _, at)| *at == epoch && *counter == last)
            .map_or(0, |(_, skipped, _)| skipped);
        return Some(PeerCounterPrior {
            last,
            skipped,
            same_epoch: true,
        });
    }
    let (counter, skipped, at) = continuity?;
    let comparable = at == epoch || chain.is_some_and(|chain| chain.covers(at, epoch));
    comparable.then_some(PeerCounterPrior {
        last: counter,
        skipped,
        same_epoch: false,
    })
}

/// `account_meta` key of one sender device's [`PeerCounterContinuity`] in a generation.
pub fn peer_send_continuity_key(
    conversation_id: &str,
    generation: i64,
    sender_did: &str,
    sender_device_id: &str,
) -> String {
    format!("peer_send_continuity:{conversation_id}:{generation}:{sender_did}:{sender_device_id}")
}

pub fn peer_send_continuity_prefix(conversation_id: &str, generation: i64) -> String {
    format!("peer_send_continuity:{conversation_id}:{generation}:")
}

/// `account_meta` key of the [`EpochChain`] of one conversation generation.
pub fn send_counter_epoch_chain_key(conversation_id: &str, generation: i64) -> String {
    format!("send_counter_epoch_chain:{conversation_id}:{generation}")
}

/// `account_meta` key of the counter evidence recorded at one seq of a conversation.
pub fn send_counter_gap_key(conversation_id: &str, seq: i64) -> String {
    format!("send_counter_gap:{conversation_id}:{seq:020}")
}

/// Prefix of every [`send_counter_gap_key`] of a conversation.
pub fn send_counter_gap_prefix(conversation_id: &str) -> String {
    format!("send_counter_gap:{conversation_id}:")
}

/// `account_meta` key of the own-receipt evidence recorded at one seq of a conversation.
pub fn own_receipt_mismatch_key(conversation_id: &str, seq: i64) -> String {
    format!("own_receipt_mismatch:{conversation_id}:{seq:020}")
}

/// Prefix of every [`own_receipt_mismatch_key`] of a conversation.
pub fn own_receipt_mismatch_prefix(conversation_id: &str) -> String {
    format!("own_receipt_mismatch:{conversation_id}:")
}

/// A seq the sequencer receipted for this account's own message that holds a different entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnReceiptMismatch {
    pub conversation_id: String,
    pub seq: i64,
    pub own_message_id: String,
    pub other_message_id: Option<String>,
    /// `entry-differs`: the entry served at the seq is not the own message.
    /// `slot-taken`: the own message was receipted at a seq another message already holds.
    pub kind: String,
    pub recorded_at_ms: i64,
}

/// Stored counter evidence for one entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendCounterEvidence {
    pub conversation_id: String,
    pub generation: i64,
    pub epoch: u64,
    pub seq: i64,
    pub sender_did: String,
    pub sender_device_id: String,
    /// `gap` or `regressed`.
    pub kind: String,
    pub last: u64,
    pub skipped: u64,
    pub expected: Option<u64>,
    pub received: u64,
    pub same_epoch: bool,
    pub recorded_at_ms: i64,
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::storage::{SqlReadTx, SqlTx};

    fn parse_counter(raw: &str) -> Result<u64, MLSError> {
        raw.parse::<u64>()
            .map_err(|_| MLSError::Internal(format!("corrupt peer send counter {raw:?}")))
    }

    fn load_continuity(
        tx: &SqlReadTx<'_>,
        key: &str,
    ) -> Result<Option<PeerCounterContinuity>, MLSError> {
        // An unreadable record is only lost evidence: it re-baselines, never blocks.
        Ok(tx
            .get_account_meta(key)?
            .and_then(|raw| serde_json::from_str(&raw).ok()))
    }

    fn load_chain(
        tx: &SqlReadTx<'_>,
        conversation_id: &str,
        generation: i64,
    ) -> Result<Option<EpochChain>, MLSError> {
        Ok(tx
            .get_account_meta(&send_counter_epoch_chain_key(conversation_id, generation))?
            .and_then(|raw| EpochChain::decode(&raw)))
    }

    /// The prior a counter of `(sender_did, sender_device_id)` in `epoch` is compared against.
    pub(crate) fn peer_counter_prior(
        tx: &SqlReadTx<'_>,
        conversation_id: &str,
        generation: i64,
        epoch: i64,
        sender_did: &str,
        sender_device_id: &str,
    ) -> Result<Option<PeerCounterPrior>, MLSError> {
        let epoch_u = u64::try_from(epoch)
            .map_err(|_| MLSError::Cryptography("peer sendCounter epoch is negative".into()))?;
        let epoch_last = tx
            .get_account_meta(&crate::client::chat_wire::peer_send_counter_key(
                conversation_id,
                generation,
                epoch,
                sender_did,
                sender_device_id,
            ))?
            .map(|raw| parse_counter(&raw))
            .transpose()?;
        let continuity = load_continuity(
            tx,
            &peer_send_continuity_key(conversation_id, generation, sender_did, sender_device_id),
        )?;
        let chain = load_chain(tx, conversation_id, generation)?;
        Ok(select_peer_counter_prior(
            epoch_last,
            continuity.map(|c| (c.counter, c.skipped, c.epoch)),
            chain,
            epoch_u,
        ))
    }

    /// Check a verified counter without recording it: only an invalid wire-range counter fails.
    pub(crate) fn check_peer_send_counter(
        tx: &SqlReadTx<'_>,
        conversation_id: &str,
        generation: i64,
        epoch: i64,
        sender_did: &str,
        sender_device_id: &str,
        counter: u64,
    ) -> Result<(), MLSError> {
        let prior = peer_counter_prior(
            tx,
            conversation_id,
            generation,
            epoch,
            sender_did,
            sender_device_id,
        )?;
        classify_peer_send_counter(prior, counter).map(|_| ())
    }

    /// Record one sequenced entry of a sender device in the transaction that applies it.
    ///
    /// `counter` is the verified `sendCounter`, or `None` for an entry whose counter this
    /// receiver cannot learn (payload pruned, or legacy evidence without it): that entry is
    /// counted so the device's next counter is still compared exactly. A mismatch is stored as
    /// evidence and never returned as an error.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_peer_send_counter(
        tx: &SqlTx<'_>,
        conversation_id: &str,
        generation: i64,
        epoch: i64,
        sender_did: &str,
        sender_device_id: &str,
        counter: Option<u64>,
        seq: i64,
        now_ms: i64,
    ) -> Result<Option<PeerCounterVerdict>, MLSError> {
        let epoch_u = u64::try_from(epoch)
            .map_err(|_| MLSError::Cryptography("peer sendCounter epoch is negative".into()))?;
        let continuity_key =
            peer_send_continuity_key(conversation_id, generation, sender_did, sender_device_id);
        let Some(counter) = counter else {
            let chain = load_chain(tx, conversation_id, generation)?;
            match load_continuity(tx, &continuity_key)? {
                Some(mut known)
                    if known.epoch == epoch_u
                        || chain.is_some_and(|chain| chain.covers(known.epoch, epoch_u)) =>
                {
                    known.skipped = known.skipped.saturating_add(1);
                    known.seq = known.seq.max(seq);
                    tx.put_account_meta(&continuity_key, &serde_json::to_string(&known)?, now_ms)?;
                }
                Some(_) => tx.delete_account_meta(&continuity_key)?,
                None => {
                    // A same-epoch counter recorded before continuity existed still anchors.
                    let epoch_last = tx
                        .get_account_meta(&crate::client::chat_wire::peer_send_counter_key(
                            conversation_id,
                            generation,
                            epoch,
                            sender_did,
                            sender_device_id,
                        ))?
                        .map(|raw| parse_counter(&raw))
                        .transpose()?;
                    if let Some(counter) = epoch_last {
                        let known = PeerCounterContinuity {
                            sender_did: sender_did.to_owned(),
                            sender_device_id: sender_device_id.to_owned(),
                            counter,
                            skipped: 1,
                            epoch: epoch_u,
                            seq,
                        };
                        tx.put_account_meta(
                            &continuity_key,
                            &serde_json::to_string(&known)?,
                            now_ms,
                        )?;
                    }
                }
            }
            return Ok(None);
        };
        let prior = peer_counter_prior(
            tx,
            conversation_id,
            generation,
            epoch,
            sender_did,
            sender_device_id,
        )?;
        let verdict = classify_peer_send_counter(prior, counter)?;
        if !matches!(verdict, PeerCounterVerdict::Regressed { .. }) {
            tx.put_account_meta(
                &crate::client::chat_wire::peer_send_counter_key(
                    conversation_id,
                    generation,
                    epoch,
                    sender_did,
                    sender_device_id,
                ),
                &counter.to_string(),
                now_ms,
            )?;
            tx.put_account_meta(
                &continuity_key,
                &serde_json::to_string(&PeerCounterContinuity {
                    sender_did: sender_did.to_owned(),
                    sender_device_id: sender_device_id.to_owned(),
                    counter,
                    skipped: 0,
                    epoch: epoch_u,
                    seq,
                })?,
                now_ms,
            )?;
        }
        if let (true, Some(prior)) = (verdict.is_anomaly(), prior) {
            let (kind, expected) = match verdict {
                PeerCounterVerdict::Gap { expected, .. } => ("gap", Some(expected)),
                _ => ("regressed", None),
            };
            let evidence = SendCounterEvidence {
                conversation_id: conversation_id.to_owned(),
                generation,
                epoch: epoch_u,
                seq,
                sender_did: sender_did.to_owned(),
                sender_device_id: sender_device_id.to_owned(),
                kind: kind.to_owned(),
                last: prior.last,
                skipped: prior.skipped,
                expected,
                received: counter,
                same_epoch: prior.same_epoch,
                recorded_at_ms: now_ms,
            };
            tracing::warn!(
                conversation_id,
                seq,
                kind,
                "recording peer sendCounter evidence"
            );
            tx.put_account_meta(
                &send_counter_gap_key(conversation_id, seq),
                &serde_json::to_string(&evidence)?,
                now_ms,
            )?;
        }
        Ok(Some(verdict))
    }

    /// Advance the epoch chain for a Commit this receiver applied from `prior_epoch` to
    /// `next_epoch`, and drop the continuity of every device the Commit left out of the group.
    pub(crate) fn advance_send_counter_epoch_chain(
        tx: &SqlTx<'_>,
        conversation_id: &str,
        generation: i64,
        prior_epoch: i64,
        next_epoch: i64,
        members_after: &std::collections::BTreeSet<(String, String)>,
        now_ms: i64,
    ) -> Result<(), MLSError> {
        let (Ok(prior), Ok(next)) = (u64::try_from(prior_epoch), u64::try_from(next_epoch)) else {
            return Ok(());
        };
        let chain = advance_epoch_chain(load_chain(tx, conversation_id, generation)?, prior, next);
        tx.put_account_meta(
            &send_counter_epoch_chain_key(conversation_id, generation),
            &chain.encode(),
            now_ms,
        )?;
        for (key, raw) in
            tx.list_account_meta_prefix(&peer_send_continuity_prefix(conversation_id, generation))?
        {
            if !key.starts_with(&peer_send_continuity_prefix(conversation_id, generation)) {
                continue;
            }
            let stays = serde_json::from_str::<PeerCounterContinuity>(&raw).is_ok_and(|known| {
                members_after.contains(&(known.sender_did, known.sender_device_id))
            });
            if !stays {
                tx.delete_account_meta(&key)?;
            }
        }
        Ok(())
    }

    /// The `(did, device)` of every leaf of `group`, for [`advance_send_counter_epoch_chain`].
    pub(crate) fn group_leaf_devices(
        group: &openmls::prelude::MlsGroup,
    ) -> std::collections::BTreeSet<(String, String)> {
        group
            .members()
            .filter_map(|member| {
                crate::push::root_did_from_credential_bytes(member.credential.serialized_content())
                    .ok()
            })
            .collect()
    }

    fn message_ids_at_seq(
        tx: &SqlReadTx<'_>,
        conversation_id: &str,
        seq: i64,
        own: bool,
    ) -> Result<Vec<String>, MLSError> {
        let mut statement = tx
            .conn()
            .prepare(
                "SELECT message_id FROM messages \
                 WHERE conversation_id = ?1 AND seq = ?2 AND is_own = ?3 ORDER BY message_id",
            )
            .map_err(|e| MLSError::Internal(format!("select messages at seq: {e}")))?;
        let rows = statement
            .query_map(rusqlite::params![conversation_id, seq, own], |row| {
                row.get(0)
            })
            .map_err(|e| MLSError::Internal(format!("select messages at seq: {e}")))?;
        rows.collect::<Result<_, _>>()
            .map_err(|e| MLSError::Internal(format!("read messages at seq: {e}")))
    }

    fn put_own_receipt_mismatch(
        tx: &SqlTx<'_>,
        evidence: &OwnReceiptMismatch,
    ) -> Result<(), MLSError> {
        tracing::warn!(
            conversation_id = evidence.conversation_id.as_str(),
            seq = evidence.seq,
            "recording own receipt mismatch evidence"
        );
        tx.put_account_meta(
            &own_receipt_mismatch_key(&evidence.conversation_id, evidence.seq),
            &serde_json::to_string(evidence)?,
            evidence.recorded_at_ms,
        )
    }

    /// Before applying the sequenced entry at `seq`: a message of this account the sequencer
    /// already receipted at `seq` must be that entry. Evidence only, never an error.
    pub(crate) fn check_own_receipt_at_entry(
        tx: &SqlTx<'_>,
        conversation_id: &str,
        seq: i64,
        entry_message_id: Option<&str>,
        now_ms: i64,
    ) -> Result<(), MLSError> {
        for own in message_ids_at_seq(tx, conversation_id, seq, true)? {
            if Some(own.as_str()) != entry_message_id {
                put_own_receipt_mismatch(
                    tx,
                    &OwnReceiptMismatch {
                        conversation_id: conversation_id.to_owned(),
                        seq,
                        own_message_id: own,
                        other_message_id: entry_message_id.map(str::to_owned),
                        kind: "entry-differs".to_owned(),
                        recorded_at_ms: now_ms,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// When the sequencer receipts this device's own message at `seq`: no other message this
    /// device already applied may hold `seq`. Evidence only, never an error.
    pub(crate) fn check_own_receipt_slot(
        tx: &SqlTx<'_>,
        conversation_id: &str,
        seq: i64,
        own_message_id: &str,
        now_ms: i64,
    ) -> Result<(), MLSError> {
        for other in message_ids_at_seq(tx, conversation_id, seq, false)? {
            if other != own_message_id {
                put_own_receipt_mismatch(
                    tx,
                    &OwnReceiptMismatch {
                        conversation_id: conversation_id.to_owned(),
                        seq,
                        own_message_id: own_message_id.to_owned(),
                        other_message_id: Some(other),
                        kind: "slot-taken".to_owned(),
                        recorded_at_ms: now_ms,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// Every own-receipt mismatch record of a conversation, in seq order.
    pub(crate) fn list_own_receipt_mismatches(
        tx: &SqlReadTx<'_>,
        conversation_id: &str,
    ) -> Result<Vec<OwnReceiptMismatch>, MLSError> {
        let prefix = own_receipt_mismatch_prefix(conversation_id);
        Ok(tx
            .list_account_meta_prefix(&prefix)?
            .into_iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(_, raw)| serde_json::from_str(&raw).ok())
            .collect())
    }

    /// Every counter evidence record of a conversation, in seq order.
    pub(crate) fn list_send_counter_evidence(
        tx: &SqlReadTx<'_>,
        conversation_id: &str,
    ) -> Result<Vec<SendCounterEvidence>, MLSError> {
        let prefix = send_counter_gap_prefix(conversation_id);
        Ok(tx
            .list_account_meta_prefix(&prefix)?
            .into_iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(_, raw)| serde_json::from_str(&raw).ok())
            .collect())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::{
    advance_send_counter_epoch_chain, check_own_receipt_at_entry, check_own_receipt_slot,
    check_peer_send_counter, group_leaf_devices, list_own_receipt_mismatches,
    list_send_counter_evidence, record_peer_send_counter,
};

#[cfg(test)]
mod tests {
    use super::*;

    const fn prior(last: u64, skipped: u64, same_epoch: bool) -> Option<PeerCounterPrior> {
        Some(PeerCounterPrior {
            last,
            skipped,
            same_epoch,
        })
    }

    #[test]
    fn strict_successor_is_contiguous_and_any_other_increase_is_a_gap() {
        assert_eq!(
            classify_peer_send_counter(None, 7).unwrap(),
            PeerCounterVerdict::Baseline
        );
        assert!(classify_peer_send_counter(None, 0).is_err());
        assert_eq!(
            classify_peer_send_counter(prior(5, 0, true), 6).unwrap(),
            PeerCounterVerdict::Contiguous
        );
        assert_eq!(
            classify_peer_send_counter(prior(5, 0, true), 7).unwrap(),
            PeerCounterVerdict::Gap {
                expected: 6,
                received: 7
            }
        );
        assert_eq!(
            classify_peer_send_counter(prior(5, 0, true), MAX_SAFE_SEND_COUNTER).unwrap(),
            PeerCounterVerdict::Gap {
                expected: 6,
                received: MAX_SAFE_SEND_COUNTER
            }
        );
        assert_eq!(
            classify_peer_send_counter(prior(5, 2, true), 8).unwrap(),
            PeerCounterVerdict::Contiguous
        );
        assert_eq!(
            classify_peer_send_counter(prior(5, 2, false), 7).unwrap(),
            PeerCounterVerdict::Gap {
                expected: 8,
                received: 7
            }
        );
    }

    #[test]
    fn non_increase_is_evidence_in_all_epochs() {
        assert_eq!(
            classify_peer_send_counter(prior(5, 0, true), 5).unwrap(),
            PeerCounterVerdict::Regressed {
                last: 5,
                received: 5
            }
        );
        assert_eq!(
            classify_peer_send_counter(prior(5, 0, true), 4).unwrap(),
            PeerCounterVerdict::Regressed {
                last: 5,
                received: 4
            }
        );
        assert_eq!(
            classify_peer_send_counter(prior(5, 0, false), 5).unwrap(),
            PeerCounterVerdict::Regressed {
                last: 5,
                received: 5
            }
        );
        assert!(classify_peer_send_counter(None, MAX_SAFE_SEND_COUNTER + 1).is_err());
        assert!(classify_peer_send_counter(prior(5, 0, false), u64::MAX).is_err());
    }

    #[test]
    fn chain_continues_only_through_applied_commits() {
        let first = advance_epoch_chain(None, 3, 4);
        assert_eq!(
            first,
            EpochChain {
                start: 3,
                current: 4
            }
        );
        let second = advance_epoch_chain(Some(first), 4, 5);
        assert_eq!(
            second,
            EpochChain {
                start: 3,
                current: 5
            }
        );
        // A Commit from an epoch this receiver never reached restarts the chain.
        assert_eq!(
            advance_epoch_chain(Some(second), 8, 9),
            EpochChain {
                start: 8,
                current: 9
            }
        );
        // A malformed step covers nothing behind it.
        assert_eq!(
            advance_epoch_chain(Some(second), 5, 7),
            EpochChain {
                start: 7,
                current: 7
            }
        );
        assert!(second.covers(3, 5) && !second.covers(2, 5) && !second.covers(4, 6));
    }

    #[test]
    fn cross_epoch_prior_needs_the_chain_to_cover_both_epochs() {
        let chain = Some(EpochChain {
            start: 3,
            current: 5,
        });
        assert_eq!(
            select_peer_counter_prior(None, Some((9, 1, 3)), chain, 5),
            prior(9, 1, false)
        );
        assert_eq!(
            select_peer_counter_prior(None, Some((9, 1, 2)), chain, 5),
            None
        );
        assert_eq!(
            select_peer_counter_prior(None, Some((9, 1, 3)), chain, 6),
            None
        );
        assert_eq!(
            select_peer_counter_prior(None, Some((9, 1, 3)), None, 5),
            None
        );
        // Same epoch without a per-epoch record compares, but never refuses.
        assert_eq!(
            select_peer_counter_prior(None, Some((9, 1, 5)), None, 5),
            prior(9, 1, false)
        );
        // The per-epoch record wins and carries the skips counted after it.
        assert_eq!(
            select_peer_counter_prior(Some(9), Some((9, 2, 5)), chain, 5),
            prior(9, 2, true)
        );
        assert_eq!(
            select_peer_counter_prior(Some(9), Some((8, 2, 5)), chain, 5),
            prior(9, 0, true)
        );
    }
}
