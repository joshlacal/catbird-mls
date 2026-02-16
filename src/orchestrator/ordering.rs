use std::collections::HashMap;

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

/// Tracks message ordering per conversation for gap detection.
pub struct OrderingState {
    /// Last seen sequence number per conversation.
    last_sequence: HashMap<ConversationId, u64>,
    /// Detected gaps: (conversation_id, expected_seq, actual_seq).
    gaps: Vec<(ConversationId, u64, u64)>,
}

impl OrderingState {
    pub fn new() -> Self {
        Self {
            last_sequence: HashMap::new(),
            gaps: Vec::new(),
        }
    }

    /// Record a message and detect gaps.
    ///
    /// Returns `true` if a gap was detected.
    pub fn record_message(&mut self, conversation_id: &str, sequence_number: u64) -> bool {
        let expected = self
            .last_sequence
            .get(conversation_id)
            .map(|s| s + 1)
            .unwrap_or(0);

        let gap_detected = sequence_number > expected && expected > 0;

        if gap_detected {
            tracing::warn!(
                conversation_id,
                expected,
                actual = sequence_number,
                "Message ordering gap detected"
            );
            self.gaps
                .push((conversation_id.to_string(), expected, sequence_number));
        }

        self.last_sequence
            .insert(conversation_id.to_string(), sequence_number);

        gap_detected
    }

    /// Get and clear detected gaps.
    pub fn drain_gaps(&mut self) -> Vec<(ConversationId, u64, u64)> {
        std::mem::take(&mut self.gaps)
    }

    /// Reset tracking for a conversation (e.g. after rejoin).
    pub fn reset(&mut self, conversation_id: &str) {
        self.last_sequence.remove(conversation_id);
        self.gaps.retain(|(cid, _, _)| cid != conversation_id);
    }
}

impl Default for OrderingState {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, A, C> MLSOrchestrator<S, A, C>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
{
    // Ordering is handled at the message processing level in messaging.rs.
    // The OrderingState struct above can be embedded in the orchestrator
    // or used externally by the platform layer for gap detection.
}
