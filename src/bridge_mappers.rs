use crate::orchestrator::error::OrchestratorError;
use crate::orchestrator::types::SequencerReceipt;
use crate::orchestrator_bridge::{
    FFIConversationState, FFISequencerReceipt, OrchestratorBridgeError, SecurityStorageCapabilities,
};

pub(crate) const SECURITY_STORAGE_CAPABILITIES_VERSION: u16 = 3;

pub(crate) fn validate_security_capabilities(
    capabilities: &SecurityStorageCapabilities,
) -> Result<(), OrchestratorBridgeError> {
    let required = [
        ("reset_state", capabilities.reset_state),
        ("quarantine", capabilities.quarantine),
        (
            "pending_message_protection",
            capabilities.pending_message_protection,
        ),
        ("sequencer_receipts", capabilities.sequencer_receipts),
        ("recovery_backoff", capabilities.recovery_backoff),
        ("pending_deletion", capabilities.pending_deletion),
        (
            "authorized_device_resolution",
            capabilities.authorized_device_resolution,
        ),
    ];

    if capabilities.version != SECURITY_STORAGE_CAPABILITIES_VERSION {
        return Err(OrchestratorBridgeError::MissingSecurityCapability {
            capability: "contract_version".to_string(),
            required_version: SECURITY_STORAGE_CAPABILITIES_VERSION,
            declared_version: capabilities.version,
        });
    }

    if let Some((capability, _)) = required.into_iter().find(|(_, enabled)| !enabled) {
        return Err(OrchestratorBridgeError::MissingSecurityCapability {
            capability: capability.to_string(),
            required_version: SECURITY_STORAGE_CAPABILITIES_VERSION,
            declared_version: capabilities.version,
        });
    }

    Ok(())
}

pub(crate) fn ffi_receipt_to_internal(receipt: FFISequencerReceipt) -> SequencerReceipt {
    SequencerReceipt {
        convo_id: receipt.convo_id,
        epoch: receipt.epoch,
        sequencer_term: receipt.sequencer_term,
        commit_hash: receipt.commit_hash,
        sequencer_did: receipt.sequencer_did,
        issued_at: receipt.issued_at,
        signature: receipt.signature,
    }
}

pub(crate) fn receipt_to_ffi(receipt: SequencerReceipt) -> FFISequencerReceipt {
    FFISequencerReceipt {
        convo_id: receipt.convo_id,
        epoch: receipt.epoch,
        sequencer_term: receipt.sequencer_term,
        commit_hash: receipt.commit_hash,
        sequencer_did: receipt.sequencer_did,
        issued_at: receipt.issued_at,
        signature: receipt.signature,
    }
}

pub(crate) fn ffi_conversation_state_to_internal(
    ffi: FFIConversationState,
) -> Result<crate::orchestrator::types::ConversationState, OrchestratorError> {
    use crate::orchestrator::types::{ConversationState, QuarantineReason};
    match ffi.state.as_str() {
        "initializing" => Ok(ConversationState::Initializing),
        "active" => Ok(ConversationState::Active),
        "fork_detected" => Ok(ConversationState::ForkDetected),
        "needs_rejoin" => Ok(ConversationState::NeedsRejoin),
        "failed" => Ok(ConversationState::Failed),
        "reset_pending" => Ok(ConversationState::ResetPending {
            new_group_id: ffi.new_group_id.ok_or_else(|| {
                OrchestratorError::Storage("reset_pending missing new_group_id".into())
            })?,
            reset_generation: ffi.reset_generation.ok_or_else(|| {
                OrchestratorError::Storage("reset_pending missing reset_generation".into())
            })?,
            notified_at_ms: ffi.notified_at_ms.ok_or_else(|| {
                OrchestratorError::Storage("reset_pending missing notified_at_ms".into())
            })?,
        }),
        "quarantined" => {
            let reason = match ffi.quarantine_reason.as_deref() {
                Some("peer_bad_commit") => QuarantineReason::PeerBadCommit,
                Some("multi_peer_bad_commits") => QuarantineReason::MultiPeerBadCommits,
                Some("repeated_framing_failures") => QuarantineReason::RepeatedFramingFailures,
                _ => {
                    return Err(OrchestratorError::Storage(
                        "quarantined missing valid reason".into(),
                    ))
                }
            };
            Ok(ConversationState::Quarantined {
                reason,
                since_ms: ffi.quarantined_since_ms.ok_or_else(|| {
                    OrchestratorError::Storage("quarantined missing since_ms".into())
                })?,
            })
        }
        state => Err(OrchestratorError::Storage(format!(
            "unknown conversation state {state}"
        ))),
    }
}

pub(crate) fn bridge_error_to_internal(error: OrchestratorBridgeError) -> OrchestratorError {
    match error {
        OrchestratorBridgeError::Storage { message } => OrchestratorError::Storage(message),
        OrchestratorBridgeError::Api { message } => OrchestratorError::Api(message),
        OrchestratorBridgeError::Credential { message } => OrchestratorError::Credential(message),
        OrchestratorBridgeError::NotAuthenticated => OrchestratorError::NotAuthenticated,
        OrchestratorBridgeError::ShuttingDown => OrchestratorError::ShuttingDown,
        OrchestratorBridgeError::ServerError { status, body } => {
            OrchestratorError::ServerError { status, body }
        }
        OrchestratorBridgeError::ConversationNotFound { id } => {
            OrchestratorError::ConversationNotFound(id)
        }
        OrchestratorBridgeError::EpochMismatch { local, remote } => {
            OrchestratorError::EpochMismatch { local, remote }
        }
        OrchestratorBridgeError::DeviceLimitReached => {
            // The FFI variant predates the internal diagnostic fields. Keep
            // the semantic error class instead of flattening it into Api.
            OrchestratorError::DeviceLimitReached { current: 0, max: 0 }
        }
        OrchestratorBridgeError::RecoveryFailed { message } => {
            OrchestratorError::RecoveryFailed(message)
        }
        OrchestratorBridgeError::InvalidInput { message } => {
            OrchestratorError::InvalidInput(message)
        }
        OrchestratorBridgeError::ConversationQuarantined { convo_id, reason } => {
            OrchestratorError::ConversationQuarantined { convo_id, reason }
        }
        other => OrchestratorError::Api(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use crate::orchestrator::types::SequencerReceipt;
    use crate::orchestrator_bridge::{
        FFISequencerReceipt, OrchestratorBridgeError, SecurityStorageCapabilities,
    };

    #[test]
    fn missing_enabled_capability_is_a_typed_construction_error() {
        let capabilities = SecurityStorageCapabilities {
            version: 3,
            reset_state: true,
            quarantine: true,
            pending_message_protection: false,
            sequencer_receipts: true,
            recovery_backoff: true,
            pending_deletion: true,
            authorized_device_resolution: true,
        };

        let error = super::validate_security_capabilities(&capabilities)
            .expect_err("missing enabled security capability must fail closed");
        assert!(matches!(
            error,
            OrchestratorBridgeError::MissingSecurityCapability {
                capability,
                required_version: 3,
                declared_version: 3,
            } if capability == "pending_message_protection"
        ));
    }

    #[test]
    fn sequencer_receipt_round_trips_without_field_loss() {
        let ffi = FFISequencerReceipt {
            convo_id: "convo-1".into(),
            epoch: 42,
            sequencer_term: 9,
            commit_hash: vec![1, 2, 3],
            sequencer_did: "did:web:sequencer.example".into(),
            issued_at: 1_725_000_000,
            signature: vec![4, 5, 6],
        };

        let internal: SequencerReceipt = super::ffi_receipt_to_internal(ffi.clone());
        let round_trip = super::receipt_to_ffi(internal);

        assert_eq!(round_trip, ffi);
        assert_eq!(round_trip.sequencer_term, 9);
    }

    #[test]
    fn shared_error_mapper_preserves_server_status_and_body() {
        let mapped = super::bridge_error_to_internal(OrchestratorBridgeError::ServerError {
            status: 429,
            body: "retry later".into(),
        });

        assert!(matches!(
            mapped,
            crate::orchestrator::error::OrchestratorError::ServerError { status: 429, body }
                if body == "retry later"
        ));
    }

    #[test]
    fn shared_error_mapper_preserves_server_404_as_typed_server_error() {
        // Recovery matches typed 404/410 responses to enter first-responder
        // bootstrap. Flattening this to Api(String) would bypass that path.
        let mapped = super::bridge_error_to_internal(OrchestratorBridgeError::ServerError {
            status: 404,
            body: "{\"error\":\"NotFound\"}".into(),
        });

        assert!(matches!(
            mapped,
            crate::orchestrator::error::OrchestratorError::ServerError { status: 404, body }
                if body == "{\"error\":\"NotFound\"}"
        ));
    }

    #[test]
    fn shared_error_mapper_preserves_specific_bridge_error_variants() {
        use crate::orchestrator::error::OrchestratorError;

        let cases = [
            (
                OrchestratorBridgeError::ConversationNotFound { id: "c1".into() },
                "conversation-not-found",
            ),
            (
                OrchestratorBridgeError::EpochMismatch {
                    local: 7,
                    remote: 9,
                },
                "epoch-mismatch",
            ),
            (
                OrchestratorBridgeError::RecoveryFailed {
                    message: "reset rejected".into(),
                },
                "recovery-failed",
            ),
            (
                OrchestratorBridgeError::InvalidInput {
                    message: "bad group id".into(),
                },
                "invalid-input",
            ),
            (
                OrchestratorBridgeError::ConversationQuarantined {
                    convo_id: "c2".into(),
                    reason: "peer_bad_commit".into(),
                },
                "conversation-quarantined",
            ),
        ];

        for (bridge, expected) in cases {
            let internal = super::bridge_error_to_internal(bridge);
            let actual = match internal {
                OrchestratorError::ConversationNotFound(id) if id == "c1" => {
                    "conversation-not-found"
                }
                OrchestratorError::EpochMismatch {
                    local: 7,
                    remote: 9,
                } => "epoch-mismatch",
                OrchestratorError::RecoveryFailed(message) if message == "reset rejected" => {
                    "recovery-failed"
                }
                OrchestratorError::InvalidInput(message) if message == "bad group id" => {
                    "invalid-input"
                }
                OrchestratorError::ConversationQuarantined { convo_id, reason }
                    if convo_id == "c2" && reason == "peer_bad_commit" =>
                {
                    "conversation-quarantined"
                }
                other => panic!("specific bridge error was flattened: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn specific_bridge_errors_round_trip_with_exact_payloads() {
        let round_trip = |bridge| {
            let internal = super::bridge_error_to_internal(bridge);
            OrchestratorBridgeError::from(internal)
        };

        assert!(matches!(
            round_trip(OrchestratorBridgeError::ConversationNotFound {
                id: "conversation-123".into()
            }),
            OrchestratorBridgeError::ConversationNotFound { id }
                if id == "conversation-123"
        ));
        assert!(matches!(
            round_trip(OrchestratorBridgeError::EpochMismatch {
                local: 41,
                remote: 42
            }),
            OrchestratorBridgeError::EpochMismatch {
                local: 41,
                remote: 42
            }
        ));
        assert!(matches!(
            round_trip(OrchestratorBridgeError::RecoveryFailed {
                message: "reset rejected".into()
            }),
            OrchestratorBridgeError::RecoveryFailed { message }
                if message == "reset rejected"
        ));
        assert!(matches!(
            round_trip(OrchestratorBridgeError::InvalidInput {
                message: "bad group id".into()
            }),
            OrchestratorBridgeError::InvalidInput { message }
                if message == "bad group id"
        ));
        assert!(matches!(
            round_trip(OrchestratorBridgeError::ConversationQuarantined {
                convo_id: "conversation-456".into(),
                reason: "peer_bad_commit".into()
            }),
            OrchestratorBridgeError::ConversationQuarantined { convo_id, reason }
                if convo_id == "conversation-456" && reason == "peer_bad_commit"
        ));
    }

    #[test]
    fn shared_error_mapper_preserves_device_limit_error_class() {
        let mapped = super::bridge_error_to_internal(OrchestratorBridgeError::DeviceLimitReached);
        assert!(matches!(
            mapped,
            crate::orchestrator::error::OrchestratorError::DeviceLimitReached { .. }
        ));
    }
}
