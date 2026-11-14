use std::str::Utf8Error;
use thiserror::Error;

const EXTERNAL_JOIN_PROPOSAL_AUTHORIZATION_OPERATION: &str = "external_join_proposal";

/// P2: Comprehensive error enum with detailed variants for better debugging
#[derive(Error, Debug)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Error))]
#[cfg_attr(not(target_arch = "wasm32"), uniffi(flat_error))]
pub enum MLSError {
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Group not found: {message}")]
    GroupNotFound { message: String },

    #[error("Direct request Welcome import deadline has passed")]
    RequestImportExpired,

    #[error("Invalid key package")]
    InvalidKeyPackage,

    #[error("Failed to add members: {message}")]
    AddMembersFailed { message: String },

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Serialization error")]
    SerializationError,

    #[error("OpenMLS error")]
    OpenMLSError,

    #[error("Invalid group ID")]
    InvalidGroupId,

    #[error("Secret export failed")]
    SecretExportFailed,

    #[error("Commit processing failed: {message}")]
    CommitProcessingFailed { message: String },

    #[error("Invalid commit")]
    InvalidCommit,

    #[error("Invalid data")]
    InvalidData,

    #[error("Context not initialized")]
    ContextNotInitialized,

    #[error("Context closed - database connections were released (app suspension or account switch); reopen the context for the active account")]
    ContextClosed,

    #[error("Wire format policy violation: {message}")]
    WireFormatPolicyViolation { message: String },

    #[error("Merge failed")]
    MergeFailed,

    #[error("No matching key package found: {message}")]
    NoMatchingKeyPackage { message: String },

    #[error("Key package desync detected for conversation {convo_id}: {message}")]
    KeyPackageDesyncDetected { convo_id: String, message: String },

    #[error("Welcome message already consumed or invalid")]
    WelcomeConsumed,

    #[error("Storage error")]
    StorageError,

    #[error("Storage operation failed")]
    StorageFailed,

    // Member operation errors
    #[error("Member not found in group: {member_id}")]
    MemberNotFound { member_id: String },

    #[error("Cannot remove last admin from group")]
    CannotRemoveLastAdmin,

    #[error("Insufficient permissions: {operation}")]
    InsufficientPermissions { operation: String },

    // Proposal errors
    #[error("Invalid proposal reference")]
    InvalidProposalRef,

    // Lock poisoning error
    #[error("Internal lock poisoned: {message}")]
    LockPoisoned { message: String },

    // P2: Additional error variants for FFI with detailed context
    /// Null pointer passed where non-null was expected
    #[error("Null pointer: {0}")]
    NullPointer(&'static str),

    /// Invalid context handle
    #[error("Invalid context handle")]
    InvalidContext,

    /// TLS codec error with details
    #[error("TLS codec error: {0}")]
    TlsCodec(String),

    /// OpenMLS error with details
    #[error("OpenMLS: {0}")]
    OpenMLS(String),

    /// Internal error for unexpected states
    #[error("Internal error: {0}")]
    Internal(String),

    /// Invalid UTF-8 string
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] Utf8Error),

    /// JSON serialization error
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Thread safety error (lock contention, etc.)
    #[error("Thread safety: {0}")]
    ThreadSafety(String),

    /// Panic occurred (caught at FFI boundary)
    #[error("Internal panic: {0}")]
    Panic(String),

    #[error("Operation not supported: {reason}")]
    OperationNotSupported { reason: String },

    /// Invalid argument supplied to an FFI / public API call (e.g. wrong
    /// byte length for a fixed-size key). Mirrors `InvalidInput` but uses a
    /// single positional field for terse call sites in
    /// `mls_context::set_content_root_key` and similar.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Caller invoked an operation that requires state which has not been
    /// initialised yet (e.g. encrypting a payload before the content root
    /// key has been set).
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Cryptography (AEAD / HKDF / HMAC) error surfaced from
    /// `crate::field_encryption` across the FFI boundary.
    #[error("Cryptography error: {0}")]
    Cryptography(String),

    /// Fencing mismatch between the epoch the server advanced to and the
    /// epoch the locally-staged commit would produce. Returned by
    /// `confirm_commit` when `server_epoch` does not equal the plan's
    /// `target_epoch` (and is not [`crate::SKIP_SERVER_EPOCH_FENCE`]). The
    /// caller must discard the staged commit and re-sync before retrying.
    #[error("Epoch mismatch: local={local}, remote={remote}")]
    EpochMismatch { local: u64, remote: u64 },

    /// A peer's valid device signature proves that it sent from a different MLS state at this
    /// device's current epoch. The entry is not decrypted, stored, or acknowledged.
    #[error("fork detected for conversation {conversation_id} at generation {generation}, epoch {epoch}")]
    ForkDetected {
        conversation_id: String,
        generation: i64,
        epoch: i64,
    },

    /// This device holds no verified roster of `conversation_id` (it learned none from the
    /// conversation's creation, a verified reset or a recovery Welcome's roster attestation), so
    /// it can establish neither admin authority nor a zero-leaf participant's entitlement there.
    #[error("no verified roster for conversation {conversation_id}")]
    RosterUnverified { conversation_id: String },

    /// `sync` reconciled every conversation it could; `applied` counts what the conversations
    /// that finished applied. Each listed conversation stopped at a step that did not verify or
    /// apply, with its cursor and acknowledgement still below that step. No failure is dropped.
    #[error("sync incomplete ({applied} applied): {}", describe_sync_failures(.failures))]
    SyncIncomplete {
        applied: u32,
        failures: Vec<ConversationSyncFailure>,
    },
    /// A valid, coordinate-bound recovery request named a participant for which this device has
    /// neither a current same-account leaf nor member-authenticated admission authority.
    #[error(
        "no member-authenticated admission proof for participant {participant_did} in conversation {conversation_id}"
    )]
    AdmissionProofUnavailable {
        conversation_id: String,
        participant_did: String,
    },
    /// A retained creation is waiting for its bounded retry deadline.
    #[error("group creation {conversation_id} is pending until {retry_at_ms} ({last_error_code})")]
    GroupCreationPending {
        conversation_id: String,
        retry_at_ms: i64,
        last_error_code: String,
    },
    /// A retained creation needs an explicit user decision before it can continue.
    #[error("group creation {conversation_id} needs user action: {reason}")]
    GroupCreationNeedsUserAction {
        conversation_id: String,
        reason: String,
    },
    /// The sequencer proved that this retained creation cannot be completed.
    #[error("group creation {conversation_id} was rejected: {code}")]
    GroupCreationRejected {
        conversation_id: String,
        code: String,
    },
    /// Cancellation could not prove that no server-side conversation exists.
    #[error("cannot cancel group creation {conversation_id}: {reason}")]
    GroupCreationCancellationUnproven {
        conversation_id: String,
        reason: String,
    },
    /// The whole encrypted client database predates or exceeds this build's storage contract.
    /// Refuse it before any operation; the app must wipe local state and re-enrol.
    #[error(
        "local state format {found} is unsupported; format {required} is required (wipe and re-enrol)"
    )]
    LocalStateFormatUnsupported { found: u32, required: u32 },

    /// This 2nd+ enrolled device is awaiting existing-device approval (`pending_approval`)
    /// or Labyrinth pairing/recovery unlock before chat mutations or leaf fulfillment proceed.
    #[error("DevicePendingApproval: {reason}")]
    PendingDeviceAccess { reason: String },
}

/// One conversation `sync` could not finish, and why.
#[derive(Debug)]
pub struct ConversationSyncFailure {
    pub conversation_id: String,
    pub error: Box<MLSError>,
}

fn describe_sync_failures(failures: &[ConversationSyncFailure]) -> String {
    failures
        .iter()
        .map(|failure| {
            format!(
                "conversation {}: {}",
                failure.conversation_id, failure.error
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

impl From<crate::metadata::MetadataError> for MLSError {
    fn from(err: crate::metadata::MetadataError) -> Self {
        Self::Cryptography(err.to_string())
    }
}

impl MLSError {
    /// Exact XRPC stale-coordinate classification; HTTP status alone is not a protocol code.
    pub(crate) fn is_stale_coordinates(&self) -> bool {
        matches!(self, Self::InvalidState(code) if code == "StaleCoordinates")
    }

    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: msg.into(),
        }
    }

    pub fn group_not_found(msg: impl Into<String>) -> Self {
        Self::GroupNotFound {
            message: msg.into(),
        }
    }

    pub fn wire_format_policy_violation(msg: impl Into<String>) -> Self {
        Self::WireFormatPolicyViolation {
            message: msg.into(),
        }
    }

    pub fn no_matching_key_package(msg: impl Into<String>) -> Self {
        Self::NoMatchingKeyPackage {
            message: msg.into(),
        }
    }

    pub fn key_package_desync_detected(
        convo_id: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::KeyPackageDesyncDetected {
            convo_id: convo_id.into(),
            message: msg.into(),
        }
    }

    pub fn member_not_found(member_id: impl Into<String>) -> Self {
        Self::MemberNotFound {
            member_id: member_id.into(),
        }
    }

    pub fn insufficient_permissions(operation: impl Into<String>) -> Self {
        Self::InsufficientPermissions {
            operation: operation.into(),
        }
    }

    pub fn lock_poisoned(msg: impl Into<String>) -> Self {
        Self::LockPoisoned {
            message: msg.into(),
        }
    }

    pub fn commit_processing_failed(msg: impl Into<String>) -> Self {
        Self::CommitProcessingFailed {
            message: msg.into(),
        }
    }

    /// A valid MLS ExternalJoinProposal was rejected because the application
    /// has not supplied an authorization decision for the outsider. This is a
    /// fail-closed policy result, not evidence that local crypto state forked.
    pub fn external_join_proposal_authorization_required() -> Self {
        Self::InsufficientPermissions {
            operation: EXTERNAL_JOIN_PROPOSAL_AUTHORIZATION_OPERATION.to_string(),
        }
    }

    /// Distinguish the deterministic ExternalJoinProposal policy rejection
    /// from unrelated permission and unsupported-operation errors. Recovery
    /// classifiers must not count this rejection as local MLS divergence.
    pub fn is_external_join_proposal_authorization_rejection(&self) -> bool {
        matches!(
            self,
            Self::InsufficientPermissions { operation }
                if operation == EXTERNAL_JOIN_PROPOSAL_AUTHORIZATION_OPERATION
        )
    }

    /// Whether this error is an OpenMLS `ValidationError(WrongEpoch)` — i.e. the
    /// ciphertext belongs to an MLS epoch we cannot decrypt (typically a commit
    /// from before our external-commit join, a stale replay, or a message from
    /// an epoch we've already advanced past). These are NORMAL during sync
    /// catch-up and MUST NOT count as "decrypt failures" for fork-detection or
    /// rejoin purposes — treating them as failures destroys local group state
    /// and causes send-break spirals.
    pub fn is_wrong_epoch(&self) -> bool {
        match self {
            Self::OpenMLS(msg) => msg.contains("WrongEpoch"),
            Self::CommitProcessingFailed { message } => message.contains("WrongEpoch"),
            _ => false,
        }
    }

    /// Whether this error represents an OpenMLS WrongGroupId rejection (e.g.
    /// an entry from a superseded generation after a conversation reset).
    /// These are NORMAL during sync catch-up when reading historical entries
    /// across reset boundaries and MUST NOT cause send/sync to fail.
    pub fn is_wrong_group_id(&self) -> bool {
        match self {
            Self::OpenMLS(msg) => msg.contains("WrongGroupId"),
            Self::CommitProcessingFailed { message } => message.contains("WrongGroupId"),
            _ => false,
        }
    }

    /// Whether OpenMLS rejected a decrypt because the generation secret was
    /// already punctured. This is not, by itself, proof that the corresponding
    /// delivery-service envelope reached durable application storage: an
    /// overlapping pipeline may have consumed the secret and then failed its
    /// final storage write.
    pub fn is_secret_reuse(&self) -> bool {
        let matches = |msg: &str| msg.contains("SecretReuse");
        match self {
            Self::OpenMLS(msg) => matches(msg),
            Self::CommitProcessingFailed { message } => matches(message),
            _ => false,
        }
    }
}

/// Dedicated error type for the sender-side three-phase commit surface on
/// [`crate::api::MLSContext`] (`stage_commit`, `confirm_commit`,
/// `discard_pending`).
///
/// [`MLSError`] itself is annotated with `#[uniffi(flat_error)]`, which
/// collapses every variant to `{ message: String }` across the UniFFI
/// boundary. That made `EpochMismatch { local, remote }` — the one
/// `MLSError` variant whose structured fields callers actually need to
/// branch on — unreachable from Swift/Kotlin without string parsing.
///
/// Rather than unflatten `MLSError` (which has variants carrying
/// `Utf8Error`, `serde_json::Error`, and `&'static str` that aren't
/// UniFFI-representable), this narrower type is used only by the
/// three-phase commit methods so iOS and catmos-cli can pattern-match on
/// the structured [`MLSCommitError::EpochMismatch`] variant. See
/// `docs/TODO.md` task #63.
#[derive(Error, Debug, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Error))]
pub enum MLSCommitError {
    /// Fencing mismatch between the epoch the server advanced to and the
    /// epoch the locally-staged commit would produce. Returned by
    /// `MLSContext::confirm_commit` when `server_epoch` does not equal
    /// the plan's `target_epoch` (and is not
    /// `crate::api::SKIP_SERVER_EPOCH_FENCE`). The caller must discard
    /// the staged commit and re-sync before retrying.
    #[error("Epoch mismatch: local={local}, remote={remote}")]
    EpochMismatch { local: u64, remote: u64 },

    /// Catch-all wrapping any other [`MLSError`] the underlying OpenMLS
    /// call can surface. The `message` field is the `Display` form of
    /// the original error.
    #[error("{message}")]
    Generic { message: String },
}

impl From<MLSError> for MLSCommitError {
    fn from(e: MLSError) -> Self {
        match e {
            MLSError::EpochMismatch { local, remote } => {
                MLSCommitError::EpochMismatch { local, remote }
            }
            other => MLSCommitError::Generic {
                message: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod decrypt_class_tests {
    use super::{ConversationSyncFailure, MLSCommitError, MLSError};
    use crate::client::{PendingGroupCreationState, PendingGroupCreationStatus};
    use crate::push::NotificationPreview;

    // The exact `{:?}` forms `map_process_message_error`'s catch-all arm
    // produces for OpenMLS `process_message` failures (see api.rs:297).
    const SECRET_REUSE: &str =
        "process_message failed: ValidationError(UnableToDecrypt(SecretTreeError(SecretReuseError)))";
    const WRONG_EPOCH: &str = "process_message failed: ValidationError(WrongEpoch)";

    #[test]
    fn secret_reuse_classifier_matches_expected_forms() {
        assert!(MLSError::OpenMLS(SECRET_REUSE.into()).is_secret_reuse());
        assert!(MLSError::CommitProcessingFailed {
            message: SECRET_REUSE.into(),
        }
        .is_secret_reuse());
    }

    #[test]
    fn wrong_epoch_and_real_failures_are_not_benign() {
        // WrongEpoch has its own silent-skip arm — it must NOT also be
        // claimed by the benign-redundant classifier (different semantics).
        assert!(!MLSError::OpenMLS(WRONG_EPOCH.into()).is_secret_reuse());
        assert!(MLSError::OpenMLS(WRONG_EPOCH.into()).is_wrong_epoch());
        // A genuine decrypt failure must still count toward rejoin.
        assert!(!MLSError::OpenMLS(
            "process_message failed: ValidationError(UnableToDecrypt(AeadError))".into()
        )
        .is_secret_reuse());
        assert!(!MLSError::InvalidCommit.is_secret_reuse());
    }

    #[test]
    fn wrong_group_id_classifier_matches_openmls_form() {
        assert!(
            MLSError::OpenMLS("process_message failed: ValidationError(WrongGroupId)".into())
                .is_wrong_group_id()
        );
        assert!(MLSError::CommitProcessingFailed {
            message: "process_message failed: ValidationError(WrongGroupId)".into(),
        }
        .is_wrong_group_id());
        assert!(!MLSError::OpenMLS(WRONG_EPOCH.into()).is_wrong_group_id());
    }

    #[test]
    fn external_join_policy_rejection_has_a_narrow_typed_classifier() {
        assert!(MLSError::external_join_proposal_authorization_required()
            .is_external_join_proposal_authorization_rejection());
        assert!(!MLSError::insufficient_permissions("remove_member")
            .is_external_join_proposal_authorization_rejection());
        assert!(!MLSError::OperationNotSupported {
            reason: "unrelated backend capability".to_string(),
        }
        .is_external_join_proposal_authorization_rejection());
    }

    #[test]
    fn stale_coordinate_classifier_requires_the_exact_protocol_error() {
        assert!(MLSError::InvalidState("StaleCoordinates".into()).is_stale_coordinates());
        assert!(
            !MLSError::InvalidState("unrelated StaleCoordinates detail".into())
                .is_stale_coordinates()
        );
        assert!(!MLSError::Internal("HTTP 409: StaleCoordinates".into()).is_stale_coordinates());
    }
    fn append_lowered<T: uniffi::Lower<crate::UniFfiTag>>(bytes: &mut Vec<u8>, value: T) {
        <T as uniffi::Lower<crate::UniFfiTag>>::write(value, bytes);
    }

    fn lower_bytes<T: uniffi::Lower<crate::UniFfiTag>>(value: T) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_lowered(&mut bytes, value);
        bytes
    }

    #[test]
    fn exported_round4_record_field_order_is_append_only() {
        let preview = NotificationPreview {
            message_id: "message".into(),
            conversation_id: "conversation".into(),
            sender_did: "sender".into(),
            sender_display_name: Some("display".into()),
            group_title: Some("group".into()),
            body: "body".into(),
            epoch: 11,
            seq: 12,
            from_cache: true,
            fallback_generic: false,
            darwin_notification_name: "darwin".into(),
            receipt_verified: true,
            is_own_sibling_sender: false,
        };
        let mut expected_preview = Vec::new();
        append_lowered(&mut expected_preview, preview.message_id.clone());
        append_lowered(&mut expected_preview, preview.conversation_id.clone());
        append_lowered(&mut expected_preview, preview.sender_did.clone());
        append_lowered(&mut expected_preview, preview.sender_display_name.clone());
        append_lowered(&mut expected_preview, preview.group_title.clone());
        append_lowered(&mut expected_preview, preview.body.clone());
        append_lowered(&mut expected_preview, preview.epoch);
        append_lowered(&mut expected_preview, preview.seq);
        append_lowered(&mut expected_preview, preview.from_cache);
        append_lowered(&mut expected_preview, preview.fallback_generic);
        append_lowered(
            &mut expected_preview,
            preview.darwin_notification_name.clone(),
        );
        append_lowered(&mut expected_preview, preview.receipt_verified);
        append_lowered(&mut expected_preview, preview.is_own_sibling_sender);
        assert_eq!(lower_bytes(preview), expected_preview);

        let status = PendingGroupCreationStatus {
            conversation_id: "conversation".into(),
            state: PendingGroupCreationState::NeedsUserAction,
            retry_at_ms: Some(13),
            last_error_code: Some("error".into()),
        };
        let mut expected_status = Vec::new();
        append_lowered(&mut expected_status, status.conversation_id.clone());
        append_lowered(&mut expected_status, status.state.clone());
        append_lowered(&mut expected_status, status.retry_at_ms);
        append_lowered(&mut expected_status, status.last_error_code.clone());
        assert_eq!(lower_bytes(status), expected_status);
    }

    fn uniffi_discriminant<T: uniffi::Lower<crate::UniFfiTag>>(value: T) -> i32 {
        let mut bytes = Vec::new();
        <T as uniffi::Lower<crate::UniFfiTag>>::write(value, &mut bytes);
        i32::from_be_bytes(bytes[..4].try_into().expect("UniFFI enum discriminant"))
    }

    #[test]
    fn exported_error_discriminants_are_append_only() {
        let invalid_utf8 = vec![0xff];
        let utf8 = std::str::from_utf8(&invalid_utf8).unwrap_err();
        let json = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let errors = [
            MLSError::InvalidInput {
                message: "x".into(),
            },
            MLSError::GroupNotFound {
                message: "x".into(),
            },
            MLSError::RequestImportExpired,
            MLSError::InvalidKeyPackage,
            MLSError::AddMembersFailed {
                message: "x".into(),
            },
            MLSError::EncryptionFailed,
            MLSError::DecryptionFailed,
            MLSError::SerializationError,
            MLSError::OpenMLSError,
            MLSError::InvalidGroupId,
            MLSError::SecretExportFailed,
            MLSError::CommitProcessingFailed {
                message: "x".into(),
            },
            MLSError::InvalidCommit,
            MLSError::InvalidData,
            MLSError::ContextNotInitialized,
            MLSError::ContextClosed,
            MLSError::WireFormatPolicyViolation {
                message: "x".into(),
            },
            MLSError::MergeFailed,
            MLSError::NoMatchingKeyPackage {
                message: "x".into(),
            },
            MLSError::KeyPackageDesyncDetected {
                convo_id: "x".into(),
                message: "x".into(),
            },
            MLSError::WelcomeConsumed,
            MLSError::StorageError,
            MLSError::StorageFailed,
            MLSError::MemberNotFound {
                member_id: "x".into(),
            },
            MLSError::CannotRemoveLastAdmin,
            MLSError::InsufficientPermissions {
                operation: "x".into(),
            },
            MLSError::InvalidProposalRef,
            MLSError::LockPoisoned {
                message: "x".into(),
            },
            MLSError::NullPointer("x"),
            MLSError::InvalidContext,
            MLSError::TlsCodec("x".into()),
            MLSError::OpenMLS("x".into()),
            MLSError::Internal("x".into()),
            MLSError::InvalidUtf8(utf8),
            MLSError::Serialization(json),
            MLSError::ThreadSafety("x".into()),
            MLSError::Panic("x".into()),
            MLSError::OperationNotSupported { reason: "x".into() },
            MLSError::InvalidArgument("x".into()),
            MLSError::InvalidState("x".into()),
            MLSError::Cryptography("x".into()),
            MLSError::EpochMismatch {
                local: 1,
                remote: 2,
            },
            MLSError::ForkDetected {
                conversation_id: "x".into(),
                generation: 1,
                epoch: 2,
            },
            MLSError::RosterUnverified {
                conversation_id: "x".into(),
            },
            MLSError::SyncIncomplete {
                applied: 0,
                failures: vec![ConversationSyncFailure {
                    conversation_id: "x".into(),
                    error: Box::new(MLSError::InvalidState("x".into())),
                }],
            },
            MLSError::AdmissionProofUnavailable {
                conversation_id: "x".into(),
                participant_did: "did:plc:x".into(),
            },
            MLSError::GroupCreationPending {
                conversation_id: "x".into(),
                retry_at_ms: 1,
                last_error_code: "x".into(),
            },
            MLSError::GroupCreationNeedsUserAction {
                conversation_id: "x".into(),
                reason: "x".into(),
            },
            MLSError::GroupCreationRejected {
                conversation_id: "x".into(),
                code: "x".into(),
            },
            MLSError::GroupCreationCancellationUnproven {
                conversation_id: "x".into(),
                reason: "x".into(),
            },
            MLSError::LocalStateFormatUnsupported {
                found: 0,
                required: 1,
            },
            MLSError::PendingDeviceAccess { reason: "x".into() },
        ];
        for (index, error) in errors.into_iter().enumerate() {
            assert_eq!(
                uniffi_discriminant(error),
                i32::try_from(index + 1).unwrap()
            );
        }

        assert_eq!(
            uniffi_discriminant(MLSCommitError::EpochMismatch {
                local: 1,
                remote: 2,
            }),
            1
        );
        assert_eq!(
            uniffi_discriminant(MLSCommitError::Generic {
                message: "x".into(),
            }),
            2
        );
    }
}
