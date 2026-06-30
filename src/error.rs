use std::str::Utf8Error;
use thiserror::Error;

/// P2: Comprehensive error enum with detailed variants for better debugging
#[derive(Error, Debug)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Error))]
#[cfg_attr(not(target_arch = "wasm32"), uniffi(flat_error))]
pub enum MLSError {
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Group not found: {message}")]
    GroupNotFound { message: String },

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

    #[error("Context closed - database connections have been released for iOS suspension")]
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
}

impl MLSError {
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

    /// Whether this decrypt error means the ciphertext was ALREADY successfully
    /// consumed, or is our own outbound message we can never decrypt — i.e. a
    /// benign redundancy, NOT a fork or corruption signal.
    ///
    /// - `SecretReuseError`: OpenMLS punctures each per-message secret-tree leaf
    ///   on successful decrypt (forward secrecy). A *second* decrypt of the SAME
    ///   ciphertext fails with SecretReuse. In practice this happens when
    ///   overlapping fetch / SSE / periodic-sync / catch-up pipelines race past
    ///   the `message_exists` dedup before the first run has stored the row, so
    ///   two threads decrypt the same message and the loser hits the punctured
    ///   leaf. It literally proves we already decrypted the message.
    /// - `CannotDecryptOwnMessage`: our own application message echoed back by
    ///   the delivery service; we hold only the encryption side and never the
    ///   matching ratchet to read it back.
    ///
    /// Both are normal. Counting them as "decrypt failures" hits
    /// `DECRYPTION_FAILURE_THRESHOLD` (3) on active groups, which flips the
    /// conversation to `NeedsRejoin` (sends blocked + the "Secure session needs
    /// repair" banner) and historically drove `force_rejoin` epoch-inflation
    /// spirals. They MUST be skipped silently, exactly like [`Self::is_wrong_epoch`].
    pub fn is_benign_redundant_decrypt(&self) -> bool {
        let matches = |msg: &str| {
            msg.contains("SecretReuse") || msg.contains("CannotDecryptOwnMessage")
        };
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
    use super::MLSError;

    // The exact `{:?}` forms `map_process_message_error`'s catch-all arm
    // produces for OpenMLS `process_message` failures (see api.rs:297).
    const SECRET_REUSE: &str =
        "process_message failed: ValidationError(UnableToDecrypt(SecretTreeError(SecretReuseError)))";
    const OWN_MESSAGE: &str =
        "process_message failed: ValidationError(CannotDecryptOwnMessage)";
    const WRONG_EPOCH: &str =
        "process_message failed: ValidationError(WrongEpoch)";

    #[test]
    fn secret_reuse_and_own_message_are_benign() {
        assert!(MLSError::OpenMLS(SECRET_REUSE.into()).is_benign_redundant_decrypt());
        assert!(MLSError::OpenMLS(OWN_MESSAGE.into()).is_benign_redundant_decrypt());
        assert!(MLSError::CommitProcessingFailed {
            message: SECRET_REUSE.into(),
        }
        .is_benign_redundant_decrypt());
    }

    #[test]
    fn wrong_epoch_and_real_failures_are_not_benign() {
        // WrongEpoch has its own silent-skip arm — it must NOT also be
        // claimed by the benign-redundant classifier (different semantics).
        assert!(!MLSError::OpenMLS(WRONG_EPOCH.into()).is_benign_redundant_decrypt());
        assert!(MLSError::OpenMLS(WRONG_EPOCH.into()).is_wrong_epoch());
        // A genuine decrypt failure must still count toward rejoin.
        assert!(!MLSError::OpenMLS(
            "process_message failed: ValidationError(UnableToDecrypt(AeadError))".into()
        )
        .is_benign_redundant_decrypt());
        assert!(!MLSError::InvalidCommit.is_benign_redundant_decrypt());
    }
}
