use thiserror::Error;

/// Errors that can occur during MLS orchestration operations.
#[derive(Error, Debug)]
pub enum OrchestratorError {
    #[error("MLS FFI error: {0}")]
    Mls(#[from] crate::MLSError),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("Credential error: {0}")]
    Credential(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Group not found: {0}")]
    GroupNotFound(String),

    #[error("Conversation not found: {0}")]
    ConversationNotFound(String),

    #[error("Epoch mismatch: local={local}, remote={remote}")]
    EpochMismatch { local: u64, remote: u64 },

    #[error("Member already exists: {0}")]
    MemberAlreadyExists(String),

    #[error("Member sync failed")]
    MemberSyncFailed,

    #[error("Device limit reached: {current}/{max}")]
    DeviceLimitReached { current: u32, max: u32 },

    #[error("Key package exhausted")]
    KeyPackageExhausted,

    #[error("Duplicate message: {0}")]
    DuplicateMessage(String),

    #[error("Shutting down")]
    ShuttingDown,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Server error: status={status}, body={body}")]
    ServerError { status: u16, body: String },

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Sync paused: circuit breaker tripped after consecutive failures")]
    SyncPaused,
}

pub type Result<T> = std::result::Result<T, OrchestratorError>;
