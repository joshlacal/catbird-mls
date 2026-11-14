//! Errors for E2EE Circles.

/// Failure while building, sealing, or opening Circle records.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CircleError {
    #[error("recipient {did} failed verification: {reason}")]
    UnverifiedRecipient { did: String, reason: String },
    #[error("too many recipients: {0} > 512")]
    TooManyRecipients(usize),
    #[error("malformed record: {0}")]
    Malformed(String),
    #[error("header does not match sealed payload")]
    HeaderMismatch,
    #[error("signature invalid")]
    BadSignature,
    /// The key record's sender is not bound to the Circle owner (wrong DID,
    /// or an epoch head not among the directory-verified owner heads), or its
    /// embedded epoch fails self-verification.
    #[error("untrusted sender: {reason}")]
    UntrustedSender { reason: String },
    #[error("crypto: {0}")]
    Crypto(String),
}
