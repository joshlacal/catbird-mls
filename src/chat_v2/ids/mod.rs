//! Canonical identifier and scalar types for the clean chat protocol.
//!
//! Every parser here rejects rather than normalizes, per CHAT_PROTOCOL.md §2.
//!
//! The generated transport types make `conversationId`, `entryId`,
//! `transitionId`, `deviceId` and friends all the *same* Rust type (each is a
//! transparent alias to the string backing). The protocol's central invariants
//! are precisely that these never substitute for one another — an append row's
//! `entryId` is a replay identity and can never stand in for a signed
//! `transitionId`, and a same-DID sibling device can never satisfy an
//! exact-device check. Reintroducing real newtypes here moves those invariants
//! from review discipline to compiler enforcement.

pub mod credential;
pub mod did;
pub mod key_id;
pub mod seq;
pub mod timestamp;
pub mod uuid;

pub use credential::{
    BasicCredential, CredentialError, BASIC_CREDENTIAL_MAX_LEN, BASIC_CREDENTIAL_MIN_LEN,
};
pub use did::{
    validate_domain_labels, validate_handle_hostname, validate_tld_label, BareDid, DidError,
    DidMethod, BARE_DID_MAX_LEN, BARE_DID_MIN_LEN, LABEL_MAX_LEN, RESERVED_TLDS,
};
pub use key_id::{KeyId, KeyIdError, ED25519_PUBLIC_KEY_LEN, KEY_ID_LEN};
pub use seq::{IntegerError, SafeInteger, Seq, MAX_SAFE_INTEGER};
pub use timestamp::{CanonicalTimestamp, TimestampError, CANONICAL_TIMESTAMP_LEN};
pub use uuid::{
    BlobId, CanonicalUuid, ConversationId, DeviceId, EntryId, IdempotencyKey, LeaveRequestId,
    MessageId, RecoveryRequestId, RecoveryWorkId, ResetRequestId, TransitionId, TypingId,
    UuidError, WelcomeId, CANONICAL_UUID_LEN,
};
