//! Consolidated MLS messaging pipeline: `I13` `archive_commitment` AAD, `.staged` -> `.space`
//! attachment promotion before MLS send (Gate 5), `[CB-22]` rearchive-before-leave, and
//! `accountDeleted` local message purging.

pub mod attachments;
pub mod receive;
pub mod send;

pub use receive as aad_commitment;
pub use send as acks;
