//! Consolidated MLS recovery policy (`Spec §5`: sibling-leaf recovery first; NEVER automated external-commit rejoin).

pub mod coordinator;

pub use coordinator as ladder;
