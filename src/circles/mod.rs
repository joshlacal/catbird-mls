//! End-to-end encrypted Circles (spec `docs/superpowers/specs/2026-11-07-e2ee-circles-design.md`).
//!
//! `records` holds the serde wire forms matching the `blue.catbird.circle.*` lexicons.

pub mod error;
pub mod keys;
pub mod post;
pub mod records;
