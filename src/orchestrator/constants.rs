// src/orchestrator/constants.rs
//! MLS Client Protocol Spec §10 — canonical constants.
//! All platforms MUST use these exact values.
//! Spec: docs/MLS_CLIENT_PROTOCOL.md

use std::time::Duration;

// §10 Recovery
pub const EPOCH_DIVERGENCE_THRESHOLD: u32 = 5;
pub const DECRYPTION_FAILURE_THRESHOLD: u32 = 3;
pub const MAX_REJOIN_ATTEMPTS: u32 = 3;
pub const GROUPINFO_404_CIRCUIT_BREAKER: u32 = 3;
pub const MIN_REJOIN_INTERVAL: Duration = Duration::from_secs(30);

pub const FORK_DETECTION_THRESHOLD: u32 = 2;
pub const FORK_READD_MAX_ATTEMPTS: u32 = 1;

// §10 Own-Commit TTL
pub const OWN_COMMIT_TTL: Duration = Duration::from_secs(300);

// §10 Send Recovery
pub const SEND_SYNC_BATCH_SIZE: u32 = 50;
pub const SEND_SYNC_MAX_ROUNDS: u32 = 3;

// §10 Sync
pub const SYNC_INTERVAL_SECS: u64 = 5;
pub const SYNC_CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
pub const SYNC_CIRCUIT_BREAKER_BASE_SECS: u64 = 30;
pub const SYNC_CIRCUIT_BREAKER_MAX_SECS: u64 = 300;

// §10 Key Packages
pub const KEY_PACKAGE_TARGET: u32 = 50;
pub const KEY_PACKAGE_LOW_THRESHOLD: u32 = 10;
pub const KEY_PACKAGE_CHECK_INTERVAL_SECS: u64 = 300;

// §10 Rejoin Backoff — indexed by attempt number (0-based)
pub const REJOIN_BACKOFF: [Duration; 3] = [
    Duration::from_secs(30),
    Duration::from_secs(120), // 2 minutes
    Duration::from_secs(600), // 10 minutes
];

// §8.8 Sequencer Failover
pub const FAILOVER_MIN_FAILURES: u32 = 3;
pub const FAILOVER_MIN_DURATION: Duration = Duration::from_secs(120);
