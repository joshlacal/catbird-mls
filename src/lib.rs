mod api;
pub mod client;
pub mod client_bridge;
mod epoch_storage;
mod error;
mod hybrid_storage;
mod keychain;
pub mod logging;
mod mls_context;
pub mod orchestrator;
pub mod orchestrator_bridge;
mod types;

// ATProto serde helpers (standalone, no external dependency)
pub mod atproto_bytes;

pub use api::*;
pub use error::*;
pub use keychain::*;
pub use types::*;

// ═══════════════════════════════════════════════════════════════════════════
// Build ID for verifying correct FFI version is shipped
// ═══════════════════════════════════════════════════════════════════════════

/// Returns the build identifier for this FFI version.
///
/// Call this at app startup in both main app and NSE to verify both processes
/// are using the same FFI binary. Log mismatches as errors.
///
/// Format: "mls-ffi-{version}-{build_timestamp}"
#[uniffi::export]
pub fn get_ffi_build_id() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let timestamp = option_env!("BUILD_TIMESTAMP").unwrap_or("dev");
    format!("mls-ffi-{}-{}", version, timestamp)
}

/// Returns detailed build information for diagnostics.
///
/// Includes:
/// - Version from Cargo.toml
/// - Build timestamp (if set during build)
/// - SQLCipher pragma settings (for verification)
#[uniffi::export]
pub fn get_ffi_build_info() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let timestamp = option_env!("BUILD_TIMESTAMP").unwrap_or("dev");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    format!(
        "mls-ffi v{} ({}) profile={} | SQLCipher: plaintext_header=32, kdf_iter=256000, page_size=4096",
        version, timestamp, profile
    )
}

// Shared async runtime for FFI→async bridging
// Used when synchronous FFI methods need to call async code
pub(crate) mod async_runtime {
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    /// Shared Tokio runtime for async operations at FFI boundary
    pub static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4) // Increased from 2 to reduce contention
            .thread_name("mls-async-worker")
            .enable_all()
            .build()
            .expect("Failed to create async runtime")
    });

    /// Execute an async operation from synchronous code.
    /// Handles the case where we're already inside a tokio runtime
    /// (e.g., when called from catmos/Tauri which has its own runtime).
    pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // We're already inside a tokio runtime — use block_in_place
            // to avoid "Cannot start a runtime from within a runtime" panic
            tokio::task::block_in_place(|| handle.block_on(f))
        } else {
            // Not inside a runtime — use our own
            RUNTIME.block_on(f)
        }
    }
}

// UniFFI setup
uniffi::setup_scaffolding!();
