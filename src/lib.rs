#![allow(
    dead_code,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::module_inception
)]
pub mod blob_crypto;
/// Clean chat protocol (`blue.catbird.chat.*`). Isolated from `orchestrator`;
/// the two protocols never interoperate.
pub mod chat_v2;
pub mod client;
#[cfg(not(target_arch = "wasm32"))]
pub mod engine;
#[cfg(not(target_arch = "wasm32"))]
mod epoch_storage;
mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;
pub mod field_encryption;
pub mod groups;
#[cfg(not(target_arch = "wasm32"))]
mod keychain;
#[cfg(feature = "labyrinth")]
pub mod labyrinth;
pub mod logging;
mod message_limits;
pub mod messaging;
pub mod metadata;
#[cfg(not(target_arch = "wasm32"))]
mod mls_context;
#[cfg(not(target_arch = "wasm32"))]
mod mls_engine_context;
pub mod orchestrator;
#[cfg(not(target_arch = "wasm32"))]
pub mod platform_lifecycle;
pub mod push;
pub mod recovery;
pub mod requests;
pub mod routing;
pub mod sim_hooks;
pub mod storage;
pub mod sync;
mod types;
// Voice depends on audiopus which has no wasm32 sysroot.
#[cfg(not(target_arch = "wasm32"))]
pub mod voice;

// ATProto serde helpers (standalone, no external dependency)
pub mod atproto_bytes;

pub use catbird_atproto as atproto;
#[cfg(not(target_arch = "wasm32"))]
pub use client::CatbirdMlsClient;
pub use client::{
    CatbirdMlsClientConfig, PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader,
    PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
};
#[cfg(not(target_arch = "wasm32"))]
pub use engine::*;
pub use error::*;
#[cfg(not(target_arch = "wasm32"))]
pub use keychain::*;
#[cfg(not(target_arch = "wasm32"))]
pub use mls_context::canonical_signer_keychain_key;
#[cfg(not(target_arch = "wasm32"))]
pub use mls_context::validate_serialized_signer_keypair_coherence;
#[cfg(not(target_arch = "wasm32"))]
pub use mls_engine_context::*;
pub use orchestrator::direct_request_types::{
    DirectRequestInput, DirectRequestOutcome, DirectRequestView, GroupInvitationReference,
    RequestCapabilities, RequestConsent, RequestCrypto, RequestIntroductionMetadata,
    RequestPreview,
};
#[cfg(not(target_arch = "wasm32"))]
pub use platform_lifecycle::*;
#[cfg(not(target_arch = "wasm32"))]
pub use push::{process_push_notification, process_push_notification_with_hooks};
#[cfg(not(target_arch = "wasm32"))]
pub use storage::SqlDriver;
pub use types::*;

#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub use mls_context::set_simulate_extension_process_for_test;
#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub use mls_engine_context::set_post_build_key_package_hook;

/// Returns the build identifier for this FFI version.
///
/// Format: "mls-ffi-{version}-{build_timestamp}"
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn get_ffi_build_id() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let timestamp = option_env!("BUILD_TIMESTAMP").unwrap_or("dev");
    format!("mls-ffi-{}-{}", version, timestamp)
}

/// Returns detailed build information for diagnostics.
#[cfg(not(target_arch = "wasm32"))]
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
        "mls-ffi v{} ({}) profile={} | SQLCipher: 96-hex raw+salt, plaintext_header=32, page_size=4096",
        version, timestamp, profile
    )
}

// Synchronous FFI/CLI -> async bridging without a background worker pool (`Spec §6.5` / `G1`).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod async_runtime {
    /// Execute an async operation from synchronous code without a persistent
    /// global Tokio pool (`Spec §4` / `G1`; NSE push decryption never calls this
    /// module). Uses `block_in_place` when already on a multi-thread runtime, or
    /// an ephemeral 2-worker runtime torn down on return so nested synchronous
    /// `block_on` calls inside spawned tasks never starve the outer future.
    pub fn block_on<F>(f: F) -> F::Output
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        let run_ephemeral = |fut: F| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(4)
                .enable_all()
                .build()
                .expect("Failed to create ephemeral async runtime");
            let out = rt.block_on(fut);
            rt.shutdown_background();
            out
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    tokio::task::block_in_place(|| handle.block_on(f))
                }
                _ => std::thread::scope(|s| {
                    s.spawn(|| run_ephemeral(f))
                        .join()
                        .expect("async_runtime::block_on worker panicked")
                }),
            }
        } else {
            run_ephemeral(f)
        }
    }
}

// UniFFI setup
#[cfg(not(target_arch = "wasm32"))]
uniffi::setup_scaffolding!();
#[cfg(test)]
extern crate self as catbird_mls;

#[cfg(test)]
#[path = "../tests/e2e_harness.rs"]
mod recovery_e2e_harness;

#[cfg(test)]
mod runtime_tests {
    #[tokio::test]
    async fn f10_async_runtime_block_on_succeeds_inside_current_thread_tokio_runtime() {
        let out = crate::async_runtime::block_on(async { 42usize });
        assert_eq!(out, 42);
    }
}
