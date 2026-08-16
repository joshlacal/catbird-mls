pub mod api_client;
pub(crate) mod canonical_transport;
pub mod constants;
pub mod credential_binding;
pub mod credentials;
pub mod crypto_provider;
pub mod devices;
pub mod error;
pub mod event_observer;
pub mod groups;
pub mod key_packages;
pub mod messaging;
pub mod mls_provider;
pub mod orchestrator;
pub mod ordering;
pub mod recovery;
pub mod staged_commit;
pub mod storage;
pub mod sync;
pub mod types;
pub mod welcome_recovery;

#[cfg(test)]
mod canonical_transport_tests;

// Re-exports for convenience
pub use api_client::MLSAPIClient;
pub use constants::*;
pub use credential_binding::{
    extract_key_package_binding, CredentialVerification, KeyPackageBindingInfo,
};
pub use credentials::CredentialStore;
pub use error::{OrchestratorError, Result};
pub use event_observer::EngineEvent;
pub use mls_provider::MlsCryptoContext;
pub use orchestrator::{MLSOrchestrator, OrchestratorConfig};
pub use storage::MLSStorageBackend;
pub use types::*;
pub use welcome_recovery::*;
