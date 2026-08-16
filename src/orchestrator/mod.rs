pub mod api_client;
pub mod canonical_transport;
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
pub use canonical_transport::{
    canonical_route, decode_clean_chat_blob_response, map_wire_error, prepare_get_conversations,
    prepare_get_entries, prepare_replenishment, route_for_nsid, CanonicalOperation,
    CleanChatAuthContext, CleanChatError, CleanChatRequest, CleanChatResponse, PreparedRequest,
    ReplenishKeyPackagesInput, TransportError,
};
#[cfg(not(target_arch = "wasm32"))]
pub use canonical_transport::{
    decode_clean_chat_blob, decode_clean_chat_error, decode_clean_chat_response,
    prepare_clean_chat_request, prepare_clean_chat_signed_request, CleanChatAuthContextFfi,
    CleanChatOperationFfi, CleanChatPreparedRequestFfi, CleanChatTransportFfiError,
};
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
