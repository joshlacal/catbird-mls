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
pub(crate) mod pagination;
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
    canonical_application_aad_bytes, canonical_application_content, canonical_cbor_for_schema,
    canonical_commit_aad_bytes, canonical_metadata_aad_bytes,
    canonical_metadata_content_signing_input, canonical_metadata_exporter_context_bytes,
    canonical_route, decode_clean_chat_blob_response, map_wire_error, prepare_get_conversations,
    prepare_get_entries, prepare_replenishment, route_for_nsid, seal_metadata_with_nonce,
    CanonicalOperation, CleanChatAuthContext, CleanChatError, CleanChatRequest, CleanChatResponse,
    CleanChatSigningContext, GatewayResponse, GatewayTransport, PreparedRequest,
    ReplenishKeyPackagesInput, TransportError,
};
#[cfg(not(target_arch = "wasm32"))]
pub use canonical_transport::{
    decode_clean_chat_blob, decode_clean_chat_error, decode_clean_chat_response,
    prepare_clean_chat_request, prepare_clean_chat_signed_request, CleanChatAuthContextFfi,
    CleanChatOperationFfi, CleanChatPreparedRequestFfi, CleanChatSigningContextFfi,
    CleanChatTransportFfiError,
};
pub use constants::*;
pub use credential_binding::{
    extract_key_package_binding, CredentialVerification, KeyPackageBindingInfo,
};
pub use credentials::{CleanChatSigningAuthority, CredentialStore};
pub use error::{OrchestratorError, Result};
pub use event_observer::EngineEvent;
pub use mls_provider::{MlsCryptoContext, MlsDecryptOutcome, OwnEchoProof};
pub use orchestrator::{MLSOrchestrator, OrchestratorConfig};
pub use storage::MLSStorageBackend;
pub use types::*;
pub use welcome_recovery::*;
