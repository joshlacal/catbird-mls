pub mod account_exit;
#[cfg(feature = "legacy-orchestrator")]
mod account_removal;
pub mod admission;
pub mod api_client;
pub mod canonical_transport;
pub mod constants;
pub mod control_journal;
pub mod credential_binding;
pub mod credentials;
pub mod crypto_provider;
#[cfg(feature = "legacy-orchestrator")]
pub mod devices;
#[cfg(feature = "legacy-orchestrator")]
mod direct_adoption;
pub mod direct_request_bootstrap;
pub mod direct_request_journal;
pub mod direct_request_keys;
pub mod direct_request_shared_crypto;
pub mod direct_request_types;
pub mod direct_requests;
pub mod error;
pub mod event_observer;
#[cfg(feature = "legacy-orchestrator")]
pub mod groups;
#[cfg(feature = "legacy-orchestrator")]
mod incoming;
#[cfg(feature = "legacy-orchestrator")]
pub mod key_packages;
#[cfg(feature = "legacy-orchestrator")]
mod leaf_recovery;
#[cfg(feature = "legacy-orchestrator")]
pub mod leave_fulfillment;
pub mod lifecycle;
#[cfg(feature = "legacy-orchestrator")]
pub mod messaging;
#[cfg(feature = "legacy-orchestrator")]
pub(crate) mod metadata_snapshot;
pub mod mls_provider;
#[cfg(feature = "legacy-orchestrator")]
pub mod orchestrator;
#[cfg(feature = "legacy-orchestrator")]
pub mod ordering;
pub(crate) mod pagination;
pub mod projection_commit;
#[cfg(feature = "legacy-orchestrator")]
pub mod recovery;
#[cfg(feature = "legacy-orchestrator")]
pub mod reset_flow;
#[cfg(feature = "legacy-orchestrator")]
pub mod staged_commit;
pub mod storage;
#[cfg(feature = "legacy-orchestrator")]
pub mod sync;
#[cfg(feature = "legacy-orchestrator")]
pub mod terminal_lifecycle;
pub mod types;
pub mod welcome_ack;
pub mod welcome_recovery;

#[cfg(test)]
mod canonical_transport_tests;

#[cfg(all(test, feature = "legacy-orchestrator", not(target_arch = "wasm32")))]
mod local_delete_persistence_tests;
#[cfg(all(test, feature = "legacy-orchestrator", not(target_arch = "wasm32")))]
mod quarantine_persistence_tests;

// Re-exports for convenience
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use api_client::MLSAPIClient;
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use canonical_transport::canonical_application_aad_bytes;
#[cfg(any(test, feature = "test-utils"))]
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use canonical_transport::{
    canonical_application_content, canonical_cbor_for_schema, canonical_metadata_aad_bytes,
    canonical_metadata_content_signing_input, canonical_metadata_exporter_context_bytes,
};
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use canonical_transport::{
    canonical_commit_aad_bytes, canonical_route, map_wire_error, prepare_get_conversations,
    prepare_get_entries, prepare_replenishment, route_for_nsid, CanonicalOperation,
    CleanChatAuthContext, CleanChatError, CleanChatRequest, CleanChatResponse,
    CleanChatSigningContext, GatewayResponse, GatewayTransport, PreparedRequest,
    ReplenishKeyPackagesInput, TransportError,
};
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use canonical_transport::{
    decode_clean_chat_error, decode_clean_chat_response, prepare_clean_chat_request,
    prepare_clean_chat_signed_request, CleanChatAuthContextFfi, CleanChatOperationFfi,
    CleanChatPreparedRequestFfi, CleanChatSigningContextFfi, CleanChatTransportFfiError,
};
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use constants::*;
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use credential_binding::{
    extract_key_package_binding, CredentialVerification, KeyPackageBindingInfo,
};
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use credentials::{CleanChatSigningAuthority, CredentialStore};
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use direct_request_types::*;
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use error::{OrchestratorError, Result};
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use event_observer::EngineEvent;
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use mls_provider::{
    MlsCryptoContext, MlsDecryptOutcome, OwnEchoProof, ReservedApplicationSend,
};
#[cfg(feature = "legacy-orchestrator")]
pub(crate) use orchestrator::{with_batch_inventory_scope, with_batch_recovery_inbox_scope};
#[cfg(feature = "legacy-orchestrator")]
pub use orchestrator::{MLSOrchestrator, OrchestratorConfig};
#[cfg(feature = "legacy-orchestrator")]
pub use recovery::DeferredRecoveryOutcome;
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use storage::MLSStorageBackend;
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use types::*;
#[cfg_attr(not(feature = "legacy-orchestrator"), allow(unused_imports))]
pub use welcome_recovery::*;

pub mod authenticated_inventory;
pub mod subscription;
