//! Where a device keeps its Labyrinth client state ([CB-30]).
//!
//! `Labyrinth::export_state` returns the device's private keys, epoch
//! secrets, MEKs, revoked set and peer pins, so the blob must live in
//! secure storage. catbird-mls already keeps secret per-account values
//! (direct-request keys, subscription cursors) in the SQLCipher-encrypted
//! MLS database through [`MlsCryptoContext::compare_exchange_request_value`];
//! the Labyrinth state uses the same store under [`STATE_NAMESPACE`], keyed
//! by the account DID. That database is already per-account, and the
//! compare-and-swap stops two processes (app and notification extension)
//! from silently overwriting each other's epoch progress.

use std::sync::Arc;

use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::MLSError;

/// Request-value namespace of the Labyrinth client state.
pub const STATE_NAMESPACE: &str = "labyrinthClientState";

/// Secure storage for one blob per account.
pub trait StateVault: Send + Sync {
    fn load(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError>;
    /// Writes `next` if the stored value is still `expected`; false if not.
    fn compare_exchange(
        &self,
        did: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError>;
}

/// [`StateVault`] in the encrypted MLS database.
pub struct MlsStateVault<M>(pub Arc<M>);

impl<M: MlsCryptoContext + 'static> StateVault for MlsStateVault<M> {
    fn load(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.0.read_request_value(STATE_NAMESPACE, did)
    }

    fn compare_exchange(
        &self,
        did: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        self.0
            .compare_exchange_request_value(STATE_NAMESPACE, did, expected, next)
    }
}
