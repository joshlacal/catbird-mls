//! Where a device keeps its Labyrinth client state ([CB-30]).
//!
//! `Labyrinth::export_state` returns the device's private keys, epoch
//! secrets, MEKs, revoked set and peer pins, so the blob lives in the
//! encrypted per-account SQLite database (`account_meta` via
//! [`MlsCryptoContext::compare_exchange_request_value`]) under
//! [`STATE_NAMESPACE`], keyed by the account DID.

use std::sync::Arc;

use labyrinth::store::{MaybeSend, MaybeSync};

use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::MLSError;

/// Request-value namespace of the Labyrinth client state.
pub const STATE_NAMESPACE: &str = "labyrinthClientState";

/// Secure storage for one blob per account.
pub trait StateVault: MaybeSend + MaybeSync {
    fn load(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError>;
    /// Checks whether a state blob exists for `did` without leaving an
    /// unzeroized copy of secret key material on the heap.
    fn has_state(&self, did: &str) -> Result<bool, MLSError> {
        Ok(self.load_zeroizing(did)?.is_some())
    }
    /// Loads the account's secret blob wrapped in [`zeroize::Zeroizing`].
    fn load_zeroizing(&self, did: &str) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, MLSError> {
        Ok(self.load(did)?.map(zeroize::Zeroizing::new))
    }
    /// Writes `next` if the stored value is still `expected`; false if not.
    fn compare_exchange(
        &self,
        did: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError>;
    /// Erases the account's blob (sign-out, account removal). Idempotent.
    fn delete(&self, did: &str) -> Result<(), MLSError>;
}

/// [`StateVault`] in the encrypted MLS database.
pub struct MlsStateVault<M>(pub Arc<M>);

impl<M: MlsCryptoContext + 'static> MlsStateVault<M> {
    pub fn has_state(&self, did: &str) -> Result<bool, MLSError> {
        self.0.has_request_value(STATE_NAMESPACE, did)
    }
}

impl<M: MlsCryptoContext + 'static> StateVault for MlsStateVault<M> {
    fn load(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.0.read_request_value(STATE_NAMESPACE, did)
    }

    fn has_state(&self, did: &str) -> Result<bool, MLSError> {
        self.0.has_request_value(STATE_NAMESPACE, did)
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

    fn delete(&self, did: &str) -> Result<(), MLSError> {
        self.0
            .delete_request_value(STATE_NAMESPACE, did)
            .map(|_| ())
    }
}
