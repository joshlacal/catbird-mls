//! The chat device's Ed25519 key as Labyrinth's transport key ([CB-3]).

use std::sync::{Arc, Mutex};

use labyrinth::sign::TransportSigner;
use labyrinth::store::{MaybeSend, MaybeSync};

use crate::orchestrator::mls_provider::MlsCryptoContext;

#[cfg(not(target_arch = "wasm32"))]
use crate::orchestrator::credentials::CredentialStore;

/// Signs with one chat device key.
pub trait ChatKeySigner: MaybeSend + MaybeSync {
    /// The device's Ed25519 public key.
    fn public_key(&self) -> [u8; 32];
    /// An Ed25519 signature over exactly `msg`.
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String>;
}

/// Synchronous identity-key signer backed directly by [`MlsCryptoContext`]
/// (works on both native and `wasm32`).
pub struct ContextIdentitySigner<M> {
    pub(crate) mls_context: Arc<M>,
    pub(crate) user_did: String,
    pub(crate) device_id: String,
    pub(crate) public_key: [u8; 32],
}

impl<M: MlsCryptoContext + 'static> ChatKeySigner for ContextIdentitySigner<M> {
    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        let signature = self
            .mls_context
            .sign_with_identity_key(
                format!("{}#{}", self.user_did, self.device_id).into_bytes(),
                msg.to_vec(),
            )
            .map_err(|e| format!("identity signer failed: {e}"))?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| "chat device signature is not 64 bytes".to_string())?;
        labyrinth::sign::verify_transport(&self.public_key, msg, &signature)
            .map_err(|_| "chat device signature does not verify".to_string())?;
        Ok(signature)
    }
}

/// The chat device key held by the orchestrator's credential store (or,
/// when the store does not sign, by the MLS identity signer).
#[cfg(not(target_arch = "wasm32"))]
pub struct OrchestratorChatSigner<C, M> {
    pub(crate) credentials: Arc<C>,
    pub(crate) mls_context: Arc<M>,
    pub(crate) user_did: String,
    pub(crate) device_id: String,
    pub(crate) key_id: String,
    pub(crate) public_key: [u8; 32],
}

#[cfg(not(target_arch = "wasm32"))]
impl<C, M> ChatKeySigner for OrchestratorChatSigner<C, M>
where
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        let authority = crate::async_runtime::block_on(
            self.credentials
                .sign_clean_chat_transcript(&self.user_did, msg, &self.key_id),
        )
        .map_err(|e| format!("credential signer failed: {e}"))?;
        let signature = match authority {
            Some(a) => {
                if a.device_id != self.device_id || a.public_key != self.public_key {
                    return Err("signing authority is not this chat device".into());
                }
                a.signature
            }
            None => self
                .mls_context
                .sign_with_identity_key(
                    format!("{}#{}", self.user_did, self.device_id).into_bytes(),
                    msg.to_vec(),
                )
                .map_err(|e| format!("identity signer failed: {e}"))?,
        };
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| "chat device signature is not 64 bytes".to_string())?;
        labyrinth::sign::verify_transport(&self.public_key, msg, &signature)
            .map_err(|_| "chat device signature does not verify".to_string())?;
        Ok(signature)
    }
}

/// The first signing failure seen by a [`LatchedTransportSigner`].
#[derive(Clone, Default)]
pub struct SignerFault(Arc<Mutex<Option<String>>>);

impl SignerFault {
    /// Takes the recorded failure, clearing it.
    pub fn take(&self) -> Option<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    fn record(&self, error: String) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(error);
    }
}

/// Adapts a [`ChatKeySigner`] to Labyrinth's infallible signer trait.
pub struct LatchedTransportSigner {
    signer: Arc<dyn ChatKeySigner>,
    fault: SignerFault,
}

impl LatchedTransportSigner {
    pub fn new(signer: Arc<dyn ChatKeySigner>, fault: SignerFault) -> Self {
        Self { signer, fault }
    }
}

impl TransportSigner for LatchedTransportSigner {
    fn transport_public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        match self.signer.sign(msg) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!(error = %e, "labyrinth: chat device signing failed");
                self.fault.record(e);
                [0u8; 64]
            }
        }
    }
}
