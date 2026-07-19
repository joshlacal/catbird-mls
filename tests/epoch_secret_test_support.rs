#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use catbird_mls::{EpochSecretStorage, MLSContext};

/// Explicit epoch-secret persistence for integration fixtures.
///
/// Production code requires a durable callback before it will publish an
/// epoch-changing operation. Tests that exercise successful MLS transitions
/// install this process-lifetime store instead of weakening that fail-closed
/// contract.
#[derive(Default)]
pub(crate) struct InMemoryEpochSecretStorage {
    secrets: Mutex<HashMap<(String, u64), Vec<u8>>>,
}

#[async_trait]
impl EpochSecretStorage for InMemoryEpochSecretStorage {
    async fn store_epoch_secret(
        &self,
        conversation_id: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> bool {
        self.secrets
            .lock()
            .unwrap()
            .insert((conversation_id, epoch), secret_data);
        true
    }

    async fn get_epoch_secret(&self, conversation_id: String, epoch: u64) -> Option<Vec<u8>> {
        self.secrets
            .lock()
            .unwrap()
            .get(&(conversation_id, epoch))
            .cloned()
    }

    async fn delete_epoch_secret(&self, conversation_id: String, epoch: u64) -> bool {
        self.secrets
            .lock()
            .unwrap()
            .remove(&(conversation_id, epoch));
        true
    }

    async fn delete_epochs_before(&self, conversation_id: String, cutoff_epoch: u64) -> u32 {
        let mut secrets = self.secrets.lock().unwrap();
        let before = secrets.len();
        secrets.retain(|(stored_conversation, epoch), _| {
            stored_conversation != &conversation_id || *epoch >= cutoff_epoch
        });
        u32::try_from(before.saturating_sub(secrets.len())).unwrap_or(u32::MAX)
    }
}

pub(crate) fn install(context: &MLSContext) {
    context
        .set_epoch_secret_storage(Box::new(InMemoryEpochSecretStorage::default()))
        .expect("install in-memory epoch-secret storage");
}
