//! Single-table `openmls_kv` `StorageProvider<CURRENT_VERSION>` (`Spec §6.1`).
//!
//! Executes inside the active SQLite transaction (`&SqlTx` on native SQLCipher
//! and `&WasmSqlTx` on WASM `sqlite3mc`) so OpenMLS state transitions and
//! application rows commit or roll back atomically.

use openmls_libcrux_crypto::CryptoProvider as LibcruxCrypto;
use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};
use openmls_traits::OpenMlsProvider;

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use crate::keychain::KeychainAccess;
use crate::MLSError;

pub const SCOPE_KEY_PACKAGE: &str = "KeyPackage";
pub const SCOPE_PSK: &str = "Psk";
pub const SCOPE_ENCRYPTION_KEY_PAIR: &str = "EncryptionKeyPair";
pub const SCOPE_SIGNATURE_KEY_PAIR: &str = "SignatureKeyPair";
pub const SCOPE_EPOCH_KEY_PAIRS: &str = "EpochKeyPairs";
pub const SCOPE_TREE: &str = "Tree";
pub const SCOPE_GROUP_CONTEXT: &str = "GroupContext";
pub const SCOPE_INTERIM_TRANSCRIPT_HASH: &str = "InterimTranscriptHash";
pub const SCOPE_CONFIRMATION_TAG: &str = "ConfirmationTag";
pub const SCOPE_JOIN_CONFIG: &str = "MlsGroupJoinConfig";
pub const SCOPE_OWN_LEAF_NODES: &str = "OwnLeafNodes";
pub const SCOPE_GROUP_STATE: &str = "GroupState";
pub const SCOPE_QUEUED_PROPOSAL: &str = "QueuedProposal";
pub const SCOPE_PROPOSAL_QUEUE_REFS: &str = "ProposalQueueRefs";
pub const SCOPE_OWN_LEAF_NODE_INDEX: &str = "OwnLeafNodeIndex";
pub const SCOPE_EPOCH_SECRETS: &str = "EpochSecrets";
pub const SCOPE_RESUMPTION_PSK_STORE: &str = "ResumptionPsk";
pub const SCOPE_MESSAGE_SECRETS: &str = "MessageSecrets";
pub const SCOPE_APPLICATION_EXPORT_TREE: &str = "ApplicationExportTree";

/// Group-keyed scopes whose `key_bytes` equal `serde_json::to_vec(group_id)`.
pub const DIRECT_GROUP_SCOPES: &[&str] = &[
    SCOPE_TREE,
    SCOPE_GROUP_CONTEXT,
    SCOPE_INTERIM_TRANSCRIPT_HASH,
    SCOPE_CONFIRMATION_TAG,
    SCOPE_JOIN_CONFIG,
    SCOPE_OWN_LEAF_NODES,
    SCOPE_GROUP_STATE,
    SCOPE_PROPOSAL_QUEUE_REFS,
    SCOPE_OWN_LEAF_NODE_INDEX,
    SCOPE_EPOCH_SECRETS,
    SCOPE_RESUMPTION_PSK_STORE,
    SCOPE_MESSAGE_SECRETS,
    SCOPE_APPLICATION_EXPORT_TREE,
];

/// Error returned by [`OpenMlsKvStorage`].
#[derive(Debug, thiserror::Error)]
pub enum OpenMlsKvError {
    #[error("openmls_kv SQLite error: {0}")]
    Sql(String),
    #[error("openmls_kv serialization error: {0}")]
    Serialization(String),
    #[error("openmls_kv keychain error: {0}")]
    Keychain(#[from] MLSError),
}

impl From<serde_json::Error> for OpenMlsKvError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<OpenMlsKvError> for MLSError {
    fn from(err: OpenMlsKvError) -> Self {
        match err {
            OpenMlsKvError::Sql(msg) => MLSError::Internal(format!("openmls_kv sql: {msg}")),
            OpenMlsKvError::Serialization(msg) => {
                MLSError::Internal(format!("openmls_kv serialization: {msg}"))
            }
            OpenMlsKvError::Keychain(err) => err,
        }
    }
}

/// Low-level synchronous key-value backend over `openmls_kv`.
pub trait KvBackend {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, OpenMlsKvError>;

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), OpenMlsKvError>;

    fn kv_delete(&self, version: u16, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError>;

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, OpenMlsKvError>;

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, OpenMlsKvError>;

    fn kv_count_all(&self) -> Result<usize, OpenMlsKvError>;
}

impl<T: KvBackend + ?Sized> KvBackend for &T {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, OpenMlsKvError> {
        (**self).kv_get(version, scope, key)
    }

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), OpenMlsKvError> {
        (**self).kv_put(version, scope, key, value)
    }

    fn kv_delete(&self, version: u16, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError> {
        (**self).kv_delete(version, scope, key)
    }

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, OpenMlsKvError> {
        (**self).kv_list_keys_in_scope(version, scope)
    }

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, OpenMlsKvError> {
        (**self).kv_list_entries_in_scope(version, scope)
    }

    fn kv_count_all(&self) -> Result<usize, OpenMlsKvError> {
        (**self).kv_count_all()
    }
}

impl<T: KvBackend + ?Sized> KvBackend for std::rc::Rc<T> {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, OpenMlsKvError> {
        (**self).kv_get(version, scope, key)
    }

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), OpenMlsKvError> {
        (**self).kv_put(version, scope, key, value)
    }

    fn kv_delete(&self, version: u16, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError> {
        (**self).kv_delete(version, scope, key)
    }

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, OpenMlsKvError> {
        (**self).kv_list_keys_in_scope(version, scope)
    }

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, OpenMlsKvError> {
        (**self).kv_list_entries_in_scope(version, scope)
    }

    fn kv_count_all(&self) -> Result<usize, OpenMlsKvError> {
        (**self).kv_count_all()
    }
}

impl<T: KvBackend + ?Sized> KvBackend for std::sync::Arc<T> {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, OpenMlsKvError> {
        (**self).kv_get(version, scope, key)
    }

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), OpenMlsKvError> {
        (**self).kv_put(version, scope, key, value)
    }

    fn kv_delete(&self, version: u16, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError> {
        (**self).kv_delete(version, scope, key)
    }

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, OpenMlsKvError> {
        (**self).kv_list_keys_in_scope(version, scope)
    }

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, OpenMlsKvError> {
        (**self).kv_list_entries_in_scope(version, scope)
    }

    fn kv_count_all(&self) -> Result<usize, OpenMlsKvError> {
        (**self).kv_count_all()
    }
}

/// Recorded `openmls_kv` write/delete batch (`Spec §6.1` / `I6`).
///
/// Commit transitions journal the serialized batch before HTTP and apply it only
/// after acceptance, including recovery from an own sequenced Commit after restart.
/// Application sends instead reserve their sender generation before dispatch:
/// a timeout cannot prove the ciphertext was not published.
#[derive(Clone, Debug, Default)]
pub struct KvWriteBatch {
    entries: std::collections::BTreeMap<(u16, String, Vec<u8>), Option<Vec<u8>>>,
}

// JSON object keys cannot represent the composite KV key; encode ordered entries as a sequence.
impl serde::Serialize for KvWriteBatch {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(&self.entries)
    }
}

impl<'de> serde::Deserialize<'de> for KvWriteBatch {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BatchVisitor;

        impl<'de> serde::de::Visitor<'de> for BatchVisitor {
            type Value = KvWriteBatch;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an OpenMLS KV write/delete entry sequence")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut batch = KvWriteBatch::new();
                while let Some((key, value)) = seq.next_element()? {
                    batch.entries.insert(key, value);
                }
                Ok(batch)
            }
        }

        deserializer.deserialize_seq(BatchVisitor)
    }
}

impl KvWriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn apply<B: KvBackend>(&self, backend: &B) -> Result<(), OpenMlsKvError> {
        for ((version, scope, key), value_opt) in &self.entries {
            match value_opt {
                Some(val) => backend.kv_put(*version, scope, key, val)?,
                None => backend.kv_delete(*version, scope, key)?,
            }
        }
        Ok(())
    }
}

/// Copy-on-write `KvBackend` overlay reading unmodified keys from `base` and
/// buffering all `kv_put`/`kv_delete` calls in memory.
pub struct KvWriteOverlay<B> {
    base: B,
    batch: std::cell::RefCell<KvWriteBatch>,
}

impl<B> KvWriteOverlay<B> {
    pub fn new(base: B) -> Self {
        Self {
            base,
            batch: std::cell::RefCell::new(KvWriteBatch::new()),
        }
    }

    pub fn into_batch(self) -> KvWriteBatch {
        self.batch.into_inner()
    }

    pub fn clone_batch(&self) -> KvWriteBatch {
        self.batch.borrow().clone()
    }
}

impl<B: KvBackend> KvBackend for KvWriteOverlay<B> {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, OpenMlsKvError> {
        let lookup = (version, scope.to_string(), key.to_vec());
        if let Some(staged) = self.batch.borrow().entries.get(&lookup) {
            return Ok(staged.clone());
        }
        self.base.kv_get(version, scope, key)
    }

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), OpenMlsKvError> {
        self.batch.borrow_mut().entries.insert(
            (version, scope.to_string(), key.to_vec()),
            Some(value.to_vec()),
        );
        Ok(())
    }

    fn kv_delete(&self, version: u16, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError> {
        self.batch
            .borrow_mut()
            .entries
            .insert((version, scope.to_string(), key.to_vec()), None);
        Ok(())
    }

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, OpenMlsKvError> {
        Ok(self
            .kv_list_entries_in_scope(version, scope)?
            .into_iter()
            .map(|(k, _)| k)
            .collect())
    }

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, OpenMlsKvError> {
        let mut merged: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = self
            .base
            .kv_list_entries_in_scope(version, scope)?
            .into_iter()
            .collect();
        for ((v, s, k), val_opt) in &self.batch.borrow().entries {
            if *v == version && s == scope {
                match val_opt {
                    Some(val) => {
                        merged.insert(k.clone(), val.clone());
                    }
                    None => {
                        merged.remove(k);
                    }
                }
            }
        }
        Ok(merged.into_iter().collect())
    }

    fn kv_count_all(&self) -> Result<usize, OpenMlsKvError> {
        let base_count = self.base.kv_count_all()? as isize;
        let mut delta: isize = 0;
        for ((v, s, k), val_opt) in &self.batch.borrow().entries {
            let existed = self.base.kv_get(*v, s, k)?.is_some();
            if !existed && val_opt.is_some() {
                delta += 1;
            } else if existed && val_opt.is_none() {
                delta -= 1;
            }
        }
        Ok((base_count + delta).max(0) as usize)
    }
}

/// Unified single-table `StorageProvider<CURRENT_VERSION>` over `openmls_kv`.
pub struct OpenMlsKvStorage<B> {
    backend: B,
    #[cfg(not(target_arch = "wasm32"))]
    keychain: Option<Arc<dyn KeychainAccess>>,
}

impl<B: KvBackend> OpenMlsKvStorage<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            #[cfg(not(target_arch = "wasm32"))]
            keychain: None,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_keychain(backend: B, keychain: Arc<dyn KeychainAccess>) -> Self {
        Self {
            backend,
            keychain: Some(keychain),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn write_entity<E: Entity<CURRENT_VERSION>>(
        &self,
        scope: &str,
        key: &[u8],
        value: &E,
    ) -> Result<(), OpenMlsKvError> {
        let bytes = serde_json::to_vec(value)?;
        self.backend.kv_put(CURRENT_VERSION, scope, key, &bytes)
    }

    fn read_entity<E: Entity<CURRENT_VERSION>>(
        &self,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<E>, OpenMlsKvError> {
        match self.backend.kv_get(CURRENT_VERSION, scope, key)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    fn delete_key(&self, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError> {
        self.backend.kv_delete(CURRENT_VERSION, scope, key)
    }

    fn read_list<E: Entity<CURRENT_VERSION>>(
        &self,
        scope: &str,
        key: &[u8],
    ) -> Result<Vec<E>, OpenMlsKvError> {
        let raw_items: Vec<Vec<u8>> = match self.backend.kv_get(CURRENT_VERSION, scope, key)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => return Ok(Vec::new()),
        };
        raw_items
            .into_iter()
            .map(|b| serde_json::from_slice(&b).map_err(OpenMlsKvError::from))
            .collect()
    }

    fn append_to_list(
        &self,
        scope: &str,
        key: &[u8],
        item_bytes: Vec<u8>,
    ) -> Result<(), OpenMlsKvError> {
        let mut raw_items: Vec<Vec<u8>> = match self.backend.kv_get(CURRENT_VERSION, scope, key)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        raw_items.push(item_bytes);
        let encoded = serde_json::to_vec(&raw_items)?;
        self.backend.kv_put(CURRENT_VERSION, scope, key, &encoded)
    }

    fn remove_from_list(
        &self,
        scope: &str,
        key: &[u8],
        item_bytes: &[u8],
    ) -> Result<(), OpenMlsKvError> {
        let mut raw_items: Vec<Vec<u8>> = match self.backend.kv_get(CURRENT_VERSION, scope, key)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        if let Some(pos) = raw_items.iter().position(|x| x.as_slice() == item_bytes) {
            raw_items.remove(pos);
        }
        let encoded = serde_json::to_vec(&raw_items)?;
        self.backend.kv_put(CURRENT_VERSION, scope, key, &encoded)
    }
}

fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, OpenMlsKvError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

impl<B: KvBackend> StorageProvider<CURRENT_VERSION> for OpenMlsKvStorage<B> {
    type Error = OpenMlsKvError;

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let pair_key = serde_json::to_vec(&(group_id, proposal_ref))?;
        self.write_entity(SCOPE_QUEUED_PROPOSAL, &pair_key, proposal)?;
        let gid_key = serde_json::to_vec(group_id)?;
        let ref_bytes = serde_json::to_vec(proposal_ref)?;
        self.append_to_list(SCOPE_PROPOSAL_QUEUE_REFS, &gid_key, ref_bytes)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list(SCOPE_PROPOSAL_QUEUE_REFS, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> =
            self.read_list(SCOPE_PROPOSAL_QUEUE_REFS, &serde_json::to_vec(group_id)?)?;
        refs.into_iter()
            .map(|proposal_ref| {
                let pair_key = serde_json::to_vec(&(group_id, &proposal_ref))?;
                let proposal: QueuedProposal = self
                    .read_entity(SCOPE_QUEUED_PROPOSAL, &pair_key)?
                    .ok_or_else(|| {
                        OpenMlsKvError::Serialization("missing queued proposal".into())
                    })?;
                Ok((proposal_ref, proposal))
            })
            .collect()
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let gid_key = serde_json::to_vec(group_id)?;
        let refs: Vec<ProposalRef> = self.read_list(SCOPE_PROPOSAL_QUEUE_REFS, &gid_key)?;
        for proposal_ref in &refs {
            let pair_key = serde_json::to_vec(&(group_id, proposal_ref))?;
            self.delete_key(SCOPE_QUEUED_PROPOSAL, &pair_key)?;
        }
        self.delete_key(SCOPE_PROPOSAL_QUEUE_REFS, &gid_key)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let gid_key = serde_json::to_vec(group_id)?;
        let ref_bytes = serde_json::to_vec(proposal_ref)?;
        self.remove_from_list(SCOPE_PROPOSAL_QUEUE_REFS, &gid_key, &ref_bytes)?;
        let pair_key = serde_json::to_vec(&(group_id, proposal_ref))?;
        self.delete_key(SCOPE_QUEUED_PROPOSAL, &pair_key)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write_entity(SCOPE_TREE, &serde_json::to_vec(group_id)?, tree)
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read_entity(SCOPE_TREE, &serde_json::to_vec(group_id)?)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_TREE, &serde_json::to_vec(group_id)?)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_GROUP_CONTEXT,
            &serde_json::to_vec(group_id)?,
            group_context,
        )
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read_entity(SCOPE_GROUP_CONTEXT, &serde_json::to_vec(group_id)?)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_GROUP_CONTEXT, &serde_json::to_vec(group_id)?)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_INTERIM_TRANSCRIPT_HASH,
            &serde_json::to_vec(group_id)?,
            interim_transcript_hash,
        )
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read_entity(
            SCOPE_INTERIM_TRANSCRIPT_HASH,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(
            SCOPE_INTERIM_TRANSCRIPT_HASH,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_CONFIRMATION_TAG,
            &serde_json::to_vec(group_id)?,
            confirmation_tag,
        )
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read_entity(SCOPE_CONFIRMATION_TAG, &serde_json::to_vec(group_id)?)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_CONFIRMATION_TAG, &serde_json::to_vec(group_id)?)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let pk_bytes = serde_json::to_vec(public_key)?;
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(keychain) = &self.keychain {
            let key = format!("sig_key_{}", hex::encode(&pk_bytes));
            let value = serde_json::to_vec(signature_key_pair)?;
            crate::async_runtime::block_on(async { keychain.write(key, value).await })?;
            return Ok(());
        }
        self.write_entity(SCOPE_SIGNATURE_KEY_PAIR, &pk_bytes, signature_key_pair)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let pk_bytes = serde_json::to_vec(public_key)?;
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(keychain) = &self.keychain {
            let key = format!("sig_key_{}", hex::encode(&pk_bytes));
            return match crate::async_runtime::block_on(async { keychain.read(key).await })? {
                Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
                None => Ok(None),
            };
        }
        self.read_entity(SCOPE_SIGNATURE_KEY_PAIR, &pk_bytes)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        let pk_bytes = serde_json::to_vec(public_key)?;
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(keychain) = &self.keychain {
            let key = format!("sig_key_{}", hex::encode(&pk_bytes));
            crate::async_runtime::block_on(async { keychain.delete(key).await })?;
            return Ok(());
        }
        self.delete_key(SCOPE_SIGNATURE_KEY_PAIR, &pk_bytes)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_KEY_PACKAGE,
            &serde_json::to_vec(hash_ref)?,
            key_package,
        )
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.read_entity(SCOPE_KEY_PACKAGE, &serde_json::to_vec(hash_ref)?)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_KEY_PACKAGE, &serde_json::to_vec(hash_ref)?)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write_entity(SCOPE_PSK, &serde_json::to_vec(psk_id)?, psk)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_entity(SCOPE_PSK, &serde_json::to_vec(psk_id)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_PSK, &serde_json::to_vec(psk_id)?)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_ENCRYPTION_KEY_PAIR,
            &serde_json::to_vec(public_key)?,
            key_pair,
        )
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read_entity(SCOPE_ENCRYPTION_KEY_PAIR, &serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_ENCRYPTION_KEY_PAIR, &serde_json::to_vec(public_key)?)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_GROUP_STATE,
            &serde_json::to_vec(group_id)?,
            group_state,
        )
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read_entity(SCOPE_GROUP_STATE, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_GROUP_STATE, &serde_json::to_vec(group_id)?)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_MESSAGE_SECRETS,
            &serde_json::to_vec(group_id)?,
            message_secrets,
        )
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read_entity(SCOPE_MESSAGE_SECRETS, &serde_json::to_vec(group_id)?)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_MESSAGE_SECRETS, &serde_json::to_vec(group_id)?)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_RESUMPTION_PSK_STORE,
            &serde_json::to_vec(group_id)?,
            resumption_psk_store,
        )
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read_entity(SCOPE_RESUMPTION_PSK_STORE, &serde_json::to_vec(group_id)?)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_RESUMPTION_PSK_STORE, &serde_json::to_vec(group_id)?)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_OWN_LEAF_NODE_INDEX,
            &serde_json::to_vec(group_id)?,
            own_leaf_index,
        )
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read_entity(SCOPE_OWN_LEAF_NODE_INDEX, &serde_json::to_vec(group_id)?)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_OWN_LEAF_NODE_INDEX, &serde_json::to_vec(group_id)?)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_EPOCH_SECRETS,
            &serde_json::to_vec(group_id)?,
            group_epoch_secrets,
        )
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read_entity(SCOPE_EPOCH_SECRETS, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_EPOCH_SECRETS, &serde_json::to_vec(group_id)?)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let bytes = serde_json::to_vec(key_pairs)?;
        self.backend
            .kv_put(CURRENT_VERSION, SCOPE_EPOCH_KEY_PAIRS, &key, &bytes)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        match self
            .backend
            .kv_get(CURRENT_VERSION, SCOPE_EPOCH_KEY_PAIRS, &key)?
        {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.delete_key(SCOPE_EPOCH_KEY_PAIRS, &key)
    }

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write_entity(SCOPE_JOIN_CONFIG, &serde_json::to_vec(group_id)?, config)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read_entity(SCOPE_JOIN_CONFIG, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_JOIN_CONFIG, &serde_json::to_vec(group_id)?)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let gid_key = serde_json::to_vec(group_id)?;
        let leaf_bytes = serde_json::to_vec(leaf_node)?;
        self.append_to_list(SCOPE_OWN_LEAF_NODES, &gid_key, leaf_bytes)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list(SCOPE_OWN_LEAF_NODES, &serde_json::to_vec(group_id)?)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(SCOPE_OWN_LEAF_NODES, &serde_json::to_vec(group_id)?)
    }

    fn write_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SCOPE_APPLICATION_EXPORT_TREE,
            &serde_json::to_vec(group_id)?,
            application_export_tree,
        )
    }

    fn application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        self.read_entity(
            SCOPE_APPLICATION_EXPORT_TREE,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_key(
            SCOPE_APPLICATION_EXPORT_TREE,
            &serde_json::to_vec(group_id)?,
        )
    }
}

/// `OpenMlsProvider` combining `LibcruxCrypto` (X-Wing PQ) with [`OpenMlsKvStorage`].
pub struct OpenMlsKvProvider<B> {
    crypto: LibcruxCrypto,
    storage: OpenMlsKvStorage<B>,
}

impl<B: KvBackend> OpenMlsKvProvider<B> {
    pub fn new(storage: OpenMlsKvStorage<B>) -> Result<Self, MLSError> {
        let crypto = LibcruxCrypto::new()
            .map_err(|e| MLSError::Internal(format!("LibcruxCrypto init failed: {e:?}")))?;
        Ok(Self { crypto, storage })
    }

    pub fn storage_ref(&self) -> &OpenMlsKvStorage<B> {
        &self.storage
    }
}

impl<B: KvBackend> OpenMlsProvider for OpenMlsKvProvider<B> {
    type CryptoProvider = LibcruxCrypto;
    type RandProvider = LibcruxCrypto;
    type StorageProvider = OpenMlsKvStorage<B>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
