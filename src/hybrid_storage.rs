use crate::error::MLSError;
use crate::keychain::KeychainAccess;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::storage::*;
use rusqlite::Connection;

// Use the version from openmls_traits
use openmls_traits::storage::CURRENT_VERSION;

pub struct HybridStorageProvider<C: Codec> {
    sqlite: SqliteStorageProvider<C, Connection>,
    keychain: Box<dyn KeychainAccess>,
}

impl<C: Codec> HybridStorageProvider<C> {
    pub fn new(
        sqlite: SqliteStorageProvider<C, Connection>,
        keychain: Box<dyn KeychainAccess>,
    ) -> Self {
        Self { sqlite, keychain }
    }
}

impl<C: Codec> StorageProvider<CURRENT_VERSION> for HybridStorageProvider<C> {
    type Error = MLSError;

    // --- Group State ---

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_mls_join_config(group_id, config)
            .map_err(|_| MLSError::StorageError)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .append_own_leaf_node(group_id, leaf_node)
            .map_err(|_| MLSError::StorageError)
    }

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
        self.sqlite
            .queue_proposal(group_id, proposal_ref, proposal)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_tree(group_id, tree)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_interim_transcript_hash(group_id, interim_transcript_hash)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_context(group_id, group_context)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_confirmation_tag(group_id, confirmation_tag)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_group_state(group_id, group_state)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_message_secrets(group_id, message_secrets)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_resumption_psk_store(group_id, resumption_psk_store)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_own_leaf_index(group_id, own_leaf_index)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_group_epoch_secrets(group_id, group_epoch_secrets)
            .map_err(|_| MLSError::StorageError)
    }

    // --- Crypto Objects ---

    // INTERCEPTED: Signature Keys -> Keychain
    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        // Serialize public key to use as lookup key
        let pk_bytes = serde_json::to_vec(public_key).map_err(|_| MLSError::SerializationError)?;
        let key = format!("sig_key_{}", hex::encode(pk_bytes));

        // Serialize key pair to store
        let value =
            serde_json::to_vec(signature_key_pair).map_err(|_| MLSError::SerializationError)?;

        // Use RUNTIME explicitly to ensure work runs on tokio threadpool
        crate::async_runtime::block_on(async { self.keychain.write(key, value).await })
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_encryption_key_pair(public_key, key_pair)
            .map_err(|_| MLSError::StorageError)
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
        self.sqlite
            .write_encryption_epoch_key_pairs(group_id, epoch, leaf_index, key_pairs)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        crate::info_log!("[HYBRID-STORAGE] write_key_package called");
        self.sqlite
            .write_key_package(hash_ref, key_package)
            .map_err(|_| MLSError::StorageError)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_psk(psk_id, psk)
            .map_err(|_| MLSError::StorageError)
    }

    // --- Getters ---

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.sqlite
            .mls_group_join_config(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.sqlite
            .own_leaf_nodes(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.sqlite
            .queued_proposal_refs(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        self.sqlite
            .queued_proposals(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.sqlite
            .tree(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.sqlite
            .group_context(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.sqlite
            .interim_transcript_hash(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.sqlite
            .confirmation_tag(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.sqlite
            .group_state(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.sqlite
            .message_secrets(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.sqlite
            .resumption_psk_store(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.sqlite
            .own_leaf_index(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.sqlite
            .group_epoch_secrets(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    // INTERCEPTED: Signature Keys -> Keychain
    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let pk_bytes = serde_json::to_vec(public_key).map_err(|_| MLSError::SerializationError)?;
        let key = format!("sig_key_{}", hex::encode(pk_bytes));

        // Use RUNTIME explicitly to ensure work runs on tokio threadpool
        match crate::async_runtime::block_on(async { self.keychain.read(key).await })? {
            Some(data) => {
                let key_pair: SignatureKeyPair =
                    serde_json::from_slice(&data).map_err(|_| MLSError::SerializationError)?;
                Ok(Some(key_pair))
            }
            None => Ok(None),
        }
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.sqlite
            .encryption_key_pair(public_key)
            .map_err(|_| MLSError::StorageError)
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
        self.sqlite
            .encryption_epoch_key_pairs(group_id, epoch, leaf_index)
            .map_err(|_| MLSError::StorageError)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let result = self
            .sqlite
            .key_package(hash_ref)
            .map_err(|_| MLSError::StorageError);
        if let Ok(ref opt) = result {
            if opt.is_some() {
                crate::debug_log!("[HYBRID-STORAGE] key_package lookup: FOUND");
            } else {
                crate::warn_log!("[HYBRID-STORAGE] key_package lookup: NOT FOUND");
            }
        }
        result
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.sqlite.psk(psk_id).map_err(|_| MLSError::StorageError)
    }

    // --- Deleters ---

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .remove_proposal(group_id, proposal_ref)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_own_leaf_nodes(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_group_config(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_tree(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_confirmation_tag(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_group_state(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_context(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_interim_transcript_hash(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_message_secrets(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_all_resumption_psk_secrets(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_own_leaf_index(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_group_epoch_secrets(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .clear_proposal_queue::<GroupId, ProposalRef>(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    // INTERCEPTED: Signature Keys -> Keychain
    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        let pk_bytes = serde_json::to_vec(public_key).map_err(|_| MLSError::SerializationError)?;
        let key = format!("sig_key_{}", hex::encode(pk_bytes));

        // Use RUNTIME explicitly to ensure work runs on tokio threadpool
        crate::async_runtime::block_on(async { self.keychain.delete(key).await })
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_encryption_key_pair(public_key)
            .map_err(|_| MLSError::StorageError)
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
        self.sqlite
            .delete_encryption_epoch_key_pairs(group_id, epoch, leaf_index)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        crate::info_log!("[HYBRID-STORAGE] delete_key_package called");
        self.sqlite
            .delete_key_package(hash_ref)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_psk(psk_id)
            .map_err(|_| MLSError::StorageError)
    }

    // --- Application Export Tree (extensions-draft-08) ---

    fn write_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .write_application_export_tree(group_id, application_export_tree)
            .map_err(|_| MLSError::StorageError)
    }

    fn application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        self.sqlite
            .application_export_tree(group_id)
            .map_err(|_| MLSError::StorageError)
    }

    fn delete_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.sqlite
            .delete_application_export_tree::<GroupId, ApplicationExportTree>(group_id)
            .map_err(|_| MLSError::StorageError)
    }
}
