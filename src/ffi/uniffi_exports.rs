//! UniFFI exports consumed by `CatbirdMLSCore` (iOS/macOS + NSE) and `android` (`mlsffi` 4-ABI).

use std::path::Path;
use std::sync::Arc;

use crate::client::{
    account_did_hash_hex, evaluate_spaces_eligibility, wipe_pre_cutover_local_artifacts,
    CatbirdMlsClient, CatbirdMlsClientConfig, EnrollmentReceipt, LabyrinthBackupStatus,
    OtcPairingCompletion, OtcPairingOffer, PlatformChangeObserver, PlatformKeyStore,
    PlatformTransport, PreCutoverWipeReport, QueuedLabyrinthArchivePayload, SpacesEligibilityInput,
    SpacesEligibilityStatus,
};
use crate::error::MLSError;
use crate::groups::lifecycle::MemberRole;
use crate::groups::metadata_v1::SpaceAvatarPointer;
use crate::push::{
    process_push_notification, should_inline_push_ciphertext, NotificationPreview,
    PushFetchTransport, PushKeystore, PushWakePayload,
};
use crate::storage::{
    BackgroundCheckpointReport, ConversationRow, GroupMetadataRow, MessageRow, RequestRow,
};

/// Compute `sha256(normalized_did)` (64 lowercase hex chars) for `<did_hash>.db` and Keychain keys (`I8`).
#[uniffi::export(name = "account_did_hash_hex")]
pub fn ffi_account_did_hash_hex(account_did: String) -> Result<String, MLSError> {
    account_did_hash_hex(&account_did)
}

/// Remove pre-cutover `.sqlite`, `.lease`, and `accounts.json` artifacts from `<storage_root>` (`I8`, `Spec §9 Step 5`).
#[uniffi::export(name = "wipe_pre_cutover_local_artifacts")]
pub fn ffi_wipe_pre_cutover_local_artifacts(
    storage_root: String,
) -> Result<PreCutoverWipeReport, MLSError> {
    wipe_pre_cutover_local_artifacts(Path::new(&storage_root))
}

/// Pure deterministic check of `I15` Spaces capability + OAuth scopes.
#[uniffi::export(name = "evaluate_spaces_eligibility")]
pub fn ffi_evaluate_spaces_eligibility(input: SpacesEligibilityInput) -> SpacesEligibilityStatus {
    evaluate_spaces_eligibility(&input)
}

/// Returns `true` iff `ciphertext` fits within the 2,200-byte inline push ceiling (`I12`).
#[uniffi::export(name = "should_inline_push_ciphertext")]
pub fn ffi_should_inline_push_ciphertext(ciphertext: Vec<u8>) -> bool {
    should_inline_push_ciphertext(&ciphertext)
}

/// Shared synchronous push notification processor (`<= 15 MB`, zero Tokio) for iOS NSE and Android FCM (`Spec §6.2`).
#[uniffi::export(name = "process_push_notification")]
pub fn ffi_process_push_notification(
    storage_root: String,
    account_did_hash: String,
    keystore: Arc<dyn PushKeystore>,
    transport: Option<Arc<dyn PushFetchTransport>>,
    wake: PushWakePayload,
) -> Result<NotificationPreview, MLSError> {
    process_push_notification(
        Path::new(&storage_root),
        &account_did_hash,
        keystore,
        transport,
        &wake,
    )
}

#[uniffi::export]
impl CatbirdMlsClient {
    #[uniffi::constructor(name = "open")]
    pub fn ffi_open(
        config: CatbirdMlsClientConfig,
        keystore: Arc<dyn PlatformKeyStore>,
        transport: Arc<dyn PlatformTransport>,
        observer: Option<Arc<dyn PlatformChangeObserver>>,
    ) -> Result<Arc<Self>, MLSError> {
        Self::open(config, keystore, transport, observer)
    }

    #[uniffi::method(name = "account_did")]
    pub fn ffi_account_did(&self) -> String {
        self.account_did().to_string()
    }

    #[uniffi::method(name = "account_did_hash")]
    pub fn ffi_account_did_hash(&self) -> String {
        self.account_did_hash().to_string()
    }

    #[uniffi::method(name = "pre_cutover_wipe_report")]
    pub fn ffi_pre_cutover_wipe_report(&self) -> PreCutoverWipeReport {
        self.pre_cutover_wipe_report().clone()
    }

    #[uniffi::method(name = "check_spaces_eligibility")]
    pub fn ffi_check_spaces_eligibility(
        &self,
        granted_oauth_scopes: Vec<String>,
    ) -> Result<SpacesEligibilityStatus, MLSError> {
        self.check_spaces_eligibility(&granted_oauth_scopes)
    }

    #[uniffi::method(name = "enroll_device")]
    pub fn ffi_enroll_device(
        &self,
        granted_oauth_scopes: Vec<String>,
    ) -> Result<EnrollmentReceipt, MLSError> {
        self.enroll_device(&granted_oauth_scopes)
    }

    #[uniffi::method(name = "prepare_for_background")]
    pub fn ffi_prepare_for_background(&self) -> Result<BackgroundCheckpointReport, MLSError> {
        self.prepare_for_background()
    }

    #[uniffi::method(name = "resume_from_background")]
    pub fn ffi_resume_from_background(&self) -> Result<(), MLSError> {
        self.resume_from_background()
    }

    #[uniffi::method(name = "is_handle_closed")]
    pub fn ffi_is_handle_closed(&self) -> bool {
        self.is_handle_closed()
    }

    #[uniffi::method(name = "handle_darwin_push_wakeup")]
    pub fn ffi_handle_darwin_push_wakeup(&self) -> Result<(), MLSError> {
        self.handle_darwin_push_wakeup()
    }

    #[uniffi::method(name = "sign_out_and_wipe")]
    pub fn ffi_sign_out_and_wipe(&self) -> Result<(), MLSError> {
        self.sign_out_and_wipe()
    }

    #[uniffi::method(name = "list_conversations")]
    pub fn ffi_list_conversations(
        &self,
        before_updated_ms: Option<i64>,
        limit: u32,
    ) -> Result<Vec<ConversationRow>, MLSError> {
        self.list_conversations(before_updated_ms, limit)
    }

    #[uniffi::method(name = "list_messages")]
    pub fn ffi_list_messages(
        &self,
        conversation_id: String,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<Vec<MessageRow>, MLSError> {
        self.list_messages(&conversation_id, before_seq, limit)
    }

    #[uniffi::method(name = "list_requests")]
    pub fn ffi_list_requests(
        &self,
        consent_filter: Option<String>,
    ) -> Result<Vec<RequestRow>, MLSError> {
        self.list_requests(consent_filter.as_deref())
    }

    #[uniffi::method(name = "get_group_metadata")]
    pub fn ffi_get_group_metadata(
        &self,
        conversation_id: String,
    ) -> Result<Option<GroupMetadataRow>, MLSError> {
        self.get_group_metadata(&conversation_id)
    }

    #[uniffi::method(name = "create_group")]
    pub fn ffi_create_group(
        &self,
        conversation_id: String,
        sequencer_did: String,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        self.create_group(&conversation_id, &sequencer_did, title, description)
    }

    #[uniffi::method(name = "send_message")]
    pub fn ffi_send_message(
        &self,
        conversation_id: String,
        message_id: String,
        text: String,
    ) -> Result<MessageRow, MLSError> {
        self.send_message(&conversation_id, &message_id, &text)
    }

    #[uniffi::method(name = "remove_group_member")]
    pub fn ffi_remove_group_member(
        &self,
        actor_role: MemberRole,
        conversation_id: String,
        target_did: String,
    ) -> Result<(), MLSError> {
        self.remove_group_member(actor_role, &conversation_id, &target_did)
    }

    #[uniffi::method(name = "update_group_metadata")]
    pub fn ffi_update_group_metadata(
        &self,
        conversation_id: String,
        title: String,
        description: String,
        space_avatar: Option<SpaceAvatarPointer>,
    ) -> Result<GroupMetadataRow, MLSError> {
        self.update_group_metadata(&conversation_id, title, description, space_avatar)
    }

    #[uniffi::method(name = "accept_direct_request")]
    pub fn ffi_accept_direct_request(&self, request_id: String) -> Result<(), MLSError> {
        self.accept_direct_request(&request_id)
    }

    #[uniffi::method(name = "decline_direct_request")]
    pub fn ffi_decline_direct_request(&self, request_id: String) -> Result<(), MLSError> {
        self.decline_direct_request(&request_id)
    }

    #[uniffi::method(name = "acknowledge_entries_up_to")]
    pub fn ffi_acknowledge_entries_up_to(
        &self,
        conversation_id: String,
        up_to_seq: i64,
    ) -> Result<(), MLSError> {
        self.acknowledge_entries_up_to(&conversation_id, up_to_seq)
    }

    #[uniffi::method(name = "labyrinth_status")]
    pub fn ffi_labyrinth_status(&self) -> Result<LabyrinthBackupStatus, MLSError> {
        self.labyrinth_status()
    }

    #[uniffi::method(name = "setup_recovery_code")]
    pub fn ffi_setup_recovery_code(&self) -> Result<String, MLSError> {
        self.setup_recovery_code()
    }

    #[uniffi::method(name = "restore_with_recovery_code")]
    pub fn ffi_restore_with_recovery_code(
        &self,
        recovery_code_input: String,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        self.restore_with_recovery_code(&recovery_code_input)
    }

    #[uniffi::method(name = "register_passkey_prf")]
    pub fn ffi_register_passkey_prf(
        &self,
        credential_id: Vec<u8>,
        prf_output_32: Vec<u8>,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        self.register_passkey_prf(credential_id, prf_output_32)
    }

    #[uniffi::method(name = "initiate_otc_pairing")]
    pub fn ffi_initiate_otc_pairing(&self) -> Result<OtcPairingOffer, MLSError> {
        self.initiate_otc_pairing()
    }

    #[uniffi::method(name = "complete_otc_pairing")]
    pub fn ffi_complete_otc_pairing(
        &self,
        six_digit_code: String,
    ) -> Result<OtcPairingCompletion, MLSError> {
        self.complete_otc_pairing(&six_digit_code)
    }

    #[uniffi::method(name = "revoke_labyrinth_device")]
    pub fn ffi_revoke_labyrinth_device(
        &self,
        target_device_id: String,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        self.revoke_labyrinth_device(&target_device_id)
    }

    #[uniffi::method(name = "import_conversation_history")]
    pub fn ffi_import_conversation_history(
        &self,
        conversation_id: String,
        messages: Vec<MessageRow>,
    ) -> Result<u32, MLSError> {
        self.import_conversation_history(&conversation_id, messages)
    }

    #[uniffi::method(name = "list_pending_labyrinth_queue")]
    pub fn ffi_list_pending_labyrinth_queue(
        &self,
        conversation_id: Option<String>,
        limit: u32,
    ) -> Result<Vec<QueuedLabyrinthArchivePayload>, MLSError> {
        self.list_pending_labyrinth_queue(conversation_id.as_deref(), limit)
    }

    #[uniffi::method(name = "flush_labyrinth_queue")]
    pub fn ffi_flush_labyrinth_queue(&self) -> Result<u32, MLSError> {
        self.flush_labyrinth_queue()
    }

    #[uniffi::method(name = "rescue_conversation_on_kick")]
    pub fn ffi_rescue_conversation_on_kick(
        &self,
        conversation_id: String,
    ) -> Result<u32, MLSError> {
        self.rescue_conversation_on_kick(&conversation_id)
    }

    #[uniffi::method(name = "restore_conversation_from_owner_mailbox")]
    pub fn ffi_restore_conversation_from_owner_mailbox(
        &self,
        conversation_id: String,
    ) -> Result<u32, MLSError> {
        self.restore_conversation_from_owner_mailbox(&conversation_id)
    }
}
