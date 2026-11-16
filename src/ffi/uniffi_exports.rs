//! UniFFI exports consumed by `CatbirdMLSCore` (iOS/macOS + NSE) and `android` (`mlsffi` 4-ABI).

use std::path::Path;
use std::sync::Arc;

use crate::client::{
    account_did_hash_hex, evaluate_spaces_eligibility, wipe_pre_cutover_local_artifacts,
    CatbirdMlsClient, CatbirdMlsClientConfig, CircleOwnerStateDto, DeviceRevocationReport,
    EnrollmentReceipt, LabyrinthBackupStatus, LeaveConversationOutcome, MailboxReadStateRecord,
    OtcInitiatedSession, OtcPairingCompletion, OtcPairingOffer, PeerRepinProposalInfo,
    PendingGroupCreationStatus, PlatformChangeObserver, PlatformKeyStore, PlatformTransport,
    PreCutoverWipeReport, QueuedLabyrinthArchivePayload, RegisteredDeviceInfo,
    SignedPushGatewayRegistration, SpacesEligibilityInput, SpacesEligibilityStatus,
    UploadedConversationAttachment,
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
use crate::voice::VoicePrepareResult;

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

/// Encode a recorded 16-bit LE mono PCM file to Opus-in-OGG, extract a 64-bar waveform, and seal an AES-256-GCM blob (`FC-09`).
#[uniffi::export]
pub fn ffi_prepare_voice_message(
    pcm_path: String,
    sample_rate: u32,
) -> Result<VoicePrepareResult, MLSError> {
    crate::voice::prepare_voice_message(&pcm_path, sample_rate)
        .map_err(|e| MLSError::invalid_input(e.to_string()))
}

/// Decode Opus-in-OGG bytes back to 16-bit LE mono PCM at 48 kHz (`FC-09`).
#[uniffi::export]
pub fn ffi_decode_opus_to_pcm(opus_data: Vec<u8>) -> Result<Vec<u8>, MLSError> {
    crate::voice::decode_opus_to_pcm(&opus_data).map_err(|e| MLSError::invalid_input(e.to_string()))
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

    #[uniffi::method(name = "list_members")]
    pub fn ffi_list_members(&self, conversation_id: String) -> Result<Vec<String>, MLSError> {
        self.list_members(&conversation_id)
    }

    #[uniffi::method(name = "create_group")]
    pub fn ffi_create_group(
        &self,
        conversation_id: String,
        sequencer_did: String,
        member_dids: Vec<String>,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        self.create_group(
            &conversation_id,
            &sequencer_did,
            member_dids,
            title,
            description,
        )
    }

    #[uniffi::method(name = "pending_group_creation_status")]
    pub fn ffi_pending_group_creation_status(
        &self,
        conversation_id: String,
    ) -> Result<Option<PendingGroupCreationStatus>, MLSError> {
        self.pending_group_creation_status(&conversation_id)
    }

    #[uniffi::method(name = "retry_pending_group_creation")]
    pub fn ffi_retry_pending_group_creation(
        &self,
        conversation_id: String,
    ) -> Result<Option<ConversationRow>, MLSError> {
        self.retry_pending_group_creation(&conversation_id)
    }

    #[uniffi::method(name = "cancel_pending_group_creation")]
    pub fn ffi_cancel_pending_group_creation(
        &self,
        conversation_id: String,
    ) -> Result<bool, MLSError> {
        self.cancel_pending_group_creation(&conversation_id)
    }

    #[uniffi::method(name = "add_group_members")]
    pub fn ffi_add_group_members(
        &self,
        conversation_id: String,
        member_dids: Vec<String>,
    ) -> Result<ConversationRow, MLSError> {
        self.add_group_members(&conversation_id, member_dids)
    }

    #[uniffi::method(name = "replenish_key_packages")]
    pub fn ffi_replenish_key_packages(&self, count: u32) -> Result<u32, MLSError> {
        self.replenish_key_packages(count)
    }

    #[uniffi::method(name = "sync")]
    pub fn ffi_sync(&self) -> Result<u32, MLSError> {
        self.sync()
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

    #[uniffi::method(name = "close_conversation")]
    pub fn ffi_close_conversation(&self, conversation_id: String) -> Result<(), MLSError> {
        self.close_conversation(&conversation_id)
    }

    #[uniffi::method(name = "acknowledge_entries_up_to")]
    pub fn ffi_acknowledge_entries_up_to(
        &self,
        conversation_id: String,
        up_to_seq: i64,
    ) -> Result<(), MLSError> {
        self.acknowledge_entries_up_to(&conversation_id, up_to_seq)
    }

    #[uniffi::method(name = "build_signed_push_gateway_registration")]
    pub fn ffi_build_signed_push_gateway_registration(
        &self,
        gateway_url: String,
        app_id: String,
        push_key: String,
        enabled: bool,
    ) -> Result<SignedPushGatewayRegistration, MLSError> {
        self.build_signed_push_gateway_registration(&gateway_url, &app_id, &push_key, enabled)
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

    #[uniffi::method(name = "unsend_message")]
    pub fn ffi_unsend_message(
        &self,
        conversation_id: String,
        message_id: String,
    ) -> Result<u32, MLSError> {
        self.unsend_message(&conversation_id, &message_id)
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

    #[uniffi::method(name = "process_push_wake")]
    pub fn ffi_process_push_wake(
        &self,
        wake: PushWakePayload,
    ) -> Result<NotificationPreview, MLSError> {
        self.process_push_wake(wake)
    }

    #[uniffi::method(name = "is_device_pending_approval")]
    pub fn ffi_is_device_pending_approval(&self) -> Result<bool, MLSError> {
        self.is_device_pending_approval()
    }

    #[uniffi::method(name = "approve_device")]
    pub fn ffi_approve_device(&self, target_device_id: String) -> Result<(), MLSError> {
        self.approve_device(&target_device_id)
    }

    #[uniffi::method(name = "approve_device_with_key")]
    pub fn ffi_approve_device_with_key(
        &self,
        target_device_id: String,
        target_signature_public_key: Vec<u8>,
        target_auth_generation: i64,
    ) -> Result<(), MLSError> {
        self.approve_device_with_key(
            &target_device_id,
            &target_signature_public_key,
            target_auth_generation,
        )
    }

    #[uniffi::method(name = "list_devices")]
    pub fn ffi_list_devices(&self) -> Result<Vec<RegisteredDeviceInfo>, MLSError> {
        self.list_devices()
    }

    #[uniffi::method(name = "revoke_device")]
    pub fn ffi_revoke_device(
        &self,
        target_device_id: String,
    ) -> Result<DeviceRevocationReport, MLSError> {
        self.revoke_device(&target_device_id)
    }

    #[uniffi::method(name = "retire_current_device")]
    pub fn ffi_retire_current_device(&self) -> Result<(), MLSError> {
        self.retire_current_device()
    }

    #[uniffi::method(name = "delete_account_data")]
    pub fn ffi_delete_account_data(&self) -> Result<(), MLSError> {
        self.delete_account_data()
    }

    #[uniffi::method(name = "export_conversation_integrity_evidence_json")]
    pub fn ffi_export_conversation_integrity_evidence_json(
        &self,
        conversation_id: String,
    ) -> Result<String, MLSError> {
        self.export_conversation_integrity_evidence_json(&conversation_id)
    }

    #[uniffi::method(name = "start_otc_pairing")]
    pub fn ffi_start_otc_pairing(
        &self,
        six_digit_code: String,
    ) -> Result<OtcInitiatedSession, MLSError> {
        self.start_otc_pairing(&six_digit_code)
    }

    #[uniffi::method(name = "respond_otc_pairing")]
    pub fn ffi_respond_otc_pairing(
        &self,
        session_id_hex: String,
        six_digit_code: Option<String>,
    ) -> Result<(), MLSError> {
        self.respond_otc_pairing(&session_id_hex, six_digit_code.as_deref())
    }

    #[uniffi::method(name = "restore_with_passkey_prf")]
    pub fn ffi_restore_with_passkey_prf(
        &self,
        credential_id: Vec<u8>,
        prf_output_32: Vec<u8>,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        self.restore_with_passkey_prf(credential_id, prf_output_32)
    }

    #[uniffi::method(name = "verify_and_reindex_history")]
    pub fn ffi_verify_and_reindex_history(&self, conversation_id: String) -> Result<u32, MLSError> {
        self.verify_and_reindex_history(&conversation_id)
    }

    #[uniffi::method(name = "propose_peer_repin")]
    pub fn ffi_propose_peer_repin(
        &self,
        peer_did: String,
    ) -> Result<PeerRepinProposalInfo, MLSError> {
        self.propose_peer_repin(&peer_did)
    }

    #[uniffi::method(name = "repin_peer")]
    pub fn ffi_repin_peer(
        &self,
        peer_did: String,
        confirmed_head: Vec<u8>,
    ) -> Result<(), MLSError> {
        self.repin_peer(&peer_did, confirmed_head)
    }

    #[uniffi::method(name = "leave_conversation")]
    pub fn ffi_leave_conversation(
        &self,
        conversation_id: String,
    ) -> Result<LeaveConversationOutcome, MLSError> {
        self.leave_conversation(&conversation_id)
    }

    #[uniffi::method(name = "fulfill_pending_group_leaves")]
    pub fn ffi_fulfill_pending_group_leaves(&self) -> Result<u32, MLSError> {
        self.fulfill_pending_group_leaves()
    }

    #[uniffi::method(name = "upload_conversation_attachment")]
    pub fn ffi_upload_conversation_attachment(
        &self,
        conversation_id: String,
        plaintext: Vec<u8>,
        mime_type: String,
    ) -> Result<UploadedConversationAttachment, MLSError> {
        self.upload_conversation_attachment(&conversation_id, plaintext, mime_type)
    }

    #[uniffi::method(name = "get_read_state")]
    pub fn ffi_get_read_state(
        &self,
        conversation_id: String,
    ) -> Result<Option<MailboxReadStateRecord>, MLSError> {
        self.get_read_state(&conversation_id)
    }

    #[uniffi::method(name = "advance_read_state")]
    pub fn ffi_advance_read_state(
        &self,
        conversation_id: String,
        candidate_seq: u64,
    ) -> Result<MailboxReadStateRecord, MLSError> {
        self.advance_read_state(&conversation_id, candidate_seq)
    }

    #[uniffi::method(name = "list_read_states")]
    pub fn ffi_list_read_states(&self) -> Result<Vec<MailboxReadStateRecord>, MLSError> {
        self.list_read_states()
    }

    #[uniffi::method(name = "get_circle_owner_state")]
    pub fn ffi_get_circle_owner_state(
        &self,
        circle_id: String,
    ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
        self.get_circle_owner_state(&circle_id)
    }

    #[uniffi::method(name = "put_circle_owner_state")]
    pub fn ffi_put_circle_owner_state(
        &self,
        state: CircleOwnerStateDto,
        swap_record_cid: Option<String>,
    ) -> Result<String, MLSError> {
        self.put_circle_owner_state(state, swap_record_cid)
    }

    #[uniffi::method(name = "merge_circle_owner_state")]
    pub fn ffi_merge_circle_owner_state(
        &self,
        update: CircleOwnerStateDto,
    ) -> Result<CircleOwnerStateDto, MLSError> {
        self.merge_circle_owner_state(update)
    }

    #[uniffi::method(name = "clear_circle_acl_tombstone")]
    pub fn ffi_clear_circle_acl_tombstone(
        &self,
        circle_id: String,
        member_did: String,
    ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
        self.clear_circle_acl_tombstone(&circle_id, &member_did)
    }

    #[uniffi::method(name = "list_circle_owner_states")]
    pub fn ffi_list_circle_owner_states(&self) -> Result<Vec<CircleOwnerStateDto>, MLSError> {
        self.list_circle_owner_states()
    }
}

/// E2EE Circles (`crate::ffi::circles_ffi`): thin wrappers; no mailbox key crosses.
#[cfg(feature = "labyrinth")]
#[uniffi::export]
impl CatbirdMlsClient {
    #[uniffi::method(name = "circle_key_generate")]
    pub fn ffi_circle_key_generate(&self) -> Vec<u8> {
        self.circle_key_generate()
    }

    #[uniffi::method(name = "circle_key_wrap")]
    pub fn ffi_circle_key_wrap(
        &self,
        req: super::circles_ffi::CircleKeyWrapRequest,
        circle_key: Vec<u8>,
    ) -> Result<super::circles_ffi::CircleKeyWrapResult, super::circles_ffi::CircleFfiError> {
        self.circle_key_wrap(req, circle_key)
    }

    #[uniffi::method(name = "circle_key_open")]
    pub fn ffi_circle_key_open(
        &self,
        record_json: String,
        space_uri: String,
        owner_did: String,
    ) -> Result<Option<super::circles_ffi::CircleKeyOpenResult>, super::circles_ffi::CircleFfiError>
    {
        self.circle_key_open(record_json, space_uri, owner_did)
    }

    #[uniffi::method(name = "circle_post_seal")]
    pub fn ffi_circle_post_seal(
        &self,
        req: super::circles_ffi::CirclePostSealRequest,
    ) -> Result<String, super::circles_ffi::CircleFfiError> {
        self.circle_post_seal(req)
    }

    #[uniffi::method(name = "circle_post_open")]
    pub fn ffi_circle_post_open(
        &self,
        req: super::circles_ffi::CirclePostOpenRequest,
    ) -> Result<String, super::circles_ffi::CircleFfiError> {
        self.circle_post_open(req)
    }

    #[uniffi::method(name = "circle_post_key")]
    pub fn ffi_circle_post_key(
        &self,
        circle_key: Vec<u8>,
        circle_id: String,
        post_uri: String,
    ) -> Result<Vec<u8>, super::circles_ffi::CircleFfiError> {
        self.circle_post_key(circle_key, circle_id, post_uri)
    }
}
