use crate::orchestrator::{
    AddMembersServerResult, ConversationState, DeviceInfo, GroupState, JoinMethod, Message,
    OrchestratorError, SyncCursor,
};
use crate::orchestrator_bridge::{
    FFIAddMembersResult, FFIDeliveryStatus, FFIDeviceInfo, FFIGroupState, FFIMessage,
    FFISyncCursor, OrchestratorBridgeError,
};

pub(crate) fn bridge_err(e: OrchestratorBridgeError) -> OrchestratorError {
    match e {
        OrchestratorBridgeError::Storage { message } => OrchestratorError::Storage(message),
        OrchestratorBridgeError::Api { message } => OrchestratorError::Api(message),
        OrchestratorBridgeError::Credential { message } => OrchestratorError::Credential(message),
        OrchestratorBridgeError::NotAuthenticated => OrchestratorError::NotAuthenticated,
        OrchestratorBridgeError::ShuttingDown => OrchestratorError::ShuttingDown,
        other => OrchestratorError::Api(other.to_string()),
    }
}

pub(crate) fn join_method_to_string(jm: JoinMethod) -> String {
    match jm {
        JoinMethod::Creator => "creator".to_string(),
        JoinMethod::Welcome => "welcome".to_string(),
        JoinMethod::ExternalCommit => "external_commit".to_string(),
    }
}

pub(crate) fn conversation_state_to_string(state: ConversationState) -> String {
    state.tag().to_string()
}

pub(crate) fn ffi_to_message(ffi: &FFIMessage) -> Message {
    Message {
        id: ffi.id.clone(),
        conversation_id: ffi.conversation_id.clone(),
        sender_did: ffi.sender_did.clone(),
        text: ffi.text.clone(),
        timestamp: ffi
            .timestamp
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_else(|_| chrono::Utc::now()),
        epoch: ffi.epoch,
        sequence_number: ffi.sequence_number,
        is_own: ffi.is_own,
        delivery_status: ffi.delivery_status.as_ref().map(ffi_to_delivery_status),
        payload_json: ffi.payload_json.clone(),
    }
}

pub(crate) fn message_to_ffi(msg: &Message) -> FFIMessage {
    FFIMessage {
        id: msg.id.clone(),
        conversation_id: msg.conversation_id.clone(),
        sender_did: msg.sender_did.clone(),
        text: msg.text.clone(),
        timestamp: msg.timestamp.to_rfc3339(),
        epoch: msg.epoch,
        sequence_number: msg.sequence_number,
        is_own: msg.is_own,
        delivery_status: msg.delivery_status.as_ref().map(delivery_status_to_ffi),
        payload_json: msg.payload_json.clone(),
    }
}

fn ffi_to_delivery_status(ffi: &FFIDeliveryStatus) -> crate::orchestrator::types::DeliveryStatus {
    use crate::orchestrator::types::DeliveryStatus;
    match ffi {
        FFIDeliveryStatus::DeliveredToAll => DeliveryStatus::DeliveredToAll,
        FFIDeliveryStatus::Partial {
            acked_count,
            total_count,
        } => DeliveryStatus::Partial {
            acked_count: *acked_count,
            total_count: *total_count,
        },
        FFIDeliveryStatus::Pending => DeliveryStatus::Pending,
        FFIDeliveryStatus::LocalOnly => DeliveryStatus::LocalOnly,
    }
}

fn delivery_status_to_ffi(
    status: &crate::orchestrator::types::DeliveryStatus,
) -> FFIDeliveryStatus {
    use crate::orchestrator::types::DeliveryStatus;
    match status {
        DeliveryStatus::DeliveredToAll => FFIDeliveryStatus::DeliveredToAll,
        DeliveryStatus::Partial {
            acked_count,
            total_count,
        } => FFIDeliveryStatus::Partial {
            acked_count: *acked_count,
            total_count: *total_count,
        },
        DeliveryStatus::Pending => FFIDeliveryStatus::Pending,
        DeliveryStatus::LocalOnly => FFIDeliveryStatus::LocalOnly,
    }
}

pub(crate) fn ffi_sync_cursor_to_domain(ffi: FFISyncCursor) -> SyncCursor {
    SyncCursor {
        conversations_cursor: ffi.conversations_cursor,
        messages_cursor: ffi.messages_cursor,
    }
}

pub(crate) fn sync_cursor_to_ffi(cursor: &SyncCursor) -> FFISyncCursor {
    FFISyncCursor {
        conversations_cursor: cursor.conversations_cursor.clone(),
        messages_cursor: cursor.messages_cursor.clone(),
    }
}

pub(crate) fn group_state_to_ffi(state: &GroupState) -> FFIGroupState {
    FFIGroupState {
        group_id: state.group_id.clone(),
        conversation_id: state.conversation_id.clone(),
        epoch: state.epoch,
        members: state.members.clone(),
    }
}

pub(crate) fn ffi_group_state_to_domain(ffi: FFIGroupState) -> GroupState {
    GroupState {
        group_id: ffi.group_id,
        conversation_id: ffi.conversation_id,
        epoch: ffi.epoch,
        members: ffi.members,
    }
}

pub(crate) fn ffi_add_members_result_to_domain(ffi: FFIAddMembersResult) -> AddMembersServerResult {
    AddMembersServerResult {
        success: ffi.success,
        new_epoch: ffi.new_epoch,
        receipt: None,
    }
}

pub(crate) fn ffi_device_info_to_domain(ffi: FFIDeviceInfo) -> DeviceInfo {
    DeviceInfo {
        device_id: ffi.device_id,
        mls_did: ffi.mls_did,
        device_uuid: ffi.device_uuid,
        created_at: ffi
            .created_at
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
    }
}
