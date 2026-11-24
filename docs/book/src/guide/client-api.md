# Client API by area

`CatbirdMlsClient` is the only object apps use. This page groups its methods; the [API reference](../reference/api.md) has their full signatures. Every method returns a `Result` that becomes a thrown error in Swift and Kotlin.

## Lifecycle and identity

| Method | Does |
|---|---|
| `open(config, keystore, transport, observer)` | Opens the account's database and returns the client |
| `account_did`, `account_did_hash` | The account, and the SHA-256 of its normalized DID used in file names and key-store IDs |
| `check_spaces_eligibility(scopes)` | Whether the granted OAuth scopes are enough for chat and backup |
| `enroll_device(scopes)` | Registers this device (idempotent) |
| `prepare_for_background`, `resume_from_background`, `is_handle_closed` | Suspension on iOS |
| `handle_darwin_push_wakeup` | Reload after the push extension committed |
| `sign_out_and_wipe` | Deletes local state and keys |
| `delete_account_data`, `delete_account_data_for_hosted_account` | Account deletion |

Free functions: `account_did_hash_hex`, `wipe_pre_cutover_local_artifacts`, `evaluate_spaces_eligibility`, `should_inline_push_ciphertext`, `process_push_notification`, and the voice helpers `ffi_prepare_voice_message` and `ffi_decode_opus_to_pcm`.

## Conversations

| Method | Does |
|---|---|
| `list_conversations(before_updated_ms, limit)` | Conversation list, newest first |
| `list_messages(conversation_id, before_seq, limit)` | Message history, page by page |
| `list_members`, `get_group_metadata` | Members and decrypted title, description and avatar |
| `create_group(...)` | Creates a group or a direct conversation |
| `pending_group_creation_status`, `retry_pending_group_creation`, `cancel_pending_group_creation` | Interrupted creations |
| `update_group_metadata(...)` | Changes the title, description or avatar |
| `add_group_members`, `remove_group_member` | Membership |
| `leave_conversation`, `close_conversation`, `fulfill_pending_group_leaves` | Leaving and closing |
| `export_conversation_integrity_evidence_json` | The receipts and evidence the client holds for a conversation, for diagnosis |

## Requests

`list_requests(consent_filter)`, `accept_direct_request(request_id)`, `decline_direct_request(request_id)`.

## Messages

| Method | Does |
|---|---|
| `send_message(conversation_id, message_id, text)` | Sends a message |
| `unsend_message(conversation_id, message_id)` | Unsends one of your messages |
| `upload_conversation_attachment(conversation_id, bytes, mime_type)` | Encrypts and uploads an attachment; returns what to embed in the message |
| `acknowledge_entries_up_to(conversation_id, seq)` | Tells the delivery service which entries this device has |
| `get_read_state`, `advance_read_state`, `list_read_states` | Read positions, synced across the account's devices |

## Sync

`sync()` fetches and applies new entries and returns how many were applied.

## Devices and keys

| Method | Does |
|---|---|
| `list_devices` | The account's devices |
| `is_device_pending_approval`, `approve_device`, `approve_device_with_key` | New-device approval |
| `revoke_device(device_id)`, `retire_current_device` | Removing devices |
| `replenish_key_packages(count)` | Uploads more KeyPackages |
| `propose_peer_repin`, `repin_peer` | Accepting a contact's reset history keys after the hold |

## Push

`build_signed_push_gateway_registration(...)` builds the signed registration; `process_push_wake(wake)` handles a wake inside the app.

## History backup and recovery

`labyrinth_status`, `labyrinth_recovery_presence`, `history_backup_enabled`, `set_history_backup_enabled`, `list_pending_labyrinth_queue`, `flush_labyrinth_queue`, `setup_recovery_code`, `setup_recovery_code_with_receipt`, `restore_with_recovery_code`, `register_passkey_prf`, `restore_with_passkey_prf`, the one-time-code pairing methods, `list_recovery_methods`, `remove_recovery_method`, `acknowledge_recovery_attention`, `acknowledge_recovery_generation`, `revoke_labyrinth_device`, `import_conversation_history`, `rescue_conversation_on_kick`, `restore_conversation_from_owner_mailbox`, `verify_and_reindex_history`. See [History backup with Labyrinth](../overview/history-backup.md).

## Circles

`get_circle_owner_state`, `put_circle_owner_state`, `merge_circle_owner_state`, `list_circle_owner_states`, `clear_circle_acl_tombstone`, and the `circle_key_*` and `circle_post_*` helpers, which report `CircleFfiError` instead of `MLSError`.
