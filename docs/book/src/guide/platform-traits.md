# Platform traits

The app implements these UniFFI callback traits. The client calls them synchronously from its own threads.

## `PlatformKeyStore`

| Method | Contract |
|---|---|
| `load_or_create_db_key(account_did_hash)` | Return exactly 32 bytes, the same every time for this account; create and store them on first use. This key encrypts the whole database. |
| `load_signature_keypair(key_id)` / `store_signature_keypair(key_id, bytes)` | Store the device's signing key pair under `key_id` |
| `delete_account_keys(account_did_hash)` | Delete everything stored for the account (sign-out and deletion) |
| `load_cached_chat_dpop_token` / `store_cached_chat_dpop_token` | Cache a short-lived service token so the push extension can fetch without refreshing OAuth |

Use storage that the push extension can read (on iOS, a Keychain access group shared with the extension), and an accessibility class that allows reads while the device is locked after first unlock, or push previews will fail.

## `PlatformTransport`

| Method | Contract |
|---|---|
| `execute_http(request)` | Perform the HTTP request against the home delivery service or the PDS, authenticated as the account, and return status, headers and body. **Pass every header through unchanged**, in both directions. Space reads depend on `Atproto-Space-Credential` and `Atproto-Space-Mac`. |
| `connect_realtime_stream(home_ds_endpoint, cursor_seq)` | Start or reconnect the single WebSocket event stream to the home delivery service. The app runs `sync()` when it reports new entries. |
| `disconnect_realtime_stream()` | Close it |

## `PlatformChangeObserver`

`on_change(event)` receives `ConversationsUpdated`, `MessagesUpdated { conversation_id }`, `RequestsUpdated`, `GroupMetadataUpdated { conversation_id }`, `SpacesEligibilityChanged { eligible }`, `LabyrinthStatusChanged { epoch_seq }`, `Backgrounded` and `Resumed`. Dispatch to the UI thread yourself.

## For the push extension

`process_push_notification` takes two smaller traits:

- `PushKeystore`: `load_db_key`, `load_signature_keypair`, `load_cached_chat_dpop_token`, read-only.
- `PushFetchTransport` (optional): `fetch_missing_entries(conversation_id, after_seq, token)` and `get_authorized_device_keys(did, token)`. Without it, the extension can only use the inline ciphertext.
