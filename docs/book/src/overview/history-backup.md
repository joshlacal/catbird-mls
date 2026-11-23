# History backup with Labyrinth

MLS deliberately forgets: old epoch keys are deleted, and the delivery service deletes ciphertext once it has been delivered. Catbird keeps long-term, encrypted history with [Labyrinth](https://joshlacal.github.io/labyrinth/), an implementation of Meta's Labyrinth protocol on AT Protocol Spaces. Its book covers the design in full; this page covers how `catbird-mls` uses it.

## What is archived

Whether a conversation is backed up is a **conversation policy**, visible to every member. `set_history_backup_enabled` publishes it as an MLS-authenticated, sequenced change: any active member may turn backup off, and turning it back on is a separate signed action.

While backup is on and the account has it enabled, each message the device sends or receives is queued for the archive with its frame, frame nonce, sequencer receipt and the sender's attestation. The app writes the queue out with `flush_labyrinth_queue`; nothing is flushed on the send path itself, so apps should call it after sending and syncing and before suspending. A failed flush keeps the queued rows.

Archived messages are encrypted under keys only the account's enrolled devices and recovery methods hold, and stored in the conversation's Space in the sender's (or a witness's) own repository. The archive commitment and receipt let a reader check that the archived copy is the message that was sequenced. The account's history keys live in its personal mailbox Space on its PDS.

## Recovery and new devices

| API | Purpose |
|---|---|
| `setup_recovery_code`, `setup_recovery_code_with_receipt` | Create a recovery code |
| `register_passkey_prf`, `restore_with_passkey_prf` | Protect the code with a passkey's PRF output, and restore with it |
| `restore_with_recovery_code` | Restore on a new device |
| `initiate_otc_pairing`, `complete_otc_pairing`, `start_otc_pairing`, `respond_otc_pairing` | Add a device with a 6-digit code shown on the new device |
| `list_recovery_methods`, `remove_recovery_method` | Manage recovery methods |
| `labyrinth_status`, `labyrinth_recovery_presence` | What the app should show about backup |

After restoring, `restore_conversation_from_owner_mailbox`, `import_conversation_history` and `verify_and_reindex_history` bring archived history back into the local database. `rescue_conversation_on_kick` re-archives a conversation's locally held history into the account's own mailbox, for when the account has been removed from it.

## Peer history keys

To archive a message for other members, the client needs their current history keys. It accepts them only when the member's public PDS record and the delivery service's copy agree exactly. If a member's history keys are reset from scratch, the client won't accept the new chain silently: `propose_peer_repin` returns the old and new safety numbers and a 72-hour hold, and `repin_peer` accepts it once the hold has passed.

## Status

The archive contract between `catbird-mls` and Labyrinth is not sealed. The live test of Space reads against real hosts is recorded as pending. See the Labyrinth book's [residual limitations](https://joshlacal.github.io/labyrinth/overview/security-model.html#residual-limitations).
