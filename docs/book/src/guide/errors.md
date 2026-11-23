# Errors

Methods report `MLSError`. Across UniFFI it is a *flat* error: Swift and Kotlin see the variant and its message string, not its fields.

## Errors apps should handle

| Error | Meaning | What to do |
|---|---|---|
| `InvalidInput` | A bad argument, for example an ID that isn't a UUIDv4 | Fix the call |
| `SyncIncomplete { applied, failures }` | Some entries were applied and some failed | Show what was applied; call `sync()` again later |
| `ForkDetected { conversation_id, generation, epoch }` | A peer's validly signed message was sent from a different MLS state at this device's current epoch. The entry is not decrypted, stored or acknowledged. | Stop sending in that conversation and offer the reset flow |
| `RosterUnverified { conversation_id }` | The device holds no verified roster for the conversation (from its creation, a verified reset or a recovery Welcome's attestation), so it can't establish admin authority there | Don't offer admin actions; sync and retry |
| `GroupCreationPending`, `GroupCreationNeedsUserAction`, `GroupCreationRejected`, `GroupCreationCancellationUnproven` | An interrupted or refused creation | Use the pending-creation methods |
| `PendingDeviceAccess { reason }` | This device is waiting for approval | Ask the user to approve it from another device |
| `LocalStateFormatUnsupported { found, required }` | The database is from another client version | Wipe local state and enroll again |
| `CannotRemoveLastAdmin`, `InsufficientPermissions` | Role rules | Explain in the UI |
| `ContextClosed` | The handle was closed by `prepare_for_background` | Call `resume_from_background` |
| `EpochMismatch`, `StorageError`, `Internal` and others | Unexpected failures | Report; retry once |

The full list is the `MLSError` enum in the [API reference](../reference/api.md). The `circle_*` methods report `CircleFfiError` instead.
