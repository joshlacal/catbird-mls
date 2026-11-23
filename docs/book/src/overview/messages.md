# Messages, sequencing and receipts

## Sending

`send_message(conversation_id, message_id, text)` takes a UUIDv4 message ID. The client:

1. builds the chat frame (`MLSMessagePayload` JSON: text, reactions, read receipts, edits, embeds and so on);
2. draws a random 32-byte **frame nonce** and computes the **archive commitment**, `HMAC-SHA256(frameNonce, frame)`;
3. signs an **original-sender attestation**: Ed25519 over the thread ID, message ID and archive commitment, with the device's key;
4. puts the frame, nonce and attestation into an MLS application message, with an AAD that carries the archive commitment and attestation;
5. reserves the device's next send counter and journals the send in the same database transaction, then sends a signed request to the delivery service.

The nonce travels only inside the encrypted message, so the commitment reveals nothing about the content to the server; it lets the archived copy be tied to the message that was actually sent.

The live send path does not pad messages.

## Sequencing (`I13`)

The conversation's sequencer gives each accepted entry the next **sequence number** (contiguous per conversation) and signs a **sequencer receipt** over:

- the sequencer's DID and the exact key ID that signs (`{sequencerDid}#mls-receipt-N`);
- the conversation ID, MLS group ID and epoch;
- the sender, as `did#deviceId`;
- the entry ID, archive commitment, sequence number and issue time.

The signature is ES256 (P-256, low-S) under a key published in the sequencer's DID document, separate from the key it uses for service authentication. When the key rotates, old key IDs stay in the document and a key ID never changes meaning, so old receipts keep verifying. A sequencer that issues receipts refuses an application message without an archive commitment.

## Receiving and the cursor rule

Clients fetch entries in sequence order, from the realtime stream or after a push wake. For every entry, of every kind, a client advances its cursor or acknowledges the entry only after:

- the receipt verifies under the exact key ID it names;
- for application messages, the original-sender attestation verifies against the MLS sender's leaf, and the sender is in the roster;
- the sender's leaf key is one its account published (`I4`).

A missing local group is an error, not something to skip. History imported from a backup never moves the live cursor. A device recognises its own messages echoed back by exact ciphertext match against its send journal, plus the receipt.

Within MLS, a device keeps keys for 5 past epochs, and tolerates 10 out-of-order and up to 2,000 skipped messages per sender.

## Retention on the server

Once every recipient account has at least one non-dormant device that has acknowledged an entry, and 72 hours have passed, the sequencer deletes the message ciphertext. Without acknowledgements it deletes it after 30 days. Sequence numbers, signatures and receipts stay; Commits and other control entries are kept for the life of the conversation.

Long-term history is the job of [Labyrinth](history-backup.md).

## Attachments

An attachment is encrypted on the device with AES-256-GCM under a fresh random 32-byte key and 12-byte nonce. Its SHA-256 is taken over the ciphertext. The ciphertext is uploaded as a blob to the sender's Space on its PDS (up to 128 MiB), and the key, nonce, hash, type and size travel in the encrypted message's embed. The receiver checks the hash before decrypting. The delivery service stores no attachments.

## Group metadata

A group's title, description and avatar pointer are encrypted with ChaCha20-Poly1305 under a 32-byte key exported from the group's current epoch (exporter label `blue.catbird/group-metadata/v1`, context the group ID and epoch). The AAD binds the group ID, epoch and metadata version. The snapshot is re-encrypted each epoch and submitted with the Commit, together with a proof signed by the author's device. The avatar image itself is an encrypted blob in the setter's Space.

## Typing indicators

Typing indicators are signed by the device but not MLS-encrypted, last 8 seconds and are delivered on a best-effort basis.
