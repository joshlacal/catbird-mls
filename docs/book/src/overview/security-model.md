# Security model

This page says what Catbird's encrypted chat is meant to protect, against whom, what it leaves visible, and where the known gaps are. It covers the live client (`CatbirdMlsClient`). History backup has its own security model in the [Labyrinth book](https://joshlacal.github.io/labyrinth/overview/security-model.html).

> Nothing here has been independently audited. The properties below are design goals that the code implements and tests.

## Goals

1. **Confidential messages.** Only the devices in a conversation's MLS group can read its messages. Servers relay and store ciphertext they cannot open.
2. **Forward secrecy and post-compromise security**, as MLS provides them: old epoch keys are deleted, and a member that updates its keys heals after a compromise.
3. **Post-quantum confidentiality.** The ciphersuite's key exchange is X-Wing (X25519 combined with ML-KEM-768), so recorded traffic stays confidential against a future quantum computer. Signatures (Ed25519) are not post-quantum; they matter only while messages are being sent.
4. **Authentic senders.** Every message is signed by the sender's device, and every device key must match a device the account published on its own PDS.
5. **One agreed order.** The sequencer signs a receipt for every entry, and clients accept an entry only with a valid receipt.
6. **Recoverable history** through Labyrinth, without giving any server the keys.

## Who we defend against

| Adversary | Assumed able to | Answer |
|---|---|---|
| **The delivery service** (mls-ds, home or sequencer) | read everything it stores and relays, drop or delay requests, sign receipts | It never holds MLS secrets, so it cannot read messages, titles or attachments. It cannot forge a message or a sender: each request is signed by the sending device, and each MLS message by the sender's leaf. It cannot add a device to a group, because Commits and Welcomes are checked by the members. It *can* refuse service, delay delivery, and order entries it has not yet signed. |
| **Another delivery service** (federation) | relay for its own users, send anything | Entries relayed from another service are re-verified: device signature, sequencer receipt and the evidence it supplies. |
| **A PDS** | serve a different set of device records | Device keys for other accounts are accepted only with a repository proof signed by the account's own DID key, and with a revision floor so an older repository can't be replayed. |
| **A removed member** | keep what it already had | It keeps the messages it already decrypted. After the Commit that removes it, it cannot derive later epochs' keys. |
| **A network attacker** | read and modify traffic | Everything travels over TLS, and everything secret is MLS-encrypted or signed in addition. |
| **A future quantum computer** | break X25519 on recorded traffic | X-Wing key exchange. |

**Out of scope.** A compromised device that is still a member; malware on the user's phone; someone who controls the account itself (its DID and PDS) and enrolls a device of their own. On that last point: a new device for an existing account starts pending, and mls-ds requires an existing device to approve it, but that check is enforced by the server, not cryptographically by other members.

## What is encrypted

| Data | Protection |
|---|---|
| Message content, reactions, edits, read receipts, replies | MLS application messages (ChaCha20-Poly1305 under the group's ratchet) |
| Group title, description and avatar pointer | ChaCha20-Poly1305 under a key exported from the group's current epoch (`blue.catbird/group-metadata/v1`), re-encrypted each epoch |
| Avatar images and attachments | AES-256-GCM with a random key per file; the key travels inside an encrypted message |
| Welcomes | HPKE-encrypted to the joining device's KeyPackage |
| The local database | SQLCipher with a 32-byte key from the platform keychain |
| Long-term history | Labyrinth (see its book) |

## What the delivery service can see

mls-ds is a public-state service: it sees the metadata it needs to order and deliver entries.

- **Membership.** Every conversation's member accounts and their roles, each member's devices and which leaf each device holds, and every change to them. Commits are sent as MLS *public* messages, so membership changes are visible to the service by design, and the ratchet tree in each GroupInfo names every leaf as `did#deviceId`.
- **Senders and timing.** For each message: the sender's account and device, the exact time the service received it, the device's signed timestamp, and its sequence number.
- **Sizes.** Message ciphertext lengths. The live send path does **not** pad messages, so sizes are visible to within the cipher overhead.
- **Delivery.** When each device acknowledged which entries.
- **Typing indicators.** These are signed but not encrypted: the service sees who is typing in which conversation.
- **Welcomes.** Which device each Welcome is for.
- **Group metadata.** Who last changed the title, description or avatar, and the metadata version (not the content).
- **Relationships.** For requests between people who haven't talked before, the service checks Bluesky block relationships.
- **Push.** The app's push gateway receives, for each wake, the conversation, generation, sequence number and epoch, and the ciphertext itself when it is at most 2,200 bytes. mls-ds itself holds no device push tokens.

Message ciphertext is deleted from the service once every recipient has acknowledged it and 72 hours have passed, and after 30 days in any case. Sequence numbers, signatures and receipts are kept.

## What a PDS can see

An account's PDS publishes its chat devices (`blue.catbird.chat.device`), device revocations and its choice of delivery service. These are public. For history, see Labyrinth's [What the hosts can see](https://joshlacal.github.io/labyrinth/overview/security-model.html#what-the-hosts-can-see).

## Residual limitations

These are known and not yet solved.

- **No cross-member check on the sequencer (split view).** A sequencer can be held to what it signed, but nothing lets members compare the receipts they hold. A dishonest sequencer could withhold entries from some members or show different members different sequences. A member that receives a validly signed message whose recorded group state differs from its own at the same epoch reports `ForkDetected`, and the next Commit exposes some forks, but neither catches every split.
- **Receipts don't cover everything.** The sequencer's receipt signs the conversation, group, epoch, entry, sender, archive commitment, sequence number and time. It does not sign the conversation generation (the client binds that locally), the request digest or the group state the sender claimed to be at.
- **Unsequenced push previews.** When the push extension cannot reach the delivery service, it may show a preview of an inline message after MLS decryption and sender checks pass but before any receipt is verified. Such a preview (`receipt_verified = false`) does not prove the sequencer accepted the message, and until the app syncs it could be replayed or reordered within the ratchet window. Apps should label these previews.
- **No padding.** See above.
- **Trust in device keys rests on the account's PDS.** A device key is accepted when the account's PDS publishes it under a valid repository signature. Users can compare safety numbers for history keys (Labyrinth), and a peer's history-key reset is held for 72 hours with an old and new safety number, but there is no safety-number check on MLS device keys yet.
- **Resets start over.** When a group's state is lost or diverges, an admin can reset it. The new generation has a fresh group with only that admin, and every other member must be re-added.
- **Not post-quantum authenticated.** Signatures are Ed25519 (MLS leaves and devices) and P-256 (receipts).
- **History backup** has its own limits, listed in the [Labyrinth book](https://joshlacal.github.io/labyrinth/overview/security-model.html#residual-limitations).
