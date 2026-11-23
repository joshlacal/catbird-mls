# Glossary

**Account.** An AT Protocol identity (DID).

**Archive commitment.** `HMAC-SHA256(frameNonce, frame)`, carried in a message's MLS AAD and its sequencer receipt.

**C33 / direct request.** A first conversation between two accounts. When they use different delivery services, the one whose DID sorts first coordinates.

**Conversation, generation.** A conversation has a UUIDv4 ID; each reset starts a new generation with a new MLS group.

**Delivery service / home DS.** The server an account names in `blue.catbird.chat.declaration/self`. Catbird's is mls-ds.

**Device.** One install, with a UUIDv4 device ID and an Ed25519 signing key.

**Entry.** Anything the sequencer orders in a conversation: a message, Commit, membership or policy change.

**KeyPackage.** A device's published MLS key material that lets others add it to a group.

**Labyrinth.** Catbird's encrypted, recoverable history layer.

**Leaf.** A device's position in an MLS group's ratchet tree.

**Leaf recovery.** The flow by which a current member adds a device to a group with a Welcome.

**Original-sender attestation.** The sender device's Ed25519 signature over the thread ID, message ID and archive commitment.

**PDS.** The account's AT Protocol data server.

**Sequencer.** The delivery service that created a conversation; it assigns sequence numbers and signs receipts.

**Sequencer receipt (`I13`).** The sequencer's ES256 signature over an entry's position and archive commitment.

**Space.** AT Protocol permissioned data, used for history.

**X-Wing.** A hybrid key encapsulation combining X25519 and ML-KEM-768.
