# Identity, devices and KeyPackages

## Accounts and devices

An **account** is an AT Protocol identity (a DID). Each install of Catbird is a **device** of that account, with a UUIDv4 device ID chosen by the client. An account can have up to 20 devices.

Each device has one long-term **Ed25519 signing key**, generated on the device. The same key:

- signs the device's MLS leaf (its MLS credential is a `BasicCredential` whose identity is `did#deviceId`);
- signs every request the device sends to the delivery service;
- is the device's *chat key* (*transport key*) in Labyrinth.

The key's ID is the base64url SHA-256 of its public key. The private key is stored in the encrypted local database and in the platform keychain.

## Enrollment

`enroll_device` registers a device. It:

1. checks that the app was granted the AT Protocol OAuth scopes chat needs (Spaces, the device records, `mailboxKeys`);
2. generates the signing key;
3. publishes the device on the account's PDS as `blue.catbird.chat.device/{deviceId}`, and the account's choice of delivery service as `blue.catbird.chat.declaration/self`, both create-only;
4. enrolls the device with the delivery service in a request signed by the new key, carrying its first KeyPackages;
5. sets up the device's Labyrinth history backup.

The first device of an account is active at once. A later device starts **pending approval**: an existing active device must approve it (`approve_device`). If every other device is lost, recovery is possible after a visible notice has stood for at least 72 hours and no other device has been active.

## Checking that a device belongs to an account (`I4`)

Before a client trusts any MLS leaf (a message sender, a Commit's author, a member being added, the sender of a Welcome), it checks that the leaf's signature key is one the account published on its own PDS:

- The client lists the account's `blue.catbird.chat.device` records. For another account's records it requires a repository proof (a CAR file verified against the account's DID-document key) and keeps a revision floor, so an older copy of the repository can't be replayed.
- The leaf's key must equal a published device key, and the device ID must match.
- An account with no valid device records is an error, not "trust anything".
- For an application message, the MLS sender's credential must also match the account and device that signed the outer request.

## Revocation and dormancy

`revoke_device` is signed by the device itself or another active device of the account. The delivery service records the revocation and marks the device's KeyPackages unusable; the client publishes `blue.catbird.chat.deviceRevocation` on the PDS. The device's leaves are then removed from its groups by Commits. Revoking a device also revokes its Space credentials.

A device that has been inactive for 60 days is treated as dormant: it no longer holds back message deletion on the server (see [Messages](messages.md)).

## KeyPackages

KeyPackages let others add a device to a group while it is offline.

- **Lifetime:** 29 days. The server rejects lifetimes over 30 days and one hour.
- **Upload:** two at enrollment, four more right after, then on request with `replenish_key_packages(count)` (1 to 32 per call). The client sets no low-water mark of its own; the app decides when to top up (Catbird's Apple app asks for 10).
- **Use:** the delivery service reserves one KeyPackage per device when a member is to be added, and expires the matching Welcome when that KeyPackage expires.
- **No last-resort KeyPackages.** The live client rejects them.

Requests from people who haven't talked before use a separate set of longer-lived KeyPackages (40 days by default), published with `publishDirectRequestKeys`.

## Capabilities

Every leaf advertises MLS 1.0, the one ciphersuite (`0x004D`), basic credentials, and no extensions or extra proposal types. The live path uses no GroupContext extensions. Each GroupInfo carries exactly the ratchet tree and the external public key; external commits are forbidden by protocol policy.
