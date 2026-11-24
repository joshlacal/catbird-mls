# Conversations and membership

A **conversation** is identified by a UUIDv4 conversation ID. Each conversation has one or more **generations**, each with its own MLS group (a fresh random group ID) starting at epoch 0. A conversation is either *direct* (two accounts) or a *group* (up to 100 accounts and 100 MLS leaves).

Every change to a conversation is a **signed request** from a device to its home delivery service, with the expected current position (generation, group ID, epoch, state version, group-context hash, confirmation tag). A request based on an out-of-date position fails with `StaleCoordinates`, and the client re-syncs and tries again. The server accepts a change before any client merges it locally (`I3`).

## Creating a group

`create_group` stages an epoch-0 MLS group with only the creator's device and submits it with a list of invited accounts. The invited accounts become **pending** participants: there is no Add Commit or Welcome yet. Creation is journaled, so an interrupted creation can be retried or cancelled (`retry_pending_group_creation`, `cancel_pending_group_creation`).

A direct conversation with someone the user hasn't talked to before is a **request**: the first message and the keys to read it are delivered to the recipient, who accepts or declines (`accept_direct_request`, `decline_direct_request`). If the two accounts use different delivery services, the one whose DID sorts first coordinates the request.

## Joining: acceptance, then Welcome

1. When an invited account's device syncs and finds a pending invitation, the client accepts it with a signed request.
2. The delivery service opens a *leaf recovery* request for the account's device and reserves one of its KeyPackages.
3. **Another, current member** fulfils it with an Add Commit and a Welcome, signed by its own leaf.
4. The joining device accepts the Welcome only if it arrives as part of that receipt-verified fulfilment, the fulfilling member's key is one its account published, the Welcome's sender is that member, and the Welcome names the conversation's current group.

The Welcome's GroupInfo carries a private extension (`0xff01`) with a roster attestation from the fulfilling member, encrypted to the joiner. The joiner then acknowledges or rejects the Welcome.

`add_group_members` invites further accounts the same way.

## Removing, leaving and closing

- **Removing a member** takes two steps: a Commit that removes all of the member's leaves, then a policy change that removes the participant.
- **Leaving.** A device first re-archives the history it can read into its own Labyrinth mailbox. Then a direct or single-member conversation is closed; a participant with no leaves leaves at once; a participant with leaves files a leave request that another member fulfils by removing them. The last admin must hand the role on before leaving.
- **Closing** ends a conversation. The delivery service deletes its operational data, keeping only the signed closing entry.

## Updating keys

In group conversations the client commits a fresh leaf key automatically once its current epoch is a day old or 100 messages have been stored in it, whichever comes first. This is what gives MLS its post-compromise security: a device whose keys leaked heals at its next update.

## When state is lost: reset

If a group's state is lost, poisoned or diverges, the client uses a fixed ladder: catch up on missed Commits, have another of the account's devices re-add the leaf, have an admin reissue a Welcome, and finally an explicit **reset**. It never rejoins on its own with an external commit.

A reset is requested and then activated by an admin. It starts a new generation with a fresh group ID at epoch 0 and the activating admin as its only leaf. Everyone else rejoins through leaf recovery. The client deletes the old generation's group state.

## Fork detection

If a member receives a validly signed application message whose recorded group state differs from its own at the same epoch, it records the conversation as forked and reports `ForkDetected`, but only after verifying the sequencer receipt for that message. See the [security model](security-model.md#residual-limitations) for what this does not catch.
