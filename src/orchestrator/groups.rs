use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use crate::error::MLSError;
use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::{MLSOrchestrator, OwnCommitExpectation};
use super::storage::MLSStorageBackend;
use super::types::*;

struct WelcomeJoinRollback<'a> {
    user_did: &'a str,
    conversation_id: Option<&'a str>,
    group_id_hex: &'a str,
    group_id: Vec<u8>,
    group_state_write_attempted: bool,
    prior_group_state: Option<GroupState>,
    remove_new_conversation: bool,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::recovery_e2e_harness::TestWorld;

    #[tokio::test(flavor = "multi_thread")]
    async fn stable_cleanup_removes_raw_group_conversation_state_alias() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let stable_id = "stable-cleanup-raw-state-alias";
        world
            .delivery_service()
            .set_next_create_conversation_id(stable_id);
        let created = alice
            .orchestrator
            .create_group("stable cleanup", None, None)
            .await
            .expect("create distinct stable conversation");
        assert_ne!(created.conversation_id, created.group_id);
        {
            let states = alice.orchestrator.conversation_states().lock().await;
            assert!(
                states.contains_key(stable_id),
                "Active must be projected under the stable conversation id"
            );
            assert!(
                !states.contains_key(&created.group_id),
                "Active must not be projected under the mutable raw group id"
            );
        }

        alice
            .orchestrator
            .force_delete_local(stable_id)
            .await
            .expect("stable local cleanup");

        let states = alice.orchestrator.conversation_states().lock().await;
        assert!(!states.contains_key(stable_id));
        assert!(
            !states.contains_key(&created.group_id),
            "stable cleanup must remove the raw group-id state alias left before export"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelling_raw_intent_commit_deletes_crypto_and_replay_clears_intent() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let before = alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .expect("list groups before create");
        let barrier = alice.storage.pause_next_pending_local_delete_write(true);

        let mut create = Box::pin(
            alice
                .orchestrator
                .create_group("cancel raw intent", None, None),
        );
        tokio::select! {
            _ = barrier.wait_until_entered() => {}
            result = &mut create => panic!("create completed before raw intent barrier: {result:?}"),
        }
        assert_eq!(alice.storage.pending_local_delete_count(), 1);
        drop(create);

        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .list_local_group_ids()
                .unwrap(),
            before,
            "the synchronous guard must delete raw MLS secrets when intent commit is cancelled"
        );
        alice.orchestrator.reconcile_pending_local_deletes().await;
        assert_eq!(alice.storage.pending_local_delete_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelling_stable_intent_handoff_leaves_only_replayable_raw_authority() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let stable_id = "stable-intent-handoff-cancel";
        world
            .delivery_service()
            .set_next_create_conversation_id(stable_id);
        let barrier = alice
            .storage
            .pause_pending_local_delete_write(stable_id, false);

        let mut create = Box::pin(
            alice
                .orchestrator
                .create_group("cancel handoff", None, None),
        );
        tokio::select! {
            _ = barrier.wait_until_entered() => {}
            result = &mut create => panic!("create completed before stable intent barrier: {result:?}"),
        }
        drop(create);

        let pending = alice.storage.pending_local_delete_ids();
        assert_eq!(pending.len(), 1, "only raw cleanup authority may remain");
        assert_ne!(pending[0], stable_id);
        assert!(alice
            .storage
            .get_conversation(&alice.did, stable_id)
            .await
            .expect("read stable row")
            .is_none());
        assert!(!alice
            .orchestrator
            .conversations()
            .lock()
            .await
            .contains_key(stable_id));

        alice.orchestrator.reconcile_pending_local_deletes().await;
        assert_eq!(alice.storage.pending_local_delete_count(), 0);
        assert!(alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .expect("list groups after replay")
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn post_stable_cancellation_replays_complete_distinct_id_cleanup() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let stable_id = "stable-post-create-cancel";
        world
            .delivery_service()
            .set_next_create_conversation_id(stable_id);
        let publish = world.delivery_service().pause_next_publish_group_info();

        let mut create = Box::pin(alice.orchestrator.create_group(
            "cancel post stable",
            None,
            None,
        ));
        tokio::select! {
            _ = publish.wait_until_reached() => {}
            result = &mut create => panic!("create completed before publish barrier: {result:?}"),
        }
        let raw_id = alice
            .storage
            .get_conversation(&alice.did, stable_id)
            .await
            .expect("read stable row")
            .expect("stable row exists before cancellation")
            .group_id;
        drop(create);

        assert_eq!(
            alice.storage.pending_local_delete_ids(),
            vec![stable_id.to_string()]
        );
        alice.orchestrator.reconcile_pending_local_deletes().await;
        assert_eq!(alice.storage.pending_local_delete_count(), 0);
        assert!(alice
            .storage
            .get_conversation(&alice.did, stable_id)
            .await
            .unwrap()
            .is_none());
        assert!(!alice.storage.has_group_state(&raw_id));
        assert!(!alice
            .orchestrator
            .conversations()
            .lock()
            .await
            .contains_key(stable_id));
        assert!(!alice
            .orchestrator
            .group_states()
            .lock()
            .await
            .contains_key(&raw_id));
        let states = alice.orchestrator.conversation_states().lock().await;
        assert!(!states.contains_key(stable_id));
        assert!(!states.contains_key(&raw_id));
        drop(states);
        assert!(!alice
            .orchestrator
            .mls_context()
            .group_exists(hex::decode(raw_id).unwrap()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn post_bootstrap_merge_cancellation_replays_exact_epoch_cleanup() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world.add_client("Bob").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let bob_did = world.register_device("Bob").await.expect("register bob");
        let stable_id = "00000000-0000-4000-8000-000000000001";
        world
            .delivery_service()
            .set_next_create_conversation_id(stable_id);
        let publish = world.delivery_service().pause_next_publish_group_info();
        let alice = world.client("Alice");
        let initial_members = [bob_did];

        let mut create = Box::pin(alice.orchestrator.create_group(
            "cancel after bootstrap merge",
            Some(&initial_members),
            None,
        ));
        tokio::select! {
            _ = publish.wait_until_reached() => {}
            result = &mut create => panic!("create completed before publish barrier: {result:?}"),
        }
        let raw_id = alice
            .storage
            .get_conversation(&alice.did, stable_id)
            .await
            .expect("read stable row")
            .expect("stable row exists after bootstrap merge")
            .group_id;
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(hex::decode(&raw_id).expect("group id is hex"))
                .expect("genesis epoch"),
            0,
            "genesis MLS group must be created at epoch zero"
        );
        drop(create);

        alice.orchestrator.reconcile_pending_local_deletes().await;
        assert_eq!(alice.storage.pending_local_delete_count(), 0);
        assert!(alice
            .storage
            .get_conversation(&alice.did, stable_id)
            .await
            .expect("read stable row after replay")
            .is_none());
        assert!(!alice.storage.has_group_state(&raw_id));
        assert!(!alice
            .orchestrator
            .mls_context()
            .group_exists(hex::decode(raw_id).expect("group id is hex")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn equal_id_success_and_cancellation_use_one_intent_key() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");

        let created = alice
            .orchestrator
            .create_group("equal success", None, None)
            .await
            .expect("equal-id create");
        assert_ne!(created.conversation_id, created.group_id);
        assert_eq!(alice.storage.pending_local_delete_count(), 0);

        let publish = world.delivery_service().pause_next_publish_group_info();
        let mut cancelled = Box::pin(alice.orchestrator.create_group("equal cancel", None, None));
        tokio::select! {
            _ = publish.wait_until_reached() => {}
            result = &mut cancelled => panic!("create completed before equal-id cancellation: {result:?}"),
        }
        drop(cancelled);
        assert_eq!(alice.storage.pending_local_delete_count(), 1);
        alice.orchestrator.reconcile_pending_local_deletes().await;
        assert_eq!(alice.storage.pending_local_delete_count(), 0);
        assert!(alice
            .storage
            .get_conversation(&alice.did, &created.conversation_id)
            .await
            .unwrap()
            .is_some(), "replay for the cancelled equal-id create must not delete the prior successful conversation");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn intent_write_and_clear_errors_return_only_after_local_cleanup() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");

        alice.storage.fail_next_mark_pending_local_delete();
        assert!(alice
            .orchestrator
            .create_group("raw mark fails", None, None)
            .await
            .is_err());
        assert!(alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .unwrap()
            .is_empty());
        assert_eq!(alice.storage.pending_local_delete_count(), 0);

        let stable_mark_id = "stable-mark-fails";
        world
            .delivery_service()
            .set_next_create_conversation_id(stable_mark_id);
        let stable_mark = alice
            .storage
            .pause_pending_local_delete_write(stable_mark_id, false);
        let mut create = Box::pin(
            alice
                .orchestrator
                .create_group("stable mark fails", None, None),
        );
        tokio::select! {
            _ = stable_mark.wait_until_entered() => {}
            result = &mut create => panic!("create completed before stable mark barrier: {result:?}"),
        }
        alice.storage.fail_next_mark_pending_local_delete();
        stable_mark.release();
        assert!(create.await.is_err());
        assert!(alice
            .storage
            .get_conversation(&alice.did, stable_mark_id)
            .await
            .unwrap()
            .is_none());
        assert!(alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .unwrap()
            .is_empty());
        assert_eq!(alice.storage.pending_local_delete_count(), 0);

        let raw_clear_id = "raw-clear-fails";
        world
            .delivery_service()
            .set_next_create_conversation_id(raw_clear_id);
        let stable_written = alice
            .storage
            .pause_pending_local_delete_write(raw_clear_id, true);
        let mut create = Box::pin(
            alice
                .orchestrator
                .create_group("raw clear fails", None, None),
        );
        tokio::select! {
            _ = stable_written.wait_until_entered() => {}
            result = &mut create => panic!("create completed before stable intent committed: {result:?}"),
        }
        let raw_intent = alice
            .storage
            .pending_local_delete_ids()
            .into_iter()
            .find(|id| id != raw_clear_id)
            .expect("raw intent remains during handoff");
        alice
            .storage
            .fail_next_clear_pending_local_delete(&raw_intent);
        stable_written.release();
        assert!(create.await.is_err());
        assert!(alice
            .storage
            .get_conversation(&alice.did, raw_clear_id)
            .await
            .unwrap()
            .is_none());
        assert!(alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .unwrap()
            .is_empty());
        assert_eq!(alice.storage.pending_local_delete_count(), 0);

        let final_clear_id = "final-clear-fails";
        world
            .delivery_service()
            .set_next_create_conversation_id(final_clear_id);
        alice
            .storage
            .fail_next_clear_pending_local_delete(final_clear_id);
        assert!(alice
            .orchestrator
            .create_group("final clear fails", None, None)
            .await
            .is_err());
        assert!(alice
            .storage
            .get_conversation(&alice.did, final_clear_id)
            .await
            .unwrap()
            .is_none());
        assert!(alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .unwrap()
            .is_empty());
        assert_eq!(alice.storage.pending_local_delete_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_fails_before_mls_state_when_pending_delete_defaults_are_undeclared() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let before = alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .unwrap();
        alice.storage.omit_pending_delete_capabilities();

        let error = alice
            .orchestrator
            .create_group("unsupported cleanup storage", None, None)
            .await
            .expect_err("create must fail closed without durable delete capabilities");
        assert!(error.to_string().contains("pending local-delete"));
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .list_local_group_ids()
                .unwrap(),
            before
        );
        assert_eq!(alice.storage.conversation_count(), 0);
        assert_eq!(alice.storage.pending_local_delete_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stale_delete_intent_replay_preserves_recreated_conversation_lifecycle() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let alice = world.client("Alice");
        let conversation_id = "delete-recreate-fence";
        world
            .delivery_service()
            .set_next_create_conversation_id(conversation_id);
        let original = alice
            .orchestrator
            .create_group("original lifecycle", None, None)
            .await
            .expect("create original lifecycle");

        alice
            .storage
            .fail_next_clear_pending_local_delete(conversation_id);
        alice
            .orchestrator
            .force_delete_local(conversation_id)
            .await
            .expect_err("injected final intent clear must surface incomplete delete");
        let stale_intent = alice
            .storage
            .list_pending_local_deletes()
            .await
            .expect("list stale intent")
            .into_iter()
            .find(|intent| intent.conversation_id == conversation_id)
            .expect("stale intent retained");

        world
            .delivery_service()
            .set_next_create_conversation_id(conversation_id);
        let recreated = alice
            .orchestrator
            .create_group("new lifecycle", None, None)
            .await
            .expect("recreate stable conversation id");
        assert_ne!(original.group_id, recreated.group_id);
        alice.storage.seed_pending_local_delete(stale_intent);

        alice.orchestrator.reconcile_pending_local_deletes().await;

        assert_eq!(alice.storage.pending_local_delete_count(), 0);
        assert!(alice
            .orchestrator
            .mls_context()
            .group_exists(hex::decode(&recreated.group_id).expect("new group id is hex")));
        let durable = alice
            .storage
            .get_conversation(&alice.did, conversation_id)
            .await
            .expect("read recreated conversation")
            .expect("recreated conversation survives stale replay");
        assert_eq!(durable.group_id, recreated.group_id);
        assert!(alice.storage.has_group_state(&recreated.group_id));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_members_rejects_higher_server_epoch_without_local_merge() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world.add_client("Bob").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let bob_did = world.register_device("Bob").await.expect("register bob");
        let alice = world.client("Alice");
        let conversation = alice
            .orchestrator
            .create_group("add epoch fence", None, None)
            .await
            .expect("create group");
        let group_id = hex::decode(&conversation.group_id).expect("group id is hex");
        let local_epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id.clone())
            .expect("local epoch");
        world
            .delivery_service()
            .set_conversation_epoch_for_test(&conversation.conversation_id, local_epoch + 7);

        let error = alice
            .orchestrator
            .add_members(&conversation.conversation_id, &[bob_did])
            .await
            .expect_err("higher DS epoch must not authorize merge");
        assert!(matches!(error, OrchestratorError::EpochMismatch { .. }));
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(group_id)
                .expect("local epoch after rejection"),
            local_epoch
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remove_members_rejects_higher_server_epoch_without_local_merge() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world.add_client("Bob").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let bob_did = world.register_device("Bob").await.expect("register bob");
        let alice = world.client("Alice");
        let conversation = alice
            .orchestrator
            .create_group("remove epoch fence", None, None)
            .await
            .expect("create group");
        alice
            .orchestrator
            .add_members(&conversation.conversation_id, std::slice::from_ref(&bob_did))
            .await
            .expect("add bob");
        let group_id = hex::decode(&conversation.group_id).expect("group id is hex");
        let local_epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id.clone())
            .expect("local epoch");
        world
            .delivery_service()
            .set_conversation_epoch_for_test(&conversation.conversation_id, local_epoch + 7);

        let error = alice
            .orchestrator
            .remove_members(&conversation.conversation_id, &[bob_did])
            .await
            .expect_err("higher DS epoch must not authorize merge");
        assert!(matches!(error, OrchestratorError::EpochMismatch { .. }));
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(group_id)
                .expect("local epoch after rejection"),
            local_epoch
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn swap_members_rejects_higher_server_epoch_without_local_merge() {
        let mut world = TestWorld::new();
        world.add_client("Alice").await;
        world.add_client("Bob").await;
        world.add_client("Carol").await;
        world
            .register_device("Alice")
            .await
            .expect("register alice");
        let bob_did = world.register_device("Bob").await.expect("register bob");
        let carol_did = world
            .register_device("Carol")
            .await
            .expect("register carol");
        let alice = world.client("Alice");
        let conversation = alice
            .orchestrator
            .create_group("swap epoch fence", None, None)
            .await
            .expect("create group");
        alice
            .orchestrator
            .add_members(&conversation.conversation_id, std::slice::from_ref(&bob_did))
            .await
            .expect("add bob");
        let group_id = hex::decode(&conversation.group_id).expect("group id is hex");
        let local_epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id.clone())
            .expect("local epoch");
        world
            .delivery_service()
            .set_conversation_epoch_for_test(&conversation.conversation_id, local_epoch + 7);

        let error = alice
            .orchestrator
            .swap_members(&conversation.group_id, &[bob_did], &[carol_did])
            .await
            .expect_err("higher DS epoch must not authorize merge");
        assert!(matches!(error, OrchestratorError::EpochMismatch { .. }));
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(group_id)
                .expect("local epoch after rejection"),
            local_epoch
        );
    }
}

/// Internal rollback identity for a group creation attempt. Before createConvo
/// returns, only the raw MLS group exists. Once the server assigns a stable
/// conversation id, all storage/cache cleanup must route through that stable
/// key while still carrying the raw group id as crypto-delete authority.
struct CreateGroupRollbackContext {
    raw_group_id: String,
    stable_conversation_id: Option<String>,
    encoded_delete_authority: String,
    owner_user_did: String,
    durable_intent_id: String,
}

impl CreateGroupRollbackContext {
    fn new(
        raw_group_id: String,
        raw_group_id_bytes: Vec<u8>,
        owner_user_did: &str,
    ) -> Result<Self> {
        let encoded_delete_authority = super::recovery::LocalDeleteSnapshot {
            groups: vec![super::recovery::LocalDeleteGroupFence {
                group_id_hex: hex::encode(raw_group_id_bytes),
                epoch: Some(0),
            }],
            group_state_keys: vec![raw_group_id.clone()],
            conversation: None,
            reset: None,
        }
        .encode_authority(owner_user_did)?;
        Ok(Self {
            durable_intent_id: raw_group_id.clone(),
            raw_group_id,
            stable_conversation_id: None,
            encoded_delete_authority,
            owner_user_did: owner_user_did.to_string(),
        })
    }

    fn bind_stable_conversation(
        &mut self,
        conversation: &ConversationView,
        bootstrap_target_epoch: Option<u64>,
    ) -> Result<()> {
        self.stable_conversation_id = Some(conversation.conversation_id.clone());
        let mut groups = vec![super::recovery::LocalDeleteGroupFence {
            group_id_hex: self.raw_group_id.clone(),
            // The local create has not merged its optional bootstrap Add yet.
            // Epoch zero remains exact cleanup authority until that merge.
            epoch: Some(0),
        }];
        if let Some(target_epoch) = bootstrap_target_epoch.filter(|epoch| *epoch != 0) {
            // The bootstrap Add is already staged locally and accepted by the
            // createConvo call. Persist both exact sides of that one authorized
            // transition before merging so cancellation at either point is
            // replayable without deriving authority from future live state.
            groups.push(super::recovery::LocalDeleteGroupFence {
                group_id_hex: self.raw_group_id.clone(),
                epoch: Some(target_epoch),
            });
        }
        self.encoded_delete_authority = super::recovery::LocalDeleteSnapshot {
            groups,
            group_state_keys: vec![self.raw_group_id.clone()],
            conversation: Some(super::recovery::LocalDeleteConversationFence {
                group_id: conversation.group_id.clone(),
                epoch: bootstrap_target_epoch.unwrap_or(0),
            }),
            reset: None,
        }
        .encode_authority(&self.owner_user_did)?;
        Ok(())
    }

    fn cleanup_conversation_id(&self) -> &str {
        self.stable_conversation_id
            .as_deref()
            .unwrap_or(&self.raw_group_id)
    }
}

/// Bridges the only cancellation gap that durable storage cannot cover: the
/// interval after synchronous MLS creation and before the raw delete intent
/// has durably committed. Once that commit returns, the guard is disarmed and
/// startup replay owns cleanup instead.
struct UnpersistedCreatedGroupGuard<M: MlsCryptoContext> {
    mls_context: std::sync::Arc<M>,
    raw_group_id: Option<Vec<u8>>,
}

impl<M: MlsCryptoContext> UnpersistedCreatedGroupGuard<M> {
    fn new(mls_context: std::sync::Arc<M>, raw_group_id: Vec<u8>) -> Self {
        Self {
            mls_context,
            raw_group_id: Some(raw_group_id),
        }
    }

    fn disarm(&mut self) {
        self.raw_group_id = None;
    }
}

impl<M: MlsCryptoContext> Drop for UnpersistedCreatedGroupGuard<M> {
    fn drop(&mut self) {
        if let Some(group_id) = self.raw_group_id.take() {
            if let Err(error) = self.mls_context.delete_group(group_id) {
                tracing::warn!(error = %error, "Failed to synchronously roll back unpersisted created group");
            }
        }
    }
}

struct GroupCreationGuard<'a> {
    groups: tokio::sync::MutexGuard<'a, std::collections::HashSet<GroupId>>,
    group_id: GroupId,
    generation: &'a std::sync::atomic::AtomicU64,
}

struct CreateGroupInitialMembers<'a> {
    dids: Option<&'a [String]>,
}

impl<'a> GroupCreationGuard<'a> {
    async fn new(
        groups: &'a tokio::sync::Mutex<std::collections::HashSet<GroupId>>,
        generation: &'a std::sync::atomic::AtomicU64,
        group_id: GroupId,
    ) -> Self {
        let mut groups = groups.lock().await;
        groups.insert(group_id.clone());
        generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self {
            groups,
            group_id,
            generation,
        }
    }
}

impl Drop for GroupCreationGuard<'_> {
    fn drop(&mut self) {
        self.groups.remove(&self.group_id);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Create a new MLS group/conversation.
    ///
    /// 1. Creates MLS group locally via FFI
    /// 2. Creates the server conversation with non-creators pending/zero-leaf
    /// 3. Persists the actor-only epoch-zero projection
    /// 4. Publishes GroupInfo for later consent/recovery joins
    pub async fn create_group(
        &self,
        name: &str,
        initial_members: Option<&[String]>,
        description: Option<&str>,
    ) -> Result<ConversationView> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        const REQUIRED_DELETE_CAPABILITIES: [&str; 3] = [
            "mark_pending_local_delete",
            "clear_pending_local_delete",
            "list_pending_local_deletes",
        ];
        let implemented = self.storage().implemented_optional_methods();
        if let Some(missing) = REQUIRED_DELETE_CAPABILITIES
            .iter()
            .find(|method| !implemented.contains(method))
        {
            return Err(OrchestratorError::Storage(format!(
                "group creation requires durable pending local-delete storage; backend does not declare {missing}"
            )));
        }

        tracing::info!(name, member_count = ?initial_members.map(|m| m.len()), "Creating MLS group");

        // Filter out creator's DID from initial members
        let filtered_members: Option<Vec<String>> = initial_members.map(|members| {
            let self_did = user_did.to_lowercase();
            members
                .iter()
                .filter(|m| m.to_lowercase() != self_did)
                .cloned()
                .collect()
        });
        let filtered_members_ref = filtered_members.as_deref();

        let initial_members = CreateGroupInitialMembers {
            dids: filtered_members_ref,
        };

        // Create MLS group locally — with scoped identity and encrypted metadata
        let scoped_identity = self.require_scoped_identity().await?;
        let identity_bytes = scoped_identity.as_bytes().to_vec();
        let mut group_config = self.config().group_config.clone();
        if !name.is_empty() {
            group_config.group_name = Some(name.to_string());
        }
        if let Some(desc) = description {
            group_config.group_description = Some(desc.to_string());
        }
        let creation_result = self
            .mls_context()
            .create_group(identity_bytes, Some(group_config))?;
        let group_id_hex = hex::encode(&creation_result.group_id);
        let mut unpersisted_group = UnpersistedCreatedGroupGuard::new(
            self.mls_context().clone(),
            creation_result.group_id.clone(),
        );
        let mut rollback = CreateGroupRollbackContext::new(
            group_id_hex.clone(),
            creation_result.group_id.clone(),
            &user_did,
        )?;

        tracing::info!(group_id = %group_id_hex, "Local MLS group created");

        // Protect from background sync deletion
        let _creation_guard = GroupCreationGuard::new(
            self.groups_being_created(),
            self.creation_generation(),
            group_id_hex.clone(),
        )
        .await;

        // Arm restart cleanup before the first server call. The synchronous
        // guard remains armed until the storage future confirms this write.
        self.storage()
            .mark_pending_local_delete(
                &rollback.raw_group_id,
                Some(&rollback.encoded_delete_authority),
            )
            .await?;
        unpersisted_group.disarm();

        // Create local conversation record
        let mut create_result = self
            .create_group_inner(
                &user_did,
                &group_id_hex,
                name,
                description,
                initial_members,
                &mut rollback,
            )
            .await;

        // This is deliberately the final awaited operation on the success
        // path. Until it completes, dropping the future leaves replayable
        // owner-bound authority for every local artifact created below.
        if create_result.is_ok() {
            if let Err(error) = self
                .storage()
                .clear_pending_local_delete(&rollback.durable_intent_id)
                .await
            {
                create_result = Err(error);
            }
        }

        // On any failure, clean up the local MLS group. The RAII creation guard
        // is released on success, error, panic unwinding, or future cancellation.
        if create_result.is_err() {
            tracing::warn!(group_id = %group_id_hex, "Cleaning up local MLS group after create_group failure");
            let cleanup_complete = self
                .force_delete_local_with_group(
                    rollback.cleanup_conversation_id(),
                    Some(&rollback.raw_group_id),
                )
                .await;
            if cleanup_complete && rollback.cleanup_conversation_id() != rollback.raw_group_id {
                if let Err(error) = self
                    .storage()
                    .clear_pending_local_delete(&rollback.raw_group_id)
                    .await
                {
                    tracing::warn!(error = %error, group_id = %rollback.raw_group_id, "Stable create rollback completed but redundant raw intent could not be cleared");
                }
            }
            return create_result;
        }

        create_result
    }

    /// Inner implementation of create_group, separated so the outer method can
    /// handle rollback on any error path.
    async fn create_group_inner(
        &self,
        user_did: &str,
        group_id_hex: &str,
        _name: &str,
        _description: Option<&str>,
        initial_members: CreateGroupInitialMembers<'_>,
        rollback: &mut CreateGroupRollbackContext,
    ) -> Result<ConversationView> {
        let group_id_bytes = hex::decode(group_id_hex)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        let scoped_identity = self.require_scoped_identity().await?;
        let group_info_bytes = self
            .mls_context()
            .export_group_info(group_id_bytes.clone(), scoped_identity.as_bytes().to_vec())?;

        let confirmation_tag = self
            .mls_context()
            .get_confirmation_tag(group_id_bytes.clone())
            .unwrap_or_else(|_| vec![0u8; 32]);
        let confirmation_tag = if confirmation_tag.len() == 32 {
            confirmation_tag
        } else {
            vec![0u8; 32]
        };
        let group_context_hash = self
            .mls_context()
            .get_group_context_hash(group_id_bytes.clone())
            .unwrap_or_else(|_| vec![0u8; 32]);
        let group_context_hash = if group_context_hash.len() == 32 {
            group_context_hash
        } else {
            vec![0u8; 32]
        };

        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use rand::RngCore;
        use sha2::{Digest, Sha256};

        let conversation_id = uuid::Uuid::new_v4().to_string();
        let convo_uuid = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|e| OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}")))?;
        let transition_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential("auth_generation must be >= 1".into()));
        }
        let public_key = self.mls_context().identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);

        let metadata_plaintext = crate::metadata::GroupMetadataV1 {
            version: 1,
            title: _name.to_string(),
            description: _description.unwrap_or("").to_string(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        };
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let metadata_key = self.mls_context().safe_export_secret(group_id_bytes.clone(), 0x8001)
            .unwrap_or_else(|_| {
                let mut k = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut k);
                k.to_vec()
            });
        let metadata_key_arr: [u8; 32] = metadata_key.as_slice().try_into().map_err(|_| {
            OrchestratorError::Mls(MLSError::Internal("metadata key length mismatch".into()))
        })?;
        let ciphertext = crate::metadata::encrypt_metadata_blob(
            &metadata_key_arr,
            &group_id_bytes,
            0,
            1,
            &metadata_plaintext,
        )
        .map_err(|e| OrchestratorError::Mls(MLSError::Internal(format!("encrypt metadata snapshot: {e:?}"))))?;
        let conversation_kind = if initial_members.dids.map_or(0, |m| m.len()) > 1 {
            "group"
        } else if initial_members.dids.map_or(0, |m| m.len()) == 1 {
            "direct"
        } else {
            "group"
        };

        let mut participants = vec![serde_json::json!({
            "userDid": user_did,
            "role": "admin",
            "status": "active"
        })];
        if let Some(dids) = initial_members.dids {
            for did in dids {
                let root_did = super::credential_binding::credential_root_did(did);
                if root_did != user_did {
                    participants.push(serde_json::json!({
                        "userDid": root_did,
                        "role": if conversation_kind == "direct" { "admin" } else { "member" },
                        "status": "pending"
                    }));
                }
            }
        }
        participants.sort_by(|a, b| {
            let a_did = a.get("userDid").and_then(|u| u.as_str()).unwrap_or("");
            let b_did = b.get("userDid").and_then(|u| u.as_str()).unwrap_or("");
            a_did.cmp(b_did)
        });

        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#creationBody",
            "absence": true,
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "conversationId": conversation_id,
            "conversationKind": conversation_kind,
            "genesisGroupInfo": {
                "bytes": STANDARD.encode(&group_info_bytes),
                "contentType": "groupInfo",
                "framing": "mlsMessage",
                "sha256": STANDARD.encode(Sha256::digest(&group_info_bytes))
            },
            "idempotencyKey": idempotency_key,
            "keyId": key_id,
            "manifest": {
                "actorLeaf": {
                    "deviceId": actor_device_id,
                    "leafOrigin": "genesis",
                    "userDid": user_did
                },
                "participants": participants
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": auth_generation,
                    "authorDeviceId": actor_device_id,
                    "authorDid": user_did,
                    "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active",
                    "originSeq": 1,
                    "originTransitionId": transition_id,
                    "roleAtOrigin": "admin",
                    "signaturePublicKey": STANDARD.encode(&public_key)
                },
                "ciphertext": STANDARD.encode(&ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "confirmationTag": STANDARD.encode(&confirmation_tag),
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": 0,
                    "generation": 0,
                    "groupContextHash": STANDARD.encode(&group_context_hash),
                    "groupId": STANDARD.encode(&group_id_bytes)
                },
                "metadataVersion": 1,
                "nonce": STANDARD.encode(&nonce),
                "originTransitionId": transition_id
            },
            "next": {
                "confirmationTag": STANDARD.encode(&confirmation_tag),
                "conversationId": conversation_id,
                "epoch": 0,
                "generation": 0,
                "groupContextHash": STANDARD.encode(&group_context_hash),
                "groupId": STANDARD.encode(&group_id_bytes),
                "lifecycle": "active",
                "stateVersion": 0
            },
            "signatureDomain": "CATBIRD-CHAT-CREATE\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "transitionId": transition_id
        });

        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::CreateConversation,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;

        if response.status != 200 {
            return Err(OrchestratorError::Api(format!(
                "create_conversation failed with status {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }

        let resp_json: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|e| {
                OrchestratorError::Serialization(format!("create_conversation response: {e}"))
            })?;

        let resp_convo_id = resp_json
            .get("result")
            .and_then(|r| r.get("coordinates"))
            .and_then(|c| c.get("conversationId"))
            .and_then(|cid| cid.as_str())
            .unwrap_or(&conversation_id)
            .to_string();

        let mut member_views = vec![MemberView {
            did: user_did.to_string(),
            role: MemberRole::Admin,
        }];
        if let Some(dids) = initial_members.dids {
            for did in dids {
                let root_did = super::credential_binding::credential_root_did(did);
                if root_did != user_did {
                    member_views.push(MemberView {
                        did: root_did.to_string(),
                        role: if conversation_kind == "direct" {
                            MemberRole::Admin
                        } else {
                            MemberRole::Member
                        },
                    });
                }
            }
        }

        let mut convo = ConversationView {
            group_id: group_id_hex.to_string(),
            conversation_id: resp_convo_id,
            epoch: 0,
            members: member_views,
            metadata: Some(ConversationMetadata {
                name: if _name.is_empty() { None } else { Some(_name.to_string()) },
                description: _description.map(|d| d.to_string()),
                avatar_url: None,
            }),
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
            sequencer_did: None,
        };
        let bootstrap_target_epoch = if initial_members.dids.as_ref().map_or(false, |d| !d.is_empty()) {
            Some(1)
        } else {
            None
        };
        let conversation_id = &convo.conversation_id;
        rollback.bind_stable_conversation(&convo, bootstrap_target_epoch)?;
        // Handoff cleanup authority before materializing any stable-keyed
        // local row/cache. Keep the raw intent until the stable write commits.
        // When both ids are equal this is already the same single intent and
        // clearing it here would silently disarm cancellation cleanup.
        if conversation_id != group_id_hex {
            self.storage()
                .mark_pending_local_delete(
                    conversation_id,
                    Some(&rollback.encoded_delete_authority),
                )
                .await?;
            rollback.durable_intent_id = conversation_id.to_string();
            self.storage()
                .clear_pending_local_delete(group_id_hex)
                .await?;
        }

        self.storage()
            .ensure_conversation_exists(user_did, conversation_id, group_id_hex)
            .await?;

        self.storage()
            .update_join_info(conversation_id, user_did, JoinMethod::Creator, 0)
            .await?;

        // Crypto merge is not the application commit point. Persist the
        // stable projection before publishing any cache entry, pruning epoch
        // secrets, uploading metadata, or reporting success.
        let ffi_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;
        convo.epoch = ffi_epoch;
        let members: Vec<String> = convo.members.iter().map(|m| m.did.clone()).collect();
        let state = GroupState {
            group_id: group_id_hex.to_string(),
            conversation_id: convo.conversation_id.clone(),
            epoch: ffi_epoch,
            members,
        };
        self.storage().set_group_state(&state).await?;
        self.group_states()
            .lock()
            .await
            .insert(group_id_hex.to_string(), state);
        self.conversations()
            .lock()
            .await
            .insert(conversation_id.to_string(), convo.clone());
        self.conversation_states()
            .lock()
            .await
            .insert(conversation_id.to_string(), ConversationState::Active);
        self.cleanup_epoch_secrets_if_needed(conversation_id, group_id_hex, ffi_epoch)
            .await;
        let _ = self.api_client().publish_group_info(conversation_id, &group_info_bytes).await;
        let ffi_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;
        convo.epoch = ffi_epoch;
        tracing::info!(group_id = %group_id_hex, epoch = convo.epoch, "Group creation complete");
        Ok(convo)
    }

    /// Read back the delivery service's accepted epoch for a staged commit
    /// whose mutation endpoint does not echo one. This is bounded and matches
    /// either the stable conversation id or the current mutable group id for
    /// legacy wrapper callers.
    async fn fetch_server_epoch_for_staged_commit(&self, identifier: &str) -> Result<u64> {
        let mut pagination =
            super::pagination::PaginationGuard::for_conversations("staged commit epoch fence");
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .api_client()
                .get_conversations(100, cursor.as_deref())
                .await?;
            pagination.observe_page(page.conversations.len(), page.cursor.as_deref())?;
            if let Some(conversation) = page.conversations.into_iter().find(|conversation| {
                conversation.conversation_id == identifier || conversation.group_id == identifier
            }) {
                return Ok(conversation.epoch);
            }
            match page.cursor {
                Some(next) => cursor = Some(next),
                None => {
                    return Err(OrchestratorError::ConversationNotFound(
                        identifier.to_string(),
                    ));
                }
            }
        }
    }

    /// Fetch + decrypt the encrypted group metadata blob for a conversation and
    /// populate the cached `ConversationView.metadata` (name / description), so
    /// every client renders the group name after joining. Newly-added members
    /// can't derive a past epoch's exporter and so never cached the plaintext;
    /// this is how they obtain it.
    ///
    /// Best-effort: any failure (no metadata set, platform hasn't wired the
    /// blob fetch, key/epoch/AAD mismatch) is logged and skipped — the join
    /// itself is never affected.
    pub(crate) async fn hydrate_conversation_metadata(&self, conversation_id: &str) {
        let resolved = match self.resolve_conversation_context(conversation_id).await {
            Ok(resolved) => resolved,
            Err(_) => return,
        };
        let group_id_hex = resolved.group_id.clone();
        let group_id_bytes = match hex::decode(&group_id_hex) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };

        let info = match self
            .mls_context()
            .get_current_metadata(group_id_bytes.clone())
        {
            Ok(Some(info)) => info,
            Ok(None) => return, // no metadata set, or backend not wired
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, "hydrate_metadata: get_current_metadata failed");
                return;
            }
        };
        let Some(reference_json) = info.metadata_reference_json else {
            return; // group has no MetadataReference yet
        };
        let reference: crate::metadata::MetadataReference = match serde_json::from_slice(
            &reference_json,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, "hydrate_metadata: bad MetadataReference JSON");
                return;
            }
        };

        let blob = match self
            .api_client()
            .get_group_metadata_blob(conversation_id, &group_id_hex, &reference.blob_locator)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, "hydrate_metadata: blob fetch failed");
                return;
            }
        };

        let key: [u8; 32] = match info.metadata_key.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => {
                tracing::warn!(
                    convo = conversation_id,
                    "hydrate_metadata: metadata key wrong length"
                );
                return;
            }
        };
        let metadata = match crate::metadata::decrypt_metadata_blob(
            &key,
            &group_id_bytes,
            info.epoch,
            reference.metadata_version,
            &blob,
        ) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, epoch = info.epoch, "hydrate_metadata: decrypt failed");
                return;
            }
        };

        if let Some(view) = self.conversations().lock().await.get_mut(conversation_id) {
            view.metadata = Some(ConversationMetadata {
                name: Some(metadata.title.clone()),
                description: if metadata.description.is_empty() {
                    None
                } else {
                    Some(metadata.description.clone())
                },
                avatar_url: None,
            });
        }
        tracing::info!(
            convo = conversation_id,
            epoch = info.epoch,
            "hydrate_metadata: group name decrypted"
        );
    }

    /// Roll back a Welcome that has already materialized an OpenMLS group but
    /// has not reached the local projection commit point.
    ///
    /// OpenMLS deletion is performed first because it is the capability that
    /// makes the half-join usable for encryption. `delete_group` removes the
    /// group from memory only after its provider-backed durable cleanup has
    /// succeeded, so no separate provider flush is available or required.
    /// App-facing storage writes are then compensated before the original
    /// error is returned. If compensation itself fails, surface that fact as a
    /// recovery failure rather than claiming that rollback completed.
    async fn rollback_failed_welcome_join(
        &self,
        rollback: WelcomeJoinRollback<'_>,
        join_error: OrchestratorError,
    ) -> OrchestratorError {
        let mut cleanup_errors = Vec::new();

        match self.mls_context().delete_group(rollback.group_id) {
            Ok(()) | Err(crate::MLSError::GroupNotFound { .. }) => {}
            Err(error) => cleanup_errors.push(format!("OpenMLS group cleanup failed: {error}")),
        }

        if rollback.group_state_write_attempted {
            let cleanup_result = match rollback.prior_group_state {
                Some(prior) => self.storage().set_group_state(&prior).await,
                None => {
                    self.storage()
                        .delete_group_state(rollback.group_id_hex)
                        .await
                }
            };
            if let Err(error) = cleanup_result {
                cleanup_errors.push(format!("GroupState cleanup failed: {error}"));
            }
        }

        if rollback.remove_new_conversation {
            if let Some(conversation_id) = rollback.conversation_id {
                if let Err(error) = self
                    .storage()
                    .delete_conversations(rollback.user_did, &[conversation_id])
                    .await
                {
                    cleanup_errors.push(format!("conversation cleanup failed: {error}"));
                }
            }
        }

        if cleanup_errors.is_empty() {
            join_error
        } else {
            OrchestratorError::RecoveryFailed(format!(
                "Welcome join failed ({join_error}); rollback incomplete: {}",
                cleanup_errors.join("; ")
            ))
        }
    }

    /// Join an existing group via a Welcome message.
    pub async fn join_group(&self, welcome_data: &[u8]) -> Result<ConversationView> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::info!("Joining group from Welcome message");

        let scoped_identity = self.require_scoped_identity().await?;
        let identity_bytes = scoped_identity.into_bytes();
        let welcome_result = self.mls_context().process_welcome(
            welcome_data.to_vec(),
            identity_bytes,
            Some(self.config().group_config.clone()),
        )?;
        let group_id_hex = hex::encode(&welcome_result.group_id);

        tracing::debug!(group_id = %group_id_hex, "Processed Welcome message");

        // Fetch the stable conversation mapping from a bounded traversal. A
        // Welcome may target a conversation beyond the first 100 rows; the DS
        // controls cursors, so cycles and excessive pages/items fail closed.
        let lookup_result: Result<ConversationView> = async {
            let mut pagination =
                super::pagination::PaginationGuard::for_conversations("join_group Welcome lookup");
            let mut cursor: Option<String> = None;
            loop {
                let page = self
                    .api_client()
                    .get_conversations(100, cursor.as_deref())
                    .await?;
                pagination.observe_page(page.conversations.len(), page.cursor.as_deref())?;
                if let Some(found) = page
                    .conversations
                    .into_iter()
                    .find(|candidate| candidate.group_id == group_id_hex)
                {
                    return Ok(found);
                }
                match page.cursor {
                    Some(next) => cursor = Some(next),
                    None => {
                        return Err(OrchestratorError::ConversationNotFound(
                            group_id_hex.clone(),
                        ));
                    }
                }
            }
        }
        .await;
        let mut convo = match lookup_result {
            Ok(conversation) => conversation,
            Err(lookup_error) => {
                return Err(self
                    .rollback_failed_welcome_join(
                        WelcomeJoinRollback {
                            user_did: &user_did,
                            conversation_id: None,
                            group_id_hex: &group_id_hex,
                            group_id: welcome_result.group_id,
                            group_state_write_attempted: false,
                            prior_group_state: None,
                            remove_new_conversation: false,
                        },
                        lookup_error,
                    )
                    .await);
            }
        };

        let ffi_epoch = match self
            .mls_context()
            .get_epoch(welcome_result.group_id.clone())
        {
            Ok(epoch) => epoch,
            Err(error) => {
                return Err(self
                    .rollback_failed_welcome_join(
                        WelcomeJoinRollback {
                            user_did: &user_did,
                            conversation_id: Some(&convo.conversation_id),
                            group_id_hex: &group_id_hex,
                            group_id: welcome_result.group_id,
                            group_state_write_attempted: false,
                            prior_group_state: None,
                            remove_new_conversation: false,
                        },
                        error.into(),
                    )
                    .await);
            }
        };

        // Snapshot the two app-facing rows before beginning the compensatable
        // write sequence. A Welcome can be a recovery path for an already-known
        // conversation, so rollback must restore a pre-existing GroupState and
        // must not delete a pre-existing conversation projection.
        let prior_group_state = match self.storage().get_group_state(&group_id_hex).await {
            Ok(state) => state,
            Err(error) => {
                return Err(self
                    .rollback_failed_welcome_join(
                        WelcomeJoinRollback {
                            user_did: &user_did,
                            conversation_id: Some(&convo.conversation_id),
                            group_id_hex: &group_id_hex,
                            group_id: welcome_result.group_id,
                            group_state_write_attempted: false,
                            prior_group_state: None,
                            remove_new_conversation: false,
                        },
                        error,
                    )
                    .await);
            }
        };
        let had_existing_conversation = match self
            .storage()
            .get_conversation(&user_did, &convo.conversation_id)
            .await
        {
            Ok(conversation) => conversation.is_some(),
            Err(error) => {
                return Err(self
                    .rollback_failed_welcome_join(
                        WelcomeJoinRollback {
                            user_did: &user_did,
                            conversation_id: Some(&convo.conversation_id),
                            group_id_hex: &group_id_hex,
                            group_id: welcome_result.group_id,
                            group_state_write_attempted: false,
                            prior_group_state: None,
                            remove_new_conversation: false,
                        },
                        error,
                    )
                    .await);
            }
        };

        let members: Vec<String> = convo.members.iter().map(|m| m.did.clone()).collect();
        let state = GroupState {
            group_id: group_id_hex.clone(),
            conversation_id: convo.conversation_id.clone(),
            epoch: ffi_epoch,
            members,
        };
        if let Err(error) = self.storage().set_group_state(&state).await {
            return Err(self
                .rollback_failed_welcome_join(
                    WelcomeJoinRollback {
                        user_did: &user_did,
                        conversation_id: Some(&convo.conversation_id),
                        group_id_hex: &group_id_hex,
                        group_id: welcome_result.group_id,
                        group_state_write_attempted: true,
                        prior_group_state,
                        remove_new_conversation: false,
                    },
                    error,
                )
                .await);
        }
        if let Err(error) = self
            .storage()
            .ensure_conversation_exists(&user_did, &convo.conversation_id, &group_id_hex)
            .await
        {
            return Err(self
                .rollback_failed_welcome_join(
                    WelcomeJoinRollback {
                        user_did: &user_did,
                        conversation_id: Some(&convo.conversation_id),
                        group_id_hex: &group_id_hex,
                        group_id: welcome_result.group_id,
                        group_state_write_attempted: true,
                        prior_group_state,
                        remove_new_conversation: !had_existing_conversation,
                    },
                    error,
                )
                .await);
        }
        if let Err(error) = self
            .storage()
            .update_join_info(
                &convo.conversation_id,
                &user_did,
                JoinMethod::Welcome,
                ffi_epoch,
            )
            .await
        {
            return Err(self
                .rollback_failed_welcome_join(
                    WelcomeJoinRollback {
                        user_did: &user_did,
                        conversation_id: Some(&convo.conversation_id),
                        group_id_hex: &group_id_hex,
                        group_id: welcome_result.group_id,
                        group_state_write_attempted: true,
                        prior_group_state,
                        remove_new_conversation: !had_existing_conversation,
                    },
                    error,
                )
                .await);
        }

        // Publish the joined group only after all fallible authoritative writes
        // have committed. Before this point, resolvers and send paths cannot
        // discover the just-processed Welcome through in-memory caches.
        self.conversations()
            .lock()
            .await
            .insert(convo.conversation_id.clone(), convo.clone());
        self.group_states()
            .lock()
            .await
            .insert(group_id_hex.clone(), state);

        // Welcome adoption can land well beyond the retention window. Run
        // cleanup only after both crypto state and the stable application
        // projection are durable and visible.
        self.cleanup_epoch_secrets_if_needed(&convo.conversation_id, &group_id_hex, ffi_epoch)
            .await;

        // Insert history boundary marker for Welcome joins.
        // On iOS, Swift inserts first — message_exists prevents duplicates.
        let marker_id = format!("hb-{}-{}", group_id_hex, ffi_epoch);
        if !self
            .storage()
            .message_exists(&marker_id)
            .await
            .unwrap_or(true)
        {
            let payload = MLSMessagePayload::system("history_boundary.new_member");
            let marker = Message {
                id: marker_id,
                conversation_id: convo.conversation_id.clone(),
                sender_did: user_did.clone(),
                text: "history_boundary.new_member".to_string(),
                timestamp: chrono::Utc::now(),
                epoch: ffi_epoch,
                sequence_number: 0,
                is_own: true,
                delivery_status: None,
                payload_json: serde_json::to_string(&payload).ok(),
            };
            if let Err(e) = self.storage().store_message(&marker).await {
                tracing::warn!(error = %e, "Failed to store history boundary marker");
            }
        }

        // Decrypt the group name/description now that we hold the joined epoch,
        // and reflect it in the returned view. Best-effort.
        self.hydrate_conversation_metadata(&convo.conversation_id)
            .await;
        if let Some(view) = self
            .conversations()
            .lock()
            .await
            .get(&convo.conversation_id)
        {
            convo.metadata = view.metadata.clone();
        }

        Ok(convo)
    }

    /// Add members to an existing group.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44. Platforms
    /// can migrate to the new API incrementally; this wrapper will remain
    /// until all clients have moved over.
    pub async fn add_members(&self, conversation_id: &str, member_dids: &[String]) -> Result<()> {
        self.check_shutdown().await?;
        let resolved = self.resolve_legacy_group_identifier(conversation_id).await?;
        let group_id = resolved.group_id;
        let conversation_id = &resolved.conversation_id;
        tracing::info!(
            conversation_id,
            group_id,
            count = member_dids.len(),
            "Adding members to group"
        );

        // Fetch key packages for the new members.
        let key_packages = if member_dids.is_empty() {
            vec![]
        } else {
            let actor_device_id = self.require_actor_device_id().await?;
            self.api_client()
                .get_key_packages(&actor_device_id, member_dids)
                .await?
        };
        // ADR-009 D3: enforce credential binding before cloning/staging.
        self.verify_fetched_key_packages(
            member_dids,
            &key_packages,
            "add_members",
            Some(&group_id),
        )
        .await?;

        let kp_data: Vec<crate::KeyPackageData> = key_packages
            .iter()
            .map(|kp| crate::KeyPackageData {
                data: kp.key_package_data.clone(),
            })
            .collect();

        super::credential_binding::enforce_outbound_key_package_did_bindings(
            member_dids,
            &kp_data,
        )?;

        // Stage the commit via the new API.
        let plan = self
            .stage_commit_for_group(
                conversation_id,
                &group_id,
                CommitKind::AddMembers {
                    member_dids: member_dids.to_vec(),
                    key_packages: kp_data,
                },
            )
            .await?;

        // Ship commit + Welcome to the DS.
        let server_result = self
            .submit_commit_transition_helper(
                conversation_id,
                &hex::decode(&group_id).unwrap_or_default(),
                plan.target_epoch,
                &plan.commit_bytes,
                plan.welcome_bytes.as_deref(),
                member_dids,
            )
            .await;

        match server_result {
            Ok(result) => {
                if !result.success {
                    self.discard_pending_after_failed_operation(
                        plan.handle,
                        "add_members",
                        "server returned success=false",
                    )
                    .await?;
                    return Err(OrchestratorError::MemberSyncFailed);
                }

                // Best-effort receipt storage, with equivocation detection
                // against previously stored receipts (WS-3 stage 1, ADR-009 D8).
                if let Some(ref receipt) = result.receipt {
                    self.record_and_check_sequencer_receipt(receipt, "add_members")
                        .await;
                }

                if result.new_epoch != plan.target_epoch {
                    let target_epoch = plan.target_epoch;
                    self.discard_pending_after_failed_operation(
                        plan.handle,
                        "add_members epoch fence",
                        "server epoch did not equal staged target",
                    )
                    .await?;
                    return Err(OrchestratorError::EpochMismatch {
                        local: target_epoch,
                        remote: result.new_epoch,
                    });
                }
                self.confirm_commit(plan.handle, result.new_epoch).await?;
            }
            Err(e) => {
                self.discard_pending_after_failed_operation(
                    plan.handle,
                    "add_members",
                    &e.to_string(),
                )
                .await?;
                return Err(e);
            }
        }

        tracing::info!(conversation_id, group_id = %group_id, "Members added successfully");
        Ok(())
    }
    /// Remove members from a group.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44.
    pub async fn remove_members(
        &self,
        conversation_id: &str,
        member_dids: &[String],
    ) -> Result<()> {
        self.check_shutdown().await?;
        let resolved = self.resolve_legacy_group_identifier(conversation_id).await?;
        let group_id = resolved.group_id;
        let conversation_id = &resolved.conversation_id;
        tracing::info!(
            conversation_id,
            group_id,
            count = member_dids.len(),
            "Removing members from group"
        );

        let plan = self
            .stage_commit_for_group(
                conversation_id,
                &group_id,
                CommitKind::RemoveMembers {
                    member_dids: member_dids.to_vec(),
                },
            )
            .await?;

        match self
            .submit_remove_transition_helper(
                conversation_id,
                &hex::decode(&group_id).unwrap_or_default(),
                plan.target_epoch,
                &plan.commit_bytes,
                member_dids,
            )
            .await
        {
            Ok(()) => {
                self.confirm_commit(plan.handle, plan.target_epoch).await?;
                Ok(())
            }
            Err(e) => {
                self.discard_pending_after_failed_operation(
                    plan.handle,
                    "remove_members",
                    &e.to_string(),
                )
                .await?;
                Err(e)
            }
        }
    }

    /// Atomically swap members: remove old devices + add new in one commit.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44.
    pub async fn swap_members(
        &self,
        group_id: &str,
        remove_dids: &[String],
        add_dids: &[String],
    ) -> Result<()> {
        self.check_shutdown().await?;
        tracing::info!(
            group_id,
            remove_count = remove_dids.len(),
            add_count = add_dids.len(),
            "swap_members"
        );

        let key_packages = if add_dids.is_empty() {
            vec![]
        } else {
            let actor_device_id = self.require_actor_device_id().await?;
            self.api_client()
                .get_key_packages(&actor_device_id, add_dids)
                .await?
        };

        // ADR-009 D3: enforce credential binding before cloning/staging.
        self.verify_fetched_key_packages(add_dids, &key_packages, "swap_members", Some(group_id))
            .await?;

        let kp_data: Vec<crate::KeyPackageData> = key_packages
            .iter()
            .map(|kp| crate::KeyPackageData {
                data: kp.key_package_data.clone(),
            })
            .collect();

        super::credential_binding::enforce_outbound_key_package_did_bindings(add_dids, &kp_data)?;

        let plan = self
            .stage_commit(
                group_id,
                CommitKind::SwapMembers {
                    remove_dids: remove_dids.to_vec(),
                    add_dids: add_dids.to_vec(),
                    add_key_packages: kp_data,
                },
            )
            .await?;

        let resolved = self.resolve_legacy_group_identifier(group_id).await?;
        let convo_id = &resolved.conversation_id;
        let group_id_bytes = resolved.group_id_bytes()?;

        if add_dids.is_empty() {
            return match self
                .submit_remove_transition_helper(
                    convo_id,
                    &group_id_bytes,
                    plan.target_epoch,
                    &plan.commit_bytes,
                    remove_dids,
                )
                .await
            {
                Ok(()) => self
                    .confirm_commit(plan.handle, plan.target_epoch)
                    .await
                    .map(|_| ()),
                Err(error) => {
                    self.discard_pending_after_failed_operation(
                        plan.handle,
                        "swap_members removal",
                        &error.to_string(),
                    )
                    .await?;
                    Err(error)
                }
            };
        }

        let server_result = self
            .submit_commit_transition_helper(
                convo_id,
                &group_id_bytes,
                plan.target_epoch,
                &plan.commit_bytes,
                plan.welcome_bytes.as_deref(),
                add_dids,
            )
            .await;

        match server_result {
            Ok(result) => {
                if !result.success {
                    self.discard_pending_after_failed_operation(
                        plan.handle,
                        "swap_members",
                        "server returned success=false",
                    )
                    .await?;
                    return Err(OrchestratorError::MemberSyncFailed);
                }

                if let Some(ref receipt) = result.receipt {
                    self.record_and_check_sequencer_receipt(receipt, "swap_members")
                        .await;
                }

                if result.new_epoch != plan.target_epoch {
                    let target_epoch = plan.target_epoch;
                    self.discard_pending_after_failed_operation(
                        plan.handle,
                        "swap_members epoch fence",
                        "server epoch did not equal staged target",
                    )
                    .await?;
                    return Err(OrchestratorError::EpochMismatch {
                        local: target_epoch,
                        remote: result.new_epoch,
                    });
                }
                self.confirm_commit(plan.handle, result.new_epoch).await?;
                tracing::info!(group_id, "swap_members complete");
                Ok(())
            }
            Err(e) => {
                self.discard_pending_after_failed_operation(
                    plan.handle,
                    "swap_members",
                    &e.to_string(),
                )
                .await?;
                Err(e)
            }
        }
    }
    /// Leave a conversation.
    pub async fn leave_group(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential("auth_generation must be >= 1".into()));
        }
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);
        let resolved = self.resolve_legacy_group_identifier(convo_id).await?;
        let convo_id = &resolved.conversation_id;
        let group_id_bytes = resolved.group_id_bytes().unwrap_or_else(|_| vec![0u8; 32]);
        let epoch = self
            .mls_context()
            .get_epoch(group_id_bytes.clone())
            .unwrap_or(0);
        let tag_bytes = self
            .mls_context()
            .get_confirmation_tag(group_id_bytes.clone())
            .unwrap_or_else(|_| vec![0u8; 32]);
        let tag_bytes = if tag_bytes.len() == 32 {
            tag_bytes
        } else {
            vec![0u8; 32]
        };
        let gc_hash = self
            .mls_context()
            .get_group_context_hash(group_id_bytes.clone())
            .unwrap_or_else(|_| vec![0u8; 32]);
        let gc_hash = if gc_hash.len() == 32 {
            gc_hash
        } else {
            vec![0u8; 32]
        };
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#leaveRequestBody",
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "keyId": key_id,
            "leaveRequestId": uuid::Uuid::new_v4().to_string(),
            "prior": {
                "confirmationTag": STANDARD.encode(&tag_bytes),
                "conversationId": convo_id,
                "epoch": epoch,
                "generation": 0,
                "groupContextHash": STANDARD.encode(&gc_hash),
                "groupId": STANDARD.encode(&group_id_bytes),
                "lifecycle": "active",
                "stateVersion": 0
            },
            "signatureDomain": "CATBIRD-CHAT-LEAVE-REQUEST\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });

        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::RequestLeave,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;

        if response.status != 200 {
            return Err(OrchestratorError::Api(format!(
                "leave_group failed: {}",
                response.status
            )));
        }

        self.force_delete_local(convo_id).await
    }

    /// Delete a conversation (admin action).
    pub async fn delete_group(&self, convo_id: &str) -> Result<()> {
        self.leave_group(convo_id).await
    }

    /// Leave a group via self-remove: propose own removal, send to group, then
    /// notify the server and clean up locally.
    pub async fn leave_via_self_remove(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let _user_did = self.require_user_did().await?;

        tracing::info!(convo_id, "Leaving group via self-remove proposal");

        let resolved = self.resolve_conversation_context(convo_id).await?;
        let group_id_bytes = resolved.group_id_bytes()?;

        let proposal_bytes = self.mls_context().propose_self_remove(group_id_bytes.clone())?;

        let epoch = {
            let states = self.group_states().lock().await;
            resolved
                .group_state(&states)
                .map(|gs| gs.epoch)
                .unwrap_or(0)
        };

        let message_id = uuid::Uuid::new_v4().to_string();
        let _ = self
            .send_message_prepared(convo_id, &proposal_bytes, epoch, &message_id)
            .await;

        self.leave_group(convo_id).await
    }

    /// Commit pending self-remove proposals for a group.
    pub async fn commit_self_remove_proposals(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::info!(convo_id, "Committing pending self-remove proposals");

        let resolved = self.resolve_conversation_context(convo_id).await?;
        let group_id_bytes = resolved.group_id_bytes()?;

        // Preflight the durable projection before staging or sending anything.
        // Once the DS accepts the commit there is no safe way to rediscover a
        // missing/mismatched application state without entering recovery.
        let cached_state = {
            let states = self.group_states().lock().await;
            resolved.group_state(&states).cloned()
        };
        let Some(mut projected_state) = (match cached_state {
            Some(state) => Some(state),
            None => self.storage().get_group_state(&resolved.group_id).await?,
        }) else {
            return Err(OrchestratorError::Storage(format!(
                "Missing GroupState before pending-proposal commit for {convo_id}"
            )));
        };
        if projected_state.group_id != resolved.group_id
            || projected_state.conversation_id != resolved.conversation_id
        {
            return Err(OrchestratorError::Storage(format!(
                "Mismatched GroupState before pending-proposal commit for {convo_id}"
            )));
        }
        let source_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;
        if projected_state.epoch != source_epoch {
            self.mark_needs_rejoin_critical(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed(format!(
                "Pending-proposal commit projection is at epoch {} but MLS is at {source_epoch} for {convo_id}",
                projected_state.epoch
            )));
        }
        let target_epoch = source_epoch.checked_add(1).ok_or_else(|| {
            OrchestratorError::InvalidInput(format!(
                "MLS epoch overflow while committing pending proposals for {convo_id}"
            ))
        })?;

        let commit_bytes = match self
            .mls_context()
            .commit_pending_proposals(group_id_bytes.clone())
        {
            Ok(bytes) => bytes,
            Err(crate::MLSError::InvalidInput { .. }) => {
                tracing::debug!(convo_id, "No pending proposals to commit");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        let hash = Sha256::digest(&commit_bytes).to_vec();
        self.track_epoch_changing_own_commit(
            hash.clone(),
            OwnCommitExpectation {
                conversation_id: convo_id.to_string(),
                group_id: resolved.group_id.clone(),
                target_epoch,
            },
        )
        .await;

        if let Err(send_error) = self
            .submit_commit_transition_helper(
                convo_id,
                &group_id_bytes,
                target_epoch,
                &commit_bytes,
                None,
                &[],
            )
            .await
        {
            if let Err(cleanup_error) = self
                .mls_context()
                .clear_pending_commit(group_id_bytes.clone())
            {
                self.mark_needs_rejoin_critical(convo_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "pending-proposal send failed ({send_error}); local pending-commit cleanup also failed ({cleanup_error})"
                )));
            }
            self.remove_own_commit_tracking(&hash).await;
            return Err(send_error);
        }

        let new_epoch = match self
            .mls_context()
            .merge_pending_commit(group_id_bytes.clone())
        {
            Ok(epoch) => epoch,
            Err(error) => {
                self.mark_needs_rejoin_critical(convo_id).await;
                return Err(error.into());
            }
        };
        if new_epoch != target_epoch {
            self.mark_needs_rejoin_critical(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed(format!(
                "pending-proposal merge advanced to epoch {new_epoch}, expected exactly {target_epoch} for {convo_id}"
            )));
        }
        if let Err(error) = self.mls_context().ensure_storage_durable() {
            self.mark_needs_rejoin_critical(convo_id).await;
            return Err(error.into());
        }
        projected_state.epoch = new_epoch;
        if let Err(error) = self.storage().set_group_state(&projected_state).await {
            self.mark_needs_rejoin_critical(convo_id).await;
            return Err(error);
        }
        // Local MLS and application storage now prove the target epoch. Keep
        // the hash for replay suppression, but no longer require a transient
        // expectation lookup when the DS fans the accepted commit back.
        self.mark_own_commit_durably_confirmed(&hash).await;
        {
            let mut states = self.group_states().lock().await;
            normalize_group_state(&mut states, projected_state);
        }
        self.cleanup_epoch_secrets_if_needed(convo_id, &resolved.group_id, new_epoch)
            .await;


        tracing::info!(
            convo_id,
            epoch = new_epoch,
            "Self-remove proposals committed"
        );
        Ok(())
    }

    /// Atomic encrypted metadata update (Phase A.2).
    ///
    /// Uses [`MlsCryptoContext::update_group_metadata_encrypted`] — staged
    /// commit + post-commit-epoch key derivation + ChaCha20-Poly1305
    /// encryption all in one shot — then uploads the encrypted blob via
    /// [`MLSAPIClient::put_group_metadata_blob`] and the commit via
    /// [`MLSAPIClient::commit_group_change`], finally merging the pending
    /// commit locally to advance the epoch.
    ///
    /// On any error, the pending commit is discarded so the local group
    /// state stays at the pre-update epoch.
    pub async fn update_group_metadata_encrypted(
        &self,
        conversation_id: &str,
        title: Option<&str>,
        description: Option<&str>,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
        avatar_bytes: Option<&[u8]>,
    ) -> Result<()> {
        self.check_shutdown().await?;

        let resolved = self.resolve_conversation_context(conversation_id).await?;
        let group_id_hex = resolved.group_id.clone();
        let group_id_bytes = hex::decode(&group_id_hex).map_err(|_| {
            OrchestratorError::InvalidInput("Invalid hex group ID for metadata update".into())
        })?;

        // 1. Stage commit + encrypt + assemble artifacts in one FFI call.
        let result = self.mls_context().update_group_metadata_encrypted(
            group_id_bytes.clone(),
            title.map(|s| s.to_string()),
            description.map(|s| s.to_string()),
            avatar_blob_locator.map(|s| s.to_string()),
            avatar_content_type.map(|s| s.to_string()),
        )?;

        // 2. Upload the encrypted blob first; if this fails we must discard the
        //    pending commit so the local epoch doesn't advance into a state
        //    other clients can't reach (no blob → can't decrypt metadata).
        if let Err(e) = self
            .put_group_metadata_blob(
                conversation_id,
                &group_id_hex,
                &result.metadata_blob_locator,
                &result.metadata_blob_ciphertext,
                "metadata",
                result.metadata_version,
                None,
            )
            .await
        {
            if let Err(cleanup_error) = self
                .mls_context()
                .clear_pending_commit(group_id_bytes.clone())
            {
                self.mark_needs_rejoin_critical(conversation_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "metadata blob upload failed ({e}); pending commit cleanup also failed: {cleanup_error}"
                )));
            }
            return Err(e);
        }

        // 3. Submit the commit. Same discard logic on failure.
        if let Err(e) = self
            .submit_commit_transition_helper(
                conversation_id,
                &group_id_bytes,
                self.mls_context().get_epoch(group_id_bytes.clone()).unwrap_or(0) + 1,
                &result.commit_bytes,
                None,
                &[],
            )
            .await
        {
            if let Err(cleanup_error) = self
                .mls_context()
                .clear_pending_commit(group_id_bytes.clone())
            {
                self.mark_needs_rejoin_critical(conversation_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "metadata commit submission failed ({e}); pending commit cleanup also failed: {cleanup_error}"
                )));
            }
            return Err(e);
        }

        // 4. Merge locally (advances epoch and applies the new
        //    MetadataReference in AppDataDictionary).
        let merge_epoch = match self
            .mls_context()
            .merge_pending_commit(group_id_bytes.clone())
        {
            Ok(epoch) => epoch,
            Err(error) => {
                self.mark_needs_rejoin_critical(conversation_id).await;
                return Err(error.into());
            }
        };

        // The crypto merge is only the first half of the commit point. Make
        // the stable conversation -> mutable group/epoch projection durable
        // before publishing it to the cache, pruning epoch secrets, or
        // returning success. A storage failure after server acceptance is a
        // recovery event, never a successful metadata update.
        let cached_state = {
            let states = self.group_states().lock().await;
            resolved.group_state(&states).cloned()
        };
        let existing_state = match cached_state {
            Some(state) => Some(state),
            None => self.storage().get_group_state(&group_id_hex).await?,
        };
        let Some(mut projected_state) = existing_state else {
            self.mark_needs_rejoin_critical(conversation_id).await;
            return Err(OrchestratorError::Storage(format!(
                "Missing GroupState after metadata commit for conversation {conversation_id} (group {group_id_hex})"
            )));
        };
        if projected_state.group_id != group_id_hex {
            self.mark_needs_rejoin_critical(conversation_id).await;
            return Err(OrchestratorError::Storage(format!(
                "Mismatched GroupState after metadata commit for conversation {conversation_id} (group {group_id_hex})"
            )));
        }
        projected_state.conversation_id = conversation_id.to_string();
        projected_state.epoch = merge_epoch;
        if let Err(error) = self.storage().set_group_state(&projected_state).await {
            self.mark_needs_rejoin_critical(conversation_id).await;
            return Err(error);
        }
        {
            let mut states = self.group_states().lock().await;
            normalize_group_state(&mut states, projected_state);
        }
        self.cleanup_epoch_secrets_if_needed(conversation_id, &group_id_hex, merge_epoch)
            .await;

        // 5. Encrypt + upload the avatar blob at the SAME post-commit
        //    (epoch, metadata_version) the metadata blob was bound to, so
        //    joiners — who fetch the avatar via `avatar_blob_locator` from the
        //    decrypted metadata and decrypt it with their current-epoch key —
        //    get a matching AAD (`group_id || epoch || metadata_version`). The
        //    metadata blob references the locator; without this upload the
        //    locator points at nothing and joiners see no avatar. Best-effort:
        //    the metadata commit already merged, so a failed avatar upload
        //    leaves the group named-but-avatarless rather than breaking it.
        if let (Some(bytes), Some(locator)) = (avatar_bytes, avatar_blob_locator) {
            match self
                .mls_context()
                .get_current_metadata(group_id_bytes.clone())
            {
                Ok(Some(info)) => match <[u8; 32]>::try_from(info.metadata_key.as_slice()) {
                    Ok(key) => {
                        match crate::metadata::encrypt_avatar_blob(
                            &key,
                            &group_id_bytes,
                            info.epoch,
                            result.metadata_version,
                            bytes,
                        ) {
                            Ok(encrypted_avatar) => {
                                tracing::info!(conversation_id, "Avatar encrypted successfully");
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, conversation_id, "Avatar encryption failed")
                            }
                        }
                    }
                    Err(_) => tracing::warn!(
                        conversation_id,
                        "Avatar upload skipped: metadata key wrong length"
                    ),
                },
                Ok(None) => tracing::warn!(
                    conversation_id,
                    "Avatar upload skipped: no current metadata after merge"
                ),
                Err(e) => {
                    tracing::warn!(error = %e, conversation_id, "Avatar upload skipped: get_current_metadata failed")
                }
            }
        }

        tracing::info!(
            conversation_id,
            new_epoch = merge_epoch,
            metadata_version = result.metadata_version,
            blob_locator = %result.metadata_blob_locator,
            has_avatar = avatar_bytes.is_some(),
            "Group metadata updated (encrypted)"
        );
        Ok(())
    }

    /// Force delete a conversation from local state only.
    ///
    /// WS-5.3 crash-safety: the MLS-layer delete and the storage deletes are
    /// separate non-atomic steps, so a crash in between would orphan state.
    /// A pending-delete intent is persisted first and cleared only after all
    /// delete steps ran; `reconcile_pending_local_deletes` (called from
    /// `initialize`) finishes any delete a crash interrupted.
    pub(crate) async fn force_delete_local(&self, convo_id: &str) -> Result<()> {
        if self.force_delete_local_with_group(convo_id, None).await {
            Ok(())
        } else {
            Err(OrchestratorError::Storage(format!(
                "local deletion for conversation {convo_id} is incomplete; durable retry intent retained"
            )))
        }
    }

    /// Roll back local state while explicitly carrying a newly-created MLS
    /// group that has not yet acquired a stable conversation or GroupState
    /// mapping. The explicit id is persisted in the same owner-bound cleanup
    /// authority as every discovered predecessor, so crash replay remains
    /// complete and tenant-bound.
    async fn force_delete_local_with_group(
        &self,
        convo_id: &str,
        explicit_group_id: Option<&str>,
    ) -> bool {
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        let owner_user_did = match self.cleanup_user_did().await {
            Ok(user_did) => user_did,
            Err(error) => {
                tracing::warn!(error = %error, convo_id, "No lifecycle-bound user during local delete; refusing destructive cleanup");
                return false;
            }
        };
        let captured_group_ids = explicit_group_id
            .map(|group_id| vec![group_id.to_string()])
            .unwrap_or_default();
        let snapshot = match self
            .snapshot_local_delete_groups(convo_id, &captured_group_ids, &[])
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(error = %error, convo_id, "Failed to snapshot complete local-delete authority; refusing destructive cleanup");
                return false;
            }
        };
        let encoded_authority = match snapshot.encode_authority(&owner_user_did) {
            Ok(authority) => authority,
            Err(error) => {
                tracing::warn!(error = %error, convo_id, "Failed to encode local-delete authority; refusing destructive cleanup");
                return false;
            }
        };

        // 1. Persist the delete intent BEFORE mutating anything. Carries the
        // resolved group id so the startup sweep can drop the MLS group even
        // after the conversation row (the id mapping) is gone.
        if let Err(e) = self
            .storage()
            .mark_pending_local_delete(convo_id, Some(&encoded_authority))
            .await
        {
            tracing::warn!(error = %e, convo_id, "Failed to persist local-delete intent; refusing destructive cleanup");
            return false;
        }

        // 2. Run the delete steps.
        let all_steps_ok = self
            .force_delete_local_steps(convo_id, Some(&encoded_authority))
            .await;

        // 3. Clear the intent only after all delete steps succeeded (trait
        // contract on `clear_pending_local_delete`). A failed step keeps the
        // intent so the next startup sweep retries the idempotent delete.
        if all_steps_ok {
            if let Err(e) = self.storage().clear_pending_local_delete(convo_id).await {
                tracing::warn!(error = %e, convo_id, "Failed to clear local-delete intent (startup sweep will redo an idempotent delete)");
                return false;
            }
            true
        } else {
            tracing::warn!(
                convo_id,
                "force_delete_local: one or more delete steps failed — keeping pending-delete intent for the startup sweep"
            );
            false
        }
    }

    /// Fault-injection helper used by rustFull E2E recovery gates.
    ///
    /// Deletes only the local OpenMLS group for a conversation and marks the
    /// conversation for rejoin. Unlike `force_delete_local`, this preserves the
    /// conversation projection so deferred Rust recovery can rediscover and
    /// repair the half-joined state.
    pub async fn debug_wipe_local_group_for_recovery(
        &self,
        convo_id: &str,
    ) -> Result<DebugWipeLocalGroupResult> {
        self.check_shutdown().await?;
        self.require_user_did().await?;
        let transition_lock = self.rejoin_lock(convo_id).await;
        let _transition_guard = transition_lock.lock().await;
        if self
            .reset_blocks_non_reset_transition_locked(convo_id)
            .await?
        {
            return Err(
                crate::orchestrator::error::OrchestratorError::RecoveryFailed(format!(
                    "durable reset authority blocks debug wipe for {convo_id}"
                )),
            );
        }

        let group_id_hex = self.group_id_hex_for_conversation(convo_id).await;
        let mut deleted_local_group = false;

        if let Some(group_id_bytes) = group_id_hex
            .as_deref()
            .and_then(|group_id| hex::decode(group_id).ok())
        {
            match self.mls_context().delete_group(group_id_bytes) {
                Ok(()) => deleted_local_group = true,
                Err(crate::MLSError::GroupNotFound { .. }) => {
                    tracing::debug!(
                        convo_id,
                        group_id = ?group_id_hex,
                        "Debug wipe found local MLS group already absent"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }

        if let Err(e) = self.storage().delete_group_state(convo_id).await {
            tracing::warn!(
                error = %e,
                convo_id,
                "Debug wipe failed to delete conversation-keyed group state"
            );
            return Err(e);
        }
        if let Some(group_id) = group_id_hex
            .as_deref()
            .filter(|group_id| *group_id != convo_id)
        {
            if let Err(e) = self.storage().delete_group_state(group_id).await {
                tracing::warn!(
                    error = %e,
                    convo_id,
                    group_id,
                    "Debug wipe failed to delete group-id-keyed group state"
                );
                return Err(e);
            }
        }

        self.storage().mark_needs_rejoin(convo_id).await?;
        self.project_non_reset_cache_locked(convo_id, ConversationState::NeedsRejoin)
            .await
            .and_then(|projected| {
                if projected {
                    Ok(())
                } else {
                    Err(
                        crate::orchestrator::error::OrchestratorError::RecoveryFailed(format!(
                            "durable reset authority blocks debug wipe projection for {convo_id}"
                        )),
                    )
                }
            })?;

        {
            let mut states = self.group_states().lock().await;
            states.remove(convo_id);
            if let Some(group_id) = group_id_hex
                .as_deref()
                .filter(|group_id| *group_id != convo_id)
            {
                states.remove(group_id);
            }
        }

        Ok(DebugWipeLocalGroupResult {
            conversation_id: convo_id.to_string(),
            group_id: group_id_hex,
            deleted_local_group,
        })
    }

    /// Validate that replay still targets the lifecycle captured before the
    /// first destructive step. Absence is accepted because an earlier replay
    /// may already have removed that row; any different mapping, epoch, reset
    /// target, or reset generation belongs to a newer lifecycle.
    async fn local_delete_lifecycle_matches(
        &self,
        user_did: &str,
        convo_id: &str,
        snapshot: &super::recovery::LocalDeleteSnapshot,
    ) -> Result<bool> {
        let current_conversation = self.storage().get_conversation(user_did, convo_id).await?;
        match (
            snapshot.conversation.as_ref(),
            current_conversation.as_ref(),
        ) {
            (Some(captured), Some(current))
                if captured.group_id == current.group_id && current.epoch <= captured.epoch => {}
            (Some(_), None) | (None, None) => {}
            _ => return Ok(false),
        }

        let current_reset = match self.storage().get_conversation_state(convo_id).await? {
            Some(ConversationState::ResetPending {
                new_group_id,
                reset_generation,
                ..
            }) => Some(super::recovery::LocalDeleteResetFence {
                new_group_id,
                reset_generation,
            }),
            Some(_) | None => None,
        };
        match (snapshot.reset.as_ref(), current_reset.as_ref()) {
            (Some(captured), Some(current)) if captured == current => {}
            (Some(_), None) | (None, None) => {}
            _ => return Ok(false),
        }

        // A same-group External Commit can recreate a deleted group id at a
        // later epoch without changing the stable mapping. Per-group epoch
        // fences close that final reincarnation gap.
        let mut group_epochs: std::collections::BTreeMap<&str, Vec<Option<u64>>> =
            std::collections::BTreeMap::new();
        for group in &snapshot.groups {
            group_epochs
                .entry(&group.group_id_hex)
                .or_default()
                .push(group.epoch);
        }
        for (group_id_hex, allowed_epochs) in group_epochs {
            let group_id = hex::decode(group_id_hex).map_err(|error| {
                OrchestratorError::InvalidInput(format!(
                    "pending local-delete group id is malformed: {error}"
                ))
            })?;
            match self.mls_context().get_epoch(group_id) {
                Ok(current_epoch)
                    if allowed_epochs
                        .iter()
                        .any(|epoch| *epoch == Some(current_epoch)) => {}
                Ok(_) => return Ok(false),
                Err(crate::MLSError::GroupNotFound { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(true)
    }

    /// Delete only group incarnations named by the persisted authority and
    /// still at their captured epoch. A newer incarnation of the same group id
    /// is skipped and remains owned by the current lifecycle.
    fn delete_exact_snapshot_groups(
        &self,
        snapshot: &super::recovery::LocalDeleteSnapshot,
    ) -> Result<std::collections::HashSet<String>> {
        let mut cleaned = std::collections::HashSet::new();
        let mut group_epochs: std::collections::BTreeMap<&str, Vec<Option<u64>>> =
            std::collections::BTreeMap::new();
        for group in &snapshot.groups {
            group_epochs
                .entry(&group.group_id_hex)
                .or_default()
                .push(group.epoch);
        }
        for (group_id_hex, allowed_epochs) in group_epochs {
            let group_id = hex::decode(group_id_hex).map_err(|error| {
                OrchestratorError::InvalidInput(format!(
                    "pending local-delete group id is malformed: {error}"
                ))
            })?;
            match self.mls_context().get_epoch(group_id.clone()) {
                Ok(current_epoch)
                    if allowed_epochs
                        .iter()
                        .any(|epoch| *epoch == Some(current_epoch)) =>
                {
                    match self.mls_context().delete_group(group_id) {
                        Ok(()) | Err(crate::MLSError::GroupNotFound { .. }) => {
                            cleaned.insert(group_id_hex.to_string());
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(_) => {
                    tracing::warn!(
                        group_id = %group_id_hex,
                        "Skipping local-delete group whose epoch no longer matches captured authority"
                    );
                }
                Err(crate::MLSError::GroupNotFound { .. }) => {
                    cleaned.insert(group_id_hex.to_string());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(cleaned)
    }

    async fn delete_exact_snapshot_group_states(
        &self,
        convo_id: &str,
        snapshot: &super::recovery::LocalDeleteSnapshot,
        lifecycle_matches: bool,
        cleaned_groups: &std::collections::HashSet<String>,
    ) -> bool {
        let mut keys: std::collections::BTreeSet<String> =
            snapshot.group_state_keys.iter().cloned().collect();
        if lifecycle_matches {
            keys.insert(convo_id.to_string());
        }
        let mut group_fences: std::collections::HashMap<&str, Vec<Option<u64>>> =
            std::collections::HashMap::new();
        for group in &snapshot.groups {
            group_fences
                .entry(group.group_id_hex.as_str())
                .or_default()
                .push(group.epoch);
        }
        let current_mapping_group = match self.cleanup_user_did().await {
            Ok(user_did) => match self.storage().get_conversation(&user_did, convo_id).await {
                Ok(conversation) => conversation.map(|view| view.group_id),
                Err(error) => {
                    tracing::warn!(error = %error, convo_id, "Failed to inspect mapping before exact GroupState cleanup");
                    return false;
                }
            },
            Err(error) => {
                tracing::warn!(error = %error, convo_id, "Failed to resolve owner before exact GroupState cleanup");
                return false;
            }
        };
        let may_delete = |state: &GroupState| {
            lifecycle_matches
                || (cleaned_groups.contains(&state.group_id)
                    && group_fences
                        .get(state.group_id.as_str())
                        .is_some_and(|epochs| {
                            epochs.iter().any(|epoch| match epoch {
                                Some(expected) => *expected == state.epoch,
                                None => current_mapping_group.as_ref() != Some(&state.group_id),
                            })
                        }))
        };

        let mut all_ok = true;
        for key in &keys {
            match self.storage().get_group_state(key).await {
                Ok(Some(state)) if may_delete(&state) => {
                    if let Err(error) = self.storage().delete_group_state(key).await {
                        all_ok = false;
                        tracing::warn!(error = %error, convo_id, group_state_key = %key, "Failed exact GroupState cleanup");
                    }
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(error) => {
                    all_ok = false;
                    tracing::warn!(error = %error, convo_id, group_state_key = %key, "Failed to inspect GroupState during exact cleanup");
                }
            }
        }
        self.group_states()
            .lock()
            .await
            .retain(|key, state| !keys.contains(key) || !may_delete(state));
        all_ok
    }

    /// The idempotent delete steps shared by `force_delete_local` and startup
    /// replay. Versioned authority is immutable: replay never re-discovers
    /// groups from current mappings, caches, or provider enumeration.
    async fn force_delete_local_steps(&self, convo_id: &str, encoded: Option<&str>) -> bool {
        let user_did = match self.cleanup_user_did().await {
            Ok(user_did) => user_did,
            Err(error) => {
                tracing::warn!(error = %error, convo_id, "No lifecycle-bound user during local delete; keeping delete intent");
                return false;
            }
        };
        let authority = match super::recovery::decode_local_delete_authority(encoded) {
            Ok(authority) => authority,
            Err(error) => {
                tracing::warn!(error = %error, convo_id, "Invalid local-delete authority; keeping delete intent");
                return false;
            }
        };

        let (snapshot, has_lifecycle_fence) = match authority {
            super::recovery::LocalDeleteAuthority::Versioned {
                owner_user_did,
                snapshot,
            } => {
                if owner_user_did != user_did {
                    tracing::warn!(
                        convo_id,
                        "Local-delete authority belongs to another lifecycle user; keeping intent"
                    );
                    return false;
                }
                (snapshot, true)
            }
            super::recovery::LocalDeleteAuthority::VersionedV1 {
                owner_user_did,
                group_ids_hex,
                group_state_keys,
            } => {
                if owner_user_did != user_did {
                    tracing::warn!(convo_id, "Legacy local-delete authority belongs to another lifecycle user; keeping intent");
                    return false;
                }
                tracing::warn!(
                    convo_id,
                    "Replaying pre-fence local-delete authority as exact orphan cleanup only"
                );
                let current_group = self
                    .storage()
                    .get_conversation(&user_did, convo_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|view| view.group_id);
                (
                    super::recovery::LocalDeleteSnapshot {
                        groups: group_ids_hex
                            .into_iter()
                            .filter(|group_id| current_group.as_ref() != Some(group_id))
                            .map(|group_id_hex| super::recovery::LocalDeleteGroupFence {
                                group_id_hex,
                                // V1 did not persist an epoch. Never promote
                                // today's live incarnation into historical
                                // deletion authority during replay.
                                epoch: None,
                            })
                            .collect(),
                        group_state_keys,
                        conversation: None,
                        reset: None,
                    },
                    false,
                )
            }
            super::recovery::LocalDeleteAuthority::LegacyGroupId(group_id_hex) => {
                tracing::warn!(
                    convo_id,
                    "Replaying unowned legacy local-delete authority as exact orphan cleanup only"
                );
                let current_group = self
                    .storage()
                    .get_conversation(&user_did, convo_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|view| view.group_id);
                let groups = if current_group.as_ref() == Some(&group_id_hex) {
                    vec![]
                } else {
                    vec![super::recovery::LocalDeleteGroupFence {
                        group_id_hex: group_id_hex.clone(),
                        // The plain legacy payload carried no epoch or owner.
                        // It may retire already-absent orphan state, but it
                        // must never authorize deletion of a live MLS group.
                        epoch: None,
                    }]
                };
                (
                    super::recovery::LocalDeleteSnapshot {
                        groups,
                        group_state_keys: vec![group_id_hex],
                        conversation: None,
                        reset: None,
                    },
                    false,
                )
            }
            super::recovery::LocalDeleteAuthority::LegacyUnbound => {
                tracing::warn!(
                    convo_id,
                    "Retiring unbound legacy local-delete authority without destructive expansion"
                );
                return true;
            }
        };

        let lifecycle_matches = if has_lifecycle_fence {
            match self
                .local_delete_lifecycle_matches(&user_did, convo_id, &snapshot)
                .await
            {
                Ok(matches) => matches,
                Err(error) => {
                    tracing::warn!(error = %error, convo_id, "Failed to validate local-delete lifecycle fence; keeping intent");
                    return false;
                }
            }
        } else {
            false
        };
        let cleaned_groups = match self.delete_exact_snapshot_groups(&snapshot) {
            Ok(cleaned) => cleaned,
            Err(error) => {
                tracing::warn!(error = %error, convo_id, "Failed exact MLS cleanup; keeping intent");
                return false;
            }
        };
        if !self
            .delete_exact_snapshot_group_states(
                convo_id,
                &snapshot,
                lifecycle_matches,
                &cleaned_groups,
            )
            .await
        {
            return false;
        }

        if !lifecycle_matches {
            tracing::info!(convo_id, "Retiring stale local-delete intent after exact orphan cleanup; current lifecycle preserved");
            return true;
        }

        if let Some(reset) = snapshot.reset.as_ref() {
            match self.storage().get_conversation_state(convo_id).await {
                Ok(Some(ConversationState::ResetPending {
                    new_group_id,
                    reset_generation,
                    ..
                })) if new_group_id == reset.new_group_id
                    && reset_generation == reset.reset_generation =>
                {
                    match self
                        .storage()

                        .clear_reset_pending_for_delete(convo_id, reset.reset_generation)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => return false,
                        Err(error) => {
                            tracing::warn!(error = %error, convo_id, "Failed exact reset-generation cleanup");
                            return false;
                        }
                    }
                }
                Ok(Some(ConversationState::ResetPending { .. })) => return false,
                Ok(Some(_)) | Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = %error, convo_id, "Failed to inspect reset state during local delete");
                    return false;
                }
            }
        }

        let mut all_ok = true;
        if let Err(error) = self
            .storage()
            .delete_conversations(&user_did, &[convo_id])
            .await
        {
            all_ok = false;
            tracing::warn!(error = %error, convo_id, "Failed to delete conversation projection");
        }
        self.recovery_tracker()
            .lock()
            .await
            .forget_conversation(convo_id);
        if let Err(error) = self.storage().clear_recovery_backoff(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %error, convo_id, "Failed to clear persisted recovery backoff");
        }
        if let Err(error) = self.storage().clear_quarantine(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %error, convo_id, "Failed to clear persisted quarantine");
        }
        if let Err(error) = self.storage().clear_rejoin_flag(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %error, convo_id, "Failed to clear persisted rejoin flag");
        }

        self.conversations().lock().await.remove(convo_id);
        let mut states = self.conversation_states().lock().await;
        states.remove(convo_id);
        for group in &snapshot.groups {
            if cleaned_groups.contains(&group.group_id_hex) {
                states.remove(&group.group_id_hex);
            }
        }
        all_ok
    }

    /// WS-5.3 startup sweep: finish local deletes that a crash interrupted
    /// between the persisted intent and completion. Called from
    /// `MLSOrchestrator::initialize`.
    pub(crate) async fn reconcile_pending_local_deletes(&self) {
        let pending = match self.storage().list_pending_local_deletes().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to list pending local deletes during startup reconcile");
                return;
            }
        };
        for intent in pending {
            let transition_lock = self.rejoin_lock(&intent.conversation_id).await;
            let _transition_guard = transition_lock.lock().await;
            tracing::info!(
                convo_id = %intent.conversation_id,
                group_id = ?intent.group_id_hex,
                "Reconciling interrupted local delete from previous run"
            );
            // Replay only the authority captured before destructive work. A
            // missing legacy payload cannot be upgraded from today's mapping:
            // that would let an old intent delete a newer lifecycle.
            let group_id_hex = intent.group_id_hex.clone();
            let steps_ok = self
                .force_delete_local_steps(&intent.conversation_id, group_id_hex.as_deref())
                .await;
            if steps_ok {
                if let Err(e) = self
                    .storage()
                    .clear_pending_local_delete(&intent.conversation_id)
                    .await
                {
                    tracing::warn!(error = %e, convo_id = %intent.conversation_id, "Failed to clear reconciled local-delete intent");
                }
            } else {
                tracing::warn!(
                    convo_id = %intent.conversation_id,
                    "Reconcile sweep: delete steps failed — keeping intent for the next startup sweep"
                );
            }
        }
    }
    async fn submit_commit_transition_helper(
        &self,
        conversation_id: &str,
        group_id: &[u8],
        target_epoch: u64,
        commit_bytes: &[u8],
        welcome_bytes: Option<&[u8]>,
        member_dids: &[String],
    ) -> Result<AddMembersServerResult> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use sha2::{Digest, Sha256};
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential("auth_generation must be >= 1".into()));
        }
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);
        let transition_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        let convo_uuid = uuid::Uuid::parse_str(conversation_id)
            .map_err(|e| OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}")))?;
        let tag_bytes = self
            .mls_context()
            .get_confirmation_tag(group_id.to_vec())?;
        if tag_bytes.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "confirmation tag must be exactly 32 bytes, got {}",
                tag_bytes.len()
            ))));
        }
        let gc_hash_bytes = self
            .mls_context()
            .get_group_context_hash(group_id.to_vec())?;
        if gc_hash_bytes.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "group context hash must be exactly 32 bytes, got {}",
                gc_hash_bytes.len()
            ))));
        }

        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let metadata_info = self.mls_context().get_current_metadata(group_id.to_vec()).ok().flatten();
        let metadata_plaintext = crate::metadata::GroupMetadataV1 {
            version: 1,
            title: "".to_string(),
            description: "".to_string(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        };
        let metadata_key = self.mls_context().safe_export_secret(group_id.to_vec(), 0x8001)
            .unwrap_or_else(|_| {
                let mut k = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut k);
                k.to_vec()
            });
        let metadata_key_arr: [u8; 32] = metadata_key.as_slice().try_into().map_err(|_| {
            OrchestratorError::Mls(MLSError::Internal("metadata key length mismatch".into()))
        })?;
        let ciphertext = crate::metadata::encrypt_metadata_blob(
            &metadata_key_arr,
            group_id,
            target_epoch,
            1,
            &metadata_plaintext,
        )
        .map_err(|e| OrchestratorError::Mls(MLSError::Internal(format!("encrypt metadata snapshot: {e:?}"))))?;
        let participants: Vec<serde_json::Value> = member_dids
            .iter()
            .map(|d| {
                serde_json::json!({
                    "userDid": d,
                    "role": "member",
                    "status": "active"
                })
            })
            .collect();
        let leaf_changes: Vec<serde_json::Value> = if welcome_bytes.is_none() && !member_dids.is_empty() {
            member_dids
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "$type": "blue.catbird.chat.defs#removeLeaf",
                        "deviceId": "00000000-0000-4000-8000-000000000001",
                        "userDid": d
                    })
                })
                .collect()
        } else {
            vec![]
        };
        let mut body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "aad": {
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": 0,
                "prior": {
                    "confirmationTag": STANDARD.encode(&tag_bytes),
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": target_epoch.saturating_sub(1),
                    "generation": 0,
                    "groupContextHash": STANDARD.encode(&gc_hash_bytes),
                    "groupId": STANDARD.encode(group_id),
                    "lifecycle": "active",
                    "stateVersion": 0
                },
                "protocolVersion": "1",
                "transitionId": STANDARD.encode(uuid::Uuid::parse_str(&transition_id).map_err(|e| OrchestratorError::InvalidInput(e.to_string()))?.as_bytes())
            },
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "commit": {
                "bytes": STANDARD.encode(commit_bytes),
                "contentType": "publicMessageCommit",
                "framing": "mlsMessage",
                "sha256": STANDARD.encode(Sha256::digest(commit_bytes))
            },
            "idempotencyKey": idempotency_key,
            "keyId": key_id,
            "manifest": {
                "leafChanges": leaf_changes,
                "participantChanges": []
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": auth_generation,
                    "authorDeviceId": actor_device_id,
                    "authorDid": user_did,
                    "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active",
                    "originSeq": 1,
                    "originTransitionId": transition_id,
                    "roleAtOrigin": "admin",
                    "signaturePublicKey": STANDARD.encode(&public_key)
                },
                "ciphertext": STANDARD.encode(&ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "confirmationTag": STANDARD.encode(&tag_bytes),
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": target_epoch,
                    "generation": 0,
                    "groupContextHash": STANDARD.encode(&gc_hash_bytes),
                    "groupId": STANDARD.encode(group_id)
                },
                "metadataVersion": 1,
                "nonce": STANDARD.encode(&nonce),
                "originTransitionId": transition_id
            },
            "next": {
                "confirmationTag": STANDARD.encode(&tag_bytes),
                "conversationId": conversation_id,
                "epoch": target_epoch,
                "generation": 0,
                "groupContextHash": STANDARD.encode(&gc_hash_bytes),
                "groupId": STANDARD.encode(group_id),
                "lifecycle": "active",
                "stateVersion": 0
            },
            "prior": {
                "confirmationTag": STANDARD.encode(&tag_bytes),
                "conversationId": conversation_id,
                "epoch": target_epoch.saturating_sub(1),
                "generation": 0,
                "groupContextHash": STANDARD.encode(&gc_hash_bytes),
                "groupId": STANDARD.encode(group_id),
                "lifecycle": "active",
                "stateVersion": 0
            },
            "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "transitionId": transition_id
        });
        if let Some(wb) = welcome_bytes {
            body["manifest"]["welcomeBundle"] = serde_json::json!({
                "contentType": "welcome",
                "deliveries": [{
                    "provenance": {
                        "keyPackageRef": STANDARD.encode([0u8; 32]),
                        "recoveryRequestId": uuid::Uuid::new_v4().to_string()
                    },
                    "recipientDeviceId": "00000000-0000-4000-8000-000000000001",
                    "recipientDid": member_dids.first().cloned().unwrap_or_default()
                }],
                "framing": "mlsMessage",
                "opaqueWelcome": STANDARD.encode(wb),
                "sha256": STANDARD.encode(Sha256::digest(wb)),
                "welcomeId": uuid::Uuid::new_v4().to_string()
            });
        }
        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::SubmitTransition,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;

        if response.status != 200 {
            if response.status == 409 {
                return Err(OrchestratorError::EpochMismatch {
                    local: target_epoch,
                    remote: target_epoch + 1,
                });
            }
            return Err(OrchestratorError::Api(format!(
                "submit_transition failed with status {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }
        let resp_json: serde_json::Value =
            serde_json::from_slice(&response.body).unwrap_or_default();
        let server_epoch = resp_json
            .get("result")
            .and_then(|r| r.get("epoch"))
            .and_then(|e| e.as_u64())
            .unwrap_or(target_epoch);
        if server_epoch != target_epoch {
            return Err(OrchestratorError::EpochMismatch {
                local: target_epoch,
                remote: server_epoch,
            });
        }

        if let Some(wb) = welcome_bytes {
            let _ = self.api_client().publish_welcome(conversation_id, wb).await;
        }

        let receipt: Option<crate::orchestrator::types::SequencerReceipt> = resp_json
            .get("result")
            .and_then(|r| r.get("receipt"))
            .and_then(|rc| serde_json::from_value(rc.clone()).ok());

        Ok(AddMembersServerResult {
            success: true,
            new_epoch: server_epoch,
            receipt,
        })
    }

    async fn submit_remove_transition_helper(
        &self,
        conversation_id: &str,
        group_id: &[u8],
        target_epoch: u64,
        commit_bytes: &[u8],
        member_dids: &[String],
    ) -> Result<()> {
        let _ = self
            .submit_commit_transition_helper(
                conversation_id,
                group_id,
                target_epoch,
                commit_bytes,
                None,
                member_dids,
            )
            .await?;
        Ok(())
    }

    pub async fn put_group_metadata_blob(
        &self,
        conversation_id: &str,
        _group_id_hex: &str,
        blob_locator: &str,
        ciphertext: &[u8],
        _kind: &str,
        _metadata_version: u64,
        _reset_generation: Option<i32>,
    ) -> Result<()> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use sha2::{Digest, Sha256};
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .unwrap_or(1);
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);

        let resolved = self.resolve_conversation_context(conversation_id).await?;
        let group_id_bytes = resolved.group_id_bytes()?;
        let epoch = self
            .mls_context()
            .get_epoch(group_id_bytes.clone())?;
        let tag_bytes = self
            .mls_context()
            .get_confirmation_tag(group_id_bytes.clone())?;
        if tag_bytes.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "confirmation tag must be exactly 32 bytes, got {}",
                tag_bytes.len()
            ))));
        }
        let gc_hash = self
            .mls_context()
            .get_group_context_hash(group_id_bytes.clone())?;
        if gc_hash.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "group context hash must be exactly 32 bytes, got {}",
                gc_hash.len()
            ))));
        }
        let plain_size = ciphertext.len().saturating_sub(16).max(1);
        let cipher_size = ciphertext.len().max(17);

        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#blobUploadPreparationBody",
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "blobId": blob_locator,
            "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
            "ciphertextSize": cipher_size,
            "conversationId": conversation_id,
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "keyId": key_id,
            "mediaType": "application/octet-stream",
            "plaintextSize": plain_size,
            "prior": {
                "confirmationTag": STANDARD.encode(&tag_bytes),
                "conversationId": conversation_id,
                "epoch": epoch,
                "generation": 0,
                "groupContextHash": STANDARD.encode(&gc_hash),
                "groupId": STANDARD.encode(&group_id_bytes),
                "lifecycle": "active",
                "stateVersion": 0
            },
            "purpose": "metadata",
            "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });
        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::PrepareBlobUpload,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::Api(format!(
                "prepare_blob_upload failed: {}",
                response.status
            )));
        }

        let upload_req = super::canonical_transport::PreparedRequest {
            operation: super::canonical_transport::CanonicalOperation::UploadBlob,
            method: "POST".into(),
            path: format!(
                "/xrpc/blue.catbird.chat.uploadBlob?blobId={blob_locator}&convoId={conversation_id}"
            ),
            body: Some(ciphertext.to_vec()),
        };
        let upload_resp = self.api_client().submit_prepared_request(upload_req).await?;
        if upload_resp.status != 200 {
            return Err(OrchestratorError::Api(format!(
                "upload_blob failed: {}",
                upload_resp.status
            )));
        }
        Ok(())
    }
}
