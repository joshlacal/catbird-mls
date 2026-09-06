//! Canonical notifications are scheduling hints, never membership or reset
//! authority. Both the live stream and inventory replay use this targeted path.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

use super::*;
use crate::chat_v2::ids::{BareDid, CanonicalTimestamp, CanonicalUuid, MAX_SAFE_INTEGER};
use crate::orchestrator::canonical_transport::CanonicalOperation;
use crate::orchestrator::groups::pending_leaf_recovery_request_id;
use crate::orchestrator::lifecycle::lifecycle_coordinates;
use crate::orchestrator::reset_flow::ServerConversationState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintKind {
    Changed,
    Closed,
    Message,
    Welcome,
    WelcomeDisposition,
    ResetRequested,
    LeafRecovery,
    LeaveRequest,
    AccessEnded,
    Watermark,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct CanonicalHint {
    kind: HintKind,
    conversation_id: Option<String>,
    recovery_request_id: Option<String>,
    terminal_seq: Option<u64>,
}

fn invalid(message: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::InvalidInput(format!("Invalid canonical server event: {message}"))
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| invalid(format!("missing string {field}")))
}

fn exact_fields(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("expected object"))?;
    if object
        .keys()
        .any(|key| key != "$type" && !fields.contains(&key.as_str()))
    {
        return Err(invalid("unexpected event field"));
    }
    if fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid("missing event field"));
    }
    Ok(())
}

impl CanonicalHint {
    pub(super) fn parse(mut value: Value) -> Result<Self> {
        if value.get("payload").is_some() {
            exact_fields(
                &value,
                &["previousCursor", "cursor", "payload", "createdAt"],
            )?;
            if value.get("$type").is_some()
                && value["$type"] != "blue.catbird.chat.defs#eventEnvelope"
            {
                return Err(invalid("unknown event envelope type"));
            }
            for field in ["previousCursor", "cursor"] {
                if !(1..=512).contains(&string(&value, field)?.len()) {
                    return Err(invalid("invalid event cursor length"));
                }
            }
            CanonicalTimestamp::parse(string(&value, "createdAt")?).map_err(invalid)?;
            value = value["payload"].take();
        }
        let (kind, fields): (_, &[&str]) = match string(&value, "$type")? {
            "blue.catbird.chat.defs#conversationChangedEvent" => {
                (HintKind::Changed, &["conversationId"])
            }
            "blue.catbird.chat.defs#conversationClosedEvent" => (
                HintKind::Closed,
                &["conversationId", "conversationKind", "terminalSeq"],
            ),
            "blue.catbird.chat.defs#messageAvailableEvent" => {
                (HintKind::Message, &["conversationId", "seq"])
            }
            "blue.catbird.chat.defs#welcomeAvailableEvent" => {
                (HintKind::Welcome, &["conversationId", "welcomeId"])
            }
            "blue.catbird.chat.defs#welcomeDispositionEvent" => {
                (HintKind::WelcomeDisposition, &["welcomeId", "status"])
            }
            "blue.catbird.chat.defs#resetRequestedEvent" => (
                HintKind::ResetRequested,
                &["conversationId", "resetRequestId"],
            ),
            "blue.catbird.chat.defs#leafRecoveryEvent" => (
                HintKind::LeafRecovery,
                &["conversationId", "recoveryRequestId", "status"],
            ),
            "blue.catbird.chat.defs#leaveRequestEvent" => (
                HintKind::LeaveRequest,
                &["conversationId", "leaveRequestId", "status"],
            ),
            "blue.catbird.chat.defs#accessEndedEvent" => (
                HintKind::AccessEnded,
                &[
                    "conversationId",
                    "membershipIntervalId",
                    "userDid",
                    "deviceId",
                    "terminalSeq",
                ],
            ),
            "blue.catbird.chat.defs#watermarkEvent" => (HintKind::Watermark, &["issuedAt"]),
            _ => return Err(invalid("unknown event payload type")),
        };
        exact_fields(&value, fields)?;
        for field in fields {
            match *field {
                "conversationId"
                | "welcomeId"
                | "resetRequestId"
                | "recoveryRequestId"
                | "leaveRequestId"
                | "membershipIntervalId"
                | "deviceId" => {
                    CanonicalUuid::parse(string(&value, field)?).map_err(invalid)?;
                }
                "seq" | "terminalSeq" => {
                    if !value[field]
                        .as_i64()
                        .is_some_and(|seq| (1..=MAX_SAFE_INTEGER).contains(&seq))
                    {
                        return Err(invalid("sequence must be a positive safe integer"));
                    }
                }
                "userDid" => {
                    BareDid::parse(string(&value, field)?).map_err(invalid)?;
                }
                "issuedAt" => {
                    CanonicalTimestamp::parse(string(&value, field)?).map_err(invalid)?;
                }
                "conversationKind" if !matches!(string(&value, field)?, "direct" | "group") => {
                    return Err(invalid("unknown conversation kind"))
                }
                "status" => {
                    let statuses: &[&str] = match kind {
                        HintKind::WelcomeDisposition => &[
                            "pending",
                            "acknowledged",
                            "rejected",
                            "expired",
                            "superseded",
                        ],
                        HintKind::LeafRecovery => {
                            &["open", "fulfilled", "cancelled", "expired", "superseded"]
                        }
                        HintKind::LeaveRequest => {
                            &["pending", "fulfilled", "cancelled", "expired", "stale"]
                        }
                        _ => unreachable!(),
                    };
                    if !statuses.contains(&string(&value, field)?) {
                        return Err(invalid("unknown request status"));
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            kind,
            conversation_id: value["conversationId"].as_str().map(str::to_owned),
            recovery_request_id: value["recoveryRequestId"].as_str().map(str::to_owned),
            terminal_seq: value["terminalSeq"].as_u64(),
        })
    }
}

fn refresh_events(conversation_id: &str) -> Vec<EngineEvent> {
    vec![
        EngineEvent::ConversationUpdated {
            convo_id: conversation_id.into(),
        },
        EngineEvent::NeedsUiRefresh {
            convo_id: conversation_id.into(),
        },
    ]
}

impl<S, A, C, M> MlsEngine<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(super) async fn process_canonical_hint(
        &self,
        hint: CanonicalHint,
    ) -> Result<Vec<EngineEvent>> {
        let Some(conversation_id) = hint.conversation_id.as_deref() else {
            // Transport owns cursor continuity. Disposition has no CID, so it
            // cannot authorize conversation lookup, joining, or a global sweep.
            return Ok(Vec::new());
        };
        let orch = &self.orchestrator;
        let user_did = orch.require_user_did().await?;
        let device = orch.require_actor_device_id().await?;
        orch.retry_welcome_acknowledgements_for_conversation(conversation_id)
            .await?;
        let terminal_confirmed = match hint.kind {
            HintKind::Closed | HintKind::AccessEnded => {
                orch.reconcile_terminal_conversation_hint(
                    conversation_id,
                    hint.terminal_seq.unwrap(),
                    hint.kind == HintKind::Closed,
                )
                .await?
            }
            HintKind::Changed => {
                orch.reconcile_terminal_conversation(conversation_id)
                    .await?
            }
            _ => false,
        };
        if terminal_confirmed {
            return Ok(refresh_events(conversation_id));
        }
        let fresh = orch.fetch_conversation_lifecycle(conversation_id).await?;
        let coordinate = lifecycle_coordinates(&fresh["state"]["coordinates"], conversation_id)?;
        if coordinate["lifecycle"] != "active" {
            orch.reconcile_terminal_conversation(conversation_id)
                .await?;
            return Ok(refresh_events(conversation_id));
        }
        let group = STANDARD
            .decode(coordinate["groupId"].as_str().unwrap())
            .map_err(invalid)?;
        let group_hex = hex::encode(&group);
        let stored = orch
            .storage()
            .get_conversation(&user_did, conversation_id)
            .await?;
        let cached = orch
            .conversations()
            .lock()
            .await
            .get(conversation_id)
            .cloned();
        let previous_group = stored
            .as_ref()
            .or(cached.as_ref())
            .map(|view| view.group_id.as_str());
        let changed_group = previous_group.is_some_and(|previous| previous != group_hex);
        let removed = orch.is_local_device_removed(conversation_id).await?;
        let mut events = Vec::new();

        // A request merely asks an administrator to act. Only independently
        // read activated coordinates can establish a successor MLS group.
        if changed_group && !removed {
            let generation = coordinate["generation"].as_u64().unwrap();
            let generation = i32::try_from(generation)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| invalid("activated reset generation is out of range"))?;
            let outcome = orch
                .record_group_reset_with_outcome(conversation_id, group.clone(), generation)
                .await?;
            events.extend(events_for_reset_outcome(conversation_id, outcome));
        } else if hint.kind == HintKind::ResetRequested {
            return Ok(refresh_events(conversation_id));
        }

        // A newly discovered conversation needs its stable identity, but a
        // remote epoch is never persisted as if this device processed it.
        if previous_group.is_none() {
            let view = orch.fetch_conversation_for_convo(conversation_id).await?;
            if view.group_id != group_hex {
                return Err(invalid(
                    "conversation changed during inventory lookup; retry",
                ));
            }
            orch.storage()
                .ensure_conversation_exists(&user_did, conversation_id, &group_hex)
                .await?;
            orch.conversations()
                .lock()
                .await
                .insert(conversation_id.into(), view);
        }

        // Events are hints; the full authenticated point-read supplies the
        // current consent policy even when a retained inventory page is old.
        orch.retain_conversation_policy_json(conversation_id, &fresh["state"])
            .await?;
        if orch.pending_conversation_admission(conversation_id).await? {
            return Ok(refresh_events(conversation_id));
        }

        let reset_pending = orch
            .reset_pending_payload_result(conversation_id)
            .await?
            .is_some();
        let identity = orch.require_scoped_identity().await?;
        let has_local_leaf = !removed
            && !reset_pending
            && orch
                .mls_context()
                .group_member_identities(group.clone())
                .ok()
                .is_some_and(|identities| {
                    identities
                        .iter()
                        .any(|member| member == identity.as_bytes())
                });
        if !has_local_leaf {
            match orch.fetch_welcome_delivery(conversation_id).await {
                Ok(delivery) => {
                    orch.join_or_rejoin_from_delivery(delivery).await?;
                    events.push(EngineEvent::RecoveryStateChanged {
                        convo_id: conversation_id.into(),
                        state: ConversationRecoveryState::Healthy,
                    });
                }
                Err(OrchestratorError::ServerError {
                    status: 404 | 410, ..
                }) => {
                    // Enrollment may discover an existing active account
                    // membership before this new device has a leaf. Request
                    // only Add; an event can never activate a reset or replace
                    // an existing leaf whose local state needs investigation.
                    if !removed
                        && matches!(
                            hint.kind,
                            HintKind::Changed
                                | HintKind::LeafRecovery
                                | HintKind::Welcome
                                | HintKind::Message
                        )
                    {
                        self.request_missing_device_add(conversation_id).await?;
                    }
                    events.push(EngineEvent::RecoveryStateChanged {
                        convo_id: conversation_id.into(),
                        state: if reset_pending {
                            ConversationRecoveryState::ResetPending
                        } else if removed {
                            ConversationRecoveryState::UnrecoverableLocal
                        } else {
                            ConversationRecoveryState::GroupMissing
                        },
                    });
                    events.extend(refresh_events(conversation_id));
                    return Ok(events);
                }
                Err(error) => return Err(error),
            }
        }

        events.extend(self.catch_up_event_conversation(conversation_id).await?);
        if matches!(hint.kind, HintKind::Changed | HintKind::LeafRecovery) {
            // Each fulfillment re-reads state and validates the reserved exact
            // device package. Processing an account's sibling is allowed.
            let current = orch.fetch_conversation_lifecycle(conversation_id).await?;
            if let Some(request_id) = pending_leaf_recovery_request_id(
                &current,
                conversation_id,
                &user_did,
                &device,
                hint.recovery_request_id.as_deref(),
            ) {
                orch.fulfill_leaf_recovery_with_target(
                    conversation_id,
                    Some(&request_id),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            }
        }
        if matches!(hint.kind, HintKind::Changed | HintKind::LeaveRequest)
            && fresh["pendingLeaveRequests"]
                .as_array()
                .is_some_and(|requests| !requests.is_empty())
        {
            orch.fulfill_pending_group_leave(conversation_id).await?;
        }
        events.extend(refresh_events(conversation_id));
        Ok(events)
    }

    async fn catch_up_event_conversation(&self, conversation_id: &str) -> Result<Vec<EngineEvent>> {
        let mut cursor = None;
        let mut pagination = PaginationGuard::for_messages("canonical event entries");
        let mut events = Vec::new();
        loop {
            let (messages, next) = self
                .orchestrator
                .fetch_messages(conversation_id, cursor.as_deref(), 100, None, None, None)
                .await?;
            pagination.observe_page(messages.len(), next.as_deref())?;
            events.extend(
                messages
                    .into_iter()
                    .map(|message| EngineEvent::MessageInserted {
                        message_id: message.id,
                        convo_id: conversation_id.into(),
                    }),
            );
            // A page containing only Commit/control entries can display no
            // messages yet still have a continuation with subsequent messages.
            cursor = next;
            if cursor.is_none() {
                return Ok(events);
            }
        }
    }

    async fn request_missing_device_add(&self, conversation_id: &str) -> Result<bool> {
        let orch = &self.orchestrator;
        let lock = orch.rejoin_lock(conversation_id).await;
        let _guard = lock.lock().await;
        if orch.is_local_conversation_terminal(conversation_id).await?
            || matches!(
                orch.storage()
                    .get_conversation_state(conversation_id)
                    .await?,
                Some(
                    ConversationState::Quarantined { .. }
                        | ConversationState::ForkDetected
                        | ConversationState::Failed
                )
            )
        {
            return Ok(false);
        }
        let did = orch.require_user_did().await?;
        let device = orch.require_actor_device_id().await?;
        let fresh = orch.fetch_conversation_lifecycle(conversation_id).await?;
        let state = &fresh["state"];
        let coordinate = lifecycle_coordinates(&state["coordinates"], conversation_id)?;
        if coordinate["lifecycle"] != "active"
            || !state["participants"]
                .as_array()
                .is_some_and(|participants| {
                    participants
                        .iter()
                        .any(|p| p["userDid"].as_str() == Some(&did) && p["status"] == "active")
                })
            || !state["leaves"].as_array().is_some_and(|leaves| {
                !leaves.iter().any(|leaf| {
                    leaf["userDid"].as_str() == Some(&did)
                        && leaf["deviceId"].as_str() == Some(&device)
                })
            })
        {
            return Ok(false);
        }
        let state = ServerConversationState::from_state_json(conversation_id, state)?;
        if orch.own_open_leaf_recovery(&state, "add").await?.is_none() {
            // A newly enrolled device must publish usable package material
            // before asking another current leaf to add it.
            if orch.get_key_package_stats().await?.available == 0
                || orch.mls_context().list_key_package_hashes()?.is_empty()
            {
                orch.publish_key_package().await?;
            }
            orch.mls_context().ensure_storage_durable()?;
            orch.request_leaf_recovery(&state, "add").await?;
        }
        orch.recovery_tracker()
            .lock()
            .await
            .note_leaf_recovery_requested(conversation_id);
        orch.project_non_reset_state_locked(conversation_id, ConversationState::NeedsRejoin)
            .await?;
        orch.storage().mark_needs_rejoin(conversation_id).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::canonical_transport::CanonicalOperation;
    use crate::recovery_e2e_harness::{
        mock_api_client::MockDeliveryService, mock_credentials::MockCredentials,
        mock_storage::MockStorage, TestWorld,
    };
    use serde_json::json;

    const ID: &str = "00000000-0000-4000-8000-000000000001";
    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";

    fn event(name: &str, fields: Value) -> Value {
        let mut value = fields;
        value["$type"] = json!(format!("blue.catbird.chat.defs#{name}"));
        value
    }

    #[test]
    fn accepts_every_canonical_payload_and_envelope_without_inventing_a_cid() {
        let fixtures = [
            event("conversationChangedEvent", json!({"conversationId":ID})),
            event(
                "conversationClosedEvent",
                json!({"conversationId":ID,"conversationKind":"group","terminalSeq":1}),
            ),
            event(
                "messageAvailableEvent",
                json!({"conversationId":ID,"seq":1}),
            ),
            event(
                "welcomeAvailableEvent",
                json!({"conversationId":ID,"welcomeId":ID}),
            ),
            event(
                "welcomeDispositionEvent",
                json!({"welcomeId":ID,"status":"acknowledged"}),
            ),
            event(
                "resetRequestedEvent",
                json!({"conversationId":ID,"resetRequestId":ID}),
            ),
            event(
                "leafRecoveryEvent",
                json!({"conversationId":ID,"recoveryRequestId":ID,"status":"open"}),
            ),
            event(
                "leaveRequestEvent",
                json!({"conversationId":ID,"leaveRequestId":ID,"status":"pending"}),
            ),
            event(
                "accessEndedEvent",
                json!({"conversationId":ID,"membershipIntervalId":ID,"userDid":DID,"deviceId":ID,"terminalSeq":1}),
            ),
            event(
                "watermarkEvent",
                json!({"issuedAt":"2026-09-05T01:00:00.000Z"}),
            ),
        ];
        for payload in fixtures {
            let raw = CanonicalHint::parse(payload.clone()).unwrap();
            let wrapped = CanonicalHint::parse(json!({
                "$type":"blue.catbird.chat.defs#eventEnvelope", "previousCursor":"before",
                "cursor":"after", "createdAt":"2026-09-05T01:00:00.000Z", "payload":payload,
            }))
            .unwrap();
            assert_eq!(raw, wrapped);
            assert_eq!(
                raw.conversation_id.is_none(),
                matches!(raw.kind, HintKind::WelcomeDisposition | HintKind::Watermark)
            );
        }
    }

    #[test]
    fn rejects_unknown_tags_extra_reset_authority_and_noncanonical_scalars() {
        let bad = [
            event(
                "prefixleafRecoveryEvent",
                json!({"conversationId":ID,"recoveryRequestId":ID,"status":"open"}),
            ),
            event(
                "resetRequestedEvent",
                json!({"conversationId":ID,"resetRequestId":ID,"newGroupId":"untrusted"}),
            ),
            event(
                "conversationChangedEvent",
                json!({"conversationId":ID.replace('-', "")}),
            ),
            event(
                "messageAvailableEvent",
                json!({"conversationId":ID,"seq":0}),
            ),
            event(
                "messageAvailableEvent",
                json!({"conversationId":ID,"seq":9007199254740992_u64}),
            ),
            event(
                "leafRecoveryEvent",
                json!({"conversationId":ID,"recoveryRequestId":ID,"status":"approved"}),
            ),
            event("watermarkEvent", json!({"issuedAt":"2026-09-05T01:00:00Z"})),
            event("welcomeAvailableEvent", json!({"welcomeId":ID})),
        ];
        for value in bad {
            assert!(CanonicalHint::parse(value.clone()).is_err(), "{value}");
        }
    }

    async fn engine_for(
        world: &TestWorld,
        name: &str,
    ) -> MlsEngine<MockStorage, MockDeliveryService, MockCredentials, crate::MLSContext> {
        let client = world.client(name);
        let engine = MlsEngine::new(
            client.orchestrator.mls_context().clone(),
            Arc::new(client.storage.clone()),
            Arc::new(world.delivery_service().clone_as(&client.did)),
            Arc::new(client.credentials.clone()),
            Arc::new(EngineLifecycle::default()),
            OrchestratorConfig::default(),
        );
        engine.orchestrator.initialize(&client.did).await.unwrap();
        engine
    }

    #[test]
    fn reset_request_and_stale_access_hint_preserve_a_healthy_device() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            world
                .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
                .await;
            world.register_device("Alice").await.unwrap();
            let alice = world.client("Alice");
            let group = alice
                .orchestrator
                .create_group("healthy", None, None)
                .await
                .unwrap();
            let other = alice
                .orchestrator
                .create_group("unrelated", None, None)
                .await
                .unwrap();
            let engine = engine_for(&world, "Alice").await;
            let start = world.delivery_service().submitted_prepared_requests().len();
            for payload in [
                event(
                    "resetRequestedEvent",
                    json!({"conversationId":group.conversation_id,"resetRequestId":ID}),
                ),
                event(
                    "accessEndedEvent",
                    json!({"conversationId":group.conversation_id,"membershipIntervalId":ID,"userDid":DID,"deviceId":ID,"terminalSeq":1}),
                ),
                event(
                    "conversationChangedEvent",
                    json!({"conversationId":group.conversation_id}),
                ),
            ] {
                engine.process_server_event(&payload.to_string()).unwrap();
            }
            assert!(alice
                .storage
                .get_persisted_reset_pending(&group.conversation_id)
                .is_none());
            assert!(!engine
                .orchestrator
                .is_local_device_removed(&group.conversation_id)
                .await
                .unwrap());
            for view in [&group, &other] {
                assert_eq!(
                    alice
                        .orchestrator
                        .mls_context()
                        .get_epoch(hex::decode(&view.group_id).unwrap())
                        .unwrap(),
                    0
                );
            }
            let requests = world.delivery_service().submitted_prepared_requests();
            for request in &requests[start..] {
                assert_eq!(
                    request.method, "GET",
                    "hint must not create reset/leave/recovery work"
                );
                if request.operation == CanonicalOperation::GetConversationState {
                    assert!(request.path.contains(&group.conversation_id));
                    assert!(!request.path.contains(&other.conversation_id));
                }
            }
            assert_eq!(
                world
                    .delivery_service()
                    .submitted_prepared_requests()
                    .iter()
                    .filter(|request| request.operation == CanonicalOperation::GetPendingWelcomes)
                    .count(),
                0
            );
        });
    }

    #[test]
    fn no_cid_notifications_do_not_read_or_repair_any_conversation() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            world
                .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
                .await;
            world.register_device("Alice").await.unwrap();
            let engine = engine_for(&world, "Alice").await;
            let start = world.delivery_service().submitted_prepared_requests().len();
            for payload in [
                event(
                    "welcomeDispositionEvent",
                    json!({"welcomeId":ID,"status":"expired"}),
                ),
                event(
                    "watermarkEvent",
                    json!({"issuedAt":"2026-09-05T01:00:00.000Z"}),
                ),
            ] {
                assert!(engine
                    .process_server_event(&payload.to_string())
                    .unwrap()
                    .is_empty());
            }
            assert_eq!(
                world.delivery_service().submitted_prepared_requests().len(),
                start
            );
        });
    }

    #[test]
    fn changed_event_retains_pending_policy_without_recovery_or_message_fetch() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            let alice_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
            let bob_did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
            world.add_client_with_did("Alice", alice_did).await;
            world.add_client_with_did("Bob", bob_did).await;
            world.register_device("Alice").await.unwrap();
            world.register_device("Bob").await.unwrap();
            let group = world
                .client("Alice")
                .orchestrator
                .create_group("pending event", Some(&[bob_did.into()]), None)
                .await
                .unwrap();
            let engine = engine_for(&world, "Bob").await;
            let start = world.delivery_service().submitted_prepared_requests().len();
            world.delivery_service().fail_next_get_messages();
            engine
                .process_server_event(
                    &event(
                        "conversationChangedEvent",
                        json!({"conversationId":group.conversation_id}),
                    )
                    .to_string(),
                )
                .unwrap();
            let policy = engine
                .orchestrator
                .mls_context()
                .get_conversation_policy(bob_did, &group.conversation_id)
                .unwrap()
                .unwrap();
            assert!(policy
                .participants
                .iter()
                .any(|participant| participant.user_did.as_str() == bob_did
                    && participant.status.as_str() == "pending"));
            assert!(
                world.delivery_service().submitted_prepared_requests()[start..]
                    .iter()
                    .all(|request| request.method == "GET"
                        && request.operation != CanonicalOperation::GetPendingWelcomes)
            );
            assert!(
                !engine
                    .orchestrator
                    .ensure_conversation_ready(&group.conversation_id)
                    .await
                    .unwrap()
                    .send_allowed
            );
            assert!(
                world
                    .delivery_service()
                    .clone_as(bob_did)
                    .get_messages(&group.conversation_id, None, 10, None, None, None)
                    .await
                    .is_err(),
                "pending event must leave the message-fetch fault unconsumed"
            );
        });
    }

    #[test]
    fn sibling_recovery_event_adds_only_target_then_welcome_and_message_events_decrypt() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            world
                .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
                .await;
            let did = world.client("Alice").did.clone();
            world.add_client_with_did("Phone", &did).await;
            world.register_device("Alice").await.unwrap();
            world.register_device("Phone").await.unwrap();
            let alice = world.client("Alice");
            let phone = world.client("Phone");
            let group = alice
                .orchestrator
                .create_group("siblings", None, None)
                .await
                .unwrap();
            let device = phone.orchestrator.require_actor_device_id().await.unwrap();
            let package = phone
                .orchestrator
                .mls_context()
                .create_key_package(format!("{did}#{device}").into_bytes())
                .unwrap();
            world.delivery_service().add_pending_leaf_recovery_request(json!({
                "conversationId":group.conversation_id,"recoveryRequestId":ID,"requesterDid":did,
                "requesterDeviceId":device,"recoveryKind":"add","status":"open",
                "reservation":{"keyPackageRef":STANDARD.encode(package.hash_ref),"keyPackage":{"bytes":STANDARD.encode(package.key_package_data)}}
            }));
            let engine = engine_for(&world, "Alice").await;
            // Notification status is deliberately stale. Only the fresh read
            // selects current open work and its exact reserved device package.
            let payload = event(
                "leafRecoveryEvent",
                json!({"conversationId":group.conversation_id,"recoveryRequestId":ID,"status":"cancelled"}),
            );
            engine.process_server_event(&payload.to_string()).unwrap();
            assert_eq!(
                alice
                    .orchestrator
                    .mls_context()
                    .get_epoch(hex::decode(&group.group_id).unwrap())
                    .unwrap(),
                1
            );
            let transitions = || {
                world
                    .delivery_service()
                    .submitted_prepared_requests()
                    .iter()
                    .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
                    .count()
            };
            let after = transitions();
            engine.process_server_event(&payload.to_string()).unwrap();
            assert_eq!(
                transitions(),
                after,
                "stale event must not add the device twice"
            );
            let phone_engine = engine_for(&world, "Phone").await;
            phone_engine
                .process_server_event(
                    &event(
                        "welcomeAvailableEvent",
                        json!({"conversationId":group.conversation_id,"welcomeId":ID}),
                    )
                    .to_string(),
                )
                .unwrap();
            assert_eq!(
                world
                    .delivery_service()
                    .submitted_prepared_requests()
                    .iter()
                    .filter(|request| request.operation == CanonicalOperation::GetPendingWelcomes)
                    .count(),
                1,
                "prefetched Welcome must not be fetched twice"
            );
            assert_eq!(
                phone
                    .orchestrator
                    .mls_context()
                    .get_epoch(hex::decode(&group.group_id).unwrap())
                    .unwrap(),
                1
            );
            // More than one page of duplicate Commit notifications precedes
            // the application. An empty displayable page must not end catch-up.
            let requests = world.delivery_service().submitted_prepared_requests();
            let fulfillment = requests
                .iter()
                .find(|request| request.operation == CanonicalOperation::SubmitTransition)
                .unwrap();
            let body: Value = serde_json::from_slice(fulfillment.body.as_ref().unwrap()).unwrap();
            let ciphertext = STANDARD
                .decode(
                    body.pointer("/signedRequest/body/commit/bytes")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                )
                .unwrap();
            for _ in 0..100 {
                world
                    .delivery_service()
                    .clone_as(&did)
                    .send_message_with_id(
                        &group.conversation_id,
                        &ciphertext,
                        1,
                        &uuid::Uuid::new_v4().to_string(),
                    )
                    .await
                    .unwrap();
            }
            let sent = engine
                .orchestrator
                .send_message(&group.conversation_id, "hello second device")
                .await
                .unwrap();
            let events = phone_engine
                .process_server_event(
                    &event(
                        "messageAvailableEvent",
                        json!({"conversationId":group.conversation_id,"seq":1}),
                    )
                    .to_string(),
                )
                .unwrap();
            assert!(events.iter().any(|event| matches!(event, EngineEvent::MessageInserted { message_id, .. } if message_id == &sent.id)), "sent {}, events {:?}, stored {:?}", sent.id, events, phone.storage.get_conversation_messages(&group.conversation_id));
            assert!(phone
                .storage
                .get_conversation_messages(&group.conversation_id)
                .iter()
                .any(|message| message.text == "hello second device"));
        });
    }

    #[test]
    fn new_sibling_inventory_requests_add_once_and_reuses_server_work_after_restart() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            world
                .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
                .await;
            let did = world.client("Alice").did.clone();
            world.add_client_with_did("Phone", &did).await;
            world.register_device("Alice").await.unwrap();
            world.register_device("Phone").await.unwrap();
            let alice = world.client("Alice");
            let phone = world.client("Phone");
            let group = alice
                .orchestrator
                .create_group("auto add", None, None)
                .await
                .unwrap();
            let start = world.delivery_service().submitted_prepared_requests().len();
            let changed = event(
                "conversationChangedEvent",
                json!({"conversationId":group.conversation_id}),
            );
            let phone_engine = engine_for(&world, "Phone").await;
            phone_engine
                .process_server_event(&changed.to_string())
                .unwrap();
            phone_engine
                .process_server_event(&changed.to_string())
                .unwrap();
            drop(phone_engine);
            let phone_engine = engine_for(&world, "Phone").await;
            phone_engine
                .process_server_event(&changed.to_string())
                .unwrap();
            let requests = world.delivery_service().submitted_prepared_requests();
            let adds: Vec<_> = requests[start..]
                .iter()
                .filter(|r| r.operation == CanonicalOperation::RequestLeafRecovery)
                .collect();
            assert_eq!(
                adds.len(),
                1,
                "open request is reused across engine recreation"
            );
            let body: Value = serde_json::from_slice(adds[0].body.as_ref().unwrap()).unwrap();
            assert_eq!(body["signedRequest"]["body"]["recoveryKind"], "add");
            assert_eq!(
                body["signedRequest"]["body"]["actorDeviceId"],
                phone.orchestrator.require_actor_device_id().await.unwrap()
            );
            assert!(requests[start..].iter().all(
                |r| r.method == "GET" || r.operation == CanonicalOperation::RequestLeafRecovery
            ));
            assert_eq!(
                alice
                    .orchestrator
                    .mls_context()
                    .get_epoch(hex::decode(&group.group_id).unwrap())
                    .unwrap(),
                0
            );
            // Inventory now wakes the existing sibling to finish exactly that
            // persisted reservation, followed by the new device's Welcome.
            engine_for(&world, "Alice")
                .await
                .process_server_event(&changed.to_string())
                .unwrap();
            phone_engine
                .process_server_event(
                    &event(
                        "welcomeAvailableEvent",
                        json!({"conversationId":group.conversation_id,"welcomeId":ID}),
                    )
                    .to_string(),
                )
                .unwrap();
            assert_eq!(
                phone
                    .orchestrator
                    .mls_context()
                    .get_epoch(hex::decode(&group.group_id).unwrap())
                    .unwrap(),
                1
            );
        });
    }

    #[test]
    fn close_notifications_preserve_retained_history_and_reject_unrelated_proof() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            world
                .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
                .await;
            world
                .add_client_with_did("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
                .await;
            world.register_device("Alice").await.unwrap();
            world.register_device("Bob").await.unwrap();
            let alice = world.client("Alice");
            let group = alice
                .orchestrator
                .create_group("direct", Some(&[world.client("Bob").did.clone()]), None)
                .await
                .unwrap();
            let engine = engine_for(&world, "Alice").await;
            engine.leave_conversation(&group.conversation_id).unwrap();
            assert!(alice
                .storage
                .get_conversation(&alice.did, &group.conversation_id)
                .await
                .unwrap()
                .is_some());
            assert_eq!(
                alice
                    .storage
                    .get_conversation_state(&group.conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::Closed)
            );
            let before = world.delivery_service().submitted_prepared_requests().len();
            let closed = event(
                "conversationClosedEvent",
                json!({"conversationId":group.conversation_id,"conversationKind":"direct","terminalSeq":20}),
            );
            engine.process_server_event(&closed.to_string()).unwrap();
            assert!(
                world.delivery_service().submitted_prepared_requests()[before..]
                    .iter()
                    .all(|request| request.method == "GET")
            );
            let mut wrong_terminal = closed;
            wrong_terminal["terminalSeq"] = json!(21);
            // A stale sequence is only a hint; the retained row is reconciled
            // against the independently authenticated actual terminal entry.
            engine
                .process_server_event(&wrong_terminal.to_string())
                .unwrap();
            wrong_terminal["conversationId"] = json!(uuid::Uuid::new_v4().to_string());
            assert!(
                engine
                    .process_server_event(&wrong_terminal.to_string())
                    .is_err(),
                "another CID cannot borrow this conversation's accepted close proof"
            );
            assert!(alice
                .storage
                .get_conversation(&alice.did, &group.conversation_id)
                .await
                .unwrap()
                .is_some());
        });
    }

    #[test]
    fn failed_entries_read_returns_error_and_does_not_request_recovery() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            world
                .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
                .await;
            world.register_device("Alice").await.unwrap();
            let group = world
                .client("Alice")
                .orchestrator
                .create_group("transport", None, None)
                .await
                .unwrap();
            let engine = engine_for(&world, "Alice").await;
            let start = world.delivery_service().submitted_prepared_requests().len();
            world.delivery_service().fail_next_get_messages();
            let error = engine
                .process_server_event(
                    &event(
                        "messageAvailableEvent",
                        json!({"conversationId":group.conversation_id,"seq":1}),
                    )
                    .to_string(),
                )
                .unwrap_err();
            assert!(error.to_string().contains("injected get_messages failure"));
            assert!(
                world.delivery_service().submitted_prepared_requests()[start..]
                    .iter()
                    .all(|request| request.method == "GET")
            );
            assert_eq!(
                world
                    .delivery_service()
                    .submitted_prepared_requests()
                    .iter()
                    .filter(|request| request.operation == CanonicalOperation::GetPendingWelcomes)
                    .count(),
                0
            );
        });
    }
}
