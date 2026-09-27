//! Request-only receive path. No ordinary message insertion, receipts or bots.
use super::projection::DirectRequestProjection;
use crate::chat_v2::transcript::direct_request::{self as transcript, DirectRequestKind};
use crate::orchestrator::{direct_request_bootstrap::*, direct_request_types::*, *};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

fn invalid() -> OrchestratorError {
    OrchestratorError::InvalidInput("Invalid direct request receive proof".into())
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    STANDARD
        .decode(
            v.as_str()
                .or_else(|| v["$bytes"].as_str())
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())
}
fn decode(raw: &[u8]) -> Result<Value> {
    if raw.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    crate::chat_v2::transcript::decode_strict_json(raw).map_err(|_| invalid())?;
    serde_json::from_slice(raw).map_err(|_| invalid())
}
fn same_request_coordinates(left: &Value, right: &Value) -> Result<bool> {
    let decode = |value: &Value| {
        super::super::canonical_transport::decode_conversation_coordinates(
            &serde_json::to_vec(value).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())
    };
    Ok(decode(left)? == decode(right)?)
}
fn bootstrap(publication: &Value) -> Result<DirectRequestBootstrap> {
    let p = &publication["body"];
    let context = json!({"protocolVersion":"2","requestId":p["requestId"],"firstMessageId":p["firstMessageId"],"conversationId":p["conversationId"],"origin":p["origin"],"actorDid":p["actorDid"],"actorDeviceId":p["actorDeviceId"],"actorKeyId":p["keyId"],"recipientDid":p["recipientDid"],"preparationDigest":p["preparationDigest"]});
    let context_json = serde_json::to_vec(&context).map_err(|_| invalid())?;
    let context_hash =
        transcript::direct_request_context_hash(&context_json).map_err(|_| invalid())?;
    if bytes(&p["contextHash"])? != context_hash {
        return Err(invalid());
    }
    let artifact = &p["artifacts"];
    let refs = artifact["welcome"]["deliveries"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|d| bytes(&d["provenance"]["keyPackageRef"]))
        .collect::<Result<Vec<_>>>()?;
    let import_until = u64::try_from(
        chrono::DateTime::parse_from_rfc3339(p["importUntil"].as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .timestamp(),
    )
    .map_err(|_| invalid())?;
    Ok(DirectRequestBootstrap {
        context_json,
        context_hash,
        coordinates: p["next"].clone(),
        import_until,
        expected_package_refs: refs,
        genesis_group_info: bytes(&artifact["genesisGroupInfo"]["bytes"])?,
        add_commit: bytes(&artifact["addCommit"]["bytes"])?,
        final_group_info: bytes(&artifact["finalGroupInfo"]["bytes"])?,
        welcome: bytes(&artifact["welcome"]["opaqueWelcome"])?,
        metadata_nonce: bytes(&artifact["metadataSnapshot"]["nonce"])?,
        metadata_ciphertext: bytes(&artifact["metadataSnapshot"]["ciphertext"])?,
        initial_ciphertext: bytes(&artifact["initialCiphertext"])?,
    })
}
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(crate) async fn known_direct_request(&self, cid: &str) -> Result<bool> {
        if !self.mls_context().supports_direct_request_bootstrap()
            || crate::chat_v2::ids::CanonicalUuid::parse(cid).is_err()
        {
            return Ok(false);
        }
        if self
            .mls_context()
            .read_direct_request_projection(cid)?
            .is_some()
        {
            return Ok(true);
        }
        let owner = self.require_user_did().await?;
        let runtime = self.conversations().lock().await.get(cid).cloned();
        let stored = if runtime.is_none() {
            self.storage().get_conversation(&owner, cid).await?
        } else {
            None
        };
        Ok(runtime.or(stored).is_some_and(|view| {
            view.canonical_state
                .is_some_and(|state| state.direct_request.is_some())
        }))
    }
    /// Adopt the authoritative winner without accepting its invitation or
    /// transferring the losing candidate's ciphertext or ratchet state.
    pub(super) async fn adopt_request_winner(&self, cid: &str, peer: &str) -> Result<bool> {
        crate::chat_v2::ids::CanonicalUuid::parse(cid).map_err(|_| invalid())?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let result = self
            .request_query(
                CanonicalOperation::GetConversationState,
                format!("actorDeviceId={device}&conversationId={cid}"),
            )
            .await?;
        let state = &result["state"];
        let participants = state["participants"].as_array().ok_or_else(invalid)?;
        if state["conversationKind"] != "direct"
            || state["coordinates"]["conversationId"] != cid
            || state["coordinates"]["lifecycle"] != "active"
            || participants.len() != 2
            || !participants.iter().any(|p| p["userDid"] == owner)
            || !participants.iter().any(|p| p["userDid"] == peer)
        {
            return Err(invalid());
        }
        if state
            .get("directRequest")
            .is_some_and(|value| !value.is_null())
        {
            let request = Box::pin(self.refresh_direct_request(cid)).await?;
            return Ok(request.consent != RequestConsent::Accepted);
        }
        let view = super::super::admission::conversation_view_from_state_json(state)
            .ok_or_else(invalid)?;
        if view.canonical_state.is_none() {
            return Err(invalid());
        }
        super::super::admission::validate_conversation_view(&view)?;
        self.retain_conversation_policy_json(cid, state).await?;
        self.storage()
            .ensure_conversation_exists(&owner, cid, &view.group_id)
            .await?;
        self.conversations().lock().await.insert(cid.into(), view);
        Ok(participants
            .iter()
            .any(|p| p["userDid"] == owner && p["status"] != "active"))
    }
    /// A device outside the publication's addressed set (for example one
    /// enrolled after publication) is refused the request entry and holds no
    /// request keys. Its truthful view is the account's consent from the
    /// validated conversation state with crypto unavailable. Nothing is
    /// retained, so later leaf recovery never inherits a fabricated preview.
    async fn unaddressed_direct_request_view(
        &self,
        cid: &str,
        owner: &str,
        device: &str,
    ) -> Result<DirectRequestView> {
        let result = self
            .request_query(
                CanonicalOperation::GetConversationState,
                format!("actorDeviceId={device}&conversationId={cid}"),
            )
            .await?;
        let view = super::super::admission::conversation_view_from_state_json(&result["state"])
            .ok_or_else(invalid)?;
        super::super::admission::validate_conversation_view(&view)?;
        let state = view.canonical_state.as_ref().ok_or_else(invalid)?;
        super::super::admission::validate_conversation_policy(state)?;
        let request = state.direct_request.as_ref().ok_or_else(invalid)?;
        if state.coordinates.conversation_id.as_str() != cid {
            return Err(invalid());
        }
        let recipient = owner == request.recipient_did.as_str();
        let sender = owner == request.sender_did.as_str();
        let consent = match request.consent.as_str() {
            _ if !(recipient || sender) => return Err(invalid()),
            "accepted" => RequestConsent::Accepted,
            "closed" | "expired" => RequestConsent::Closed,
            "incomingPending" | "outgoingPending" if recipient => RequestConsent::IncomingPending,
            "incomingPending" | "outgoingPending" => RequestConsent::OutgoingPending,
            _ => return Err(invalid()),
        };
        Ok(DirectRequestView {
            introduction: None,
            conversation_id: cid.into(),
            first_message_id: None,
            consent,
            crypto: RequestCrypto::Unavailable,
            preview: Some(RequestPreview::Unavailable {
                code: "DeviceNotAddressed".into(),
            }),
            capabilities: RequestCapabilities::derive(consent, RequestCrypto::Unavailable, false),
            state_version: u64::try_from(state.coordinates.state_version).map_err(|_| invalid())?,
            generation: u64::try_from(state.coordinates.generation).map_err(|_| invalid())?,
        })
    }
    pub(crate) async fn request_query(
        &self,
        operation: CanonicalOperation,
        query: String,
    ) -> Result<Value> {
        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation,
                method: "GET".into(),
                path: format!("{}?{}", operation.path(), query),
                body: None,
            })
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into(),
            });
        }
        decode(&response.body)
    }
    pub(super) async fn refresh_direct_request(&self, cid: &str) -> Result<DirectRequestView> {
        crate::chat_v2::ids::CanonicalUuid::parse(cid).map_err(|_| invalid())?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let lock = self.direct_request_operation_lock(cid).await;
        let _guard = lock.lock().await;
        if let Some(raw) = self.mls_context().read_direct_request_projection(cid)? {
            let view =
                DirectRequestProjection::decode(&raw, &owner, &device)?.view(&owner, &device)?;
            if view.consent == RequestConsent::Closed {
                return Ok(view);
            }
        }
        if self
            .mls_context()
            .list_direct_request_journal()?
            .iter()
            .any(|journal| {
                journal.conversation_id == cid
                    && journal.phase
                        == direct_request_journal::DirectRequestJournalPhase::RetiredPublished
            })
        {
            return Err(OrchestratorError::InvalidInput("RequestRetired".into()));
        }
        let mut raw = self.mls_context().read_direct_request_projection(cid)?;
        let mut projection = if let Some(raw) = &raw {
            DirectRequestProjection::decode(raw, &owner, &device)?
        } else {
            let entries = match self
                .request_query(
                    CanonicalOperation::GetEntries,
                    format!("actorDeviceId={device}&conversationId={cid}&afterSeq=0&limit=100"),
                )
                .await
            {
                Err(OrchestratorError::ServerError { status: 400, body })
                    if serde_json::from_str::<Value>(&body)
                        .is_ok_and(|error| error["error"] == "NotEntitled") =>
                {
                    crate::info_log!("[request] convo={} GetEntries NotEntitled: unaddressed view, nothing persisted", cid);
                    return self.unaddressed_direct_request_view(cid, &owner, &device).await;
                }
                result => result?,
            };
            let entries = entries["entries"].as_array().ok_or_else(invalid)?;
            let requests = entries
                .iter()
                .filter(|e| e["$type"] == "blue.catbird.chat.defs#directRequestEntry")
                .collect::<Vec<_>>();
            if requests.len() != 1 {
                return Err(OrchestratorError::ConversationNotFound(cid.into()));
            }
            let entry = super::projection::request_control_entry(requests[0].clone())?;
            let publication = &entry["signedRequest"];
            let p = &publication["body"];
            if entry["conversationId"] != cid
                || p["conversationId"] != cid
                || (p["actorDid"] != owner && p["recipientDid"] != owner)
            {
                return Err(invalid());
            }
            let candidate_key =
                bytes(&p["artifacts"]["metadataSnapshot"]["authorProof"]["signaturePublicKey"])?;
            let publication = serde_json::to_vec(publication).map_err(|_| invalid())?;
            let verified = transcript::verify_received_signed_request(
                DirectRequestKind::Publish,
                &publication,
                &candidate_key,
            )
            .map_err(|_| invalid())?;
            let request_id = verified.body()["requestId"].as_str().ok_or_else(invalid)?;
            let outcome = self
                .request_query(
                    CanonicalOperation::GetDirectRequestOutcome,
                    format!("actorDeviceId={device}&requestId={request_id}"),
                )
                .await?;
            if outcome["outcome"]["$type"] != "blue.catbird.chat.defs#signedDirectRequestReceipt" {
                return Err(invalid());
            }
            let mut receipt = outcome["outcome"].clone();
            receipt.as_object_mut().ok_or_else(invalid)?.remove("$type");
            // Retain the canonical bare receipt, independent of presentation.
            let receipt = transcript::normalize_read_presentation(
                &serde_json::to_vec(&receipt).map_err(|_| invalid())?,
                "signedDirectRequestReceipt",
                false,
            )
            .map_err(|_| invalid())?;
            let expected_coordinator = super::intent::CANONICAL_DIRECT_REQUEST_AUTHORITY;
            let document = self
                .credentials()
                .direct_request_receipt_authority_document(expected_coordinator)
                .await?
                .ok_or_else(|| {
                    OrchestratorError::Mls(crate::MLSError::OperationNotSupported {
                        reason: "Direct request receipt authority resolution unavailable".into(),
                    })
                })?;
            let projection = DirectRequestProjection {
                owner_did: owner.clone(),
                device_id: device.clone(),
                trusted_authority_document: document,
                publication,
                publication_entry: Some(entry.clone()),
                sender_public_key: candidate_key,
                publication_receipt: serde_json::to_vec(&receipt).map_err(|_| invalid())?,
                crypto: RequestCrypto::WelcomeAvailable,
                preview: None,
                acceptance_proof: None,
                recipient_public_key: None,
                pending_acceptance: None,
                close_proof: None,
            };
            // This verifies the authority's exact publication digest, actor and
            // immutable key fingerprint before any local MLS mutation.
            projection.view(&owner, &device)?;
            self.save_received_request(cid, &projection, &mut raw)?;
            projection
        };
        projection.view(&owner, &device)?;
        if projection.crypto != RequestCrypto::Ready
            && projection.crypto != RequestCrypto::Unavailable
        {
            let publication = decode(&projection.publication)?;
            let p = &publication["body"];
            let deliveries = p["artifacts"]["welcome"]["deliveries"]
                .as_array()
                .ok_or_else(invalid)?;
            let addressed = deliveries
                .iter()
                .filter(|d| d["recipientDid"] == owner && d["recipientDeviceId"] == device)
                .collect::<Vec<_>>();
            if addressed.len() > 1 {
                return Err(invalid());
            }
            if let Some(delivery) = addressed.first() {
                let auth_did = {
                    let val: Value = serde_json::from_slice(&projection.trusted_authority_document)
                        .map_err(|_| invalid())?;
                    val["id"].as_str().ok_or_else(invalid)?.to_string()
                };
                let receipt = decode(&projection.publication_receipt)?;
                let key = transcript::resolve_direct_request_receipt_key_for_authority(
                    &auth_did,
                    &projection.trusted_authority_document,
                    receipt["body"]["keyId"].as_str().ok_or_else(invalid)?,
                )
                .map_err(|_| invalid())?;
                let input = DirectRequestWelcomeInput {
                    bootstrap: bootstrap(&publication)?,
                    local_identity: format!("{owner}#{device}").into_bytes(),
                    local_package_ref: bytes(&delivery["provenance"]["keyPackageRef"])?,
                    publication_request: projection.publication.clone(),
                    actor_signature_public_key: projection.sender_public_key.clone(),
                    published_receipt: projection.publication_receipt.clone(),
                    receipt_authority_key: key,
                    preparation_request_digest: bytes(
                        &receipt["body"]["receipt"]["preparationRequestDigest"],
                    )?
                    .try_into()
                    .map_err(|_| invalid())?,
                };
                projection.crypto = RequestCrypto::Importing;
                self.save_received_request(cid, &projection, &mut raw)?;
                // Native cached import and cached decrypt precede the expiry
                // check. A crash between these commits safely resumes here.
                match self.mls_context().process_direct_request_welcome(&input) {
                    Ok(_) => {
                        projection.crypto = RequestCrypto::Ready;
                        match self
                            .mls_context()
                            .decrypt_direct_request_introduction(&input)?
                        {
                            DirectRequestIntroductionResult::Ready { plaintext } => {
                                let intro =
                                    transcript::decode_direct_request_introduction(&plaintext)
                                        .map_err(|_| invalid())?;
                                if intro
                                    .get("invitation")
                                    .is_some_and(|i| i["recipientDid"] != p["recipientDid"])
                                {
                                    return Err(invalid());
                                }
                                let invitation = intro
                                    .get("invitation")
                                    .map(|value| {
                                        serde_json::from_value(value.clone()).map_err(|_| invalid())
                                    })
                                    .transpose()?;
                                projection.preview = Some(RequestPreview::Ready {
                                    invitation,
                                    text: intro["text"].as_str().ok_or_else(invalid)?.into(),
                                });
                            }
                            DirectRequestIntroductionResult::Unavailable { code } => {
                                projection.preview = Some(RequestPreview::Unavailable { code });
                            }
                        }
                    }
                    Err(crate::MLSError::RequestImportExpired) => {
                        projection.crypto = RequestCrypto::Unavailable;
                        projection.preview = Some(RequestPreview::Unavailable {
                            code: "ImportExpired".into(),
                        });
                    }
                    Err(
                        crate::MLSError::InvalidInput { .. }
                        | crate::MLSError::InvalidKeyPackage
                        | crate::MLSError::NoMatchingKeyPackage { .. },
                    ) => {
                        projection.crypto = RequestCrypto::Unavailable;
                        projection.preview = Some(RequestPreview::Unavailable {
                            code: "InvalidBootstrap".into(),
                        });
                    }
                    Err(error) => return Err(error.into()),
                }
            } else {
                projection.crypto = RequestCrypto::Unavailable;
                projection.preview = Some(RequestPreview::Unavailable {
                    code: "DeviceNotAddressed".into(),
                });
            }
            self.save_received_request(cid, &projection, &mut raw)?;
        }
        // Snapshot consent is a routing hint. Only the recipient signature and
        // dedicated acceptance-commit receipt may release pending capabilities.
        if let Err(error) = self
            .refresh_request_acceptance(cid, &owner, &device, &mut projection, &mut raw)
            .await
        {
            tracing::warn!(conversation_id=cid,%error,"Request acceptance proof refresh deferred; retained preview and consent preserved");
        }
        let view = projection.view(&owner, &device)?;
        let publication = decode(&projection.publication)?;
        let group = hex::encode(bytes(&publication["body"]["next"]["groupId"])?);
        self.storage()
            .ensure_conversation_exists(&owner, cid, &group)
            .await?;
        // A successful import is native custody, independently of introduction
        // decoding or account consent. Persist its actual epoch before exposing
        // a ready projection so terminal cleanup can fence that same group.
        if let Ok(epoch) = self
            .mls_context()
            .get_epoch(bytes(&publication["body"]["next"]["groupId"])?)
        {
            self.storage()
                .set_group_state(&GroupState {
                    group_id: group.clone(),
                    conversation_id: cid.into(),
                    epoch,
                    members: self
                        .mls_context()
                        .group_member_identities(hex::decode(&group).map_err(|_| invalid())?)?
                        .into_iter()
                        .map(|identity| String::from_utf8(identity).map_err(|_| invalid()))
                        .collect::<Result<Vec<_>>>()?,
                })
                .await?;
        }
        Ok(view)
    }
    async fn refresh_request_acceptance(
        &self,
        cid: &str,
        owner: &str,
        device: &str,
        projection: &mut DirectRequestProjection,
        raw: &mut Option<Vec<u8>>,
    ) -> Result<bool> {
        let mut candidate = projection.clone();
        let state = self
            .request_query(
                CanonicalOperation::GetConversationState,
                format!("actorDeviceId={device}&conversationId={cid}"),
            )
            .await?;
        let proof = &state["state"]["directRequest"]["acceptanceProof"];
        if !proof.is_null() && candidate.acceptance_proof.is_none() {
            let body = &proof["entry"]["signedRequest"]["body"];
            let recipient = body["actorDid"].as_str().ok_or_else(invalid)?;
            let key_id = body["keyId"].as_str().ok_or_else(invalid)?;
            let recipient_device = body["actorDeviceId"].as_str().ok_or_else(invalid)?;
            let key = self
                .request_historical_device_key(recipient, recipient_device, key_id)
                .await?;
            let method = proof["receipt"]["body"]["keyId"]
                .as_str()
                .ok_or_else(invalid)?;
            let auth_did = {
                let val: Value = serde_json::from_slice(&candidate.trusted_authority_document)
                    .map_err(|_| invalid())?;
                val["id"].as_str().ok_or_else(invalid)?.to_string()
            };
            if transcript::resolve_direct_request_receipt_key_for_authority(
                &auth_did,
                &candidate.trusted_authority_document,
                method,
            )
            .is_err()
            {
                let doc = self
                    .credentials()
                    .direct_request_receipt_authority_document(&auth_did)
                    .await?
                    .ok_or_else(invalid)?;
                transcript::resolve_direct_request_receipt_key_for_authority(&auth_did, &doc, method)
                    .map_err(|_| invalid())?;
                candidate.trusted_authority_document =
                    super::intent::merge_trusted_documents_for_expected_authority(
                        &candidate.trusted_authority_document,
                        &doc,
                        &auth_did,
                    )?;
            }
            let authority_key = transcript::resolve_direct_request_receipt_key_for_authority(
                &auth_did,
                &candidate.trusted_authority_document,
                method,
            )
            .map_err(|_| invalid())?;
            let canonical =
                transcript::verify_received_direct_request_acceptance_proof_for_authority(
                    &auth_did,
                    &serde_json::to_vec(proof).map_err(|_| invalid())?,
                    &authority_key,
                    &key,
                )
                .map_err(|_| invalid())?;
            candidate.acceptance_proof =
                Some(serde_json::to_vec(&canonical).map_err(|_| invalid())?);
            candidate.recipient_public_key = Some(key);
            candidate.view(&owner, &device)?;
            candidate.pending_acceptance = None;
            self.save_received_request(cid, &candidate, raw)?;
            *projection = candidate;
        }
        let expected = if let Some(accepted) = &projection.acceptance_proof {
            let value: Value = serde_json::from_slice(accepted).map_err(|_| invalid())?;
            value["receipt"]["body"]["next"].clone()
        } else {
            let value: Value =
                serde_json::from_slice(&projection.publication).map_err(|_| invalid())?;
            value["body"]["next"].clone()
        };
        // Point-read metadata cannot establish acceptance. After the independent
        // proof reducer succeeds, retain only its exact current coordinate so
        // normal sends use the accepted policy version at the same MLS epoch.
        if same_request_coordinates(&state["state"]["coordinates"], &expected)? {
            if let Some(view) =
                super::super::admission::conversation_view_from_state_json(&state["state"])
            {
                if view.canonical_state.is_some() {
                    super::super::admission::validate_conversation_view(&view)?;
                    let mut view = view;
                    if let Ok(group) = hex::decode(&view.group_id) {
                        if let Ok(epoch) = self.mls_context().get_epoch(group) {
                            view.epoch = view.epoch.max(epoch);
                        }
                    }
                    let aliases = match self
                        .persist_sync_conversation_projection(owner, &view)
                        .await?
                    {
                        crate::orchestrator::sync::SyncProjectionOutcome::Committed {
                            retired_aliases,
                        } => retired_aliases,
                        // An in-flight reset owns this conversation; neither the
                        // accepted policy nor the view may be published until it
                        // completes. A later sync retries the refresh.
                        crate::orchestrator::sync::SyncProjectionOutcome::FencedByReset => {
                            return Ok(false)
                        }
                    };
                    self.retain_conversation_policy_json(cid, &state["state"])
                        .await?;
                    let mut conversations = self.conversations().lock().await;
                    for alias in aliases {
                        conversations.remove(&alias);
                    }
                    conversations.insert(cid.into(), view);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn save_received_request(
        &self,
        cid: &str,
        projection: &DirectRequestProjection,
        raw: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        let next = projection.encode()?;
        if !self
            .mls_context()
            .compare_exchange_direct_request_projection(cid, raw.as_deref(), &next)?
        {
            return Err(OrchestratorError::Storage(
                "Request projection changed concurrently".into(),
            ));
        }
        *raw = Some(next);
        Ok(())
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Invoked only after the existing canonical terminal verifier has accepted
    /// the server entry and authorized historical actor key.
    /// Callers pass an entry normalized once at the read boundary.
    pub(crate) async fn retain_verified_request_close(
        &self,
        cid: &str,
        entry: &Value,
        key: &[u8],
    ) -> Result<()> {
        if !self.mls_context().supports_direct_request_bootstrap() {
            return Ok(());
        }
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let lock = self.direct_request_operation_lock(cid).await;
        let _guard = lock.lock().await;
        let Some(raw) = self.mls_context().read_direct_request_projection(cid)? else {
            return Ok(());
        };
        let mut projection = DirectRequestProjection::decode(&raw, &owner, &device)?;
        let entry = entry.clone();
        let hash = super::projection::DirectRequestCloseProof::hash(&entry)?;
        if let Some(old) = &projection.close_proof {
            if old.entry_sha256 != hash {
                return Err(invalid());
            }
            if !self
                .mls_context()
                .commit_closed_direct_request_projection(cid, &raw, &raw)?
            {
                return Err(invalid());
            }
            return Ok(());
        }
        let publication = transcript::verify_received_signed_request(
            DirectRequestKind::Publish,
            &projection.publication,
            &projection.sender_public_key,
        )
        .map_err(|_| invalid())?;
        projection.close_proof = Some(super::projection::DirectRequestCloseProof {
            verified_prior: entry["signedRequest"]["body"]["prior"].clone(),
            entry,
            actor_public_key: key.to_vec(),
            entry_sha256: hash,
            publication_digest: *publication.request_digest(),
        });
        projection.pending_acceptance = None;
        let next = projection.encode()?;
        if !self
            .mls_context()
            .commit_closed_direct_request_projection(cid, &raw, &next)?
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Callers pass an entry normalized once at the read boundary.
    pub(crate) async fn replay_verified_request_close(
        &self,
        cid: &str,
        entry: &Value,
    ) -> Result<bool> {
        if !self.mls_context().supports_direct_request_bootstrap() {
            return Ok(false);
        }
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let Some(raw) = self.mls_context().read_direct_request_projection(cid)? else {
            return Ok(false);
        };
        let projection = DirectRequestProjection::decode(&raw, &owner, &device)?;
        let Some(proof) = &projection.close_proof else {
            return Ok(false);
        };
        if proof.entry_sha256 != super::projection::DirectRequestCloseProof::hash(entry)? {
            return Err(invalid());
        }
        if !self
            .mls_context()
            .commit_closed_direct_request_projection(cid, &raw, &raw)?
        {
            return Err(invalid());
        }
        Ok(true)
    }
    pub async fn close_direct_request(&self, cid: &str) -> Result<DirectRequestView> {
        self.require_direct_request_support()?;
        let existing = self.retained_direct_request_view(cid).await?;
        if existing
            .as_ref()
            .is_some_and(|v| v.consent == RequestConsent::Closed)
        {
            // Replay the canonical account-exit completion before returning;
            // its host tombstone may lag the atomic protected close commit.
            Box::pin(self.resume_account_exits(&std::collections::HashSet::new())).await?;
            return existing.ok_or_else(invalid);
        }
        let existing = match existing {
            Some(view) => view,
            None => Box::pin(self.refresh_request_preview(cid)).await?,
        };
        if existing.crypto == RequestCrypto::Unavailable {
            let owner = self.require_user_did().await?;
            let device = self.require_actor_device_id().await?;
            let lock = self.direct_request_operation_lock(cid).await;
            let _guard = lock.lock().await;
            let mut raw = self.mls_context().read_direct_request_projection(cid)?;
            let mut projection = DirectRequestProjection::decode(
                raw.as_deref().ok_or_else(invalid)?,
                &owner,
                &device,
            )?;
            let expected = if let Some(accepted) = &projection.acceptance_proof {
                let proof: Value = serde_json::from_slice(accepted).map_err(|_| invalid())?;
                proof["receipt"]["body"]["next"].clone()
            } else {
                let publication: Value =
                    serde_json::from_slice(&projection.publication).map_err(|_| invalid())?;
                publication["body"]["next"].clone()
            };
            let accepted_exit = self
                .mls_context()
                .list_account_exits()?
                .iter()
                .any(|record| {
                    record.accepted_response.is_some()
                        && record.storage_identity().is_ok_and(|identity| {
                            identity.conversation_id == cid
                                && identity.actor_did == owner
                                && identity.actor_device_id == device
                        })
                        && record.wrapper().is_ok_and(|wrapper| {
                            wrapper["signedRequest"]["body"]["$type"]
                                == "blue.catbird.chat.defs#conversationCloseBody"
                                && same_request_coordinates(
                                    &wrapper["signedRequest"]["body"]["prior"],
                                    &expected,
                                )
                                .unwrap_or(false)
                        })
                });
            let projected = self
                .storage()
                .get_conversation(&owner, cid)
                .await?
                .and_then(|view| view.canonical_state)
                .is_some_and(|state| {
                    serde_json::to_value(&state.coordinates)
                        .ok()
                        .is_some_and(|coordinate| {
                            same_request_coordinates(&coordinate, &expected).unwrap_or(false)
                        })
                });
            if !accepted_exit && !projected {
                // A device omitted from bootstrap has no native epoch. Retain
                // the independently verified request coordinate before an exit
                // can be submitted, so terminal host projection has a fence.
                // Only this exact incarnation's accepted close bypasses reads.
                if !self
                    .refresh_request_acceptance(cid, &owner, &device, &mut projection, &mut raw)
                    .await?
                {
                    return Err(OrchestratorError::InvalidInput(
                        "Request close requires an exact verified conversation coordinate".into(),
                    ));
                }
            }
        }
        Box::pin(self.leave_conversation(cid)).await?;
        let closed = self
            .retained_direct_request_view(cid)
            .await?
            .ok_or_else(invalid)?;
        if closed.consent != RequestConsent::Closed {
            return Err(invalid());
        }
        Ok(closed)
    }
}

#[cfg(test)]
mod coordinate_tests {
    use super::*;
    #[test]
    fn coordinates_accept_exact_schema_byte_aliases_and_reject_different_incarnations() {
        let coordinate = json!({"conversationId":"00000000-0000-4000-8000-000000000001","groupId":STANDARD.encode([1;32]),"generation":0,"epoch":1,"stateVersion":1,"confirmationTag":STANDARD.encode([2;32]),"groupContextHash":STANDARD.encode([3;32]),"lifecycle":"active"});
        let mut read = coordinate.clone();
        for field in ["groupId", "confirmationTag", "groupContextHash"] {
            read[field] = json!({"$bytes":coordinate[field]});
        }
        assert!(same_request_coordinates(&coordinate, &read).unwrap());
        read["epoch"] = json!(2);
        assert!(!same_request_coordinates(&coordinate, &read).unwrap());
        read["epoch"] = json!(1);
        read["generation"] = json!(1);
        assert!(!same_request_coordinates(&coordinate, &read).unwrap());
        read["groupId"]["extra"] = json!(true);
        assert!(same_request_coordinates(&coordinate, &read).is_err());
    }

    #[test]
    fn replay_verified_close_hash_accepts_read_boundary_bytes_identically() {
        let tombstone = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseTombstone",
            "conversationId": "11111111-1111-4111-9111-111111111111",
            "conversationKind": "direct",
            "retired": {
                "conversationId": "11111111-1111-4111-9111-111111111111",
                "groupId": STANDARD.encode([2u8; 32]),
                "generation": 0,
                "epoch": 0,
                "stateVersion": 1,
                "groupContextHash": STANDARD.encode([3u8; 32]),
                "confirmationTag": STANDARD.encode([4u8; 32]),
                "lifecycle": "superseded"
            },
            "closedByDid": "did:plc:alicefixtureaaaaaaaaaaaa",
            "closedByDeviceId": "72727272-7272-4272-b272-727272727272",
            "terminalSeq": 10,
            "closedAt": "2026-07-22T12:34:56.000Z"
        });
        let canonical = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseEntry",
            "entryId": "66666666-6666-4666-a666-666666666666",
            "conversationId": "11111111-1111-4111-9111-111111111111",
            "seq": 10,
            "signedRequest": {
                "body": {
                    "$type": "blue.catbird.chat.defs#conversationCloseBody",
                    "actorDid": "did:plc:alicefixtureaaaaaaaaaaaa",
                    "actorDeviceId": "72727272-7272-4272-b272-727272727272",
                    "authGeneration": 1,
                    "conversationKind": "direct",
                    "idempotencyKey": "67676767-6767-4767-a767-676767676767",
                    "keyId": "OQpJSMbjoMkp9Mz8qJRGo6zAieMT1g9qNZJr8WtW6i8",
                    "prior": {
                        "conversationId": "11111111-1111-4111-9111-111111111111",
                        "groupId": STANDARD.encode([2u8; 32]),
                        "generation": 0,
                        "epoch": 0,
                        "stateVersion": 0,
                        "groupContextHash": STANDARD.encode([3u8; 32]),
                        "confirmationTag": STANDARD.encode([4u8; 32]),
                        "lifecycle": "active"
                    },
                    "retired": {
                        "conversationId": "11111111-1111-4111-9111-111111111111",
                        "groupId": STANDARD.encode([2u8; 32]),
                        "generation": 0,
                        "epoch": 0,
                        "stateVersion": 1,
                        "groupContextHash": STANDARD.encode([3u8; 32]),
                        "confirmationTag": STANDARD.encode([4u8; 32]),
                        "lifecycle": "superseded"
                    },
                    "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
                    "signedAt": "2026-07-22T12:34:55.000Z",
                    "transitionId": "03adfab0-b088-4e86-b992-0f611d2eb64a"
                },
                "signature": STANDARD.encode([5u8; 64])
            },
            "receivedAt": "2026-07-22T12:34:56.000Z",
            "tombstone": tombstone
        });
        let canonical_hash = super::super::projection::DirectRequestCloseProof::hash(&canonical).unwrap();
        let mut server_read = canonical.clone();
        server_read["signedRequest"]["signature"] = json!({
            "$bytes": canonical["signedRequest"]["signature"]
        });
        let server_read_hash = super::super::projection::DirectRequestCloseProof::hash(
            &super::super::projection::normalized_close_entry(server_read.clone()).unwrap(),
        ).unwrap();
        assert_eq!(canonical_hash, server_read_hash);

        let mut forged = server_read.clone();
        forged["signedRequest"]["signature"] = json!({"$bytes": STANDARD.encode([88u8; 64])});
        let forged_hash = super::super::projection::DirectRequestCloseProof::hash(
            &super::super::projection::normalized_close_entry(forged).unwrap(),
        ).unwrap();
        assert_ne!(canonical_hash, forged_hash);
    }
}
