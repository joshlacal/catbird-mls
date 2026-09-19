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
    async fn request_query(&self, operation: CanonicalOperation, query: String) -> Result<Value> {
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
        let mut raw = self.mls_context().read_direct_request_projection(cid)?;
        let mut projection = if let Some(raw) = &raw {
            DirectRequestProjection::decode(raw, &owner, &device)?
        } else {
            let entries = self
                .request_query(
                    CanonicalOperation::GetEntries,
                    format!("actorDeviceId={device}&conversationId={cid}&afterSeq=0&limit=100"),
                )
                .await?;
            let entries = entries["entries"].as_array().ok_or_else(invalid)?;
            let requests = entries
                .iter()
                .filter(|e| e["$type"] == "blue.catbird.chat.defs#directRequestEntry")
                .collect::<Vec<_>>();
            if requests.len() != 1 {
                return Err(OrchestratorError::ConversationNotFound(cid.into()));
            }
            let entry = requests[0];
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
            let verified = transcript::verify_signed_request(
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
            let document = self
                .credentials()
                .direct_request_receipt_authority_document()
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
                sender_public_key: candidate_key,
                publication_receipt: serde_json::to_vec(&receipt).map_err(|_| invalid())?,
                crypto: RequestCrypto::WelcomeAvailable,
                preview: None,
                acceptance_proof: None,
                recipient_public_key: None,
                pending_acceptance: None,
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
                let receipt = decode(&projection.publication_receipt)?;
                let key = transcript::resolve_direct_request_receipt_key(
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
                                projection.preview = Some(RequestPreview::Ready {
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
        Ok(view)
    }
    async fn refresh_request_acceptance(
        &self,
        cid: &str,
        owner: &str,
        device: &str,
        projection: &mut DirectRequestProjection,
        raw: &mut Option<Vec<u8>>,
    ) -> Result<()> {
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
            if let Some(keys) = self
                .credentials()
                .get_authorized_device_keys(recipient)
                .await?
            {
                let keys = keys
                    .into_iter()
                    .filter(|key| canonical_transport::derive_key_id(key) == key_id)
                    .collect::<Vec<_>>();
                if keys.len() == 1 {
                    candidate.acceptance_proof =
                        Some(serde_json::to_vec(proof).map_err(|_| invalid())?);
                    candidate.recipient_public_key = Some(keys[0].clone());
                    candidate.view(&owner, &device)?;
                    self.save_received_request(cid, &candidate, raw)?;
                    *projection = candidate;
                }
            }
        }
        Ok(())
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
