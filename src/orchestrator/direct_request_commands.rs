//! Durable sender operation: exact retries and publication proof precede adoption.
use super::{intent, projection::DirectRequestProjection, DirectRequestIntent};
use crate::chat_v2::transcript::direct_request::{self as transcript, DirectRequestKind};
use crate::orchestrator::{direct_request_types::*, *};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn invalid() -> OrchestratorError {
    OrchestratorError::InvalidInput("Invalid direct request protocol binding".into())
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    STANDARD
        .decode(
            value
                .as_str()
                .or_else(|| value["$bytes"].as_str())
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())
}
fn timestamp(value: &Value) -> Result<u64> {
    let t = chrono::DateTime::parse_from_rfc3339(value.as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    u64::try_from(t.timestamp()).map_err(|_| invalid())
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn date(seconds: u64) -> Result<String> {
    chrono::DateTime::from_timestamp(i64::try_from(seconds).map_err(|_| invalid())?, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .ok_or_else(invalid)
}
fn wire(operation: CanonicalOperation, wrapper: &[u8]) -> PreparedRequest {
    let mut body = b"{\"signedRequest\":".to_vec();
    body.extend(wrapper);
    body.push(b'}');
    PreparedRequest {
        operation,
        method: "POST".into(),
        path: operation.path().into(),
        body: Some(body),
    }
}
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    async fn sign_direct_request_body(
        &self,
        kind: DirectRequestKind,
        body: Value,
    ) -> Result<Vec<u8>> {
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        if body["actorDid"] != owner || body["actorDeviceId"] != device {
            return Err(invalid());
        }
        let key_id = body["keyId"].as_str().ok_or_else(invalid)?;
        let signing = transcript::direct_request_signing_bytes(
            kind,
            &serde_json::to_vec(&body).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let identity = format!("{owner}#{device}").into_bytes();
        let public = self.mls_context().identity_public_key(identity.clone())?;
        let signature = if let Some(authority) = self
            .credentials()
            .sign_clean_chat_transcript(&owner, &signing, key_id)
            .await?
        {
            if authority.device_id != device
                || authority.auth_generation != body["authGeneration"].as_i64()
                || authority.public_key != public
            {
                return Err(invalid());
            }
            authority.signature
        } else {
            self.mls_context()
                .sign_with_identity_key(identity, signing)?
        };
        let wrapper =
            serde_json::to_vec(&json!({"body":body,"signature":STANDARD.encode(signature)}))
                .map_err(|_| invalid())?;
        transcript::verify_signed_request(kind, &wrapper, &public).map_err(|_| invalid())?;
        Ok(wrapper)
    }
    pub async fn start_direct_request(
        &self,
        input: DirectRequestInput,
    ) -> Result<DirectRequestOutcome> {
        super::validate_direct_request_input(&input)?;
        self.require_direct_request_support()?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        if input.recipient_did == owner {
            return Err(invalid());
        }
        let lock = self.direct_request_operation_lock(&input.draft_id).await;
        let _guard = lock.lock().await;
        let previous_raw = self
            .mls_context()
            .read_direct_request_intent(&input.draft_id)?;
        let mut previous_attempts = Vec::new();
        if let Some(raw) = &previous_raw {
            let previous = DirectRequestIntent::decode(raw, &owner, &device)?;
            if previous.matches_input(&input) {
                return self
                    .resume_direct_request_locked(previous, raw.clone())
                    .await;
            }
            let terminal =
                intent::DirectRequestTerminalAttempt::from_intent(&previous).map_err(|_| {
                    OrchestratorError::InvalidInput(
                        "Draft has an unresolved immutable request attempt".into(),
                    )
                })?;
            previous_attempts = previous.previous_attempts;
            previous_attempts.push(terminal);
        }
        if let Some(reference) = &input.invitation {
            if reference.invited_by_did != owner
                || self
                    .get_group_invitation_reference(
                        &reference.conversation_id,
                        &reference.recipient_did,
                    )
                    .await?
                    .as_ref()
                    != Some(reference)
            {
                return Err(OrchestratorError::InvalidInput(
                    "Group invitation is no longer eligible for a note".into(),
                ));
            }
        }
        let document = self
            .credentials()
            .direct_request_receipt_authority_document()
            .await?
            .ok_or_else(|| {
                OrchestratorError::Mls(crate::MLSError::OperationNotSupported {
                    reason: "Direct request receipt authority resolution unavailable".into(),
                })
            })?;
        intent::validate_authority_document(&document).map_err(|refusal| match refusal {
            // A structurally valid document naming another authority: the
            // request has no canonical transaction to join, so report the
            // typed unsupported capability and never fall back to legacy
            // federation delivery.
            intent::AuthorityDocumentRefusal::ForeignAuthority => {
                OrchestratorError::Mls(crate::MLSError::OperationNotSupported {
                    reason: "Direct request receipt authority is not the canonical authority"
                        .into(),
                })
            }
            intent::AuthorityDocumentRefusal::Malformed => OrchestratorError::Storage(
                "Invalid direct request ownership record".into(),
            ),
        })?;
        let public = self
            .mls_context()
            .identity_public_key(format!("{owner}#{device}").into_bytes())?;
        let generation = self
            .credentials()
            .get_auth_generation(&owner)
            .await?
            .ok_or_else(invalid)?;
        let legacy_origin_snapshot = self
            .discover_direct_request_origin(&owner, &input.recipient_did)
            .await?;
        let origin = match &legacy_origin_snapshot {
            Some(state) => super::origin::legacy_origin(state, &owner, &input.recipient_did)?
                .ok_or_else(invalid)?,
            None => json!({"$type":"blue.catbird.chat.defs#freshDirectOrigin"}),
        };
        let conversation_id = legacy_origin_snapshot
            .as_ref()
            .and_then(|s| s["coordinates"]["conversationId"].as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let request_id = Uuid::new_v4().to_string();
        let body = json!({"$type":"blue.catbird.chat.defs#directRequestPreparationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2","actorDid":owner,"actorDeviceId":device,"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"authGeneration":generation,"requestId":request_id,"firstMessageId":Uuid::new_v4().to_string(),"conversationId":conversation_id,"recipientDid":input.recipient_did,"origin":origin,"profile":"encryptedIntroduction1","idempotencyKey":request_id,"signedAt":now()});
        let wrapper = self
            .sign_direct_request_body(DirectRequestKind::Prepare, body)
            .await?;
        let intent = DirectRequestIntent {
            input,
            actor_did: owner,
            actor_device_id: device,
            actor_public_key: public,
            prepare_wrapper: wrapper,
            legacy_origin_snapshot,
            trusted_authority_document: document,
            preparation_response: None,
            cancel_wrapper: None,
            publication_wrapper: None,
            terminal_response: None,
            publication_attempted: false,
            cancellation_requested: false,
            projection_completed: false,
            previous_attempts,
        };
        let raw = intent.encode()?;
        if !self.mls_context().compare_exchange_direct_request_intent(
            &intent.input.draft_id,
            previous_raw.as_deref(),
            &raw,
        )? {
            return Err(OrchestratorError::Storage(
                "Request draft changed concurrently".into(),
            ));
        }
        self.resume_direct_request_locked(intent, raw).await
    }
    pub async fn resume_direct_request(&self, draft_id: &str) -> Result<DirectRequestOutcome> {
        self.require_direct_request_support()?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let lock = self.direct_request_operation_lock(draft_id).await;
        let _guard = lock.lock().await;
        let raw = self
            .mls_context()
            .read_direct_request_intent(draft_id)?
            .ok_or_else(|| OrchestratorError::InvalidInput("Unknown request draft".into()))?;
        let intent = DirectRequestIntent::decode(&raw, &owner, &device)?;
        self.resume_direct_request_locked(intent, raw).await
    }
    pub(crate) fn require_direct_request_support(&self) -> Result<()> {
        if !self.mls_context().supports_direct_request_bootstrap() {
            return Err(OrchestratorError::Mls(
                crate::MLSError::OperationNotSupported {
                    reason: "Durable direct request storage unavailable".into(),
                },
            ));
        }
        Ok(())
    }
    fn save_direct_request_intent(
        &self,
        intent: &DirectRequestIntent,
        old: &mut Vec<u8>,
    ) -> Result<()> {
        let next = intent.encode()?;
        if !self.mls_context().compare_exchange_direct_request_intent(
            &intent.input.draft_id,
            Some(old),
            &next,
        )? {
            return Err(OrchestratorError::Storage(
                "Request ownership changed concurrently".into(),
            ));
        }
        *old = next;
        Ok(())
    }
    async fn resume_direct_request_locked(
        &self,
        mut intent: DirectRequestIntent,
        mut raw: Vec<u8>,
    ) -> Result<DirectRequestOutcome> {
        let id = intent.request_id()?;
        let unknown = || DirectRequestOutcome::OutcomeUnknown {
            request_id: id.clone(),
        };
        if let Some(receipt) = intent.terminal_response.clone() {
            return self
                .resolve_direct_request_receipt(&mut intent, &mut raw, &receipt)
                .await;
        }
        if intent.cancellation_requested {
            let wrapper = intent.cancel_wrapper.as_ref().ok_or_else(invalid)?;
            let response = match self
                .api_client()
                .submit_prepared_request(wire(
                    CanonicalOperation::CancelDirectRequestPreparation,
                    wrapper,
                ))
                .await
            {
                Ok(r) if r.status == 200 => r,
                _ => return Ok(unknown()),
            };
            return self
                .handle_direct_request_response(&mut intent, &mut raw, &response.body)
                .await;
        }
        let existing = self
            .mls_context()
            .list_direct_request_journal()?
            .into_iter()
            .find(|j| j.request_id == id);
        if let Some(journal) = &existing {
            if let Some(receipt) = &journal.terminal_receipt {
                return self
                    .resolve_direct_request_receipt(&mut intent, &mut raw, receipt)
                    .await;
            }
        }
        if intent.preparation_response.is_none() {
            let response = match self
                .api_client()
                .submit_prepared_request(wire(
                    CanonicalOperation::PrepareDirectRequest,
                    &intent.prepare_wrapper,
                ))
                .await
            {
                Ok(r) if r.status == 200 => r,
                _ => return Ok(unknown()),
            };
            crate::chat_v2::transcript::decode_strict_json(&response.body)
                .map_err(|_| invalid())?;
            let value: Value = serde_json::from_slice(&response.body).map_err(|_| invalid())?;
            if value["outcome"]["$type"] != "blue.catbird.chat.defs#directRequestPreparedOutcome" {
                return self
                    .handle_direct_request_response(&mut intent, &mut raw, &response.body)
                    .await;
            }
            let preparation =
                serde_json::to_vec(&value["outcome"]["preparation"]).map_err(|_| invalid())?;
            let canonical = self.validate_direct_request_preparation(&intent, &preparation)?;
            intent.preparation_response =
                Some(serde_json::to_vec(&canonical).map_err(|_| invalid())?);
            self.save_direct_request_intent(&intent, &mut raw)?;
        }
        let preparation = self.validate_direct_request_preparation(
            &intent,
            intent.preparation_response.as_ref().ok_or_else(invalid)?,
        )?;
        let journal = match existing {
            Some(j) => j,
            None => self.prepare_direct_request_crypto(&intent, &preparation)?,
        };
        let exact = if let Some(bytes) = journal.publish_request.clone() {
            bytes
        } else {
            let wrapper = self
                .build_direct_request_publication(&intent, &preparation, &journal)
                .await?;
            let request = wire(CanonicalOperation::PublishDirectRequest, &wrapper);
            let exact = request.body.ok_or_else(invalid)?;
            self.mls_context()
                .persist_direct_request_publish(&id, &exact)?;
            exact
        };
        let exact_value: Value = serde_json::from_slice(&exact).map_err(|_| invalid())?;
        intent.publication_wrapper = Some(
            serde_json::to_vec(exact_value.get("signedRequest").unwrap_or(&exact_value))
                .map_err(|_| invalid())?,
        );
        intent.publication_attempted = true;
        self.save_direct_request_intent(&intent, &mut raw)?;
        let request = PreparedRequest {
            operation: CanonicalOperation::PublishDirectRequest,
            method: "POST".into(),
            path: CanonicalOperation::PublishDirectRequest.path().into(),
            body: Some(exact),
        };
        let response = match self.api_client().submit_prepared_request(request).await {
            Ok(r) if r.status == 200 => r,
            _ => return Ok(unknown()),
        };
        self.handle_direct_request_response(&mut intent, &mut raw, &response.body)
            .await
    }
    fn validate_direct_request_preparation(
        &self,
        intent: &DirectRequestIntent,
        raw: &[u8],
    ) -> Result<Value> {
        if raw.len() > transcript::MAX_PREPARE_HTTP_RESPONSE_BYTES {
            return Err(invalid());
        }
        let value = transcript::normalize_direct_request_read_presentation(
            raw,
            "directRequestPreparationView",
            false,
        )
        .map_err(|_| invalid())?;
        let method = value["receiptKeyId"].as_str().ok_or_else(invalid)?;
        let key = transcript::resolve_direct_request_receipt_key(
            &intent.trusted_authority_document,
            method,
        )
        .map_err(|_| invalid())?;
        let preparation = transcript::verify_direct_request_preparation(
            &serde_json::to_vec(&value).map_err(|_| invalid())?,
            &key,
        )
        .map_err(|_| invalid())?;
        let prepare = transcript::verify_signed_request(
            DirectRequestKind::Prepare,
            &intent.prepare_wrapper,
            &intent.actor_public_key,
        )
        .map_err(|_| invalid())?;
        for field in [
            "requestId",
            "firstMessageId",
            "conversationId",
            "recipientDid",
            "origin",
            "profile",
        ] {
            if preparation[field] != prepare.body()[field] {
                return Err(invalid());
            }
        }
        for field in ["actorDid", "actorDeviceId", "keyId", "authGeneration"] {
            if preparation["creator"][field] != prepare.body()[field] {
                return Err(invalid());
            }
        }
        if preparation["preparationRequestDigest"] != STANDARD.encode(prepare.request_digest()) {
            return Err(invalid());
        }
        Ok(preparation)
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    fn prepare_direct_request_crypto(
        &self,
        intent: &DirectRequestIntent,
        preparation: &Value,
    ) -> Result<direct_request_journal::DirectRequestJournal> {
        let prepared = transcript::verify_signed_request(
            DirectRequestKind::Prepare,
            &intent.prepare_wrapper,
            &intent.actor_public_key,
        )
        .map_err(|_| invalid())?;
        let body = prepared.body();
        let selected = preparation["selectedDevices"]
            .as_array()
            .ok_or_else(invalid)?;
        let mut packages = Vec::new();
        let mut refs = Vec::new();
        let minimum_import_until = timestamp(&preparation["minimumImportUntil"])?;
        let mut deadline = u64::MAX;
        let mut recipient_count = 0;
        let mut devices = std::collections::HashSet::new();
        for device in selected {
            let did = device["actorDid"].as_str().ok_or_else(invalid)?;
            let device_id = device["actorDeviceId"].as_str().ok_or_else(invalid)?;
            if did != intent.actor_did && did != intent.input.recipient_did {
                return Err(invalid());
            }
            if !devices.insert((did, device_id))
                || (did == intent.actor_did && device_id == intent.actor_device_id)
            {
                return Err(invalid());
            }
            if did == intent.input.recipient_did {
                recipient_count += 1;
            }
            let package = bytes(&device["keyPackage"]["bytes"])?;
            let binding =
                credential_binding::extract_key_package_binding(&package).map_err(|_| invalid())?;
            if binding.identity != format!("{did}#{device_id}") {
                return Err(invalid());
            }
            let grant = transcript::verify_received_signed_request(
                DirectRequestKind::Grant,
                &serde_json::to_vec(&device["grant"]).map_err(|_| invalid())?,
                &binding.signature_key,
            )
            .map_err(|_| invalid())?;
            for field in ["actorDid", "actorDeviceId", "keyId", "authGeneration"] {
                if grant.body()[field] != device[field] {
                    return Err(invalid());
                }
            }
            if grant.body()["keyPackageRef"] != device["keyPackage"]["keyPackageRef"]
                || bytes(&grant.body()["keyPackageSha256"])? != Sha256::digest(&package).as_slice()
            {
                return Err(invalid());
            }
            deadline = deadline.min(timestamp(&grant.body()["expiresAt"])?);
            refs.push(bytes(&device["keyPackage"]["keyPackageRef"])?);
            packages.push(package);
        }
        if recipient_count == 0 || deadline < minimum_import_until {
            return Err(invalid());
        }
        let context = json!({"protocolVersion":"2","requestId":body["requestId"],"firstMessageId":body["firstMessageId"],"conversationId":body["conversationId"],"origin":body["origin"],"actorDid":body["actorDid"],"actorDeviceId":body["actorDeviceId"],"actorKeyId":body["keyId"],"recipientDid":body["recipientDid"],"preparationDigest":preparation["preparationDigest"]});
        let method = preparation["receiptKeyId"].as_str().ok_or_else(invalid)?;
        let key = transcript::resolve_direct_request_receipt_key(
            &intent.trusted_authority_document,
            method,
        )
        .map_err(|_| invalid())?;
        self.mls_context()
            .prepare_direct_request_bootstrap(
                &direct_request_bootstrap::DirectRequestBootstrapInput {
                    draft_id: intent.input.draft_id.clone(),
                    context_json: serde_json::to_vec(&context).map_err(|_| invalid())?,
                    group_id: rand::random::<[u8; 32]>().to_vec(),
                    generation: match &intent.legacy_origin_snapshot {
                        Some(s) => s["coordinates"]["generation"]
                            .as_u64()
                            .and_then(|g| g.checked_add(1))
                            .ok_or_else(invalid)?,
                        None => 0,
                    },
                    state_version: 1,
                    key_packages: packages,
                    expected_package_refs: refs,
                    authority_import_until: deadline,
                    preparation_request_digest: *prepared.request_digest(),
                    receipt_authority_key: key,
                    text: intent.input.text.clone(),
                    invitation: intent.input.invitation.clone(),
                    metadata: crate::metadata::GroupMetadataV1 {
                        version: 1,
                        title: String::new(),
                        description: String::new(),
                        avatar_blob_locator: None,
                        avatar_content_type: None,
                    },
                },
            )
            .map_err(Into::into)
    }
    async fn build_direct_request_publication(
        &self,
        intent: &DirectRequestIntent,
        preparation: &Value,
        journal: &direct_request_journal::DirectRequestJournal,
    ) -> Result<Vec<u8>> {
        let prepared = transcript::verify_signed_request(
            DirectRequestKind::Prepare,
            &intent.prepare_wrapper,
            &intent.actor_public_key,
        )
        .map_err(|_| invalid())?;
        let mut body = prepared.body().clone();
        let b = &journal.bootstrap;
        let import_until = date(b.import_until)?;
        body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
        body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
        body["signedAt"] = json!(now());
        body["preparationDigest"] = preparation["preparationDigest"].clone();
        body["preparationRequestDigest"] = json!(STANDARD.encode(prepared.request_digest()));
        body["contextHash"] = json!(STANDARD.encode(b.context_hash));
        body["next"] = b.coordinates.clone();
        body["importUntil"] = json!(import_until);
        let artifact = |data: &[u8], content_type: &str| json!({"framing":"mlsMessage","contentType":content_type,"bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))});
        let deliveries=preparation["selectedDevices"].as_array().ok_or_else(invalid)?.iter().map(|d|json!({"recipientDid":d["actorDid"],"recipientDeviceId":d["actorDeviceId"],"provenance":{"requestId":journal.request_id,"preparationDigest":preparation["preparationDigest"],"contextHash":STANDARD.encode(b.context_hash),"grantId":d["grant"]["body"]["grantId"],"grantRevision":d["grant"]["body"]["grantRevision"],"keyPackageRef":d["keyPackage"]["keyPackageRef"],"importUntil":import_until}})).collect::<Vec<_>>();
        let author = json!({"authorDid":body["actorDid"],"authorDeviceId":body["actorDeviceId"],"authorKeyId":body["keyId"],"signaturePublicKey":STANDARD.encode(&intent.actor_public_key),"authGenerationAtOrigin":body["authGeneration"],"originTransitionId":journal.request_id,"originSeq":match &intent.legacy_origin_snapshot { Some(s) => s["snapshotSeq"].as_u64().and_then(|n| n.checked_add(1)).ok_or_else(invalid)?, None => 1 },"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"});
        body["artifacts"] = json!({"genesisGroupInfo":artifact(&b.genesis_group_info,"groupInfo"),"addCommit":artifact(&b.add_commit,"publicMessageCommit"),"finalGroupInfo":artifact(&b.final_group_info,"groupInfo"),"welcome":{"opaqueWelcome":STANDARD.encode(&b.welcome),"sha256":STANDARD.encode(Sha256::digest(&b.welcome)),"deliveries":deliveries},"initialCiphertext":STANDARD.encode(&b.initial_ciphertext),"metadataSnapshot":{"coordinate":direct_request_bootstrap::metadata_coordinate(&b.coordinates)?,"originTransitionId":journal.request_id,"metadataVersion":1,"nonce":STANDARD.encode(&b.metadata_nonce),"ciphertext":STANDARD.encode(&b.metadata_ciphertext),"ciphertextSha256":STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),"ciphertextSize":b.metadata_ciphertext.len(),"authorProof":author}});
        self.sign_direct_request_body(DirectRequestKind::Publish, body)
            .await
    }
    async fn handle_direct_request_response(
        &self,
        intent: &mut DirectRequestIntent,
        raw: &mut Vec<u8>,
        response: &[u8],
    ) -> Result<DirectRequestOutcome> {
        if response.len() > transcript::MAX_PREPARE_HTTP_RESPONSE_BYTES {
            return Err(invalid());
        }
        crate::chat_v2::transcript::decode_strict_json(response).map_err(|_| invalid())?;
        let value: Value = serde_json::from_slice(response).map_err(|_| invalid())?;
        if value
            .as_object()
            .is_none_or(|object| object.len() != 1 || !object.contains_key("outcome"))
        {
            return Err(invalid());
        }
        if value["outcome"]["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt" {
            let mut receipt = value["outcome"].clone();
            receipt.as_object_mut().ok_or_else(invalid)?.remove("$type");
            return self
                .resolve_direct_request_receipt(
                    intent,
                    raw,
                    &serde_json::to_vec(&receipt).map_err(|_| invalid())?,
                )
                .await;
        }
        Ok(DirectRequestOutcome::OutcomeUnknown {
            request_id: intent.request_id()?,
        })
    }
    async fn resolve_direct_request_receipt(
        &self,
        intent: &mut DirectRequestIntent,
        raw: &mut Vec<u8>,
        receipt: &[u8],
    ) -> Result<DirectRequestOutcome> {
        let value: Value = serde_json::from_slice(receipt).map_err(|_| invalid())?;
        let method = value["body"]["keyId"].as_str().ok_or_else(invalid)?;
        let key = match transcript::resolve_direct_request_receipt_key(
            &intent.trusted_authority_document,
            method,
        ) {
            Ok(key) => key,
            Err(_) => {
                let authenticated = self
                    .credentials()
                    .direct_request_receipt_authority_document()
                    .await?
                    .ok_or_else(invalid)?;
                let key = transcript::resolve_direct_request_receipt_key(&authenticated, method)
                    .map_err(|_| invalid())?;
                let mut previous: Value =
                    serde_json::from_slice(&intent.trusted_authority_document)
                        .map_err(|_| invalid())?;
                let current: Value =
                    serde_json::from_slice(&authenticated).map_err(|_| invalid())?;
                let methods = previous["verificationMethod"]
                    .as_array_mut()
                    .ok_or_else(invalid)?;
                for method in current["verificationMethod"]
                    .as_array()
                    .ok_or_else(invalid)?
                {
                    if let Some(old) = methods.iter().find(|old| old["id"] == method["id"]) {
                        if old != method {
                            return Err(invalid());
                        }
                    } else {
                        methods.push(method.clone());
                    }
                }
                intent.trusted_authority_document =
                    serde_json::to_vec(&previous).map_err(|_| invalid())?;
                self.save_direct_request_intent(intent, raw)?;
                key
            }
        };
        let verified =
            transcript::verify_received_signed_request(DirectRequestKind::Outcome, receipt, &key)
                .map_err(|_| invalid())?;
        let prepare = transcript::verify_signed_request(
            DirectRequestKind::Prepare,
            &intent.prepare_wrapper,
            &intent.actor_public_key,
        )
        .map_err(|_| invalid())?;
        let proof = &verified.body()["receipt"];
        let id = intent.request_id()?;
        if proof["requestId"] != id
            || bytes(&proof["preparationRequestDigest"])? != prepare.request_digest()
        {
            return Err(invalid());
        }
        for (receipt_field, prepare_field) in [
            ("actorDid", "actorDid"),
            ("actorDeviceId", "actorDeviceId"),
            ("actorKeyId", "keyId"),
            ("authGeneration", "authGeneration"),
        ] {
            if proof[receipt_field] != prepare.body()[prepare_field] {
                return Err(invalid());
            }
        }
        let trigger_digest = match proof["requestKind"].as_str() {
            Some("prepare" | "expiry") => *prepare.request_digest(),
            Some("cancel") => *transcript::verify_signed_request(
                DirectRequestKind::Cancel,
                intent.cancel_wrapper.as_ref().ok_or_else(invalid)?,
                &intent.actor_public_key,
            )
            .map_err(|_| invalid())?
            .request_digest(),
            Some("publish") => {
                let j = self
                    .mls_context()
                    .list_direct_request_journal()?
                    .into_iter()
                    .find(|j| j.request_id == id)
                    .ok_or_else(invalid)?;
                let exact: Value =
                    serde_json::from_slice(j.publish_request.as_ref().ok_or_else(invalid)?)
                        .map_err(|_| invalid())?;
                *transcript::verify_signed_request(
                    DirectRequestKind::Publish,
                    &serde_json::to_vec(exact.get("signedRequest").unwrap_or(&exact))
                        .map_err(|_| invalid())?,
                    &intent.actor_public_key,
                )
                .map_err(|_| invalid())?
                .request_digest()
            }
            _ => return Err(invalid()),
        };
        if bytes(&proof["requestDigest"])? != trigger_digest {
            return Err(invalid());
        }
        let journal = self
            .mls_context()
            .list_direct_request_journal()?
            .into_iter()
            .find(|j| j.request_id == id);
        let kind = proof["$type"].as_str().ok_or_else(invalid)?;
        if kind == "blue.catbird.chat.defs#directRequestPublishedReceipt" {
            let journal = journal.ok_or_else(invalid)?;
            if journal.phase == direct_request_journal::DirectRequestJournalPhase::RetiredPublished
            {
                return Err(OrchestratorError::InvalidInput("RequestRetired".into()));
            }
            let adopted = self
                .mls_context()
                .confirm_published_bootstrap(&id, receipt, &key)?;
            intent.terminal_response = Some(receipt.to_vec());
            intent.publication_attempted = true;
            self.save_direct_request_intent(intent, raw)?;
            let exact: Value =
                serde_json::from_slice(journal.publish_request.as_ref().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let wrapper = exact.get("signedRequest").unwrap_or(&exact);
            let candidate = DirectRequestProjection {
                owner_did: intent.actor_did.clone(),
                device_id: intent.actor_device_id.clone(),
                trusted_authority_document: intent.trusted_authority_document.clone(),
                publication_entry: None,
                publication: serde_json::to_vec(wrapper).map_err(|_| invalid())?,
                sender_public_key: intent.actor_public_key.clone(),
                publication_receipt: receipt.to_vec(),
                crypto: RequestCrypto::Ready,
                preview: Some(RequestPreview::Ready {
                    text: intent.input.text.clone(),
                    invitation: intent.input.invitation.clone(),
                }),
                acceptance_proof: None,
                recipient_public_key: None,
                pending_acceptance: None,
                close_proof: None,
            };
            let current = self
                .mls_context()
                .read_direct_request_projection(&adopted.conversation_id)?;
            if let Some(raw) = &current {
                let retained = DirectRequestProjection::decode(
                    raw,
                    &intent.actor_did,
                    &intent.actor_device_id,
                )?;
                if retained.publication != candidate.publication
                    || retained.publication_receipt != candidate.publication_receipt
                    || retained.sender_public_key != candidate.sender_public_key
                {
                    return Err(OrchestratorError::Storage(
                        "Conflicting request publication projection".into(),
                    ));
                }
            }
            if current.is_none()
                && !self
                    .mls_context()
                    .compare_exchange_direct_request_projection(
                        &adopted.conversation_id,
                        None,
                        &candidate.encode()?,
                    )?
            {
                return Err(OrchestratorError::Storage(
                    "Request projection raced".into(),
                ));
            }
            self.storage()
                .ensure_conversation_exists(
                    &intent.actor_did,
                    &adopted.conversation_id,
                    &hex::encode(bytes(&adopted.bootstrap.coordinates["groupId"])?),
                )
                .await?;
            self.mls_context().mark_direct_request_projected(&id)?;
            intent.projection_completed = true;
            self.save_direct_request_intent(intent, raw)?;
            return Ok(DirectRequestOutcome::RequestSent {
                conversation_id: adopted.conversation_id,
                message_id: adopted.first_message_id,
                request_id: id,
            });
        }
        if journal.is_some() {
            self.mls_context()
                .abandon_rejected_bootstrap(&id, receipt, &key)?;
        }
        intent.terminal_response = Some(receipt.to_vec());
        self.save_direct_request_intent(intent, raw)?;
        match kind {
            "blue.catbird.chat.defs#directRequestExistingDirectReceipt" => {
                let winner = proof["conversationId"].as_str().ok_or_else(invalid)?;
                let pending =
                    Box::pin(self.adopt_request_winner(winner, &intent.input.recipient_did))
                        .await?;
                Ok(DirectRequestOutcome::ExistingDirect {
                    conversation_id: winner.into(),
                    requires_acceptance: pending
                        || proof["requiresAcceptance"].as_bool().ok_or_else(invalid)?,
                })
            }
            "blue.catbird.chat.defs#directRequestCancelledReceipt" => {
                Ok(DirectRequestOutcome::TerminalNotPublished {
                    request_id: id,
                    code: "PreparationCancelled".into(),
                })
            }
            "blue.catbird.chat.defs#directRequestExpiredReceipt" => {
                let code = match proof.get("requestKind").and_then(|v| v.as_str()) {
                    Some("publishedExpiry") => "RequestExpired",
                    _ => "PreparationExpired",
                };
                Ok(DirectRequestOutcome::TerminalNotPublished {
                    request_id: id,
                    code: code.into(),
                })
            }
            "blue.catbird.chat.defs#directRequestRejectedReceipt" => {
                Ok(DirectRequestOutcome::TerminalNotPublished {
                    request_id: id,
                    code: proof["code"].as_str().ok_or_else(invalid)?.into(),
                })
            }
            _ => Err(invalid()),
        }
    }
    pub async fn cancel_direct_request(&self, draft_id: &str) -> Result<DirectRequestOutcome> {
        self.require_direct_request_support()?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let lock = self.direct_request_operation_lock(draft_id).await;
        let _guard = lock.lock().await;
        let mut raw = self
            .mls_context()
            .read_direct_request_intent(draft_id)?
            .ok_or_else(invalid)?;
        let mut intent = DirectRequestIntent::decode(&raw, &owner, &device)?;
        if intent.terminal_response.is_none() && !intent.cancellation_requested {
            let prepare = transcript::verify_signed_request(
                DirectRequestKind::Prepare,
                &intent.prepare_wrapper,
                &intent.actor_public_key,
            )
            .map_err(|_| invalid())?;
            let p = prepare.body();
            let body = json!({"$type":"blue.catbird.chat.defs#directRequestCancellationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-CANCEL\0","protocolVersion":"2","actorDid":owner,"actorDeviceId":device,"keyId":p["keyId"],"authGeneration":p["authGeneration"],"requestId":p["requestId"],"idempotencyKey":Uuid::new_v4().to_string(),"recipientDid":p["recipientDid"],"preparationRequestDigest":STANDARD.encode(prepare.request_digest()),"signedAt":now()});
            intent.cancel_wrapper = Some(
                self.sign_direct_request_body(DirectRequestKind::Cancel, body)
                    .await?,
            );
            intent.cancellation_requested = true;
            self.save_direct_request_intent(&intent, &mut raw)?;
        }
        self.resume_direct_request_locked(intent, raw).await
    }
    pub async fn refresh_request_preview(
        &self,
        conversation_id: &str,
    ) -> Result<DirectRequestView> {
        self.require_direct_request_support()?;
        self.refresh_direct_request(conversation_id).await
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(crate) async fn try_accept_direct_request(
        &self,
        conversation_id: &str,
    ) -> Result<Option<Value>> {
        if !self.mls_context().supports_direct_request_bootstrap()
            || crate::chat_v2::ids::CanonicalUuid::parse(conversation_id).is_err()
        {
            return Ok(None);
        }
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let lock = self.direct_request_operation_lock(conversation_id).await;
        let _guard = lock.lock().await;
        let Some(mut raw) = self
            .mls_context()
            .read_direct_request_projection(conversation_id)?
        else {
            return Ok(None);
        };
        let mut projection = DirectRequestProjection::decode(&raw, &owner, &device)?;
        let view = projection.view(&owner, &device)?;
        if view.consent == RequestConsent::Accepted {
            let proof: Value =
                serde_json::from_slice(projection.acceptance_proof.as_ref().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            return Ok(Some(
                json!({"coordinates":proof["receipt"]["body"]["next"],"acceptanceProof":proof}),
            ));
        }
        if view.consent != RequestConsent::IncomingPending {
            return Err(invalid());
        }
        if projection.pending_acceptance.is_none() {
            let publication = transcript::verify_received_signed_request(
                DirectRequestKind::Publish,
                &projection.publication,
                &projection.sender_public_key,
            )
            .map_err(|_| invalid())?;
            let p = publication.body();
            let prior = p["next"].clone();
            let mut next = prior.clone();
            next["stateVersion"] = json!(prior["stateVersion"]
                .as_u64()
                .ok_or_else(invalid)?
                .checked_add(1)
                .ok_or_else(invalid)?);
            let public = self
                .mls_context()
                .identity_public_key(format!("{owner}#{device}").into_bytes())?;
            let transition = Uuid::new_v4().to_string();
            let body = json!({"$type":"blue.catbird.chat.defs#directRequestAcceptanceBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0","protocolVersion":"2","actorDid":owner,"actorDeviceId":device,"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"authGeneration":self.credentials().get_auth_generation(&owner).await?.ok_or_else(invalid)?,"requestId":p["requestId"],"transitionId":transition,"prior":prior,"next":next,"invitationProvenance":{"invitationTransitionId":p["requestId"],"invitedByDid":p["actorDid"],"invitedByDeviceId":p["actorDeviceId"]},"idempotencyKey":transition,"signedAt":now()});
            projection.pending_acceptance = Some(
                self.sign_direct_request_body(DirectRequestKind::Accept, body)
                    .await?,
            );
            let bytes = projection.encode()?;
            if !self
                .mls_context()
                .compare_exchange_direct_request_projection(conversation_id, Some(&raw), &bytes)?
            {
                return Err(invalid());
            }
            raw = bytes;
        }
        let wrapper = projection.pending_acceptance.as_ref().ok_or_else(invalid)?;
        let signer = self
            .mls_context()
            .identity_public_key(format!("{owner}#{device}").into_bytes())?;
        let pending =
            transcript::verify_signed_request(DirectRequestKind::Accept, wrapper, &signer)
                .map_err(|_| invalid())?;
        let publication = transcript::verify_received_signed_request(
            DirectRequestKind::Publish,
            &projection.publication,
            &projection.sender_public_key,
        )
        .map_err(|_| invalid())?;
        if pending.actor_did() != Some(owner.as_str())
            || pending.actor_device_id() != Some(device.as_str())
            || pending.body()["prior"] != publication.body()["next"]
            || pending.body()["requestId"] != publication.body()["requestId"]
        {
            return Err(invalid());
        }
        let mut wire = b"{\"directRequest\":".to_vec();
        wire.extend(wrapper);
        wire.push(b'}');
        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation: CanonicalOperation::AcceptConversation,
                method: "POST".into(),
                path: CanonicalOperation::AcceptConversation.path().into(),
                body: Some(wire),
            })
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into(),
            });
        }
        crate::chat_v2::transcript::decode_strict_json(&response.body).map_err(|_| invalid())?;
        let result: Value = serde_json::from_slice(&response.body).map_err(|_| invalid())?;
        let proof = serde_json::to_vec(&result["acceptanceProof"]).map_err(|_| invalid())?;
        let public = self
            .mls_context()
            .identity_public_key(format!("{owner}#{device}").into_bytes())?;
        let proof_value: Value = serde_json::from_slice(&proof).map_err(|_| invalid())?;
        let method = proof_value["receipt"]["body"]["keyId"]
            .as_str()
            .ok_or_else(invalid)?;
        if transcript::resolve_direct_request_receipt_key(
            &projection.trusted_authority_document,
            method,
        )
        .is_err()
        {
            let doc = self
                .credentials()
                .direct_request_receipt_authority_document()
                .await?
                .ok_or_else(invalid)?;
            transcript::resolve_direct_request_receipt_key(&doc, method).map_err(|_| invalid())?;
            projection.trusted_authority_document =
                intent::merge_trusted_documents(&projection.trusted_authority_document, &doc)?;
        }
        let authority_key = transcript::resolve_direct_request_receipt_key(
            &projection.trusted_authority_document,
            method,
        )
        .map_err(|_| invalid())?;
        let canonical_proof = transcript::verify_received_direct_request_acceptance_proof(
            &proof,
            &authority_key,
            &public,
        )
        .map_err(|_| invalid())?;
        projection.acceptance_proof =
            Some(serde_json::to_vec(&canonical_proof).map_err(|_| invalid())?);
        projection.recipient_public_key = Some(public);
        let accepted = projection.view(&owner, &device)?;
        if accepted.consent != RequestConsent::Accepted {
            return Err(invalid());
        }
        projection.pending_acceptance = None;
        let bytes = projection.encode()?;
        if !self
            .mls_context()
            .compare_exchange_direct_request_projection(conversation_id, Some(&raw), &bytes)?
        {
            return Err(invalid());
        }
        Ok(Some(result))
    }
}
