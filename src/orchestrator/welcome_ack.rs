//! Exact Welcome acceptance and durable, entry-less acknowledgement retries.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    CanonicalOperation, CredentialStore, MLSAPIClient, MLSOrchestrator, MLSStorageBackend,
    MlsCryptoContext, OrchestratorError, PreparedRequest, Result,
};

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native;

fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(format!("Welcome delivery: {message}"))
}
pub(crate) fn bytes(value: &Value) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .or_else(|| value["$bytes"].as_str())
        .ok_or_else(|| invalid("missing bytes"))?;
    STANDARD
        .decode(encoded)
        .map_err(|_| invalid("invalid base64"))
}
fn uuid(value: &Value) -> Result<&str> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid("missing identifier"))?;
    crate::chat_v2::ids::uuid::ConversationId::parse(value)
        .map_err(|_| invalid("invalid identifier"))?;
    Ok(value)
}

/// The original device-addressed inventory object, retained before any ACK.
/// Coordinates always refer to the Welcome's Add, never to a later head.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WelcomeDelivery {
    pub envelope: Value,
}
impl WelcomeDelivery {
    pub fn from_value(envelope: Value) -> Result<Self> {
        let result = Self { envelope };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        let e = &self.envelope;
        let cid = uuid(&e["conversationId"])?;
        uuid(&e["welcomeId"])?;
        uuid(&e["recipientDeviceId"])?;
        let did = e["recipientDid"]
            .as_str()
            .ok_or_else(|| invalid("missing recipient"))?;
        crate::chat_v2::ids::did::BareDid::parse(did).map_err(|_| invalid("invalid recipient"))?;
        if !e["transitionSeq"]
            .as_u64()
            .is_some_and(|seq| seq > 0 && seq <= 9_007_199_254_740_991)
            || e["status"] != "pending"
        {
            return Err(invalid("invalid transition or disposition"));
        }
        let coordinate = super::lifecycle::lifecycle_coordinates(&e["coordinates"], cid)?;
        if coordinate["lifecycle"] != "active" {
            return Err(invalid("Welcome coordinate is inactive"));
        }
        let opaque = bytes(&e["opaqueWelcome"])?;
        if !(8..=1_048_576).contains(&opaque.len())
            || bytes(&e["sha256"])? != Sha256::digest(&opaque).as_slice()
        {
            return Err(invalid("Welcome hash mismatch"));
        }
        uuid(&e["provenance"]["recoveryRequestId"])?;
        if bytes(&e["provenance"]["keyPackageRef"])?.len() != 32 {
            return Err(invalid("invalid KeyPackage provenance"));
        }
        let expiry = e["expiresAt"]
            .as_str()
            .ok_or_else(|| invalid("missing expiry"))?;
        let parsed =
            chrono::DateTime::parse_from_rfc3339(expiry).map_err(|_| invalid("invalid expiry"))?;
        if parsed.to_rfc3339_opts(chrono::SecondsFormat::Millis, true) != expiry {
            return Err(invalid("noncanonical expiry"));
        }
        Ok(())
    }
    pub fn welcome_id(&self) -> &str {
        self.envelope["welcomeId"].as_str().unwrap()
    }
    pub fn conversation_id(&self) -> &str {
        self.envelope["conversationId"].as_str().unwrap()
    }
    pub fn recipient_identity(&self) -> String {
        format!(
            "{}#{}",
            self.envelope["recipientDid"].as_str().unwrap(),
            self.envelope["recipientDeviceId"].as_str().unwrap()
        )
    }
    pub fn group_id(&self) -> Result<Vec<u8>> {
        bytes(&self.envelope["coordinates"]["groupId"])
    }
    pub fn epoch(&self) -> u64 {
        self.envelope["coordinates"]["epoch"].as_u64().unwrap()
    }
}

/// This row is created only by the native transaction that verifies/imports
/// the exact Welcome. Ordinary journal updates cannot create a receipt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WelcomeAcceptance {
    pub delivery: WelcomeDelivery,
    pub projection_completed: bool,
    pub request_body: Option<Vec<u8>>,
    pub terminal_response: Option<Value>,
}
impl WelcomeAcceptance {
    pub(crate) fn validate(&self) -> Result<()> {
        self.delivery.validate()?;
        if let Some(raw) = &self.request_body {
            let wrapper: Value =
                serde_json::from_slice(raw).map_err(|_| invalid("corrupt ACK journal"))?;
            let body = &wrapper["signedRequest"]["body"];
            let e = &self.delivery.envelope;
            if !self.projection_completed
                || body["welcomeId"] != e["welcomeId"]
                || body["transitionSeq"] != e["transitionSeq"]
                || super::lifecycle::lifecycle_coordinates(
                    &body["coordinates"],
                    self.delivery.conversation_id(),
                )? != super::lifecycle::lifecycle_coordinates(
                    &e["coordinates"],
                    self.delivery.conversation_id(),
                )?
                || body["actorDid"] != e["recipientDid"]
                || body["actorDeviceId"] != e["recipientDeviceId"]
                || body["$type"] != "blue.catbird.chat.defs#welcomeAcknowledgementBody"
                || body["signatureDomain"] != "CATBIRD-CHAT-WELCOME-ACK\0"
                || bytes(&wrapper["signedRequest"]["signature"])?.len() != 64
            {
                return Err(invalid("ACK no longer matches its native receipt"));
            }
            uuid(&body["idempotencyKey"])?;
        } else if self.terminal_response.is_some() {
            return Err(invalid("terminal ACK has no request"));
        }
        if let Some(response) = &self.terminal_response {
            let body = &response["body"];
            if !(response["status"] == 200
                && body["status"] == "acknowledged"
                && body["acknowledgedAt"]
                    .as_str()
                    .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok()))
                && !(response["status"] == 400
                    && matches!(
                        body["error"].as_str(),
                        Some("WelcomeSuperseded" | "WelcomeExpired")
                    ))
            {
                return Err(invalid("unproven terminal acknowledgement"));
            }
        }
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
    async fn welcome_read(
        &self,
        operation: CanonicalOperation,
        parameters: Vec<(&str, String)>,
    ) -> Result<Value> {
        let route = super::canonical_transport::canonical_route(operation);
        let encode = |value: &str| {
            value
                .bytes()
                .map(|byte| {
                    if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                        (byte as char).to_string()
                    } else {
                        format!("%{byte:02X}")
                    }
                })
                .collect::<String>()
        };
        let query = parameters
            .into_iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation,
                path: format!("{}?{}", route.path, query),
                method: "GET".into(),
                body: None,
            })
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        serde_json::from_slice(&response.body).map_err(|_| invalid("invalid inventory response"))
    }

    pub(crate) async fn fetch_welcome_delivery(&self, cid: &str) -> Result<WelcomeDelivery> {
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let inventory = self
            .welcome_read(
                CanonicalOperation::GetConversations,
                vec![("actorDeviceId", device.clone()), ("limit", "1".into())],
            )
            .await?;
        let session = inventory["inventorySessionId"]
            .as_str()
            .ok_or_else(|| invalid("missing inventory session"))?;
        let fence = inventory["snapshotEventCursor"]
            .as_str()
            .ok_or_else(|| invalid("missing inventory fence"))?;
        let mut pagination =
            super::pagination::PaginationGuard::for_conversations("Welcome delivery");
        let mut cursor = None;
        let mut latest: Option<WelcomeDelivery> = None;
        loop {
            let mut params = vec![
                ("actorDeviceId", device.clone()),
                ("inventorySessionId", session.into()),
                ("limit", "100".into()),
            ];
            if let Some(value) = cursor {
                params.push(("pageCursor", value));
            }
            let page = self
                .welcome_read(CanonicalOperation::GetPendingWelcomes, params)
                .await?;
            if page["inventorySessionId"].as_str() != Some(session)
                || page["snapshotEventCursor"].as_str() != Some(fence)
            {
                return Err(invalid("inventory session changed"));
            }
            let items = page["items"]
                .as_array()
                .ok_or_else(|| invalid("missing Welcome inventory"))?;
            let next = page["nextPageCursor"].as_str().map(str::to_owned);
            if page["hasMore"].as_bool() != Some(next.is_some()) {
                return Err(invalid("inconsistent pagination"));
            }
            pagination.observe_page(items.len(), next.as_deref())?;
            for item in items {
                if item["conversationId"] != cid {
                    continue;
                }
                let delivery = WelcomeDelivery::from_value(item.clone())?;
                if item["recipientDid"] != did || item["recipientDeviceId"] != device {
                    return Err(invalid("wrong recipient"));
                }
                if latest.as_ref().is_none_or(|old| {
                    old.envelope["transitionSeq"].as_u64() < item["transitionSeq"].as_u64()
                }) {
                    latest = Some(delivery);
                }
            }
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        latest.ok_or_else(|| OrchestratorError::ServerError {
            status: 404,
            body: "Welcome not found".into(),
        })
    }

    pub(crate) async fn delivery_for_welcome_bytes(
        &self,
        cid: &str,
        welcome: &[u8],
    ) -> Result<WelcomeDelivery> {
        let identity = self.require_scoped_identity().await?;
        let digest = Sha256::digest(welcome);
        for receipt in self.mls_context().list_welcome_acceptances()? {
            if receipt.delivery.conversation_id() == cid
                && receipt.delivery.recipient_identity() == identity
                && bytes(&receipt.delivery.envelope["sha256"])? == digest.as_slice()
            {
                return Ok(receipt.delivery);
            }
        }
        let delivery = self.fetch_welcome_delivery(cid).await?;
        if bytes(&delivery.envelope["opaqueWelcome"])? != welcome {
            return Err(invalid("fetched delivery does not match supplied Welcome"));
        }
        Ok(delivery)
    }

    /// Called only after durable native and application projections have
    /// completed the verified Welcome/catch-up path under the transition lock.
    pub(crate) async fn complete_welcome_acknowledgements_locked(&self, cid: &str) -> Result<()> {
        let identity = self.require_scoped_identity().await?;
        let resolved = self.resolve_conversation_context(cid).await?;
        self.mls_context().ensure_storage_durable()?;
        for mut receipt in self.mls_context().list_welcome_acceptances()? {
            if receipt.delivery.conversation_id() != cid
                || receipt.delivery.recipient_identity() != identity
                || hex::encode(receipt.delivery.group_id()?) != resolved.group_id
                || receipt.terminal_response.is_some()
            {
                continue;
            }
            if !receipt.projection_completed {
                receipt.projection_completed = true;
                self.mls_context().update_welcome_acceptance(&receipt)?;
            }
        }
        self.drain_welcome_acknowledgements_locked(Some(cid))
            .await
            .map(|_| ())
    }

    async fn drain_welcome_acknowledgements_locked(&self, cid: Option<&str>) -> Result<usize> {
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let identity = self.require_scoped_identity().await?;
        let mut completed = 0;
        for mut receipt in self.mls_context().list_welcome_acceptances()? {
            let delivery = &receipt.delivery;
            if cid.is_some_and(|cid| cid != delivery.conversation_id())
                || delivery.recipient_identity() != identity
                || !receipt.projection_completed
                || receipt.terminal_response.is_some()
            {
                continue;
            }
            if receipt.request_body.is_none() {
                let auth_generation = self
                    .credentials()
                    .get_auth_generation(&did)
                    .await?
                    .filter(|value| *value >= 1)
                    .ok_or_else(|| {
                        OrchestratorError::Credential("missing auth generation".into())
                    })?;
                let public_key = self
                    .mls_context()
                    .identity_public_key(identity.as_bytes().to_vec())?;
                let body = json!({
                    "$type":"blue.catbird.chat.defs#welcomeAcknowledgementBody", "signatureDomain":"CATBIRD-CHAT-WELCOME-ACK\0",
                    "welcomeId":delivery.envelope["welcomeId"], "transitionSeq":delivery.envelope["transitionSeq"],
                    "coordinates":delivery.envelope["coordinates"], "actorDid":did, "actorDeviceId":device,
                    "keyId":super::canonical_transport::derive_key_id(&public_key), "authGeneration":auth_generation,
                    "idempotencyKey":uuid::Uuid::new_v4().to_string(),
                    "signedAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),
                });
                let request = self
                    .prepare_clean_chat_signed_request(
                        super::CleanChatSigningContext {
                            actor_did: did.clone(),
                            device_id: device.clone(),
                            auth_generation: Some(auth_generation),
                        },
                        CanonicalOperation::AcknowledgeWelcome,
                        serde_json::to_vec(&body).map_err(|_| invalid("ACK encoding failed"))?,
                    )
                    .await
                    .map_err(|error| OrchestratorError::Api(error.to_string()))?;
                receipt.request_body =
                    Some(request.body.ok_or_else(|| invalid("ACK body missing"))?);
                // Exact body/signature/operation id are durable before the
                // first possible transmission. No later retry re-signs it.
                self.mls_context().update_welcome_acceptance(&receipt)?;
            }
            let response = self
                .api_client()
                .submit_prepared_request(PreparedRequest {
                    operation: CanonicalOperation::AcknowledgeWelcome,
                    path: super::canonical_transport::canonical_route(
                        CanonicalOperation::AcknowledgeWelcome,
                    )
                    .path
                    .into(),
                    method: "POST".into(),
                    body: receipt.request_body.clone(),
                })
                .await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(welcome_id=receipt.delivery.welcome_id(), %error, "Welcome acknowledgement remains queued");
                    continue;
                }
            };
            let parsed: Value = match serde_json::from_slice(&response.body) {
                Ok(value) => value,
                Err(_) => {
                    tracing::warn!(
                        welcome_id = receipt.delivery.welcome_id(),
                        "Invalid Welcome acknowledgement response; retaining request"
                    );
                    continue;
                }
            };
            let acknowledged = response.status == 200
                && parsed["status"] == "acknowledged"
                && parsed["acknowledgedAt"]
                    .as_str()
                    .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok());
            let terminal = response.status == 400
                && matches!(
                    parsed["error"].as_str(),
                    Some("WelcomeSuperseded" | "WelcomeExpired")
                );
            if acknowledged || terminal {
                receipt.terminal_response = Some(json!({"status":response.status,"body":parsed}));
                self.mls_context().update_welcome_acceptance(&receipt)?;
                completed += 1;
            } else {
                // An auth error, arbitrary 4xx, or expired signing window says
                // nothing about a previous transmission's acceptance.
                tracing::warn!(
                    welcome_id = receipt.delivery.welcome_id(),
                    status = response.status,
                    "Welcome acknowledgement remains queued"
                );
            }
        }
        Ok(completed)
    }

    /// Independent from membership recovery: healthy and terminal devices can
    /// retry a receipt-bound historical ACK without reprocessing any Welcome.
    pub async fn retry_pending_welcome_acknowledgements(&self) -> Result<usize> {
        self.check_shutdown().await?;
        let identity = self.require_scoped_identity().await?;
        let receipts = self.mls_context().list_welcome_acceptances()?;
        let mut conversations = std::collections::BTreeSet::new();
        for receipt in receipts {
            if receipt.delivery.recipient_identity() != identity
                || receipt.terminal_response.is_some()
            {
                continue;
            }
            let cid = receipt.delivery.conversation_id();
            conversations.insert(cid.to_owned());
            if !receipt.projection_completed {
                // The original receipt authorizes resuming local publication,
                // but fresh current membership is still required to restore
                // sends. A terminal ACK never re-adds or removes membership.
                if let Err(error) = self
                    .join_or_rejoin_from_available_welcome(
                        cid,
                        bytes(&receipt.delivery.envelope["opaqueWelcome"])?,
                    )
                    .await
                {
                    tracing::warn!(conversation_id=cid, %error, "Verified Welcome publication still needs completion");
                }
            }
        }
        let mut completed = 0;
        for cid in conversations {
            let lock = self.rejoin_lock(&cid).await;
            let _guard = lock.lock().await;
            completed += self
                .drain_welcome_acknowledgements_locked(Some(&cid))
                .await?;
        }
        Ok(completed)
    }

    pub(crate) async fn pending_welcome_publications(
        &self,
    ) -> Result<std::collections::HashSet<String>> {
        let identity = self.require_scoped_identity().await?;
        let mut pending = std::collections::HashSet::new();
        for receipt in self.mls_context().list_welcome_acceptances()? {
            if receipt.projection_completed || receipt.delivery.recipient_identity() != identity {
                continue;
            }
            let cid = receipt.delivery.conversation_id();
            match self.resolve_conversation_context(cid).await {
                Ok(context) if context.group_id == hex::encode(receipt.delivery.group_id()?) => {
                    pending.insert(cid.to_owned());
                }
                Err(OrchestratorError::ConversationNotFound(_)) => {
                    pending.insert(cid.to_owned());
                }
                Err(error) => return Err(error),
                _ => {}
            }
        }
        Ok(pending)
    }

    pub(crate) async fn retry_welcome_acknowledgements_for_conversation(
        &self,
        cid: &str,
    ) -> Result<usize> {
        let lock = self.rejoin_lock(cid).await;
        let _guard = lock.lock().await;
        self.drain_welcome_acknowledgements_locked(Some(cid)).await
    }
}
