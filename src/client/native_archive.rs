use std::future::Future;

// Native adapters for the shared, verified Labyrinth session. Included in native_client.

#[cfg(feature = "labyrinth")]
struct NativeArchiveClock(crate::sim_hooks::SimClientHooks);

#[cfg(feature = "labyrinth")]
impl labyrinth::client::Clock for NativeArchiveClock {
    fn now_ms(&self) -> u64 { self.0.now_ms().max(0) as u64 }
}

#[cfg(feature = "labyrinth")]
struct NativeArchiveSigner(SignatureKeyPair);

#[cfg(feature = "labyrinth")]
impl crate::labyrinth::ChatKeySigner for NativeArchiveSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.public().try_into().expect("enrolled Ed25519 key checked at construction")
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        self.0.sign(message).map_err(|e| format!("archive signer: {e:?}"))?
            .try_into().map_err(|_| "archive signature is not 64 bytes".into())
    }
}

#[cfg(feature = "labyrinth")]
struct NativeArchiveVault {
    db: Arc<MlsAccountDb>,
    namespace: &'static str,
    hooks: crate::sim_hooks::SimClientHooks,
}

#[cfg(feature = "labyrinth")]
impl crate::labyrinth::StateVault for NativeArchiveVault {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.db.read_tx(|tx| tx.get_labyrinth_state(&format!("{}:{key}", self.namespace)))
    }
    fn compare_exchange(&self, key: &str, expected: Option<&[u8]>, next: &[u8]) -> Result<bool, MLSError> {
        self.db.write_tx(|tx| {
            let key = format!("{}:{key}", self.namespace);
            let current = Zeroizing::new(tx.get_labyrinth_state(&key)?);
            if current.as_deref() != expected { return Ok(false); }
            tx.put_labyrinth_state(&key, next, self.hooks.now_ms())?;
            Ok(true)
        })
    }
    fn delete(&self, key: &str) -> Result<(), MLSError> {
        self.db.write_tx(|tx| {
            tx.conn().execute("DELETE FROM labyrinth_state WHERE state_key = ?1", [format!("{}:{key}", self.namespace)])
                .map_err(|e| MLSError::Internal(format!("delete archive state: {e}")))?;
            Ok(())
        })
    }
}

#[cfg(feature = "labyrinth")]
struct NativeArchiveGateway {
    config: CatbirdMlsClientConfig,
    db: Arc<MlsAccountDb>,
    transport: Arc<dyn PlatformTransport>,
    signer: Arc<NativeArchiveSigner>,
    hooks: crate::sim_hooks::SimClientHooks,
}

#[cfg(feature = "labyrinth")]
impl NativeArchiveGateway {
    fn execute(&self, base: &str, method: String, path: String, headers: Vec<(String, String)>, body: Option<Vec<u8>>) -> Result<PlatformHttpResponse, String> {
        if !self.db.is_open() { return Err("native_archive_context_closed".into()); }
        let mut headers: Vec<PlatformHttpHeader> = headers.into_iter().map(|(name, value)| PlatformHttpHeader { name, value }).collect();
        if body.is_some() && !headers.iter().any(|h| h.name.eq_ignore_ascii_case("content-type")) {
            headers.push(PlatformHttpHeader { name: "content-type".into(), value: "application/json".into() });
        }
        let response = self.transport.execute_http(PlatformHttpRequest {
            method, url: format!("{}{path}", base.trim_end_matches('/')), headers, body,
        }).map_err(|e| e.to_string())?;
        if !self.db.is_open() { return Err("native_archive_context_closed".into()); }
        Ok(response)
    }
    fn response(response: PlatformHttpResponse) -> crate::orchestrator::canonical_transport::GatewayResponse {
        crate::orchestrator::canonical_transport::GatewayResponse {
            status: response.status,
            content_type: response.header("content-type").map(str::to_owned),
            body: response.body,
        }
    }
}

#[cfg(feature = "labyrinth")]
#[async_trait::async_trait]
impl crate::labyrinth::LabyrinthGateway for NativeArchiveGateway {
    async fn submit_labyrinth(&self, request: crate::labyrinth::LabyrinthRequest) -> Result<crate::orchestrator::canonical_transport::GatewayResponse, String> {
        self.execute(&self.config.home_ds_endpoint, request.method, request.path, request.headers, request.body).map(Self::response)
    }
    async fn submit_canonical(&self, request: crate::orchestrator::canonical_transport::PreparedRequest) -> Result<crate::orchestrator::canonical_transport::GatewayResponse, String> {
        // These directory requests contain only canonical DID/UUID coordinates.
        // Sort the already-percent-encoded pairs exactly like chat read signing.
        let mut query: Vec<&str> = request.path.split_once('?').map(|(_, q)| q.split('&').collect()).unwrap_or_default();
        query.sort_unstable();
        let query = query.join("&");
        let headers = super::chat_wire::build_chat_read_headers(
            request.operation.nsid(), &query, &self.config.account_did,
            &self.config.device_id, &self.signer.0, self.hooks.now_ms(),
        ).map_err(|e| e.to_string())?.into_iter().map(|h| (h.name, h.value)).collect();
        self.execute(&self.config.home_ds_endpoint, request.method, request.path, headers, request.body).map(Self::response)
    }
    async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
        let path = format!("/xrpc/com.atproto.identity.resolveDid?did={}", super::chat_wire::urlencode_form_component(did));
        let response = self.execute(&self.config.pds_endpoint, "GET".into(), path, vec![], None)?;
        if response.status == 200 {
            return super::chat_wire::extract_did_doc_from_resolve_response(&response.body).map(Some).map_err(|e| e.to_string());
        }
        let url = crate::labyrinth::transport::did_document_url(did)?;
        if !self.db.is_open() { return Err("native_archive_context_closed".into()); }
        let response = self.transport.execute_http(PlatformHttpRequest { method: "GET".into(), url, headers: vec![], body: None }).map_err(|e| e.to_string())?;
        if !self.db.is_open() { return Err("native_archive_context_closed".into()); }
        if response.status == 404 { return Ok(None); }
        if response.status != 200 { return Err(format!("resolve archive DID returned HTTP {}", response.status)); }
        super::chat_wire::extract_did_doc_from_resolve_response(&response.body).map(Some).map_err(|e| e.to_string())
    }
}

#[cfg(feature = "labyrinth")]
#[async_trait::async_trait]
impl crate::labyrinth::LabyrinthSpaceGateway for NativeArchiveGateway {
    async fn submit_space(&self, request: crate::labyrinth::LabyrinthSpaceRequest) -> Result<crate::orchestrator::canonical_transport::GatewayResponse, String> {
        let response = self.submit_space_with_headers(request).await?;
        Ok(crate::orchestrator::canonical_transport::GatewayResponse { status: response.status, content_type: response.content_type, body: response.body })
    }
    async fn submit_space_with_headers(&self, request: crate::labyrinth::LabyrinthSpaceRequest) -> Result<crate::labyrinth::LabyrinthSpaceResponse, String> {
        self.execute_authenticated_space(request).await
    }
}

#[cfg(feature = "labyrinth")]
impl NativeArchiveGateway {
    fn pds_json(&self, base: &str, method: &str, path: String, body: Option<Vec<u8>>) -> labyrinth::Result<serde_json::Value> {
        let bytes = crate::labyrinth::transport::decode_response_bounded(
            self.execute(base, method.into(), path, vec![], body).map(Self::response),
            crate::labyrinth::transport::MAX_LABYRINTH_XRPC_RESPONSE_BYTES,
        ).map_err(|error| {
            if error.error.as_deref() == Some("InvalidSwap") {
                labyrinth::Error::Conflict
            } else if matches!(error.status, 400 | 404) && error.error.as_deref() == Some("RecordNotFound") {
                labyrinth::Error::NotFound("record")
            } else {
                crate::labyrinth::transport::map_xrpc_error(error)
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|_| labyrinth::Error::Malformed("PDS repository response"))
    }

    async fn account_pds(&self, did: &str) -> labyrinth::Result<String> {
        if did == self.config.account_did { return Ok(self.config.pds_endpoint.clone()); }
        let doc = crate::labyrinth::LabyrinthGateway::resolve_did_document(self, did).await
            .map_err(labyrinth::Error::Backend)?.ok_or(labyrinth::Error::Unattested)?;
        super::chat_wire::extract_pds_endpoint_from_did_doc(&doc).ok_or(labyrinth::Error::Unattested)
    }
}

#[cfg(feature = "labyrinth")]
#[async_trait::async_trait]
impl labyrinth::store::pds::PublicRepoBackend for NativeArchiveGateway {
    async fn put_mailbox_keys(&self, did: &str, rkey: &str, record: &[u8], swap_cid: Option<&str>) -> labyrinth::Result<String> {
        if did != self.config.account_did { return Err(labyrinth::Error::Forbidden); }
        crate::labyrinth::transport::enforce_pds_record_cap(record).map_err(labyrinth::Error::Backend)?;
        let record: serde_json::Value = serde_json::from_slice(record).map_err(|_| labyrinth::Error::Malformed("mailboxKeys JSON"))?;
        let mut body = serde_json::json!({
            "repo": did, "collection": labyrinth::records::nsid::MAILBOX_KEYS, "rkey": rkey, "record": record,
        });
        if let Some(cid) = swap_cid { body["swapRecord"] = cid.into(); }
        let response = self.pds_json(&self.config.pds_endpoint, "POST", "/xrpc/com.atproto.repo.putRecord".into(),
            Some(serde_json::to_vec(&body).map_err(|e| labyrinth::Error::Backend(e.to_string()))?))?;
        response["cid"].as_str().filter(|cid| !cid.is_empty()).map(str::to_owned)
            .ok_or(labyrinth::Error::Malformed("putRecord missing CID"))
    }

    async fn get_mailbox_keys(&self, did: &str, rkey: &str) -> labyrinth::Result<Option<(Vec<u8>, String)>> {
        let base = self.account_pds(did).await?;
        let path = format!("/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
            super::chat_wire::urlencode_form_component(did), labyrinth::records::nsid::MAILBOX_KEYS,
            super::chat_wire::urlencode_form_component(rkey));
        let response = match self.pds_json(&base, "GET", path, None) {
            Ok(value) => value,
            Err(labyrinth::Error::NotFound("record")) => return Ok(None),
            Err(error) => return Err(error),
        };
        let cid = response["cid"].as_str().filter(|cid| !cid.is_empty())
            .ok_or(labyrinth::Error::Malformed("getRecord missing CID"))?.to_owned();
        let value = response.get("value").ok_or(labyrinth::Error::Malformed("getRecord missing value"))?;
        let bytes = serde_json::to_vec(value).map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
        crate::labyrinth::transport::enforce_pds_record_cap(&bytes).map_err(labyrinth::Error::Backend)?;
        Ok(Some((bytes, cid)))
    }

    async fn delete_all_mailbox_keys(&self, did: &str) -> labyrinth::Result<()> {
        if did != self.config.account_did { return Err(labyrinth::Error::Forbidden); }
        let mut cursor: Option<String> = None;
        let mut seen = std::collections::BTreeSet::new();
        let prefix = format!("at://{did}/{}/", labyrinth::records::nsid::MAILBOX_KEYS);
        loop {
            let mut path = format!("/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit=100",
                super::chat_wire::urlencode_form_component(did), labyrinth::records::nsid::MAILBOX_KEYS);
            if let Some(cursor) = &cursor { path.push_str(&format!("&cursor={}", super::chat_wire::urlencode_form_component(cursor))); }
            let page = self.pds_json(&self.config.pds_endpoint, "GET", path, None)?;
            let records = page["records"].as_array().ok_or(labyrinth::Error::Malformed("listRecords missing records"))?;
            for record in records {
                let uri = record["uri"].as_str().ok_or(labyrinth::Error::Malformed("mailboxKeys URI"))?;
                let rkey = uri.strip_prefix(&prefix).filter(|key| !key.is_empty() && !key.contains('/'))
                    .ok_or(labyrinth::Error::Malformed("mailboxKeys URI binding"))?;
                let cid = record["cid"].as_str().ok_or(labyrinth::Error::Malformed("mailboxKeys CID"))?;
                self.pds_json(&self.config.pds_endpoint, "POST", "/xrpc/com.atproto.repo.deleteRecord".into(),
                    Some(serde_json::to_vec(&serde_json::json!({
                        "repo": did, "collection": labyrinth::records::nsid::MAILBOX_KEYS, "rkey": rkey, "swapRecord": cid,
                    })).map_err(|e| labyrinth::Error::Backend(e.to_string()))?))?;
            }
            cursor = page["cursor"].as_str().map(str::to_owned);
            match &cursor {
                None => return Ok(()),
                Some(next) if !seen.insert(next.clone()) => return Err(labyrinth::Error::Malformed("repeated mailboxKeys cursor")),
                Some(_) => {}
            }
        }
    }
}

#[cfg(feature = "labyrinth")]
fn native_archive_error(error: crate::orchestrator::error::OrchestratorError) -> MLSError {
    if error.to_string().contains("native_archive_context_closed") {
        return MLSError::ContextClosed;
    }
    match error {
        crate::orchestrator::error::OrchestratorError::Mls(MLSError::ContextClosed) => MLSError::ContextClosed,
        crate::orchestrator::error::OrchestratorError::InvalidInput(m) => MLSError::invalid_input(m),
        other => MLSError::Internal(other.to_string()),
    }
}

#[cfg(feature = "labyrinth")]
struct ArchiveThreadWaker(std::thread::Thread);

#[cfg(feature = "labyrinth")]
impl std::task::Wake for ArchiveThreadWaker {
    fn wake(self: Arc<Self>) { self.0.unpark(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.unpark(); }
}

#[cfg(feature = "labyrinth")]
fn block_on_sync<F: Future>(future: F) -> F::Output {
    let waker = std::task::Waker::from(Arc::new(ArchiveThreadWaker(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(out) => return out,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}

#[cfg(feature = "labyrinth")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct NativeArchiveEvidence {
    pub(crate) message_id: String,
    pub(crate) conversation_id: String,
    pub(crate) labyrinth_frame_json: String,
    pub(crate) frame_nonce_b64: Option<String>,
    pub(crate) sequencer_receipt_json: Option<String>,
    pub(crate) created_at_ms: i64,
}

#[cfg(feature = "labyrinth")]
impl NativeArchiveEvidence {
    fn from_queue(item: &QueuedLabyrinthArchivePayload) -> Self {
        Self {
            message_id: item.message_id.clone(), conversation_id: item.conversation_id.clone(),
            labyrinth_frame_json: item.labyrinth_frame_json.clone(), frame_nonce_b64: item.frame_nonce_b64.clone(),
            sequencer_receipt_json: item.sequencer_receipt_json.clone(), created_at_ms: item.created_at_ms,
        }
    }
}

#[cfg(feature = "labyrinth")]
type RestoreCopy = (MessageRow, NativeArchiveEvidence, super::chat_wire::StoredArchivedReceipt);

/// Verified archive copies as restorable rows, grouped by message id with equal rows merged.
/// Labyrinth never returns a witness copy that contradicts an accepted one (ruling 3); what can
/// still differ under one id are two members' own copies.
#[cfg(feature = "labyrinth")]
fn native_restore_copies(conversation_id: &str, self_did: &str, messages: Vec<labyrinth::client::LoadedMessage>)
    -> Result<std::collections::BTreeMap<String, Vec<RestoreCopy>>, MLSError> {
    let mut by_id: std::collections::BTreeMap<String, Vec<RestoreCopy>> = std::collections::BTreeMap::new();
    for message in messages {
        let archived = message.archived_receipt.as_ref().ok_or_else(|| MLSError::Cryptography("archive frame missing sequencer receipt".into()))?;
        let nonce = message.frame_nonce.ok_or_else(|| MLSError::Cryptography("archive frame missing blinded commitment nonce".into()))?;
        let receipt = &archived.signed.payload;
        let (sender_did, sender_device_id) = receipt.split_sender_device().map_err(|_| MLSError::Cryptography("archive sender device malformed".into()))?;
        if message.thread_id != conversation_id || receipt.conversation_id != conversation_id
            || message.sender.as_deref() != Some(sender_did) {
            return Err(MLSError::Cryptography("archive coordinates/attribution conflict".into()));
        }
        crate::orchestrator::MLSMessagePayload::decode(&message.frame).map_err(|e| MLSError::Cryptography(format!("invalid canonical archive frame: {e}")))?;
        let plaintext_json = String::from_utf8(message.frame).map_err(|e| MLSError::Cryptography(e.to_string()))?;
        let row = MessageRow {
            message_id: message.message_id.clone(), conversation_id: conversation_id.into(), group_id: receipt.group_id.clone(),
            epoch: i64::try_from(receipt.epoch).map_err(|_| MLSError::Cryptography("archive epoch overflow".into()))?,
            seq: i64::try_from(receipt.seq).map_err(|_| MLSError::Cryptography("archive seq overflow".into()))?,
            sender_did: sender_did.into(), sender_device_id: sender_device_id.into(), plaintext_json,
            created_at_ms: i64::try_from(message.timestamp).map_err(|_| MLSError::Cryptography("archive timestamp overflow".into()))?,
            is_own: sender_did == self_did,
        };
        let stored = super::chat_wire::StoredArchivedReceipt {
            sequencer_did: receipt.sequencer_did.clone(), conversation_id: receipt.conversation_id.clone(), group_id: receipt.group_id.clone(),
            epoch: receipt.epoch, sender_device_did_url: receipt.sender_device_did_url.clone(), entry_id: receipt.entry_id.clone(),
            archive_commitment: receipt.archive_commitment.to_vec(), seq: receipt.seq, issued_at_ms: receipt.issued_at_ms,
            key_id: archived.signed.key_id.clone(), signature: archived.signed.signature.to_vec(), generation: archived.generation,
        };
        let evidence = NativeArchiveEvidence {
            message_id: row.message_id.clone(), conversation_id: conversation_id.into(), labyrinth_frame_json: row.plaintext_json.clone(),
            frame_nonce_b64: Some(BASE64_STANDARD.encode(nonce)),
            sequencer_receipt_json: Some(serde_json::to_string(&stored).map_err(|e| MLSError::Internal(e.to_string()))?),
            created_at_ms: row.created_at_ms,
        };
        let copies = by_id.entry(row.message_id.clone()).or_default();
        if copies.iter().all(|(kept, _, _)| *kept != row) {
            copies.push((row, evidence, stored));
        }
    }
    Ok(by_id)
}

/// The copy restore may import for one message id: the one equal to the local message, else the
/// only copy. Members' disagreeing copies, or a copy disagreeing with local history, cannot be
/// resolved from the archive, so restore skips that id instead of failing.
#[cfg(feature = "labyrinth")]
fn select_restore_copy<'a>(copies: &'a [RestoreCopy], local: Option<&MessageRow>) -> Option<&'a RestoreCopy> {
    match local {
        Some(local) => copies.iter().find(|(row, _, _)| {
            local.conversation_id == row.conversation_id && local.seq == row.seq && local.epoch == row.epoch
                && local.sender_did == row.sender_did && local.sender_device_id == row.sender_device_id
                && canonical_labyrinth_frame_json(&local.plaintext_json) == row.plaintext_json
        }),
        None => match copies {
            [only] => Some(only),
            _ => None,
        },
    }
}

#[cfg(feature = "labyrinth")]
impl CatbirdMlsClient {
    fn native_archive_run<F: Future + Send>(&self, future: F) -> F::Output where F::Output: Send {
        let hooks = self.hooks.clone();
        hooks.with_labyrinth_rng(|| block_on_sync(future))
    }

    fn native_archive_deps(&self) -> Result<crate::labyrinth::SessionDeps, MLSError> {
        if self.is_handle_closed() { return Err(MLSError::ContextClosed); }
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let _: [u8; 32] = signer.public().try_into().map_err(|_| MLSError::Cryptography("archive chat key is not Ed25519".into()))?;
        let signer = Arc::new(NativeArchiveSigner(signer));
        let mut config = self.config.clone();
        config.account_did = self.normalized_did.clone();
        config.device_id = self.canonical_uuid_v4_device_id().ok_or_else(|| MLSError::invalid_input("archive requires UUIDv4 device_id"))?;
        let gateway = Arc::new(NativeArchiveGateway { config: config.clone(), db: self.db.clone(), transport: self.transport.clone(), signer: signer.clone(), hooks: self.hooks.clone() });
        let transport = Arc::new(crate::labyrinth::GatewayXrpcTransport::new(gateway.clone(), signer.clone(), self.normalized_did.clone(), config.device_id)
            .with_clock(Arc::new(NativeArchiveClock(self.hooks.clone()))));
        Ok(crate::labyrinth::SessionDeps {
            did: self.normalized_did.clone(), transport, signer,
            vault: Arc::new(NativeArchiveVault { db: self.db.clone(), namespace: "native.session", hooks: self.hooks.clone() }),
            placements: Arc::new(NativeArchiveVault { db: self.db.clone(), namespace: "native.placements", hooks: self.hooks.clone() }),
            pds: Some(gateway.clone()), space: Some(Arc::new(crate::labyrinth::SpaceXrpcTransport::new(gateway))),
            local_authority: None, sequencer_key: None, sequencer_receipt_key: None,
            default_conversation_authority_did: None,
        })
    }

    fn save_native_archive_status(&self, session: &crate::labyrinth::LabyrinthSession, recovery_code: bool) -> Result<LabyrinthBackupStatus, MLSError> {
        let status = self.db.write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| MLSError::InvalidState("archive status missing".into()))?;
            let mut status: LabyrinthBackupStatus = serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            status.epoch_seq = session.latest_epoch();
            status.has_recovery_code |= recovery_code;
            tx.put_labyrinth_state("status_json", &serde_json::to_vec(&status).map_err(|e| MLSError::Internal(e.to_string()))?, self.hooks.now_ms())?;
            Ok(status)
        })?;
        self.notify(PlatformChangeEvent::LabyrinthStatusChanged { epoch_seq: status.epoch_seq });
        Ok(status)
    }

    pub fn setup_recovery_code(&self) -> Result<String, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_setup_recovery_code(); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.enable().await.map_err(native_archive_error)?;
            let code = session.create_recovery_code().await.map_err(native_archive_error)?;
            self.save_native_archive_status(&session, true)?;
            Ok(code)
        })
    }

    pub fn restore_with_recovery_code(&self, code: &str) -> Result<LabyrinthBackupStatus, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_restore_with_recovery_code(code); }
        labyrinth::recovery_code::RecoveryCode::candidates(code).map_err(|_| MLSError::invalid_input("invalid 40-character Labyrinth recovery code"))?;
        // A recovery code enrolls storage keys, not an unverified chat device.
        // Register this new device normally before the library attests its binding.
        if self.db.read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?.is_none() {
            self.enroll_device(&super::REQUIRED_LABYRINTH_OAUTH_SCOPES.iter().map(|scope| (*scope).to_owned()).collect::<Vec<_>>())?;
        }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let session = self.native_archive_deps()?.restore_with_recovery_code(code).await.map_err(native_archive_error)?;
            self.save_native_archive_status(&session, true)
        })
    }

    fn pin_native_conversation(&self, conversation_id: &str) -> Result<(), MLSError> {
        self.db.write_tx(|tx| {
            let Some(conversation) = tx.get_conversation(conversation_id)? else { return Ok(()); };
            if conversation.sequencer_did.is_empty() { return Ok(()); }
            let generation = u64::try_from(conversation.generation)
                .map_err(|_| MLSError::Cryptography("negative conversation generation".into()))?;
            let space = conversation.space_uri.unwrap_or_else(|| format!(
                "at://{}/space/blue.catbird.labyrinth.conversation/{}-{}",
                conversation.sequencer_did, conversation_id, conversation.generation,
            ));
            let parsed = labyrinth::store::space::SpaceRef::parse(&space)
                .map_err(|e| MLSError::Cryptography(e.to_string()))?;
            if parsed.space_did != conversation.sequencer_did {
                return Err(MLSError::Cryptography("conversation Space authority differs from pinned sequencer".into()));
            }
            let key = format!("native.placements:{}", crate::labyrinth::space::thread_placement_key(&self.normalized_did));
            let mut placements: std::collections::BTreeMap<String, crate::labyrinth::space::ThreadPlacement> =
                tx.get_labyrinth_state(&key)?.map(|raw| serde_json::from_slice(&raw))
                    .transpose().map_err(|e| MLSError::Cryptography(format!("invalid archive Space pins: {e}")))?
                    .unwrap_or_default();
            if placements.get(conversation_id).is_some_and(|pin| pin.space.as_deref() == Some(space.as_str()) && pin.generation == generation) {
                return Ok(());
            }
            placements.insert(conversation_id.to_owned(), crate::labyrinth::space::ThreadPlacement {
                space: Some(space), generation,
            });
            tx.put_labyrinth_state(&key, &serde_json::to_vec(&placements).map_err(|e| MLSError::Internal(e.to_string()))?, self.hooks.now_ms())
        })
    }

    async fn native_backup_owner_items(&self, session: &mut crate::labyrinth::LabyrinthSession, conversation_id: &str, items: &[NativeArchiveEvidence]) -> Result<u32, MLSError> {
        // P11 drops the kicked member's OwnerBatch fallback on every path (flush denial and kick rescue).
        if crate::planted::is_planted_bug_active(crate::planted::PlantedBug::P11RevokeSpaceAccessBeforeKickedMemberFlushes) { return Ok(0); }
        let pending = self.db.read_tx(|tx| {
            let mut pending = Vec::new();
            for item in items {
                if item.conversation_id != conversation_id {
                    return Err(MLSError::Cryptography("owner archive conversation mismatch".into()));
                }
                crate::orchestrator::MLSMessagePayload::decode(item.labyrinth_frame_json.as_bytes())
                    .map_err(|e| MLSError::Cryptography(format!("invalid canonical owner frame: {e}")))?;
                let bytes = serde_json::to_vec(item).map_err(|e| MLSError::Internal(e.to_string()))?;
                let digest = Sha256::digest(&bytes).to_vec();
                let key = format!("native.owner:{conversation_id}:{}", item.message_id);
                if tx.get_labyrinth_state(&key)?.as_deref() != Some(digest.as_slice()) {
                    pending.push((key, digest, item));
                }
            }
            Ok(pending)
        })?;
        if pending.is_empty() { return Ok(0); }
        let items: Vec<_> = pending.iter().map(|(_, _, item)| *item).collect();
        session.archive_native_owner(conversation_id, &items).await.map_err(native_archive_error)?
            .map_err(|e| MLSError::Cryptography(format!("owner archive: {e}")))?;
        self.db.write_tx(|tx| {
            for (key, digest, _) in &pending { tx.put_labyrinth_state(key, digest, self.hooks.now_ms())?; }
            Ok(())
        })?;
        Ok(pending.len() as u32)
    }

    pub fn flush_labyrinth_queue(&self) -> Result<u32, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_flush_labyrinth_queue(); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        if self.is_handle_closed() { return Err(MLSError::ContextClosed); }
        if !self.labyrinth_status()?.backup_enabled { return Ok(0); }
        let conversations = self.db.read_tx(|tx| tx.list_labyrinth_queue_conversations())?;
        if conversations.is_empty() { return Ok(0); }
        if crate::buggify!("between_labyrinth_enqueue_and_flush") { return Err(MLSError::Internal("sim buggify: between_labyrinth_enqueue_and_flush".into())); }
        self.native_archive_run(async {
            let deps = self.native_archive_deps()?;
            let mut session = deps.clone().enable().await.map_err(native_archive_error)?;
            let mut count = 0;
            let mut first_error = None;
            for cid in conversations {
                let result: Result<u32, MLSError> = async {
                    self.pin_native_conversation(&cid)?;
                    let local_members = self.list_members(&cid)?;
                    let local_has_self = local_members.iter().any(|did| did == &self.normalized_did);
                    let owner_only = match deps.transport.query("blue.catbird.chat.getConversationState", &[("conversationId", cid.clone())]).await {
                        Ok(_) => !local_has_self,
                        Err(error) => match crate::labyrinth::transport::map_xrpc_error(error) {
                            labyrinth::Error::Forbidden => true,
                            labyrinth::Error::NotFound("conversation") if !local_has_self => true,
                            error => return Err(MLSError::Cryptography(format!("archive conversation state: {error}"))),
                        }
                    };
                    let mut committed = 0;
                    loop {
                        let queued = self.db.read_tx(|tx| tx.list_labyrinth_queue(Some(&cid), 100))?;
                        if queued.is_empty() { break; }
                        let payloads = queued.iter().map(|row| self.decode_queue_row(row)).collect::<Result<Vec<_>, _>>()?;
                        let mut start = 0;
                        while start < payloads.len() {
                            let first = &payloads[start];
                            if first.conversation_id != cid || first.expected_member_dids.is_empty()
                                || !first.expected_member_dids.contains(&first.sender_did) {
                                return Err(MLSError::Cryptography("archive missing authenticated send-time roster".into()));
                            }
                            let mut end = start + 1;
                            while end < payloads.len() && payloads[end].group_id_hex == first.group_id_hex
                                && payloads[end].epoch == first.epoch && payloads[end].expected_member_dids == first.expected_member_dids {
                                end += 1;
                            }
                            let chunk = &payloads[start..end];
                            let denied = if owner_only { true } else {
                                match session.archive_native_sender(&cid, &first.expected_member_dids, chunk).await.map_err(native_archive_error)? {
                                    Ok(()) => false,
                                    Err(labyrinth::Error::Forbidden) => true,
                                    Err(error) => return Err(MLSError::Cryptography(format!("sender archive: {error}"))),
                                }
                            };
                            if denied {
                                let items: Vec<_> = chunk.iter().map(NativeArchiveEvidence::from_queue).collect();
                                self.native_backup_owner_items(&mut session, &cid, &items).await?;
                            }
                            start = end;
                        }
                        self.db.write_tx(|tx| { for row in &queued { tx.dequeue_labyrinth_item(&row.item_id)?; } Ok(()) })?;
                        committed += queued.len() as u32;
                    }
                    Ok(committed)
                }.await;
                match result {
                    Ok(n) => count += n,
                    Err(MLSError::ContextClosed) => { session.discard_pending(&cid); return Err(MLSError::ContextClosed); }
                    Err(error) => { session.discard_pending(&cid); if first_error.is_none() { first_error = Some(error); } }
                }
            }
            self.save_native_archive_status(&session, false)?;
            match first_error { Some(error) => Err(error), None => Ok(count) }
        })
    }

    pub fn rescue_conversation_on_kick(&self, conversation_id: &str) -> Result<u32, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_rescue_conversation_on_kick(conversation_id); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        if !self.labyrinth_status()?.backup_enabled { return Ok(0); }
        self.pin_native_conversation(conversation_id)?;
        let (items, queued_ids) = self.db.read_tx(|tx| {
            let mut statement = tx.conn().prepare("SELECT message_id FROM messages WHERE conversation_id = ?1 ORDER BY seq, message_id")
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let ids = statement.query_map([conversation_id], |row| row.get::<_, String>(0))
                .map_err(|e| MLSError::Internal(e.to_string()))?.collect::<Result<Vec<_>, _>>()
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let mut items = std::collections::BTreeMap::new();
            for id in ids {
                let raw = tx.get_labyrinth_state(&format!("native.message:{conversation_id}:{id}"))?
                    .ok_or_else(|| MLSError::Cryptography(format!("missing authenticated archive evidence for {id}")))?;
                let item: NativeArchiveEvidence = serde_json::from_slice(&raw).map_err(|e| MLSError::Cryptography(format!("invalid archive evidence: {e}")))?;
                if item.message_id != id || item.conversation_id != conversation_id {
                    return Err(MLSError::Cryptography("cached archive evidence coordinates mismatch".into()));
                }
                items.insert(id, item);
            }
            let mut statement = tx.conn().prepare("SELECT item_id, payload_bytes FROM labyrinth_queue WHERE conversation_id = ?1 ORDER BY seq, item_id")
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let queued = statement.query_map([conversation_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let mut queued_ids = Vec::new();
            for row in queued {
                let (id, bytes) = row.map_err(|e| MLSError::Internal(e.to_string()))?;
                let item: NativeArchiveEvidence = serde_json::from_slice(&bytes).map_err(|e| MLSError::Cryptography(format!("invalid archive queue: {e}")))?;
                if item.message_id != id || item.conversation_id != conversation_id {
                    return Err(MLSError::Cryptography("queued archive evidence coordinates mismatch".into()));
                }
                queued_ids.push(id.clone());
                items.insert(id, item);
            }
            Ok((items.into_values().collect::<Vec<_>>(), queued_ids))
        })?;
        self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.enable().await.map_err(native_archive_error)?;
            let count = self.native_backup_owner_items(&mut session, conversation_id, &items).await?;
            self.db.write_tx(|tx| { for id in &queued_ids { tx.dequeue_labyrinth_item(id)?; } Ok(()) })?;
            self.save_native_archive_status(&session, false)?;
            Ok(count)
        })
    }

    /// Hides every copy (sender, witness or owner) attributed to an account whose deletion
    /// `conversation_id` sequenced. Live sync and restore record each verified `accountDeletedEntry`; no
    /// server redaction covers the witness and owner copies other members already published. A
    /// copy stays only if its sequencer receipt orders it after the deletion. Returns how many it hid.
    fn hide_deleted_accounts(db: &MlsAccountDb, conversation_id: &str, messages: &mut Vec<labyrinth::client::LoadedMessage>) -> Result<usize, MLSError> {
        let senders: std::collections::BTreeSet<String> = messages.iter().filter_map(|m| m.sender.clone()).collect();
        let deleted: std::collections::BTreeMap<String, u64> = db.read_tx(|tx| {
            let mut deleted = std::collections::BTreeMap::new();
            for did in &senders {
                if let Some(raw) = tx.get_labyrinth_state(&super::live_sync::account_deletion_key(conversation_id, did))? {
                    // An unreadable marker still hides: it can only widen what the deletion covers.
                    let seq = std::str::from_utf8(&raw).ok().and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
                    deleted.insert(did.clone(), seq);
                }
            }
            Ok(deleted)
        })?;
        let before = messages.len();
        messages.retain(|m| match m.sender.as_deref().and_then(|s| deleted.get(s)) {
            Some(&at) => m.archived_receipt.as_ref().is_some_and(|r| r.signed.payload.seq > at),
            None => true,
        });
        Ok(before - messages.len())
    }

    /// A fresh device never sees `accountDeletedEntry` in `getEntries`, so restore applies each
    /// deletion the conversation state lists whose sequencer authority verifies: under the pinned
    /// sequencer, or without local state the one whose receipts authenticated the restored copies.
    fn apply_listed_account_deletions(&self, conversation_id: &str, history: &[labyrinth::client::LoadedMessage]) -> Result<(), MLSError> {
        let pinned = self.db.read_tx(|tx| tx.get_conversation(conversation_id))?.map(|row| row.sequencer_did).filter(|did| !did.is_empty());
        let Some(sequencer) = pinned.or_else(|| history.iter().filter_map(|m| m.archived_receipt.as_ref())
            .max_by_key(|r| r.signed.payload.seq).map(|r| r.signed.payload.sequencer_did.clone())) else { return Ok(()) };
        let device = self.canonical_uuid_v4_device_id().ok_or_else(|| MLSError::invalid_input("archive requires UUIDv4 device_id"))?;
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let state = match self.query_signed_chat_ds("blue.catbird.chat.getConversationState",
            &[("actorDeviceId", &device), ("conversationId", conversation_id)], &device, &signer) {
            Ok(state) => state,
            // This device may not read the state; deletions live sync recorded still apply.
            Err(MLSError::InvalidState(code)) if matches!(code.as_str(), "ConversationNotFound" | "NotEntitled" | "AccessOutsideMembershipInterval") => return Ok(()),
            Err(error) => return Err(error),
        };
        let deletions = state["accountDeletions"].as_array()
            .ok_or_else(|| MLSError::Cryptography("getConversationState is missing accountDeletions".into()))?;
        for entry in deletions {
            if let Some((did, seq)) = self.verify_account_deleted_entry(conversation_id, &sequencer, entry)? {
                self.apply_verified_account_deletion(conversation_id, &did, seq)?;
            }
        }
        Ok(())
    }

    pub fn open_rescued_owner_batch(&self, batch_json: &[u8]) -> Result<Vec<(String, Option<String>, Vec<u8>)>, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_open_rescued_owner_batch(batch_json); }
        let batch: labyrinth::records::OwnerBatch = serde_json::from_slice(batch_json).map_err(|e| MLSError::Cryptography(e.to_string()))?;
        self.pin_native_conversation(&batch.thread_id)?;
        let conversation_id = batch.thread_id.clone();
        let mut messages = self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.open().await.map_err(native_archive_error)?.ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            session.open_owner_record(batch).await.map_err(native_archive_error)
        })?;
        Self::hide_deleted_accounts(&self.db, &conversation_id, &mut messages)?;
        messages.into_iter().map(|message| {
            if message.archived_receipt.is_none() || message.frame_nonce.is_none() {
                return Err(MLSError::Cryptography("owner frame missing I13 evidence".into()));
            }
            crate::orchestrator::MLSMessagePayload::decode(&message.frame)
                .map_err(|e| MLSError::Cryptography(format!("invalid canonical owner frame: {e}")))?;
            Ok((message.message_id, message.sender, message.frame))
        }).collect()
    }

    pub fn restore_conversation_from_owner_mailbox(&self, conversation_id: &str) -> Result<u32, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_restore_conversation_from_owner_mailbox(conversation_id); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.pin_native_conversation(conversation_id)?;
        let local_has_self = match self.list_members(conversation_id) {
            Ok(members) => Some(members.iter().any(|did| did == &self.normalized_did)),
            Err(MLSError::GroupNotFound { .. }) => None,
            Err(error) => return Err(error),
        };
        let (mut history, rejected) = self.native_archive_run(async {
            let deps = self.native_archive_deps()?;
            // Without local MLS state, an authenticated `ConversationNotFound` leaves only this
            // account's owner records (as in flush); it never unlocks Conversation Space reads.
            let owner_only = match local_has_self {
                Some(has_self) => !has_self,
                None => matches!(
                    deps.transport.query("blue.catbird.chat.getConversationState", &[("conversationId", conversation_id.to_owned())]).await
                        .map_err(crate::labyrinth::transport::map_xrpc_error),
                    Err(labyrinth::Error::NotFound("conversation"))
                ),
            };
            let mut session = deps.open().await.map_err(native_archive_error)?.ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            if owner_only { return session.load_owner_history(conversation_id).await.map(|m| (m, 0)).map_err(native_archive_error); }
            let history = session.load_history(conversation_id, labyrinth::store::TimeRange::ALL).await.map_err(native_archive_error)?;
            if history.undecryptable != 0 { return Err(MLSError::Cryptography("conversation archive contains undecryptable or unverified frames".into())); }
            let space_readable = history.space_readable;
            // Active members trust Conversation Space (sender and witness copies); owner records
            // are only a Forbidden fallback.
            Ok((history.messages.into_iter().filter(|message| !space_readable || message.source != labyrinth::client::MessageSource::Owner).collect(), history.rejected))
        })?;
        if rejected > 0 {
            tracing::warn!(conversation_id, rejected, "labyrinth restore: ignored witness copies that contradict accepted archive copies");
        }
        self.apply_listed_account_deletions(conversation_id, &history)?;
        let deleted = Self::hide_deleted_accounts(&self.db, conversation_id, &mut history)?;
        if deleted > 0 {
            tracing::info!(conversation_id, deleted, "labyrinth restore: hid archive copies of deleted accounts' messages");
        }
        let copies = native_restore_copies(conversation_id, &self.normalized_did, history)?;
        let (count, skipped) = self.db.write_tx(|tx| {
            let mut chosen = Vec::new();
            let mut skipped = 0usize;
            for group in copies.values() {
                let local = tx.get_message(&group[0].0.message_id)?;
                match select_restore_copy(group, local.as_ref()) {
                    Some(copy) => chosen.push((copy, local.is_none())),
                    None => skipped += 1,
                }
            }
            chosen.sort_by(|((a, _, _), _), ((b, _, _), _)| a.seq.cmp(&b.seq).then_with(|| a.message_id.cmp(&b.message_id)));
            let mut count: u32 = 0;
            for ((row, evidence, _), new) in &chosen {
                if *new { tx.insert_message(row)?; count += 1; }
                tx.put_labyrinth_state(&format!("native.message:{conversation_id}:{}", row.message_id),
                    &serde_json::to_vec(evidence).map_err(|e| MLSError::Internal(e.to_string()))?, self.hooks.now_ms())?;
            }
            // Archive recovery does not create MLS state or advance a live delivery cursor.
            if tx.get_conversation(conversation_id)?.is_none() {
                if let Some(((row, _, receipt), _)) = chosen.last() {
                    tx.upsert_conversation(&ConversationRow {
                        conversation_id: conversation_id.into(), group_id: row.group_id.clone(),
                        generation: i64::try_from(receipt.generation).map_err(|_| MLSError::Cryptography("archive generation overflow".into()))?,
                        epoch: row.epoch, last_seq: 0, sequencer_did: receipt.sequencer_did.clone(),
                        space_uri: None, title: None, unread_count: 0, updated_at_ms: self.hooks.now_ms(),
                    })?;
                }
            }
            Ok((count, skipped))
        })?;
        if skipped > 0 {
            tracing::warn!(conversation_id, skipped, "labyrinth restore: skipped message ids whose archive copies disagree");
        }
        if count > 0 {
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            self.notify(PlatformChangeEvent::MessagesUpdated { conversation_id: conversation_id.into() });
        }
        Ok(count)
    }

    fn rotate_native_archive(&self, target_device_id: Option<&str>) -> Result<u64, MLSError> {
        let key = target_device_id.map(|id| {
            hex::decode(id.trim()).ok().and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                .ok_or_else(|| MLSError::invalid_input("target_device_id must resolve to a 32-byte Labyrinth device key; UUID-only revocation is not supported"))
        }).transpose()?;
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test {
            let now_ms = self.hooks.now_ms();
            if let Some((remote_seq, remote_root)) = self.rotate_mailbox_epoch_if_supported(key.as_ref(), now_ms)? {
                self.db.write_tx(|tx| tx.put_labyrinth_state(&owner_epoch_root_key(remote_seq), remote_root.as_slice(), now_ms))?;
                return Ok(remote_seq);
            }
            if target_device_id.is_some() { return Err(MLSError::invalid_input("revocation requires an authenticated mailbox device key")); }
            let next_seq = self.labyrinth_status()?.epoch_seq.saturating_add(1);
            self.db.write_tx(|tx| { let _ = ensure_owner_epoch_root(tx, next_seq, now_ms, &self.hooks)?; Ok(()) })?;
            return Ok(next_seq);
        }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.enable().await.map_err(native_archive_error)?;
            match key {
                Some(key) => session.revoke_device(key).await.map_err(native_archive_error),
                None => session.rotate_epoch().await.map_err(native_archive_error),
            }
        })
    }

    /// Deterministically enroll a disposable chat device, publish a valid newest `EpochPublic`
    /// attested by that device to `mls-ds` (`publishEpochHead`), and immediately revoke that
    /// chat device (`blue.catbird.chat.revokeDevice`) so `DsDirectoryStore::latest(did)` returns
    /// a self-valid head whose attester is NOT a current chat device (`[CB-18]` / `P5`).
    /// Returns `(epoch_head, storage_device_key_hex)`; revoke that storage
    /// device after the exposure probe to close the untrusted-head window.
    #[cfg(feature = "sim")]
    pub fn sim_publish_unauthorized_epoch(&self, rogue_seed: u64) -> Result<(Vec<u8>, String), MLSError> {
        use labyrinth::store::MailboxDirectory as _;

        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let actor_dev_id = self
            .canonical_uuid_v4_device_id()
            .ok_or_else(|| MLSError::InvalidState("canonical UUIDv4 device_id required".into()))?;
        let (actor_signer, actor_auth_gen) = self.load_enrolled_signer_and_auth_gen()?;

        let derive = |tag: &[u8]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"catbird.sim.p5.rogue\0");
            h.update(self.normalized_did.as_bytes());
            h.update([0u8]);
            h.update(rogue_seed.to_le_bytes());
            h.update(tag);
            h.finalize().into()
        };
        let mut rogue_uuid = [0u8; 16];
        rogue_uuid.copy_from_slice(&derive(b"device_uuid")[..16]);
        rogue_uuid[6] = (rogue_uuid[6] & 0x0f) | 0x40;
        rogue_uuid[8] = (rogue_uuid[8] & 0x3f) | 0x80;
        let mut rogue_dev_id = uuid::Uuid::from_bytes(rogue_uuid).hyphenated().to_string();
        if rogue_dev_id == actor_dev_id {
            rogue_uuid[0] ^= 0x01;
            rogue_dev_id = uuid::Uuid::from_bytes(rogue_uuid).hyphenated().to_string();
        }

        let rogue_seed_bytes = derive(b"ed25519_signer");
        let rogue_dalek = ed25519_dalek::SigningKey::from_bytes(&rogue_seed_bytes);
        let rogue_pub = rogue_dalek.verifying_key().to_bytes();
        let rogue_mls_signer = SignatureKeyPair::from_raw(
            CIPHERSUITE.signature_algorithm(),
            rogue_seed_bytes.to_vec(),
            rogue_pub.to_vec(),
        );

        // 1. Temporarily enroll the rogue chat device on home `mls-ds` (never added to any group).
        let now_secs = self.hooks.now_secs();
        let kps_json = {
            let mem_provider = self
                .hooks
                .openmls_provider(openmls_memory_storage::MemoryStorage::default());
            let scoped_id = format!("{}#{rogue_dev_id}", self.normalized_did);
            let cred_with_key = CredentialWithKey {
                credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                signature_key: rogue_mls_signer.public().into(),
            };
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let mut items: Vec<(Vec<u8>, serde_json::Value)> = Vec::with_capacity(2);
            for _ in 0..2 {
                let kp_bundle = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::init(
                        now_secs.saturating_sub(60),
                        now_secs + 29 * 86_400,
                    ))
                    .leaf_node_capabilities(caps.clone())
                    .build(CIPHERSUITE, &mem_provider, &rogue_mls_signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build rogue KP: {e:?}")))?;
                let kp_bytes = MlsMessageOut::from(kp_bundle.key_package().clone())
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize rogue KP: {e:?}")))?;
                let kp_ref = kp_bundle
                    .key_package()
                    .hash_ref(mem_provider.crypto())
                    .map_err(|e| MLSError::Cryptography(format!("rogue KP hash_ref: {e:?}")))?
                    .as_slice()
                    .to_vec();
                items.push((
                    kp_ref.clone(),
                    serde_json::json!({
                        "framing": "mlsMessage",
                        "contentType": "keyPackage",
                        "bytes": { "$bytes": BASE64_STANDARD.encode(&kp_bytes) },
                        "sha256": BASE64_STANDARD.encode(Sha256::digest(&kp_bytes)),
                        "keyPackageRef": { "$bytes": BASE64_STANDARD.encode(&kp_ref) },
                    }),
                ));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            items.into_iter().map(|(_, v)| v).collect::<Vec<_>>()
        };

        let rogue_key_id = crate::orchestrator::canonical_transport::derive_key_id(&rogue_pub);
        let enroll_body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\0",
            "actorDid": self.normalized_did,
            "deviceId": rogue_dev_id,
            "deviceName": "RogueSim",
            "keyId": rogue_key_id,
            "signaturePublicKey": { "$bytes": BASE64_STANDARD.encode(rogue_pub) },
            "expectedAuthGeneration": 0,
            "capability": {
                "protocolVersion": "1",
                "mlsVersion": "1.0",
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "credentialType": "basic",
                "addByValue": "supported",
                "updatePath": "supported",
                "removeByValue": "supported",
                "ratchetTreeGroupInfo": "supported",
                "externalPubGroupInfo": "presentButExternalCommitsForbidden",
                "applicationFrameProfile": "dagCborApplication1",
                "controlProfile": "publicGroup1",
                "attachmentProfile": "aes256GcmBlob1",
                "metadataProfile": "exporterAes256Gcm1",
                "typingProfile": "signedClearEphemeral1"
            },
            "keyPackages": kps_json,
            "idempotencyKey": self.hooks.uuid_v4().to_string(),
            "signedAt": self.hooks.now_rfc3339_millis(),
        });
        let enroll_resp = self.submit_signed_chat_op(
            &rogue_dev_id,
            None,
            crate::orchestrator::canonical_transport::CanonicalOperation::EnrollDevice,
            &enroll_body,
            &rogue_mls_signer,
        )?;
        let rogue_auth_gen = enroll_resp
            .get("device")
            .and_then(|d| d.get("authGeneration"))
            .and_then(|g| g.as_i64())
            .or_else(|| enroll_resp.get("authGeneration").and_then(|g| g.as_i64()))
            .unwrap_or(1)
            .max(1);

        // 2. Enroll the disposable storage device through the real recovery protocol.
        // The primary retains its own transport-bound session and is carried into
        // the new mailbox epoch. Only the disposable session uses the rogue signer;
        // putting it in native.session would make every later primary open fail.
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        let (head_vec, storage_device_key) = self.native_archive_run(async {
            let mut primary_session = self.native_archive_deps()?
                .enable().await.map_err(native_archive_error)?;
            let recovery_code = Zeroizing::new(primary_session
                .create_recovery_code().await.map_err(native_archive_error)?);
            let mut rogue_cfg = self.config.clone();
            rogue_cfg.account_did = self.normalized_did.clone();
            rogue_cfg.device_id = rogue_dev_id.clone();
            let rogue_arc_signer = Arc::new(NativeArchiveSigner(rogue_mls_signer));
            let rogue_gateway = Arc::new(NativeArchiveGateway {
                config: rogue_cfg,
                db: self.db.clone(),
                transport: self.transport.clone(),
                signer: rogue_arc_signer.clone(),
                hooks: self.hooks.clone(),
            });
            let rogue_xrpc = Arc::new(
                crate::labyrinth::GatewayXrpcTransport::new(
                    rogue_gateway.clone(),
                    rogue_arc_signer.clone(),
                    self.normalized_did.clone(),
                    rogue_dev_id.clone(),
                )
                .with_clock(Arc::new(NativeArchiveClock(self.hooks.clone()))),
            );
            let rogue_deps = crate::labyrinth::SessionDeps {
                did: self.normalized_did.clone(),
                transport: rogue_xrpc,
                signer: rogue_arc_signer,
                vault: Arc::new(NativeArchiveVault {
                    db: self.db.clone(),
                    namespace: "native.sim.rogue.session",
                    hooks: self.hooks.clone(),
                }),
                placements: Arc::new(NativeArchiveVault {
                    db: self.db.clone(),
                    namespace: "native.sim.rogue.placements",
                    hooks: self.hooks.clone(),
                }),
                pds: Some(rogue_gateway.clone()),
                space: Some(Arc::new(crate::labyrinth::SpaceXrpcTransport::new(
                    rogue_gateway,
                ))),
                local_authority: None,
                sequencer_key: None,
                sequencer_receipt_key: None,
                default_conversation_authority_did: None,
            };
            let session = rogue_deps
                .clone()
                .restore_with_recovery_code(&recovery_code)
                .await
                .map_err(native_archive_error)?;
            self.save_native_archive_status(&session, false)?;
            let published = rogue_deps
                .ds_directory()
                .latest(&self.normalized_did)
                .await
                .map_err(|e| MLSError::Internal(format!("query rogue latest epoch head: {e}")))?
                .ok_or_else(|| {
                    MLSError::Internal("rogue enable did not publish epoch head to mls-ds".into())
                })?;
            Ok::<_, MLSError>((published.head.to_vec(), session.device_key_hex()))
        })?;

        // 3. Immediately revoke the rogue chat device using the primary enrolled device so its
        //    transport key has `revokedAt != None` in `getChatDeviceKeys` (`!is_current()`).
        let actor_key_id =
            crate::orchestrator::canonical_transport::derive_key_id(actor_signer.public());
        let revoke_body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#deviceRevocationBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\0",
            "actorDid": self.normalized_did,
            "actorDeviceId": actor_dev_id,
            "authGeneration": actor_auth_gen,
            "targetDeviceId": rogue_dev_id,
            "targetAuthGeneration": rogue_auth_gen,
            "idempotencyKey": self.hooks.uuid_v4().to_string(),
            "keyId": actor_key_id,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });
        let _ = self.submit_signed_chat_op(
            &actor_dev_id,
            Some(actor_auth_gen),
            crate::orchestrator::canonical_transport::CanonicalOperation::RevokeDevice,
            &revoke_body,
            &actor_signer,
        )?;

        Ok((head_vec, storage_device_key))
    }
}

/// Restore over real Labyrinth verification: a member's relabelled witness copies, or its own
/// copy colliding with another member's message id, never fail or alter restore.
#[cfg(all(test, feature = "labyrinth"))]
mod native_restore_tests {
    use super::{block_on_sync, native_restore_copies, select_restore_copy, MessageRow};
    use labyrinth::client::{Backends, Clock, Labyrinth};
    use labyrinth::message::ArchivedReceipt;
    use labyrinth::protocol::receipt::{
        compute_archive_commitment, expected_receipt_key_id, sign_sequencer_receipt, SequencerReceiptPayload,
    };
    use labyrinth::sign::TransportSigner;
    use labyrinth::store::memory::MemoryBackend;
    use labyrinth::store::{SequencerReceiptKey, TimeRange};

    const CONVERSATION: &str = "5f0f6c1e-7a4b-4c1d-9e2f-3a4b5c6d7e8f";
    const SEQUENCER: &str = "did:web:ds.example";
    const DEVICE: &str = "6f1d2c3b-4a59-4687-8796-a5b4c3d2e1f0";
    const ALICE: &str = "did:plc:alice";
    const BOB: &str = "did:plc:bob";
    const CAROL: &str = "did:plc:carol";

    struct FixedClock;
    impl Clock for FixedClock {
        fn now_ms(&self) -> u64 { 1_791_000_000_000 }
    }

    struct ChatKey(ed25519_dalek::SigningKey);
    impl TransportSigner for ChatKey {
        fn transport_public_key(&self) -> [u8; 32] { self.0.verifying_key().to_bytes() }
        fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
            use ed25519_dalek::Signer as _;
            self.0.sign(msg).to_bytes()
        }
    }

    struct Sent { frame: Vec<u8>, nonce: [u8; 32], receipt: ArchivedReceipt }

    struct World { net: MemoryBackend, sequencer: p256::ecdsa::SigningKey }

    impl World {
        fn new() -> Self {
            let net = MemoryBackend::new();
            net.enable_server_order();
            let sequencer = p256::ecdsa::SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
            net.set_sequencer_receipt_key(CONVERSATION, SequencerReceiptKey {
                did: SEQUENCER.into(),
                public_key_sec1: sequencer.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
            });
            Self { net, sequencer }
        }

        fn join(&self, did: &str, seed: u8) -> Labyrinth {
            let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let public = key.verifying_key().to_bytes();
            self.net.register_chat_device(did, public);
            let backends = Backends {
                mailbox: Box::new(self.net.mailbox(did)), threads: Box::new(self.net.threads(did)),
                directory: Box::new(self.net.directory()), publishers: vec![], clock: Box::new(FixedClock),
            };
            let lab = block_on_sync(Labyrinth::initialize(did, Box::new(ChatKey(key)), backends)).unwrap();
            self.net.add_leaf(CONVERSATION, did, public);
            lab
        }

        /// The sequencer orders `sender`'s canonical text frame and receipts it.
        fn sequence(&self, sender: &str, id: &str, text: &str) -> Sent {
            let frame = serde_json::to_vec(&crate::orchestrator::MLSMessagePayload::text(text)).unwrap();
            let mut nonce = [0u8; 32];
            for (n, b) in nonce.iter_mut().zip(id.bytes().cycle()) { *n = b; }
            let seq = self.net.append_chat_entry(CONVERSATION);
            let payload = SequencerReceiptPayload {
                sequencer_did: SEQUENCER.into(), conversation_id: CONVERSATION.into(), group_id: vec![0x99; 32], epoch: 1,
                sender_device_did_url: format!("{sender}#{DEVICE}"), entry_id: format!("entry-{id}"),
                archive_commitment: compute_archive_commitment(&nonce, &frame), seq, issued_at_ms: 1_791_000_000_000 + seq as i64,
            };
            let signed = sign_sequencer_receipt(&self.sequencer, &expected_receipt_key_id(SEQUENCER), &payload).unwrap();
            Sent { frame, nonce, receipt: ArchivedReceipt::new(signed) }
        }
    }

    /// `lab` archives `m`'s exact frame, nonce and receipt under `id`.
    fn archive(lab: &mut Labyrinth, id: &str, m: &Sent, ts: u64) {
        let roster = block_on_sync(lab.resolve_roster(&[ALICE, BOB, CAROL])).unwrap();
        block_on_sync(lab.archive_outgoing_committed(CONVERSATION, &roster, id, ts, &m.nonce, &m.frame, &m.receipt)).unwrap();
        block_on_sync(lab.flush()).unwrap();
    }

    /// `(messageId, sender, frame)` restore would import for `lab` next to `local` rows.
    fn restored(lab: &mut Labyrinth, local: &[MessageRow]) -> Vec<(String, String, Vec<u8>)> {
        let history = block_on_sync(lab.load_thread(CONVERSATION, TimeRange::ALL)).unwrap();
        assert!(history.undecryptable.is_empty(), "{:?}", history.undecryptable);
        let copies = native_restore_copies(CONVERSATION, BOB, history.messages).unwrap();
        copies.values()
            .filter_map(|group| select_restore_copy(group, local.iter().find(|row| row.message_id == group[0].0.message_id)))
            .map(|(row, _, _)| (row.message_id.clone(), row.sender_did.clone(), row.plaintext_json.clone().into_bytes()))
            .collect()
    }

    #[test]
    fn restore_yields_exactly_the_genuine_messages_despite_relabelled_witness_copies() {
        let w = World::new();
        let mut alice = w.join(ALICE, 1);
        let mut bob = w.join(BOB, 2);
        let mut carol = w.join(CAROL, 3);
        let m1 = w.sequence(ALICE, "m1", "hello");
        let m2 = w.sequence(ALICE, "m2", "world");
        archive(&mut alice, "m1", &m1, 100);
        archive(&mut alice, "m2", &m2, 110);
        // Carol files genuine frames under the wrong ids: m2's as m1, m1's as m3.
        archive(&mut carol, "m1", &m2, 120);
        archive(&mut carol, "m3", &m1, 130);
        assert_eq!(restored(&mut bob, &[]), [
            ("m1".to_owned(), ALICE.to_owned(), m1.frame.clone()),
            ("m2".to_owned(), ALICE.to_owned(), m2.frame.clone()),
        ]);
    }

    #[test]
    fn a_members_colliding_own_copy_cannot_fail_restore() {
        let w = World::new();
        let mut alice = w.join(ALICE, 1);
        let mut bob = w.join(BOB, 2);
        let mut carol = w.join(CAROL, 3);
        let m1 = w.sequence(ALICE, "m1", "hello");
        let m2 = w.sequence(ALICE, "m2", "world");
        let c1 = w.sequence(CAROL, "c1", "mine");
        archive(&mut alice, "m1", &m1, 100);
        archive(&mut alice, "m2", &m2, 110);
        // Carol archives her own message under Alice's id.
        archive(&mut carol, "m1", &c1, 120);
        // Undecidable from the archive alone: m1 is skipped, the rest restores.
        assert_eq!(restored(&mut bob, &[]), [("m2".to_owned(), ALICE.to_owned(), m2.frame.clone())]);
        // The local message decides which copy is genuine.
        let local = MessageRow {
            message_id: "m1".into(), conversation_id: CONVERSATION.into(), group_id: vec![0x99; 32], epoch: 1,
            seq: m1.receipt.signed.payload.seq as i64, sender_did: ALICE.into(), sender_device_id: DEVICE.into(),
            plaintext_json: String::from_utf8(m1.frame.clone()).unwrap(), created_at_ms: 100, is_own: false,
        };
        assert_eq!(restored(&mut bob, &[local]), [
            ("m1".to_owned(), ALICE.to_owned(), m1.frame.clone()),
            ("m2".to_owned(), ALICE.to_owned(), m2.frame.clone()),
        ]);
    }

    /// Production readers get no sequencer redactions; the authenticated `accountDeletedEntry`
    /// live sync recorded decides. Every copy attributed to the deleted account that its receipt
    /// orders before the entry is hidden, in Space and owner history alike: its own copy, another
    /// member's published witness copy of a message it never archived, and re-archived owner
    /// copies. Other members' messages, and its messages sequenced after the entry, stay.
    #[test]
    fn a_sequenced_account_deletion_hides_every_published_copy_of_its_messages() {
        use super::CatbirdMlsClient;
        use crate::storage::{MlsAccountDb, OpenMode};
        fn visible(db: &MlsAccountDb, lab: &mut Labyrinth, owner: bool) -> Vec<String> {
            let history = if owner {
                block_on_sync(lab.load_owner_thread(CONVERSATION))
            } else {
                block_on_sync(lab.load_thread(CONVERSATION, TimeRange::ALL))
            }
            .unwrap();
            assert!(history.undecryptable.is_empty(), "{:?}", history.undecryptable);
            let mut messages = history.messages;
            CatbirdMlsClient::hide_deleted_accounts(db, CONVERSATION, &mut messages).unwrap();
            messages.into_iter().map(|m| m.message_id).collect()
        }
        let w = World::new();
        let mut alice = w.join(ALICE, 1);
        let mut bob = w.join(BOB, 2);
        let mut carol = w.join(CAROL, 3);
        let a1 = w.sequence(ALICE, "a1", "own copy");
        let a2 = w.sequence(ALICE, "a2", "never archived by alice");
        let b1 = w.sequence(BOB, "b1", "bob stays");
        archive(&mut alice, "a1", &a1, 100);
        archive(&mut carol, "a1", &a1, 110);
        archive(&mut carol, "a2", &a2, 120);
        archive(&mut bob, "b1", &b1, 130);
        assert_eq!(block_on_sync(bob.rearchive_thread_before_leave(CONVERSATION)).unwrap(), 3);
        let dir = tempfile::tempdir().unwrap();
        let db = MlsAccountDb::open_native(dir.path().join("deleted.db"), &[7; 32], OpenMode::App).unwrap();
        // Published copies stay visible until this device holds the deletion entry.
        assert_eq!(visible(&db, &mut bob, false), ["a1", "a2", "b1"]);
        assert_eq!(visible(&db, &mut bob, true), ["a1", "a2", "b1"]);

        let deleted_at = i64::try_from(w.net.append_chat_entry(CONVERSATION)).unwrap();
        db.write_tx(|tx| super::super::live_sync::record_account_deletion(tx, CONVERSATION, ALICE, deleted_at, 1)).unwrap();
        let a3 = w.sequence(ALICE, "a3", "after the deletion");
        archive(&mut alice, "a3", &a3, 200);
        assert_eq!(visible(&db, &mut bob, false), ["b1", "a3"]);
        assert_eq!(visible(&db, &mut bob, true), ["b1"]);
    }
}
