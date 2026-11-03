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
        let mut headers = request.headers;
        if let Some(content_type) = request.content_type { headers.push(("content-type".into(), content_type)); }
        let response = self.execute(&self.config.pds_endpoint, request.method, request.path, headers, request.body)?;
        Ok(crate::labyrinth::LabyrinthSpaceResponse {
            status: response.status, content_type: response.header("content-type").map(str::to_owned),
            headers: response.headers.into_iter().map(|h| (h.name, h.value)).collect(), body: response.body,
        })
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
        config.device_id = self.canonical_uuid_v4_device_id().unwrap_or_else(|| self.config.device_id.clone());
        let gateway = Arc::new(NativeArchiveGateway { config: config.clone(), db: self.db.clone(), transport: self.transport.clone(), signer: signer.clone(), hooks: self.hooks.clone() });
        let transport = Arc::new(crate::labyrinth::GatewayXrpcTransport::new(gateway.clone(), signer.clone(), self.normalized_did.clone(), config.device_id)
            .with_clock(Arc::new(NativeArchiveClock(self.hooks.clone()))));
        Ok(crate::labyrinth::SessionDeps {
            did: self.normalized_did.clone(), transport, signer,
            vault: Arc::new(NativeArchiveVault { db: self.db.clone(), namespace: "native.session", hooks: self.hooks.clone() }),
            placements: Arc::new(NativeArchiveVault { db: self.db.clone(), namespace: "native.placements", hooks: self.hooks.clone() }),
            pds: None, space: Some(Arc::new(crate::labyrinth::SpaceXrpcTransport::new(gateway))),
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
        if self.canonical_uuid_v4_device_id().is_none() { return self.offline_setup_recovery_code(); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.enable().await.map_err(native_archive_error)?;
            let code = session.create_recovery_code().await.map_err(native_archive_error)?;
            self.save_native_archive_status(&session, true)?;
            Ok(code)
        })
    }

    pub fn restore_with_recovery_code(&self, code: &str) -> Result<LabyrinthBackupStatus, MLSError> {
        if self.canonical_uuid_v4_device_id().is_none() { return self.offline_restore_with_recovery_code(code); }
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

    fn native_cached_archive_rows(&self, conversation_id: &str) -> Result<Vec<MessageRow>, MLSError> {
        self.db.read_tx(|tx| {
            let mut statement = tx.conn().prepare(
                "SELECT message_id, conversation_id, group_id, epoch, seq, sender_did, sender_device_id, plaintext_json, created_at_ms, is_own FROM messages WHERE conversation_id = ?1 ORDER BY seq, message_id"
            ).map_err(|e| MLSError::Internal(format!("read archive messages: {e}")))?;
            let rows = statement.query_map([conversation_id], |row| Ok(MessageRow {
                message_id: row.get(0)?, conversation_id: row.get(1)?, group_id: row.get(2)?, epoch: row.get(3)?, seq: row.get(4)?, sender_did: row.get(5)?, sender_device_id: row.get(6)?, plaintext_json: row.get(7)?, created_at_ms: row.get(8)?, is_own: row.get::<_, i64>(9)? != 0,
            })).map_err(|e| MLSError::Internal(format!("read archive messages: {e}")))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|e| MLSError::Internal(format!("read archive messages: {e}")))
        })
    }

    async fn native_backup_owner_rows(&self, session: &mut crate::labyrinth::LabyrinthSession, conversation_id: &str, rows: &[MessageRow]) -> Result<u32, MLSError> {
        let mut items = Vec::new();
        let mut saved = Vec::new();
        for row in rows {
            let frame = serde_json::to_vec(row).map_err(|e| MLSError::Internal(e.to_string()))?;
            let digest = Sha256::digest(&frame).to_vec();
            let key = format!("native.owner:{conversation_id}:{}", row.message_id);
            if self.db.read_tx(|tx| tx.get_labyrinth_state(&key))?.as_deref() == Some(digest.as_slice()) { continue; }
            items.push((row.message_id.clone(), row.created_at_ms.max(0) as u64, row.sender_did.clone(), frame));
            saved.push((key, digest));
        }
        if items.is_empty() { return Ok(0); }
        session.archive_owner_fallback(conversation_id, &items).await.map_err(native_archive_error)?
            .map_err(|e| MLSError::Internal(format!("owner archive: {e}")))?;
        self.db.write_tx(|tx| {
            for (key, digest) in &saved { tx.put_labyrinth_state(key, digest, self.hooks.now_ms())?; }
            Ok(())
        })?;
        Ok(items.len() as u32)
    }

    pub fn flush_labyrinth_queue(&self) -> Result<u32, MLSError> {
        if self.canonical_uuid_v4_device_id().is_none() { return self.offline_flush_labyrinth_queue(); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        if self.is_handle_closed() { return Err(MLSError::ContextClosed); }
        if !self.labyrinth_status()?.backup_enabled { return Ok(0); }
        if crate::buggify!("between_labyrinth_enqueue_and_flush") { return Err(MLSError::Internal("sim buggify: between_labyrinth_enqueue_and_flush".into())); }
        let conversations = self.db.read_tx(|tx| {
            let mut stmt = tx.conn().prepare("SELECT conversation_id FROM messages UNION SELECT conversation_id FROM labyrinth_queue ORDER BY conversation_id").map_err(|e| MLSError::Internal(e.to_string()))?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0)).map_err(|e| MLSError::Internal(e.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|e| MLSError::Internal(e.to_string()))
        })?;
        if conversations.is_empty() { return Ok(0); }
        self.native_archive_run(async {
            let deps = self.native_archive_deps()?;
            let mut session = deps.clone().enable().await.map_err(native_archive_error)?;
            let mut count = 0;
            let mut first_error = None;
            for cid in conversations {
                let result: Result<u32, MLSError> = async {
                    let mut committed = 0;
                    loop {
                        let queued = self.db.read_tx(|tx| tx.list_labyrinth_queue(Some(&cid), 100))?;
                        if queued.is_empty() { break; }
                        let payloads = queued.iter().map(|row| serde_json::from_slice::<QueuedLabyrinthArchivePayload>(&row.payload_bytes).map_err(|e| MLSError::Internal(format!("invalid archive queue: {e}")))).collect::<Result<Vec<_>, _>>()?;
                        let members = self.list_members(&cid)?;
                        let state = deps.transport.query("blue.catbird.chat.getConversationState", &[("conversationId", cid.clone())]).await;
                        let archive = match state {
                            Ok(body) => {
                                let state: serde_json::Value = serde_json::from_slice(&body).map_err(|e| MLSError::Internal(e.to_string()))?;
                                let mut remote = crate::labyrinth::hooks::roster_members(&state).map_err(|e| MLSError::Internal(e.to_string()))?;
                                remote.sort(); remote.dedup();
                                let mut local = members.clone(); local.sort(); local.dedup();
                                if remote != local { return Err(MLSError::Cryptography("archive DS roster differs from local MLS leaves".into())); }
                                session.archive_native_sender(&cid, &members, &payloads).await.map_err(native_archive_error)?
                            }
                            Err(error) => Err(crate::labyrinth::transport::map_xrpc_error(error)),
                        };
                        let denied = match &archive {
                            Err(labyrinth::Error::Forbidden | labyrinth::Error::NotFound("space" | "conversation")) => true,
                            Err(labyrinth::Error::Backend(msg)) if msg.contains("native_archive_context_closed") => return Err(MLSError::ContextClosed),
                            Err(error) => return Err(MLSError::Internal(format!("sender archive: {error}"))),
                            Ok(()) => false,
                        };
                        let lose_on_kick = denied && crate::planted::is_planted_bug_active(crate::planted::PlantedBug::P11RevokeSpaceAccessBeforeKickedMemberFlushes);
                        if !lose_on_kick {
                            let ids: std::collections::BTreeSet<_> = queued.iter().map(|row| row.item_id.as_str()).collect();
                            let mut cached = self.native_cached_archive_rows(&cid)?.into_iter().filter(|row| ids.contains(row.message_id.as_str())).collect::<Vec<_>>();
                            let seen: std::collections::BTreeSet<_> = cached.iter().map(|row| row.message_id.clone()).collect();
                            for payload in payloads.iter().filter(|p| !seen.contains(&p.message_id)) {
                                let group_id = hex::decode(&payload.group_id_hex).unwrap_or_else(|_| Sha256::digest(cid.as_bytes()).to_vec());
                                cached.push(MessageRow {
                                    message_id: payload.message_id.clone(), conversation_id: cid.clone(), group_id,
                                    epoch: payload.epoch, seq: payload.seq, sender_did: payload.sender_did.clone(),
                                    sender_device_id: payload.sender_device_id.clone(), plaintext_json: payload.plaintext_json.clone(),
                                    created_at_ms: payload.created_at_ms, is_own: payload.sender_did == self.normalized_did,
                                });
                            }
                            self.native_backup_owner_rows(&mut session, &cid, &cached).await?;
                        }
                        self.db.write_tx(|tx| { for row in &queued { tx.dequeue_labyrinth_item(&row.item_id)?; } Ok(()) })?;
                        committed += queued.len() as u32;
                    }
                    let incoming = self.native_cached_archive_rows(&cid)?.into_iter().filter(|row| row.sender_did != self.normalized_did).collect::<Vec<_>>();
                    self.native_backup_owner_rows(&mut session, &cid, &incoming).await?;
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
        if self.canonical_uuid_v4_device_id().is_none() { return self.offline_rescue_conversation_on_kick(conversation_id); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        if !self.labyrinth_status()?.backup_enabled { return Ok(0); }
        self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.enable().await.map_err(native_archive_error)?;
            let mut rows = self.native_cached_archive_rows(conversation_id)?;
            let queued_rows = self.db.read_tx(|tx| {
                let mut statement = tx.conn().prepare(
                    "SELECT item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms FROM labyrinth_queue WHERE conversation_id = ?1 ORDER BY seq, item_id"
                ).map_err(|e| MLSError::Internal(e.to_string()))?;
                let iter = statement.query_map([conversation_id], |row| Ok(LabyrinthQueueRow {
                    item_id: row.get(0)?, conversation_id: row.get(1)?, group_id_hex: row.get(2)?, seq: row.get(3)?, payload_bytes: row.get(4)?, created_at_ms: row.get(5)?,
                })).map_err(|e| MLSError::Internal(e.to_string()))?;
                iter.collect::<Result<Vec<_>, _>>().map_err(|e| MLSError::Internal(e.to_string()))
            })?;
            let queued_ids: Vec<String> = queued_rows.iter().map(|row| row.item_id.clone()).collect();
            if crate::planted::is_planted_bug_active(crate::planted::PlantedBug::P11RevokeSpaceAccessBeforeKickedMemberFlushes) {
                rows.retain(|row| !queued_ids.contains(&row.message_id));
            } else {
                let seen: std::collections::BTreeSet<_> = rows.iter().map(|row| row.message_id.clone()).collect();
                for queued in &queued_rows {
                    let payload = self.decode_queue_row(queued)?;
                    if !seen.contains(&payload.message_id) {
                        let group_id = hex::decode(&payload.group_id_hex).unwrap_or_else(|_| Sha256::digest(conversation_id.as_bytes()).to_vec());
                        rows.push(MessageRow {
                            message_id: payload.message_id, conversation_id: conversation_id.into(), group_id,
                            epoch: payload.epoch, seq: payload.seq, sender_did: payload.sender_did.clone(),
                            sender_device_id: payload.sender_device_id, plaintext_json: payload.plaintext_json,
                            created_at_ms: payload.created_at_ms, is_own: payload.sender_did == self.normalized_did,
                        });
                    }
                }
            }
            self.native_backup_owner_rows(&mut session, conversation_id, &rows).await?;
            self.db.write_tx(|tx| { for id in &queued_ids { tx.dequeue_labyrinth_item(id)?; } Ok(()) })?;
            self.save_native_archive_status(&session, false)?;
            Ok(rows.len() as u32)
        })
    }

    pub fn open_rescued_owner_batch(&self, batch_json: &[u8]) -> Result<Vec<(String, Option<String>, Vec<u8>)>, MLSError> {
        if self.canonical_uuid_v4_device_id().is_none() { return self.offline_open_rescued_owner_batch(batch_json); }
        let batch: labyrinth::records::OwnerBatch = serde_json::from_slice(batch_json).map_err(|e| MLSError::Internal(e.to_string()))?;
        self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.open().await.map_err(native_archive_error)?.ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            session.open_owner_record(batch).await.map_err(native_archive_error)?.into_iter().map(|message| {
                let row: MessageRow = serde_json::from_slice(&message.frame).map_err(|e| MLSError::Internal(format!("native owner frame: {e}")))?;
                Ok((message.message_id, message.sender, canonical_labyrinth_frame_json(&row.plaintext_json).into_bytes()))
            }).collect()
        })
    }

    pub fn restore_conversation_from_owner_mailbox(&self, conversation_id: &str) -> Result<u32, MLSError> {
        if self.canonical_uuid_v4_device_id().is_none() { return self.offline_restore_conversation_from_owner_mailbox(conversation_id); }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        let history = self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.open().await.map_err(native_archive_error)?.ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            session.load_owner_history(conversation_id).await.map_err(native_archive_error)
        })?;
        // Every device of this account archives the rows it saw. Copies of one message
        // may differ only in device-local receipt time; authoritative fields must agree.
        let mut by_id: std::collections::BTreeMap<String, MessageRow> = std::collections::BTreeMap::new();
        for message in history {
            let row: MessageRow = serde_json::from_slice(&message.frame).map_err(|e| MLSError::Internal(format!("native owner frame: {e}")))?;
            if row.conversation_id != conversation_id || row.message_id != message.message_id || message.sender.as_deref() != Some(row.sender_did.as_str()) || row.seq < 0 || row.epoch < 0 {
                return Err(MLSError::Cryptography("owner frame coordinates/attribution mismatch".into()));
            }
            match by_id.entry(row.message_id.clone()) {
                std::collections::btree_map::Entry::Vacant(slot) => { slot.insert(row); }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    let kept = slot.get_mut();
                    if kept.sender_did != row.sender_did || kept.group_id != row.group_id || kept.epoch != row.epoch || kept.seq != row.seq || kept.plaintext_json != row.plaintext_json {
                        return Err(MLSError::Cryptography("conflicting owner archive copies".into()));
                    }
                    if row.created_at_ms < kept.created_at_ms { *kept = row; }
                }
            }
        }
        let mut rows: Vec<MessageRow> = by_id.into_values().collect();
        rows.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.created_at_ms.cmp(&b.created_at_ms)).then_with(|| a.message_id.cmp(&b.message_id)));
        let count = self.db.write_tx(|tx| {
            let mut count = 0;
            for row in &rows {
                if let Some(existing) = tx.get_message(&row.message_id)? {
                    if existing.conversation_id != row.conversation_id || existing.seq != row.seq || existing.epoch != row.epoch || existing.sender_did != row.sender_did || existing.plaintext_json != row.plaintext_json {
                        return Err(MLSError::Cryptography("owner history conflicts with local message".into()));
                    }
                    continue;
                }
                let mut row = row.clone(); row.is_own = row.sender_did == self.normalized_did;
                tx.insert_message(&row)?; count += 1;
                // Already archived for this account: a later flush must not seal it again.
                let frame = serde_json::to_vec(&row).map_err(|e| MLSError::Internal(e.to_string()))?;
                let digest: [u8; 32] = Sha256::digest(&frame).into();
                tx.put_labyrinth_state(&format!("native.owner:{conversation_id}:{}", row.message_id), &digest, self.hooks.now_ms())?;
            }
            // History never advances the live cursor. A restored archive is not MLS state.
            if tx.get_conversation(conversation_id)?.is_none() {
                if let Some(row) = rows.last() {
                    tx.upsert_conversation(&ConversationRow {
                        conversation_id: conversation_id.into(), group_id: row.group_id.clone(), generation: 0, epoch: row.epoch, last_seq: 0,
                        sequencer_did: self.config.home_ds_did.clone(), space_uri: None, title: None, unread_count: 0, updated_at_ms: self.hooks.now_ms(),
                    })?;
                }
            }
            Ok(count)
        })?;
        if count > 0 {
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            self.notify(PlatformChangeEvent::MessagesUpdated { conversation_id: conversation_id.into() });
        }
        Ok(count)
    }

    fn rotate_native_archive(&self, target_device_id: Option<&str>) -> Result<u64, MLSError> {
        if self.canonical_uuid_v4_device_id().is_none() {
            let now_ms = self.hooks.now_ms();
            let key: Option<[u8; 32]> = target_device_id.and_then(|id| hex::decode(id.trim()).ok()?.as_slice().try_into().ok());
            if let Some((remote_seq, remote_root)) = self.rotate_mailbox_epoch_if_supported(key.as_ref(), now_ms)? {
                self.db.write_tx(|tx| tx.put_labyrinth_state(&owner_epoch_root_key(remote_seq), remote_root.as_slice(), now_ms))?;
                return Ok(remote_seq);
            }
            let next_seq = self.labyrinth_status()?.epoch_seq.saturating_add(1);
            self.db.write_tx(|tx| { let _ = ensure_owner_epoch_root(tx, next_seq, now_ms, &self.hooks)?; Ok(()) })?;
            return Ok(next_seq);
        }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        let key: Option<[u8; 32]> = target_device_id.and_then(|id| hex::decode(id.trim()).ok()?.as_slice().try_into().ok());
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
                pds: None,
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
