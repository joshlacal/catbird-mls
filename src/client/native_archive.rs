use std::future::Future;

// Native adapters for the shared, verified Labyrinth session. Included in native_client.
const PENDING_DEVICE_ACTIVATION_REFRESH_STATE: &str =
    "pending_device_activation_refresh";

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
#[derive(Clone)]
struct VerifiedArchiveRecord {
    collection: String,
    rkey: String,
    cid: String,
    value: serde_json::Value,
}

#[cfg(feature = "labyrinth")]
#[derive(Clone, Default)]
struct VerifiedArchiveInventory {
    writers: std::collections::BTreeMap<String, Vec<VerifiedArchiveRecord>>,
}

#[cfg(feature = "labyrinth")]
struct NativeArchiveGateway {
    config: CatbirdMlsClientConfig,
    db: Arc<MlsAccountDb>,
    transport: Arc<dyn PlatformTransport>,
    signer: Arc<NativeArchiveSigner>,
    hooks: crate::sim_hooks::SimClientHooks,
    verified_inventories:
        Mutex<std::collections::BTreeMap<String, VerifiedArchiveInventory>>,
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
    async fn submit_canonical(
        &self,
        request: crate::orchestrator::canonical_transport::PreparedRequest,
        extra_headers: Vec<(String, String)>,
    ) -> Result<crate::orchestrator::canonical_transport::GatewayResponse, String> {
        // These directory requests contain only canonical DID/UUID coordinates.
        // Sort the already-percent-encoded pairs exactly like chat read signing.
        let mut query: Vec<&str> = request.path.split_once('?').map(|(_, q)| q.split('&').collect()).unwrap_or_default();
        query.sort_unstable();
        let query = query.join("&");
        let mut headers = super::chat_wire::build_chat_read_headers(
            request.operation.nsid(), &query, &self.config.account_did,
            &self.config.device_id, &self.signer.0, self.hooks.now_ms(),
        ).map_err(|e| e.to_string())?.into_iter().map(|h| (h.name, h.value)).collect::<Vec<_>>();
        headers.extend(extra_headers);
        self.execute(&self.config.home_ds_endpoint, request.method, request.path, headers, request.body).map(Self::response)
    }
    async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
        // The crate's one strict resolver: PLC directory or the `did:web` host, never an
        // account PDS, sharing the provenance-tagged `did_doc:` cache with the live plane.
        if !self.db.is_open() { return Err("native_archive_context_closed".into()); }
        let resolved = super::did_resolution::resolve_did_document_strict(
            &self.db,
            self.transport.as_ref(),
            self.hooks.now_ms(),
            did,
        )
        .map_err(|e| e.to_string());
        if !self.db.is_open() { return Err("native_archive_context_closed".into()); }
        resolved
    }
}

#[cfg(feature = "labyrinth")]
#[async_trait::async_trait]
impl crate::labyrinth::LabyrinthSpaceGateway for NativeArchiveGateway {
    fn authenticates_responses(&self) -> bool {
        true
    }
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

    fn peer_mailbox_keys_json(
        &self,
        did: &str,
        rkey: &str,
    ) -> labyrinth::Result<serde_json::Value> {
        const NSID: &str = "blue.catbird.labyrinth.getMailboxKeysRecord";
        let query = format!(
            "did={}&rkey={}",
            super::chat_wire::urlencode_form_component(did),
            super::chat_wire::urlencode_form_component(rkey),
        );
        let mut headers = super::chat_wire::build_chat_read_headers(
            NSID,
            &query,
            &self.config.account_did,
            &self.config.device_id,
            &self.signer.0,
            self.hooks.now_ms(),
        )
        .map_err(|e| labyrinth::Error::Backend(e.to_string()))?
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect::<Vec<_>>();
        let claim = crate::labyrinth::write_auth::ReadClaim::new(
            NSID,
            &[("did", did.to_owned()), ("rkey", rkey.to_owned())],
            &self.config.account_did,
            &self.config.device_id,
            self.hooks.now_ms().max(0) as u64,
        );
        let claim_json = claim.to_json();
        let signature = crate::labyrinth::ChatKeySigner::sign(
            self.signer.as_ref(),
            &crate::labyrinth::write_auth::ReadClaim::signing_input(&claim_json),
        )
        .map_err(labyrinth::Error::Backend)?;
        headers.extend(crate::labyrinth::write_auth::read_headers(
            &claim_json,
            &signature,
        ));
        let response = crate::labyrinth::transport::decode_response_bounded(
            self.execute(
                &self.config.home_ds_endpoint,
                "GET".into(),
                format!("/xrpc/{NSID}?{query}"),
                headers,
                None,
            )
            .map(Self::response),
            crate::labyrinth::transport::MAX_LABYRINTH_XRPC_RESPONSE_BYTES,
        )
        .map_err(|error| {
            if matches!(error.status, 400 | 404)
                && error.error.as_deref() == Some("RecordNotFound")
            {
                labyrinth::Error::NotFound("record")
            } else {
                crate::labyrinth::transport::map_xrpc_error(error)
            }
        })?;
        serde_json::from_slice(&response)
            .map_err(|_| labyrinth::Error::Malformed("mailboxKeys relay response"))
    }

    fn verify_peer_mailbox_keys_car_proof(
        &self,
        did: &str,
        rkey: &str,
        response: &serde_json::Value,
        expected_cid: &str,
    ) -> labyrinth::Result<()> {
        let doc = self
            .space_document(did)
            .map_err(labyrinth::Error::Backend)?;
        let Some(ref atproto_key) = doc.atproto_key else {
            return Err(labyrinth::Error::BadSignature);
        };
        let inline_proof = response
            .get("proof")
            .and_then(|p| p.as_str().or_else(|| p.get("$bytes").and_then(|b| b.as_str())));
        let car_bytes = if let Some(b64) = inline_proof {
            BASE64_STANDARD
                .decode(b64)
                .map_err(|_| labyrinth::Error::Malformed("mailboxKeys inline CAR proof"))?
        } else {
            let path = format!(
                "/xrpc/com.atproto.sync.getRecord?did={}&collection={}&rkey={}",
                super::chat_wire::urlencode_form_component(did),
                labyrinth::records::nsid::MAILBOX_KEYS,
                super::chat_wire::urlencode_form_component(rkey),
            );
            let pds = doc
                .pds_endpoint()
                .map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
            let car_resp = self
                .execute(pds, "GET".into(), path, vec![], None)
                .map_err(labyrinth::Error::Backend)?;
            if car_resp.status >= 400 {
                return Err(labyrinth::Error::BadSignature);
            }
            car_resp.body
        };
        let record_val = response
            .get("value")
            .ok_or(labyrinth::Error::Malformed("getRecord missing value"))?;
        let (_, commit_rev) = crate::labyrinth::repo_proof::verify_car_record_json_match_with_rev(
            &car_bytes,
            did,
            labyrinth::records::nsid::MAILBOX_KEYS,
            rkey,
            Some(expected_cid),
            record_val,
            atproto_key,
        )
        .map_err(|_| labyrinth::Error::BadSignature)?;
        crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
            &self.db,
            did,
            &commit_rev,
            self.hooks.now_ms(),
        )
        .map_err(|_| labyrinth::Error::BadSignature)
    }
}

#[cfg(feature = "labyrinth")]
fn parse_mailbox_keys_record(
    response: &serde_json::Value,
    did: &str,
    rkey: &str,
) -> labyrinth::Result<(Vec<u8>, String)> {
    let expected_uri = format!(
        "at://{did}/{}/{rkey}",
        labyrinth::records::nsid::MAILBOX_KEYS
    );
    if response["uri"].as_str() != Some(expected_uri.as_str()) {
        return Err(labyrinth::Error::Malformed(
            "mailboxKeys relay URI binding",
        ));
    }
    let cid = response["cid"]
        .as_str()
        .filter(|cid| !cid.is_empty())
        .ok_or(labyrinth::Error::Malformed("getRecord missing CID"))?
        .to_owned();
    let value = response
        .get("value")
        .ok_or(labyrinth::Error::Malformed("getRecord missing value"))?;
    let bytes =
        serde_json::to_vec(value).map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
    crate::labyrinth::transport::enforce_pds_record_cap(&bytes)
        .map_err(labyrinth::Error::Backend)?;
    Ok((bytes, cid))
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
        let response = if did == self.config.account_did {
            let path = format!("/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
                super::chat_wire::urlencode_form_component(did), labyrinth::records::nsid::MAILBOX_KEYS,
                super::chat_wire::urlencode_form_component(rkey));
            match self.pds_json(&self.config.pds_endpoint, "GET", path, None) {
                Ok(value) => value,
                Err(labyrinth::Error::NotFound("record")) => return Ok(None),
                Err(error) => return Err(error),
            }
        } else {
            let value = match self.peer_mailbox_keys_json(did, rkey) {
                Ok(value) => value,
                Err(labyrinth::Error::NotFound("record")) => return Ok(None),
                Err(error) => return Err(error),
            };
            let parsed = parse_mailbox_keys_record(&value, did, rkey)?;
            self.verify_peer_mailbox_keys_car_proof(did, rkey, &value, &parsed.1)?;
            return Ok(Some(parsed));
        };
        parse_mailbox_keys_record(&response, did, rkey).map(Some)
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

/// Marks a conversation Space refusal that is not the authority's verified signed denial.
#[cfg(feature = "labyrinth")]
const NATIVE_UNAUTHENTICATED_DENIAL: &str = "native_space_unauthenticated_denial";

#[cfg(feature = "labyrinth")]
fn native_archive_error(error: crate::orchestrator::error::OrchestratorError) -> MLSError {
    let message = error.to_string();
    if message.contains("native_archive_context_closed") {
        return MLSError::ContextClosed;
    }
    // An unproven refusal proves no removal: the restore waits for the authority's signed denial.
    if message.contains(NATIVE_UNAUTHENTICATED_DENIAL) {
        return MLSError::InvalidState("ArchiveRestorePending".into());
    }
    if message.contains("WriterRollback:") || message.contains("space writer revision rolled back for ") {
        return MLSError::Cryptography(message);
    }
    match error {
        crate::orchestrator::error::OrchestratorError::Mls(MLSError::ContextClosed) => MLSError::ContextClosed,
        crate::orchestrator::error::OrchestratorError::InvalidInput(m) => MLSError::invalid_input(m),
        other => MLSError::Internal(other.to_string()),
    }
}

/// Maps an owner-archive failure: invalid evidence for the messages themselves
/// (frame, nonce, receipt, attestation) is `Cryptography`; a transport, directory
/// or store failure keeps its retryable class.
#[cfg(feature = "labyrinth")]
fn owner_archive_error(error: labyrinth::Error) -> MLSError {
    use labyrinth::Error as E;
    match error {
        E::Decrypt | E::BadSignature | E::BadPublicKey | E::Malformed(_) | E::Unsupported(_)
        | E::ReceiptCommitmentMismatch => MLSError::Cryptography(format!("owner archive: {error}")),
        other => native_archive_error(crate::labyrinth::map_error(other)),
    }
}

/// `labyrinth_state` key: the author unsent `message_id`. No flush or kick rescue
/// archives it again, from the queue or from cached evidence.
#[cfg(feature = "labyrinth")]
fn unsent_message_key(conversation_id: &str, message_id: &str) -> String {
    format!("native.unsent:{conversation_id}:{message_id}")
}

/// This device's MLS groups: the independent authority `mls-ds` member-device
/// answers are cross-checked against.
#[cfg(feature = "labyrinth")]
struct NativeLocalAuthority {
    db: Arc<MlsAccountDb>,
    hooks: crate::sim_hooks::SimClientHooks,
    account_did: String,
    gateway: Arc<NativeArchiveGateway>,
    tombstoned_pds_dids: Mutex<std::collections::BTreeSet<String>>,
    preverified_deleted_dids: std::collections::BTreeMap<String, u64>,
}

#[cfg(feature = "labyrinth")]
type NativeLocalGroup = (Vec<u8>, u64, i64, Vec<(String, Vec<u8>)>);

#[cfg(feature = "labyrinth")]
impl NativeLocalAuthority {
    fn is_pds_repo_tombstone_response(status: u16, body: &[u8]) -> bool {
        if !matches!(status, 400 | 404) {
            return false;
        }
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .is_some_and(|code| matches!(code.as_str(), "RepoNotFound" | "RepoTakendown"))
    }

    fn is_pds_repo_tombstoned_sync(&self, did: &str) -> bool {
        self.tombstoned_pds_dids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(did)
    }

    fn verified_deleted_ms_sync(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<u64>> {
        let key = super::deletion_authority::verified_deleted_account_key(did);
        let db_ms = self
            .db
            .read_tx(|tx| tx.get_account_meta(&key))
            .map_err(crate::orchestrator::error::OrchestratorError::Mls)?
            .and_then(|raw| raw.parse::<i64>().ok())
            .map(|ms| u64::try_from(ms.max(0)).unwrap_or(0));
        let pre_ms = self.preverified_deleted_dids.get(did).copied();
        Ok(match (db_ms, pre_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        })
    }

    /// `(group id, MLS epoch, last applied entry seq, leaves as (root DID, signing key))`.
    fn group(&self, conversation_id: &str) -> crate::orchestrator::error::Result<Option<NativeLocalGroup>> {
        let group = self.db.read_tx(|tx| {
            let Some(convo) = tx.get_conversation(conversation_id)? else { return Ok(None) };
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let Some(group) = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
            else {
                return Ok(None);
            };
            let leaves = group
                .members()
                .map(|member| {
                    crate::push::root_did_from_credential_bytes(member.credential.serialized_content())
                        .map(|(did, _)| (did, member.signature_key))
                })
                .collect::<Result<Vec<_>, MLSError>>()?;
            Ok(Some((convo.group_id, group.epoch().as_u64(), convo.last_seq, leaves)))
        });
        group.map_err(crate::orchestrator::error::OrchestratorError::Mls)
    }
    fn paginate_pds_collection(
        &self,
        pds_endpoint: &str,
        did: &str,
        collection: &str,
        allow_not_found: bool,
    ) -> crate::orchestrator::error::Result<Option<Vec<serde_json::Value>>> {
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut all_records = Vec::new();
        for page_idx in 0..super::chat_wire::MAX_PDS_LIST_RECORDS_PAGES {
            let mut path = format!(
                "/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit={}",
                super::chat_wire::urlencode_form_component(did),
                super::chat_wire::urlencode_form_component(collection),
                super::chat_wire::PDS_LIST_RECORDS_PAGE_LIMIT,
            );
            if let Some(ref c) = cursor {
                path.push_str(&format!(
                    "&cursor={}",
                    super::chat_wire::urlencode_form_component(c)
                ));
            }
            let resp = self
                .gateway
                .execute(pds_endpoint, "GET".into(), path, vec![], None)
                .map_err(crate::orchestrator::error::OrchestratorError::Credential)?;
            if page_idx == 0 && Self::is_pds_repo_tombstone_response(resp.status, &resp.body) {
                self.tombstoned_pds_dids
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(did.to_owned());
                return Ok(None);
            }
            if page_idx == 0 && allow_not_found && resp.status == 404 {
                return Ok(None);
            }
            if resp.status >= 400 {
                return Err(crate::orchestrator::error::OrchestratorError::Credential(
                    format!(
                        "PDS listRecords({did}, {collection}) failed with HTTP {}",
                        resp.status
                    ),
                ));
            }
            let (page_records, next_cursor) =
                super::chat_wire::parse_pds_list_records_page(did, collection, &resp.body)
                    .map_err(crate::orchestrator::error::OrchestratorError::Mls)?;
            all_records.extend(page_records);
            if all_records.len() > super::chat_wire::MAX_PDS_LIST_RECORDS_ITEMS {
                return Err(crate::orchestrator::error::OrchestratorError::Credential(
                    format!(
                        "PDS listRecords({did}, {collection}) exceeded {} record ceiling",
                        super::chat_wire::MAX_PDS_LIST_RECORDS_ITEMS
                    ),
                ));
            }
            match next_cursor {
                None => return Ok(Some(all_records)),
                Some(next) => {
                    if !seen_cursors.insert(next.clone()) {
                        return Err(crate::orchestrator::error::OrchestratorError::Credential(
                            format!(
                                "PDS listRecords({did}, {collection}) repeated pagination cursor"
                            ),
                        ));
                    }
                    if page_idx + 1 == super::chat_wire::MAX_PDS_LIST_RECORDS_PAGES {
                        return Err(crate::orchestrator::error::OrchestratorError::Credential(
                            format!(
                                "PDS listRecords({did}, {collection}) truncated past {} pages",
                                super::chat_wire::MAX_PDS_LIST_RECORDS_PAGES
                            ),
                        ));
                    }
                    cursor = Some(next);
                }
            }
        }
        Ok(Some(all_records))
    }

    fn verify_record_car_proof_and_pin_rev(
        &self,
        pds_endpoint: &str,
        did: &str,
        collection: &str,
        rkey: &str,
        record_entry: &serde_json::Value,
        atproto_key: &atproto_spaces::tokens::SpaceVerifyingKey,
    ) -> crate::orchestrator::error::Result<()> {
        let expected_uri = format!("at://{did}/{collection}/{rkey}");
        let expected_cid = record_entry["cid"]
            .as_str()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                crate::orchestrator::error::OrchestratorError::Credential(format!(
                    "missing CID on `{expected_uri}`"
                ))
            })?;
        let record_val = record_entry.get("value").ok_or_else(|| {
            crate::orchestrator::error::OrchestratorError::Credential(format!(
                "missing value on `{expected_uri}`"
            ))
        })?;
        let inline_proof = record_entry.get("proof").and_then(|p| {
            p.as_str()
                .or_else(|| p.get("$bytes").and_then(serde_json::Value::as_str))
        });
        let max_car_bytes = if matches!(
            collection,
            super::deletion_authority::DEVICE_RECORD_COLLECTION
                | super::deletion_authority::DEVICE_REVOCATION_COLLECTION
        ) {
            super::deletion_authority::MAX_REVOCATION_PROOF_BYTES
        } else {
            crate::labyrinth::repo_proof::MAX_CAR_ARCHIVE_BYTES
        };
        let car_bytes = if let Some(b64) = inline_proof {
            if b64.len() > max_car_bytes.saturating_mul(2) {
                return Err(crate::orchestrator::error::OrchestratorError::Credential(
                    format!(
                        "inline CAR proof exceeds {max_car_bytes}-byte ceiling on `{expected_uri}`"
                    ),
                ));
            }
            BASE64_STANDARD.decode(b64).map_err(|e| {
                crate::orchestrator::error::OrchestratorError::Credential(format!(
                    "inline CAR proof decode on `{expected_uri}`: {e}"
                ))
            })?
        } else {
            let proof_path = format!(
                "/xrpc/com.atproto.sync.getRecord?did={}&collection={}&rkey={}",
                super::chat_wire::urlencode_form_component(did),
                super::chat_wire::urlencode_form_component(collection),
                super::chat_wire::urlencode_form_component(rkey),
            );
            let proof_resp = self
                .gateway
                .execute(pds_endpoint, "GET".into(), proof_path, vec![], None)
                .map_err(crate::orchestrator::error::OrchestratorError::Credential)?;
            if proof_resp.status >= 400 {
                return Err(crate::orchestrator::error::OrchestratorError::Credential(
                    format!(
                        "CARv1 sync.getRecord(`{expected_uri}`) failed with HTTP {}",
                        proof_resp.status
                    ),
                ));
            }
            proof_resp.body
        };
        if car_bytes.is_empty() || car_bytes.len() > max_car_bytes {
            return Err(crate::orchestrator::error::OrchestratorError::Credential(
                format!(
                    "CARv1 proof on `{expected_uri}` has invalid length {} (limit {max_car_bytes})",
                    car_bytes.len()
                ),
            ));
        }
        let (_, commit_rev) =
            crate::labyrinth::repo_proof::verify_car_record_json_match_with_rev(
                &car_bytes,
                did,
                collection,
                rkey,
                Some(expected_cid),
                record_val,
                atproto_key,
            )
            .map_err(|e| {
                crate::orchestrator::error::OrchestratorError::Credential(format!(
                    "CARv1 repo proof failed for `{expected_uri}`: {e}"
                ))
            })?;
        crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
            &self.db,
            did,
            &commit_rev,
            self.hooks.now_ms(),
        )
        .map_err(|e| {
            crate::orchestrator::error::OrchestratorError::Credential(format!(
                "repository commit rev floor check failed for `{expected_uri}`: {e}"
            ))
        })?;
        Ok(())
    }

    #[cfg(test)]
    fn load_cached_peer_device_keys(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<(Vec<[u8; 32]>, Vec<[u8; 32]>)>> {
        let cached = self
            .db
            .read_tx(|tx| tx.get_account_meta(&format!("authorized_device_keys:{did}")))
            .map_err(crate::orchestrator::error::OrchestratorError::Mls)?;
        let Some(raw) = cached else {
            return Ok(None);
        };
        let items: Vec<AuthorizedPeerDeviceKey> = serde_json::from_str(&raw).map_err(|e| {
            crate::orchestrator::error::OrchestratorError::Credential(format!(
                "decode cached authorized_device_keys: {e}"
            ))
        })?;
        let mut keys = Vec::with_capacity(items.len());
        for item in items {
            if let Ok(key) = <[u8; 32]>::try_from(item.signature_public_key.as_slice()) {
                keys.push(key);
            }
        }
        Ok(Some((keys, Vec::new())))
    }

    async fn fetch_verified_pds_chat_devices_with_times(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<(Vec<[u8; 32]>, Vec<([u8; 32], u64)>)>> {
        use crate::labyrinth::LabyrinthGateway as _;

        let revocation_created_at_ms = |val: &serde_json::Value| -> u64 {
            val.get("createdAt")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map_or(1, |dt| u64::try_from(dt.timestamp_millis().max(1)).unwrap_or(1))
        };

        if did == self.account_did {
            let doc_bytes = self
                .gateway
                .resolve_did_document(did)
                .await
                .map_err(crate::orchestrator::error::OrchestratorError::Credential)?
                .ok_or_else(|| crate::orchestrator::error::OrchestratorError::Credential(
                    format!("DID document not found for own account `{did}`"),
                ))?;
            let parsed_doc =
                atproto_spaces::did_resolver::DidDocument::parse_json(did, &doc_bytes).ok();
            let atproto_key = parsed_doc.as_ref().and_then(|d| d.atproto_key.clone());
            #[cfg(not(test))]
            if atproto_key.is_none() {
                return Err(crate::orchestrator::error::OrchestratorError::Credential(
                    format!("missing #atproto repository signing key in DID document for `{did}`"),
                ));
            }
            let allow_test_fallback = cfg!(test) && atproto_key.is_none();
            let pds_endpoint = super::chat_wire::extract_pds_endpoint_from_did_doc(&doc_bytes, did)
                .ok_or_else(|| crate::orchestrator::error::OrchestratorError::Credential(
                    format!("no #atproto_pds service in the DID document of own account `{did}`"),
                ))?;

            let raw_devices = match self.paginate_pds_collection(
                &pds_endpoint,
                did,
                "blue.catbird.chat.device",
                allow_test_fallback,
            ) {
                Ok(Some(records)) => records,
                Ok(None) => return Ok(None),
                Err(_) if allow_test_fallback => return Ok(None),
                Err(error) => return Err(error),
            };
            let entries = super::chat_wire::parse_pds_device_entries(did, &raw_devices);
            if entries.is_empty() {
                return Ok(None);
            }
            if let Some(ref atproto_key) = atproto_key {
                for (device_id, _, record_entry) in &entries {
                    self.verify_record_car_proof_and_pin_rev(
                        &pds_endpoint,
                        did,
                        "blue.catbird.chat.device",
                        device_id,
                        record_entry,
                        atproto_key,
                    )?;
                }
            }
            let mut enrolled_map = std::collections::BTreeMap::new();
            for (device_id, pk, _) in &entries {
                enrolled_map.insert(device_id.clone(), pk.clone());
            }
            let raw_revocations = self
                .paginate_pds_collection(
                    &pds_endpoint,
                    did,
                    "blue.catbird.chat.deviceRevocation",
                    true,
                )?
                .unwrap_or_default();
            let rev_prefix = format!("at://{did}/blue.catbird.chat.deviceRevocation/");
            let mut revoked_times = std::collections::BTreeMap::<String, u64>::new();
            for rev_entry in &raw_revocations {
                let Some(uri) = rev_entry.get("uri").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(rkey) = uri
                    .strip_prefix(&rev_prefix)
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.contains('/'))
                else {
                    continue;
                };
                let Some(record_val) = rev_entry.get("value") else {
                    return Err(crate::orchestrator::error::OrchestratorError::Credential(
                        format!("missing value on `{uri}`"),
                    ));
                };
                if let Some(ref atproto_key) = atproto_key {
                    self.verify_record_car_proof_and_pin_rev(
                        &pds_endpoint,
                        did,
                        "blue.catbird.chat.deviceRevocation",
                        rkey,
                        rev_entry,
                        atproto_key,
                    )?;
                }
                let target_id = super::chat_wire::verify_pds_device_revocation_record(
                    did,
                    rkey,
                    record_val,
                    &enrolled_map,
                )
                .map_err(crate::orchestrator::error::OrchestratorError::Mls)?;
                let raw_ms = revocation_created_at_ms(record_val);
                let at_ms = if super::deletion_authority::is_valid_self_deletion_revocation_record(
                    record_val,
                    &target_id,
                ) {
                    super::deletion_authority::self_deletion_archive_revocation_bound_ms(raw_ms)
                } else {
                    raw_ms
                };
                revoked_times
                    .entry(target_id)
                    .and_modify(|prev| *prev = (*prev).min(at_ms))
                    .or_insert(at_ms);
            }
            let mut active = Vec::new();
            let mut revoked = Vec::new();
            for (device_id, pk, _) in entries {
                if let Ok(key) = <[u8; 32]>::try_from(pk.as_slice()) {
                    if let Some(&at_ms) = revoked_times.get(&device_id) {
                        revoked.push((key, at_ms));
                    } else {
                        active.push(key);
                    }
                }
            }
            return Ok(Some((active, revoked)));
        }

        let doc_opt = self
            .gateway
            .resolve_did_document(did)
            .await
            .map_err(crate::orchestrator::error::OrchestratorError::Credential)?;
        let Some(doc_bytes) = doc_opt else {
            #[cfg(test)]
            {
                return Ok(self
                    .load_cached_peer_device_keys(did)?
                    .map(|(active, revoked)| (active, revoked.into_iter().map(|k| (k, 1)).collect())));
            }
            #[cfg(not(test))]
            {
                return Err(crate::orchestrator::error::OrchestratorError::Credential(
                    format!("DID document not found for peer `{did}`"),
                ));
            }
        };
        let parsed_doc =
            atproto_spaces::did_resolver::DidDocument::parse_json(did, &doc_bytes).ok();
        let atproto_key = parsed_doc.as_ref().and_then(|d| d.atproto_key.clone());
        #[cfg(not(test))]
        if atproto_key.is_none() {
            return Err(crate::orchestrator::error::OrchestratorError::Credential(
                format!("missing #atproto repository signing key in DID document for `{did}`"),
            ));
        }
        // Another account's records come only from the PDS its own DID document names.
        let pds_endpoint = super::chat_wire::extract_pds_endpoint_from_did_doc(&doc_bytes, did)
            .ok_or_else(|| {
                crate::orchestrator::error::OrchestratorError::Credential(format!(
                    "no #atproto_pds service in the DID document of peer `{did}`"
                ))
            })?;

        let allow_test_fallback = cfg!(test) && atproto_key.is_none();
        let raw_devices = match self.paginate_pds_collection(
            &pds_endpoint,
            did,
            "blue.catbird.chat.device",
            allow_test_fallback,
        )? {
            Some(records) => records,
            None => {
                if self.is_pds_repo_tombstoned_sync(did)
                    || self.verified_deleted_ms_sync(did)?.is_some()
                {
                    return Ok(None);
                }
                #[cfg(test)]
                {
                    return Ok(self
                        .load_cached_peer_device_keys(did)?
                        .map(|(active, revoked)| (active, revoked.into_iter().map(|k| (k, 1)).collect())));
                }
                #[cfg(not(test))]
                {
                    return Err(crate::orchestrator::error::OrchestratorError::Credential(
                        format!("peer PDS chat.device listRecords({did}) returned 404"),
                    ));
                }
            }
        };
        let entries = super::chat_wire::parse_pds_device_entries(did, &raw_devices);
        if entries.is_empty() {
            if self.is_pds_repo_tombstoned_sync(did) || self.verified_deleted_ms_sync(did)?.is_some() {
                return Ok(None);
            }
            return Err(crate::orchestrator::error::OrchestratorError::Credential(
                format!("peer PDS holds zero valid chat.device records for `{did}`"),
            ));
        }
        if let Some(ref atproto_key) = atproto_key {
            for (device_id, _, record_entry) in &entries {
                self.verify_record_car_proof_and_pin_rev(
                    &pds_endpoint,
                    did,
                    "blue.catbird.chat.device",
                    device_id,
                    record_entry,
                    atproto_key,
                )?;
            }
        }
        let mut enrolled_map = std::collections::BTreeMap::new();
        for (device_id, pk, _) in &entries {
            enrolled_map.insert(device_id.clone(), pk.clone());
        }
        let raw_revocations = self
            .paginate_pds_collection(
                &pds_endpoint,
                did,
                "blue.catbird.chat.deviceRevocation",
                allow_test_fallback,
            )?
            .unwrap_or_default();
        let rev_prefix = format!("at://{did}/blue.catbird.chat.deviceRevocation/");
        let mut revoked_times = std::collections::BTreeMap::<String, u64>::new();
        for rev_entry in &raw_revocations {
            let Some(uri) = rev_entry.get("uri").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Some(rkey) = uri
                .strip_prefix(&rev_prefix)
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.contains('/'))
            else {
                continue;
            };
            let Some(record_val) = rev_entry.get("value") else {
                return Err(crate::orchestrator::error::OrchestratorError::Credential(
                    format!("missing value on `{uri}`"),
                ));
            };
            if let Some(ref atproto_key) = atproto_key {
                self.verify_record_car_proof_and_pin_rev(
                    &pds_endpoint,
                    did,
                    "blue.catbird.chat.deviceRevocation",
                    rkey,
                    rev_entry,
                    atproto_key,
                )?;
            }
            let target_id = super::chat_wire::verify_pds_device_revocation_record(
                did,
                rkey,
                record_val,
                &enrolled_map,
            )
            .map_err(crate::orchestrator::error::OrchestratorError::Mls)?;
            let raw_ms = revocation_created_at_ms(record_val);
            let at_ms = if super::deletion_authority::is_valid_self_deletion_revocation_record(
                record_val,
                &target_id,
            ) {
                super::deletion_authority::self_deletion_archive_revocation_bound_ms(raw_ms)
            } else {
                raw_ms
            };
            revoked_times
                .entry(target_id)
                .and_modify(|prev| *prev = (*prev).min(at_ms))
                .or_insert(at_ms);
        }
        let mut active = Vec::new();
        let mut revoked = Vec::new();
        for (device_id, pk, _) in entries {
            if let Ok(key) = <[u8; 32]>::try_from(pk.as_slice()) {
                if let Some(&at_ms) = revoked_times.get(&device_id) {
                    revoked.push((key, at_ms));
                } else {
                    active.push(key);
                }
            }
        }
        Ok(Some((active, revoked)))
    }

    async fn fetch_verified_pds_chat_devices(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<(Vec<[u8; 32]>, Vec<[u8; 32]>)>> {
        Ok(self
            .fetch_verified_pds_chat_devices_with_times(did)
            .await?
            .map(|(active, revoked)| (active, revoked.into_iter().map(|(k, _)| k).collect())))
    }
}

#[cfg(feature = "labyrinth")]
#[async_trait::async_trait]
impl crate::labyrinth::session::LocalConversationAuthority for NativeLocalAuthority {
    async fn current_group_snapshot(
        &self,
        conversation_id: &str,
        _queued_group_id_hex: Option<&str>,
    ) -> crate::orchestrator::error::Result<Option<crate::labyrinth::session::LocalGroupSnapshot>> {
        let Some((group_id, epoch, _, leaves)) = self.group(conversation_id)? else { return Ok(None) };
        let mut member_dids: Vec<String> = leaves.into_iter().map(|(did, _)| did).collect();
        member_dids.sort();
        member_dids.dedup();
        Ok(Some(crate::labyrinth::session::LocalGroupSnapshot { group_id_hex: hex::encode(group_id), epoch, member_dids }))
    }

    async fn leaf_keys(
        &self,
        conversation_id: &str,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<crate::labyrinth::session::LocalLeafKeys>> {
        let Some((_, _, applied, leaves)) = self.group(conversation_id)? else { return Ok(None) };
        // A group that applied no entry, or that this account is no longer in, is no live view.
        let applied_chat_seq = u64::try_from(applied).unwrap_or(0);
        if applied_chat_seq == 0 || !leaves.iter().any(|(member, _)| *member == self.account_did) {
            return Ok(None);
        }
        let keys = leaves
            .into_iter()
            .filter(|(member, _)| member == did)
            .map(|(_, key)| {
                <[u8; 32]>::try_from(key.as_slice()).map_err(|_| {
                    crate::orchestrator::error::OrchestratorError::Credential(
                        "MLS leaf signing key is not Ed25519".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(crate::labyrinth::session::LocalLeafKeys { applied_chat_seq, keys }))
    }

    async fn authorized_chat_device_keys(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<Vec<[u8; 32]>>> {
        if did == self.account_did {
            return Ok(None);
        }
        let Some((active, revoked)) = self.fetch_verified_pds_chat_devices(did).await? else {
            return Ok(None);
        };
        if active.is_empty() && revoked.is_empty() {
            return Err(crate::orchestrator::error::OrchestratorError::Credential(
                format!("peer PDS holds zero valid chat.device records for `{did}`"),
            ));
        }
        Ok(Some(active))
    }

    async fn revoked_chat_device_keys(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Vec<[u8; 32]>> {
        Ok(self
            .fetch_verified_pds_chat_devices(did)
            .await?
            .map(|(_, revoked)| revoked)
            .unwrap_or_default())
    }

    async fn revoked_chat_device_keys_with_times(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Vec<([u8; 32], u64)>> {
        Ok(self
            .fetch_verified_pds_chat_devices_with_times(did)
            .await?
            .map(|(_, revoked)| revoked)
            .unwrap_or_default())
    }

    async fn shared_group_leaf_keys(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<Vec<[u8; 32]>>> {
        if did == self.account_did {
            return Ok(None);
        }
        // Snapshot IDs in one read transaction; display pagination is intentionally capped.
        let conversation_ids = super::all_local_conversation_ids(&self.db)
            .map_err(crate::orchestrator::error::OrchestratorError::Mls)?;
        let mut shared = std::collections::BTreeSet::new();
        let mut saw_live_shared_group = false;
        for conversation_id in conversation_ids {
            let Some((_, _, applied, leaves)) = self.group(&conversation_id)? else {
                continue;
            };
            if applied <= 0 || !leaves.iter().any(|(m, _)| *m == self.account_did) {
                continue;
            }
            let mut peer_present = false;
            for (member, key) in leaves {
                if member == did {
                    peer_present = true;
                    let k: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                        crate::orchestrator::error::OrchestratorError::Credential(
                            "MLS leaf signing key is not Ed25519".into(),
                        )
                    })?;
                    shared.insert(k);
                }
            }
            if peer_present {
                saw_live_shared_group = true;
            }
        }
        if !saw_live_shared_group {
            return Ok(None);
        }
        Ok(Some(shared.into_iter().collect()))
    }

    async fn verified_deleted_account_ms(
        &self,
        did: &str,
    ) -> crate::orchestrator::error::Result<Option<u64>> {
        self.verified_deleted_ms_sync(did)
    }

    async fn is_pds_repo_tombstoned(&self, did: &str) -> crate::orchestrator::error::Result<bool> {
        Ok(self.is_pds_repo_tombstoned_sync(did))
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
    pub(crate) original_sender_attestation_json: Option<String>,
    pub(crate) created_at_ms: i64,
}

#[cfg(feature = "labyrinth")]
impl NativeArchiveEvidence {
    fn from_queue(item: &QueuedLabyrinthArchivePayload) -> Self {
        Self {
            message_id: item.message_id.clone(),
            conversation_id: item.conversation_id.clone(),
            labyrinth_frame_json: item.labyrinth_frame_json.clone(),
            frame_nonce_b64: item.frame_nonce_b64.clone(),
            sequencer_receipt_json: item.sequencer_receipt_json.clone(),
            original_sender_attestation_json: item
                .original_sender_attestation_json
                .clone(),
            created_at_ms: item.created_at_ms,
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
            original_sender_attestation: Some(
                crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope::from_labyrinth(
                    &archived.original_sender_attestation,
                ),
            ),
        };
        let evidence = NativeArchiveEvidence {
            message_id: row.message_id.clone(), conversation_id: conversation_id.into(), labyrinth_frame_json: row.plaintext_json.clone(),
            frame_nonce_b64: Some(BASE64_STANDARD.encode(nonce)),
            sequencer_receipt_json: Some(serde_json::to_string(&stored).map_err(|e| MLSError::Internal(e.to_string()))?),
            original_sender_attestation_json: Some(
                serde_json::to_string(
                    stored
                        .original_sender_attestation
                        .as_ref()
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "archive copy missing original sender attestation".into(),
                            )
                        })?,
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            ),
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
/// resolved from the archive, so restore skips that id instead of failing. A local undecryptable
/// gap row (`local_gap`, its `native.undecryptable` evidence present) holds no plaintext: the one
/// copy at its exact sequenced coordinates replaces it.
#[cfg(feature = "labyrinth")]
fn select_restore_copy<'a>(copies: &'a [RestoreCopy], local: Option<&MessageRow>, local_gap: bool) -> Option<&'a RestoreCopy> {
    let Some(local) = local else {
        return match copies {
            [only] => Some(only),
            _ => None,
        };
    };
    let mut matching = copies.iter().filter(|(row, _, _)| {
        local.conversation_id == row.conversation_id
            && local.group_id == row.group_id
            && local.seq == row.seq
            && local.epoch == row.epoch
            && local.sender_did == row.sender_did
            && local.sender_device_id == row.sender_device_id
            && (local_gap
                || super::chat_wire::archive_frame_matches_local_plaintext(
                    &local.plaintext_json,
                    &row.plaintext_json,
                ))
    });
    let first = matching.next()?;
    (!local_gap || matching.next().is_none()).then_some(first)
}

#[cfg(feature = "labyrinth")]
fn unavailable_placeholder_matches_restore_copy(
    conversation_id: &str,
    placeholder: &MessageRow,
    unavailable: &super::chat_wire::UnavailableEntryEvidence,
    copy: &RestoreCopy,
) -> Result<bool, MLSError> {
    let (row, _, receipt) = copy;
    let Some(seq) = u64::try_from(unavailable.seq).ok() else {
        return Ok(false);
    };
    let Some(epoch) = u64::try_from(unavailable.epoch).ok() else {
        return Ok(false);
    };
    let Some(generation) = u64::try_from(unavailable.generation).ok() else {
        return Ok(false);
    };
    if unavailable.version != 1
        || unavailable.reason != super::chat_wire::PAYLOAD_PRUNED_REASON
        || unavailable.conversation_id != conversation_id
        || unavailable.message_id != unavailable.entry_id
        || unavailable.entry_id != receipt.entry_id
        || seq != receipt.seq
        || epoch != receipt.epoch
        || generation != receipt.generation
        || row.conversation_id != conversation_id
        || row.group_id != receipt.group_id
        || row.seq != unavailable.seq
        || row.epoch != unavailable.epoch
        || row.sender_did != unavailable.sender_did
        || row.sender_device_id != unavailable.sender_device_id
        || receipt.conversation_id != conversation_id
        || receipt.sender_device_did_url
            != format!(
                "{}#{}",
                unavailable.sender_did, unavailable.sender_device_id
            )
        || unavailable.placeholder_row(&receipt.group_id, placeholder.is_own)? != *placeholder
    {
        return Ok(false);
    }

    let wire = &unavailable.receipt;
    if wire.get("sequencerDid").and_then(serde_json::Value::as_str)
        != Some(receipt.sequencer_did.as_str())
        || wire.get("conversationId").and_then(serde_json::Value::as_str)
            != Some(receipt.conversation_id.as_str())
        || wire.get("generation").and_then(serde_json::Value::as_u64)
            != Some(receipt.generation)
        || super::chat_wire::json_bytes(
            wire.get("groupId")
                .ok_or_else(|| MLSError::Cryptography("unavailable receipt missing groupId".into()))?,
        )? != receipt.group_id
        || wire.get("epoch").and_then(serde_json::Value::as_u64) != Some(receipt.epoch)
        || wire.get("seq").and_then(serde_json::Value::as_u64) != Some(receipt.seq)
        || wire.get("entryId").and_then(serde_json::Value::as_str)
            != Some(receipt.entry_id.as_str())
        || wire.get("senderDid").and_then(serde_json::Value::as_str)
            != Some(unavailable.sender_did.as_str())
        || wire.get("senderDeviceId").and_then(serde_json::Value::as_str)
            != Some(unavailable.sender_device_id.as_str())
        || super::chat_wire::json_bytes(
            wire.get("archiveCommitment").ok_or_else(|| {
                MLSError::Cryptography("unavailable receipt missing archiveCommitment".into())
            })?,
        )? != receipt.archive_commitment
        || wire.get("issuedAtMs").and_then(serde_json::Value::as_i64)
            != Some(receipt.issued_at_ms)
        || wire.get("kid").and_then(serde_json::Value::as_str)
            != Some(receipt.key_id.as_str())
        || super::chat_wire::json_bytes(
            wire.get("signature").ok_or_else(|| {
                MLSError::Cryptography("unavailable receipt missing signature".into())
            })?,
        )? != receipt.signature
    {
        return Ok(false);
    }

    let commitment: [u8; 32] = receipt
        .archive_commitment
        .as_slice()
        .try_into()
        .map_err(|_| MLSError::Cryptography("archive commitment must be 32 bytes".into()))?;
    let attestation = receipt
        .original_sender_attestation
        .as_ref()
        .ok_or_else(|| {
            MLSError::Cryptography("archive copy missing original sender attestation".into())
        })?;
    if attestation.sender_did != row.sender_did
        || attestation.sender_device_id != row.sender_device_id
    {
        return Ok(false);
    }
    attestation.verify(conversation_id, &row.message_id, &commitment)?;
    Ok(true)
}

#[cfg(feature = "labyrinth")]
fn bound_unavailable_placeholder(
    tx: &crate::storage::SqlTx<'_>,
    conversation_id: &str,
    copies: &[RestoreCopy],
) -> Result<Option<(MessageRow, String)>, MLSError> {
    let [copy] = copies else {
        return Ok(None);
    };
    let evidence_key =
        super::chat_wire::unavailable_message_key(conversation_id, &copy.2.entry_id);
    let Some(raw) = tx.get_labyrinth_state(&evidence_key)? else {
        return Ok(None);
    };
    let unavailable: super::chat_wire::UnavailableEntryEvidence =
        serde_json::from_slice(&raw).map_err(|_| {
            MLSError::Cryptography("invalid unavailable-entry evidence".into())
        })?;
    let Some(placeholder) = tx.get_message(&unavailable.message_id)? else {
        return Ok(None);
    };
    if unavailable_placeholder_matches_restore_copy(
        conversation_id,
        &placeholder,
        &unavailable,
        copy,
    )? {
        Ok(Some((placeholder, evidence_key)))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "labyrinth")]
fn is_stored_unavailable_placeholder(
    tx: &crate::storage::SqlTx<'_>,
    conversation_id: &str,
    row: &MessageRow,
) -> Result<bool, MLSError> {
    let key = super::chat_wire::unavailable_message_key(conversation_id, &row.message_id);
    let Some(raw) = tx.get_labyrinth_state(&key)? else {
        return Ok(false);
    };
    let evidence: super::chat_wire::UnavailableEntryEvidence =
        serde_json::from_slice(&raw).map_err(|_| {
            MLSError::Cryptography("invalid unavailable-entry evidence".into())
        })?;
    let group_id = super::chat_wire::json_bytes(
        evidence
            .receipt
            .get("groupId")
            .ok_or_else(|| MLSError::Cryptography("unavailable receipt missing groupId".into()))?,
    )?;
    Ok(evidence.message_id == row.message_id
        && evidence.placeholder_row(&group_id, row.is_own)? == *row)
}

#[cfg(feature = "labyrinth")]
struct NativeRotationResult {
    new_epoch: u64,
    exclusions: Vec<LabyrinthRotationExclusion>,
    rekeyed_recovery_code: Option<String>,
    rekeyed_passkeys: Vec<Vec<u8>>,
}

#[cfg(feature = "labyrinth")]
impl CatbirdMlsClient {
    fn ensure_recovery_share_home_service_pin(&self) -> Result<(), MLSError> {
        let proven = self.resolve_peer_home_ds_did(&self.normalized_did)?;
        let proven = proven.ok_or_else(|| {
                MLSError::InvalidState(
                    "account home delivery-service declaration is unproven".into(),
                )
            })?;
        if proven != self.config.home_ds_did {
            return Err(MLSError::InvalidState(
                "account home delivery service differs from the configured service".into(),
            ));
        }
        let placements = NativeArchiveVault {
            db: self.db.clone(),
            namespace: "native.placements",
            hooks: self.hooks.clone(),
        };
        crate::labyrinth::recovery_shares::pin_proven_home_service(
            &placements,
            &self.normalized_did,
            &proven,
        )
        .map_err(|error| native_archive_error(crate::labyrinth::map_error(error)))
    }

    fn native_archive_run<F: Future + Send>(&self, future: F) -> F::Output where F::Output: Send {
        let hooks = self.hooks.clone();
        hooks.with_labyrinth_rng(|| block_on_sync(future))
    }

    fn native_archive_deps_with_gateway(
        &self,
    ) -> Result<(crate::labyrinth::SessionDeps, Arc<NativeArchiveGateway>), MLSError> {
        self.native_archive_deps_with_gateway_preverified(std::collections::BTreeMap::new())
    }

    fn native_archive_deps_with_gateway_preverified(
        &self,
        preverified_deleted_dids: std::collections::BTreeMap<String, u64>,
    ) -> Result<(crate::labyrinth::SessionDeps, Arc<NativeArchiveGateway>), MLSError> {
        if self.is_handle_closed() { return Err(MLSError::ContextClosed); }
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let _: [u8; 32] = signer.public().try_into().map_err(|_| MLSError::Cryptography("archive chat key is not Ed25519".into()))?;
        let signer = Arc::new(NativeArchiveSigner(signer));
        let mut config = self.config.clone();
        config.account_did = self.normalized_did.clone();
        config.device_id = self.canonical_uuid_v4_device_id().ok_or_else(|| MLSError::invalid_input("archive requires UUIDv4 device_id"))?;
        let gateway = Arc::new(NativeArchiveGateway {
            config: config.clone(),
            db: self.db.clone(),
            transport: self.transport.clone(),
            signer: signer.clone(),
            hooks: self.hooks.clone(),
            verified_inventories: Mutex::new(std::collections::BTreeMap::new()),
        });
        let transport = Arc::new(crate::labyrinth::GatewayXrpcTransport::new(gateway.clone(), signer.clone(), self.normalized_did.clone(), config.device_id)
            .with_clock(Arc::new(NativeArchiveClock(self.hooks.clone())))
            .with_home_ds_did(config.home_ds_did.clone()));
        let deps = crate::labyrinth::SessionDeps {
            did: self.normalized_did.clone(), transport, signer,
            vault: Arc::new(NativeArchiveVault { db: self.db.clone(), namespace: "native.session", hooks: self.hooks.clone() }),
            placements: Arc::new(NativeArchiveVault { db: self.db.clone(), namespace: "native.placements", hooks: self.hooks.clone() }),
            pds: Some(gateway.clone()), space: Some(Arc::new(crate::labyrinth::SpaceXrpcTransport::new(gateway.clone()))),
            local_authority: Some(Arc::new(NativeLocalAuthority {
                db: self.db.clone(),
                hooks: self.hooks.clone(),
                account_did: self.normalized_did.clone(),
                gateway: gateway.clone(),
                tombstoned_pds_dids: Mutex::new(std::collections::BTreeSet::new()),
                preverified_deleted_dids,
            })),
            sequencer_receipt_key: None,
            default_conversation_authority_did: None,
        };
        Ok((deps, gateway))
    }

    fn native_archive_deps(&self) -> Result<crate::labyrinth::SessionDeps, MLSError> {
        self.native_archive_deps_with_gateway().map(|(deps, _)| deps)
    }

    fn native_archive_deps_preverified(
        &self,
        preverified_deleted_dids: std::collections::BTreeMap<String, u64>,
    ) -> Result<crate::labyrinth::SessionDeps, MLSError> {
        self.native_archive_deps_with_gateway_preverified(preverified_deleted_dids)
            .map(|(deps, _)| deps)
    }

    /// Runs an E2EE Circles operation (`crate::ffi::circles_ffi`) on the native
    /// archive runtime, serialized with other session users by the outbox lock.
    pub(crate) fn circles_run<F: Future + Send>(&self, future: F) -> Result<F::Output, MLSError>
    where
        F::Output: Send,
    {
        if self.canonical_uuid_v4_device_id().is_none() {
            return Err(MLSError::InvalidState(
                "circles require a live mls-ds device".into(),
            ));
        }
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        Ok(self.native_archive_run(future))
    }

    /// This account's enrolled Labyrinth session, for `circles_run`.
    pub(crate) async fn circles_open_session(
        &self,
    ) -> Result<crate::labyrinth::LabyrinthSession, MLSError> {
        self.native_archive_deps()?
            .open()
            .await
            .map_err(native_archive_error)?
            .ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))
    }

    /// Retry only a durably recorded held publication/activation completion. Status reads are
    /// otherwise local-only, and callers already holding the archive lifecycle lock keep their
    /// existing operation responsible for the retry.
    fn refresh_pending_native_archive_publication_if_due(&self) {
        let due = self
            .db
            .read_tx(|tx| {
                let pending = tx
                    .get_labyrinth_state("status_json")?
                    .and_then(|raw| {
                        serde_json::from_slice::<LabyrinthBackupStatus>(&raw)
                            .ok()
                            .and_then(|status| status.pending_directory_epoch)
                    })
                    .is_some();
                Ok(pending
                    || tx
                        .get_labyrinth_state(PENDING_DEVICE_ACTIVATION_REFRESH_STATE)?
                        .is_some())
            })
            .unwrap_or(false);
        if !due {
            return;
        }
        let Ok(_guard) = self.outbox_flush_lock.try_lock() else {
            return;
        };
        if let Err(error) = self.native_archive_run(async {
            let Some(session) = self
                .native_archive_deps()?
                .open()
                .await
                .map_err(native_archive_error)?
            else {
                return Ok(());
            };
            self.save_native_archive_status(&session, false)?;
            Ok::<_, MLSError>(())
        }) {
            tracing::warn!(%error, "held archive directory publication refresh failed");
        }
    }

    fn save_native_archive_status(&self, session: &crate::labyrinth::LabyrinthSession, recovery_code: bool) -> Result<LabyrinthBackupStatus, MLSError> {
        let (status, activation_refresh_due) = self.db.write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| MLSError::InvalidState("archive status missing".into()))?;
            let mut status: LabyrinthBackupStatus = serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            let had_pending_publication = status.pending_directory_epoch.is_some();
            status.epoch_seq = session.latest_epoch();
            status.recovery_method_stale |= session.recovery_method_stale();
            status.has_recovery_code |= recovery_code;
            status.pending_directory_epoch = session.pending_directory_epoch();
            if session.directory_publish_attempted() {
                status.directory_publication_retry_count =
                    status.directory_publication_retry_count.saturating_add(1);
            }
            status.directory_publication_error =
                session.directory_publish_error().map(str::to_owned);
            status.directory_publication_stalled = status.pending_directory_epoch.is_some()
                && status.directory_publication_error.is_some();
            if recovery_code {
                status
                    .rotation_exclusions
                    .retain(|exclusion| exclusion.recovery_method.as_deref() != Some("code"));
            }
            let completed_held_publication =
                had_pending_publication && status.pending_directory_epoch.is_none();
            if completed_held_publication {
                tx.put_labyrinth_state(
                    PENDING_DEVICE_ACTIVATION_REFRESH_STATE,
                    b"1",
                    self.hooks.now_ms(),
                )?;
            }
            tx.put_labyrinth_state("status_json", &serde_json::to_vec(&status).map_err(|e| MLSError::Internal(e.to_string()))?, self.hooks.now_ms())?;
            let activation_refresh_due = status.pending_directory_epoch.is_none()
                && tx
                    .get_labyrinth_state(PENDING_DEVICE_ACTIVATION_REFRESH_STATE)?
                    .is_some();
            Ok((status, activation_refresh_due))
        })?;
        self.notify(PlatformChangeEvent::LabyrinthStatusChanged { epoch_seq: status.epoch_seq });
        self.finish_pending_approval_after_archive_promotion(activation_refresh_due);
        Ok(status)
    }

    pub fn labyrinth_recovery_presence(&self) -> Result<LabyrinthRecoveryPresence, MLSError> {
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let presence = self.native_archive_deps()?.recovery_presence().await.map_err(native_archive_error)?;
            Ok(LabyrinthRecoveryPresence {
                local_state: presence.local_state,
                mailbox_epoch: presence.mailbox_epoch,
                pds_head: presence.pds_head,
                ds_head: presence.ds_head,
                requires_recovery: presence.requires_recovery(),
            })
        })
    }

    pub fn list_recovery_methods(&self) -> Result<Vec<LabyrinthRecoveryMethodInfo>, MLSError> {
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let session = self.native_archive_deps()?.open().await.map_err(native_archive_error)?
                .ok_or_else(|| MLSError::InvalidState("Labyrinth must be restored before listing recovery methods".into()))?;
            let now_ms = self.hooks.now_ms().max(0) as u64;
            session.list_recovery_methods().await.map_err(native_archive_error).map(|methods| {
                methods.into_iter().map(|method| LabyrinthRecoveryMethodInfo {
                    vdevice_id: method.vdevice_id.to_vec(),
                    mechanism: method.mechanism.as_str().to_owned(),
                    device_key: method.device_key.0.to_vec(),
                    created_at_ms: method.created_at_ms,
                    last_used_at_ms: method.last_used_at_ms,
                    stale_at_ms: method.stale_at_ms,
                    stale_now: method.stale_at(now_ms),
                    revoked: method.revoked,
                }).collect()
            })
        })
    }

    /// Serialize recovery credential changes across handles and processes for this account.
    /// An OS-held advisory lock is released on crash, even if a remote rotation is in flight.
    fn lock_recovery_receipts(&self) -> Result<std::fs::File, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.db_path.with_extension("recovery.lock"))
            .map_err(|e| MLSError::Internal(format!("open recovery receipt lock: {e}")))?;
        // Mobile std file locking may report Unsupported. The kernel holds this advisory
        // lock for the open file description and releases it on close or process exit.
        #[cfg(unix)]
        let acquired =
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
                |error| {
                    if error == rustix::io::Errno::WOULDBLOCK {
                        std::fs::TryLockError::WouldBlock
                    } else {
                        std::fs::TryLockError::Error(std::io::Error::from(error))
                    }
                },
            );
        #[cfg(not(unix))]
        let acquired = file.try_lock();
        match acquired {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(MLSError::InvalidState("RecoveryOperationInProgress".into()))
            }
            Err(std::fs::TryLockError::Error(e)) => {
                Err(MLSError::Internal(format!("lock recovery receipts: {e}")))
            }
        }
    }

    /// Commit the receipt transition before the first irreversible mutation. Seed each fresh
    /// database independently so a receipt surviving a local reset cannot match a new code.
    fn begin_recovery_generation(&self) -> Result<(bool, u64), MLSError> {
        self.db.write_tx(|tx| {
            let raw = tx
                .get_labyrinth_state("status_json")?
                .ok_or_else(|| MLSError::InvalidState("Labyrinth status not initialized".into()))?;
            let mut status: LabyrinthBackupStatus = serde_json::from_slice(&raw)?;
            let previous_attention = status.recovery_needs_attention;
            status.recovery_generation = match status.recovery_generation {
                0 => (self.hooks.uuid_v4().as_u128() as u64) >> 1,
                old => old
                    .checked_add(1)
                    .ok_or_else(|| MLSError::InvalidState("RecoveryGenerationExhausted".into()))?,
            };
            status.recovery_needs_attention = true;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&status)?,
                self.hooks.now_ms(),
            )?;
            Ok((previous_attention, status.recovery_generation))
        })
    }

    /// Retained for callers using pre-generation receipts. A versioned receipt must be
    /// acknowledged using its expected generation.
    pub fn acknowledge_recovery_attention(&self) -> Result<LabyrinthBackupStatus, MLSError> {
        self.acknowledge_recovery_receipt(0)
    }

    pub fn acknowledge_recovery_generation(
        &self,
        expected_generation: u64,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        if expected_generation == 0 {
            return Err(MLSError::invalid_input(
                "recovery receipt generation must be nonzero",
            ));
        }
        self.acknowledge_recovery_receipt(expected_generation)
    }

    fn acknowledge_recovery_receipt(
        &self,
        expected: u64,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        let _guard = self.lock_recovery_receipts()?;
        let status = self.db.write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?
                .ok_or_else(|| MLSError::InvalidState("Labyrinth status not initialized".into()))?;
            let mut status: LabyrinthBackupStatus = serde_json::from_slice(&raw)?;
            if status.recovery_generation != expected {
                return Err(MLSError::InvalidState("StaleRecoveryReceipt".into()));
            }
            status.recovery_needs_attention = false;
            tx.put_labyrinth_state("status_json", &serde_json::to_vec(&status)?, self.hooks.now_ms())?;
            Ok(status)
        })?;
        drop(_guard);
        self.notify(PlatformChangeEvent::LabyrinthStatusChanged { epoch_seq: status.epoch_seq });
        Ok(status)
    }

    fn persist_native_passkey_recovery(
        &self,
        credential_id: &[u8],
        prf_output: &[u8],
    ) -> Result<(), MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test {
            return self.offline_register_passkey_recovery(credential_id, prf_output);
        }
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            session
                .create_passkey_recovery(prf_output, credential_id)
                .await
                .map_err(native_archive_error)?;
            self.db.write_tx(|tx| {
                let raw = tx
                    .get_labyrinth_state("status_json")?
                    .ok_or_else(|| MLSError::InvalidState("archive status missing".into()))?;
                let mut status: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                status.epoch_seq = session.latest_epoch();
                status.pending_directory_epoch = session.pending_directory_epoch();
                if session.directory_publish_attempted() {
                    status.directory_publication_retry_count =
                        status.directory_publication_retry_count.saturating_add(1);
                }
                status.directory_publication_error =
                    session.directory_publish_error().map(str::to_owned);
                status.directory_publication_stalled = status.pending_directory_epoch.is_some()
                    && status.directory_publication_error.is_some();
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&status)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    self.hooks.now_ms(),
                )?;
                Ok(())
            })
        })
    }

    pub fn setup_recovery_code(&self) -> Result<String, MLSError> {
        Ok(self.setup_recovery_code_with_receipt()?.code)
    }

    pub fn setup_recovery_code_with_receipt(&self) -> Result<GeneratedRecoveryCode, MLSError> {
        let _receipt_guard = self.lock_recovery_receipts()?;
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test {
            let (_, recovery_generation) = self.begin_recovery_generation()?;
            let code = self.offline_setup_recovery_code()?;
            return Ok(GeneratedRecoveryCode {
                code,
                recovery_generation,
            });
        }
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self.native_archive_deps()?.enable().await.map_err(native_archive_error)?;
            // Set the durable reminder before a code can be minted. A later
            // status-write failure must not make the only displayable code
            // disappear into an error return.
            let (_, recovery_generation) = self.begin_recovery_generation()?;
            let code = session.create_recovery_code().await.map_err(native_archive_error)?;
            if let Err(error) = self.save_native_archive_status(&session, true) {
                tracing::warn!(%error, "recovery code created but archive status refresh failed");
            }
            Ok(GeneratedRecoveryCode { code, recovery_generation })
        })
    }

    fn finish_pending_approval_after_archive_promotion(&self, refresh_due: bool) {
        if !refresh_due {
            return;
        }
        let pending = match self.is_device_pending_approval() {
            Ok(pending) => pending,
            Err(error) => {
                tracing::warn!(%error, "could not read pending device activation state");
                return;
            }
        };
        if pending {
            let scopes = super::REQUIRED_LABYRINTH_OAUTH_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>();
            if let Err(error) = self.enroll_device(&scopes) {
                tracing::warn!(
                    %error,
                    "directory publication completed but device activation refresh failed"
                );
                return;
            }
        }
        if let Err(error) = self.db.write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM labyrinth_state WHERE state_key = ?1",
                    [PENDING_DEVICE_ACTIVATION_REFRESH_STATE],
                )
                .map_err(|e| {
                    MLSError::Internal(format!("clear pending device activation refresh: {e}"))
                })?;
            Ok(())
        }) {
            tracing::warn!(%error, "could not clear completed device activation refresh");
        }
    }

    pub fn restore_with_recovery_code(&self, code: &str) -> Result<LabyrinthBackupStatus, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_restore_with_recovery_code(code); }
        // A recovery code enrolls storage keys, not an unverified chat device.
        // Register this new device normally before the library attests its binding.
        if self.db.read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?.is_none() {
            self.enroll_device(&super::REQUIRED_LABYRINTH_OAUTH_SCOPES.iter().map(|scope| (*scope).to_owned()).collect::<Vec<_>>())?;
        }
        let requires_share = self.native_archive_run(async {
            self.native_archive_deps()?
                .recovery_code_requires_share(code)
                .await
                .map_err(native_archive_error)
        })?;
        if requires_share {
            self.ensure_recovery_share_home_service_pin()?;
        }
        let status = {
            let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
            self.native_archive_run(async {
                let session = self.native_archive_deps()?.restore_with_recovery_code(code).await.map_err(native_archive_error)?;
                if session.pending_directory_epoch().is_none()
                    && self.is_device_pending_approval()?
                {
                    self.db.write_tx(|tx| {
                        tx.put_labyrinth_state(
                            PENDING_DEVICE_ACTIVATION_REFRESH_STATE,
                            b"1",
                            self.hooks.now_ms(),
                        )
                    })?;
                }
                self.save_native_archive_status(&session, true)
            })?
        };
        Ok(status)
    }

    fn pin_native_conversation_coordinates(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
        generation: u64,
        explicit_space: Option<&str>,
        group_id: &[u8],
    ) -> Result<(), MLSError> {
        if !sequencer_did.starts_with("did:") || sequencer_did.contains('#') {
            return Err(MLSError::Cryptography(
                "archive receipt has an invalid sequencer DID".into(),
            ));
        }
        let space_ref = match explicit_space {
            Some(space) => labyrinth::store::space::SpaceRef::parse(space)
                .map_err(|e| MLSError::Cryptography(e.to_string()))?,
            None => labyrinth::store::space::SpaceRef::conversation(
                sequencer_did,
                &format!("{conversation_id}-{generation}"),
            ),
        };
        if space_ref.space_did != sequencer_did {
            return Err(MLSError::Cryptography(
                "conversation Space authority differs from pinned sequencer".into(),
            ));
        }
        let space = space_ref.to_string();
        let group_id = hex::encode(group_id);
        self.db.write_tx(|tx| {
            let key = format!(
                "native.placements:{}",
                crate::labyrinth::space::thread_placement_key(&self.normalized_did)
            );
            let mut placements: std::collections::BTreeMap<
                String,
                crate::labyrinth::space::ThreadPlacement,
            > = tx
                .get_labyrinth_state(&key)?
                .map(|raw| serde_json::from_slice(&raw))
                .transpose()
                .map_err(|e| {
                    MLSError::Cryptography(format!("invalid archive Space pins: {e}"))
                })?
                .unwrap_or_default();
            if let Some(existing) = placements.get(conversation_id) {
                existing
                    .validate()
                    .map_err(|e| MLSError::Cryptography(e.to_string()))?;
                let existing_space = existing
                    .space
                    .as_deref()
                    .ok_or_else(|| MLSError::Cryptography("archive Space pin is empty".into()))?;
                let existing_ref = labyrinth::store::space::SpaceRef::parse(existing_space)
                    .map_err(|e| MLSError::Cryptography(e.to_string()))?;
                if existing_ref.space_did != sequencer_did {
                    return Err(MLSError::Cryptography(
                        "archive receipt cannot replace the pinned sequencer".into(),
                    ));
                }
                if existing.generation > generation {
                    return Ok(());
                }
                if existing.generation == generation {
                    if existing_space != space {
                        return Err(MLSError::Cryptography(
                            "archive receipt conflicts with the pinned Space".into(),
                        ));
                    }
                    // A pin made before groups were pinned gains its group here.
                    match existing.group_id.as_deref() {
                        Some(pinned) if pinned == group_id => return Ok(()),
                        Some(_) => {
                            return Err(MLSError::Cryptography(
                                "archive receipt conflicts with the pinned MLS group".into(),
                            ))
                        }
                        None => {}
                    }
                }
            }
            placements.insert(
                conversation_id.to_owned(),
                crate::labyrinth::space::ThreadPlacement {
                    space: Some(space),
                    generation,
                    group_id: Some(group_id),
                },
            );
            tx.put_labyrinth_state(
                &key,
                &serde_json::to_vec(&placements)
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
                self.hooks.now_ms(),
            )
        })
    }

    fn pin_native_conversation(&self, conversation_id: &str) -> Result<(), MLSError> {
        let conversation = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?;
        let Some(conversation) = conversation else {
            return Ok(());
        };
        self.pin_native_conversation_coordinates(
            conversation_id,
            &conversation.sequencer_did,
            u64::try_from(conversation.generation).map_err(|_| {
                MLSError::Cryptography("archive conversation generation is negative".into())
            })?,
            conversation.space_uri.as_deref(),
            &conversation.group_id,
        )
    }

    /// Owner records are local proof that this account held authenticated conversation material.
    /// Their verified I13 receipts can bootstrap a Space pin but never replace its authority. The
    /// receipt signature covers the sequencer and MLS group, not the generation the Space name
    /// uses: every owner copy from the newest signed group must name one generation, and the pin
    /// keeps that signed group. The authority signs its group into a denial, so a denial for a
    /// Space named by a wrong generation never matches the pin.
    fn pin_native_conversation_from_owner_history(
        &self,
        conversation_id: &str,
        history: &[labyrinth::client::LoadedMessage],
    ) -> Result<(), MLSError> {
        let mut authority: Option<&str> = None;
        let mut newest: Option<&labyrinth::message::ArchivedReceipt> = None;
        for message in history {
            let receipt = message.archived_receipt.as_ref().ok_or_else(|| {
                MLSError::Cryptography("owner archive frame missing sequencer receipt".into())
            })?;
            let payload = &receipt.signed.payload;
            if message.thread_id != conversation_id
                || payload.conversation_id != conversation_id
                || authority.is_some_and(|did| did != payload.sequencer_did.as_str())
            {
                return Err(MLSError::Cryptography(
                    "owner archive receipt conflicts with conversation coordinates".into(),
                ));
            }
            authority = Some(&payload.sequencer_did);
            if newest.is_none_or(|current| payload.seq > current.signed.payload.seq) {
                newest = Some(receipt);
            }
        }
        let Some(newest) = newest else {
            return Err(MLSError::InvalidState(
                "ArchiveRemovalUnproven".into(),
            ));
        };
        let group_id = &newest.signed.payload.group_id;
        if history
            .iter()
            .filter_map(|message| message.archived_receipt.as_ref())
            .any(|receipt| {
                receipt.signed.payload.group_id == *group_id
                    && receipt.generation != newest.generation
            })
        {
            return Err(MLSError::InvalidState("ArchiveRemovalUnproven".into()));
        }
        self.pin_native_conversation_coordinates(
            conversation_id,
            &newest.signed.payload.sequencer_did,
            newest.generation,
            None,
            group_id,
        )
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
                if tx.get_labyrinth_state(&unsent_message_key(conversation_id, &item.message_id))?.is_some() {
                    continue;
                }
                let Some(message) = tx.get_message(&item.message_id)? else {
                    continue;
                };
                if message.conversation_id != conversation_id
                    || !super::archive_policy::should_archive_frame(
                        tx,
                        conversation_id,
                        message.seq,
                        &item.labyrinth_frame_json,
                    )?
                {
                    continue;
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
            .map_err(owner_archive_error)?;
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
        if conversations.is_empty()
            && self
                .db
                .read_tx(|tx| {
                    tx.get_labyrinth_state(&format!("native.session:{}", self.normalized_did))
                })?
                .is_none()
        {
            return Ok(0);
        }
        if crate::buggify!("between_labyrinth_enqueue_and_flush") { return Err(MLSError::Internal("sim buggify: between_labyrinth_enqueue_and_flush".into())); }
        self.native_archive_run(async {
            let (deps, gateway) = self.native_archive_deps_with_gateway()?;
            let mut session = deps.clone().enable().await.map_err(native_archive_error)?;
            let mut count = 0;
            let mut first_error = None;
            for cid in conversations {
                let result: Result<u32, MLSError> = async {
                    self.pin_native_conversation(&cid)?;
                    let local_members = match self.list_members(&cid) {
                        Ok(members) => members,
                        Err(MLSError::GroupNotFound { .. }) => Vec::new(),
                        Err(error) => return Err(error),
                    };
                    let local_has_self = local_members.iter().any(|did| did == &self.normalized_did);
                    let owner_only = match deps.transport.query("blue.catbird.chat.getConversationState", &[("conversationId", cid.clone())]).await {
                        Ok(_) => !local_has_self,
                        Err(error) => match crate::labyrinth::transport::map_xrpc_error(error) {
                            labyrinth::Error::Forbidden if !local_has_self => true,
                            labyrinth::Error::Forbidden => {
                                match gateway.verify_conversation_space_removal(&cid) {
                                    Ok(true) => true,
                                    _ => {
                                        return Err(MLSError::InvalidState(
                                            "ArchiveFlushDenialUnverified".into(),
                                        ));
                                    }
                                }
                            }
                            labyrinth::Error::NotFound("conversation") if !local_has_self => true,
                            error => return Err(MLSError::Cryptography(format!("archive conversation state: {error}"))),
                        }
                    };
                    let mut committed = 0;
                    loop {
                        let queued = self.db.read_tx(|tx| tx.list_labyrinth_queue(Some(&cid), 100))?;
                        if queued.is_empty() { break; }
                        let payloads = queued.iter().map(|row| self.decode_queue_row(row)).collect::<Result<Vec<_>, _>>()?;
                        // Unsent by the author: dequeued below like the rest, archived nowhere.
                        let payloads = self.db.read_tx(|tx| {
                            let mut kept = Vec::with_capacity(payloads.len());
                            for payload in payloads {
                                if tx.get_labyrinth_state(&unsent_message_key(&cid, &payload.message_id))?.is_none()
                                    && super::archive_policy::should_enqueue(tx, &payload)? {
                                    kept.push(payload);
                                }
                            }
                            Ok(kept)
                        })?;
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
                            // A verified account deletion purged that account's mailbox: its
                            // missing epoch head must not block the survivors' archive. Only the
                            // recorded `accountDeletedEntry` excludes it, never a server 404.
                            let roster: Vec<String> = self.db.read_tx(|tx| {
                                let mut kept = Vec::new();
                                for did in &first.expected_member_dids {
                                    if tx.get_labyrinth_state(&super::chat_wire::account_deletion_key(&cid, did))?.is_none() { kept.push(did.clone()); }
                                }
                                Ok(kept)
                            })?;
                            let denied = if owner_only {
                                true
                            } else {
                                match session
                                    .archive_native_sender(&cid, &roster, chunk)
                                    .await
                                    .map_err(native_archive_error)?
                                {
                                    Ok(false) => false,
                                    Ok(true) if !local_has_self => true,
                                    Ok(true) => {
                                        match gateway.verify_conversation_space_removal(&cid) {
                                            Ok(true) => true,
                                            _ => {
                                                return Err(MLSError::InvalidState(
                                                    "ArchiveFlushDenialUnverified".into(),
                                                ));
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        return Err(MLSError::Cryptography(format!(
                                            "sender archive prerequisite: {error}"
                                        )));
                                    }
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

    /// Hide the sender's local timeline row and, when the frame was eligible for backup,
    /// publish a durable Labyrinth author redaction. A live peer's MLS timeline still needs
    /// its own authenticated tombstone to hide its copy.
    pub fn unsend_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<u32, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        let message = self
            .db
            .read_tx(|tx| tx.get_message(message_id))?
            .ok_or_else(|| MLSError::invalid_input("message not found"))?;
        if message.conversation_id != conversation_id
            || !message.is_own
            || message.sender_did != self.normalized_did
        {
            return Err(MLSError::invalid_input(
                "only the original sender may unsend this message",
            ));
        }
        if self.db.read_tx(|tx| {
            Ok(tx
                .get_labyrinth_state(&unsent_message_key(conversation_id, message_id))?
                .is_some())
        })? {
            return Ok(0);
        }
        let local_only = self.db.read_tx(|tx| {
            let evidence = tx.get_labyrinth_state(&format!(
                "native.message:{conversation_id}:{message_id}"
            ))?;
            let frame = evidence
                .as_deref()
                .and_then(|bytes| serde_json::from_slice::<NativeArchiveEvidence>(bytes).ok());
            match frame {
                Some(frame) => Ok(!super::archive_policy::should_archive_frame(
                    tx,
                    conversation_id,
                    message.seq,
                    &frame.labyrinth_frame_json,
                )?),
                None => Ok(true),
            }
        })?;
        if local_only {
            self.db.write_tx(|tx| {
                tx.dequeue_labyrinth_item(message_id)?;
                tx.put_labyrinth_state(
                    &unsent_message_key(conversation_id, message_id),
                    b"unsent-local",
                    self.hooks.now_ms(),
                )
            })?;
            self.notify(PlatformChangeEvent::MessagesUpdated {
                conversation_id: conversation_id.to_owned(),
            });
            return Ok(0);
        }
        if !self.labyrinth_status()?.backup_enabled {
            return Err(MLSError::InvalidState(
                "LabyrinthBackupDisabled".to_string(),
            ));
        }
        self.pin_native_conversation(conversation_id)?;
        let count = self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let count = session
                .unsend_native_message(conversation_id, message_id)
                .await
                .map_err(native_archive_error)?
                .map_err(|error| {
                    MLSError::Cryptography(format!("Labyrinth unsend: {error}"))
                })?;
            // The redaction is durable. Drop the queued copy and mark the message in one
            // transaction: no later flush or kick rescue archives it, whether it is queued
            // again by a replayed send journal or read from cached evidence. The evidence
            // stays, because sync recognises this device's own echo by it.
            self.db.write_tx(|tx| {
                tx.dequeue_labyrinth_item(message_id)?;
                tx.put_labyrinth_state(
                    &unsent_message_key(conversation_id, message_id),
                    b"unsent",
                    self.hooks.now_ms(),
                )
            })?;
            u32::try_from(count)
                .map_err(|_| MLSError::Internal("unsend count overflow".into()))
        })?;
        self.notify(PlatformChangeEvent::MessagesUpdated {
            conversation_id: conversation_id.to_owned(),
        });
        Ok(count)
    }

    pub fn rescue_conversation_on_kick(
        &self,
        conversation_id: &str,
    ) -> Result<u32, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test {
            return self.offline_rescue_conversation_on_kick(conversation_id);
        }
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        if !self.labyrinth_status()?.backup_enabled {
            return Ok(0);
        }
        self.pin_native_conversation(conversation_id)?;
        let (items, queued_ids, skipped) = self.db.read_tx(|tx| {
            let mut statement = tx
                .conn()
                .prepare(
                    "SELECT message_id FROM messages WHERE conversation_id = ?1 ORDER BY seq, message_id",
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let ids = statement
                .query_map([conversation_id], |row| row.get::<_, String>(0))
                .map_err(|e| MLSError::Internal(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let mut items = std::collections::BTreeMap::new();
            let mut skipped = std::collections::BTreeSet::new();
            for id in ids {
                if tx.get_labyrinth_state(&unsent_message_key(conversation_id, &id))?.is_some() {
                    continue;
                }
                let key = format!("native.message:{conversation_id}:{id}");
                let Some(raw) = tx.get_labyrinth_state(&key)? else {
                    skipped.insert(id);
                    continue;
                };
                let Ok(item) = serde_json::from_slice::<NativeArchiveEvidence>(&raw) else {
                    skipped.insert(id);
                    continue;
                };
                if item.message_id != id || item.conversation_id != conversation_id {
                    skipped.insert(id);
                    continue;
                }
                items.insert(id, item);
            }
            let mut statement = tx
                .conn()
                .prepare(
                    "SELECT item_id, payload_bytes FROM labyrinth_queue WHERE conversation_id = ?1 ORDER BY seq, item_id",
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let queued = statement
                .query_map([conversation_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let mut queued_ids = std::collections::BTreeSet::new();
            for row in queued {
                let (id, bytes) = row.map_err(|e| MLSError::Internal(e.to_string()))?;
                let Ok(item) = serde_json::from_slice::<NativeArchiveEvidence>(&bytes) else {
                    skipped.insert(id);
                    continue;
                };
                if item.message_id != id || item.conversation_id != conversation_id {
                    skipped.insert(id);
                    continue;
                }
                queued_ids.insert(id.clone());
                items.insert(id, item);
            }
            Ok((items.into_values().collect::<Vec<_>>(), queued_ids, skipped))
        })?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let mut rescued = 0u32;
            let mut completed = std::collections::BTreeSet::new();
            let mut skipped = skipped;
            for item in &items {
                match self
                    .native_backup_owner_items(
                        &mut session,
                        conversation_id,
                        std::slice::from_ref(item),
                    )
                    .await
                {
                    Ok(count) => {
                        rescued = rescued.saturating_add(count);
                        completed.insert(item.message_id.clone());
                    }
                    Err(MLSError::Cryptography(reason)) => {
                        // Only this message's own evidence is invalid: rescue the rest.
                        tracing::warn!(
                            conversation_id,
                            message_id = %item.message_id,
                            %reason,
                            "Labyrinth kick rescue skipped invalid message evidence"
                        );
                        skipped.insert(item.message_id.clone());
                    }
                    // A transport, directory, store or session failure may clear on retry. Fail
                    // the rescue so every remaining message stays pending, never reported skipped.
                    Err(error) => return Err(error),
                }
            }
            let skipped_evidence_ids = skipped.into_iter().collect::<Vec<_>>();
            self.db.write_tx(|tx| {
                for id in queued_ids.intersection(&completed) {
                    tx.dequeue_labyrinth_item(id)?;
                }
                tx.put_labyrinth_state(
                    &format!("native.rescue-report:{conversation_id}"),
                    &serde_json::to_vec(&serde_json::json!({
                        "rescuedCount": rescued,
                        "skippedEvidenceIds": &skipped_evidence_ids,
                    }))
                    .map_err(|error| MLSError::Internal(error.to_string()))?,
                    self.hooks.now_ms(),
                )
            })?;
            if !skipped_evidence_ids.is_empty() {
                tracing::warn!(
                    conversation_id,
                    skipped_evidence_ids = ?skipped_evidence_ids,
                    "Labyrinth kick rescue completed with skipped evidence"
                );
            }
            self.save_native_archive_status(&session, false)?;
            Ok(rescued)
        })
    }

    /// Hides every copy (sender, witness or owner) attributed to an account whose deletion
    /// was previously applied for `conversation_id`. Live sync and restore quarantine new
    /// deletions until historical non-revocation is proven; no
    /// Hide every restored message of any account deleted in this conversation, closing the gap
    /// server redaction covers the witness and owner copies other members already published. A
    /// copy stays only if its sequencer receipt orders it after the deletion (and is not from an
    /// ephemeral PDS repo tombstone discovered on this restore). Returns how many it hid.
    fn hide_deleted_accounts(
        db: &MlsAccountDb,
        conversation_id: &str,
        tombstoned_dids: &std::collections::BTreeSet<String>,
        messages: &mut Vec<labyrinth::client::LoadedMessage>,
    ) -> Result<usize, MLSError> {
        let senders: std::collections::BTreeSet<String> =
            messages.iter().filter_map(|m| m.sender.clone()).collect();
        use super::deletion_authority::{AppliedAccountDeletion, StoredAccountDeletion};
        let deleted: std::collections::BTreeMap<String, StoredAccountDeletion> =
            db.read_tx(|tx| {
                let mut deleted = std::collections::BTreeMap::new();
                for did in &senders {
                    if tombstoned_dids.contains(did) {
                        deleted.insert(did.clone(), StoredAccountDeletion::SeqOnly(i64::MAX));
                    } else if let Some(raw) = tx.get_labyrinth_state(
                        &super::chat_wire::account_deletion_key(conversation_id, did),
                    )? {
                        // An unreadable marker still hides: it can only widen what the deletion covers.
                        let marker = AppliedAccountDeletion::decode(&raw)
                            .unwrap_or(StoredAccountDeletion::SeqOnly(i64::MAX));
                        deleted.insert(did.clone(), marker);
                    }
                }
                Ok(deleted)
            })?;
        for m in messages.iter() {
            if let (Some(sender), Some(r)) = (m.sender.as_deref(), m.archived_receipt.as_ref()) {
                if let Some(marker) = deleted.get(sender) {
                    let seq = i64::try_from(r.signed.payload.seq).unwrap_or(i64::MAX);
                    if let Ok((_, sender_device_id)) = r.signed.payload.split_sender_device() {
                        if marker.self_deleted_device_post_entry(seq, sender_device_id) {
                            return Err(MLSError::Cryptography(
                                "archive contains frame from self-deleted device at or after accountDeletedEntry"
                                    .into(),
                            ));
                        }
                    }
                }
            }
        }
        let before = messages.len();
        // A copy stays unless the deletion covers it: ordered before the deletion and, for a
        // device-signed deletion, issued no later than its signed instant. A copy without a
        // receipt cannot show either and is hidden.
        messages.retain(|m| match m.sender.as_deref().and_then(|s| deleted.get(s)) {
            Some(marker) => m.archived_receipt.as_ref().is_some_and(|r| {
                !marker.covers(
                    i64::try_from(r.signed.payload.seq).unwrap_or(i64::MAX),
                    i64::try_from(r.signed.payload.issued_at_ms).ok(),
                )
            }),
            None => true,
        });
        Ok(before - messages.len())
    }

    fn conversation_state_with_deletions(
        &self,
        cid: &str,
        device: &str,
        signer: &SignatureKeyPair,
    ) -> Result<serde_json::Value, MLSError> {
        let mut after = 0i64;
        let mut entries = Vec::new();
        // Bound work if the sequencer appends new entries continuously.
        for _ in 0..1024 {
            let mut state = self.query_signed_chat_ds(
                "blue.catbird.chat.getConversationState",
                &[
                    ("actorDeviceId", device),
                    ("conversationId", cid),
                    ("deletionsAfter", &after.to_string()),
                ],
                device,
                signer,
            )?;
            let page = state["accountDeletions"]
                .as_array_mut()
                .ok_or_else(|| MLSError::Cryptography("missing deletion inventory page".into()))?;
            if page.len() > 100 {
                return Err(MLSError::Cryptography(
                    "oversized deletion inventory page".into(),
                ));
            }
            let mut last = after;
            for entry in page.iter() {
                let seq = entry["seq"]
                    .as_i64()
                    .filter(|s| *s > last && *s <= 9_007_199_254_740_991)
                    .ok_or_else(|| {
                        MLSError::Cryptography("invalid deletion inventory order".into())
                    })?;
                last = seq;
            }
            entries.append(page);
            match state.get("deletionsCursor") {
                None => {
                    state["accountDeletions"] = serde_json::Value::Array(entries);
                    return Ok(state);
                }
                Some(cursor) if cursor.as_i64() == Some(last) && last > after => after = last,
                _ => {
                    return Err(MLSError::Cryptography(
                        "invalid deletion inventory cursor".into(),
                    ))
                }
            }
        }
        Err(MLSError::InvalidState(
            "ArchiveDeletionInventoryUnavailable".into(),
        ))
    }

    /// Fetch `getConversationState["accountDeletions"]` prior to `session.load_history` so
    /// deleted accounts are already bound before `LocallyCheckedDirectory` enforces live PDS
    /// device inventory or shared MLS leaf keys. Unpinned conversations avoid DB writes here and
    /// return an in-memory map until `load_history` authenticates the sequencer receipt.
    fn preverify_conversation_deletions(
        &self,
        conversation_id: &str,
    ) -> Result<
        (
            Option<serde_json::Value>,
            std::collections::BTreeMap<String, u64>,
        ),
        MLSError,
    > {
        let device = self
            .canonical_uuid_v4_device_id()
            .ok_or_else(|| MLSError::invalid_input("archive requires UUIDv4 device_id"))?;
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let state = match self.conversation_state_with_deletions(conversation_id, &device, &signer) {
            Ok(state) => state,
            Err(MLSError::InvalidState(code))
                if matches!(
                    code.as_str(),
                    "ConversationNotFound" | "NotEntitled" | "AccessOutsideMembershipInterval"
                ) =>
            {
                return Ok((None, std::collections::BTreeMap::new()));
            }
            Err(error) => return Err(error),
        };
        let pinned = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .map(|row| row.sequencer_did)
            .filter(|did| !did.is_empty());
        let candidate_sequencer = pinned.clone().or_else(|| {
            state["state"]["sequencerDid"]
                .as_str()
                .or_else(|| state["sequencerDid"].as_str())
                .filter(|did| !did.is_empty())
                .map(str::to_owned)
        });
        let mut preverified = std::collections::BTreeMap::new();
        if let Some(sequencer) = candidate_sequencer {
            let deletions = state["accountDeletions"].as_array().ok_or_else(|| {
                MLSError::Cryptography("getConversationState is missing accountDeletions".into())
            })?;
            let mut ordered_deletions: Vec<&serde_json::Value> = deletions.iter().collect();
            ordered_deletions.sort_by_key(|entry| entry["seq"].as_i64().unwrap_or(i64::MAX));
            for entry in ordered_deletions {
                let decision =
                    self.authorize_account_deletion(conversation_id, &sequencer, entry)?;
                if pinned.is_some() {
                    self.apply_account_deletion_decision(conversation_id, entry, &decision)?;
                    if let super::live_sync::live_integrity::AccountDeletionDecision::Unverified {
                        reason,
                        ..
                    } = &decision
                    {
                        if !matches!(
                            reason,
                            super::deletion_authority::UnverifiedDeletionReason::OtherConversation
                                | super::deletion_authority::UnverifiedDeletionReason::Replayed
                        ) {
                            tracing::warn!(
                                conversation_id,
                                ?reason,
                                "archive restore blocked on unverified account deletion"
                            );
                            return Err(MLSError::InvalidState(
                                "ArchiveDeletionUnverified".into(),
                            ));
                        }
                    }
                } else if let super::live_sync::live_integrity::AccountDeletionDecision::Apply {
                    deleted_did,
                    write,
                    ..
                } = decision
                {
                    let ms = u64::try_from(write.signed_at_ms.max(0)).unwrap_or(0);
                    preverified
                        .entry(deleted_did)
                        .and_modify(|prev: &mut u64| *prev = (*prev).min(ms))
                        .or_insert(ms);
                }
            }
        }
        Ok((Some(state), preverified))
    }

    /// A fresh device never sees `accountDeletedEntry` in `getEntries`, so archive reads verify
    /// every deletion the conversation state lists under the pinned sequencer, or without local
    /// state under the sequencer authenticated by restored receipts. Inaccessible state holds
    /// nonempty history because the local deletion-marker set may be incomplete.
    fn apply_listed_account_deletions(
        &self,
        conversation_id: &str,
        history: &[labyrinth::client::LoadedMessage],
        prefetched_state: Option<serde_json::Value>,
    ) -> Result<std::collections::BTreeSet<String>, MLSError> {
        if history.is_empty() {
            return Ok(std::collections::BTreeSet::new());
        }
        let pinned = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .map(|row| row.sequencer_did)
            .filter(|did| !did.is_empty());
        let Some(sequencer) = pinned.or_else(|| {
            history
                .iter()
                .filter_map(|m| m.archived_receipt.as_ref())
                .max_by_key(|r| r.signed.payload.seq)
                .map(|r| r.signed.payload.sequencer_did.clone())
        }) else {
            return Err(MLSError::InvalidState(
                "ArchiveDeletionInventoryUnavailable".into(),
            ));
        };
        let state = match prefetched_state {
            Some(state) => state,
            None => {
                let device = self
                    .canonical_uuid_v4_device_id()
                    .ok_or_else(|| MLSError::invalid_input("archive requires UUIDv4 device_id"))?;
                let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
                match self.conversation_state_with_deletions(conversation_id, &device, &signer) {
                    Ok(state) => state,
                    // A denied or forgotten conversation state cannot prove which deletions preceded
                    // this archive. Local markers may be incomplete on a restored device, so stop
                    // before returning or importing any plaintext copies.
                    Err(MLSError::InvalidState(code))
                        if matches!(
                            code.as_str(),
                            "ConversationNotFound"
                                | "NotEntitled"
                                | "AccessOutsideMembershipInterval"
                        ) =>
                    {
                        return Err(MLSError::InvalidState(
                            "ArchiveDeletionInventoryUnavailable".into(),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        let deletions = state["accountDeletions"].as_array().ok_or_else(|| {
            MLSError::Cryptography("getConversationState is missing accountDeletions".into())
        })?;
        // Each listed deletion needs the deleting device's signature and historical status.
        // A key proof can verify the device key when this device holds no leaf of it.
        let mut ordered_deletions: Vec<&serde_json::Value> = deletions.iter().collect();
        ordered_deletions.sort_by_key(|entry| entry["seq"].as_i64().unwrap_or(i64::MAX));
        for entry in ordered_deletions {
            let decision = self.authorize_account_deletion(conversation_id, &sequencer, entry)?;
            self.apply_account_deletion_decision(conversation_id, entry, &decision)?;
            if let super::live_sync::live_integrity::AccountDeletionDecision::Unverified {
                reason,
                ..
            } = decision
            {
                if matches!(
                    reason,
                    super::deletion_authority::UnverifiedDeletionReason::OtherConversation
                        | super::deletion_authority::UnverifiedDeletionReason::Replayed
                ) {
                    continue;
                }
                // No archived row is made visible while a sequencer-listed deletion remains
                // unauthorised, including after DID-key rotation or missing revocation proof.
                tracing::warn!(
                    conversation_id,
                    ?reason,
                    "archive restore blocked on unverified account deletion"
                );
                return Err(MLSError::InvalidState(
                    "ArchiveDeletionUnverified".into(),
                ));
            }
        }
        // PDS completeness check for foreign message senders whose deletion may have been
        // omitted from `getConversationState["accountDeletions"]`.
        let senders: std::collections::BTreeSet<&str> = history
            .iter()
            .filter_map(|message| message.sender.as_deref())
            .collect();
        let mut tombstoned_dids = std::collections::BTreeSet::new();
        for sender in senders {
            if self.verify_foreign_sender_pds_deletion(conversation_id, sender)? {
                tombstoned_dids.insert(sender.to_owned());
            }
        }
        Ok(tombstoned_dids)
    }

    pub(crate) fn fetch_pds_record_car(
        &self,
        pds_endpoint: &str,
        did: &str,
        collection: &str,
        rkey: &str,
    ) -> Result<Vec<u8>, MLSError> {
        let base = pds_endpoint.trim_end_matches('/');
        let url = format!(
            "{base}/xrpc/com.atproto.sync.getRecord?did={}&collection={}&rkey={}",
            super::chat_wire::urlencode_form_component(did),
            super::chat_wire::urlencode_form_component(collection),
            super::chat_wire::urlencode_form_component(rkey),
        );
        let resp = self.transport.execute_http(PlatformHttpRequest {
            method: "GET".to_owned(),
            url,
            headers: Vec::new(),
            body: None,
        })?;
        if resp.status >= 400 {
            return Err(MLSError::Cryptography(format!(
                "CARv1 sync.getRecord(at://{did}/{collection}/{rkey}) failed with HTTP {}",
                resp.status
            )));
        }
        if resp.body.is_empty()
            || resp.body.len() > super::deletion_authority::MAX_REVOCATION_PROOF_BYTES
        {
            return Err(MLSError::Cryptography(format!(
                "CARv1 sync.getRecord(at://{did}/{collection}/{rkey}) size {} out of bounds",
                resp.body.len()
            )));
        }
        Ok(resp.body)
    }

    fn list_pds_revocations_or_tombstone(
        &self,
        pds_endpoint: &str,
        did: &str,
        expected_records: usize,
    ) -> Result<Option<Vec<serde_json::Value>>, MLSError> {
        let base = pds_endpoint.trim_end_matches('/');
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut all_records = Vec::new();
        // A server may return fewer records than requested. Each page must make progress,
        // and the signed tree bounds the total number of values that can legitimately arrive.
        let max_pages = expected_records.saturating_add(1);
        for page_idx in 0..max_pages {
            let mut url = format!(
                "{base}/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit={}",
                super::chat_wire::urlencode_form_component(did),
                super::chat_wire::urlencode_form_component(
                    super::deletion_authority::DEVICE_REVOCATION_COLLECTION,
                ),
                super::chat_wire::PDS_LIST_RECORDS_PAGE_LIMIT,
            );
            if let Some(ref c) = cursor {
                url.push_str(&format!(
                    "&cursor={}",
                    super::chat_wire::urlencode_form_component(c)
                ));
            }
            let resp = self
                .transport
                .execute_http(PlatformHttpRequest {
                    method: "GET".to_owned(),
                    url,
                    headers: Vec::new(),
                    body: None,
                })
                .map_err(|_| MLSError::InvalidState("ArchiveDeletionInventoryUnavailable".into()))?;
            if resp.status >= 400 {
                let err_code = serde_json::from_slice::<serde_json::Value>(&resp.body)
                    .ok()
                    .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned));
                if matches!(resp.status, 400 | 404)
                    && matches!(err_code.as_deref(), Some("RepoNotFound" | "RepoTakendown"))
                {
                    return Ok(None);
                }
                return Err(MLSError::InvalidState("ArchiveDeletionInventoryUnavailable".into()));
            }
            let (page_records, next_cursor) = super::chat_wire::parse_pds_list_records_page(
                did,
                super::deletion_authority::DEVICE_REVOCATION_COLLECTION,
                &resp.body,
            )?;
            let empty_page = page_records.is_empty();
            all_records.extend(page_records);
            if all_records.len() > expected_records || empty_page && next_cursor.is_some() {
                return Err(MLSError::InvalidState("ArchiveDeletionUnverified".into()));
            }
            match next_cursor {
                None => return Ok(Some(all_records)),
                Some(next) => {
                    if !seen_cursors.insert(next.clone())
                        || page_idx + 1 == max_pages
                    {
                        return Err(MLSError::InvalidState(
                            "ArchiveDeletionInventoryUnavailable".into(),
                        ));
                    }
                    cursor = Some(next);
                }
            }
        }
        Ok(Some(all_records))
    }

    /// Returns `Ok(true)` if `sender_did`'s PDS repo returned a terminal tombstone (`RepoNotFound`
    /// or `RepoTakendown`), `Ok(false)` if the live PDS has no self-deletion revocation record, or
    /// fails closed (`ArchiveDeletionUnverified` / `ArchiveDeletionInventoryUnavailable`) if the live
    /// PDS carries an unsequenced self-deletion record omitted by `getConversationState`.
    fn verify_foreign_sender_pds_deletion(
        &self,
        conversation_id: &str,
        sender_did: &str,
    ) -> Result<bool, MLSError> {
        let Some(doc_bytes) = self.resolve_did_document(sender_did).ok().flatten() else {
            return Err(MLSError::InvalidState(
                "ArchiveDeletionInventoryUnavailable".into(),
            ));
        };
        let Some(pds_endpoint) =
            super::chat_wire::extract_pds_endpoint_from_did_doc(&doc_bytes, sender_did)
        else {
            return Err(MLSError::InvalidState(
                "ArchiveDeletionInventoryUnavailable".into(),
            ));
        };
        let unavailable = || MLSError::InvalidState("ArchiveDeletionInventoryUnavailable".into());
        let unverified = || MLSError::InvalidState("ArchiveDeletionUnverified".into());
        let atproto_key =
            atproto_spaces::did_resolver::DidDocument::parse_json(sender_did, &doc_bytes)
                .ok()
                .and_then(|d| d.atproto_key)
                .ok_or_else(unavailable)?;
        let fetch_sync = |method: &str, cid: Option<&str>| {
            let mut url = format!(
                "{}/xrpc/com.atproto.sync.{method}?did={}",
                pds_endpoint.trim_end_matches('/'),
                super::chat_wire::urlencode_form_component(sender_did)
            );
            if let Some(cid) = cid {
                url.push_str("&cids=");
                url.push_str(&super::chat_wire::urlencode_form_component(cid));
            }
            self.transport
                .execute_http(PlatformHttpRequest {
                    method: "GET".into(),
                    url,
                    headers: vec![super::PlatformHttpHeader {
                        name: "cache-control".into(),
                        value: "no-cache".into(),
                    }],
                    body: None,
                })
                .map_err(|_| unavailable())
        };
        let head = fetch_sync("getLatestCommit", None)?;
        if matches!(head.status, 400 | 404)
            && serde_json::from_slice::<serde_json::Value>(&head.body)
                .ok()
                .is_some_and(|body| {
                    matches!(
                        body["error"].as_str(),
                        Some("RepoNotFound" | "RepoTakendown")
                    )
                })
        {
            return Ok(true);
        }
        if head.status != 200 {
            return Err(unavailable());
        }
        let head: serde_json::Value =
            serde_json::from_slice(&head.body).map_err(|_| unavailable())?;
        let head_cid = head["cid"].as_str().ok_or_else(unavailable)?;
        let head_rev = head["rev"].as_str().ok_or_else(unavailable)?;
        let mut inventory = crate::labyrinth::repo_proof::RevocationInventory::new(
            sender_did,
            head_cid,
            head_rev,
            &atproto_key,
        )
        .map_err(|_| unverified())?;
        let authenticated = loop {
            let Some(cid) = inventory.next_block() else {
                break inventory.finish().map_err(|_| unverified())?;
            };
            let reply = fetch_sync("getBlocks", Some(&cid))?;
            if reply.status == 200 {
                inventory.ingest(&reply.body).map_err(|_| unverified())?;
                continue;
            }
            let unsupported = matches!(reply.status, 404 | 405 | 501)
                || matches!(reply.status, 400)
                    && serde_json::from_slice::<serde_json::Value>(&reply.body)
                        .ok()
                        .is_some_and(|value| {
                            matches!(
                                value["error"].as_str(),
                                Some("MethodNotImplemented" | "XRPCNotSupported")
                            )
                        });
            if !unsupported {
                return Err(unavailable());
            }
            let snapshot = fetch_sync("getRepo", None)?;
            if snapshot.status != 200 {
                return Err(unavailable());
            }
            break crate::labyrinth::repo_proof::verify_revocation_inventory(
                &snapshot.body,
                sender_did,
                head_cid,
                head_rev,
                &atproto_key,
            )
            .map_err(|_| unverified())?;
        };
        crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
            &self.db,
            sender_did,
            head_rev,
            self.hooks.now_ms(),
        )
        .map_err(MLSError::Cryptography)?;
        let records = self
            .list_pds_revocations_or_tombstone(&pds_endpoint, sender_did, authenticated.len())?
            .ok_or_else(unavailable)?;
        let rev_prefix = format!(
            "at://{sender_did}/{}/",
            super::deletion_authority::DEVICE_REVOCATION_COLLECTION
        );
        let mut listed = Vec::with_capacity(records.len());
        for row in &records {
            let rkey = row["uri"]
                .as_str()
                .and_then(|uri| uri.strip_prefix(&rev_prefix))
                .ok_or_else(unverified)?;
            let cid = row["cid"].as_str().ok_or_else(unverified)?;
            let (actual, _) =
                crate::labyrinth::repo_proof::encode_atproto_json_record_dagcbor(&row["value"])
                    .map_err(|_| unverified())?;
            if actual.to_string() != cid {
                return Err(unverified());
            }
            listed.push((rkey.to_owned(), cid.to_owned()));
        }
        listed.sort_unstable();
        if listed != authenticated {
            return Err(unverified());
        }
        for rec_entry in &records {
            let Some(uri) = rec_entry.get("uri").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Some(rkey) = uri
                .strip_prefix(&rev_prefix)
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.contains('/'))
            else {
                continue;
            };
            let Some(val) = rec_entry.get("value") else {
                continue;
            };
            let is_self_deletion = val.get("actorDeviceId").and_then(serde_json::Value::as_str)
                == Some(rkey)
                && val.get("targetDeviceId").and_then(serde_json::Value::as_str) == Some(rkey)
                && val
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|r| {
                        r.starts_with(
                            super::deletion_authority::DELETE_ACCOUNT_DATA_REVOCATION_REASON_PREFIX,
                        )
                    });
            if !is_self_deletion {
                continue;
            }
            let Some(rev_cid) = rec_entry
                .get("cid")
                .and_then(serde_json::Value::as_str)
                .filter(|c| !c.is_empty())
            else {
                return Err(MLSError::InvalidState("ArchiveDeletionUnverified".into()));
            };
            let device_car = self
                .fetch_pds_record_car(
                    &pds_endpoint,
                    sender_did,
                    super::deletion_authority::DEVICE_RECORD_COLLECTION,
                    rkey,
                )
                .map_err(|_| MLSError::InvalidState("ArchiveDeletionInventoryUnavailable".into()))?;
            let revocation_car = self
                .fetch_pds_record_car(
                    &pds_endpoint,
                    sender_did,
                    super::deletion_authority::DEVICE_REVOCATION_COLLECTION,
                    rkey,
                )
                .map_err(|_| MLSError::InvalidState("ArchiveDeletionInventoryUnavailable".into()))?;
            let (_, dev_rev) = crate::labyrinth::repo_proof::verify_car_record_proof_with_rev(
                &device_car,
                sender_did,
                super::deletion_authority::DEVICE_RECORD_COLLECTION,
                rkey,
                &atproto_key,
            )
            .map_err(|_| MLSError::InvalidState("ArchiveDeletionUnverified".into()))?;
            crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
                &self.db,
                sender_did,
                &dev_rev,
                self.hooks.now_ms(),
            )
            .map_err(MLSError::Cryptography)?;
            let (_, rev_rev) =
                crate::labyrinth::repo_proof::verify_car_record_json_match_with_rev(
                    &revocation_car,
                    sender_did,
                    super::deletion_authority::DEVICE_REVOCATION_COLLECTION,
                    rkey,
                    Some(rev_cid),
                    val,
                    &atproto_key,
                )
                .map_err(|_| MLSError::InvalidState("ArchiveDeletionUnverified".into()))?;
            crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
                &self.db,
                sender_did,
                &rev_rev,
                self.hooks.now_ms(),
            )
            .map_err(MLSError::Cryptography)?;
            let verified = super::deletion_authority::verify_foreign_self_deletion_from_cars(
                &device_car,
                &revocation_car,
                sender_did,
                rkey,
                &doc_bytes,
            )
            .ok_or_else(|| MLSError::InvalidState("ArchiveDeletionUnverified".into()))?;
            // A matching operation must have passed sequencer and device proof
            // verification specifically in this conversation.
            let recorded = self.db.read_tx(|tx| tx.get_labyrinth_state(
                &super::chat_wire::account_deletion_key(conversation_id, sender_did),
            ))?.and_then(|raw| super::deletion_authority::AppliedAccountDeletion::decode(&raw));
            if !recorded.as_ref().and_then(|m| m.operation(&verified.operation_id))
                .is_some_and(|op| op.actor_device_id == verified.actor_device_id)
            {
                return Err(unverified());
            }
        }
        Ok(false)
    }

    pub fn open_rescued_owner_batch(&self, batch_json: &[u8]) -> Result<Vec<(String, Option<String>, Vec<u8>)>, MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test { return self.offline_open_rescued_owner_batch(batch_json); }
        let batch: labyrinth::records::OwnerBatch = serde_json::from_slice(batch_json).map_err(|e| MLSError::Cryptography(e.to_string()))?;
        self.pin_native_conversation(&batch.thread_id)?;
        let conversation_id = batch.thread_id.clone();
        let (prefetched_state, preverified_deletions) =
            self.preverify_conversation_deletions(&conversation_id)?;
        let mut messages = self.native_archive_run(async {
            let mut session = self
                .native_archive_deps_preverified(preverified_deletions)?
                .open()
                .await
                .map_err(native_archive_error)?
                .ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            session.open_owner_record(batch).await.map_err(native_archive_error)
        })?;
        let tombstoned_dids = self.apply_listed_account_deletions(
            &conversation_id,
            &messages,
            prefetched_state,
        )?;
        Self::hide_deleted_accounts(&self.db, &conversation_id, &tombstoned_dids, &mut messages)?;
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
        let (prefetched_state, preverified_deletions) =
            self.preverify_conversation_deletions(conversation_id)?;
        let (mut history, rejected) = self.native_archive_run(async {
            let deps = self.native_archive_deps_preverified(preverified_deletions)?;
            // A verified local roster that excludes this account is sufficient removal proof.
            // Without MLS state, the home DS's ConversationNotFound or NotEntitled is only a lead
            // (`Some(conversation unknown)`): authenticated owner evidence must pin the
            // conversation Space, and that Space's own authority must deny this account. An
            // unknown conversation without owner evidence has nothing to restore. Generic
            // 400/401/403 and directory errors fail closed.
            let (owner_only, denial_lead) = match local_has_self {
                Some(has_self) => (!has_self, None),
                None => match deps
                    .transport
                    .query(
                        "blue.catbird.chat.getConversationState",
                        &[("conversationId", conversation_id.to_owned())],
                    )
                    .await
                {
                    Ok(_) => (false, None),
                    Err(error)
                        if matches!(error.status, 400 | 404)
                            && error.error.as_deref() == Some("ConversationNotFound") =>
                    {
                        (false, Some(true))
                    }
                    Err(error)
                        if error.status == 400
                            && error.error.as_deref() == Some("NotEntitled") =>
                    {
                        (false, Some(false))
                    }
                    Err(error) => {
                        return Err(native_archive_error(crate::labyrinth::map_error(
                            crate::labyrinth::transport::map_xrpc_error(error),
                        )))
                    }
                },
            };
            let mut session = deps.open().await.map_err(native_archive_error)?.ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            if owner_only {
                return session
                    .load_owner_history(conversation_id)
                    .await
                    .map(|messages| (messages, 0))
                    .map_err(native_archive_error);
            }
            if let Some(conversation_unknown) = denial_lead {
                let owner = session
                    .load_owner_history(conversation_id)
                    .await
                    .map_err(native_archive_error)?;
                if conversation_unknown && owner.is_empty() {
                    return Ok((owner, 0));
                }
                self.pin_native_conversation_from_owner_history(conversation_id, &owner)?;
            }
            let history = session.load_history(conversation_id, labyrinth::store::TimeRange::ALL).await.map_err(native_archive_error)?;
            if denial_lead.is_some() && history.space_readable {
                return Err(MLSError::InvalidState(
                    "ArchiveRemovalUnverified".into(),
                ));
            }
            if history.undecryptable != 0 {
                return Err(MLSError::Cryptography("conversation archive contains corrupt or unverified frames".into()));
            }
            if history.not_recipient != 0 {
                tracing::debug!(conversation_id, skipped = history.not_recipient,
                    "labyrinth restore: skipped authenticated records outside this account's recipient interval");
            }
            Ok((history.messages, history.rejected))
        })?;
        if rejected > 0 {
            tracing::warn!(conversation_id, rejected, "labyrinth restore: ignored witness copies that contradict accepted archive copies");
        }
        let tombstoned_dids = self.apply_listed_account_deletions(
            conversation_id,
            &history,
            prefetched_state,
        )?;
        let deleted = Self::hide_deleted_accounts(
            &self.db,
            conversation_id,
            &tombstoned_dids,
            &mut history,
        )?;
        if deleted > 0 {
            tracing::info!(conversation_id, deleted, "labyrinth restore: hid archive copies of deleted accounts' messages");
        }
        let copies = native_restore_copies(conversation_id, &self.normalized_did, history)?;
        let (count, skipped) = self.db.write_tx(|tx| {
            let mut chosen = Vec::new();
            let mut skipped = 0usize;
            for group in copies.values() {
                let message_id = &group[0].0.message_id;
                let local = tx.get_message(message_id)?;
                // A placeholder under the original message id is the ordinary undecryptable
                // case. A pruned entry has no message id on the wire, so its unavailable
                // placeholder is keyed by entry id; replace that distinct row only when the
                // exact signed receipt and original-sender attestation bind it to one copy.
                let mut gap_key = None;
                for key in [super::chat_wire::undecryptable_evidence_key(conversation_id, message_id),
                    super::chat_wire::unavailable_message_key(conversation_id, message_id)] {
                    if gap_key.is_none() && tx.get_labyrinth_state(&key)?.is_some() { gap_key = Some(key); }
                }
                let direct_gap = local.is_some() && gap_key.is_some();
                let bound_placeholder = if local.is_none() {
                    bound_unavailable_placeholder(tx, conversation_id, group)?
                } else {
                    None
                };
                if let Some((_, evidence_key)) = &bound_placeholder {
                    gap_key = Some(evidence_key.clone());
                }
                let replaced_placeholder_id = bound_placeholder
                    .as_ref()
                    .map(|(placeholder, _)| placeholder.message_id.clone());
                let effective_local = local
                    .as_ref()
                    .or_else(|| bound_placeholder.as_ref().map(|(placeholder, _)| placeholder));
                let gap = direct_gap || bound_placeholder.is_some();
                match select_restore_copy(group, effective_local, gap) {
                    Some(copy) => chosen.push((
                        copy,
                        local.is_none() || gap,
                        if gap { gap_key } else { None },
                        replaced_placeholder_id,
                    )),
                    None => skipped += 1,
                }
            }
            chosen.sort_by(|((a, _, _), _, _, _), ((b, _, _), _, _, _)| a.seq.cmp(&b.seq).then_with(|| a.message_id.cmp(&b.message_id)));
            let mut count: u32 = 0;
            for ((row, evidence, _), write, gap_key, replaced_placeholder_id) in &chosen {
                if let Some(placeholder_id) = replaced_placeholder_id {
                    tx.conn()
                        .execute(
                            "DELETE FROM messages WHERE conversation_id = ?1 AND message_id = ?2",
                            rusqlite::params![conversation_id, placeholder_id],
                        )
                        .map_err(|e| {
                            MLSError::Internal(format!(
                                "replace authenticated unavailable placeholder: {e}"
                            ))
                        })?;
                }
                if *write { tx.insert_message(row)?; count += 1; }
                // The verified copy now stands in for the authenticated gap row.
                if let Some(gap_key) = gap_key {
                    tx.conn().execute("DELETE FROM labyrinth_state WHERE state_key = ?1", [gap_key])
                        .map_err(|e| MLSError::Internal(format!("clear undecryptable evidence: {e}")))?;
                }
                tx.put_labyrinth_state(&format!("native.message:{conversation_id}:{}", row.message_id),
                    &serde_json::to_vec(evidence).map_err(|e| MLSError::Internal(e.to_string()))?, self.hooks.now_ms())?;
            }
            // Archive recovery does not create MLS state or advance a live delivery cursor.
            if tx.get_conversation(conversation_id)?.is_none() {
                if let Some(((row, _, receipt), _, _, _)) = chosen.last() {
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

    fn rotate_native_archive(
        &self,
        target_device_id: Option<&str>,
    ) -> Result<NativeRotationResult, MLSError> {
        let key = target_device_id.map(|id| {
            hex::decode(id.trim()).ok().and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                .ok_or_else(|| MLSError::invalid_input("target_device_id must resolve to a 32-byte Labyrinth device key; UUID-only revocation is not supported"))
        }).transpose()?;
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test {
            let now_ms = self.hooks.now_ms();
            if let Some((remote_seq, remote_root)) =
                self.rotate_mailbox_epoch_if_supported(key.as_ref(), now_ms)?
            {
                self.db.write_tx(|tx| {
                    tx.put_labyrinth_state(
                        &owner_epoch_root_key(remote_seq),
                        remote_root.as_slice(),
                        now_ms,
                    )
                })?;
                return Ok(NativeRotationResult {
                    new_epoch: remote_seq,
                    exclusions: Vec::new(),
                    rekeyed_recovery_code: None,
                    rekeyed_passkeys: Vec::new(),
                });
            }
            if target_device_id.is_some() {
                return Err(MLSError::invalid_input(
                    "revocation requires an authenticated mailbox device key",
                ));
            }
            let next_seq = self.labyrinth_status()?.epoch_seq.saturating_add(1);
            self.db.write_tx(|tx| {
                let _ = ensure_owner_epoch_root(tx, next_seq, now_ms, &self.hooks)?;
                Ok(())
            })?;
            return Ok(NativeRotationResult {
                new_epoch: next_seq,
                exclusions: Vec::new(),
                rekeyed_recovery_code: None,
                rekeyed_passkeys: Vec::new(),
            });
        }
        // Even a v2 method invokes the configured share store on removal.
        // Prove the account's home DS before a rotation can reach that path;
        // a v3 share must never be silently left live on an unproven service.
        self.ensure_recovery_share_home_service_pin()?;
        let _guard = self.outbox_flush_lock.lock().map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            // Targeted revocation and ordinary rotation both report every dropped member,
            // including recovery bundles past their TTL.
            let report = match key {
                Some(key) => session.revoke_device(key).await,
                None => session.rotate_epoch().await,
            }
            .map_err(native_archive_error)?;
            if let Err(error) = self.save_native_archive_status(&session, report.rekeyed_recovery_code.is_some()) {
                tracing::warn!(%error, "archive rotation committed but status refresh failed");
            }
            Ok(NativeRotationResult {
                new_epoch: report.new_epoch,
                exclusions: report
                    .exclusions
                    .into_iter()
                    .map(|excluded| LabyrinthRotationExclusion {
                        device_key_hex: excluded.device_key.map(hex::encode),
                        reason: excluded.reason,
                        recovery_method: excluded
                            .recovery_method
                            .map(|method| method.as_str().to_owned()),
                    })
                    .collect(),
                rekeyed_recovery_code: report.rekeyed_recovery_code,
                rekeyed_passkeys: report
                    .rekeyed_passkeys
                    .into_iter()
                    .map(|id| id.to_vec())
                    .collect(),
            })
        })
    }

    pub fn restore_with_passkey_prf(
        &self,
        credential_id: Vec<u8>,
        prf_output_32: Vec<u8>,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        if credential_id.is_empty() || prf_output_32.len() != 32 {
            return Err(MLSError::invalid_input(
                "passkey PRF restore requires non-empty credential_id and 32-byte PRF output",
            ));
        }
        let prf_output_32 = Zeroizing::new(prf_output_32);
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test {
            return self.offline_restore_with_passkey_prf(&credential_id, &prf_output_32);
        }
        if self
            .db
            .read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?
            .is_none()
        {
            self.enroll_device(
                &super::REQUIRED_LABYRINTH_OAUTH_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned())
                    .collect::<Vec<_>>(),
            )?;
        }
        let requires_share = self.native_archive_run(async {
            self.native_archive_deps()?
                .passkey_recovery_requires_share(&credential_id, &prf_output_32)
                .await
                .map_err(native_archive_error)
        })?;
        if requires_share {
            self.ensure_recovery_share_home_service_pin()?;
        }
        let status = {
            let _guard = self
                .outbox_flush_lock
                .lock()
                .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
            self.native_archive_run(async {
                let session = self
                    .native_archive_deps()?
                    .restore_with_passkey_prf(&credential_id, &prf_output_32)
                    .await
                    .map_err(native_archive_error)?;
                self.save_native_archive_status(&session, false)
            })?
        };
        let now_ms = self.hooks.now_ms();
        let updated = self.db.write_tx(|tx| {
            let raw = tx
                .get_labyrinth_state("status_json")?
                .ok_or_else(|| MLSError::InvalidState("archive status missing".into()))?;
            let mut st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            st.has_passkey_prf = true;
            st.rotation_exclusions
                .retain(|exclusion| exclusion.recovery_method.as_deref() != Some("passkey"));
            tx.put_labyrinth_state("passkey_credential_id", &credential_id, now_ms)?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                now_ms,
            )?;
            Ok(st)
        })?;
        self.finish_pending_approval_after_archive_promotion(
            status.pending_directory_epoch.is_none(),
        );
        self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
            epoch_seq: updated.epoch_seq,
        });
        Ok(updated)
    }

    pub(super) fn ensure_native_archive_ready_for_otc_offer(&self) -> Result<(), MLSError> {
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        if self.offline_archive_for_test {
            return Ok(());
        }
        if self
            .db
            .read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?
            .is_none()
        {
            return Ok(());
        }
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let deps = self.native_archive_deps()?;
            let session = match deps.clone().open().await.map_err(native_archive_error)? {
                Some(session) => session,
                None => deps.enable().await.map_err(native_archive_error)?,
            };
            let status = self.save_native_archive_status(&session, false)?;
            if let Some(error) = status.directory_publication_error {
                return Err(MLSError::InvalidState(format!(
                    "archive directory is not ready for an OTC offer: {error}"
                )));
            }
            if let Some(epoch) = status.pending_directory_epoch {
                return Err(MLSError::InvalidState(format!(
                    "archive epoch {epoch} is still pending directory publication"
                )));
            }
            Ok(())
        })
    }

    pub(super) fn start_live_otc_pairing(
        &self,
        six_digit_code: &str,
    ) -> Result<OtcInitiatedSession, MLSError> {
        let parsed = labyrinth::otc::OneTimeCode::parse(six_digit_code)
            .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?;
        let code_digest: [u8; 32] = sha2::Sha256::digest(parsed.as_str().as_bytes()).into();
        if self
            .db
            .read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?
            .is_none()
        {
            self.enroll_device(
                &super::REQUIRED_LABYRINTH_OAUTH_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned())
                    .collect::<Vec<_>>(),
            )?;
        }
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        let now_ms = self.hooks.now_ms().max(0) as u64;
        let (initiator, session_id_hex, expires_at_ms, ek_len) = self.native_archive_run(async {
            self.native_archive_deps()?
                .start_otc_session(parsed.as_str(), now_ms)
                .await
                .map_err(native_archive_error)
        })?;
        let mut guard = self
            .pending_otc_initiator
            .lock()
            .map_err(|_| MLSError::lock_poisoned("pending_otc_initiator"))?;
        *guard = Some((session_id_hex.clone(), initiator, ek_len, code_digest));
        Ok(OtcInitiatedSession {
            session_id_hex,
            expires_at_ms: i64::try_from(expires_at_ms).unwrap_or(i64::MAX),
            initiator_mlkem768_ek_len: ek_len,
        })
    }

    pub(super) fn respond_live_otc_pairing(
        &self,
        session_id_hex: &str,
        six_digit_code: Option<&str>,
    ) -> Result<(), MLSError> {
        let now_ms = self.hooks.now_ms();
        let mem_digits = self
            .pending_otc_offer_digits
            .lock()
            .map_err(|_| MLSError::lock_poisoned("pending_otc_offer_digits"))?
            .clone();
        let resolved_digits = self.db.write_tx(|tx| {
            let maybe_offer = tx.get_labyrinth_state("pending_otc_offer")?;
            if let Some(raw_offer) = maybe_offer {
                let mut offer: serde_json::Value = serde_json::from_slice(&raw_offer)
                    .map_err(|e| MLSError::Internal(format!("parse pending_otc_offer: {e}")))?;
                let expires_at_ms = offer["expires_at_ms"].as_i64().unwrap_or(0);
                if now_ms >= expires_at_ms {
                    let _ = tx.conn().execute(
                        "DELETE FROM labyrinth_state WHERE state_key IN ('pending_otc_offer', 'pending_otc_digits')",
                        [],
                    );
                    return Ok(Err(MLSError::InvalidState("OTC offer expired".into())));
                }
                let attempts = offer["attempts"].as_u64().unwrap_or(0);
                if attempts >= u64::from(labyrinth::otc::MAX_ATTEMPTS) {
                    let _ = tx.conn().execute(
                        "DELETE FROM labyrinth_state WHERE state_key IN ('pending_otc_offer', 'pending_otc_digits')",
                        [],
                    );
                    return Ok(Err(MLSError::insufficient_permissions(
                        "OTC offer exceeded maximum attempts",
                    )));
                }
                let salt_bytes = hex::decode(
                    offer["salt_hex"]
                        .as_str()
                        .ok_or_else(|| MLSError::Internal("pending_otc_offer missing salt_hex".into()))?,
                )
                .map_err(|e| MLSError::Internal(format!("decode OTC salt_hex: {e}")))?;
                let expected_digest = offer["code_digest_hex"]
                    .as_str()
                    .ok_or_else(|| {
                        MLSError::Internal("pending_otc_offer missing code_digest_hex".into())
                    })?
                    .to_owned();
                let candidate = match six_digit_code {
                    Some(provided) => labyrinth::otc::OneTimeCode::parse(provided)
                        .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?
                        .as_str()
                        .to_owned(),
                    None => mem_digits
                        .as_ref()
                        .map(|z| z.as_str().to_owned())
                        .ok_or_else(|| {
                            MLSError::InvalidState(
                                "Active OTC offer requires six_digit_code after client restart"
                                    .into(),
                            )
                        })?,
                };
                let mut hasher = sha2::Sha256::new();
                hasher.update(b"catbird.otc.offer.v1\0");
                hasher.update(&salt_bytes);
                hasher.update(candidate.as_bytes());
                let candidate_digest = hex::encode(hasher.finalize());
                let next_attempts = attempts.saturating_add(1);
                offer["attempts"] = serde_json::json!(next_attempts);
                tx.put_labyrinth_state(
                    "pending_otc_offer",
                    &serde_json::to_vec(&offer)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    now_ms,
                )?;
                if candidate_digest != expected_digest {
                    return Ok(Err(MLSError::insufficient_permissions(
                        "OTC code does not match active offer",
                    )));
                }
                return Ok(Ok(zeroize::Zeroizing::new(candidate)));
            }
            let Some(provided) = six_digit_code else {
                return Err(MLSError::InvalidState(
                    "No active OTC offer on this device; pass six_digit_code or call initiate_otc_pairing first".into(),
                ));
            };
            let parsed = labyrinth::otc::OneTimeCode::parse(provided)
                .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?;
            Ok(Ok(zeroize::Zeroizing::new(parsed.as_str().to_owned())))
        })?;
        let digits = match resolved_digits {
            Ok(d) => d,
            Err(err) => {
                if matches!(err, MLSError::InvalidState(_))
                    || matches!(err, MLSError::InsufficientPermissions { .. })
                {
                    let still_active = self
                        .db
                        .read_tx(|tx| tx.get_labyrinth_state("pending_otc_offer"))?
                        .is_some();
                    if !still_active {
                        if let Ok(mut guard) = self.pending_otc_offer_digits.lock() {
                            *guard = None;
                        }
                    }
                }
                return Err(err);
            }
        };
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let deps = self.native_archive_deps()?;
            let mailbox = deps.open_mailbox_store().map_err(native_archive_error)?;
            let mut session = deps
                .open()
                .await
                .map_err(native_archive_error)?
                .ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            session
                .respond_otc_session(
                    &mailbox,
                    session_id_hex,
                    digits.as_str(),
                    now_ms.max(0) as u64,
                )
                .await
                .map_err(native_archive_error)?;
            self.save_native_archive_status(&session, false)?;
            Ok::<_, MLSError>(())
        })?;
        let _ = self.db.write_tx(|tx| {
            let _ = tx.conn().execute(
                "DELETE FROM labyrinth_state WHERE state_key IN ('pending_otc_offer', 'pending_otc_digits')",
                [],
            );
            Ok(())
        });
        if let Ok(mut guard) = self.pending_otc_offer_digits.lock() {
            *guard = None;
        }
        Ok(())
    }

    pub(super) fn complete_live_otc_pairing(
        &self,
        six_digit_code: &str,
    ) -> Result<OtcPairingCompletion, MLSError> {
        let provided_digest: [u8; 32] = sha2::Sha256::digest(six_digit_code.as_bytes()).into();
        let (session_id_hex, initiator, ek_len) = {
            let mut guard = self
                .pending_otc_initiator
                .lock()
                .map_err(|_| MLSError::lock_poisoned("pending_otc_initiator"))?;
            let Some((_, _, _, expected_digest)) = guard.as_ref() else {
                return Err(MLSError::InvalidState(
                    "No pending live OTC initiator session".into(),
                ));
            };
            if *expected_digest != provided_digest {
                return Err(MLSError::insufficient_permissions(
                    "OTC code does not match initiated session",
                ));
            }
            let (sid, init, ek, _) = guard.take().expect("checked Some");
            (sid, init, ek)
        };
        let session_id = hex::decode(&session_id_hex)
            .map_err(|_| MLSError::Internal("invalid OTC session_id_hex".into()))?;
        let (new_epoch_seq, kem_ct_len, promoted) = {
            let _guard = self
                .outbox_flush_lock
                .lock()
                .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
            let now_ms = self.hooks.now_ms().max(0) as u64;
            self.native_archive_run(async {
                let (session, new_epoch, kem_ct_len) = self
                    .native_archive_deps()?
                    .complete_otc_session(initiator, &session_id_hex, now_ms)
                    .await
                    .map_err(native_archive_error)?;
                let status = self.save_native_archive_status(&session, false)?;
                Ok::<_, MLSError>((
                    status.epoch_seq.max(new_epoch),
                    kem_ct_len,
                    status.pending_directory_epoch.is_none(),
                ))
            })?
        };
        let ts = self.hooks.now_ms();
        self.db.write_tx(|tx| {
            let raw = tx
                .get_labyrinth_state("status_json")?
                .ok_or_else(|| MLSError::InvalidState("archive status missing".into()))?;
            let mut st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            st.epoch_seq = new_epoch_seq;
            if !st.active_device_ids.contains(&self.config.device_id) {
                st.active_device_ids.push(self.config.device_id.clone());
            }
            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: format!("otc-epoch-{new_epoch_seq}"),
                op_type: "epoch_rotation".to_string(),
                epoch_seq: new_epoch_seq,
                state_json: serde_json::json!({
                    "trigger": "otc_pq_pairing",
                    "sessionId": session_id_hex,
                })
                .to_string(),
                status: "completed".to_string(),
                created_at_ms: ts,
                updated_at_ms: ts,
            })?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )
        })?;
        self.finish_pending_approval_after_archive_promotion(promoted);
        self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
            epoch_seq: new_epoch_seq,
        });
        Ok(OtcPairingCompletion {
            session_id,
            initiator_mlkem768_ek_len: ek_len,
            responder_mlkem768_ct_len: kem_ct_len,
            new_epoch_seq,
        })
    }

    /// Re-verifies local history rows for `conversation_id` against authenticated Space and
    /// `OwnerMailbox` records carrying ES256 sequencer receipts (`I13`), purging any local
    /// unverified history rows that lack or contradict verified archive evidence and importing
    /// missing verified archive rows.
    pub fn verify_and_reindex_history(&self, conversation_id: &str) -> Result<u32, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.pin_native_conversation(conversation_id)?;
        let (prefetched_state, preverified_deletions) =
            self.preverify_conversation_deletions(conversation_id)?;
        let mut history = self.native_archive_run(async {
            let deps = self.native_archive_deps_preverified(preverified_deletions)?;
            let mut session = deps
                .open()
                .await
                .map_err(native_archive_error)?
                .ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
            let page = session
                .load_history(conversation_id, labyrinth::store::TimeRange::ALL)
                .await
                .map_err(native_archive_error)?;
            if page.undecryptable != 0 {
                return Err(MLSError::Cryptography(
                    "conversation archive contains corrupt or unverified frames".into(),
                ));
            }
            Ok::<_, MLSError>(page.messages)
        })?;
        let tombstoned_dids = self.apply_listed_account_deletions(
            conversation_id,
            &history,
            prefetched_state,
        )?;
        Self::hide_deleted_accounts(&self.db, conversation_id, &tombstoned_dids, &mut history)?;
        let copies = native_restore_copies(conversation_id, &self.normalized_did, history)?;
        let verified = self.db.write_tx(|tx| {
            let mut chosen_by_id = std::collections::BTreeMap::new();
            for group in copies.values() {
                let message_id = &group[0].0.message_id;
                if tx
                    .get_labyrinth_state(&unsent_message_key(conversation_id, message_id))?
                    .is_some()
                {
                    continue;
                }
                let local = tx.get_message(message_id)?;
                let raw_evidence = tx.get_labyrinth_state(&format!(
                    "native.message:{conversation_id}:{message_id}"
                ))?;
                let retained_receipt = raw_evidence
                    .as_deref()
                    .and_then(|raw| serde_json::from_slice::<NativeArchiveEvidence>(raw).ok())
                    .filter(|evidence| {
                        evidence.conversation_id == conversation_id
                            && evidence.message_id == *message_id
                    })
                    .and_then(|evidence| evidence.sequencer_receipt_json)
                    .and_then(|json| {
                        serde_json::from_str::<super::chat_wire::StoredArchivedReceipt>(&json).ok()
                    });
                let has_local_evidence = retained_receipt.is_some();
                let mut gap_key = None;
                for key in [
                    super::chat_wire::undecryptable_evidence_key(
                        conversation_id,
                        message_id,
                    ),
                    super::chat_wire::unavailable_message_key(conversation_id, message_id),
                ] {
                    if gap_key.is_none() && tx.get_labyrinth_state(&key)?.is_some() {
                        gap_key = Some(key);
                    }
                }
                let direct_gap = local.is_some() && gap_key.is_some();
                let bound_placeholder = if local.is_none() {
                    bound_unavailable_placeholder(tx, conversation_id, group)?
                } else {
                    None
                };
                if let Some((_, evidence_key)) = &bound_placeholder {
                    gap_key = Some(evidence_key.clone());
                }
                let effective_local = if has_local_evidence || direct_gap {
                    local.as_ref()
                } else {
                    bound_placeholder
                        .as_ref()
                        .map(|(placeholder, _)| placeholder)
                };
                let gap = direct_gap || bound_placeholder.is_some();
                // Earlier reindex versions wrote verified evidence beside an unchanged stale
                // display row. The same freshly verified receipt also identifies the repair copy.
                let receipt_copy = retained_receipt
                    .as_ref()
                    .and_then(|receipt| group.iter().find(|(_, _, signed)| signed == receipt));
                if let Some(copy) =
                    receipt_copy.or_else(|| select_restore_copy(group, effective_local, gap))
                {
                    chosen_by_id.insert(
                        message_id.clone(),
                        (
                            copy,
                            gap.then_some(gap_key).flatten(),
                            bound_placeholder
                                .map(|(placeholder, _)| placeholder.message_id),
                        ),
                    );
                }
            }
            let replaced_placeholders: std::collections::BTreeSet<_> = chosen_by_id
                .values()
                .filter_map(|(_, _, placeholder_id)| placeholder_id.clone())
                .collect();
            // Rebuild rows without local evidence from the authenticated copy.
            // Scan by primary key inside this transaction so equal sequences,
            // page boundaries and deletions cannot drop rows between batches.
            let mut after: Option<String> = None;
            loop {
                let mut statement = tx.conn().prepare(
                    "SELECT message_id FROM messages WHERE conversation_id = ?1
                     AND (?2 IS NULL OR message_id > ?2)
                     ORDER BY message_id LIMIT 500"
                ).map_err(|e| MLSError::Internal(e.to_string()))?;
                let ids = statement.query_map(rusqlite::params![conversation_id, after], |row| row.get::<_, String>(0))
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>().map_err(|e| MLSError::Internal(e.to_string()))?;
                let Some(last) = ids.last() else { break };
                after = Some(last.clone());
                for id in ids {
                    if replaced_placeholders.contains(&id)
                        || tx.get_labyrinth_state(&format!("native.message:{conversation_id}:{id}"))?.is_some()
                        || tx.get_labyrinth_state(&unsent_message_key(conversation_id, &id))?.is_some() {
                        continue;
                    }
                    if let Some(row) = tx.get_message(&id)? {
                        if is_stored_unavailable_placeholder(tx, conversation_id, &row)? {
                            continue;
                        }
                    }
                    tx.conn().execute("DELETE FROM messages WHERE conversation_id=?1 AND message_id=?2",
                        rusqlite::params![conversation_id, id]).map_err(|e| MLSError::Internal(e.to_string()))?;
                }
            }
            let mut count = 0u32;
            for ((row, evidence, evidence_receipt), gap_key, replaced_placeholder_id) in
                chosen_by_id.into_values()
            {
                if let Some(placeholder_id) = replaced_placeholder_id {
                    tx.conn()
                        .execute(
                            "DELETE FROM messages WHERE conversation_id = ?1 AND message_id = ?2",
                            rusqlite::params![conversation_id, placeholder_id],
                        )
                        .map_err(|e| {
                            MLSError::Internal(format!(
                                "replace authenticated unavailable placeholder: {e}"
                            ))
                        })?;
                }
                tx.insert_message_with_commitment(
                    row,
                    Some(&evidence_receipt.archive_commitment),
                    evidence.sequencer_receipt_json.as_deref(),
                )?;
                if let Some(gap_key) = gap_key {
                    tx.conn()
                        .execute("DELETE FROM labyrinth_state WHERE state_key = ?1", [&gap_key])
                        .map_err(|e| {
                            MLSError::Internal(format!("clear undecryptable evidence: {e}"))
                        })?;
                }
                tx.put_labyrinth_state(
                    &format!("native.message:{conversation_id}:{}", row.message_id),
                    &serde_json::to_vec(&evidence)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    self.hooks.now_ms(),
                )?;
                count = count.saturating_add(1);
            }
            Ok(count)
        })?;
        self.notify(PlatformChangeEvent::MessagesUpdated {
            conversation_id: conversation_id.to_owned(),
        });
        Ok(verified)
    }

    pub fn propose_peer_repin(&self, peer_did: &str) -> Result<PeerRepinProposalInfo, MLSError> {
        const PEER_REPIN_HOLD_MS: i64 = 72 * 60 * 60 * 1000;
        let peer_did = super::normalize_account_did(peer_did)?;
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        let proposal = self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            session
                .propose_repin(&peer_did)
                .await
                .map_err(native_archive_error)
        })?;
        let offered_head_hex = hex::encode(proposal.offered_head);
        let hold_key = format!("native.repin_hold:{peer_did}:{offered_head_hex}");
        let now_ms = self.hooks.now_ms();
        let first_seen_ms = self.db.write_tx(|tx| {
            if let Some(raw) = tx.get_labyrinth_state(&hold_key)? {
                if let Some(ts) = std::str::from_utf8(&raw).ok().and_then(|s| s.parse::<i64>().ok()) {
                    return Ok(ts);
                }
            }
            tx.put_labyrinth_state(&hold_key, now_ms.to_string().as_bytes(), now_ms)?;
            Ok(now_ms)
        })?;
        let eligible_at_ms = first_seen_ms.saturating_add(PEER_REPIN_HOLD_MS);
        let hold_remaining_ms = (eligible_at_ms - now_ms).max(0);
        Ok(PeerRepinProposalInfo {
            did: proposal.did,
            previous_seq: proposal.pinned_seq,
            old_safety_number: proposal.old_safety_number,
            offered_seq: proposal.offered_seq,
            offered_head_hex,
            safety_number: proposal.new_safety_number,
            eligible_at_ms,
            hold_remaining_ms,
        })
    }

    pub fn repin_peer(&self, peer_did: &str, confirmed_head: Vec<u8>) -> Result<(), MLSError> {
        const PEER_REPIN_HOLD_MS: i64 = 72 * 60 * 60 * 1000;
        let peer_did = super::normalize_account_did(peer_did)?;
        let head: [u8; 32] = confirmed_head
            .try_into()
            .map_err(|_| MLSError::invalid_input("confirmed_head must be 32 bytes"))?;
        let head_hex = hex::encode(head);
        let hold_key = format!("native.repin_hold:{peer_did}:{head_hex}");
        let now_ms = self.hooks.now_ms();
        let first_seen_ms = self
            .db
            .read_tx(|tx| tx.get_labyrinth_state(&hold_key))?
            .and_then(|raw| String::from_utf8(raw).ok()?.parse::<i64>().ok())
            .ok_or_else(|| {
                MLSError::InvalidState(
                    "PeerRepinProposalRequired: call propose_peer_repin before repin_peer".into(),
                )
            })?;
        let eligible_at_ms = first_seen_ms.saturating_add(PEER_REPIN_HOLD_MS);
        if now_ms < eligible_at_ms {
            return Err(MLSError::InvalidState(format!(
                "PeerRepinHoldActive: {}ms remaining before peer chain reset can be accepted",
                eligible_at_ms - now_ms
            )));
        }
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            session
                .repin_peer(&peer_did, head)
                .await
                .map_err(native_archive_error)?;
            self.save_native_archive_status(&session, false)?;
            Ok::<_, MLSError>(())
        })?;
        self.db.write_tx(|tx| {
            tx.conn()
                .execute("DELETE FROM labyrinth_state WHERE state_key = ?1", [&hold_key])
                .map_err(|e| MLSError::Internal(format!("clear repin_hold: {e}")))?;
            Ok(())
        })
    }

    pub fn upload_conversation_attachment(
        &self,
        conversation_id: &str,
        plaintext: Vec<u8>,
        mime_type: String,
    ) -> Result<UploadedConversationAttachment, MLSError> {
        if conversation_id.trim().is_empty() {
            return Err(MLSError::invalid_input("conversation_id must not be empty"));
        }
        if plaintext.is_empty() {
            return Err(MLSError::invalid_input(
                "attachment plaintext must not be empty",
            ));
        }
        let encrypted = crate::blob_crypto::encrypt_blob(&plaintext)
            .map_err(|e| MLSError::Cryptography(format!("encrypt attachment: {e}")))?;
        let meta = labyrinth::attachment::AttachmentCiphertextMeta::from_ciphertext(
            &encrypted.ciphertext,
            (!mime_type.is_empty()).then(|| mime_type.clone()),
        )
        .map_err(|e| MLSError::invalid_input(format!("attachment metadata: {e}")))?;
        self.pin_native_conversation(conversation_id)?;
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        let created_at = labyrinth::records::datetime_from_ms(self.hooks.now_ms().max(0) as u64);
        let (space_uri, cid, rkey) = self.native_archive_run(async {
            use labyrinth::store::ThreadStore as _;
            let deps = self.native_archive_deps()?;
            let store = deps
                .resolving_thread_store()
                .map_err(native_archive_error)?;
            let out = store
                .upload_conversation_attachment_blob(
                    conversation_id,
                    &encrypted.ciphertext,
                    &meta,
                    &created_at,
                )
                .await
                .map_err(|e| native_archive_error(crate::labyrinth::map_error(e)))?;
            crate::labyrinth::SessionDeps::persist_writer_rev_floors(
                &*deps.placements,
                &deps.did,
                &store.export_writer_rev_floors(),
            );
            Ok::<_, MLSError>(out)
        })?;
        let locator = format!("{space_uri}|{}|{cid}", self.normalized_did);
        Ok(UploadedConversationAttachment {
            locator,
            space_uri,
            repo_did: self.normalized_did.clone(),
            cid,
            rkey,
            symmetric_key: encrypted.key,
            iv: encrypted.iv,
            ciphertext_sha256: meta.sha256.to_vec(),
            ciphertext_size: meta.ciphertext_size,
            mime_type,
        })
    }

    pub fn get_read_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<MailboxReadStateRecord>, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let state = session
                .get_read_state(conversation_id)
                .await
                .map_err(native_archive_error)?;
            Ok(state.map(|s| MailboxReadStateRecord {
                conversation_id: s.conversation_id,
                read_through_seq: s.read_through_seq,
                updated_at: s.updated_at,
            }))
        })
    }

    pub fn advance_read_state(
        &self,
        conversation_id: &str,
        candidate_seq: u64,
    ) -> Result<MailboxReadStateRecord, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let s = session
                .advance_read_state(conversation_id, candidate_seq)
                .await
                .map_err(native_archive_error)?;
            Ok(MailboxReadStateRecord {
                conversation_id: s.conversation_id,
                read_through_seq: s.read_through_seq,
                updated_at: s.updated_at,
            })
        })
    }

    pub fn list_read_states(&self) -> Result<Vec<MailboxReadStateRecord>, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let list = session
                .list_read_states()
                .await
                .map_err(native_archive_error)?;
            Ok(list
                .into_iter()
                .map(|s| MailboxReadStateRecord {
                    conversation_id: s.conversation_id,
                    read_through_seq: s.read_through_seq,
                    updated_at: s.updated_at,
                })
                .collect())
        })
    }

    fn circle_owner_state_to_dto(
        state: labyrinth::client::CircleOwnerState,
        record_cid: Option<String>,
    ) -> Result<CircleOwnerStateDto, MLSError> {
        Ok(CircleOwnerStateDto {
            circle_id: state.circle_id,
            space_uri: state.space_uri,
            current_key_version: state.current_key_version,
            joined_at_version_json: serde_json::to_string(&state.joined_at_version_by_did)
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            pending_ops_json: serde_json::to_string(&state.pending_ops)
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            updated_at: state.updated_at,
            record_cid,
        })
    }

    fn circle_owner_state_from_dto(
        dto: &CircleOwnerStateDto,
        default_now_rfc3339: &str,
    ) -> Result<labyrinth::client::CircleOwnerState, MLSError> {
        let joined_at_version_by_did: std::collections::BTreeMap<String, u64> =
            if dto.joined_at_version_json.trim().is_empty() {
                std::collections::BTreeMap::new()
            } else {
                serde_json::from_str(&dto.joined_at_version_json).map_err(|e| {
                    MLSError::invalid_input(format!("invalid joined_at_version_json: {e}"))
                })?
            };
        let pending_ops: std::collections::BTreeMap<String, String> =
            if dto.pending_ops_json.trim().is_empty() {
                std::collections::BTreeMap::new()
            } else {
                serde_json::from_str(&dto.pending_ops_json)
                    .map_err(|e| MLSError::invalid_input(format!("invalid pending_ops_json: {e}")))?
            };
        let updated_at = if dto.updated_at.trim().is_empty() {
            default_now_rfc3339.to_owned()
        } else {
            dto.updated_at.clone()
        };
        let state = labyrinth::client::CircleOwnerState {
            circle_id: dto.circle_id.clone(),
            space_uri: dto.space_uri.clone(),
            current_key_version: dto.current_key_version,
            joined_at_version_by_did,
            pending_ops,
            updated_at,
        };
        state
            .validate()
            .map_err(|e| MLSError::invalid_input(format!("circleOwnerState: {e}")))?;
        Ok(state)
    }

    pub fn get_circle_owner_state(
        &self,
        circle_id: &str,
    ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let found = session
                .get_circle_owner_state(circle_id)
                .await
                .map_err(native_archive_error)?;
            found
                .map(|(state, cid)| Self::circle_owner_state_to_dto(state, cid))
                .transpose()
        })
    }

    pub fn put_circle_owner_state(
        &self,
        state: CircleOwnerStateDto,
        swap_record_cid: Option<String>,
    ) -> Result<String, MLSError> {
        let now = labyrinth::records::datetime_from_ms(self.hooks.now_ms().max(0) as u64);
        let parsed = Self::circle_owner_state_from_dto(&state, &now)?;
        let expected_cid = swap_record_cid.or_else(|| state.record_cid.clone());
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            session
                .put_circle_owner_state(&parsed, expected_cid.as_deref())
                .await
                .map_err(native_archive_error)
        })
    }

    pub fn merge_circle_owner_state(
        &self,
        update: CircleOwnerStateDto,
    ) -> Result<CircleOwnerStateDto, MLSError> {
        let now = labyrinth::records::datetime_from_ms(self.hooks.now_ms().max(0) as u64);
        let parsed = Self::circle_owner_state_from_dto(&update, &now)?;
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let (merged, cid) = session
                .merge_circle_owner_state(&parsed)
                .await
                .map_err(native_archive_error)?;
            Self::circle_owner_state_to_dto(merged, Some(cid))
        })
    }

    pub fn clear_circle_acl_tombstone(
        &self,
        circle_id: &str,
        member_did: &str,
    ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let cleared = session
                .clear_circle_acl_tombstone(circle_id, member_did)
                .await
                .map_err(native_archive_error)?;
            cleared
                .map(|(state, cid)| Self::circle_owner_state_to_dto(state, (!cid.is_empty()).then_some(cid)))
                .transpose()
        })
    }

    pub fn list_circle_owner_states(&self) -> Result<Vec<CircleOwnerStateDto>, MLSError> {
        let _guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
        self.native_archive_run(async {
            let mut session = self
                .native_archive_deps()?
                .enable()
                .await
                .map_err(native_archive_error)?;
            let list = session
                .list_circle_owner_states()
                .await
                .map_err(native_archive_error)?;
            list.into_iter()
                .map(|state| Self::circle_owner_state_to_dto(state, None))
                .collect()
        })
    }

    /// Fail-closed full account deletion (`D-3`): persists retry state, publishes a self-signed
    /// `blue.catbird.chat.deviceRevocation/{own_device_id}` record on PDS (aborting before DS call
    /// if a sibling device already revoked this device), fetches and locally verifies CARv1 proofs
    /// for `device` + `deviceRevocation`, purges remote OwnerMailbox/PDS/DS state with both
    /// proofs attached, and finally wipes local SQLCipher + Keychain state.
    pub fn delete_account_data(&self) -> Result<(), MLSError> {
        self.delete_account_data_impl(false)
    }

    pub fn delete_account_data_for_hosted_account(&self) -> Result<(), MLSError> {
        self.delete_account_data_impl(true)
    }

    fn delete_account_data_impl(&self, require_peer_completion: bool) -> Result<(), MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct DeleteAccountRetryState {
            operation_id: String,
            #[serde(alias = "signedAtMs")]
            created_at_ms: i64,
        }
        const RETRY_META_KEY: &str = "delete_account_retry_state";
        {
            let _guard = self
                .outbox_flush_lock
                .lock()
                .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
            if self.is_device_pending_approval()? {
                return Err(MLSError::PendingDeviceAccess {
                    reason: "DevicePendingApproval".into(),
                });
            }
            let deps = self.native_archive_deps()?;
            let own_device_id = self
                .canonical_uuid_v4_device_id()
                .ok_or_else(|| MLSError::invalid_input("archive requires UUIDv4 device_id"))?;
            let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
            let signer_pk: [u8; 32] = signer
                .public()
                .try_into()
                .map_err(|_| MLSError::Cryptography("archive chat key is not Ed25519".into()))?;

            let existing_retry = self
                .db
                .read_tx(|tx| tx.get_account_meta(RETRY_META_KEY))?
                .and_then(|raw| serde_json::from_str::<DeleteAccountRetryState>(&raw).ok())
                .and_then(|state| {
                    let op_vec = hex::decode(&state.operation_id).ok()?;
                    let op_id: [u8; 16] = op_vec.try_into().ok()?;
                    let _ = chrono::DateTime::from_timestamp_millis(state.created_at_ms)?;
                    Some((op_id, state.operation_id, state.created_at_ms))
                });
            let (operation_id, op_hex, created_at_ms) = match existing_retry {
                Some(loaded) => loaded,
                None => {
                    // Probe PDS for an existing deviceRevocation record (e.g. sibling revocation)
                    // before persisting local retry state so we never poison `RETRY_META_KEY`.
                    let probe_url = format!(
                        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
                        self.pds_base(),
                        super::chat_wire::urlencode_form_component(&self.normalized_did),
                        super::chat_wire::urlencode_form_component(
                            super::deletion_authority::DEVICE_REVOCATION_COLLECTION,
                        ),
                        super::chat_wire::urlencode_form_component(&own_device_id),
                    );
                    if let Ok(probe_resp) = self.transport.execute_http(PlatformHttpRequest {
                        method: "GET".to_string(),
                        url: probe_url,
                        headers: Vec::new(),
                        body: None,
                    }) {
                        if probe_resp.status == 200
                            && serde_json::from_slice::<serde_json::Value>(&probe_resp.body)
                                .ok()
                                .and_then(|v| v.get("value").cloned())
                                .is_some()
                        {
                            return Err(MLSError::InvalidState(format!(
                                "EnrollmentPdsRecordConflict:{}/{own_device_id}",
                                super::deletion_authority::DEVICE_REVOCATION_COLLECTION
                            )));
                        }
                    }
                    let mut op_id = [0u8; 16];
                    self.hooks
                        .with_labyrinth_rng(|| labyrinth::encoding::random(&mut op_id))
                        .map_err(|e| native_archive_error(crate::labyrinth::map_error(e)))?;
                    let created_at_ms = self.hooks.now_ms().max(0);
                    let _ = chrono::DateTime::from_timestamp_millis(created_at_ms)
                        .ok_or_else(|| {
                            MLSError::Cryptography("invalid archive deletion clock".into())
                        })?;
                    let op_hex = hex::encode(op_id);
                    let serialized = serde_json::to_string(&DeleteAccountRetryState {
                        operation_id: op_hex.clone(),
                        created_at_ms,
                    })
                    .map_err(|e| {
                        MLSError::Internal(format!("serialize delete_account_retry_state: {e}"))
                    })?;
                    let now_ms = self.hooks.now_ms();
                    self.db
                        .write_tx(|tx| tx.put_account_meta(RETRY_META_KEY, &serialized, now_ms))?;
                    (op_id, op_hex, created_at_ms)
                }
            };

            let now_ms = self.hooks.now_ms().max(created_at_ms);
            let write_signed_at_ms = if now_ms.saturating_sub(created_at_ms) > 120_000 {
                now_ms
            } else {
                created_at_ms
            };
            let created_at = chrono::DateTime::from_timestamp_millis(created_at_ms)
                .ok_or_else(|| MLSError::Cryptography("invalid archive deletion creation clock".into()))?;
            let write_signed_at = chrono::DateTime::from_timestamp_millis(write_signed_at_ms)
                .ok_or_else(|| MLSError::Cryptography("invalid archive deletion clock".into()))?;
            let created_at_str = created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let reason = format!(
                "{}{op_hex}",
                super::deletion_authority::DELETE_ACCOUNT_DATA_REVOCATION_REASON_PREFIX
            );
            let create_body =
                super::chat_wire::build_pds_device_revocation_create_record_body_at(
                    &self.normalized_did,
                    &own_device_id,
                    &own_device_id,
                    &created_at_str,
                    &signer,
                    Some(&reason),
                )?;
            if let Err(error) = self.publish_pds_record_create_only(
                super::deletion_authority::DEVICE_REVOCATION_COLLECTION,
                &own_device_id,
                create_body,
                |existing| {
                    super::deletion_authority::verify_self_deletion_revocation_json(
                        &self.normalized_did,
                        &own_device_id,
                        &op_hex,
                        write_signed_at,
                        &signer_pk,
                        existing,
                    )
                },
            ) {
                if matches!(
                    &error,
                    MLSError::InvalidState(code)
                        if code.starts_with("EnrollmentPdsRecordConflict:")
                ) {
                    let _ = self.db.write_tx(|tx| tx.delete_account_meta(RETRY_META_KEY));
                }
                return Err(error);
            }

            let doc_bytes = self
                .resolve_did_document(&self.normalized_did)?
                .ok_or_else(|| {
                    MLSError::Cryptography(format!(
                        "DID document not found for own account `{}`",
                        self.normalized_did
                    ))
                })?;
            let pds_endpoint = super::chat_wire::extract_pds_endpoint_from_did_doc(
                &doc_bytes,
                &self.normalized_did,
            )
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "no #atproto_pds service in DID document for `{}`",
                    self.normalized_did
                ))
            })?;
            let key_proof = self.fetch_pds_record_car(
                &pds_endpoint,
                &self.normalized_did,
                super::deletion_authority::DEVICE_RECORD_COLLECTION,
                &own_device_id,
            )?;
            let proved_key = super::deletion_authority::device_key_from_key_proof(
                &key_proof,
                &self.normalized_did,
                &own_device_id,
                write_signed_at_ms,
                &doc_bytes,
            );
            if proved_key.as_deref() != Some(signer_pk.as_slice()) {
                return Err(MLSError::insufficient_permissions(format!(
                    "own blue.catbird.chat.device/{own_device_id} CARv1 proof failed local verification"
                )));
            }
            let revocation_proof = self.fetch_pds_record_car(
                &pds_endpoint,
                &self.normalized_did,
                super::deletion_authority::DEVICE_REVOCATION_COLLECTION,
                &own_device_id,
            )?;
            if let Err(reason) = super::deletion_authority::verify_self_deletion_revocation_car_at(
                &revocation_proof,
                &self.normalized_did,
                &own_device_id,
                &op_hex,
                write_signed_at,
                &signer_pk,
                &doc_bytes,
            ) {
                return Err(MLSError::insufficient_permissions(format!(
                    "own blue.catbird.chat.deviceRevocation/{own_device_id} CARv1 proof failed local verification: {reason:?}"
                )));
            }
            let prepared = crate::labyrinth::PreparedAccountDeletion {
                operation_id,
                signed_at: write_signed_at,
                key_proof,
                revocation_proof,
            };
            self.native_archive_run(async {
                let cleanup = if require_peer_completion {
                    deps.confirm_hosted_account_erasure(&prepared)
                        .await
                        .map_err(|error| {
                            let code = if error.error.as_deref() == Some("PeerErasurePending") {
                                "PeerErasurePending"
                            } else {
                                "PeerErasureUnverified"
                            };
                            MLSError::InvalidState(code.into())
                        })?;
                    deps.finish_confirmed_account_erasure().await
                } else {
                    deps.delete_account_remote_prepared(&prepared).await
                };
                cleanup.map_err(|e| native_archive_error(crate::labyrinth::map_error(e)))
            })?;
        }
        if require_peer_completion {
            // The provider may still reject or expire the account confirmation. Keep the
            // operation and signing authority until the caller completes provider deletion.
            Ok(())
        } else {
            self.sign_out_and_wipe()
        }
    }

    fn extract_own_device_views(resp: &serde_json::Value) -> Vec<&serde_json::Value> {
        resp.get("items")
            .and_then(serde_json::Value::as_array)
            .or_else(|| resp.get("devices").and_then(serde_json::Value::as_array))
            .map(|arr| {
                arr.iter()
                    .map(|item| item.get("device").unwrap_or(item))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn decode_device_pubkey_field(field: &serde_json::Value) -> Vec<u8> {
        super::chat_wire::json_bytes(field)
            .ok()
            .or_else(|| {
                field
                    .get("$bytes")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| field.as_str())
                    .and_then(|b64| {
                        BASE64_STANDARD
                            .decode(b64)
                            .ok()
                            .or_else(|| BASE64_STANDARD.decode(b64.trim_end_matches('=')).ok())
                    })
            })
            .unwrap_or_default()
    }

    /// Clean single-device sign-out (`#29` §c / `Y-8`): leaves active MLS conversations when
    /// this device is the account's sole active device, best-effort removes this device's PDS
    /// `blue.catbird.chat.device/<device_id>` record, and wipes local SQLCipher + Keychain
    /// state WITHOUT touching the account's `OwnerMailbox` Space or recovery methods.
    pub fn retire_current_device(&self) -> Result<(), MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let _ = self.flush_labyrinth_queue();
        if let Some(own_device_id) = self.canonical_uuid_v4_device_id() {
            if let Ok((signer, _)) = self.load_enrolled_signer_and_auth_gen() {
                let own_devices_opt = self
                    .query_signed_chat_ds(
                        "blue.catbird.chat.getOwnDevices",
                        &[("actorDeviceId", &own_device_id), ("limit", "100")],
                        &own_device_id,
                        &signer,
                    )
                    .ok();
                let other_active = own_devices_opt
                    .as_ref()
                    .map(|resp| {
                        Self::extract_own_device_views(resp).into_iter().any(|d| {
                            d["deviceId"].as_str() != Some(own_device_id.as_str())
                                && matches!(d["status"].as_str(), Some("active"))
                        })
                    })
                    .unwrap_or(false);
                if !other_active {
                    if let Ok(convs) = self.list_conversations(None, 500) {
                        for conv in convs {
                            let _ = self.leave_conversation(&conv.conversation_id);
                        }
                    }
                    let mut enrolled_map = std::collections::BTreeMap::new();
                    enrolled_map.insert(own_device_id.clone(), signer.public().to_vec());
                    if let Some(ref resp) = own_devices_opt {
                        for item in Self::extract_own_device_views(resp) {
                            if let Some(dev_id) = item["deviceId"].as_str() {
                                let pk =
                                    Self::decode_device_pubkey_field(&item["signaturePublicKey"]);
                                if pk.len() == 32 {
                                    enrolled_map.insert(dev_id.to_owned(), pk);
                                }
                            }
                        }
                    }
                    let created_at = self.hooks.now_rfc3339_millis();
                    if let Ok(body) =
                        super::chat_wire::build_pds_device_revocation_create_record_body_at(
                            &self.normalized_did,
                            &own_device_id,
                            &own_device_id,
                            &created_at,
                            &signer,
                            Some("retired"),
                        )
                    {
                        let _ = self.publish_pds_record_create_only(
                            "blue.catbird.chat.deviceRevocation",
                            &own_device_id,
                            body,
                            |existing_val| {
                                super::chat_wire::verify_pds_device_revocation_record(
                                    &self.normalized_did,
                                    &own_device_id,
                                    existing_val,
                                    &enrolled_map,
                                )
                                .is_ok()
                            },
                        );
                    }
                }
            }
        }
        self.sign_out_and_wipe()
    }

    /// Unified account device inventory combining `mls-ds` `getOwnDevices` (`deviceName`,
    /// `status`, `lastActiveAt`, `dormantAt`) with `OwnerMailbox` `device` records.
    pub fn list_devices(&self) -> Result<Vec<RegisteredDeviceInfo>, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let own_device_id = self
            .canonical_uuid_v4_device_id()
            .ok_or_else(|| MLSError::invalid_input("list_devices requires UUIDv4 device_id"))?;
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        // Compare the home DS inventory with the account's independently resolved PDS records.
        // A PDS-only chat.device is surfaced as a row so the UI can alert on a ghost device even
        // when the home DS omits it or is temporarily unavailable. Every record and revocation
        // must have a CAR proof under the account DID's #atproto key; a bare PDS list is not
        // authoritative enough to decide whether a device is unrecognized.
        let mut pds_by_device: std::collections::BTreeMap<String, Vec<u8>> = self
            .fetch_and_cache_authorized_pds_device_keys_checked(&self.normalized_did, true)?
            .into_iter()
            .map(|record| (record.device_id, record.signature_public_key))
            .collect();
        let ds_resp = match self.query_signed_chat_ds(
            "blue.catbird.chat.getOwnDevices",
            &[("actorDeviceId", &own_device_id), ("limit", "100")],
            &own_device_id,
            &signer,
        ) {
            Ok(response) => Some(response),
            Err(error) => {
                tracing::warn!(%error, "home DS device inventory unavailable; showing verified PDS records");
                None
            }
        };
        let mailbox_by_transport: std::collections::BTreeMap<[u8; 32], String> =
            if self.is_device_pending_approval()? {
                std::collections::BTreeMap::new()
            } else {
                let _guard = self
                    .outbox_flush_lock
                    .lock()
                    .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
                self.native_archive_run(async {
                    let Ok(deps) = self.native_archive_deps() else {
                        return std::collections::BTreeMap::new();
                    };
                    match deps.list_mailbox_devices().await {
                        Ok(devs) => devs
                            .into_iter()
                            .filter(|d| !d.r#virtual && d.revoked_at.is_none())
                            .filter_map(|d| {
                                let binding = d.chat_binding().ok().flatten()?;
                                let dev_key = hex::encode(&d.device_key_pubkey.0);
                                Some((binding.transport_public_key, dev_key))
                            })
                            .collect(),
                        Err(_) => std::collections::BTreeMap::new(),
                    }
                })
            };
        let mut out = Vec::new();
        for item in ds_resp
            .as_ref()
            .map(Self::extract_own_device_views)
            .unwrap_or_default()
        {
            let Some(device_id) = item["deviceId"].as_str().map(str::to_owned) else {
                continue;
            };
            let pubkey_bytes = Self::decode_device_pubkey_field(&item["signaturePublicKey"]);
            let labyrinth_device_key_hex = <[u8; 32]>::try_from(pubkey_bytes.as_slice())
                .ok()
                .and_then(|pk| mailbox_by_transport.get(&pk).cloned());
            let key_id = item["keyId"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    crate::orchestrator::canonical_transport::derive_key_id(&pubkey_bytes)
                });
            // The home DS cannot label an arbitrary row as this device to suppress the alert.
            let is_current = device_id == own_device_id;
            let pds_key = pds_by_device.remove(&device_id);
            let recognized_key = self.db.read_tx(|tx| {
                tx.get_account_meta(&format!("recognized_own_device:{device_id}"))
            })?;
            let status = item["status"].as_str().unwrap_or("unknown").to_owned();
            let unrecognized = if status == "revoked" {
                // A still-authorized PDS record contradicts a revoked DS row.
                pds_key.is_some()
            } else {
                pds_key.as_deref() != Some(pubkey_bytes.as_slice())
                    || (is_current && pubkey_bytes.as_slice() != signer.public())
                    || (!is_current
                        && recognized_key.as_deref()
                            != Some(hex::encode(&pubkey_bytes).as_str()))
            };
            out.push(RegisteredDeviceInfo {
                device_id,
                device_name: item["deviceName"].as_str().map(str::to_owned),
                signature_public_key: pubkey_bytes,
                key_id,
                auth_generation: item["authGeneration"].as_i64().unwrap_or(1),
                status,
                created_at: item["createdAt"].as_str().unwrap_or("").to_owned(),
                last_active_at: item["lastActiveAt"].as_str().map(str::to_owned),
                dormant_at: item["dormantAt"].as_str().map(str::to_owned),
                labyrinth_device_key_hex,
                is_current_device: is_current,
                unrecognized,
            });
        }
        for (device_id, signature_public_key) in pds_by_device {
            let key_id =
                crate::orchestrator::canonical_transport::derive_key_id(&signature_public_key);
            let is_current_device = device_id == own_device_id;
            let recognized_key = self.db.read_tx(|tx| {
                tx.get_account_meta(&format!("recognized_own_device:{device_id}"))
            })?;
            let unrecognized = if is_current_device {
                signature_public_key.as_slice() != signer.public()
            } else {
                recognized_key.as_deref()
                    != Some(hex::encode(&signature_public_key).as_str())
            };
            out.push(RegisteredDeviceInfo {
                is_current_device,
                device_id,
                device_name: None,
                signature_public_key,
                key_id,
                auth_generation: 0,
                status: if ds_resp.is_some() {
                    "pds_only"
                } else {
                    "ds_unavailable"
                }
                .to_owned(),
                created_at: String::new(),
                last_active_at: None,
                dormant_at: None,
                labyrinth_device_key_hex: None,
                unrecognized: ds_resp.is_some() || unrecognized,
            });
        }
        Ok(out)
    }

    /// Unified peer-device revocation across `mls-ds` (`chat.revokeDevice`), active local MLS
    /// groups, `LabyrinthSession::revoke_chat_device` (atomic recovery-method re-key), and
    /// best-effort PDS `blue.catbird.chat.device/<target_device_id>` cleanup.
    pub fn revoke_device(
        &self,
        target_device_id: &str,
    ) -> Result<DeviceRevocationReport, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let target_trimmed = target_device_id.trim();
        if target_trimmed.is_empty() {
            return Err(MLSError::invalid_input("target_device_id must not be empty"));
        }
        let own_device_id = self
            .canonical_uuid_v4_device_id()
            .ok_or_else(|| MLSError::invalid_input("revoke_device requires UUIDv4 device_id"))?;
        if target_trimmed == own_device_id {
            return Err(MLSError::invalid_input(
                "cannot revoke current device via revoke_device; use retire_current_device to sign out cleanly",
            ));
        }
        let (actor_signer, actor_auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let own_devices = self.query_signed_chat_ds(
            "blue.catbird.chat.getOwnDevices",
            &[("actorDeviceId", &own_device_id), ("limit", "100")],
            &own_device_id,
            &actor_signer,
        )?;
        let target_entry = Self::extract_own_device_views(&own_devices)
            .into_iter()
            .find(|d| d["deviceId"].as_str() == Some(target_trimmed))
            .ok_or_else(|| MLSError::invalid_input("target_device_id not found in getOwnDevices"))?;
        let target_auth_gen = target_entry["authGeneration"].as_i64().unwrap_or(1).max(1);
        let target_pubkey_opt: Option<[u8; 32]> =
            <[u8; 32]>::try_from(Self::decode_device_pubkey_field(&target_entry["signaturePublicKey"]).as_slice()).ok();
        let already_revoked = target_entry["status"].as_str() == Some("revoked");
        let _receipt_guard = self.lock_recovery_receipts()?;
        let (prior_needs_attention, recovery_generation) = if target_pubkey_opt.is_some() {
            // Fail before changing server or live-group state if a v3 share
            // cannot be deleted on the proven home service. Reserve a durable
            // reminder for a replacement code before any rotation can start.
            self.ensure_recovery_share_home_service_pin()?;
            self.begin_recovery_generation()?
        } else {
            let status = self.labyrinth_status()?;
            (status.recovery_needs_attention, status.recovery_generation)
        };

        if !already_revoked {
            let actor_key_id =
                crate::orchestrator::canonical_transport::derive_key_id(actor_signer.public());
            let revoke_body = serde_json::json!({
                "$type": "blue.catbird.chat.defs#deviceRevocationBody",
                "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\0",
                "actorDid": self.normalized_did,
                "actorDeviceId": own_device_id,
                "authGeneration": actor_auth_gen,
                "targetDeviceId": target_trimmed,
                "targetAuthGeneration": target_auth_gen,
                "idempotencyKey": self.hooks.uuid_v4().to_string(),
                "keyId": actor_key_id,
                "signedAt": self.hooks.now_rfc3339_millis(),
            });
            let _ = self.submit_signed_chat_op(
                &own_device_id,
                Some(actor_auth_gen),
                crate::orchestrator::canonical_transport::CanonicalOperation::RevokeDevice,
                &revoke_body,
                &actor_signer,
            )?;
        }
        let ds_revoked = true;

        let groups_updated = self
            .remove_specific_device_from_active_groups(target_trimmed)
            .unwrap_or(0);

        let mut labyrinth_rotated = false;
        let mut new_epoch_seq = None;
        let mut rekeyed_recovery_code = None;
        let mut rekeyed_passkey_ids = Vec::new();
        let mut collected_exclusions = Vec::new();
        if let Some(chat_pubkey) = target_pubkey_opt {
            let _guard = self
                .outbox_flush_lock
                .lock()
                .map_err(|_| MLSError::lock_poisoned("archive lifecycle"))?;
            let reports = self.native_archive_run(async {
                let mut session = self
                    .native_archive_deps()?
                    .enable()
                    .await
                    .map_err(native_archive_error)?;
                let out = session
                    .revoke_chat_device(chat_pubkey)
                    .await
                    .map_err(native_archive_error)?;
                if let Err(error) = self.save_native_archive_status(
                    &session,
                    out.iter().any(|r| r.rekeyed_recovery_code.is_some()),
                ) {
                    tracing::warn!(%error, "chat device revocation committed but archive status refresh failed");
                }
                Ok::<_, MLSError>(out)
            })?;
            for rep in reports {
                labyrinth_rotated = true;
                new_epoch_seq = Some(rep.new_epoch);
                if rep.rekeyed_recovery_code.is_some() {
                    rekeyed_recovery_code = rep.rekeyed_recovery_code;
                }
                for pk_id in rep.rekeyed_passkeys {
                    rekeyed_passkey_ids.push(pk_id.to_vec());
                }
                for excluded in rep.exclusions {
                    collected_exclusions.push(LabyrinthRotationExclusion {
                        device_key_hex: excluded.device_key.map(hex::encode),
                        reason: excluded.reason,
                        recovery_method: excluded.recovery_method.map(|m| m.as_str().to_owned()),
                    });
                }
            }
        }

        let mut pds_record_deleted = false;
        {
            let mut enrolled_map = std::collections::BTreeMap::new();
            enrolled_map.insert(own_device_id.clone(), actor_signer.public().to_vec());
            for item in Self::extract_own_device_views(&own_devices) {
                if let Some(dev_id) = item["deviceId"].as_str() {
                    let pk = Self::decode_device_pubkey_field(&item["signaturePublicKey"]);
                    if pk.len() == 32 {
                        enrolled_map.insert(dev_id.to_owned(), pk);
                    }
                }
            }
            let created_at = self.hooks.now_rfc3339_millis();
            if let Ok(body) = super::chat_wire::build_pds_device_revocation_create_record_body_at(
                &self.normalized_did,
                &own_device_id,
                target_trimmed,
                &created_at,
                &actor_signer,
                Some("revoked_by_sibling"),
            ) {
                pds_record_deleted = self
                    .publish_pds_record_create_only(
                        "blue.catbird.chat.deviceRevocation",
                        target_trimmed,
                        body,
                        |existing_val| {
                            super::chat_wire::verify_pds_device_revocation_record(
                                &self.normalized_did,
                                target_trimmed,
                                existing_val,
                                &enrolled_map,
                            )
                            .is_ok()
                        },
                    )
                    .is_ok();
            }
            let own_cache_key = format!("authorized_device_keys:{}", self.normalized_did);
            let _ = self.db.write_tx(|tx| tx.delete_account_meta(&own_cache_key));
        }

        let now_ms = self.hooks.now_ms();
        let status = self.db.write_tx(|tx| {
            let raw = tx
                .get_labyrinth_state("status_json")?
                .ok_or_else(|| MLSError::InvalidState("Labyrinth status not initialized".into()))?;
            let mut st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            st.active_device_ids.retain(|d| d != target_trimmed);
            if let Some(seq) = new_epoch_seq {
                st.epoch_seq = seq;
            }
            if !collected_exclusions.is_empty() {
                st.rotation_exclusions = collected_exclusions;
            }
            if !rekeyed_passkey_ids.is_empty() {
                st.has_passkey_prf = false;
            }
            st.recovery_needs_attention =
                prior_needs_attention || rekeyed_recovery_code.is_some();
            if rekeyed_recovery_code.is_some() {
                st.has_recovery_code = true;
            }
            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: format!("revoke-{target_trimmed}-{}", st.epoch_seq),
                op_type: "device_revocation".to_string(),
                epoch_seq: st.epoch_seq,
                state_json: serde_json::json!({ "revokedDeviceId": target_trimmed }).to_string(),
                status: "completed".to_string(),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            })?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                now_ms,
            )?;
            Ok(st)
        });
        match status {
            Ok(status) => self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
                epoch_seq: status.epoch_seq,
            }),
            Err(error) => {
                tracing::warn!(%error, "chat device revocation committed but UI status update failed");
                if let Some(epoch_seq) = new_epoch_seq {
                    self.notify(PlatformChangeEvent::LabyrinthStatusChanged { epoch_seq });
                }
            }
        }

        Ok(DeviceRevocationReport {
            target_device_id: target_trimmed.to_owned(),
            recovery_generation,
            ds_revoked,
            groups_updated,
            labyrinth_rotated,
            new_epoch_seq,
            pds_record_deleted,
            rekeyed_recovery_code,
            rekeyed_passkey_ids,
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
        if enroll_resp
            .get("device")
            .and_then(|d| d.get("status"))
            .and_then(|s| s.as_str())
            == Some("pending_approval")
            || enroll_resp.get("status").and_then(|s| s.as_str()) == Some("pending_approval")
        {
            let _ = self.approve_device_with_key(&rogue_dev_id, &rogue_pub, rogue_auth_gen);
        }

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
                verified_inventories: Mutex::new(std::collections::BTreeMap::new()),
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
    use super::{
        block_on_sync, native_restore_copies, parse_mailbox_keys_record, select_restore_copy,
        unavailable_placeholder_matches_restore_copy, MessageRow,
    };
    use base64::Engine as _;
    use labyrinth::client::{Backends, Clock, Labyrinth};
    use labyrinth::message::{ArchivedReceipt, OriginalSenderArchiveAttestation};
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

    #[test]
    fn mailbox_keys_relay_cannot_substitute_a_peer_record() {
        let response = serde_json::json!({
            "uri": format!(
                "at://{CAROL}/{}/epoch-7",
                labyrinth::records::nsid::MAILBOX_KEYS
            ),
            "cid": "bafy-substituted",
            "value": {"epoch": 7}
        });
        assert!(matches!(
            parse_mailbox_keys_record(&response, ALICE, "epoch-7"),
            Err(labyrinth::Error::Malformed(
                "mailboxKeys relay URI binding"
            ))
        ));
    }

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
            let seed = match sender {
                ALICE => 1,
                BOB => 2,
                CAROL => 3,
                _ => panic!("sender fixture has no key"),
            };
            let sender_key = ChatKey(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
            let attestation = OriginalSenderArchiveAttestation::sign(
                sender.to_owned(),
                DEVICE.to_owned(),
                CONVERSATION,
                id,
                &payload.archive_commitment,
                &sender_key,
            );
            Sent { frame, nonce, receipt: ArchivedReceipt::new(signed, attestation) }
        }
    }

    /// `lab` archives `m`'s exact frame, nonce and receipt under `id`.
    fn try_archive(lab: &mut Labyrinth, id: &str, m: &Sent, ts: u64) -> labyrinth::Result<()> {
        let roster = block_on_sync(lab.resolve_roster(&[ALICE, BOB, CAROL]))?;
        block_on_sync(lab.archive_outgoing_committed(
            CONVERSATION, &roster, id, ts, &m.nonce, &m.frame, &m.receipt,
        ))?;
        block_on_sync(lab.flush())?;
        Ok(())
    }

    fn archive(lab: &mut Labyrinth, id: &str, m: &Sent, ts: u64) {
        try_archive(lab, id, m, ts).unwrap();
    }

    /// `(messageId, sender, frame)` restore would import for `lab` next to `local` rows.
    fn restored(lab: &mut Labyrinth, local: &[MessageRow]) -> Vec<(String, String, Vec<u8>)> {
        let history = block_on_sync(lab.load_thread(CONVERSATION, TimeRange::ALL)).unwrap();
        assert!(history.undecryptable.is_empty(), "{:?}", history.undecryptable);
        let copies = native_restore_copies(CONVERSATION, BOB, history.messages).unwrap();
        copies.values()
            .filter_map(|group| select_restore_copy(group, local.iter().find(|row| row.message_id == group[0].0.message_id), false))
            .map(|(row, _, _)| (row.message_id.clone(), row.sender_did.clone(), row.plaintext_json.clone().into_bytes()))
            .collect()
    }

    #[test]
    fn unavailable_placeholder_replacement_requires_the_exact_archived_receipt_tuple() {
        let w = World::new();
        let mut alice = w.join(ALICE, 1);
        let mut bob = w.join(BOB, 2);
        let _carol = w.join(CAROL, 3);
        let sent = w.sequence(ALICE, "gap-message", "restored");
        archive(&mut alice, "gap-message", &sent, 100);

        let history =
            block_on_sync(bob.load_thread(CONVERSATION, TimeRange::ALL)).expect("load history");
        // A sibling device of the sender stored the pruned placeholder as not-own, while the
        // restored account-level archive row is own. That UI bit is not receipt authority.
        let copies = native_restore_copies(CONVERSATION, ALICE, history.messages)
            .expect("verified restore copies");
        let copy = &copies["gap-message"][0];
        let (row, _, receipt) = copy;
        let bytes = |value: &[u8]| {
            serde_json::json!({
                "$bytes": base64::engine::general_purpose::STANDARD.encode(value)
            })
        };
        let unavailable = super::super::chat_wire::UnavailableEntryEvidence {
            version: 1,
            conversation_id: CONVERSATION.into(),
            message_id: receipt.entry_id.clone(),
            entry_id: receipt.entry_id.clone(),
            seq: i64::try_from(receipt.seq).unwrap(),
            generation: i64::try_from(receipt.generation).unwrap(),
            epoch: i64::try_from(receipt.epoch).unwrap(),
            sender_did: row.sender_did.clone(),
            sender_device_id: row.sender_device_id.clone(),
            reason: super::super::chat_wire::PAYLOAD_PRUNED_REASON.into(),
            receipt: serde_json::json!({
                "kid": receipt.key_id,
                "sequencerDid": receipt.sequencer_did,
                "conversationId": receipt.conversation_id,
                "generation": receipt.generation,
                "groupId": bytes(&receipt.group_id),
                "epoch": receipt.epoch,
                "seq": receipt.seq,
                "entryId": receipt.entry_id,
                "senderDid": row.sender_did,
                "senderDeviceId": row.sender_device_id,
                "archiveCommitment": bytes(&receipt.archive_commitment),
                "issuedAtMs": receipt.issued_at_ms,
                "signature": bytes(&receipt.signature),
            }),
            recorded_at_ms: 1_791_000_000_123,
        };
        let placeholder = unavailable
            .placeholder_row(&receipt.group_id, false)
            .expect("placeholder");
        assert!(
            unavailable_placeholder_matches_restore_copy(
                CONVERSATION,
                &placeholder,
                &unavailable,
                copy,
            )
            .expect("match")
        );

        let mut wrong_coordinate = unavailable.clone();
        wrong_coordinate.seq += 1;
        assert!(
            !unavailable_placeholder_matches_restore_copy(
                CONVERSATION,
                &placeholder,
                &wrong_coordinate,
                copy,
            )
            .expect("mismatch")
        );
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
        // Sender attestation binds the message id, so relabelled witness
        // copies are rejected before they reach the archive.
        assert_eq!(
            try_archive(&mut carol, "m1", &m2, 120).unwrap_err(),
            labyrinth::Error::BadSignature
        );
        assert_eq!(
            try_archive(&mut carol, "m3", &m1, 130).unwrap_err(),
            labyrinth::Error::BadSignature
        );
        assert_eq!(restored(&mut bob, &[]), [
            ("m1".to_owned(), ALICE.to_owned(), m1.frame.clone()),
            ("m2".to_owned(), ALICE.to_owned(), m2.frame.clone()),
        ]);
    }

    #[test]
    fn a_member_cannot_publish_a_colliding_own_copy() {
        let w = World::new();
        let mut alice = w.join(ALICE, 1);
        let mut bob = w.join(BOB, 2);
        let mut carol = w.join(CAROL, 3);
        let m1 = w.sequence(ALICE, "m1", "hello");
        let m2 = w.sequence(ALICE, "m2", "world");
        let c1 = w.sequence(CAROL, "c1", "mine");
        archive(&mut alice, "m1", &m1, 100);
        archive(&mut alice, "m2", &m2, 110);
        assert_eq!(
            try_archive(&mut carol, "m1", &c1, 120).unwrap_err(),
            labyrinth::Error::BadSignature
        );
        assert_eq!(
            restored(&mut bob, &[]),
            [
                ("m1".to_owned(), ALICE.to_owned(), m1.frame.clone()),
                ("m2".to_owned(), ALICE.to_owned(), m2.frame.clone()),
            ]
        );
    }

    /// Production readers get no sequencer redactions; the authenticated `accountDeletedEntry`
    /// live sync recorded decides. Every copy attributed to the deleted account that its receipt
    /// orders before the entry is hidden, in Space and owner history alike: its own copy, another
    /// member's published witness copy of a message it never archived, and re-archived owner
    /// copies. If a legacy marker cannot identify the deleted actor, a later frame from that
    /// account requires a verified backfill before it can be shown.
    #[test]
    fn a_sequenced_account_deletion_hides_every_published_copy_of_its_messages() {
        use super::{CatbirdMlsClient, MLSError};
        use crate::storage::{MlsAccountDb, OpenMode};
        fn visible(
            db: &MlsAccountDb,
            lab: &mut Labyrinth,
            deletion_cid: &str,
            owner: bool,
        ) -> Result<Vec<String>, MLSError> {
            let history = if owner {
                block_on_sync(lab.load_owner_thread(CONVERSATION))
            } else {
                block_on_sync(lab.load_thread(CONVERSATION, TimeRange::ALL))
            }
            .unwrap();
            assert!(history.undecryptable.is_empty(), "{:?}", history.undecryptable);
            let mut messages = history.messages;
            CatbirdMlsClient::hide_deleted_accounts(
                db,
                deletion_cid,
                &std::collections::BTreeSet::new(),
                &mut messages,
            )?;
            Ok(messages.into_iter().map(|m| m.message_id).collect())
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
        assert_eq!(
            visible(&db, &mut bob, CONVERSATION, false).unwrap(),
            ["a1", "a2", "b1"]
        );
        assert_eq!(
            visible(&db, &mut bob, CONVERSATION, true).unwrap(),
            ["a1", "a2", "b1"]
        );

        let deleted_at = i64::try_from(w.net.append_chat_entry(CONVERSATION)).unwrap();
        db.write_tx(|tx| super::super::live_sync::record_account_deletion(tx, CONVERSATION, ALICE, deleted_at, 1)).unwrap();
        let a3 = w.sequence(ALICE, "a3", "after the deletion");
        archive(&mut alice, "a3", &a3, 200);
        assert_eq!(
            visible(&db, &mut bob, "00000000-0000-4000-8000-00000000ffff", false).unwrap(),
            ["a1", "a2", "b1", "a3"],
            "another conversation's authority hides no archive copy"
        );
        assert!(
            matches!(
                visible(&db, &mut bob, CONVERSATION, false),
                Err(MLSError::Cryptography(_))
            ),
            "the legacy seq-only marker must quarantine a later frame with an unresolved actor"
        );
        assert_eq!(visible(&db, &mut bob, CONVERSATION, true).unwrap(), ["b1"]);
    }
}
