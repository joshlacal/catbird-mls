// Included beside native_archive.rs in native_client. Authentication stays request-scoped.
#[cfg(feature = "labyrinth")]
mod native_archive_space_auth {
    use super::{
        block_on_sync, NativeArchiveGateway, PlatformHttpResponse, VerifiedArchiveInventory,
        VerifiedArchiveRecord,
    };
    use crate::labyrinth::{LabyrinthSpaceRequest, LabyrinthSpaceResponse};
    use atproto_spaces::{
        did_resolver::DidDocument,
        http_signature::sign_credential_request_minimal,
        kem::{encapsulate_p256_deterministic, encode_p256_did_key, P256SecretKey},
        lthash::{compute_dagcbor_cid, LtHash},
        mac::{
            format_accept_signature, verify_commit_mac, verify_record_mac, MacProfile,
            ACCEPT_SIGNATURE_HEADER, COMMIT_MAC_HEADER, RECORD_MAC_HEADER, SIGNATURE_HEADER,
            SIGNATURE_INPUT_HEADER,
        },
        star::{read_star_repo_authenticated, validate_canonical_dagcbor_record, ParsedStarRepo},
        sync_engine::WriterSyncState,
        tokens::{verify_space_token, SpaceKeyResolver, SpaceTokenKind, SpaceVerifyingKey},
        SpaceUri,
    };
    use catbird_atproto::com_atproto::space::{
        get_record::GetRecordOutput, list_records::ListRecordsOutput,
        list_repo_ops::ListRepoOpsOutput,
    };
    use http::{HeaderMap, HeaderName, HeaderValue};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use zeroize::Zeroizing;

    const GET_RECORD: &str = "com.atproto.space.getRecord";
    const GET_REPO: &str = "com.atproto.space.getRepo";
    const LIST_RECORDS: &str = "com.atproto.space.listRecords";
    const LIST_WRITERS: &str = "com.atproto.space.listWriters";
    const LIST_OPS: &str = "com.atproto.space.listRepoOps";
    const MAX_BODY: usize = crate::labyrinth::space::MAX_SPACE_XRPC_RESPONSE_BYTES;
    const MAX_INVENTORY_PAGES: usize = 1_000;
    const MAX_INVENTORY_WRITERS: usize = 100_000;
    const MAX_INVENTORY_BYTES: usize = 64 * 1024 * 1024;
    /// mls-ds `space_host`: the authority's signed refusal of a credential request.
    const SPACE_DENIAL_TYP: &str = "catbird-space-denial+jwt";
    const SPACE_DENIAL_REASON: &str = "notActiveMember";
    const SPACE_DENIAL_MAX_LIFETIME_SECS: u64 = 60;

    type NegotiatedMacSecret = (String, Zeroizing<[u8; 32]>);

    struct Credential {
        jwt: Zeroizing<String>,
        key: P256SecretKey,
        expires_at: u64,
    }

    struct ReadContext {
        space: SpaceUri,
        writer: String,
        personal: bool,
        kem_key: Option<String>,
        credential: Credential,
    }

    struct AuthorityKeys<'a> {
        gateway: &'a NativeArchiveGateway,
        document: DidDocument,
    }

    #[async_trait::async_trait(?Send)]
    impl SpaceKeyResolver for AuthorityKeys<'_> {
        async fn resolve_atproto_key(
            &self,
            issuer: &str,
            refresh: bool,
        ) -> atproto_spaces::Result<SpaceVerifyingKey> {
            if issuer != self.document.id {
                return Err(atproto_spaces::SpacesError::InvalidSpaceCredential(
                    "unexpected credential authority".into(),
                ));
            }
            let key = if refresh {
                self.gateway
                    .space_document(issuer)
                    .map_err(atproto_spaces::SpacesError::DidResolution)?
                    .atproto_key
            } else {
                self.document.atproto_key.clone()
            };
            key.ok_or_else(|| {
                atproto_spaces::SpacesError::DidResolution("authority has no #atproto key".into())
            })
        }
    }

    #[derive(Deserialize)]
    struct TokenOutput {
        token: String,
    }
    #[derive(Deserialize)]
    struct CredentialOutput {
        credential: String,
    }
    #[derive(Deserialize)]
    struct RecordEnvelope {
        uri: String,
        cid: String,
    }
    #[derive(Deserialize)]
    struct ListedRecord {
        collection: String,
        rkey: String,
        cid: String,
        uri: Option<String>,
        repo: Option<String>,
        space: Option<String>,
    }
    #[derive(Deserialize)]
    struct ListedPage {
        records: Vec<ListedRecord>,
        cursor: Option<String>,
    }
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Commit {
        space: String,
        repo: String,
        rev: String,
        ver: u64,
        #[serde(with = "catbird_atproto::jacquard_common::serde_bytes_helper")]
        data: catbird_atproto::jacquard_common::deps::bytes::Bytes,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(tag = "$type")]
    enum InventoryWriterItem {
        #[serde(rename = "com.atproto.space.defs#repoWrite", rename_all = "camelCase")]
        RepoWrite {
            repo: String,
            repo_rev: String,
            space_rev: String,
            #[serde(with = "catbird_atproto::jacquard_common::serde_bytes_helper")]
            data: catbird_atproto::jacquard_common::deps::bytes::Bytes,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            prev_space_rev: Option<String>,
        },
        #[serde(rename = "com.atproto.space.defs#repoRemoved", rename_all = "camelCase")]
        RepoRemoved {
            repo: String,
            space_rev: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            prev_space_rev: Option<String>,
        },
    }

    impl InventoryWriterItem {
        fn repo_did(&self) -> &str {
            match self {
                Self::RepoWrite { repo, .. } | Self::RepoRemoved { repo, .. } => repo,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct ActiveInventoryRepo {
        did: String,
        repo_rev: String,
        space_rev: String,
        data: [u8; 32],
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct InventoryPage {
        #[serde(default)]
        repos: Vec<InventoryWriterItem>,
        complete: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
        commit: Commit,
    }

    #[derive(Deserialize)]
    struct CommitEnvelope {
        commit: Option<Commit>,
        cursor: Option<String>,
    }
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    struct OpStub {
        collection: String,
        rkey: String,
        rev: String,
        cid: Option<String>,
        prev: Option<String>,
    }
    #[derive(Deserialize)]
    struct OpsPage {
        ops: Vec<OpStub>,
    }
    /// Record JSON exactly as served. Re-rendering jacquard `Data` pads atproto `$bytes`,
    /// which labyrinth's strict codec rejects; it is released only after verification.
    #[derive(Deserialize)]
    struct ServedValue {
        value: Option<serde_json::Value>,
    }
    #[derive(Deserialize)]
    struct ServedOps {
        ops: Vec<ServedValue>,
    }

    impl NativeArchiveGateway {
        pub(super) async fn execute_authenticated_space(
            &self,
            request: LabyrinthSpaceRequest,
        ) -> Result<LabyrinthSpaceResponse, String> {
            let params = parse_query(&request)?;
            // The platform callback owns the account's OAuth/DPoP session, including
            // refresh. Never replace OAuth writes with a Space credential presentation.
            if request.method == "POST"
                || (request.method == "GET"
                    && request.nsid == "com.atproto.space.listSpaces"
                    && request.body.is_none())
            {
                let mut headers = request.headers;
                if let Some(content_type) = request.content_type {
                    headers.push(("content-type".into(), content_type));
                }
                return self
                    .execute(
                        &self.config.pds_endpoint,
                        request.method,
                        request.path,
                        headers,
                        request.body,
                    )
                    .and_then(bounded)
                    .map(into_response);
            }
            if request.method != "GET" || request.body.is_some() {
                return Err("native_space_invalid_read_method".into());
            }
            let writer_endpoint = match request.nsid.as_str() {
                GET_RECORD
                | LIST_RECORDS
                | LIST_OPS
                | "com.atproto.space.getRepo"
                | "com.atproto.space.getLatestCommit"
                | "com.atproto.space.getBlob" => true,
                "com.atproto.space.getSpace" | LIST_WRITERS => false,
                _ => return Err(format!("native_space_unsupported_read: {}", request.nsid)),
            };
            if request.headers.iter().any(|(name, _)| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "authorization"
                        | "atproto-space-audience"
                        | "atproto-space-want-mac"
                        | "accept-signature"
                        | "signature"
                        | "signature-input"
                )
            }) {
                return Err("native_space_conflicting_auth_headers".into());
            }
            let space = SpaceUri::parse(required(&params, "space")?)
                .map_err(|e| format!("native_space_invalid_space: {e}"))?;
            let writer = if writer_endpoint {
                required(&params, "repo")?.to_owned()
            } else {
                space.authority.clone()
            };
            if !atproto_spaces::is_valid_did(&writer) {
                return Err("native_space_invalid_writer".into());
            }
            let personal = space.space_type == "blue.catbird.labyrinth.mailbox";
            if personal {
                if space.authority != self.config.account_did
                    || space.rkey != "self"
                    || writer != self.config.account_did
                {
                    return Err("native_space_personal_mailbox_binding_mismatch".into());
                }
            } else if space.space_type != "blue.catbird.labyrinth.conversation" {
                return Err("native_space_unsupported_space_type".into());
            }
            let authority = self.space_document(&space.authority)?;
            let authority_kem = authority.atproto_kem_did_key.clone();
            let kem_key = if writer == authority.id {
                authority_kem.clone()
            } else {
                self.space_document(&writer)?.atproto_kem_did_key
            };
            // Only the Space authority can deny membership: the account PDS for its personal
            // mailbox, over the account's own session; for a conversation Space, its signed denial
            // of this credential request (`verify_space_denial`), which a home DS relays byte for
            // byte whether or not it is that authority. An unsigned refusal, of the credential or
            // of a read after it was granted, proves no removal.
            let credential = match self.space_credential(&space, personal, authority)? {
                Ok(credential) => credential,
                Err(denied) => return Ok(into_response(denied)),
            };
            let mut context = ReadContext {
                space,
                writer,
                personal,
                kem_key,
                credential,
            };
            if context.space.space_type == "blue.catbird.labyrinth.conversation"
                && matches!(request.nsid.as_str(), GET_RECORD | LIST_RECORDS)
            {
                // Conversation records are listed only from a verified writer inventory. A listing
                // with none verified yet (unsend, leave, purge of the own repo) verifies it first.
                if request.nsid == LIST_RECORDS && !self.inventory_verified(&context.space)? {
                    self.verify_space_inventory(&mut context, authority_kem)?;
                }
                if self.inventory_verified(&context.space)? {
                    let mut cached = PlatformHttpResponse {
                        status: 200,
                        headers: vec![],
                        body: vec![],
                    };
                    if request.nsid == GET_RECORD {
                        self.release_verified_inventory_record(&context, &params, &mut cached)?;
                    } else {
                        self.release_verified_inventory_records(&context, &params, &mut cached)?;
                    }
                    self.space_credential_live(&context)?;
                    return bounded(cached).map(into_response);
                }
            }
            let mac_profile = match request.nsid.as_str() {
                GET_RECORD | LIST_RECORDS | "com.atproto.space.getBlob" => Some(MacProfile::Record),
                LIST_WRITERS | LIST_OPS | GET_REPO | "com.atproto.space.getLatestCommit" => {
                    Some(MacProfile::Commit)
                }
                _ => None,
            };
            let (mut response, negotiated) = self.space_read(
                &context,
                &request.nsid,
                &request.path,
                request.headers,
                mac_profile,
            )?;
            if !(200..300).contains(&response.status) {
                return Ok(into_response(response));
            }
            match request.nsid.as_str() {
                GET_RECORD => {
                    let (full, value) = verify_record(
                        &context,
                        &params,
                        &response,
                        negotiated
                            .as_ref()
                            .ok_or("native_space_missing_request_secret")?,
                    )?;
                    response.body = serde_json::to_vec(&serde_json::json!({
                        "uri": full.uri,
                        "cid": full.cid,
                        "value": value
                    }))
                    .map_err(|e| format!("native_space_encode_record: {e}"))?;
                }
                LIST_RECORDS => self.verify_listed_records(&context, &params, &mut response)?,
                LIST_WRITERS => self
                    .verify_inventory(
                        &mut context,
                        &params,
                        &mut response,
                        negotiated
                            .as_ref()
                            .ok_or("native_space_missing_request_secret")?,
                    )
                    .map_err(|error| {
                        if error.starts_with("WriterRollback:") {
                            error
                        } else {
                            format!("ArchiveInventoryIncomplete: {error}")
                        }
                    })?,
                GET_REPO => {
                    let parsed = verify_star(
                        &context,
                        &response,
                        negotiated
                            .as_ref()
                            .ok_or("native_space_missing_request_secret")?,
                    )?;
                    self.observe_writer_rev(&context.space.raw, &context.writer, &parsed.rev)?;
                }
                LIST_OPS => {
                    let head = self.verify_repo_ops(
                        &context,
                        &mut response,
                        negotiated
                            .as_ref()
                            .ok_or("native_space_missing_request_secret")?,
                        None,
                    )?;
                    self.observe_writer_rev(&context.space.raw, &context.writer, &head.rev)?;
                }
                "com.atproto.space.getLatestCommit" => {
                    let envelope: CommitEnvelope = decode(&response.body, "commit envelope")?;
                    let commit = envelope.commit.ok_or("native_space_missing_commit")?;
                    verify_commit(
                        &context,
                        &response,
                        negotiated
                            .as_ref()
                            .ok_or("native_space_missing_request_secret")?,
                        &commit,
                    )?;
                    self.observe_writer_rev(&context.space.raw, &context.writer, &commit.rev)?;
                    response.body = serde_json::to_vec(&serde_json::json!({"commit": commit}))
                        .map_err(|e| format!("native_space_encode_commit: {e}"))?;
                }
                "com.atproto.space.getBlob" => {
                    verify_blob(required(&params, "cid")?, &response.body)?
                }
                _ => {}
            }
            self.space_credential_live(&context)?;
            bounded(response).map(into_response)
        }

        fn writer_rev_floors_state_key(&self) -> String {
            format!(
                "native.writer_rev_floors:{}",
                crate::labyrinth::space::thread_placement_key(&self.config.account_did)
            )
        }

        fn writer_rev_floors_placements_key(&self) -> String {
            format!(
                "native.placements:{}",
                crate::labyrinth::SessionDeps::writer_rev_floors_key(&self.config.account_did)
            )
        }

        pub(super) fn load_persisted_writer_rev_floors(
            &self,
        ) -> Result<BTreeMap<(String, String), String>, String> {
            let key = self.writer_rev_floors_state_key();
            let placements_key = self.writer_rev_floors_placements_key();
            let (raw_a, raw_b) = self
                .db
                .read_tx(|tx| Ok((tx.get_labyrinth_state(&key)?, tx.get_labyrinth_state(&placements_key)?)))
                .map_err(|e: crate::MLSError| e.to_string())?;
            let mut out = BTreeMap::new();
            for raw in [raw_a, raw_b].into_iter().flatten() {
                let list: Vec<(String, String, String)> = serde_json::from_slice(&raw)
                    .map_err(|e| format!("native_space_invalid_writer_rev_floors: {e}"))?;
                for (space, author, rev) in list {
                    if labyrinth::store::validate_writer_rev_floor(&space, &author, &rev).is_ok() {
                        let k = (space, author);
                        match out.get(&k) {
                            Some(cur) if cur >= &rev => {}
                            Some(_) => {
                                out.insert(k, rev);
                            }
                            None if out.len() < labyrinth::store::MAX_WRITER_FLOOR_ENTRIES => {
                                out.insert(k, rev);
                            }
                            None => {}
                        }
                    }
                }
            }
            Ok(out)
        }

        pub(super) fn persist_writer_rev_floors(
            &self,
            floors: &BTreeMap<(String, String), String>,
        ) -> Result<(), String> {
            let key = self.writer_rev_floors_state_key();
            let placements_key = self.writer_rev_floors_placements_key();
            let now_ms = self.hooks.now_ms();
            self.db
                .write_tx(|tx| {
                    let mut merged: BTreeMap<(String, String), String> = BTreeMap::new();
                    for state_key in [&key, &placements_key] {
                        if let Some(raw) = tx.get_labyrinth_state(state_key)? {
                            for (s, a, r) in serde_json::from_slice::<Vec<(String, String, String)>>(&raw)
                                .unwrap_or_default()
                            {
                                if labyrinth::store::validate_writer_rev_floor(&s, &a, &r).is_ok() {
                                    let k = (s, a);
                                    if merged.get(&k).is_none_or(|cur| cur < &r) {
                                        merged.insert(k, r);
                                    }
                                }
                            }
                        }
                    }
                    for ((space, author), rev) in floors {
                        if labyrinth::store::validate_writer_rev_floor(space, author, rev).is_err()
                        {
                            continue;
                        }
                        let k = (space.clone(), author.clone());
                        match merged.get(&k) {
                            Some(cur) if cur.as_str() >= rev.as_str() => {}
                            Some(_) => {
                                merged.insert(k, rev.clone());
                            }
                            None if merged.len() < labyrinth::store::MAX_WRITER_FLOOR_ENTRIES => {
                                merged.insert(k, rev.clone());
                            }
                            None => {}
                        }
                    }
                    let encoded_list: Vec<(&str, &str, &str)> = merged
                        .iter()
                        .map(|((s, a), r)| (s.as_str(), a.as_str(), r.as_str()))
                        .collect();
                    let raw = serde_json::to_vec(&encoded_list)
                        .map_err(|e| crate::MLSError::Internal(e.to_string()))?;
                    tx.put_labyrinth_state(&key, &raw, now_ms)?;
                    tx.put_labyrinth_state(&placements_key, &raw, now_ms)
                })
                .map_err(|e| e.to_string())
        }

        fn check_writer_rev_not_rolled_back(
            &self,
            space: &str,
            writer: &str,
            rev: &str,
        ) -> Result<(), String> {
            labyrinth::store::validate_writer_rev_floor(space, writer, rev)
                .map_err(|e| format!("native_space_invalid_writer_rev: {e}"))?;
            let current = self.load_persisted_writer_rev_floors()?;
            let key = (space.to_owned(), writer.to_owned());
            if let Some(floor) = current.get(&key) {
                if rev < floor.as_str() {
                    return Err(format!(
                        "WriterRollback: space={space} writer={writer} offered={rev} floor={floor}"
                    ));
                }
            }
            Ok(())
        }

        fn observe_writer_rev(&self, space: &str, writer: &str, rev: &str) -> Result<(), String> {
            labyrinth::store::validate_writer_rev_floor(space, writer, rev)
                .map_err(|e| format!("native_space_invalid_writer_rev: {e}"))?;
            let current = self.load_persisted_writer_rev_floors()?;
            let key = (space.to_owned(), writer.to_owned());
            if let Some(floor) = current.get(&key) {
                if rev < floor.as_str() {
                    return Err(format!(
                        "WriterRollback: space={space} writer={writer} offered={rev} floor={floor}"
                    ));
                }
                if rev == floor.as_str() {
                    return Ok(());
                }
            }
            let mut updated = current;
            if updated.len() < labyrinth::store::MAX_WRITER_FLOOR_ENTRIES
                || updated.contains_key(&key)
            {
                updated.insert(key, rev.to_owned());
                self.persist_writer_rev_floors(&updated)?;
            }
            Ok(())
        }

        pub(super) fn space_document(&self, did: &str) -> Result<DidDocument, String> {
            let bare = did.split('#').next().unwrap_or(did).trim();
            let response = if bare.starts_with("did:plc:") {
                let url = crate::labyrinth::transport::did_document_url(bare)?;
                if !self.db.is_open() {
                    return Err("native_archive_context_closed".into());
                }
                let resp = self
                    .transport
                    .execute_http(crate::PlatformHttpRequest {
                        method: "GET".into(),
                        url,
                        headers: vec![],
                        body: None,
                    })
                    .map_err(|e| e.to_string())?;
                if !self.db.is_open() {
                    return Err("native_archive_context_closed".into());
                }
                bounded(resp)?
            } else {
                // For `did:web:*`, resolve through the account PDS so a direct `.well-known`
                // connection never leaks Space interest to a foreign sequencer under D1.
                let path = format!(
                    "/xrpc/com.atproto.identity.resolveDid?did={}",
                    encode(bare)
                );
                let resp = self.execute(
                    &self.config.pds_endpoint,
                    "GET".into(),
                    path,
                    vec![],
                    None,
                )?;
                bounded(resp)?
            };
            require_success(&response, "resolveDid")?;
            let bytes =
                super::super::chat_wire::extract_did_doc_from_resolve_response(&response.body)
                    .map_err(|e| format!("native_space_did_document: {e}"))?;
            DidDocument::parse_json(bare, &bytes)
                .map_err(|e| format!("native_space_did_document: {e}"))
        }

        fn space_key(&self) -> Result<P256SecretKey, String> {
            // Rejection sampling, not reduction modulo n: production hooks are the
            // system CSPRNG; injected simulation hooks own every random draw.
            for _ in 0..128 {
                let bytes = Zeroizing::new(self.hooks.random_array::<32>());
                if let Ok(key) = P256SecretKey::from_slice(bytes.as_ref()) {
                    return Ok(key);
                }
            }
            Err("native_space_invalid_entropy".into())
        }

        /// Exchange a fresh Space credential, replaying a recent server refusal instead of
        /// asking again. Only HTTP refusals are remembered: a transport failure, a closed
        /// context or a membership denial is never cached.
        fn space_credential(
            &self,
            space: &SpaceUri,
            personal: bool,
            authority: DidDocument,
        ) -> Result<Result<Credential, PlatformHttpResponse>, String> {
            let cache_key = format!(
                "{}|{}",
                if personal { "personal" } else { "relay" },
                space.raw
            );
            let now = self.hooks.now_secs();
            {
                let mut failures = self
                    .credential_failures
                    .lock()
                    .map_err(|_| "native_space_credential_failure_cache_poisoned")?;
                match failures.get(&cache_key) {
                    Some((retry_at, error)) if *retry_at > now => return Err(error.clone()),
                    Some(_) => {
                        failures.remove(&cache_key);
                    }
                    None => {}
                }
            }
            let result = self.space_credential_uncached(space, personal, authority);
            let mut failures = self
                .credential_failures
                .lock()
                .map_err(|_| "native_space_credential_failure_cache_poisoned")?;
            match &result {
                Err(error) if is_credential_refusal(error) => {
                    if failures.len() >= MAX_CREDENTIAL_FAILURES
                        && !failures.contains_key(&cache_key)
                    {
                        failures.retain(|_, (retry_at, _)| *retry_at > now);
                        if failures.len() >= MAX_CREDENTIAL_FAILURES {
                            failures.pop_first();
                        }
                    }
                    failures.insert(
                        cache_key,
                        (
                            now.saturating_add(CREDENTIAL_FAILURE_BACKOFF_SECS),
                            error.clone(),
                        ),
                    );
                }
                Ok(_) => {
                    failures.remove(&cache_key);
                }
                Err(_) => {}
            }
            result
        }

        fn space_credential_uncached(
            &self,
            space: &SpaceUri,
            personal: bool,
            authority: DidDocument,
        ) -> Result<Result<Credential, PlatformHttpResponse>, String> {
            let key = self.space_key()?;
            let kid = encode_p256_did_key(&key.public_key());
            let delegation_path = format!(
                "/xrpc/com.atproto.space.getDelegationToken?space={}",
                encode(&space.raw)
            );
            let delegation_response = bounded(self.execute(
                &self.config.pds_endpoint,
                "GET".into(),
                delegation_path,
                vec![],
                None,
            )?)?;
            require_success(&delegation_response, "getDelegationToken")?;
            let delegation: TokenOutput = decode(&delegation_response.body, "delegation token")?;
            if delegation.token.is_empty()
                || delegation.token.len() > atproto_spaces::tokens::MAX_COMPACT_JWT_BYTES
            {
                return Err("native_space_invalid_delegation_token".into());
            }
            let (base, nsid, body) = if personal {
                (
                    &self.config.pds_endpoint,
                    "com.atproto.space.authorizeSpaceSync",
                    serde_json::json!({
                        "space": space.raw,
                        "credentialKey": kid,
                        "delegationToken": delegation.token,
                    }),
                )
            } else {
                (
                    &self.config.home_ds_endpoint,
                    "blue.catbird.chat.relaySpaceCredential",
                    serde_json::json!({
                        "actorDeviceId": self.config.device_id,
                        "authorityDid": space.authority,
                        "space": space.raw,
                        "delegationToken": delegation.token,
                        "cnfKey": kid,
                    }),
                )
            };
            let body = serde_json::to_vec(&body)
                .map_err(|e| format!("native_space_encode_credential_exchange: {e}"))?;
            // No Authorization header here: the existing transport callback supplies
            // PDS OAuth or endpoint-specific home-DS service auth, never a foreign DS.
            let response = bounded(self.execute(
                base,
                "POST".into(),
                format!("/xrpc/{nsid}"),
                vec![],
                Some(body),
            )?)?;
            if response.status == 403 {
                if !personal {
                    self.verify_space_denial(space, &kid, &authority, &response.body)
                        .map_err(|error| {
                            format!("{}: {error}", super::NATIVE_UNAUTHENTICATED_DENIAL)
                        })?;
                    return Ok(Err(response));
                }
                let denied = serde_json::from_slice::<Value>(&response.body)
                    .ok()
                    .and_then(|body| body["error"].as_str().map(str::to_owned))
                    .is_some_and(|code| {
                        matches!(
                            code.as_str(),
                            "Forbidden" | "NotAuthorized" | "AccountNotAuthorized"
                        )
                    });
                if denied {
                    return Ok(Err(response));
                }
            }
            // A revoked/invalid delegation (401), an undeclared 403, and every other transport or
            // directory failure are authentication failures, never proof of Space removal.
            require_success(&response, "authorizeSpaceSync")?;
            let output: CredentialOutput = decode(&response.body, "Space credential")?;
            let jwt = Zeroizing::new(output.credential);
            let now = self.hooks.now_secs();
            let resolver = AuthorityKeys {
                gateway: self,
                document: authority,
            };
            let claims = block_on_sync(verify_space_token(
                SpaceTokenKind::Credential,
                &jwt,
                &resolver,
                now,
            ))
            .map_err(|e| format!("native_space_invalid_credential: {e}"))?;
            let claims_space = SpaceUri::parse(&claims.sub).ok().map(|s| s.raw);
            if claims.iss != space.authority
                || claims_space.as_deref() != Some(space.raw.as_str())
                || claims.cnf_kid.as_deref() != Some(kid.as_str())
            {
                return Err("native_space_credential_binding_mismatch".into());
            }
            // Token verification permits clock skew. A newly obtained credential
            // must still be strictly live before it can authorize a read.
            if claims.exp <= now {
                return Err("native_space_credential_expired".into());
            }
            Ok(Ok(Credential {
                jwt,
                key,
                expires_at: claims.exp,
            }))
        }

        fn space_credential_live(&self, context: &ReadContext) -> Result<(), String> {
            if !self.db.is_open() {
                return Err("native_archive_context_closed".into());
            }
            if context.credential.expires_at <= self.hooks.now_secs() {
                return Err("native_space_credential_expired".into());
            }
            Ok(())
        }

        /// The Space authority's signed refusal of this credential request. Its `#atproto` key
        /// (`kid` names it) signed `catbird-space-denial+jwt` claims for exactly this Space and its
        /// `{conversationId}-{generation}`, the MLS group pinned for it, this account, the
        /// non-member reason, and a live window of at most 60 s. `cnf.kid` must be this request's
        /// fresh PoP key, so no refusal answers any other request.
        fn verify_space_denial(
            &self,
            space: &SpaceUri,
            kid: &str,
            authority: &DidDocument,
            body: &[u8],
        ) -> Result<(), String> {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            #[derive(Deserialize)]
            struct Refusal {
                denial: String,
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Header {
                alg: String,
                typ: String,
                kid: String,
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Cnf {
                kid: String,
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields, rename_all = "camelCase")]
            struct Claims {
                iss: String,
                sub: String,
                aud: String,
                iat: u64,
                exp: u64,
                jti: String,
                cnf: Cnf,
                conversation_id: String,
                generation: u64,
                group_id: String,
                reason: String,
            }
            let denial = serde_json::from_slice::<Refusal>(body)
                .map_err(|_| "refusal carries no signed denial")?
                .denial;
            if denial.len() > atproto_spaces::tokens::MAX_COMPACT_JWT_BYTES {
                return Err("oversized denial".into());
            }
            let (input, signature) = denial.rsplit_once('.').ok_or("malformed denial")?;
            let (header, claims) = input.split_once('.').ok_or("malformed denial")?;
            let part = |part: &str| {
                URL_SAFE_NO_PAD
                    .decode(part)
                    .map_err(|_| "malformed denial".to_owned())
            };
            let header: Header =
                serde_json::from_slice(&part(header)?).map_err(|_| "malformed denial header")?;
            let claims: Claims =
                serde_json::from_slice(&part(claims)?).map_err(|_| "malformed denial claims")?;
            let signature = part(signature)?;
            if header.typ != SPACE_DENIAL_TYP
                || header.kid != atproto_spaces::tokens::ATPROTO_KEY_ID
            {
                return Err("not a Space denial".into());
            }
            let claims_space = SpaceUri::parse(&claims.sub).ok().map(|s| s.raw);
            if claims.iss != space.authority
                || claims_space.as_deref() != Some(space.raw.as_str())
                || claims.aud != self.config.account_did
                || claims.cnf.kid != kid
                || claims.reason != SPACE_DENIAL_REASON
                || format!("{}-{}", claims.conversation_id, claims.generation) != space.rkey
                || self.pinned_space_group(space)?.as_deref() != Some(claims.group_id.as_str())
                || claims.jti.is_empty()
                || claims.jti.len() > atproto_spaces::tokens::MAX_JTI_BYTES
            {
                return Err("denial binding mismatch".into());
            }
            let now = self.hooks.now_secs();
            if claims.exp <= now
                || claims.exp <= claims.iat
                || claims.exp - claims.iat > SPACE_DENIAL_MAX_LIFETIME_SECS
                || claims.iat > now + atproto_spaces::tokens::MAX_IAT_LEAD_SECS
            {
                return Err("stale denial".into());
            }
            // A rotated `#atproto` key: one fresh DID document, as for credentials.
            let verifies = |document: &DidDocument| {
                document
                    .atproto_key
                    .as_ref()
                    .is_some_and(|key| key.verify_raw(&header.alg, input.as_bytes(), &signature))
            };
            if verifies(authority) || verifies(&self.space_document(&space.authority)?) {
                return Ok(());
            }
            Err("denial signature".into())
        }

        /// The MLS group pinned with `space` (`pin_native_conversation*`): from the verified local
        /// roster or the newest signed owner receipt.
        fn pinned_space_group(&self, space: &SpaceUri) -> Result<Option<String>, String> {
            let key = format!(
                "native.placements:{}",
                crate::labyrinth::space::thread_placement_key(&self.config.account_did)
            );
            let Some(raw) = self
                .db
                .read_tx(|tx| tx.get_labyrinth_state(&key))
                .map_err(|e| e.to_string())?
            else {
                return Ok(None);
            };
            let pins: BTreeMap<String, crate::labyrinth::space::ThreadPlacement> =
                serde_json::from_slice(&raw)
                    .map_err(|e| format!("native_space_invalid_pins: {e}"))?;
            Ok(pins
                .into_values()
                .find(|pin| {
                    pin.space
                        .as_deref()
                        .and_then(|s| SpaceUri::parse_hedged(s).ok())
                        .is_some_and(|parsed| parsed.raw == space.raw)
                })
                .and_then(|pin| pin.group_id))
        }

        /// Verifies whether `conversation_id`'s Space authority cryptographically
        /// attests removal via `catbird-space-denial+jwt` (`Ok(true)`), still
        /// grants Space access (`Ok(false)`), or returned an unverified/transient
        /// error (`Err`).
        pub(super) fn verify_conversation_space_removal(
            &self,
            conversation_id: &str,
        ) -> Result<bool, String> {
            let key = format!(
                "native.placements:{}",
                crate::labyrinth::space::thread_placement_key(&self.config.account_did)
            );
            let Some(raw) = self
                .db
                .read_tx(|tx| tx.get_labyrinth_state(&key))
                .map_err(|e| e.to_string())?
            else {
                return Err(format!(
                    "{}: conversation Space placement not pinned",
                    super::NATIVE_UNAUTHENTICATED_DENIAL
                ));
            };
            let pins: BTreeMap<String, crate::labyrinth::space::ThreadPlacement> =
                serde_json::from_slice(&raw)
                    .map_err(|e| format!("native_space_invalid_pins: {e}"))?;
            let Some(space_str) = pins
                .get(conversation_id)
                .and_then(|pin| pin.space.as_deref())
            else {
                return Err(format!(
                    "{}: conversation Space URI not pinned",
                    super::NATIVE_UNAUTHENTICATED_DENIAL
                ));
            };
            let space = SpaceUri::parse_hedged(space_str)
                .map_err(|e| format!("native_space_uri: {e}"))?;
            let authority = self.space_document(&space.authority)?;
            match self.space_credential(&space, false, authority)? {
                Err(_) => Ok(true),
                Ok(_) => Ok(false),
            }
        }

        fn space_read(
            &self,
            context: &ReadContext,
            nsid: &str,
            path: &str,
            mut headers: Vec<(String, String)>,
            mac_profile: Option<MacProfile>,
        ) -> Result<(PlatformHttpResponse, Option<NegotiatedMacSecret>), String> {
            self.space_credential_live(context)?;
            let signed = sign_credential_request_minimal(
                &context.credential.key,
                &context.credential.jwt,
                &context.writer,
            )
            .map_err(|e| format!("native_space_request_pop: {e}"))?;
            let negotiated = if let Some(profile) = mac_profile {
                let kem = context
                    .kem_key
                    .as_deref()
                    .ok_or("native_space_writer_missing_atproto_kem")?;
                let ephemeral = self.space_key()?;
                let encap = encapsulate_p256_deterministic(kem, &ephemeral)
                    .map_err(|e| format!("native_space_request_kem: {e}"))?;
                let accept = format_accept_signature(profile, &encap.key_share_did_key)
                    .map_err(|e| format!("native_space_accept_signature: {e}"))?;
                Some((
                    accept,
                    encap.key_share_did_key,
                    Zeroizing::new(encap.shared_secret),
                ))
            } else {
                None
            };
            let response = if context.personal {
                headers.extend([
                    ("authorization".into(), signed.authorization),
                    (
                        "atproto-space-audience".into(),
                        signed.atproto_space_audience,
                    ),
                    ("signature-input".into(), signed.signature_input),
                    ("signature".into(), signed.signature),
                ]);
                if let Some((accept, _, _)) = &negotiated {
                    headers.push((ACCEPT_SIGNATURE_HEADER.into(), accept.clone()));
                }
                self.execute(
                    &self.config.pds_endpoint,
                    "GET".into(),
                    path.into(),
                    headers,
                    None,
                )?
            } else {
                let query = path.split_once('?').map(|(_, query)| query);
                let body = serde_json::to_vec(&serde_json::json!({
                    "actorDeviceId": self.config.device_id,
                    "targetDid": context.writer,
                    "nsid": nsid,
                    "query": query,
                    "credential": context.credential.jwt.as_str(),
                    "spaceAudience": signed.atproto_space_audience,
                    "signatureInput": signed.signature_input,
                    "signature": signed.signature,
                    "acceptSignature": negotiated.as_ref().map(|(accept, _, _)| accept.as_str()),
                }))
                .map_err(|e| format!("native_space_encode_read_relay: {e}"))?;
                self.execute(
                    &self.config.home_ds_endpoint,
                    "POST".into(),
                    "/xrpc/blue.catbird.chat.relaySpaceRead".into(),
                    vec![],
                    Some(body),
                )?
            };
            if !context.personal
                && !(200..300).contains(&response.status)
                && reads_as_space_denial(&response)
            {
                return Err(format!(
                    "{}: unsigned HTTP {}",
                    super::NATIVE_UNAUTHENTICATED_DENIAL,
                    response.status
                ));
            }
            self.space_credential_live(context)?;
            Ok((
                bounded(response)?,
                negotiated.map(|(_, ks, secret)| (ks, secret)),
            ))
        }

        fn inventory_verified(&self, space: &SpaceUri) -> Result<bool, String> {
            Ok(self
                .verified_inventories
                .lock()
                .map_err(|_| "native_space_inventory_cache_poisoned")?
                .contains_key(&space.raw))
        }

        /// Verify and cache the Space's writer inventory as an authority read under the same
        /// credential; `context` then addresses its own writer again.
        fn verify_space_inventory(
            &self,
            context: &mut ReadContext,
            authority_kem: Option<String>,
        ) -> Result<(), String> {
            let writer = std::mem::replace(&mut context.writer, context.space.authority.clone());
            let kem_key = std::mem::replace(&mut context.kem_key, authority_kem);
            let params = BTreeMap::from([("space".to_owned(), context.space.raw.clone())]);
            let (mut response, negotiated) = self.space_read(
                context,
                LIST_WRITERS,
                &query_path(LIST_WRITERS, &params),
                vec![],
                Some(MacProfile::Commit),
            )?;
            require_success(&response, "listWriters inventory")?;
            self.verify_inventory(
                context,
                &params,
                &mut response,
                negotiated
                    .as_ref()
                    .ok_or("native_space_missing_request_secret")?,
            )
            .map_err(|error| {
                if error.starts_with("WriterRollback:") {
                    error
                } else {
                    format!("ArchiveInventoryIncomplete: {error}")
                }
            })?;
            context.writer = writer;
            context.kem_key = kem_key;
            Ok(())
        }

        fn verify_inventory(
            &self,
            context: &mut ReadContext,
            params: &BTreeMap<String, String>,
            response: &mut PlatformHttpResponse,
            negotiated: &NegotiatedMacSecret,
        ) -> Result<(), String> {
            if params
                .keys()
                .any(|key| !matches!(key.as_str(), "space" | "cursor" | "limit"))
                || params.contains_key("cursor")
            {
                return Err("native_space_inventory_must_start_at_snapshot_head".into());
            }
            let limit = params
                .get("limit")
                .map(|value| value.parse::<usize>())
                .transpose()
                .map_err(|_| "native_space_invalid_inventory_limit")?
                .unwrap_or(100);
            if limit == 0 || limit > 1_000 {
                return Err("native_space_invalid_inventory_limit".into());
            }
            if context.writer != context.space.authority {
                return Err("native_space_inventory_authority_mismatch".into());
            }

            let authority = context.space.authority.clone();
            let authority_kem = context.kem_key.clone();
            self.verified_inventories
                .lock()
                .map_err(|_| "native_space_inventory_cache_poisoned")?
                .remove(&context.space.raw);
            let mut current = PlatformHttpResponse {
                status: response.status,
                headers: std::mem::take(&mut response.headers),
                body: std::mem::take(&mut response.body),
            };
            let mut current_negotiated = negotiated.clone();
            let mut expected_commit: Option<Commit> = None;
            let mut wire_items = Vec::new();
            let mut active_repos = Vec::new();
            let mut cursors = BTreeSet::new();
            let mut previous_did: Option<String> = None;
            let mut total_bytes = 0usize;
            let mut terminal = false;

            for _ in 0..MAX_INVENTORY_PAGES {
                total_bytes = total_bytes
                    .checked_add(current.body.len())
                    .ok_or("native_space_inventory_bytes_overflow")?;
                if total_bytes > MAX_INVENTORY_BYTES {
                    return Err("native_space_inventory_bytes_exceeded".into());
                }
                let page: InventoryPage = decode(&current.body, "writer inventory")?;
                if page.repos.len() > limit {
                    return Err("native_space_inventory_limit_exceeded".into());
                }
                if page.commit.rev.is_empty() {
                    return Err("native_space_inventory_commit_revision_missing".into());
                }
                verify_commit(context, &current, &current_negotiated, &page.commit)?;
                let _: [u8; 32] = page
                    .commit
                    .data
                    .as_ref()
                    .try_into()
                    .map_err(|_| "native_space_invalid_inventory_commitment")?;
                if expected_commit.is_none() {
                    expected_commit = Some(page.commit.clone());
                } else if expected_commit.as_ref() != Some(&page.commit) {
                    return Err("native_space_inventory_commit_changed".into());
                }

                if page.complete != page.cursor.is_none() {
                    return Err("native_space_inventory_terminal_cursor_mismatch".into());
                }
                if !page.complete && page.repos.is_empty() {
                    return Err("native_space_inventory_empty_nonterminal_page".into());
                }
                for item in page.repos {
                    let item_did = item.repo_did().to_owned();
                    if !atproto_spaces::is_valid_did(&item_did) {
                        return Err("native_space_invalid_inventory_row".into());
                    }
                    if previous_did
                        .as_deref()
                        .is_some_and(|previous| previous >= item_did.as_str())
                    {
                        return Err("native_space_inventory_not_strictly_ordered".into());
                    }
                    match &item {
                        InventoryWriterItem::RepoWrite {
                            repo,
                            repo_rev,
                            space_rev,
                            data,
                            ..
                        } => {
                            if repo_rev.is_empty() || space_rev.is_empty() {
                                return Err("native_space_invalid_inventory_row".into());
                            }
                            let data_32: [u8; 32] = data
                                .as_ref()
                                .try_into()
                                .map_err(|_| "native_space_invalid_inventory_repo_commitment")?;
                            active_repos.push(ActiveInventoryRepo {
                                did: repo.clone(),
                                repo_rev: repo_rev.clone(),
                                space_rev: space_rev.clone(),
                                data: data_32,
                            });
                        }
                        InventoryWriterItem::RepoRemoved { space_rev, .. } => {
                            if space_rev.is_empty() {
                                return Err("native_space_invalid_inventory_row".into());
                            }
                        }
                    }
                    previous_did = Some(item_did);
                    wire_items.push(item);
                    if wire_items.len() > MAX_INVENTORY_WRITERS {
                        return Err("native_space_inventory_writer_limit_exceeded".into());
                    }
                }

                let Some(cursor) = page.cursor else {
                    terminal = true;
                    break;
                };
                check_cursor(Some(&cursor))?;
                if !cursors.insert(cursor.clone()) {
                    return Err("native_space_inventory_cursor_cycle".into());
                }
                let mut next_params = params.clone();
                next_params.insert("cursor".into(), cursor);
                let (next, next_negotiated) = self.space_read(
                    context,
                    LIST_WRITERS,
                    &query_path(LIST_WRITERS, &next_params),
                    vec![],
                    Some(MacProfile::Commit),
                )?;
                require_success(&next, "listWriters inventory")?;
                current = next;
                current_negotiated =
                    next_negotiated.ok_or("native_space_missing_request_secret")?;
            }
            if !terminal {
                return Err("native_space_inventory_page_limit_exceeded".into());
            }

            let commit = expected_commit.ok_or("native_space_inventory_commit_missing")?;
            let expected_data: [u8; 32] = commit
                .data
                .as_ref()
                .try_into()
                .map_err(|_| "native_space_invalid_inventory_commitment")?;
            let mut inventory_hash = LtHash::empty();
            for row in &active_repos {
                inventory_hash
                    .add_inventory_entry(&row.did, &row.repo_rev, &row.space_rev, &row.data)
                    .map_err(|error| format!("native_space_inventory_hash: {error}"))?;
            }
            if inventory_hash.commitment() != expected_data {
                return Err("native_space_inventory_commitment_mismatch".into());
            }

            let mut verified = VerifiedArchiveInventory::default();
            let mut verified_bytes = 0usize;
            for row in &active_repos {
                self.check_writer_rev_not_rolled_back(
                    &context.space.raw,
                    &row.did,
                    &row.repo_rev,
                )?;
                context.writer = row.did.clone();
                context.kem_key = if row.did == authority {
                    authority_kem.clone()
                } else {
                    self.space_document(&row.did)?.atproto_kem_did_key
                };
                let (records, writer_bytes) = self.verify_inventory_writer(context, row)?;
                self.observe_writer_rev(&context.space.raw, &row.did, &row.repo_rev)?;
                verified_bytes = verified_bytes
                    .checked_add(writer_bytes)
                    .ok_or("native_space_inventory_cache_bytes_overflow")?;
                if verified_bytes > MAX_INVENTORY_BYTES {
                    return Err("native_space_inventory_cache_bytes_exceeded".into());
                }
                if verified
                    .writers
                    .insert(row.did.clone(), records)
                    .is_some()
                {
                    return Err("native_space_inventory_duplicate_writer".into());
                }
            }
            self.verified_inventories
                .lock()
                .map_err(|_| "native_space_inventory_cache_poisoned")?
                .insert(context.space.raw.clone(), verified);
            context.writer = authority;
            context.kem_key = authority_kem;

            response.status = current.status;
            response.headers = std::mem::take(&mut current.headers);
            response.body = serde_json::to_vec(&InventoryPage {
                repos: wire_items,
                complete: true,
                cursor: None,
                commit,
            })
            .map_err(|error| format!("native_space_encode_inventory: {error}"))?;
            Ok(())
        }

        fn verify_inventory_writer(
            &self,
            context: &mut ReadContext,
            row: &ActiveInventoryRepo,
        ) -> Result<(Vec<VerifiedArchiveRecord>, usize), String> {
            let expected_data = row.data;
            let params = BTreeMap::from([
                ("space".into(), context.space.raw.clone()),
                ("repo".into(), row.did.clone()),
            ]);

            let (star_response, star_negotiated) = self.space_read(
                context,
                GET_REPO,
                &query_path(GET_REPO, &params),
                vec![],
                Some(MacProfile::Commit),
            )?;
            require_success(&star_response, "inventory getRepo")?;
            let repo = verify_star(
                context,
                &star_response,
                star_negotiated
                    .as_ref()
                    .ok_or("native_space_missing_request_secret")?,
            )?;
            if repo.rev != row.repo_rev || repo.data != expected_data {
                return Err("native_space_inventory_star_head_mismatch".into());
            }

            let mut ops_params = params;
            ops_params.insert("excludeValues".into(), "true".into());
            ops_params.insert("limit".into(), "1000".into());
            let (mut ops_response, ops_negotiated) = self.space_read(
                context,
                LIST_OPS,
                &query_path(LIST_OPS, &ops_params),
                vec![],
                Some(MacProfile::Commit),
            )?;
            require_success(&ops_response, "inventory listRepoOps")?;
            let head = self.verify_repo_ops(
                context,
                &mut ops_response,
                ops_negotiated
                    .as_ref()
                    .ok_or("native_space_missing_request_secret")?,
                Some(&repo),
            )?;
            if head.rev != row.repo_rev || head.data.as_ref() != expected_data.as_slice() {
                return Err("native_space_inventory_oplog_head_mismatch".into());
            }
            let mut records = Vec::with_capacity(repo.records.len());
            let mut coordinates = BTreeSet::new();
            let mut cached_bytes = 0usize;
            for record in repo.records {
                if !coordinates.insert((record.collection.clone(), record.rkey.clone())) {
                    return Err("native_space_inventory_duplicate_record".into());
                }
                let get_params = BTreeMap::from([
                    ("space".into(), context.space.raw.clone()),
                    ("repo".into(), row.did.clone()),
                    ("collection".into(), record.collection.clone()),
                    ("rkey".into(), record.rkey.clone()),
                ]);
                let (record_response, record_negotiated) = self.space_read(
                    context,
                    GET_RECORD,
                    &query_path(GET_RECORD, &get_params),
                    vec![],
                    Some(MacProfile::Record),
                )?;
                require_success(&record_response, "inventory getRecord")?;
                let (full, value) = verify_record(
                    context,
                    &get_params,
                    &record_response,
                    record_negotiated
                        .as_ref()
                        .ok_or("native_space_missing_request_secret")?,
                )?;
                let cid = record.cid.to_string();
                if full.cid.as_str() != cid {
                    return Err("native_space_inventory_record_cid_mismatch".into());
                }
                cached_bytes = cached_bytes
                    .checked_add(record_response.body.len())
                    .and_then(|size| size.checked_add(record.collection.len()))
                    .and_then(|size| size.checked_add(record.rkey.len()))
                    .and_then(|size| size.checked_add(cid.len()))
                    .ok_or("native_space_inventory_cache_bytes_overflow")?;
                records.push(VerifiedArchiveRecord {
                    collection: record.collection,
                    rkey: record.rkey,
                    cid,
                    value,
                });
            }
            records.sort_by(|left, right| {
                (&left.collection, &left.rkey).cmp(&(&right.collection, &right.rkey))
            });
            Ok((records, cached_bytes))
        }

        fn release_verified_inventory_record(
            &self,
            context: &ReadContext,
            params: &BTreeMap<String, String>,
            response: &mut PlatformHttpResponse,
        ) -> Result<(), String> {
            if params
                .keys()
                .any(|key| !matches!(key.as_str(), "space" | "repo" | "collection" | "rkey"))
            {
                return Err("native_space_inventory_record_parameter_mismatch".into());
            }
            let inventories = self
                .verified_inventories
                .lock()
                .map_err(|_| "native_space_inventory_cache_poisoned")?;
            let collection = required(params, "collection")?;
            let rkey = required(params, "rkey")?;
            let inventory = inventories
                .get(&context.space.raw)
                .ok_or("native_space_inventory_snapshot_missing")?;
            let record = inventory
                .writers
                .get(&context.writer)
                .and_then(|records| {
                    records
                        .iter()
                        .find(|record| record.collection == collection && record.rkey == rkey)
                });
            let Some(record) = record else {
                response.status = 404;
                response.body = serde_json::to_vec(&serde_json::json!({
                    "error": "RecordNotFound",
                }))
                .map_err(|error| format!("native_space_encode_record_absence: {error}"))?;
                return Ok(());
            };
            let uri = context
                .space
                .record_uri(&context.writer, collection, rkey)
                .map_err(|error| format!("native_space_record_coordinates: {error}"))?;
            response.body = serde_json::to_vec(&serde_json::json!({
                "uri": uri,
                "cid": record.cid,
                "value": record.value,
            }))
            .map_err(|error| format!("native_space_encode_inventory_record: {error}"))?;
            Ok(())
        }

        fn release_verified_inventory_records(
            &self,
            context: &ReadContext,
            params: &BTreeMap<String, String>,
            response: &mut PlatformHttpResponse,
        ) -> Result<(), String> {
            if params.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "space"
                        | "repo"
                        | "collection"
                        | "cursor"
                        | "limit"
                        | "reverse"
                        | "excludeValues"
                )
            }) {
                return Err("native_space_inventory_list_parameter_mismatch".into());
            }
            let inventories = self
                .verified_inventories
                .lock()
                .map_err(|_| "native_space_inventory_cache_poisoned")?;
            let inventory = inventories
                .get(&context.space.raw)
                .ok_or("native_space_inventory_snapshot_missing")?;
            // The verified inventory lists every writer: one it omits has no records here.
            let records = inventory
                .writers
                .get(&context.writer)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let limit = params
                .get("limit")
                .map(|value| value.parse::<usize>())
                .transpose()
                .map_err(|_| "native_space_invalid_list_limit")?
                .unwrap_or(50);
            if limit == 0 || limit > 1_000 {
                return Err("native_space_invalid_list_limit".into());
            }
            let reverse = match params.get("reverse").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => return Err("native_space_invalid_list_reverse".into()),
            };
            let exclude = match params.get("excludeValues").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => return Err("native_space_invalid_exclude_values".into()),
            };
            let cursor = params.get("cursor");
            check_cursor(cursor.map(String::as_str))?;
            let collection = params.get("collection");
            let mut selected: Vec<_> = records
                .iter()
                .filter(|record| {
                    collection.is_none_or(|wanted| wanted == &record.collection)
                        && cursor.is_none_or(|cursor| {
                            let path = format!("{}/{}", record.collection, record.rkey);
                            if reverse {
                                path.as_str() < cursor.as_str()
                            } else {
                                path.as_str() > cursor.as_str()
                            }
                        })
                })
                .collect();
            if reverse {
                selected.reverse();
            }
            let more = selected.len() > limit;
            selected.truncate(limit);
            let next = more.then(|| {
                let record = selected
                    .last()
                    .expect("more records implies a nonempty selected page");
                format!("{}/{}", record.collection, record.rkey)
            });
            let records: Vec<_> = selected
                .into_iter()
                .map(|record| {
                    let mut value = serde_json::json!({
                        "collection": record.collection,
                        "rkey": record.rkey,
                        "cid": record.cid,
                    });
                    if !exclude {
                        value["value"] = record.value.clone();
                    }
                    value
                })
                .collect();
            let mut body = serde_json::json!({"records": records});
            if let Some(next) = next {
                body["cursor"] = next.into();
            }
            response.headers.clear();
            response.body = serde_json::to_vec(&body)
                .map_err(|error| format!("native_space_encode_inventory_records: {error}"))?;
            Ok(())
        }

        fn verify_listed_records(
            &self,
            context: &ReadContext,
            params: &BTreeMap<String, String>,
            response: &mut PlatformHttpResponse,
        ) -> Result<(), String> {
            if context.space.space_type == "blue.catbird.labyrinth.conversation" {
                return self.release_verified_inventory_records(context, params, response);
            }
            // Parse only coordinates first. Values are skipped by serde until every
            // corresponding getRecord has passed MAC and content-CID verification.
            let page: ListedPage = decode(&response.body, "listRecords envelope")?;
            let limit = params
                .get("limit")
                .map(|s| s.parse::<usize>())
                .transpose()
                .map_err(|_| "native_space_invalid_list_limit")?
                .unwrap_or(50);
            if limit == 0 || limit > 1000 || page.records.len() > limit {
                return Err("native_space_list_limit_exceeded".into());
            }
            check_cursor(page.cursor.as_deref())?;
            let exclude = match params.get("excludeValues").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                _ => return Err("native_space_invalid_exclude_values".into()),
            };
            let mut seen = BTreeSet::new();
            let mut authenticated = Vec::with_capacity(page.records.len());
            for stub in &page.records {
                let expected_uri = context
                    .space
                    .record_uri(&context.writer, &stub.collection, &stub.rkey)
                    .map_err(|e| format!("native_space_list_coordinates: {e}"))?;
                let stub_uri_norm = stub.uri.as_deref().map(|u| {
                    if let Some((prefix, rest)) = u.split_once(&format!("/{}/", context.writer)) {
                        if let Ok(parsed) = SpaceUri::parse(prefix) {
                            return format!("{}/{}/{rest}", parsed.raw, context.writer);
                        }
                    }
                    u.to_owned()
                });
                let stub_space_norm = stub
                    .space
                    .as_deref()
                    .and_then(|s| SpaceUri::parse(s).ok().map(|p| p.raw));
                if params
                    .get("collection")
                    .is_some_and(|c| c != &stub.collection)
                    || stub_uri_norm
                        .as_deref()
                        .is_some_and(|uri| uri != expected_uri)
                    || stub.repo.as_deref().is_some_and(|repo| repo != context.writer)
                    || stub
                        .space
                        .as_ref()
                        .is_some_and(|_| stub_space_norm.as_deref() != Some(context.space.raw.as_str()))
                    || !seen.insert((&stub.collection, &stub.rkey))
                {
                    return Err("native_space_list_coordinate_mismatch".into());
                }
                let get_params = BTreeMap::from([
                    ("space".into(), context.space.raw.clone()),
                    ("repo".into(), context.writer.clone()),
                    ("collection".into(), stub.collection.clone()),
                    ("rkey".into(), stub.rkey.clone()),
                ]);
                let path = query_path(GET_RECORD, &get_params);
                let (record_response, negotiated) = self.space_read(
                    context,
                    GET_RECORD,
                    &path,
                    vec![],
                    Some(MacProfile::Record),
                )?;
                require_success(&record_response, "listed getRecord")?;
                let (full, value) = verify_record(
                    context,
                    &get_params,
                    &record_response,
                    negotiated
                        .as_ref()
                        .ok_or("native_space_missing_request_secret")?,
                )?;
                if full.cid.as_str() != stub.cid {
                    return Err("native_space_list_cid_mismatch".into());
                }
                authenticated.push((full, value));
            }
            // Only authenticated records can now be compared to inline list data.
            let full_page: ListRecordsOutput = decode(&response.body, "listRecords values")?;
            let mut records = Vec::with_capacity(authenticated.len());
            for ((listed, (verified, value)), stub) in full_page
                .records
                .into_iter()
                .zip(authenticated)
                .zip(page.records)
            {
                if listed
                    .value
                    .as_ref()
                    .is_some_and(|inline| inline != &verified.value)
                    || (!exclude && listed.value.is_none())
                {
                    return Err("native_space_list_value_mismatch".into());
                }
                let mut record = serde_json::json!({"collection": stub.collection, "rkey": stub.rkey, "cid": verified.cid});
                if !exclude {
                    record["value"] = value;
                }
                records.push(record);
            }
            let mut body = serde_json::json!({"records": records});
            if let Some(cursor) = page.cursor {
                body["cursor"] = cursor.into();
            }
            response.body =
                serde_json::to_vec(&body).map_err(|e| format!("native_space_encode_list: {e}"))?;
            Ok(())
        }

        fn verify_repo_ops(
            &self,
            context: &ReadContext,
            response: &mut PlatformHttpResponse,
            negotiated: &NegotiatedMacSecret,
            verified_star_hint: Option<&ParsedStarRepo>,
        ) -> Result<Commit, String> {
            let requested_head: CommitEnvelope =
                decode(&response.body, "listRepoOps commit envelope")?;
            check_cursor(requested_head.cursor.as_deref())?;
            if requested_head.commit.is_some() && requested_head.cursor.is_some() {
                return Err("native_space_commit_before_oplog_head".into());
            }
            if let Some(commit) = &requested_head.commit {
                verify_commit(context, response, negotiated, commit)?;
            }
            if requested_head.commit.is_none() && requested_head.cursor.is_none() {
                return Err("native_space_missing_head_commit".into());
            }
            let requested: OpsPage = decode(&response.body, "listRepoOps coordinates")?;
            if requested.ops.len() > 1000 {
                return Err("native_space_ops_limit_exceeded".into());
            }
            let wanted: BTreeMap<_, _> = requested
                .ops
                .iter()
                .map(|op| ((op.rev.clone(), op.collection.clone(), op.rkey.clone()), op))
                .collect();
            if wanted.len() != requested.ops.len() {
                return Err("native_space_duplicate_ops".into());
            }
            let mut found = BTreeSet::new();
            let mut state = WriterSyncState::empty();
            let mut touched_paths = BTreeSet::new();
            let mut genesis_replay_complete = true;
            let mut cursor: Option<String> = None;
            let mut cursors = BTreeSet::new();
            let mut total_bytes = 0usize;
            for _ in 0..50 {
                let mut params = BTreeMap::from([
                    ("space".into(), context.space.raw.clone()),
                    ("repo".into(), context.writer.clone()),
                    ("excludeValues".into(), "true".into()),
                    ("limit".into(), "1000".into()),
                ]);
                if let Some(cursor) = &cursor {
                    params.insert("cursor".into(), cursor.clone());
                }
                let (page_response, page_negotiated) = self.space_read(
                    context,
                    LIST_OPS,
                    &query_path(LIST_OPS, &params),
                    vec![],
                    Some(MacProfile::Commit),
                )?;
                require_success(&page_response, "listRepoOps replay")?;
                total_bytes += page_response.body.len();
                if total_bytes > 64 * 1024 * 1024 {
                    return Err("native_space_ops_replay_bytes_exceeded".into());
                }
                let envelope: CommitEnvelope =
                    decode(&page_response.body, "listRepoOps replay envelope")?;
                if let Some(commit) = &envelope.commit {
                    if envelope.cursor.is_some() {
                        return Err("native_space_commit_before_oplog_head".into());
                    }
                    verify_commit(
                        context,
                        &page_response,
                        page_negotiated
                            .as_ref()
                            .ok_or("native_space_missing_request_secret")?,
                        commit,
                    )?;
                }
                let page: OpsPage = decode(&page_response.body, "listRepoOps replay coordinates")?;
                if page.ops.len() > 1000 {
                    return Err("native_space_ops_limit_exceeded".into());
                }
                for op in page.ops {
                    context
                        .space
                        .record_uri(&context.writer, &op.collection, &op.rkey)
                        .map_err(|e| format!("native_space_op_coordinates: {e}"))?;
                    if op.rev.is_empty()
                        || state
                            .latest_rev
                            .as_ref()
                            .is_some_and(|rev| rev > &op.rev)
                    {
                        return Err("native_space_nonmonotonic_ops".into());
                    }
                    state.latest_rev = Some(op.rev.clone());
                    let identity = (op.rev.clone(), op.collection.clone(), op.rkey.clone());
                    if let Some(expected) = wanted.get(&identity) {
                        if **expected != op || !found.insert(identity) {
                            return Err("native_space_requested_op_mismatch".into());
                        }
                    }
                    let path = format!("{}/{}", op.collection, op.rkey);
                    let seen_in_replay = !touched_paths.insert(path.clone());
                    let old = state.cid_by_path.remove(&path);
                    let prev = op
                        .prev
                        .as_deref()
                        .map(str::parse)
                        .transpose()
                        .map_err(|_| "native_space_invalid_prev_cid")?;
                    if seen_in_replay {
                        if old != prev {
                            return Err("native_space_op_previous_cid_mismatch".into());
                        }
                        if let Some(cid) = old {
                            state
                                .lt_hash
                                .remove_record(&op.collection, &op.rkey, &cid);
                        }
                    } else if prev.is_some() {
                        // Retained oplog starts after genesis (compacted or post-importRepo):
                        // require verified `getRepo` STAR snapshot commitment reconciliation.
                        genesis_replay_complete = false;
                    }
                    if let Some(cid) = op.cid {
                        let cid = cid.parse().map_err(|_| "native_space_invalid_op_cid")?;
                        state.lt_hash.add_record(&op.collection, &op.rkey, &cid);
                        state.cid_by_path.insert(path, cid);
                    } else if prev.is_none() {
                        return Err("native_space_delete_without_record".into());
                    }
                }
                if let Some(next) = envelope.cursor {
                    check_cursor(Some(&next))?;
                    if !cursors.insert(next.clone()) {
                        return Err("native_space_oplog_cursor_cycle".into());
                    }
                    cursor = Some(next);
                    continue;
                }
                let head = envelope.commit.ok_or("native_space_missing_head_commit")?;
                if state
                    .latest_rev
                    .as_ref()
                    .is_some_and(|rev| rev.as_str() > head.rev.as_str())
                {
                    return Err("native_space_oplog_commitment_mismatch".into());
                }
                if let Some(requested_head) = &requested_head.commit {
                    if requested_head != &head {
                        return Err("native_space_oplog_head_changed".into());
                    }
                }
                if found.len() != wanted.len() {
                    return Err("native_space_requested_ops_not_found".into());
                }
                if !genesis_replay_complete
                    || state.lt_hash.commitment().as_slice() != head.data.as_ref()
                {
                    // Post-`importRepo`/`clearRecords` (`ops: []` + non-empty `LtHash`) or
                    // retention-compacted `listRepoOps`: fall back to an authenticated `getRepo`
                    // STAR snapshot bound to the exact same `(rev, data)` head commitment.
                    let owned_star;
                    let star_repo = match verified_star_hint {
                        Some(repo) => repo,
                        None => {
                            let star_params = BTreeMap::from([
                                ("space".into(), context.space.raw.clone()),
                                ("repo".into(), context.writer.clone()),
                            ]);
                            let (star_response, star_negotiated) = self.space_read(
                                context,
                                GET_REPO,
                                &query_path(GET_REPO, &star_params),
                                vec![],
                                Some(MacProfile::Commit),
                            )?;
                            require_success(&star_response, "listRepoOps star fallback getRepo")?;
                            owned_star = verify_star(
                                context,
                                &star_response,
                                star_negotiated
                                    .as_ref()
                                    .ok_or("native_space_missing_request_secret")?,
                            )?;
                            &owned_star
                        }
                    };
                    if star_repo.rev != head.rev || star_repo.data.as_slice() != head.data.as_ref()
                    {
                        return Err("native_space_oplog_commitment_mismatch".into());
                    }
                    let mut star_cid_by_path = BTreeMap::new();
                    for record in &star_repo.records {
                        context
                            .space
                            .record_uri(&context.writer, &record.collection, &record.rkey)
                            .map_err(|e| format!("native_space_star_coordinates: {e}"))?;
                        let path = format!("{}/{}", record.collection, record.rkey);
                        if star_cid_by_path.insert(path, record.cid).is_some() {
                            return Err("native_space_star_duplicate_record".into());
                        }
                    }
                    for path in &touched_paths {
                        if state.cid_by_path.get(path) != star_cid_by_path.get(path) {
                            return Err("native_space_oplog_commitment_mismatch".into());
                        }
                    }
                    state.cid_by_path = star_cid_by_path;
                }
                // A current-state commitment cannot authenticate superseded values.
                // The protocol omits those values; refuse a host that includes them.
                let mut full: ListRepoOpsOutput =
                    decode(&response.body, "authenticated listRepoOps values")?;
                for op in &mut full.ops {
                    op.extra_data = None;
                    if let Some(value) = &op.value {
                        let path = format!("{}/{}", op.collection.as_str(), op.rkey.as_ref());
                        let current = state
                            .cid_by_path
                            .get(&path)
                            .ok_or("native_space_stale_op_value")?;
                        let claimed = op
                            .cid
                            .as_ref()
                            .ok_or("native_space_stale_op_value")?
                            .as_str()
                            .parse()
                            .map_err(|_| "native_space_invalid_op_cid")?;
                        if current != &claimed {
                            return Err("native_space_stale_op_value".into());
                        }
                        let bytes = serde_ipld_dagcbor::to_vec(value)
                            .map_err(|e| format!("native_space_encode_op_value: {e}"))?;
                        validate_canonical_dagcbor_record(&bytes)
                            .map_err(|e| format!("native_space_invalid_op_value: {e}"))?;
                        if &compute_dagcbor_cid(&bytes) != current {
                            return Err("native_space_op_value_cid_mismatch".into());
                        }
                    }
                }
                full.extra_data = None;
                full.commit.extra_data = None;
                let mut body = serde_json::to_value(&full)
                    .map_err(|e| format!("native_space_encode_ops: {e}"))?;
                let served: ServedOps = decode(&response.body, "authenticated listRepoOps JSON")?;
                for (op, served) in body
                    .get_mut("ops")
                    .and_then(serde_json::Value::as_array_mut)
                    .into_iter()
                    .flatten()
                    .zip(served.ops)
                {
                    if let Some(value) = served.value {
                        op["value"] = value;
                    }
                }
                response.body = serde_json::to_vec(&body)
                    .map_err(|e| format!("native_space_encode_ops: {e}"))?;
                return Ok(head);
            }
            Err("native_space_oplog_page_limit_exceeded".into())
        }
    }

    fn verify_record(
        context: &ReadContext,
        params: &BTreeMap<String, String>,
        response: &PlatformHttpResponse,
        negotiated: &NegotiatedMacSecret,
    ) -> Result<(GetRecordOutput, serde_json::Value), String> {
        let (key_share, secret) = negotiated;
        let envelope: RecordEnvelope = decode(&response.body, "getRecord envelope")?;
        let expected = context
            .space
            .record_uri(
                &context.writer,
                required(params, "collection")?,
                required(params, "rkey")?,
            )
            .map_err(|e| format!("native_space_record_coordinates: {e}"))?;
        let envelope_uri = if let Some((prefix, rest)) =
            envelope.uri.split_once(&format!("/{}/", context.writer))
        {
            if let Ok(parsed) = SpaceUri::parse(prefix) {
                format!("{}/{}/{rest}", parsed.raw, context.writer)
            } else {
                envelope.uri.clone()
            }
        } else {
            envelope.uri.clone()
        };
        if envelope_uri != expected {
            return Err("native_space_record_uri_mismatch".into());
        }
        let (_, cid) = multibase::decode(&envelope.cid)
            .map_err(|e| format!("native_space_invalid_record_cid: {e}"))?;
        let headers = mac_headers(response, RECORD_MAC_HEADER)?;
        verify_record_mac(secret, key_share, &headers, &envelope.uri, &envelope.cid)
            .map_err(|e| format!("native_space_record_mac: {e}"))?;
        let mut full: GetRecordOutput = decode(&response.body, "authenticated getRecord value")?;
        let bytes = serde_ipld_dagcbor::to_vec(&full.value)
            .map_err(|e| format!("native_space_encode_record_value: {e}"))?;
        validate_canonical_dagcbor_record(&bytes)
            .map_err(|e| format!("native_space_invalid_record_value: {e}"))?;
        if compute_dagcbor_cid(&bytes).to_bytes() != cid {
            return Err("native_space_record_value_cid_mismatch".into());
        }
        full.extra_data = None;
        let served: ServedValue = decode(&response.body, "authenticated getRecord JSON")?;
        Ok((full, served.value.ok_or("native_space_missing_record_value")?))
    }

    fn verify_commit(
        context: &ReadContext,
        response: &PlatformHttpResponse,
        negotiated: &NegotiatedMacSecret,
        commit: &Commit,
    ) -> Result<(), String> {
        let (key_share, secret) = negotiated;
        let commit_space = SpaceUri::parse(&commit.space)
            .ok()
            .map(|s| s.raw);
        if commit_space.as_deref() != Some(context.space.raw.as_str())
            || commit.repo != context.writer
            || commit.ver != 1
        {
            return Err("native_space_commit_binding_mismatch".into());
        }
        let data: [u8; 32] = commit
            .data
            .as_ref()
            .try_into()
            .map_err(|_| "native_space_invalid_commit_data")?;
        let headers = mac_headers(response, COMMIT_MAC_HEADER)?;
        verify_commit_mac(
            secret,
            key_share,
            &headers,
            &commit.space,
            &context.writer,
            &commit.rev,
            &data,
        )
        .map_err(|e| format!("native_space_commit_mac: {e}"))
    }

    fn verify_star(
        context: &ReadContext,
        response: &PlatformHttpResponse,
        negotiated: &NegotiatedMacSecret,
    ) -> Result<ParsedStarRepo, String> {
        let (key_share, secret) = negotiated;
        let headers = mac_headers(response, COMMIT_MAC_HEADER)?;
        read_star_repo_authenticated(&response.body, &context.space.raw, &context.writer, |meta| {
            verify_commit_mac(
                secret,
                key_share,
                &headers,
                &context.space.raw,
                &context.writer,
                &meta.rev,
                &meta.data,
            )
        })
        .map_err(|e| match e {
            atproto_spaces::SpacesError::MacMismatch(msg) => {
                format!("native_space_star_mac: {msg}")
            }
            atproto_spaces::SpacesError::SetHashMismatch(_) => {
                "native_space_star_commitment_mismatch".into()
            }
            other => format!("native_space_star_records: {other}"),
        })
    }

    fn verify_blob(cid: &str, body: &[u8]) -> Result<(), String> {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        let (_, bytes) =
            multibase::decode(cid).map_err(|e| format!("native_space_invalid_blob_cid: {e}"))?;
        // ATProto blob references are CIDv1/raw/sha2-256. The requested CID is
        // carried by the already authenticated attachment-manifest record.
        if bytes.len() != 36 || bytes[..4] != [1, 0x55, 0x12, 0x20] {
            return Err("native_space_unsupported_blob_cid".into());
        }
        if !bool::from(Sha256::digest(body)[..].ct_eq(&bytes[4..])) {
            return Err("native_space_blob_cid_mismatch".into());
        }
        Ok(())
    }

    fn mac_headers(
        response: &PlatformHttpResponse,
        expected_covered: &'static str,
    ) -> Result<HeaderMap, String> {
        let mut map = HeaderMap::new();
        for required_name in [expected_covered, SIGNATURE_INPUT_HEADER, SIGNATURE_HEADER] {
            let mut matching = response
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case(required_name));
            let first = matching
                .next()
                .ok_or("native_space_missing_response_mac")?;
            if matching.next().is_some() {
                return Err("native_space_duplicate_response_mac".into());
            }
            let hdr_name = HeaderName::from_static(required_name);
            let hdr_val = HeaderValue::from_str(&first.value)
                .map_err(|_| "native_space_invalid_response_mac_header")?;
            map.insert(hdr_name, hdr_val);
        }
        Ok(map)
    }

    fn bounded(response: PlatformHttpResponse) -> Result<PlatformHttpResponse, String> {
        if response.body.len() > MAX_BODY {
            return Err("native_space_response_too_large".into());
        }
        Ok(response)
    }

    /// How long a server refusal of a credential exchange is replayed before asking again.
    const CREDENTIAL_FAILURE_BACKOFF_SECS: u64 = 30;
    /// Upper bound on remembered refusals, so a long session cannot grow the cache unbounded.
    const MAX_CREDENTIAL_FAILURES: usize = 256;

    /// A credential exchange the server answered with an error status (see `require_success`).
    fn is_credential_refusal(error: &str) -> bool {
        (error.starts_with("native_space_getDelegationToken: HTTP ")
            || error.starts_with("native_space_authorizeSpaceSync: HTTP "))
            && !error.contains(": HTTP 401 ")
    }

    fn require_success(response: &PlatformHttpResponse, operation: &str) -> Result<(), String> {
        if !(200..300).contains(&response.status) {
            #[derive(Deserialize)]
            struct XrpcError {
                error: String,
            }
            let code = serde_json::from_slice::<XrpcError>(&response.body)
                .ok()
                .map(|e| e.error)
                .unwrap_or_else(|| "UnknownError".into());
            return Err(format!(
                "native_space_{operation}: HTTP {} {code}",
                response.status
            ));
        }
        Ok(())
    }

    pub(super) fn into_response(response: PlatformHttpResponse) -> LabyrinthSpaceResponse {
        let content_type = response.header("content-type").map(str::to_owned);
        let omit_mac = crate::planted::is_planted_bug_active(
            crate::planted::PlantedBug::P17OmitSpaceMacHeaderForwarding,
        );
        LabyrinthSpaceResponse {
            status: response.status,
            content_type,
            headers: response
                .headers
                .into_iter()
                .filter(|header| {
                    !omit_mac
                        || !(header.name.eq_ignore_ascii_case("atproto-space-mac")
                            || header.name.eq_ignore_ascii_case(RECORD_MAC_HEADER)
                            || header.name.eq_ignore_ascii_case(COMMIT_MAC_HEADER)
                            || header.name.eq_ignore_ascii_case(SIGNATURE_INPUT_HEADER)
                            || header.name.eq_ignore_ascii_case(SIGNATURE_HEADER))
                })
                .map(|header| (header.name, header.value))
                .collect(),
            body: response.body,
        }
    }

    /// Whether an unsigned post-credential refusal could be mistaken for membership denial.
    fn reads_as_space_denial(response: &PlatformHttpResponse) -> bool {
        let error = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|body| body["error"].as_str().map(str::to_owned));
        if matches!(response.status, 400 | 404) && error.as_deref() == Some("SpaceNotFound") {
            // P16 lets the unsigned refusal through to Labyrinth's planted mapping.
            return !crate::planted::is_planted_bug_active(
                crate::planted::PlantedBug::P16MemberRepoSpaceNotFoundAsNotFound,
            );
        }
        let refusal = labyrinth::store::space::SpaceError {
            status: response.status,
            error,
            message: None,
        };
        matches!(
            labyrinth::store::space::map_space_error(refusal),
            labyrinth::Error::Forbidden
        )
    }

    fn decode<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> Result<T, String> {
        serde_json::from_slice(body).map_err(|e| format!("native_space_invalid_{what}: {e}"))
    }

    fn required<'a>(params: &'a BTreeMap<String, String>, field: &str) -> Result<&'a str, String> {
        params
            .get(field)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("native_space_missing_{field}"))
    }

    fn check_cursor(cursor: Option<&str>) -> Result<(), String> {
        if cursor.is_some_and(|s| {
            s.is_empty() || s.len() > 1024 || s.bytes().any(|b| b < 0x20 || b == 0x7f)
        }) {
            return Err("native_space_invalid_cursor".into());
        }
        Ok(())
    }

    fn encode(value: &str) -> String {
        crate::orchestrator::canonical_transport::encode_query(value)
    }

    fn query_path(nsid: &str, params: &BTreeMap<String, String>) -> String {
        let query = params
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("/xrpc/{nsid}?{query}")
    }

    fn parse_query(request: &LabyrinthSpaceRequest) -> Result<BTreeMap<String, String>, String> {
        if !atproto_spaces::is_valid_nsid(&request.nsid)
            || !(request.nsid.starts_with("com.atproto.space.")
                || (request.nsid == "com.atproto.repo.uploadBlob" && request.method == "POST"))
            || request.path.len() > 16 * 1024
            || request
                .path
                .bytes()
                .any(|b| b <= 0x20 || b == 0x7f || b == b'#')
        {
            return Err("native_space_invalid_request_target".into());
        }
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        if path != format!("/xrpc/{}", request.nsid) {
            return Err("native_space_nsid_path_mismatch".into());
        }
        let mut params = BTreeMap::new();
        for pair in query.split('&').filter(|s| !s.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or("native_space_invalid_query_pair")?;
            let key = decode_component(key)?;
            let value = decode_component(value)?;
            if params.insert(key, value).is_some() {
                return Err("native_space_duplicate_query_parameter".into());
            }
        }
        Ok(params)
    }

    fn decode_component(input: &str) -> Result<String, String> {
        let mut output = Vec::with_capacity(input.len());
        let mut bytes = input.bytes();
        while let Some(byte) = bytes.next() {
            match byte {
                b'%' => {
                    let high = bytes
                        .next()
                        .and_then(|b| (b as char).to_digit(16))
                        .ok_or("native_space_invalid_percent_encoding")?;
                    let low = bytes
                        .next()
                        .and_then(|b| (b as char).to_digit(16))
                        .ok_or("native_space_invalid_percent_encoding")?;
                    output.push(((high << 4) | low) as u8);
                }
                b'+' => output.push(b' '),
                _ => output.push(byte),
            }
        }
        let value = String::from_utf8(output).map_err(|_| "native_space_invalid_query_utf8")?;
        if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err("native_space_invalid_query_control_character".into());
        }
        Ok(value)
    }

    #[cfg(test)]
    mod tests {
        use super::super::NativeArchiveSigner;
        use super::*;
        use crate::client::{
            CatbirdMlsClientConfig, PlatformHttpHeader, PlatformHttpRequest, PlatformTransport,
        };
        use crate::sim_hooks::{ChaChaSimEntropy, FixedStepClock, SimClientHooks};
        use crate::storage::{MlsAccountDb, OpenMode};
        use atproto_spaces::{
            kem::decapsulate_p256,
            mac::{
                parse_accept_signature, sign_commit_mac, sign_record_mac, SpaceMacResponseHeaders,
            },
            star::{write_star_repo, StarRecordEntry},
            tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims},
        };
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use serde_json::{json, Value};
        use std::sync::{Arc, Mutex};

        const ACCOUNT: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        const WRITER: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
        const AUTHORITY: &str = "did:web:foreign.example";
        const COLLECTION: &str = "blue.catbird.labyrinth.messageBatch";
        const REV: &str = "3jzfcijpj2z2a";
        const NOW: u64 = 1_700_000_000;
        const BLOB: &[u8] = b"sealed attachment ciphertext";
        /// The MLS group the conversation Space `conversation-0` is pinned with.
        const GROUP: [u8; 32] = [6; 32];

        struct Host {
            signing: P256SecretKey,
            kem: P256SecretKey,
            fault: Mutex<&'static str>,
            requests: Mutex<Vec<PlatformHttpRequest>>,
            replayed_mac: Mutex<Option<SpaceMacResponseHeaders>>,
        }

        impl Host {
            /// The authority's refusal of the credential request for `space` under PoP key `kid`,
            /// as mls-ds signs it, with one `mutation` applied.
            fn signed_refusal(&self, space: &SpaceUri, kid: &str, mutation: &str) -> Vec<u8> {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use p256::ecdsa::signature::Signer as _;
                if mutation == "unsigned" {
                    return br#"{"error":"NotAuthorized","message":"not a member"}"#.to_vec();
                }
                let (conversation, generation) = space.rkey.rsplit_once('-').unwrap();
                let mut header =
                    json!({"alg": "ES256", "typ": "catbird-space-denial+jwt", "kid": "#atproto"});
                let mut claims = json!({
                    "iss": space.authority, "sub": space.raw, "aud": ACCOUNT, "iat": NOW, "exp": NOW + 60,
                    "jti": "denial-from-test-host", "cnf": {"kid": kid},
                    "conversationId": conversation, "generation": generation.parse::<u64>().unwrap(),
                    "groupId": hex::encode(GROUP), "reason": "notActiveMember",
                });
                match mutation {
                    "valid" | "tampered_signature" | "tampered_claims" | "foreign_key" => {}
                    "replayed" => {
                        claims["cnf"]["kid"] = encode_p256_did_key(&self.kem.public_key()).into()
                    }
                    "wrong_authority" => claims["iss"] = "did:web:other-authority.example".into(),
                    "wrong_requester" => claims["aud"] = WRITER.into(),
                    "wrong_space" => {
                        claims["sub"] =
                            format!("at:space/{}/{}/other-0", space.authority, space.space_type)
                                .into()
                    }
                    "wrong_conversation" => claims["conversationId"] = "other".into(),
                    "wrong_generation" => claims["generation"] = 1.into(),
                    "wrong_group" => claims["groupId"] = hex::encode([8; 32]).into(),
                    "expired" => (claims["iat"], claims["exp"]) = ((NOW - 60).into(), NOW.into()),
                    "long_lived" => claims["exp"] = (NOW + 61).into(),
                    "future" => {
                        (claims["iat"], claims["exp"]) = ((NOW + 30).into(), (NOW + 90).into())
                    }
                    "wrong_reason" => claims["reason"] = "spaceDeleted".into(),
                    "wrong_typ" => header["typ"] = "atproto-space-credential+jwt".into(),
                    "wrong_kid" => header["kid"] = "#mls-receipt-1".into(),
                    "extra_claim" => {
                        claims["lxm"] = "com.atproto.space.authorizeSpaceSync".into()
                    }
                    other => panic!("unknown refusal mutation {other}"),
                }
                let encode =
                    |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
                let input = format!("{}.{}", encode(&header), encode(&claims));
                let signing = if mutation == "foreign_key" {
                    P256SecretKey::from_slice(&[9; 32]).unwrap()
                } else {
                    self.signing.clone()
                };
                let signature: p256::ecdsa::Signature =
                    p256::ecdsa::SigningKey::from(&signing).sign(input.as_bytes());
                let mut signature = signature.to_bytes().to_vec();
                if mutation == "tampered_signature" {
                    signature[7] ^= 1;
                }
                let input = if mutation == "tampered_claims" {
                    claims["jti"] = "tampered".into();
                    format!("{}.{}", encode(&header), encode(&claims))
                } else {
                    input
                };
                let denial = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
                serde_json::to_vec(&json!({
                    "error": "NotAuthorized",
                    "message": "not a member",
                    "denial": denial
                }))
                .unwrap()
            }
        }

        fn response(body: Value) -> PlatformHttpResponse {
            PlatformHttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            }
        }

        fn push_mac_headers(resp: &mut PlatformHttpResponse, mac: SpaceMacResponseHeaders) {
            resp.headers.push(PlatformHttpHeader {
                name: mac.covered_header_name.into(),
                value: mac.covered_header,
            });
            resp.headers.push(PlatformHttpHeader {
                name: SIGNATURE_INPUT_HEADER.into(),
                value: mac.signature_input,
            });
            resp.headers.push(PlatformHttpHeader {
                name: SIGNATURE_HEADER.into(),
                value: mac.signature,
            });
        }

        #[cfg(feature = "sim")]
        #[test]
        fn p17_omits_only_the_space_mac_headers() {
            let platform = PlatformHttpResponse {
                status: 200,
                headers: vec![
                    PlatformHttpHeader {
                        name: RECORD_MAC_HEADER.into(),
                        value: "uri=\"at:space/...\"".into(),
                    },
                    PlatformHttpHeader {
                        name: SIGNATURE_INPUT_HEADER.into(),
                        value: "mac=(\"atproto-space-record\";sf)".into(),
                    },
                    PlatformHttpHeader {
                        name: SIGNATURE_HEADER.into(),
                        value: "mac=:AAAA:".into(),
                    },
                    PlatformHttpHeader {
                        name: "Content-Type".into(),
                        value: "application/json".into(),
                    },
                ],
                body: b"{}".to_vec(),
            };
            assert_eq!(into_response(platform.clone()).headers.len(), 4);
            let planted = crate::planted::with_planted_bug(
                Some(crate::planted::PlantedBug::P17OmitSpaceMacHeaderForwarding),
                || into_response(platform),
            );
            assert_eq!(
                planted.headers,
                vec![("Content-Type".into(), "application/json".into())]
            );
        }

        fn header<'a>(request: &'a PlatformHttpRequest, name: &str) -> &'a str {
            let mut values = request
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case(name));
            let value = values.next().unwrap();
            assert!(values.next().is_none(), "duplicate request auth header");
            &value.value
        }

        /// A real labyrinth record whose 32/64-byte keys need base64 padding if re-rendered.
        fn served_record() -> labyrinth::records::Device {
            labyrinth::records::Device {
                type_: labyrinth::records::nsid::DEVICE.into(),
                device_key_pubkey: labyrinth::records::Bytes(vec![1; 32]),
                epoch_storage_key_pubkey: labyrinth::records::Bytes(vec![2; 32]),
                epoch_storage_key_sig: labyrinth::records::Bytes(vec![3; 64]),
                epoch_storage_auth_key_pubkey: None,
                epoch_storage_auth_key_sig: None,
                r#virtual: false,
                chat_binding: None,
                revoked_at: None,
                revocation: None,
                created_at: "2026-11-03T00:00:00.000Z".into(),
            }
        }

        fn value_bytes(value: &Value) -> Vec<u8> {
            let data: catbird_atproto::types::value::Data =
                serde_json::from_value(value.clone()).unwrap();
            serde_ipld_dagcbor::to_vec(&data).unwrap()
        }

        impl PlatformTransport for Host {
            fn execute_http(
                &self,
                request: PlatformHttpRequest,
            ) -> Result<PlatformHttpResponse, crate::MLSError> {
                self.requests.lock().unwrap().push(request.clone());
                let fault = *self.fault.lock().unwrap();
                if let Some(did) = request.url.strip_prefix("https://plc.directory/") {
                    assert!(request
                        .headers
                        .iter()
                        .all(|h| !h.name.eq_ignore_ascii_case("authorization")));
                    let signing = encode_p256_did_key(&self.signing.public_key());
                    let kem = encode_p256_did_key(&self.kem.public_key());
                    return Ok(response(json!({
                        "id": did,
                        "verificationMethod": [
                            {"id": format!("{did}#atproto"), "type": "Multikey", "controller": did,
                             "publicKeyMultibase": signing.strip_prefix("did:key:").unwrap()},
                            {"id": format!("{did}#atproto_kem"), "type": "Multikey", "controller": did,
                             "publicKeyMultibase": kem.strip_prefix("did:key:").unwrap()},
                        ],
                        "service": [{"id": format!("{did}#atproto_pds"), "type": "AtprotoPersonalDataServer",
                                     "serviceEndpoint": "https://writer-pds.example"}],
                    })));
                }
                let target = request.url.split_once("/xrpc/").unwrap().1;
                let (nsid, query) = target.split_once('?').unwrap_or((target, ""));
                if nsid == "com.atproto.identity.resolveDid" {
                    assert!(request.url.starts_with("https://account-pds.example/"));
                    let did = decode_component(query.strip_prefix("did=").unwrap()).unwrap();
                    assert!(
                        !did.starts_with("did:plc:"),
                        "did:plc must resolve directly from plc.directory, never via account PDS"
                    );
                    let signing = encode_p256_did_key(&self.signing.public_key());
                    let kem = encode_p256_did_key(&self.kem.public_key());
                    return Ok(response(json!({
                        "id": did,
                        "verificationMethod": [
                            {"id": format!("{did}#atproto"), "type": "Multikey", "controller": did,
                             "publicKeyMultibase": signing.strip_prefix("did:key:").unwrap()},
                            {"id": format!("{did}#atproto_kem"), "type": "Multikey", "controller": did,
                             "publicKeyMultibase": kem.strip_prefix("did:key:").unwrap()},
                        ],
                        "service": [{"id": format!("{did}#atproto_pds"), "type": "AtprotoPersonalDataServer",
                                     "serviceEndpoint": "https://writer-pds.example"}],
                    })));
                }
                if nsid == "com.atproto.space.getDelegationToken" {
                    assert!(request.url.starts_with("https://account-pds.example/"));
                    assert!(request
                        .headers
                        .iter()
                        .all(|h| !h.name.eq_ignore_ascii_case("authorization")));
                    if fault == "delegation_invalid_request" {
                        return Ok(PlatformHttpResponse {
                            status: 400,
                            headers: vec![],
                            body: br#"{"error":"InvalidRequest"}"#.to_vec(),
                        });
                    }
                    return Ok(response(json!({"token": "pds-oauth-delegation"})));
                }
                if matches!(
                    nsid,
                    "com.atproto.space.authorizeSpaceSync"
                        | "blue.catbird.chat.relaySpaceCredential"
                ) {
                    assert_eq!(request.method, "POST");
                    if fault == "credential_auth_failed" {
                        return Ok(PlatformHttpResponse {
                            status: 401,
                            headers: vec![],
                            body: br#"{"error":"InvalidDelegationToken"}"#.to_vec(),
                        });
                    }
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
                    let space = SpaceUri::parse_hedged(body["space"].as_str().unwrap()).unwrap();
                    let kid = if nsid.starts_with("blue.") {
                        assert!(request.url.starts_with("https://home.example/"));
                        assert_eq!(body["authorityDid"], AUTHORITY);
                        body["cnfKey"].as_str().unwrap()
                    } else {
                        assert!(request.url.starts_with("https://account-pds.example/"));
                        body["credentialKey"].as_str().unwrap()
                    };
                    assert!(request
                        .headers
                        .iter()
                        .all(|h| !h.name.eq_ignore_ascii_case("authorization")));
                    if fault == "credential_denied" {
                        return Ok(PlatformHttpResponse {
                            status: 403,
                            headers: vec![],
                            body: self.signed_refusal(&space, kid, "unsigned"),
                        });
                    }
                    if let Some(mutation) = fault.strip_prefix("denied:") {
                        return Ok(PlatformHttpResponse {
                            status: 403,
                            headers: vec![],
                            body: self.signed_refusal(&space, kid, mutation),
                        });
                    }
                    let signing = if fault == "bad_signature" {
                        P256SecretKey::from_slice(&[9; 32]).unwrap()
                    } else {
                        self.signing.clone()
                    };
                    let other_kid = encode_p256_did_key(&self.kem.public_key());
                    let subject = if fault == "wrong_space" {
                        format!(
                            "at:space/{}/{}/other",
                            space.authority, space.space_type
                        )
                    } else {
                        space.raw
                    };
                    let expired = fault == "expired";
                    let token = mint_space_token(
                        SpaceTokenKind::Credential,
                        &SpaceSigningKey::from_p256_secret(&signing, "#atproto"),
                        &SpaceTokenClaims {
                            iss: space.authority,
                            sub: subject,
                            aud: None,
                            iat: if expired { NOW - 100 } else { NOW },
                            exp: if expired { NOW - 1 } else { NOW + 600 },
                            jti: "credential-from-test-host".into(),
                            cnf_kid: Some(if fault == "wrong_key" {
                                other_kid
                            } else {
                                kid.into()
                            }),
                        },
                    )
                    .unwrap();
                    return Ok(response(json!({"credential": token})));
                }
                if nsid == "com.atproto.space.applyWrites" {
                    assert!(request.url.starts_with("https://account-pds.example/"));
                    assert_eq!(header(&request, "x-oauth-transport-test"), "preserved");
                    return Ok(response(json!({"results": []})));
                }
                let (read_nsid, read_query, accept_sig, relay_target) =
                    if nsid == "blue.catbird.chat.relaySpaceRead" {
                        assert!(request.url.starts_with("https://home.example/"));
                        let body: Value =
                            serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
                        assert_eq!(body["spaceAudience"], body["targetDid"]);
                        assert!(body["signatureInput"]
                            .as_str()
                            .unwrap()
                            .contains("atproto-space-credential"));
                        assert!(body["signature"]
                            .as_str()
                            .unwrap()
                            .starts_with("atproto-space-credential=:"));
                        (
                            body["nsid"].as_str().unwrap().to_owned(),
                            body["query"].as_str().unwrap().to_owned(),
                            body["acceptSignature"].as_str().unwrap().to_owned(),
                            Some(body["targetDid"].as_str().unwrap().to_owned()),
                        )
                    } else {
                        assert!(request.url.starts_with("https://account-pds.example/"));
                        assert!(header(&request, "authorization")
                            .starts_with("Atproto-Space-Credential "));
                        assert_eq!(header(&request, "atproto-space-audience"), ACCOUNT);
                        assert!(header(&request, "signature")
                            .starts_with("atproto-space-credential=:"));
                        (
                            nsid.into(),
                            query.into(),
                            header(&request, ACCEPT_SIGNATURE_HEADER).into(),
                            None,
                        )
                    };
                let params = parse_query(&LabyrinthSpaceRequest::get(
                    &read_nsid,
                    format!("/xrpc/{read_nsid}?{read_query}"),
                ))
                .unwrap();
                let space =
                    SpaceUri::parse_hedged(required(&params, "space").unwrap()).unwrap();
                let writer = params
                    .get("repo")
                    .map(String::as_str)
                    .unwrap_or(space.authority.as_str());
                if let Some(target) = relay_target {
                    assert_eq!(target, writer);
                }
                if fault == "read_denied" {
                    return Ok(PlatformHttpResponse {
                        status: 403,
                        headers: vec![],
                        body: br#"{"error":"NotAuthorized","message":"not a member"}"#.to_vec(),
                    });
                }
                if read_nsid == "com.atproto.space.getBlob" {
                    return Ok(PlatformHttpResponse {
                        status: 200,
                        headers: vec![],
                        body: BLOB.to_vec(),
                    });
                }
                let mut batch0_value = serde_json::to_value(served_record()).unwrap();
                batch0_value["createdAt"] = "2026-11-02T00:00:00.000Z".into();
                let batch0_bytes = value_bytes(&batch0_value);
                let batch0_cid = compute_dagcbor_cid(&batch0_bytes);
                let mut value = serde_json::to_value(served_record()).unwrap();
                if fault == "record_changed_after_inventory" {
                    value["createdAt"] = "2026-11-04T00:00:00.000Z".into();
                }
                let bytes = value_bytes(&value);
                let cid = compute_dagcbor_cid(&bytes);
                if read_nsid == LIST_WRITERS {
                    if fault == "inventory_snapshot_changed" && params.contains_key("cursor") {
                        return Ok(PlatformHttpResponse {
                            status: 409,
                            headers: vec![],
                            body: br#"{"error":"SnapshotChanged"}"#.to_vec(),
                        });
                    }
                    let (label, client_share) =
                        parse_accept_signature(&accept_sig, MacProfile::Commit).unwrap();
                    let (share, secret) = if fault == "keyshare_swap_inventory" {
                        let enc = encapsulate_p256_deterministic(
                            &encode_p256_did_key(&self.kem.public_key()),
                            &P256SecretKey::from_slice(&[99; 32]).unwrap(),
                        )
                        .unwrap();
                        assert_ne!(enc.key_share_did_key, client_share);
                        (enc.key_share_did_key, enc.shared_secret)
                    } else {
                        let secret = decapsulate_p256(&self.kem, &client_share).unwrap();
                        (client_share, secret)
                    };
                    let mut repo_hash = LtHash::empty();
                    if fault.starts_with("ops_compacted") {
                        repo_hash.add_record(COLLECTION, "batch-0", &batch0_cid);
                    }
                    repo_hash.add_record(COLLECTION, "batch-1", &cid);
                    let repo_data = repo_hash.commitment();
                    let many = matches!(
                        fault,
                        "inventory_101"
                            | "inventory_changed_commit"
                            | "inventory_snapshot_changed"
                    );
                    let cycle = fault == "inventory_cursor_cycle";
                    let logical_dids: Vec<String> = if many || cycle {
                        let count = if cycle { 102 } else { 101 };
                        (0..count)
                            .map(|index| format!("did:web:writer-{index:03}.example"))
                            .collect()
                    } else if matches!(
                        fault,
                        "inventory_truncated"
                            | "inventory_omitted"
                            | "inventory_reordered"
                            | "inventory_duplicate"
                    ) {
                        vec![
                            WRITER.to_owned(),
                            "did:plc:cccccccccccccccccccccccc".to_owned(),
                        ]
                    } else {
                        vec![WRITER.to_owned()]
                    };
                    let logical_rows: Vec<(String, String, String, [u8; 32])> = logical_dids
                        .into_iter()
                        .enumerate()
                        .map(|(index, did)| {
                            let data = if fault == "inventory_star_head" {
                                [9; 32]
                            } else {
                                repo_data
                            };
                            (
                                did,
                                REV.to_owned(),
                                format!("3jzfcijpj{index:04}a"),
                                data,
                            )
                        })
                        .collect();
                    let mut inventory_hash = LtHash::empty();
                    for (did, repo_rev, space_rev, data) in &logical_rows {
                        inventory_hash
                            .add_inventory_entry(did, repo_rev, space_rev, data)
                            .unwrap();
                    }
                    let inventory_data = inventory_hash.commitment();
                    let second_page = params.contains_key("cursor");
                    let mut served_rows: Vec<_> = if many || cycle {
                        if second_page {
                            if cycle {
                                logical_rows[100..101].to_vec()
                            } else {
                                logical_rows[100..].to_vec()
                            }
                        } else {
                            logical_rows[..100].to_vec()
                        }
                    } else {
                        logical_rows.clone()
                    };
                    if matches!(fault, "inventory_truncated" | "inventory_omitted") {
                        served_rows.truncate(1);
                    } else if fault == "inventory_reordered" {
                        served_rows.reverse();
                    } else if fault == "inventory_duplicate" {
                        served_rows[1] = served_rows[0].clone();
                    }
                    let nonterminal = (many || cycle) && (!second_page || cycle);
                    let cursor = nonterminal.then_some("inventory-page-100");
                    let mut commit_data = inventory_data;
                    if fault == "inventory_changed_commit" && second_page {
                        commit_data[0] ^= 1;
                    }
                    let commit_repo = if fault == "inventory_wrong_authority" {
                        "did:web:wrong-authority.example"
                    } else {
                        AUTHORITY
                    };
                    let commit = json!({
                        "space": space.raw,
                        "repo": commit_repo,
                        "rev": REV,
                        "ver": 1,
                        "data": {"$bytes": STANDARD.encode(commit_data)}
                    });
                    let repos: Vec<Value> = served_rows
                        .into_iter()
                        .map(|(did, repo_rev, space_rev, data)| {
                            json!({
                                "$type": "com.atproto.space.defs#repoWrite",
                                "repo": did,
                                "repoRev": repo_rev,
                                "spaceRev": space_rev,
                                "data": {"$bytes": STANDARD.encode(data)}
                            })
                        })
                        .collect();
                    let mut body = json!({
                        "repos": repos,
                        "complete": !nonterminal,
                        "commit": commit
                    });
                    if let Some(cursor) = cursor {
                        body["cursor"] = cursor.into();
                    }
                    if fault == "inventory_truncated" {
                        body["complete"] = false.into();
                        body.as_object_mut().unwrap().remove("cursor");
                    }
                    let (mut mac_headers, _) = sign_commit_mac(
                        &secret,
                        &share,
                        &label,
                        &space.raw,
                        commit_repo,
                        REV,
                        &commit_data,
                    )
                    .unwrap();
                    if fault == "inventory_bad_mac" {
                        mac_headers.signature = format!("{label}=:{}:", STANDARD.encode([0u8; 32]));
                    }
                    let mut output = response(body);
                    if fault != "inventory_missing_mac" {
                        push_mac_headers(&mut output, mac_headers);
                    }
                    return Ok(output);
                }
                if read_nsid == LIST_RECORDS {
                    if fault == "listed_omitted_after_inventory" {
                        return Ok(response(json!({"records": []})));
                    }
                    let listed_value = if fault == "listed_value" {
                        json!({"ciphertext": "forged"})
                    } else {
                        value
                    };
                    return Ok(response(json!({"records": [{
                        "collection": if fault == "listed_collection" { "blue.catbird.labyrinth.other" } else { COLLECTION },
                        "rkey": "batch-1",
                        "cid": if fault == "listed_cid" { compute_dagcbor_cid(b"other").to_string() } else { cid.to_string() },
                        "value": listed_value,
                    }]})));
                }
                let profile = if read_nsid == GET_RECORD {
                    MacProfile::Record
                } else {
                    MacProfile::Commit
                };
                let (label, client_share) = parse_accept_signature(&accept_sig, profile).unwrap();
                let (share, secret) = if fault == "keyshare_swap" {
                    let enc = encapsulate_p256_deterministic(
                        &encode_p256_did_key(&self.kem.public_key()),
                        &P256SecretKey::from_slice(&[99; 32]).unwrap(),
                    )
                    .unwrap();
                    assert_ne!(enc.key_share_did_key, client_share);
                    (enc.key_share_did_key, enc.shared_secret)
                } else {
                    let secret = decapsulate_p256(&self.kem, &client_share).unwrap();
                    (client_share, secret)
                };
                let mut output = if read_nsid == GET_RECORD {
                    let rkey = params.get("rkey").map(String::as_str).unwrap_or("batch-1");
                    let (rec_val, rec_cid) = if rkey == "batch-0" {
                        (batch0_value, batch0_cid)
                    } else {
                        (value, cid)
                    };
                    let uri = space.record_uri(writer, COLLECTION, rkey).unwrap();
                    let cid_str = rec_cid.to_string();
                    let (mut mac_headers, _) =
                        sign_record_mac(&secret, &share, &label, &uri, &cid_str).unwrap();
                    if fault == "bad_mac" {
                        mac_headers.signature = format!("{label}=:{}:", STANDARD.encode([0u8; 32]));
                    } else if fault == "capture_mac" {
                        *self.replayed_mac.lock().unwrap() = Some(mac_headers.clone());
                    } else if fault == "replay_mac" {
                        mac_headers = self.replayed_mac.lock().unwrap().clone().unwrap();
                    }
                    let mut output = response(json!({
                        "uri": if fault == "wrong_uri" { format!("{uri}x") } else { uri },
                        "cid": cid_str,
                        "value": if fault == "record_value" { json!({"ciphertext": "forged"}) } else { rec_val },
                    }));
                    push_mac_headers(&mut output, mac_headers);
                    output
                } else {
                    let mut hash = LtHash::empty();
                    if fault.starts_with("ops_compacted") {
                        hash.add_record(COLLECTION, "batch-0", &batch0_cid);
                    }
                    if !(read_nsid == "com.atproto.space.getRepo"
                        && fault == "ops_empty_star_head_mismatch")
                    {
                        hash.add_record(COLLECTION, "batch-1", &cid);
                    } else {
                        hash.add_record(COLLECTION, "batch-0", &batch0_cid);
                    }
                    let data = hash.commitment();
                    let (mut mac_headers, _) = sign_commit_mac(
                        &secret,
                        &share,
                        &label,
                        &space.raw,
                        writer,
                        REV,
                        &data,
                    )
                    .unwrap();
                    if fault == "bad_mac" {
                        mac_headers.signature = format!("{label}=:{}:", STANDARD.encode([0u8; 32]));
                    } else if fault == "capture_mac" {
                        *self.replayed_mac.lock().unwrap() = Some(mac_headers.clone());
                    } else if fault == "replay_mac" {
                        mac_headers = self.replayed_mac.lock().unwrap().clone().unwrap();
                    }
                    let commit = json!({"space": space.raw, "repo": writer, "rev": REV, "ver": 1, "data": {"$bytes": STANDARD.encode(data)}});
                    let mut output = if read_nsid == LIST_OPS {
                        let ops = if fault.starts_with("ops_empty") {
                            json!([])
                        } else {
                            let claimed_cid = if fault == "ops_compacted_final_cid_mismatch" {
                                batch0_cid
                            } else {
                                cid
                            };
                            let mut op = json!({
                                "collection": COLLECTION,
                                "rkey": "batch-1",
                                "cid": claimed_cid.to_string(),
                                "rev": REV
                            });
                            if fault.starts_with("ops_compacted") {
                                let prior_cid = compute_dagcbor_cid(&value_bytes(
                                    &json!({"superseded": true}),
                                ));
                                op["prev"] = prior_cid.to_string().into();
                            }
                            if params.get("excludeValues").map(String::as_str) != Some("true") {
                                op["value"] = if fault == "op_value" {
                                    json!({"ciphertext": "forged"})
                                } else if fault == "ops_compacted_final_cid_mismatch" {
                                    batch0_value
                                } else {
                                    value
                                };
                            }
                            json!([op])
                        };
                        response(json!({"commit": commit, "ops": ops}))
                    } else {
                        assert_eq!(read_nsid, "com.atproto.space.getRepo");
                        let entries = if fault == "ops_empty_star_head_mismatch" {
                            vec![StarRecordEntry {
                                path: format!("{COLLECTION}/batch-0"),
                                record_dagcbor: batch0_bytes,
                            }]
                        } else if fault.starts_with("ops_compacted") {
                            vec![
                                StarRecordEntry {
                                    path: format!("{COLLECTION}/batch-0"),
                                    record_dagcbor: batch0_bytes,
                                },
                                StarRecordEntry {
                                    path: format!("{COLLECTION}/batch-1"),
                                    record_dagcbor: bytes,
                                },
                            ]
                        } else {
                            let record =
                                if matches!(fault, "star_value" | "ops_empty_star_tampered") {
                                    value_bytes(&json!({"ciphertext": "forged"}))
                                } else {
                                    bytes
                                };
                            vec![StarRecordEntry {
                                path: format!("{COLLECTION}/batch-1"),
                                record_dagcbor: record,
                            }]
                        };
                        PlatformHttpResponse {
                            status: 200,
                            headers: vec![],
                            body: write_star_repo(&space.raw, writer, REV, &data, &entries)
                                .unwrap(),
                        }
                    };
                    push_mac_headers(&mut output, mac_headers);
                    output
                };
                if fault == "missing_mac" {
                    output.headers.clear();
                }
                Ok(output)
            }
            fn connect_realtime_stream(
                &self,
                _: String,
                _: Option<i64>,
            ) -> Result<(), crate::MLSError> {
                Ok(())
            }
            fn disconnect_realtime_stream(&self) -> Result<(), crate::MLSError> {
                Ok(())
            }
        }

        fn gateway() -> (tempfile::TempDir, NativeArchiveGateway, Arc<Host>) {
            let directory = tempfile::tempdir().unwrap();
            let db = Arc::new(
                MlsAccountDb::open_native(
                    directory.path().join("space.db"),
                    &[7; 32],
                    OpenMode::App,
                )
                .unwrap(),
            );
            let hooks = SimClientHooks::new(
                Arc::new(FixedStepClock::new((NOW * 1000) as i64, 0)),
                Arc::new(ChaChaSimEntropy::from_seed(41, b"native-space-auth")),
            );
            let signer = hooks
                .signature_keypair(openmls_traits::types::SignatureScheme::ED25519)
                .unwrap();
            let host = Arc::new(Host {
                signing: P256SecretKey::from_slice(&[1; 32]).unwrap(),
                kem: P256SecretKey::from_slice(&[2; 32]).unwrap(),
                fault: Mutex::new(""),
                requests: Mutex::new(vec![]),
                replayed_mac: Mutex::new(None),
            });
            let gateway = NativeArchiveGateway {
                config: CatbirdMlsClientConfig {
                    storage_root: directory.path().display().to_string(),
                    account_did: ACCOUNT.into(),
                    device_id: "11111111-1111-4111-8111-111111111111".into(),
                    home_ds_did: "did:web:home.example".into(),
                    home_ds_endpoint: "https://home.example".into(),
                    pds_endpoint: "https://account-pds.example".into(),
                },
                db,
                transport: host.clone(),
                signer: Arc::new(NativeArchiveSigner(signer)),
                hooks,
                verified_inventories: Mutex::new(BTreeMap::new()),
                credential_failures: Mutex::new(BTreeMap::new()),
            };
            (directory, gateway, host)
        }

        fn space(personal: bool) -> SpaceUri {
            if personal {
                SpaceUri::new(ACCOUNT, "blue.catbird.labyrinth.mailbox", "self").unwrap()
            } else {
                SpaceUri::new(
                    AUTHORITY,
                    "blue.catbird.labyrinth.conversation",
                    "conversation-0",
                )
                .unwrap()
            }
        }

        fn request(nsid: &str, personal: bool) -> LabyrinthSpaceRequest {
            let space = space(personal);
            let mut params = BTreeMap::from([("space".into(), space.raw)]);
            if nsid != LIST_WRITERS {
                params.insert(
                    "repo".into(),
                    if personal {
                        ACCOUNT.into()
                    } else {
                        WRITER.into()
                    },
                );
            }
            if matches!(nsid, GET_RECORD | LIST_RECORDS) {
                params.insert("collection".into(), COLLECTION.into());
            }
            if nsid == GET_RECORD {
                params.insert("rkey".into(), "batch-1".into());
            }
            LabyrinthSpaceRequest::get(nsid, query_path(nsid, &params))
        }

        #[test]
        fn native_space_get_blob_sends_the_lexicon_repo_parameter() {
            use labyrinth::store::space::SpaceRpc as _;
            use sha2::{Digest as _, Sha256};
            let cid = multibase::encode(
                multibase::Base::Base32Lower,
                [&[1, 0x55, 0x12, 0x20][..], &Sha256::digest(BLOB)[..]].concat(),
            );
            for personal in [true, false] {
                let (_directory, gateway, host) = gateway();
                let (space, writer) = (space(personal), if personal { ACCOUNT } else { WRITER });
                let transport = crate::labyrinth::SpaceXrpcTransport::new(Arc::new(gateway));
                assert_eq!(
                    block_on_sync(transport.get_blob(&space.raw, writer, &cid)).unwrap(),
                    BLOB
                );
                let query = host
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .find_map(|r| match r.url.split_once("/xrpc/com.atproto.space.getBlob?") {
                        Some((_, query)) => Some(query.to_owned()),
                        None if r.url.ends_with("/xrpc/blue.catbird.chat.relaySpaceRead") => {
                            let body: Value =
                                serde_json::from_slice(r.body.as_deref().unwrap()).unwrap();
                            (body["nsid"] == "com.atproto.space.getBlob")
                                .then(|| body["query"].as_str().unwrap().to_owned())
                        }
                        None => None,
                    })
                    .expect("getBlob reached the writer's PDS");
                let sent = parse_query(&LabyrinthSpaceRequest::get(
                    "com.atproto.space.getBlob",
                    format!("/xrpc/com.atproto.space.getBlob?{query}"),
                ))
                .unwrap();
                assert_eq!(
                    sent,
                    BTreeMap::from([
                        ("space".into(), space.raw.clone()),
                        ("repo".into(), writer.into()),
                        ("cid".into(), cid.clone()),
                    ]),
                    "personal {personal}: the lexicon's exact params"
                );
            }
        }

        #[test]
        fn native_space_auth_preserves_oauth_writes_and_scopes_deterministic_read_secrets() {
            let (_a, first, first_host) = gateway();
            let (_b, second, second_host) = gateway();
            for gateway in [&first, &second] {
                for personal in [true, false] {
                    let response = block_on_sync(
                        gateway.execute_authenticated_space(request(GET_RECORD, personal)),
                    )
                    .unwrap();
                    assert_eq!(response.status, 200);
                    if !personal {
                        block_on_sync(
                            gateway.execute_authenticated_space(request(LIST_WRITERS, false)),
                        )
                        .unwrap();
                    }
                    let response = block_on_sync(
                        gateway.execute_authenticated_space(request(LIST_RECORDS, personal)),
                    )
                    .unwrap();
                    let listed: Value = serde_json::from_slice(&response.body).unwrap();
                    assert_eq!(listed["records"][0]["rkey"], "batch-1");
                }
                let mut write = LabyrinthSpaceRequest::post_json(
                    "com.atproto.space.applyWrites",
                    br#"{"writes":[]}"#.to_vec(),
                );
                write
                    .headers
                    .push(("x-oauth-transport-test".into(), "preserved".into()));
                block_on_sync(gateway.execute_authenticated_space(write)).unwrap();
            }
            let first_requests = first_host.requests.lock().unwrap();
            assert_eq!(
                *first_requests,
                *second_host.requests.lock().unwrap(),
                "same hook seed must reproduce the complete HTTP transcript"
            );
            assert!(
                first_requests.iter().all(|r| {
                    r.url.starts_with("https://account-pds.example/")
                        || r.url.starts_with("https://home.example/")
                        || r.url.starts_with("https://plc.directory/")
                }),
                "D1 forbids direct foreign DS requests"
            );
            let shares: Vec<_> = first_requests
                .iter()
                .filter_map(|r| {
                    if r.url.ends_with("/xrpc/blue.catbird.chat.relaySpaceRead") {
                        let body: Value =
                            serde_json::from_slice(r.body.as_deref().unwrap()).unwrap();
                        Some(body["acceptSignature"].as_str().unwrap().to_owned())
                    } else {
                        r.headers
                            .iter()
                            .find(|h| h.name == ACCEPT_SIGNATURE_HEADER)
                            .map(|h| h.value.clone())
                    }
                })
                .collect();
            assert_eq!(
                shares.len(),
                shares.iter().collect::<BTreeSet<_>>().len(),
                "every writer read gets a fresh KEM share"
            );
        }

        #[test]
        fn writer_inventory_pages_past_one_hundred_only_release_after_head_reconciliation() {
            let (_directory, gateway, host) = gateway();
            *host.fault.lock().unwrap() = "inventory_101";
            let response = block_on_sync(
                gateway.execute_authenticated_space(request(LIST_WRITERS, false)),
            )
            .unwrap();
            let inventory: InventoryPage = serde_json::from_slice(&response.body).unwrap();
            assert!(inventory.complete);
            assert!(inventory.cursor.is_none());
            assert_eq!(inventory.repos.len(), 101);
            assert!(inventory
                .repos
                .windows(2)
                .all(|pair| pair[0].repo_did() < pair[1].repo_did()));

            let requests = host.requests.lock().unwrap();
            let relay_bodies: Vec<Value> = requests
                .iter()
                .filter(|request| {
                    request
                        .url
                        .ends_with("/xrpc/blue.catbird.chat.relaySpaceRead")
                })
                .map(|request| serde_json::from_slice(request.body.as_deref().unwrap()).unwrap())
                .collect();
            assert!(relay_bodies.iter().any(|body| {
                body["nsid"] == LIST_WRITERS
                    && body["query"]
                        .as_str()
                        .is_some_and(|query| query.contains("cursor=inventory-page-100"))
            }));
            let last = inventory.repos[100].repo_did();
            assert!(relay_bodies
                .iter()
                .any(|body| { body["nsid"] == GET_REPO && body["targetDid"].as_str() == Some(last) }));
            assert!(relay_bodies
                .iter()
                .any(|body| { body["nsid"] == LIST_OPS && body["targetDid"].as_str() == Some(last) }));
        }

        #[test]
        fn conversation_records_are_released_from_the_authenticated_star_snapshot() {
            let (_directory, gateway, host) = gateway();
            block_on_sync(gateway.execute_authenticated_space(request(LIST_WRITERS, false)))
                .unwrap();

            for fault in [
                "listed_omitted_after_inventory",
                "listed_value",
                "listed_cid",
                "listed_collection",
            ] {
                *host.fault.lock().unwrap() = fault;
                let listed = block_on_sync(
                    gateway.execute_authenticated_space(request(LIST_RECORDS, false)),
                )
                .unwrap();
                let listed: Value = serde_json::from_slice(&listed.body).unwrap();
                assert_eq!(listed["records"].as_array().unwrap().len(), 1);
                assert_eq!(listed["records"][0]["rkey"], "batch-1");
            }

            *host.fault.lock().unwrap() = "record_changed_after_inventory";
            let record =
                block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, false)))
                    .unwrap();
            let record: Value = serde_json::from_slice(&record.body).unwrap();
            assert_eq!(record["value"]["createdAt"], "2026-11-03T00:00:00.000Z");

            let mut absent = request(GET_RECORD, false);
            absent.path = absent.path.replace("rkey=batch-1", "rkey=missing");
            let absent = block_on_sync(gateway.execute_authenticated_space(absent)).unwrap();
            assert_eq!(absent.status, 404);
            let absent: Value = serde_json::from_slice(&absent.body).unwrap();
            assert_eq!(absent["error"], "RecordNotFound");
        }

        #[test]
        fn conversation_listing_verifies_the_inventory_first_and_an_omitted_writer_lists_nothing() {
            let (_directory, gateway, host) = gateway();
            let listed =
                block_on_sync(gateway.execute_authenticated_space(request(LIST_RECORDS, false)))
                    .unwrap();
            let listed: Value = serde_json::from_slice(&listed.body).unwrap();
            assert_eq!(listed["records"][0]["rkey"], "batch-1");
            assert!(host.requests.lock().unwrap().iter().any(|r| {
                r.url.ends_with("/xrpc/blue.catbird.chat.relaySpaceRead")
                    && serde_json::from_slice::<Value>(r.body.as_deref().unwrap()).unwrap()["nsid"]
                        == LIST_WRITERS
            }));
            let own = LabyrinthSpaceRequest::get(
                LIST_RECORDS,
                query_path(
                    LIST_RECORDS,
                    &BTreeMap::from([
                        ("space".into(), space(false).raw),
                        ("repo".into(), ACCOUNT.into()),
                        ("collection".into(), COLLECTION.into()),
                    ]),
                ),
            );
            let own = block_on_sync(gateway.execute_authenticated_space(own)).unwrap();
            let own: Value = serde_json::from_slice(&own.body).unwrap();
            assert_eq!(own["records"], json!([]));
        }

        #[test]
        fn writer_inventory_rejects_every_incomplete_or_inconsistent_snapshot_shape() {
            for (fault, expected) in [
                ("inventory_truncated", "inventory_terminal_cursor_mismatch"),
                ("inventory_omitted", "inventory_commitment_mismatch"),
                ("inventory_reordered", "inventory_not_strictly_ordered"),
                ("inventory_duplicate", "inventory_not_strictly_ordered"),
                ("inventory_changed_commit", "inventory_commit_changed"),
                ("inventory_bad_mac", "native_space_commit_mac"),
                ("inventory_missing_mac", "native_space_missing_response_mac"),
                (
                    "inventory_wrong_authority",
                    "native_space_commit_binding_mismatch",
                ),
                ("inventory_cursor_cycle", "inventory_cursor_cycle"),
                (
                    "inventory_snapshot_changed",
                    "listWriters inventory: HTTP 409 SnapshotChanged",
                ),
                ("inventory_star_head", "inventory_star_head_mismatch"),
            ] {
                let (_directory, gateway, host) = gateway();
                *host.fault.lock().unwrap() = fault;
                let error = block_on_sync(
                    gateway.execute_authenticated_space(request(LIST_WRITERS, false)),
                )
                .unwrap_err();
                assert!(
                    error.starts_with("ArchiveInventoryIncomplete:")
                        && error.contains(expected),
                    "{fault}: {error}"
                );
            }
        }

        #[test]
        fn native_space_auth_rejects_unbound_credentials_and_unsigned_or_mismatched_records() {
            for (fault, expected, nsid) in [
                (
                    "wrong_key",
                    "native_space_credential_binding_mismatch",
                    GET_RECORD,
                ),
                (
                    "wrong_space",
                    "native_space_credential_binding_mismatch",
                    GET_RECORD,
                ),
                ("expired", "native_space_credential_expired", GET_RECORD),
                (
                    "bad_signature",
                    "native_space_invalid_credential",
                    GET_RECORD,
                ),
                (
                    "missing_mac",
                    "native_space_missing_response_mac",
                    GET_RECORD,
                ),
                ("bad_mac", "native_space_record_mac", GET_RECORD),
                ("wrong_uri", "native_space_record_uri_mismatch", GET_RECORD),
                (
                    "record_value",
                    "native_space_record_value_cid_mismatch",
                    GET_RECORD,
                ),
            ] {
                let (_directory, gateway, host) = gateway();
                *host.fault.lock().unwrap() = fault;
                let error =
                    block_on_sync(gateway.execute_authenticated_space(request(nsid, false)))
                        .unwrap_err();
                assert!(error.starts_with(expected), "{fault}: {error}");
            }
        }

        #[test]
        fn native_space_auth_does_not_treat_an_auth_failure_as_membership_denial() {
            let (_directory, gateway, host) = gateway();
            *host.fault.lock().unwrap() = "credential_auth_failed";
            let error =
                block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, false)))
                    .unwrap_err();
            assert!(
                error.starts_with("native_space_authorizeSpaceSync: HTTP 401"),
                "{error}"
            );
        }

        fn count_requests(host: &Host, nsid: &str) -> usize {
            host.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.url.contains(&format!("/xrpc/{nsid}")))
                .count()
        }

        #[test]
        fn native_space_auth_replays_a_recent_credential_refusal_instead_of_asking_again() {
            let (_directory, gateway, host) = gateway();
            *host.fault.lock().unwrap() = "delegation_invalid_request";
            let first =
                block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, false)))
                    .unwrap_err();
            assert_eq!(
                first, "native_space_getDelegationToken: HTTP 400 InvalidRequest",
                "{first}"
            );
            for _ in 0..5 {
                let again =
                    block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, false)))
                        .unwrap_err();
                assert_eq!(again, first);
            }
            assert_eq!(
                count_requests(&host, "com.atproto.space.getDelegationToken"),
                1,
                "a refused exchange must not be retried inside the backoff window"
            );

            // Once the window passes, the next read asks the server again.
            for (retry_at, _) in gateway.credential_failures.lock().unwrap().values_mut() {
                *retry_at = NOW;
            }
            *host.fault.lock().unwrap() = "";
            block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, false))).unwrap();
            assert_eq!(
                count_requests(&host, "com.atproto.space.getDelegationToken"),
                2
            );
            assert!(gateway.credential_failures.lock().unwrap().is_empty());
        }

        #[test]
        fn native_space_auth_backoff_is_per_space_and_exchange_kind() {
            let (_directory, gateway, host) = gateway();
            *host.fault.lock().unwrap() = "delegation_invalid_request";
            block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, false)))
                .unwrap_err();
            // The personal mailbox exchange is a different key and still asks the server.
            block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, true)))
                .unwrap_err();
            assert_eq!(
                count_requests(&host, "com.atproto.space.getDelegationToken"),
                2
            );
        }

        #[test]
        fn native_space_auth_does_not_remember_an_auth_failure() {
            // A 401 can clear once the platform refreshes its session, so it is retried at once.
            let (_directory, gateway, host) = gateway();
            *host.fault.lock().unwrap() = "credential_auth_failed";
            for _ in 0..2 {
                block_on_sync(gateway.execute_authenticated_space(request(GET_RECORD, false)))
                    .unwrap_err();
            }
            assert_eq!(
                count_requests(&host, "blue.catbird.chat.relaySpaceCredential"),
                2
            );
            assert!(gateway.credential_failures.lock().unwrap().is_empty());
        }

        fn pin_group(gateway: &NativeArchiveGateway, group: [u8; 32]) {
            let pins = json!({"conversation": {"space": space(false).raw, "generation": 0, "groupId": hex::encode(group)}});
            let key = format!(
                "native.placements:{}",
                crate::labyrinth::space::thread_placement_key(ACCOUNT)
            );
            gateway
                .db
                .write_tx(|tx| tx.put_labyrinth_state(&key, &serde_json::to_vec(&pins).unwrap(), 0))
                .unwrap();
        }

        fn restore_outcome(gateway: NativeArchiveGateway) -> Result<(), crate::MLSError> {
            let transport = crate::labyrinth::SpaceXrpcTransport::new(Arc::new(gateway));
            match block_on_sync(transport.get_record(
                &space(false).raw,
                WRITER,
                COLLECTION,
                "batch-1",
            ))
            .unwrap_err()
            {
                labyrinth::store::space::SpaceError {
                    status: 403, error, ..
                } => {
                    let refusal = labyrinth::store::space::SpaceError {
                        status: 403,
                        error,
                        message: None,
                    };
                    assert_eq!(
                        labyrinth::store::space::map_space_error(refusal),
                        labyrinth::Error::Forbidden
                    );
                    Ok(())
                }
                refused => Err(super::super::native_archive_error(
                    crate::labyrinth::map_error(labyrinth::store::space::map_space_error(refused)),
                )),
            }
        }

        #[test]
        fn native_space_auth_accepts_only_the_authoritys_signed_refusal_as_space_denial() {
            let (_directory, personal, host) = gateway();
            *host.fault.lock().unwrap() = "credential_denied";
            let response =
                block_on_sync(personal.execute_authenticated_space(request(GET_RECORD, true)))
                    .unwrap();
            assert_eq!(response.status, 403);

            for home_ds_did in ["did:web:home.example", AUTHORITY] {
                let (_directory, mut accepted, host) = gateway();
                accepted.config.home_ds_did = home_ds_did.into();
                pin_group(&accepted, GROUP);
                *host.fault.lock().unwrap() = "denied:valid";
                let response = block_on_sync(
                    accepted.execute_authenticated_space(request(GET_RECORD, false)),
                )
                .unwrap();
                assert_eq!(response.status, 403, "{home_ds_did}");
                assert!(
                    host.requests
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|r| !r.url.ends_with("/xrpc/blue.catbird.chat.relaySpaceRead")),
                    "{home_ds_did}: no read follows a refused credential"
                );
                restore_outcome(accepted).expect("the authority's signed denial is Space denial");

                for fault in [
                    "credential_denied",
                    "denied:tampered_signature",
                    "denied:tampered_claims",
                    "denied:foreign_key",
                    "denied:replayed",
                    "denied:wrong_authority",
                    "denied:wrong_requester",
                    "denied:wrong_space",
                    "denied:wrong_conversation",
                    "denied:wrong_generation",
                    "denied:wrong_group",
                    "denied:expired",
                    "denied:long_lived",
                    "denied:future",
                    "denied:wrong_reason",
                    "denied:wrong_typ",
                    "denied:wrong_kid",
                    "denied:extra_claim",
                ] {
                    let (_directory, mut refused, host) = gateway();
                    refused.config.home_ds_did = home_ds_did.into();
                    pin_group(&refused, GROUP);
                    *host.fault.lock().unwrap() = fault;
                    let error = restore_outcome(refused).expect_err(fault);
                    assert!(
                        matches!(&error, crate::MLSError::InvalidState(code) if code == "ArchiveRestorePending"),
                        "{home_ds_did} {fault}: {error}"
                    );
                }
            }
            let (_directory, unpinned, host) = gateway();
            *host.fault.lock().unwrap() = "denied:valid";
            let error =
                block_on_sync(unpinned.execute_authenticated_space(request(GET_RECORD, false)))
                    .unwrap_err();
            assert!(
                error.starts_with(super::super::NATIVE_UNAUTHENTICATED_DENIAL),
                "{error}"
            );
        }

        #[test]
        fn native_space_read_refused_after_a_granted_credential_is_never_conversation_denial() {
            let (_directory, personal, host) = gateway();
            *host.fault.lock().unwrap() = "read_denied";
            let response =
                block_on_sync(personal.execute_authenticated_space(request(GET_RECORD, true)))
                    .unwrap();
            assert_eq!(response.status, 403);
            assert!(
                host.requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|r| r.url.contains("/xrpc/com.atproto.space.getRecord?")),
                "the read followed a granted credential"
            );
            for home_ds_did in ["did:web:home.example", AUTHORITY] {
                let (_directory, mut refused, host) = gateway();
                refused.config.home_ds_did = home_ds_did.into();
                *host.fault.lock().unwrap() = "read_denied";
                let error = restore_outcome(refused).expect_err(home_ds_did);
                assert!(
                    host.requests
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|r| r.url.ends_with("/xrpc/blue.catbird.chat.relaySpaceRead")),
                    "{home_ds_did}: the read followed a granted credential"
                );
                assert!(
                    matches!(&error, crate::MLSError::InvalidState(code) if code == "ArchiveRestorePending"),
                    "{home_ds_did}: {error}"
                );
            }
        }

        #[test]
        fn native_space_auth_verifies_nested_commit_and_binary_star_before_releasing_values() {
            for nsid in [LIST_OPS, "com.atproto.space.getRepo"] {
                let (_directory, gateway, host) = gateway();
                block_on_sync(gateway.execute_authenticated_space(request(nsid, false))).unwrap();
                *host.fault.lock().unwrap() = if nsid == LIST_OPS {
                    "op_value"
                } else {
                    "star_value"
                };
                let error =
                    block_on_sync(gateway.execute_authenticated_space(request(nsid, false)))
                        .unwrap_err();
                assert_eq!(
                    error,
                    if nsid == LIST_OPS {
                        "native_space_op_value_cid_mismatch"
                    } else {
                        "native_space_star_commitment_mismatch"
                    }
                );
            }
        }

        #[test]
        fn native_space_auth_releases_served_record_json_that_labyrinth_opens() {
            let served = serde_json::to_value(served_record()).unwrap();
            let (_directory, gateway, _host) = gateway();
            let released = |nsid: &str, personal: bool, pointer: &str| {
                if nsid == LIST_RECORDS && !personal {
                    block_on_sync(
                        gateway.execute_authenticated_space(request(LIST_WRITERS, false)),
                    )
                    .unwrap();
                }
                let response =
                    block_on_sync(gateway.execute_authenticated_space(request(nsid, personal)))
                        .unwrap();
                let body: Value = serde_json::from_slice(&response.body).unwrap();
                body.pointer(pointer).unwrap().clone()
            };
            for (nsid, personal, pointer) in [
                (GET_RECORD, true, "/value"),
                (GET_RECORD, false, "/value"),
                (LIST_RECORDS, true, "/records/0/value"),
                (LIST_RECORDS, false, "/records/0/value"),
                (LIST_OPS, false, "/ops/0/value"),
            ] {
                let value = released(nsid, personal, pointer);
                assert_eq!(
                    value, served,
                    "{nsid}: every string, including `$bytes`, is released unchanged"
                );
                assert_eq!(
                    serde_json::from_value::<labyrinth::records::Device>(value).unwrap(),
                    served_record(),
                    "{nsid}"
                );
            }
        }

        #[test]
        fn native_space_auth_rejects_accept_signature_keyshare_swap_and_pop_header_replay() {
            for (nsid, fault, expected) in [
                (GET_RECORD, "keyshare_swap", "native_space_record_mac"),
                (LIST_OPS, "keyshare_swap", "native_space_commit_mac"),
                (GET_REPO, "keyshare_swap", "native_space_star_mac"),
                (
                    LIST_WRITERS,
                    "keyshare_swap_inventory",
                    "native_space_commit_mac",
                ),
            ] {
                let (_directory, gateway, host) = gateway();
                *host.fault.lock().unwrap() = fault;
                let error =
                    block_on_sync(gateway.execute_authenticated_space(request(nsid, false)))
                        .unwrap_err();
                assert!(error.contains(expected), "{nsid} ({fault}): {error}");
            }

            for (nsid, expected) in [
                (GET_RECORD, "native_space_record_mac"),
                (LIST_OPS, "native_space_commit_mac"),
                (GET_REPO, "native_space_star_mac"),
            ] {
                let (_directory, gateway, host) = gateway();
                *host.fault.lock().unwrap() = "capture_mac";
                let ok_resp =
                    block_on_sync(gateway.execute_authenticated_space(request(nsid, true)))
                        .unwrap();
                assert_eq!(ok_resp.status, 200, "{nsid} initial capture");
                assert!(
                    host.replayed_mac.lock().unwrap().is_some(),
                    "{nsid} captured valid PoP MAC headers"
                );

                *host.fault.lock().unwrap() = "replay_mac";
                let error = block_on_sync(gateway.execute_authenticated_space(request(nsid, true)))
                    .unwrap_err();
                assert!(error.starts_with(expected), "{nsid} replay: {error}");
            }
        }

        #[test]
        fn native_space_auth_verifies_empty_and_compacted_oplogs_via_authenticated_star_fallback() {
            let served = serde_json::to_value(served_record()).unwrap();

            // Post-`importRepo`/`clearRecords`: `ops: []` + non-empty `LtHash` succeeds via verified STAR.
            {
                let (_directory, gateway, host) = gateway();
                *host.fault.lock().unwrap() = "ops_empty_after_import";
                let inv_resp =
                    block_on_sync(gateway.execute_authenticated_space(request(LIST_WRITERS, false)))
                        .unwrap();
                assert_eq!(inv_resp.status, 200);

                let ops_resp =
                    block_on_sync(gateway.execute_authenticated_space(request(LIST_OPS, false)))
                        .unwrap();
                assert_eq!(ops_resp.status, 200);
                let body: Value = serde_json::from_slice(&ops_resp.body).unwrap();
                assert_eq!(body["ops"], json!([]));
                assert_eq!(body["commit"]["rev"], REV);
            }

            // Retention-compacted oplog: retained op has `prev: Some(...)` and untouched pre-window
            // `batch-0` in `LtHash`; verified STAR reconciles commitment and releases inline value.
            {
                let (_directory, gateway, host) = gateway();
                *host.fault.lock().unwrap() = "ops_compacted";
                let inv_resp =
                    block_on_sync(gateway.execute_authenticated_space(request(LIST_WRITERS, false)))
                        .unwrap();
                assert_eq!(inv_resp.status, 200);

                let ops_resp =
                    block_on_sync(gateway.execute_authenticated_space(request(LIST_OPS, false)))
                        .unwrap();
                assert_eq!(ops_resp.status, 200);
                let body: Value = serde_json::from_slice(&ops_resp.body).unwrap();
                assert_eq!(body["ops"].as_array().unwrap().len(), 1);
                assert_eq!(body["ops"][0]["value"], served);
            }

            // Negative controls: tampered STAR CAR, mismatched STAR head commitment, or compacted
            // final CID disagreeing with STAR must all fail closed.
            for (fault, expected) in [
                (
                    "ops_empty_star_tampered",
                    "native_space_star_commitment_mismatch",
                ),
                (
                    "ops_empty_star_head_mismatch",
                    "native_space_oplog_commitment_mismatch",
                ),
                (
                    "ops_compacted_final_cid_mismatch",
                    "native_space_oplog_commitment_mismatch",
                ),
            ] {
                let (_directory, gateway, host) = gateway();
                *host.fault.lock().unwrap() = fault;
                let error =
                    block_on_sync(gateway.execute_authenticated_space(request(LIST_OPS, false)))
                        .unwrap_err();
                assert_eq!(error, expected, "{fault}");
            }
        }
    }
}

#[cfg(feature = "sim")]
pub fn convert_platform_space_response_for_sim(
    response: PlatformHttpResponse,
) -> crate::labyrinth::LabyrinthSpaceResponse {
    native_archive_space_auth::into_response(response)
}
