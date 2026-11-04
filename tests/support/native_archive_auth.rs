//! Account-bound, in-process PDS/Space host for native archive integration tests.
//! Fixed test-only DID keys and sequence JTIs keep complete HTTP transcripts reproducible.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use atproto_spaces::{
    http_signature::{verify_credential_request, SpaceRequestHeaders},
    kem::{decapsulate_p256, decode_p256_did_key, encode_p256_did_key, P256SecretKey},
    lthash::{compute_dagcbor_cid, LtHash},
    mac::{
        compute_commit_mac, compute_record_mac, format_commit_mac_header, format_record_mac_header,
        parse_want_mac_header, COMMIT_MAC_TYPE, RECORD_MAC_TYPE,
    },
    star::{validate_canonical_dagcbor_record, write_star_repo, StarRecordEntry},
    tokens::{
        mint_space_token, verify_space_token, SpaceKeyResolver, SpaceSigningKey, SpaceTokenClaims,
        SpaceTokenKind, SpaceVerifyingKey,
    },
    SpaceUri,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::{MLSError, PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type RecordKey = (String, String, String, String);

#[derive(Clone)]
struct Record {
    value: Value,
    dagcbor: Vec<u8>,
    cid: String,
}

#[derive(Default)]
struct World {
    records: BTreeMap<RecordKey, Record>,
    mailbox_keys: BTreeMap<(String, String), Record>,
    ops: BTreeMap<(String, String), Vec<Value>>,
    repo_revisions: BTreeMap<(String, String), String>,
    blobs: BTreeMap<(String, String), Vec<u8>>,
    spent_delegations: BTreeSet<String>,
    sequence: u64,
    committed_space_writes: usize,
}

impl World {
    fn next(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }
}

pub struct NativeArchiveAuthFixture {
    account: String,
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    world: Mutex<World>,
}

struct Keys;

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for Keys {
    async fn resolve_atproto_key(
        &self,
        issuer: &str,
        _: bool,
    ) -> atproto_spaces::Result<SpaceVerifyingKey> {
        let did = issuer.split('#').next().unwrap();
        if !atproto_spaces::is_valid_did(did) {
            return Err(atproto_spaces::SpacesError::InvalidDid(did.into()));
        }
        Ok(SpaceSigningKey::from_p256_secret(&key(did, b"sign"), "#atproto").verifying_key())
    }
}

impl NativeArchiveAuthFixture {
    pub fn new(account_did: impl Into<String>, now_ms: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            account: account_did.into(),
            now_ms,
            world: Mutex::new(World::default()),
        }
    }

    pub fn committed_space_write_count(&self) -> usize {
        self.world.lock().unwrap().committed_space_writes
    }

    pub fn execute(
        &self,
        request: &PlatformHttpRequest,
        raw: impl FnOnce(&PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError>,
    ) -> Result<PlatformHttpResponse, MLSError> {
        self.execute_for(&self.account, request, raw)
    }

    /// A shared mock server must call this with its per-client OAuth session DID.
    pub fn execute_for(
        &self,
        account: &str,
        request: &PlatformHttpRequest,
        raw: impl FnOnce(&PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError>,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let Some((_, target)) = request.url.split_once("/xrpc/") else {
            return raw(request);
        };
        let (nsid, query) = target.split_once('?').unwrap_or((target, ""));
        // Only the routes this host serves are parsed strictly; pass-through XRPC
        // keeps repeated array keys (`supportedProtocolVersions=1&...=2`).
        let served = nsid == "com.atproto.identity.resolveDid"
            || nsid.starts_with("com.atproto.repo.")
            || nsid.starts_with("com.atproto.space.")
            || matches!(
                nsid,
                "blue.catbird.chat.relaySpaceCredential" | "blue.catbird.chat.relaySpaceRead"
            );
        if !served {
            return raw(request);
        }
        let params = query_params(query)?;
        if nsid == "com.atproto.identity.resolveDid" {
            let did = required(&params, "did")?;
            let original = raw(request)?;
            let mut root = if original.status == 200 {
                parse(&original.body)?
            } else {
                json!({"id": did})
            };
            let document = if root.get("didDoc").is_some() {
                &mut root["didDoc"]
            } else {
                &mut root
            };
            if document["id"].as_str() != Some(did) {
                return Err(failure("DID document identity mismatch"));
            }
            self.augment_document(did, document, &request.url)?;
            return Ok(reply(200, root));
        }
        let mailbox_collection = labyrinth::records::nsid::MAILBOX_KEYS;
        if nsid.starts_with("com.atproto.repo.") && nsid != "com.atproto.repo.uploadBlob" {
            let body = request.body.as_deref().map(parse).transpose()?;
            let collection = body
                .as_ref()
                .and_then(|v| v["collection"].as_str())
                .or_else(|| params.get("collection").map(String::as_str));
            if collection != Some(mailbox_collection) {
                return raw(request);
            }
            return self.mailbox_keys(account, nsid, &params, body.as_ref());
        }
        if !(nsid.starts_with("com.atproto.space.")
            || nsid == "com.atproto.repo.uploadBlob"
            || matches!(
                nsid,
                "blue.catbird.chat.relaySpaceCredential" | "blue.catbird.chat.relaySpaceRead"
            ))
        {
            return raw(request);
        }
        let now = ((self.now_ms)().max(0) as u64) / 1000;
        match nsid {
            "com.atproto.space.getDelegationToken" => {
                let space = SpaceUri::parse(required(&params, "space")?).map_err(failure)?;
                let sequence = self.world.lock().unwrap().next();
                let claims = SpaceTokenClaims {
                    iss: account.into(),
                    sub: space.raw,
                    aud: Some(format!("{}#atproto_pds", space.authority)),
                    iat: now,
                    exp: now + 60,
                    jti: format!("delegation-{sequence}"),
                    cnf_kid: None,
                };
                let token = mint_space_token(
                    SpaceTokenKind::Delegation,
                    &SpaceSigningKey::from_p256_secret(&key(account, b"sign"), "#atproto"),
                    &claims,
                )
                .map_err(failure)?;
                Ok(reply(200, json!({"token": token})))
            }
            "com.atproto.space.getSpaceCredential" | "blue.catbird.chat.relaySpaceCredential" => {
                let body = parse(
                    request
                        .body
                        .as_deref()
                        .ok_or_else(|| failure("credential body missing"))?,
                )?;
                let space = SpaceUri::parse(text(&body, "space")?).map_err(failure)?;
                let relayed = nsid.starts_with("blue.");
                if relayed && text(&body, "authorityDid")? != space.authority {
                    return Err(failure("relay authority mismatch"));
                }
                let kid = text(&body, if relayed { "cnfKey" } else { "credentialKid" })?;
                decode_p256_did_key(kid).map_err(failure)?;
                let delegation = complete(verify_space_token(
                    SpaceTokenKind::Delegation,
                    text(&body, "delegationToken")?,
                    &Keys,
                    now,
                ))
                .map_err(failure)?;
                if delegation.iss != account || delegation.sub != space.raw || delegation.exp <= now
                {
                    return Err(failure("delegation account/Space/expiry mismatch"));
                }
                let mut world = self.world.lock().unwrap();
                if !world
                    .spent_delegations
                    .insert(format!("{}:{}", delegation.iss, delegation.jti))
                {
                    return Err(failure("delegation replay"));
                }
                let claims = SpaceTokenClaims {
                    iss: space.authority.clone(),
                    sub: space.raw,
                    aud: None,
                    iat: now,
                    exp: now + 600,
                    jti: format!("credential-{}", world.next()),
                    cnf_kid: Some(kid.into()),
                };
                let credential = mint_space_token(
                    SpaceTokenKind::Credential,
                    &SpaceSigningKey::from_p256_secret(&key(&space.authority, b"sign"), "#atproto"),
                    &claims,
                )
                .map_err(failure)?;
                let expires = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                    .unwrap()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                Ok(reply(
                    200,
                    json!({"credential": credential, "expiresAt": expires}),
                ))
            }
            "blue.catbird.chat.relaySpaceRead" => {
                let body = parse(
                    request
                        .body
                        .as_deref()
                        .ok_or_else(|| failure("read relay body missing"))?,
                )?;
                let nsid = text(&body, "nsid")?;
                let params = query_params(body["query"].as_str().unwrap_or(""))?;
                let audience = text(&body, "spaceAudience")?;
                if text(&body, "targetDid")? != audience {
                    return Err(failure("relay target/audience mismatch"));
                }
                let headers = SpaceRequestHeaders {
                    authorization: format!(
                        "Atproto-Space-Credential {}",
                        text(&body, "credential")?
                    ),
                    atproto_space_audience: audience.into(),
                    signature_input: text(&body, "signatureInput")?.into(),
                    signature: text(&body, "signature")?.into(),
                };
                self.read(
                    account,
                    nsid,
                    &params,
                    &headers,
                    body["wantMac"].as_str(),
                    now,
                )
            }
            "com.atproto.space.applyWrites" => self.apply(
                account,
                &parse(
                    request
                        .body
                        .as_deref()
                        .ok_or_else(|| failure("applyWrites body missing"))?,
                )?,
            ),
            "com.atproto.space.deleteRecord" => {
                let body = parse(
                    request
                        .body
                        .as_deref()
                        .ok_or_else(|| failure("deleteRecord body missing"))?,
                )?;
                let converted = json!({"space": body["space"], "repo": body["repo"], "writes": [{
                    "$type": "com.atproto.space.applyWrites#delete", "collection": body["collection"], "rkey": body["rkey"],
                }]});
                self.apply(account, &converted)
            }
            "com.atproto.repo.uploadBlob" => {
                let bytes = request
                    .body
                    .as_deref()
                    .ok_or_else(|| failure("blob bytes missing"))?;
                let mut cid = vec![1, 0x55, 0x12, 0x20];
                cid.extend_from_slice(&Sha256::digest(bytes));
                let cid = multibase::encode(multibase::Base::Base32Lower, cid);
                self.world
                    .lock()
                    .unwrap()
                    .blobs
                    .insert((account.into(), cid.clone()), bytes.to_vec());
                Ok(reply(
                    200,
                    json!({"blob": {"$type": "blob", "ref": {"$link": cid}, "mimeType": "application/octet-stream", "size": bytes.len()}}),
                ))
            }
            "com.atproto.space.listSpaces" => {
                let world = self.world.lock().unwrap();
                let spaces: BTreeSet<_> = world
                    .records
                    .keys()
                    .filter(|(_, repo, _, _)| repo == account)
                    .map(|(space, _, _, _)| space)
                    .collect();
                Ok(reply(
                    200,
                    json!({"spaces": spaces.into_iter().map(|uri| json!({"uri": uri})).collect::<Vec<_>>()}),
                ))
            }
            "com.atproto.space.getSpace" if !params.contains_key("space") => Ok(reply(
                400,
                json!({"error": "InvalidRequest", "message": "space required"}),
            )),
            _ if request.method == "GET" => {
                let headers = SpaceRequestHeaders {
                    authorization: request_header(request, "authorization")?.into(),
                    atproto_space_audience: request_header(request, "atproto-space-audience")?
                        .into(),
                    signature_input: request_header(request, "signature-input")?.into(),
                    signature: request_header(request, "signature")?.into(),
                };
                let want = optional_header(request, "atproto-space-want-mac")?;
                self.read(account, nsid, &params, &headers, want, now)
            }
            _ => Err(failure(format!(
                "unsupported native Space fixture endpoint: {nsid}"
            ))),
        }
    }

    fn augment_document(
        &self,
        did: &str,
        document: &mut Value,
        request_url: &str,
    ) -> Result<(), MLSError> {
        let methods = document
            .as_object_mut()
            .ok_or_else(|| failure("DID document not object"))?
            .entry("verificationMethod")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| failure("DID methods not array"))?;
        for (fragment, purpose) in [
            ("atproto", b"sign".as_slice()),
            ("atproto_kem", b"kem".as_slice()),
        ] {
            let id = format!("{did}#{fragment}");
            let public = encode_p256_did_key(&key(did, purpose).public_key());
            // Other fragments, including immutable receipt-key documents, stay intact.
            methods.retain(|method| {
                method["id"].as_str() != Some(&id)
                    && method["id"].as_str() != Some(&format!("#{fragment}"))
            });
            methods.push(json!({"id": id, "controller": did, "type": "Multikey", "publicKeyMultibase": public.strip_prefix("did:key:").unwrap()}));
        }
        let base = request_url.split_once("/xrpc/").unwrap().0;
        let services = document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| failure("DID services not array"))?;
        if !services.iter().any(|service| {
            service["id"]
                .as_str()
                .is_some_and(|id| id.ends_with("#atproto_pds"))
        }) {
            services.push(json!({"id": format!("{did}#atproto_pds"), "type": "AtprotoPersonalDataServer", "serviceEndpoint": base}));
        }
        Ok(())
    }

    fn mailbox_keys(
        &self,
        account: &str,
        nsid: &str,
        params: &BTreeMap<String, String>,
        body: Option<&Value>,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let repo = body
            .and_then(|v| v["repo"].as_str())
            .or_else(|| params.get("repo").map(String::as_str))
            .ok_or_else(|| failure("mailbox repo missing"))?;
        let rkey = body
            .and_then(|v| v["rkey"].as_str())
            .or_else(|| params.get("rkey").map(String::as_str));
        let mut world = self.world.lock().unwrap();
        match nsid {
            "com.atproto.repo.putRecord" => {
                if account != repo {
                    return Ok(reply(403, json!({"error": "NotAuthorized"})));
                }
                let body = body.unwrap();
                let rkey = rkey.ok_or_else(|| failure("mailbox rkey missing"))?;
                let current = world.mailbox_keys.get(&(repo.into(), rkey.into()));
                if body
                    .get("swapRecord")
                    .is_some_and(|swap| swap.as_str() != current.map(|record| record.cid.as_str()))
                {
                    return Ok(reply(400, json!({"error": "InvalidSwap"})));
                }
                let record = record(
                    body.get("record")
                        .ok_or_else(|| failure("mailbox record missing"))?,
                )?;
                let cid = record.cid.clone();
                world
                    .mailbox_keys
                    .insert((repo.into(), rkey.into()), record);
                Ok(reply(
                    200,
                    json!({"uri": format!("at://{repo}/{}/{rkey}", labyrinth::records::nsid::MAILBOX_KEYS), "cid": cid}),
                ))
            }
            "com.atproto.repo.getRecord" => {
                let rkey = rkey.ok_or_else(|| failure("mailbox rkey missing"))?;
                match world.mailbox_keys.get(&(repo.into(), rkey.into())) {
                    Some(record) => Ok(reply(
                        200,
                        json!({"uri": format!("at://{repo}/{}/{rkey}", labyrinth::records::nsid::MAILBOX_KEYS), "cid": record.cid, "value": record.value}),
                    )),
                    None => Ok(reply(404, json!({"error": "RecordNotFound"}))),
                }
            }
            "com.atproto.repo.listRecords" => {
                let cursor = params.get("cursor");
                let limit = limit(params, 100)?;
                let mut records: Vec<_> = world.mailbox_keys.iter().filter(|((owner, key), _)| owner == repo && cursor.is_none_or(|cursor| key > cursor)).map(|((_, key), record)| json!({
                    "uri": format!("at://{repo}/{}/{key}", labyrinth::records::nsid::MAILBOX_KEYS), "cid": record.cid, "value": record.value,
                })).collect();
                let more = records.len() > limit;
                records.truncate(limit);
                let next = more.then(|| {
                    records.last().unwrap()["uri"]
                        .as_str()
                        .unwrap()
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .to_owned()
                });
                Ok(reply(200, json!({"records": records, "cursor": next})))
            }
            "com.atproto.repo.deleteRecord" => {
                if account != repo {
                    return Ok(reply(403, json!({"error": "NotAuthorized"})));
                }
                let rkey = rkey.ok_or_else(|| failure("mailbox rkey missing"))?;
                let key = (repo.into(), rkey.into());
                if body
                    .and_then(|v| v["swapRecord"].as_str())
                    .is_some_and(|expected| {
                        world
                            .mailbox_keys
                            .get(&key)
                            .map(|record| record.cid.as_str())
                            != Some(expected)
                    })
                {
                    return Ok(reply(400, json!({"error": "InvalidSwap"})));
                }
                world.mailbox_keys.remove(&key);
                Ok(reply(200, json!({})))
            }
            _ => Err(failure(format!("unsupported mailbox endpoint: {nsid}"))),
        }
    }

    fn apply(&self, account: &str, body: &Value) -> Result<PlatformHttpResponse, MLSError> {
        let space = SpaceUri::parse(text(body, "space")?).map_err(failure)?;
        let repo = text(body, "repo")?;
        if repo != account {
            return Ok(reply(403, json!({"error": "NotAuthorized"})));
        }
        let writes = body["writes"]
            .as_array()
            .ok_or_else(|| failure("writes missing"))?;
        let mut world = self.world.lock().unwrap();
        let mut records = world.records.clone();
        let rev = tid(world.next());
        let mut results = Vec::with_capacity(writes.len());
        let mut ops = Vec::with_capacity(writes.len());
        for (index, write) in writes.iter().enumerate() {
            let collection = text(write, "collection")?;
            let rkey = write["rkey"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| tid(world.sequence + index as u64 + 1));
            let uri = space.record_uri(repo, collection, &rkey).map_err(failure)?;
            let key = (
                space.raw.clone(),
                repo.into(),
                collection.into(),
                rkey.clone(),
            );
            let current = records.get(&key);
            let previous = current.map(|record| record.cid.clone());
            if write
                .get("swapRecord")
                .is_some_and(|swap| swap.as_str() != current.map(|record| record.cid.as_str()))
            {
                return Ok(reply(400, json!({"error": "InvalidSwap"})));
            }
            let action = text(write, "$type")?.rsplit('#').next().unwrap();
            let cid = match action {
                "create" if current.is_some() => {
                    return Ok(reply(400, json!({"error": "RecordAlreadyExists"})))
                }
                "update" | "delete" if current.is_none() => {
                    return Ok(reply(400, json!({"error": "RecordNotFound"})))
                }
                "create" | "update" => {
                    let record = record(
                        write
                            .get("value")
                            .ok_or_else(|| failure("write value missing"))?,
                    )?;
                    let cid = record.cid.clone();
                    records.insert(key, record);
                    Some(cid)
                }
                "delete" => {
                    records.remove(&key);
                    None
                }
                _ => return Err(failure("unsupported Space write action")),
            };
            let mut result =
                json!({"$type": format!("com.atproto.space.applyWrites#{action}Result")});
            if let Some(cid) = &cid {
                result["uri"] = uri.into();
                result["cid"] = cid.clone().into();
            }
            results.push(result);
            ops.push(json!({"collection": collection, "rkey": rkey, "rev": rev, "cid": cid, "prev": previous}));
        }
        world.records = records;
        world.committed_space_writes += writes.len();
        world
            .repo_revisions
            .insert((space.raw.clone(), repo.into()), rev);
        world
            .ops
            .entry((space.raw, repo.into()))
            .or_default()
            .extend(ops);
        Ok(reply(200, json!({"results": results})))
    }

    fn read(
        &self,
        account: &str,
        nsid: &str,
        params: &BTreeMap<String, String>,
        headers: &SpaceRequestHeaders,
        want_mac: Option<&str>,
        now: u64,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let space = SpaceUri::parse(required(params, "space")?).map_err(failure)?;
        let authority_read = matches!(
            nsid,
            "com.atproto.space.getSpace" | "com.atproto.space.listRepos"
        );
        let writer = if authority_read {
            space.authority.as_str()
        } else {
            required(params, "repo")?
        };
        if headers.atproto_space_audience != writer {
            return Err(failure("Space audience mismatch"));
        }
        let jwt = headers
            .authorization
            .strip_prefix("Atproto-Space-Credential ")
            .ok_or_else(|| failure("Space credential missing"))?;
        let claims = complete(verify_space_token(
            SpaceTokenKind::Credential,
            jwt,
            &Keys,
            now,
        ))
        .map_err(failure)?;
        if claims.iss != space.authority || claims.sub != space.raw || claims.exp <= now {
            return Err(failure("Space credential binding mismatch"));
        }
        let proof = verify_credential_request(
            &headers.to_header_map().map_err(failure)?,
            claims
                .cnf_kid
                .as_deref()
                .ok_or_else(|| failure("credential cnf missing"))?,
            now,
        )
        .map_err(failure)?;
        if proof.credential_jwt != jwt || proof.audience_did != writer {
            return Err(failure("Space proof binding mismatch"));
        }
        if space.space_type == "blue.catbird.labyrinth.mailbox"
            && (space.authority != account || writer != account || space.rkey != "self")
        {
            return Ok(reply(403, json!({"error": "NotAuthorized"})));
        }
        let world = self.world.lock().unwrap();
        let entries: Vec<_> = world
            .records
            .iter()
            .filter(|((s, repo, _, _), _)| s == &space.raw && repo == writer)
            .collect();
        let rev = world
            .repo_revisions
            .get(&(space.raw.clone(), writer.into()))
            .cloned()
            .unwrap_or_else(|| tid(0));
        let commit = commitment(&entries)?;
        let commit_json = json!({"space": space.raw, "repo": writer, "ver": 1, "rev": rev, "data": {"$bytes": STANDARD.encode(commit)}});
        match nsid {
            "com.atproto.space.getRecord" => {
                let collection = required(params, "collection")?;
                let rkey = required(params, "rkey")?;
                let Some(record) = world.records.get(&(
                    space.raw.clone(),
                    writer.into(),
                    collection.into(),
                    rkey.into(),
                )) else {
                    return Ok(reply(404, json!({"error": "RecordNotFound"})));
                };
                let uri = space
                    .record_uri(writer, collection, rkey)
                    .map_err(failure)?;
                let secret = shared_secret(writer, want_mac, RECORD_MAC_TYPE)?;
                let (_, cid) = multibase::decode(&record.cid).map_err(failure)?;
                let mac = compute_record_mac(&secret, &uri, &cid).map_err(failure)?;
                Ok(with_mac(
                    reply(
                        200,
                        json!({"uri": uri, "cid": record.cid, "value": record.value}),
                    ),
                    format_record_mac_header(&mac),
                ))
            }
            "com.atproto.space.listRecords" => {
                let collection = params.get("collection");
                let reverse = params.get("reverse").map(String::as_str) == Some("true");
                let mut matching: Vec<_> = entries
                    .into_iter()
                    .filter(|((_, _, c, rkey), _)| {
                        let path = format!("{c}/{rkey}");
                        collection.is_none_or(|wanted| c == wanted)
                            && params.get("cursor").is_none_or(|cursor| {
                                if reverse {
                                    &path < cursor
                                } else {
                                    &path > cursor
                                }
                            })
                    })
                    .collect();
                if reverse {
                    matching.reverse();
                }
                let limit = limit(params, 50)?;
                let more = matching.len() > limit;
                matching.truncate(limit);
                let cursor = more.then(|| {
                    let ((_, _, c, rkey), _) = matching.last().unwrap();
                    format!("{c}/{rkey}")
                });
                let records: Vec<_> = matching
                    .into_iter()
                    .map(|((_, _, collection, rkey), record)| {
                        let mut item =
                            json!({"collection": collection, "rkey": rkey, "cid": record.cid});
                        if params.get("excludeValues").map(String::as_str) != Some("true") {
                            item["value"] = record.value.clone();
                        }
                        item
                    })
                    .collect();
                Ok(reply(200, json!({"records": records, "cursor": cursor})))
            }
            "com.atproto.space.listRepos" => {
                let dids: BTreeSet<_> = world
                    .records
                    .keys()
                    .filter(|(s, _, _, _)| s == &space.raw)
                    .map(|(_, did, _, _)| did)
                    .collect();
                let mut repos = Vec::new();
                for did in dids {
                    let records: Vec<_> = world
                        .records
                        .iter()
                        .filter(|((s, repo, _, _), _)| s == &space.raw && repo == did)
                        .collect();
                    let repo_rev = world
                        .repo_revisions
                        .get(&(space.raw.clone(), did.clone()))
                        .cloned()
                        .unwrap_or_else(|| tid(0));
                    repos.push(json!({"did": did, "repoRev": repo_rev, "spaceRev": repo_rev, "data": {"$bytes": STANDARD.encode(commitment(&records)?)}}));
                }
                Ok(reply(200, json!({"repos": repos})))
            }
            "com.atproto.space.getSpace" => Ok(reply(
                200,
                json!({"uri": space.raw, "policy": {"$type": "blue.catbird.labyrinth.conversationPolicy", "authority": space.authority}}),
            )),
            "com.atproto.space.getLatestCommit"
            | "com.atproto.space.getRepo"
            | "com.atproto.space.listRepoOps" => {
                let secret = shared_secret(writer, want_mac, COMMIT_MAC_TYPE)?;
                let mac = format_commit_mac_header(
                    &compute_commit_mac(&secret, &space.raw, writer, &rev, &commit)
                        .map_err(failure)?,
                );
                if nsid == "com.atproto.space.getRepo" {
                    let records: Vec<_> = entries
                        .into_iter()
                        .map(|((_, _, collection, rkey), record)| StarRecordEntry {
                            path: format!("{collection}/{rkey}"),
                            record_dagcbor: record.dagcbor.clone(),
                        })
                        .collect();
                    return Ok(with_mac(
                        PlatformHttpResponse {
                            status: 200,
                            headers: vec![PlatformHttpHeader {
                                name: "content-type".into(),
                                value: "application/vnd.atproto.star".into(),
                            }],
                            body: write_star_repo(&space.raw, writer, &rev, &commit, &records)
                                .map_err(failure)?,
                        },
                        mac,
                    ));
                }
                if nsid == "com.atproto.space.getLatestCommit" {
                    return Ok(with_mac(reply(200, json!({"commit": commit_json})), mac));
                }
                let mut ops = world
                    .ops
                    .get(&(space.raw.clone(), writer.into()))
                    .cloned()
                    .unwrap_or_default();
                ops.retain(|op| {
                    params
                        .get("since")
                        .is_none_or(|since| op["rev"].as_str().unwrap() > since.as_str())
                });
                let start = params
                    .get("cursor")
                    .map(|s| s.parse::<usize>())
                    .transpose()
                    .map_err(failure)?
                    .unwrap_or(0);
                let limit = limit(params, 100)?;
                let end = start.saturating_add(limit).min(ops.len());
                if start > end {
                    return Err(failure("oplog cursor out of range"));
                }
                let mut selected = ops[start..end].to_vec();
                if params.get("excludeValues").map(String::as_str) != Some("true") {
                    for op in &mut selected {
                        if let Some(record) = world.records.get(&(
                            space.raw.clone(),
                            writer.into(),
                            text(op, "collection")?.into(),
                            text(op, "rkey")?.into(),
                        )) {
                            if op["cid"].as_str() == Some(record.cid.as_str()) {
                                op["value"] = record.value.clone();
                            }
                        }
                    }
                }
                if end < ops.len() {
                    Ok(reply(
                        200,
                        json!({"ops": selected, "cursor": end.to_string()}),
                    ))
                } else {
                    Ok(with_mac(
                        reply(200, json!({"ops": selected, "commit": commit_json})),
                        mac,
                    ))
                }
            }
            "com.atproto.space.getBlob" => match world
                .blobs
                .get(&(writer.into(), required(params, "cid")?.into()))
            {
                Some(bytes) => Ok(PlatformHttpResponse {
                    status: 200,
                    headers: vec![],
                    body: bytes.clone(),
                }),
                None => Ok(reply(404, json!({"error": "BlobNotFound"}))),
            },
            _ => Err(failure(format!("unsupported Space read: {nsid}"))),
        }
    }
}

fn commitment(entries: &[(&RecordKey, &Record)]) -> Result<[u8; 32], MLSError> {
    let mut hash = LtHash::empty();
    for ((_, _, collection, rkey), record) in entries {
        let cid = record.cid.parse().map_err(failure)?;
        hash.add_record(collection, rkey, &cid);
    }
    Ok(hash.commitment())
}

fn record(value: &Value) -> Result<Record, MLSError> {
    let typed: catbird_atproto::types::value::Data =
        serde_json::from_value(value.clone()).map_err(failure)?;
    let dagcbor = serde_ipld_dagcbor::to_vec(&typed).map_err(failure)?;
    validate_canonical_dagcbor_record(&dagcbor).map_err(failure)?;
    // Served as written: jacquard re-renders `$bytes` padded, which is not atproto JSON.
    Ok(Record {
        value: value.clone(),
        cid: compute_dagcbor_cid(&dagcbor).to_string(),
        dagcbor,
    })
}

fn shared_secret(writer: &str, want: Option<&str>, kind: &str) -> Result<[u8; 32], MLSError> {
    let share = parse_want_mac_header(want.ok_or_else(|| failure("Want-Mac missing"))?, kind)
        .map_err(failure)?;
    decapsulate_p256(&key(writer, b"kem"), &share).map_err(failure)
}

fn key(did: &str, purpose: &[u8]) -> P256SecretKey {
    for attempt in 0u32..128 {
        let mut hash = Sha256::new();
        hash.update(b"catbird-native-archive-fixture-only\0");
        hash.update(purpose);
        hash.update(did.as_bytes());
        hash.update(attempt.to_be_bytes());
        if let Ok(secret) = P256SecretKey::from_slice(&hash.finalize()) {
            return secret;
        }
    }
    panic!("fixture key derivation exhausted");
}

fn tid(sequence: u64) -> String {
    const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let value = (1u64 << 62) | sequence;
    (0..13)
        .rev()
        .map(|i| ALPHABET[((value >> (5 * i)) & 31) as usize] as char)
        .collect()
}

fn limit(params: &BTreeMap<String, String>, default: usize) -> Result<usize, MLSError> {
    let limit = params
        .get("limit")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(failure)?
        .unwrap_or(default);
    if !(1..=1000).contains(&limit) {
        return Err(failure("invalid page limit"));
    }
    Ok(limit)
}

fn query_params(query: &str) -> Result<BTreeMap<String, String>, MLSError> {
    let mut params = BTreeMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| failure("invalid query pair"))?;
        let key = decode(key)?;
        if params.insert(key.clone(), decode(value)?).is_some() {
            return Err(failure(format!(
                "duplicate query parameter {key} in {query}"
            )));
        }
    }
    Ok(params)
}

fn decode(value: &str) -> Result<String, MLSError> {
    let mut bytes = value.bytes();
    let mut decoded = Vec::with_capacity(value.len());
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|b| (b as char).to_digit(16))
                    .ok_or_else(|| failure("bad percent encoding"))?;
                let low = bytes
                    .next()
                    .and_then(|b| (b as char).to_digit(16))
                    .ok_or_else(|| failure("bad percent encoding"))?;
                ((high << 4) | low) as u8
            }
            b'+' => b' ',
            _ => byte,
        });
    }
    String::from_utf8(decoded).map_err(failure)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, MLSError> {
    value[field]
        .as_str()
        .ok_or_else(|| failure(format!("missing {field}")))
}
fn required<'a>(params: &'a BTreeMap<String, String>, field: &str) -> Result<&'a str, MLSError> {
    params
        .get(field)
        .map(String::as_str)
        .ok_or_else(|| failure(format!("missing {field}")))
}
fn parse(bytes: &[u8]) -> Result<Value, MLSError> {
    serde_json::from_slice(bytes).map_err(failure)
}
fn failure(error: impl std::fmt::Display) -> MLSError {
    MLSError::Internal(format!("native archive test host: {error}"))
}
fn reply(status: u16, body: Value) -> PlatformHttpResponse {
    PlatformHttpResponse {
        status,
        headers: vec![PlatformHttpHeader {
            name: "content-type".into(),
            value: "application/json".into(),
        }],
        body: serde_json::to_vec(&body).unwrap(),
    }
}
fn with_mac(mut response: PlatformHttpResponse, value: String) -> PlatformHttpResponse {
    response.headers.push(PlatformHttpHeader {
        name: "atproto-space-mac".into(),
        value,
    });
    response
}
fn optional_header<'a>(
    request: &'a PlatformHttpRequest,
    name: &str,
) -> Result<Option<&'a str>, MLSError> {
    let mut values = request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name));
    let value = values.next().map(|h| h.value.as_str());
    if values.next().is_some() {
        return Err(failure(format!("duplicate {name}")));
    }
    Ok(value)
}
fn request_header<'a>(request: &'a PlatformHttpRequest, name: &str) -> Result<&'a str, MLSError> {
    optional_header(request, name)?.ok_or_else(|| failure(format!("missing {name}")))
}

fn complete<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture key resolver unexpectedly suspended"),
    }
}
