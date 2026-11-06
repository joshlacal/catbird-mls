//! Opt-in G5 faults against a real conversation Space through the production
//! `NativeArchiveGateway`. Set `LABYRINTH_G5_LIVE_FIXTURE` to run it.
//!
//! The fixture JSON supplies a copied, provisioned account storage root whose
//! conversation is active but local message history is empty; Keychain bytes;
//! account/DS/PDS coordinates; an OAuth authorization value; the conversation
//! ID; a loopback fault-controller URL; and exact `inventoryRecords` /
//! `expectedMessages` counts. The loopback proxy forwards to the real hosts
//! and implements the four mode strings used below.

#![cfg(all(feature = "labyrinth", not(target_arch = "wasm32")))]

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use catbird_mls::client::{
    CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpHeader, PlatformHttpRequest,
    PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
};
use catbird_mls::MLSError;
use serde::Deserialize;

const FIXTURE_ENV: &str = "LABYRINTH_G5_LIVE_FIXTURE";

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    account_did: String,
    device_id: String,
    home_ds_did: String,
    home_ds_endpoint: String,
    pds_endpoint: String,
    conversation_id: String,
    storage_root_template: PathBuf,
    database_key_base64: String,
    signer_keypair_base64: String,
    authorization: String,
    fault_control_url: String,
    expected_messages: usize,
    inventory_records: usize,
}

impl Fixture {
    fn load() -> Option<Self> {
        let path = match std::env::var(FIXTURE_ENV) {
            Ok(path) => path,
            Err(_) => {
                eprintln!("skipped G5 live faults: {FIXTURE_ENV} is not set");
                return None;
            }
        };
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("explicit G5 fixture {path:?} is unreadable: {error}"));
        let mut fixture: Self =
            serde_json::from_slice(&bytes).expect("explicit G5 fixture is invalid JSON");
        if fixture.storage_root_template.is_relative() {
            fixture.storage_root_template = Path::new(&path)
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&fixture.storage_root_template);
        }
        Some(fixture)
    }

    fn decode(&self, field: &str, value: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap_or_else(|error| panic!("G5 fixture {field} is not base64: {error}"))
    }
}

struct LiveKeys {
    database_key: Vec<u8>,
    signer: Vec<u8>,
    tokens: Mutex<HashMap<String, Vec<u8>>>,
}

impl PlatformKeyStore for LiveKeys {
    fn load_or_create_db_key(&self, _account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        Ok(self.database_key.clone())
    }

    fn load_signature_keypair(&self, _key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(Some(self.signer.clone()))
    }

    fn store_signature_keypair(&self, key_id: String, bytes: Vec<u8>) -> Result<(), MLSError> {
        self.tokens.lock().unwrap().insert(key_id, bytes);
        Ok(())
    }

    fn delete_account_keys(&self, _account_did_hash: String) -> Result<(), MLSError> {
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .get(&format!("dpop:{account_did_hash}"))
            .and_then(|value| String::from_utf8(value.clone()).ok()))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        _expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.tokens
            .lock()
            .unwrap()
            .insert(format!("dpop:{account_did_hash}"), token.into_bytes());
        Ok(())
    }
}

/// The live fixture is an HTTP loopback fault proxy in front of real DS/PDS/Space
/// hosts. TLS stays between that proxy and the hosts; keeping this client HTTP-only
/// prevents an accidental direct production run with fixture credentials.
struct LoopbackTransport {
    authorization: String,
}

impl PlatformTransport for LoopbackTransport {
    fn execute_http(
        &self,
        mut request: PlatformHttpRequest,
    ) -> Result<PlatformHttpResponse, MLSError> {
        if !request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("authorization"))
        {
            request.headers.push(PlatformHttpHeader {
                name: "authorization".into(),
                value: self.authorization.clone(),
            });
        }
        http(
            &request.method,
            &request.url,
            &request.headers,
            request.body.as_deref(),
        )
    }

    fn connect_realtime_stream(
        &self,
        _home_ds_endpoint: String,
        _cursor_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

fn split_http_url(url: &str) -> Result<(&str, &str), MLSError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        MLSError::Internal("G5 live fixture endpoints must be an HTTP loopback fault proxy".into())
    })?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if !(authority.starts_with("127.0.0.1:") || authority.starts_with("localhost:")) {
        return Err(MLSError::Internal(
            "G5 live fixture proxy must listen on loopback".into(),
        ));
    }
    Ok((authority, path))
}

fn http(
    method: &str,
    url: &str,
    headers: &[PlatformHttpHeader],
    body: Option<&[u8]>,
) -> Result<PlatformHttpResponse, MLSError> {
    let (authority, path) = split_http_url(url)?;
    let mut stream = TcpStream::connect(authority)
        .map_err(|error| MLSError::Internal(format!("connect G5 fixture proxy: {error}")))?;
    let body = body.unwrap_or_default();
    write!(
        stream,
        "{method} /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .map_err(|error| MLSError::Internal(error.to_string()))?;
    for header in headers {
        write!(stream, "{}: {}\r\n", header.name, header.value)
            .map_err(|error| MLSError::Internal(error.to_string()))?;
    }
    stream
        .write_all(b"\r\n")
        .and_then(|()| stream.write_all(body))
        .map_err(|error| MLSError::Internal(error.to_string()))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|error| MLSError::Internal(error.to_string()))?;
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| MLSError::Internal("G5 fixture proxy returned malformed HTTP".into()))?;
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|error| MLSError::Internal(error.to_string()))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| MLSError::Internal("G5 fixture proxy omitted HTTP status".into()))?;
    let response_headers: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| PlatformHttpHeader {
            name: name.trim().to_owned(),
            value: value.trim().to_owned(),
        })
        .collect();
    let mut response_body = raw[header_end + 4..].to_vec();
    if response_headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header.value.eq_ignore_ascii_case("chunked")
    }) {
        response_body = decode_chunked(&response_body)?;
    }
    Ok(PlatformHttpResponse {
        status,
        headers: response_headers,
        body: response_body,
    })
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, MLSError> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| MLSError::Internal("malformed chunked response".into()))?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&input[..line_end])
                .map_err(|error| MLSError::Internal(error.to_string()))?
                .split(';')
                .next()
                .unwrap(),
            16,
        )
        .map_err(|error| MLSError::Internal(error.to_string()))?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(MLSError::Internal("truncated chunked response".into()));
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create isolated G5 storage root");
    for entry in fs::read_dir(from).expect("read G5 storage template") {
        let entry = entry.expect("read G5 storage template entry");
        let destination = to.join(entry.file_name());
        if entry.file_type().expect("read G5 entry type").is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy G5 storage template file");
        }
    }
}

fn set_fault(fixture: &Fixture, mode: &str) {
    let body = serde_json::to_vec(&serde_json::json!({ "mode": mode })).unwrap();
    let response = http(
        "POST",
        &fixture.fault_control_url,
        &[PlatformHttpHeader {
            name: "content-type".into(),
            value: "application/json".into(),
        }],
        Some(&body),
    )
    .expect("configure G5 live fault");
    assert!(
        (200..300).contains(&response.status),
        "G5 fault controller rejected {mode}: HTTP {}",
        response.status
    );
}

fn client(fixture: &Fixture, root: &Path) -> Arc<CatbirdMlsClient> {
    let keys = Arc::new(LiveKeys {
        database_key: fixture.decode("databaseKeyBase64", &fixture.database_key_base64),
        signer: fixture.decode("signerKeypairBase64", &fixture.signer_keypair_base64),
        tokens: Mutex::new(HashMap::new()),
    });
    CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: root.to_string_lossy().into_owned(),
            account_did: fixture.account_did.clone(),
            device_id: fixture.device_id.clone(),
            home_ds_did: fixture.home_ds_did.clone(),
            home_ds_endpoint: fixture.home_ds_endpoint.clone(),
            pds_endpoint: fixture.pds_endpoint.clone(),
        },
        keys,
        Arc::new(LoopbackTransport {
            authorization: fixture.authorization.clone(),
        }),
        None,
    )
    .expect("open provisioned G5 client")
}

#[test]
fn g5_live_native_archive_faults_fail_closed_and_inventory_is_complete() {
    let Some(fixture) = Fixture::load() else {
        return;
    };
    assert!(
        fixture.inventory_records > 100,
        "G5 fixture must provision more than 100 conversation-Space records"
    );
    assert!(
        fixture.expected_messages > 100,
        "G5 fixture must make more than 100 records independently observable as restored messages"
    );

    let temp = tempfile::tempdir().expect("create G5 test root");
    for mode in [
        "expire_credential_mid_read",
        "replay_record_mac_wrong_uri",
        "replay_record_mac_wrong_cid",
        "list_get_value_mismatch",
    ] {
        set_fault(&fixture, mode);
        let root = temp.path().join(mode);
        copy_tree(&fixture.storage_root_template, &root);
        let live = client(&fixture, &root);
        let error = live
            .restore_conversation_from_owner_mailbox(&fixture.conversation_id)
            .expect_err("injected G5 fault must fail closed");
        assert!(
            live.list_messages(&fixture.conversation_id, None, 1)
                .expect("inspect failed G5 restore")
                .is_empty(),
            "{mode} released partial archive data before failing: {error}"
        );
    }

    set_fault(&fixture, "none");
    let root = temp.path().join("inventory_complete");
    copy_tree(&fixture.storage_root_template, &root);
    let live = client(&fixture, &root);
    let restored = live
        .restore_conversation_from_owner_mailbox(&fixture.conversation_id)
        .expect("restore complete >100-record live Space inventory");
    assert_eq!(
        usize::try_from(restored).unwrap(),
        fixture.expected_messages
    );
    assert_eq!(
        live.list_messages(
            &fixture.conversation_id,
            None,
            u32::try_from(fixture.expected_messages).unwrap()
        )
        .expect("list restored G5 messages")
        .len(),
        fixture.expected_messages
    );
}
