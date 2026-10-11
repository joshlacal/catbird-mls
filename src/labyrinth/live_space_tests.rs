//! The Space mailbox against a real atproto PDS from the upstream
//! `permissioned-data` branch. Opt-in: it runs only when
//! `LABYRINTH_SPACE_PDS` names the session file written by the labyrinth
//! repo's `scripts/space-pds/start.mjs`, and passes trivially otherwise.
//!
//! ```bash
//! node ../labyrinth/scripts/space-pds/start.mjs ../atproto /tmp/space-pds.json &
//! LABYRINTH_SPACE_PDS=/tmp/space-pds.json \
//!   cargo test --features labyrinth --lib live_space -- --test-threads=1
//! ```
//!
//! Each run needs a fresh network (the accounts' mailboxes must start
//! empty). Space requests go from [`SpaceXrpcTransport`] to the PDS over
//! plain HTTP with the dev session JWT, standing in for the platform's
//! OAuth session; `mailboxKeys` go to the public repo over
//! `com.atproto.repo.*`. mls-ds is the reference server behind
//! [`RefGateway`].

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use labyrinth::records::nsid;
use labyrinth::store::pds::{PdsPublisher, PdsRecords};
use labyrinth::store::space::SpaceMailboxStore;
use labyrinth::store::{MailboxDirectory, MailboxStore, TimeRange};
use serde_json::{json, Value};

use super::super::space::{LabyrinthSpaceGateway, LabyrinthSpaceRequest, SpaceXrpcTransport};
use super::*;
use crate::orchestrator::canonical_transport::encode_query;

const A1: &str = "11111111-1111-4111-8111-111111111111";
const A2: &str = "33333333-3333-4333-8333-333333333333";
const B1: &str = "22222222-2222-4222-8222-222222222222";

struct Account {
    did: String,
    jwt: String,
}

fn session() -> Option<(String, Account, Account)> {
    let path = std::env::var("LABYRINTH_SPACE_PDS").ok()?;
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let acct = |n: &str| Account {
        did: v["accounts"][n]["did"].as_str().unwrap().to_owned(),
        jwt: v["accounts"][n]["accessJwt"].as_str().unwrap().to_owned(),
    };
    Some((
        v["pds"].as_str().unwrap().to_owned(),
        acct("alice"),
        acct("bob"),
    ))
}

/// Plain HTTP/1.0 to the dev PDS (`http://host:port`), no proxy.
#[derive(Clone)]
struct Http {
    host: String,
    jwt: String,
}

impl Http {
    fn new(base: &str, jwt: &str) -> Self {
        Self {
            host: base
                .strip_prefix("http://")
                .unwrap()
                .trim_end_matches('/')
                .to_owned(),
            jwt: jwt.to_owned(),
        }
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<GatewayResponse, String> {
        let mut s = TcpStream::connect(&self.host).map_err(|e| e.to_string())?;
        let body = body.unwrap_or_default();
        let mut head = format!(
            "{method} {path} HTTP/1.0\r\nHost: {}\r\nAuthorization: Bearer {}\r\n",
            self.host, self.jwt
        );
        if method == "POST" {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        s.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
        s.write_all(body).map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("no header end")?;
        let header = String::from_utf8_lossy(&raw[..split]).to_string();
        let status: u16 = header
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or("no status")?;
        Ok(GatewayResponse {
            status,
            content_type: Some("application/json".into()),
            body: raw[split + 4..].to_vec(),
        })
    }

    fn xrpc(&self, method: &str, nsid: &str, query: &str, body: Option<&Value>) -> Value {
        let path = format!("/xrpc/{nsid}{query}");
        let body = body.map(|b| serde_json::to_vec(b).unwrap());
        let r = self.send(method, &path, body.as_deref()).unwrap();
        assert!(r.status < 300, "{nsid} {}", r.status);
        serde_json::from_slice(&r.body).unwrap_or(Value::Null)
    }
}

/// The platform's OAuth route to the account's PDS.
impl LabyrinthSpaceGateway for Http {
    fn submit_space(&self, req: LabyrinthSpaceRequest) -> Result<GatewayResponse, String> {
        self.send(&req.method, &req.path, req.body.as_deref())
    }
}

/// `mailboxKeys` in the public repo, over `com.atproto.repo.*`.
struct PublicRepo {
    did: String,
    http: Http,
}

fn query(params: &[(&str, &str)]) -> String {
    let q: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", encode_query(v)))
        .collect();
    format!("?{}", q.join("&"))
}

impl PdsRecords for PublicRepo {
    fn put_mailbox_keys(&self, rkey: &str, record: &[u8]) -> Result<(), String> {
        let record: Value = serde_json::from_slice(record).map_err(|e| e.to_string())?;
        let body = json!({
            "repo": self.did, "collection": nsid::MAILBOX_KEYS, "rkey": rkey,
            "record": record, "validate": false,
        });
        let r = self.http.send(
            "POST",
            "/xrpc/com.atproto.repo.putRecord",
            Some(&serde_json::to_vec(&body).unwrap()),
        )?;
        (r.status == 200)
            .then_some(())
            .ok_or_else(|| String::from_utf8_lossy(&r.body).to_string())
    }

    fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<Vec<u8>>, String> {
        let path = format!(
            "/xrpc/com.atproto.repo.getRecord{}",
            query(&[
                ("repo", did),
                ("collection", nsid::MAILBOX_KEYS),
                ("rkey", rkey)
            ])
        );
        let r = self.http.send("GET", &path, None)?;
        let v: Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
        match r.status {
            200 => Ok(Some(serde_json::to_vec(&v["value"]).unwrap())),
            400 if v["error"] == "RecordNotFound" => Ok(None),
            s => Err(format!("getRecord {s}: {v}")),
        }
    }

    fn delete_all_mailbox_keys(&self) -> Result<(), String> {
        let v = self.http.xrpc(
            "GET",
            "com.atproto.repo.listRecords",
            &query(&[
                ("repo", &self.did),
                ("collection", nsid::MAILBOX_KEYS),
                ("limit", "100"),
            ]),
            None,
        );
        for r in v["records"].as_array().into_iter().flatten() {
            let rkey = r["uri"].as_str().unwrap().rsplit('/').next().unwrap();
            let body = json!({ "repo": self.did, "collection": nsid::MAILBOX_KEYS, "rkey": rkey });
            self.http
                .xrpc("POST", "com.atproto.repo.deleteRecord", "", Some(&body));
        }
        Ok(())
    }
}

struct Live {
    gw: RefGateway,
    pds: String,
}

impl Live {
    fn device(&self, a: &Account, device_id: &str, seed: u8, space: bool) -> Device {
        let mut d = Device::new(&self.gw, &a.did, device_id, seed);
        let http = Http::new(&self.pds, &a.jwt);
        d.deps.pds = Some(Arc::new(PublicRepo {
            did: a.did.clone(),
            http: http.clone(),
        }));
        if space {
            d.deps.space = Some(Arc::new(SpaceXrpcTransport::new(Arc::new(http))));
        }
        d
    }

    /// `a`'s Space mailbox as the crate store sees it, read back from the PDS.
    fn mailbox(&self, d: &Device) -> SpaceMailboxStore {
        SpaceMailboxStore::new(
            &d.deps.did,
            d.deps.space.clone().unwrap(),
            Box::new(PdsPublisher::new(&d.deps.did, d.deps.pds.clone().unwrap())),
        )
    }
}

fn history_len(s: &mut super::super::session::LabyrinthSession) -> usize {
    s.load_history(THREAD, TimeRange::ALL)
        .unwrap()
        .messages
        .len()
}

#[test]
fn live_space_mailbox_lifecycle_through_the_orchestrator_session() {
    let Some((pds, alice, bob)) = session() else {
        eprintln!("LABYRINTH_SPACE_PDS not set; skipping the live Space test");
        return;
    };
    let live = Live {
        gw: RefGateway::new(),
        pds,
    };

    // Alice's first device creates her mailbox in her Space.
    let alice1 = live.device(&alice, A1, 1, true);
    let mut a1 = alice1.deps.clone().enable().unwrap();
    assert_eq!(
        alice1.deps.placements.load(&alice.did).unwrap().as_deref(),
        Some(&b"space"[..])
    );
    let space = live.mailbox(&alice1);
    assert_eq!(space.list_epochs().unwrap().len(), 1);
    assert_eq!(space.list_devices().unwrap().len(), 1);
    assert!(PdsRecords::get_mailbox_keys(
        alice1.deps.pds.as_ref().unwrap().as_ref(),
        &alice.did,
        "self"
    )
    .unwrap()
    .is_some());
    assert!(live
        .gw
        .net()
        .mailbox(&alice.did)
        .list_epochs()
        .unwrap()
        .is_empty());

    // Bob keeps his mailbox on mls-ds and addresses Alice through the real
    // PDS × mls-ds composite.
    let bob1 = live.device(&bob, B1, 2, false);
    let mut b = bob1.deps.clone().enable().unwrap();
    let members = vec![alice.did.clone(), bob.did.clone()];
    b.archive_sent(THREAD, &members, "m-1", 1_791_000_000_000, b"hi")
        .unwrap();
    assert_eq!(history_len(&mut a1), 1);

    // A second device restores from the Space with the recovery code.
    let code = a1.create_recovery_code().unwrap();
    let alice2 = live.device(&alice, A2, 3, true);
    let mut a2 = alice2
        .deps
        .clone()
        .restore_with_recovery_code(&code)
        .unwrap();
    assert_eq!(
        alice2.deps.placements.load(&alice.did).unwrap().as_deref(),
        Some(&b"space"[..])
    );
    assert_eq!(history_len(&mut a2), 1);

    // Revoking the first device opens epoch 1 in the Space; the mls-ds
    // head chain follows.
    let key: [u8; 32] = hex::decode(a1.device_key_hex())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(a2.revoke_device(key).unwrap(), 1);
    assert_eq!(space.list_epochs().unwrap().len(), 2);
    assert_eq!(
        live.gw
            .net()
            .ds_directory()
            .latest(&alice.did)
            .unwrap()
            .map(|e| e.seq),
        Some(1)
    );
    b.archive_sent(THREAD, &members, "m-2", 1_791_000_000_100, b"again")
        .unwrap();
    assert_eq!(history_len(&mut a2), 2);

    // Account deletion empties the Space and the public repo.
    let report = a2.purge_account().unwrap();
    assert!(report.remote_pending.is_none(), "{report:?}");
    assert!(space.list_epochs().unwrap().is_empty());
    assert!(space.list_devices().unwrap().is_empty());
    assert!(space.list_virtual_devices().unwrap().is_empty());
    assert!(PdsRecords::get_mailbox_keys(
        alice2.deps.pds.as_ref().unwrap().as_ref(),
        &alice.did,
        "self"
    )
    .unwrap()
    .is_none());
}
