//! The mailbox in the account's own PDS Space ([`super::super::space`]).
//!
//! Space requests go through [`SpaceXrpcTransport`] to [`HostGateway`],
//! which parses them back the way a PDS would and serves them from the
//! labyrinth crate's reference Space host. Threads, the ORF and the head
//! chain stay on the mls-ds reference server behind [`RefGateway`].

use labyrinth::records::nsid;
use labyrinth::store::space::host::{MemorySpaceHost, SpaceClient};
use labyrinth::store::space::SpaceRef;
use labyrinth::store::xrpc::XrpcTransport;
use labyrinth::store::{MailboxDirectory, MailboxStore, TimeRange};

use super::super::session::LabyrinthSession;
use super::super::space::{
    LabyrinthSpaceGateway, LabyrinthSpaceRequest, SpaceXrpcTransport, PLACEMENT_NAMESPACE,
};
use super::queue_tests::{with_pds, Repos};
use super::*;

const A1: &str = "11111111-1111-4111-8111-111111111111";
const A2: &str = "33333333-3333-4333-8333-333333333333";
const B1: &str = "22222222-2222-4222-8222-222222222222";

/// The platform's OAuth route to one account's PDS, over the reference
/// Space host.
struct HostGateway {
    client: SpaceClient,
    log: Arc<Mutex<Vec<LabyrinthSpaceRequest>>>,
}

impl LabyrinthSpaceGateway for HostGateway {
    fn submit_space(&self, req: LabyrinthSpaceRequest) -> Result<GatewayResponse, String> {
        self.log.lock().unwrap().push(req.clone());
        let (route, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
        assert_eq!(route, format!("/xrpc/{}", req.nsid));
        Ok(match req.method.as_str() {
            "GET" => {
                let params: Vec<(String, String)> = query
                    .split('&')
                    .filter(|kv| !kv.is_empty())
                    .map(|kv| {
                        let (k, v) = kv.split_once('=').unwrap();
                        (percent_decode(k), percent_decode(v))
                    })
                    .collect();
                let p: Vec<(&str, String)> = params
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.clone()))
                    .collect();
                reply(self.client.query(&req.nsid, &p))
            }
            _ => reply(self.client.procedure(
                &req.nsid,
                req.body.as_deref().unwrap_or_default(),
                [0; 16],
            )),
        })
    }
}

struct Net {
    gw: RefGateway,
    host: MemorySpaceHost,
    repos: Repos,
    space_log: Arc<Mutex<Vec<LabyrinthSpaceRequest>>>,
}

impl Net {
    fn new() -> Self {
        Self {
            gw: RefGateway::new(),
            host: MemorySpaceHost::new(),
            repos: Repos::default(),
            space_log: Arc::default(),
        }
    }

    /// A device whose platform publishes `mailboxKeys` but has no Space.
    fn pds_device(&self, did: &str, device_id: &str, seed: u8) -> Device {
        with_pds(Device::new(&self.gw, did, device_id, seed), &self.repos)
    }

    /// A device whose platform also reaches the account's Space.
    fn space_device(&self, did: &str, device_id: &str, seed: u8) -> Device {
        let mut d = self.pds_device(did, device_id, seed);
        d.deps.space = Some(self.space_transport(did));
        d
    }

    fn space_transport(&self, did: &str) -> Arc<dyn XrpcTransport> {
        Arc::new(SpaceXrpcTransport::new(Arc::new(HostGateway {
            client: self.host.client(did),
            log: self.space_log.clone(),
        })))
    }

    fn space_records(&self, did: &str, collection: Option<&str>) -> usize {
        self.host
            .record_count(&SpaceRef::mailbox(did), did, collection)
    }

    fn has_mailbox_keys(&self, did: &str) -> bool {
        self.repos.lock().unwrap().keys().any(|(d, _)| d == did)
    }

    fn labyrinth_calls(&self, name: &str) -> usize {
        let nsid = format!("blue.catbird.labyrinth.{name}");
        self.gw
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.nsid == nsid)
            .count()
    }
}

fn placement(d: &Device) -> Option<Vec<u8>> {
    d.deps.placements.load(&d.deps.did).unwrap()
}

fn history_len(s: &mut LabyrinthSession) -> usize {
    s.load_history(THREAD, TimeRange::ALL)
        .unwrap()
        .messages
        .len()
}

#[test]
fn a_new_mailbox_goes_into_the_space_and_restores_from_it() {
    let net = Net::new();
    let alice1 = net.space_device(ALICE, A1, 1);
    let mut a1 = alice1.deps.clone().enable().unwrap();
    assert_eq!(placement(&alice1).as_deref(), Some(&b"space"[..]));

    // The mailbox is in Alice's Space; mls-ds holds none of it, but it has
    // her head chain (the independent directory) and the PDS her
    // mailboxKeys.
    assert_eq!(net.space_records(ALICE, Some(nsid::EPOCH)), 1);
    assert_eq!(net.space_records(ALICE, Some(nsid::DEVICE)), 1);
    assert!(net
        .gw
        .net()
        .mailbox(ALICE)
        .list_devices()
        .unwrap()
        .is_empty());
    assert_eq!(
        net.gw
            .net()
            .ds_directory()
            .latest(ALICE)
            .unwrap()
            .map(|e| e.seq),
        Some(0)
    );
    assert!(net.has_mailbox_keys(ALICE));
    // Every Space request was a com.atproto.space call.
    assert!(net
        .space_log
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.nsid.starts_with("com.atproto.space.")));

    // Bob's mailbox stays on mls-ds; he addresses Alice through the
    // PDS × mls-ds composite.
    let bob = net.pds_device(BOB, B1, 2);
    let mut b = bob.deps.clone().enable().unwrap();
    assert_eq!(placement(&bob).as_deref(), Some(&b"mlsds"[..]));
    assert_eq!(net.space_records(BOB, None), 0);
    let members = vec![ALICE.to_owned(), BOB.to_owned()];
    b.archive_sent(THREAD, &members, "m-1", 1_791_000_000_000, b"hi")
        .unwrap();
    assert_eq!(history_len(&mut a1), 1);

    // A second device restores from the Space with the recovery code.
    let code = a1.create_recovery_code().unwrap();
    assert_eq!(net.space_records(ALICE, Some(nsid::VIRTUAL_DEVICE)), 1);
    let alice2 = net.space_device(ALICE, A2, 3);
    let mut a2 = alice2
        .deps
        .clone()
        .restore_with_recovery_code(&code)
        .unwrap();
    assert_eq!(placement(&alice2).as_deref(), Some(&b"space"[..]));
    assert_eq!(history_len(&mut a2), 1);

    // Revoking the first device opens epoch 1 in the Space, and both
    // directories follow.
    let key: [u8; 32] = hex::decode(a1.device_key_hex())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(a2.revoke_device(key).unwrap(), 1);
    assert_eq!(net.space_records(ALICE, Some(nsid::EPOCH)), 2);
    assert_eq!(
        net.gw
            .net()
            .ds_directory()
            .latest(ALICE)
            .unwrap()
            .map(|e| e.seq),
        Some(1)
    );
    b.archive_sent(THREAD, &members, "m-2", 1_791_000_000_100, b"again")
        .unwrap();
    assert_eq!(history_len(&mut a2), 2);
    assert!(net
        .gw
        .net()
        .mailbox(ALICE)
        .list_epochs()
        .unwrap()
        .is_empty());
}

#[test]
fn an_mlsds_mailbox_stays_on_mlsds_when_the_space_appears() {
    let net = Net::new();
    let alice1 = net.pds_device(ALICE, A1, 1);
    let mut a1 = alice1.deps.clone().enable().unwrap();
    let code = a1.create_recovery_code().unwrap();
    drop(a1);

    // A new device on a Space-capable platform finds the mls-ds mailbox.
    let alice2 = net.space_device(ALICE, A2, 3);
    alice2
        .deps
        .clone()
        .restore_with_recovery_code(&code)
        .unwrap();
    assert_eq!(placement(&alice2).as_deref(), Some(&b"mlsds"[..]));

    // State saved before placements existed is an mls-ds mailbox, even
    // once the platform reaches a Space.
    let mut legacy = alice1;
    legacy.deps.placements.delete(ALICE).unwrap();
    legacy.deps.space = Some(net.space_transport(ALICE));
    let mut a1 = legacy.deps.clone().open().unwrap().unwrap();
    a1.create_recovery_code().unwrap();
    assert_eq!(net.space_records(ALICE, None), 0);
    assert_eq!(
        net.gw
            .net()
            .mailbox(ALICE)
            .list_virtual_devices()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn a_space_mailbox_is_not_opened_without_the_space() {
    let net = Net::new();
    let mut alice = net.space_device(ALICE, A1, 1);
    drop(alice.deps.clone().enable().unwrap());
    alice.deps.space = None;
    let e = alice.deps.clone().open().err().unwrap();
    assert!(e.to_string().contains("PDS Space"), "{e}");
    // Without a PDS publisher the Space store cannot be built either.
    let mut alice = net.space_device(ALICE, A1, 1);
    alice.deps.placements = Arc::new(MemVault::default());
    alice.deps.pds = None;
    assert_eq!(
        alice.deps.probe_placement().unwrap(),
        super::super::space::Placement::MlsDs
    );
}

#[test]
fn account_deletion_clears_the_space_the_pds_and_mlsds() {
    let net = Net::new();
    let alice = net.space_device(ALICE, A1, 1);
    let mut a = alice.deps.clone().enable().unwrap();
    a.create_recovery_code().unwrap();
    let members = vec![ALICE.to_owned()];
    a.archive_sent(THREAD, &members, "m-1", 1_791_000_000_000, b"mine")
        .unwrap();
    a.rearchive_before_leave(THREAD).unwrap();
    assert!(net.space_records(ALICE, Some(nsid::OWNER_BATCH)) > 0);

    let report = a.purge_account().unwrap();
    assert!(report.remote_pending.is_none(), "{report:?}");
    assert!(report.server_side);
    assert_eq!(net.labyrinth_calls("deleteAccountData"), 1);
    assert_eq!(net.space_records(ALICE, None), 0);
    assert!(!net.has_mailbox_keys(ALICE));
    assert!(net.gw.net().ds_directory().latest(ALICE).unwrap().is_none());
    assert_eq!(placement(&alice), None);
    assert!(alice.deps.vault.load(ALICE).unwrap().is_none());

    // The retry path needs no saved state and is idempotent.
    alice.deps.delete_account_remote().unwrap();
    assert_eq!(net.labyrinth_calls("deleteAccountData"), 2);
}

#[test]
fn the_space_transport_sends_only_space_requests() {
    let net = Net::new();
    let t = net.space_transport(ALICE);
    let e = t
        .query(
            "blue.catbird.labyrinth.getEpoch",
            &[("epochNumber", "0".into())],
        )
        .unwrap_err();
    assert_eq!(e.status, 0);
    let e = t
        .procedure("com.atproto.repo.putRecord", b"{}", [0; 16])
        .unwrap_err();
    assert_eq!(e.status, 0);
    let e = t
        .query_with_headers(
            "com.atproto.space.getRecord",
            &[],
            &[("x".into(), "y".into())],
        )
        .unwrap_err();
    assert_eq!(e.status, 0);
    assert!(net.space_log.lock().unwrap().is_empty());

    let _ = t.query(
        "com.atproto.space.listRecords",
        &[("space", SpaceRef::mailbox("did:plc:a b").to_string())],
    );
    let req = net.space_log.lock().unwrap().pop().unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/xrpc/com.atproto.space.listRecords?space=at%3A%2F%2Fdid%3Aplc%3Aa%20b%2Fspace%2Fblue.catbird.labyrinth.mailbox%2Fself"
    );
    assert_eq!(PLACEMENT_NAMESPACE, "labyrinthMailboxPlacement");
}
