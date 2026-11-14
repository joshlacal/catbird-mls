//! `circle-report-decrypt` moderation tool: decrypt one disclosed post with its post key.

#![cfg(feature = "labyrinth")]

use std::path::PathBuf;
use std::process::{Command, Output};

use catbird_mls::circles::post::{derive_post_key, seal_post, CirclePostHeader, CirclePostPayload};
use catbird_mls::circles::records::CirclePostRecord;
use ed25519_dalek::{Signer as _, SigningKey};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::MailboxKeysRecord;
use labyrinth::sign::TransportSigner;
use serde_json::{json, Value};

const AUTHOR: &str = "did:plc:circleauthor0000000000000";
const CIRCLE_ID: &str = "3kcircleid22a";
const POST_URI: &str = "at://did:plc:circleauthor0000000000000/blue.catbird.circle.post/3kpost";
const CREATED: &str = "2026-11-07T12:00:00.000Z";

struct TestTransport(SigningKey);

impl TransportSigner for TestTransport {
    fn transport_public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    labyrinth::encoding::random(&mut out).expect("rng");
    out
}

struct Fixture {
    dir: PathBuf,
    record: CirclePostRecord,
    epoch_json: String,
    post_key: [u8; 32],
    payload: CirclePostPayload,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "circle-report-decrypt-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let root = random32();
        let keys = MailboxKeys::derive(&root, 0);
        let transport = TestTransport(SigningKey::from_bytes(&random32()));
        let epoch = EpochPublic::sign(AUTHOR, 0, &keys, random32(), None, None, &transport)
            .expect("sign epoch");
        epoch.verify(AUTHOR, None).expect("verify epoch");

        let circle_key = random32();
        let header = CirclePostHeader {
            circle_id: CIRCLE_ID.into(),
            key_version: 1,
            post_uri: POST_URI.into(),
            author_did: AUTHOR.into(),
            created_at: CREATED.into(),
        };
        let payload = CirclePostPayload {
            post: json!({"text": "hello circle", "createdAt": CREATED}),
            media: vec![],
            created_at: CREATED.into(),
        };
        let sealed = seal_post(&payload, &header, &circle_key, &keys, epoch.head).expect("seal");
        let record = CirclePostRecord::from_sealed(&sealed, &header, None, vec![]);
        let epoch_json = envelope(
            AUTHOR,
            serde_json::to_value(MailboxKeysRecord::from_public(
                &epoch,
                None,
                CREATED.to_owned(),
            ))
            .unwrap(),
        );
        Self {
            dir,
            record,
            epoch_json,
            post_key: derive_post_key(&circle_key, CIRCLE_ID, POST_URI),
            payload,
        }
    }

    fn run_with_epoch(&self, epoch_json: &str) -> Output {
        self.write(&self.record);
        std::fs::write(self.dir.join("epoch.json"), epoch_json).unwrap();
        self.invoke(&self.post_key)
    }

    fn write(&self, record: &CirclePostRecord) {
        std::fs::write(
            self.dir.join("record.json"),
            serde_json::to_vec(record).unwrap(),
        )
        .unwrap();
        std::fs::write(self.dir.join("epoch.json"), &self.epoch_json).unwrap();
    }

    fn run(&self, record: &CirclePostRecord, post_key: &[u8; 32]) -> Output {
        self.write(record);
        self.invoke(post_key)
    }

    fn invoke(&self, post_key: &[u8; 32]) -> Output {
        let record_path = self.dir.join("record.json");
        let epoch_path = self.dir.join("epoch.json");
        Command::new(env!("CARGO_BIN_EXE_circle-report-decrypt"))
            .arg("--record")
            .arg(&record_path)
            .args(["--post-key", &hex::encode(post_key)])
            .args(["--post-uri", POST_URI])
            .args(["--author-did", AUTHOR])
            .arg("--author-epoch")
            .arg(&epoch_path)
            .output()
            .expect("run bin")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A `com.atproto.repo.getRecord` response for `mailboxKeys/self` in `repo`.
fn envelope(repo: &str, value: Value) -> String {
    json!({
        "uri": format!("at://{repo}/blue.catbird.labyrinth.mailboxKeys/self"),
        "cid": "bafyreiepochrecord",
        "value": value,
    })
    .to_string()
}

fn assert_no_key(out: &Output, key: &[u8; 32]) {
    let hex = hex::encode(key);
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&hex));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&hex));
}

#[test]
fn decrypts_disclosed_post() {
    let f = Fixture::new("ok");
    let out = f.run(&f.record, &f.post_key);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed: Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(printed, serde_json::to_value(&f.payload).unwrap());
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&hex::encode(f.post_key)));
}

#[test]
fn tampered_ciphertext_exits_2() {
    let f = Fixture::new("tamper");
    let mut bad = f.record.clone();
    let last = bad.ciphertext.0.len() - 1;
    bad.ciphertext.0[last] ^= 1;
    let out = f.run(&bad, &f.post_key);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_no_key(&out, &f.post_key);
}

#[test]
fn wrong_post_key_exits_3() {
    let f = Fixture::new("wrongkey");
    let wrong = random32();
    let out = f.run(&f.record, &wrong);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert_no_key(&out, &wrong);
    assert_no_key(&out, &f.post_key);
}

#[test]
fn bad_usage_exits_64() {
    let out = Command::new(env!("CARGO_BIN_EXE_circle-report-decrypt"))
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn flag_equals_form_works() {
    let f = Fixture::new("equals");
    f.write(&f.record);
    let out = Command::new(env!("CARGO_BIN_EXE_circle-report-decrypt"))
        .arg(format!("--record={}", f.dir.join("record.json").display()))
        .arg(format!("--post-key={}", hex::encode(f.post_key)))
        .arg(format!("--post-uri={POST_URI}"))
        .arg(format!("--author-did={AUTHOR}"))
        .arg(format!(
            "--author-epoch={}",
            f.dir.join("epoch.json").display()
        ))
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn unknown_argument_never_echoes_key() {
    let f = Fixture::new("unknown");
    let out = Command::new(env!("CARGO_BIN_EXE_circle-report-decrypt"))
        .arg(format!("--post-kee={}", hex::encode(f.post_key)))
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(64));
    assert_no_key(&out, &f.post_key);
}

#[test]
fn flag_value_starting_with_dashes_is_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_circle-report-decrypt"))
        .args(["--record", "--post-key", "00"])
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn epoch_record_from_another_repo_is_refused() {
    let f = Fixture::new("otherrepo");
    let value = serde_json::from_str::<Value>(&f.epoch_json).unwrap()["value"].clone();
    let out = f.run_with_epoch(&envelope("did:plc:someoneelse0000000000000", value));
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.trim().lines().count(), 1, "{err}");
    assert!(err.contains("author"), "{err}");
}

#[test]
fn bare_epoch_record_without_uri_is_refused() {
    let f = Fixture::new("bare");
    let value = serde_json::from_str::<Value>(&f.epoch_json).unwrap()["value"].clone();
    let out = f.run_with_epoch(&value.to_string());
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

#[test]
fn epoch_record_from_another_collection_is_refused() {
    let f = Fixture::new("othercoll");
    let mut env: Value = serde_json::from_str(&f.epoch_json).unwrap();
    env["uri"] = json!(format!("at://{AUTHOR}/app.bsky.actor.profile/self"));
    let out = f.run_with_epoch(&env.to_string());
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_states_the_epoch_trust_runbook() {
    let out = Command::new(env!("CARGO_BIN_EXE_circle-report-decrypt"))
        .arg("--help")
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("author's own PDS"), "{help}");
    assert!(help.contains("NOT trusted on its own"), "{help}");
}
