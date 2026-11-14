//! Offline moderation tool: decrypt one reported Circle post with its disclosed post key.
//!
//! ```text
//! circle-report-decrypt --record <post-record.json> --post-key <hex32> \
//!     --post-uri <uri> --author-did <did> --author-epoch <getRecord-response.json>
//! ```
//!
//! `--author-epoch` is the `com.atproto.repo.getRecord` response (`uri`,
//! `value`) for the author's `blue.catbird.labyrinth.mailboxKeys` record,
//! fetched from the author's own PDS. The tool refuses it unless its URI
//! names the author's repo and that collection; the file is not trusted on
//! its own (the epoch must also self-verify for the author DID).
//!
//! Prints the payload JSON on stdout. Exit codes: 0 success; 2 signature or
//! trust failure; 3 any other failure; 64 usage. The post key and other key
//! material are never printed.

use std::path::PathBuf;
use std::process::ExitCode;

use catbird_mls::circles::error::CircleError;
use catbird_mls::circles::post::open_post_with_post_key;
use catbird_mls::circles::records::{
    check_record_payload_consistency, header_from_record, CirclePostRecord,
};
use labyrinth::mailbox::EpochPublic;
use labyrinth::records::MailboxKeysRecord;

const EXIT_TRUST: u8 = 2;
const EXIT_FAILURE: u8 = 3;
const EXIT_USAGE: u8 = 64;

const USAGE: &str = "usage: circle-report-decrypt --record <post-record.json> --post-key <hex32> \
--post-uri <uri> --author-did <did> --author-epoch <getRecord-response.json>";

const HELP: &str = "\
--author-epoch is the com.atproto.repo.getRecord response (with its `uri`) for the author's
blue.catbird.labyrinth.mailboxKeys record. Runbook: the epoch file must be fetched from the
author's own PDS and is NOT trusted on its own; the tool refuses it unless its URI names the
author's repo, and the epoch must self-verify for --author-did.
Exit codes: 0 success; 2 signature or trust failure; 3 other failure; 64 usage.";

struct Args {
    record: PathBuf,
    post_key: String,
    post_uri: String,
    author_did: String,
    author_epoch: PathBuf,
}

enum Failure {
    Trust(String),
    Other(String),
}

impl Failure {
    fn other(msg: impl Into<String>) -> Self {
        Failure::Other(msg.into())
    }
}

impl From<CircleError> for Failure {
    fn from(e: CircleError) -> Self {
        match e {
            CircleError::BadSignature | CircleError::UntrustedSender { .. } => {
                Failure::Trust(e.to_string())
            }
            other => Failure::Other(other.to_string()),
        }
    }
}

const HELP_REQUESTED: &str = "help";

fn inline_is_flag(v: &str) -> bool {
    v.starts_with("--")
}

fn parse_args(raw: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut record, mut post_key, mut post_uri, mut author_did, mut author_epoch) =
        (None, None, None, None, None);
    let mut it = raw;
    while let Some(token) = it.next() {
        if token == "--help" || token == "-h" {
            return Err(HELP_REQUESTED.to_owned());
        }
        // Accept `--flag value` and `--flag=value`. Never echo a raw token:
        // it may carry a post key.
        let (flag, inline) = match token.split_once('=') {
            Some((f, v)) => (f.to_owned(), Some(v.to_owned())),
            None => (token, None),
        };
        let slot = match flag.as_str() {
            "--record" => &mut record,
            "--post-key" => &mut post_key,
            "--post-uri" => &mut post_uri,
            "--author-did" => &mut author_did,
            "--author-epoch" => &mut author_epoch,
            _ => return Err("unknown argument".to_owned()),
        };
        if slot.is_some() {
            return Err(format!("{flag} given twice"));
        }
        let value = match inline {
            Some(v) => v,
            None => it.next().ok_or_else(|| format!("{flag} needs a value"))?,
        };
        if inline_is_flag(&value) {
            return Err(format!("{flag} needs a value"));
        }
        *slot = Some(value);
    }
    let need = |v: Option<String>, name: &str| v.ok_or_else(|| format!("missing {name}"));
    Ok(Args {
        record: need(record, "--record")?.into(),
        post_key: need(post_key, "--post-key")?,
        post_uri: need(post_uri, "--post-uri")?,
        author_did: need(author_did, "--author-did")?,
        author_epoch: need(author_epoch, "--author-epoch")?.into(),
    })
}

const MAILBOX_KEYS: &str = "blue.catbird.labyrinth.mailboxKeys";

/// The author's epoch from a `getRecord` response, refused unless the
/// response's URI is `at://<author_did>/blue.catbird.labyrinth.mailboxKeys/<rkey>`.
fn parse_author_epoch(json: &str, author_did: &str) -> Result<EpochPublic, Failure> {
    let envelope: serde_json::Value =
        serde_json::from_str(json).map_err(|_| Failure::other("author epoch file is not JSON"))?;
    let uri = envelope["uri"].as_str().ok_or_else(|| {
        Failure::Trust(
            "author epoch must be the getRecord response (with uri) from the author's PDS".into(),
        )
    })?;
    let rest = uri
        .strip_prefix("at://")
        .ok_or_else(|| Failure::Trust("author epoch uri is not an at:// URI".into()))?;
    let mut parts = rest.splitn(3, '/');
    let (repo, collection, rkey) = (parts.next(), parts.next(), parts.next());
    if repo != Some(author_did) {
        return Err(Failure::Trust(
            "author epoch record is not from the author's repo".into(),
        ));
    }
    if collection != Some(MAILBOX_KEYS) || rkey.is_none_or(str::is_empty) {
        return Err(Failure::Trust(format!(
            "author epoch uri is not a {MAILBOX_KEYS} record"
        )));
    }
    let value = envelope["value"].to_string();
    serde_json::from_str::<MailboxKeysRecord>(&value)
        .map_err(|e| e.to_string())
        .and_then(|r| r.to_public().map_err(|e| e.to_string()))
        .map_err(|e| Failure::Other(format!("author epoch: {e}")))
}

fn run(args: &Args) -> Result<String, Failure> {
    let post_key: [u8; 32] = hex::decode(args.post_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Failure::other("post key must be 64 hex characters (32 bytes)"))?;
    let read = |p: &PathBuf, what: &str| {
        std::fs::read_to_string(p).map_err(|e| Failure::Other(format!("reading {what}: {e}")))
    };
    let record: CirclePostRecord = serde_json::from_str(&read(&args.record, "record")?)
        .map_err(|e| Failure::Other(format!("record: {e}")))?;
    let sealed = record.to_sealed()?;
    let header = header_from_record(&record, &args.post_uri, &args.author_did)?;

    let epoch = parse_author_epoch(&read(&args.author_epoch, "author epoch")?, &args.author_did)?;
    if epoch.head != sealed.author_epoch_head {
        return Err(Failure::Trust(
            "author epoch head does not match the record's authorEpochHead".into(),
        ));
    }
    epoch
        .verify(&args.author_did, None)
        .map_err(|e| Failure::Trust(format!("author epoch failed verification: {e}")))?;

    let payload = open_post_with_post_key(&sealed, &header, &post_key, &epoch.keys.sig)?;
    check_record_payload_consistency(&record, &payload)?;
    serde_json::to_string(&payload).map_err(|e| Failure::Other(e.to_string()))
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) if e == HELP_REQUESTED => {
            println!("{USAGE}\n{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match run(&args) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(Failure::Trust(e)) => {
            eprintln!("trust failure: {e}");
            ExitCode::from(EXIT_TRUST)
        }
        Err(Failure::Other(e)) => {
            eprintln!("error: {e}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}
