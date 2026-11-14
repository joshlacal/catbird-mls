#![no_main]

use std::sync::OnceLock;

use atproto_spaces::lthash::compute_dagcbor_cid;
use atproto_spaces::star::{
    read_star_metadata, read_star_repo, validate_canonical_dagcbor_record, write_star_repo,
    StarRecordEntry,
};
use catbird_mls::atproto::types::value::Data;
use libfuzzer_sys::fuzz_target;

const EXPECTED_SPACE: &str = "at://did:plc:alice/blue.catbird.labyrinth.mailbox/self";
const EXPECTED_REPO: &str = "did:plc:alice";

fn star_seed() -> &'static Vec<u8> {
    static SEED: OnceLock<Vec<u8>> = OnceLock::new();
    SEED.get_or_init(|| {
        let rec = serde_ipld_dagcbor::to_vec(&serde_json::json!({
            "$type": "blue.catbird.labyrinth.epoch",
            "epochNumber": 1,
            "createdAt": "2026-11-13T00:00:00.000Z"
        }))
        .expect("encode seed record");
        let entries = vec![StarRecordEntry {
            path: "blue.catbird.labyrinth.epoch/1".to_string(),
            record_dagcbor: rec,
        }];
        write_star_repo(
            EXPECTED_SPACE,
            EXPECTED_REPO,
            "3lc2zzzzzzzzz",
            &[0x42u8; 32],
            &entries,
        )
        .expect("write_star_repo")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }

    // 1. Canonical DAG-CBOR validator: every accepted frame must hash cleanly to a CID
    //    and round-trip deterministically without floats or trailing bytes.
    if validate_canonical_dagcbor_record(data).is_ok() {
        let cid_a = compute_dagcbor_cid(data);
        let cid_b = compute_dagcbor_cid(data);
        assert_eq!(cid_a, cid_b);
        let _ = serde_ipld_dagcbor::from_slice::<Data>(data);
    } else {
        // Non-canonical or malformed frames must still never panic in `Data` decoding.
        let _ = serde_ipld_dagcbor::from_slice::<Data>(data);
    }

    // 2. Arbitrary STAR-lite repository archive metadata + full archive parsing.
    let _ = read_star_metadata(data, EXPECTED_SPACE, EXPECTED_REPO);
    if let Ok(parsed) = read_star_repo(data, EXPECTED_SPACE, EXPECTED_REPO) {
        let entries: Vec<StarRecordEntry> = parsed
            .records
            .iter()
            .map(|r| StarRecordEntry {
                path: r.path.clone(),
                record_dagcbor: r.record_dagcbor.clone(),
            })
            .collect();
        let reencoded = write_star_repo(
            &parsed.space,
            &parsed.repo,
            &parsed.rev,
            &parsed.data,
            &entries,
        )
        .expect("parsed STAR-lite repo must re-serialize canonically");
        assert_eq!(reencoded.as_slice(), data);
    }

    // 3. Differential mutation over a valid STAR-lite archive.
    if data.len() >= 3 {
        let base = star_seed();
        if !base.is_empty() {
            let mut mutated = base.clone();
            let off = usize::from(u16::from_be_bytes([data[0], data[1]])) % mutated.len();
            for (dst, &mask) in mutated[off..].iter_mut().zip(data[2..].iter()) {
                *dst ^= mask;
            }
            let _ = read_star_repo(&mutated, EXPECTED_SPACE, EXPECTED_REPO);
        }
    }
});
