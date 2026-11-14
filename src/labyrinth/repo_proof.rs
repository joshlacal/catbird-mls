//! Bounded ATProto CARv1, v3 signed commit, and MST Merkle inclusion/exclusion
//! proof verification for public repository records (`mailboxKeys`, `chat.device`).

use std::collections::{HashMap, HashSet};
use std::io::Cursor;

use atproto_spaces::lthash::compute_dagcbor_cid;
use atproto_spaces::tokens::{SpaceSigningKey, SpaceVerifyingKey};
use cid::Cid;
use serde::{Deserialize, Serialize};

pub const MAX_CAR_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CAR_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_CAR_SECTIONS: usize = 4_096;
const DAG_CBOR_CODEC: u64 = 0x71;
const DAGCBOR_MAX_DEPTH: usize = 32;
const MST_MAX_DEPTH: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
struct CarHeader {
    version: u64,
    roots: Vec<Cid>,
}

mod cbor_bytes {
    use serde::{Deserializer, Serializer};

    pub mod vec {
        use super::*;
        pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(bytes)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<u8>, D::Error> {
            struct BytesVisitor;
            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a CBOR byte string")
                }
                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                    Ok(v.to_vec())
                }
                fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                    Ok(v)
                }
            }
            deserializer.deserialize_byte_buf(BytesVisitor)
        }
    }

    pub mod slice {
        use super::*;
        pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(bytes)
        }
    }
}

fn sign_space_key_raw(signing_key: &SpaceSigningKey, signing_input: &[u8]) -> Vec<u8> {
    match signing_key {
        SpaceSigningKey::P256 { signing_key, .. } => {
            use p256::ecdsa::signature::Signer as _;
            let sig: p256::ecdsa::Signature = signing_key.sign(signing_input);
            sig.normalize_s().unwrap_or(sig).to_bytes().to_vec()
        }
        SpaceSigningKey::K256 { signing_key, .. } => {
            let (sig, _) = signing_key
                .sign_recoverable(signing_input)
                .expect("secp256k1 ECDSA sign");
            sig.normalize_s().unwrap_or(sig).to_bytes().to_vec()
        }
    }
}

#[derive(Debug, Deserialize)]
struct SignedAtprotoCommitV3 {
    did: String,
    version: u64,
    data: Cid,
    rev: String,
    #[serde(default)]
    prev: Option<Cid>,
    #[serde(with = "cbor_bytes::vec")]
    sig: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct UnsignedAtprotoCommitV3<'a> {
    did: &'a str,
    version: u64,
    data: Cid,
    rev: &'a str,
    prev: Option<Cid>,
}

#[derive(Debug, Serialize)]
struct SignedAtprotoCommitV3Encode<'a> {
    did: &'a str,
    version: u64,
    data: Cid,
    rev: &'a str,
    prev: Option<Cid>,
    #[serde(with = "cbor_bytes::slice")]
    sig: &'a [u8],
}

#[derive(Debug, Serialize, Deserialize)]
struct MstEntry {
    p: usize,
    #[serde(with = "cbor_bytes::vec")]
    k: Vec<u8>,
    v: Cid,
    t: Option<Cid>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MstNodeData {
    l: Option<Cid>,
    e: Vec<MstEntry>,
}

fn read_uvarint(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for idx in 0..10 {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| "truncated varint in CAR archive".to_owned())?;
        *pos = pos
            .checked_add(1)
            .ok_or_else(|| "CAR cursor overflow".to_owned())?;
        if idx == 9 && byte > 1 {
            return Err("varint u64 overflow in CAR archive".to_owned());
        }
        if byte < 0x80 {
            if idx > 0 && byte == 0 {
                return Err("non-minimal varint in CAR archive".to_owned());
            }
            return Ok(value | (u64::from(byte) << shift));
        }
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }
    Err("unterminated varint in CAR archive".to_owned())
}

fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_cbor_uint(bytes: &[u8], pos: &mut usize, info: u8) -> Result<u64, String> {
    match info {
        0..=23 => Ok(u64::from(info)),
        24 => {
            let b = *bytes
                .get(*pos)
                .ok_or_else(|| "truncated CBOR uint8".to_owned())?;
            *pos += 1;
            if b < 24 {
                return Err("non-canonical CBOR uint8".to_owned());
            }
            Ok(u64::from(b))
        }
        25 => {
            let end = pos
                .checked_add(2)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| "truncated CBOR uint16".to_owned())?;
            let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
            *pos = end;
            if v <= u16::from(u8::MAX) {
                return Err("non-canonical CBOR uint16".to_owned());
            }
            Ok(u64::from(v))
        }
        26 => {
            let end = pos
                .checked_add(4)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| "truncated CBOR uint32".to_owned())?;
            let v = u32::from_be_bytes([
                bytes[*pos],
                bytes[*pos + 1],
                bytes[*pos + 2],
                bytes[*pos + 3],
            ]);
            *pos = end;
            if v <= u32::from(u16::MAX) {
                return Err("non-canonical CBOR uint32".to_owned());
            }
            Ok(u64::from(v))
        }
        27 => {
            let end = pos
                .checked_add(8)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| "truncated CBOR uint64".to_owned())?;
            let v = u64::from_be_bytes([
                bytes[*pos],
                bytes[*pos + 1],
                bytes[*pos + 2],
                bytes[*pos + 3],
                bytes[*pos + 4],
                bytes[*pos + 5],
                bytes[*pos + 6],
                bytes[*pos + 7],
            ]);
            *pos = end;
            if v <= u64::from(u32::MAX) {
                return Err("non-canonical CBOR uint64".to_owned());
            }
            Ok(v)
        }
        _ => Err("indefinite or reserved CBOR integer encoding".to_owned()),
    }
}

fn verify_canonical_dagcbor_item(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
) -> Result<(), String> {
    if depth > DAGCBOR_MAX_DEPTH {
        return Err("DAG-CBOR nesting depth exceeded".to_owned());
    }
    let head = *bytes
        .get(*pos)
        .ok_or_else(|| "truncated DAG-CBOR item".to_owned())?;
    *pos += 1;
    let major = head >> 5;
    let info = head & 0x1f;
    match major {
        0 | 1 => {
            read_cbor_uint(bytes, pos, info)?;
            Ok(())
        }
        2 => {
            let len = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR bytes length overflow".to_owned())?;
            let end = pos
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| "truncated CBOR bytes".to_owned())?;
            *pos = end;
            Ok(())
        }
        3 => {
            let len = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR text length overflow".to_owned())?;
            let end = pos
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| "truncated CBOR text".to_owned())?;
            std::str::from_utf8(&bytes[*pos..end])
                .map_err(|_| "invalid UTF-8 in CBOR text".to_owned())?;
            *pos = end;
            Ok(())
        }
        4 => {
            let count = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR array length overflow".to_owned())?;
            for _ in 0..count {
                verify_canonical_dagcbor_item(bytes, pos, depth + 1)?;
            }
            Ok(())
        }
        5 => {
            let count = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR map length overflow".to_owned())?;
            let mut prev_key: Option<&[u8]> = None;
            for _ in 0..count {
                let key_head = *bytes
                    .get(*pos)
                    .ok_or_else(|| "truncated CBOR map key".to_owned())?;
                if (key_head >> 5) != 3 {
                    return Err("DAG-CBOR map key must be a UTF-8 string".to_owned());
                }
                *pos += 1;
                let key_len = usize::try_from(read_cbor_uint(bytes, pos, key_head & 0x1f)?)
                    .map_err(|_| "CBOR map key length overflow".to_owned())?;
                let key_end = pos
                    .checked_add(key_len)
                    .filter(|&end| end <= bytes.len())
                    .ok_or_else(|| "truncated CBOR map key".to_owned())?;
                let key_slice = &bytes[*pos..key_end];
                std::str::from_utf8(key_slice)
                    .map_err(|_| "invalid UTF-8 in CBOR map key".to_owned())?;
                if let Some(prev) = prev_key {
                    if (prev.len(), prev) >= (key_slice.len(), key_slice) {
                        return Err("non-canonical or duplicate DAG-CBOR map key order".to_owned());
                    }
                }
                prev_key = Some(key_slice);
                *pos = key_end;
                verify_canonical_dagcbor_item(bytes, pos, depth + 1)?;
            }
            Ok(())
        }
        6 => {
            let tag = read_cbor_uint(bytes, pos, info)?;
            if tag != 42 {
                return Err("unsupported CBOR tag in DAG-CBOR".to_owned());
            }
            let payload_head = *bytes
                .get(*pos)
                .ok_or_else(|| "truncated CBOR CID tag".to_owned())?;
            if (payload_head >> 5) != 2 {
                return Err("DAG-CBOR tag 42 payload must be byte string".to_owned());
            }
            *pos += 1;
            let len = usize::try_from(read_cbor_uint(bytes, pos, payload_head & 0x1f)?)
                .map_err(|_| "CBOR CID tag length overflow".to_owned())?;
            let end = pos
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| "truncated CBOR CID bytes".to_owned())?;
            let cid_bytes = &bytes[*pos..end];
            if cid_bytes.first() != Some(&0x00) {
                return Err("DAG-CBOR tag 42 CID missing identity multibase prefix".to_owned());
            }
            let parsed = Cid::try_from(&cid_bytes[1..])
                .map_err(|_| "invalid CID inside tag 42".to_owned())?;
            if parsed.to_bytes().as_slice() != &cid_bytes[1..] {
                return Err("non-canonical CID bytes inside tag 42".to_owned());
            }
            *pos = end;
            Ok(())
        }
        7 => match info {
            20..=22 => Ok(()),
            _ => Err("floats and undefined are forbidden in ATProto DAG-CBOR".to_owned()),
        },
        _ => Err("invalid CBOR major type".to_owned()),
    }
}

pub fn verify_canonical_dagcbor(bytes: &[u8]) -> Result<(), String> {
    let mut pos = 0usize;
    verify_canonical_dagcbor_item(bytes, &mut pos, 0)?;
    if pos != bytes.len() {
        return Err("trailing bytes after DAG-CBOR block".to_owned());
    }
    Ok(())
}

fn is_valid_tid(tid: &str) -> bool {
    if tid.len() != 13 {
        return false;
    }
    let bytes = tid.as_bytes();
    if !matches!(bytes[0], b'2'..=b'9' | b'a'..=b'j') {
        return false;
    }
    bytes
        .iter()
        .all(|&b| matches!(b, b'2'..=b'7' | b'a'..=b'z'))
}

pub fn parse_verified_car_v1(car_bytes: &[u8]) -> Result<(Cid, HashMap<Cid, Vec<u8>>), String> {
    if car_bytes.is_empty() || car_bytes.len() > MAX_CAR_ARCHIVE_BYTES {
        return Err("CARv1 archive empty or exceeds 4 MiB ceiling".to_owned());
    }
    let mut pos = 0usize;
    let header_len = usize::try_from(read_uvarint(car_bytes, &mut pos)?)
        .map_err(|_| "CAR header length overflow".to_owned())?;
    if !(1..=MAX_CAR_HEADER_BYTES).contains(&header_len) {
        return Err("CAR header length outside [1, 65536]".to_owned());
    }
    let header_end = pos
        .checked_add(header_len)
        .filter(|&end| end <= car_bytes.len())
        .ok_or_else(|| "truncated CAR header".to_owned())?;
    let header_bytes = &car_bytes[pos..header_end];
    pos = header_end;
    verify_canonical_dagcbor(header_bytes)?;
    let header: CarHeader = serde_ipld_dagcbor::from_slice(header_bytes)
        .map_err(|_| "malformed CARv1 header".to_owned())?;
    if header.version != 1 || header.roots.len() != 1 {
        return Err("CARv1 header must have version 1 and exactly 1 root CID".to_owned());
    }
    let root_cid = header.roots[0];

    let mut blocks = HashMap::new();
    while pos < car_bytes.len() {
        if blocks.len() >= MAX_CAR_SECTIONS {
            return Err("CARv1 section count exceeds maximum".to_owned());
        }
        let section_len = usize::try_from(read_uvarint(car_bytes, &mut pos)?)
            .map_err(|_| "CAR section length overflow".to_owned())?;
        if section_len == 0 {
            return Err("empty CAR block section".to_owned());
        }
        let section_end = pos
            .checked_add(section_len)
            .filter(|&end| end <= car_bytes.len())
            .ok_or_else(|| "truncated CAR block section".to_owned())?;
        let section = &car_bytes[pos..section_end];
        pos = section_end;

        let mut reader = Cursor::new(section);
        let block_cid =
            Cid::read_bytes(&mut reader).map_err(|_| "malformed CID in CAR section".to_owned())?;
        let cid_len =
            usize::try_from(reader.position()).map_err(|_| "CAR CID length overflow".to_owned())?;
        let _data_len = section_len
            .checked_sub(cid_len)
            .ok_or_else(|| "CAR section shorter than CID".to_owned())?;
        if block_cid.to_bytes().as_slice() != &section[..cid_len] {
            return Err("non-canonical CID encoding in CAR block".to_owned());
        }
        if block_cid.version() != cid::Version::V1 || block_cid.codec() != DAG_CBOR_CODEC {
            return Err("CAR block must use CIDv1 dag-cbor (0x71)".to_owned());
        }
        let block_data = &section[cid_len..];
        verify_canonical_dagcbor(block_data)?;
        if compute_dagcbor_cid(block_data) != block_cid {
            return Err("CAR block CID digest mismatch".to_owned());
        }
        if blocks.insert(block_cid, block_data.to_vec()).is_some() {
            return Err("duplicate CID block in CAR proof".to_owned());
        }
    }

    if !blocks.contains_key(&root_cid) {
        return Err("CARv1 proof missing root commit block".to_owned());
    }
    Ok((root_cid, blocks))
}

pub fn verify_atproto_v3_commit(
    commit_bytes: &[u8],
    expected_did: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<Cid, String> {
    let commit: SignedAtprotoCommitV3 = serde_ipld_dagcbor::from_slice(commit_bytes)
        .map_err(|_| "malformed ATProto v3 commit".to_owned())?;
    if commit.version != 3 {
        return Err("ATProto commit version must be 3".to_owned());
    }
    if commit.did != expected_did {
        return Err("ATProto commit DID does not match target DID".to_owned());
    }
    if !is_valid_tid(&commit.rev) {
        return Err("ATProto commit rev is not a valid TID".to_owned());
    }
    if commit.sig.len() != 64 {
        return Err("ATProto commit signature must be 64 bytes".to_owned());
    }
    let unsigned = UnsignedAtprotoCommitV3 {
        did: &commit.did,
        version: commit.version,
        data: commit.data,
        rev: &commit.rev,
        prev: commit.prev,
    };
    let unsigned_bytes = serde_ipld_dagcbor::to_vec(&unsigned)
        .map_err(|_| "failed to encode unsigned ATProto commit".to_owned())?;
    if !atproto_key.verify_raw(atproto_key.expected_alg(), &unsigned_bytes, &commit.sig) {
        return Err("ATProto commit signature failed verification under #atproto key".to_owned());
    }
    Ok(commit.data)
}

fn walk_mst_proof(
    blocks: &HashMap<Cid, Vec<u8>>,
    node_cid: Cid,
    target_key: &[u8],
    lower_bound: Option<&[u8]>,
    upper_bound: Option<&[u8]>,
    visited: &mut HashSet<Cid>,
    depth: usize,
) -> Result<Option<Cid>, String> {
    if depth > MST_MAX_DEPTH {
        return Err("MST proof exceeded maximum depth".to_owned());
    }
    if !visited.insert(node_cid) {
        return Err("cycle detected in MST proof".to_owned());
    }
    let node_bytes = blocks
        .get(&node_cid)
        .ok_or_else(|| "missing MST node block in CAR proof".to_owned())?;
    let node: MstNodeData = serde_ipld_dagcbor::from_slice(node_bytes)
        .map_err(|_| "malformed MST node block".to_owned())?;
    if depth > 0 && node.e.is_empty() {
        return Err("non-root MST node cannot be empty".to_owned());
    }

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(node.e.len());
    for (idx, entry) in node.e.iter().enumerate() {
        if entry.k.is_empty() {
            return Err("MST entry key suffix cannot be empty".to_owned());
        }
        let full_key = if idx == 0 {
            if entry.p != 0 {
                return Err("first MST entry must have zero prefix length".to_owned());
            }
            entry.k.clone()
        } else {
            let prev = &keys[idx - 1];
            if entry.p > prev.len() {
                return Err("MST entry prefix length exceeds previous key".to_owned());
            }
            if entry.p < prev.len() && prev[entry.p] == entry.k[0] {
                return Err("non-canonical MST entry prefix length".to_owned());
            }
            let suffix_total = entry
                .p
                .checked_add(entry.k.len())
                .ok_or_else(|| "MST key length overflow".to_owned())?;
            let mut full = Vec::with_capacity(suffix_total);
            full.extend_from_slice(&prev[..entry.p]);
            full.extend_from_slice(&entry.k);
            if prev.as_slice() >= full.as_slice() {
                return Err("MST entries are not in strict lexicographic order".to_owned());
            }
            full
        };
        if std::str::from_utf8(&full_key).is_err() {
            return Err("MST entry key is not valid UTF-8".to_owned());
        }
        if let Some(lo) = lower_bound {
            if full_key.as_slice() <= lo {
                return Err("MST entry key violates parent lower bound".to_owned());
            }
        }
        if let Some(hi) = upper_bound {
            if full_key.as_slice() >= hi {
                return Err("MST entry key violates parent upper bound".to_owned());
            }
        }
        keys.push(full_key);
    }

    if keys.is_empty() {
        return match node.l {
            Some(left_cid) => walk_mst_proof(
                blocks,
                left_cid,
                target_key,
                lower_bound,
                upper_bound,
                visited,
                depth + 1,
            ),
            None => Ok(None),
        };
    }

    match keys.binary_search_by(|candidate| candidate.as_slice().cmp(target_key)) {
        Ok(idx) => Ok(Some(node.e[idx].v)),
        Err(0) => match node.l {
            Some(left_cid) => walk_mst_proof(
                blocks,
                left_cid,
                target_key,
                lower_bound,
                Some(keys[0].as_slice()),
                visited,
                depth + 1,
            ),
            None => Ok(None),
        },
        Err(insert_pos) => {
            let idx = insert_pos - 1;
            let next_upper = keys.get(insert_pos).map(Vec::as_slice).or(upper_bound);
            match node.e[idx].t {
                Some(sub_cid) => walk_mst_proof(
                    blocks,
                    sub_cid,
                    target_key,
                    Some(keys[idx].as_slice()),
                    next_upper,
                    visited,
                    depth + 1,
                ),
                None => Ok(None),
            }
        }
    }
}

/// Verify a CARv1 repository proof (`com.atproto.sync.getRecord`) against `atproto_key`.
///
/// Returns `Ok(Some((record_cid, canonical_record_dagcbor)))` on verified inclusion, or
/// `Ok(None)` on verified MST exclusion.
pub fn verify_car_record_proof(
    car_bytes: &[u8],
    expected_did: &str,
    collection: &str,
    rkey: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<Option<(Cid, Vec<u8>)>, String> {
    let (root_cid, mut blocks) = parse_verified_car_v1(car_bytes)?;
    let commit_bytes = blocks
        .get(&root_cid)
        .ok_or_else(|| "missing root commit block".to_owned())?;
    let mst_root_cid = verify_atproto_v3_commit(commit_bytes, expected_did, atproto_key)?;
    let mst_key = format!("{collection}/{rkey}");
    let mut visited = HashSet::new();
    let Some(record_cid) = walk_mst_proof(
        &blocks,
        mst_root_cid,
        mst_key.as_bytes(),
        None,
        None,
        &mut visited,
        0,
    )?
    else {
        return Ok(None);
    };
    let record_bytes = blocks
        .remove(&record_cid)
        .ok_or_else(|| "MST included record CID but CAR omitted record block".to_owned())?;
    Ok(Some((record_cid, record_bytes)))
}

/// Encode an ATProto JSON record value to canonical DAG-CBOR via `catbird_atproto::types::value::Data`
/// and compute its CIDv1 (`0x71`, SHA-256).
pub fn encode_atproto_json_record_dagcbor(
    value: &serde_json::Value,
) -> Result<(Cid, Vec<u8>), String> {
    let typed: catbird_atproto::types::value::Data = serde_json::from_value(value.clone())
        .map_err(|e| format!("decode ATProto JSON record value: {e}"))?;
    let dagcbor = serde_ipld_dagcbor::to_vec(&typed)
        .map_err(|e| format!("encode ATProto DAG-CBOR record: {e}"))?;
    verify_canonical_dagcbor(&dagcbor)?;
    Ok((compute_dagcbor_cid(&dagcbor), dagcbor))
}

/// Verify that `car_bytes` proves inclusion of `(collection, rkey)` in `expected_did`'s repository
/// under `atproto_key`, and that the proved record matches `expected_value_json` (and optional `expected_cid`).
pub fn verify_car_record_json_match(
    car_bytes: &[u8],
    expected_did: &str,
    collection: &str,
    rkey: &str,
    expected_cid: Option<&str>,
    expected_value_json: &serde_json::Value,
    atproto_key: &SpaceVerifyingKey,
) -> Result<Cid, String> {
    let (proved_cid, proved_dagcbor) =
        verify_car_record_proof(car_bytes, expected_did, collection, rkey, atproto_key)?
            .ok_or_else(|| {
                format!("CARv1 proof excluded {collection}/{rkey} for {expected_did}")
            })?;
    let (expected_calc_cid, expected_dagcbor) =
        encode_atproto_json_record_dagcbor(expected_value_json)?;
    if proved_cid != expected_calc_cid || proved_dagcbor != expected_dagcbor {
        return Err("CARv1 proved record bytes disagree with returned JSON value".to_owned());
    }
    if let Some(cid_str) = expected_cid {
        let parsed_expected =
            Cid::try_from(cid_str).map_err(|_| "invalid expected record CID".to_owned())?;
        if parsed_expected != proved_cid {
            return Err("returned record CID disagrees with CARv1 proved CID".to_owned());
        }
    }
    Ok(proved_cid)
}

/// Build a canonical single-branch CARv1 inclusion (or empty-MST exclusion) proof signed by `signing_key`.
pub fn build_repo_proof_car_v1(
    did: &str,
    rev: &str,
    records: &[(String, Vec<u8>)],
    signing_key: &SpaceSigningKey,
) -> Result<(Cid, Vec<u8>), String> {
    if !is_valid_tid(rev) {
        return Err("invalid TID for repo proof commit".to_owned());
    }
    let mut sorted: Vec<(String, Cid, Vec<u8>)> = Vec::with_capacity(records.len());
    for (path, dagcbor) in records {
        verify_canonical_dagcbor(dagcbor)?;
        sorted.push((path.clone(), compute_dagcbor_cid(dagcbor), dagcbor.clone()));
    }
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("duplicate MST path in repo proof builder".to_owned());
    }

    let mut mst_entries = Vec::with_capacity(sorted.len());
    let mut prev: Option<&[u8]> = None;
    for (path, cid, _) in &sorted {
        let bytes = path.as_bytes();
        let prefix = match prev {
            None => 0,
            Some(p) => p
                .iter()
                .zip(bytes.iter())
                .take_while(|(a, b)| a == b)
                .count(),
        };
        mst_entries.push(MstEntry {
            p: prefix,
            k: bytes[prefix..].to_vec(),
            v: *cid,
            t: None,
        });
        prev = Some(bytes);
    }
    let mst_node = MstNodeData {
        l: None,
        e: mst_entries,
    };
    let mst_bytes =
        serde_ipld_dagcbor::to_vec(&mst_node).map_err(|e| format!("encode MST node: {e}"))?;
    let mst_cid = compute_dagcbor_cid(&mst_bytes);

    let unsigned = UnsignedAtprotoCommitV3 {
        did,
        version: 3,
        data: mst_cid,
        rev,
        prev: None,
    };
    let unsigned_bytes = serde_ipld_dagcbor::to_vec(&unsigned)
        .map_err(|e| format!("encode unsigned commit: {e}"))?;
    let sig = sign_space_key_raw(signing_key, &unsigned_bytes);
    let signed = SignedAtprotoCommitV3Encode {
        did,
        version: 3,
        data: mst_cid,
        rev,
        prev: None,
        sig: &sig,
    };
    let commit_bytes =
        serde_ipld_dagcbor::to_vec(&signed).map_err(|e| format!("encode signed commit: {e}"))?;
    let commit_cid = compute_dagcbor_cid(&commit_bytes);

    let header = CarHeader {
        version: 1,
        roots: vec![commit_cid],
    };
    let header_bytes =
        serde_ipld_dagcbor::to_vec(&header).map_err(|e| format!("encode CAR header: {e}"))?;

    let mut out = Vec::new();
    write_uvarint(&mut out, header_bytes.len() as u64);
    out.extend_from_slice(&header_bytes);

    let mut write_block = |cid: &Cid, data: &[u8]| {
        let cid_bytes = cid.to_bytes();
        write_uvarint(&mut out, (cid_bytes.len() + data.len()) as u64);
        out.extend_from_slice(&cid_bytes);
        out.extend_from_slice(data);
    };
    write_block(&commit_cid, &commit_bytes);
    write_block(&mst_cid, &mst_bytes);
    for (_, cid, data) in &sorted {
        write_block(cid, data);
    }
    Ok((commit_cid, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn car_v1_inclusion_and_exclusion_proofs_verify_and_reject_tampering() {
        let did = "did:plc:proofpeer000000000000000";
        let rev = "3lb2zzzzzzzzz";
        let signing_key = SpaceSigningKey::random_p256();
        let verifying_key = signing_key.verifying_key();
        let wrong_key = SpaceSigningKey::random_p256().verifying_key();

        let record_json = json!({
            "$type": "blue.catbird.chat.device",
            "deviceId": "11111111-1111-4111-8111-111111111111",
            "signingPublicKey": { "$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
            "createdAt": "2026-11-12T00:00:00.000Z",
        });
        let (record_cid, record_cbor) = encode_atproto_json_record_dagcbor(&record_json).unwrap();
        let (_, car) = build_repo_proof_car_v1(
            did,
            rev,
            &[(
                "blue.catbird.chat.device/11111111-1111-4111-8111-111111111111".into(),
                record_cbor,
            )],
            &signing_key,
        )
        .unwrap();

        let verified = verify_car_record_json_match(
            &car,
            did,
            "blue.catbird.chat.device",
            "11111111-1111-4111-8111-111111111111",
            Some(&record_cid.to_string()),
            &record_json,
            &verifying_key,
        )
        .unwrap();
        assert_eq!(verified, record_cid);

        // Verified MST exclusion for an absent rkey returns Ok(None).
        let excluded = verify_car_record_proof(
            &car,
            did,
            "blue.catbird.chat.device",
            "22222222-2222-4222-8222-222222222222",
            &verifying_key,
        )
        .unwrap();
        assert!(excluded.is_none());

        // Wrong #atproto key fails closed.
        assert!(verify_car_record_proof(
            &car,
            did,
            "blue.catbird.chat.device",
            "11111111-1111-4111-8111-111111111111",
            &wrong_key,
        )
        .is_err());

        // Substituted JSON value fails closed even if the CAR itself is valid.
        let tampered_json = json!({
            "$type": "blue.catbird.chat.device",
            "deviceId": "11111111-1111-4111-8111-111111111111",
            "signingPublicKey": { "$bytes": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" },
            "createdAt": "2026-11-12T00:00:00.000Z",
        });
        assert!(verify_car_record_json_match(
            &car,
            did,
            "blue.catbird.chat.device",
            "11111111-1111-4111-8111-111111111111",
            Some(&record_cid.to_string()),
            &tampered_json,
            &verifying_key,
        )
        .is_err());

        // Truncated / malformed varint CAR fails without panicking.
        assert!(parse_verified_car_v1(&[]).is_err());
        assert!(parse_verified_car_v1(&[0xff; 12]).is_err());
        assert!(parse_verified_car_v1(&car[..car.len() - 3]).is_err());
    }
}
