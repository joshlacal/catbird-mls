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

pub fn is_valid_tid(tid: &str) -> bool {
    if tid.len() != 13 {
        return false;
    }
    let bytes = tid.as_bytes();
    if !matches!(bytes[0], b'2'..=b'7' | b'a'..=b'j') {
        return false;
    }
    bytes
        .iter()
        .all(|&b| matches!(b, b'2'..=b'7' | b'a'..=b'z'))
}

fn verified_car_blocks(
    car_bytes: &[u8],
    rooted: bool,
) -> Result<(Option<Cid>, HashMap<Cid, Vec<u8>>), String> {
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
    if header.version != 1 || header.roots.len() != usize::from(rooted) {
        return Err("CARv1 header version or root count mismatch".to_owned());
    }
    let root_cid = header.roots.first().copied();

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

    if root_cid.is_some_and(|root| !blocks.contains_key(&root)) {
        return Err("CARv1 proof missing root commit block".to_owned());
    }
    Ok((root_cid, blocks))
}

pub fn parse_verified_car_v1(car_bytes: &[u8]) -> Result<(Cid, HashMap<Cid, Vec<u8>>), String> {
    let (root, blocks) = verified_car_blocks(car_bytes, true)?;
    Ok((root.ok_or("missing CAR root")?, blocks))
}

pub fn verify_atproto_v3_commit_with_rev(
    commit_bytes: &[u8],
    expected_did: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<(Cid, String), String> {
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
    Ok((commit.data, commit.rev))
}

pub fn verify_atproto_v3_commit(
    commit_bytes: &[u8],
    expected_did: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<Cid, String> {
    verify_atproto_v3_commit_with_rev(commit_bytes, expected_did, atproto_key)
        .map(|(mst_root_cid, _)| mst_root_cid)
}

fn bounded_mst_keys(
    node: &MstNodeData,
    lower_bound: Option<&[u8]>,
    upper_bound: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(node.e.len());
    for (idx, entry) in node.e.iter().enumerate() {
        if entry.p.saturating_add(entry.k.len()) > 1024 {
            return Err("MST record path exceeds the repository key limit".into());
        }
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

    Ok(keys)
}

/// Enumerate every revocation key under the signed commit identified by the
/// authoritative PDS head. Each intersecting subtree must be present, even
/// when no records are found. Numeric rev equality without CID equality
/// cannot authenticate the same repository revision.
pub fn verify_revocation_inventory(
    car: &[u8],
    did: &str,
    head_cid: &str,
    head_rev: &str,
    key: &SpaceVerifyingKey,
) -> Result<Vec<(String, String)>, String> {
    let (root, blocks) = parse_verified_car_v1(car)?;
    let mut inventory = RevocationInventory::new(did, head_cid, head_rev, key)?;
    if root != inventory.head {
        return Err("snapshot does not match current head".into());
    }
    while let Some(cid) = inventory.expected() {
        inventory.consume(
            cid,
            blocks
                .get(&cid)
                .ok_or("missing revocation inventory subtree")?,
        )?;
    }
    inventory.finish()
}

type InventorySubtree = (Cid, Option<Vec<u8>>, Option<Vec<u8>>, usize);

/// Verify a collection range by fetching its signed head and only the MST blocks that overlap it.
/// Other collections and record payloads do not count against the proof budget.
pub struct RevocationInventory {
    did: String,
    head: Cid,
    rev: String,
    key: SpaceVerifyingKey,
    awaiting_commit: bool,
    failed: bool,
    pending: Vec<InventorySubtree>,
    visited: HashSet<Cid>,
    entries: Vec<(String, String)>,
    bytes: usize,
}

impl RevocationInventory {
    pub fn new(
        did: &str,
        head_cid: &str,
        head_rev: &str,
        key: &SpaceVerifyingKey,
    ) -> Result<Self, String> {
        let head: Cid = head_cid
            .parse()
            .map_err(|_| "invalid repository head CID")?;
        if head.to_string() != head_cid || !is_valid_tid(head_rev) {
            return Err("invalid repository head".into());
        }
        Ok(Self {
            did: did.to_owned(),
            head,
            rev: head_rev.to_owned(),
            key: key.clone(),
            awaiting_commit: true,
            failed: false,
            pending: vec![],
            visited: HashSet::new(),
            entries: vec![],
            bytes: 0,
        })
    }

    fn expected(&self) -> Option<Cid> {
        if self.awaiting_commit {
            Some(self.head)
        } else {
            self.pending.last().map(|item| item.0)
        }
    }

    pub fn next_block(&self) -> Option<String> {
        self.expected().map(|cid| cid.to_string())
    }

    /// Accept the rootless CAR returned by getBlocks for exactly the requested identifier.
    pub fn ingest(&mut self, car: &[u8]) -> Result<(), String> {
        if self.failed {
            return Err("inventory verification has failed".into());
        }
        self.failed = true;
        let expected = self
            .expected()
            .ok_or("unexpected block after complete inventory")?;
        let (_, blocks) = verified_car_blocks(car, false)?;
        if blocks.len() != 1 {
            return Err("expected one requested repository block".into());
        }
        self.consume(
            expected,
            blocks
                .get(&expected)
                .ok_or("missing requested repository block")?,
        )?;
        self.failed = false;
        Ok(())
    }

    fn consume(&mut self, cid: Cid, raw: &[u8]) -> Result<(), String> {
        self.bytes = self
            .bytes
            .checked_add(raw.len())
            .ok_or("overflow in repository inventory")?;
        if self.bytes > MAX_CAR_ARCHIVE_BYTES
            || self.visited.len() >= MAX_CAR_SECTIONS
            || !self.visited.insert(cid)
        {
            return Err("repository inventory too large or contains a repeated subtree".into());
        }
        if self.awaiting_commit {
            let (tree_root, rev) = verify_atproto_v3_commit_with_rev(raw, &self.did, &self.key)?;
            if rev != self.rev {
                return Err("repository snapshot does not match current revision".into());
            }
            self.awaiting_commit = false;
            self.pending.push((tree_root, None, None, 0));
            return Ok(());
        }
        let (_, lo, hi, depth) = self.pending.pop().ok_or("unexpected inventory node")?;
        if depth > MST_MAX_DEPTH {
            return Err("inventory tree exceeds depth bound".into());
        }
        const PREFIX: &[u8] = b"blue.catbird.chat.deviceRevocation/";
        // '/' + 1 encloses exactly the keys with this collection prefix.
        const END: &[u8] = b"blue.catbird.chat.deviceRevocation0";
        let node: MstNodeData = serde_ipld_dagcbor::from_slice(raw)
            .map_err(|_| "invalid revocation inventory tree node")?;
        let keys = bounded_mst_keys(&node, lo.as_deref(), hi.as_deref())?;
        let children = std::iter::once(node.l).chain(node.e.iter().map(|entry| entry.t));
        for (idx, child) in children.enumerate() {
            let left = idx.checked_sub(1).and_then(|i| keys.get(i)).or(lo.as_ref());
            let right = keys.get(idx).or(hi.as_ref());
            if let Some(child) = child {
                if left.is_none_or(|k| k.as_slice() < END)
                    && right.is_none_or(|k| k.as_slice() > PREFIX)
                {
                    self.pending
                        .push((child, left.cloned(), right.cloned(), depth + 1));
                }
            }
        }
        for (path, entry) in keys.iter().zip(&node.e) {
            if let Some(raw_key) = path.strip_prefix(PREFIX) {
                let rkey = std::str::from_utf8(raw_key).map_err(|_| "invalid revocation key")?;
                if rkey.is_empty() || rkey.contains('/') {
                    return Err("invalid revocation key".into());
                }
                self.entries.push((rkey.to_owned(), entry.v.to_string()));
            }
        }

        Ok(())
    }

    pub fn finish(mut self) -> Result<Vec<(String, String)>, String> {
        if self.failed || self.expected().is_some() {
            return Err("incomplete repository inventory".into());
        }
        self.entries.sort_unstable();
        Ok(self.entries)
    }
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
    if depth > 0 && node.e.is_empty() && node.l.is_none() {
        return Err("non-root MST node cannot be empty".to_owned());
    }

    let keys = bounded_mst_keys(&node, lower_bound, upper_bound)?;
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

/// Verify the same record under today's repository key after a signing-key rotation.
/// The historical CAR supplies only a content identifier. Authority comes from
/// a fresh, independently fetched and signature-verified proof of identical bytes.
pub fn verify_reanchored_record(
    historical_car: &[u8],
    current_car: &[u8],
    did: &str,
    collection: &str,
    rkey: &str,
    current_key: &SpaceVerifyingKey,
) -> Result<String, String> {
    let (current, rev) =
        verify_car_record_proof_with_rev(current_car, did, collection, rkey, current_key)?;
    let (cid, _) = current.ok_or("current repository excludes the historical record")?;
    let (root, blocks) = parse_verified_car_v1(historical_car)?;
    let old: SignedAtprotoCommitV3 = serde_ipld_dagcbor::from_slice(&blocks[&root])
        .map_err(|_| "malformed historical repository commit")?;
    if old.did != did || old.version != 3 {
        return Err("historical repository DID or format mismatch".into());
    }
    let path = format!("{collection}/{rkey}");
    let old_cid = walk_mst_proof(
        &blocks,
        old.data,
        path.as_bytes(),
        None,
        None,
        &mut HashSet::new(),
        0,
    )?;
    if old_cid != Some(cid) || !blocks.contains_key(&cid) {
        return Err("current repository record differs from historical proof".into());
    }
    Ok(rev)
}

/// Verify a CARv1 repository proof (`com.atproto.sync.getRecord`) against `atproto_key`,
/// returning both the inclusion/exclusion result and the signed commit `rev` TID.
pub fn verify_car_record_proof_with_rev(
    car_bytes: &[u8],
    expected_did: &str,
    collection: &str,
    rkey: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<(Option<(Cid, Vec<u8>)>, String), String> {
    let (root_cid, mut blocks) = parse_verified_car_v1(car_bytes)?;
    let commit_bytes = blocks
        .get(&root_cid)
        .ok_or_else(|| "missing root commit block".to_owned())?;
    let (mst_root_cid, commit_rev) =
        verify_atproto_v3_commit_with_rev(commit_bytes, expected_did, atproto_key)?;
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
        return Ok((None, commit_rev));
    };
    let record_bytes = blocks
        .remove(&record_cid)
        .ok_or_else(|| "MST included record CID but CAR omitted record block".to_owned())?;
    Ok((Some((record_cid, record_bytes)), commit_rev))
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
    verify_car_record_proof_with_rev(car_bytes, expected_did, collection, rkey, atproto_key)
        .map(|(proved, _)| proved)
}

/// Encode an ATProto JSON record value to canonical DAG-CBOR via [`petrel_core::Value`]
/// and compute its CIDv1 (`0x71`, SHA-256).
pub fn encode_atproto_json_record_dagcbor(
    value: &serde_json::Value,
) -> Result<(Cid, Vec<u8>), String> {
    let raw = serde_json::to_vec(value).map_err(|e| format!("render ATProto JSON record: {e}"))?;
    let typed: petrel_core::Value = petrel_core::from_json(&raw)
        .map_err(|e| format!("decode ATProto JSON record value: {e}"))?;
    let dagcbor = petrel_core::to_dag_cbor(&typed)
        .map_err(|e| format!("encode ATProto DAG-CBOR record: {e}"))?;
    verify_canonical_dagcbor(&dagcbor)?;
    Ok((compute_dagcbor_cid(&dagcbor), dagcbor))
}

/// Verify that `car_bytes` proves inclusion of `(collection, rkey)` in `expected_did`'s repository
/// under `atproto_key`, that the proved record matches `expected_value_json` (and optional `expected_cid`),
/// and return `(proved_cid, signed_commit_rev)`.
pub fn verify_car_record_json_match_with_rev(
    car_bytes: &[u8],
    expected_did: &str,
    collection: &str,
    rkey: &str,
    expected_cid: Option<&str>,
    expected_value_json: &serde_json::Value,
    atproto_key: &SpaceVerifyingKey,
) -> Result<(Cid, String), String> {
    let (proved_opt, commit_rev) =
        verify_car_record_proof_with_rev(car_bytes, expected_did, collection, rkey, atproto_key)?;
    let (proved_cid, proved_dagcbor) = proved_opt
        .ok_or_else(|| format!("CARv1 proof excluded {collection}/{rkey} for {expected_did}"))?;
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
    Ok((proved_cid, commit_rev))
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
    verify_car_record_json_match_with_rev(
        car_bytes,
        expected_did,
        collection,
        rkey,
        expected_cid,
        expected_value_json,
        atproto_key,
    )
    .map(|(cid, _)| cid)
}

/// Persist and enforce a monotonic signed commit `rev` floor per target DID so a stale
/// repository snapshot cannot replay retired records below the highest verified commit revision.
#[cfg(not(target_arch = "wasm32"))]
pub fn observe_pds_repo_rev_floor(
    db: &crate::storage::MlsAccountDb,
    did: &str,
    rev: &str,
    now_ms: i64,
) -> Result<(), String> {
    if !is_valid_tid(rev) {
        return Err(format!("invalid ATProto commit rev TID `{rev}`"));
    }
    let meta_key = format!("pds_repo_rev_floor:{did}");
    db.write_tx(|tx| {
        if let Some(existing) = tx.get_account_meta(&meta_key)? {
            if !is_valid_tid(&existing) {
                return Err(crate::error::MLSError::Cryptography(format!(
                    "corrupt pinned repository commit rev floor for `{did}`"
                )));
            }
            if rev < existing.as_str() {
                return Err(crate::error::MLSError::Cryptography(format!(
                    "ATProto commit rev rolled back for `{did}`: `{rev}` < `{existing}`"
                )));
            }
            if rev > existing.as_str() {
                tx.put_account_meta(&meta_key, rev, now_ms)?;
            }
        } else {
            tx.put_account_meta(&meta_key, rev, now_ms)?;
        }
        Ok(())
    })
    .map_err(|e| e.to_string())
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

    let mut written = HashSet::new();
    let mut write_block = |cid: &Cid, data: &[u8]| {
        if !written.insert(*cid) {
            return;
        }
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

    fn block_response(cid: Cid, block: &[u8]) -> Vec<u8> {
        let header = serde_ipld_dagcbor::to_vec(&CarHeader {
            version: 1,
            roots: vec![],
        })
        .unwrap();
        let mut response = vec![];
        write_uvarint(&mut response, header.len() as u64);
        response.extend(header);
        let cid_bytes = cid.to_bytes();
        write_uvarint(&mut response, (cid_bytes.len() + block.len()) as u64);
        response.extend(cid_bytes);
        response.extend(block);
        response
    }

    #[test]
    fn range_inventory_requests_every_intersecting_subtree_and_skips_its_neighbors() {
        let did = "did:plc:inventory";
        let rev = "3lb2zzzzzzzzz";
        let signer = SpaceSigningKey::random_p256();
        let omitted = compute_dagcbor_cid(&[0]);
        let record = compute_dagcbor_cid(&[1]);
        let entry = |path: &str, child| MstEntry {
            p: 0,
            k: path.as_bytes().to_vec(),
            v: record,
            t: child,
        };
        let leaf = serde_ipld_dagcbor::to_vec(&MstNodeData {
            l: None,
            e: vec![entry("blue.catbird.chat.deviceRevocation/first", None)],
        })
        .unwrap();
        let leaf_cid = compute_dagcbor_cid(&leaf);
        let tree = serde_ipld_dagcbor::to_vec(&MstNodeData {
            l: Some(omitted),
            e: vec![
                entry("app.bsky.feed.post/before", Some(leaf_cid)),
                entry("com.atproto.test/after", Some(omitted)),
            ],
        })
        .unwrap();
        let data = compute_dagcbor_cid(&tree);
        let unsigned = UnsignedAtprotoCommitV3 {
            did,
            version: 3,
            data,
            rev,
            prev: None,
        };
        let signature =
            sign_space_key_raw(&signer, &serde_ipld_dagcbor::to_vec(&unsigned).unwrap());
        let commit = serde_ipld_dagcbor::to_vec(&SignedAtprotoCommitV3Encode {
            did,
            version: 3,
            data,
            rev,
            prev: None,
            sig: &signature,
        })
        .unwrap();
        let head = compute_dagcbor_cid(&commit);
        let build = || {
            let mut inventory =
                RevocationInventory::new(did, &head.to_string(), rev, &signer.verifying_key())
                    .unwrap();
            inventory.ingest(&block_response(head, &commit)).unwrap();
            assert_eq!(inventory.next_block(), Some(data.to_string()));
            inventory.ingest(&block_response(data, &tree)).unwrap();
            assert_eq!(inventory.next_block(), Some(leaf_cid.to_string()));
            inventory
        };
        assert!(
            build().finish().is_err(),
            "the in-range child must be fetched"
        );
        let mut complete = build();
        complete.ingest(&block_response(leaf_cid, &leaf)).unwrap();
        assert_eq!(
            complete.finish().unwrap(),
            vec![("first".into(), record.to_string())]
        );
    }

    #[test]
    fn inventory_requires_current_signed_head_and_covers_empty_collections() {
        let did = "did:plc:inventory";
        let rev = "3lb2zzzzzzzzz";
        let key = SpaceSigningKey::random_p256();
        let (record, bytes) = encode_atproto_json_record_dagcbor(&json!({"value": "one"})).unwrap();
        let (root, car) = build_repo_proof_car_v1(did, rev, &[], &key).unwrap();
        let verify = |car: &[u8], head: &Cid| {
            verify_revocation_inventory(car, did, &head.to_string(), rev, &key.verifying_key())
        };
        assert!(verify(&car, &root).unwrap().is_empty());
        let (filled, snapshot) = build_repo_proof_car_v1(
            did,
            rev,
            &[(
                "blue.catbird.chat.deviceRevocation/device".into(),
                bytes.clone(),
            )],
            &key,
        )
        .unwrap();
        assert_eq!(
            verify(&snapshot, &filled).unwrap(),
            vec![("device".into(), record.to_string())]
        );
        assert!(verify(&car, &filled).is_err());
        let (root_block, mut blocks) = parse_verified_car_v1(&snapshot).unwrap();
        let mut partial =
            RevocationInventory::new(did, &filled.to_string(), rev, &key.verifying_key()).unwrap();
        let mut count = 0;
        while let Some(requested) = partial.next_block() {
            let cid: Cid = requested.parse().unwrap();
            let block = &blocks[&cid];
            partial.ingest(&block_response(cid, block)).unwrap();
            count += 1;
        }
        assert_eq!(
            count, 2,
            "only head and MST node fetched, never record payloads"
        );
        assert_eq!(
            partial.finish().unwrap(),
            verify(&snapshot, &filled).unwrap()
        );
        let commit = blocks.remove(&root_block).unwrap();
        let mut header_only = Vec::new();
        let header = serde_ipld_dagcbor::to_vec(&CarHeader {
            version: 1,
            roots: vec![root_block],
        })
        .unwrap();
        write_uvarint(&mut header_only, header.len() as u64);
        header_only.extend(header);
        let cid_bytes = root_block.to_bytes();
        write_uvarint(&mut header_only, (cid_bytes.len() + commit.len()) as u64);
        header_only.extend(cid_bytes);
        header_only.extend(commit);
        assert!(verify(&header_only, &root_block).is_err());
        let next = SpaceSigningKey::random_p256();
        let (_, reanchored) = build_repo_proof_car_v1(
            did,
            rev,
            &[("blue.catbird.chat.deviceRevocation/device".into(), bytes)],
            &next,
        )
        .unwrap();
        assert_eq!(
            verify_reanchored_record(
                &snapshot,
                &reanchored,
                did,
                "blue.catbird.chat.deviceRevocation",
                "device",
                &next.verifying_key()
            )
            .unwrap(),
            rev
        );
        assert!(verify_reanchored_record(
            &snapshot,
            &car,
            did,
            "blue.catbird.chat.deviceRevocation",
            "device",
            &key.verifying_key()
        )
        .is_err());
    }

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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn car_v1_commit_rev_is_extracted_and_monotonic_floor_rejects_rollback() {
        let did = "did:plc:proofpeer222222222222222";
        let signing_key = SpaceSigningKey::random_p256();
        let verifying_key = signing_key.verifying_key();
        let record_json = json!({
            "$type": "blue.catbird.chat.device",
            "deviceId": "11111111-1111-4111-8111-111111111111",
            "signingPublicKey": { "$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
            "createdAt": "2026-11-12T00:00:00.000Z",
        });
        let (record_cid, record_cbor) = encode_atproto_json_record_dagcbor(&record_json).unwrap();
        let entries = [(
            "blue.catbird.chat.device/11111111-1111-4111-8111-111111111111".into(),
            record_cbor,
        )];
        let (_, car_v1) =
            build_repo_proof_car_v1(did, "3lb2zzzzzzzzd", &entries, &signing_key).unwrap();
        let (_, car_v2) =
            build_repo_proof_car_v1(did, "3lb2zzzzzzzzf", &entries, &signing_key).unwrap();
        let (_, car_old) =
            build_repo_proof_car_v1(did, "3lb2zzzzzzzzb", &entries, &signing_key).unwrap();

        let (cid1, rev1) = verify_car_record_json_match_with_rev(
            &car_v1,
            did,
            "blue.catbird.chat.device",
            "11111111-1111-4111-8111-111111111111",
            Some(&record_cid.to_string()),
            &record_json,
            &verifying_key,
        )
        .unwrap();
        assert_eq!(cid1, record_cid);
        assert_eq!(rev1, "3lb2zzzzzzzzd");

        let db = crate::storage::MlsAccountDb::open_in_memory_for_test().unwrap();
        observe_pds_repo_rev_floor(&db, did, &rev1, 1000).unwrap();
        // Equal revision from the same commit snapshot remains valid.
        observe_pds_repo_rev_floor(&db, did, &rev1, 1001).unwrap();

        // Higher revision advances the pinned floor.
        let (_, rev2) = verify_car_record_json_match_with_rev(
            &car_v2,
            did,
            "blue.catbird.chat.device",
            "11111111-1111-4111-8111-111111111111",
            Some(&record_cid.to_string()),
            &record_json,
            &verifying_key,
        )
        .unwrap();
        assert_eq!(rev2, "3lb2zzzzzzzzf");
        observe_pds_repo_rev_floor(&db, did, &rev2, 1002).unwrap();

        // Stale CARv1 proof signed at an older commit rev is rejected by the monotonic floor.
        let (_, rev_old) = verify_car_record_json_match_with_rev(
            &car_old,
            did,
            "blue.catbird.chat.device",
            "11111111-1111-4111-8111-111111111111",
            Some(&record_cid.to_string()),
            &record_json,
            &verifying_key,
        )
        .unwrap();
        assert_eq!(rev_old, "3lb2zzzzzzzzb");
        assert!(observe_pds_repo_rev_floor(&db, did, &rev_old, 1003).is_err());
        assert!(observe_pds_repo_rev_floor(&db, did, "~~~~", 1004).is_err());
    }
}
