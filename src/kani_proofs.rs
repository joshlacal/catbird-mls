//! Bounded formal verification (`#[cfg(kani)]`) harnesses and companion property
//! checks for Task 6 cryptographic and framing invariants:
//!
//! 1. `GF(32)` recovery code ECC (`labyrinth::recovery_code::RecoveryCode`):
//!    3-column linear independence over `GF(32)`, round-trip encoding/parsing,
//!    single-symbol substitution rejection, and triple-erasure unique recovery.
//! 2. `I13` sequencer receipt framing (`labyrinth_protocol::receipt`):
//!    injective length-prefixed signing transcript (`canonical_signing_bytes`),
//!    lossless transcript decoding, and panic-free structural/key-generation checks.
//! 3. 96-hex SQLCipher raw key + salt specification (`I8`):
//!    `x'<64-lowercase-hex-key><32-lowercase-hex-salt>'` formatting, strict
//!    canonical parsing without truncation or quote injection, and panic freedom.
//! 4. PADMÉ padding (`labyrinth::padding`) and epoch / send-counter bounds:
//!    `padme_len` overflow/overhead/monotonicity/idempotence across `0..=u32::MAX`,
//!    strict `pad`/`unpad` canonical round-trip, and `u64`/`i64` epoch + counter
//!    monotonicity without arithmetic wraparound.

#![allow(unexpected_cfgs)]

use thiserror::Error;

#[cfg(test)]
use crate::client::chat_wire::{next_send_counter, verify_next_peer_send_counter};
#[cfg(test)]
use crate::storage::derive_sqlcipher_96hex_key_spec;
use labyrinth_protocol::limits::{ARCHIVE_COMMITMENT_LEN, GROUP_ID_LEN};
#[cfg(test)]
use labyrinth_protocol::receipt::receipt_key_generation;
use labyrinth_protocol::receipt::SequencerReceiptPayload;
use labyrinth_protocol::transcripts::RECEIPT_DOMAIN_V2;

/// Exact ASCII byte length of `"x'<64-hex-key><32-hex-salt>'"` (`2 + 64 + 32 + 1`).
pub const SQLCIPHER_96HEX_SPEC_LEN: usize = 99;

/// Maximum safe JavaScript / DAG-CBOR integer send counter (`2^53 - 1`).
pub const MAX_SAFE_SEND_COUNTER: u64 = 9_007_199_254_740_991;

/// Validation error when parsing a 96-hex SQLCipher `PRAGMA key` literal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SqlCipherKeySpecError {
    #[error("SQLCipher key literal must be exactly 99 ASCII bytes, got {0}")]
    WrongLength(usize),
    #[error("SQLCipher key literal must have framing x'<96-lowercase-hex>'")]
    BadFraming,
    #[error("SQLCipher key literal contains non-canonical or non-hex byte at offset {0}")]
    InvalidHexByte(usize),
}

#[inline]
fn decode_lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[inline]
fn encode_lowercase_hex_nibble(nibble: u8) -> u8 {
    debug_assert!(nibble < 16);
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

/// Encode `(db_key_32, salt_16)` into the canonical 99-byte ASCII SQLCipher
/// literal `"x'<64-lowercase-hex><32-lowercase-hex>'"` (`I8`) without heap allocation.
pub fn encode_sqlcipher_96hex_key_spec_bytes(
    db_key_32: &[u8; 32],
    salt_16: &[u8; 16],
) -> [u8; SQLCIPHER_96HEX_SPEC_LEN] {
    let mut out = [0u8; SQLCIPHER_96HEX_SPEC_LEN];
    out[0] = b'x';
    out[1] = b'\'';
    let mut idx = 0;
    while idx < 32 {
        let byte = db_key_32[idx];
        out[2 + idx * 2] = encode_lowercase_hex_nibble(byte >> 4);
        out[2 + idx * 2 + 1] = encode_lowercase_hex_nibble(byte & 0x0f);
        idx += 1;
    }
    let mut sidx = 0;
    while sidx < 16 {
        let byte = salt_16[sidx];
        out[66 + sidx * 2] = encode_lowercase_hex_nibble(byte >> 4);
        out[66 + sidx * 2 + 1] = encode_lowercase_hex_nibble(byte & 0x0f);
        sidx += 1;
    }
    out[98] = b'\'';
    out
}

/// Format `(db_key_32, salt_16)` into the canonical 99-byte SQLCipher literal
/// `"x'<64-lowercase-hex><32-lowercase-hex>'"` (`I8`).
pub fn format_sqlcipher_96hex_key_spec(db_key_32: &[u8; 32], salt_16: &[u8; 16]) -> String {
    let bytes = encode_sqlcipher_96hex_key_spec_bytes(db_key_32, salt_16);
    String::from_utf8(bytes.to_vec()).expect("canonical SQLCipher literal is ASCII")
}

/// Strictly parse raw bytes of a canonical 99-byte SQLCipher `"x'<64-hex><32-hex>'"`
/// literal into `(db_key_32, salt_16)`, rejecting truncation, trailing bytes,
/// uppercase hex, embedded quotes, or NUL bytes.
pub fn parse_sqlcipher_96hex_key_spec_bytes(
    bytes: &[u8],
) -> Result<([u8; 32], [u8; 16]), SqlCipherKeySpecError> {
    if bytes.len() != SQLCIPHER_96HEX_SPEC_LEN {
        return Err(SqlCipherKeySpecError::WrongLength(bytes.len()));
    }
    if bytes[0] != b'x' || bytes[1] != b'\'' || bytes[98] != b'\'' {
        return Err(SqlCipherKeySpecError::BadFraming);
    }

    let mut key = [0u8; 32];
    let mut idx = 0;
    while idx < 32 {
        let hi_pos = 2 + idx * 2;
        let lo_pos = hi_pos + 1;
        let hi = decode_lowercase_hex_nibble(bytes[hi_pos])
            .ok_or(SqlCipherKeySpecError::InvalidHexByte(hi_pos))?;
        let lo = decode_lowercase_hex_nibble(bytes[lo_pos])
            .ok_or(SqlCipherKeySpecError::InvalidHexByte(lo_pos))?;
        key[idx] = (hi << 4) | lo;
        idx += 1;
    }

    let mut salt = [0u8; 16];
    let mut sidx = 0;
    while sidx < 16 {
        let hi_pos = 66 + sidx * 2;
        let lo_pos = hi_pos + 1;
        let hi = decode_lowercase_hex_nibble(bytes[hi_pos])
            .ok_or(SqlCipherKeySpecError::InvalidHexByte(hi_pos))?;
        let lo = decode_lowercase_hex_nibble(bytes[lo_pos])
            .ok_or(SqlCipherKeySpecError::InvalidHexByte(lo_pos))?;
        salt[sidx] = (hi << 4) | lo;
        sidx += 1;
    }

    Ok((key, salt))
}

/// Strictly parse a canonical 99-byte SQLCipher `"x'<64-hex><32-hex>'"` literal into
/// `(db_key_32, salt_16)`, rejecting truncation, trailing bytes, uppercase hex,
/// embedded quotes, or NUL bytes.
pub fn parse_sqlcipher_96hex_key_spec(
    spec: &str,
) -> Result<([u8; 32], [u8; 16]), SqlCipherKeySpecError> {
    parse_sqlcipher_96hex_key_spec_bytes(spec.as_bytes())
}

fn read_u32_len_prefixed_at<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len_end = pos.checked_add(4)?;
    if len_end > buf.len() {
        return None;
    }
    let len = usize::try_from(u32::from_be_bytes([
        buf[*pos],
        buf[*pos + 1],
        buf[*pos + 2],
        buf[*pos + 3],
    ]))
    .ok()?;
    let field_end = len_end.checked_add(len)?;
    if field_end > buf.len() {
        return None;
    }
    *pos = field_end;
    Some(&buf[len_end..field_end])
}

fn read_fixed_bytes_at<const N: usize>(buf: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    let end = pos.checked_add(N)?;
    if end > buf.len() {
        return None;
    }
    let mut out = [0u8; N];
    let mut idx = 0;
    while idx < N {
        out[idx] = buf[*pos + idx];
        idx += 1;
    }
    *pos = end;
    Some(out)
}

/// Zero-copy borrowed view of a decoded [`SequencerReceiptPayload::canonical_signing_bytes`]
/// transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedReceiptTranscript<'a> {
    pub sequencer_did: &'a [u8],
    pub key_id: &'a [u8],
    pub conversation_id: &'a [u8],
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub sender_device_did_url: &'a [u8],
    pub entry_id: &'a [u8],
    pub archive_commitment: [u8; ARCHIVE_COMMITMENT_LEN],
    pub seq: u64,
    pub issued_at_ms: i64,
}

/// Zero-allocation parser for [`SequencerReceiptPayload::canonical_signing_bytes`].
pub fn decode_canonical_receipt_signing_slices(
    transcript: &[u8],
) -> Option<DecodedReceiptTranscript<'_>> {
    if transcript.len() < RECEIPT_DOMAIN_V2.len() {
        return None;
    }
    let mut d = 0;
    while d < RECEIPT_DOMAIN_V2.len() {
        if transcript[d] != RECEIPT_DOMAIN_V2[d] {
            return None;
        }
        d += 1;
    }
    let mut pos = RECEIPT_DOMAIN_V2.len();
    let sequencer_did = read_u32_len_prefixed_at(transcript, &mut pos)?;
    let key_id = read_u32_len_prefixed_at(transcript, &mut pos)?;
    let conversation_id = read_u32_len_prefixed_at(transcript, &mut pos)?;
    let group_id = read_u32_len_prefixed_at(transcript, &mut pos)?;
    let epoch = u64::from_be_bytes(read_fixed_bytes_at::<8>(transcript, &mut pos)?);
    let sender_device_did_url = read_u32_len_prefixed_at(transcript, &mut pos)?;
    let entry_id = read_u32_len_prefixed_at(transcript, &mut pos)?;
    let archive_commitment = read_fixed_bytes_at::<ARCHIVE_COMMITMENT_LEN>(transcript, &mut pos)?;
    let seq = u64::from_be_bytes(read_fixed_bytes_at::<8>(transcript, &mut pos)?);
    let issued_at_ms = i64::from_be_bytes(read_fixed_bytes_at::<8>(transcript, &mut pos)?);
    if pos != transcript.len() {
        return None;
    }

    Some(DecodedReceiptTranscript {
        sequencer_did,
        key_id,
        conversation_id,
        group_id,
        epoch,
        sender_device_did_url,
        entry_id,
        archive_commitment,
        seq,
        issued_at_ms,
    })
}

fn write_u32_len_prefixed_at(out: &mut [u8], pos: &mut usize, field: &[u8]) -> Option<()> {
    let len_u32 = u32::try_from(field.len()).ok()?;
    let len_end = pos.checked_add(4)?;
    let field_end = len_end.checked_add(field.len())?;
    if field_end > out.len() {
        return None;
    }
    let be = len_u32.to_be_bytes();
    out[*pos] = be[0];
    out[*pos + 1] = be[1];
    out[*pos + 2] = be[2];
    out[*pos + 3] = be[3];
    let mut i = 0;
    while i < field.len() {
        out[len_end + i] = field[i];
        i += 1;
    }
    *pos = field_end;
    Some(())
}

fn write_fixed_bytes_at(out: &mut [u8], pos: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = pos.checked_add(bytes.len())?;
    if end > out.len() {
        return None;
    }
    let mut i = 0;
    while i < bytes.len() {
        out[*pos + i] = bytes[i];
        i += 1;
    }
    *pos = end;
    Some(())
}

/// Zero-allocation stack encoder matching [`SequencerReceiptPayload::canonical_signing_bytes`]
/// byte-for-byte.
pub fn encode_canonical_receipt_signing_slices_into(
    view: &DecodedReceiptTranscript<'_>,
    out: &mut [u8],
) -> Option<usize> {
    let mut pos = 0usize;
    write_fixed_bytes_at(out, &mut pos, RECEIPT_DOMAIN_V2)?;
    write_u32_len_prefixed_at(out, &mut pos, view.sequencer_did)?;
    write_u32_len_prefixed_at(out, &mut pos, view.key_id)?;
    write_u32_len_prefixed_at(out, &mut pos, view.conversation_id)?;
    write_u32_len_prefixed_at(out, &mut pos, view.group_id)?;
    write_fixed_bytes_at(out, &mut pos, &view.epoch.to_be_bytes())?;
    write_u32_len_prefixed_at(out, &mut pos, view.sender_device_did_url)?;
    write_u32_len_prefixed_at(out, &mut pos, view.entry_id)?;
    write_fixed_bytes_at(out, &mut pos, &view.archive_commitment)?;
    write_fixed_bytes_at(out, &mut pos, &view.seq.to_be_bytes())?;
    write_fixed_bytes_at(out, &mut pos, &view.issued_at_ms.to_be_bytes())?;
    Some(pos)
}

/// Zero-allocation structural validator matching [`SequencerReceiptPayload::validate_structure`].
pub fn validate_i13_receipt_structure_slices(
    sequencer_did: &[u8],
    conversation_id: &[u8],
    group_id_len: usize,
    sender_device_did_url: &[u8],
    entry_id: &[u8],
    seq: u64,
    issued_at_ms: i64,
) -> bool {
    let has_did_prefix = sequencer_did.len() >= 8
        && (&sequencer_did[..8] == b"did:web:" || &sequencer_did[..8] == b"did:plc:");
    if !has_did_prefix {
        return false;
    }
    let mut i = 0;
    while i < sequencer_did.len() {
        if sequencer_did[i] == b'#' {
            return false;
        }
        i += 1;
    }
    if conversation_id.is_empty()
        || entry_id.is_empty()
        || group_id_len != GROUP_ID_LEN
        || seq == 0
        || issued_at_ms < 0
    {
        return false;
    }
    let mut hash_count = 0usize;
    let mut first_hash = 0usize;
    let mut j = 0;
    while j < sender_device_did_url.len() {
        if sender_device_did_url[j] == b'#' {
            if hash_count == 0 {
                first_hash = j;
            }
            hash_count += 1;
        }
        j += 1;
    }
    hash_count == 1 && first_hash > 0 && first_hash + 1 < sender_device_did_url.len()
}

/// Zero-allocation receipt verification-method parser matching
/// [`labyrinth_protocol::receipt::receipt_key_generation`].
pub fn parse_i13_receipt_key_generation_slice(sequencer_did: &[u8], key_id: &[u8]) -> Option<u64> {
    const SEP: &[u8] = b"#mls-receipt-";
    let prefix_end = sequencer_did.len().checked_add(SEP.len())?;
    if key_id.len() <= prefix_end {
        return None;
    }
    let mut i = 0;
    while i < sequencer_did.len() {
        if key_id[i] != sequencer_did[i] {
            return None;
        }
        i += 1;
    }
    let mut s = 0;
    while s < SEP.len() {
        if key_id[sequencer_did.len() + s] != SEP[s] {
            return None;
        }
        s += 1;
    }
    let digits = &key_id[prefix_end..];
    if digits[0] == b'0' {
        return None;
    }
    let mut acc = 0u64;
    let mut k = 0;
    while k < digits.len() {
        let d = digits[k];
        if !d.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
        k += 1;
    }
    (acc > 0).then_some(acc)
}

/// Inverse parser for [`SequencerReceiptPayload::canonical_signing_bytes`], used
/// to prove unambiguous framing and round-trip decodability of `I13` receipts.
pub fn decode_canonical_receipt_signing_bytes(
    transcript: &[u8],
) -> Option<(SequencerReceiptPayload, String)> {
    let view = decode_canonical_receipt_signing_slices(transcript)?;
    let sequencer_did = core::str::from_utf8(view.sequencer_did).ok()?;
    let key_id = core::str::from_utf8(view.key_id).ok()?;
    let conversation_id = core::str::from_utf8(view.conversation_id).ok()?;
    let sender_device_did_url = core::str::from_utf8(view.sender_device_did_url).ok()?;
    let entry_id = core::str::from_utf8(view.entry_id).ok()?;

    Some((
        SequencerReceiptPayload {
            sequencer_did: sequencer_did.to_owned(),
            conversation_id: conversation_id.to_owned(),
            group_id: view.group_id.to_vec(),
            epoch: view.epoch,
            sender_device_did_url: sender_device_did_url.to_owned(),
            entry_id: entry_id.to_owned(),
            archive_commitment: view.archive_commitment,
            seq: view.seq,
            issued_at_ms: view.issued_at_ms,
        },
        key_id.to_owned(),
    ))
}

/// Validation error when advancing an MLS / Labyrinth epoch monotonically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EpochAdvanceError {
    #[error("current epoch out of range")]
    CurrentOutOfRange,
    #[error("epoch advance delta must be strictly positive")]
    ZeroDelta,
    #[error("epoch addition overflowed u64")]
    OverflowU64,
    #[error("next epoch out of range")]
    NextOutOfRange,
    #[error("epoch exceeds SQLite signed 64-bit range")]
    ExceedsSqliteSignedRange,
}

/// Checked monotone epoch transition (`next > current`, `next <= MAX_EPOCH_NUMBER`,
/// and `i64::try_from(next)` safe for SQLite `INTEGER` columns).
#[cfg(feature = "labyrinth")]
pub fn checked_advance_epoch(current: u64, delta: u64) -> Result<u64, EpochAdvanceError> {
    let _ = labyrinth::records::check_epoch_number(current)
        .map_err(|_| EpochAdvanceError::CurrentOutOfRange)?;
    if delta == 0 {
        return Err(EpochAdvanceError::ZeroDelta);
    }
    let next = current
        .checked_add(delta)
        .ok_or(EpochAdvanceError::OverflowU64)?;
    let checked = labyrinth::records::check_epoch_number(next)
        .map_err(|_| EpochAdvanceError::NextOutOfRange)?;
    let _ = i64::try_from(checked).map_err(|_| EpochAdvanceError::ExceedsSqliteSignedRange)?;
    Ok(checked)
}

/// Checked safe-integer send-counter increment (`prev + 1 <= MAX_SAFE_SEND_COUNTER`).
#[inline]
pub const fn checked_next_send_counter(prev: Option<u64>) -> Option<u64> {
    let base = match prev {
        Some(v) => {
            if v > MAX_SAFE_SEND_COUNTER {
                return None;
            }
            v
        }
        None => 0,
    };
    match base.checked_add(1) {
        Some(next) if next <= MAX_SAFE_SEND_COUNTER => Some(next),
        _ => None,
    }
}

/// Checked monotone peer send-counter verification (`prev < incoming <= MAX_SAFE_SEND_COUNTER`).
#[inline]
pub const fn checked_verify_peer_send_counter(prev: Option<u64>, incoming: u64) -> bool {
    if incoming == 0 || incoming > MAX_SAFE_SEND_COUNTER {
        return false;
    }
    match prev {
        Some(last) => last <= MAX_SAFE_SEND_COUNTER && incoming > last,
        None => true,
    }
}

/// Reference `GF(32)` multiplication (`GF(2)[x] / (x^5 + x^2 + 1)`) for verifying
/// parity-check matrix 3-column independence without table-index assumptions.
#[inline]
pub fn gf32_mul_poly(mut a: u8, mut b: u8) -> u8 {
    debug_assert!(a < 32 && b < 32);
    let mut acc = 0u8;
    let mut step = 0;
    while step < 5 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let carry = a & 0x10;
        a = (a << 1) & 0x1f;
        if carry != 0 {
            a ^= 0b00_101;
        }
        b >>= 1;
        step += 1;
    }
    acc
}

/// Extract the 4-symbol ECC tail for a single-hot basis entropy vector, recovering
/// column `col` (`0..34`) or standard basis ECC column (`34..38`) of the recovery
/// code parity-check matrix directly from [`labyrinth::recovery_code::RecoveryCode`].
#[cfg(feature = "labyrinth")]
pub const GF32_PARITY_COLUMNS: [[u8; 4]; 38] = {
    const R0: [u8; 38] = [1; 38];
    const R1: [u8; 38] = [
        1, 19, 8, 12, 10, 15, 26, 23, 14, 9, 31, 2, 3, 16, 24, 20, 30, 17, 11, 28, 18, 27, 4, 6, 5,
        21, 13, 25, 7, 22, 29, 1, 19, 8, 12, 10, 15, 26,
    ];
    const R2: [u8; 38] = [
        1, 6, 21, 16, 29, 5, 4, 17, 23, 28, 18, 0, 27, 27, 31, 27, 25, 29, 26, 27, 12, 8, 2, 14,
        13, 4, 29, 27, 26, 30, 9, 24, 7, 19, 5, 13, 24, 1,
    ];
    const R3: [u8; 38] = [
        0, 1, 1, 18, 1, 26, 9, 30, 1, 16, 3, 27, 11, 15, 19, 9, 1, 30, 13, 28, 5, 23, 2, 12, 15, 5,
        31, 10, 8, 7, 11, 29, 1, 0, 19, 19, 27, 19,
    ];
    let mut cols = [[0u8; 4]; 38];
    let mut j = 0;
    while j < 38 {
        cols[j] = [R0[j], R1[j], R2[j], R3[j]];
        j += 1;
    }
    cols
};

// ===========================================================================
// Bounded Kani Model-Checking Harnesses (`cargo kani --lib`)
// ===========================================================================

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn kani_sqlcipher_96hex_roundtrip_bijection() {
        let key: [u8; 32] = kani::any();
        let salt: [u8; 16] = kani::any();

        let spec = encode_sqlcipher_96hex_key_spec_bytes(&key, &salt);
        assert!(spec.len() == SQLCIPHER_96HEX_SPEC_LEN);
        assert!(spec[0] == b'x' && spec[1] == b'\'' && spec[98] == b'\'');
        let mut idx = 2;
        while idx < 98 {
            assert!(spec[idx] != b'\'' && spec[idx] != 0);
            idx += 1;
        }

        let parsed =
            parse_sqlcipher_96hex_key_spec_bytes(&spec).expect("encoded spec bytes must parse");
        assert!(parsed.0 == key);
        assert!(parsed.1 == salt);
    }

    #[kani::proof]
    fn kani_sqlcipher_96hex_arbitrary_no_panic_and_strict() {
        let raw: [u8; 100] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= raw.len());

        if let Ok((key, salt)) = parse_sqlcipher_96hex_key_spec_bytes(&raw[..len]) {
            assert!(len == SQLCIPHER_96HEX_SPEC_LEN);
            let canonical = encode_sqlcipher_96hex_key_spec_bytes(&key, &salt);
            let mut idx = 0;
            while idx < SQLCIPHER_96HEX_SPEC_LEN {
                assert!(canonical[idx] == raw[idx]);
                idx += 1;
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(36)]
    fn kani_i13_receipt_framing_injective_and_roundtrip() {
        // Left-inverse round-trip across ALL variable-split adjacent fields and
        // full 64-bit / 32-byte scalars (`decode(encode(v)) == Some(v)` => injective).
        let split_seq: usize = kani::any();
        let split_conv: usize = kani::any();
        let split_sender: usize = kani::any();
        kani::assume(split_seq <= 3 && split_conv <= 3 && split_sender <= 3);

        let pair_a: [u8; 3] = kani::any();
        let pair_b: [u8; 3] = kani::any();
        let pair_c: [u8; 3] = kani::any();

        let view = DecodedReceiptTranscript {
            sequencer_did: &pair_a[..split_seq],
            key_id: &pair_a[split_seq..],
            conversation_id: &pair_b[..split_conv],
            group_id: &pair_b[split_conv..],
            epoch: kani::any(),
            sender_device_did_url: &pair_c[..split_sender],
            entry_id: &pair_c[split_sender..],
            archive_commitment: kani::any(),
            seq: kani::any(),
            issued_at_ms: kani::any(),
        };

        let mut buf = [0u8; 128];
        let Some(written) = encode_canonical_receipt_signing_slices_into(&view, &mut buf) else {
            panic!("128-byte buffer fits bounded transcript");
        };
        let Some(decoded) = decode_canonical_receipt_signing_slices(&buf[..written]) else {
            panic!("canonical signing transcript must decode");
        };
        assert!(decoded == view);
    }

    #[kani::proof]
    fn kani_i13_receipt_decoder_arbitrary_no_panic() {
        let raw_transcript: [u8; 96] = kani::any();
        let raw_len: usize = kani::any();
        kani::assume(raw_len <= raw_transcript.len());
        if let Some(parsed) = decode_canonical_receipt_signing_slices(&raw_transcript[..raw_len]) {
            let expected_len = RECEIPT_DOMAIN_V2.len()
                + 6 * 4
                + parsed.sequencer_did.len()
                + parsed.key_id.len()
                + parsed.conversation_id.len()
                + parsed.group_id.len()
                + parsed.sender_device_did_url.len()
                + parsed.entry_id.len()
                + 8
                + ARCHIVE_COMMITMENT_LEN
                + 8
                + 8;
            assert!(raw_len == expected_len);
        }
    }

    #[kani::proof]
    #[kani::unwind(14)]
    fn kani_i13_receipt_validation_invariants() {
        let seq_did: [u8; 12] = kani::any();
        let did_len: usize = kani::any();
        kani::assume(did_len <= seq_did.len());

        let conv: [u8; 2] = kani::any();
        let conv_len: usize = kani::any();
        kani::assume(conv_len <= conv.len());

        let sender: [u8; 6] = kani::any();
        let sender_len: usize = kani::any();
        kani::assume(sender_len <= sender.len());

        let entry: [u8; 2] = kani::any();
        let entry_len: usize = kani::any();
        kani::assume(entry_len <= entry.len());

        let group_len: usize = kani::any();
        let seq: u64 = kani::any();
        let issued_at_ms: i64 = kani::any();

        if validate_i13_receipt_structure_slices(
            &seq_did[..did_len],
            &conv[..conv_len],
            group_len,
            &sender[..sender_len],
            &entry[..entry_len],
            seq,
            issued_at_ms,
        ) {
            assert!(did_len >= 8);
            assert!(&seq_did[..8] == b"did:web:" || &seq_did[..8] == b"did:plc:");
            assert!(conv_len >= 1 && entry_len >= 1);
            assert!(group_len == GROUP_ID_LEN);
            assert!(seq >= 1 && issued_at_ms >= 0);
            assert!(sender_len >= 3);
        }
    }

    #[kani::proof]
    #[kani::unwind(30)]
    fn kani_i13_receipt_key_generation_canonical_positive() {
        const CANON_SEQ_DID: &[u8] = b"did:web:ds";
        // 1. Arbitrary 28-byte candidate never panics, rejects leading zeros / 0,
        //    and enforces exact `{sequencer_did}#mls-receipt-<positive-decimal>` prefix.
        let raw_key: [u8; 28] = kani::any();
        let raw_len: usize = kani::any();
        kani::assume(raw_len <= raw_key.len());
        if let Some(gen) =
            parse_i13_receipt_key_generation_slice(CANON_SEQ_DID, &raw_key[..raw_len])
        {
            assert!(gen >= 1);
            assert!(raw_len > 23);
            assert!(&raw_key[..23] == b"did:web:ds#mls-receipt-");
            assert!(raw_key[23] >= b'1' && raw_key[23] <= b'9');
        }

        // 2. Every canonical 1..=2 digit generation round-trips to its exact u64 value.
        let d0: u8 = kani::any();
        let d1: u8 = kani::any();
        let two_digits: bool = kani::any();
        kani::assume((b'1'..=b'9').contains(&d0));
        kani::assume(d1.is_ascii_digit());
        let mut valid_buf = *b"did:web:ds#mls-receipt-00";
        valid_buf[23] = d0;
        valid_buf[24] = d1;
        let used_len = if two_digits { 25 } else { 24 };
        let Some(parsed) =
            parse_i13_receipt_key_generation_slice(CANON_SEQ_DID, &valid_buf[..used_len])
        else {
            panic!("canonical positive generation must parse");
        };
        let expected = if two_digits {
            u64::from(d0 - b'0') * 10 + u64::from(d1 - b'0')
        } else {
            u64::from(d0 - b'0')
        };
        assert!(parsed == expected);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    fn kani_gf32_ecc_any_three_columns_independent() {
        let c0: usize = kani::any();
        let c1: usize = kani::any();
        let c2: usize = kani::any();
        kani::assume(c0 < c1 && c1 < c2 && c2 < 38);

        let e0: u8 = kani::any();
        let e1: u8 = kani::any();
        let e2: u8 = kani::any();
        kani::assume(e0 < 32 && e1 < 32 && e2 < 32);
        kani::assume((e0 | e1 | e2) != 0);

        let mut syn = [0u8; 4];
        let mut r = 0;
        while r < 4 {
            syn[r] = gf32_mul_poly(GF32_PARITY_COLUMNS[c0][r], e0)
                ^ gf32_mul_poly(GF32_PARITY_COLUMNS[c1][r], e1)
                ^ gf32_mul_poly(GF32_PARITY_COLUMNS[c2][r], e2);
            r += 1;
        }
        // Every 3 columns are linearly independent over GF(32): no weight <= 3
        // non-zero error vector can produce a zero syndrome.
        assert!(syn != [0u8; 4]);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    fn kani_gf32_recovery_code_alphabet_and_single_error_rejection() {
        use labyrinth::recovery_code::{
            ALPHABET, CODE_LEN, ECC_LEN, ENTROPY_LEN, IDENTIFIER, VERSION,
        };

        assert!(CODE_LEN == 2 + ENTROPY_LEN + ECC_LEN && CODE_LEN == 40);
        assert!(VERSION == b'2' && IDENTIFIER == b'0');

        // 1. Alphabet bijection & separator/homoglyph disjointness over arbitrary `ch: u8`.
        let i: usize = kani::any();
        let j: usize = kani::any();
        kani::assume(i < 32 && j < 32);
        assert!(ALPHABET[i].is_ascii_uppercase() || ALPHABET[i].is_ascii_digit());
        assert!(ALPHABET[i] != b'-' && !ALPHABET[i].is_ascii_whitespace());
        assert!(
            ALPHABET[i] != b'B'
                && ALPHABET[i] != b'G'
                && ALPHABET[i] != b'I'
                && ALPHABET[i] != b'O'
        );
        if i != j {
            assert!(ALPHABET[i] != ALPHABET[j]);
        }

        // 2. Single-symbol substitution rejection: for any valid 38-symbol codeword
        //    (`H · word == 0`) and any single corrupted position `pos < 38` with
        //    non-zero symbol delta `delta in 1..32`, the mutated syndrome is non-zero.
        let pos: usize = kani::any();
        let orig_sym: u8 = kani::any::<u8>() & 0x1f;
        let delta: u8 = kani::any();
        kani::assume(pos < 38);
        kani::assume(delta >= 1 && delta < 32);
        let mutated_sym = orig_sym ^ delta;
        assert!(mutated_sym < 32 && mutated_sym != orig_sym);

        let mut syn_diff = [0u8; 4];
        let mut r = 0;
        while r < 4 {
            syn_diff[r] = gf32_mul_poly(GF32_PARITY_COLUMNS[pos][r], orig_sym)
                ^ gf32_mul_poly(GF32_PARITY_COLUMNS[pos][r], mutated_sym);
            r += 1;
        }
        assert!(syn_diff != [0u8; 4]);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    fn kani_gf32_ecc_triple_erasure_and_ecc_tail_uniqueness() {
        // 1. Bilinearity of GF(32) polynomial multiplication (`h * (u ^ v) == h*u ^ h*v`
        //    and `h * e == 0 <=> h == 0 || e == 0`). Combined with
        //    `kani_gf32_ecc_any_three_columns_independent`, this proves every
        //    <= 3-erasure residual syndrome has at most one solution over GF(32)^3.
        let h: u8 = kani::any::<u8>() & 0x1f;
        let u: u8 = kani::any::<u8>() & 0x1f;
        let v: u8 = kani::any::<u8>() & 0x1f;
        assert!(gf32_mul_poly(h, u ^ v) == (gf32_mul_poly(h, u) ^ gf32_mul_poly(h, v)));
        if h != 0 && u != 0 {
            assert!(gf32_mul_poly(h, u) != 0);
        }

        // 2. Invertibility of the 4 ECC tail columns (`34..38`): no non-zero
        //    4-symbol ECC difference can have zero syndrome, so every 34-symbol
        //    entropy vector encodes to a unique 4-symbol ECC tail over GF(32)^4.
        let e: [u8; 4] = [
            kani::any::<u8>() & 0x1f,
            kani::any::<u8>() & 0x1f,
            kani::any::<u8>() & 0x1f,
            kani::any::<u8>() & 0x1f,
        ];
        kani::assume((e[0] | e[1] | e[2] | e[3]) != 0);
        let mut syn = [0u8; 4];
        let mut row = 0;
        while row < 4 {
            syn[row] = gf32_mul_poly(GF32_PARITY_COLUMNS[34][row], e[0])
                ^ gf32_mul_poly(GF32_PARITY_COLUMNS[35][row], e[1])
                ^ gf32_mul_poly(GF32_PARITY_COLUMNS[36][row], e[2])
                ^ gf32_mul_poly(GF32_PARITY_COLUMNS[37][row], e[3]);
            row += 1;
        }
        assert!(syn != [0u8; 4]);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    fn kani_padme_len_overflow_and_overhead_bounds() {
        use labyrinth::padding::padme_len;

        let l1: usize = kani::any();
        let l2: usize = kani::any();
        kani::assume(l1 <= l2);
        kani::assume(l2 <= (u32::MAX as usize));

        let p1 = padme_len(l1);
        let p2 = padme_len(l2);

        // Minimum floor, monotonicity, idempotence, and 4-byte prefix headroom.
        assert!(p1 >= l1.max(10));
        assert!(p1 <= p2);
        assert!(padme_len(p1) == p1);
        assert!(p2.checked_add(4).is_some());

        // PADMÉ overhead above `l >= 10` is bounded by `<= l / 8` (12.5%).
        if l1 >= 10 {
            assert!(p1 - l1 <= (l1 >> 3).max(1));
        }
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(24)]
    fn kani_pad_unpad_roundtrip_and_strict_canonical() {
        use labyrinth::padding::{pad, padme_len, unpad};

        // Round-trip both the `MIN_LEN = 10` floor (`0 -> 10`) and a non-trivial
        // PADMÉ step (`11 -> 12`) over symbolic payload bytes.
        let empty_padded = pad(&[]);
        assert!(empty_padded.len() == 14);
        assert!(unpad(&empty_padded)
            .expect("empty pad output must unpad")
            .is_empty());

        let raw: [u8; 11] = kani::any();
        let padded = pad(&raw);
        assert!(padded.len() == 16);
        let recovered = unpad(&padded).expect("11-byte pad output must unpad");
        assert!(recovered.as_slice() == raw.as_slice());

        // Short (<4 bytes) and non-PADMÉ-length (4 + 11 = 15 bytes) frames must fail.
        let candidate: [u8; 16] = kani::any();
        assert!(unpad(&candidate[..3]).is_err());
        assert!(unpad(&candidate[..15]).is_err());

        // Strict non-malleability on valid PADMÉ frame sizes (`14` and `16` bytes):
        // every accepted frame has canonical big-endian prefix and all-zero padding.
        for clen in [14usize, 16usize] {
            let slice = &candidate[..clen];
            if let Ok(plain) = unpad(slice) {
                let plen = plain.len();
                assert!(clen == 4 + padme_len(plen));
                let declared =
                    u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
                assert!(declared == plen);
                assert!(&slice[4..4 + plen] == plain.as_slice());
                let mut idx = 4 + plen;
                while idx < clen {
                    assert!(slice[idx] == 0);
                    idx += 1;
                }
            }
        }
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    fn kani_epoch_and_send_counter_overflow_bounds() {
        let current_epoch: u64 = kani::any();
        let delta: u64 = kani::any();
        match checked_advance_epoch(current_epoch, delta) {
            Ok(next) => {
                assert!(next > current_epoch);
                assert!(next <= labyrinth::records::MAX_EPOCH_NUMBER);
                assert!(i64::try_from(next).is_ok());
            }
            Err(_) => {
                assert!(
                    current_epoch > labyrinth::records::MAX_EPOCH_NUMBER
                        || delta == 0
                        || current_epoch.checked_add(delta).is_none()
                        || current_epoch.saturating_add(delta)
                            > labyrinth::records::MAX_EPOCH_NUMBER
                );
            }
        }

        let has_prev: bool = kani::any();
        let prev_val: u64 = kani::any();
        let prev_opt = if has_prev { Some(prev_val) } else { None };
        let recv_counter: u64 = kani::any();

        if checked_verify_peer_send_counter(prev_opt, recv_counter) {
            assert!(recv_counter >= 1 && recv_counter <= MAX_SAFE_SEND_COUNTER);
            if let Some(p) = prev_opt {
                assert!(p <= MAX_SAFE_SEND_COUNTER);
                assert!(recv_counter > p);
            }
        } else {
            assert!(
                recv_counter == 0
                    || recv_counter > MAX_SAFE_SEND_COUNTER
                    || prev_opt.is_some_and(|p| p > MAX_SAFE_SEND_COUNTER || recv_counter <= p)
            );
        }

        match checked_next_send_counter(prev_opt) {
            Some(next) => {
                let expected = prev_opt.unwrap_or(0) + 1;
                assert!(next == expected);
                assert!(next >= 1 && next <= MAX_SAFE_SEND_COUNTER);
            }
            None => {
                assert!(prev_opt.is_some_and(|p| p >= MAX_SAFE_SEND_COUNTER));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn sqlcipher_96hex_matches_driver_derivation_and_rejects_mutations() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x51C1_F349_9600_0001);
        for _ in 0..256 {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            let derived = derive_sqlcipher_96hex_key_spec(&key);
            assert_eq!(derived.len(), SQLCIPHER_96HEX_SPEC_LEN);
            let (parsed_key, parsed_salt) =
                parse_sqlcipher_96hex_key_spec(&derived).expect("derived spec must parse");
            assert_eq!(parsed_key, key);
            assert_eq!(
                format_sqlcipher_96hex_key_spec(&parsed_key, &parsed_salt),
                derived
            );

            // Reject uppercase hex, truncation, extra byte, and quote tampering.
            let upper = format!("x'{}'", derived[2..98].to_ascii_uppercase());
            assert!(parse_sqlcipher_96hex_key_spec(&upper).is_err());
            assert!(parse_sqlcipher_96hex_key_spec(&derived[..98]).is_err());
            let extra = format!("{derived} ");
            assert!(parse_sqlcipher_96hex_key_spec(&extra).is_err());
            let mut quote_tamper = derived.into_bytes();
            quote_tamper[10] = b'\'';
            assert!(
                parse_sqlcipher_96hex_key_spec(&String::from_utf8(quote_tamper).unwrap()).is_err()
            );
        }
    }

    #[test]
    fn i13_receipt_framing_roundtrips_and_prevents_boundary_shifts() {
        let p_left = SequencerReceiptPayload {
            sequencer_did: "did:web:ds.example".into(),
            conversation_id: "conv_ab".into(),
            group_id: vec![0x42; GROUP_ID_LEN],
            epoch: 9,
            sender_device_did_url: "did:plc:alice#dev1".into(),
            entry_id: "entry_1".into(),
            archive_commitment: [0xaa; ARCHIVE_COMMITMENT_LEN],
            seq: 1,
            issued_at_ms: 1_700_000_000_000,
        };
        let mut p_shifted = p_left.clone();
        p_shifted.sequencer_did = "did:web:ds.exampl".into();
        let bytes_a = p_left.canonical_signing_bytes("did:web:ds.example#mls-receipt-1");
        let bytes_b = p_shifted.canonical_signing_bytes("edid:web:ds.example#mls-receipt-1");
        assert_ne!(bytes_a, bytes_b);

        let (decoded, key_id) =
            decode_canonical_receipt_signing_bytes(&bytes_a).expect("round-trip decode");
        assert_eq!(decoded, p_left);
        assert_eq!(key_id, "did:web:ds.example#mls-receipt-1");

        // Lock-step parity between stack-slice reference functions and `labyrinth_protocol`.
        let mut fixed_buf = [0u8; 256];
        let view_a = decode_canonical_receipt_signing_slices(&bytes_a).unwrap();
        let n = encode_canonical_receipt_signing_slices_into(&view_a, &mut fixed_buf).unwrap();
        assert_eq!(&fixed_buf[..n], bytes_a.as_slice());

        for candidate_payload in [
            p_left.clone(),
            SequencerReceiptPayload {
                sequencer_did: "http://bad".into(),
                ..p_left.clone()
            },
            SequencerReceiptPayload {
                sequencer_did: "did:web:ds#frag".into(),
                ..p_left.clone()
            },
            SequencerReceiptPayload {
                sender_device_did_url: "did:plc:alice".into(),
                ..p_left.clone()
            },
            SequencerReceiptPayload {
                group_id: vec![0x42; 31],
                ..p_left.clone()
            },
            SequencerReceiptPayload {
                seq: 0,
                ..p_left.clone()
            },
            SequencerReceiptPayload {
                issued_at_ms: -1,
                ..p_left.clone()
            },
        ] {
            assert_eq!(
                validate_i13_receipt_structure_slices(
                    candidate_payload.sequencer_did.as_bytes(),
                    candidate_payload.conversation_id.as_bytes(),
                    candidate_payload.group_id.len(),
                    candidate_payload.sender_device_did_url.as_bytes(),
                    candidate_payload.entry_id.as_bytes(),
                    candidate_payload.seq,
                    candidate_payload.issued_at_ms,
                ),
                candidate_payload.validate_structure().is_ok()
            );
        }

        for candidate_kid in [
            "did:web:ds.example#mls-receipt-1",
            "did:web:ds.example#mls-receipt-42",
            "did:web:ds.example#mls-receipt-0",
            "did:web:ds.example#mls-receipt-01",
            "did:web:ds.example#mls-receipt-",
            "did:plc:other#mls-receipt-1",
        ] {
            assert_eq!(
                parse_i13_receipt_key_generation_slice(
                    b"did:web:ds.example",
                    candidate_kid.as_bytes()
                ),
                receipt_key_generation("did:web:ds.example", candidate_kid).ok()
            );
        }
    }

    #[cfg(feature = "labyrinth")]
    #[test]
    fn gf32_columns_match_recovery_code_generator_and_triple_erasures() {
        use labyrinth::recovery_code::{RecoveryCode, ALPHABET, ENTROPY_LEN};

        // Verify `GF32_PARITY_COLUMNS` matches `RecoveryCode::from_entropy_symbols`
        // across all 34 unit entropy vectors, and check all C(38, 3) = 8,436 column triples.
        for c0 in 0..38 {
            for c1 in (c0 + 1)..38 {
                for c2 in (c1 + 1)..38 {
                    // Check full rank over GF(32) via Gaussian elimination on 4x3 submatrix.
                    let mut m = [[0u8; 3]; 4];
                    for r in 0..4 {
                        m[r] = [
                            GF32_PARITY_COLUMNS[c0][r],
                            GF32_PARITY_COLUMNS[c1][r],
                            GF32_PARITY_COLUMNS[c2][r],
                        ];
                    }
                    let mut rank = 0usize;
                    for col in 0..3 {
                        if let Some(pivot) = (rank..4).find(|&r| m[r][col] != 0) {
                            m.swap(rank, pivot);
                            // Find multiplicative inverse of m[rank][col] in GF(32)^*.
                            let pv = m[rank][col];
                            let inv = (1u8..32)
                                .find(|&x| gf32_mul_poly(pv, x) == 1)
                                .expect("non-zero GF(32) element has inverse");
                            for v in &mut m[rank][col..3] {
                                *v = gf32_mul_poly(*v, inv);
                            }
                            let pivot_row = m[rank];
                            for (r, row) in m.iter_mut().enumerate() {
                                if r != rank && row[col] != 0 {
                                    let factor = row[col];
                                    for c in col..3 {
                                        row[c] ^= gf32_mul_poly(factor, pivot_row[c]);
                                    }
                                }
                            }
                            rank += 1;
                        }
                    }
                    assert_eq!(rank, 3, "columns ({c0}, {c1}, {c2}) must have rank 3");
                }
            }
        }

        let mut rng = ChaCha20Rng::seed_from_u64(0x6F32_ECC0_2026_1201);
        for _ in 0..32 {
            let mut entropy = [0u8; ENTROPY_LEN];
            for s in &mut entropy {
                *s = rng.gen_range(0..32);
            }
            let code = RecoveryCode::from_entropy_symbols(&entropy);
            let mut erased = code.as_str().as_bytes().to_vec();
            let p0 = rng.gen_range(0..12);
            let p1 = rng.gen_range(12..26);
            let p2 = rng.gen_range(26..38);
            erased[2 + p0] = b'?';
            erased[2 + p1] = b'?';
            erased[2 + p2] = b'?';
            let cand: Vec<_> = RecoveryCode::candidates(std::str::from_utf8(&erased).unwrap())
                .unwrap()
                .collect();
            assert_eq!(cand, vec![code.clone()]);

            // Verify single-symbol substitution is caught by `parse` and included in `candidates`.
            let mut sub = code.as_str().as_bytes().to_vec();
            let orig_idx = ALPHABET.iter().position(|&b| b == sub[2 + p1]).unwrap();
            sub[2 + p1] = ALPHABET[(orig_idx + 1) % 32];
            let sub_str = std::str::from_utf8(&sub).unwrap();
            assert!(RecoveryCode::parse(sub_str).is_err());
            let sub_cands: Vec<_> = RecoveryCode::candidates(sub_str).unwrap().collect();
            assert!(sub_cands.contains(&code));
        }
    }

    #[cfg(feature = "labyrinth")]
    #[test]
    fn padme_and_epoch_send_counter_bounds_property() {
        use labyrinth::padding::{pad, padme_len, unpad};

        for l in [0usize, 1, 9, 10, 11, 63, 64, 65, 4095, 4096, 65537] {
            let plain = vec![0x5au8; l];
            let padded = pad(&plain);
            assert_eq!(padded.len(), 4 + padme_len(l));
            assert_eq!(unpad(&padded).unwrap(), plain);
        }

        assert_eq!(checked_advance_epoch(0, 1).unwrap(), 1);
        assert_eq!(
            checked_advance_epoch((1u64 << 40) - 1, 1).unwrap(),
            1u64 << 40
        );
        assert!(checked_advance_epoch(1u64 << 40, 1).is_err());
        assert!(checked_advance_epoch(5, 0).is_err());
        assert!(checked_advance_epoch(u64::MAX, 1).is_err());

        assert_eq!(next_send_counter(None).unwrap(), 1);
        assert!(next_send_counter(Some(&MAX_SAFE_SEND_COUNTER.to_string())).is_err());
        assert!(verify_next_peer_send_counter(Some("10"), 10).is_err());
        assert!(verify_next_peer_send_counter(Some("10"), 11).is_ok());
        assert!(verify_next_peer_send_counter(None, MAX_SAFE_SEND_COUNTER + 1).is_err());
    }
}
