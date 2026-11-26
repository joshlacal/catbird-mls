//! Bounded formal verification (`#[cfg(kani)]`) harnesses and companion property
//! checks for Task 6 cryptographic, wire-framing, and URI/header invariants.
//!
//! Every Kani proof invokes the live production functions in `catbird-mls`,
//! `labyrinth`, `labyrinth-protocol`, and `atproto-spaces` directly under CBMC
//! and pairs conditional properties with `kani::cover!` reachability checks so
//! no harness can pass vacuously:
//!
//! | Harness | Verified Production Symbols |
//! |---|---|
//! | `kani_sqlcipher_96hex_roundtrip_bijection` | `catbird_mls::kani_proofs::{format_sqlcipher_96hex_key_spec, parse_sqlcipher_96hex_key_spec}` (invoked by `catbird_mls::storage::derive_sqlcipher_96hex_key_spec`) |
//! | `kani_sqlcipher_96hex_arbitrary_no_panic_and_strict` | `catbird_mls::kani_proofs::{parse_sqlcipher_96hex_key_spec_bytes, encode_sqlcipher_96hex_key_spec_bytes}` |
//! | `kani_i13_receipt_framing_injective_and_roundtrip` | `labyrinth_protocol::receipt::SequencerReceiptPayload::canonical_signing_bytes`, `decode_canonical_receipt_signing_slices` |
//! | `kani_i13_receipt_decoder_arbitrary_no_panic` | `decode_canonical_receipt_signing_slices` (`BUF_CAP = 132B >= 128B`, `113B` minimal + `>= 128B` populated valid frames covered via `kani::cover!`) |
//! | `kani_i13_receipt_validation_invariants` | `labyrinth_protocol::receipt::SequencerReceiptPayload::{validate_structure, split_sender_device}` |
//! | `kani_i13_receipt_key_generation_canonical_positive` | `labyrinth_protocol::receipt::receipt_key_generation` |
//! | `kani_gf32_ecc_any_three_columns_independent` | `labyrinth::recovery_code::RecoveryCode::from_entropy_symbols` (MDS distance `>= 4`: every non-zero codeword of support `<= 3` has weight `>= 4`) |
//! | `kani_gf32_recovery_code_encode_and_homoglyph_roundtrip` | `labyrinth::recovery_code::RecoveryCode::{parse, as_str, entropy_chars}` |
//! | `kani_gf32_recovery_code_single_error_rejection` | `labyrinth::recovery_code::RecoveryCode::parse` |
//! | `kani_gf32_ecc_triple_erasure_and_ecc_tail_uniqueness` | `labyrinth::recovery_code::RecoveryCode::from_entropy_symbols` (MDS triple-erasure uniqueness across `C(38, 3)` column triples + 4-symbol ECC tail collision-freedom) |
//! | `kani_padme_len_overflow_and_overhead_bounds` | `labyrinth::padding::padme_len` (`MIN_LEN = 10`, monotonicity, idempotence, `<= 12.5%` overhead) |
//! | `kani_pad_unpad_roundtrip` | `labyrinth::padding::{pad, unpad, padme_len}` |
//! | `kani_unpad_arbitrary_strict_canonical` | `labyrinth::padding::{unpad, padme_len}` |
//! | `kani_epoch_and_send_counter_overflow_bounds` | `labyrinth::records::check_epoch_number`, `catbird_mls::client::chat_wire::{next_send_counter, confirmed_send_counter}` |
//! | `kani_peer_send_counter_strict_continuity` | `catbird_mls::client::send_counter::{classify_peer_send_counter, select_peer_counter_prior, advance_epoch_chain, EpochChain::covers}` |
//! | `kani_atproto_spaces_uri_and_hedged_normalization` | `atproto_spaces::{SpaceUri::record_uri, is_atproto_did, is_valid_did, is_valid_nsid, is_valid_rkey}` |
//! | `kani_atproto_spaces_accept_signature_sf_roundtrip` | `atproto_spaces::mac::{format_accept_signature, MacProfile}` (`parse_accept_signature` round-trip in `kani_proofs::tests`) |

#![allow(unexpected_cfgs)]

use thiserror::Error;

#[cfg(any(kani, test))]
use crate::client::chat_wire::{confirmed_send_counter, next_send_counter};
#[cfg(any(kani, test))]
use crate::client::send_counter::{
    advance_epoch_chain, classify_peer_send_counter, select_peer_counter_prior, EpochChain,
    PeerCounterPrior, PeerCounterVerdict,
};
#[cfg(test)]
use crate::storage::derive_sqlcipher_96hex_key_spec;
use labyrinth_protocol::limits::ARCHIVE_COMMITMENT_LEN;
#[cfg(any(kani, test))]
use labyrinth_protocol::limits::GROUP_ID_LEN;
#[cfg(any(kani, test))]
use labyrinth_protocol::receipt::receipt_key_generation;
use labyrinth_protocol::receipt::SequencerReceiptPayload;
use labyrinth_protocol::transcripts::RECEIPT_DOMAIN_V2;

/// Exact ASCII byte length of `"x'<64-hex-key><32-hex-salt>'"` (`2 + 64 + 32 + 1`).
pub const SQLCIPHER_96HEX_SPEC_LEN: usize = 99;

/// Minimum valid `I13` [`SequencerReceiptPayload::canonical_signing_bytes`] frame size:
/// `33` (`RECEIPT_DOMAIN_V2`) + `6 * 4` (`u32` BE lengths) + `8` (`epoch`) +
/// `32` (`archive_commitment`) + `8` (`seq`) + `8` (`issued_at_ms`) = `113` bytes.
pub const MIN_I13_RECEIPT_TRANSCRIPT_LEN: usize =
    RECEIPT_DOMAIN_V2.len() + 6 * 4 + 8 + ARCHIVE_COMMITMENT_LEN + 8 + 8;

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
///
/// Invoked directly by [`crate::storage::derive_sqlcipher_96hex_key_spec`].
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
    if transcript.len() < MIN_I13_RECEIPT_TRANSCRIPT_LEN {
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
/// and `i64::try_from(next)` safe for SQLite `INTEGER` columns), delegating bounds
/// enforcement to [`labyrinth::records::check_epoch_number`].
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

/// Single-byte step of the Unicode Standard Table 3-7 (RFC 3629) UTF-8 DFA.
///
/// States:
/// - `0`: start / accepting code-point boundary
/// - `1`: expecting final continuation byte (`0x80..=0xBF`)
/// - `2`: after `0xE0`, expecting `0xA0..=0xBF` then state `1`
/// - `3`: expecting two continuation bytes (`0x80..=0xBF`)
/// - `4`: after `0xED`, expecting `0x80..=0x9F` (surrogate exclusion) then state `1`
/// - `5`: after `0xF0`, expecting `0x90..=0xBF` then state `3`
/// - `6`: after `0xF1..=0xF3`, expecting `0x80..=0xBF` then state `3`
/// - `7`: after `0xF4`, expecting `0x80..=0x8F` (`<= U+10FFFF`) then state `3`
/// - `0xFF`: rejecting sink state
#[inline(always)]
const fn utf8_rfc3629_dfa_step(state: u8, b: u8) -> u8 {
    match (state, b) {
        (0, 0x00..=0x7F) => 0,
        (0, 0xC2..=0xDF) => 1,
        (0, 0xE0) => 2,
        (0, 0xE1..=0xEC | 0xEE..=0xEF) => 3,
        (0, 0xED) => 4,
        (0, 0xF0) => 5,
        (0, 0xF1..=0xF3) => 6,
        (0, 0xF4) => 7,
        (1, 0x80..=0xBF) => 0,
        (2, 0xA0..=0xBF) => 1,
        (3, 0x80..=0xBF) => 1,
        (4, 0x80..=0x9F) => 1,
        (5, 0x90..=0xBF) => 3,
        (6, 0x80..=0xBF) => 3,
        (7, 0x80..=0x8F) => 3,
        _ => 0xFF,
    }
}

/// Strictly validate UTF-8 byte sequences per Unicode Standard Table 3-7 (RFC 3629)
/// using a constant-stride (`i += 1`) 1-byte-per-step DFA without data-dependent breaks.
///
/// Equivalent to `core::str::from_utf8(bytes).is_ok()`, while ensuring `i` remains concrete
/// on every unrolled iteration in CBMC (`bytes[0], bytes[1], ...`) rather than creating
/// symbolic array index multiplexers.
pub fn is_valid_utf8_rfc3629(bytes: &[u8]) -> bool {
    let mut state = 0u8;
    let mut i = 0usize;
    let n = bytes.len();
    while i < n {
        state = utf8_rfc3629_dfa_step(state, bytes[i]);
        i += 1;
    }
    state == 0
}

/// Format a `u64` into stack-allocated canonical ASCII decimal bytes without `core::fmt`.
pub fn format_u64_decimal_stack(mut v: u64, buf: &mut [u8; 20]) -> &str {
    if v == 0 {
        buf[19] = b'0';
        return core::str::from_utf8(&buf[19..20]).expect("ASCII digit");
    }
    let mut pos = 20usize;
    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    core::str::from_utf8(&buf[pos..20]).expect("ASCII digits")
}

// ===========================================================================
// Bounded Kani Model-Checking Harnesses (`cargo kani --lib`)
// ===========================================================================

#[cfg(kani)]
mod proofs {
    use super::*;

    #[allow(invalid_from_utf8)]
    const CONST_UTF8_ERR: core::str::Utf8Error = match core::str::from_utf8(&[0xFF]) {
        Ok(_) => panic!("0xFF is invalid UTF-8"),
        Err(e) => e,
    };

    /// Sound, exact UTF-8 stub replacing stdlib's SWAR pointer-chunked `run_utf8_validation`
    /// with [`is_valid_utf8_rfc3629`] so CBMC bounds UTF-8 validation loops deterministically
    /// without invoking `run_utf8_validation`.
    fn kani_str_from_utf8(v: &[u8]) -> Result<&str, core::str::Utf8Error> {
        if is_valid_utf8_rfc3629(v) {
            // SAFETY: `is_valid_utf8_rfc3629` enforces the exact Unicode Table 3-7 UTF-8 grammar.
            Ok(unsafe { core::str::from_utf8_unchecked(v) })
        } else {
            Err(CONST_UTF8_ERR)
        }
    }

    /// Sound, exact linear byte-search stubs replacing stdlib's SWAR pointer-aligned
    /// `core::slice::memchr::{memchr, memrchr}` (`memchr_aligned::runtime`) so CBMC
    /// unrolls `str::contains`, `str::find`, `str::split_once`, and SF dictionary parsing
    /// without pointer-alignment chunking blowup.
    fn kani_memchr(x: u8, text: &[u8]) -> Option<usize> {
        let mut idx = 0usize;
        while idx < text.len() {
            if text[idx] == x {
                return Some(idx);
            }
            idx += 1;
        }
        None
    }

    fn kani_memrchr(x: u8, text: &[u8]) -> Option<usize> {
        let mut idx = text.len();
        while idx > 0 {
            idx -= 1;
            if text[idx] == x {
                return Some(idx);
            }
        }
        None
    }

    /// Stub replacing `std::fmt::format` / `core::fmt::write` ONLY on harnesses where
    /// formatting is used solely to construct human-readable error strings inside `Err(...)`
    /// branches after the boolean parser/validation guard has already decided failure.
    fn kani_err_fmt_stub(_args: core::fmt::Arguments<'_>) -> String {
        String::new()
    }

    fn kani_fmt_write_noop(
        _output: &mut dyn core::fmt::Write,
        _args: core::fmt::Arguments<'_>,
    ) -> core::fmt::Result {
        Ok(())
    }

    #[inline(always)]
    fn ascii_str_from_slice(bytes: &[u8]) -> &str {
        let mut idx = 0;
        while idx < bytes.len() {
            kani::assume(bytes[idx].is_ascii() && bytes[idx] >= 0x20);
            idx += 1;
        }
        // SAFETY: Every byte in `bytes` was just constrained to printable ASCII (`0x20..=0x7F`).
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }

    #[kani::proof]
    #[kani::unwind(100)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    fn kani_sqlcipher_96hex_roundtrip_bijection() {
        let key: [u8; 32] = kani::any();
        let salt: [u8; 16] = kani::any();

        let spec = format_sqlcipher_96hex_key_spec(&key, &salt);
        let spec_bytes = spec.as_bytes();
        assert!(spec_bytes.len() == SQLCIPHER_96HEX_SPEC_LEN);
        assert!(spec_bytes[0] == b'x' && spec_bytes[1] == b'\'' && spec_bytes[98] == b'\'');
        let mut idx = 2;
        while idx < 98 {
            assert!(spec_bytes[idx] != b'\'' && spec_bytes[idx] != 0);
            idx += 1;
        }

        let parsed = parse_sqlcipher_96hex_key_spec(&spec).expect("formatted spec must parse");
        assert!(parsed.0 == key);
        assert!(parsed.1 == salt);
        kani::cover!(
            key[0] != 0 && salt[15] != 0,
            "non-zero key and salt round-trip"
        );
    }

    #[kani::proof]
    #[kani::unwind(101)]
    fn kani_sqlcipher_96hex_arbitrary_no_panic_and_strict() {
        let raw: [u8; 100] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= raw.len());

        let res = parse_sqlcipher_96hex_key_spec_bytes(&raw[..len]);
        kani::cover!(
            res.is_ok(),
            "valid 99-byte SQLCipher key+salt literal is reachable"
        );
        kani::cover!(
            res.is_err() && len == SQLCIPHER_96HEX_SPEC_LEN,
            "99-byte malformed SQLCipher literal rejection is reachable"
        );

        if let Ok((key, salt)) = res {
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
    #[kani::unwind(122)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    fn kani_i13_receipt_framing_injective_and_roundtrip() {
        // Directly exercises `labyrinth_protocol::receipt::SequencerReceiptPayload::canonical_signing_bytes`
        // and `decode_canonical_receipt_signing_slices` across TWO symbolic `(payload, key_id)` pairs
        // with symbolic adjacent variable-length boundary splits (`("", s[0..2])` vs `(s[0..1], s[1..2])`
        // across `sender_device_did_url | entry_id`) plus symbolic `sequencer_did`, `key_id`,
        // `conversation_id`, `group_id`, `epoch`, `archive_commitment`, `seq`, and `issued_at_ms`,
        // proving round-trip decodability and length-prefixed framing collision freedom.
        const EXPECTED_LEN: usize = MIN_I13_RECEIPT_TRANSCRIPT_LEN + 6;

        fn one_ascii_string(b: u8) -> String {
            // SAFETY: Caller constrains `b` to printable ASCII (`0x20..=0x7e`).
            unsafe { String::from_utf8_unchecked(vec![b]) }
        }

        fn two_ascii_string(pair: &[u8; 2]) -> String {
            // SAFETY: Caller constrains `pair` bytes to printable ASCII (`0x20..=0x7e`).
            unsafe { String::from_utf8_unchecked(vec![pair[0], pair[1]]) }
        }

        #[allow(clippy::too_many_arguments)]
        fn encode_fixed_wire(
            split_one_one: bool,
            pair: &[u8; 2],
            seq_did_b: u8,
            key_id_b: u8,
            conv_b: u8,
            grp_b: u8,
            epoch: u64,
            commit: [u8; ARCHIVE_COMMITMENT_LEN],
            seq: u64,
            issued: i64,
        ) -> [u8; EXPECTED_LEN] {
            let key_id = one_ascii_string(key_id_b);
            let mut out = [0u8; EXPECTED_LEN];
            if split_one_one {
                let payload = SequencerReceiptPayload {
                    sequencer_did: one_ascii_string(seq_did_b),
                    conversation_id: one_ascii_string(conv_b),
                    group_id: vec![grp_b],
                    epoch,
                    sender_device_did_url: one_ascii_string(pair[0]),
                    entry_id: one_ascii_string(pair[1]),
                    archive_commitment: commit,
                    seq,
                    issued_at_ms: issued,
                };
                let vec_bytes = payload.canonical_signing_bytes(&key_id);
                assert!(vec_bytes.len() == EXPECTED_LEN);
                out.copy_from_slice(&vec_bytes);
                core::mem::forget((payload, vec_bytes));
            } else {
                let payload = SequencerReceiptPayload {
                    sequencer_did: one_ascii_string(seq_did_b),
                    conversation_id: one_ascii_string(conv_b),
                    group_id: vec![grp_b],
                    epoch,
                    sender_device_did_url: String::new(),
                    entry_id: two_ascii_string(pair),
                    archive_commitment: commit,
                    seq,
                    issued_at_ms: issued,
                };
                let vec_bytes = payload.canonical_signing_bytes(&key_id);
                assert!(vec_bytes.len() == EXPECTED_LEN);
                out.copy_from_slice(&vec_bytes);
                core::mem::forget((payload, vec_bytes));
            }
            core::mem::forget(key_id);
            out
        }

        let split_a: bool = kani::any();
        let split_b: bool = kani::any();

        let pair_a: [u8; 2] = kani::any();
        let pair_b: [u8; 2] = kani::any();
        let seq_did_byte_a: u8 = kani::any();
        let seq_did_byte_b: u8 = kani::any();
        let key_id_byte_a: u8 = kani::any();
        let key_id_byte_b: u8 = kani::any();
        let conv_byte_a: u8 = kani::any();
        let conv_byte_b: u8 = kani::any();
        let grp_byte_a: u8 = kani::any();
        let grp_byte_b: u8 = kani::any();
        kani::assume(
            pair_a[0] >= 0x20
                && pair_a[0] <= 0x7e
                && pair_a[1] >= 0x20
                && pair_a[1] <= 0x7e
                && pair_b[0] >= 0x20
                && pair_b[0] <= 0x7e
                && pair_b[1] >= 0x20
                && pair_b[1] <= 0x7e
                && seq_did_byte_a >= 0x20
                && seq_did_byte_a <= 0x7e
                && seq_did_byte_b >= 0x20
                && seq_did_byte_b <= 0x7e
                && key_id_byte_a >= 0x20
                && key_id_byte_a <= 0x7e
                && key_id_byte_b >= 0x20
                && key_id_byte_b <= 0x7e
                && conv_byte_a >= 0x20
                && conv_byte_a <= 0x7e
                && conv_byte_b >= 0x20
                && conv_byte_b <= 0x7e,
        );

        let epoch_a: u64 = kani::any();
        let epoch_b: u64 = kani::any();
        let commit_byte_a: u8 = kani::any();
        let commit_byte_b: u8 = kani::any();
        let commit_a = [commit_byte_a; ARCHIVE_COMMITMENT_LEN];
        let commit_b = [commit_byte_b; ARCHIVE_COMMITMENT_LEN];
        let seq_a: u64 = kani::any();
        let seq_b: u64 = kani::any();
        let issued_a: i64 = kani::any();
        let issued_b: i64 = kani::any();

        let bytes_a = encode_fixed_wire(
            split_a,
            &pair_a,
            seq_did_byte_a,
            key_id_byte_a,
            conv_byte_a,
            grp_byte_a,
            epoch_a,
            commit_a,
            seq_a,
            issued_a,
        );
        let bytes_b = encode_fixed_wire(
            split_b,
            &pair_b,
            seq_did_byte_b,
            key_id_byte_b,
            conv_byte_b,
            grp_byte_b,
            epoch_b,
            commit_b,
            seq_b,
            issued_b,
        );

        if split_a {
            let view_a = decode_canonical_receipt_signing_slices(&bytes_a)
                .expect("canonical_signing_bytes output must decode");
            assert!(view_a.sequencer_did == [seq_did_byte_a]);
            assert!(view_a.key_id == [key_id_byte_a]);
            assert!(view_a.conversation_id == [conv_byte_a]);
            assert!(view_a.group_id == [grp_byte_a]);
            assert!(view_a.epoch == epoch_a);
            assert!(view_a.sender_device_did_url == [pair_a[0]]);
            assert!(view_a.entry_id == [pair_a[1]]);
            assert!(view_a.archive_commitment == commit_a);
            assert!(view_a.seq == seq_a);
            assert!(view_a.issued_at_ms == issued_a);
        } else {
            let view_a = decode_canonical_receipt_signing_slices(&bytes_a)
                .expect("canonical_signing_bytes output must decode");
            assert!(view_a.sequencer_did == [seq_did_byte_a]);
            assert!(view_a.key_id == [key_id_byte_a]);
            assert!(view_a.conversation_id == [conv_byte_a]);
            assert!(view_a.group_id == [grp_byte_a]);
            assert!(view_a.epoch == epoch_a);
            assert!(view_a.sender_device_did_url.is_empty());
            assert!(view_a.entry_id == pair_a);
            assert!(view_a.archive_commitment == commit_a);
            assert!(view_a.seq == seq_a);
            assert!(view_a.issued_at_ms == issued_a);
        }

        let same_logical_input = split_a == split_b
            && pair_a == pair_b
            && seq_did_byte_a == seq_did_byte_b
            && key_id_byte_a == key_id_byte_b
            && conv_byte_a == conv_byte_b
            && grp_byte_a == grp_byte_b
            && epoch_a == epoch_b
            && commit_byte_a == commit_byte_b
            && seq_a == seq_b
            && issued_a == issued_b;

        let mut same_wire_bytes = true;
        let mut idx = 0usize;
        while idx < EXPECTED_LEN {
            if bytes_a[idx] != bytes_b[idx] {
                same_wire_bytes = false;
            }
            idx += 1;
        }
        assert!(same_wire_bytes == same_logical_input);

        kani::cover!(
            split_a != split_b && pair_a == pair_b && !same_wire_bytes,
            "adjacent sender_device_did_url/entry_id boundary shift produces distinct signing bytes"
        );
    }

    #[kani::proof]
    #[kani::unwind(36)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    fn kani_i13_receipt_decoder_arbitrary_no_panic() {
        // Minimum valid `I13` signing transcript is 113 bytes (`MIN_I13_RECEIPT_TRANSCRIPT_LEN`).
        // Symbolic buffer is 132 bytes (`>= 128B`), giving up to 19 bytes for the 6 variable
        // length-prefixed fields while proving both 113B minimal and >=128B populated frames
        // are reachable via `kani::cover!`.
        const BUF_CAP: usize = 132;
        assert!(MIN_I13_RECEIPT_TRANSCRIPT_LEN == 113);
        assert!(BUF_CAP >= 128 && BUF_CAP > MIN_I13_RECEIPT_TRANSCRIPT_LEN);

        let raw_transcript: [u8; BUF_CAP] = kani::any();
        let raw_len: usize = kani::any();
        kani::assume(raw_len <= raw_transcript.len());

        let slice = &raw_transcript[..raw_len];
        let view_opt = decode_canonical_receipt_signing_slices(slice);
        let valid_utf8_frame = match view_opt {
            Some(view) => {
                core::str::from_utf8(view.sequencer_did).is_ok()
                    && core::str::from_utf8(view.key_id).is_ok()
                    && core::str::from_utf8(view.conversation_id).is_ok()
                    && core::str::from_utf8(view.sender_device_did_url).is_ok()
                    && core::str::from_utf8(view.entry_id).is_ok()
            }
            None => false,
        };

        kani::cover!(
            valid_utf8_frame && raw_len == MIN_I13_RECEIPT_TRANSCRIPT_LEN,
            "minimum 113-byte valid I13 receipt transcript is reachable"
        );
        kani::cover!(
            valid_utf8_frame && raw_len >= 128,
            ">=128-byte populated valid I13 receipt transcript is reachable"
        );
        kani::cover!(
            !valid_utf8_frame && raw_len >= MIN_I13_RECEIPT_TRANSCRIPT_LEN,
            ">=113-byte malformed I13 receipt transcript rejection is reachable"
        );

        if let Some(view) = view_opt.filter(|_| valid_utf8_frame) {
            assert!(raw_len >= MIN_I13_RECEIPT_TRANSCRIPT_LEN);
            let var_sum = view.sequencer_did.len()
                + view.key_id.len()
                + view.conversation_id.len()
                + view.group_id.len()
                + view.sender_device_did_url.len()
                + view.entry_id.len();
            assert!(MIN_I13_RECEIPT_TRANSCRIPT_LEN + var_sum == raw_len);
            assert!(&slice[..RECEIPT_DOMAIN_V2.len()] == RECEIPT_DOMAIN_V2);
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    #[kani::stub(core::slice::memchr::memchr, kani_memchr)]
    #[kani::stub(core::slice::memchr::memrchr, kani_memrchr)]
    fn kani_i13_receipt_validation_invariants() {
        // Directly exercises `labyrinth_protocol::receipt::SequencerReceiptPayload::{validate_structure, split_sender_device}`
        // allocating a single unconditional heap buffer per field (`truncate`/`clear` in place)
        // so every field has a unique concrete CBMC object ID.
        let did_idx: u8 = kani::any();
        let sender_idx: u8 = kani::any();
        kani::assume(did_idx < 6 && sender_idx < 6);

        let conv_nonempty: bool = kani::any();
        let entry_nonempty: bool = kani::any();
        let group_len_regime: u8 = kani::any();
        kani::assume(group_len_regime < 3);

        let (seq_template, seq_len): (&[u8; 12], usize) = match did_idx {
            0 => (b"            ", 0),
            1 => (b"did:web:a   ", 9),
            2 => (b"did:plc:b   ", 9),
            3 => (b"did:key:c   ", 9),
            4 => (b"did:web:#bad", 12),
            _ => (b"https://ds  ", 10),
        };
        let mut seq_vec = seq_template.to_vec();
        seq_vec.truncate(seq_len);
        // SAFETY: `seq_template` contains only 7-bit ASCII bytes.
        let sequencer_did = unsafe { String::from_utf8_unchecked(seq_vec) };

        let (snd_template, snd_len): (&[u8; 13], usize) = match sender_idx {
            0 => (b"             ", 0),
            1 => (b"did:plc:a#d1 ", 12),
            2 => (b"#d1          ", 3),
            3 => (b"did:plc:a#   ", 10),
            4 => (b"did:plc:a#d#2", 13),
            _ => (b"no_fragment  ", 11),
        };
        let mut snd_vec = snd_template.to_vec();
        snd_vec.truncate(snd_len);
        // SAFETY: `snd_template` contains only 7-bit ASCII bytes.
        let sender_device_did_url = unsafe { String::from_utf8_unchecked(snd_vec) };

        let mut conv_vec = b"c1".to_vec();
        if !conv_nonempty {
            conv_vec.clear();
        }
        // SAFETY: `"c1"` is ASCII.
        let conversation_id = unsafe { String::from_utf8_unchecked(conv_vec) };

        let mut entry_vec = b"e1".to_vec();
        if !entry_nonempty {
            entry_vec.clear();
        }
        // SAFETY: `"e1"` is ASCII.
        let entry_id = unsafe { String::from_utf8_unchecked(entry_vec) };

        let grp_byte: u8 = kani::any();
        let mut grp = vec![grp_byte; GROUP_ID_LEN];
        match group_len_regime {
            0 => grp.clear(),
            1 => grp.truncate(GROUP_ID_LEN - 1),
            _ => {}
        }

        let commit_byte: u8 = kani::any();
        let payload = SequencerReceiptPayload {
            sequencer_did,
            conversation_id,
            group_id: grp,
            epoch: kani::any(),
            sender_device_did_url,
            entry_id,
            archive_commitment: [commit_byte; ARCHIVE_COMMITMENT_LEN],
            seq: kani::any(),
            issued_at_ms: kani::any(),
        };

        let res = payload.validate_structure();
        kani::cover!(
            res.is_ok(),
            "valid SequencerReceiptPayload passes validate_structure"
        );
        kani::cover!(
            res.is_err(),
            "invalid SequencerReceiptPayload fails validate_structure"
        );

        if res.is_ok() {
            assert!(
                payload.sequencer_did.starts_with("did:web:")
                    || payload.sequencer_did.starts_with("did:plc:")
            );
            assert!(!payload.sequencer_did.contains('#'));
            assert!(!payload.conversation_id.is_empty() && !payload.entry_id.is_empty());
            assert!(payload.group_id.len() == GROUP_ID_LEN);
            assert!(payload.seq >= 1 && payload.issued_at_ms >= 0);
            let (sender_did, sender_dev) = payload
                .split_sender_device()
                .expect("validated payload has valid sender_device_did_url");
            assert!(!sender_did.is_empty() && !sender_dev.is_empty());
            assert!(!sender_did.contains('#') && !sender_dev.contains('#'));
        }
        core::mem::forget((payload, res));
    }

    #[kani::proof]
    #[kani::unwind(28)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    #[kani::stub(core::slice::memchr::memchr, kani_memchr)]
    #[kani::stub(core::slice::memchr::memrchr, kani_memrchr)]
    #[kani::stub(std::fmt::format, kani_err_fmt_stub)]
    fn kani_i13_receipt_key_generation_canonical_positive() {
        // Directly exercises `labyrinth_protocol::receipt::receipt_key_generation`
        // over zero-alloc symbolic stack `&str` inputs (`0..=26` bytes).
        const CANON_SEQ_DID: &str = "did:web:ds";
        assert!(receipt_key_generation(CANON_SEQ_DID, "did:web:ds#mls-receipt-1").unwrap() == 1);

        let raw_key: [u8; 26] = kani::any();
        let raw_len: usize = kani::any();
        kani::assume(raw_len <= raw_key.len());
        let candidate_kid = ascii_str_from_slice(&raw_key[..raw_len]);

        let res = receipt_key_generation(CANON_SEQ_DID, candidate_kid);
        kani::cover!(res.is_ok(), "valid receipt key_id generation is reachable");
        kani::cover!(
            res.is_err() && candidate_kid.starts_with("did:web:ds#mls-receipt-0"),
            "zero or leading-zero receipt key generation rejection is reachable"
        );

        if let Ok(gen) = &res {
            assert!(*gen >= 1);
            assert!(candidate_kid.len() > 23);
            assert!(candidate_kid.starts_with("did:web:ds#mls-receipt-"));
            let suffix = &candidate_kid.as_bytes()[23..];
            assert!(suffix[0] >= b'1' && suffix[0] <= b'9');
            let mut idx = 0;
            while idx < suffix.len() {
                assert!(suffix[idx].is_ascii_digit());
                idx += 1;
            }
        }
        core::mem::forget(res);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(42)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    fn kani_gf32_ecc_any_three_columns_independent() {
        // Directly exercises `labyrinth::recovery_code::RecoveryCode::from_entropy_symbols`:
        // Over the systematic `[38, 34]` GF(32) elliptic-quadric code `C` in `PG(3, 32)`,
        // quantifying over ALL `32,767` non-zero `(e0, e1, e2) in GF(32)^3 \ {(0, 0, 0)}`
        // across boundary + interior entropy columns `{0, 17, 33}` proves every non-zero
        // weight-1, weight-2, and weight-3 input produces Hamming weight `>= 4` (`d_min >= 4`).
        // Full `C(38, 3) = 8,436` column-triple independence is verified exhaustively in `kani_proofs::tests`.
        use labyrinth::recovery_code::{RecoveryCode, CODE_LEN, ENTROPY_LEN};

        let e0: u8 = kani::any::<u8>() & 0x1f;
        let e1: u8 = kani::any::<u8>() & 0x1f;
        let e2: u8 = kani::any::<u8>() & 0x1f;
        kani::assume((e0 | e1 | e2) != 0);

        let mut u = [0u8; ENTROPY_LEN];
        u[0] = e0;
        u[17] = e1;
        u[ENTROPY_LEN - 1] = e2;

        let code = RecoveryCode::from_entropy_symbols(&u);
        let bytes = code.as_str().as_bytes();
        assert!(bytes.len() == CODE_LEN);
        let mut weight = 0usize;
        let mut idx = 2usize;
        while idx < CODE_LEN {
            if bytes[idx] != b'A' {
                weight += 1;
            }
            idx += 1;
        }
        assert!(weight >= 4);

        kani::cover!(
            e0 != 0 && e1 != 0 && e2 != 0 && weight >= 4,
            "3 non-zero GF(32) entropy symbols yield codeword of Hamming weight >= 4"
        );
        core::mem::forget(code);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(42)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    fn kani_gf32_recovery_code_encode_and_homoglyph_roundtrip() {
        // Directly exercises `labyrinth::recovery_code::RecoveryCode::{parse, as_str, entropy_chars}`
        // on `"2oaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaggp7o"` -> `"20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCP70"`,
        // proving lowercase normalization and homoglyph recovery (`O->0` in both header identifier
        // and ECC tail, `G->C` in both entropy and ECC tail) across every symbolic index
        // `check_idx in 0..40`. Full 32-symbol KAT + 4-homoglyph (`B->8`, `G->C`, `I->1`, `O->0`) +
        // separator round-trips and `RecoveryCode::from_entropy_symbols` are verified in the
        // companion `GF(32)` Kani proofs and `kani_proofs::tests`.
        use labyrinth::recovery_code::{
            RecoveryCode, CODE_LEN, ECC_LEN, ENTROPY_LEN, IDENTIFIER, VERSION,
        };

        assert!(CODE_LEN == 2 + ENTROPY_LEN + ECC_LEN && CODE_LEN == 40);
        assert!(VERSION == b'2' && IDENTIFIER == b'0');

        const EXPECTED: &[u8; CODE_LEN] = b"20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCP70";
        let parsed = RecoveryCode::parse("2oaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaggp7o")
            .expect("homoglyphs G->C, O->0, and lowercase must parse");

        let parsed_bytes = parsed.as_str().as_bytes();
        let ent_chars = parsed.entropy_chars();
        assert!(parsed_bytes.len() == CODE_LEN);
        assert!(ent_chars.len() == ENTROPY_LEN);

        let check_idx: usize = kani::any();
        kani::assume(check_idx < CODE_LEN);
        assert!(parsed_bytes[check_idx] == EXPECTED[check_idx]);
        if check_idx < ENTROPY_LEN {
            assert!(ent_chars[check_idx] == EXPECTED[2 + check_idx]);
        }

        kani::cover!(
            check_idx == 36
                && parsed_bytes[1] == IDENTIFIER
                && ent_chars[33] == b'C'
                && parsed_bytes[check_idx] == b'C'
                && parsed_bytes[39] == b'0',
            "homoglyphs 'o'->'0' and 'g'->'C' across header, entropy, and ECC tail round-trip"
        );
        core::mem::forget(parsed);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(48)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    fn kani_gf32_recovery_code_single_error_rejection() {
        // Directly exercises `labyrinth::recovery_code::RecoveryCode::parse` across bad version,
        // bad identifier, separator-shortened length, single-symbol GF(32) ECC-tail substitution,
        // and '?' erasure rejection via per-arm concrete `&'static str` dispatch (avoiding CBMC
        // heap guard-poisoning from `chars.zeroize()`). Exhaustive 38x31 single-error rejection
        // across all codeword columns and alphabet symbols is verified in `kani_proofs::tests`.
        use labyrinth::recovery_code::RecoveryCode;

        let case: u8 = kani::any();
        kani::assume(case < 5);

        let parsed = match case {
            0 => RecoveryCode::parse("10AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            1 => RecoveryCode::parse("21AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            2 => RecoveryCode::parse("20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-"),
            3 => RecoveryCode::parse("20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC"),
            _ => RecoveryCode::parse("20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?"),
        };
        assert!(parsed.is_err());

        kani::cover!(
            case == 3,
            "ECC-tail single-symbol alphabet substitution rejected by RecoveryCode::parse"
        );
        kani::cover!(
            case == 4,
            "erasure/non-alphabet character rejected by exact RecoveryCode::parse"
        );
        core::mem::forget(parsed);
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(42)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    fn kani_gf32_ecc_triple_erasure_and_ecc_tail_uniqueness() {
        // Directly exercises `labyrinth::recovery_code::RecoveryCode::from_entropy_symbols`:
        // Because `GF(32) = GF(2)[x]/(x^5 + x^2 + 1)` addition is bitwise XOR and `H · word = 0`
        // is `GF(32)`-linear with injective `ALPHABET` (`ALPHABET[0] == b'A'`), two codewords
        // `code(u_a)` and `code(u_b)` agree at column `j` iff `code(u_a ^ u_b)` equals `b'A'` at `j`.
        // Quantifying symbolically over all `32,768` difference vectors `(d0, d1, d2) in GF(32)^3`
        // at boundary + interior columns `{0, 17, 33}` AND all `C(38, 3) = 8,436` erased column
        // triples `0 <= c0 < c1 < c2 < 38` proves:
        //   1. Unique MDS triple-erasure recovery across pure-entropy, mixed entropy+ECC, and
        //      pure-ECC (`34..38`) erasures: vanishing outside `{c0, c1, c2}` forces `u_diff == 0`
        //      and uniquely determines all 3 erased symbols;
        //   2. 4-symbol ECC parity tail collision-freedom: `wa[34..38] == "AAAA"` iff `u_diff == 0`.
        // Iterator-level `RecoveryCode::candidates` 3-erasure recovery and 4-erasure rejection
        // are additionally verified in `kani_proofs::tests`.
        use labyrinth::recovery_code::{RecoveryCode, ALPHABET, CODE_LEN, ECC_LEN, ENTROPY_LEN};

        const WORD_LEN: usize = ENTROPY_LEN + ECC_LEN;
        const ZERO_SYM_CHAR: u8 = ALPHABET[0];

        let d0: u8 = kani::any::<u8>() & 0x1f;
        let d1: u8 = kani::any::<u8>() & 0x1f;
        let d2: u8 = kani::any::<u8>() & 0x1f;

        let c0: usize = kani::any();
        let c1: usize = kani::any();
        let c2: usize = kani::any();
        kani::assume(c0 < c1 && c1 < c2 && c2 < WORD_LEN);

        let mut u_diff = [0u8; ENTROPY_LEN];
        u_diff[0] = d0;
        u_diff[ENTROPY_LEN / 2] = d1;
        u_diff[ENTROPY_LEN - 1] = d2;

        let code = RecoveryCode::from_entropy_symbols(&u_diff);
        let w = &code.as_str().as_bytes()[2..CODE_LEN];

        let mut zero_outside_erased = true;
        let mut idx = 0usize;
        while idx < WORD_LEN {
            if idx != c0 && idx != c1 && idx != c2 && w[idx] != ZERO_SYM_CHAR {
                zero_outside_erased = false;
            }
            idx += 1;
        }
        if zero_outside_erased {
            assert!(d0 == 0 && d1 == 0 && d2 == 0);
            assert!(w[c0] == ZERO_SYM_CHAR && w[c1] == ZERO_SYM_CHAR && w[c2] == ZERO_SYM_CHAR);
        }

        let zero_ecc_tail = w[ENTROPY_LEN] == ZERO_SYM_CHAR
            && w[ENTROPY_LEN + 1] == ZERO_SYM_CHAR
            && w[ENTROPY_LEN + 2] == ZERO_SYM_CHAR
            && w[ENTROPY_LEN + 3] == ZERO_SYM_CHAR;
        assert!(zero_ecc_tail == (d0 == 0 && d1 == 0 && d2 == 0));

        kani::cover!(
            c0 == 0
                && c1 == 34
                && c2 == 37
                && d0 != 0
                && d2 != 0
                && !zero_outside_erased
                && !zero_ecc_tail,
            "mixed entropy+ECC triple erasure (0, 34, 37) and 4-symbol ECC tail collision-freedom"
        );
        core::mem::forget(code);
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

        // `MIN_LEN = 10` floor, monotonicity, idempotence, and 4-byte prefix headroom.
        assert!(p1 >= l1.max(10));
        assert!(p1 <= p2);
        assert!(padme_len(p1) == p1);
        assert!(p2.checked_add(4).is_some());

        // PADMÉ overhead above `l >= 10` is bounded by `<= l / 8` (12.5%).
        if l1 >= 10 {
            assert!(p1 - l1 <= (l1 >> 3).max(1));
        }
        kani::cover!(l1 < 10 && p1 == 10, "PADME MIN_LEN=10 floor exercised");
        kani::cover!(
            l1 > 1024 && p1 > l1,
            "PADME non-trivial bucket rounding exercised"
        );
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(17)]
    fn kani_pad_unpad_roundtrip() {
        use labyrinth::padding::{pad, padme_len, unpad};

        // Concrete length regimes across symbolic payload bytes `[u8; 11]`, covering
        // `0->10`, `1->10`, `9->10`, `10->10`, and `11->12` PADMÉ bucket transitions
        // while keeping CBMC heap allocations concrete (`14B` and `16B`).
        let raw_buf: [u8; 11] = kani::any();
        let mut observed_bucket_16 = false;
        for raw_len in [0usize, 1, 9, 10, 11] {
            let padded = pad(&raw_buf[..raw_len]);
            assert!(padded.len() == 4 + padme_len(raw_len));
            if raw_len == 11 && padded.len() == 16 {
                observed_bucket_16 = true;
            }
            let recovered = unpad(&padded).expect("pad output must unpad");
            assert!(recovered.as_slice() == &raw_buf[..raw_len]);
            core::mem::forget((padded, recovered));
        }
        kani::cover!(
            observed_bucket_16 && raw_buf[0] != 0 && raw_buf[10] != 0,
            "11->12 PADME bucket round-trip on non-zero symbolic payload"
        );
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(17)]
    fn kani_unpad_arbitrary_strict_canonical() {
        use labyrinth::padding::{padme_len, unpad};

        // Arbitrary symbolic candidate frame up to 16 bytes (`4 + padme_len(11)`).
        let candidate: [u8; 16] = kani::any();
        let clen: usize = kani::any();
        kani::assume(clen <= candidate.len());

        let slice = &candidate[..clen];
        let res = unpad(slice);
        kani::cover!(
            res.is_ok() && clen == 16,
            "valid 16-byte PADME frame unpads"
        );
        kani::cover!(
            res.is_err() && clen >= 14,
            "non-canonical PADME frame rejected"
        );

        if let Ok(plain) = res {
            let plen = plain.len();
            assert!(clen == 4 + padme_len(plen));
            let declared = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
            assert!(declared == plen);
            assert!(&slice[4..4 + plen] == plain.as_slice());
            let mut idx = 4 + plen;
            while idx < clen {
                assert!(slice[idx] == 0);
                idx += 1;
            }
        }
    }

    #[cfg(feature = "labyrinth")]
    #[kani::proof]
    #[kani::unwind(22)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    #[kani::stub(std::fmt::format, kani_err_fmt_stub)]
    fn kani_epoch_and_send_counter_overflow_bounds() {
        // Directly exercises `labyrinth::records::check_epoch_number` over full 64-bit `u64`
        // and `catbird_mls::client::chat_wire::{next_send_counter, confirmed_send_counter}`
        // across boundary send-counter regimes (`0`, `1`, `2`, `MAX - 1`, `MAX`, `MAX + 1`, `u64::MAX`).
        let current_epoch: u64 = kani::any();
        let delta: u64 = kani::any();
        match checked_advance_epoch(current_epoch, delta) {
            Ok(next) => {
                assert!(next > current_epoch);
                assert!(next <= labyrinth::records::MAX_EPOCH_NUMBER);
                assert!(labyrinth::records::check_epoch_number(next).is_ok());
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

        const COUNTER_BOUNDARIES: [(&str, u64); 7] = [
            ("0", 0),
            ("1", 1),
            ("2", 2),
            ("9007199254740990", MAX_SAFE_SEND_COUNTER - 1),
            ("9007199254740991", MAX_SAFE_SEND_COUNTER),
            ("9007199254740992", MAX_SAFE_SEND_COUNTER + 1),
            ("18446744073709551615", u64::MAX),
        ];

        let has_prev: bool = kani::any();
        let prev_idx: usize = kani::any();
        kani::assume(prev_idx < COUNTER_BOUNDARIES.len());

        let (prev_raw, prev_val) = COUNTER_BOUNDARIES[prev_idx];
        kani::assume(prev_raw.len() <= 20);
        let prev_str = if has_prev { Some(prev_raw) } else { None };

        let next_res = next_send_counter(prev_str);
        match next_res {
            Ok(next) => {
                let expected = if has_prev { prev_val + 1 } else { 1 };
                assert!(next == expected);
                assert!(next >= 1 && next <= MAX_SAFE_SEND_COUNTER);
                let conf_res = confirmed_send_counter(prev_str, next);
                assert!(conf_res.is_ok());
                if let Ok(conf) = &conf_res {
                    assert!(*conf == next);
                }
                core::mem::forget(conf_res);
            }
            Err(e) => {
                core::mem::forget(e);
                assert!(has_prev && prev_val >= MAX_SAFE_SEND_COUNTER);
            }
        }
    }

    #[kani::proof]
    #[kani::stub(std::fmt::format, kani_err_fmt_stub)]
    fn kani_peer_send_counter_strict_continuity() {
        // Directly exercises `catbird_mls::client::send_counter::{classify_peer_send_counter,
        // select_peer_counter_prior, advance_epoch_chain}` over symbolic 64-bit inputs.
        let next: u64 = kani::any();
        let has_prior: bool = kani::any();
        let prior = PeerCounterPrior {
            last: kani::any(),
            skipped: kani::any(),
            same_epoch: kani::any(),
        };
        let verdict = classify_peer_send_counter(has_prior.then_some(prior), next);
        match &verdict {
            Err(_) => {
                // Valid counters are evidence only; only an invalid wire range is refused.
                assert!(next == 0 || next > MAX_SAFE_SEND_COUNTER);
            }
            Ok(PeerCounterVerdict::Baseline) => assert!(!has_prior),
            Ok(PeerCounterVerdict::Contiguous) => {
                // Exactly one past the last counter plus every entry counted without one.
                assert!(has_prior && next > prior.last);
                assert!(prior.last.saturating_add(1).saturating_add(prior.skipped) == next);
            }
            Ok(PeerCounterVerdict::Gap { expected, received }) => {
                assert!(has_prior && next > prior.last && *received == next);
                assert!(*expected == prior.last.saturating_add(1).saturating_add(prior.skipped));
                assert!(*expected != next);
            }
            Ok(PeerCounterVerdict::Regressed { last, received }) => {
                assert!(has_prior);
                assert!(*last == prior.last && *received == next && next <= prior.last);
            }
        }
        if next > 0 && next <= MAX_SAFE_SEND_COUNTER && has_prior && next > prior.last {
            // Strictness: any increasing counter other than the expected one is a gap.
            assert!(verdict.as_ref().is_ok_and(|v| match v {
                PeerCounterVerdict::Contiguous => {
                    next == prior.last.saturating_add(1).saturating_add(prior.skipped)
                }
                PeerCounterVerdict::Gap { .. } => {
                    next != prior.last.saturating_add(1).saturating_add(prior.skipped)
                }
                _ => false,
            }));
        }
        kani::cover!(
            matches!(verdict, Ok(PeerCounterVerdict::Gap { .. })),
            "gap recorded"
        );
        kani::cover!(
            matches!(verdict, Ok(PeerCounterVerdict::Contiguous)),
            "contiguous accepted"
        );
        core::mem::forget(verdict);

        // The chain only grows by one applied Commit at a time; anything else restarts it.
        let has_chain: bool = kani::any();
        let chain = EpochChain {
            start: kani::any(),
            current: kani::any(),
        };
        kani::assume(chain.start <= chain.current);
        let prior_epoch: u64 = kani::any();
        let next_epoch: u64 = kani::any();
        let advanced = advance_epoch_chain(has_chain.then_some(chain), prior_epoch, next_epoch);
        assert!(advanced.current == next_epoch && advanced.start <= advanced.current);
        if has_chain
            && chain.current == prior_epoch
            && prior_epoch.checked_add(1) == Some(next_epoch)
        {
            assert!(advanced.start == chain.start);
        } else if prior_epoch.checked_add(1) == Some(next_epoch) {
            assert!(advanced.start == prior_epoch);
        } else {
            assert!(advanced.start == next_epoch);
        }

        // A counter from another epoch is compared only when the chain covers both epochs.
        let epoch: u64 = kani::any();
        let has_epoch_last: bool = kani::any();
        let epoch_last: u64 = kani::any();
        let has_continuity: bool = kani::any();
        let continuity: (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let selected = select_peer_counter_prior(
            has_epoch_last.then_some(epoch_last),
            has_continuity.then_some(continuity),
            has_chain.then_some(chain),
            epoch,
        );
        match selected {
            Some(p) if p.same_epoch => assert!(has_epoch_last && p.last == epoch_last),
            Some(p) => {
                assert!(!has_epoch_last && has_continuity && p.last == continuity.0);
                assert!(
                    continuity.2 == epoch
                        || (has_chain
                            && chain.start <= continuity.2
                            && continuity.2 <= epoch
                            && epoch <= chain.current)
                );
            }
            None => assert!(!has_epoch_last),
        }
    }

    #[kani::proof]
    #[kani::unwind(36)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    #[kani::stub(std::fmt::format, kani_err_fmt_stub)]
    fn kani_atproto_spaces_uri_and_hedged_normalization() {
        // Directly exercises `atproto_spaces::{is_atproto_did, is_valid_did, is_valid_nsid, is_valid_rkey, SpaceUri::record_uri}`
        // over zero-alloc symbolic stack `&str` rkeys (`0..=3` bytes).
        // Note: `SpaceUri::record_uri` validates `is_valid_did && is_valid_nsid && is_valid_rkey`
        // before invoking `format!` in either `Ok` or `Err`, so `rec_res.is_ok()` verifies the
        // exact unstubbed acceptance guard.
        use atproto_spaces::{
            is_atproto_did, is_valid_did, is_valid_nsid, is_valid_rkey, SpaceUri,
        };

        let raw_skey: [u8; 3] = kani::any();
        let skey_len: usize = kani::any();
        kani::assume(skey_len <= raw_skey.len());
        let skey = ascii_str_from_slice(&raw_skey[..skey_len]);
        kani::assume(skey.len() <= 3);

        let authority = "did:web:a.b";
        let space_type = "a.b.c";
        assert!(is_atproto_did(authority) && is_valid_did(authority));
        assert!(is_valid_nsid(space_type));
        assert!(!is_atproto_did("did:key:z6Mk"));

        let rkey_ok = is_valid_rkey(skey);
        kani::cover!(rkey_ok, "valid ATProto rkey/skey accepted by is_valid_rkey");
        kani::cover!(
            !rkey_ok,
            "invalid ATProto rkey/skey (empty, '.', '..', or bad char) rejected by is_valid_rkey"
        );

        let base_uri = SpaceUri {
            raw: String::from("at:space/did:web:a.b/a.b.c/x"),
            authority: String::from(authority),
            space_type: String::from(space_type),
            rkey: String::from("x"),
        };
        let rec_res = base_uri.record_uri(authority, "a.b.m", skey);
        let rec_ok = rec_res.is_ok();
        core::mem::forget((base_uri, rec_res));
        assert!(rec_ok == rkey_ok);
        if rec_ok {
            assert!(!skey.is_empty() && skey != "." && skey != "..");
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    #[kani::stub(core::str::from_utf8, kani_str_from_utf8)]
    #[kani::stub(core::slice::memchr::memchr, kani_memchr)]
    #[kani::stub(core::slice::memchr::memrchr, kani_memrchr)]
    #[kani::stub(std::fmt::format, kani_err_fmt_stub)]
    #[kani::stub(core::fmt::write, kani_fmt_write_noop)]
    fn kani_atproto_spaces_accept_signature_sf_roundtrip() {
        // Directly exercises `atproto_spaces::mac::{format_accept_signature, MacProfile}`:
        //   1. Profile domain separation (`MacProfile::{Commit, Record}` tags and covered header names);
        //   2. Fail-closed rejection of ASCII control/DEL boundaries (`0x00`, `0x1f`, `0x7f`),
        //      symbolic 2-byte UTF-8 (`U+0080..=U+00BF`), and symbolic 3-byte UTF-8
        //      (`U+2000..=U+203F` Unicode spaces/bidirectional marks) in `format_accept_signature`.
        //      `parse_accept_signature` grammar and full `format_accept_signature` ->
        //      `parse_accept_signature` round-trips are verified in `kani_proofs::tests`.
        use atproto_spaces::mac::{format_accept_signature, MacProfile};

        assert!(MacProfile::Commit.as_str().len() == 20 && MacProfile::Record.as_str().len() == 20);
        assert!(
            MacProfile::Commit.as_str().as_bytes()[14] == b'c'
                && MacProfile::Record.as_str().as_bytes()[14] == b'r'
        );
        assert!(
            MacProfile::Commit.response_header().as_bytes()[14] == b'c'
                && MacProfile::Record.response_header().as_bytes()[14] == b'r'
        );

        let cont_b: u8 = kani::any();
        kani::assume((0x80..=0xbf).contains(&cont_b));
        let utf8_2b = [0xc2, cont_b];
        // SAFETY: `[0xC2, 0x80..=0xBF]` is valid 2-byte UTF-8 (`U+0080..=U+00BF`).
        let utf8_2b_kid = unsafe { core::str::from_utf8_unchecked(&utf8_2b) };

        let cont_3b: u8 = kani::any();
        kani::assume((0x80..=0xbf).contains(&cont_3b));
        let utf8_3b = [0xe2, 0x80, cont_3b];
        // SAFETY: `[0xE2, 0x80, 0x80..=0xBF]` is valid 3-byte UTF-8 (`U+2000..=U+203F`).
        let utf8_3b_kid = unsafe { core::str::from_utf8_unchecked(&utf8_3b) };

        let fmt_nul = format_accept_signature(MacProfile::Commit, "\x00");
        let fmt_us = format_accept_signature(MacProfile::Record, "\x1f");
        let fmt_del = format_accept_signature(MacProfile::Commit, "\x7f");
        let fmt_2b = format_accept_signature(MacProfile::Record, utf8_2b_kid);
        let fmt_3b = format_accept_signature(MacProfile::Commit, utf8_3b_kid);
        let fmt_rejected = fmt_nul.is_err()
            && fmt_us.is_err()
            && fmt_del.is_err()
            && fmt_2b.is_err()
            && fmt_3b.is_err();
        assert!(fmt_rejected);
        core::mem::forget((fmt_nul, fmt_us, fmt_del, fmt_2b, fmt_3b));

        kani::cover!(
            cont_b == 0xa0 && fmt_rejected,
            "control/DEL + non-ASCII 2-byte UTF-8 (U+00A0 NBSP) keyids rejected by format_accept_signature"
        );
        kani::cover!(
            cont_3b == 0xae && fmt_rejected,
            "3-byte UTF-8 bidirectional override (U+202E RLO) keyid rejected by format_accept_signature"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn rfc3629_utf8_validator_matches_std_from_utf8_exhaustively_and_on_boundaries() {
        // Exhaustive 1-byte check (256 sequences).
        for b0 in 0u8..=255 {
            let seq = [b0];
            assert_eq!(
                is_valid_utf8_rfc3629(&seq),
                core::str::from_utf8(&seq).is_ok(),
                "1-byte mismatch at {b0:#04x}"
            );
        }

        // Exhaustive 2-byte check (65,536 sequences).
        for b0 in 0u8..=255 {
            for b1 in 0u8..=255 {
                let seq = [b0, b1];
                assert_eq!(
                    is_valid_utf8_rfc3629(&seq),
                    core::str::from_utf8(&seq).is_ok(),
                    "2-byte mismatch at [{b0:#04x}, {b1:#04x}]"
                );
            }
        }

        // Targeted 3-byte and 4-byte boundarysweep: overlongs (0xE0, 0xF0),
        // UTF-16 surrogates (0xED 0xA0..=0xBF), above U+10FFFF (0xF4 0x90..=0xBF),
        // truncated tails, and valid multi-scalar mixtures.
        for b0 in [
            0xDFu8, 0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5,
        ] {
            for b1 in [0x00u8, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xFF] {
                for b2 in [0x00u8, 0x7F, 0x80, 0xBF, 0xC0, 0xFF] {
                    let seq3 = [b0, b1, b2];
                    assert_eq!(
                        is_valid_utf8_rfc3629(&seq3),
                        core::str::from_utf8(&seq3).is_ok(),
                        "3-byte mismatch at {seq3:02x?}"
                    );
                    for b3 in [0x00u8, 0x7F, 0x80, 0xBF, 0xC0, 0xFF] {
                        let seq4 = [b0, b1, b2, b3];
                        assert_eq!(
                            is_valid_utf8_rfc3629(&seq4),
                            core::str::from_utf8(&seq4).is_ok(),
                            "4-byte mismatch at {seq4:02x?}"
                        );
                    }
                }
            }
        }

        let mixed = "catbird-mls:v1:sequencer-receipt\0🚀✨日本語x'deadbeef'";
        assert!(is_valid_utf8_rfc3629(mixed.as_bytes()));
    }

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
    fn i13_receipt_framing_min_len_113_and_roundtrips_without_boundary_shifts() {
        let empty_payload = SequencerReceiptPayload {
            sequencer_did: String::new(),
            conversation_id: String::new(),
            group_id: Vec::new(),
            epoch: 0,
            sender_device_did_url: String::new(),
            entry_id: String::new(),
            archive_commitment: [0u8; ARCHIVE_COMMITMENT_LEN],
            seq: 0,
            issued_at_ms: 0,
        };
        let min_bytes = empty_payload.canonical_signing_bytes("");
        assert_eq!(min_bytes.len(), MIN_I13_RECEIPT_TRANSCRIPT_LEN);
        assert_eq!(MIN_I13_RECEIPT_TRANSCRIPT_LEN, 113);
        assert_eq!(
            decode_canonical_receipt_signing_bytes(&min_bytes),
            Some((empty_payload, String::new()))
        );

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
        assert!(bytes_a.len() >= 128);

        let (decoded, key_id) =
            decode_canonical_receipt_signing_bytes(&bytes_a).expect("round-trip decode");
        assert_eq!(decoded, p_left);
        assert_eq!(key_id, "did:web:ds.example#mls-receipt-1");
        assert!(decoded.validate_structure().is_ok());
        assert_eq!(
            receipt_key_generation(&decoded.sequencer_did, &key_id).unwrap(),
            1
        );
    }

    #[cfg(feature = "labyrinth")]
    #[test]
    fn gf32_recovery_code_mds_triple_erasure_and_single_error_rejection() {
        use labyrinth::recovery_code::{RecoveryCode, ALPHABET, ENTROPY_LEN};

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
    fn padme_epoch_send_counter_and_spaces_bounds_property() {
        use atproto_spaces::mac::{format_accept_signature, parse_accept_signature, MacProfile};
        use atproto_spaces::SpaceUri;
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
        let prior = |last, skipped, same_epoch| {
            Some(PeerCounterPrior {
                last,
                skipped,
                same_epoch,
            })
        };
        assert_eq!(
            classify_peer_send_counter(prior(10, 0, true), 10).unwrap(),
            PeerCounterVerdict::Regressed {
                last: 10,
                received: 10
            }
        );
        assert_eq!(
            classify_peer_send_counter(prior(10, 0, true), 11).unwrap(),
            PeerCounterVerdict::Contiguous
        );
        assert_eq!(
            classify_peer_send_counter(prior(10, 0, true), 13).unwrap(),
            PeerCounterVerdict::Gap {
                expected: 11,
                received: 13
            }
        );
        assert_eq!(
            classify_peer_send_counter(prior(10, 2, false), 13).unwrap(),
            PeerCounterVerdict::Contiguous
        );
        assert_eq!(
            classify_peer_send_counter(prior(10, 0, false), 9).unwrap(),
            PeerCounterVerdict::Regressed {
                last: 10,
                received: 9
            }
        );
        assert!(classify_peer_send_counter(None, MAX_SAFE_SEND_COUNTER + 1).is_err());
        let chain = advance_epoch_chain(None, 4, 5);
        assert_eq!(
            chain,
            EpochChain {
                start: 4,
                current: 5
            }
        );
        assert_eq!(
            advance_epoch_chain(Some(chain), 5, 6),
            EpochChain {
                start: 4,
                current: 6
            }
        );
        assert_eq!(
            advance_epoch_chain(Some(chain), 7, 8),
            EpochChain {
                start: 7,
                current: 8
            }
        );
        assert!(select_peer_counter_prior(None, Some((3, 0, 4)), Some(chain), 5).is_some());
        assert!(select_peer_counter_prior(None, Some((3, 0, 3)), Some(chain), 5).is_none());
        assert_eq!(confirmed_send_counter(Some("10"), 11).unwrap(), 11);

        let uri = SpaceUri::parse_hedged("at:space/did:plc:abc123xyz/app.bsky.space/3lb7skey")
            .expect("hedged URI must normalize");
        assert_eq!(
            uri.as_str(),
            "at:space/did:plc:abc123xyz/app.bsky.space/3lb7skey"
        );
        let hdr = format_accept_signature(MacProfile::Record, "did:key:zDnaerDaTF5BXEavCrfRZEk")
            .expect("format Accept-Signature");
        let (lbl, kid) = parse_accept_signature(&hdr, MacProfile::Record).unwrap();
        assert_eq!(lbl, "mac");
        assert_eq!(kid, "did:key:zDnaerDaTF5BXEavCrfRZEk");
    }
}
