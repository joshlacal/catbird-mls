#![no_main]

use std::sync::OnceLock;

use catbird_mls::kani_proofs::{
    decode_canonical_receipt_signing_bytes, parse_sqlcipher_96hex_key_spec,
};
use labyrinth::mek::Mek;
use labyrinth::message::{open_owner_content, open_sender, seal_owner_attributed, OwnerMessage};
use labyrinth::padding::{pad, unpad};
use labyrinth::records::{AuthorRedaction, Batch, BatchEntry, MekDistribution, OwnerBatch};
use labyrinth_protocol::receipt::{verify_sequencer_receipt, SignedSequencerReceipt};
use libfuzzer_sys::fuzz_target;
use p256::ecdsa::{SigningKey, VerifyingKey};

struct FrameFixture {
    root: [u8; 32],
    mek: Mek,
    owner_msg: OwnerMessage,
    sequencer_vk: VerifyingKey,
}

fn fixture() -> &'static FrameFixture {
    static FIXTURE: OnceLock<FrameFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root = [0x37u8; 32];
        let mek = Mek::generate(&[[0x12u8; 32]]).expect("generate mek");
        let owner_msg = seal_owner_attributed(
            &root,
            3,
            "conv_fuzz",
            "msg_fuzz_1",
            1_760_000_000_000,
            "did:plc:alice",
            b"archived-frame-seed",
        )
        .expect("seal_owner_attributed");
        let sk = SigningKey::from_bytes((&[0x11u8; 32]).into()).expect("p256 key");
        let sequencer_vk = *sk.verifying_key();
        FrameFixture {
            root,
            mek,
            owner_msg,
            sequencer_vk,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }

    // 1. PADMÉ strict unpad -> canonical re-pad invariant.
    if let Ok(plain) = unpad(data) {
        assert_eq!(pad(&plain).as_slice(), data);
    }

    let fx = fixture();

    // 2. DAG-CBOR decoding of sender Batch, OwnerBatch, MekDistribution, AuthorRedaction.
    if let Ok(batch_rec) = serde_ipld_dagcbor::from_slice::<Batch>(data) {
        if let Ok(entries) = batch_rec.entries() {
            for entry in &entries {
                if let BatchEntry::Sealed(sealed) = entry {
                    let _ = open_sender(sealed, &batch_rec.thread_id, &fx.mek);
                }
            }
        }
    }

    if let Ok(owner_batch_rec) = serde_ipld_dagcbor::from_slice::<OwnerBatch>(data) {
        if let Ok(messages) = owner_batch_rec.to_messages() {
            for msg in &messages {
                let _ = open_owner_content(&fx.root, msg);
            }
        }
    }

    if let Ok(mek_rec) = serde_ipld_dagcbor::from_slice::<MekDistribution>(data) {
        let _ = mek_rec.to_record();
    }

    if let Ok(redaction_rec) = serde_ipld_dagcbor::from_slice::<AuthorRedaction>(data) {
        let _ = redaction_rec.to_redaction();
    }

    // 3. I13 sequencer receipt wire and canonical signing-transcript decoding.
    if let Ok(receipt) = serde_ipld_dagcbor::from_slice::<SignedSequencerReceipt>(data) {
        let _ = receipt.payload.validate_structure();
        let _ = verify_sequencer_receipt(&fx.sequencer_vk, "did:web:ds.example", &receipt);
    }
    if let Some((payload, key_id)) = decode_canonical_receipt_signing_bytes(data) {
        assert_eq!(payload.canonical_signing_bytes(&key_id).as_slice(), data);
    }

    // 4. Differential ciphertext + version mutation on v5 OwnerMessage.
    if data.len() >= 3 && !fx.owner_msg.encrypted.is_empty() {
        let mut mutated = fx.owner_msg.clone();
        mutated.version = data[0] % 8;
        let off = usize::from(data[1]) % mutated.encrypted.len();
        for (dst, &mask) in mutated.encrypted[off..].iter_mut().zip(data[2..].iter()) {
            *dst ^= mask;
        }
        let _ = open_owner_content(&fx.root, &mutated);
    }

    if let Ok(s) = core::str::from_utf8(data) {
        let _ = parse_sqlcipher_96hex_key_spec(s);
    }
});
