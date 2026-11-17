//! Standalone Wave 2 client integration & UniFFI boundary tests covering:
//! - OAuth scope eligibility gate (`REQUIRED_LABYRINTH_OAUTH_SCOPES` & explicit grant verification);
//! - Live 2-device hybrid PQ CPace + ML-KEM-768 OTC pairing over `OwnerMailbox` `otcSession`,
//!   3-attempt lockout, 5-minute TTL expiry, and zero plaintext digits in SQLCipher;
//! - WebAuthn passkey PRF registration and second-device restore round-trip;
//! - Monotonic `MAX` CRDT `readState` and CAS-protected `circleOwnerState` synchronization;
//! - 72-hour peer full-chain reset (`propose_peer_repin` / `repin_peer`) hold enforcement;
//! - Native UniFFI Opus voice encode/seal/decrypt/decode PCM round-trip and malformed input rejection.

#![cfg(not(target_arch = "wasm32"))]

#[path = "support/circles_live_platform.rs"]
mod circles_live_platform;

use std::sync::Arc;

use catbird_mls::blob_crypto::decrypt_blob;
use catbird_mls::client::{
    account_db_path, CircleOwnerStateDto, SpacesEligibilityInput, SpacesUnavailableReason,
    REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::ffi::circles_ffi::CircleKeyWrapRequest;
use catbird_mls::ffi::uniffi_exports::{
    ffi_decode_opus_to_pcm, ffi_evaluate_spaces_eligibility, ffi_prepare_voice_message,
};
use catbird_mls::sim_hooks::{FixedStepClock, SimClientHooks};
use catbird_mls::storage::{MlsAccountDb, OpenMode};
use catbird_mls::MLSError;
use circles_live_platform::LiveWorld;

const ALICE: &str = "did:plc:waveaaliceaaaaaaaaaaaaaa";
const BOB: &str = "did:plc:waveabobbbbbbbbbbbbbbbbb";
const CAROL: &str = "did:plc:waveacarolcccccccccccccc";
const CIRCLE_SPACE: &str =
    "at://did:plc:waveaaliceaaaaaaaaaaaaaa/space/app.bsky.circle/01982b6e-a100-7000-8000-000000000001";
const CIRCLE_ID: &str = "01982b6e-a100-7000-8000-000000000001";

fn all_scopes() -> Vec<String> {
    REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

fn hooks_with_clock(clock: Arc<FixedStepClock>) -> SimClientHooks {
    let mut hooks = SimClientHooks::system_default();
    hooks.clock = clock;
    hooks
}

fn pick_distinct_six_digit_code(actual: &str) -> String {
    if actual == "000000" {
        "999999".to_owned()
    } else {
        "000000".to_owned()
    }
}

#[test]
fn spaces_eligibility_requires_full_wave2_oauth_scopes_and_rejects_partial_grants() {
    let canonical = ffi_evaluate_spaces_eligibility(SpacesEligibilityInput {
        account_did: ALICE.to_owned(),
        pds_endpoint: "https://pds.circles.test".to_owned(),
        pds_supports_spaces: true,
        granted_oauth_scopes: all_scopes(),
    });
    assert!(canonical.eligible, "{canonical:?}");
    assert_eq!(canonical.reason, SpacesUnavailableReason::Available);
    assert!(canonical.bluesky_dms_available);

    // Reordered query parameters and multi-action repo grants from the BFF gateway must pass.
    let reordered_gateway_grants = vec![
        "atproto".to_owned(),
        "blob:*/*".to_owned(),
        "repo:blue.catbird.labyrinth.mailboxKeys?action=delete&action=update&action=create"
            .to_owned(),
        "repo:blue.catbird.chat.device?action=create&action=delete".to_owned(),
        "repo:blue.catbird.chat.deviceRevocation?action=create".to_owned(),
        "space:blue.catbird.labyrinth.mailbox?manage=delete&manage=create&collection=blue.catbird.labyrinth.virtualDevice&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.attachmentManifest&action=update&action=read&action=delete&action=create".to_owned(),
        "space:blue.catbird.labyrinth.conversation?collection=blue.catbird.labyrinth.mek&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.attachmentManifest&authority=*&action=update&action=read&action=delete&action=create".to_owned(),
    ];
    let gateway_ok = ffi_evaluate_spaces_eligibility(SpacesEligibilityInput {
        account_did: ALICE.to_owned(),
        pds_endpoint: "https://pds.circles.test".to_owned(),
        pds_supports_spaces: true,
        granted_oauth_scopes: reordered_gateway_grants,
    });
    assert!(gateway_ok.eligible, "{gateway_ok:?}");

    // Missing `repo:blue.catbird.labyrinth.mailboxKeys` fails closed while preserving standard DMs.
    let without_mailbox_keys: Vec<String> = all_scopes()
        .into_iter()
        .filter(|s| *s != "repo:blue.catbird.labyrinth.mailboxKeys")
        .collect();
    let missing_repo = ffi_evaluate_spaces_eligibility(SpacesEligibilityInput {
        account_did: ALICE.to_owned(),
        pds_endpoint: "https://pds.circles.test".to_owned(),
        pds_supports_spaces: true,
        granted_oauth_scopes: without_mailbox_keys,
    });
    assert!(!missing_repo.eligible);
    assert!(missing_repo.bluesky_dms_available);
    assert_eq!(
        missing_repo.reason,
        SpacesUnavailableReason::MissingOAuthScopes {
            missing_scopes: vec!["repo:blue.catbird.labyrinth.mailboxKeys".to_owned()],
        }
    );

    // Delete-only `chat.device` grant is rejected because device publication requires `create`.
    let delete_only_device: Vec<String> = all_scopes()
        .into_iter()
        .map(|s| {
            if s.starts_with("repo:blue.catbird.chat.device?") {
                "repo:blue.catbird.chat.device?action=delete".to_owned()
            } else {
                s
            }
        })
        .collect();
    let missing_device_create = ffi_evaluate_spaces_eligibility(SpacesEligibilityInput {
        account_did: ALICE.to_owned(),
        pds_endpoint: "https://pds.circles.test".to_owned(),
        pds_supports_spaces: true,
        granted_oauth_scopes: delete_only_device,
    });
    assert!(!missing_device_create.eligible);
    assert_eq!(
        missing_device_create.reason,
        SpacesUnavailableReason::MissingOAuthScopes {
            missing_scopes: vec!["repo:blue.catbird.chat.device?action=create".to_owned()],
        }
    );

    // Mailbox scope missing `readState`, `circleOwnerState`, or `otcSession` fails closed.
    let missing_mailbox_collections: Vec<String> = all_scopes()
        .into_iter()
        .map(|s| {
            if s.starts_with("space:blue.catbird.labyrinth.mailbox?") {
                s.replace("&collection=blue.catbird.labyrinth.readState", "")
                    .replace("&collection=blue.catbird.labyrinth.circleOwnerState", "")
            } else {
                s
            }
        })
        .collect();
    let denied_collections = ffi_evaluate_spaces_eligibility(SpacesEligibilityInput {
        account_did: ALICE.to_owned(),
        pds_endpoint: "https://pds.circles.test".to_owned(),
        pds_supports_spaces: true,
        granted_oauth_scopes: missing_mailbox_collections,
    });
    assert!(!denied_collections.eligible);
    assert!(matches!(
        denied_collections.reason,
        SpacesUnavailableReason::MissingOAuthScopes { ref missing_scopes }
            if missing_scopes.len() == 1
                && missing_scopes[0].starts_with("space:blue.catbird.labyrinth.mailbox?")
    ));
}

#[test]
fn otc_pairing_live_two_device_handshake_attempt_cap_ttl_and_zero_sqlcipher_plaintext_digits() {
    let base_ms = chrono::Utc::now().timestamp_millis();
    let clock = Arc::new(FixedStepClock::new(base_ms, 0));
    let clock_for_world = clock.clone();
    let world = LiveWorld::with_clock(Arc::new(move || clock_for_world.peek_ms()));

    let d1_dir = tempfile::tempdir().unwrap();
    let alice_d1 = world.client_with_hooks(ALICE, d1_dir.path(), hooks_with_clock(clock.clone()));
    alice_d1.enroll_device(&all_scopes()).unwrap();
    alice_d1.advance_read_state("conv-otc-history", 17).unwrap();

    let offer1 = alice_d1.initiate_otc_pairing().unwrap();
    assert_eq!(offer1.six_digit_code.len(), 6);
    assert!(offer1.six_digit_code.chars().all(|c| c.is_ascii_digit()));

    // Verify SQLCipher stores salted SHA-256 metadata only and zero plaintext 6-digit codes.
    let d1_db_path = account_db_path(d1_dir.path(), ALICE).unwrap();
    let raw_db = MlsAccountDb::open_native(&d1_db_path, &[0x5a; 32], OpenMode::App).unwrap();
    raw_db
        .read_tx(|tx| {
            assert!(
                tx.get_labyrinth_state("pending_otc_digits")?.is_none(),
                "legacy plaintext pending_otc_digits row must never exist"
            );
            let offer_bytes = tx
                .get_labyrinth_state("pending_otc_offer")?
                .expect("salted pending_otc_offer row must exist");
            let parsed: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();
            assert_eq!(parsed["salt_hex"].as_str().map(str::len), Some(32));
            assert_eq!(parsed["code_digest_hex"].as_str().map(str::len), Some(64));
            assert_eq!(parsed["attempts"].as_u64(), Some(0));

            let mut stmt = tx
                .conn()
                .prepare("SELECT state_key, value_bytes FROM labyrinth_state")
                .unwrap();
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let needle = offer1.six_digit_code.as_bytes();
            for (key, value) in rows {
                assert!(
                    !value.windows(needle.len()).any(|w| w == needle),
                    "state_key {key} leaked plaintext 6-digit OTC bytes"
                );
            }
            Ok(())
        })
        .unwrap();

    // Negative 1: 3 wrong guesses lock out and evict the offer, so a 4th attempt with the right code fails.
    let d2_dir = tempfile::tempdir().unwrap();
    let alice_d2 = world.client_with_hooks(ALICE, d2_dir.path(), hooks_with_clock(clock.clone()));
    let wrong_code = pick_distinct_six_digit_code(&offer1.six_digit_code);
    let dummy_init = alice_d2.ffi_start_otc_pairing(wrong_code.clone()).unwrap();
    for attempt in 1..=3 {
        let err = alice_d1
            .ffi_respond_otc_pairing(dummy_init.session_id_hex.clone(), Some(wrong_code.clone()))
            .expect_err("wrong OTC code must fail");
        assert!(
            matches!(err, MLSError::InsufficientPermissions { .. }),
            "attempt {attempt} expected InsufficientPermissions, got {err:?}"
        );
    }
    let fourth_err = alice_d1
        .ffi_respond_otc_pairing(
            dummy_init.session_id_hex.clone(),
            Some(offer1.six_digit_code.clone()),
        )
        .expect_err("4th attempt after 3 wrong guesses must fail closed");
    assert!(
        matches!(fourth_err, MLSError::InsufficientPermissions { .. }),
        "expected lockout error, got {fourth_err:?}"
    );
    raw_db
        .read_tx(|tx| {
            assert!(
                tx.get_labyrinth_state("pending_otc_offer")?.is_none(),
                "exhausted offer must be evicted from SQLCipher"
            );
            Ok(())
        })
        .unwrap();

    // Negative 2: advancing past the 5-minute TTL expires a fresh offer and evicts it.
    let offer2 = alice_d1.initiate_otc_pairing().unwrap();
    clock.advance_ms(5 * 60 * 1000 + 1_000);
    let expired_err = alice_d1
        .ffi_respond_otc_pairing(
            dummy_init.session_id_hex.clone(),
            Some(offer2.six_digit_code.clone()),
        )
        .expect_err("expired OTC offer must fail closed");
    assert!(
        matches!(expired_err, MLSError::InvalidState(ref msg) if msg.contains("expired")),
        "expected expired error, got {expired_err:?}"
    );

    // Positive: live 2-device CPace + ML-KEM-768 handshake over OwnerMailbox `otcSession`.
    let offer3 = alice_d1.initiate_otc_pairing().unwrap();
    let d3_dir = tempfile::tempdir().unwrap();
    let alice_d3 = world.client_with_hooks(ALICE, d3_dir.path(), hooks_with_clock(clock.clone()));
    let initiated = alice_d3
        .ffi_start_otc_pairing(offer3.six_digit_code.clone())
        .expect("new device publishes otcSession initiator frame");
    assert_eq!(initiated.initiator_mlkem768_ek_len, 1184);

    alice_d1
        .ffi_respond_otc_pairing(initiated.session_id_hex.clone(), None)
        .expect("enrolled device responds to otcSession");

    let wrong_for_offer3 = pick_distinct_six_digit_code(&offer3.six_digit_code);
    let mismatch_err = alice_d3
        .complete_otc_pairing(&wrong_for_offer3)
        .expect_err("completing with mismatched code must fail without dropping session");
    assert!(matches!(
        mismatch_err,
        MLSError::InsufficientPermissions { .. }
    ));

    let completion = alice_d3
        .complete_otc_pairing(&offer3.six_digit_code)
        .expect("live 2-device OTC completion succeeds and rotates mailbox epoch");
    assert_eq!(completion.initiator_mlkem768_ek_len, 1184);
    assert_eq!(completion.responder_mlkem768_ct_len, 1088);
    assert!(completion.new_epoch_seq >= 1);

    // Paired device decrypts pre-pairing epoch-0 OwnerMailbox state (`readState`).
    let synced_read = alice_d3
        .ffi_get_read_state("conv-otc-history".to_owned())
        .expect("read_state query on paired device")
        .expect("epoch-0 readState accessible on newly paired device");
    assert_eq!(synced_read.read_through_seq, 17);
}

#[test]
fn passkey_prf_registration_and_second_device_restore_roundtrip() {
    let world = LiveWorld::default();
    let d1_dir = tempfile::tempdir().unwrap();
    let alice_d1 = world.client(ALICE, d1_dir.path());
    alice_d1.enroll_device(&all_scopes()).unwrap();
    alice_d1.advance_read_state("conv-passkey", 42).unwrap();

    // Input validation rejects empty credential_id or non-32-byte PRF output.
    assert!(matches!(
        alice_d1.register_passkey_prf(Vec::new(), vec![0x11; 32]),
        Err(MLSError::InvalidInput { .. })
    ));
    assert!(matches!(
        alice_d1.register_passkey_prf(b"cred-1".to_vec(), vec![0x11; 31]),
        Err(MLSError::InvalidInput { .. })
    ));

    let cred_id = b"webauthn-cred-wave2-primary".to_vec();
    let prf_secret = vec![0x37_u8; 32];
    assert_eq!(world.ds_head_seqs(ALICE), vec![0]);
    assert!(world.mailbox_keys(ALICE, "000000000001").is_none());

    let registered = alice_d1
        .register_passkey_prf(cred_id.clone(), prf_secret.clone())
        .expect("register passkey PRF virtual device");
    assert!(registered.backup_enabled);
    assert!(registered.has_passkey_prf);
    assert_eq!(
        registered.epoch_seq, 1,
        "passkey registration must rotate OwnerMailbox epoch 0 -> 1 so members_hash anchors virtualDevice"
    );
    assert_eq!(world.ds_head_seqs(ALICE), vec![0, 1]);
    assert!(
        world.mailbox_keys(ALICE, "000000000001").is_some(),
        "rotated epoch 1 mailboxKeys must be published to PDS"
    );
    let mailbox_space = format!("at://{ALICE}/space/blue.catbird.labyrinth.mailbox/self");
    let epoch1_members: Vec<String> = world
        .archive_auth
        .space_record_rkeys(
            &mailbox_space,
            ALICE,
            labyrinth::records::nsid::EPOCH_MEMBER,
        )
        .into_iter()
        .filter(|rkey| rkey.starts_with("000000000001-"))
        .collect();
    assert_eq!(
        epoch1_members.len(),
        2,
        "epoch 1 must carry both the physical device and passkey virtualDevice: {epoch1_members:?}"
    );

    let d2_dir = tempfile::tempdir().unwrap();
    let alice_d2 = world.client(ALICE, d2_dir.path());
    assert!(matches!(
        alice_d2.ffi_restore_with_passkey_prf(Vec::new(), prf_secret.clone()),
        Err(MLSError::InvalidInput { .. })
    ));
    assert!(matches!(
        alice_d2.ffi_restore_with_passkey_prf(cred_id.clone(), vec![0x37_u8; 16]),
        Err(MLSError::InvalidInput { .. })
    ));

    // Wrong 32-byte PRF output must fail closed on unwrap.
    let wrong_prf_err = alice_d2
        .ffi_restore_with_passkey_prf(cred_id.clone(), vec![0x99_u8; 32])
        .expect_err("wrong passkey PRF secret must fail");
    assert!(!matches!(wrong_prf_err, MLSError::ContextClosed));

    // Correct 32-byte PRF output restores the account mailbox and historical epoch roots.
    let restored = alice_d2
        .ffi_restore_with_passkey_prf(cred_id, prf_secret)
        .expect("restore second device via passkey PRF");
    assert!(restored.backup_enabled);
    assert!(restored.has_passkey_prf);
    assert_eq!(restored.epoch_seq, 2);

    let read_state = alice_d2
        .ffi_get_read_state("conv-passkey".to_owned())
        .unwrap()
        .expect("restored device reads epoch-0 readState");
    assert_eq!(read_state.read_through_seq, 42);
}

#[test]
fn read_state_monotonic_max_crdt_and_circle_owner_state_cas_sync() {
    let world = LiveWorld::default();
    let d1_dir = tempfile::tempdir().unwrap();
    let d2_dir = tempfile::tempdir().unwrap();
    let alice_d1 = world.client(ALICE, d1_dir.path());
    alice_d1.enroll_device(&all_scopes()).unwrap();
    let cred_id = b"cred-sync-crdt".to_vec();
    let prf = vec![0x51_u8; 32];
    alice_d1
        .register_passkey_prf(cred_id.clone(), prf.clone())
        .unwrap();

    let alice_d2 = world.client(ALICE, d2_dir.path());
    alice_d2.ffi_restore_with_passkey_prf(cred_id, prf).unwrap();

    // `readState` monotonic MAX CRDT: 10 -> 4 stays 10; 10 -> 25 advances to 25.
    let r1 = alice_d1
        .ffi_advance_read_state("conv-crdt-1".to_owned(), 10)
        .unwrap();
    assert_eq!(r1.read_through_seq, 10);

    let r2 = alice_d2
        .ffi_advance_read_state("conv-crdt-1".to_owned(), 4)
        .unwrap();
    assert_eq!(
        r2.read_through_seq, 10,
        "lower candidate seq must not regress"
    );

    let r3 = alice_d2
        .ffi_advance_read_state("conv-crdt-1".to_owned(), 25)
        .unwrap();
    assert_eq!(r3.read_through_seq, 25);

    let fetched = alice_d1
        .ffi_get_read_state("conv-crdt-1".to_owned())
        .unwrap()
        .expect("d1 observes d2 readState advance");
    assert_eq!(fetched.read_through_seq, 25);

    alice_d1
        .ffi_advance_read_state("conv-crdt-2".to_owned(), 7)
        .unwrap();
    let all_reads = alice_d2.ffi_list_read_states().unwrap();
    assert_eq!(all_reads.len(), 2);

    // `circleOwnerState` CAS + deterministic merge + tombstone clear across sibling devices.
    let initial = CircleOwnerStateDto {
        circle_id: CIRCLE_ID.to_owned(),
        space_uri: CIRCLE_SPACE.to_owned(),
        current_key_version: 1,
        joined_at_version_json: serde_json::json!({ BOB: 1 }).to_string(),
        pending_ops_json: "{}".to_owned(),
        updated_at: String::new(),
        record_cid: None,
    };
    let cid_v1 = alice_d1
        .ffi_put_circle_owner_state(initial, None)
        .expect("initial circleOwnerState write");
    assert!(!cid_v1.is_empty());

    let loaded_d2 = alice_d2
        .ffi_get_circle_owner_state(CIRCLE_ID.to_owned())
        .unwrap()
        .expect("d2 loads circleOwnerState");
    assert_eq!(loaded_d2.current_key_version, 1);
    assert_eq!(loaded_d2.record_cid.as_deref(), Some(cid_v1.as_str()));

    let mut v2 = loaded_d2.clone();
    v2.current_key_version = 2;
    let cid_v2 = alice_d2
        .ffi_put_circle_owner_state(v2, Some(cid_v1.clone()))
        .expect("CAS update with current CID succeeds");
    assert_ne!(cid_v1, cid_v2);

    // Stale `swap_record_cid` on `d1` must fail closed instead of clobbering `d2`'s write.
    let stale_attempt = CircleOwnerStateDto {
        circle_id: CIRCLE_ID.to_owned(),
        space_uri: CIRCLE_SPACE.to_owned(),
        current_key_version: 2,
        joined_at_version_json: serde_json::json!({ BOB: 1, CAROL: 2 }).to_string(),
        pending_ops_json: "{}".to_owned(),
        updated_at: String::new(),
        record_cid: None,
    };
    assert!(
        alice_d1
            .ffi_put_circle_owner_state(stale_attempt, Some(cid_v1))
            .is_err(),
        "stale swapRecord CID must be rejected"
    );

    // `merge_circle_owner_state` reconciles concurrent updates and records ACL tombstones.
    let acl_key = format!("__acl__:{BOB}");
    let merge_input = CircleOwnerStateDto {
        circle_id: CIRCLE_ID.to_owned(),
        space_uri: CIRCLE_SPACE.to_owned(),
        current_key_version: 3,
        joined_at_version_json: serde_json::json!({ CAROL: 2 }).to_string(),
        pending_ops_json: serde_json::json!({
            acl_key.clone(): "aclRemovePending"
        })
        .to_string(),
        updated_at: String::new(),
        record_cid: None,
    };
    let merged = alice_d1
        .ffi_merge_circle_owner_state(merge_input)
        .expect("CAS merge succeeds");
    assert_eq!(merged.current_key_version, 3);
    let joined_map: serde_json::Value =
        serde_json::from_str(&merged.joined_at_version_json).unwrap();
    // Tombstone-wins merge evicts BOB from joined_at_version_by_did while keeping CAROL!
    assert!(joined_map.get(BOB).is_none());
    assert_eq!(joined_map[CAROL].as_u64(), Some(2));
    let pending_map: serde_json::Value = serde_json::from_str(&merged.pending_ops_json).unwrap();
    assert_eq!(pending_map[&acl_key].as_str(), Some("aclRemovePending"));

    // `clear_circle_acl_tombstone` removes the settled ACL removal entry.
    let cleared = alice_d2
        .ffi_clear_circle_acl_tombstone(CIRCLE_ID.to_owned(), BOB.to_owned())
        .expect("clear ACL tombstone")
        .expect("circleOwnerState exists");
    let cleared_ops: serde_json::Value = serde_json::from_str(&cleared.pending_ops_json).unwrap();
    assert!(cleared_ops.get(&acl_key).is_none());

    let listed = alice_d1.ffi_list_circle_owner_states().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].circle_id, CIRCLE_ID);
}

#[test]
fn peer_repin_enforces_72h_hold_and_rejects_unproposed_or_early_confirmation() {
    let base_ms = chrono::Utc::now().timestamp_millis();
    let clock = Arc::new(FixedStepClock::new(base_ms, 0));
    let clock_for_world = clock.clone();
    let world = LiveWorld::with_clock(Arc::new(move || clock_for_world.peek_ms()));

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_old_dir = tempfile::tempdir().unwrap();
    let alice = world.client_with_hooks(ALICE, alice_dir.path(), hooks_with_clock(clock.clone()));
    let bob_old = world.client_with_hooks(BOB, bob_old_dir.path(), hooks_with_clock(clock.clone()));
    alice.enroll_device(&all_scopes()).unwrap();
    bob_old.enroll_device(&all_scopes()).unwrap();
    alice.advance_read_state("init", 1).unwrap();
    bob_old.advance_read_state("init", 1).unwrap();

    // Negative attachment validation checks at client boundary.
    assert!(matches!(
        alice.ffi_upload_conversation_attachment(
            String::new(),
            b"hello".to_vec(),
            "text/plain".into()
        ),
        Err(MLSError::InvalidInput { .. })
    ));
    assert!(matches!(
        alice.ffi_upload_conversation_attachment("conv-1".into(), Vec::new(), "text/plain".into()),
        Err(MLSError::InvalidInput { .. })
    ));

    // Alice wraps a Circle key to Bob, pinning Bob's initial epoch-0 chain head.
    let ck1 = alice.ffi_circle_key_generate();
    let initial_wrap = alice
        .ffi_circle_key_wrap(
            CircleKeyWrapRequest {
                circle_id: CIRCLE_ID.to_owned(),
                key_version: 1,
                space_uri: CIRCLE_SPACE.to_owned(),
                reason: "initial".to_owned(),
                member_dids: vec![BOB.to_owned()],
                created_at: "2026-11-14T00:00:00.000Z".to_owned(),
            },
            ck1,
        )
        .expect("initial wrap pins Bob's epoch-0 chain");
    assert!(
        initial_wrap.excluded_dids.is_empty(),
        "Bob must be wrapped cleanly before chain reset: {initial_wrap:?}"
    );

    // Simulate Bob deleting their old account state and starting an unchained fresh epoch-0 mailbox.
    bob_old
        .ffi_delete_account_data()
        .expect("bob_old purges OwnerMailbox, mailboxKeys, and mls-ds epoch chain");
    assert!(bob_old.is_handle_closed());
    world.reset_peer_chain(BOB);
    let bob_new_dir = tempfile::tempdir().unwrap();
    let bob_new = world.client_with_hooks(BOB, bob_new_dir.path(), hooks_with_clock(clock.clone()));
    bob_new.enroll_device(&all_scopes()).unwrap();
    bob_new.advance_read_state("init", 1).unwrap();
    let ck_bob_init = bob_new.ffi_circle_key_generate();
    bob_new
        .ffi_circle_key_wrap(
            CircleKeyWrapRequest {
                circle_id: "01982b6e-a200-7000-8000-000000000002".to_owned(),
                key_version: 1,
                space_uri:
                    "at://did:plc:waveabobbbbbbbbbbbbbbbbb/space/app.bsky.circle/01982b6e-a200-7000-8000-000000000002"
                        .to_owned(),
                reason: "initial".to_owned(),
                member_dids: Vec::new(),
                created_at: "2026-11-14T00:01:00.000Z".to_owned(),
            },
            ck_bob_init,
        )
        .expect("bob_new publishes fresh epoch-0 chain");

    // Alice's next wrap to Bob refuses to wrap to Bob's unchained epoch-0 reset (`excluded_dids`).
    let ck2 = alice.ffi_circle_key_generate();
    let excluded_wrap = alice
        .ffi_circle_key_wrap(
            CircleKeyWrapRequest {
                circle_id: CIRCLE_ID.to_owned(),
                key_version: 2,
                space_uri: CIRCLE_SPACE.to_owned(),
                reason: "rotation".to_owned(),
                member_dids: vec![BOB.to_owned()],
                created_at: "2026-11-14T00:02:00.000Z".to_owned(),
            },
            ck2.clone(),
        )
        .expect("circle_key_wrap soft-excludes unverified peer");
    assert_eq!(
        excluded_wrap.excluded_dids,
        vec![BOB.to_owned()],
        "unchained peer reset must be excluded with zero wraps: {excluded_wrap:?}"
    );
    assert!(
        bob_new
            .ffi_circle_key_open(
                excluded_wrap.record_json,
                CIRCLE_SPACE.to_owned(),
                ALICE.to_owned(),
            )
            .expect("open excluded record")
            .is_none(),
        "bob_new must receive zero wrapped keys before repin"
    );

    // Calling `repin_peer` without `propose_peer_repin` is rejected.
    let unproposed_err = alice
        .ffi_repin_peer(BOB.to_owned(), vec![0xAB; 32])
        .expect_err("unproposed head must fail");
    assert!(
        matches!(unproposed_err, MLSError::InvalidState(ref msg) if msg.contains("PeerRepinProposalRequired")),
        "got {unproposed_err:?}"
    );

    let proposal = alice
        .ffi_propose_peer_repin(BOB.to_owned())
        .expect("propose_peer_repin inspects new head and starts 72h hold");
    assert_eq!(proposal.previous_seq, Some(0));
    assert_eq!(proposal.offered_seq, 0);
    assert_eq!(proposal.hold_remaining_ms, 72 * 60 * 60 * 1000);
    assert!(!proposal.safety_number.is_empty());
    let offered_head = hex::decode(&proposal.offered_head_hex).unwrap();

    // Confirming at +71h (still inside 72h hold window) fails closed.
    clock.advance_ms(71 * 60 * 60 * 1000);
    let hold_err = alice
        .ffi_repin_peer(BOB.to_owned(), offered_head.clone())
        .expect_err("repin before 72h hold expires must fail");
    assert!(
        matches!(hold_err, MLSError::InvalidState(ref msg) if msg.contains("PeerRepinHoldActive")),
        "got {hold_err:?}"
    );

    // Advancing past 72h unlocks `repin_peer`, and `bob_new` decrypts the newly wrapped Circle key.
    clock.advance_ms(60 * 60 * 1000 + 1_000);
    alice
        .ffi_repin_peer(BOB.to_owned(), offered_head)
        .expect("repin succeeds once 72h hold has elapsed");

    let wrapped = alice
        .ffi_circle_key_wrap(
            CircleKeyWrapRequest {
                circle_id: CIRCLE_ID.to_owned(),
                key_version: 2,
                space_uri: CIRCLE_SPACE.to_owned(),
                reason: "rotation".to_owned(),
                member_dids: vec![BOB.to_owned()],
                created_at: "2026-11-17T00:05:00.000Z".to_owned(),
            },
            ck2.clone(),
        )
        .expect("wrap succeeds after confirmed peer repin");
    assert!(wrapped.excluded_dids.is_empty(), "{wrapped:?}");
    let opened = bob_new
        .ffi_circle_key_open(
            wrapped.record_json,
            CIRCLE_SPACE.to_owned(),
            ALICE.to_owned(),
        )
        .expect("bob_new opens repinned wrap")
        .expect("recipient entry present");
    assert_eq!(opened.circle_key, ck2);
}

#[test]
fn ffi_voice_opus_prepare_and_decode_pcm_roundtrip_and_invalid_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let empty_path = dir.path().join("empty.pcm");
    std::fs::write(&empty_path, []).unwrap();
    assert!(matches!(
        ffi_prepare_voice_message(empty_path.display().to_string(), 48_000),
        Err(MLSError::InvalidInput { .. })
    ));

    // Synthesize 500ms of a 440 Hz sine wave at 48 kHz 16-bit LE mono (`24_000` samples).
    let sample_rate = 48_000_u32;
    let total_samples = 24_000_usize;
    let mut pcm_bytes = Vec::with_capacity(total_samples * 2);
    for i in 0..total_samples {
        let t = i as f32 / sample_rate as f32;
        let sample = ((2.0 * std::f32::consts::PI * 440.0 * t).sin() * 12_000.0) as i16;
        pcm_bytes.extend_from_slice(&sample.to_le_bytes());
    }
    let pcm_path = dir.path().join("tone440.pcm");
    std::fs::write(&pcm_path, &pcm_bytes).unwrap();

    // Unsupported sample rate `0` fails closed.
    assert!(matches!(
        ffi_prepare_voice_message(pcm_path.display().to_string(), 0),
        Err(MLSError::InvalidInput { .. })
    ));

    let prepared = ffi_prepare_voice_message(pcm_path.display().to_string(), sample_rate)
        .expect("ffi_prepare_voice_message encodes Opus-in-OGG and encrypts AES-256-GCM blob");
    assert!(
        (450..=550).contains(&prepared.duration_ms),
        "duration_ms={}",
        prepared.duration_ms
    );
    assert_eq!(prepared.waveform.len(), 64);
    assert!(prepared.waveform.iter().any(|&bar| bar > 0.01));
    assert_eq!(prepared.key.len(), 32);
    assert_eq!(prepared.iv.len(), 12);
    assert_eq!(prepared.size, prepared.opus_data.len() as u64);
    assert_eq!(prepared.encrypted_blob.len(), prepared.opus_data.len() + 16);
    assert!(prepared.opus_data.starts_with(b"OggS"));

    let decrypted_ogg = decrypt_blob(
        &prepared.encrypted_blob,
        &prepared.key,
        &prepared.iv,
        &prepared.sha256,
    )
    .expect("AES-256-GCM voice blob decrypts cleanly");
    assert_eq!(decrypted_ogg, prepared.opus_data);

    let decoded_pcm = ffi_decode_opus_to_pcm(decrypted_ogg)
        .expect("ffi_decode_opus_to_pcm decodes Opus-in-OGG back to 48 kHz 16-bit LE PCM");
    assert_eq!(decoded_pcm.len() % 2, 0);
    let decoded_samples = decoded_pcm.len() / 2;
    assert!(
        (20_000..=28_800).contains(&decoded_samples),
        "unexpected decoded sample count: {decoded_samples}"
    );
    let max_abs = decoded_pcm
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]).unsigned_abs())
        .max()
        .unwrap_or(0);
    assert!(
        max_abs > 1_000,
        "decoded waveform lost audible signal: max_abs={max_abs}"
    );

    // Corrupt OGG/Opus bytes fail closed.
    assert!(matches!(
        ffi_decode_opus_to_pcm(b"not-a-valid-ogg-opus-stream".to_vec()),
        Err(MLSError::InvalidInput { .. })
    ));
}

#[test]
fn concurrent_two_device_circle_owner_state_create_cas_preserves_acl_tombstone_and_read_state_max()
{
    use std::sync::atomic::{AtomicBool, Ordering};

    let world = LiveWorld::default();
    let d1_dir = tempfile::tempdir().unwrap();
    let d2_dir = tempfile::tempdir().unwrap();
    let alice_d1 = world.client(ALICE, d1_dir.path());
    alice_d1.enroll_device(&all_scopes()).unwrap();
    let cred_id = b"cred-cas-create-race".to_vec();
    let prf = vec![0x63_u8; 32];
    alice_d1
        .register_passkey_prf(cred_id.clone(), prf.clone())
        .unwrap();
    let alice_d2 = world.client(ALICE, d2_dir.path());
    alice_d2.ffi_restore_with_passkey_prf(cred_id, prf).unwrap();

    // Seed initial version `000000000001` with BOB at key version 1.
    let initial = CircleOwnerStateDto {
        circle_id: CIRCLE_ID.to_owned(),
        space_uri: CIRCLE_SPACE.to_owned(),
        current_key_version: 1,
        joined_at_version_json: serde_json::json!({ BOB: 1 }).to_string(),
        pending_ops_json: "{}".to_owned(),
        updated_at: String::new(),
        record_cid: None,
    };
    alice_d1.ffi_put_circle_owner_state(initial, None).unwrap();

    // Pre-compute d2's genuine encrypted version-2 `applyWrites` calls, then restore Space
    // state back to version 1 so d2's writes are replayed mid-flight right as d1 submits
    // `#create` `<CIRCLE_ID>-000000000002`.
    let target_v2_rkey = format!("{CIRCLE_ID}-000000000002");
    let acl_key = format!("__acl__:{BOB}");
    let v1_snap = world.archive_auth.snapshot_space_state();
    let _ = world.archive_auth.drain_apply_calls();
    let d2_evict_bob = CircleOwnerStateDto {
        circle_id: CIRCLE_ID.to_owned(),
        space_uri: CIRCLE_SPACE.to_owned(),
        current_key_version: 2,
        joined_at_version_json: "{}".to_owned(),
        pending_ops_json: serde_json::json!({
            acl_key.clone(): "aclRemovePending:rotated"
        })
        .to_string(),
        updated_at: String::new(),
        record_cid: None,
    };
    alice_d2
        .ffi_merge_circle_owner_state(d2_evict_bob)
        .expect("d2 produces encrypted #create version 2 with __acl__ tombstone");
    let d2_v2_calls = world.archive_auth.drain_apply_calls();
    assert!(
        !d2_v2_calls.is_empty(),
        "d2 must emit applyWrites for version 2"
    );
    world.archive_auth.restore_space_state(v1_snap);

    let conflict_injected = Arc::new(AtomicBool::new(false));
    {
        let world_for_hook = world.clone();
        let target_rkey_for_hook = target_v2_rkey.clone();
        let fired = conflict_injected.clone();
        world
            .archive_auth
            .set_before_apply_hook(Some(Arc::new(move |_account, body| {
                let is_v2_create = body["writes"].as_array().is_some_and(|writes| {
                    writes.iter().any(|w| {
                        w["$type"].as_str() == Some("com.atproto.space.applyWrites#create")
                            && w["collection"].as_str()
                                == Some(labyrinth::records::nsid::CIRCLE_OWNER_STATE)
                            && w["rkey"].as_str() == Some(target_rkey_for_hook.as_str())
                    })
                });
                if is_v2_create && !fired.swap(true, Ordering::SeqCst) {
                    world_for_hook.archive_auth.set_before_apply_hook(None);
                    for (acct, call_body) in &d2_v2_calls {
                        let resp = world_for_hook
                            .archive_auth
                            .replay_apply(acct, call_body)
                            .expect("d2 version 2 replay succeeds");
                        assert_eq!(resp.status, 200);
                    }
                }
            })));
    }

    // d1 attempts to merge a stale view `{ BOB: 1, CAROL: 2 }`:
    // d2 wins `<CIRCLE_ID>-000000000002`, d1 receives `400 RecordAlreadyExists` on `#create`,
    // re-reads d2's version 2, preserves `__acl__:<BOB>`, keeps BOB evicted, and commits version 3!
    let d1_add_carol_with_stale_bob = CircleOwnerStateDto {
        circle_id: CIRCLE_ID.to_owned(),
        space_uri: CIRCLE_SPACE.to_owned(),
        current_key_version: 2,
        joined_at_version_json: serde_json::json!({ BOB: 1, CAROL: 2 }).to_string(),
        pending_ops_json: serde_json::json!({ BOB: "stalePendingAdd" }).to_string(),
        updated_at: String::new(),
        record_cid: None,
    };
    let merged = alice_d1
        .ffi_merge_circle_owner_state(d1_add_carol_with_stale_bob)
        .expect("d1 retries after #create RecordAlreadyExists and merges cleanly");
    assert!(
        conflict_injected.load(Ordering::SeqCst),
        "interleaved #create conflict hook must fire on version 2"
    );

    for snapshot in [
        merged,
        alice_d2
            .ffi_get_circle_owner_state(CIRCLE_ID.to_owned())
            .unwrap()
            .expect("d2 reads settled version 3"),
    ] {
        assert_eq!(snapshot.current_key_version, 2);
        let joined: serde_json::Value =
            serde_json::from_str(&snapshot.joined_at_version_json).unwrap();
        assert!(
            joined.get(BOB).is_none(),
            "__acl__ tombstone must keep BOB evicted across #create CAS retry: {joined}"
        );
        assert_eq!(joined[CAROL].as_u64(), Some(2));
        let ops: serde_json::Value = serde_json::from_str(&snapshot.pending_ops_json).unwrap();
        assert!(ops.get(BOB).is_none(), "stale non-tombstone op suppressed");
        assert_eq!(ops[&acl_key].as_str(), Some("aclRemovePending:rotated"));
    }

    let mailbox_space = format!("at://{ALICE}/space/blue.catbird.labyrinth.mailbox/self");
    let remaining_rkeys = world.archive_auth.space_record_rkeys(
        &mailbox_space,
        ALICE,
        labyrinth::records::nsid::CIRCLE_OWNER_STATE,
    );
    assert_eq!(
        remaining_rkeys,
        vec![
            format!("{CIRCLE_ID}-000000000001"),
            format!("{CIRCLE_ID}-000000000002"),
            format!("{CIRCLE_ID}-000000000003"),
        ],
        "append-only versioned CAS retains prior version rows without deleting history"
    );

    // Also verify true mid-flight `#create` conflict on `readState` merges monotonic `MAX(readThroughSeq)`.
    alice_d1
        .ffi_advance_read_state("conv-race-max".to_owned(), 5)
        .unwrap();
    let read_v1_snap = world.archive_auth.snapshot_space_state();
    let _ = world.archive_auth.drain_apply_calls();
    alice_d2
        .ffi_advance_read_state("conv-race-max".to_owned(), 38)
        .expect("d2 produces encrypted readState version 2 with seq=38");
    let d2_read_v2_calls = world.archive_auth.drain_apply_calls();
    assert!(
        !d2_read_v2_calls.is_empty(),
        "d2 must emit applyWrites for readState version 2"
    );
    world.archive_auth.restore_space_state(read_v1_snap);

    let read_conflict_injected = Arc::new(AtomicBool::new(false));
    {
        let world_for_hook = world.clone();
        let fired = read_conflict_injected.clone();
        world
            .archive_auth
            .set_before_apply_hook(Some(Arc::new(move |_account, body| {
                let is_read_v2_create = body["writes"].as_array().is_some_and(|writes| {
                    writes.iter().any(|w| {
                        w["$type"].as_str() == Some("com.atproto.space.applyWrites#create")
                            && w["collection"].as_str()
                                == Some(labyrinth::records::nsid::READ_STATE)
                            && w["rkey"].as_str() == Some("conv-race-max-000000000002")
                    })
                });
                if is_read_v2_create && !fired.swap(true, Ordering::SeqCst) {
                    world_for_hook.archive_auth.set_before_apply_hook(None);
                    for (acct, call_body) in &d2_read_v2_calls {
                        let resp = world_for_hook
                            .archive_auth
                            .replay_apply(acct, call_body)
                            .expect("d2 readState version 2 replay succeeds");
                        assert_eq!(resp.status, 200);
                    }
                }
            })));
    }
    let settled_read = alice_d1
        .ffi_advance_read_state("conv-race-max".to_owned(), 12)
        .expect("d1 retries readState conflict and merges MAX(12, 38)");
    assert!(read_conflict_injected.load(Ordering::SeqCst));
    assert_eq!(settled_read.read_through_seq, 38);
    assert_eq!(
        alice_d2
            .ffi_get_read_state("conv-race-max".to_owned())
            .unwrap()
            .unwrap()
            .read_through_seq,
        38
    );
}

#[tokio::test]
async fn resolving_space_thread_store_find_meks_probes_batch_author_first_o1_with_fallback() {
    use catbird_mls::labyrinth::space::ResolvingSpaceThreadStore;
    use catbird_mls::labyrinth::state::StateVault;
    use labyrinth::records::{Bytes, MekDistribution, MekSenderDef, TransportSenderDef};
    use labyrinth::store::space::{SpaceError, SpaceRef, SpaceRpc};
    use labyrinth::store::ThreadStore as _;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemVault(Mutex<BTreeMap<String, Vec<u8>>>);
    impl StateVault for MemVault {
        fn load(&self, key: &str) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn delete(&self, key: &str) -> Result<(), MLSError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
        fn compare_exchange(
            &self,
            key: &str,
            expected: Option<&[u8]>,
            next: &[u8],
        ) -> Result<bool, MLSError> {
            let mut g = self.0.lock().unwrap();
            if g.get(key).map(Vec::as_slice) != expected {
                return Ok(false);
            }
            g.insert(key.to_owned(), next.to_vec());
            Ok(true)
        }
    }

    #[derive(Default)]
    struct MockMekSpaceRpc {
        mek_records: Mutex<BTreeMap<(String, String), serde_json::Value>>,
        writers: Mutex<Vec<String>>,
        mek_get_repos: Mutex<Vec<String>>,
        list_writers_calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SpaceRpc for MockMekSpaceRpc {
        fn authenticates_responses(&self) -> bool {
            true
        }

        async fn query(
            &self,
            nsid: &str,
            params: &[(&str, String)],
        ) -> Result<Vec<u8>, SpaceError> {
            let param = |k: &str| {
                params
                    .iter()
                    .find(|(name, _)| *name == k)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or_default()
            };
            match nsid {
                "com.atproto.space.getRecord" => {
                    let repo = param("repo").to_owned();
                    let collection = param("collection");
                    let rkey = param("rkey").to_owned();
                    if collection == labyrinth::records::nsid::MEK {
                        self.mek_get_repos.lock().unwrap().push(repo.clone());
                    }
                    match self
                        .mek_records
                        .lock()
                        .unwrap()
                        .get(&(repo.clone(), rkey.clone()))
                    {
                        Some(val) => Ok(serde_json::to_vec(&serde_json::json!({
                            "uri": format!("at://{repo}/space/rec/{collection}/{rkey}"),
                            "cid": "bafyreimek0000000000000000000000000000000000000000000000",
                            "value": val,
                        }))
                        .unwrap()),
                        None => Err(SpaceError {
                            status: 404,
                            error: Some("RecordNotFound".into()),
                            message: Some("not found".into()),
                        }),
                    }
                }
                "com.atproto.space.listWriters" => {
                    self.list_writers_calls
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let repos: Vec<serde_json::Value> = self
                        .writers
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|did| {
                            serde_json::json!({
                                "$type": "com.atproto.space.defs#repoWrite",
                                "repo": did,
                                "repoRev": "2222222222222",
                                "spaceRev": "2222222222222",
                                "data": { "$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
                            })
                        })
                        .collect();
                    Ok(serde_json::to_vec(&serde_json::json!({
                        "repos": repos,
                        "complete": true,
                    }))
                    .unwrap())
                }
                other => Err(SpaceError {
                    status: 501,
                    error: Some("Unmocked".into()),
                    message: Some(other.into()),
                }),
            }
        }

        async fn procedure(&self, nsid: &str, _body: &[u8]) -> Result<Vec<u8>, SpaceError> {
            Err(SpaceError {
                status: 501,
                error: Some("Unmocked".into()),
                message: Some(nsid.into()),
            })
        }

        async fn upload_blob(&self, _: &[u8], _: &str) -> Result<String, SpaceError> {
            unreachable!()
        }

        async fn get_blob(&self, _: &str, _: &str, _: &str) -> Result<Vec<u8>, SpaceError> {
            unreachable!()
        }
    }

    let rpc = Arc::new(MockMekSpaceRpc::default());
    let mek_id: [u8; 12] = [0x42; 12];
    let mek_rkey = hex::encode(mek_id);
    let dist = MekDistribution {
        type_: labyrinth::records::nsid::MEK.to_owned(),
        thread_id: "conv-o1".to_owned(),
        mek_id: Bytes(mek_id.to_vec()),
        roster_hash: Bytes(vec![0x33; 32]),
        sender: MekSenderDef::Transport(TransportSenderDef {
            transport_pubkey: Bytes(vec![0x44; 32]),
            ephemeral_auth_pubkey: Bytes(vec![0x55; 32]),
            sig: Bytes(vec![0x66; 64]),
        }),
        recipients: Vec::new(),
        created_at: "2026-11-14T00:00:00.000Z".to_owned(),
    };
    let dist_json = serde_json::to_value(&dist).unwrap();

    // Populate 14 writers in `listWriters`, with BOB and CAROL both holding valid MEK distributions.
    let mut all_writers = vec![ALICE.to_owned(), BOB.to_owned(), CAROL.to_owned()];
    for idx in 0..11u8 {
        all_writers.push(format!("did:plc:peerwriter{idx:012}"));
    }
    *rpc.writers.lock().unwrap() = all_writers;
    rpc.mek_records
        .lock()
        .unwrap()
        .insert((BOB.to_owned(), mek_rkey.clone()), dist_json.clone());
    rpc.mek_records
        .lock()
        .unwrap()
        .insert((CAROL.to_owned(), mek_rkey.clone()), dist_json);

    let store = ResolvingSpaceThreadStore::new(
        ALICE,
        rpc.clone(),
        None,
        Arc::new(MemVault::default()),
        Some(circles_live_platform::DS_DID.to_owned()),
    );
    store.set_thread_space(
        "conv-o1",
        SpaceRef::conversation(circles_live_platform::DS_DID, "conv-o1-0"),
    );
    assert!(store.supports_author_mek_fast_path());

    // 1. O(1) author fast path: `find_mek_from_author(BOB)` issues 1 `getRecord` and 0 `listWriters`.
    let author_hit = store
        .find_mek_from_author("conv-o1", BOB, &mek_id)
        .await
        .expect("author fast path query succeeds")
        .expect("BOB holds valid MekDistribution");
    assert_eq!(author_hit.author, BOB);
    assert_eq!(
        rpc.list_writers_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "O(1) author fast path must not call listWriters"
    );
    assert_eq!(
        *rpc.mek_get_repos.lock().unwrap(),
        vec![BOB.to_owned()],
        "O(1) author fast path must probe only batch author BOB"
    );

    // 2. When batch author BOB lacks the MEK record, `find_meks_with_hint(..., Some(BOB))` probes BOB first,
    // then falls back across remaining `listWriters` without re-querying BOB and recovers CAROL's record.
    rpc.mek_records
        .lock()
        .unwrap()
        .remove(&(BOB.to_owned(), mek_rkey));
    rpc.mek_get_repos.lock().unwrap().clear();

    let fallback_hits = store
        .find_meks_with_hint("conv-o1", &mek_id, Some(BOB))
        .await
        .expect("bounded fallback across writers succeeds");
    assert_eq!(fallback_hits.len(), 1);
    assert_eq!(fallback_hits[0].author, CAROL);
    assert_eq!(
        rpc.list_writers_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "fallback queries listWriters once"
    );
    let probed = rpc.mek_get_repos.lock().unwrap().clone();
    assert_eq!(probed.first().map(String::as_str), Some(BOB));
    assert_eq!(
        probed.iter().filter(|d| d.as_str() == BOB).count(),
        1,
        "BOB must not be re-probed during fallback sweep"
    );
}
