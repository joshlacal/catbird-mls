//! Proven `chat.declaration` reads.

use p256::ecdsa::SigningKey as P256SigningKey;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use super::super::did_resolution::identity_unit_tests::{
    json_response, open_client, IdentityMockTransport, PDS_URL,
};
use super::proven_declaration_cache_key;
use crate::error::MLSError;

const PEER: &str = "did:plc:declpeerbbbbbbbbbbbbbbbb";
const PEER_PDS: &str = "https://peer-pds.example.net";
const PEER_DS: &str = "did:web:peer-ds.example.net";

fn atproto_secret(did: &str, salt: &str) -> p256::SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(did.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    p256::SecretKey::from_slice(&digest).unwrap()
}

fn multikey(secret: &p256::SecretKey) -> String {
    let sec1 = P256SigningKey::from(secret)
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let mut prefixed = vec![0x80, 0x24];
    prefixed.extend_from_slice(&sec1);
    multibase::encode(multibase::Base::Base58Btc, prefixed)
}

fn peer_doc(pds: Option<&str>) -> Value {
    let mut doc = json!({
        "id": PEER,
        "verificationMethod": [{
            "id": format!("{PEER}#atproto"),
            "type": "Multikey",
            "controller": PEER,
            "publicKeyMultibase": multikey(&atproto_secret(PEER, "real")),
        }],
    });
    if let Some(pds) = pds {
        doc["service"] = json!([{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds,
        }]);
    }
    doc
}

fn declaration_car(rev: &str, delivery_service: Option<&str>, signer_salt: &str) -> Vec<u8> {
    let secret = atproto_secret(PEER, signer_salt);
    let key = atproto_spaces::tokens::SpaceSigningKey::from_p256_secret(
        &secret,
        format!("{PEER}#atproto"),
    );
    let records = match delivery_service {
        Some(ds) => {
            let value = json!({
                "$type": "blue.catbird.chat.declaration",
                "allowIncoming": "all",
                "deliveryService": ds,
                "protocolVersion": "2",
                "createdAt": "2026-11-16T00:00:00.000Z",
            });
            let (_, cbor) =
                crate::labyrinth::repo_proof::encode_atproto_json_record_dagcbor(&value).unwrap();
            vec![("blue.catbird.chat.declaration/self".to_string(), cbor)]
        }
        None => Vec::new(),
    };
    crate::labyrinth::repo_proof::build_repo_proof_car_v1(PEER, rev, &records, &key)
        .unwrap()
        .1
}

fn car_response(car: Vec<u8>) -> Result<crate::client::traits::PlatformHttpResponse, MLSError> {
    Ok(crate::client::traits::PlatformHttpResponse {
        status: 200,
        headers: Vec::new(),
        body: car,
    })
}

fn sync_url() -> String {
    format!(
        "{PEER_PDS}/xrpc/com.atproto.sync.getRecord?did={}&collection=blue.catbird.chat.declaration&rkey=self",
        crate::client::chat_wire::urlencode_form_component(PEER)
    )
}

fn plc_url() -> String {
    format!("https://plc.directory/{PEER}")
}

#[test]
fn proven_declaration_from_the_peer_pds_is_accepted_and_cached() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        car_response(declaration_car("3lb2aaaaaaaaa", Some(PEER_DS), "real")),
    );
    assert_eq!(
        client.resolve_peer_home_ds_did(PEER).unwrap().as_deref(),
        Some(PEER_DS)
    );
    assert!(
        transport.urls().iter().all(|u| !u.starts_with(PDS_URL)),
        "a peer declaration is never read from this account's PDS"
    );
    let cached = client
        .db
        .read_tx(|tx| tx.get_account_meta(&proven_declaration_cache_key(PEER)))
        .unwrap()
        .unwrap();
    let cached: Value = serde_json::from_str(&cached).unwrap();
    assert_eq!(cached["deliveryService"], PEER_DS);
    assert_eq!(cached["rev"], "3lb2aaaaaaaaa");
}

#[test]
fn unproven_or_forged_declarations_are_errors_not_defaults() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    // Seed a last proven answer: an invalid proof must not fall back to it either.
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        car_response(declaration_car("3lb2aaaaaaaaa", Some(PEER_DS), "real")),
    );
    client.resolve_peer_home_ds_did(PEER).unwrap();

    // Signed by a key that is not the DID document's #atproto key.
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        car_response(declaration_car(
            "3lb2bbbbbbbbb",
            Some("did:web:evil.example.net"),
            "forged",
        )),
    );
    assert!(client.resolve_peer_home_ds_did(PEER).is_err());

    // A plain JSON getRecord answer (no proof).
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        json_response(
            200,
            &json!({ "value": { "deliveryService": "did:web:evil.example.net" } }),
        ),
    );
    assert!(client.resolve_peer_home_ds_did(PEER).is_err());

    // A 404 without a proof is not a proven absence.
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        json_response(404, &json!({ "error": "RecordNotFound" })),
    );
    assert!(client.resolve_peer_home_ds_did(PEER).is_err());

    // A rev below the floor already observed for this DID.
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        car_response(declaration_car("3lb27zzzzzzzz", Some(PEER_DS), "real")),
    );
    assert!(
        client.resolve_peer_home_ds_did(PEER).is_err(),
        "rev rollback refused"
    );

    // A DID document naming no PDS: never the account's own PDS instead.
    transport.queue(&plc_url(), json_response(200, &peer_doc(None)));
    assert!(client.resolve_peer_home_ds_did(PEER).is_err());
    assert!(transport.urls().iter().all(|u| !u.starts_with(PDS_URL)));
}

#[test]
fn proven_absence_is_none_and_unreachable_pds_serves_only_the_last_proven_answer() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());

    // Unreachable with nothing proven yet: an error.
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        Err(MLSError::Internal("network unreachable".into())),
    );
    assert!(client.resolve_peer_home_ds_did(PEER).is_err());

    // Proven answer, then the PDS goes away: the proven answer stands in.
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        car_response(declaration_car("3lb2aaaaaaaaa", Some(PEER_DS), "real")),
    );
    assert_eq!(
        client.resolve_peer_home_ds_did(PEER).unwrap().as_deref(),
        Some(PEER_DS)
    );
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        json_response(503, &json!({ "error": "Unavailable" })),
    );
    assert_eq!(
        client.resolve_peer_home_ds_did(PEER).unwrap().as_deref(),
        Some(PEER_DS)
    );

    // A verified exclusion proof means no declaration.
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        car_response(declaration_car("3lb2ccccccccc", None, "real")),
    );
    assert_eq!(client.resolve_peer_home_ds_did(PEER).unwrap(), None);
}

#[test]
fn last_proven_declaration_does_not_survive_a_newer_repo_rev_or_identity_change() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        car_response(declaration_car("3lb2aaaaaaaaa", Some(PEER_DS), "real")),
    );
    client.resolve_peer_home_ds_did(PEER).unwrap();

    crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(&client.db, PEER, "3lb2bbbbbbbbb", 2)
        .unwrap();
    transport.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport.queue(
        &sync_url(),
        json_response(503, &json!({ "error": "Unavailable" })),
    );
    assert!(client.resolve_peer_home_ds_did(PEER).is_err());

    // A key-change marker independently blocks the cached answer.
    let transport2 = IdentityMockTransport::new();
    let (_dir2, client2) = open_client(transport2.clone());
    transport2.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport2.queue(
        &sync_url(),
        car_response(declaration_car("3lb2aaaaaaaaa", Some(PEER_DS), "real")),
    );
    client2.resolve_peer_home_ds_did(PEER).unwrap();
    client2
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &super::super::did_resolution::did_identity_changed_key(PEER),
                "1",
                3,
            )
        })
        .unwrap();
    transport2.queue(&plc_url(), json_response(200, &peer_doc(Some(PEER_PDS))));
    transport2.queue(
        &sync_url(),
        json_response(503, &json!({ "error": "Unavailable" })),
    );
    assert!(client2.resolve_peer_home_ds_did(PEER).is_err());
}

#[test]
fn declared_delivery_service_must_be_a_resolvable_bare_did() {
    let valid = json!({
        "$type": "blue.catbird.chat.declaration",
        "allowIncoming": "all",
        "deliveryService": "did:web:ds.example.net",
        "protocolVersion": "2",
        "createdAt": "2026-11-16T00:00:00.000Z",
    });
    let mut legacy = valid.clone();
    legacy.as_object_mut().unwrap().remove("deliveryService");
    legacy["homeDsDid"] = json!("did:web:ds.example.net");
    let mut missing_policy = valid.clone();
    missing_policy
        .as_object_mut()
        .unwrap()
        .remove("allowIncoming");
    let mut wrong_type = valid.clone();
    wrong_type["$type"] = json!("blue.catbird.chat.other");
    let mut local = valid.clone();
    local["deliveryService"] = json!("did:web:localhost");
    let mut fragment = valid.clone();
    fragment["deliveryService"] = json!("did:web:ds.example.net#x");
    for (value, ok) in [
        (valid, true),
        (legacy, false),
        (missing_policy, false),
        (wrong_type, false),
        (local, false),
        (fragment, false),
    ] {
        let (_, cbor) =
            crate::labyrinth::repo_proof::encode_atproto_json_record_dagcbor(&value).unwrap();
        assert_eq!(
            super::declared_delivery_service(&cbor).is_ok(),
            ok,
            "{value}"
        );
    }
}

#[test]
fn existing_declaration_conflicts_if_it_uses_the_retired_home_field() {
    let expected = "did:web:ds.example.net";
    let mut value = json!({
        "$type": "blue.catbird.chat.declaration",
        "allowIncoming": "all",
        "deliveryService": expected,
        "protocolVersion": "2",
        "createdAt": "2026-11-16T00:00:00.000Z",
    });
    assert!(crate::client::chat_wire::pds_chat_declaration_matches(
        &value, expected
    ));
    value.as_object_mut().unwrap().remove("deliveryService");
    value["homeDsDid"] = json!(expected);
    assert!(!crate::client::chat_wire::pds_chat_declaration_matches(
        &value, expected
    ));
}
