//! Transport projection of canonical append entries. These checks preserve row
//! identity and ordering; they do not replace MLS sender/credential verification.
use super::{IncomingEnvelope, OrchestratorError, Result};
use crate::chat_v2::ids::{CanonicalTimestamp, CanonicalUuid, SafeInteger, Seq, MAX_SAFE_INTEGER};
use crate::chat_v2::wire::{
    APPLICATION_ENTRY_KIND, COMMIT_ENTRY_KIND, LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
    LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

fn invalid(field: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(format!("Canonical conversation entry has invalid {field}"))
}

impl IncomingEnvelope {
    /// Validate metadata only on canonical transports. Legacy transports have
    /// no append sequence and retain their historical arbitrary message IDs.
    pub fn validate_server_metadata(&self) -> Result<()> {
        if let Some(sequence) = self.server_sequence {
            CanonicalUuid::parse(&self.conversation_id).map_err(|_| invalid("conversationId"))?;
            if sequence == 0 || sequence > MAX_SAFE_INTEGER as u64 {
                return Err(invalid("sequence"));
            }
            CanonicalUuid::parse(
                self.server_message_id
                    .as_deref()
                    .ok_or_else(|| invalid("entryId"))?,
            )
            .map_err(|_| invalid("entryId"))?;
            if self
                .server_epoch
                .is_none_or(|epoch| epoch > MAX_SAFE_INTEGER as u64)
            {
                return Err(invalid("epoch"));
            }
        }
        Ok(())
    }

    /// Map the four MLS-bearing canonical entry variants. No receivedAt, epoch,
    /// sequence or identifier is invented when a known row is malformed.
    pub fn from_canonical_entry(
        entry: &Value,
        expected_conversation_id: &str,
    ) -> Result<Option<Self>> {
        // Reads present declared bytes as lexicon `{"$bytes"}` or bare base64;
        // the one schema-directed read normalizer yields bare base64 for every
        // entry kind before any field is read or retained.
        let Some(name) = entry["$type"]
            .as_str()
            .and_then(|tag| tag.strip_prefix(crate::chat_v2::transcript::TYPE_PREFIX))
            .filter(|name| {
                matches!(
                    *name,
                    "directRequestEntry"
                        | "directRequestAcceptanceEntry"
                        | "conversationCloseEntry"
                        | "applicationEntry"
                        | "commitEntry"
                        | "leafRecoveryFulfillmentEntry"
                        | "leaveCommitFulfillmentEntry"
                )
            })
        else {
            return Ok(None);
        };
        let mut normalized = entry.clone();
        crate::chat_v2::transcript::direct_request::normalize_read_bytes(name, &mut normalized)
            .map_err(|_| invalid("entry bytes presentation"))?;
        let entry = &normalized;
        if matches!(
            entry["$type"].as_str(),
            Some(
                "blue.catbird.chat.defs#directRequestEntry"
                    | "blue.catbird.chat.defs#directRequestAcceptanceEntry"
                    | "blue.catbird.chat.defs#conversationCloseEntry"
            )
        ) {
            let body = &entry["signedRequest"]["body"];
            let coordinate = if entry["$type"] == "blue.catbird.chat.defs#conversationCloseEntry" {
                &body["prior"]
            } else {
                &body["next"]
            };
            let cid = entry["conversationId"]
                .as_str()
                .ok_or_else(|| invalid("conversationId"))?;
            if cid != expected_conversation_id || coordinate["conversationId"] != cid {
                return Err(invalid("control conversation binding"));
            }
            let received_at = entry["receivedAt"]
                .as_str()
                .ok_or_else(|| invalid("receivedAt"))?;
            CanonicalTimestamp::parse(received_at).map_err(|_| invalid("receivedAt"))?;
            let envelope = Self {
                canonical_entry_json: Some(
                    serde_json::to_string(entry).map_err(|_| invalid("control JSON"))?,
                ),
                conversation_id: cid.into(),
                sender_did: body["actorDid"]
                    .as_str()
                    .ok_or_else(|| invalid("actorDid"))?
                    .into(),
                ciphertext: Vec::new(),
                timestamp: received_at.parse().map_err(|_| invalid("receivedAt"))?,
                server_message_id: Some(
                    entry["entryId"]
                        .as_str()
                        .ok_or_else(|| invalid("entryId"))?
                        .into(),
                ),
                server_sequence: Some(entry["seq"].as_u64().ok_or_else(|| invalid("seq"))?),
                server_epoch: Some(
                    coordinate["epoch"]
                        .as_u64()
                        .ok_or_else(|| invalid("epoch"))?,
                ),
            };
            envelope.validate_server_metadata()?;
            return Ok(Some(envelope));
        }
        let application = match entry["$type"].as_str() {
            Some(APPLICATION_ENTRY_KIND) => true,
            Some(
                COMMIT_ENTRY_KIND
                | LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND
                | LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
            ) => false,
            _ => return Ok(None),
        };
        let id = entry["entryId"]
            .as_str()
            .ok_or_else(|| invalid("entryId"))?;
        CanonicalUuid::parse(id).map_err(|_| invalid("entryId"))?;
        let conversation_id = entry["conversationId"]
            .as_str()
            .ok_or_else(|| invalid("conversationId"))?;
        CanonicalUuid::parse(conversation_id).map_err(|_| invalid("conversationId"))?;
        let body = &entry["signedRequest"]["body"];
        if conversation_id != expected_conversation_id
            || body["prior"]["conversationId"].as_str() != Some(conversation_id)
            || (!application && body["next"]["conversationId"].as_str() != Some(conversation_id))
        {
            return Err(invalid("conversation binding"));
        }
        let seq = Seq::new(entry["seq"].as_i64().ok_or_else(|| invalid("seq"))?)
            .map_err(|_| invalid("seq"))?
            .get() as u64;
        let timestamp = entry["receivedAt"]
            .as_str()
            .ok_or_else(|| invalid("receivedAt"))?;
        CanonicalTimestamp::parse(timestamp).map_err(|_| invalid("receivedAt"))?;
        let timestamp = timestamp.parse().map_err(|_| invalid("receivedAt"))?;
        let epoch = &body[if application { "prior" } else { "next" }]["epoch"];
        let epoch = SafeInteger::new(epoch.as_i64().ok_or_else(|| invalid("epoch"))?)
            .map_err(|_| invalid("epoch"))?
            .get() as u64;
        let actor = body["actorDid"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("actorDid"))?;
        let artifact = &body[if application {
            "applicationMessage"
        } else {
            "commit"
        }];
        let encoded = artifact["bytes"]
            .as_str()
            .ok_or_else(|| invalid("MLS artifact"))?;
        let ciphertext = STANDARD
            .decode(encoded)
            .map_err(|_| invalid("MLS artifact bytes"))?;
        if ciphertext.is_empty() {
            return Err(invalid("MLS artifact bytes"));
        }
        crate::message_limits::validate_inbound_mls_message_len(
            ciphertext.len(),
            "canonical entry ciphertext",
        )?;
        let envelope = Self {
            canonical_entry_json: None,
            conversation_id: conversation_id.into(),
            sender_did: actor.into(),
            ciphertext,
            timestamp,
            server_message_id: Some(id.into()),
            server_epoch: Some(epoch),
            server_sequence: Some(seq),
        };
        envelope.validate_server_metadata()?;
        Ok(Some(envelope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const CID: &str = "70f81686-7619-490d-8686-fd4e012183c4";
    const ID: &str = "3958b8bb-5dc7-4982-a4e9-953998ad58ac";
    fn row() -> Value {
        json!({"$type": APPLICATION_ENTRY_KIND, "entryId": ID, "conversationId": CID,
        "seq": 519, "receivedAt": "2026-09-05T05:40:30.125Z", "signedRequest": {"body": {
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "actorDid": "did:plc:alice", "prior": {"conversationId": CID, "epoch": 7},
            "applicationMessage": {"bytes": {"$bytes": STANDARD.encode([1,2,3])}}
        }, "signature": {"$bytes": STANDARD.encode([9u8; 64])}}})
    }
    #[test]
    fn lexicon_and_bare_byte_presentations_yield_the_same_envelope() {
        let mut bare = row();
        bare["signedRequest"]["body"]["applicationMessage"]["bytes"] =
            json!(STANDARD.encode([1, 2, 3]));
        bare["signedRequest"]["signature"] = json!(STANDARD.encode([9u8; 64]));
        let lexicon = IncomingEnvelope::from_canonical_entry(&row(), CID).unwrap().unwrap();
        let bare = IncomingEnvelope::from_canonical_entry(&bare, CID).unwrap().unwrap();
        assert_eq!(lexicon.ciphertext, [1, 2, 3]);
        assert_eq!(lexicon.ciphertext, bare.ciphertext);
        // Byte objects outside declared bytes fields and non-canonical base64
        // are refused, never guessed.
        let mut wrong = row();
        wrong["signedRequest"]["body"]["applicationMessage"]["bytes"] =
            json!({"$bytes": "AQID", "extra": 1});
        assert!(IncomingEnvelope::from_canonical_entry(&wrong, CID).is_err());
        let mut wrong = row();
        wrong["signedRequest"]["body"]["applicationMessage"]["bytes"] = json!({"$bytes": "AQI"});
        assert!(IncomingEnvelope::from_canonical_entry(&wrong, CID).is_err());
    }
    #[test]
    fn canonical_entries_retain_wire_identity_sequence_timestamp_and_epoch() {
        let envelope = IncomingEnvelope::from_canonical_entry(&row(), CID)
            .unwrap()
            .unwrap();
        assert_eq!(envelope.server_message_id.as_deref(), Some(ID));
        assert_eq!(envelope.server_sequence, Some(519));
        assert_eq!(envelope.server_epoch, Some(7));
        assert_eq!(envelope.ciphertext, [1, 2, 3]);
        assert_eq!(
            envelope
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "2026-09-05T05:40:30.125Z"
        );
    }
    #[test]
    fn canonical_entry_rejects_reserved_ids_bad_scalars_and_conversation_substitution() {
        for id in [
            format!("membership-left:{ID}:{ID}"),
            ID.to_uppercase(),
            "3958b8bb-5dc7-1982-a4e9-953998ad58ac".into(),
            String::new(),
        ] {
            let mut value = row();
            value["entryId"] = json!(id);
            assert!(IncomingEnvelope::from_canonical_entry(&value, CID).is_err());
        }
        for seq in [
            json!(0),
            json!(-1),
            json!(MAX_SAFE_INTEGER + 1),
            json!("519"),
            Value::Null,
        ] {
            let mut value = row();
            value["seq"] = seq;
            assert!(IncomingEnvelope::from_canonical_entry(&value, CID).is_err());
        }
        for stamp in [
            "2026-09-05T05:40:30Z",
            "2026-09-05T05:40:30.125+00:00",
            "2026-02-30T05:40:30.125Z",
            "invalid",
        ] {
            let mut value = row();
            value["receivedAt"] = json!(stamp);
            assert!(IncomingEnvelope::from_canonical_entry(&value, CID).is_err());
        }
        let mut value = row();
        value["signedRequest"]["body"]["prior"]["conversationId"] = json!(ID);
        assert!(IncomingEnvelope::from_canonical_entry(&value, CID).is_err());
        assert!(IncomingEnvelope::from_canonical_entry(&row(), ID).is_err());
        for epoch in [json!(-1), json!(MAX_SAFE_INTEGER + 1), Value::Null] {
            let mut value = row();
            value["signedRequest"]["body"]["prior"]["epoch"] = epoch;
            assert!(IncomingEnvelope::from_canonical_entry(&value, CID).is_err());
        }
    }
    #[test]
    fn canonical_commit_variants_retain_target_epoch_and_order() {
        for kind in [
            COMMIT_ENTRY_KIND,
            LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
            LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
        ] {
            let mut value = row();
            value["$type"] = json!(kind);
            value["signedRequest"]["body"]
                .as_object_mut()
                .unwrap()
                .remove("$type");
            value["signedRequest"]["body"]["next"] = json!({"conversationId": CID, "epoch":8});
            value["signedRequest"]["body"]["commit"] = json!({"bytes": STANDARD.encode([4,5,6])});
            let envelope = IncomingEnvelope::from_canonical_entry(&value, CID)
                .unwrap()
                .unwrap();
            assert_eq!(envelope.server_epoch, Some(8));
            assert_eq!(envelope.server_sequence, Some(519));
            assert_eq!(envelope.ciphertext, [4, 5, 6]);
            value["signedRequest"]["body"]["next"]["conversationId"] = json!(ID);
            assert!(IncomingEnvelope::from_canonical_entry(&value, CID).is_err());
        }
    }
    #[test]
    fn ffi_projection_preserves_metadata_and_rejects_conflicting_epochs_or_invalid_time() {
        let envelope = crate::orchestrator_bridge::FFIIncomingEnvelope {
            canonical_entry_json: None,
            conversation_id: CID.into(),
            sender_did: "did:plc:alice".into(),
            ciphertext: vec![1, 2, 3],
            timestamp: "2026-09-05T05:40:30.125Z".into(),
            server_message_id: Some(ID.into()),
            server_sequence: Some(519),
            server_epoch: Some(7),
        };
        let mapped = crate::orchestrator_bridge::ffi_incoming_envelope_to_internal(
            envelope.clone(),
            Some(7),
        )
        .unwrap();
        assert_eq!(mapped.server_sequence, Some(519));
        assert_eq!(mapped.server_epoch, Some(7));
        let mut wrong_conversation = envelope.clone();
        wrong_conversation.conversation_id = "not-a-canonical-conversation".into();
        assert!(
            crate::orchestrator_bridge::ffi_incoming_envelope_to_internal(wrong_conversation, None)
                .is_err()
        );
        assert!(
            crate::orchestrator_bridge::ffi_incoming_envelope_to_internal(
                envelope.clone(),
                Some(8)
            )
            .is_err()
        );
        let mut malformed = envelope.clone();
        malformed.timestamp = "bad timestamp".into();
        assert!(
            crate::orchestrator_bridge::ffi_incoming_envelope_to_internal(malformed, None).is_err()
        );
        let mut legacy = envelope;
        legacy.server_sequence = None;
        legacy.server_epoch = None;
        legacy.server_message_id = Some("arbitrary-legacy-id".into());
        assert!(
            crate::orchestrator_bridge::ffi_incoming_envelope_to_internal(legacy, None).is_ok()
        );
    }
}
