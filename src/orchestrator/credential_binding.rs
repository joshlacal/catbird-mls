//! WS-3 stage 1: credential binding checks (ADR-009, warn-and-allow).
//!
//! Binds MLS leaf credentials to ATProto DIDs at the two trust boundaries
//! that previously had none:
//!
//! 1. **Key-package fetch** (ADR-009 D3): DS-returned key packages are
//!    structurally decoded and their leaf credential identity is compared
//!    against the DID the package was fetched for.
//! 2. **Inbound processing** (ADR-009 D4): the MLS sender credential of every
//!    decrypted message/commit is compared against the envelope's claimed
//!    sender DID (the envelope is a routing hint, the credential is the
//!    proof-bearing side).
//!
//! It also wires the previously-unwired `SequencerReceipt::detect_equivocation`
//! (ADR-009 D8 / backlog invariant E3) into the receipt-storage chokepoint
//! used by the External-Commit recovery path and member-change commits.
//!
//! ## Rollout mode (ADR-009 D5)
//!
//! Stage 1 is hard-wired **warn-and-allow**: every check logs a structured
//! warning through the platform logging facility (`error_log!` → `MLSLogger`,
//! so Android/iOS/catmos all see it) and escalates through
//! `OrchestratorEventObserver`, then continues exactly as before. The later
//! enforce flip is an ADR-gated change confined to the `emit_*` chokepoints
//! in this file — callers already receive the structured outcome, so flipping
//! to enforcement means returning an error from the chokepoint instead of
//! logging, not rewriting call sites.
//!
//! ## Verification depth (stage 1 vs later stages)
//!
//! Stage 1 implements the **structural** half of ADR-009's proof: credential
//! decodes, identity is UTF-8, and the DID root of the claimed identity
//! (substring before `#`, fragment/device-id aware) equals the expected DID.
//! The second half — leaf signature key matches an active
//! `blue.catbird.mlsChat.device` record in the root DID's ATProto repo, with
//! D6 caching/revocation — is the platform-overridable seam on
//! `CredentialStore::verify_member_credential`. Platforms with repo access
//! override that method; the default stays structural.

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::{KeyPackageRef, SequencerReceipt};

/// Outcome of verifying a member's MLS credential against an expected
/// ATProto DID (ADR-009).
///
/// Returned by `CredentialStore::verify_member_credential`. Stage 1 only
/// produces these structurally; platform overrides that add DID-doc
/// device-key binding return the same vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialVerification {
    /// The credential's identity claim is consistent with the expected DID.
    /// For the stage-1 default this means the DID roots match; overriding
    /// platforms additionally verified the device signing key.
    Verified,
    /// The credential's root DID differs from the expected DID — the
    /// signature-bearing identity does not belong to the member it was
    /// presented for.
    DidMismatch {
        expected_did: String,
        claimed_identity: String,
        claimed_root_did: String,
    },
    /// The credential could not be interpreted (e.g. identity is not UTF-8).
    Unverifiable { reason: String },
}

/// Extract the DID root from a credential identity (ADR-009 D1 part 1).
///
/// The MLS BasicCredential identity is either the bare ATProto DID or a
/// DID-rooted device identity of the form `did:...#device-id`. The root is
/// the substring before `#`, or the full value when no fragment is present.
pub fn credential_root_did(identity: &str) -> &str {
    identity.split('#').next().unwrap_or(identity)
}

/// Structural identity-claim consistency check (stage-1 default verifier).
///
/// Compares the DID root of `claimed_identity` against the DID root of
/// `expected_did` (fragment-aware on both sides). ASCII-case-insensitive to
/// match the orchestrator's existing own-DID comparison semantics
/// (`messaging.rs` lowercases before comparing).
pub fn check_identity_claim(expected_did: &str, claimed_identity: &str) -> CredentialVerification {
    let claimed_root = credential_root_did(claimed_identity);
    let expected_root = credential_root_did(expected_did);
    if !claimed_root.is_empty() && claimed_root.eq_ignore_ascii_case(expected_root) {
        CredentialVerification::Verified
    } else {
        CredentialVerification::DidMismatch {
            expected_did: expected_did.to_string(),
            claimed_identity: claimed_identity.to_string(),
            claimed_root_did: claimed_root.to_string(),
        }
    }
}

/// Structurally decode a serialized MLS KeyPackage and extract its leaf
/// credential identity as a UTF-8 string.
///
/// This performs TLS decoding only — no signature verification (that still
/// happens in `MLSContext::add_members` via `KeyPackageIn::validate`). It is
/// deliberately a pure function so both fetch-time verification and tests can
/// use it without an MLS group in scope.
pub fn extract_key_package_identity(key_package_data: &[u8]) -> Result<String, String> {
    use openmls::prelude::tls_codec::DeserializeBytes;
    use openmls::prelude::KeyPackageIn;

    let (kp_in, _rest) = KeyPackageIn::tls_deserialize_bytes(key_package_data)
        .map_err(|e| format!("key package TLS decode failed: {e:?}"))?;
    let credential_with_key = kp_in.unverified_credential();
    String::from_utf8(credential_with_key.credential.serialized_content().to_vec())
        .map_err(|_| "credential identity is not UTF-8".to_string())
}

/// Short hash prefix of a key package's serialized bytes for log correlation
/// (ADR-009 D5 structured-warning field).
fn kp_hash_prefix(key_package_data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(key_package_data)[..8])
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// ADR-009 D3 (verify-on-fetch), stage-1 warn-and-allow.
    ///
    /// Runs the credential-binding check against every key package returned
    /// by `getKeyPackages` before the packages are used in an Add/Welcome
    /// path. Checks, per package:
    ///
    /// 1. `keyPackageRef.did` is one of the DIDs the caller requested,
    /// 2. the package's leaf credential decodes structurally,
    /// 3. the credential's DID root equals `keyPackageRef.did`
    ///    (via `CredentialStore::verify_member_credential`, so platforms
    ///    that override it also get device-key binding here).
    ///
    /// Warn-only: every failure is logged/escalated and the operation
    /// continues unchanged. Never returns an error.
    pub(crate) async fn verify_fetched_key_packages(
        &self,
        requested_dids: &[String],
        key_packages: &[KeyPackageRef],
        context: &str,
        conversation_id: Option<&str>,
    ) {
        for kp in key_packages {
            let hash_prefix = kp_hash_prefix(&kp.key_package_data);

            // 1. Response DID must be one the caller actually requested.
            if !requested_dids
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&kp.did))
            {
                // The credential hasn't been parsed yet at this point, so
                // there is no claimed identity to report — only the DS label.
                self.emit_credential_binding_warning(
                    conversation_id,
                    "fetch",
                    context,
                    &kp.did,
                    "<unparsed>",
                    &hash_prefix,
                    "key package returned for a DID that was not requested",
                )
                .await;
                // Still run the credential check below against the labeled DID.
            }

            // 2. Structural decode of the leaf credential.
            let claimed_identity = match extract_key_package_identity(&kp.key_package_data) {
                Ok(identity) => identity,
                Err(reason) => {
                    self.emit_credential_binding_warning(
                        conversation_id,
                        "fetch",
                        context,
                        &kp.did,
                        "<unparsable>",
                        &hash_prefix,
                        &reason,
                    )
                    .await;
                    continue;
                }
            };

            // 3. Identity-claim consistency via the CredentialStore seam.
            match self
                .credentials()
                .verify_member_credential(&kp.did, &claimed_identity)
                .await
            {
                Ok(CredentialVerification::Verified) => {
                    tracing::debug!(
                        did = %kp.did,
                        context,
                        "key package credential binding verified"
                    );
                }
                Ok(CredentialVerification::DidMismatch {
                    expected_did,
                    claimed_identity,
                    claimed_root_did,
                }) => {
                    let reason = format!(
                        "credential root DID `{claimed_root_did}` does not match expected DID `{expected_did}`"
                    );
                    self.emit_credential_binding_warning(
                        conversation_id,
                        "fetch",
                        context,
                        &expected_did,
                        &claimed_identity,
                        &hash_prefix,
                        &reason,
                    )
                    .await;
                }
                Ok(CredentialVerification::Unverifiable { reason }) => {
                    self.emit_credential_binding_warning(
                        conversation_id,
                        "fetch",
                        context,
                        &kp.did,
                        &claimed_identity,
                        &hash_prefix,
                        &reason,
                    )
                    .await;
                }
                Err(e) => {
                    // Verifier infrastructure failure (platform override hit
                    // a network/storage error). Warn-only — never block the
                    // operation on the verifier itself in stage 1.
                    let reason = format!("credential verifier error: {e}");
                    self.emit_credential_binding_warning(
                        conversation_id,
                        "fetch",
                        context,
                        &kp.did,
                        &claimed_identity,
                        &hash_prefix,
                        &reason,
                    )
                    .await;
                }
            }
        }
    }

    /// ADR-009 D4 (verify inbound), stage-1 warn-and-allow.
    ///
    /// Cross-checks the MLS sender credential extracted from a decrypted
    /// message/commit against the envelope's claimed sender DID. The envelope
    /// `senderDid` is a routing hint, not proof — a mismatch means either the
    /// DS mislabeled the envelope or the leaf credential does not belong to
    /// the claimed sender. Warn-only; the message continues to be processed.
    ///
    /// Scope note (documented limitation): at the orchestrator layer only the
    /// *sender* credential is visible per inbound frame
    /// (`DecryptResult.sender_credential`). Credentials of members *added* by
    /// an inbound commit are consumed inside `MlsCryptoContext`
    /// (`decrypt_message` → staged commit → `merge_incoming_commit`) and are
    /// not surfaced through the trait, so per-added-leaf verification at
    /// inbound-commit time needs an `MlsCryptoContext` extension (follow-up,
    /// see ADR-009 D4 "Add proposals and commits"). The sender check below
    /// still covers External-Commit joiners and commit senders, because their
    /// credential IS the sender credential of the commit frame.
    pub(crate) async fn verify_inbound_sender_credential(
        &self,
        conversation_id: &str,
        envelope_sender_did: &str,
        credential_identity: &[u8],
    ) {
        if envelope_sender_did.is_empty() {
            // No expected DID available — nothing to bind against. Structural
            // UTF-8 validity is still checkable.
            if String::from_utf8(credential_identity.to_vec()).is_err() {
                self.emit_credential_binding_warning(
                    Some(conversation_id),
                    "message",
                    "process_incoming",
                    "<unknown>",
                    "<non-utf8>",
                    "",
                    "sender credential identity is not UTF-8 and envelope carries no sender DID",
                )
                .await;
            }
            return;
        }

        let claimed_identity = match String::from_utf8(credential_identity.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                self.emit_credential_binding_warning(
                    Some(conversation_id),
                    "message",
                    "process_incoming",
                    envelope_sender_did,
                    "<non-utf8>",
                    "",
                    "sender credential identity is not UTF-8",
                )
                .await;
                return;
            }
        };

        match self
            .credentials()
            .verify_member_credential(envelope_sender_did, &claimed_identity)
            .await
        {
            Ok(CredentialVerification::Verified) => {}
            Ok(CredentialVerification::DidMismatch {
                expected_did,
                claimed_identity,
                claimed_root_did,
            }) => {
                let reason = format!(
                    "MLS sender credential root `{claimed_root_did}` does not match envelope sender DID `{expected_did}`"
                );
                self.emit_credential_binding_warning(
                    Some(conversation_id),
                    "message",
                    "process_incoming",
                    &expected_did,
                    &claimed_identity,
                    "",
                    &reason,
                )
                .await;
            }
            Ok(CredentialVerification::Unverifiable { reason }) => {
                self.emit_credential_binding_warning(
                    Some(conversation_id),
                    "message",
                    "process_incoming",
                    envelope_sender_did,
                    &claimed_identity,
                    "",
                    &reason,
                )
                .await;
            }
            Err(e) => {
                let reason = format!("credential verifier error: {e}");
                self.emit_credential_binding_warning(
                    Some(conversation_id),
                    "message",
                    "process_incoming",
                    envelope_sender_did,
                    &claimed_identity,
                    "",
                    &reason,
                )
                .await;
            }
        }
    }

    /// Single chokepoint for credential-binding failures (ADR-009 D5).
    ///
    /// Stage 1: structured `error_log!` (platform logging — Android/iOS see
    /// it, unlike bare `tracing`) + `OrchestratorEventObserver` escalation,
    /// then return — callers continue unchanged. The future enforce flip
    /// converts this chokepoint into an error return; call sites already
    /// pass everything an enforcement decision needs.
    #[allow(clippy::too_many_arguments)]
    async fn emit_credential_binding_warning(
        &self,
        conversation_id: Option<&str>,
        operation: &str,
        context: &str,
        expected_did: &str,
        claimed_identity: &str,
        kp_hash_prefix: &str,
        reason: &str,
    ) {
        let convo = conversation_id.unwrap_or("<none>");
        let claimed_root = credential_root_did(claimed_identity);
        crate::error_log!(
            "[CREDENTIAL-BINDING] mode=warn_only operation={} context={} conversation={} expected_did={} claimed_identity={} claimed_root_did={} kp_hash_prefix={} path=rust-orchestrator reason={}",
            operation,
            context,
            convo,
            expected_did,
            claimed_identity,
            claimed_root,
            kp_hash_prefix,
            reason
        );
        tracing::error!(
            operation,
            context,
            conversation = convo,
            expected_did,
            claimed_identity,
            claimed_root_did = claimed_root,
            kp_hash_prefix,
            reason,
            "credential binding check failed (warn-and-allow — continuing)"
        );
        if let Some(observer) = self.current_event_observer().await {
            observer.on_credential_binding_warning(
                convo,
                operation,
                expected_did,
                claimed_identity,
                reason,
            );
        }
    }

    /// ADR-009 D8 / backlog E3: store a sequencer receipt, first comparing it
    /// against previously stored receipts for the same conversation to detect
    /// sequencer equivocation (two receipts for the same `(conversation,
    /// epoch)` with different commit hashes).
    ///
    /// Stage 1 is detection, not refusal: on equivocation this logs loudly
    /// (both receipts' identifying fields), escalates via
    /// `OrchestratorEventObserver::on_sequencer_equivocation`, and the
    /// calling operation continues. Backends whose
    /// `get_sequencer_receipts` is the default no-op (returns empty) simply
    /// never detect — receipt persistence is the existing
    /// `store_sequencer_receipt` seam, no new storage was added.
    pub(crate) async fn record_and_check_sequencer_receipt(
        &self,
        receipt: &SequencerReceipt,
        operation: &str,
    ) {
        match self
            .storage()
            .get_sequencer_receipts(&receipt.convo_id, Some(receipt.epoch))
            .await
        {
            Ok(prior_receipts) => {
                for prior in prior_receipts
                    .iter()
                    .filter(|prior| prior.detect_equivocation(receipt))
                {
                    let stored_hash = hex::encode(&prior.commit_hash);
                    let new_hash = hex::encode(&receipt.commit_hash);
                    crate::error_log!(
                        "[SEQUENCER-EQUIVOCATION] mode=warn_only operation={} convo_id={} epoch={} stored_commit_hash={} stored_sequencer_did={} stored_issued_at={} new_commit_hash={} new_sequencer_did={} new_issued_at={} — two receipts for the same (conversation, epoch) with different commit hashes prove sequencer equivocation (ADR-009 D8); stage-1 continues the operation",
                        operation,
                        receipt.convo_id,
                        receipt.epoch,
                        stored_hash,
                        prior.sequencer_did,
                        prior.issued_at,
                        new_hash,
                        receipt.sequencer_did,
                        receipt.issued_at
                    );
                    tracing::error!(
                        operation,
                        convo_id = %receipt.convo_id,
                        epoch = receipt.epoch,
                        stored_commit_hash = %stored_hash,
                        stored_sequencer_did = %prior.sequencer_did,
                        new_commit_hash = %new_hash,
                        new_sequencer_did = %receipt.sequencer_did,
                        "sequencer equivocation detected (warn-and-allow — continuing)"
                    );
                    if let Some(observer) = self.current_event_observer().await {
                        observer.on_sequencer_equivocation(
                            &receipt.convo_id,
                            receipt.epoch,
                            &stored_hash,
                            &new_hash,
                            &receipt.sequencer_did,
                        );
                    }
                }
            }
            Err(e) => {
                // Platform-visible (warn_log! routes through MLSLogger, unlike
                // bare tracing): a failed load means equivocation detection is
                // silently degraded for this receipt — infra failure, not a
                // security signal, but platforms must be able to see it.
                crate::warn_log!(
                    "[SEQUENCER-EQUIVOCATION] receipt-load-failed operation={} convo_id={} epoch={} error={} — equivocation detection skipped for this receipt",
                    operation,
                    receipt.convo_id,
                    receipt.epoch,
                    e
                );
                tracing::warn!(
                    error = %e,
                    operation,
                    convo_id = %receipt.convo_id,
                    "Failed to load stored sequencer receipts for equivocation check"
                );
            }
        }

        // Best-effort storage (pre-existing behavior, now behind the check).
        if let Err(e) = self.storage().store_sequencer_receipt(receipt).await {
            tracing::warn!(
                error = %e,
                convo_id = %receipt.convo_id,
                "Failed to store sequencer receipt"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_did_bare() {
        assert_eq!(credential_root_did("did:plc:alice"), "did:plc:alice");
    }

    #[test]
    fn root_did_with_device_fragment() {
        assert_eq!(
            credential_root_did("did:plc:alice#device-1"),
            "did:plc:alice"
        );
    }

    #[test]
    fn claim_check_matches_bare_did() {
        assert_eq!(
            check_identity_claim("did:plc:alice", "did:plc:alice"),
            CredentialVerification::Verified
        );
    }

    #[test]
    fn claim_check_matches_device_rooted_identity() {
        assert_eq!(
            check_identity_claim("did:plc:alice", "did:plc:alice#device-1"),
            CredentialVerification::Verified
        );
    }

    #[test]
    fn claim_check_is_ascii_case_insensitive() {
        assert_eq!(
            check_identity_claim("did:web:Example.Com", "did:web:example.com"),
            CredentialVerification::Verified
        );
    }

    #[test]
    fn claim_check_rejects_mismatched_root() {
        match check_identity_claim("did:plc:alice", "did:plc:mallory#device-1") {
            CredentialVerification::DidMismatch {
                expected_did,
                claimed_root_did,
                ..
            } => {
                assert_eq!(expected_did, "did:plc:alice");
                assert_eq!(claimed_root_did, "did:plc:mallory");
            }
            other => panic!("expected DidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn claim_check_rejects_empty_identity() {
        assert!(matches!(
            check_identity_claim("did:plc:alice", ""),
            CredentialVerification::DidMismatch { .. }
        ));
    }

    #[test]
    fn extract_identity_rejects_garbage() {
        assert!(extract_key_package_identity(&[0xFF, 0x00, 0x13]).is_err());
        assert!(extract_key_package_identity(&[]).is_err());
    }

    /// Round-trip: build a real OpenMLS key package with a DID-rooted
    /// identity and confirm the structural extractor recovers it.
    #[test]
    fn extract_identity_round_trip() {
        use openmls::prelude::{tls_codec::Serialize as _, *};
        use openmls_basic_credential::SignatureKeyPair;
        use openmls_rust_crypto::OpenMlsRustCrypto;

        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let identity = "did:plc:alice#device-1";

        let credential = BasicCredential::new(identity.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };

        let bundle = KeyPackage::builder()
            .build(ciphersuite, &provider, &signer, credential_with_key)
            .unwrap();
        let kp_bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .expect("serialize key package");

        let extracted = extract_key_package_identity(&kp_bytes).expect("extract identity");
        assert_eq!(extracted, identity);
        assert_eq!(
            check_identity_claim("did:plc:alice", &extracted),
            CredentialVerification::Verified
        );
    }
}
