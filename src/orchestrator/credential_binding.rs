//! Credential binding enforcement (ADR-009).
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
//! ## Enforcement mode (ADR-009 D5)
//!
//! Every failed check is logged through the platform logging facility and
//! escalated through `OrchestratorEventObserver`, then returned as an error.
//! A candidate MLS key must match a repository-authorized key resolved by
//! the platform for the credential DID. The delivery service is never a key
//! authority. Missing or malformed repository authority is a hard failure.
//!
//! ## Verification depth (stage 1 vs stage 2)
//!
//! Stage 1 implements the **structural** half of ADR-009's proof: credential
//! decodes, identity is UTF-8, and the DID root of the claimed identity
//! (substring before `#`, fragment/device-id aware) equals the expected DID.
//!
//! Stage 2 adds the **device-key** half on the fetch path: the leaf signature
//! public key must be an authorized MLS device key for the credential's root
//! DID (ADR-009 D1 part 2). The platform `CredentialStore` must resolve the
//! repository-published device records and return their authorized raw keys.
//! A missing callback or an empty repository set cannot fall back to the DS.
//! Positive and negative results share `constants::DEVICE_KEY_CACHE_TTL`;
//! repository failures are never cached. A cached key miss refreshes once so
//! a newly published sibling does not wait for the positive-cache TTL.
//!
//! The device-key half does NOT yet run on the inbound path:
//! `DecryptResult.sender_credential` (`CredentialData`) carries only the
//! identity, not the leaf signature key, and extending that UniFFI record is
//! out of scope for this stage (backlog N44d). Inbound DID-root binding is
//! enforced, while OpenMLS remains responsible for authenticating the sender
//! credential and frame signature.

use web_time::Instant;

use super::api_client::MLSAPIClient;
use super::constants;
use super::credentials::CredentialStore;
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::{KeyPackageRef, SequencerReceipt};

/// Maximum number of KeyPackages accepted from one DS fetch. This matches the
/// delivery-service batch ceiling and bounds per-item validation work even if
/// an untrusted caller supplies an oversized DID list.
pub(crate) const MAX_FETCHED_KEY_PACKAGE_COUNT: usize = 100;

/// A serialized hybrid/PQ KeyPackage is normally only a few KiB. One MiB is a
/// deliberately generous compatibility ceiling that still prevents a single
/// DS-controlled element from reaching TLS decoding with attacker-selected
/// multi-megabyte input.
pub(crate) const MAX_FETCHED_KEY_PACKAGE_BYTES: usize = 1024 * 1024;

/// Aggregate bound aligned with the existing C FFI Add-members input ceiling.
/// This is checked before cloning KeyPackage bytes into `KeyPackageData`.
pub(crate) const MAX_FETCHED_KEY_PACKAGE_BATCH_BYTES: usize = 10 * 1024 * 1024;

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
/// `expected_did` (fragment-aware on both sides). DID method-specific
/// identifiers may be case-sensitive, so authorization uses exact equality;
/// display/routing normalization must not collapse distinct DID authorities.
pub fn check_identity_claim(expected_did: &str, claimed_identity: &str) -> CredentialVerification {
    let claimed_root = credential_root_did(claimed_identity);
    let expected_root = credential_root_did(expected_did);
    if !claimed_root.is_empty() && claimed_root == expected_root {
        CredentialVerification::Verified
    } else {
        CredentialVerification::DidMismatch {
            expected_did: expected_did.to_string(),
            claimed_identity: claimed_identity.to_string(),
            claimed_root_did: claimed_root.to_string(),
        }
    }
}

/// Credential-binding material structurally extracted from a serialized MLS
/// KeyPackage: the two fields ADR-009's proof binds together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageBindingInfo {
    /// UTF-8 leaf credential identity (bare DID or `did:...#device-id`).
    pub identity: String,
    /// Raw leaf signature public key bytes.
    pub signature_key: Vec<u8>,
}

/// Structurally decode a serialized MLS KeyPackage and extract its leaf
/// credential identity plus leaf signature public key.
///
/// This performs TLS decoding only — no signature verification (that still
/// happens in `MLSContext::add_members` via `KeyPackageIn::validate`). It is
/// deliberately a pure function so both fetch-time verification and tests can
/// use it without an MLS group in scope.
pub fn extract_key_package_binding(
    key_package_data: &[u8],
) -> Result<KeyPackageBindingInfo, String> {
    use openmls::prelude::tls_codec::DeserializeBytes;
    use openmls::prelude::{KeyPackageIn, MlsMessageBodyIn, MlsMessageIn};

    let wrapped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MlsMessageIn::tls_deserialize_bytes(key_package_data)
    }));
    let kp_in = match wrapped {
        Ok(Ok((message, remaining))) => {
            if !remaining.is_empty() {
                return Err(format!(
                    "wrapped key package has {} trailing bytes",
                    remaining.len()
                ));
            }
            match message.extract() {
                MlsMessageBodyIn::KeyPackage(key_package) => key_package,
                _ => return Err("MLS message body is not a key package".to_string()),
            }
        }
        Ok(Err(_)) | Err(_) => {
            let raw = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                KeyPackageIn::tls_deserialize_bytes(key_package_data)
            }))
            .map_err(|_| "raw key package TLS decoder panicked on malformed input".to_string())?;
            let (key_package, remaining) =
                raw.map_err(|e| format!("key package TLS decode failed: {e:?}"))?;
            if !remaining.is_empty() {
                return Err(format!(
                    "raw key package has {} trailing bytes",
                    remaining.len()
                ));
            }
            key_package
        }
    };
    let credential_with_key = kp_in.unverified_credential();
    let identity = String::from_utf8(credential_with_key.credential.serialized_content().to_vec())
        .map_err(|_| "credential identity is not UTF-8".to_string())?;
    Ok(KeyPackageBindingInfo {
        identity,
        signature_key: credential_with_key.signature_key.as_slice().to_vec(),
    })
}

/// Structurally decode a serialized MLS KeyPackage and extract its leaf
/// credential identity as a UTF-8 string. See [`extract_key_package_binding`]
/// for the variant that also returns the leaf signature key.
pub fn extract_key_package_identity(key_package_data: &[u8]) -> Result<String, String> {
    extract_key_package_binding(key_package_data).map(|info| info.identity)
}

/// Validate the untrusted DS response shape before parsing or cloning any
/// serialized KeyPackage bytes.
///
/// The response labels are routing metadata rather than credential authority,
/// but requiring their exact multiset to match the request prevents appended,
/// missing, duplicate, or unrelated response elements from reaching more
/// expensive credential decoding. Embedded credential roots are checked
/// separately by [`MLSOrchestrator::verify_fetched_key_packages`].
pub(crate) fn validate_fetched_key_package_batch(
    requested_dids: &[String],
    key_packages: &[KeyPackageRef],
) -> super::error::Result<()> {
    use std::collections::BTreeMap;

    if requested_dids.len() > MAX_FETCHED_KEY_PACKAGE_COUNT {
        return Err(super::error::OrchestratorError::InvalidInput(format!(
            "key-package request count {} exceeds maximum {}",
            requested_dids.len(),
            MAX_FETCHED_KEY_PACKAGE_COUNT
        )));
    }
    if key_packages.len() != requested_dids.len() {
        return Err(super::error::OrchestratorError::InvalidInput(format!(
            "delivery service returned {} key packages for {} requested DIDs",
            key_packages.len(),
            requested_dids.len()
        )));
    }

    let mut expected_labels = BTreeMap::<String, usize>::new();
    for did in requested_dids {
        if !did.starts_with("did:")
            || credential_root_did(did) != did
            || catbird_atproto::types::string::Did::new(did.as_str()).is_err()
        {
            return Err(super::error::OrchestratorError::InvalidInput(
                "key-package request authority must contain syntactically valid bare DIDs"
                    .to_string(),
            ));
        }
        *expected_labels.entry(did.clone()).or_default() += 1;
    }

    let mut returned_labels = BTreeMap::<String, usize>::new();
    let mut aggregate_bytes = 0usize;
    for (index, key_package) in key_packages.iter().enumerate() {
        let package_bytes = key_package.key_package_data.len();
        if package_bytes > MAX_FETCHED_KEY_PACKAGE_BYTES {
            return Err(super::error::OrchestratorError::InvalidInput(format!(
                "delivery-service key package {index} is {package_bytes} bytes, exceeding the {MAX_FETCHED_KEY_PACKAGE_BYTES}-byte maximum"
            )));
        }
        aggregate_bytes = aggregate_bytes.checked_add(package_bytes).ok_or_else(|| {
            super::error::OrchestratorError::InvalidInput(
                "delivery-service key-package byte count overflowed".to_string(),
            )
        })?;
        if aggregate_bytes > MAX_FETCHED_KEY_PACKAGE_BATCH_BYTES {
            return Err(super::error::OrchestratorError::InvalidInput(format!(
                "delivery-service key-package batch is {aggregate_bytes} bytes, exceeding the {MAX_FETCHED_KEY_PACKAGE_BATCH_BYTES}-byte maximum"
            )));
        }
        *returned_labels.entry(key_package.did.clone()).or_default() += 1;
    }

    if returned_labels != expected_labels {
        return Err(super::error::OrchestratorError::InvalidInput(format!(
            "delivery-service key-package labels do not exactly match requested DIDs (expected {expected_labels:?}, returned {returned_labels:?})"
        )));
    }

    Ok(())
}

/// Fail-closed structural gate for outbound Add/Swap key-package batches.
///
/// Unlike [`MLSOrchestrator::verify_fetched_key_packages`], this helper is an
/// enforcing precondition. It derives authority from the credential embedded
/// in each raw KeyPackage, not from a delivery-service label, and requires the
/// resulting DID-root multiset to exactly equal the requested DID multiset.
/// Callers must invoke it before any MLS add/swap operation so a substituted,
/// appended, missing, malformed, or mismatched package cannot create a pending
/// commit or partially mutate a swap.
pub(crate) fn enforce_outbound_key_package_did_bindings(
    expected_dids: &[String],
    key_packages: &[crate::KeyPackageData],
) -> super::error::Result<()> {
    use std::collections::BTreeMap;

    let mut expected = BTreeMap::<String, usize>::new();
    for did in expected_dids {
        if !did.starts_with("did:")
            || credential_root_did(did) != did
            || catbird_atproto::types::string::Did::new(did.as_str()).is_err()
        {
            return Err(super::error::OrchestratorError::InvalidInput(
                "outbound key-package authority must contain syntactically valid bare DIDs"
                    .to_string(),
            ));
        }
        *expected.entry(did.clone()).or_default() += 1;
    }

    let mut claimed = BTreeMap::<String, usize>::new();
    for (index, key_package) in key_packages.iter().enumerate() {
        let identity = extract_key_package_identity(&key_package.data).map_err(|reason| {
            super::error::OrchestratorError::InvalidInput(format!(
                "outbound key package {index} has an unverifiable credential: {reason}"
            ))
        })?;
        let root = credential_root_did(&identity);
        if !root.starts_with("did:") || catbird_atproto::types::string::Did::new(root).is_err() {
            return Err(super::error::OrchestratorError::InvalidInput(format!(
                "outbound key package {index} does not claim a syntactically valid credential DID root"
            )));
        }
        *claimed.entry(root.to_string()).or_default() += 1;
    }

    if claimed != expected {
        return Err(super::error::OrchestratorError::InvalidInput(format!(
            "outbound key-package credential DID roots do not exactly match requested DIDs (expected {expected:?}, claimed {claimed:?})"
        )));
    }

    Ok(())
}

/// Cached outcome of repository-authorized device-key resolution (ADR-009 D6).
/// Positive and negative results share a bounded TTL; errors are uncached.
#[derive(Debug, Clone)]
pub enum DeviceKeyLookup {
    /// The platform cannot resolve repository-published device keys.
    Unsupported,
    /// The repository-authorized signing keys for this exact root DID.
    /// An empty set is an explicit denial, not an unavailable capability.
    Keys(std::sync::Arc<Vec<Vec<u8>>>),
}

/// A device-key cache row: when it was resolved plus what was resolved.
#[derive(Debug, Clone)]
pub struct DeviceKeyCacheEntry {
    pub resolved_at: Instant,
    pub lookup: DeviceKeyLookup,
}

/// Short SHA-256 prefix of a byte blob (key package or signature key) for
/// log correlation (ADR-009 D5 structured-warning field).
fn sha256_prefix(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(data)[..8])
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// ADR-009 D3 (verify-on-fetch), enforced before MLS state changes.
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
    /// The untrusted response count and byte bounds are checked before any
    /// KeyPackage is parsed. Every credential or resolver failure is then
    /// logged/escalated and returned to the caller before bytes are cloned
    /// into `KeyPackageData` or handed to OpenMLS.
    pub(crate) async fn verify_fetched_key_packages(
        &self,
        requested_dids: &[String],
        key_packages: &[KeyPackageRef],
        context: &str,
        conversation_id: Option<&str>,
    ) -> super::error::Result<()> {
        validate_fetched_key_package_batch(requested_dids, key_packages)?;

        for kp in key_packages {
            let hash_prefix = sha256_prefix(&kp.key_package_data);

            // Structural decode of the leaf credential + signature key. This
            // is not OpenMLS authentication; it extracts application-binding
            // material before OpenMLS is allowed to validate/stage the package.
            let binding = match extract_key_package_binding(&kp.key_package_data) {
                Ok(info) => info,
                Err(reason) => {
                    return Err(self
                        .emit_credential_binding_rejection(
                            conversation_id,
                            "fetch",
                            context,
                            &kp.did,
                            "<unparsable>",
                            &hash_prefix,
                            &reason,
                        )
                        .await);
                }
            };
            let claimed_identity = binding.identity.clone();

            // Identity-claim consistency via the CredentialStore seam.
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
                    // Device-key half of the ADR-009 proof —
                    // the leaf signing key must be an authorized device key
                    // for the credential's root DID. Unsupported resolution,
                    // an empty/mismatched key set, and resolver errors all fail
                    // closed before OpenMLS sees the package.
                    self.verify_leaf_device_key_binding(
                        conversation_id,
                        "fetch",
                        context,
                        credential_root_did(&claimed_identity),
                        &claimed_identity,
                        &binding.signature_key,
                        &hash_prefix,
                    )
                    .await?;
                }
                Ok(CredentialVerification::DidMismatch {
                    expected_did,
                    claimed_identity,
                    claimed_root_did,
                }) => {
                    let reason = format!(
                        "credential root DID `{claimed_root_did}` does not match expected DID `{expected_did}`"
                    );
                    return Err(self
                        .emit_credential_binding_rejection(
                            conversation_id,
                            "fetch",
                            context,
                            &expected_did,
                            &claimed_identity,
                            &hash_prefix,
                            &reason,
                        )
                        .await);
                }
                Ok(CredentialVerification::Unverifiable { reason }) => {
                    return Err(self
                        .emit_credential_binding_rejection(
                            conversation_id,
                            "fetch",
                            context,
                            &kp.did,
                            &claimed_identity,
                            &hash_prefix,
                            &reason,
                        )
                        .await);
                }
                Err(e) => {
                    let reason = format!("credential verifier error: {e}");
                    return Err(self
                        .emit_credential_binding_rejection(
                            conversation_id,
                            "fetch",
                            context,
                            &kp.did,
                            &claimed_identity,
                            &hash_prefix,
                            &reason,
                        )
                        .await);
                }
            }
        }

        Ok(())
    }

    /// Resolve (with ADR-009 D6 caching) the authorized device signing keys
    /// for a root DID via the optional `CredentialStore` capability.
    ///
    /// Cache semantics: positive, negative, and `Unsupported` outcomes are
    /// all cached for `constants::DEVICE_KEY_CACHE_TTL`; seam **errors are
    /// not cached** (the next check retries). Cache keys preserve exact root
    /// DID bytes, including case-sensitive method-specific identifiers.
    pub(crate) async fn lookup_authorized_device_keys(
        &self,
        root_did: &str,
    ) -> super::error::Result<DeviceKeyLookup> {
        self.lookup_authorized_device_keys_with_origin(root_did, false)
            .await
            .map(|(lookup, _)| lookup)
    }

    pub(crate) async fn refresh_authorized_device_keys(
        &self,
        root_did: &str,
    ) -> super::error::Result<DeviceKeyLookup> {
        self.lookup_authorized_device_keys_with_origin(root_did, true)
            .await
            .map(|(lookup, _)| lookup)
    }

    pub(crate) async fn lookup_authorized_device_keys_with_origin(
        &self,
        root_did: &str,
        force_refresh: bool,
    ) -> super::error::Result<(DeviceKeyLookup, bool)> {
        let cache_key = root_did.to_string();
        if !force_refresh {
            let cache = self.device_key_cache().lock().await;
            if let Some(entry) = cache.get(&cache_key) {
                if entry.resolved_at.elapsed() < constants::DEVICE_KEY_CACHE_TTL {
                    return Ok((entry.lookup.clone(), true));
                }
            }
        }

        let lookup = match self
            .credentials()
            .get_authorized_device_keys(root_did)
            .await
        {
            Ok(Some(keys)) => DeviceKeyLookup::Keys(std::sync::Arc::new(keys)),
            Ok(None) => DeviceKeyLookup::Unsupported,
            Err(e) => return Err(e),
        };

        self.device_key_cache().lock().await.insert(
            cache_key,
            DeviceKeyCacheEntry {
                resolved_at: Instant::now(),
                lookup: lookup.clone(),
            },
        );
        Ok((lookup, false))
    }

    /// A newly enrolled sibling must not wait for the positive-cache TTL.
    /// Refresh a cached repository-key miss once; a fresh miss still rejects.
    /// Every returned key still comes solely from the repository callback.
    pub(crate) async fn lookup_candidate_device_key(
        &self,
        root_did: &str,
        candidate_key: &[u8],
    ) -> super::error::Result<DeviceKeyLookup> {
        let (lookup, cached) = self
            .lookup_authorized_device_keys_with_origin(root_did, false)
            .await?;
        if cached
            && matches!(&lookup, DeviceKeyLookup::Keys(keys)
            if !keys.iter().any(|key| key.as_slice() == candidate_key))
        {
            return self.refresh_authorized_device_keys(root_did).await;
        }
        Ok(lookup)
    }

    /// ADR-009 full check, device-key half (enforced):
    /// verify that a leaf's signature public key is currently published as
    /// an authorized MLS device key for the credential's root DID.
    ///
    /// Outcomes:
    /// - platform has no DID-resolution surface → reject;
    /// - key found in the authorized set → `debug!`;
    /// - key NOT in the authorized set (including "resolved, zero keys") →
    ///   structured rejection;
    /// - resolution infrastructure error → reject.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn verify_leaf_device_key_binding(
        &self,
        conversation_id: Option<&str>,
        operation: &str,
        context: &str,
        root_did: &str,
        claimed_identity: &str,
        leaf_signature_key: &[u8],
        kp_hash_prefix: &str,
    ) -> super::error::Result<()> {
        match self
            .lookup_candidate_device_key(root_did, leaf_signature_key)
            .await
        {
            Ok(DeviceKeyLookup::Unsupported) => {
                let reason = "authorized-device-key resolution is required but unsupported";
                Err(self
                    .emit_credential_binding_rejection(
                        conversation_id,
                        operation,
                        context,
                        root_did,
                        claimed_identity,
                        kp_hash_prefix,
                        reason,
                    )
                    .await)
            }
            Ok(DeviceKeyLookup::Keys(keys)) => {
                if keys.iter().any(|k| k.as_slice() == leaf_signature_key) {
                    tracing::debug!(
                        root_did,
                        context,
                        "leaf signature key verified against authorized device keys"
                    );
                    Ok(())
                } else {
                    let key_hash_prefix = sha256_prefix(leaf_signature_key);
                    let reason = format!(
                        "leaf signature key (sha256 prefix {key_hash_prefix}) is not an \
                         authorized device key for `{root_did}` ({} authorized key(s) resolved)",
                        keys.len()
                    );
                    Err(self
                        .emit_credential_binding_rejection(
                            conversation_id,
                            operation,
                            context,
                            root_did,
                            claimed_identity,
                            kp_hash_prefix,
                            &reason,
                        )
                        .await)
                }
            }
            Err(e) => {
                let reason = format!("authorized-device-key resolution failed: {e}");
                Err(self
                    .emit_credential_binding_rejection(
                        conversation_id,
                        operation,
                        context,
                        root_did,
                        claimed_identity,
                        kp_hash_prefix,
                        &reason,
                    )
                    .await)
            }
        }
    }

    /// ADR-009 D4 (verify inbound), enforced before commit merge/application
    /// delivery.
    ///
    /// Cross-checks the MLS sender credential extracted from a decrypted
    /// message/commit against the envelope's claimed sender DID. The envelope
    /// `senderDid` is a routing hint, not proof — a mismatch means either the
    /// DS mislabeled the envelope or the leaf credential does not belong to
    /// the claimed sender. A mismatch is returned to the caller so the frame
    /// is not applied under a false application identity.
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
    ///
    /// Stage-2 scope note: the device-key half of the ADR-009 proof
    /// (`verify_leaf_device_key_binding`) cannot run here either —
    /// `CredentialData` carries the identity but not the sender's leaf
    /// signature public key, and extending that UniFFI record is out of
    /// scope for this stage (backlog N44d). Inbound therefore enforces the
    /// available DID-root binding. OpenMLS separately authenticates the MLS
    /// frame; this check does not replace that cryptographic validation.
    pub(crate) async fn verify_inbound_sender_credential(
        &self,
        conversation_id: &str,
        envelope_sender_did: &str,
        credential_identity: &[u8],
    ) -> super::error::Result<()> {
        if envelope_sender_did.is_empty() {
            return Err(self
                .emit_credential_binding_rejection(
                    Some(conversation_id),
                    "message",
                    "process_incoming",
                    "<unknown>",
                    "<non-utf8>",
                    "",
                    "envelope carries no sender DID, so application credential binding is unavailable",
                )
                .await);
        }

        let claimed_identity = match String::from_utf8(credential_identity.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                return Err(self
                    .emit_credential_binding_rejection(
                        Some(conversation_id),
                        "message",
                        "process_incoming",
                        envelope_sender_did,
                        "<non-utf8>",
                        "",
                        "sender credential identity is not UTF-8",
                    )
                    .await);
            }
        };

        match self
            .credentials()
            .verify_member_credential(envelope_sender_did, &claimed_identity)
            .await
        {
            Ok(CredentialVerification::Verified) => Ok(()),
            Ok(CredentialVerification::DidMismatch {
                expected_did,
                claimed_identity,
                claimed_root_did,
            }) => {
                let reason = format!(
                    "MLS sender credential root `{claimed_root_did}` does not match envelope sender DID `{expected_did}`"
                );
                Err(self
                    .emit_credential_binding_rejection(
                        Some(conversation_id),
                        "message",
                        "process_incoming",
                        &expected_did,
                        &claimed_identity,
                        "",
                        &reason,
                    )
                    .await)
            }
            Ok(CredentialVerification::Unverifiable { reason }) => Err(self
                .emit_credential_binding_rejection(
                    Some(conversation_id),
                    "message",
                    "process_incoming",
                    envelope_sender_did,
                    &claimed_identity,
                    "",
                    &reason,
                )
                .await),
            Err(e) => {
                let reason = format!("credential verifier error: {e}");
                Err(self
                    .emit_credential_binding_rejection(
                        Some(conversation_id),
                        "message",
                        "process_incoming",
                        envelope_sender_did,
                        &claimed_identity,
                        "",
                        &reason,
                    )
                    .await)
            }
        }
    }

    /// Single enforcing chokepoint for credential-binding failures (ADR-009
    /// D5). It emits platform-visible telemetry, then constructs the error the
    /// caller must propagate before any state-changing MLS operation.
    #[allow(clippy::too_many_arguments)]
    async fn emit_credential_binding_rejection(
        &self,
        conversation_id: Option<&str>,
        operation: &str,
        context: &str,
        expected_did: &str,
        claimed_identity: &str,
        kp_hash_prefix: &str,
        reason: &str,
    ) -> super::error::OrchestratorError {
        let convo = conversation_id.unwrap_or("<none>");
        let claimed_root = credential_root_did(claimed_identity);
        crate::error_log!(
            "[CREDENTIAL-BINDING] mode=enforce operation={} context={} conversation={} expected_did={} claimed_identity={} claimed_root_did={} kp_hash_prefix={} path=rust-orchestrator reason={}",
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
            "credential binding check rejected the operation"
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
        super::error::OrchestratorError::InvalidInput(format!(
            "application DID/device credential binding rejected during {context}: {reason}"
        ))
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

    fn key_package_ref(did: &str, byte_len: usize) -> KeyPackageRef {
        KeyPackageRef {
            did: did.to_string(),
            key_package_data: vec![0xA5; byte_len],
            hash: None,
            cipher_suite: "test".to_string(),
        }
    }

    fn key_package_bundle(identity: &str) -> openmls::prelude::KeyPackageBundle {
        use openmls::prelude::*;
        use openmls_basic_credential::SignatureKeyPair;
        use openmls_rust_crypto::OpenMlsRustCrypto;

        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let credential = BasicCredential::new(identity.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        KeyPackage::builder()
            .build(ciphersuite, &provider, &signer, credential_with_key)
            .unwrap()
    }

    fn serialized_key_package(identity: &str) -> crate::KeyPackageData {
        use openmls::prelude::tls_codec::Serialize as _;

        let bundle = key_package_bundle(identity);
        crate::KeyPackageData {
            data: bundle
                .key_package()
                .tls_serialize_detached()
                .expect("serialize key package"),
        }
    }

    fn serialized_wrapped_key_package(identity: &str) -> crate::KeyPackageData {
        use openmls::prelude::{tls_codec::Serialize as _, MlsMessageOut};

        crate::KeyPackageData {
            data: MlsMessageOut::from(key_package_bundle(identity))
                .tls_serialize_detached()
                .expect("serialize wrapped key package"),
        }
    }

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
    fn claim_check_does_not_fold_method_specific_identifier_case() {
        assert!(matches!(
            check_identity_claim("did:method:Value", "did:method:value"),
            CredentialVerification::DidMismatch { .. }
        ));
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

    #[test]
    fn fetched_batch_rejects_missing_or_appended_packages_before_parsing() {
        let requested = vec!["did:plc:alice".to_string()];
        let missing = Vec::new();
        let appended = vec![
            key_package_ref("did:plc:alice", 1),
            key_package_ref("did:plc:mallory", 1),
        ];

        let missing_error = validate_fetched_key_package_batch(&requested, &missing)
            .expect_err("missing package must fail exact cardinality");
        let appended_error = validate_fetched_key_package_batch(&requested, &appended)
            .expect_err("appended package must fail exact cardinality");
        assert!(missing_error.to_string().contains("returned 0"));
        assert!(appended_error.to_string().contains("returned 2"));
    }

    #[test]
    fn fetched_batch_rejects_duplicate_labels_with_exact_count() {
        let requested = vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()];
        let duplicated = vec![
            key_package_ref("did:plc:alice", 1),
            key_package_ref("did:plc:alice", 1),
        ];

        let error = validate_fetched_key_package_batch(&requested, &duplicated)
            .expect_err("duplicate label must not substitute for a missing DID");
        assert!(error.to_string().contains("do not exactly match"));
    }

    #[test]
    fn fetched_batch_rejects_oversized_element_before_tls_decode() {
        let requested = vec!["did:plc:alice".to_string()];
        let oversized = vec![key_package_ref(
            "did:plc:alice",
            MAX_FETCHED_KEY_PACKAGE_BYTES + 1,
        )];

        let error = validate_fetched_key_package_batch(&requested, &oversized)
            .expect_err("oversized invalid bytes must fail at the size gate");
        assert!(error.to_string().contains("exceeding"));
    }

    #[test]
    fn fetched_batch_rejects_oversized_aggregate() {
        let count = (MAX_FETCHED_KEY_PACKAGE_BATCH_BYTES / MAX_FETCHED_KEY_PACKAGE_BYTES) + 1;
        let requested: Vec<String> = (0..count)
            .map(|index| format!("did:plc:user{index}"))
            .collect();
        let packages: Vec<KeyPackageRef> = requested
            .iter()
            .map(|did| key_package_ref(did, MAX_FETCHED_KEY_PACKAGE_BYTES))
            .collect();

        let error = validate_fetched_key_package_batch(&requested, &packages)
            .expect_err("aggregate bytes must be bounded before parsing");
        assert!(error.to_string().contains("batch"));
        assert!(error.to_string().contains("exceeding"));
    }

    #[test]
    fn outbound_binding_accepts_raw_and_mls_message_wrapped_key_packages() {
        for package in [
            serialized_key_package("did:plc:alice#device-1"),
            serialized_wrapped_key_package("did:plc:alice#device-1"),
        ] {
            enforce_outbound_key_package_did_bindings(&["did:plc:alice".to_string()], &[package])
                .expect("both supported KeyPackage encodings must bind identically");
        }
    }

    #[test]
    fn outbound_binding_rejects_trailing_bytes_for_both_encodings() {
        for mut package in [
            serialized_key_package("did:plc:alice#device-1"),
            serialized_wrapped_key_package("did:plc:alice#device-1"),
        ] {
            package.data.extend_from_slice(&[0xde, 0xad]);
            enforce_outbound_key_package_did_bindings(&["did:plc:alice".to_string()], &[package])
                .expect_err("trailing bytes must not be ignored");
        }
    }

    #[test]
    fn outbound_binding_rejects_matching_non_did_authority() {
        let error = enforce_outbound_key_package_did_bindings(
            &["alice".to_string()],
            &[serialized_key_package("alice")],
        )
        .expect_err("matching arbitrary strings are not DID authority");
        assert!(matches!(
            error,
            super::super::error::OrchestratorError::InvalidInput(_)
        ));
        assert!(error.to_string().contains("DID"));
    }

    #[test]
    fn outbound_binding_does_not_globally_fold_method_specific_id_case() {
        use catbird_atproto::types::string::Did;

        assert!(Did::new("did:method:Value").is_ok());
        assert!(Did::new("did:method:value").is_ok());
        assert!(Did::new("did:METHOD:value").is_err());

        let error = enforce_outbound_key_package_did_bindings(
            &["did:method:Value".to_string()],
            &[serialized_key_package("did:method:value")],
        )
        .expect_err("method-specific identifier case cannot be globally normalized");
        assert!(matches!(
            error,
            super::super::error::OrchestratorError::InvalidInput(_)
        ));
    }

    /// Round-trip: build a real OpenMLS key package with a DID-rooted
    /// identity and confirm the structural extractor recovers it.
    #[test]
    fn extract_identity_round_trip() {
        let identity = "did:plc:alice#device-1";

        let kp_bytes = serialized_key_package(identity).data;

        let extracted = extract_key_package_identity(&kp_bytes).expect("extract identity");
        assert_eq!(extracted, identity);
        assert_eq!(
            check_identity_claim("did:plc:alice", &extracted),
            CredentialVerification::Verified
        );
    }
}
