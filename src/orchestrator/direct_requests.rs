//! Direct-request orchestration primitives shared by every client.
//!
//! A public view is a projection. Only verified signed controls may change
//! account consent; imports and decryptions change exact-device crypto state.
#[path = "direct_request_commands.rs"]
mod commands;
#[path = "direct_request_intent.rs"]
mod intent;
#[path = "direct_request_projection.rs"]
mod projection;
#[path = "direct_request_receive.rs"]
mod receive;
pub use intent::DirectRequestIntent;

use super::direct_request_types::*;
use super::{OrchestratorError, Result};

pub fn validate_direct_request_input(input: &DirectRequestInput) -> Result<()> {
    use crate::chat_v2::ids::{BareDid, CanonicalUuid};
    let invalid = || OrchestratorError::InvalidInput("Invalid direct request input".into());
    CanonicalUuid::parse(&input.draft_id).map_err(|_| invalid())?;
    BareDid::parse(&input.recipient_did).map_err(|_| invalid())?;
    if input.text.trim().is_empty()
        || input.text.len()
            > crate::chat_v2::transcript::direct_request::MAX_REQUEST_TEXT_UTF8_BYTES
    {
        return Err(invalid());
    }
    if let Some(invitation) = &input.invitation {
        for did in [
            &invitation.authority_did,
            &invitation.invited_by_did,
            &invitation.recipient_did,
        ] {
            BareDid::parse(did).map_err(|_| invalid())?;
        }
        for id in [
            &invitation.conversation_id,
            &invitation.invitation_transition_id,
            &invitation.invited_by_device_id,
        ] {
            CanonicalUuid::parse(id).map_err(|_| invalid())?;
        }
        if invitation.recipient_did != input.recipient_did {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Crypto-only update. Deliberately has no consent field and cannot authorize
/// an account action. The persisted imported Welcome remains valid even when
/// the separately authenticated introduction fails decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestPreviewUpdate {
    BeginImport,
    Imported,
    Decrypted {
        text: String,
        invitation: Option<GroupInvitationReference>,
    },
    Unavailable {
        code: RequestPreviewFailure,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestPreviewFailure {
    ImportExpired,
    DeviceNotAddressed,
    InvalidIntroduction,
    InvalidApplicationBinding,
}
impl RequestPreviewFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::ImportExpired => "ImportExpired",
            Self::DeviceNotAddressed => "DeviceNotAddressed",
            Self::InvalidIntroduction => "InvalidIntroduction",
            Self::InvalidApplicationBinding => "InvalidApplicationBinding",
        }
    }
}

/// This reducer runs only after the caller verifies the envelope/AAD and
/// durably records its import/decrypt result. It never dispatches a message
/// insertion, read receipt, bot forwarding, or any other ordinary effect.
pub fn reduce_request_preview(
    view: &DirectRequestView,
    update: RequestPreviewUpdate,
) -> DirectRequestView {
    let mut next = view.clone();
    match update {
        RequestPreviewUpdate::BeginImport => {
            if next.crypto != RequestCrypto::Ready {
                next.crypto = RequestCrypto::Importing;
            }
        }
        RequestPreviewUpdate::Imported => next.crypto = RequestCrypto::Ready,
        RequestPreviewUpdate::Decrypted { text, invitation } => {
            next.crypto = RequestCrypto::Ready;
            next.preview = Some(RequestPreview::Ready { text, invitation });
        }
        RequestPreviewUpdate::Unavailable { code } => {
            // Never discard a previously authenticated preview merely because
            // another delivery expired or a retry observed malformed bytes.
            if !matches!(next.preview, Some(RequestPreview::Ready { .. })) {
                next.preview = Some(RequestPreview::Unavailable {
                    code: code.code().into(),
                });
            }
            if next.crypto != RequestCrypto::Ready {
                next.crypto = RequestCrypto::Unavailable;
            }
        }
    }
    next.capabilities = RequestCapabilities::derive(
        next.consent,
        next.crypto,
        matches!(next.preview, Some(RequestPreview::Ready { .. })),
    );
    next
}

use super::{CredentialStore, MLSAPIClient, MLSOrchestrator, MLSStorageBackend, MlsCryptoContext};
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Offline startup fence. Network resolution must be scheduled after Ready,
    /// so an unreachable request cannot stall independent conversations.
    pub(crate) async fn hydrate_direct_request_ownership(&self, owner: &str) -> Result<()> {
        if !self.mls_context().supports_direct_request_bootstrap() {
            return Ok(());
        }
        let intents = self.mls_context().list_direct_request_intents()?;
        let journals = self.mls_context().list_direct_request_journal()?;
        if intents.is_empty()
            && journals.is_empty()
            && self
                .mls_context()
                .list_direct_request_projections()?
                .is_empty()
        {
            return Ok(());
        }
        let device = self
            .credentials()
            .get_device_uuid(owner)
            .await?
            .ok_or_else(|| {
                OrchestratorError::Credential("Request journal has no device owner".into())
            })?;
        let mut attempts = std::collections::HashMap::new();
        let mut drafts = std::collections::HashSet::new();
        for raw in intents {
            let intent = DirectRequestIntent::decode(&raw, owner, &device)?;
            if !drafts.insert(intent.input.draft_id.clone())
                || attempts.insert(intent.request_id()?, intent).is_some()
            {
                return Err(OrchestratorError::Storage(
                    "Duplicate direct request ownership".into(),
                ));
            }
        }
        for raw in self.mls_context().list_direct_request_projections()? {
            let projection = projection::DirectRequestProjection::decode(&raw, owner, &device)?;
            if let Some(pending) = &projection.pending_acceptance {
                let public = self
                    .mls_context()
                    .identity_public_key(format!("{owner}#{device}").into_bytes())?;
                let accepted = crate::chat_v2::transcript::direct_request::verify_signed_request(
                    crate::chat_v2::transcript::direct_request::DirectRequestKind::Accept,
                    pending,
                    &public,
                )
                .map_err(|_| {
                    OrchestratorError::Storage(
                        "Invalid pending request acceptance signature".into(),
                    )
                })?;
                let publication: serde_json::Value =
                    serde_json::from_slice(&projection.publication)
                        .map_err(|_| OrchestratorError::Storage("Invalid publication".into()))?;
                if accepted.actor_did() != Some(owner)
                    || accepted.actor_device_id() != Some(device.as_str())
                    || accepted.body()["requestId"] != publication["body"]["requestId"]
                    || accepted.body()["prior"] != publication["body"]["next"]
                {
                    return Err(OrchestratorError::Storage(
                        "Invalid pending acceptance binding".into(),
                    ));
                }
            }
        }
        for journal in journals {
            journal.validate()?;
            if journal.actor_did != owner || journal.actor_device_id != device {
                return Err(OrchestratorError::Storage(
                    "Direct request bootstrap owner mismatch".into(),
                ));
            }
            // A terminal bootstrap tombstone can outlive its replaced draft.
            // Every live candidate must still have its pre-reservation intent.
            if journal.phase
                != super::direct_request_journal::DirectRequestJournalPhase::TerminalNotPublished
            {
                let intent = attempts.get(&journal.request_id).ok_or_else(|| {
                    OrchestratorError::Storage("Live request bootstrap lacks intent fence".into())
                })?;
                if journal.draft_id != intent.input.draft_id {
                    return Err(OrchestratorError::Storage(
                        "Request draft binding mismatch".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(crate) async fn retained_direct_request_view(
        &self,
        conversation_id: &str,
    ) -> Result<Option<DirectRequestView>> {
        if !self.mls_context().supports_direct_request_bootstrap()
            || crate::chat_v2::ids::CanonicalUuid::parse(conversation_id).is_err()
        {
            return Ok(None);
        }
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        self.mls_context()
            .read_direct_request_projection(conversation_id)?
            .map(|raw| {
                let projection =
                    projection::DirectRequestProjection::decode(&raw, &owner, &device)?;
                let view = projection.view(&owner, &device)?;
                if view.conversation_id != conversation_id {
                    return Err(OrchestratorError::Storage(
                        "Request projection conversation mismatch".into(),
                    ));
                }
                Ok(view)
            })
            .transpose()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Called after ordinary startup/sync work, never from initialization.
    /// Each turn has at most two requests and each network future two seconds.
    /// Timeout drops only the transport future; exact intent bytes stay fenced.
    pub(crate) async fn reconcile_direct_request_outcomes(&self) {
        if !self.mls_context().supports_direct_request_bootstrap() {
            return;
        }
        let Ok(records) = self.mls_context().list_direct_request_intents() else {
            return;
        };
        let mut considered = 0;
        for raw in records {
            let Ok(intent) = serde_json::from_slice::<DirectRequestIntent>(&raw) else {
                continue;
            };
            if intent.projection_completed
                || (intent.terminal_response.is_some()
                    && intent::DirectRequestTerminalAttempt::from_intent(&intent).is_ok())
            {
                continue;
            }
            let id = intent.input.draft_id;
            let now = web_time::Instant::now();
            let attempts = {
                let mut backoff = self.direct_request_reconcile_backoff.lock().await;
                if backoff
                    .get(&id)
                    .is_some_and(|(_, deadline)| *deadline > now)
                {
                    continue;
                }
                let attempts = backoff
                    .get(&id)
                    .map(|(n, _)| n.saturating_add(1))
                    .unwrap_or(1);
                let delay =
                    std::time::Duration::from_secs(2u64.saturating_pow(attempts.min(6)).min(60));
                backoff.insert(id.clone(), (attempts, now + delay));
                attempts
            };
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                Box::pin(self.resume_direct_request(&id)),
            )
            .await
            {
                Ok(Ok(
                    super::DirectRequestOutcome::RequestSent { .. }
                    | super::DirectRequestOutcome::TerminalNotPublished { .. }
                    | super::DirectRequestOutcome::ExistingDirect { .. },
                )) => {
                    self.direct_request_reconcile_backoff
                        .lock()
                        .await
                        .remove(&id);
                }
                Ok(Err(error)) => {
                    tracing::warn!(draft_id=id,attempts,%error,"Request reconciliation deferred; immutable attempt retained")
                }
                _ => {}
            }
            considered += 1;
            if considered >= 2 {
                break;
            }
        }
    }
}
