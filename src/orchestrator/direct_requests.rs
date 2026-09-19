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
    Decrypted { text: String },
    Unavailable { code: RequestPreviewFailure },
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
        RequestPreviewUpdate::Decrypted { text } => {
            next.crypto = RequestCrypto::Ready;
            next.preview = Some(RequestPreview::Ready { text });
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
            projection::DirectRequestProjection::decode(&raw, owner, &device)?;
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
        if !self.mls_context().supports_direct_request_bootstrap() {
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
