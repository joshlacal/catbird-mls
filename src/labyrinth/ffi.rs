//! UniFFI surface for Labyrinth history backup (feature `labyrinth`).
//!
//! Declared as a child module of `orchestrator_bridge` so it can reach the
//! bridge's inner orchestrator. The platform side is
//! `OrchestratorAPICallback::submit_labyrinth_request` (every Labyrinth
//! XRPC) and the `*_labyrinth_mailbox_keys` methods (the PDS directory).
//! Those callback methods are in every build's FFI surface (UniFFI cannot
//! gate a callback method), with refusing defaults. Bindings are NOT
//! regenerated in this change: run the `ffi-propagate` workflow before any
//! platform build picks up this revision.

use super::{OrchestratorBridge, OrchestratorBridgeError};
use crate::labyrinth::{ArchiveStatusReport, HistoryPage, ImportReport};
use labyrinth::client::MessageSource;

/// One decrypted history message.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthMessage {
    pub message_id: String,
    /// Absent for owner-archive copies, which carry no sender.
    pub sender_did: Option<String>,
    pub timestamp_ms: u64,
    /// The archived frame: the sent `MLSMessagePayload` JSON.
    pub frame: Vec<u8>,
    /// True for a copy from this account's own re-archive.
    pub from_owner_archive: bool,
    /// Another copy shares this message id ([CB-31]); show both.
    pub conflict: bool,
}

/// How a redacted history message must be labelled.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FfiLabyrinthRedactionLabel {
    /// Signed by one of the author's chat devices: "unsent".
    Unsent,
    /// Signed by the conversation's sequencer DS: "deleted (account
    /// removed)".
    AccountDeleted,
    /// Nothing proves why: "removed by server".
    RemovedByServer,
}

/// One redacted history message.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthRedacted {
    pub message_id: String,
    pub sender_did: String,
    pub timestamp_ms: u64,
    pub label: FfiLabyrinthRedactionLabel,
}

/// One page of decrypted history.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthHistory {
    pub messages: Vec<FfiLabyrinthMessage>,
    pub undecryptable_count: u64,
    pub space_readable: bool,
    pub redacted: Vec<FfiLabyrinthRedacted>,
}

/// What account deletion did.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthDeletion {
    /// Publishers that could not retract their records.
    pub publishers_not_retracted: u64,
    /// The remote half failed with this error and is retried in the
    /// background; this device's state is erased regardless.
    pub remote_pending: Option<String>,
}

/// A queued message the archive skips until retried.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthQuarantined {
    pub conversation_id: String,
    pub message_id: String,
    pub failures: u32,
    pub last_error: Option<String>,
}

/// A member left out of a conversation's archive (it cannot read the
/// messages archived meanwhile).
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthExcludedMember {
    pub conversation_id: String,
    pub did: String,
    pub reason: String,
    /// A pin conflict: offer `labyrinth_propose_repin(did)`.
    pub needs_repin: bool,
    pub at_ms: u64,
}

/// A queued message dropped unarchived.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthDropped {
    pub conversation_id: String,
    pub message_id: String,
    pub reason: String,
    pub at_ms: u64,
}

/// What background Labyrinth work could not do.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthArchiveStatus {
    pub pending: u64,
    pub quarantined: Vec<FfiLabyrinthQuarantined>,
    pub excluded_members: Vec<FfiLabyrinthExcludedMember>,
    pub dropped: Vec<FfiLabyrinthDropped>,
    /// The last error of an account deletion whose remote half is pending.
    pub remote_deletion_pending: Option<String>,
}

/// A safety-number change to confirm before re-pinning a peer.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthRepinProposal {
    pub did: String,
    pub pinned_epoch: Option<u64>,
    pub old_safety_number: Option<String>,
    pub new_epoch: u64,
    /// Pass back to `labyrinth_repin_peer` once the user accepts.
    pub new_head_hex: String,
    pub new_safety_number: String,
}

/// The conversations this account has history in.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthThreads {
    pub conversation_ids: Vec<String>,
    /// Sequencer DSes mls-ds could not reach: the list may miss their
    /// conversations.
    pub incomplete_sequencers: Vec<String>,
}

fn status_to_ffi(r: ArchiveStatusReport) -> FfiLabyrinthArchiveStatus {
    FfiLabyrinthArchiveStatus {
        pending: r.pending as u64,
        quarantined: r
            .quarantined
            .into_iter()
            .map(|q| FfiLabyrinthQuarantined {
                conversation_id: q.conversation_id,
                message_id: q.message_id,
                failures: q.failures,
                last_error: q.last_error,
            })
            .collect(),
        excluded_members: r
            .status
            .excluded_members
            .into_iter()
            .map(|x| FfiLabyrinthExcludedMember {
                conversation_id: x.conversation_id,
                did: x.did,
                reason: x.reason,
                needs_repin: x.needs_repin,
                at_ms: x.at_ms,
            })
            .collect(),
        dropped: r
            .status
            .dropped
            .into_iter()
            .map(|d| FfiLabyrinthDropped {
                conversation_id: d.conversation_id,
                message_id: d.message_id,
                reason: d.reason,
                at_ms: d.at_ms,
            })
            .collect(),
        remote_deletion_pending: r.status.pending_remote_deletion.map(|p| p.last_error),
    }
}

/// What importing a conversation's history stored.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthImport {
    pub imported: u64,
    pub already_present: u64,
    pub skipped: u64,
    pub undecryptable: u64,
}

fn history_to_ffi(page: HistoryPage) -> FfiLabyrinthHistory {
    FfiLabyrinthHistory {
        undecryptable_count: page.undecryptable as u64,
        space_readable: page.space_readable,
        redacted: page
            .redacted
            .into_iter()
            .map(|r| FfiLabyrinthRedacted {
                label: if r.by_author {
                    FfiLabyrinthRedactionLabel::Unsent
                } else if r.account_deleted {
                    FfiLabyrinthRedactionLabel::AccountDeleted
                } else {
                    FfiLabyrinthRedactionLabel::RemovedByServer
                },
                message_id: r.message_id,
                sender_did: r.sender,
                timestamp_ms: r.timestamp,
            })
            .collect(),
        messages: page
            .messages
            .into_iter()
            .map(|m| FfiLabyrinthMessage {
                message_id: m.message_id,
                sender_did: m.sender,
                timestamp_ms: m.timestamp,
                frame: m.frame,
                from_owner_archive: m.source == MessageSource::Owner,
                conflict: m.conflict,
            })
            .collect(),
    }
}

fn import_to_ffi(r: ImportReport) -> FfiLabyrinthImport {
    FfiLabyrinthImport {
        imported: r.imported as u64,
        already_present: r.already_present as u64,
        skipped: (r.skipped_conflicts + r.skipped_unattributed + r.skipped_undecodable) as u64,
        undecryptable: r.undecryptable as u64,
    }
}

#[uniffi::export]
impl OrchestratorBridge {
    /// Turn on encrypted history backup for the signed-in account on this
    /// device. Returns this device's Labyrinth device key (hex).
    pub fn labyrinth_enable_backup(&self) -> Result<String, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_enable(),
        )?)
    }

    /// Create a recovery code. Show it to the user once; it is not stored.
    pub fn labyrinth_create_recovery_code(&self) -> Result<String, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_create_recovery_code(),
        )?)
    }

    /// Enroll this device into the account's backup with a recovery code.
    /// Returns this device's Labyrinth device key (hex).
    pub fn labyrinth_restore_with_recovery_code(
        &self,
        code: String,
    ) -> Result<String, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_restore_with_recovery_code(&code),
        )?)
    }

    /// Decrypted history of a conversation in `[from_ms, until_ms)`.
    pub fn labyrinth_load_history_page(
        &self,
        conversation_id: String,
        from_ms: Option<u64>,
        until_ms: Option<u64>,
    ) -> Result<FfiLabyrinthHistory, OrchestratorBridgeError> {
        let page = crate::async_runtime::block_on(self.inner.labyrinth_load_history(
            &conversation_id,
            from_ms,
            until_ms,
        ))?;
        Ok(history_to_ffi(page))
    }

    /// Store a conversation's archived history locally (new device).
    pub fn labyrinth_import_history(
        &self,
        conversation_id: String,
    ) -> Result<FfiLabyrinthImport, OrchestratorBridgeError> {
        let report =
            crate::async_runtime::block_on(self.inner.labyrinth_import_history(&conversation_id))?;
        Ok(import_to_ffi(report))
    }

    /// Archive every queued sent message now. Call it when the app is about
    /// to suspend and at launch (a killed process leaves its queue saved).
    /// Returns how many messages were archived.
    pub fn labyrinth_flush_archive(&self) -> Result<u64, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(self.inner.labyrinth_flush_archive())? as u64)
    }

    /// Sign-out or account removal on this device: erase this device's
    /// backup state and queue. The account's backup on the server stays, so
    /// a later sign-in restores with a recovery code. Returns whether any
    /// state was saved.
    pub fn labyrinth_sign_out(&self) -> Result<bool, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_sign_out(),
        )?)
    }

    /// Delete the account's history backup everywhere: the server mailbox
    /// and every message the account archived (shown to others as removed),
    /// the PDS `mailboxKeys` records, and this device's state. This
    /// device's state is erased even if the server cannot be reached; the
    /// remote half is then retried (`remote_pending`).
    pub fn labyrinth_delete_account(
        &self,
    ) -> Result<FfiLabyrinthDeletion, OrchestratorBridgeError> {
        let report = crate::async_runtime::block_on(self.inner.labyrinth_delete_account())?;
        Ok(FfiLabyrinthDeletion {
            publishers_not_retracted: report.publishers_not_retracted as u64,
            remote_pending: report.remote_pending.map(|e| e.to_string()),
        })
    }

    /// Retry a pending remote account deletion now. Returns true when
    /// nothing is pending any more.
    pub fn labyrinth_retry_remote_deletion(&self) -> Result<bool, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_retry_remote_deletion(),
        )?)
    }

    /// What background archiving and deletion could not do (show it):
    /// quarantined messages, members left out of a conversation's archive
    /// (with pin conflicts to resolve), dropped messages, and a pending
    /// remote deletion.
    pub fn labyrinth_archive_status(
        &self,
    ) -> Result<FfiLabyrinthArchiveStatus, OrchestratorBridgeError> {
        Ok(status_to_ffi(crate::async_runtime::block_on(
            self.inner.labyrinth_archive_status(),
        )?))
    }

    /// Retry every quarantined message now. Returns how many there were.
    pub fn labyrinth_retry_quarantined(&self) -> Result<u64, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(self.inner.labyrinth_retry_quarantined())? as u64)
    }

    /// Forget the recorded exclusions and dropped messages (the user saw them).
    pub fn labyrinth_clear_archive_reports(&self) -> Result<(), OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_clear_archive_reports(),
        )?)
    }

    /// A contact's history keys changed (they reset their backup): the
    /// safety-number change to show, like Signal. Fails if the new keys are
    /// not vouched for by one of the contact's current chat devices.
    pub fn labyrinth_propose_repin(
        &self,
        did: String,
    ) -> Result<FfiLabyrinthRepinProposal, OrchestratorBridgeError> {
        let p = crate::async_runtime::block_on(self.inner.labyrinth_propose_repin(&did))?;
        Ok(FfiLabyrinthRepinProposal {
            did: p.did,
            pinned_epoch: p.pinned_seq,
            old_safety_number: p.old_safety_number,
            new_epoch: p.offered_seq,
            new_head_hex: hex::encode(p.offered_head),
            new_safety_number: p.new_safety_number,
        })
    }

    /// The user accepted the new safety number: trust the contact's new
    /// history keys (`new_head_hex` from the proposal).
    pub fn labyrinth_repin_peer(
        &self,
        did: String,
        new_head_hex: String,
    ) -> Result<(), OrchestratorBridgeError> {
        let head: [u8; 32] = hex::decode(&new_head_hex)
            .ok()
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| OrchestratorBridgeError::InvalidInput {
                message: "labyrinth: head must be 32 hex bytes".into(),
            })?;
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_repin_peer(&did, head),
        )?)
    }

    /// The conversations this account has backed-up history in. A
    /// non-empty `incomplete_sequencers` means the list is partial.
    pub fn labyrinth_list_threads(&self) -> Result<FfiLabyrinthThreads, OrchestratorBridgeError> {
        let l = crate::async_runtime::block_on(self.inner.labyrinth_list_threads())?;
        Ok(FfiLabyrinthThreads {
            conversation_ids: l.threads.into_iter().map(|t| t.thread_id).collect(),
            incomplete_sequencers: l.incomplete,
        })
    }

    /// Revoke another device of this account from the backup.
    pub fn labyrinth_revoke_device(
        &self,
        device_key_hex: String,
    ) -> Result<u64, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_revoke_device(&device_key_hex),
        )?)
    }
}

#[cfg(test)]
mod forwarding_tests {
    //! `APIAdapter` forwards the Labyrinth gateway seam to the UniFFI
    //! `OrchestratorAPICallback` unchanged, and the defaults refuse.

    use std::sync::{Arc, Mutex};

    use super::super::*;
    use crate::labyrinth::LabyrinthRequest;
    use crate::orchestrator::api_client::MLSAPIClient;

    type Seen = (
        String,
        String,
        String,
        Option<Vec<u8>>,
        Vec<FFILabyrinthHeader>,
    );

    #[derive(Default)]
    struct Platform {
        seen: Mutex<Vec<Seen>>,
        pds: Mutex<Vec<(String, Vec<u8>)>>,
        implements: bool,
    }

    fn unused<T>() -> Result<T, OrchestratorBridgeError> {
        Err(OrchestratorBridgeError::Api {
            message: "unused".into(),
        })
    }

    impl OrchestratorAPICallback for Platform {
        fn is_authenticated_as(&self, _: String) -> bool {
            true
        }
        fn current_did(&self) -> Option<String> {
            None
        }
        fn submit_prepared_request(
            &self,
            _: String,
            _: String,
            _: Option<Vec<u8>>,
            _: Option<Vec<u8>>,
        ) -> Result<FFIGatewayResponse, OrchestratorBridgeError> {
            unused()
        }
        fn get_conversations(
            &self,
            _: u32,
            _: Option<String>,
        ) -> Result<FFIConversationListPage, OrchestratorBridgeError> {
            unused()
        }
        fn get_messages(
            &self,
            _: String,
            _: Option<String>,
            _: u32,
            _: Option<String>,
            _: Option<u32>,
            _: Option<u32>,
        ) -> Result<FFIMessagesPage, OrchestratorBridgeError> {
            unused()
        }
        fn get_key_packages(
            &self,
            _: String,
            _: Vec<String>,
        ) -> Result<Vec<FFIKeyPackageRef>, OrchestratorBridgeError> {
            unused()
        }
        fn get_key_package_stats(&self) -> Result<FFIKeyPackageStats, OrchestratorBridgeError> {
            unused()
        }
        fn sync_key_packages(
            &self,
            _: Vec<String>,
            _: String,
        ) -> Result<FFIKeyPackageSyncResult, OrchestratorBridgeError> {
            unused()
        }
        fn list_devices(&self, _: String) -> Result<Vec<FFIDeviceInfo>, OrchestratorBridgeError> {
            unused()
        }
        fn get_group_info(&self, _: String) -> Result<Vec<u8>, OrchestratorBridgeError> {
            unused()
        }
        fn get_welcome(&self, _: String) -> Result<Vec<u8>, OrchestratorBridgeError> {
            unused()
        }
        fn get_delivery_status(
            &self,
            _: String,
            _: Vec<String>,
        ) -> Result<Vec<FFIDeliveryStatusPair>, OrchestratorBridgeError> {
            unused()
        }
        fn get_group_metadata_blob(
            &self,
            _: String,
            _: String,
            _: String,
        ) -> Result<Vec<u8>, OrchestratorBridgeError> {
            unused()
        }
        fn submit_labyrinth_request(
            &self,
            method: String,
            nsid: String,
            path: String,
            body: Option<Vec<u8>>,
            headers: Vec<FFILabyrinthHeader>,
        ) -> Result<FFIGatewayResponse, OrchestratorBridgeError> {
            if !self.implements {
                return unused();
            }
            self.seen
                .lock()
                .unwrap()
                .push((method, nsid, path, body, headers));
            Ok(FFIGatewayResponse {
                status: 409,
                content_type: Some("application/json".into()),
                body: br#"{"error":"RecordAlreadyExists"}"#.to_vec(),
            })
        }
        fn labyrinth_pds_enabled(&self) -> bool {
            self.implements
        }
        fn put_labyrinth_mailbox_keys(
            &self,
            rkey: String,
            record: Vec<u8>,
        ) -> Result<(), OrchestratorBridgeError> {
            self.pds.lock().unwrap().push((rkey, record));
            Ok(())
        }
        fn get_labyrinth_mailbox_keys(
            &self,
            _did: String,
            rkey: String,
        ) -> Result<Option<Vec<u8>>, OrchestratorBridgeError> {
            Ok(self
                .pds
                .lock()
                .unwrap()
                .iter()
                .find(|(k, _)| *k == rkey)
                .map(|(_, v)| v.clone()))
        }
    }

    #[tokio::test]
    async fn the_adapter_forwards_labyrinth_requests_and_pds_records() {
        let platform = Arc::new(Platform {
            implements: true,
            ..Platform::default()
        });
        let adapter = APIAdapter(platform.clone());
        let req = LabyrinthRequest {
            nsid: "blue.catbird.labyrinth.createDevice".into(),
            method: "POST".into(),
            path: "/xrpc/blue.catbird.labyrinth.createDevice".into(),
            body: Some(b"{}".to_vec()),
            headers: vec![("catbird-labyrinth-write".into(), "abc".into())],
        };
        let r = adapter.submit_labyrinth_request(req).await.unwrap();
        assert_eq!(r.status, 409);
        let seen = platform.seen.lock().unwrap().pop().unwrap();
        assert_eq!(seen.0, "POST");
        assert_eq!(seen.1, "blue.catbird.labyrinth.createDevice");
        assert_eq!(seen.2, "/xrpc/blue.catbird.labyrinth.createDevice");
        assert_eq!(seen.3.as_deref(), Some(&b"{}"[..]));
        assert_eq!(
            seen.4,
            vec![FFILabyrinthHeader {
                name: "catbird-labyrinth-write".into(),
                value: "abc".into()
            }]
        );

        assert!(adapter.labyrinth_pds_enabled().await);
        adapter
            .put_labyrinth_mailbox_keys("self", b"rec")
            .await
            .unwrap();
        assert_eq!(
            adapter
                .get_labyrinth_mailbox_keys("did:plc:x", "self")
                .await
                .unwrap(),
            Some(b"rec".to_vec())
        );
        // A method the platform left at its default refuses.
        assert!(adapter.delete_labyrinth_mailbox_keys().await.is_err());

        let legacy = APIAdapter(Arc::new(Platform::default()));
        assert!(!legacy.labyrinth_pds_enabled().await);
    }
}
