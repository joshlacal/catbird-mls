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
use crate::labyrinth::{HistoryPage, ImportReport};
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

/// One page of decrypted history.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthHistory {
    pub messages: Vec<FfiLabyrinthMessage>,
    pub undecryptable_count: u64,
    pub space_readable: bool,
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
