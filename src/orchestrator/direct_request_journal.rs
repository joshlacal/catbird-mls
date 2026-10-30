//! Request-only durable ownership. Unknown outcomes never release crypto state.
use super::direct_request_bootstrap::{DirectRequestBootstrap, DirectRequestBootstrapInput};
use crate::error::MLSError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DirectRequestJournalPhase {
    PreparedCrypto,
    OutcomeUnknown,
    PublishedAwaitingProjection,
    RequestSent,
    /// Published proof retained after authorized local group cleanup.
    RetiredPublished,
    TerminalNotPublished,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectRequestJournal {
    pub request_id: String,
    pub draft_id: String,
    pub actor_did: String,
    pub actor_device_id: String,
    pub first_message_id: String,
    pub conversation_id: String,
    pub input_sha256: [u8; 32],
    pub preparation_request_digest: [u8; 32],
    pub receipt_authority_key: Vec<u8>,
    pub bootstrap: DirectRequestBootstrap,
    pub phase: DirectRequestJournalPhase,
    /// Exact signed wire bytes, immutable once recorded and before transport.
    pub publish_request: Option<Vec<u8>>,
    pub publish_request_sha256: Option<[u8; 32]>,
    pub publication_digest: Option<[u8; 32]>,
    pub terminal_receipt: Option<Vec<u8>>,
    pub terminal_authority_key: Option<Vec<u8>>,
}
impl DirectRequestJournal {
    pub fn from_prepared(
        input: &DirectRequestBootstrapInput,
        bootstrap: DirectRequestBootstrap,
    ) -> Result<Self, MLSError> {
        let (ctx, _) = super::direct_request_bootstrap::context(&input.context_json)?;
        Ok(Self {
            request_id: ctx["requestId"].as_str().unwrap().into(),
            draft_id: input.draft_id.clone(),
            actor_did: ctx["actorDid"].as_str().unwrap().into(),
            actor_device_id: ctx["actorDeviceId"].as_str().unwrap().into(),
            first_message_id: ctx["firstMessageId"].as_str().unwrap().into(),
            conversation_id: ctx["conversationId"].as_str().unwrap().into(),
            input_sha256: Self::input_digest(input)?,
            preparation_request_digest: input.preparation_request_digest,
            receipt_authority_key: input.receipt_authority_key.clone(),
            bootstrap,
            phase: DirectRequestJournalPhase::PreparedCrypto,
            publish_request: None,
            publish_request_sha256: None,
            publication_digest: None,
            terminal_receipt: None,
            terminal_authority_key: None,
        })
    }
    pub fn input_digest(input: &DirectRequestBootstrapInput) -> Result<[u8; 32], MLSError> {
        Ok(
            Sha256::digest(serde_json::to_vec(input).map_err(|_| MLSError::SerializationError)?)
                .into(),
        )
    }
    pub fn validate(&self) -> Result<(), MLSError> {
        let (ctx, hash) = super::direct_request_bootstrap::context(&self.bootstrap.context_json)?;
        if hash != self.bootstrap.context_hash
            || ctx["requestId"] != self.request_id
            || ctx["actorDid"] != self.actor_did
            || ctx["actorDeviceId"] != self.actor_device_id
            || ctx["firstMessageId"] != self.first_message_id
            || ctx["conversationId"] != self.conversation_id
            || uuid::Uuid::parse_str(&self.draft_id).is_err()
        {
            return Err(MLSError::StorageFailed);
        }
        if self
            .publish_request
            .as_ref()
            .map(|b| <[u8; 32]>::from(Sha256::digest(b)))
            != self.publish_request_sha256
        {
            return Err(MLSError::StorageFailed);
        }
        if self.publish_request.is_some() != self.publication_digest.is_some()
            || (self.phase == DirectRequestJournalPhase::PreparedCrypto
                && self.publish_request.is_some())
        {
            return Err(MLSError::StorageFailed);
        }
        let terminal = matches!(
            self.phase,
            DirectRequestJournalPhase::PublishedAwaitingProjection
                | DirectRequestJournalPhase::RequestSent
                | DirectRequestJournalPhase::RetiredPublished
                | DirectRequestJournalPhase::TerminalNotPublished
        );
        if terminal != self.terminal_receipt.is_some()
            || terminal != self.terminal_authority_key.is_some()
            || (matches!(
                self.phase,
                DirectRequestJournalPhase::OutcomeUnknown
                    | DirectRequestJournalPhase::PublishedAwaitingProjection
                    | DirectRequestJournalPhase::RequestSent
                    | DirectRequestJournalPhase::RetiredPublished
            ) && self.publish_request.is_none())
        {
            return Err(MLSError::StorageFailed);
        }
        if let (Some(receipt), Some(key)) = (&self.terminal_receipt, &self.terminal_authority_key) {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let verified = super::direct_request_shared_crypto::verify_pinned_terminal_receipt(
                receipt, key,
            )
            .map_err(|_| MLSError::StorageFailed)?;
            let proof = &verified.body()["receipt"];
            let published = matches!(
                self.phase,
                DirectRequestJournalPhase::PublishedAwaitingProjection
                    | DirectRequestJournalPhase::RequestSent
                    | DirectRequestJournalPhase::RetiredPublished
            );
            if proof["requestId"] != self.request_id
                || proof["preparationRequestDigest"].as_str()
                    != Some(STANDARD.encode(self.preparation_request_digest).as_str())
                || published
                    != (proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt")
                || (published
                    && (proof["coordinates"] != self.bootstrap.coordinates
                        || proof["requestDigest"].as_str()
                            != self
                                .publication_digest
                                .map(|d| STANDARD.encode(d))
                                .as_deref()))
            {
                return Err(MLSError::StorageFailed);
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native {
    use super::*;
    use crate::mls_context::{JsonCodec, ManifestStorage};
    use openmls_sqlite_storage::SqliteStorageProvider;
    use openmls_traits::OpenMlsProvider;
    use rusqlite::{Connection, OptionalExtension};
    pub(crate) fn error(_: impl std::fmt::Debug) -> MLSError {
        MLSError::StorageFailed
    }
    fn key(id: &str) -> String {
        format!("direct_request_v2:{id}")
    }
    pub(crate) fn read(
        conn: &Connection,
        id: &str,
    ) -> Result<Option<DirectRequestJournal>, MLSError> {
        let raw: Option<String> = conn
            .query_row(
                "SELECT value FROM mls_manifests WHERE key=?1",
                [key(id)],
                |r| r.get(0),
            )
            .optional()
            .map_err(error)?;
        let record: Option<DirectRequestJournal> = raw
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(error)?;
        if let Some(record) = &record {
            record.validate()?;
        }
        Ok(record)
    }
    pub(crate) fn write(conn: &Connection, record: &DirectRequestJournal) -> Result<(), MLSError> {
        record.validate()?;
        conn.execute(
            "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES(?1,?2)",
            [
                key(&record.request_id),
                serde_json::to_string(record).map_err(error)?,
            ],
        )
        .map_err(error)?;
        Ok(())
    }
    pub(crate) fn list(storage: &ManifestStorage) -> Result<Vec<DirectRequestJournal>, MLSError> {
        let mut statement = storage
            .welcome_ack_connection()
            .prepare("SELECT value FROM mls_manifests WHERE key LIKE 'direct_request_v2:%'")
            .map_err(error)?;
        let rows = statement
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(error)?;
        rows.map(|row| {
            let record: DirectRequestJournal =
                serde_json::from_str(&row.map_err(error)?).map_err(error)?;
            record.validate()?;
            Ok(record)
        })
        .collect()
    }
    pub(crate) struct Provider<'a> {
        pub storage: SqliteStorageProvider<JsonCodec, &'a Connection>,
        pub crypto: &'a openmls_libcrux_crypto::CryptoProvider,
    }
    impl<'a> OpenMlsProvider for Provider<'a> {
        type CryptoProvider = openmls_libcrux_crypto::CryptoProvider;
        type RandProvider = openmls_libcrux_crypto::CryptoProvider;
        type StorageProvider = SqliteStorageProvider<JsonCodec, &'a Connection>;
        fn storage(&self) -> &Self::StorageProvider {
            &self.storage
        }
        fn crypto(&self) -> &Self::CryptoProvider {
            self.crypto
        }
        fn rand(&self) -> &Self::RandProvider {
            self.crypto
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn retire_published_group(
    inner: &mut crate::mls_context::MLSContext,
    group_id: &[u8],
) -> Result<Option<bool>, MLSError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use native::*;
    use openmls::prelude::*;
    use openmls_traits::OpenMlsProvider;
    use rusqlite::OptionalExtension;
    let mut owned = None;
    for record in list(&inner.manifest_storage)? {
        let id = STANDARD
            .decode(
                record.bootstrap.coordinates["groupId"]
                    .as_str()
                    .ok_or(MLSError::StorageFailed)?,
            )
            .map_err(error)?;
        if id == group_id {
            if owned.is_some() {
                return Err(MLSError::StorageFailed);
            }
            owned = Some(record);
        }
    }
    let Some(mut record) = owned else {
        return Ok(None);
    };
    if record.phase == DirectRequestJournalPhase::RetiredPublished {
        // A durability barrier can fail after commit; repeat it before the
        // caller releases any remaining in-memory copy.
        inner.manifest_storage.flush_database()?;
        return Ok(Some(false));
    }
    if !matches!(
        record.phase,
        DirectRequestJournalPhase::PublishedAwaitingProjection
            | DirectRequestJournalPhase::RequestSent
    ) {
        return Err(MLSError::InvalidState(
            "Cannot delete an unpublished request-owned group".into(),
        ));
    }
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let provider = Provider {
        storage: openmls_sqlite_storage::SqliteStorageProvider::new(&*tx),
        crypto: inner.provider.crypto(),
    };
    let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
        .map_err(error)?
        .ok_or(MLSError::StorageFailed)?;
    group.delete(provider.storage()).map_err(error)?;
    let encoded = hex::encode(group_id);
    let raw: String = tx
        .query_row(
            "SELECT value FROM mls_manifests WHERE key='group_ids'",
            [],
            |row| row.get(0),
        )
        .map_err(error)?;
    let mut ids: Vec<String> = serde_json::from_str(&raw).map_err(error)?;
    if !ids.contains(&encoded) {
        return Err(MLSError::StorageFailed);
    }
    ids.retain(|id| id != &encoded);
    tx.execute(
        "UPDATE mls_manifests SET value=?1 WHERE key='group_ids'",
        [serde_json::to_string(&ids).map_err(error)?],
    )
    .map_err(error)?;
    let pending: Option<String> = tx
        .query_row(
            "SELECT value FROM mls_manifests WHERE key='pending_external_joins'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(error)?;
    if let Some(raw) = pending {
        let mut pending: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&raw).map_err(error)?;
        pending.remove(&encoded);
        tx.execute(
            "UPDATE mls_manifests SET value=?1 WHERE key='pending_external_joins'",
            [serde_json::to_string(&pending).map_err(error)?],
        )
        .map_err(error)?;
    }
    record.phase = DirectRequestJournalPhase::RetiredPublished;
    write(&tx, &record)?;
    tx.commit().map_err(error)?;
    inner.manifest_storage.flush_database()?;
    Ok(Some(true))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn prepare(
    inner: &mut crate::mls_context::MLSContext,
    input: &DirectRequestBootstrapInput,
) -> Result<DirectRequestJournal, MLSError> {
    use native::*;
    use openmls::prelude::*;
    use openmls_traits::OpenMlsProvider;
    let (ctx, _) = super::direct_request_bootstrap::context(&input.context_json)?;
    let id = ctx["requestId"].as_str().unwrap();
    if let Some(old) = read(inner.manifest_storage.welcome_ack_connection(), id)? {
        if old.input_sha256 != DirectRequestJournal::input_digest(input)? {
            return Err(MLSError::invalid_input(
                "Request attempt already owns different crypto",
            ));
        }
        return Ok(old);
    }
    let identity = format!(
        "{}#{}",
        ctx["actorDid"].as_str().unwrap(),
        ctx["actorDeviceId"].as_str().unwrap()
    );
    let signer = inner
        .get_signer_for_identity(&identity)
        .ok_or(MLSError::StorageFailed)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error)?
        .as_secs();
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let provider = Provider {
        storage: openmls_sqlite_storage::SqliteStorageProvider::new(&*tx),
        crypto: inner.provider.crypto(),
    };
    if MlsGroup::load(provider.storage(), &GroupId::from_slice(&input.group_id))
        .map_err(error)?
        .is_some()
    {
        return Err(MLSError::invalid_input("Request group ID already exists"));
    }
    let (_group, bootstrap) =
        super::direct_request_bootstrap::prepare_with_provider(&provider, &signer, input, now)?;
    let record = DirectRequestJournal::from_prepared(input, bootstrap)?;
    write(&tx, &record)?;
    tx.commit().map_err(error)?;
    inner.manifest_storage.flush_database()?;
    Ok(record)
}

/// Verify exact signed publication before recording any possible transmission.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn persist_publish(
    inner: &mut crate::mls_context::MLSContext,
    id: &str,
    bytes: &[u8],
) -> Result<(), MLSError> {
    use native::*;
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let mut record = read(&tx, id)?.ok_or(MLSError::StorageFailed)?;
    let identity = format!("{}#{}", record.actor_did, record.actor_device_id);
    let signer = inner
        .get_signer_for_identity(&identity)
        .ok_or(MLSError::StorageFailed)?;
    let publication_digest = record.verify_publication(bytes, signer.public())?;
    let b = &record.bootstrap;
    if let Some(old) = &record.publish_request {
        if old != bytes {
            return Err(MLSError::invalid_input(
                "Cannot replace transmitted request bytes",
            ));
        }
        return Ok(());
    }
    if record.phase != DirectRequestJournalPhase::PreparedCrypto {
        return Err(MLSError::StorageFailed);
    }
    super::direct_request_bootstrap::require_import_horizon(
        b.import_until,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(error)?
            .as_secs(),
    )?;
    record.publish_request = Some(bytes.into());
    record.publish_request_sha256 = Some(Sha256::digest(bytes).into());
    record.publication_digest = Some(publication_digest);
    record.phase = DirectRequestJournalPhase::OutcomeUnknown;
    write(&tx, &record)?;
    tx.commit().map_err(error)?;
    inner.manifest_storage.flush_database()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn resolve(
    inner: &mut crate::mls_context::MLSContext,
    id: &str,
    receipt: &[u8],
    authority_key: &[u8],
    published: bool,
) -> Result<DirectRequestJournal, MLSError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use native::*;
    use openmls::prelude::*;
    use openmls_traits::OpenMlsProvider;
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let mut record = read(&tx, id)?.ok_or(MLSError::StorageFailed)?;
    record.verify_terminal_receipt(receipt, authority_key, published)?;
    if let Some(old) = &record.terminal_receipt {
        if old != receipt {
            return Err(MLSError::invalid_input("Terminal receipt is immutable"));
        }
        return Ok(record);
    }
    let provider = Provider {
        storage: openmls_sqlite_storage::SqliteStorageProvider::new(&*tx),
        crypto: inner.provider.crypto(),
    };
    let group_id = STANDARD
        .decode(
            record.bootstrap.coordinates["groupId"]
                .as_str()
                .ok_or(MLSError::StorageFailed)?,
        )
        .map_err(error)?;
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
        .map_err(error)?
        .ok_or(MLSError::StorageFailed)?;
    if super::direct_request_bootstrap::group_coordinates(
        &group,
        &provider,
        &record.conversation_id,
        record.bootstrap.coordinates["generation"]
            .as_u64()
            .ok_or(MLSError::StorageFailed)?,
        record.bootstrap.coordinates["stateVersion"]
            .as_u64()
            .ok_or(MLSError::StorageFailed)?,
    )? != record.bootstrap.coordinates
    {
        return Err(MLSError::StorageFailed);
    }
    let signer_public = group
        .own_leaf_node()
        .ok_or(MLSError::StorageFailed)?
        .signature_key()
        .as_slice()
        .to_vec();
    if published {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM mls_manifests WHERE key='group_ids'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(error)?;
        let mut ids: Vec<String> = raw
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(error)?
            .unwrap_or_default();
        let hex_id = hex::encode(&group_id);
        if !ids.contains(&hex_id) {
            ids.push(hex_id);
        }
        tx.execute(
            "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES('group_ids',?1)",
            [serde_json::to_string(&ids).map_err(error)?],
        )
        .map_err(error)?;
        record.phase = DirectRequestJournalPhase::PublishedAwaitingProjection;
    } else {
        // Retain encrypted candidate state and terminal evidence; never add a live index.
        record.phase = DirectRequestJournalPhase::TerminalNotPublished;
    }
    record.terminal_receipt = Some(receipt.into());
    record.terminal_authority_key = Some(authority_key.into());
    write(&tx, &record)?;
    tx.commit().map_err(error)?;
    if published {
        inner.publish_welcome_group(group, signer_public);
    }
    inner.manifest_storage.flush_database()?;
    Ok(record)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn projected(
    inner: &mut crate::mls_context::MLSContext,
    id: &str,
) -> Result<(), MLSError> {
    use native::*;
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let mut record = read(&tx, id)?.ok_or(MLSError::StorageFailed)?;
    if record.phase == DirectRequestJournalPhase::RequestSent {
        return Ok(());
    }
    if record.phase != DirectRequestJournalPhase::PublishedAwaitingProjection {
        return Err(MLSError::StorageFailed);
    }
    record.phase = DirectRequestJournalPhase::RequestSent;
    write(&tx, &record)?;
    tx.commit().map_err(error)?;
    inner.manifest_storage.flush_database()
}

#[cfg(not(target_arch = "wasm32"))]
fn intent_key(id: &str) -> Result<String, MLSError> {
    if uuid::Uuid::parse_str(id)
        .map_err(native::error)?
        .to_string()
        != id
    {
        return Err(MLSError::invalid_input(
            "Intent draft ID must be a canonical UUID",
        ));
    }
    Ok(format!("direct_request_intent_v2:{id}"))
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn intent_read(
    storage: &crate::mls_context::ManifestStorage,
    id: &str,
) -> Result<Option<Vec<u8>>, MLSError> {
    use rusqlite::OptionalExtension;
    storage
        .welcome_ack_connection()
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [intent_key(id)?],
            |row| row.get(0),
        )
        .optional()
        .map_err(native::error)
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn intent_cas(
    storage: &crate::mls_context::ManifestStorage,
    id: &str,
    expected: Option<&[u8]>,
    next: &[u8],
) -> Result<bool, MLSError> {
    use rusqlite::OptionalExtension;
    if next.is_empty() || next.len() > 16777216 {
        return Err(MLSError::invalid_input(
            "Request intent exceeds storage bound",
        ));
    }
    let key = intent_key(id)?;
    let tx = storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(native::error)?;
    let old: Option<Vec<u8>> = tx
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [&key],
            |r| r.get(0),
        )
        .optional()
        .map_err(native::error)?;
    if old.as_deref() != expected {
        return Ok(false);
    }
    tx.execute(
        "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES(?1,?2)",
        rusqlite::params![key, next],
    )
    .map_err(native::error)?;
    tx.commit().map_err(native::error)?;
    storage.flush_database()?;
    Ok(true)
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn intent_list(
    storage: &crate::mls_context::ManifestStorage,
) -> Result<Vec<Vec<u8>>, MLSError> {
    let mut query=storage.welcome_ack_connection().prepare("SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key LIKE 'direct_request_intent_v2:%'").map_err(native::error)?;
    let rows = query
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(native::error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(native::error)
}
#[cfg(not(target_arch = "wasm32"))]
fn projection_key(id: &str) -> Result<String, MLSError> {
    if uuid::Uuid::parse_str(id)
        .map_err(native::error)?
        .to_string()
        != id
    {
        return Err(MLSError::invalid_input(
            "Projection conversation ID must be a canonical UUID",
        ));
    }
    Ok(format!("direct_request_projection_v2:{id}"))
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn projection_read(
    storage: &crate::mls_context::ManifestStorage,
    id: &str,
) -> Result<Option<Vec<u8>>, MLSError> {
    use rusqlite::OptionalExtension;
    storage
        .welcome_ack_connection()
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [projection_key(id)?],
            |row| row.get(0),
        )
        .optional()
        .map_err(native::error)
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn projection_cas(
    storage: &crate::mls_context::ManifestStorage,
    id: &str,
    expected: Option<&[u8]>,
    next: &[u8],
) -> Result<bool, MLSError> {
    use rusqlite::OptionalExtension;
    if next.is_empty() || next.len() > 16777216 {
        return Err(MLSError::invalid_input(
            "Request intent exceeds storage bound",
        ));
    }
    let key = projection_key(id)?;
    let tx = storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(native::error)?;
    let old: Option<Vec<u8>> = tx
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [&key],
            |r| r.get(0),
        )
        .optional()
        .map_err(native::error)?;
    if old.as_deref() != expected {
        return Ok(false);
    }
    tx.execute(
        "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES(?1,?2)",
        rusqlite::params![key, next],
    )
    .map_err(native::error)?;
    tx.commit().map_err(native::error)?;
    storage.flush_database()?;
    Ok(true)
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn projection_list(
    storage: &crate::mls_context::ManifestStorage,
) -> Result<Vec<Vec<u8>>, MLSError> {
    let mut query=storage.welcome_ack_connection().prepare("SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key LIKE 'direct_request_projection_v2:%'").map_err(native::error)?;
    let rows = query
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(native::error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(native::error)
}

impl DirectRequestJournal {
    /// Validates exact publication bytes against this immutable crypto record.
    /// `signer_public_key` must be the actor's authenticated historical device key.
    pub fn verify_publication(
        &self,
        bytes: &[u8],
        signer_public_key: &[u8],
    ) -> Result<[u8; 32], MLSError> {
        use crate::chat_v2::transcript::direct_request::{
            verify_signed_request, DirectRequestKind,
        };
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        fn error(_: impl std::fmt::Debug) -> MLSError {
            MLSError::StorageFailed
        }
        let record = self;
        crate::chat_v2::transcript::decode_strict_json(bytes).map_err(error)?;
        let parsed: serde_json::Value = serde_json::from_slice(bytes).map_err(error)?;
        if parsed.get("signedRequest").is_some() && parsed.as_object().is_none_or(|o| o.len() != 1)
        {
            return Err(MLSError::invalid_input(
                "Unexpected publication wrapper fields",
            ));
        }
        let wrapper = parsed.get("signedRequest").unwrap_or(&parsed);
        let verified = verify_signed_request(
            DirectRequestKind::Publish,
            &serde_json::to_vec(wrapper).map_err(error)?,
            signer_public_key,
        )
        .map_err(error)?;
        let body = verified.body();
        let b = &record.bootstrap;
        let eq_bytes = |v: &serde_json::Value, expected: &[u8]| {
            v.as_str()
                .or_else(|| v["$bytes"].as_str())
                .and_then(|s| STANDARD.decode(s).ok())
                .is_some_and(|bytes| bytes == expected)
        };
        if body["requestId"] != record.request_id
            || body["firstMessageId"] != record.first_message_id
            || body["conversationId"] != record.conversation_id
            || body["next"] != b.coordinates
            || !eq_bytes(&body["contextHash"], &b.context_hash)
        {
            return Err(MLSError::invalid_input(
                "Publication differs from prepared request",
            ));
        }
        let (ctx, _) = super::direct_request_bootstrap::context(&b.context_json)?;
        for field in [
            "actorDid",
            "actorDeviceId",
            "recipientDid",
            "origin",
            "preparationDigest",
        ] {
            if body[field] != ctx[field] {
                return Err(MLSError::invalid_input(
                    "Publication request context mismatch",
                ));
            }
        }
        if body["keyId"] != ctx["actorKeyId"] {
            return Err(MLSError::invalid_input("Publication signer mismatch"));
        }
        let import_until = chrono::DateTime::parse_from_rfc3339(
            body["importUntil"]
                .as_str()
                .ok_or(MLSError::StorageFailed)?,
        )
        .map_err(error)?;
        if import_until.timestamp() < 0
            || import_until.timestamp() as u64 != b.import_until
            || import_until.timestamp_subsec_nanos() != 0
        {
            return Err(MLSError::invalid_input(
                "Publication import deadline mismatch",
            ));
        }
        if !eq_bytes(
            &body["preparationRequestDigest"],
            &record.preparation_request_digest,
        ) {
            return Err(MLSError::invalid_input(
                "Publication preparation request digest mismatch",
            ));
        }
        let artifacts = &body["artifacts"];
        // The signed manifest must carry the precise crypto bytes, never fresh encryption.
        for (value, expected) in [
            (
                &artifacts["genesisGroupInfo"]["bytes"],
                &b.genesis_group_info,
            ),
            (&artifacts["addCommit"]["bytes"], &b.add_commit),
            (&artifacts["finalGroupInfo"]["bytes"], &b.final_group_info),
            (&artifacts["welcome"]["opaqueWelcome"], &b.welcome),
            (&artifacts["initialCiphertext"], &b.initial_ciphertext),
        ] {
            if !eq_bytes(value, expected) {
                return Err(MLSError::invalid_input(
                    "Publication artifact differs from prepared request",
                ));
            }
        }
        for (value, expected) in [
            (&artifacts["genesisGroupInfo"], &b.genesis_group_info),
            (&artifacts["addCommit"], &b.add_commit),
            (&artifacts["finalGroupInfo"], &b.final_group_info),
            (&artifacts["welcome"], &b.welcome),
        ] {
            if !eq_bytes(&value["sha256"], &Sha256::digest(expected)) {
                return Err(MLSError::invalid_input(
                    "Publication artifact digest mismatch",
                ));
            }
        }
        let metadata = &artifacts["metadataSnapshot"];
        if !eq_bytes(&metadata["nonce"], &b.metadata_nonce)
            || !eq_bytes(&metadata["ciphertext"], &b.metadata_ciphertext)
            || !eq_bytes(
                &metadata["ciphertextSha256"],
                &Sha256::digest(&b.metadata_ciphertext),
            )
            || metadata["ciphertextSize"].as_u64() != Some(b.metadata_ciphertext.len() as u64)
            || metadata["metadataVersion"] != 1
            || metadata["originTransitionId"] != record.request_id
            || metadata["coordinate"]
                != super::direct_request_bootstrap::metadata_coordinate(&b.coordinates)?
        {
            return Err(MLSError::invalid_input(
                "Publication metadata differs from prepared snapshot",
            ));
        }
        let deliveries = artifacts["welcome"]["deliveries"]
            .as_array()
            .ok_or(MLSError::StorageFailed)?;
        let expected_refs: std::collections::BTreeSet<_> =
            b.expected_package_refs.iter().cloned().collect();
        let mut found = std::collections::BTreeSet::new();
        for delivery in deliveries {
            let provenance = &delivery["provenance"];
            let reference = provenance["keyPackageRef"]
                .as_str()
                .and_then(|s| STANDARD.decode(s).ok())
                .ok_or(MLSError::StorageFailed)?;
            if !found.insert(reference)
                || provenance["requestId"] != record.request_id
                || provenance["preparationDigest"] != ctx["preparationDigest"]
                || !eq_bytes(&provenance["contextHash"], &b.context_hash)
                || provenance["importUntil"] != body["importUntil"]
            {
                return Err(MLSError::invalid_input(
                    "Publication Welcome provenance mismatch",
                ));
            }
        }
        if found != expected_refs {
            return Err(MLSError::invalid_input(
                "Publication dropped or added a Welcome device",
            ));
        }
        Ok(*verified.request_digest())
    }
}

/// Commit verified Closed preview custody and retire the exact native group in
/// one transaction. Host tombstones follow this barrier and can be replayed.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn commit_closed_projection(
    inner: &mut crate::mls_context::MLSContext,
    cid: &str,
    expected: &[u8],
    next: &[u8],
) -> Result<bool, MLSError> {
    use native::*;
    use openmls::prelude::*;
    use openmls_traits::OpenMlsProvider;
    use rusqlite::OptionalExtension;
    let gid = super::direct_requests::validate_closed_request_projection(cid, expected, next)?;
    let group_id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &gid);
    let mut journal = None;
    for candidate in list(&inner.manifest_storage)? {
        if candidate.conversation_id == cid {
            if journal.is_some()
                || candidate.bootstrap.coordinates["groupId"] != group_id
                || !matches!(
                    candidate.phase,
                    DirectRequestJournalPhase::PublishedAwaitingProjection
                        | DirectRequestJournalPhase::RequestSent
                        | DirectRequestJournalPhase::RetiredPublished
                )
            {
                return Err(MLSError::StorageFailed);
            }
            journal = Some(candidate);
        }
    }
    let key = projection_key(cid)?;
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let current: Option<Vec<u8>> = tx
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [&key],
            |r| r.get(0),
        )
        .optional()
        .map_err(error)?;
    if current.as_deref() == Some(next) {
        drop(tx);
        inner.manifest_storage.flush_database()?;
        inner.groups.remove(&gid);
        return Ok(true);
    }
    if current.as_deref() != Some(expected) {
        return Ok(false);
    }
    let provider = Provider {
        storage: openmls_sqlite_storage::SqliteStorageProvider::new(&*tx),
        crypto: inner.provider.crypto(),
    };
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&gid)).map_err(error)?;
    let was_loaded = group.is_some();
    if let Some(mut group) = group {
        group.delete(provider.storage()).map_err(error)?;
    }
    let encoded = hex::encode(&gid);
    let ids: Option<String> = tx
        .query_row(
            "SELECT value FROM mls_manifests WHERE key='group_ids'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(error)?;
    let mut ids: Vec<String> = ids
        .map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map_err(error)?
        .unwrap_or_default();
    if was_loaded != ids.contains(&encoded) {
        return Err(MLSError::StorageFailed);
    }
    ids.retain(|id| id != &encoded);
    tx.execute(
        "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES('group_ids',?1)",
        [serde_json::to_string(&ids).map_err(error)?],
    )
    .map_err(error)?;
    if let Some(mut journal) = journal {
        journal.phase = DirectRequestJournalPhase::RetiredPublished;
        write(&tx, &journal)?;
    }
    tx.execute(
        "UPDATE mls_manifests SET value=?1 WHERE key=?2",
        rusqlite::params![next, key],
    )
    .map_err(error)?;
    tx.commit().map_err(error)?;
    inner.manifest_storage.flush_database()?;
    inner.groups.remove(&gid);
    Ok(true)
}
