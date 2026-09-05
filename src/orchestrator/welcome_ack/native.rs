//! One SQLCipher transaction owns KP consumption, MLS import, manifests, and receipt.
use super::{bytes, WelcomeAcceptance, WelcomeDelivery};
use crate::{
    error::MLSError,
    mls_context::{JsonCodec, ManifestStorage},
};
use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_sqlite_storage::{Codec as _, SqliteStorageProvider};
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const PREFIX: &str = "welcome_acceptance_v1:";
fn storage_error<E: std::fmt::Debug>(_: E) -> MLSError {
    MLSError::StorageFailed
}
fn key(id: &str) -> String {
    format!("{PREFIX}{id}")
}

pub(crate) fn list(storage: &ManifestStorage) -> Result<Vec<WelcomeAcceptance>, MLSError> {
    let mut query = storage
        .welcome_ack_connection()
        .prepare("SELECT value FROM mls_manifests WHERE key LIKE 'welcome_acceptance_v1:%'")
        .map_err(storage_error)?;
    let rows = query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage_error)?;
    rows.map(|raw| {
        let receipt: WelcomeAcceptance =
            serde_json::from_str(&raw.map_err(storage_error)?).map_err(storage_error)?;
        receipt.validate().map_err(storage_error)?;
        Ok(receipt)
    })
    .collect()
}
fn read(conn: &Connection, id: &str) -> Result<Option<WelcomeAcceptance>, MLSError> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM mls_manifests WHERE key=?1",
            [key(id)],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    let record: Option<WelcomeAcceptance> = raw
        .map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map_err(storage_error)?;
    if let Some(record) = &record {
        record.validate().map_err(storage_error)?;
    }
    Ok(record)
}
pub(crate) fn update(
    storage: &ManifestStorage,
    record: &WelcomeAcceptance,
) -> Result<(), MLSError> {
    record.validate().map_err(storage_error)?;
    let tx = storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(storage_error)?;
    let old = read(&tx, record.delivery.welcome_id())?.ok_or(MLSError::StorageFailed)?;
    if old.delivery != record.delivery
        || old.projection_completed && !record.projection_completed
        || old
            .request_body
            .as_ref()
            .is_some_and(|value| Some(value) != record.request_body.as_ref())
        || old
            .terminal_response
            .as_ref()
            .is_some_and(|value| Some(value) != record.terminal_response.as_ref())
    {
        return Err(MLSError::StorageFailed);
    }
    tx.execute(
        "UPDATE mls_manifests SET value=?2 WHERE key=?1",
        [
            key(record.delivery.welcome_id()),
            serde_json::to_string(record).map_err(storage_error)?,
        ],
    )
    .map_err(storage_error)?;
    tx.commit().map_err(storage_error)?;
    storage.flush_database()
}

struct WelcomeProvider<'a> {
    storage: SqliteStorageProvider<JsonCodec, &'a Connection>,
    crypto: &'a openmls_libcrux_crypto::CryptoProvider,
}
impl<'a> OpenMlsProvider for WelcomeProvider<'a> {
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

/// Preserve the inactive incarnation's ratchet material before replacing the
/// live rows. This is encrypted by the same database and committed atomically
/// with the new Welcome receipt. It is never a second active group mapping.
fn archive_inactive_group(
    connection: &Connection,
    group: &MlsGroup,
    delivery: &WelcomeDelivery,
) -> Result<(), MLSError> {
    let encoded_group = JsonCodec::to_vec(group.group_id()).map_err(storage_error)?;
    let mut query = connection
        .prepare("SELECT provider_version,data_type,group_data FROM openmls_group_data WHERE group_id=?1 ORDER BY provider_version,data_type")
        .map_err(storage_error)?;
    let data = query
        .query_map([&encoded_group], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let mut query = connection
        .prepare("SELECT provider_version,id,leaf_node FROM openmls_own_leaf_nodes WHERE group_id=?1 ORDER BY id")
        .map_err(storage_error)?;
    let own_leaves = query
        .query_map([&encoded_group], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let mut query = connection
        .prepare("SELECT provider_version,proposal_ref,proposal FROM openmls_proposals WHERE group_id=?1 ORDER BY provider_version,proposal_ref")
        .map_err(storage_error)?;
    let proposals = query
        .query_map([&encoded_group], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let archive = serde_json::json!({
        "groupId": group.group_id().as_slice(),
        "epoch": group.epoch().as_u64(),
        "welcomeId": delivery.welcome_id(),
        "welcomeSha256": delivery.envelope["sha256"],
        "groupData": data,
        "ownLeafNodes": own_leaves,
        "proposals": proposals,
    });
    connection
        .execute(
            "INSERT INTO mls_manifests(key,value) VALUES(?1,?2)",
            [
                format!("welcome_prior_group_v1:{}", delivery.welcome_id()),
                serde_json::to_string(&archive).map_err(storage_error)?,
            ],
        )
        .map_err(storage_error)?;
    Ok(())
}

pub(crate) fn adopt(
    inner: &mut crate::mls_context::MLSContext,
    delivery: &WelcomeDelivery,
    identity: &[u8],
    config: Option<crate::types::GroupConfig>,
) -> Result<crate::types::WelcomeResult, MLSError> {
    delivery.validate().map_err(storage_error)?;
    if identity != delivery.recipient_identity().as_bytes() {
        return Err(MLSError::StorageFailed);
    }
    let identity_str = std::str::from_utf8(identity).map_err(storage_error)?;
    let signer = inner
        .get_signer_for_identity(identity_str)
        .ok_or(MLSError::StorageFailed)?;
    let signer_public_key = signer.public().to_vec();
    let group_id = delivery.group_id().map_err(storage_error)?;
    let gid = GroupId::from_slice(&group_id);
    if let Some(receipt) = read(
        inner.manifest_storage.welcome_ack_connection(),
        delivery.welcome_id(),
    )? {
        if receipt.delivery != *delivery {
            return Err(MLSError::StorageFailed);
        }
        if !inner.groups.contains_key(&group_id) {
            return Err(MLSError::StorageFailed);
        }
    } else {
        // A new Welcome cannot overwrite a current live leaf. Presence by
        // itself never creates a receipt for an unprocessed envelope.
        if inner
            .groups
            .get(&group_id)
            .is_some_and(|state| state.group.is_active())
        {
            return Err(MLSError::invalid_input(
                "This group is already joined without an acceptance receipt for this Welcome",
            ));
        }
        let config = config.unwrap_or_default();
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        let tx = inner
            .manifest_storage
            .welcome_ack_connection()
            .unchecked_transaction()
            .map_err(storage_error)?;
        let provider = WelcomeProvider {
            storage: SqliteStorageProvider::new(&*tx),
            crypto: inner.provider.crypto(),
        };
        // Recheck durable state through the transaction connection. A stale
        // in-memory inactive projection must not overwrite a current leaf.
        let prior_group = MlsGroup::load(provider.storage(), &gid).map_err(storage_error)?;
        if let Some(prior) = &prior_group {
            if prior.is_active() || prior.epoch().as_u64() >= delivery.epoch() {
                return Err(MLSError::invalid_input(
                    "Welcome cannot replace this existing group incarnation",
                ));
            }
            // Removal can clear or reuse the old own-leaf slot. The durable
            // local identity signer is resolved above; its exact credential
            // and key must match the NEW cryptographically verified leaf below.
        }
        let opaque = bytes(&delivery.envelope["opaqueWelcome"]).map_err(storage_error)?;
        let (message, remainder) =
            MlsMessageIn::tls_deserialize_bytes(&opaque).map_err(storage_error)?;
        if !remainder.is_empty() {
            return Err(MLSError::SerializationError);
        }
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(MLSError::SerializationError);
        };
        let package_ref =
            bytes(&delivery.envelope["provenance"]["keyPackageRef"]).map_err(storage_error)?;
        if welcome.secrets().len() != 1
            || welcome.secrets()[0].new_member().as_slice() != package_ref
        {
            return Err(MLSError::invalid_input(
                "Welcome KeyPackage does not match its delivery provenance",
            ));
        }
        let bundle: KeyPackageBundle = provider
            .storage()
            .key_package(&welcome.secrets()[0].new_member())
            .map_err(storage_error)?
            .ok_or_else(|| MLSError::no_matching_key_package("Welcome KeyPackage not found"))?;
        let not_after = bundle.key_package().life_time().not_after();
        let last_resort = bundle.key_package().last_resort();
        let expires =
            chrono::DateTime::parse_from_rfc3339(delivery.envelope["expiresAt"].as_str().unwrap())
                .map_err(storage_error)?;
        if expires.timestamp() < 0
            || expires.timestamp() as u64 != not_after
            || expires.timestamp_subsec_nanos() != 0
        {
            return Err(MLSError::invalid_input(
                "Welcome expiry differs from its exact KeyPackage lifetime",
            ));
        }
        if let Some(prior) = &prior_group {
            archive_inactive_group(&tx, prior, delivery)?;
            // These queues belong to the removed leaf. The builder stores the
            // new group but otherwise leaves same-ID auxiliary rows behind.
            provider
                .storage()
                .delete_own_leaf_nodes(&gid)
                .map_err(storage_error)?;
            provider
                .storage()
                .clear_proposal_queue::<GroupId, ProposalRef>(&gid)
                .map_err(storage_error)?;
        }
        let group = StagedWelcome::build_from_welcome(&provider, &join_config, welcome)
            .and_then(|builder| {
                if prior_group.is_some() {
                    builder.replace_old_group().build()
                } else {
                    builder.build()
                }
            })
            .and_then(|staged| staged.into_group(&provider))
            .map_err(|error| {
                MLSError::OpenMLS(format!("Welcome verification failed: {error:?}"))
            })?;
        if group.group_id() != &gid
            || group.epoch().as_u64() != delivery.epoch()
            || !group.is_active()
            || !group.own_leaf_node().is_some_and(|leaf| {
                leaf.credential().serialized_content() == identity
                    && leaf.signature_key().as_slice() == signer_public_key
            })
        {
            return Err(MLSError::invalid_input(
                "Welcome native coordinate or recipient mismatch",
            ));
        }
        let context: GroupContext = provider
            .storage()
            .group_context(&gid)
            .map_err(storage_error)?
            .ok_or(MLSError::StorageFailed)?;
        let tag: ConfirmationTag = provider
            .storage()
            .confirmation_tag(&gid)
            .map_err(storage_error)?
            .ok_or(MLSError::StorageFailed)?;
        let tag = tag.tls_serialize_detached().map_err(storage_error)?;
        let tag = if tag.len() == 33 && tag[0] == 32 {
            &tag[1..]
        } else {
            &tag
        };
        if bytes(&delivery.envelope["coordinates"]["groupContextHash"]).map_err(storage_error)?
            != Sha256::digest(context.tls_serialize_detached().map_err(storage_error)?).as_slice()
            || bytes(&delivery.envelope["coordinates"]["confirmationTag"]).map_err(storage_error)?
                != tag
        {
            return Err(MLSError::invalid_input(
                "Welcome cryptographic coordinate mismatch",
            ));
        }
        if !last_resort {
            tx.execute(
                "DELETE FROM mls_key_package_bundles WHERE hash_ref=?1",
                [hex::encode(&package_ref)],
            )
            .map_err(storage_error)?;
        }
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM mls_manifests WHERE key='group_ids'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?;
        let mut ids: Vec<String> = raw
            .map(|raw| serde_json::from_str(&raw))
            .transpose()
            .map_err(storage_error)?
            .unwrap_or_default();
        let hex_group = hex::encode(&group_id);
        if !ids.contains(&hex_group) {
            ids.push(hex_group);
        }
        tx.execute(
            "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES('group_ids',?1)",
            [serde_json::to_string(&ids).map_err(storage_error)?],
        )
        .map_err(storage_error)?;
        let record = WelcomeAcceptance {
            delivery: delivery.clone(),
            projection_completed: false,
            request_body: None,
            terminal_response: None,
        };
        tx.execute(
            "INSERT INTO mls_manifests(key,value) VALUES(?1,?2)",
            [
                key(delivery.welcome_id()),
                serde_json::to_string(&record).map_err(storage_error)?,
            ],
        )
        .map_err(storage_error)?;
        drop(provider);
        tx.commit().map_err(storage_error)?;
        // After COMMIT never invoke unpublished-group compensation. A failure
        // now is recoverable from the atomically retained receipt and group.
        inner.publish_welcome_group(group, signer_public_key);
        if !last_resort {
            inner.key_package_bundles.remove(&package_ref);
        }
    }
    inner.manifest_storage.flush_database()?;
    let manager = inner.epoch_secret_manager().clone();
    inner.with_group(&gid, |group, provider, _| {
        crate::async_runtime::block_on(manager.export_current_epoch_secret(group, provider))
            .map(|_| ())
    })?;
    Ok(crate::types::WelcomeResult { group_id })
}
