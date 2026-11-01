//! One SQLCipher transaction owns KP consumption, MLS import, manifests, and receipt.
use super::{bytes, WelcomeAcceptance, WelcomeDelivery};
use crate::{
    error::MLSError,
    mls_context::ManifestStorage,
    storage::{
        driver_native::RusqliteKvBackend,
        openmls_kv::{
            OpenMlsKvStorage, SCOPE_OWN_LEAF_NODES, SCOPE_PROPOSAL_QUEUE_REFS,
            SCOPE_QUEUED_PROPOSAL,
        },
    },
};
use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
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
    storage.with_connection(|conn| {
        let mut query = conn
            .prepare("SELECT value_json FROM account_meta WHERE key LIKE 'welcome_acceptance_v1:%'")
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
    })
}

fn read(conn: &Connection, id: &str) -> Result<Option<WelcomeAcceptance>, MLSError> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value_json FROM account_meta WHERE key=?1",
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
    storage.with_connection(|conn| {
        let tx = conn.unchecked_transaction().map_err(storage_error)?;
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
            "UPDATE account_meta SET value_json=?2 WHERE key=?1",
            [
                key(record.delivery.welcome_id()),
                serde_json::to_string(record).map_err(storage_error)?,
            ],
        )
        .map_err(storage_error)?;
        tx.commit().map_err(storage_error)
    })?;
    storage.flush_database()
}

struct WelcomeProvider<'a> {
    storage: OpenMlsKvStorage<RusqliteKvBackend<'a>>,
    crypto: &'a openmls_libcrux_crypto::CryptoProvider,
}

impl<'a> OpenMlsProvider for WelcomeProvider<'a> {
    type CryptoProvider = openmls_libcrux_crypto::CryptoProvider;
    type RandProvider = openmls_libcrux_crypto::CryptoProvider;
    type StorageProvider = OpenMlsKvStorage<RusqliteKvBackend<'a>>;

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
    let encoded_group = serde_json::to_vec(group.group_id()).map_err(storage_error)?;
    let mut query = connection
        .prepare(
            "SELECT version, scope, value_bytes FROM openmls_kv
             WHERE key_bytes = ?1 AND scope NOT IN (?2, ?3)
             ORDER BY version, scope",
        )
        .map_err(storage_error)?;
    let data = query
        .query_map(
            rusqlite::params![
                &encoded_group,
                SCOPE_OWN_LEAF_NODES,
                SCOPE_PROPOSAL_QUEUE_REFS
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;

    let mut own_query = connection
        .prepare(
            "SELECT version, value_bytes FROM openmls_kv
             WHERE scope = ?1 AND key_bytes = ?2
             ORDER BY version",
        )
        .map_err(storage_error)?;
    let own_leaves = own_query
        .query_map(
            rusqlite::params![SCOPE_OWN_LEAF_NODES, &encoded_group],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;

    let queue_refs_raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT value_bytes FROM openmls_kv WHERE version = 1 AND scope = ?1 AND key_bytes = ?2",
            rusqlite::params![SCOPE_PROPOSAL_QUEUE_REFS, &encoded_group],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    let mut proposals = Vec::new();
    if let Some(raw_refs) = queue_refs_raw {
        let refs: Vec<ProposalRef> = serde_json::from_slice(&raw_refs).map_err(storage_error)?;
        for proposal_ref in refs {
            let pair_key =
                serde_json::to_vec(&(group.group_id(), &proposal_ref)).map_err(storage_error)?;
            if let Some((version, blob)) = connection
                .query_row(
                    "SELECT version, value_bytes FROM openmls_kv WHERE scope = ?1 AND key_bytes = ?2",
                    rusqlite::params![SCOPE_QUEUED_PROPOSAL, &pair_key],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
                .map_err(storage_error)?
            {
                proposals.push((version, pair_key, blob));
            }
        }
    }

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
            "INSERT INTO account_meta(key, value_json) VALUES(?1, ?2)",
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

    let existing_receipt = inner
        .manifest_storage
        .with_connection(|conn| read(conn, delivery.welcome_id()))?;

    if let Some(receipt) = existing_receipt {
        if receipt.delivery != *delivery {
            return Err(MLSError::StorageFailed);
        }
        if !inner.groups.contains_key(&group_id) {
            return Err(MLSError::StorageFailed);
        }
    } else {
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

        let crypto = inner.provider.crypto();
        let (group, package_ref, last_resort) = inner.manifest_storage.with_connection(|conn| {
            let tx = conn.unchecked_transaction().map_err(storage_error)?;
            let provider = WelcomeProvider {
                storage: OpenMlsKvStorage::new(RusqliteKvBackend(&tx)),
                crypto,
            };
            let prior_group = MlsGroup::load(provider.storage(), &gid).map_err(storage_error)?;
            if let Some(prior) = &prior_group {
                if prior.is_active() || prior.epoch().as_u64() >= delivery.epoch() {
                    return Err(MLSError::invalid_input(
                        "Welcome cannot replace this existing group incarnation",
                    ));
                }
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
            let expires = chrono::DateTime::parse_from_rfc3339(
                delivery.envelope["expiresAt"].as_str().unwrap(),
            )
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
            if bytes(&delivery.envelope["coordinates"]["groupContextHash"])
                .map_err(storage_error)?
                != Sha256::digest(context.tls_serialize_detached().map_err(storage_error)?)
                    .as_slice()
                || bytes(&delivery.envelope["coordinates"]["confirmationTag"])
                    .map_err(storage_error)?
                    != tag
            {
                return Err(MLSError::invalid_input(
                    "Welcome cryptographic coordinate mismatch",
                ));
            }
            if !last_resort {
                tx.execute(
                    "DELETE FROM pending_ops WHERE op_kind = 'kp_bundle' AND op_key = ?1",
                    [hex::encode(&package_ref)],
                )
                .map_err(storage_error)?;
            }
            let raw: Option<String> = tx
                .query_row(
                    "SELECT value_json FROM account_meta WHERE key='group_ids'",
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
                "INSERT OR REPLACE INTO account_meta(key, value_json) VALUES('group_ids', ?1)",
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
                "INSERT INTO account_meta(key, value_json) VALUES(?1, ?2)",
                [
                    key(delivery.welcome_id()),
                    serde_json::to_string(&record).map_err(storage_error)?,
                ],
            )
            .map_err(storage_error)?;
            drop(provider);
            tx.commit().map_err(storage_error)?;
            Ok((group, package_ref, last_resort))
        })?;

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
