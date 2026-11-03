// Space-only offline archive harness. Included only with `labyrinth` and
// `cfg(any(test, feature = "test-utils", feature = "sim"))`, and selected explicitly
// by `open_offline_archive_for_test`; production clients use `native_archive.rs`.

fn owner_epoch_root_key(epoch_seq: u64) -> String {
    format!("owner_epoch_root:{epoch_seq}")
}

fn ensure_owner_epoch_root(
    tx: &crate::storage::SqlTx<'_>,
    epoch_seq: u64,
    now_ms: i64,
    hooks: &crate::sim_hooks::SimClientHooks,
) -> Result<Zeroizing<[u8; 32]>, MLSError> {
    let key = owner_epoch_root_key(epoch_seq);
    if let Some(existing) = tx.get_labyrinth_state(&key)? {
        if let Ok(arr) = <[u8; 32]>::try_from(existing.as_slice()) {
            return Ok(Zeroizing::new(arr));
        }
    }
    let mut fresh = Zeroizing::new([0u8; 32]);
    hooks.fill_bytes(&mut *fresh);
    tx.put_labyrinth_state(&key, fresh.as_slice(), now_ms)?;
    Ok(fresh)
}

#[cfg(feature = "labyrinth")]
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredLabyrinthDeviceSecrets {
    device_key_hex: String,
    storage_hex: String,
    storage_auth_hex: String,
    public_device_json: String,
}

#[cfg(feature = "labyrinth")]
fn decode_stored_device_secrets(raw_dev: &[u8]) -> Option<labyrinth::device::DeviceSecrets> {
    let stored: StoredLabyrinthDeviceSecrets = serde_json::from_slice(raw_dev).ok()?;
    let dk = hex::decode(&stored.device_key_hex).ok()?;
    let st = hex::decode(&stored.storage_hex).ok()?;
    let sa = hex::decode(&stored.storage_auth_hex).ok()?;
    let dev_rec: labyrinth::records::Device =
        serde_json::from_str(&stored.public_device_json).ok()?;
    let dk_arr = <[u8; 32]>::try_from(dk.as_slice()).ok()?;
    let st_arr =
        <[u8; labyrinth::hpke::hawk::HAWK_ENC_SECRET_LEN]>::try_from(st.as_slice()).ok()?;
    let sa_arr = <[u8; 32]>::try_from(sa.as_slice()).ok()?;
    let pub_dev = dev_rec.to_public().ok()?;
    labyrinth::device::DeviceSecrets::from_parts(
        labyrinth::sign::XSigningKey::from_bytes(dk_arr),
        labyrinth::hpke::hawk::HawkEncSecret::from_bytes(st_arr),
        Some(labyrinth::hpke::X25519Secret::from_bytes(sa_arr)),
        pub_dev,
    )
    .ok()
}

#[cfg(feature = "labyrinth")]
fn ensure_device_secrets_and_salt(
    tx: &crate::storage::SqlTx<'_>,
    now_ms: i64,
    hooks: &crate::sim_hooks::SimClientHooks,
) -> Result<(labyrinth::device::DeviceSecrets, [u8; 32]), MLSError> {
    let salt = match tx
        .get_labyrinth_state("mailbox_root_salt")?
        .and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok())
    {
        Some(arr) => arr,
        None => {
            let mut fresh_salt = [0u8; 32];
            hooks.fill_bytes(&mut fresh_salt);
            tx.put_labyrinth_state("mailbox_root_salt", &fresh_salt, now_ms)?;
            fresh_salt
        }
    };

    if let Some(raw_dev) = tx.get_labyrinth_state("physical_device_secrets_json")? {
        if let Some(rebuilt) = decode_stored_device_secrets(&raw_dev) {
            return Ok((rebuilt, salt));
        }
    }

    let fresh = hooks
        .with_labyrinth_rng(labyrinth::device::DeviceSecrets::generate_physical)
        .map_err(|e| {
            MLSError::Cryptography(format!("generate Labyrinth physical DeviceSecrets: {e}"))
        })?;
    let auth_bytes = fresh
        .storage_auth
        .as_ref()
        .map(|a| a.to_bytes())
        .ok_or_else(|| MLSError::Internal("physical device missing storage_auth".to_string()))?;
    let dev_rec = labyrinth::records::Device::from_public(
        fresh.public(),
        labyrinth::records::datetime_from_ms(now_ms.max(0) as u64),
    );
    let stored = StoredLabyrinthDeviceSecrets {
        device_key_hex: hex::encode(Zeroizing::new(fresh.device_key.to_bytes()).as_slice()),
        storage_hex: hex::encode(Zeroizing::new(fresh.storage.to_bytes()).as_slice()),
        storage_auth_hex: hex::encode(Zeroizing::new(auth_bytes).as_slice()),
        public_device_json: serde_json::to_string(&dev_rec)
            .map_err(|e| MLSError::Internal(format!("serialize Device record: {e}")))?,
    };
    let bytes = serde_json::to_vec(&stored).map_err(|e| {
        MLSError::Internal(format!("serialize StoredLabyrinthDeviceSecrets: {e}"))
    })?;
    tx.put_labyrinth_state("physical_device_secrets_json", &bytes, now_ms)?;
    Ok((fresh, salt))
}

#[cfg(feature = "labyrinth")]
struct ClientTransportSigner {
    public_key: [u8; 32],
    sign_fn: Box<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>,
}

#[cfg(feature = "labyrinth")]
impl labyrinth::sign::TransportSigner for ClientTransportSigner {
    fn transport_public_key(&self) -> [u8; 32] {
        self.public_key
    }
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        (self.sign_fn)(msg)
    }
}

#[cfg(feature = "labyrinth")]
fn load_or_create_transport_signer(
    db: &MlsAccountDb,
    now_ms: i64,
    hooks: &crate::sim_hooks::SimClientHooks,
) -> Result<ClientTransportSigner, MLSError> {
    let enrolled_opt = db.read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?;
    if let Some(signer_json) = enrolled_opt {
        let signer: SignatureKeyPair = serde_json::from_str(&signer_json)
            .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
        if let Ok(pk) = <[u8; 32]>::try_from(signer.public()) {
            return Ok(ClientTransportSigner {
                public_key: pk,
                sign_fn: Box::new(move |msg: &[u8]| {
                    let sig = signer.sign(msg).unwrap_or_else(|_| vec![0u8; 64]);
                    <[u8; 64]>::try_from(sig.as_slice()).unwrap_or([0u8; 64])
                }),
            });
        }
    }
    let seed: Zeroizing<[u8; 32]> = db.write_tx(|tx| {
        if let Some(existing) = tx.get_labyrinth_state("transport_ed25519_seed")? {
            if let Ok(arr) = <[u8; 32]>::try_from(existing.as_slice()) {
                return Ok(Zeroizing::new(arr));
            }
        }
        let mut fresh = Zeroizing::new([0u8; 32]);
        hooks.fill_bytes(&mut *fresh);
        tx.put_labyrinth_state("transport_ed25519_seed", fresh.as_slice(), now_ms)?;
        Ok(fresh)
    })?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    Ok(ClientTransportSigner {
        public_key,
        sign_fn: Box::new(move |msg: &[u8]| {
            use ed25519_dalek::Signer as _;
            signing_key.sign(msg).to_bytes()
        }),
    })
}

#[cfg(feature = "labyrinth")]
fn ensure_convo_sender_mek(
    db: &MlsAccountDb,
    conversation_id: &str,
    transport_pub: [u8; 32],
    now_ms: i64,
    hooks: &crate::sim_hooks::SimClientHooks,
) -> Result<labyrinth::mek::Mek, MLSError> {
    let state_key = format!("convo_sender_mek:{conversation_id}");
    let secret: Zeroizing<[u8; 32]> = db.write_tx(|tx| {
        if let Some(existing) = tx.get_labyrinth_state(&state_key)? {
            if let Ok(arr) = <[u8; 32]>::try_from(existing.as_slice()) {
                return Ok(Zeroizing::new(arr));
            }
        }
        let mut fresh = Zeroizing::new([0u8; 32]);
        hooks.fill_bytes(&mut *fresh);
        tx.put_labyrinth_state(&state_key, fresh.as_slice(), now_ms)?;
        Ok(fresh)
    })?;
    let head = Sha256::digest(format!("catbird.convo.mek:{conversation_id}").as_bytes());
    let mut head_arr = [0u8; 32];
    head_arr.copy_from_slice(&head);
    let r_hash = labyrinth::mek::roster_hash(&[head_arr]);
    Ok(labyrinth::mek::Mek::from_secret(
        secret,
        r_hash,
        labyrinth::mek::MekProvenance::Transport {
            transport_pub,
            created_here: true,
        },
    ))
}

#[cfg(feature = "labyrinth")]
fn deterministic_tid(timestamp_ms: i64, sub_seq: u64, discriminator: &str) -> String {
    const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let micros = (timestamp_ms.max(0) as u64)
        .saturating_mul(1_000)
        .saturating_add(sub_seq)
        & ((1u64 << 53) - 1);
    let digest = Sha256::digest(discriminator.as_bytes());
    let clock_id = (u16::from_be_bytes([digest[0], digest[1]]) as u64) & 0x3ff;
    let v = (micros << 10) | clock_id;
    (0..13)
        .rev()
        .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
        .collect()
}

#[cfg(feature = "labyrinth")]
fn percent_encode_query_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 16);
    for &b in raw.as_bytes() {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(feature = "labyrinth")]
fn is_space_write_committed(resp: &PlatformHttpResponse) -> bool {
    if (200..300).contains(&resp.status) || resp.status == 409 {
        return true;
    }
    if resp.status == 400 {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
            if parsed.get("error").and_then(|v| v.as_str()) == Some("RecordAlreadyExists") {
                return true;
            }
        }
    }
    false
}

#[cfg(feature = "labyrinth")]
struct RemoteMailboxEpochState {
    epochs: std::collections::BTreeMap<u64, labyrinth::epoch::EpochRecord>,
    members_by_epoch: std::collections::BTreeMap<u64, Vec<labyrinth::epoch::EpochMemberRecord>>,
    physical_devices: std::collections::HashMap<[u8; 32], (labyrinth::device::DevicePublic, bool)>,
    virtual_devices: std::collections::HashMap<[u8; 32], labyrinth::device::DevicePublic>,
    vdev_bundles: std::collections::HashMap<[u8; 16], labyrinth::virtual_device::VirtualDeviceRecord>,
}

#[cfg(feature = "labyrinth")]
impl CatbirdMlsClient {
    fn fetch_remote_mailbox_epoch_state(
        &self,
        mailbox_space_uri: &str,
    ) -> Result<Option<RemoteMailboxEpochState>, MLSError> {
        let Some(epoch_vals) = self
            .list_space_records_if_supported(mailbox_space_uri, labyrinth::records::nsid::EPOCH)?
        else {
            return Ok(None);
        };
        let member_vals = self
            .list_space_records_if_supported(
                mailbox_space_uri,
                labyrinth::records::nsid::EPOCH_MEMBER,
            )?
            .unwrap_or_default();
        let device_vals = self
            .list_space_records_if_supported(mailbox_space_uri, labyrinth::records::nsid::DEVICE)?
            .unwrap_or_default();
        let vdev_vals = self
            .list_space_records_if_supported(
                mailbox_space_uri,
                labyrinth::records::nsid::VIRTUAL_DEVICE,
            )?
            .unwrap_or_default();

        let mut epochs = std::collections::BTreeMap::new();
        for val in epoch_vals {
            if let Ok(doc) = serde_json::from_value::<labyrinth::records::Epoch>(val) {
                if let Ok(rec) = doc.to_record() {
                    epochs.insert(rec.public.seq, rec);
                }
            }
        }

        let mut members_by_epoch: std::collections::BTreeMap<
            u64,
            Vec<labyrinth::epoch::EpochMemberRecord>,
        > = std::collections::BTreeMap::new();
        for val in member_vals {
            if let Ok(doc) = serde_json::from_value::<labyrinth::records::EpochMember>(val) {
                if let Ok(rec) = doc.to_record() {
                    let bucket = members_by_epoch.entry(rec.seq).or_default();
                    if !bucket
                        .iter()
                        .any(|m| m.device_key_pub == rec.device_key_pub)
                    {
                        bucket.push(rec);
                    }
                }
            }
        }

        let mut physical_devices = std::collections::HashMap::new();
        for val in device_vals {
            if let Ok(doc) = serde_json::from_value::<labyrinth::records::Device>(val) {
                let is_revoked = doc.revoked_at.is_some();
                if let Ok(pub_dev) = doc.to_public() {
                    if !pub_dev.is_virtual && pub_dev.verify().is_ok() {
                        physical_devices.insert(pub_dev.device_key_pub.0, (pub_dev, is_revoked));
                    }
                }
            }
        }

        let mut virtual_devices = std::collections::HashMap::new();
        let mut vdev_bundles = std::collections::HashMap::new();
        for val in vdev_vals {
            if let Ok(doc) = serde_json::from_value::<labyrinth::records::VirtualDevice>(val) {
                if let Ok((bundle, _)) = doc.to_bundle() {
                    virtual_devices.insert(bundle.public.device_key_pub.0, bundle.public.clone());
                    vdev_bundles.insert(bundle.vdevice_id, bundle);
                }
            }
        }

        Ok(Some(RemoteMailboxEpochState {
            epochs,
            members_by_epoch,
            physical_devices,
            virtual_devices,
            vdev_bundles,
        }))
    }

    fn publish_physical_device_if_needed(
        &self,
        mailbox_space_uri: &str,
        me_secrets: &labyrinth::device::DeviceSecrets,
        remote: &mut RemoteMailboxEpochState,
        now_ms: i64,
    ) -> Result<(), MLSError> {
        let dk = me_secrets.public().device_key_pub.0;
        if remote.physical_devices.contains_key(&dk) {
            return Ok(());
        }
        let created_at = labyrinth::records::datetime_from_ms(now_ms.max(0) as u64);
        let phys_dev_doc =
            labyrinth::records::Device::from_public(me_secrets.public(), created_at);
        let phys_dev_rkey = hex::encode(dk);
        let phys_dev_val = serde_json::to_value(&phys_dev_doc)
            .map_err(|e| MLSError::Internal(format!("serialize Device: {e}")))?;
        let resp = self.apply_space_writes(
            mailbox_space_uri,
            &[serde_json::json!({
                "$type": "com.atproto.space.applyWrites#create",
                "collection": labyrinth::records::nsid::DEVICE,
                "rkey": phys_dev_rkey,
                "value": phys_dev_val,
            })],
        )?;
        if !is_space_write_committed(&resp) {
            return Err(MLSError::Internal(format!(
                "publish_physical_device_if_needed applyWrites returned HTTP {}",
                resp.status
            )));
        }
        remote
            .physical_devices
            .insert(dk, (me_secrets.public().clone(), false));
        Ok(())
    }

    fn ensure_local_epoch_chain_published(
        &self,
        mailbox_space_uri: &str,
        target_seq: u64,
        me_secrets: &labyrinth::device::DeviceSecrets,
        transport_signer: &ClientTransportSigner,
        remote: &mut RemoteMailboxEpochState,
        now_ms: i64,
    ) -> Result<(), MLSError> {
        use labyrinth::epoch::EpochKeys as _;

        self.publish_physical_device_if_needed(mailbox_space_uri, me_secrets, remote, now_ms)?;
        let created_at = labyrinth::records::datetime_from_ms(now_ms.max(0) as u64);

        for seq in 0..=target_seq {
            if remote.epochs.contains_key(&seq) {
                continue;
            }
            let root = self
                .db
                .write_tx(|tx| ensure_owner_epoch_root(tx, seq, now_ms, &self.hooks))?;
            let cur_secret = labyrinth::epoch::EpochSecret::from_parts(
                seq,
                labyrinth::epoch::space_epoch_id(seq),
                *root,
            );
            let members_hash =
                labyrinth::mailbox::members_hash_for_devices(std::slice::from_ref(me_secrets.public()))
                    .map_err(|e| MLSError::Cryptography(format!("members_hash_for_devices: {e}")))?;

            let (public, encrypted_prev_seq, encrypted_prev_root) = if seq == 0 {
                let pub0 = self
                    .hooks
                    .with_labyrinth_rng(|| {
                        labyrinth::mailbox::EpochPublic::sign(
                            &self.normalized_did,
                            0,
                            &cur_secret.mailbox_keys(),
                            members_hash,
                            None,
                            None,
                            transport_signer,
                        )
                    })
                    .map_err(|e| MLSError::Cryptography(format!("EpochPublic::sign(0): {e}")))?;
                (pub0, None, None)
            } else {
                let prev_seq = seq - 1;
                let prev_root = self
                    .db
                    .write_tx(|tx| ensure_owner_epoch_root(tx, prev_seq, now_ms, &self.hooks))?;
                let prev_secret = labyrinth::epoch::EpochSecret::from_parts(
                    prev_seq,
                    labyrinth::epoch::space_epoch_id(prev_seq),
                    *prev_root,
                );
                let prev_head = remote
                    .epochs
                    .get(&prev_seq)
                    .map(|r| r.public.head)
                    .ok_or_else(|| {
                        MLSError::InvalidState(format!(
                            "missing predecessor Space epoch {prev_seq} head"
                        ))
                    })?;
                let prev_keys = prev_secret.mailbox_keys();
                let data_key = cur_secret.data_key();
                let (pub_n, enc_prev_seq, enc_prev_root) =
                    self.hooks.with_labyrinth_rng(|| {
                        let pub_n = labyrinth::mailbox::EpochPublic::sign(
                            &self.normalized_did,
                            seq,
                            &cur_secret.mailbox_keys(),
                            members_hash,
                            Some(prev_head),
                            Some(&prev_keys.sig_secret),
                            transport_signer,
                        )
                        .map_err(|e| {
                            MLSError::Cryptography(format!("EpochPublic::sign({seq}): {e}"))
                        })?;
                        let enc_seq = labyrinth::aead::seal(
                            &data_key,
                            b"epoch_data_metadata",
                            prev_seq.to_string().as_bytes(),
                        )
                        .map_err(|e| MLSError::Cryptography(format!("seal prev_seq: {e}")))?;
                        let enc_root = labyrinth::aead::seal(
                            &data_key,
                            b"epoch_data_metadata",
                            prev_secret.root(),
                        )
                        .map_err(|e| MLSError::Cryptography(format!("seal prev_root: {e}")))?;
                        Ok::<_, MLSError>((pub_n, enc_seq, enc_root))
                    })?;
                (pub_n, Some(enc_prev_seq), Some(enc_prev_root))
            };

            let epoch_rec = labyrinth::epoch::EpochRecord {
                public,
                encrypted_prev_seq,
                encrypted_prev_root,
                opened_by: me_secrets.public().device_key_pub,
            };
            let member_rec = labyrinth::epoch::add_device_mac(&cur_secret, me_secrets.public())
                .map_err(|e| MLSError::Cryptography(format!("add_device_mac({seq}): {e}")))?;

            let epoch_doc =
                labyrinth::records::Epoch::from_record(&epoch_rec, created_at.clone());
            let epoch_val = serde_json::to_value(&epoch_doc)
                .map_err(|e| MLSError::Internal(format!("serialize Epoch({seq}): {e}")))?;
            let member_doc =
                labyrinth::records::EpochMember::from_record(&member_rec, created_at.clone());
            let member_rkey = member_doc.rkey();
            let member_val = serde_json::to_value(&member_doc)
                .map_err(|e| MLSError::Internal(format!("serialize EpochMember({seq}): {e}")))?;

            let resp = self.apply_space_writes(
                mailbox_space_uri,
                &[
                    serde_json::json!({
                        "$type": "com.atproto.space.applyWrites#create",
                        "collection": labyrinth::records::nsid::EPOCH,
                        "rkey": labyrinth::epoch::space_epoch_id(seq),
                        "value": epoch_val,
                    }),
                    serde_json::json!({
                        "$type": "com.atproto.space.applyWrites#create",
                        "collection": labyrinth::records::nsid::EPOCH_MEMBER,
                        "rkey": member_rkey,
                        "value": member_val,
                    }),
                ],
            )?;
            if !is_space_write_committed(&resp) {
                return Err(MLSError::Internal(format!(
                    "ensure_local_epoch_chain_published({seq}) returned HTTP {}",
                    resp.status
                )));
            }
            remote.epochs.insert(seq, epoch_rec);
            remote
                .members_by_epoch
                .entry(seq)
                .or_default()
                .push(member_rec);
        }
        Ok(())
    }

    fn catch_up_physical_epoch_roots_from_remote(
        &self,
        me_secrets: &labyrinth::device::DeviceSecrets,
        remote: &RemoteMailboxEpochState,
        now_ms: i64,
    ) -> Result<Option<(u64, Zeroizing<[u8; 32]>)>, MLSError> {
        use labyrinth::epoch::EpochKeys as _;

        let Some(&latest_seq) = remote.epochs.keys().next_back() else {
            return Ok(None);
        };

        let mut anchor: Option<(u64, Zeroizing<[u8; 32]>)> = None;
        for seq in (0..=latest_seq).rev() {
            let maybe_bytes = self
                .db
                .read_tx(|tx| tx.get_labyrinth_state(&owner_epoch_root_key(seq)))?;
            if let Some(bytes) = maybe_bytes {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    anchor = Some((seq, Zeroizing::new(arr)));
                    break;
                }
            }
        }
        let Some((start_seq, start_root)) = anchor else {
            return Ok(None);
        };
        if start_seq == latest_seq {
            return Ok(Some((latest_seq, start_root)));
        }

        let Some(start_rec) = remote.epochs.get(&start_seq) else {
            return Ok(None);
        };
        let mut cur_secret = labyrinth::epoch::EpochSecret::from_parts(
            start_seq,
            labyrinth::epoch::space_epoch_id(start_seq),
            *start_root,
        );
        let mut cur_public = start_rec.public.clone();
        let mut newly_derived: Vec<(u64, Zeroizing<[u8; 32]>)> = Vec::new();

        for next_seq in (start_seq + 1)..=latest_seq {
            let next_rec = remote
                .epochs
                .get(&next_seq)
                .ok_or_else(|| MLSError::InvalidState(format!("missing Space epoch {next_seq}")))?;
            let next_members = remote.members_by_epoch.get(&next_seq).ok_or_else(|| {
                MLSError::InvalidState(format!("missing Space epochMember set for {next_seq}"))
            })?;
            let my_member = next_members
                .iter()
                .find(|m| m.device_key_pub == me_secrets.public().device_key_pub)
                .ok_or_else(|| {
                    MLSError::insufficient_permissions(format!(
                        "device is not a member of mailbox epoch {next_seq}"
                    ))
                })?;
            let opener = remote
                .physical_devices
                .get(&next_rec.opened_by.0)
                .map(|(d, _)| d)
                .ok_or_else(|| {
                    MLSError::InvalidState(format!(
                        "missing Space Device record for opener of epoch {next_seq}"
                    ))
                })?;
            let opener_prev_member = remote
                .members_by_epoch
                .get(&(next_seq - 1))
                .and_then(|ms| ms.iter().find(|m| m.device_key_pub == next_rec.opened_by));
            let next_id = labyrinth::epoch::space_epoch_id(next_seq);
            let opened = labyrinth::epoch::OpenedEpoch {
                epoch_id: &next_id,
                record: next_rec,
                my_member,
                opener,
                opener_prev_member,
            };
            let derived = labyrinth::epoch::forward_chain(
                &self.normalized_did,
                &cur_secret,
                &cur_public,
                &opened,
                &me_secrets.storage,
                false,
            )
            .map_err(|e| {
                MLSError::Cryptography(format!("forward_chain physical epoch {next_seq}: {e}"))
            })?;
            newly_derived.push((next_seq, Zeroizing::new(*derived.root())));
            cur_public = next_rec.public.clone();
            cur_secret = derived;
        }

        let final_root = Zeroizing::new(*cur_secret.root());
        if !newly_derived.is_empty() {
            self.db.write_tx(|tx| {
                for (seq, root) in &newly_derived {
                    tx.put_labyrinth_state(&owner_epoch_root_key(*seq), root.as_slice(), now_ms)?;
                }
                Ok(())
            })?;
        }
        Ok(Some((latest_seq, final_root)))
    }

    fn collect_continuing_epoch_devices(
        prev_secret: &labyrinth::epoch::EpochSecret,
        prev_members: &[labyrinth::epoch::EpochMemberRecord],
        remote: &RemoteMailboxEpochState,
        exclude_device_key_pub: Option<&[u8; 32]>,
    ) -> Vec<labyrinth::device::DevicePublic> {
        let mut out: Vec<labyrinth::device::DevicePublic> = Vec::new();
        for m in prev_members {
            if exclude_device_key_pub == Some(&m.device_key_pub.0) {
                continue;
            }
            if out.iter().any(|d| d.device_key_pub == m.device_key_pub) {
                continue;
            }
            if let Some(vdev_pub) = remote.virtual_devices.get(&m.device_key_pub.0) {
                if labyrinth::epoch::verify_member(prev_secret, m, true).is_ok()
                    && vdev_pub.verify().is_ok()
                {
                    out.push(vdev_pub.clone());
                }
            } else if let Some((pdev_pub, is_revoked)) =
                remote.physical_devices.get(&m.device_key_pub.0)
            {
                if !*is_revoked
                    && labyrinth::epoch::verify_member(prev_secret, m, false).is_ok()
                    && pdev_pub.verify().is_ok()
                {
                    out.push(pdev_pub.clone());
                }
            }
        }
        out
    }

    fn publish_opened_epoch(
        &self,
        mailbox_space_uri: &str,
        opened: &labyrinth::epoch::NewEpoch,
        now_ms: i64,
    ) -> Result<(), MLSError> {
        let created_at = labyrinth::records::datetime_from_ms(now_ms.max(0) as u64);
        let seq = opened.record.public.seq;
        let epoch_doc = labyrinth::records::Epoch::from_record(&opened.record, created_at.clone());
        let epoch_val = serde_json::to_value(&epoch_doc)
            .map_err(|e| MLSError::Internal(format!("serialize Epoch({seq}): {e}")))?;
        let mut writes = Vec::with_capacity(1 + opened.members.len());
        writes.push(serde_json::json!({
            "$type": "com.atproto.space.applyWrites#create",
            "collection": labyrinth::records::nsid::EPOCH,
            "rkey": labyrinth::epoch::space_epoch_id(seq),
            "value": epoch_val,
        }));
        for member in &opened.members {
            let member_doc =
                labyrinth::records::EpochMember::from_record(member, created_at.clone());
            let member_rkey = member_doc.rkey();
            let member_val = serde_json::to_value(&member_doc)
                .map_err(|e| MLSError::Internal(format!("serialize EpochMember({seq}): {e}")))?;
            writes.push(serde_json::json!({
                "$type": "com.atproto.space.applyWrites#create",
                "collection": labyrinth::records::nsid::EPOCH_MEMBER,
                "rkey": member_rkey,
                "value": member_val,
            }));
        }
        let resp = self.apply_space_writes(mailbox_space_uri, &writes)?;
        if !is_space_write_committed(&resp) {
            return Err(MLSError::Internal(format!(
                "publish_opened_epoch({seq}) applyWrites returned HTTP {}",
                resp.status
            )));
        }
        Ok(())
    }

    pub(super) fn rotate_mailbox_epoch_if_supported(
        &self,
        exclude_device_key_pub: Option<&[u8; 32]>,
        now_ms: i64,
    ) -> Result<Option<(u64, Zeroizing<[u8; 32]>)>, MLSError> {
        use labyrinth::epoch::EpochKeys as _;

        let (st_snapshot, me_secrets) = self.db.write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                MLSError::InvalidState("Labyrinth status not initialized".to_string())
            })?;
            let st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            let _ = ensure_owner_epoch_root(tx, st.epoch_seq, now_ms, &self.hooks)?;
            let (me, _) = ensure_device_secrets_and_salt(tx, now_ms, &self.hooks)?;
            Ok((st, me))
        })?;

        let Some(mut remote) =
            self.fetch_remote_mailbox_epoch_state(&st_snapshot.mailbox_space_uri)?
        else {
            return Ok(None);
        };

        let transport_signer = load_or_create_transport_signer(&self.db, now_ms, &self.hooks)?;
        let (prev_seq, prev_root) = match remote.epochs.keys().next_back().copied() {
            None => {
                self.ensure_local_epoch_chain_published(
                    &st_snapshot.mailbox_space_uri,
                    st_snapshot.epoch_seq,
                    &me_secrets,
                    &transport_signer,
                    &mut remote,
                    now_ms,
                )?;
                let root = self.db.write_tx(|tx| {
                    ensure_owner_epoch_root(tx, st_snapshot.epoch_seq, now_ms, &self.hooks)
                })?;
                (st_snapshot.epoch_seq, root)
            }
            Some(remote_max) if st_snapshot.epoch_seq > remote_max => {
                self.ensure_local_epoch_chain_published(
                    &st_snapshot.mailbox_space_uri,
                    st_snapshot.epoch_seq,
                    &me_secrets,
                    &transport_signer,
                    &mut remote,
                    now_ms,
                )?;
                let root = self.db.write_tx(|tx| {
                    ensure_owner_epoch_root(tx, st_snapshot.epoch_seq, now_ms, &self.hooks)
                })?;
                (st_snapshot.epoch_seq, root)
            }
            Some(_) => {
                self.publish_physical_device_if_needed(
                    &st_snapshot.mailbox_space_uri,
                    &me_secrets,
                    &mut remote,
                    now_ms,
                )?;
                if let Some(caught_up) =
                    self.catch_up_physical_epoch_roots_from_remote(&me_secrets, &remote, now_ms)?
                {
                    caught_up
                } else {
                    let root = self.db.write_tx(|tx| {
                        ensure_owner_epoch_root(tx, st_snapshot.epoch_seq, now_ms, &self.hooks)
                    })?;
                    (st_snapshot.epoch_seq, root)
                }
            }
        };

        let prev_rec = remote.epochs.get(&prev_seq).ok_or_else(|| {
            MLSError::InvalidState(format!("missing Space epoch {prev_seq} before rotation"))
        })?;
        let prev_members = remote
            .members_by_epoch
            .get(&prev_seq)
            .cloned()
            .unwrap_or_default();
        let prev_secret = labyrinth::epoch::EpochSecret::from_parts(
            prev_seq,
            labyrinth::epoch::space_epoch_id(prev_seq),
            *prev_root,
        );
        let mut continuing = Self::collect_continuing_epoch_devices(
            &prev_secret,
            &prev_members,
            &remote,
            exclude_device_key_pub,
        );
        let me_in_prev = prev_members.iter().any(|m| {
            m.device_key_pub == me_secrets.public().device_key_pub
                && labyrinth::epoch::verify_member(&prev_secret, m, false).is_ok()
        });

        let (pending_next, opened_next) = self.hooks.with_labyrinth_rng(|| {
            if me_in_prev {
                labyrinth::epoch::open_next(
                    &self.normalized_did,
                    &prev_secret,
                    &prev_rec.public,
                    &prev_members,
                    &continuing,
                    &me_secrets,
                    &transport_signer,
                )
                .map_err(|e| MLSError::Cryptography(format!("epoch::open_next: {e}")))
            } else {
                continuing.retain(|d| d.device_key_pub != me_secrets.public().device_key_pub);
                labyrinth::epoch::open_next_enrolling(
                    &self.normalized_did,
                    &prev_secret,
                    &prev_rec.public,
                    &prev_members,
                    &continuing,
                    &me_secrets,
                    &transport_signer,
                )
                .map_err(|e| MLSError::Cryptography(format!("epoch::open_next_enrolling: {e}")))
            }
        })?;

        self.publish_opened_epoch(&st_snapshot.mailbox_space_uri, &opened_next, now_ms)?;
        Ok(Some((
            pending_next.seq(),
            Zeroizing::new(*pending_next.root()),
        )))
    }

    pub(super) fn offline_setup_recovery_code(&self) -> Result<String, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let code = self
            .hooks
            .with_labyrinth_rng(labyrinth::recovery_code::RecoveryCode::generate)
            .map_err(|e| MLSError::Cryptography(format!("generate RecoveryCode: {e}")))?;
        let grouped = code.format_grouped();
        let now_ms = self.hooks.now_ms();
        let created_at = labyrinth::records::datetime_from_ms(now_ms.max(0) as u64);

        let (st_snapshot, mut active_seq, mut owner_root, me_secrets, salt) =
            self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                let seq = st.epoch_seq;
                let root = ensure_owner_epoch_root(tx, seq, now_ms, &self.hooks)?;
                let (me, salt) = ensure_device_secrets_and_salt(tx, now_ms, &self.hooks)?;
                Ok((st, seq, root, me, salt))
            })?;

        if let Some(mut remote) =
            self.fetch_remote_mailbox_epoch_state(&st_snapshot.mailbox_space_uri)?
        {
            let transport_signer = load_or_create_transport_signer(&self.db, now_ms, &self.hooks)?;
            match remote.epochs.keys().next_back().copied() {
                None => {
                    self.ensure_local_epoch_chain_published(
                        &st_snapshot.mailbox_space_uri,
                        active_seq,
                        &me_secrets,
                        &transport_signer,
                        &mut remote,
                        now_ms,
                    )?;
                }
                Some(remote_max) if active_seq > remote_max => {
                    self.ensure_local_epoch_chain_published(
                        &st_snapshot.mailbox_space_uri,
                        active_seq,
                        &me_secrets,
                        &transport_signer,
                        &mut remote,
                        now_ms,
                    )?;
                }
                Some(_) => {
                    self.publish_physical_device_if_needed(
                        &st_snapshot.mailbox_space_uri,
                        &me_secrets,
                        &mut remote,
                        now_ms,
                    )?;
                    if let Some((caught_seq, caught_root)) =
                        self.catch_up_physical_epoch_roots_from_remote(&me_secrets, &remote, now_ms)?
                    {
                        active_seq = caught_seq;
                        owner_root = caught_root;
                    }
                }
            }
        } else {
            let phys_dev_doc =
                labyrinth::records::Device::from_public(me_secrets.public(), created_at.clone());
            let phys_dev_rkey = hex::encode(me_secrets.public().device_key_pub.0);
            let phys_dev_val = serde_json::to_value(&phys_dev_doc)
                .map_err(|e| MLSError::Internal(format!("serialize Device: {e}")))?;
            let dev_resp = self.apply_space_writes(
                &st_snapshot.mailbox_space_uri,
                &[serde_json::json!({
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": labyrinth::records::nsid::DEVICE,
                    "rkey": phys_dev_rkey,
                    "value": phys_dev_val,
                })],
            )?;
            if !is_space_write_committed(&dev_resp) {
                return Err(MLSError::Internal(format!(
                    "setup_recovery_code device applyWrites returned HTTP {}",
                    dev_resp.status
                )));
            }
        }

        let current_epoch = labyrinth::epoch::EpochSecret::from_parts(
            active_seq,
            labyrinth::epoch::space_epoch_id(active_seq),
            *owner_root,
        );
        let (vdev_bundle, member_rec) = self
            .hooks
            .with_labyrinth_rng(|| {
                labyrinth::virtual_device::create(
                    &self.normalized_did,
                    &code,
                    &me_secrets,
                    &current_epoch,
                    &salt,
                    labyrinth::virtual_device::Mechanism::Code,
                )
            })
            .map_err(|e| MLSError::Cryptography(format!("virtual_device::create: {e}")))?;

        let vdev_doc =
            labyrinth::records::VirtualDevice::from_bundle(&vdev_bundle, None, created_at.clone());
        let vdev_rkey = vdev_doc.rkey();
        let vdev_doc_bytes = serde_json::to_vec(&vdev_doc)
            .map_err(|e| MLSError::Internal(format!("serialize VirtualDevice: {e}")))?;
        let vdev_val = serde_json::to_value(&vdev_doc)
            .map_err(|e| MLSError::Internal(format!("serialize VirtualDevice Value: {e}")))?;

        let epoch_member_doc =
            labyrinth::records::EpochMember::from_record(&member_rec, created_at);
        let epoch_member_rkey = epoch_member_doc.rkey();
        let epoch_member_val = serde_json::to_value(&epoch_member_doc)
            .map_err(|e| MLSError::Internal(format!("serialize EpochMember: {e}")))?;

        let bundle_resp = self.apply_space_writes(
            &st_snapshot.mailbox_space_uri,
            &[
                serde_json::json!({
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": labyrinth::records::nsid::VIRTUAL_DEVICE,
                    "rkey": vdev_rkey,
                    "value": vdev_val,
                }),
                serde_json::json!({
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": labyrinth::records::nsid::EPOCH_MEMBER,
                    "rkey": epoch_member_rkey,
                    "value": epoch_member_val,
                }),
            ],
        )?;
        if !is_space_write_committed(&bundle_resp) {
            return Err(MLSError::Internal(format!(
                "setup_recovery_code virtualDevice applyWrites returned HTTP {}",
                bundle_resp.status
            )));
        }

        let status = self.db.write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                MLSError::InvalidState("Labyrinth status not initialized".to_string())
            })?;
            let mut st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            st.epoch_seq = st.epoch_seq.max(active_seq);
            st.has_recovery_code = true;
            tx.put_labyrinth_state("recovery_vdevice_id", &vdev_bundle.vdevice_id, now_ms)?;
            tx.put_labyrinth_state("recovery_vdev_doc_json", &vdev_doc_bytes, now_ms)?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                now_ms,
            )?;
            Ok(st)
        })?;

        self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
            epoch_seq: status.epoch_seq,
        });
        Ok(grouped)
    }

    pub(super) fn offline_restore_with_recovery_code(
        &self,
        recovery_code_input: &str,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        use labyrinth::epoch::EpochKeys as _;

        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }

        let _ =
            labyrinth::recovery_code::RecoveryCode::candidates(recovery_code_input).map_err(|_| {
                MLSError::invalid_input("invalid 40-character Labyrinth recovery code")
            })?;

        let now_ms = self.hooks.now_ms();
        let (st_before, local_vdev_doc, me_secrets) = self.db.write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                MLSError::InvalidState("Labyrinth status not initialized".to_string())
            })?;
            let st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            let local_doc = tx.get_labyrinth_state("recovery_vdev_doc_json")?;
            let (me, _) = ensure_device_secrets_and_salt(tx, now_ms, &self.hooks)?;
            Ok((st, local_doc, me))
        })?;

        let remote_opt = self.fetch_remote_mailbox_epoch_state(&st_before.mailbox_space_uri)?;
        let mut bundles: std::collections::HashMap<
            [u8; 16],
            labyrinth::virtual_device::VirtualDeviceRecord,
        > = std::collections::HashMap::new();

        if let Some(ref remote) = remote_opt {
            bundles.extend(remote.vdev_bundles.iter().map(|(k, v)| (*k, v.clone())));
        } else if let Some(raw_doc) = local_vdev_doc {
            if let Ok(vdev_doc) =
                serde_json::from_slice::<labyrinth::records::VirtualDevice>(&raw_doc)
            {
                if let Ok((bundle, _)) = vdev_doc.to_bundle() {
                    bundles.insert(bundle.vdevice_id, bundle);
                }
            }
        }

        if bundles.is_empty() {
            return Err(MLSError::insufficient_permissions(
                "no enrolled Labyrinth virtual device found in personal mailbox Space",
            ));
        }

        let matched_code = labyrinth::virtual_device::find_code(
            recovery_code_input,
            &self.normalized_did,
            |cand_id| bundles.contains_key(cand_id),
        )
        .map_err(|_| {
            MLSError::insufficient_permissions(
                "recovery code does not match enrolled Labyrinth virtual device",
            )
        })?;
        let (matched_vdev_id, _) = matched_code.derive(&self.normalized_did);
        let bundle = bundles.get(&matched_vdev_id).ok_or_else(|| {
            MLSError::insufficient_permissions(
                "recovery code does not match enrolled Labyrinth virtual device",
            )
        })?;
        let restored =
            labyrinth::virtual_device::open(bundle, &matched_code, &self.normalized_did).map_err(
                |e| {
                    MLSError::insufficient_permissions(format!(
                        "failed to decrypt Labyrinth virtual device bundle: {e}"
                    ))
                },
            )?;
        let recovered_seq = restored.epoch.seq();
        let recovered_root = Zeroizing::new(*restored.epoch.root());
        let recovered_salt = restored.mailbox_root_salt;

        let mut recovered_roots: std::collections::BTreeMap<u64, Zeroizing<[u8; 32]>> =
            std::collections::BTreeMap::new();
        recovered_roots.insert(recovered_seq, recovered_root.clone());

        let new_epoch_seq = if let Some(mut remote) = remote_opt {
            let transport_signer = load_or_create_transport_signer(&self.db, now_ms, &self.hooks)?;
            self.publish_physical_device_if_needed(
                &st_before.mailbox_space_uri,
                &me_secrets,
                &mut remote,
                now_ms,
            )?;

            if remote.epochs.is_empty() {
                self.db.write_tx(|tx| {
                    tx.put_labyrinth_state(
                        &owner_epoch_root_key(recovered_seq),
                        recovered_root.as_slice(),
                        now_ms,
                    )
                })?;
                self.ensure_local_epoch_chain_published(
                    &st_before.mailbox_space_uri,
                    recovered_seq,
                    &me_secrets,
                    &transport_signer,
                    &mut remote,
                    now_ms,
                )?;
            }

            if remote.epochs.contains_key(&recovered_seq) {
                let recovered_secret = labyrinth::epoch::EpochSecret::from_parts(
                    recovered_seq,
                    labyrinth::epoch::space_epoch_id(recovered_seq),
                    *recovered_root,
                );

                let mut back_cur = recovered_secret.clone();
                for s in (1..=recovered_seq).rev() {
                    let cur_rec = remote.epochs.get(&s).ok_or_else(|| {
                        MLSError::InvalidState(format!("missing Space epoch record for epoch {s}"))
                    })?;
                    let prev_id = labyrinth::epoch::space_epoch_id(s - 1);
                    let prev_secret =
                        labyrinth::epoch::backward_chain(&back_cur, cur_rec, &prev_id).map_err(
                            |e| {
                                MLSError::Cryptography(format!(
                                    "backward_chain({s} -> {}): {e}",
                                    s - 1
                                ))
                            },
                        )?;
                    recovered_roots.insert(s - 1, Zeroizing::new(*prev_secret.root()));
                    back_cur = prev_secret;
                }

                let latest_seq = *remote.epochs.keys().next_back().unwrap_or(&recovered_seq);
                let mut fwd_cur = recovered_secret;
                let mut fwd_pub = remote
                    .epochs
                    .get(&recovered_seq)
                    .ok_or_else(|| {
                        MLSError::InvalidState(format!(
                            "missing Space epoch record for recovered epoch {recovered_seq}"
                        ))
                    })?
                    .public
                    .clone();

                for next_seq in (recovered_seq + 1)..=latest_seq {
                    let next_rec = remote.epochs.get(&next_seq).ok_or_else(|| {
                        MLSError::InvalidState(format!(
                            "missing Space epoch record for epoch {next_seq}"
                        ))
                    })?;
                    let next_members = remote.members_by_epoch.get(&next_seq).ok_or_else(|| {
                        MLSError::InvalidState(format!(
                            "missing Space epochMember records for epoch {next_seq}"
                        ))
                    })?;
                    let my_member = next_members
                        .iter()
                        .find(|m| m.device_key_pub == restored.device.public().device_key_pub)
                        .ok_or_else(|| {
                            MLSError::InvalidState(format!(
                                "virtual device missing EpochMember in epoch {next_seq}"
                            ))
                        })?;
                    let opener = remote
                        .physical_devices
                        .get(&next_rec.opened_by.0)
                        .map(|(d, _)| d)
                        .ok_or_else(|| {
                            MLSError::InvalidState(format!(
                                "missing Space Device record for opener of epoch {next_seq}"
                            ))
                        })?;
                    let opener_prev_member =
                        remote.members_by_epoch.get(&(next_seq - 1)).and_then(|ms| {
                            ms.iter().find(|m| m.device_key_pub == next_rec.opened_by)
                        });
                    let next_id = labyrinth::epoch::space_epoch_id(next_seq);
                    let opened = labyrinth::epoch::OpenedEpoch {
                        epoch_id: &next_id,
                        record: next_rec,
                        my_member,
                        opener,
                        opener_prev_member,
                    };
                    let next_secret = labyrinth::epoch::forward_chain(
                        &self.normalized_did,
                        &fwd_cur,
                        &fwd_pub,
                        &opened,
                        &restored.device.storage,
                        true,
                    )
                    .map_err(|e| {
                        MLSError::Cryptography(format!(
                            "forward_chain({} -> {next_seq}): {e}",
                            next_seq - 1
                        ))
                    })?;
                    recovered_roots.insert(next_seq, Zeroizing::new(*next_secret.root()));
                    fwd_pub = next_rec.public.clone();
                    fwd_cur = next_secret;
                }

                let mut latest_members = remote
                    .members_by_epoch
                    .get(&latest_seq)
                    .cloned()
                    .unwrap_or_default();
                if !latest_members
                    .iter()
                    .any(|m| m.device_key_pub == restored.device.public().device_key_pub)
                {
                    let vdev_mem = labyrinth::epoch::EpochMemberRecord {
                        seq: latest_seq,
                        device_key_pub: restored.device.public().device_key_pub,
                        device_mac: fwd_cur
                            .device_mac(&restored.device.public().device_key_pub, true),
                        encrypted_entropy: None,
                    };
                    latest_members.push(vdev_mem);
                }
                let mut continuing = Self::collect_continuing_epoch_devices(
                    &fwd_cur,
                    &latest_members,
                    &remote,
                    None,
                );
                let me_in_latest = latest_members.iter().any(|m| {
                    m.device_key_pub == me_secrets.public().device_key_pub
                        && labyrinth::epoch::verify_member(&fwd_cur, m, false).is_ok()
                });
                let (pending_next, opened_next) = self.hooks.with_labyrinth_rng(|| {
                    if me_in_latest {
                        labyrinth::epoch::open_next(
                            &self.normalized_did,
                            &fwd_cur,
                            &fwd_pub,
                            &latest_members,
                            &continuing,
                            &me_secrets,
                            &transport_signer,
                        )
                        .map_err(|e| MLSError::Cryptography(format!("restore epoch::open_next: {e}")))
                    } else {
                        continuing
                            .retain(|d| d.device_key_pub != me_secrets.public().device_key_pub);
                        labyrinth::epoch::open_next_enrolling(
                            &self.normalized_did,
                            &fwd_cur,
                            &fwd_pub,
                            &latest_members,
                            &continuing,
                            &me_secrets,
                            &transport_signer,
                        )
                        .map_err(|e| {
                            MLSError::Cryptography(format!(
                                "restore epoch::open_next_enrolling: {e}"
                            ))
                        })
                    }
                })?;
                self.publish_opened_epoch(&st_before.mailbox_space_uri, &opened_next, now_ms)?;
                let rotated_seq = pending_next.seq();
                recovered_roots.insert(rotated_seq, Zeroizing::new(*pending_next.root()));
                rotated_seq
            } else {
                st_before.epoch_seq.max(recovered_seq).saturating_add(1)
            }
        } else {
            st_before.epoch_seq.max(recovered_seq).saturating_add(1)
        };

        let status = self.db.write_tx(|tx| {
            tx.put_labyrinth_state("recovery_vdevice_id", &matched_vdev_id, now_ms)?;
            tx.put_labyrinth_state("mailbox_root_salt", &recovered_salt, now_ms)?;
            for (seq, root) in &recovered_roots {
                tx.put_labyrinth_state(&owner_epoch_root_key(*seq), root.as_slice(), now_ms)?;
            }

            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                MLSError::InvalidState("Labyrinth status not initialized".to_string())
            })?;
            let mut st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            st.epoch_seq = new_epoch_seq;
            st.has_recovery_code = true;
            if !st.active_device_ids.contains(&self.config.device_id) {
                st.active_device_ids.push(self.config.device_id.clone());
            }
            let _ = ensure_owner_epoch_root(tx, st.epoch_seq, now_ms, &self.hooks)?;

            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: format!("restore-epoch-{}", st.epoch_seq),
                op_type: "epoch_rotation".to_string(),
                epoch_seq: st.epoch_seq,
                state_json: serde_json::json!({
                    "trigger": "recovery_code_restore",
                    "recoveredEpochSeq": recovered_seq,
                })
                .to_string(),
                status: "completed".to_string(),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            })?;

            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                now_ms,
            )?;
            Ok(st)
        })?;

        self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
            epoch_seq: status.epoch_seq,
        });
        Ok(status)
    }

    fn load_status_and_owner_root(
        &self,
    ) -> Result<(LabyrinthBackupStatus, Zeroizing<[u8; 32]>), MLSError> {
        let maybe = self.db.read_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                MLSError::InvalidState("Labyrinth status not initialized".to_string())
            })?;
            let st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            let root_opt = tx.get_labyrinth_state(&owner_epoch_root_key(st.epoch_seq))?;
            Ok((st, root_opt))
        })?;
        if let Some(bytes) = maybe.1 {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok((maybe.0, Zeroizing::new(arr)));
            }
        }
        let now_ms = self.hooks.now_ms();
        let epoch_seq = maybe.0.epoch_seq;
        let root = self
            .db
            .write_tx(|tx| ensure_owner_epoch_root(tx, epoch_seq, now_ms, &self.hooks))?;
        Ok((maybe.0, root))
    }

    fn apply_space_writes(
        &self,
        space_uri: &str,
        writes: &[serde_json::Value],
    ) -> Result<PlatformHttpResponse, MLSError> {
        let endpoint = format!(
            "{}/xrpc/com.atproto.space.applyWrites",
            self.config.pds_endpoint.trim_end_matches('/')
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "repo": self.normalized_did,
            "space": space_uri,
            "validate": false,
            "writes": writes,
        }))
        .map_err(|e| MLSError::Internal(format!("serialize Space applyWrites: {e}")))?;
        self.transport.execute_http(PlatformHttpRequest {
            method: "POST".to_string(),
            url: endpoint,
            headers: vec![PlatformHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: Some(body),
        })
    }

    fn list_space_records_if_supported(
        &self,
        space_uri: &str,
        collection: &str,
    ) -> Result<Option<Vec<serde_json::Value>>, MLSError> {
        let base = self.config.pds_endpoint.trim_end_matches('/');
        let mut cursor: Option<String> = None;
        let mut all_values: Vec<serde_json::Value> = Vec::new();
        let mut saw_records_array = false;

        loop {
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            let mut url = format!(
                "{base}/xrpc/com.atproto.space.listRecords?space={}&repo={}&collection={}&limit=100",
                percent_encode_query_component(space_uri),
                percent_encode_query_component(&self.normalized_did),
                percent_encode_query_component(collection),
            );
            if let Some(ref c) = cursor {
                url.push_str("&cursor=");
                url.push_str(&percent_encode_query_component(c));
            }

            let resp = self.transport.execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url,
                headers: Vec::new(),
                body: None,
            })?;
            if resp.status >= 400 {
                return Err(MLSError::Internal(format!(
                    "com.atproto.space.listRecords({collection}) returned HTTP {}",
                    resp.status
                )));
            }
            let parsed: serde_json::Value = serde_json::from_slice(&resp.body)
                .map_err(|e| MLSError::Internal(format!("parse Space listRecords: {e}")))?;
            let Some(arr) = parsed.get("records").and_then(|v| v.as_array()) else {
                if !saw_records_array {
                    return Ok(None);
                }
                break;
            };
            saw_records_array = true;
            for entry in arr {
                if let Some(val) = entry.get("value") {
                    all_values.push(val.clone());
                }
            }
            match parsed
                .get("cursor")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                Some(next) if !arr.is_empty() => cursor = Some(next.to_string()),
                _ => break,
            }
        }

        Ok(Some(all_values))
    }

    pub(super) fn offline_flush_labyrinth_queue(&self) -> Result<u32, MLSError> {
        use labyrinth::sign::TransportSigner as _;

        let _outbox_guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("CatbirdMlsClient.outbox_flush_lock"))?;

        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }

        let (status, owner_root) = self.load_status_and_owner_root()?;
        if !status.backup_enabled {
            return Ok(0);
        }

        let pending_convos = self
            .db
            .read_tx(|tx| tx.list_labyrinth_queue_conversations())?;
        if pending_convos.is_empty() {
            return Ok(0);
        }

        if crate::buggify!("between_labyrinth_enqueue_and_flush") {
            return Err(MLSError::Internal(
                "sim buggify: between_labyrinth_enqueue_and_flush".to_string(),
            ));
        }

        let now_ms = self.hooks.now_ms();
        let transport_signer = load_or_create_transport_signer(&self.db, now_ms, &self.hooks)?;
        let mut mek_cache: std::collections::HashMap<String, labyrinth::mek::Mek> =
            std::collections::HashMap::new();
        let mut total_committed: u32 = 0;
        let mut first_err: Option<MLSError> = None;

        for convo_id in pending_convos {
            loop {
                if self.is_handle_closed() {
                    return Err(MLSError::ContextClosed);
                }
                let rows = self
                    .db
                    .read_tx(|tx| tx.list_labyrinth_queue(Some(&convo_id), 100))?;
                if rows.is_empty() {
                    break;
                }

                let mut committed_ids: Vec<String> = Vec::with_capacity(rows.len());
                let mut convo_err: Option<MLSError> = None;

                for row in &rows {
                    if self.is_handle_closed() {
                        convo_err = Some(MLSError::ContextClosed);
                        break;
                    }
                    let payload = match self.decode_queue_row(row) {
                        Ok(p) => p,
                        Err(e) => {
                            convo_err = Some(e);
                            break;
                        }
                    };
                    let convo_space = payload.space_uri.clone().unwrap_or_else(|| {
                        format!(
                            "at://{}/space/blue.catbird.labyrinth.conversation/{}-0",
                            payload.sequencer_did, payload.conversation_id
                        )
                    });

                    let mek = if let Some(m) = mek_cache.get(&payload.conversation_id) {
                        m.clone()
                    } else {
                        let m = ensure_convo_sender_mek(
                            &self.db,
                            &payload.conversation_id,
                            transport_signer.transport_public_key(),
                            now_ms,
                            &self.hooks,
                        )?;
                        mek_cache.insert(payload.conversation_id.clone(), m.clone());
                        m
                    };

                    let ts_ms = payload.created_at_ms.max(0) as u64;
                    let decoded_nonce_32: Option<[u8; 32]> = payload
                        .frame_nonce_b64
                        .as_ref()
                        .and_then(|nonce_b64| BASE64_STANDARD.decode(nonce_b64.as_bytes()).ok())
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());
                    if payload.sequencer_receipt_json.is_some() && decoded_nonce_32.is_none() {
                        convo_err = Some(MLSError::Cryptography(
                            "I13 offline archive receipt requires a 32-byte frame nonce".to_string(),
                        ));
                        break;
                    }

                    let item_seq_u64 = payload.seq.max(0) as u64;
                    let item_sub_seq = item_seq_u64 % 1_000;

                    let sealed_msg = if let (Some(nonce_32), Some(receipt_json)) =
                        (decoded_nonce_32, &payload.sequencer_receipt_json)
                    {
                        let stored_receipt: super::chat_wire::StoredArchivedReceipt =
                            match serde_json::from_str(receipt_json) {
                                Ok(r) => r,
                                Err(e) => {
                                    convo_err = Some(MLSError::Internal(format!(
                                        "parse StoredArchivedReceipt JSON: {e}"
                                    )));
                                    break;
                                }
                            };
                        let archived = match stored_receipt.to_labyrinth_archived() {
                            Ok(a) => a,
                            Err(e) => {
                                convo_err = Some(e);
                                break;
                            }
                        };
                        if let Err(e) = self.offline_verify_committed_frame(
                            &payload.conversation_id,
                            &payload.message_id,
                            &archived,
                            &nonce_32,
                            payload.labyrinth_frame_json.as_bytes(),
                        ) {
                            convo_err = Some(e);
                            break;
                        }
                        match self.hooks.with_labyrinth_rng(|| {
                            labyrinth::message::seal_sender_committed(
                                &mek,
                                &payload.conversation_id,
                                &payload.message_id,
                                ts_ms,
                                &nonce_32,
                                payload.labyrinth_frame_json.as_bytes(),
                                &archived,
                                &transport_signer,
                            )
                        }) {
                            Ok(s) => s,
                            Err(e) => {
                                convo_err = Some(MLSError::Cryptography(format!(
                                    "seal_sender_committed conversation Batch: {e}"
                                )));
                                break;
                            }
                        }
                    } else {
                        let sender_data: Zeroizing<Vec<u8>> = if let Some(nonce_32) =
                            decoded_nonce_32
                        {
                            let mut combined =
                                Vec::with_capacity(32 + payload.labyrinth_frame_json.len());
                            combined.extend_from_slice(&nonce_32);
                            combined.extend_from_slice(payload.labyrinth_frame_json.as_bytes());
                            Zeroizing::new(combined)
                        } else {
                            Zeroizing::new(payload.labyrinth_frame_json.as_bytes().to_vec())
                        };

                        let mut s = match self.hooks.with_labyrinth_rng(|| {
                            labyrinth::message::seal_sender(
                                &mek,
                                &payload.conversation_id,
                                &payload.message_id,
                                ts_ms,
                                &sender_data,
                                &transport_signer,
                            )
                        }) {
                            Ok(s) => s,
                            Err(e) => {
                                convo_err = Some(MLSError::Cryptography(format!(
                                    "seal_sender conversation Batch: {e}"
                                )));
                                break;
                            }
                        };
                        s.seq = Some(item_seq_u64);
                        s
                    };

                    let sender_batch = match labyrinth::records::Batch::from_messages(
                        &payload.conversation_id,
                        &[sealed_msg],
                        labyrinth::records::datetime_from_ms(ts_ms),
                    ) {
                        Ok(b) => b,
                        Err(e) => {
                            convo_err =
                                Some(MLSError::Internal(format!("Batch::from_messages: {e}")));
                            break;
                        }
                    };
                    let batch_val = match serde_json::to_value(&sender_batch) {
                        Ok(v) => v,
                        Err(e) => {
                            convo_err = Some(MLSError::Internal(format!("serialize Batch: {e}")));
                            break;
                        }
                    };
                    let tid = deterministic_tid(
                        payload.created_at_ms,
                        item_sub_seq,
                        &format!("batch:{}:{}", payload.conversation_id, row.item_id),
                    );
                    let rkey = format!("{item_seq_u64:016x}-{tid}");

                    if self.is_handle_closed() {
                        convo_err = Some(MLSError::ContextClosed);
                        break;
                    }
                    let primary_resp = match self.apply_space_writes(
                        &convo_space,
                        &[serde_json::json!({
                            "$type": "com.atproto.space.applyWrites#create",
                            "collection": labyrinth::records::nsid::BATCH,
                            "rkey": rkey,
                            "value": batch_val,
                        })],
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            convo_err = Some(e);
                            break;
                        }
                    };

                    if is_space_write_committed(&primary_resp) {
                        committed_ids.push(row.item_id.clone());
                        continue;
                    }

                    if matches!(primary_resp.status, 401 | 403 | 404) {
                        if self.is_handle_closed() {
                            convo_err = Some(MLSError::ContextClosed);
                            break;
                        }
                        let owner_msg = match self.hooks.with_labyrinth_rng(|| {
                            labyrinth::message::seal_owner_attributed(
                                &owner_root,
                                status.epoch_seq,
                                &payload.conversation_id,
                                &payload.message_id,
                                ts_ms,
                                &payload.sender_did,
                                payload.labyrinth_frame_json.as_bytes(),
                            )
                        }) {
                            Ok(m) => m,
                            Err(e) => {
                                convo_err = Some(MLSError::Cryptography(format!(
                                    "seal_owner_attributed fallback: {e}"
                                )));
                                break;
                            }
                        };
                        let owner_batch = match labyrinth::records::OwnerBatch::from_messages(
                            &[owner_msg],
                            labyrinth::records::datetime_from_ms(ts_ms),
                        ) {
                            Ok(b) => b,
                            Err(e) => {
                                convo_err = Some(MLSError::Internal(format!(
                                    "OwnerBatch::from_messages: {e}"
                                )));
                                break;
                            }
                        };
                        let owner_batch_val = match serde_json::to_value(&owner_batch) {
                            Ok(v) => v,
                            Err(e) => {
                                convo_err = Some(MLSError::Internal(format!(
                                    "serialize OwnerBatch: {e}"
                                )));
                                break;
                            }
                        };
                        let fb_rkey = deterministic_tid(
                            payload.created_at_ms,
                            item_sub_seq,
                            &format!("fb:{}:{}", payload.conversation_id, row.item_id),
                        );
                        match self.apply_space_writes(
                            &status.mailbox_space_uri,
                            &[serde_json::json!({
                                "$type": "com.atproto.space.applyWrites#create",
                                "collection": labyrinth::records::nsid::OWNER_BATCH,
                                "rkey": fb_rkey,
                                "value": owner_batch_val,
                            })],
                        ) {
                            Ok(fb_resp) if is_space_write_committed(&fb_resp) => {
                                committed_ids.push(row.item_id.clone());
                            }
                            Ok(fb_resp) => {
                                convo_err = Some(MLSError::Internal(format!(
                                    "personal mailbox OwnerBatch fallback returned HTTP {}",
                                    fb_resp.status
                                )));
                                break;
                            }
                            Err(e) => {
                                convo_err = Some(e);
                                break;
                            }
                        }
                    } else {
                        convo_err = Some(MLSError::Internal(format!(
                            "conversation Space applyWrites returned HTTP {}",
                            primary_resp.status
                        )));
                        break;
                    }
                }

                if !committed_ids.is_empty() && !self.is_handle_closed() {
                    self.db.write_tx(|tx| {
                        for id in &committed_ids {
                            tx.dequeue_labyrinth_item(id)?;
                        }
                        Ok(())
                    })?;
                    total_committed = total_committed.saturating_add(committed_ids.len() as u32);
                }

                if matches!(convo_err, Some(MLSError::ContextClosed)) || self.is_handle_closed() {
                    return Err(MLSError::ContextClosed);
                }
                if let Some(err) = convo_err {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                    break;
                }
                if committed_ids.is_empty() {
                    break;
                }
            }
        }

        if let Some(err) = first_err {
            return Err(err);
        }

        Ok(total_committed)
    }

    pub(super) fn offline_rescue_conversation_on_kick(
        &self,
        conversation_id: &str,
    ) -> Result<u32, MLSError> {
        let _outbox_guard = self
            .outbox_flush_lock
            .lock()
            .map_err(|_| MLSError::lock_poisoned("CatbirdMlsClient.outbox_flush_lock"))?;

        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }

        let (mut cached_msgs, queued_rows) = self.db.read_tx(|tx| {
            let mut all_msgs: Vec<MessageRow> = Vec::new();
            let mut after_rowid: i64 = 0;
            let mut msg_stmt = tx
                .conn()
                .prepare(
                    "SELECT rowid, message_id, conversation_id, group_id, epoch, seq, sender_did, \
                            sender_device_id, plaintext_json, created_at_ms, is_own \
                     FROM messages WHERE conversation_id = ?1 AND rowid > ?2 \
                     ORDER BY rowid ASC LIMIT 500",
                )
                .map_err(|e| MLSError::Internal(format!("prepare rescue messages query: {e}")))?;
            loop {
                let rows = msg_stmt
                    .query_map(rusqlite::params![conversation_id, after_rowid], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            MessageRow {
                                message_id: row.get(1)?,
                                conversation_id: row.get(2)?,
                                group_id: row.get(3)?,
                                epoch: row.get(4)?,
                                seq: row.get(5)?,
                                sender_did: row.get(6)?,
                                sender_device_id: row.get(7)?,
                                plaintext_json: row.get(8)?,
                                created_at_ms: row.get(9)?,
                                is_own: row.get::<_, i64>(10)? != 0,
                            },
                        ))
                    })
                    .map_err(|e| {
                        MLSError::Internal(format!("execute rescue messages query: {e}"))
                    })?;
                let mut page_len = 0usize;
                for r in rows {
                    let (rid, msg) = r.map_err(|e| {
                        MLSError::Internal(format!("read rescue message row: {e}"))
                    })?;
                    after_rowid = rid;
                    all_msgs.push(msg);
                    page_len += 1;
                }
                if page_len < 500 {
                    break;
                }
            }

            let mut stmt = tx
                .conn()
                .prepare(
                    "SELECT item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms \
                     FROM labyrinth_queue WHERE conversation_id = ?1 ORDER BY seq ASC, item_id ASC",
                )
                .map_err(|e| MLSError::Internal(format!("prepare rescue queue query: {e}")))?;
            let queued_iter = stmt
                .query_map([conversation_id], |row| {
                    Ok(LabyrinthQueueRow {
                        item_id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        group_id_hex: row.get(2)?,
                        seq: row.get(3)?,
                        payload_bytes: row.get(4)?,
                        created_at_ms: row.get(5)?,
                    })
                })
                .map_err(|e| MLSError::Internal(format!("execute rescue queue query: {e}")))?;
            let mut all_queued = Vec::new();
            for r in queued_iter {
                all_queued
                    .push(r.map_err(|e| MLSError::Internal(format!("read rescue queue row: {e}")))?);
            }
            Ok((all_msgs, all_queued))
        })?;
        cached_msgs.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.seq.cmp(&b.seq))
                .then_with(|| a.message_id.cmp(&b.message_id))
        });

        let (status, owner_root) = self.load_status_and_owner_root()?;
        if !status.backup_enabled {
            return Ok(0);
        }

        let mut seen_ids = std::collections::HashSet::new();
        let mut sealed_items = Vec::new();
        for msg in &cached_msgs {
            if !seen_ids.insert(msg.message_id.clone()) {
                continue;
            }
            let frame_json = canonical_labyrinth_frame_json(&msg.plaintext_json);
            let owner_msg = self
                .hooks
                .with_labyrinth_rng(|| {
                    labyrinth::message::seal_owner_attributed(
                        &owner_root,
                        status.epoch_seq,
                        conversation_id,
                        &msg.message_id,
                        msg.created_at_ms.max(0) as u64,
                        &msg.sender_did,
                        frame_json.as_bytes(),
                    )
                })
                .map_err(|e| MLSError::Cryptography(format!("seal_owner_attributed: {e}")))?;
            sealed_items.push(owner_msg);
        }

        for row in &queued_rows {
            let payload = self.decode_queue_row(row)?;
            if !seen_ids.insert(payload.message_id.clone()) {
                continue;
            }
            let owner_msg = self
                .hooks
                .with_labyrinth_rng(|| {
                    labyrinth::message::seal_owner_attributed(
                        &owner_root,
                        status.epoch_seq,
                        conversation_id,
                        &payload.message_id,
                        payload.created_at_ms.max(0) as u64,
                        &payload.sender_did,
                        payload.labyrinth_frame_json.as_bytes(),
                    )
                })
                .map_err(|e| MLSError::Cryptography(format!("seal_owner_attributed: {e}")))?;
            sealed_items.push(owner_msg);
        }

        if sealed_items.is_empty() {
            return Ok(0);
        }

        let now_ms = self.hooks.now_ms();
        let created_at = labyrinth::records::datetime_from_ms(now_ms.max(0) as u64);
        for (chunk_idx, chunk) in sealed_items
            .chunks(labyrinth::records::MAX_BATCH_ITEMS)
            .enumerate()
        {
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            let first_ts = chunk.first().map(|m| m.timestamp as i64).unwrap_or(now_ms);
            let first_id = chunk.first().map(|m| m.message_id.as_str()).unwrap_or("0");
            let rkey = deterministic_tid(
                first_ts,
                chunk_idx as u64,
                &format!("rescue:{conversation_id}:{chunk_idx}:{first_id}"),
            );
            let batch = labyrinth::records::OwnerBatch::from_messages(chunk, created_at.clone())
                .map_err(|e| MLSError::Internal(format!("OwnerBatch::from_messages: {e}")))?;
            let batch_val = serde_json::to_value(&batch)
                .map_err(|e| MLSError::Internal(format!("serialize OwnerBatch: {e}")))?;
            let resp = self.apply_space_writes(
                &status.mailbox_space_uri,
                &[serde_json::json!({
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": labyrinth::records::nsid::OWNER_BATCH,
                    "rkey": rkey,
                    "value": batch_val,
                })],
            )?;
            if !is_space_write_committed(&resp) {
                return Err(MLSError::Internal(format!(
                    "rescue_conversation_on_kick applyWrites returned HTTP {}",
                    resp.status
                )));
            }
        }

        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        self.db.write_tx(|tx| {
            for row in &queued_rows {
                tx.dequeue_labyrinth_item(&row.item_id)?;
            }
            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: format!("kick-rescue-{conversation_id}-{}", status.epoch_seq),
                op_type: "kick_rescue".to_string(),
                epoch_seq: status.epoch_seq,
                state_json: serde_json::json!({
                    "conversationId": conversation_id,
                    "rescuedCount": sealed_items.len(),
                })
                .to_string(),
                status: "completed".to_string(),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            })?;
            Ok(())
        })?;

        Ok(sealed_items.len() as u32)
    }

    fn offline_verify_committed_frame<'r>(
        &self,
        conversation_id: &str,
        message_id: &str,
        receipt: &'r labyrinth::message::ArchivedReceipt,
        frame_nonce: &[u8; 32],
        frame: &[u8],
    ) -> Result<&'r str, MLSError> {
        let signed = &receipt.signed;
        if signed.payload.conversation_id != conversation_id
            || signed.payload.entry_id != message_id
        {
            return Err(MLSError::Cryptography(
                "I13 offline archive receipt coordinates mismatch".to_string(),
            ));
        }
        let conversation = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| {
                MLSError::Cryptography(
                    "I13 offline archive requires a pinned conversation sequencer".to_string(),
                )
            })?;
        let key = self
            .resolve_sequencer_receipt_key(&conversation.sequencer_did, "#mls-receipt-1")?
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "I13 offline archive cannot resolve `{}` receipt key",
                    conversation.sequencer_did
                ))
            })?;
        labyrinth_protocol::receipt::verify_sequencer_receipt_sec1(
            &key,
            &conversation.sequencer_did,
            signed,
        )
        .map_err(|e| MLSError::Cryptography(format!("I13 offline archive receipt: {e}")))?;
        labyrinth_protocol::receipt::verify_archived_item_commitment(signed, frame_nonce, frame)
            .map_err(|e| MLSError::Cryptography(format!("I13 offline archive commitment: {e}")))?;
        let (sender_did, _) = signed
            .payload
            .split_sender_device()
            .map_err(|e| MLSError::Cryptography(format!("I13 offline archive sender: {e}")))?;
        Ok(sender_did)
    }

    fn offline_open_owner_message(
        &self,
        msg: &labyrinth::message::OwnerMessage,
    ) -> Result<Option<(Option<String>, Vec<u8>)>, MLSError> {
        let root_bytes = self
            .db
            .read_tx(|tx| tx.get_labyrinth_state(&owner_epoch_root_key(msg.epoch_seq)))?
            .ok_or_else(|| {
                MLSError::InvalidState(format!(
                    "missing owner_epoch_root for epoch {}",
                    msg.epoch_seq
                ))
            })?;
        let root: Zeroizing<[u8; 32]> = Zeroizing::new(
            root_bytes.as_slice().try_into().map_err(|_| {
                MLSError::Internal("invalid owner_epoch_root length".to_string())
            })?,
        );
        let opened = labyrinth::message::open_owner_content(&root, msg)
            .map_err(|e| MLSError::Cryptography(format!("open_owner_content: {e}")))?;
        if msg.sequencer_receipt.is_some()
            && !matches!(&opened, labyrinth::message::OwnerContent::CommittedFrame { .. })
        {
            return Err(MLSError::Cryptography(
                "I13 offline archive receipt requires a committed frame".to_string(),
            ));
        }
        match opened {
            labyrinth::message::OwnerContent::Frame(frame) => Ok(Some((None, frame))),
            labyrinth::message::OwnerContent::AttributedFrame { sender_did, frame } => {
                Ok(Some((Some(sender_did), frame)))
            }
            labyrinth::message::OwnerContent::CommittedFrame { frame_nonce, frame } => {
                let receipt = msg.sequencer_receipt.as_ref().ok_or_else(|| {
                    MLSError::Cryptography(
                        "I13 offline committed frame is missing its receipt".to_string(),
                    )
                })?;
                if msg.seq != Some(receipt.signed.payload.seq) {
                    return Err(MLSError::Cryptography(
                        "I13 offline archive receipt sequence mismatch".to_string(),
                    ));
                }
                let sender = self.offline_verify_committed_frame(
                    &msg.thread_id,
                    &msg.message_id,
                    receipt,
                    &frame_nonce,
                    &frame,
                )?;
                Ok(Some((Some(sender.to_string()), frame)))
            }
            labyrinth::message::OwnerContent::Tombstone { .. } => Ok(None),
        }
    }

    pub(super) fn offline_open_rescued_owner_batch(
        &self,
        batch_json: &[u8],
    ) -> Result<Vec<(String, Option<String>, Vec<u8>)>, MLSError> {
        let batch: labyrinth::records::OwnerBatch = serde_json::from_slice(batch_json)
            .map_err(|e| MLSError::Internal(format!("parse OwnerBatch: {e}")))?;
        let msgs = batch
            .to_messages()
            .map_err(|e| MLSError::Internal(format!("OwnerBatch::to_messages: {e}")))?;
        let mut out = Vec::with_capacity(msgs.len());
        for msg in msgs {
            if let Some((sender, frame)) = self.offline_open_owner_message(&msg)? {
                out.push((msg.message_id, sender, frame));
            }
        }
        Ok(out)
    }

    pub(super) fn offline_restore_conversation_from_owner_mailbox(
        &self,
        conversation_id: &str,
    ) -> Result<u32, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let status = self.labyrinth_status()?;
        let Some(records) = self.list_space_records_if_supported(
            &status.mailbox_space_uri,
            labyrinth::records::nsid::OWNER_BATCH,
        )?
        else {
            return Ok(0);
        };

        let mut recovered_items: Vec<(u64, String, String, String)> = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        for rec_val in records {
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            let batch: labyrinth::records::OwnerBatch = serde_json::from_value(rec_val)
                .map_err(|e| MLSError::Internal(format!("parse OwnerBatch: {e}")))?;
            let msgs = batch
                .to_messages()
                .map_err(|e| MLSError::Internal(format!("OwnerBatch::to_messages: {e}")))?;
            for msg in msgs {
                if msg.thread_id != conversation_id {
                    continue;
                }
                let Some((sender_opt, frame_bytes)) = self.offline_open_owner_message(&msg)? else {
                    continue;
                };
                let Some(sender_did) = sender_opt else {
                    continue;
                };
                if !seen_ids.insert(msg.message_id.clone()) {
                    continue;
                }
                let plaintext_json = String::from_utf8(frame_bytes)
                    .map_err(|e| MLSError::Internal(format!("restored frame is not UTF-8: {e}")))?;
                recovered_items.push((
                    msg.timestamp,
                    msg.message_id,
                    sender_did,
                    plaintext_json,
                ));
            }
        }

        if recovered_items.is_empty() {
            return Ok(0);
        }
        recovered_items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let now_ms = self.hooks.now_ms();
        let imported = self.db.write_tx(|tx| {
            let existing_convo = tx.get_conversation(conversation_id)?;
            let group_id = existing_convo
                .as_ref()
                .map(|c| c.group_id.clone())
                .unwrap_or_else(|| Sha256::digest(conversation_id.as_bytes()).to_vec());
            let max_msg_seq: i64 = tx
                .conn()
                .query_row(
                    "SELECT COALESCE(MAX(seq), 0) FROM messages WHERE conversation_id = ?1",
                    [conversation_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let mut next_seq = max_msg_seq;
            let mut count = 0u32;

            for (ts_ms, msg_id, sender_did, plaintext_json) in &recovered_items {
                if tx.get_message(msg_id)?.is_some() {
                    continue;
                }
                next_seq = next_seq.saturating_add(1);
                let is_own = sender_did == &self.normalized_did;
                tx.insert_message(&MessageRow {
                    message_id: msg_id.clone(),
                    conversation_id: conversation_id.to_string(),
                    group_id: group_id.clone(),
                    epoch: 0,
                    seq: next_seq,
                    sender_did: sender_did.clone(),
                    sender_device_id: "restored-labyrinth".to_string(),
                    plaintext_json: plaintext_json.clone(),
                    created_at_ms: *ts_ms as i64,
                    is_own,
                })?;
                count = count.saturating_add(1);
            }

            if existing_convo.is_none() {
                tx.upsert_conversation(&ConversationRow {
                    conversation_id: conversation_id.to_string(),
                    group_id,
                    generation: 0,
                    epoch: 0,
                    last_seq: 0,
                    sequencer_did: self.config.home_ds_did.clone(),
                    space_uri: None,
                    title: None,
                    unread_count: 0,
                    updated_at_ms: now_ms,
                })?;
            }

            Ok(count)
        })?;

        if imported > 0 {
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            self.notify(PlatformChangeEvent::MessagesUpdated {
                conversation_id: conversation_id.to_string(),
            });
        }
        Ok(imported)
    }
}
