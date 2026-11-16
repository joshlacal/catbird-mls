//! Version-3 recovery-share transport. The code-derived fetch token is sent
//! only after the caller's home service DID and explicit HPKE capability have
//! been checked. The private response is opened with a fresh single-use key.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use hpke_rs::{hpke_types::*, Hpke, Mode};
use hpke_rs_libcrux::HpkeLibcrux;
use labyrinth::recovery_share::{RecoveryShare, ShareStore};
use labyrinth::virtual_device::Mechanism;
use labyrinth::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::state::StateVault;
use super::transport::{map_xrpc_error, GatewayXrpcTransport, XrpcTransportError};

const CAPABILITY_NSID: &str = "blue.catbird.labyrinth.getRecoveryShareCapabilities";
const PUT_NSID: &str = "blue.catbird.labyrinth.putRecoveryShare";
const GET_NSID: &str = "blue.catbird.labyrinth.getRecoveryShare";
const DELETE_NSID: &str = "blue.catbird.labyrinth.deleteRecoveryShare";
const EXPECTED_SUITE: &str = "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM";
const HPKE_INFO: &[u8] = b"catbird.labyrinth.recovery_share.seal.v1";

fn service_pin_key(did: &str) -> String {
    format!("recovery_share_home_service:{did}")
}

fn diagnostic_key_id_key(did: &str) -> String {
    format!("recovery_share_last_key_id:{did}")
}

/// Persist an independently proved declaration target. The configured home
/// service must agree with this value before any share operation runs.
pub fn pin_proven_home_service(
    placements: &dyn StateVault,
    did: &str,
    proven_home_ds_did: &str,
) -> Result<()> {
    if !proven_home_ds_did.starts_with("did:") || proven_home_ds_did.contains('#') {
        return Err(Error::Malformed("invalid recovery-share home service DID"));
    }
    let key = service_pin_key(did);
    let current = placements
        .load(&key)
        .map_err(|e| Error::Backend(format!("recovery-share service pin: {e}")))?;
    if let Some(saved) = current {
        if saved != proven_home_ds_did.as_bytes() {
            return Err(Error::Backend(
                "recovery-share home service changed from its proven pin".into(),
            ));
        }
        return Ok(());
    }
    if !placements
        .compare_exchange(&key, None, proven_home_ds_did.as_bytes())
        .map_err(|e| Error::Backend(format!("recovery-share service pin: {e}")))?
    {
        let raced = placements
            .load(&key)
            .map_err(|e| Error::Backend(format!("recovery-share service pin: {e}")))?;
        if raced.as_deref() != Some(proven_home_ds_did.as_bytes()) {
            return Err(Error::Backend(
                "recovery-share home service pin changed concurrently".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Capability {
    supported: bool,
    version: u8,
    hpke_suite: String,
    key_id: String,
}

#[derive(Serialize)]
struct BytesOut<'a> {
    #[serde(rename = "$bytes")]
    value: &'a str,
}

#[derive(Deserialize)]
struct BytesIn {
    #[serde(rename = "$bytes")]
    value: String,
}

impl BytesIn {
    fn decode<const N: usize>(&self) -> Result<[u8; N]> {
        let bytes = STANDARD_NO_PAD
            .decode(&self.value)
            .or_else(|_| STANDARD.decode(&self.value))
            .map_err(|_| Error::Malformed("recovery-share $bytes encoding"))?;
        bytes
            .try_into()
            .map_err(|_| Error::Malformed("recovery-share $bytes length"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetShareOutput {
    vdevice_id: BytesIn,
    enc: BytesIn,
    sealed_share: BytesIn,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareMutationOutput {
    vdevice_id: BytesIn,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetShareInput<'a> {
    vdevice_id: BytesOut<'a>,
    fetch_token: BytesOut<'a>,
    recipient_public_key: BytesOut<'a>,
    purpose: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PutShareInput<'a> {
    vdevice_id: BytesOut<'a>,
    share: BytesOut<'a>,
    fetch_verifier: BytesOut<'a>,
    mechanism: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteShareInput<'a> {
    vdevice_id: BytesOut<'a>,
}

/// A home-DS share store. `verify_vids` is only for choosing the server's
/// `verify` event after a same-process put; it grants no access.
pub struct GatewayRecoveryShareStore {
    did: String,
    transport: Arc<GatewayXrpcTransport>,
    placements: Arc<dyn StateVault>,
    verify_vids: Mutex<BTreeSet<[u8; 16]>>,
}

impl GatewayRecoveryShareStore {
    pub fn new(
        did: String,
        transport: Arc<GatewayXrpcTransport>,
        placements: Arc<dyn StateVault>,
    ) -> Self {
        Self {
            did,
            transport,
            placements,
            verify_vids: Mutex::new(BTreeSet::new()),
        }
    }

    fn check_service_pin(&self) -> Result<()> {
        let configured = self
            .transport
            .home_ds_did()
            .ok_or(Error::NotSupported("recovery-share home service pin"))?;
        let pinned = self
            .placements
            .load(&service_pin_key(&self.did))
            .map_err(|e| Error::Backend(format!("recovery-share service pin: {e}")))?
            .ok_or(Error::NotSupported("recovery-share home service proof"))?;
        if pinned != configured.as_bytes() {
            return Err(Error::Backend(
                "recovery-share home service differs from its proven pin".into(),
            ));
        }
        Ok(())
    }

    async fn check_capability(&self) -> Result<()> {
        self.check_service_pin()?;
        let raw = self
            .transport
            .query(CAPABILITY_NSID, &[])
            .await
            .map_err(map_xrpc_error)?;
        let capability: Capability = serde_json::from_slice(&raw)
            .map_err(|_| Error::Malformed("recovery-share capability response"))?;
        if !capability.supported
            || capability.version != 1
            || capability.hpke_suite != EXPECTED_SUITE
            || capability.key_id.is_empty()
            || capability.key_id.len() > 128
        {
            return Err(Error::NotSupported("recovery-share service capability"));
        }
        // The KEK id is operational metadata, not a trust anchor: a server
        // may rotate its KEK without invalidating its DID or HPKE suite.
        let key = diagnostic_key_id_key(&self.did);
        let previous = self
            .placements
            .load(&key)
            .map_err(|e| Error::Backend(format!("recovery-share key id: {e}")))?;
        if previous.as_deref() != Some(capability.key_id.as_bytes()) {
            let swapped = self
                .placements
                .compare_exchange(&key, previous.as_deref(), capability.key_id.as_bytes())
                .map_err(|e| Error::Backend(format!("recovery-share key id: {e}")))?;
            if !swapped {
                return Err(Error::Backend(
                    "recovery-share key id changed concurrently".into(),
                ));
            }
        }
        Ok(())
    }

    fn parse_mutation(&self, raw: &[u8], expected_vid: &[u8; 16]) -> Result<()> {
        let result: ShareMutationOutput = serde_json::from_slice(raw)
            .map_err(|_| Error::Malformed("recovery-share mutation response"))?;
        if &result.vdevice_id.decode::<16>()? != expected_vid {
            return Err(Error::Malformed(
                "recovery-share response vdeviceId mismatch",
            ));
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ShareStore for GatewayRecoveryShareStore {
    async fn put_share(
        &self,
        vdevice_id: &[u8; 16],
        share: &RecoveryShare,
        fetch_verifier: &[u8; 32],
        mechanism: Mechanism,
    ) -> Result<()> {
        self.check_capability().await?;
        let mechanism = match mechanism {
            Mechanism::Code => "code",
            Mechanism::Passkey => "passkey",
            _ => return Err(Error::NotSupported("recovery-share mechanism")),
        };
        let vid = STANDARD_NO_PAD.encode(vdevice_id);
        let share_b64 = Zeroizing::new(STANDARD_NO_PAD.encode(share.as_bytes()));
        let verifier = STANDARD_NO_PAD.encode(fetch_verifier);
        let payload = Zeroizing::new(
            serde_json::to_vec(&PutShareInput {
                vdevice_id: BytesOut { value: &vid },
                share: BytesOut { value: &share_b64 },
                fetch_verifier: BytesOut { value: &verifier },
                mechanism,
            })
            .map_err(|_| Error::Malformed("recovery-share put request"))?,
        );
        let raw = self
            .transport
            .procedure(
                PUT_NSID,
                &payload,
                super::transport::deterministic_op_id(PUT_NSID, &payload),
            )
            .await
            .map_err(map_xrpc_error)?;
        self.parse_mutation(&raw, vdevice_id)?;
        self.verify_vids
            .lock()
            .map_err(|_| Error::Backend("recovery-share verify set poisoned".into()))?
            .insert(*vdevice_id);
        Ok(())
    }

    async fn get_share(
        &self,
        vdevice_id: &[u8; 16],
        fetch_token: &[u8; 32],
    ) -> Result<Option<RecoveryShare>> {
        // This signed read and exact suite check happen before the token is
        // serialized or sent to the home DS.
        self.check_capability().await?;
        let mut hpke = Hpke::<HpkeLibcrux>::new(
            Mode::Base,
            KemAlgorithm::DhKem25519,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes256Gcm,
        );
        let (secret, public) = hpke
            .generate_key_pair()
            .map_err(|_| Error::Rng)?
            .into_keys();
        let recipient_key = public.as_slice();
        if recipient_key.len() != 32 {
            return Err(Error::Malformed("recovery-share recipient key length"));
        }
        let vid = STANDARD_NO_PAD.encode(vdevice_id);
        let token = Zeroizing::new(STANDARD_NO_PAD.encode(fetch_token));
        let recipient = STANDARD_NO_PAD.encode(recipient_key);
        let purpose = if self
            .verify_vids
            .lock()
            .map_err(|_| Error::Backend("recovery-share verify set poisoned".into()))?
            .remove(vdevice_id)
        {
            "verify"
        } else {
            "restore"
        };
        let payload = Zeroizing::new(
            serde_json::to_vec(&GetShareInput {
                vdevice_id: BytesOut { value: &vid },
                fetch_token: BytesOut { value: &token },
                recipient_public_key: BytesOut { value: &recipient },
                purpose,
            })
            .map_err(|_| Error::Malformed("recovery-share get request"))?,
        );
        let raw = match self
            .transport
            .procedure(
                GET_NSID,
                &payload,
                super::transport::deterministic_op_id(GET_NSID, &payload),
            )
            .await
        {
            Ok(raw) => raw,
            Err(XrpcTransportError {
                status: 404,
                error: Some(ref name),
                ..
            }) if name == "RecoveryShareUnavailable" => return Ok(None),
            Err(error) => return Err(map_xrpc_error(error)),
        };
        let response: GetShareOutput = serde_json::from_slice(&raw)
            .map_err(|_| Error::Malformed("recovery-share get response"))?;
        if response.vdevice_id.decode::<16>()? != *vdevice_id {
            return Err(Error::Malformed(
                "recovery-share response vdeviceId mismatch",
            ));
        }
        let enc = response.enc.decode::<32>()?;
        let sealed = response.sealed_share.decode::<48>()?;
        let mut aad = Vec::with_capacity(self.did.len() + 1 + vdevice_id.len());
        aad.extend_from_slice(self.did.as_bytes());
        aad.push(0);
        aad.extend_from_slice(vdevice_id);
        let clear = Zeroizing::new(
            hpke.open(&enc, &secret, HPKE_INFO, &aad, &sealed, None, None, None)
                .map_err(|_| Error::Decrypt)?,
        );
        let share_bytes: [u8; 32] = clear
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed("recovery-share plaintext length"))?;
        Ok(Some(RecoveryShare::from_bytes(share_bytes)))
    }

    async fn delete_share(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.check_capability().await?;
        let vid = STANDARD_NO_PAD.encode(vdevice_id);
        let payload = serde_json::to_vec(&DeleteShareInput {
            vdevice_id: BytesOut { value: &vid },
        })
        .map_err(|_| Error::Malformed("recovery-share delete request"))?;
        match self
            .transport
            .procedure(
                DELETE_NSID,
                &payload,
                super::transport::deterministic_op_id(DELETE_NSID, &payload),
            )
            .await
        {
            Ok(raw) => self.parse_mutation(&raw, vdevice_id),
            Err(XrpcTransportError {
                status: 404,
                error: Some(ref name),
                ..
            }) if name == "RecoveryShareNotFound" => Ok(()),
            Err(error) => Err(map_xrpc_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::labyrinth::signer::ChatKeySigner;
    use crate::labyrinth::LabyrinthRequest;
    use crate::orchestrator::canonical_transport::{GatewayResponse, PreparedRequest};
    use crate::MLSError;

    #[derive(Default)]
    struct Vault(Mutex<BTreeMap<String, Vec<u8>>>);

    impl StateVault for Vault {
        fn load(&self, key: &str) -> std::result::Result<Option<Vec<u8>>, MLSError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }

        fn compare_exchange(
            &self,
            key: &str,
            expected: Option<&[u8]>,
            next: &[u8],
        ) -> std::result::Result<bool, MLSError> {
            let mut values = self.0.lock().unwrap();
            if values.get(key).map(Vec::as_slice) != expected {
                return Ok(false);
            }
            values.insert(key.to_owned(), next.to_vec());
            Ok(true)
        }

        fn delete(&self, key: &str) -> std::result::Result<(), MLSError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    struct Signer;

    impl ChatKeySigner for Signer {
        fn public_key(&self) -> [u8; 32] {
            [3; 32]
        }

        fn sign(&self, _message: &[u8]) -> std::result::Result<[u8; 64], String> {
            Ok([4; 64])
        }
    }

    #[derive(Default)]
    struct Gateway {
        key_id: Mutex<String>,
        supported: Mutex<bool>,
        requests: Mutex<Vec<LabyrinthRequest>>,
    }

    #[async_trait::async_trait]
    impl super::super::transport::LabyrinthGateway for Gateway {
        async fn submit_labyrinth(
            &self,
            request: LabyrinthRequest,
        ) -> std::result::Result<GatewayResponse, String> {
            let nsid = request.nsid.clone();
            self.requests.lock().unwrap().push(request);
            match nsid.as_str() {
                CAPABILITY_NSID => Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({
                        "supported": *self.supported.lock().unwrap(),
                        "version": 1,
                        "hpkeSuite": EXPECTED_SUITE,
                        "keyId": self.key_id.lock().unwrap().as_str(),
                    }))
                    .unwrap(),
                }),
                GET_NSID => Ok(GatewayResponse {
                    status: 404,
                    content_type: Some("application/json".into()),
                    body: br#"{"error":"RecoveryShareUnavailable"}"#.to_vec(),
                }),
                _ => panic!("unexpected recovery-share endpoint: {nsid}"),
            }
        }

        async fn submit_canonical(
            &self,
            _request: PreparedRequest,
            _headers: Vec<(String, String)>,
        ) -> std::result::Result<GatewayResponse, String> {
            panic!("recovery-share calls must use the Labyrinth route")
        }
    }

    #[tokio::test]
    async fn fetch_token_waits_for_proven_home_and_signed_capability() {
        const DID: &str = "did:plc:recoverytest";
        const HOME: &str = "did:web:home.example";
        let vault = Arc::new(Vault::default());
        let gateway = Arc::new(Gateway::default());
        *gateway.key_id.lock().unwrap() = "kek-1".into();
        let transport = Arc::new(
            GatewayXrpcTransport::new(
                gateway.clone(),
                Arc::new(Signer),
                DID.into(),
                "device-a".into(),
            )
            .with_home_ds_did(HOME.into()),
        );
        let store = GatewayRecoveryShareStore::new(DID.into(), transport, vault.clone());
        let vid = [5; 16];
        let token = [6; 32];

        assert!(store.get_share(&vid, &token).await.is_err());
        assert!(gateway.requests.lock().unwrap().is_empty());

        pin_proven_home_service(vault.as_ref(), DID, HOME).unwrap();
        assert!(store.get_share(&vid, &token).await.is_err());
        let requests = gateway.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].nsid, CAPABILITY_NSID);
        assert_eq!(requests[0].method, "GET");
        assert!(requests[0].body.is_none());
        assert!(requests[0]
            .headers
            .iter()
            .any(|(name, _)| name == super::super::write_auth::READ_HEADER));

        *gateway.supported.lock().unwrap() = true;
        assert!(store.get_share(&vid, &token).await.unwrap().is_none());
        let requests = gateway.requests.lock().unwrap().clone();
        assert_eq!(requests[1].nsid, CAPABILITY_NSID);
        assert_eq!(requests[2].nsid, GET_NSID);
        assert_eq!(requests[2].method, "POST");
        let body: serde_json::Value =
            serde_json::from_slice(requests[2].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["fetchToken"]["$bytes"], STANDARD_NO_PAD.encode(token));
        assert_eq!(body["vdeviceId"]["$bytes"], STANDARD_NO_PAD.encode(vid));
        assert_eq!(body["purpose"], "restore");

        *gateway.key_id.lock().unwrap() = "kek-2".into();
        assert!(store.get_share(&vid, &token).await.unwrap().is_none());
        assert_eq!(
            vault.load(&diagnostic_key_id_key(DID)).unwrap().unwrap(),
            b"kek-2"
        );
    }
}
