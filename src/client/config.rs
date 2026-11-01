//! Client configuration, DID hashing (`sha256(normalized_did)`), and pre-cutover
//! App Group / local data directory hygiene (`Spec §5 I8`, `Spec §6.1`, `Spec §9 Step 5`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::MLSError;

/// Configuration for opening a per-account [`super::CatbirdMlsClient`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct CatbirdMlsClientConfig {
    /// Root storage directory (`<AppGroup>` on iOS/macOS, internal files dir on Android,
    /// app data dir on desktop/CLI). Databases live at `<storage_root>/catbird-mls/<did_hash>.db`.
    pub storage_root: String,
    /// Account DID (`did:plc:...` or `did:web:...`).
    pub account_did: String,
    /// Logical device identifier (`dev-...`).
    pub device_id: String,
    /// User's declared `#atproto_mls` home `mls-ds` DID (`D1`).
    pub home_ds_did: String,
    /// User's declared `#atproto_mls` home `mls-ds` HTTPS base URL.
    pub home_ds_endpoint: String,
    /// User's ATProto PDS HTTPS base URL.
    pub pds_endpoint: String,
}

/// Summary of pre-cutover files removed from `<storage_root>` on launch (`Spec §9 Step 5`, `I8`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct PreCutoverWipeReport {
    pub removed_files: Vec<String>,
}

/// Canonicalize an ATProto DID (`did:plc:...` or `did:web:...`) before hashing (`I8`).
pub fn normalize_account_did(did: &str) -> Result<String, MLSError> {
    let trimmed = did.trim();
    let bare = trimmed.split('#').next().unwrap_or("").trim();
    if !bare.starts_with("did:") || bare.split(':').count() < 3 {
        return Err(MLSError::invalid_input(format!(
            "invalid ATProto account DID `{did}`"
        )));
    }
    let mut parts = bare.splitn(3, ':');
    let scheme = parts.next().unwrap_or("did").to_ascii_lowercase();
    let method = parts.next().unwrap_or("").to_ascii_lowercase();
    let method_specific = parts.next().unwrap_or("");
    if method.is_empty() || method_specific.is_empty() {
        return Err(MLSError::invalid_input(format!(
            "invalid ATProto account DID `{did}`"
        )));
    }
    let normalized_id = if method == "web" {
        method_specific.to_ascii_lowercase()
    } else {
        method_specific.to_string()
    };
    Ok(format!("{scheme}:{method}:{normalized_id}"))
}

/// Compute the 64-character lowercase hex `SHA-256(normalized_did)` used for `<did_hash>.db`
/// and Keychain item keys (`Spec §5 I8`, `A-7` — zero `accounts.json` in App Group).
pub fn account_did_hash_hex(did: &str) -> Result<String, MLSError> {
    let normalized = normalize_account_did(did)?;
    Ok(hex::encode(Sha256::digest(normalized.as_bytes())))
}

/// Compute `<storage_root>/catbird-mls/<sha256(normalized_did)>.db` (`Spec §6.1`).
pub fn account_db_path(storage_root: &Path, account_did: &str) -> Result<PathBuf, MLSError> {
    let hash = account_did_hash_hex(account_did)?;
    if storage_root
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n == "catbird-mls")
    {
        Ok(storage_root.join(format!("{hash}.db")))
    } else {
        Ok(storage_root.join("catbird-mls").join(format!("{hash}.db")))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn is_canonical_account_db_file(file_name: &str) -> bool {
    let stem = if let Some(s) = file_name.strip_suffix(".db") {
        s
    } else if let Some(s) = file_name.strip_suffix(".db-wal") {
        s
    } else if let Some(s) = file_name.strip_suffix(".db-shm") {
        s
    } else {
        return false;
    };
    stem.len() == 64
        && stem
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Enforce `I8` & `Spec §9 Step 5` hygiene in `<storage_root>` and `<storage_root>/catbird-mls`:
/// removes any pre-cutover `.sqlite`, `.sqlite-wal`, `.sqlite-shm`, `.lease`, `.lock`, or
/// `accounts.json` artifacts so `<storage_root>/catbird-mls/` contains **only** `<64-hex>.db`
/// (`-wal`/`-shm`) files.
#[cfg(not(target_arch = "wasm32"))]
pub fn wipe_pre_cutover_local_artifacts(
    storage_root: &Path,
) -> Result<PreCutoverWipeReport, MLSError> {
    let mut removed_files = Vec::new();

    if storage_root.exists() {
        if let Ok(entries) = std::fs::read_dir(storage_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let is_legacy_root_artifact = name == "accounts.json"
                    || name.ends_with(".lease")
                    || (name.starts_with("mls") && name.contains(".sqlite"));
                if path.is_file() && is_legacy_root_artifact && std::fs::remove_file(&path).is_ok()
                {
                    removed_files.push(path.display().to_string());
                }
            }
        }
    }

    let mls_dir = if storage_root
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n == "catbird-mls")
    {
        storage_root.to_path_buf()
    } else {
        storage_root.join("catbird-mls")
    };

    if mls_dir.exists() {
        let entries = std::fs::read_dir(&mls_dir).map_err(|e| {
            MLSError::invalid_input(format!("failed to scan {:?} for I8 hygiene: {e}", mls_dir))
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if path.is_file() && !is_canonical_account_db_file(name) {
                std::fs::remove_file(&path).map_err(|e| {
                    MLSError::invalid_input(format!(
                        "failed to remove pre-cutover artifact {:?}: {e}",
                        path
                    ))
                })?;
                removed_files.push(path.display().to_string());
            }
        }
    }

    removed_files.sort();
    Ok(PreCutoverWipeReport { removed_files })
}
