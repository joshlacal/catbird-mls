//! Cross-platform bounds for attacker-controlled MLS wire messages.
//!
//! This module is intentionally available on native and WASM targets. The
//! direct native API, legacy C FFI, and platform-agnostic orchestrator must all
//! reject oversized inputs before padding removal, cloning, or OpenMLS parsing.

use crate::error::MLSError;
use crate::types::KeyPackageData;

/// Maximum encoded size accepted for an inbound MLS wire message.
///
/// Preserves the legacy C FFI's 100 MiB compatibility ceiling while applying
/// it consistently to every first-party processing surface.
pub(crate) const MAX_INBOUND_MLS_MESSAGE_BYTES: usize = 100 * 1024 * 1024;

/// Maximum number of locally generated KeyPackages accepted in one public
/// call. This matches the bounded remote batch ceiling and prevents an FFI
/// caller from driving an unbounded allocation/CPU loop.
pub(crate) const MAX_KEY_PACKAGE_BATCH_COUNT: u32 = 100;

pub(crate) fn validate_inbound_mls_message_len(
    len: usize,
    input_name: &'static str,
) -> Result<(), MLSError> {
    if len > MAX_INBOUND_MLS_MESSAGE_BYTES {
        return Err(MLSError::invalid_input(format!(
            "{input_name} length {len} exceeds maximum {MAX_INBOUND_MLS_MESSAGE_BYTES}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_key_package_batch_count(count: u32) -> Result<(), MLSError> {
    if count > MAX_KEY_PACKAGE_BATCH_COUNT {
        return Err(MLSError::invalid_input(format!(
            "key package batch count {count} exceeds maximum {MAX_KEY_PACKAGE_BATCH_COUNT}"
        )));
    }
    Ok(())
}

/// Apply the delivery-service KeyPackage ceilings to every cross-platform
/// public path that accepts caller-supplied serialized packages. This lives in
/// the target-neutral limits module because the orchestrator is compiled for
/// WASM while the direct native API is not.
pub(crate) fn validate_outbound_key_package_lengths(
    package_count: usize,
    package_lengths: impl IntoIterator<Item = usize>,
) -> Result<(), MLSError> {
    use crate::orchestrator::credential_binding::{
        MAX_FETCHED_KEY_PACKAGE_BATCH_BYTES, MAX_FETCHED_KEY_PACKAGE_BYTES,
        MAX_FETCHED_KEY_PACKAGE_COUNT,
    };

    if package_count > MAX_FETCHED_KEY_PACKAGE_COUNT {
        return Err(MLSError::invalid_input(format!(
            "outbound key-package batch contains {package_count} packages, exceeding the {MAX_FETCHED_KEY_PACKAGE_COUNT}-package maximum"
        )));
    }

    let mut aggregate_bytes = 0usize;
    for (index, package_bytes) in package_lengths.into_iter().enumerate() {
        if package_bytes > MAX_FETCHED_KEY_PACKAGE_BYTES {
            return Err(MLSError::invalid_input(format!(
                "outbound key package {index} is {package_bytes} bytes, exceeding the {MAX_FETCHED_KEY_PACKAGE_BYTES}-byte maximum"
            )));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(package_bytes)
            .ok_or_else(|| MLSError::invalid_input("outbound key-package byte count overflowed"))?;
        if aggregate_bytes > MAX_FETCHED_KEY_PACKAGE_BATCH_BYTES {
            return Err(MLSError::invalid_input(format!(
                "outbound key-package batch is {aggregate_bytes} bytes, exceeding the {MAX_FETCHED_KEY_PACKAGE_BATCH_BYTES}-byte maximum"
            )));
        }
    }

    Ok(())
}

pub(crate) fn validate_outbound_key_package_data_batch(
    key_packages: &[KeyPackageData],
) -> Result<(), MLSError> {
    validate_outbound_key_package_lengths(
        key_packages.len(),
        key_packages
            .iter()
            .map(|key_package| key_package.data.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_limit_accepts_boundary_and_rejects_one_byte_over() {
        assert!(
            validate_inbound_mls_message_len(MAX_INBOUND_MLS_MESSAGE_BYTES, "group_info").is_ok()
        );
        assert!(
            validate_inbound_mls_message_len(MAX_INBOUND_MLS_MESSAGE_BYTES + 1, "group_info")
                .is_err()
        );
    }

    #[test]
    fn key_package_batch_limit_is_bounded() {
        assert!(validate_key_package_batch_count(MAX_KEY_PACKAGE_BATCH_COUNT).is_ok());
        assert!(validate_key_package_batch_count(MAX_KEY_PACKAGE_BATCH_COUNT + 1).is_err());
    }
}
