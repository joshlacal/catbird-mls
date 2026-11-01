//! Scope-aware KeyPackage replenishment policy (`direct-request` vs `recovery`).

use serde::{Deserialize, Serialize};

use super::c33::{
    validate_direct_request_key_package_lifetime, validate_recovery_key_package_lifetime,
    DIRECT_REQUEST_KP_MIN_LIFETIME_SECS, RECOVERY_KP_MAX_LIFETIME_SECS,
};
use crate::MLSError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyPackageUsageScope {
    DirectRequest,
    Recovery,
}

impl KeyPackageUsageScope {
    pub fn default_lifetime_secs(self) -> u64 {
        match self {
            // 40 days comfortably satisfies C33 >= 35d while staying below mls-ds 45d+1h cap.
            Self::DirectRequest => DIRECT_REQUEST_KP_MIN_LIFETIME_SECS + 5 * 86_400,
            Self::Recovery => RECOVERY_KP_MAX_LIFETIME_SECS,
        }
    }

    pub fn validate_lifetime(self, not_before_sec: u64, not_after_sec: u64) -> Result<(), MLSError> {
        match self {
            Self::DirectRequest => {
                validate_direct_request_key_package_lifetime(not_before_sec, not_after_sec)
            }
            Self::Recovery => validate_recovery_key_package_lifetime(not_before_sec, not_after_sec),
        }
    }
}
