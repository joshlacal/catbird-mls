use crate::error::MLSError;

/// One key/value row returned by [`OpenMlsStorageDriver::scan`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OpenMlsStorageDriverEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Experimental host-owned OpenMLS storage driver.
///
/// This callback interface is intentionally behind the
/// `storage-driver-prototype` feature. The production path remains
/// `openmls_sqlite_storage` plus `HybridStorageProvider`; enabling this feature
/// only gives fixture tests and platform prototypes a stable UniFFI contract to
/// exercise before any storage migration decision.
#[uniffi::export(callback_interface)]
pub trait OpenMlsStorageDriver: Send + Sync {
    fn read(&self, prefix: Vec<u8>, key: Vec<u8>) -> Result<Option<Vec<u8>>, MLSError>;

    fn write(&self, prefix: Vec<u8>, key: Vec<u8>, value: Vec<u8>) -> Result<(), MLSError>;

    fn delete(&self, prefix: Vec<u8>, key: Vec<u8>) -> Result<(), MLSError>;

    fn scan(&self, prefix: Vec<u8>) -> Result<Vec<OpenMlsStorageDriverEntry>, MLSError>;
}
