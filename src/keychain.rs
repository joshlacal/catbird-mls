use crate::error::MLSError;

#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait KeychainAccess: Send + Sync {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError>;
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError>;
    async fn delete(&self, key: String) -> Result<(), MLSError>;
}
