//! WASM `sqlite3mc` (`sqlite-wasm-rs` + `opfs-sahpool`) storage driver contract (`Spec §6.1`).
//!
//! Enforces:
//! - Exact pragma order: `PRAGMA cipher = 'chacha20';` BEFORE `PRAGMA key = "x'<64-hex>'";`
//! - `DELETE` rollback journal (NEVER `WAL` on `opfs-sahpool`, which lacks shared memory `-shm`)
//! - Unified 15-table schema (`UNIFIED_SCHEMA_DDL`) + single-table `openmls_kv` `StorageProvider<1>`

use crate::error::MLSError;

use super::openmls_kv::{KvBackend, OpenMlsKvProvider, OpenMlsKvStorage};
use super::queries::{
    ConversationRow, GroupMetadataRow, LabyrinthQueueRow, MessageRow, MutationJournalRow,
    RequestRow, RoutingCacheRow,
};

/// Build the canonical `sqlite3mc` initialization SQL for WASM OPFS (`Spec §6.1`):
/// 1. `PRAGMA cipher = 'chacha20';` (MUST run before `PRAGMA key`)
/// 2. `PRAGMA key = "x'<64-hex>'";`
/// 3. `PRAGMA page_size = 4096;`
/// 4. `PRAGMA journal_mode = DELETE;` (the pinned VFS corrupts rollback in retained-journal modes)
/// 5. `PRAGMA synchronous = FULL;`
pub fn wasm_sqlite3mc_init_pragmas(db_key_32: &[u8; 32]) -> String {
    let hex_key = hex::encode(db_key_32);
    format!(
        "PRAGMA cipher = 'chacha20';\n\
         PRAGMA key = \"x'{hex_key}'\";\n\
         PRAGMA page_size = 4096;\n\
         PRAGMA journal_mode = DELETE;\n\
         PRAGMA synchronous = FULL;"
    )
}

/// Abstract synchronous SQLite backend implemented by `catbird-mls-web::SqliteConn`.
pub trait WasmSqlBackend: KvBackend {
    fn begin_immediate(&self) -> Result<(), MLSError>;
    fn commit_tx(&self) -> Result<(), MLSError>;
    fn rollback_tx(&self) -> Result<(), MLSError>;

    fn get_account_meta(&self, key: &str) -> Result<Option<String>, MLSError>;
    fn put_account_meta(
        &self,
        key: &str,
        value_json: &str,
        updated_at_ms: i64,
    ) -> Result<(), MLSError>;
    fn delete_account_meta(&self, key: &str) -> Result<(), MLSError>;

    fn upsert_conversation(&self, row: &ConversationRow) -> Result<(), MLSError>;
    fn get_conversation(&self, conversation_id: &str) -> Result<Option<ConversationRow>, MLSError>;
    fn list_conversations(
        &self,
        before_updated_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ConversationRow>, MLSError>;
    fn delete_conversation(&self, conversation_id: &str) -> Result<(), MLSError>;

    fn insert_message(&self, row: &MessageRow) -> Result<(), MLSError>;
    fn list_messages(
        &self,
        conversation_id: &str,
        before_seq: Option<i64>,
        limit: usize,
    ) -> Result<Vec<MessageRow>, MLSError>;
    fn purge_messages_from_sender(
        &self,
        conversation_id: Option<&str>,
        sender_did: &str,
    ) -> Result<usize, MLSError>;

    fn upsert_request(&self, row: &RequestRow) -> Result<(), MLSError>;
    fn get_request(&self, request_id: &str) -> Result<Option<RequestRow>, MLSError>;
    fn list_requests(&self, consent_filter: Option<&str>) -> Result<Vec<RequestRow>, MLSError>;

    fn upsert_group_metadata(&self, row: &GroupMetadataRow) -> Result<(), MLSError>;
    fn get_group_metadata(
        &self,
        conversation_id: &str,
    ) -> Result<Option<GroupMetadataRow>, MLSError>;

    fn upsert_mutation_journal(&self, row: &MutationJournalRow) -> Result<(), MLSError>;
    fn list_mutation_journal_pending(&self) -> Result<Vec<MutationJournalRow>, MLSError>;
    fn delete_mutation_journal(&self, journal_id: &str) -> Result<(), MLSError>;

    fn upsert_routing_cache(&self, row: &RoutingCacheRow) -> Result<(), MLSError>;
    fn get_routing_cache(&self, did: &str) -> Result<Option<RoutingCacheRow>, MLSError>;

    fn put_labyrinth_state(
        &self,
        state_key: &str,
        value_bytes: &[u8],
        updated_at_ms: i64,
    ) -> Result<(), MLSError>;
    fn get_labyrinth_state(&self, state_key: &str) -> Result<Option<Vec<u8>>, MLSError>;

    fn enqueue_labyrinth_item(&self, row: &LabyrinthQueueRow) -> Result<(), MLSError>;
    fn list_labyrinth_queue(
        &self,
        conversation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<LabyrinthQueueRow>, MLSError>;
    fn dequeue_labyrinth_item(&self, item_id: &str) -> Result<(), MLSError>;
}

impl<T: WasmSqlBackend + ?Sized> WasmSqlBackend for std::rc::Rc<T> {
    fn begin_immediate(&self) -> Result<(), MLSError> {
        (**self).begin_immediate()
    }
    fn commit_tx(&self) -> Result<(), MLSError> {
        (**self).commit_tx()
    }
    fn rollback_tx(&self) -> Result<(), MLSError> {
        (**self).rollback_tx()
    }
    fn get_account_meta(&self, key: &str) -> Result<Option<String>, MLSError> {
        (**self).get_account_meta(key)
    }
    fn put_account_meta(
        &self,
        key: &str,
        value_json: &str,
        updated_at_ms: i64,
    ) -> Result<(), MLSError> {
        (**self).put_account_meta(key, value_json, updated_at_ms)
    }
    fn delete_account_meta(&self, key: &str) -> Result<(), MLSError> {
        (**self).delete_account_meta(key)
    }
    fn upsert_conversation(&self, row: &ConversationRow) -> Result<(), MLSError> {
        (**self).upsert_conversation(row)
    }
    fn get_conversation(&self, conversation_id: &str) -> Result<Option<ConversationRow>, MLSError> {
        (**self).get_conversation(conversation_id)
    }
    fn list_conversations(
        &self,
        before_updated_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ConversationRow>, MLSError> {
        (**self).list_conversations(before_updated_ms, limit)
    }
    fn delete_conversation(&self, conversation_id: &str) -> Result<(), MLSError> {
        (**self).delete_conversation(conversation_id)
    }
    fn insert_message(&self, row: &MessageRow) -> Result<(), MLSError> {
        (**self).insert_message(row)
    }
    fn list_messages(
        &self,
        conversation_id: &str,
        before_seq: Option<i64>,
        limit: usize,
    ) -> Result<Vec<MessageRow>, MLSError> {
        (**self).list_messages(conversation_id, before_seq, limit)
    }
    fn purge_messages_from_sender(
        &self,
        conversation_id: Option<&str>,
        sender_did: &str,
    ) -> Result<usize, MLSError> {
        (**self).purge_messages_from_sender(conversation_id, sender_did)
    }
    fn upsert_request(&self, row: &RequestRow) -> Result<(), MLSError> {
        (**self).upsert_request(row)
    }
    fn get_request(&self, request_id: &str) -> Result<Option<RequestRow>, MLSError> {
        (**self).get_request(request_id)
    }
    fn list_requests(&self, consent_filter: Option<&str>) -> Result<Vec<RequestRow>, MLSError> {
        (**self).list_requests(consent_filter)
    }
    fn upsert_group_metadata(&self, row: &GroupMetadataRow) -> Result<(), MLSError> {
        (**self).upsert_group_metadata(row)
    }
    fn get_group_metadata(
        &self,
        conversation_id: &str,
    ) -> Result<Option<GroupMetadataRow>, MLSError> {
        (**self).get_group_metadata(conversation_id)
    }
    fn upsert_mutation_journal(&self, row: &MutationJournalRow) -> Result<(), MLSError> {
        (**self).upsert_mutation_journal(row)
    }
    fn list_mutation_journal_pending(&self) -> Result<Vec<MutationJournalRow>, MLSError> {
        (**self).list_mutation_journal_pending()
    }
    fn delete_mutation_journal(&self, journal_id: &str) -> Result<(), MLSError> {
        (**self).delete_mutation_journal(journal_id)
    }
    fn upsert_routing_cache(&self, row: &RoutingCacheRow) -> Result<(), MLSError> {
        (**self).upsert_routing_cache(row)
    }
    fn get_routing_cache(&self, did: &str) -> Result<Option<RoutingCacheRow>, MLSError> {
        (**self).get_routing_cache(did)
    }
    fn put_labyrinth_state(
        &self,
        state_key: &str,
        value_bytes: &[u8],
        updated_at_ms: i64,
    ) -> Result<(), MLSError> {
        (**self).put_labyrinth_state(state_key, value_bytes, updated_at_ms)
    }
    fn get_labyrinth_state(&self, state_key: &str) -> Result<Option<Vec<u8>>, MLSError> {
        (**self).get_labyrinth_state(state_key)
    }
    fn enqueue_labyrinth_item(&self, row: &LabyrinthQueueRow) -> Result<(), MLSError> {
        (**self).enqueue_labyrinth_item(row)
    }
    fn list_labyrinth_queue(
        &self,
        conversation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<LabyrinthQueueRow>, MLSError> {
        (**self).list_labyrinth_queue(conversation_id, limit)
    }
    fn dequeue_labyrinth_item(&self, item_id: &str) -> Result<(), MLSError> {
        (**self).dequeue_labyrinth_item(item_id)
    }
}

/// Per-account WASM SQLite wrapper executing `openmls_kv` and app tables in one transaction.
pub struct WasmAccountDb<B> {
    backend: B,
}

impl<B: WasmSqlBackend> WasmAccountDb<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn openmls_provider(&self) -> Result<OpenMlsKvProvider<&B>, MLSError> {
        OpenMlsKvProvider::new(self.openmls_storage())
    }

    pub fn openmls_storage(&self) -> OpenMlsKvStorage<&B> {
        OpenMlsKvStorage::new(&self.backend)
    }

    pub fn write_tx<T>(&self, f: impl FnOnce(&B) -> Result<T, MLSError>) -> Result<T, MLSError> {
        self.backend.begin_immediate()?;
        match f(&self.backend) {
            Ok(val) => {
                if let Err(err) = self.backend.commit_tx() {
                    let _ = self.backend.rollback_tx();
                    return Err(err);
                }
                Ok(val)
            }
            Err(err) => {
                let _ = self.backend.rollback_tx();
                Err(err)
            }
        }
    }
}
