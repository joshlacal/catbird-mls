//! Post-SQLite-commit `acknowledgeEntries` discipline (`Spec §5 I2, I6`):
//! network acknowledgments NEVER run inside a SQLite transaction or before `COMMIT` succeeds.

use std::future::Future;

#[cfg(not(target_arch = "wasm32"))]
use crate::storage::{MlsAccountDb, SqlTx};
use crate::storage::{WasmAccountDb, WasmSqlBackend};
use crate::MLSError;

/// Commit decrypted/applied sequencer entries inside an atomic `write_tx` (`BEGIN IMMEDIATE` ->
/// `COMMIT`) and ONLY AFTER SQLite durability succeeds invoke `acknowledge_on_ds` with the
/// committed sequence numbers (`I2`, `I6`). If `write_tx` fails or rolls back,
/// `acknowledge_on_ds` is never called so `mls-ds` retains the transient delivery entries.
#[cfg(not(target_arch = "wasm32"))]
pub async fn persist_entries_then_acknowledge<WriteFn, AckFn, AckFut>(
    db: &MlsAccountDb,
    write_step: WriteFn,
    acknowledge_on_ds: AckFn,
) -> Result<Vec<i64>, MLSError>
where
    WriteFn: FnOnce(&SqlTx<'_>) -> Result<Vec<i64>, MLSError>,
    AckFn: FnOnce(Vec<i64>) -> AckFut,
    AckFut: Future<Output = Result<(), MLSError>>,
{
    let committed_seqs = db.write_tx(write_step)?;
    if !committed_seqs.is_empty() {
        acknowledge_on_ds(committed_seqs.clone()).await?;
    }
    Ok(committed_seqs)
}

/// Browser WASM (`sqlite3mc` rollback journal) counterpart to [`persist_entries_then_acknowledge`].
pub async fn persist_entries_then_acknowledge_wasm<B, WriteFn, AckFn, AckFut>(
    db: &WasmAccountDb<B>,
    write_step: WriteFn,
    acknowledge_on_ds: AckFn,
) -> Result<Vec<i64>, MLSError>
where
    B: WasmSqlBackend,
    WriteFn: FnOnce(&B) -> Result<Vec<i64>, MLSError>,
    AckFn: FnOnce(Vec<i64>) -> AckFut,
    AckFut: Future<Output = Result<(), MLSError>>,
{
    let committed_seqs = db.write_tx(write_step)?;
    if !committed_seqs.is_empty() {
        acknowledge_on_ds(committed_seqs.clone()).await?;
    }
    Ok(committed_seqs)
}
