//! Stored alpha-form Space URIs (`at://{did}/space/...`) are rewritten to `at:space/{did}/...`
//! once, when the account database opens. TODO: remove before beta.

use catbird_mls::storage::space_uri_rewrite::SPACE_URI_REWRITE_MARKER_KEY;
use catbird_mls::storage::{ConversationRow, MlsAccountDb, OpenMode};
use catbird_mls::MLSError;

const OLD: &str = "at://did:web:ds.example/space/blue.catbird.labyrinth.conversation/c1-0";
const NEW: &str = "at:space/did:web:ds.example/blue.catbird.labyrinth.conversation/c1-0";
const PINS_KEY: &str = "native.placements:threads:did:plc:alice";
const OTHER_KEY: &str = "native.message:c1:m1";
const C33_KEY: &str = "c33_pending_opening:c1";

#[test]
fn open_rewrites_stored_alpha_space_uris() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("space-uri.db");
    let key = [0x24u8; 32];
    {
        let db = MlsAccountDb::open_native(&path, &key, OpenMode::App).expect("open");
        db.write_tx(|tx| {
            tx.upsert_conversation(&ConversationRow {
                conversation_id: "c1".into(),
                group_id: vec![1; 16],
                generation: 0,
                epoch: 0,
                last_seq: 0,
                sequencer_did: "did:web:ds.example".into(),
                space_uri: Some(OLD.into()),
                title: None,
                unread_count: 0,
                updated_at_ms: 0,
            })?;
            let pins = format!(r#"{{"c1":{{"space":"{OLD}","generation":0}}}}"#);
            tx.put_labyrinth_state(PINS_KEY, pins.as_bytes(), 0)?;
            tx.put_labyrinth_state(OTHER_KEY, OLD.as_bytes(), 0)?;
            let opening = format!(r#"{{"space_uri":"{OLD}","signed":"{OLD}"}}"#);
            tx.conn()
                .execute(
                    "INSERT OR REPLACE INTO account_meta(key, value_json, updated_at_ms) \
                     VALUES(?1, ?2, 0)",
                    rusqlite::params![C33_KEY, opening],
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            // Pretend this database predates the rewrite.
            tx.conn()
                .execute(
                    "DELETE FROM account_meta WHERE key = ?1",
                    [SPACE_URI_REWRITE_MARKER_KEY],
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            Ok(())
        })
        .expect("seed alpha-form rows");
    }

    let db = MlsAccountDb::open_native(&path, &key, OpenMode::App).expect("reopen");
    db.read_tx(|tx| {
        let row = tx.get_conversation("c1")?.expect("conversation row");
        assert_eq!(row.space_uri.as_deref(), Some(NEW));
        let pins = tx.get_labyrinth_state(PINS_KEY)?.expect("pins");
        let pins: serde_json::Value = serde_json::from_slice(&pins).expect("pins json");
        assert_eq!(pins["c1"]["space"], NEW);
        assert_eq!(pins["c1"]["generation"], 0);
        let opening: String = tx
            .conn()
            .query_row(
                "SELECT value_json FROM account_meta WHERE key = ?1",
                [C33_KEY],
                |row| row.get(0),
            )
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let opening: serde_json::Value = serde_json::from_str(&opening).expect("opening json");
        assert_eq!(opening["space_uri"], NEW);
        // Only `space_uri` is rewritten; other fields keep their values.
        assert_eq!(opening["signed"], OLD);
        // Stores outside the rewrite's list are left alone.
        assert_eq!(
            tx.get_labyrinth_state(OTHER_KEY)?.as_deref(),
            Some(OLD.as_bytes())
        );
        Ok(())
    })
    .expect("read back");
}
