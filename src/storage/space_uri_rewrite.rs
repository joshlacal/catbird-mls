//! Stored Space URI rewrite for the 2026-11-24 alpha URI change.
//!
//! Space URIs moved from `at://{spaceDid}/space/{rest}` to `at:space/{spaceDid}/{rest}`.
//! Like the reference PDS migration (`rewrite-space-uris.ts`), only values still in the old
//! form change, so a re-run is a no-op. Only local bookkeeping is rewritten (conversation
//! rows, queued archive payloads, Space pins and writer revision floors); signed or encrypted
//! bytes, MLS state and message content are never touched.
//!
//! TODO: remove before beta.

use serde_json::Value;

/// Prefix of every Space URI and Space record URI.
pub const SPACE_URI_PREFIX: &str = "at:space/";

/// `account_meta` key set once a database's stored Space URIs have been rewritten.
pub const SPACE_URI_REWRITE_MARKER_KEY: &str = "space_uri_at_space_rewrite_v1";

/// Old-form `at://{did}/space/{rest}` -> `at:space/{did}/{rest}`; `None` for anything else.
///
/// Lenient read of values stored during the alpha only; never use it on request input.
/// TODO: remove before beta.
pub fn from_legacy_space_uri(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix("at://")?;
    let (authority, tail) = rest.split_once('/')?;
    let tail = tail.strip_prefix("space/")?;
    if !authority.starts_with("did:") || tail.is_empty() {
        return None;
    }
    Some(format!("{SPACE_URI_PREFIX}{authority}/{tail}"))
}

/// Rewrites every JSON string and object key that is an old-form Space URI, returning whether
/// anything changed. Only for local bookkeeping JSON that holds no record values or message
/// content. TODO: remove before beta.
pub fn rewrite_json_space_uris(value: &mut Value) -> bool {
    match value {
        Value::String(s) => match from_legacy_space_uri(s) {
            Some(new) => {
                *s = new;
                true
            }
            None => false,
        },
        Value::Array(items) => {
            let mut changed = false;
            for item in items.iter_mut() {
                changed |= rewrite_json_space_uris(item);
            }
            changed
        }
        Value::Object(map) => {
            let mut changed = false;
            let legacy_keys: Vec<String> = map
                .keys()
                .filter(|k| from_legacy_space_uri(k).is_some())
                .cloned()
                .collect();
            for key in legacy_keys {
                if let (Some(v), Some(new_key)) = (map.remove(&key), from_legacy_space_uri(&key)) {
                    map.insert(new_key, v);
                    changed = true;
                }
            }
            for (_, v) in map.iter_mut() {
                changed |= rewrite_json_space_uris(v);
            }
            changed
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_only_old_form_space_uris() {
        assert_eq!(
            from_legacy_space_uri("at://did:plc:alice/space/blue.catbird.labyrinth.mailbox/self")
                .as_deref(),
            Some("at:space/did:plc:alice/blue.catbird.labyrinth.mailbox/self")
        );
        assert_eq!(
            from_legacy_space_uri("at://did:web:ds.example/space/t.y.p/k/did:plc:bob/c.o.l/r")
                .as_deref(),
            Some("at:space/did:web:ds.example/t.y.p/k/did:plc:bob/c.o.l/r")
        );
        for unchanged in [
            "at:space/did:plc:alice/blue.catbird.labyrinth.mailbox/self",
            "at://did:plc:alice/app.bsky.feed.post/3k",
            "at://alice.test/space/t.y.p/k",
            "at://did:plc:alice/space/",
            "space",
        ] {
            assert_eq!(from_legacy_space_uri(unchanged), None, "{unchanged}");
        }
    }

    #[test]
    fn json_rewrite_is_idempotent() {
        let mut v = serde_json::json!({
            "c1": {"space": "at://did:web:ds/space/a.b.c/c1-0", "generation": 0},
            "list": [["at://did:web:ds/space/a.b.c/c1-0", "did:plc:bob", "3k"]],
            "at://did:web:ds/space/a.b.c/c2-0": "x",
        });
        assert!(rewrite_json_space_uris(&mut v));
        let once = v.clone();
        assert!(!rewrite_json_space_uris(&mut v));
        assert_eq!(v, once);
        assert_eq!(v["c1"]["space"], "at:space/did:web:ds/a.b.c/c1-0");
        assert_eq!(v["list"][0][0], "at:space/did:web:ds/a.b.c/c1-0");
        assert_eq!(v["at:space/did:web:ds/a.b.c/c2-0"], "x");
    }
}
