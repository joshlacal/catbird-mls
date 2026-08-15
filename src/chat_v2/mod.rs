//! Clean chat protocol (`blue.catbird.chat.*`, protocol version `"1"`).
//!
//! This tree is deliberately isolated from [`crate::orchestrator`], which
//! implements the superseded `blue.catbird.mlsChat*` protocol. The two never
//! interoperate: CHAT_PROTOCOL.md §1 states that the superseded namespace,
//! storage, cursors, routes, device bindings, and cryptographic state are never
//! read or translated.
//!
//! The isolation rule for this tree is mechanical, not stylistic:
//!
//! - No module under `chat_v2` may `use crate::orchestrator::...`. The v1
//!   orchestrator's storage seam is flat and has no namespace concept to
//!   parallel, so v2 defines its own traits and expects platforms to open a
//!   separate store.
//! - Nothing here may reach v1 storage keys, cursors, or MLS group state.
//! - The one genuinely shared layer is the MLS crypto engine itself, which is
//!   pure RFC 9420 and carries no protocol-version knowledge. When v2 needs it,
//!   it will be behind a v2-owned trait rather than a direct dependency on a v1
//!   module path.
//!
//! Two further rules follow from the normative contract and are worth stating
//! where they will be read:
//!
//! - **No autonomous destructive recovery.** v1's ladder deletes the local
//!   group and joins by external commit; the clean protocol forbids external
//!   commits outright and has no autonomous reset. The bounded ladder is
//!   catch-up, pending Welcome, target-device recovery request, reset request —
//!   and reset activation is an explicit authorized act, never a fallback.
//! - **Verify before decrypt.** Signature, transcript, and fingerprint
//!   validation precede decryption, attribution, display, and effects, for both
//!   application entries and all thirteen control kinds.
//!
//! # Continuing this work
//!
//! `HANDOFF.md`, alongside this file, is the current state of play: the sealed
//! commit map, the ratified policy decisions and why each was decided that way,
//! what the reducer has and has not built, which named refusals the next slices
//! must convert into implementations, and the plan for envelope verification.
//!
//! Read it before changing anything here. Several decisions in this tree look
//! arbitrary from the code alone and are not — the strict `nextAfterSeq`
//! equality, the cumulative bare-DID length rule, and the two-code auto-retry
//! set were each settled against evidence and are pinned by tests.

pub mod append_log;
pub mod content;
pub mod coordinate;
pub mod cursor;
pub mod endpoint_error;
/// Platform binding surface. Compiled out on wasm32, matching the crate layout
/// where `uniffi::setup_scaffolding!` is itself gated off wasm.
#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;
pub mod ids;
pub mod interval;
pub mod journal;
pub mod provenance;
pub mod reducer;
pub mod transcript;
pub mod wire;

/// Enforces the v1/v2 isolation rule stated in this module's documentation.
///
/// The constraint is easy to violate by accident — `crate::orchestrator`
/// re-exports a large, conveniently named surface, and an editor's import
/// completion will happily reach into it. A grep in a review will not reliably
/// catch that, so the rule is checked here instead of merely written down.
#[cfg(test)]
mod isolation {
    use std::path::Path;

    /// The superseded module's name, spelled once.
    ///
    /// The needles are assembled at runtime rather than written as literals so
    /// that this gate's own source does not read as a violation of itself.
    const V1_MODULE: &str = "orchestrator";

    /// Every path prefix that would couple v2 to the superseded protocol.
    fn forbidden_imports() -> Vec<String> {
        ["crate", "super::super", "catbird_mls"]
            .iter()
            .map(|root| format!("{root}::{V1_MODULE}"))
            .collect()
    }

    fn source_files(dir: &Path, found: &mut Vec<std::path::PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("chat_v2 source tree must be readable");
        for entry in entries {
            let path = entry.expect("directory entry must be readable").path();
            if path.is_dir() {
                source_files(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }

    /// Strips `//`-comments so the module documentation, which necessarily
    /// names the forbidden paths in order to forbid them, is not itself a
    /// violation.
    fn code_only(line: &str) -> &str {
        match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        }
    }

    #[test]
    fn chat_v2_never_imports_the_superseded_orchestrator() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chat_v2");
        let mut files = Vec::new();
        source_files(&root, &mut files);
        assert!(
            !files.is_empty(),
            "the walk found no sources, so this test would pass vacuously"
        );

        let forbidden = forbidden_imports();
        let mut violations = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file).expect("source file must be readable");
            for (number, line) in text.lines().enumerate() {
                let code = code_only(line);
                for forbidden in &forbidden {
                    if code.contains(forbidden.as_str()) {
                        violations.push(format!(
                            "{}:{}: {}",
                            file.display(),
                            number + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }

        assert!(
            violations.is_empty(),
            "chat_v2 must not depend on the superseded v1 orchestrator; found:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn the_isolation_check_can_actually_fail() {
        // A gate that cannot fail is not a gate. This proves the matcher would
        // catch a real import rather than silently passing on every input.
        let forbidden = forbidden_imports();
        let offending = format!("use crate::{V1_MODULE}::types::ConversationState;");
        assert!(
            forbidden
                .iter()
                .any(|needle| code_only(&offending).contains(needle.as_str())),
            "the matcher must flag a genuine v1 import"
        );

        // And that stripping comments is what spares the module documentation,
        // which has to name the forbidden path in order to forbid it.
        let documented = format!("//! - No module may use crate::{V1_MODULE}::... here.");
        assert!(
            !forbidden
                .iter()
                .any(|needle| code_only(&documented).contains(needle.as_str())),
            "a mention inside a comment must not count as a violation"
        );
    }
}
