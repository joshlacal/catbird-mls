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

#[cfg(test)]
mod gate_support;

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
pub mod participation;
pub mod provenance;
pub mod recovery;
pub mod reducer;
pub mod storage;
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
    use super::gate_support::SourceScan;

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

    #[test]
    fn chat_v2_never_imports_the_superseded_orchestrator() {
        let scan = SourceScan::of_chat_v2();
        assert!(
            scan.file_count() > 0,
            "the walk found no sources, so this test would pass vacuously"
        );
        assert!(
            scan.unresolved_includes.is_empty(),
            "code reached by an unscanned include is code this gate never saw: {:?}",
            scan.unresolved_includes
        );

        let violations: Vec<String> = forbidden_imports()
            .iter()
            .flat_map(|needle| scan.findings(needle))
            .map(|finding| finding.describe())
            .collect();
        assert!(
            violations.is_empty(),
            "chat_v2 must not depend on the superseded v1 orchestrator; found:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn the_isolation_check_can_actually_fail() {
        // A gate that cannot fail is not a gate. This proves the matcher would
        // catch a real import rather than silently passing on every input —
        // including the brace form, which is what an import organizer emits and
        // which the previous substring matcher missed entirely.
        let forbidden = forbidden_imports();
        for offending in [
            format!("use crate::{V1_MODULE}::types::ConversationState;"),
            format!(
                "use {}::{}{V1_MODULE}::types::ConversationState, ids::Seq{};",
                "crate", "{", "}"
            ),
            format!("let doc = \"https://x\"; use crate::{V1_MODULE}::X;"),
        ] {
            assert!(
                forbidden
                    .iter()
                    .any(|needle| SourceScan::line_contains(&offending, needle)),
                "the matcher must flag: {offending}"
            );
        }

        // And that stripping comments is what spares the module documentation,
        // which has to name the forbidden path in order to forbid it.
        let documented = format!("//! - No module may use crate::{V1_MODULE}::... here.");
        assert!(
            !forbidden
                .iter()
                .any(|needle| SourceScan::line_contains(&documented, needle)),
            "a mention inside a comment must not count as a violation"
        );
    }
}
