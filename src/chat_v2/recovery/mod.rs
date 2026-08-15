//! Bounded recovery.
//!
//! The ladder itself lives in [`ladder`]. This module additionally carries the
//! **absence gate**: a test that fails if the forbidden recovery mechanisms ever
//! reappear in this tree.
//!
//! A comment saying "no external commits" is worth very little. v1 has the same
//! prohibition in its documentation and `force_rejoin_unlocked` in its code, and
//! the result was production epochs in the 700-800 range. So the rule is
//! checked mechanically here, in the same shape as the v1 isolation gate, with a
//! positive control proving the matcher can actually fail.

pub mod ladder;
pub mod poison;

pub use ladder::{LadderError, RecoveryLadder, RecoveryRung};
pub use poison::{
    poisoned_device_next_rung, select_fulfiller, Containment, FulfillerCandidate, PoisonEscalation,
    PoisonObservation, PoisonSource, ProcessingFailure, RecoveryKind,
};

/// Enforces the deliberate absences the recovery design depends on.
///
/// These are not stylistic. Each names a mechanism the protocol forbids
/// outright, and each is the mechanism a well-intentioned implementer reaches
/// for when recovery is not working.
#[cfg(test)]
mod absence {
    use crate::chat_v2::gate_support::SourceScan;

    /// The forbidden mechanisms, assembled at runtime so this gate's own source
    /// is not a violation of itself.
    ///
    /// Split into fragments for the same reason the v1 isolation gate splits its
    /// needles: a literal here would make the file that forbids the thing look
    /// like it does the thing.
    fn forbidden_mechanisms() -> Vec<(String, &'static str)> {
        vec![
            (
                ["create", "external", "commit"].join("_"),
                "external commits are forbidden outright by §1 and inflate the epoch",
            ),
            (
                ["join", "by", "external", "commit"].join("_"),
                "the same prohibition, spelled the way OpenMLS spells it",
            ),
            (
                ["force", "rejoin"].join("_"),
                "v1's delete-then-external-commit path; never reproduce it here",
            ),
            (
                ["external", "commit", "builder"].join("_"),
                "the OpenMLS builder for the forbidden operation",
            ),
        ]
    }

    #[test]
    fn chat_v2_never_reaches_for_a_forbidden_recovery_mechanism() {
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

        let mut violations = Vec::new();
        for (needle, why) in &forbidden_mechanisms() {
            for finding in scan.findings(needle) {
                violations.push(format!("{} — {why}", finding.describe()));
            }
        }
        assert!(
            violations.is_empty(),
            "chat_v2 must never use a forbidden recovery mechanism; found:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn the_absence_gate_can_actually_fail() {
        // A control that cannot fail is not a control. This proves the matcher
        // would catch a real reintroduction rather than passing on every input,
        // that comment-stripping is what spares the documentation above, and
        // that a string literal on the line cannot hide the reintroduction.
        let forbidden = forbidden_mechanisms();
        let mechanism = ["create", "external", "commit"].join("_");
        for offending in [
            format!("    let group = {mechanism}(&provider)?;"),
            format!("    let url = \"https://mls.example\"; {mechanism}(&provider)?;"),
        ] {
            assert!(
                forbidden
                    .iter()
                    .any(|(needle, _)| SourceScan::line_contains(&offending, needle)),
                "the matcher must flag: {offending}"
            );
        }

        let documented = format!(
            "//! - No {}, at any rung.",
            ["external", "commit"].join(" ")
        );
        assert!(
            forbidden
                .iter()
                .all(|(needle, _)| !SourceScan::line_contains(&documented, needle)),
            "a mention inside a comment must not count as a violation"
        );
    }

    #[test]
    fn every_forbidden_mechanism_carries_its_reason() {
        // The list is only useful if a future reader learns why each entry is
        // there rather than deleting the one that is inconveniencing them.
        let forbidden = forbidden_mechanisms();
        assert_eq!(forbidden.len(), 4);
        for (needle, why) in &forbidden {
            assert!(!needle.is_empty());
            assert!(
                why.len() > 20,
                "{needle} needs a real explanation, not a label"
            );
        }
    }
}
