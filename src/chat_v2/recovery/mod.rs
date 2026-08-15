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
    use std::path::Path;

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

    /// Strips `//` comments, so documentation that names a forbidden mechanism
    /// in order to forbid it is not itself a violation.
    fn code_only(line: &str) -> &str {
        match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        }
    }

    #[test]
    fn chat_v2_never_reaches_for_a_forbidden_recovery_mechanism() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chat_v2");
        let mut files = Vec::new();
        source_files(&root, &mut files);
        assert!(
            !files.is_empty(),
            "the walk found no sources, so this test would pass vacuously"
        );

        let forbidden = forbidden_mechanisms();
        let mut violations = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file).expect("source file must be readable");
            for (number, line) in text.lines().enumerate() {
                let code = code_only(line);
                for (needle, why) in &forbidden {
                    if code.contains(needle.as_str()) {
                        violations.push(format!(
                            "{}:{}: {} — {why}",
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
            "chat_v2 must never use a forbidden recovery mechanism; found:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn the_absence_gate_can_actually_fail() {
        // A control that cannot fail is not a control. This proves the matcher
        // would catch a real reintroduction rather than passing on every input,
        // and that comment-stripping is what spares the documentation above.
        let forbidden = forbidden_mechanisms();
        let offending = format!(
            "    let group = {}(&provider)?;",
            ["create", "external", "commit"].join("_")
        );
        assert!(
            forbidden
                .iter()
                .any(|(needle, _)| code_only(&offending).contains(needle.as_str())),
            "the matcher must flag a genuine reintroduction"
        );

        let documented = format!(
            "//! - No {}, at any rung.",
            ["external", "commit"].join(" ")
        );
        assert!(
            forbidden
                .iter()
                .all(|(needle, _)| !code_only(&documented).contains(needle.as_str())),
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
