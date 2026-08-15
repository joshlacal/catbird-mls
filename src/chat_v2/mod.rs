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
    use super::gate_support::{crate_root_glob_exports, SourceScan};

    /// The superseded module's name, spelled once.
    ///
    /// The needles are assembled at runtime rather than written as literals so
    /// that this gate's own source does not read as a violation of itself.
    const V1_MODULE: &str = "orchestrator";

    /// Every path prefix that would couple v2 to the superseded protocol.
    ///
    /// The bare `super` root is not redundant with `crate`: this file's own
    /// `super` IS the crate root — `chat_v2/mod.rs` is the one file in the
    /// tree at depth one — so `use super::orchestrator::…;` there resolves
    /// while spelling neither `crate` nor a double super. The single-`super`
    /// needle also covers every deeper file by substring: `super::super::…`
    /// contains it.
    fn forbidden_imports() -> Vec<String> {
        ["crate", "super", "catbird_mls"]
            .iter()
            .map(|root| format!("{root}::{V1_MODULE}"))
            .collect()
    }

    /// Every `crate::<Name>` the crate root's re-export globs make reachable —
    /// in BOTH spellings a chat_v2 file can reach it by.
    ///
    /// Module-path needles cannot cover these, and that is not a gap to be
    /// patched with two more literals — it is structural. `src/lib.rs` globs six
    /// modules, so `use crate::MLSContext;` reaches v1's SQLCipher group and
    /// crypto surface while naming no forbidden path at all. The set is derived
    /// from the re-export surface, so a new glob, a new `pub` item in a module
    /// already globbed, or a name a globbed module re-exports (the depth-two
    /// form) is covered without anyone extending a list.
    ///
    /// Each name is spelled two ways: `crate::<Name>`, and `super::<Name>` —
    /// the spelling from `chat_v2/mod.rs`, whose `super` is the crate root,
    /// and by substring containment the spelling from any deeper file's
    /// `super::super::<Name>` chain too. A collision with a chat_v2 module's
    /// own `super::<Name>` reference would over-refuse, and that is the
    /// accepted direction: the failure names the line, and the resolution is
    /// to spell the local item by its full `crate::chat_v2::…` path.
    fn forbidden_crate_root_names() -> Vec<(String, String)> {
        crate_root_glob_exports()
            .into_iter()
            .flat_map(|export| {
                [
                    (format!("crate::{}", export.name), export.module.clone()),
                    (format!("super::{}", export.name), export.module),
                ]
            })
            .collect()
    }

    /// The walk boundary, asserted rather than assumed.
    ///
    /// Every needle gate scans the DIRECTORY `src/chat_v2`, and Rust module
    /// membership is not directory membership. The final re-probe proved two
    /// deliberate-act escapes through that seam, each with a compile-time
    /// positive control: a `#[path]` attribute relocating a chat_v2 module's
    /// source file outside the walk (invisible to every gate at once — the
    /// same blast radius the unresolved-include assertion exists to prevent),
    /// and a crate-root alias (`use crate as x;`) that reaches v1 under a
    /// spelling no needle family covers. Neither mechanism has a legitimate
    /// use in this tree, so both are refused outright — the mechanism, not
    /// the instance — which keeps the scanned set provably the compiled set
    /// and the needle roots provably the only root spellings.
    ///
    /// A known residue, recorded rather than covered: a `cfg_attr`-wrapped
    /// path attribute is matched by the second relocation needle, but stranger
    /// attribute machinery would be a review event, same category as the
    /// chartered F8 wrapper.
    #[test]
    fn no_module_relocation_and_no_root_aliasing() {
        let scan = SourceScan::of_chat_v2();
        assert!(
            scan.file_count() > 0,
            "the walk found no sources, so this test would pass vacuously"
        );

        // Assembled at runtime so this file does not flag itself; the
        // whitespace inside the alias needles is removed by the same
        // normalization applied to the scanned code, so a spaced or wrapped
        // spelling of either mechanism still matches.
        let relocations = [["#[", "path"].concat(), [",", " path", " ="].concat()];
        let aliases = [
            ["crate", " as "].concat(),
            ["super", " as "].concat(),
            ["catbird_mls", " as "].concat(),
            ["extern ", "crate "].concat(),
        ];

        // Positive controls, built through the real matcher: each mechanism's
        // canonical spelling and its spaced variant must be findable, or the
        // silence below means nothing.
        for control in [
            format!("{}{} = \"../smuggled.rs\"]", "#[", "path"),
            format!("{}{} {} = \"../smuggled.rs\"]", "#[", " ", "path"),
            format!("cfg_attr(test,{} = \"../smuggled.rs\")", " path"),
            format!("use {}{}v1root;", "crate", " as "),
            format!("pub use {}{}v1root;", "super", " as "),
            format!("{}{}mls;", "extern ", "crate "),
        ] {
            assert!(
                relocations
                    .iter()
                    .chain(aliases.iter())
                    .any(|needle| SourceScan::line_contains(&control, needle)),
                "a mechanism control must be matchable: {control}"
            );
        }

        let violations: Vec<String> = relocations
            .iter()
            .chain(aliases.iter())
            .flat_map(|needle| scan.findings(needle))
            .map(|finding| finding.describe())
            .collect();
        assert!(
            violations.is_empty(),
            "chat_v2 must not relocate a module's file outside the scanned tree \
             or alias a needle root under a new name; both mechanisms defeat \
             every gate at once and neither has a legitimate use here:\n{}",
            violations.join("\n")
        );
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
    fn chat_v2_never_reaches_v1_through_a_crate_root_re_export() {
        let scan = SourceScan::of_chat_v2();
        let derived = forbidden_crate_root_names();
        assert!(
            derived.len() > 20,
            "the derivation found only {} crate-root names, so it is not reading lib.rs",
            derived.len()
        );

        let mut violations = Vec::new();
        for (needle, module) in &derived {
            for finding in scan.findings(needle) {
                violations.push(format!(
                    "{} — {needle} is `{module}` hoisted to the crate root",
                    finding.describe()
                ));
            }
        }
        assert!(
            violations.is_empty(),
            "chat_v2 must not reach a crate-root re-export; v2 defines its own \
             types, and these names are v1's surface under a shorter spelling:\n{}",
            violations.join("\n")
        );
    }

    /// A new glob widens what the derivation must cover, so its arrival must
    /// be a deliberate re-pin here, not a silent extension. This is one of the
    /// assertions `gate_support.rs`'s depth paragraph refers to.
    #[test]
    fn the_re_export_surface_is_the_reviewed_one() {
        let mut modules = super::gate_support::crate_root_glob_modules();
        modules.sort();
        assert_eq!(
            modules,
            [
                "api",
                "engine",
                "error",
                "keychain",
                "platform_lifecycle",
                "types"
            ],
            "lib.rs's glob re-export surface changed; re-review the derivation's \
             depth-one limit against the changed module set before re-pinning \
             this list"
        );
    }

    /// A glob source that itself GLOBS a third module would hoist that
    /// module's names, and deriving them would take recursive scanning.
    /// Refuse the shape at its source instead. (The NAMED depth-two form —
    /// a `pub use path::Name;` inside a glob source — is derived, and the
    /// spot-check test below pins the live instance.)
    #[test]
    fn no_glob_source_module_globs_a_third() {
        use super::gate_support::{parse_use_decl, PubUseTarget, UseParse};
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

        // Positive control: the matcher must find real glob lines in lib.rs,
        // or its silence over the modules below means nothing.
        let lib = std::fs::read_to_string(src.join("lib.rs")).expect("lib.rs must be readable");
        assert!(
            lib.lines().any(|line| matches!(
                parse_use_decl(line),
                UseParse::Decl(decl) if decl.targets.contains(&PubUseTarget::Glob)
            )),
            "the matcher found no glob in lib.rs itself, so it is not reading re-exports"
        );

        let mut violations = Vec::new();
        for module in super::gate_support::crate_root_glob_modules() {
            let relative = module.replace("::", "/");
            let path = [
                src.join(format!("{relative}.rs")),
                src.join(&relative).join("mod.rs"),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
            .unwrap_or_else(|| panic!("glob source `{module}` must have a source file"));
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("{} must be readable: {err}", path.display()));
            for (index, line) in source.lines().enumerate() {
                if let UseParse::Decl(decl) = parse_use_decl(line) {
                    if decl.is_pub && decl.targets.contains(&PubUseTarget::Glob) {
                        violations.push(format!(
                            "{}:{} — `{module}` globs `{}`; the crate root hoists that \
                             module's names at depth two, which the derivation does not \
                             cover. Extend the derivation before allowing this.",
                            path.display(),
                            index + 1,
                            decl.module
                        ));
                    }
                }
            }
        }
        assert!(
            violations.is_empty(),
            "a glob-re-exported module must not glob a third module:\n{}",
            violations.join("\n")
        );
    }

    /// The nested-tail evasion the review found: a named re-export with a
    /// nested path hoists its FINAL segment, and requiring the whole tail to
    /// be one plain identifier skipped it entirely.
    #[test]
    fn the_parser_hoists_the_final_segment_of_a_nested_re_export() {
        use super::gate_support::{parse_use_decl, PubUseTarget, UseParse};
        // Assembled at runtime so this file does not read as a violation.
        let v1 = ["orch", "estrator"].concat();
        match parse_use_decl(&format!("pub use {v1}::types::ConversationState;")) {
            UseParse::Decl(decl) => {
                assert_eq!(decl.module, format!("{v1}::types"));
                assert_eq!(
                    decl.targets,
                    [PubUseTarget::Named("ConversationState".to_owned())]
                );
                assert!(decl.is_pub && !decl.indented);
            }
            other => panic!("a nested named re-export must parse, got {other:?}"),
        }
        match parse_use_decl(&format!("pub use {v1}::types::*;")) {
            UseParse::Decl(decl) => {
                assert_eq!(decl.module, format!("{v1}::types"));
                assert_eq!(decl.targets, [PubUseTarget::Glob]);
            }
            other => panic!("a nested glob must parse, got {other:?}"),
        }
        // Renames stay skipped by design: a declaration, hoisting nothing.
        match parse_use_decl("pub use api::MLSContext as V1Ctx;") {
            UseParse::Decl(decl) => assert!(decl.targets.is_empty()),
            other => panic!("a rename must parse as an empty declaration, got {other:?}"),
        }
    }

    /// The four escapes the spot-check of the depth-two seal found, each held
    /// as a permanent control. Every one was a `use` line the old parser
    /// silently returned `None` for while the compiler resolved the name from
    /// `chat_v2` — proven by compilation at the time, pinned here since.
    #[test]
    fn the_shapes_the_spot_check_found_are_now_read() {
        use super::gate_support::{parse_use_decl, PubUseTarget, UseParse};
        let v1 = ["orch", "estrator"].concat();

        // F-1: the brace list. An import organizer's output, not an exotic.
        match parse_use_decl(&format!(
            "pub use {v1}::types::{}ConversationState, GroupState{};",
            "{", "}"
        )) {
            UseParse::Decl(decl) => assert_eq!(
                decl.targets,
                [
                    PubUseTarget::Named("ConversationState".to_owned()),
                    PubUseTarget::Named("GroupState".to_owned()),
                ]
            ),
            other => panic!("the brace list must parse, got {other:?}"),
        }

        // F-2: restricted visibility is still crate-wide reachability.
        match parse_use_decl(&format!("pub(crate) use {v1}::types::ConversationState;")) {
            UseParse::Decl(decl) => {
                assert!(decl.is_pub, "pub(crate) carries a pub marker");
                assert_eq!(
                    decl.targets,
                    [PubUseTarget::Named("ConversationState".to_owned())]
                );
            }
            other => panic!("pub(crate) use must parse, got {other:?}"),
        }

        // F-3: a PRIVATE use at the crate root is visible to descendants.
        match parse_use_decl(&format!("use {v1}::types::ConversationState;")) {
            UseParse::Decl(decl) => {
                assert!(!decl.is_pub);
                assert_eq!(
                    decl.targets,
                    [PubUseTarget::Named("ConversationState".to_owned())]
                );
            }
            other => panic!("a private use must parse, got {other:?}"),
        }

        // The fail-closed hinge: a shape the parser cannot read must be
        // distinguished from a non-use, because the derivation panics on one
        // and skips the other. A wrapped use tree is the everyday instance.
        assert_eq!(
            parse_use_decl(&format!("pub use {v1}::types::{}", "{")),
            UseParse::Unparseable { is_pub: true },
            "an unreadable use must be loud, not skipped"
        );
        assert_eq!(
            parse_use_decl("pub fn not_a_use() {}"),
            UseParse::NotAUse,
            "a non-use must not trip the fail-closed arm"
        );
    }

    /// F-4, the escape that was LIVE in the tree: `engine` re-exports a v1
    /// orchestrator type by name, and lib.rs globs `engine`, so the name is
    /// reachable as `crate::<Name>` at depth two. The derivation now reads a
    /// glob source's `pub use` lines, so the name must be in the forbidden
    /// set. If this fails, the derivation has stopped reading them.
    #[test]
    fn the_named_depth_two_re_export_is_derived() {
        let name = ["Message", "Processing", "Result"].concat();
        let needle = format!("crate::{name}");
        let derived = forbidden_crate_root_names();
        let found = derived
            .iter()
            .find(|(candidate, _)| *candidate == needle)
            .unwrap_or_else(|| panic!("{needle} must be derived through the `engine` glob"));
        assert_eq!(found.1, "engine", "{needle} is hoisted through `engine`");
    }

    #[test]
    fn the_derivation_covers_the_spellings_that_defeated_every_gate() {
        // The two the review found, named explicitly — not as the rule, but as
        // proof that the rule reaches them. If the derivation ever stops
        // covering these, it has stopped reading the re-export surface.
        let derived = forbidden_crate_root_names();
        for (name, module) in [
            (["MLS", "Context"].concat(), "api"),
            (["Mls", "Engine"].concat(), "engine"),
        ] {
            let needle = format!("crate::{name}");
            let found = derived
                .iter()
                .find(|(candidate, _)| *candidate == needle)
                .unwrap_or_else(|| panic!("{needle} must be derived from the crate root"));
            assert_eq!(found.1, module, "{needle} comes from `{module}`");
        }
    }

    #[test]
    fn the_isolation_check_can_actually_fail() {
        // A gate that cannot fail is not a gate. This proves the matcher would
        // catch a real import rather than silently passing on every input,
        // across every evasion form the review found: the brace form an import
        // organizer emits, a string literal holding a slash pair, and the
        // crate-root spellings that name no module path at all.
        let mut needles = forbidden_imports();
        needles.extend(forbidden_crate_root_names().into_iter().map(|(n, _)| n));

        for offending in [
            format!("use crate::{V1_MODULE}::types::ConversationState;"),
            format!(
                "use {}::{}{V1_MODULE}::types::ConversationState, ids::Seq{};",
                "crate", "{", "}"
            ),
            format!("let doc = \"https://x\"; use crate::{V1_MODULE}::X;"),
            format!("use crate::{};", ["MLS", "Context"].concat()),
            format!("use crate::{};", ["Mls", "Engine"].concat()),
            format!("use crate::{}{}{};", "{", ["MLS", "Context"].concat(), "}"),
            // The depth-two name the spot-check reached past every gate.
            format!(
                "use crate::{};",
                ["Message", "Processing", "Result"].concat()
            ),
            // F-5: from chat_v2/mod.rs a SINGLE super is the crate root, so
            // the module path and the derived names both have a super spelling
            // naming neither `crate` nor a double super. Deeper files' longer
            // super chains are covered by substring containment, pinned by the
            // double-super pair.
            format!("use super::{V1_MODULE}::types::ConversationState;"),
            format!(
                "use super::{};",
                ["Message", "Processing", "Result"].concat()
            ),
            format!("use super::super::{V1_MODULE}::types::ConversationState;"),
            format!("use super::super::{};", ["MLS", "Context"].concat()),
        ] {
            assert!(
                needles
                    .iter()
                    .any(|needle| SourceScan::line_contains(&offending, needle)),
                "the matcher must flag: {offending}"
            );
        }

        // And that stripping comments is what spares the module documentation,
        // which has to name the forbidden path in order to forbid it.
        let documented = format!("//! - No module may use crate::{V1_MODULE}::... here.");
        assert!(
            !needles
                .iter()
                .any(|needle| SourceScan::line_contains(&documented, needle)),
            "a mention inside a comment must not count as a violation"
        );

        // The over-refusal control: chat_v2's own paths must stay legal, or the
        // gate would forbid the tree it is protecting.
        for legitimate in [
            "use crate::chat_v2::ids::Seq;",
            "use crate::chat_v2::transcript::EnvelopeVerification;",
        ] {
            assert!(
                !needles
                    .iter()
                    .any(|needle| SourceScan::line_contains(legitimate, needle)),
                "the gate must not flag chat_v2's own paths: {legitimate}"
            );
        }
    }
}
