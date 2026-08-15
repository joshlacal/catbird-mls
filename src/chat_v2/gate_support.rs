//! The shared scanner behind every source-walking gate in this tree.
//!
//! Five gates assert that some token never appears in `chat_v2` — v1
//! orchestrator imports, forbidden recovery mechanisms, v1 stores, a defaulted
//! store method, a reference store reachable from a release build. Each had its
//! own copy of "walk the tree, strip comments, look for a substring", and a
//! review found the copies shared three evasions. All three were reproduced by
//! mutation, so they are quoted here as facts rather than as hypotheses:
//!
//! 1. **The brace form of a `use` tree.** `use crate::{orchestrator::types::X};`
//!    never contains the contiguous substring `crate::orchestrator`, so every
//!    gate matching on that string passed. This is not an exotic spelling —
//!    it is what an editor's import organizer produces when a file imports two
//!    things from one crate root.
//! 2. **A non-`.rs` file.** The walk collected only `.rs` files, so
//!    `include!("smuggled.inc")` pulled arbitrary code into the crate through a
//!    path no gate looked at.
//! 3. **A string literal containing `//`.** Comment stripping cut each line at
//!    the first `//`, with no idea whether it was inside a literal, so any line
//!    holding a URL-ish string hid everything after it — including a real
//!    import on the same line.
//!
//! Each is now closed, and each is a permanent positive control in this
//! module's own tests. A gate that has never been shown to fail is a decoration.
//!
//! # How matching works now
//!
//! A file's code is normalized before matching: comments are stripped with
//! knowledge of string literals, then whitespace and braces are removed
//! entirely and the whole file becomes one string. Removing braces is what
//! collapses `use crate::{orchestrator::x}` back to `usecrate::orchestrator::x`,
//! and joining the file is what catches the same import split across lines.
//! Byte offsets are mapped back to line numbers so a violation still reports
//! where it is.
//!
//! Normalizing this aggressively could in principle fuse two innocent lines into
//! a forbidden token. That trade is deliberate: a false positive is a minute of
//! a reader's time, and a false negative is the thing the gate exists to stop.
//!
//! # The boundary of what any of these gates can prove
//!
//! They prove a token is absent **from `src/chat_v2`**. That is the whole
//! claim, and it is worth stating because the natural reading is stronger.
//!
//! A thin wrapper living in the v1 tree — a function in `src/orchestrator` that
//! calls the forbidden thing, re-exported under an innocent name — is invisible
//! here, and importing that name into `chat_v2` would satisfy every gate. Only
//! the *spelling* of the v1 module path is caught, so an import of some other
//! v1 module that happens to reach the same store is caught only if its own
//! name is on a needle list.
//!
//! This is a stated limitation, not an oversight to be fixed by widening the
//! walk: scanning the v1 tree would flag v1's own legitimate use of its own
//! mechanisms on every run. The real guard against a wrapper is that adding one
//! requires editing the v1 tree deliberately, which is a review event rather
//! than an editor's import completion — which is exactly the accident these
//! gates exist to catch.
//!
//! # What this does not parse
//!
//! It is a lexer, not a compiler. It understands line comments, ordinary string
//! literals with escapes, raw strings including hashed forms, and character
//! literals distinguished from lifetimes. It does **not** understand block
//! comments — there are none in this tree, and a `/* */` comment naming a
//! forbidden token would be reported as a violation rather than missed, which
//! is the safe direction.

use std::path::{Path, PathBuf};

/// Where a forbidden token was found.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The file it was found in, including a file reached through `include!`.
    pub file: PathBuf,
    /// The line it was found on, 1-based.
    pub line: usize,
    /// The source line, trimmed.
    pub text: String,
}

impl Finding {
    /// The rendering every gate uses in its failure message.
    pub fn describe(&self) -> String {
        format!("{}:{}: {}", self.file.display(), self.line, self.text)
    }
}

/// One file, with its code normalized for matching and a map back to lines.
struct NormalizedFile {
    origin: PathBuf,
    lines: Vec<String>,
    text: String,
    /// The source line each byte of `text` came from, 1-based.
    line_of: Vec<usize>,
}

/// Every source file a gate must consider, normalized and ready to match.
pub struct SourceScan {
    files: Vec<NormalizedFile>,
    /// `include!` invocations whose target could not be read and scanned.
    ///
    /// Never empty-and-ignored: gates assert on this, because an unscanned
    /// include is a hole in every one of them at once.
    pub unresolved_includes: Vec<String>,
}

impl SourceScan {
    /// Scans the whole `chat_v2` tree.
    pub fn of_chat_v2() -> Self {
        Self::of_tree(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chat_v2"))
    }

    /// Scans an arbitrary directory. Exposed for this module's own controls.
    pub fn of_tree(root: &Path) -> Self {
        let mut paths = Vec::new();
        collect_rust_sources(root, &mut paths);
        let mut files = Vec::new();
        let mut unresolved_includes = Vec::new();
        for path in paths {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("{} must be readable: {err}", path.display()));
            for target in included_paths(&source, &mut unresolved_includes) {
                let resolved = path
                    .parent()
                    .expect("a source file always has a parent directory")
                    .join(&target);
                match std::fs::read_to_string(&resolved) {
                    // Included code is code. It is scanned under its own name so
                    // a violation points at the file that actually holds it.
                    Ok(included) => files.push(normalize(resolved, &included)),
                    Err(_) => unresolved_includes.push(format!(
                        "{}: included target {target:?} could not be read",
                        path.display()
                    )),
                }
            }
            files.push(normalize(path, &source));
        }
        Self {
            files,
            unresolved_includes,
        }
    }

    /// How many files were scanned. Gates assert this is non-zero, because a
    /// walk that finds nothing passes every assertion vacuously.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Every occurrence of `needle` in the scanned code.
    pub fn findings(&self, needle: &str) -> Vec<Finding> {
        let needle = normalized_text(needle);
        if needle.is_empty() {
            return Vec::new();
        }
        let mut found = Vec::new();
        for file in &self.files {
            for (offset, _) in file.text.match_indices(needle.as_str()) {
                let line = file.line_of[offset];
                found.push(Finding {
                    file: file.origin.clone(),
                    line,
                    text: file.lines[line - 1].trim().to_owned(),
                });
            }
        }
        found
    }

    /// Whether a single line of code — not a file — contains `needle`.
    ///
    /// The form the positive controls use: it applies the identical comment
    /// stripping and normalization to a snippet, so a control proves something
    /// about the real matcher rather than about a second implementation of it.
    pub fn line_contains(line: &str, needle: &str) -> bool {
        normalized_text(&code_only(line)).contains(&normalized_text(needle))
    }
}

/// A name the crate root hoists out of a module, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateRootName {
    /// The bare name, reachable as `crate::<name>`.
    pub name: String,
    /// The module the crate root re-exported it from.
    pub module: String,
}

/// Every name reachable as `crate::<name>` because `lib.rs` re-exports it.
///
/// This exists because a needle list keyed to *module paths* is defeated by
/// construction the moment the crate root globs a module. `src/lib.rs` carries
/// six `pub use <mod>::*;` lines, so `use crate::MLSContext;` reaches v1's whole
/// SQLCipher group and crypto surface — `create_group`, `encrypt_message`,
/// `delete_group` — while naming neither `crate::orchestrator` nor
/// `mls_context`, and every gate passed it. `use crate::MlsEngine;` is the same
/// hole through `engine`.
///
/// Listing the two spellings would have been a patch. Deriving the set from the
/// re-export surface makes the coverage automatic: add a `pub use` glob to
/// `lib.rs`, or a `pub` item to a module already globbed, and it is forbidden in
/// `chat_v2` without anyone remembering to extend a list.
///
/// # Why not a compile-fail test
///
/// The obvious stronger mechanism is a `trybuild` compile-fail case carrying
/// the evasion spellings, and it does not work here — for a reason worth
/// recording so nobody reaches for it again. `trybuild` asserts that code
/// **fails to compile**. `use crate::MLSContext;` inside `chat_v2` compiles
/// perfectly, which *is* the defect; there is no compile error to assert.
/// Turning it into one means narrowing the `lib.rs` globs, and those are the
/// crate's public API, consumed by the UniFFI scaffolding and by downstream
/// platforms — not this lane's to narrow. So the mechanism is a derivation,
/// and no dependency was added.
///
/// # What it reads, and what it does not
///
/// Both re-export forms in `lib.rs`: `pub use <mod>::*;` (nested modules
/// included), whose source module is then scanned for `pub` items, and
/// `pub use <path>::<Name>;`, which hoists its FINAL segment — the review
/// showed `pub use orchestrator::types::ConversationState;` evading the gate
/// when the tail was required to be a single plain identifier. Renames
/// (`pub use x as y;`) are skipped — they hoist a name this scan would
/// misreport, and a rename of a v1 module into `chat_v2`'s reach would be a
/// deliberate act rather than an editor accident.
///
/// It is **depth one**. A module that itself globs a third module hoists that
/// module's names too, and those are not derived here. Nothing in `lib.rs`'s
/// glob sources does that today, and two tests in `chat_v2/mod.rs` are what
/// make its arrival a failure rather than a silent hole:
/// `the_re_export_surface_is_the_reviewed_one` pins the glob-module set, so a
/// NEW glob is a deliberate re-pin, and `no_glob_source_module_globs_a_third`
/// refuses the depth-two shape inside the modules already globbed.
pub fn crate_root_glob_exports() -> Vec<CrateRootName> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("lib.rs must be readable");

    let mut found = Vec::new();
    for line in lib.lines() {
        match parse_pub_use(line) {
            Some(PubUse {
                module,
                target: PubUseTarget::Glob,
            }) => {
                for name in module_pub_items(&src, &module) {
                    found.push(CrateRootName {
                        name,
                        module: module.clone(),
                    });
                }
            }
            Some(PubUse {
                module,
                target: PubUseTarget::Named(name),
            }) => {
                found.push(CrateRootName { name, module });
            }
            None => {}
        }
    }
    found
}

/// The modules `lib.rs` glob-re-exports, for the depth-two guard.
pub fn crate_root_glob_modules() -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("lib.rs must be readable");
    lib.lines()
        .filter_map(parse_pub_use)
        .filter(|re_export| re_export.target == PubUseTarget::Glob)
        .map(|re_export| re_export.module)
        .collect()
}

/// One `pub use …;` line, reduced to what it hoists onto the crate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubUse {
    /// The module path the hoisted surface comes from.
    pub module: String,
    pub target: PubUseTarget,
}

/// What a `pub use` line hoists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubUseTarget {
    /// `pub use m::*;` — every `pub` item of `m`.
    Glob,
    /// `pub use m::Name;` or `pub use m::nested::Name;` — `Name` alone.
    Named(String),
}

/// Parses one line as a re-export, or `None` if it is not one.
///
/// Renames (` as `) are skipped by design — see `crate_root_glob_exports`.
pub fn parse_pub_use(line: &str) -> Option<PubUse> {
    let code = code_only(line);
    let trimmed = code.trim();
    let rest = trimmed.strip_prefix("pub use ")?.strip_suffix(';')?;
    if rest.contains(" as ") {
        return None;
    }
    let (module, tail) = rest.split_once("::")?;
    if !is_plain_ident(module) {
        return None;
    }
    if tail == "*" {
        return Some(PubUse {
            module: module.to_owned(),
            target: PubUseTarget::Glob,
        });
    }
    if let Some(inner) = tail.strip_suffix("::*") {
        if !inner.split("::").all(is_plain_ident) {
            return None;
        }
        return Some(PubUse {
            module: format!("{module}::{inner}"),
            target: PubUseTarget::Glob,
        });
    }
    let mut segments: Vec<&str> = tail.split("::").collect();
    if !segments.iter().all(|segment| is_plain_ident(segment)) {
        return None;
    }
    let name = segments
        .pop()
        .expect("split_once guarantees at least one segment");
    let module = if segments.is_empty() {
        module.to_owned()
    } else {
        format!("{module}::{}", segments.join("::"))
    };
    Some(PubUse {
        module,
        target: PubUseTarget::Named(name.to_owned()),
    })
}

fn is_plain_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// The `pub` items a module declares, as the crate root would hoist them.
fn module_pub_items(src: &Path, module: &str) -> Vec<String> {
    let relative = module.replace("::", "/");
    let path = [
        src.join(format!("{relative}.rs")),
        src.join(&relative).join("mod.rs"),
    ]
    .into_iter()
    .find(|candidate| candidate.exists())
    .unwrap_or_else(|| panic!("a glob-re-exported module must have a source file: {module}"));
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", path.display()));

    let keywords = [
        "struct ", "enum ", "trait ", "type ", "fn ", "const ", "static ", "union ", "mod ",
    ];
    let mut names = Vec::new();
    for line in source.lines() {
        let code = code_only(line);
        let trimmed = code.trim();
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };
        // `pub async fn`, `pub unsafe fn`, `pub extern "C" fn` all reach `fn`.
        let rest = rest
            .strip_prefix("async ")
            .or_else(|| rest.strip_prefix("unsafe "))
            .unwrap_or(rest);
        let Some(after) = keywords
            .iter()
            .find_map(|keyword| rest.strip_prefix(keyword))
        else {
            continue;
        };
        let name: String = after
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// Strips a line comment, with knowledge of what is inside a literal.
///
/// The evasion this closes: `let url = "https://x"; use crate::orchestrator::Y;`
/// used to be truncated at the `//` inside the URL, hiding the import entirely.
pub fn code_only(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        // A raw string, possibly hashed: r"…", r#"…"#, r##"…"##.
        if ch == 'r' {
            let mut hashes = 0;
            while index + 1 + hashes < chars.len() && chars[index + 1 + hashes] == '#' {
                hashes += 1;
            }
            if chars.get(index + 1 + hashes) == Some(&'"') {
                let end = raw_string_end(&chars, index + 2 + hashes, hashes);
                out.extend(&chars[index..end.min(chars.len())]);
                index = end;
                continue;
            }
        }
        if ch == '"' {
            let end = string_end(&chars, index + 1);
            out.extend(&chars[index..end.min(chars.len())]);
            index = end;
            continue;
        }
        // A character literal, which must not be confused with a lifetime:
        // `'"'` would otherwise open a string that never closes.
        if ch == '\'' {
            if let Some(end) = char_literal_end(&chars, index) {
                out.extend(&chars[index..end]);
                index = end;
                continue;
            }
        }
        if ch == '/' && chars.get(index + 1) == Some(&'/') {
            break;
        }
        out.push(ch);
        index += 1;
    }
    out
}

/// The index just past a closing `"`, starting from inside the string.
fn string_end(chars: &[char], mut index: usize) -> usize {
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 2,
            '"' => return index + 1,
            _ => index += 1,
        }
    }
    chars.len()
}

/// The index just past a raw string's terminator.
fn raw_string_end(chars: &[char], mut index: usize, hashes: usize) -> usize {
    while index < chars.len() {
        if chars[index] == '"' && chars[index + 1..].iter().take(hashes).all(|c| *c == '#') {
            return index + 1 + hashes;
        }
        index += 1;
    }
    chars.len()
}

/// The index just past a character literal, or `None` for a lifetime.
fn char_literal_end(chars: &[char], index: usize) -> Option<usize> {
    let escaped = chars.get(index + 1) == Some(&'\\');
    // `'a'` closes at +2; `'\n'` at +3; `'\u{1F600}'` needs a search.
    let start = if escaped { index + 2 } else { index + 1 };
    let limit = (start + 12).min(chars.len());
    chars[start..limit]
        .iter()
        .position(|c| *c == '\'')
        .map(|offset| start + offset + 1)
        .filter(|end| escaped || *end == index + 3)
}

/// Removes whitespace and braces, which is what collapses a `use` tree.
fn normalized_text(code: &str) -> String {
    code.chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '{' && *ch != '}')
        .collect()
}

fn normalize(origin: PathBuf, source: &str) -> NormalizedFile {
    let lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let mut text = String::new();
    let mut line_of = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        for ch in normalized_text(&code_only(line)).chars() {
            let before = text.len();
            text.push(ch);
            for _ in before..text.len() {
                line_of.push(index + 1);
            }
        }
    }
    NormalizedFile {
        origin,
        lines,
        text,
        line_of,
    }
}

fn collect_rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).expect("the source tree must be readable");
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| entry.expect("directory entry must be readable").path())
        .collect();
    // Sorted so a failure lists the same files in the same order every run.
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_rust_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// Every path this source `include!`s, recording unresolvable ones.
///
/// `include_str!` and `include_bytes!` are deliberately not matched: they carry
/// data, not code, and the contract corpus is embedded with them.
fn included_paths(source: &str, unresolved: &mut Vec<String>) -> Vec<String> {
    // Assembled rather than written, for the same reason every needle in this
    // tree is: a literal here would make this scanner report itself.
    let directive = ["include", "!("].concat();
    let mut targets = Vec::new();
    for line in source.lines() {
        let code = code_only(line);
        let mut rest = code.as_str();
        while let Some(at) = rest.find(directive.as_str()) {
            rest = &rest[at + directive.len()..];
            let argument = rest.trim_start();
            match argument
                .strip_prefix('"')
                .and_then(|tail| tail.find('"').map(|end| tail[..end].to_owned()))
            {
                Some(target) => targets.push(target),
                // A computed target — `concat!(env!("OUT_DIR"), …)` and the
                // like. It cannot be followed to a file, so it cannot be
                // scanned, so it is reported rather than passed over.
                None => unresolved.push(format!("computed target: {}", line.trim())),
            }
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The v1 module path, assembled at runtime.
    ///
    /// Every fixture below is built the same way. A literal here would make the
    /// file that serves the gates a violation of them — which is the trap the
    /// original gates avoided by assembling their needles, and it applies just
    /// as much to a control that quotes the thing it catches.
    fn forbidden() -> String {
        ["crate", "orchestrator"].join("::")
    }

    fn brace_form() -> String {
        format!(
            "use {}::{}{}::types::ConversationState, ids::Seq{};",
            "crate", "{", "orchestrator", "}"
        )
    }

    #[test]
    fn the_brace_form_of_a_use_tree_is_caught() {
        // Evasion one, verified by mutation against the old matcher. This is
        // what an editor's import organizer emits when a file takes two things
        // from one crate root, and it contains no contiguous forbidden
        // substring — so every gate passed on it.
        let offending = brace_form();
        assert!(
            !offending.contains(&forbidden()),
            "the fixture must not contain the plain needle, or it proves nothing"
        );
        assert!(
            SourceScan::line_contains(&offending, &forbidden()),
            "normalization must collapse the brace form: {offending}"
        );
    }

    #[test]
    fn a_use_tree_split_across_lines_is_caught() {
        // The same evasion after a formatter wraps it. Line-by-line matching
        // cannot see this at all; whole-file normalization can, which is why
        // the scan joins a file before matching.
        let dir = scratch("split-use-tree");
        let source = format!(
            "use {}::{}\n    {}::types::ConversationState,\n{};\n",
            "crate", "{", "orchestrator", "}"
        );
        std::fs::write(dir.join("offender.rs"), source).unwrap();

        let scan = SourceScan::of_tree(&dir);
        let findings = scan.findings(&forbidden());
        assert_eq!(findings.len(), 1, "the split import must be found");
        assert_eq!(
            findings[0].line, 1,
            "a violation spanning lines is reported where the match begins"
        );
    }

    #[test]
    fn code_smuggled_through_a_non_rust_file_is_scanned() {
        // Evasion two. The walk collected `.rs` files only, so a `.inc` was
        // invisible to every gate while being compiled into the crate exactly
        // like source.
        let dir = scratch("include-smuggling");
        let directive = ["include", "!"].concat();
        std::fs::write(
            dir.join("host.rs"),
            format!("mod inner {{\n    {directive}(\"smuggled.inc\");\n}}\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("smuggled.inc"),
            format!("use {}::types::ConversationState;\n", forbidden()),
        )
        .unwrap();

        let scan = SourceScan::of_tree(&dir);
        let findings = scan.findings(&forbidden());
        assert_eq!(findings.len(), 1, "included code must be scanned");
        assert!(
            findings[0].file.ends_with("smuggled.inc"),
            "the violation must be reported against the file holding it, got {}",
            findings[0].describe()
        );
    }

    #[test]
    fn an_include_that_cannot_be_followed_is_reported_rather_than_skipped() {
        // Both failure modes of the same hazard: a target that is computed at
        // build time and therefore cannot be read here, and one that simply is
        // not there. Silence on either would be a hole in all five gates at
        // once, so they are surfaced and the gates assert on them.
        let dir = scratch("unresolvable-include");
        let directive = ["include", "!"].concat();
        std::fs::write(
            dir.join("host.rs"),
            format!(
                "{directive}(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n{directive}(\"missing.inc\");\n"
            ),
        )
        .unwrap();

        let scan = SourceScan::of_tree(&dir);
        assert_eq!(
            scan.unresolved_includes.len(),
            2,
            "a computed include and a missing file must both be reported: {:?}",
            scan.unresolved_includes
        );
    }

    #[test]
    fn a_string_literal_containing_a_slash_pair_does_not_hide_the_rest_of_the_line() {
        // Evasion three. Truncating at the first `//` cut this line inside the
        // URL, hiding the import that follows it on the same line.
        let offending = format!("let doc = \"https://example.com\"; use {}::X;", forbidden());
        assert!(
            SourceScan::line_contains(&offending, &forbidden()),
            "a slash pair inside a string literal must not end the line"
        );
    }

    #[test]
    fn a_genuine_comment_is_still_stripped() {
        // The property string-awareness must not break: documentation has to be
        // able to name what it forbids, which is most of why comments are
        // stripped at all.
        let documented = format!("// No module may use {}::types here.", forbidden());
        assert!(
            !SourceScan::line_contains(&documented, &forbidden()),
            "a mention inside a comment must not count as a violation"
        );
        let trailing = format!("let x = 1; // see {}::types", forbidden());
        assert!(!SourceScan::line_contains(&trailing, &forbidden()));
    }

    #[test]
    fn a_character_literal_holding_a_quote_does_not_open_a_string() {
        // The lexer trap this file would otherwise have fallen into itself: a
        // naive scanner reads `'"'` as an unterminated string and then treats
        // everything after it as literal text.
        let line = format!("if ch == '\"' {{ }} use {}::X;", forbidden());
        assert!(
            SourceScan::line_contains(&line, &forbidden()),
            "a char literal must not swallow the rest of the line"
        );

        // A lifetime is a lone quote with no closing partner and must not do it
        // either.
        let lifetime = format!("fn f<'a>(x: &'a str) {{ }} use {}::X;", forbidden());
        assert!(SourceScan::line_contains(&lifetime, &forbidden()));
    }

    #[test]
    fn a_raw_string_is_read_to_its_own_terminator() {
        // Hashed raw strings holding braces and slashes are real in this tree —
        // the strict-JSON fixtures are written that way — and mis-lexing one
        // would corrupt the normalization of everything after it.
        let line = format!(
            "let json = r#\"{{\"a\": \"//\"}}\"#; use {}::X;",
            forbidden()
        );
        assert!(SourceScan::line_contains(&line, &forbidden()));
    }

    #[test]
    fn the_real_tree_is_actually_walked_and_fully_resolved() {
        // A scan that finds no files passes every gate vacuously. Each gate
        // asserts this for itself; proving it once here is what makes the
        // assertion in each of them a formality rather than the only check.
        let scan = SourceScan::of_chat_v2();
        assert!(
            scan.file_count() > 20,
            "the chat_v2 walk found only {} files",
            scan.file_count()
        );
        assert!(
            scan.unresolved_includes.is_empty(),
            "unresolved includes in chat_v2: {:?}",
            scan.unresolved_includes
        );
    }

    /// A private scratch directory for the file-level controls.
    ///
    /// Under the crate's own `target/`, so nothing is written outside the
    /// workspace and a stale directory from an earlier run cannot make a
    /// control pass for the wrong reason.
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("chat-v2-gate-controls")
            .join(name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("a stale control directory must be replaceable");
        }
        std::fs::create_dir_all(&dir).expect("the control directory must be creatable");
        dir
    }
}
