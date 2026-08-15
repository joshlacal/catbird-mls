//! The v2 store trait: every method required.
//!
//! # The footgun this exists to not reproduce
//!
//! v1's [`crate::orchestrator`] storage backend declares thirty-four methods and
//! ships default no-op bodies for twenty of them. A platform that never
//! implements one does not fail to compile, does not fail at runtime, and does
//! not fail at all — the call returns `Ok(())` and the state is gone. v1 knows
//! this is a hazard and mitigates it with an init-time capabilities *warning*, a
//! list a backend self-reports and can silently fall out of date with.
//!
//! Every method here is required. A platform that has not implemented one
//! cannot construct the type, and the failure is a compile error naming the
//! method. That is the whole design: not a warning, not a checklist, and not a
//! convention — an unimplementable trait.
//!
//! A test in this module enforces it mechanically, because "do not add a default
//! body" is exactly the kind of rule that erodes the first time a method is
//! added to unblock somebody.
//!
//! # No cursor setter
//!
//! There is deliberately no method that writes a scan position. §9 requires that
//! effects persist atomically *before* advancing, and the only way to advance
//! here is [`ChatV2Store::commit_page`], which carries the effects that justify
//! the advance. See [`super::page`] for why that is one value rather than
//! several calls.
//!
//! # Reads return absence; they do not interpret it
//!
//! [`ChatV2Store::cursor`] returns `Option`, not a defaulted
//! [`AfterSeq::START`]. Deciding that a device with no stored position should
//! scan from the beginning is a caller's decision — a fresh conversation and a
//! store that lost its cursor want different handling, and a layer that
//! substitutes a default erases the difference before anyone can act on it.

use super::super::cursor::AfterSeq;
use super::super::interval::RecipientBinding;
use super::super::journal::{JournalEntry, OperationIdentity};
use super::super::reducer::ApplicationReducer;
use super::page::{PageCommit, PersistedEntry, RatchetCheckpoint};
use super::{StorageError, StoreScope};
use async_trait::async_trait;

/// The auto-trait bounds a store must satisfy on this target.
///
/// Mirrors the split v1 uses: native platforms hand stores across threads, while
/// wasm's single-threaded executor does not require `Send`/`Sync` and cannot
/// satisfy them for browser-backed handles.
#[cfg(not(target_arch = "wasm32"))]
pub trait ChatV2StoreBounds: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> ChatV2StoreBounds for T {}

/// The auto-trait bounds a store must satisfy on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait ChatV2StoreBounds {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> ChatV2StoreBounds for T {}

/// Durable storage for one principal's clean-chat state.
///
/// Opened per DID, against its own database file, never shared with v1 or with
/// another principal. See [`super`] for why that separation is physical.
///
/// **Every method is required.** There are no defaults, and a test in this
/// module fails the build if one appears.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait ChatV2Store: ChatV2StoreBounds {
    /// The principal this store was opened for.
    ///
    /// Every method below refuses an access naming a different DID with
    /// [`StorageError::CrossDidAccess`]; this exposes the owner so a caller can
    /// route correctly rather than discover the mistake by failing.
    fn scope(&self) -> &StoreScope;

    /// The stored scan position for one exact device.
    ///
    /// `None` means this store holds no position for that device. It is not
    /// [`AfterSeq::START`], and the difference is the caller's to act on.
    async fn cursor(&self, binding: &RecipientBinding) -> Result<Option<AfterSeq>, StorageError>;

    /// Persists a page's entire effect and advances the scan position, as one
    /// atomic act.
    ///
    /// Either every entry, the ratchet checkpoint, and the new position become
    /// durable together, or none of them does and the store is untouched.
    /// Implementations must run every fallible check before touching state.
    ///
    /// The commit is a compare-and-set: it is refused with
    /// [`StorageError::CursorMismatch`] when the stored position is not the one
    /// the page was fetched against, so two commits racing on one device cannot
    /// lose each other's effects. A page continuing from a non-initial position
    /// against a store holding none is refused as
    /// [`StorageError::NotFound`] — a different fault, and a different mistake,
    /// from losing a race.
    async fn commit_page(&self, page: &PageCommit) -> Result<(), StorageError>;

    /// Reads durably stored entries for one exact device, oldest first.
    ///
    /// Returns entries strictly above `after`, capped at `limit`. Rejections are
    /// returned alongside frames: both are durable outcomes, and a caller that
    /// saw only frames would re-request entries the ratchet has already passed.
    async fn entries_after(
        &self,
        binding: &RecipientBinding,
        after: AfterSeq,
        limit: u32,
    ) -> Result<Vec<PersistedEntry>, StorageError>;

    /// The most recent ratchet checkpoint stored for one exact device.
    ///
    /// `None` when no page has yet moved ratchet state for it.
    async fn ratchet_checkpoint(
        &self,
        binding: &RecipientBinding,
    ) -> Result<Option<RatchetCheckpoint>, StorageError>;

    /// Durably records a journalled mutation, or updates its progress.
    ///
    /// The bytes are stored verbatim. §5 deduplicates on
    /// `(endpoint NSID, principal DID, operation ID)` and compares the stored
    /// transcript digest and signature byte-for-byte, so an implementation that
    /// re-encoded a body — reserializing it, or normalizing it on the way to a
    /// column — would produce a retry the server reads as a different request.
    async fn put_journal_entry(&self, entry: &JournalEntry) -> Result<(), StorageError>;

    /// Reads one journalled mutation by its idempotency identity.
    async fn journal_entry(
        &self,
        identity: &OperationIdentity,
    ) -> Result<Option<JournalEntry>, StorageError>;

    /// Every journalled mutation whose outcome is still unknown.
    ///
    /// The restart path. These are the operations that may or may not have
    /// committed, and the only way to find out is to resubmit the identical
    /// stored bytes and read the result the server kept.
    async fn outstanding_journal_entries(&self) -> Result<Vec<JournalEntry>, StorageError>;

    /// Durably records one exact-device application access schedule.
    ///
    /// Keyed by the reducer's own binding — `(conversation, recipient DID,
    /// recipient device)`. §9 makes application visibility per exact
    /// `(DID, deviceId)` MLS leaf, never shared across a DID's devices, so a key
    /// that omitted the device would let one device's schedule answer for a
    /// sibling's and hand it history it never had.
    async fn put_schedule(&self, schedule: &ApplicationReducer) -> Result<(), StorageError>;

    /// Reads the schedule for one exact device.
    ///
    /// `None` when this store holds none. Implementations reconstruct it with
    /// [`ApplicationReducer::rehydrate`], which refuses a schedule whose
    /// intervals name another device or whose expected context disagrees with
    /// its intervals.
    async fn schedule(
        &self,
        binding: &RecipientBinding,
    ) -> Result<Option<ApplicationReducer>, StorageError>;
}

/// Enforces that [`ChatV2Store`] never grows a default method body.
///
/// The rule this protects is the whole reason the trait exists in the form it
/// does, and it is the kind of rule that erodes quietly: a method gets a default
/// "just for now" so one platform can compile, and the silent-data-loss shape
/// this trait was written to avoid is back.
///
/// The scan is confined to the trait body, which is why the test functions in
/// this very file — all of which have bodies — are not violations of it.
#[cfg(test)]
mod required_methods {
    use std::path::Path;

    /// The trait whose methods must all be required.
    ///
    /// Assembled at runtime for the same reason the other gates in this tree
    /// assemble their needles: so the gate's own source does not read as the
    /// thing it forbids.
    fn guarded_trait() -> String {
        ["pub trait", "ChatV2Store"].join(" ")
    }

    /// Removes `//` comments so documentation that shows a method body, or
    /// mentions one, is not mistaken for a declaration.
    fn strip_comments(source: &str) -> String {
        source
            .lines()
            .map(|line| match line.find("//") {
                Some(index) => &line[..index],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The text between the guarded trait's braces, or `None` if absent.
    ///
    /// The name must end exactly where the header does. This file also declares
    /// `ChatV2StoreBounds`, whose declaration *starts with* the guarded trait's
    /// full header, and matching it instead finds an empty body — a gate that
    /// scans nothing and passes. That is not hypothetical: it is what this
    /// scanner did on its first run, and the vacuity assertion below is what
    /// caught it.
    fn trait_body(code: &str, header: &str) -> Option<String> {
        let mut search = 0usize;
        while let Some(relative) = code[search..].find(header) {
            let start = search + relative;
            let after = start + header.len();
            if code[after..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                // A longer name that merely begins the same way.
                search = after;
                continue;
            }

            let open = code[start..].find('{')? + start;
            let mut depth = 0usize;
            for (offset, character) in code[open..].char_indices() {
                match character {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(code[open + 1..open + offset].to_owned());
                        }
                    }
                    _ => {}
                }
            }
            return None;
        }
        None
    }

    /// Every method in the trait body, paired with whether it carries a body.
    ///
    /// A declaration terminated by `;` is required; one that opens a brace
    /// before its terminator ships a default.
    fn methods(body: &str) -> Vec<(String, bool)> {
        let mut found = Vec::new();
        let mut rest = body;
        while let Some(index) = rest.find("fn ") {
            let after = &rest[index + 3..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let terminator = after.find(';');
            let opener = after.find('{');
            let has_default = match (terminator, opener) {
                (Some(semicolon), Some(brace)) => brace < semicolon,
                (None, Some(_)) => true,
                _ => false,
            };
            found.push((name, has_default));
            rest = after;
        }
        found
    }

    fn guarded_methods(source: &str) -> Vec<(String, bool)> {
        let code = strip_comments(source);
        let body = trait_body(&code, &guarded_trait()).expect("the guarded trait must be present");
        methods(&body)
    }

    #[test]
    fn every_store_method_is_required() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chat_v2/storage/store.rs");
        let source = std::fs::read_to_string(path).expect("the trait's source must be readable");
        let methods = guarded_methods(&source);

        assert!(
            methods.len() >= 5,
            "the scan found only {} methods, so it is not looking at the trait",
            methods.len()
        );

        let defaulted: Vec<&String> = methods
            .iter()
            .filter(|(_, has_default)| *has_default)
            .map(|(name, _)| name)
            .collect();
        assert!(
            defaulted.is_empty(),
            "every v2 store method must be required; these ship a default body \
             and would silently discard state on a platform that ignored them: {defaulted:?}"
        );
    }

    #[test]
    fn the_method_count_is_pinned_so_the_scope_sweep_stays_complete() {
        // Every method taking a principal-bearing argument must refuse a
        // foreign one, and that is checked by calling them — in
        // `memory::tests`, across the three `another_principal...` and
        // `every_read_and_write...` sweeps. A call-based sweep cannot notice a
        // method nobody added to it, so the count is pinned here: adding a
        // method fails this assertion, and the fix is to extend the sweep
        // rather than to bump the number.
        //
        // Of the ten, `scope` and `outstanding_journal_entries` take no
        // principal-bearing argument and are inherently scoped; the other eight
        // are swept.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chat_v2/storage/store.rs");
        let source = std::fs::read_to_string(path).expect("the trait's source must be readable");
        let methods = guarded_methods(&source);
        let names: Vec<&str> = methods.iter().map(|(name, _)| name.as_str()).collect();

        assert_eq!(
            names,
            vec![
                "scope",
                "cursor",
                "commit_page",
                "entries_after",
                "ratchet_checkpoint",
                "put_journal_entry",
                "journal_entry",
                "outstanding_journal_entries",
                "put_schedule",
                "schedule",
            ],
            "the store's method set changed; extend the foreign-principal sweep \
             in memory::tests to cover any new principal-bearing method, then \
             update this list"
        );
    }

    #[test]
    fn the_gate_can_actually_fail() {
        // A control that cannot fail is not a control. This proves the scanner
        // recognizes a default body rather than reporting every input clean,
        // and that it distinguishes one from an ordinary required declaration.
        let offending = format!(
            "{} {{\n    async fn store(&self) -> Result<(), E> {{\n        Ok(())\n    }}\n}}",
            guarded_trait()
        );
        let scanned = guarded_methods(&offending);
        assert_eq!(scanned.len(), 1);
        assert!(scanned[0].1, "the scanner must flag a genuine default body");

        let clean = format!(
            "{} {{\n    async fn store(&self) -> Result<(), E>;\n}}",
            guarded_trait()
        );
        let scanned = guarded_methods(&clean);
        assert_eq!(scanned.len(), 1);
        assert!(
            !scanned[0].1,
            "a required declaration must not be reported as defaulted"
        );
    }

    #[test]
    fn a_longer_trait_name_starting_the_same_way_is_not_the_guarded_one() {
        // The trap this scanner actually fell into. `ChatV2StoreBounds` begins
        // with the guarded header, and matching it yields an empty body, so the
        // gate would scan nothing and pass on any input — including a trait full
        // of defaults.
        let decoys = format!(
            "{}Bounds: Send + Sync {{}}\n{}: {}Bounds {{\n    async fn store(&self) -> Result<(), E>;\n}}",
            guarded_trait(),
            guarded_trait(),
            guarded_trait().split(' ').next_back().unwrap(),
        );
        let scanned = guarded_methods(&decoys);
        assert_eq!(
            scanned.len(),
            1,
            "the scanner must skip the decoy and find the real trait's methods"
        );
        assert_eq!(scanned[0].0, "store");
    }

    #[test]
    fn a_commented_out_default_is_not_a_violation() {
        // Documentation in this tree quotes method shapes, and the module docs
        // above discuss default bodies at length. Comment stripping is what
        // keeps that prose from failing the gate it describes.
        let documented = format!(
            "{} {{\n    // async fn store(&self) -> Result<(), E> {{ Ok(()) }}\n    async fn store(&self) -> Result<(), E>;\n}}",
            guarded_trait()
        );
        let scanned = guarded_methods(&documented);
        assert_eq!(scanned.len(), 1, "the commented shape must not be counted");
        assert!(!scanned[0].1);
    }
}
