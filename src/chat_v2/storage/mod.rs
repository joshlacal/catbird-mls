//! Durable storage for the clean chat protocol.
//!
//! The isolation rule for this layer is **physical**, and that word is doing
//! real work. It is not a naming convention, not a table prefix, and not a
//! discipline reviewers are asked to maintain.
//!
//! # Why a separate store, rather than a namespace inside v1's
//!
//! Two independent reasons, and either alone would be sufficient:
//!
//! - **v1's storage seam is flat.** [`crate::orchestrator`]'s backend addresses
//!   conversations and groups by bare string id with no namespace concept to
//!   parallel. There is no prefix to claim and no scope to nest under.
//! - **The OpenMLS store has no prefix mechanism either.** So a v2 group living
//!   in a shared context would sit in the same table as a v1 group, keyed only
//!   by group id.
//!
//! A shared store therefore has no place to put the version, which means the
//! only thing separating a v1 group from a v2 group would be the id itself.
//! §1 requires that the superseded namespace, storage, cursors, routes, device
//! bindings, and cryptographic state are *never read or translated*; a scheme
//! whose separation depends on ids never colliding cannot make that promise.
//!
//! Platforms therefore open a **separate store with its own database file**.
//! That is the platform contract, and [`StoreScope`] is how it is stated in a
//! form the compiler and the tests can see.
//!
//! # One store per DID
//!
//! Per-DID isolation is the platform contract: one store per DID, never one
//! store partitioned by a DID column. [`StoreScope`] carries the owning DID and
//! refuses, **by name**, any access naming a different one — including a
//! recipient binding whose device belongs to another principal.
//!
//! The refusal is [`StorageError::CrossDidAccess`], and it is deliberately not
//! a `NotFound`. Reporting "no such record" for another principal's state would
//! read as ordinary absence and be retried or repaired; it is instead a
//! containment breach, and it is named as one.
//!
//! # What this layer does not do
//!
//! It stores and retrieves. It never derives policy. Nothing here decides
//! whether a row is visible, whether a device may escalate, or whether an
//! interval may close — those answers belong to [`super::reducer`],
//! [`super::recovery`], and [`super::participation`], which have already
//! decided them by the time anything reaches storage.

pub mod error;
pub mod page;
pub mod store;

/// The non-durable reference store, **compiled only into test builds**.
///
/// Labelling it "not a production store" is not enough. A store that silently
/// forgets everything on process exit is the exact failure this whole layer
/// exists to prevent, and a type that is merely documented as unsuitable is one
/// import away from being used. Gating it on `cfg(test)` means a production or
/// FFI path cannot reach it even by mistake: there is no such symbol in a
/// release build.
///
/// A platform wanting an in-memory store for its own tests writes one against
/// [`store::ChatV2Store`], which is the point — every method is required, so
/// theirs cannot quietly skip one either.
#[cfg(test)]
mod memory;

#[cfg(test)]
mod memory_tests;

pub use error::{RecordKind, StorageError};
pub use page::{EntryOutcome, PageCommit, PersistedEntry, RatchetCheckpoint};
pub use store::ChatV2Store;

use super::ids::BareDid;
use super::interval::RecipientBinding;

/// The identity of one opened v2 store: exactly one principal's state.
///
/// A store is opened *for* a DID. It is not a shared store that filters by DID,
/// and the distinction is the whole point — a filter is a predicate someone can
/// forget to apply, while a scope is a value every access must pass through.
///
/// This type deliberately offers no way to widen itself. There is no
/// `for_all_dids`, no way to mutate the owner after construction, and no
/// comparison that treats two DIDs as equivalent. Opening a second principal's
/// state means opening a second store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreScope {
    owner_did: BareDid,
}

impl StoreScope {
    /// Opens a scope for exactly one principal.
    pub fn for_did(owner_did: BareDid) -> Self {
        Self { owner_did }
    }

    /// The principal this store holds state for.
    pub fn owner_did(&self) -> &BareDid {
        &self.owner_did
    }

    /// Confirms an access names this store's principal.
    ///
    /// Refused accesses are a containment breach rather than a miss, so this
    /// returns [`StorageError::CrossDidAccess`] and never an absence.
    pub fn require_owner(&self, requested: &BareDid) -> Result<(), StorageError> {
        if &self.owner_did != requested {
            return Err(StorageError::CrossDidAccess {
                owner: self.owner_did.clone(),
                requested: requested.clone(),
            });
        }
        Ok(())
    }

    /// Confirms a recipient binding belongs to this store's principal.
    ///
    /// A binding names `(conversation, DID, device)`. Only the DID is this
    /// layer's business: whether the *device* is the right one is an
    /// exact-device schedule question, answered by
    /// [`RecipientBinding::matches`] where the schedule itself is compared. What
    /// this check catches is one principal's store being handed another
    /// principal's schedule, which no amount of device comparison downstream
    /// would correct.
    pub fn require_binding_owner(&self, binding: &RecipientBinding) -> Result<(), StorageError> {
        self.require_owner(binding.recipient_did())
    }
}

/// Enforces that no module under `chat_v2` reaches into a v1 storage mechanism.
///
/// The existing isolation gate forbids importing `crate::orchestrator`, which
/// catches the v1 storage *trait* because it lives there. It does not catch the
/// stores underneath: `HybridStorageProvider`, the OpenMLS SQLite provider, and
/// v1's SQLCipher context are reachable by other paths, and any one of them
/// would put v2 state into a store that has nowhere to record which protocol
/// version wrote it.
///
/// This gate is the storage counterpart to the recovery tree's
/// forbidden-mechanism gate, and it is built the same way: needles assembled at
/// runtime, comments stripped, a positive control, and every entry carrying its
/// reason so that whoever eventually wants to delete one has to read why it is
/// there first.
#[cfg(test)]
mod physical_separation {
    use crate::chat_v2::gate_support::SourceScan;
    use std::path::Path;

    /// The v1 storage mechanisms v2 must never reach, each with its reason.
    ///
    /// Assembled from fragments so this gate's own source does not read as a
    /// violation of itself.
    fn forbidden_stores() -> Vec<(String, &'static str)> {
        vec![
            (
                ["openmls", "sqlite", "storage"].join("_"),
                "the OpenMLS store has no prefix or namespace mechanism, so a shared \
                 context puts v1 and v2 groups in one table keyed only by group id",
            ),
            (
                ["Hybrid", "Storage", "Provider"].concat(),
                "v1's OpenMLS-plus-keychain store; v2 opens a separate store with its \
                 own database file rather than nesting inside this one",
            ),
            (
                ["MLS", "Storage", "Backend"].concat(),
                "v1's flat storage seam, twenty of whose thirty-four methods default to \
                 no-ops that discard state and report success",
            ),
            (
                ["hybrid", "storage"].join("_"),
                "the module path to the same v1 store, reachable without naming the type",
            ),
            (
                ["mls", "context"].join("_"),
                "v1's SQLCipher connection and MlsGroup map; §1 forbids reading or \
                 translating superseded storage and cryptographic state",
            ),
        ]
    }

    #[test]
    fn chat_v2_never_reaches_a_v1_store() {
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
        for (needle, why) in &forbidden_stores() {
            for finding in scan.findings(needle) {
                violations.push(format!("{} — {why}", finding.describe()));
            }
        }
        assert!(
            violations.is_empty(),
            "v2 storage must be physically separate from v1's; found:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn the_separation_gate_can_actually_fail() {
        // A control that cannot fail is not a control. These are the exact
        // spellings the real v1 modules use, so the matcher is proven against
        // the thing it exists to catch rather than against an invented string —
        // including the two forms the previous matcher missed: a brace-form
        // import, and a line whose string literal holds a slash pair.
        let forbidden = forbidden_stores();
        let provider = ["Hybrid", "Storage", "Provider"].concat();
        let backend = ["MLS", "Storage", "Backend"].concat();
        let sqlite = ["openmls", "sqlite", "storage"].join("_");
        for offending in [
            format!("use {sqlite}::SqliteStorageProvider;"),
            format!("    let provider = {provider}::new();"),
            format!("impl {backend} for ChatV2Store {{"),
            format!(
                "use crate::{}{}::SqliteStorageProvider{};",
                "{", sqlite, "}"
            ),
            format!("let doc = \"https://x\"; let p = {provider}::new();"),
            // The module-path spelling of v1's MLS context, which this gate has
            // always caught — and that is exactly the asymmetry the crate-root
            // finding turns on. `use crate::MLSContext;` reaches the identical
            // type, names no module path at all, and is caught by the
            // *isolation* gate's derived crate-root set instead. Keeping this
            // control here stops a pass on the short spelling from reading as a
            // clean tree.
            format!(
                "use crate::{}::{};",
                ["mls", "context"].join("_"),
                ["MLS", "Context"].concat()
            ),
        ] {
            assert!(
                forbidden
                    .iter()
                    .any(|(needle, _)| SourceScan::line_contains(&offending, needle)),
                "the matcher must flag: {offending}"
            );
        }

        // And that comment stripping is what spares this module's own docs,
        // which necessarily name every store they forbid.
        let documented = format!("//! - v1's {backend} is flat and has no namespace to parallel.");
        assert!(
            forbidden
                .iter()
                .all(|(needle, _)| !SourceScan::line_contains(&documented, needle)),
            "a mention inside a comment must not count as a violation"
        );
    }

    #[test]
    fn the_reference_store_is_unreachable_from_a_production_build() {
        // A non-durable store is the failure this layer exists to prevent, so
        // it must be structurally absent from release builds rather than
        // documented as unsuitable. Documentation does not survive an editor's
        // import completion; a missing symbol does.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chat_v2/storage/mod.rs");
        let source = std::fs::read_to_string(path).expect("this module's source must be readable");

        // Assembled so this assertion's own source is not what it matches.
        let declaration = ["mod", "memory;"].join(" ");
        let lines: Vec<&str> = source.lines().collect();
        let index = lines
            .iter()
            .position(|line| line.trim() == declaration)
            .expect("the reference store's module declaration must be present");

        // Walk back over any documentation to the attribute above it.
        let gate = lines[..index]
            .iter()
            .rev()
            .find(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with("///")
            })
            .expect("the declaration must carry an attribute above it");

        assert_eq!(
            gate.trim(),
            format!("#[{}(test)]", "cfg"),
            "the reference store must be gated out of production builds"
        );
    }

    #[test]
    fn every_forbidden_store_carries_its_reason() {
        // The list is only useful if a future reader learns why each entry is
        // there rather than deleting whichever one is inconveniencing them.
        let forbidden = forbidden_stores();
        assert_eq!(forbidden.len(), 5);
        for (needle, why) in &forbidden {
            assert!(!needle.is_empty());
            assert!(
                why.len() > 20,
                "{needle} needs a real explanation, not a label"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::ids::{ConversationId, DeviceId};

    const OWNER: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const STRANGER: &str = "did:plc:44ybard66vv44zksje25o7dz";
    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const SIBLING_DEVICE: &str = "72727272-7272-4272-b272-727272727272";

    fn did(value: &str) -> BareDid {
        BareDid::parse(value).expect("test DID must be valid")
    }

    fn scope() -> StoreScope {
        StoreScope::for_did(did(OWNER))
    }

    fn binding(owner: &str, device: &str) -> RecipientBinding {
        RecipientBinding::new(
            ConversationId::parse(CONVERSATION).unwrap(),
            did(owner),
            DeviceId::parse(device).unwrap(),
        )
    }

    #[test]
    fn a_scope_admits_its_own_principal() {
        assert!(scope().require_owner(&did(OWNER)).is_ok());
        assert_eq!(scope().owner_did(), &did(OWNER));
    }

    #[test]
    fn another_principal_is_refused_by_name() {
        // The named refusal matters more than the fact of refusing. A store
        // holding one principal's state and asked for another's has been
        // misrouted, and the error has to say so.
        let err = scope().require_owner(&did(STRANGER)).unwrap_err();
        assert_eq!(
            err,
            StorageError::CrossDidAccess {
                owner: did(OWNER),
                requested: did(STRANGER),
            }
        );
    }

    #[test]
    fn a_cross_did_access_is_never_reported_as_absence() {
        // If this read as NotFound, a caller would treat another principal's
        // state as a missing record: retry it, repair it, or create it. It is a
        // containment breach, and the taxonomy must not let it look routine.
        let err = scope().require_owner(&did(STRANGER)).unwrap_err();
        assert!(
            !matches!(err, StorageError::NotFound { .. }),
            "a foreign principal must not be indistinguishable from a miss"
        );
        assert!(err.is_isolation_breach());
        assert!(
            !StorageError::NotFound {
                record: RecordKind::Cursor,
                key: "any".to_owned(),
            }
            .is_isolation_breach(),
            "an ordinary miss must not be reported as a breach either"
        );
    }

    #[test]
    fn a_binding_is_admitted_by_its_did_not_its_device() {
        // Both devices below belong to the owner. The schedule layer is what
        // distinguishes them; this layer's question is only whose store it is.
        let scope = scope();
        assert!(scope.require_binding_owner(&binding(OWNER, DEVICE)).is_ok());
        assert!(scope
            .require_binding_owner(&binding(OWNER, SIBLING_DEVICE))
            .is_ok());
    }

    #[test]
    fn another_principals_binding_is_refused() {
        let err = scope()
            .require_binding_owner(&binding(STRANGER, DEVICE))
            .unwrap_err();
        assert_eq!(
            err,
            StorageError::CrossDidAccess {
                owner: did(OWNER),
                requested: did(STRANGER),
            }
        );
    }

    #[test]
    fn two_principals_need_two_stores() {
        // The type offers no way to widen a scope: no constructor taking two
        // DIDs, no setter, no "any principal" variant. The only way to reach a
        // second principal's state is to open a second store, which is the
        // per-DID contract stated as an API rather than as a rule.
        let owner = scope();
        let stranger = StoreScope::for_did(did(STRANGER));
        assert_ne!(owner, stranger);
        assert!(owner.require_owner(stranger.owner_did()).is_err());
        assert!(stranger.require_owner(owner.owner_did()).is_err());
    }
}
