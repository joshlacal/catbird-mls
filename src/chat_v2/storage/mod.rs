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

pub use error::{RecordKind, StorageError};

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
