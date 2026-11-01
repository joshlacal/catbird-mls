//! Consolidated cursor reconciliation (`I2`, `I6` post-commit `acknowledgeEntries`) and
//! realtime event classification (`accountDeleted`, `epoch_head`, `space_uri`).

pub mod events;
pub mod reconcile;

pub use events as realtime;
pub use reconcile as cursor;
