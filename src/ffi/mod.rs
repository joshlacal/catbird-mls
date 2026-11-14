//! UniFFI bindings for [`crate::client::CatbirdMlsClient`] and [`crate::push::process_push_notification`] (`Spec §6.3`).

#[cfg(feature = "labyrinth")]
pub mod circles_ffi;
pub mod uniffi_exports;

#[cfg(feature = "labyrinth")]
pub use circles_ffi::{
    CircleFfiError, CircleKeyWrapRequest, CircleKeyWrapResult, CirclePostOpenRequest,
    CirclePostSealRequest,
};
pub use uniffi_exports::*;
