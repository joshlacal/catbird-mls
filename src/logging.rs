use crate::types::MLSLogger;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};

/// Global logger instance that can be set from Swift
static LOGGER: Lazy<RwLock<Option<Arc<dyn MLSLogger>>>> = Lazy::new(|| RwLock::new(None));

/// Set the global logger (called from Swift)
pub fn set_logger(logger: Box<dyn MLSLogger>) {
    if let Ok(mut guard) = LOGGER.write() {
        *guard = Some(Arc::from(logger));
    }
}

/// Log a debug message
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        $crate::logging::log_message("debug", &format!($($arg)*));
    };
}

/// Log an info message
#[macro_export]
macro_rules! info_log {
    ($($arg:tt)*) => {
        $crate::logging::log_message("info", &format!($($arg)*));
    };
}

/// Log a warning message
#[macro_export]
macro_rules! warn_log {
    ($($arg:tt)*) => {
        $crate::logging::log_message("warning", &format!($($arg)*));
    };
}

/// Log an error message
#[macro_export]
macro_rules! error_log {
    ($($arg:tt)*) => {
        $crate::logging::log_message("error", &format!($($arg)*));
    };
}

/// Synchronous log sink callback so NSE (`<= 15 MB` budget) never initializes
/// a multi-threaded Tokio worker pool just to emit a log line.
pub trait SyncLogSink: Send + Sync {
    fn log_sync(&self, level: &str, message: &str);
}

static SYNC_SINK: Lazy<RwLock<Option<Arc<dyn SyncLogSink>>>> = Lazy::new(|| RwLock::new(None));

/// Register a zero-Tokio synchronous log sink (used by iOS NSE and Android FCM).
pub fn set_sync_log_sink(sink: Arc<dyn SyncLogSink>) {
    if let Ok(mut guard) = SYNC_SINK.write() {
        *guard = Some(sink);
    }
}

/// Internal function to emit log messages without ever spawning or initializing
/// a multi-thread Tokio runtime (`G1`, `I9`).
#[cfg(not(target_arch = "wasm32"))]
pub fn log_message(level: &str, message: &str) {
    match level {
        "error" => tracing::error!(target: "catbird_mls", "{message}"),
        "warning" => tracing::warn!(target: "catbird_mls", "{message}"),
        "debug" => tracing::debug!(target: "catbird_mls", "{message}"),
        _ => tracing::info!(target: "catbird_mls", "{message}"),
    }
    if let Ok(guard) = SYNC_SINK.read() {
        if let Some(sink) = guard.as_ref() {
            sink.log_sync(level, message);
        }
    }
    if let Ok(guard) = LOGGER.read() {
        if let Some(logger) = guard.as_ref() {
            // Only forward to legacy async MLSLogger if the caller is ALREADY inside
            // an active Tokio runtime — NEVER initialize `async_runtime::RUNTIME`.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let logger_clone = Arc::clone(logger);
                let level = level.to_string();
                let message = message.to_string();
                handle.spawn(async move {
                    logger_clone.log(level, message).await;
                });
            }
        }
    }
}

/// On WASM, log directly to the browser console.
#[cfg(target_arch = "wasm32")]
pub fn log_message(level: &str, message: &str) {
    let formatted: String = format!("[MLS-{level}] {message}");
    let js_val: wasm_bindgen::JsValue = formatted.into();
    match level {
        "error" => web_sys::console::error_1(&js_val),
        "warning" => web_sys::console::warn_1(&js_val),
        "debug" => web_sys::console::debug_1(&js_val),
        _ => web_sys::console::log_1(&js_val),
    }
}

// Re-export macros
pub use debug_log;
pub use error_log;
pub use info_log;
pub use warn_log;
