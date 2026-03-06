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

/// Internal function to send log messages to the platform logger (fire-and-forget)
#[cfg(not(target_arch = "wasm32"))]
pub fn log_message(level: &str, message: &str) {
    if let Ok(guard) = LOGGER.read() {
        if let Some(logger) = guard.as_ref() {
            // Clone the Arc for the async task (safe, no unsafe needed)
            let logger_clone = Arc::clone(logger);
            let level = level.to_string();
            let message = message.to_string();

            // Fire-and-forget: spawn async log without blocking
            crate::async_runtime::RUNTIME.spawn(async move {
                logger_clone.log(level, message).await;
            });
        }
        // If no logger set, silently ignore (no-op on iOS without stderr)
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
