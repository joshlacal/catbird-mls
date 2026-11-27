//! Petrel Rust AT Protocol types that appear on this crate's public surface.
//!
//! `chat` is the generated `blue.catbird.chat` overlay module
//! (`petrel_catbird::generated::blue::catbird::chat`): each endpoint module
//! holds `Input`/`Parameters`/`Output`/`Error` and the shared records live in
//! `chat::defs`.

pub use petrel_catbird;
pub use petrel_catbird::generated::blue::catbird::chat;
pub use petrel_core;

use serde::ser::SerializeMap;

/// One generated endpoint error together with the server's optional message.
///
/// Petrel's generated `Error` enums carry only the declared error name (an
/// undeclared name is kept verbatim in `Unknown`); the human-readable
/// `message` of the XRPC error body travels beside it. Serializes back to the
/// XRPC error-body shape `{"error": <name>, "message"?: <text>}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedXrpcError<E> {
    pub error: E,
    pub message: Option<String>,
}

impl<E: petrel_core::DeclaredXrpcError> GeneratedXrpcError<E> {
    pub fn new(error: E, message: Option<String>) -> Self {
        Self { error, message }
    }

    /// Strictly decode an XRPC error body (`{"error", "message"?}`).
    pub fn parse(
        body: &[u8],
    ) -> Result<Self, crate::orchestrator::canonical_transport::TransportError> {
        let parsed: petrel_core::XrpcErrorBody = petrel_core::from_json(body).map_err(|error| {
            crate::orchestrator::canonical_transport::TransportError::Decoding(error.to_string())
        })?;
        Ok(Self {
            error: E::from_wire_name(&parsed.error),
            message: parsed.message,
        })
    }

    /// The error name exactly as it appears on the wire.
    pub fn wire_name(&self) -> &str {
        self.error.wire_name()
    }
}

impl<E: petrel_core::DeclaredXrpcError> serde::Serialize for GeneratedXrpcError<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1 + usize::from(self.message.is_some())))?;
        map.serialize_entry("error", self.error.wire_name())?;
        if let Some(message) = &self.message {
            map.serialize_entry("message", message)?;
        }
        map.end()
    }
}

impl<'de, E: petrel_core::DeclaredXrpcError> serde::Deserialize<'de> for GeneratedXrpcError<E> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let body = <petrel_core::XrpcErrorBody as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self {
            error: E::from_wire_name(&body.error),
            message: body.message,
        })
    }
}

/// JSON rendering of generated values that keeps the pre-Petrel `$bytes`
/// spelling.
///
/// Petrel always writes `{"$bytes": ...}` as unpadded base64 (the reference
/// PDS form). The deployed delivery service, the persisted canonical state and
/// the platform adapters were all built against padded standard base64, and
/// this crate's strict signed-JSON reader requires canonical padded base64.
/// These helpers re-pad every `$bytes` member after serializing, so the bytes
/// that leave this crate are unchanged by the move to Petrel. Decoding needs
/// no adapter: Petrel accepts either form.
pub mod json {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use base64::Engine as _;
    use serde::Serialize;

    /// `serde_json::to_value` with every `$bytes` member padded.
    pub fn to_value<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<serde_json::Value> {
        let mut value = serde_json::to_value(value)?;
        pad_bytes(&mut value);
        Ok(value)
    }

    /// `serde_json::to_vec` with every `$bytes` member padded.
    pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&to_value(value)?)
    }

    /// `serde_json::to_string` with every `$bytes` member padded.
    pub fn to_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
        serde_json::to_string(&to_value(value)?)
    }

    /// `#[serde(serialize_with)]` adapter: writes a field with every `$bytes`
    /// member padded.
    pub fn serialize_padded<T: Serialize, S: serde::Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        to_value(value)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    /// Re-pads each `{"$bytes": <unpadded standard base64>}` in place.
    pub fn pad_bytes(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Array(values) => values.iter_mut().for_each(pad_bytes),
            serde_json::Value::Object(map) => {
                if map.len() == 1 {
                    if let Some(serde_json::Value::String(text)) = map.get_mut("$bytes") {
                        if !text.ends_with('=') {
                            if let Ok(bytes) = STANDARD_NO_PAD.decode(text.as_bytes()) {
                                *text = STANDARD.encode(bytes);
                            }
                        }
                        return;
                    }
                }
                map.values_mut().for_each(pad_bytes);
            }
            _ => {}
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pads_nested_bytes_and_leaves_everything_else() {
            let mut value = serde_json::json!({
                "a": {"$bytes": "AAE"},
                "b": [{"$bytes": "AAEC"}, {"$bytes": "AA=="}],
                "c": {"$bytes": "AAE", "other": 1},
                "d": "AAE",
            });
            pad_bytes(&mut value);
            assert_eq!(
                value,
                serde_json::json!({
                    "a": {"$bytes": "AAE="},
                    "b": [{"$bytes": "AAEC"}, {"$bytes": "AA=="}],
                    "c": {"$bytes": "AAE", "other": 1},
                    "d": "AAE",
                })
            );
        }

        #[test]
        fn generated_bytes_render_padded() {
            let bytes = petrel_core::Bytes(vec![0, 1]);
            assert_eq!(to_vec(&bytes).unwrap(), br#"{"$bytes":"AAE="}"#);
        }
    }
}
