/// Custom serde module for handling ATProto bytes format: { "$bytes": "base64..." }
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

#[derive(serde::Deserialize)]
struct BytesWrapper {
    #[serde(rename = "$bytes")]
    bytes: String,
}

pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::Serialize;

    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        #[serde(rename = "$bytes")]
        bytes: &'a str,
    }

    let base64_string = base64::engine::general_purpose::STANDARD.encode(bytes);
    Wrapper {
        bytes: &base64_string,
    }
    .serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let wrapper = BytesWrapper::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(&wrapper.bytes)
        .map_err(serde::de::Error::custom)
}

/// Serde module for optional ATProto bytes: None -> null, Some(bytes) -> {"$bytes": "base64..."}
pub mod option {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(serde::Deserialize)]
    struct BytesWrapper {
        #[serde(rename = "$bytes")]
        bytes: String,
    }

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::Serialize;

        #[derive(serde::Serialize)]
        struct Wrapper<'a> {
            #[serde(rename = "$bytes")]
            bytes: &'a str,
        }

        match bytes {
            None => serializer.serialize_none(),
            Some(b) => {
                let base64_string = base64::engine::general_purpose::STANDARD.encode(b);
                Wrapper {
                    bytes: &base64_string,
                }
                .serialize(serializer)
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_wrapper: Option<BytesWrapper> = Option::deserialize(deserializer)?;
        match opt_wrapper {
            None => Ok(None),
            Some(wrapper) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&wrapper.bytes)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::atproto_bytes")]
        data: Vec<u8>,
    }

    #[test]
    fn test_deserialize() {
        let json = r#"{"data": {"$bytes": "SGVsbG8gV29ybGQ="}}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, b"Hello World");
    }

    #[test]
    fn test_serialize() {
        let test_struct = TestStruct {
            data: b"Hello World".to_vec(),
        };
        let json = serde_json::to_string(&test_struct).unwrap();
        assert!(json.contains(r#""$bytes""#));
        assert!(json.contains("SGVsbG8gV29ybGQ="));
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestOptionalStruct {
        #[serde(default)]
        #[serde(with = "crate::atproto_bytes::option")]
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Vec<u8>>,
    }

    #[test]
    fn test_optional_deserialize_some() {
        let json = r#"{"data": {"$bytes": "SGVsbG8gV29ybGQ="}}"#;
        let result: TestOptionalStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, Some(b"Hello World".to_vec()));
    }

    #[test]
    fn test_optional_deserialize_null() {
        let json = r#"{"data": null}"#;
        let result: TestOptionalStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, None);
    }

    #[test]
    fn test_optional_deserialize_missing() {
        let json = r#"{}"#;
        let result: TestOptionalStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, None);
    }

    #[test]
    fn test_optional_serialize_some() {
        let test_struct = TestOptionalStruct {
            data: Some(b"Hello World".to_vec()),
        };
        let json = serde_json::to_string(&test_struct).unwrap();
        assert!(json.contains(r#""$bytes""#));
        assert!(json.contains("SGVsbG8gV29ybGQ="));
    }

    #[test]
    fn test_optional_serialize_none() {
        let test_struct = TestOptionalStruct { data: None };
        let json = serde_json::to_string(&test_struct).unwrap();
        // With skip_serializing_if, None should not appear in JSON
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_optional_roundtrip() {
        let original = TestOptionalStruct {
            data: Some(b"Test Data".to_vec()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TestOptionalStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }
}
