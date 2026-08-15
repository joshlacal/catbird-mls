//! Projection of strict wire JSON through the embedded lexicon contract.
//!
//! This is what turns arbitrary signed-body JSON into a [`CanonicalBody`] that
//! [`super::SigningTranscript`] can encode. Until it existed, the only way to
//! build a canonical body was a test fixture that declared its own field types,
//! which is a scaffold and was never allowed into a non-test path.
//!
//! The contract is embedded as bytes, exactly as the server embeds it, and the
//! projection walks it field by field. **No generated DTO participates.**
//! Generated DTOs emit fields alphabetically and carry a flattened `extra_data`
//! catch-all, and the protocol forbids DTO bytes as transcript or fingerprint
//! input.
//!
//! # The lexicon alone does not tell you which fields are UUID bytes
//!
//! This is the single most surprising thing here, and it is worth stating
//! before anyone tries to "derive" the rule from the schema.
//!
//! In the contract, `operationId` and `deviceId` are declared as ordinary
//! strings — `{"type":"string","minLength":36,"maxLength":36}`. Nothing in the
//! schema marks them as bytes. What makes them sixteen raw bytes in a
//! transcript is a **hardcoded set of four reference names** in the projection
//! itself, which short-circuit before the schema is ever consulted:
//!
//! | ref name | becomes | in the transcript |
//! |---|---|---|
//! | `operationId`, `deviceId` | [`CanonicalValue::Uuid`] | 16 raw bytes |
//! | `bareDid` | [`CanonicalValue::Did`] | text |
//! | `keyId` | [`CanonicalValue::Thumbprint`] | text |
//! | `canonicalDatetime` | [`CanonicalValue::Timestamp`] | text |
//!
//! So a field is UUID-bytes exactly when its schema is a `ref` to
//! `#operationId` or `#deviceId`. An implementer who read only the lexicon
//! would encode every one of them as text and produce signatures that verify
//! nowhere. The set is mirrored from the server verbatim and is pinned by a
//! test that cross-checks it against the golden fixtures' own declared byte
//! paths.
//!
//! # Closed means closed
//!
//! The projection iterates the *input's* fields, not the schema's, so a field
//! the contract does not declare is refused rather than dropped. Dropping it
//! would mean the signature covered less than the request carried — the same
//! failure the two-field wrapper rule exists to prevent, one level down.

use super::strict_json::{decode_standard_base64, StrictJson};
use super::{CanonicalBody, CanonicalValue, SignedMutationKind};
use crate::chat_v2::ids::{BareDid, CanonicalTimestamp, CanonicalUuid, KeyId, MAX_SAFE_INTEGER};
use core::fmt;
use serde_json::Value as Schema;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The type-ID prefix every closed union variant and tagged object carries.
pub const TYPE_PREFIX: &str = "blue.catbird.chat.defs#";

/// The embedded contract, byte-identical to the copy the server embeds.
///
/// See `vectors/PROVENANCE.md` for its source and hash.
const CONTRACT_JSON: &str = include_str!("vectors/blue.catbird.chat.defs.json");

/// Reference names whose projection is decided by name rather than by schema.
///
/// Mirrored verbatim from the server. See the module docs for why this cannot
/// be derived from the contract.
pub const UUID_REF_NAMES: [&str; 2] = ["operationId", "deviceId"];

/// String-shaped field names that project as key thumbprints.
const THUMBPRINT_FIELD_NAMES: [&str; 3] = ["dpopJkt", "currentDpopJkt", "newDpopJkt"];

fn contract() -> &'static Schema {
    static CONTRACT: OnceLock<Schema> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        serde_json::from_str(CONTRACT_JSON).expect("the embedded contract must be valid JSON")
    })
}

fn definition(name: &str) -> Result<&'static Schema, ProjectionError> {
    contract()["defs"]
        .get(name)
        .ok_or_else(|| ProjectionError::UnknownDefinition {
            name: name.to_owned(),
        })
}

/// Why a body could not be projected through the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    /// The contract has no definition by that name.
    UnknownDefinition { name: String },
    /// A schema declared a type this projection does not implement.
    UnsupportedSchemaType,
    /// A value's JSON shape did not match its declared type.
    FieldType { expected: &'static str },
    /// The input carried a field the contract does not declare.
    ///
    /// Refused, never dropped: a dropped field is data the signature does not
    /// cover travelling inside a signed request.
    UnknownField { name: String },
    /// A required field was absent.
    MissingRequiredField { name: String },
    /// A `$type` appeared on an object that is not tagged.
    UnexpectedTypeTag,
    /// A tagged object carried no `$type`.
    MissingTypeTag,
    /// A tagged object's `$type` was not the one its definition requires.
    WrongTypeTag { expected: String },
    /// A union variant was outside the union's closed set.
    UnknownUnionVariant { type_id: String },
    /// A union `$type` was outside the contract's namespace.
    UnionTypeNamespace,
    /// A string violated a `const`, `enum`, or `knownValues` constraint.
    StringValue,
    /// A string was outside its declared length bounds.
    StringLength,
    /// A bytes field was not canonical STANDARD base64.
    BytesEncoding,
    /// A bytes field was outside its declared length bounds.
    BytesLength,
    /// An integer was outside its declared bounds or the safe-integer ceiling.
    IntegerBound,
    /// A boolean violated a `const` constraint.
    BooleanConst,
    /// An array was outside its declared length bounds.
    ArrayLength,
    /// An identifier failed its own grammar.
    Identifier { kind: &'static str },
    /// A contract-ordered array was not strictly ascending.
    ///
    /// Strict ordering is what makes these arrays canonical; two orderings of
    /// the same members would otherwise be two valid signatures over one intent.
    NotStrictlyOrdered { what: &'static str },
    /// A leaf change named an operation outside the closed pair.
    UnknownLeafChangeOperation,
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDefinition { name } => write!(f, "no contract definition named {name}"),
            Self::UnsupportedSchemaType => f.write_str("unsupported contract schema type"),
            Self::FieldType { expected } => write!(f, "expected a {expected} value"),
            Self::UnknownField { name } => {
                write!(f, "the contract does not declare a field named {name}")
            }
            Self::MissingRequiredField { name } => write!(f, "missing required field {name}"),
            Self::UnexpectedTypeTag => f.write_str("unexpected $type on an untagged object"),
            Self::MissingTypeTag => f.write_str("a tagged object requires $type"),
            Self::WrongTypeTag { expected } => write!(f, "$type must be {expected}"),
            Self::UnknownUnionVariant { type_id } => {
                write!(f, "{type_id} is not a variant of this closed union")
            }
            Self::UnionTypeNamespace => {
                f.write_str("union $type is outside the contract namespace")
            }
            Self::StringValue => f.write_str("string outside its closed value set"),
            Self::StringLength => f.write_str("string length bound"),
            Self::BytesEncoding => f.write_str("bytes field is not canonical STANDARD base64"),
            Self::BytesLength => f.write_str("bytes length bound"),
            Self::IntegerBound => f.write_str("integer value bound"),
            Self::BooleanConst => f.write_str("wrong constant boolean"),
            Self::ArrayLength => f.write_str("array length bound"),
            Self::Identifier { kind } => write!(f, "invalid {kind}"),
            Self::NotStrictlyOrdered { what } => write!(f, "{what} are not strictly ordered"),
            Self::UnknownLeafChangeOperation => f.write_str("unknown leaf change operation"),
        }
    }
}

impl core::error::Error for ProjectionError {}

/// Projects a signed body through the definition its kind names.
///
/// This is the entry point that replaces the fixture scaffold: given the strict
/// JSON of a signed body and its kind, it produces the canonical body a
/// transcript is built from.
pub fn project_signed_body(
    kind: SignedMutationKind,
    body: &StrictJson,
) -> Result<CanonicalBody, ProjectionError> {
    match project_ref(kind.body_name(), body, true)? {
        CanonicalValue::Map(map) => Ok(map),
        _ => Err(ProjectionError::FieldType { expected: "object" }),
    }
}

/// Projects a value against a named contract definition.
pub fn project_ref(
    name: &str,
    input: &StrictJson,
    tagged: bool,
) -> Result<CanonicalValue, ProjectionError> {
    // The four by-name special cases, ahead of any schema lookup. See the
    // module docs: this mapping is not derivable from the contract.
    match name {
        "operationId" | "deviceId" => {
            let StrictJson::String(value) = input else {
                return Err(ProjectionError::FieldType { expected: "UUID" });
            };
            let uuid = CanonicalUuid::parse(value)
                .map_err(|_| ProjectionError::Identifier { kind: "UUID" })?;
            Ok(CanonicalValue::Uuid(*uuid.as_bytes()))
        }
        "bareDid" => {
            let StrictJson::String(value) = input else {
                return Err(ProjectionError::FieldType { expected: "DID" });
            };
            let did =
                BareDid::parse(value).map_err(|_| ProjectionError::Identifier { kind: "DID" })?;
            Ok(CanonicalValue::Did(did.to_string()))
        }
        "keyId" => {
            let StrictJson::String(value) = input else {
                return Err(ProjectionError::FieldType {
                    expected: "key thumbprint",
                });
            };
            let key_id = KeyId::parse(value).map_err(|_| ProjectionError::Identifier {
                kind: "key thumbprint",
            })?;
            Ok(CanonicalValue::Thumbprint(key_id.as_str().to_owned()))
        }
        "canonicalDatetime" => {
            let StrictJson::String(value) = input else {
                return Err(ProjectionError::FieldType {
                    expected: "timestamp",
                });
            };
            let stamp = CanonicalTimestamp::parse(value)
                .map_err(|_| ProjectionError::Identifier { kind: "timestamp" })?;
            Ok(CanonicalValue::Timestamp(stamp.as_str().to_owned()))
        }
        _ => project_schema(definition(name)?, input, Some(name), tagged),
    }
}

fn project_schema(
    schema: &Schema,
    input: &StrictJson,
    field_name: Option<&str>,
    tagged_object: bool,
) -> Result<CanonicalValue, ProjectionError> {
    match schema["type"].as_str() {
        Some("ref") => {
            let name = schema["ref"]
                .as_str()
                .and_then(|value| value.strip_prefix('#'))
                .ok_or(ProjectionError::UnsupportedSchemaType)?;
            project_ref(name, input, false)
        }
        Some("union") => project_union(schema, input),
        Some("object") => project_object(schema, input, field_name, tagged_object),
        Some("string") => project_string(schema, input, field_name),
        Some("bytes") => project_bytes(schema, input),
        Some("integer") => project_integer(schema, input),
        Some("boolean") => project_boolean(schema, input),
        Some("array") => project_array(schema, input, field_name),
        _ => Err(ProjectionError::UnsupportedSchemaType),
    }
}

fn project_union(schema: &Schema, input: &StrictJson) -> Result<CanonicalValue, ProjectionError> {
    let StrictJson::Object(values) = input else {
        return Err(ProjectionError::FieldType { expected: "object" });
    };
    let type_id = match values.get("$type") {
        Some(StrictJson::String(value)) => value.as_str(),
        _ => return Err(ProjectionError::MissingTypeTag),
    };
    let name = type_id
        .strip_prefix(TYPE_PREFIX)
        .ok_or(ProjectionError::UnionTypeNamespace)?;
    let allowed = schema["refs"]
        .as_array()
        .ok_or(ProjectionError::UnsupportedSchemaType)?
        .iter()
        .filter_map(Schema::as_str)
        .filter_map(|value| value.strip_prefix('#'))
        .any(|candidate| candidate == name);
    if !allowed {
        return Err(ProjectionError::UnknownUnionVariant {
            type_id: type_id.to_owned(),
        });
    }
    project_ref(name, input, true)
}

fn project_object(
    schema: &Schema,
    input: &StrictJson,
    definition_name: Option<&str>,
    tagged: bool,
) -> Result<CanonicalValue, ProjectionError> {
    let StrictJson::Object(values) = input else {
        return Err(ProjectionError::FieldType { expected: "object" });
    };
    let properties = schema["properties"]
        .as_object()
        .ok_or(ProjectionError::UnsupportedSchemaType)?;

    let mut output = BTreeMap::new();
    // Iterating the INPUT means an undeclared field is refused rather than
    // dropped. A dropped field is data the signature does not cover.
    for (name, value) in values {
        if name == "$type" {
            if !tagged {
                return Err(ProjectionError::UnexpectedTypeTag);
            }
            let expected = format!("{TYPE_PREFIX}{}", definition_name.unwrap_or_default());
            match value {
                StrictJson::String(actual) if actual == &expected => {
                    output.insert(name.clone(), CanonicalValue::Text(actual.clone()));
                }
                _ => return Err(ProjectionError::WrongTypeTag { expected }),
            }
            continue;
        }
        let property = properties
            .get(name)
            .ok_or_else(|| ProjectionError::UnknownField { name: name.clone() })?;
        output.insert(
            name.clone(),
            project_schema(property, value, Some(name), false)?,
        );
    }

    if tagged && !output.contains_key("$type") {
        return Err(ProjectionError::MissingTypeTag);
    }
    for required in schema["required"]
        .as_array()
        .ok_or(ProjectionError::UnsupportedSchemaType)?
        .iter()
        .filter_map(Schema::as_str)
    {
        if !output.contains_key(required) {
            return Err(ProjectionError::MissingRequiredField {
                name: required.to_owned(),
            });
        }
    }
    if let Some(name) = definition_name {
        enforce_contract_order(name, &output)?;
    }
    Ok(CanonicalValue::Map(output))
}

fn project_string(
    schema: &Schema,
    input: &StrictJson,
    field_name: Option<&str>,
) -> Result<CanonicalValue, ProjectionError> {
    let StrictJson::String(value) = input else {
        return Err(ProjectionError::FieldType { expected: "string" });
    };
    if let Some(expected) = schema["const"].as_str() {
        if value != expected {
            return Err(ProjectionError::StringValue);
        }
    }
    for closed in ["enum", "knownValues"] {
        if let Some(values) = schema[closed].as_array() {
            if !values
                .iter()
                .filter_map(Schema::as_str)
                .any(|item| item == value)
            {
                return Err(ProjectionError::StringValue);
            }
        }
    }
    let length = value.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(ProjectionError::StringLength);
    }
    if field_name.is_some_and(|name| THUMBPRINT_FIELD_NAMES.contains(&name)) {
        let key_id = KeyId::parse(value).map_err(|_| ProjectionError::Identifier {
            kind: "key thumbprint",
        })?;
        return Ok(CanonicalValue::Thumbprint(key_id.as_str().to_owned()));
    }
    Ok(CanonicalValue::Text(value.clone()))
}

fn project_bytes(schema: &Schema, input: &StrictJson) -> Result<CanonicalValue, ProjectionError> {
    let StrictJson::String(value) = input else {
        return Err(ProjectionError::FieldType { expected: "bytes" });
    };
    let decoded = decode_standard_base64(value).map_err(|_| ProjectionError::BytesEncoding)?;
    let length = decoded.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(ProjectionError::BytesLength);
    }
    Ok(CanonicalValue::Bytes(decoded))
}

fn project_integer(schema: &Schema, input: &StrictJson) -> Result<CanonicalValue, ProjectionError> {
    let StrictJson::Integer(value) = input else {
        return Err(ProjectionError::FieldType {
            expected: "integer",
        });
    };
    if *value > MAX_SAFE_INTEGER as u64
        || schema["minimum"].as_u64().is_some_and(|min| *value < min)
        || schema["maximum"].as_u64().is_some_and(|max| *value > max)
        || schema["const"]
            .as_u64()
            .is_some_and(|constant| *value != constant)
    {
        return Err(ProjectionError::IntegerBound);
    }
    Ok(CanonicalValue::Integer(*value))
}

fn project_boolean(schema: &Schema, input: &StrictJson) -> Result<CanonicalValue, ProjectionError> {
    let StrictJson::Bool(value) = input else {
        return Err(ProjectionError::FieldType {
            expected: "boolean",
        });
    };
    if schema["const"]
        .as_bool()
        .is_some_and(|constant| *value != constant)
    {
        return Err(ProjectionError::BooleanConst);
    }
    Ok(CanonicalValue::Bool(*value))
}

fn project_array(
    schema: &Schema,
    input: &StrictJson,
    field_name: Option<&str>,
) -> Result<CanonicalValue, ProjectionError> {
    let StrictJson::Array(values) = input else {
        return Err(ProjectionError::FieldType { expected: "array" });
    };
    let length = values.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(ProjectionError::ArrayLength);
    }
    let items = schema
        .get("items")
        .ok_or(ProjectionError::UnsupportedSchemaType)?;
    values
        .iter()
        .map(|value| project_schema(items, value, field_name, false))
        .collect::<Result<Vec<_>, _>>()
        .map(CanonicalValue::Array)
}

// ---- contract ordering -----------------------------------------------------

fn field<'a>(
    map: &'a CanonicalBody,
    name: &'static str,
) -> Result<&'a CanonicalValue, ProjectionError> {
    map.get(name).ok_or(ProjectionError::MissingRequiredField {
        name: name.to_owned(),
    })
}

fn as_array(value: &CanonicalValue) -> Result<&[CanonicalValue], ProjectionError> {
    match value {
        CanonicalValue::Array(items) => Ok(items),
        _ => Err(ProjectionError::FieldType { expected: "array" }),
    }
}

fn as_map(value: &CanonicalValue) -> Result<&CanonicalBody, ProjectionError> {
    match value {
        CanonicalValue::Map(map) => Ok(map),
        _ => Err(ProjectionError::FieldType { expected: "object" }),
    }
}

fn as_did(value: &CanonicalValue) -> Result<&str, ProjectionError> {
    match value {
        CanonicalValue::Did(did) => Ok(did),
        _ => Err(ProjectionError::FieldType { expected: "DID" }),
    }
}

fn as_uuid(value: &CanonicalValue) -> Result<&[u8; 16], ProjectionError> {
    match value {
        CanonicalValue::Uuid(raw) => Ok(raw),
        _ => Err(ProjectionError::FieldType { expected: "UUID" }),
    }
}

fn as_bytes(value: &CanonicalValue) -> Result<&[u8], ProjectionError> {
    match value {
        CanonicalValue::Bytes(raw) => Ok(raw),
        _ => Err(ProjectionError::FieldType { expected: "bytes" }),
    }
}

/// Enforces the strict orderings the contract requires of certain arrays.
///
/// Two orderings of the same members would otherwise be two different valid
/// signatures over one intent, which is exactly the ambiguity canonical forms
/// exist to remove.
fn enforce_contract_order(
    definition_name: &str,
    object: &CanonicalBody,
) -> Result<(), ProjectionError> {
    if matches!(
        definition_name,
        "creationManifest" | "resetActivationManifest"
    ) {
        enforce_did_array(object, "participants", "userDid")?;
    }
    if matches!(
        definition_name,
        "transitionManifest" | "policyTransitionBody"
    ) {
        enforce_did_array(object, "participantChanges", "userDid")?;
    }
    if definition_name == "transitionManifest" {
        let mut prior: Option<(Vec<u8>, [u8; 16], u8)> = None;
        for value in as_array(field(object, "leafChanges")?)? {
            let item = as_map(value)?;
            let did = as_did(field(item, "userDid")?)?.as_bytes().to_vec();
            let device = *as_uuid(field(item, "deviceId")?)?;
            let rank = match field(item, "$type")? {
                CanonicalValue::Text(value) if value == "blue.catbird.chat.defs#removeLeaf" => 0u8,
                CanonicalValue::Text(value)
                    if value == "blue.catbird.chat.defs#addLeafByRecovery" =>
                {
                    1u8
                }
                _ => return Err(ProjectionError::UnknownLeafChangeOperation),
            };
            let current = (did, device, rank);
            if prior.as_ref().is_some_and(|previous| *previous >= current) {
                return Err(ProjectionError::NotStrictlyOrdered {
                    what: "leaf changes",
                });
            }
            prior = Some(current);
        }
    }
    if matches!(
        definition_name,
        "deviceEnrollmentBody" | "keyPackageReplenishmentBody"
    ) {
        let mut prior: Option<Vec<u8>> = None;
        for value in as_array(field(object, "keyPackages")?)? {
            let item = as_map(value)?;
            let reference = as_bytes(field(item, "keyPackageRef")?)?.to_vec();
            if prior
                .as_ref()
                .is_some_and(|previous| *previous >= reference)
            {
                return Err(ProjectionError::NotStrictlyOrdered {
                    what: "KeyPackage refs",
                });
            }
            prior = Some(reference);
        }
    }
    Ok(())
}

fn enforce_did_array(
    object: &CanonicalBody,
    array_name: &'static str,
    did_name: &'static str,
) -> Result<(), ProjectionError> {
    let mut prior: Option<Vec<u8>> = None;
    for value in as_array(field(object, array_name)?)? {
        let item = as_map(value)?;
        let did = as_did(field(item, did_name)?)?.as_bytes().to_vec();
        if prior.as_ref().is_some_and(|previous| *previous >= did) {
            return Err(ProjectionError::NotStrictlyOrdered { what: "DID arrays" });
        }
        prior = Some(did);
    }
    Ok(())
}
