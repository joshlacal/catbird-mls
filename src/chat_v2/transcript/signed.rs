//! The signed wrapper and strict Ed25519 verification.
//!
//! A signed mutation arrives as a wrapper carrying exactly two fields — the
//! body and its signature — and nothing else. The exactness is enforced rather
//! than merely expected: an extra sibling field would be unsigned data
//! travelling inside a signed request, which is the shape every "signature
//! covers less than you think" bug takes.
//!
//! # Strict means strict
//!
//! [`verify_ed25519_strict`] uses dalek's `verify_strict`, matching the server.
//! Plain `verify` accepts signatures under public keys with a small-order
//! (torsion) component, which admits signatures that verify under more than one
//! key. For a protocol that binds identity to a key, "this signature is valid
//! under exactly one key" is the property being relied on everywhere else, so
//! the permissive check is not an option.
//!
//! # The key ID is checked before the signature, not after
//!
//! A body states its `keyId` and the caller supplies the historical public key
//! it believes that names. Those are separate wire fields an attacker controls
//! independently, so the thumbprint is re-derived from the supplied key and
//! compared before any signature work happens. Verifying first and comparing
//! later would mean a signature had already been accepted under a key the body
//! never claimed.

use super::strict_json::{decode_standard_base64, decode_strict_json, StrictJson, StrictJsonError};
use super::{CanonicalBody, SignedMutationKind, SigningTranscript, TranscriptError};
use crate::chat_v2::ids::{KeyId, ED25519_PUBLIC_KEY_LEN};
use core::fmt;
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::BTreeMap;

/// The exact byte length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Why a signed mutation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedMutationError {
    /// The wrapper JSON was outside the strict profile.
    Json(StrictJsonError),
    /// The transcript could not be built from the projected body.
    Transcript(TranscriptError),
    /// The wrapper was not an object, or did not carry exactly `body` and
    /// `signature`.
    ///
    /// Anything else in the wrapper would be unsigned data riding inside a
    /// signed request.
    WrapperFieldSet,
    /// The signed body was not an object.
    BodyNotObject,
    /// The signature was absent, not a string, or not canonical base64.
    SignatureEncoding,
    /// The signature did not decode to exactly 64 bytes.
    SignatureLength,
    /// The supplied public key was not exactly 32 bytes.
    PublicKeyLength,
    /// The supplied public key was not a valid Ed25519 point.
    PublicKeyInvalid,
    /// The body's `keyId` was absent or was not the thumbprint of the supplied
    /// public key.
    KeyIdMismatch,
    /// Strict Ed25519 verification failed.
    Signature,
}

impl From<StrictJsonError> for SignedMutationError {
    fn from(err: StrictJsonError) -> Self {
        Self::Json(err)
    }
}

impl From<TranscriptError> for SignedMutationError {
    fn from(err: TranscriptError) -> Self {
        Self::Transcript(err)
    }
}

impl fmt::Display for SignedMutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "{err}"),
            Self::Transcript(err) => write!(f, "{err}"),
            Self::WrapperFieldSet => {
                f.write_str("signed wrapper must carry exactly body and signature")
            }
            Self::BodyNotObject => f.write_str("signed body must be an object"),
            Self::SignatureEncoding => f.write_str("signed wrapper signature encoding"),
            Self::SignatureLength => f.write_str("Ed25519 signature length"),
            Self::PublicKeyLength => f.write_str("Ed25519 public key length"),
            Self::PublicKeyInvalid => f.write_str("invalid Ed25519 public key"),
            Self::KeyIdMismatch => f.write_str("signed body key ID mismatch"),
            Self::Signature => f.write_str("invalid Ed25519 signature"),
        }
    }
}

impl core::error::Error for SignedMutationError {}

/// The two fields of a signed wrapper, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWrapper {
    /// The signed body, still in the strict JSON profile.
    pub body: StrictJson,
    /// The 64-byte Ed25519 signature.
    pub signature: [u8; ED25519_SIGNATURE_LEN],
}

impl SignedWrapper {
    /// Decodes a signed wrapper from its exact request bytes.
    pub fn decode(raw_json: &[u8]) -> Result<Self, SignedMutationError> {
        let StrictJson::Object(mut wrapper) = decode_strict_json(raw_json)? else {
            return Err(SignedMutationError::WrapperFieldSet);
        };
        // Exactly two. A third field is unsigned data inside a signed request,
        // and dropping it silently is how a signature comes to cover less than
        // the request it travelled with.
        if wrapper.len() != 2 {
            return Err(SignedMutationError::WrapperFieldSet);
        }
        let body = wrapper
            .remove("body")
            .ok_or(SignedMutationError::WrapperFieldSet)?;
        let signature = match wrapper.remove("signature") {
            Some(StrictJson::String(value)) => decode_standard_base64(&value)
                .map_err(|_| SignedMutationError::SignatureEncoding)?,
            _ => return Err(SignedMutationError::WrapperFieldSet),
        };
        let signature: [u8; ED25519_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| SignedMutationError::SignatureLength)?;
        if !matches!(body, StrictJson::Object(_)) {
            return Err(SignedMutationError::BodyNotObject);
        }
        Ok(Self { body, signature })
    }

    /// The body's `$type`, if it names a known kind.
    ///
    /// Fails closed on anything unrecognized, because the kind selects the
    /// signing domain and the domain is what keeps one operation's signature
    /// from being replayed as another's.
    pub fn kind(&self) -> Option<SignedMutationKind> {
        let StrictJson::Object(fields) = &self.body else {
            return None;
        };
        match fields.get("$type") {
            Some(StrictJson::String(value)) => SignedMutationKind::from_type_id(value),
            _ => None,
        }
    }
}

/// Verifies an Ed25519 signature strictly, exactly as the server does.
///
/// Rejects public keys with a small-order component, which plain `verify`
/// accepts. See the module documentation for why that matters here.
pub fn verify_ed25519_strict(
    public_key: &[u8],
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), SignedMutationError> {
    let public_key: [u8; ED25519_PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| SignedMutationError::PublicKeyLength)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SignedMutationError::PublicKeyInvalid)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| SignedMutationError::SignatureLength)?;
    verifying_key
        .verify_strict(transcript, &signature)
        .map_err(|_| SignedMutationError::Signature)
}

/// A signed mutation whose signature has been strictly verified.
///
/// Constructible only through [`Self::verify`], so holding one is proof that
/// the transcript was rebuilt from the projected body, the body's `keyId`
/// matched the supplied key, and `verify_strict` accepted the signature. No
/// constructor takes an unverified body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMutation {
    kind: SignedMutationKind,
    body: CanonicalBody,
    transcript: SigningTranscript,
    signature: [u8; ED25519_SIGNATURE_LEN],
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl VerifiedMutation {
    /// Rebuilds the transcript for a projected body and verifies its signature.
    ///
    /// The body must already have been projected through the lexicon contract;
    /// this is the step that turns a projection plus a signature into authority.
    pub fn verify(
        body: CanonicalBody,
        signature: [u8; ED25519_SIGNATURE_LEN],
        public_key: &[u8],
    ) -> Result<Self, SignedMutationError> {
        let public_key: [u8; ED25519_PUBLIC_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| SignedMutationError::PublicKeyLength)?;

        // Before any signature work: the body's claimed key ID must be the
        // thumbprint of the key we were handed. These are independent wire
        // fields, and verifying first would mean accepting a signature under a
        // key the body never claimed.
        let claimed = match body.get("keyId") {
            Some(super::CanonicalValue::Thumbprint(value))
            | Some(super::CanonicalValue::Text(value)) => value.as_str(),
            _ => return Err(SignedMutationError::KeyIdMismatch),
        };
        let claimed = KeyId::parse(claimed).map_err(|_| SignedMutationError::KeyIdMismatch)?;
        if !claimed.matches_public_key(&public_key) {
            return Err(SignedMutationError::KeyIdMismatch);
        }

        let transcript = SigningTranscript::build(&body)?;
        verify_ed25519_strict(&public_key, transcript.bytes(), &signature)?;
        Ok(Self {
            kind: transcript.kind(),
            body,
            transcript,
            signature,
            public_key,
        })
    }

    /// The verified kind.
    pub fn kind(&self) -> SignedMutationKind {
        self.kind
    }

    /// The projected body this signature covers.
    pub fn body(&self) -> &BTreeMap<String, super::CanonicalValue> {
        &self.body
    }

    /// The transcript the signature was verified against.
    pub fn transcript(&self) -> &SigningTranscript {
        &self.transcript
    }

    /// SHA-256 of the transcript. One of the outer fingerprint's inputs.
    pub fn request_digest(&self) -> &[u8; 32] {
        self.transcript.request_digest()
    }

    /// The verified signature.
    pub fn signature(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.signature
    }

    /// The public key the signature was verified under.
    pub fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.public_key
    }
}
