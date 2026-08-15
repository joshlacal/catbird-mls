//! Application content predicates.
//!
//! These are the rules that apply to **decrypted** application content, and
//! they have a different character from everything in [`super::transcript`].
//!
//! # There is no server to mirror here
//!
//! Envelope verification could be anchored on the server byte for byte, because
//! the server verifies the same envelopes. Application content is different:
//! it travels encrypted, so **the server never sees it**. Confirmed by
//! inspection — `mls-ds` declares no Unicode dependency and contains no
//! grapheme or normalization code — and it follows from the design rather than
//! being an oversight.
//!
//! Two consequences worth stating plainly, because they change how this code
//! must be judged:
//!
//! - **There are no golden vectors to lift.** The S7 rule that a failing vector
//!   is a finding rather than something to adjust has no analogue here; the
//!   test vectors in this module are constructed, and they are constructed from
//!   the spec text rather than from an implementation.
//! - **Every client is the whole enforcement, independently.** A disagreement
//!   between two clients is not caught anywhere upstream. That is why the
//!   Unicode version is pinned and asserted rather than assumed, and why the
//!   closed sets here fail closed on anything unrecognized.
//!
//! # These are the rules the lexicon cannot express
//!
//! The contract bounds `ciphertextSize` and `plaintextSize` separately but has
//! no way to require they differ by exactly the AEAD tag. It annotates
//! `minGraphemes` and `maxGraphemes` on a reaction but the projection enforces
//! only byte length. Those gaps are this module's subject matter.

pub mod at_uri;
pub mod link;
pub mod media;
pub mod reaction;

pub use at_uri::{AtUriError, RestrictedAtUri, AT_URI_MAX_LEN, NSID_MAX_LEN, RKEY_MAX_LEN, SCHEME};
pub use link::{require_external_link, LinkError, EXTERNAL_LINK_MAX_BYTES, HTTPS_SCHEME};
pub use media::{
    require_alt_text, require_blurhash, require_ciphertext_size, require_dimensions,
    require_duration, require_waveform, AudioMime, ImageMime, MediaError, AEAD_TAG_LEN,
    ALT_TEXT_MAX_BYTES, AUDIO_CIPHERTEXT_MAX, AUDIO_DURATION_MAX_MILLIS, BLURHASH_MAX_BYTES,
    BLURHASH_MIN_BYTES, IMAGE_CIPHERTEXT_MAX, IMAGE_DIMENSION_MAX, WAVEFORM_LEN,
};
pub use reaction::{
    require_reaction_shape, require_reaction_value, segmenter_unicode_version, ReactionError,
    REACTION_MAX_BYTES, REQUIRED_UNICODE_VERSION,
};

#[cfg(test)]
mod media_tests;
#[cfg(test)]
mod uri_tests;
