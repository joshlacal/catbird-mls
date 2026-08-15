//! Encrypted image and audio predicates.
//!
//! These are the rules the lexicon contract **cannot express**, which is why
//! they live here rather than falling out of the projection. The contract bounds
//! `ciphertextSize` and `plaintextSize` independently; it has no way to say they
//! must differ by exactly the AEAD tag length. That relationship is the whole
//! point:
//!
//! > Checked arithmetic requires exact `ciphertextSize == plaintextSize + 16`
//! > for both image and audio.
//!
//! # Why the arithmetic is checked rather than computed
//!
//! Deriving `plaintextSize` from `ciphertextSize` would silently accept any
//! ciphertext size a peer sent and invent a matching plaintext size. Both
//! numbers arrive on the wire, both are signed, and the client's job is to
//! confirm they agree — not to reconcile them. Every operation here is checked:
//! a `plaintextSize` near the integer ceiling must not wrap into a plausible
//! ciphertext size.
//!
//! # The MIME sets are closed, and GIF is ordinary
//!
//! §8: "The transport/application encrypted-image MIME set is exactly
//! `image/heic | image/jpeg | image/png | image/webp | image/gif`; **GIF is an
//! ordinary encrypted-image embed, not a remote dialect.**" That sentence exists
//! because GIF is the format a client is most likely to special-case into a
//! remote-loading path, which would leak the fetch and defeat the encryption.
//! There is no remote dialect here to route it to.

use core::fmt;

/// The AEAD tag length appended to every ciphertext.
///
/// A256GCM with a 12-byte nonce and an appended 16-byte tag; the nonce is not
/// part of the ciphertext size.
pub const AEAD_TAG_LEN: u64 = 16;

/// Maximum encrypted-image ciphertext, tag included.
pub const IMAGE_CIPHERTEXT_MAX: u64 = 10 * 1024 * 1024;
/// Maximum encrypted-audio ciphertext, tag included.
pub const AUDIO_CIPHERTEXT_MAX: u64 = 8 * 1024 * 1024;
/// Maximum image dimension on either axis.
pub const IMAGE_DIMENSION_MAX: u64 = 16_384;
/// Maximum alt text, in UTF-8 bytes.
pub const ALT_TEXT_MAX_BYTES: usize = 4_096;
/// Blurhash bounds, in UTF-8 bytes.
pub const BLURHASH_MIN_BYTES: usize = 6;
/// See [`BLURHASH_MIN_BYTES`].
pub const BLURHASH_MAX_BYTES: usize = 256;
/// An audio waveform is exactly this many bytes.
pub const WAVEFORM_LEN: usize = 64;
/// Maximum audio duration, in milliseconds.
pub const AUDIO_DURATION_MAX_MILLIS: u64 = 300_000;

/// The closed encrypted-image MIME set.
///
/// GIF is a member. It is an ordinary encrypted-image embed and must never be
/// routed to a remote-loading path — there is no remote dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageMime {
    /// `image/heic`
    Heic,
    /// `image/jpeg`
    Jpeg,
    /// `image/png`
    Png,
    /// `image/webp`
    Webp,
    /// `image/gif`, on the ordinary encrypted path like every other member.
    Gif,
}

impl ImageMime {
    /// Every member, for exhaustive sweeps.
    pub const ALL: [Self; 5] = [Self::Heic, Self::Jpeg, Self::Png, Self::Webp, Self::Gif];

    /// The exact wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Heic => "image/heic",
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Webp => "image/webp",
            Self::Gif => "image/gif",
        }
    }

    /// Resolves a wire token, failing closed on anything else.
    ///
    /// Never case-folds: the contract declares these tokens exactly, and
    /// accepting `IMAGE/PNG` would be accepting a value the signature covered
    /// as something else.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mime| mime.as_str() == value)
    }
}

/// The closed MIME set for an encrypted **metadata avatar**.
///
/// A separate predicate from [`ImageMime`] because the contract declares a
/// separate, narrower set: `metadataAvatarEmbed.mimeType` omits `image/gif`,
/// which `encryptedImageEmbed.mimeType` includes. Two sets, both pinned against
/// the contract by their own test.
///
/// Reusing the image predicate here would accept an animated avatar the server
/// rejects — and it would do so on the *encrypted* path, where nothing upstream
/// sees the value to disagree with. That is the whole reason this is a type
/// rather than a comment on the image one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvatarMime {
    /// `image/heic`
    Heic,
    /// `image/jpeg`
    Jpeg,
    /// `image/png`
    Png,
    /// `image/webp`
    Webp,
}

impl AvatarMime {
    /// Every member, for exhaustive sweeps.
    pub const ALL: [Self; 4] = [Self::Heic, Self::Jpeg, Self::Png, Self::Webp];

    /// The exact wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Heic => "image/heic",
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Webp => "image/webp",
        }
    }

    /// Resolves a wire token, failing closed on anything else.
    ///
    /// `image/gif` fails here and succeeds in [`ImageMime::parse`]. That is the
    /// point of the type, not an inconsistency.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mime| mime.as_str() == value)
    }
}

/// The closed encrypted-audio MIME set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AudioMime {
    /// `audio/aac`
    Aac,
    /// `audio/mp4`
    Mp4,
    /// `audio/ogg`
    Ogg,
    /// `audio/opus`
    Opus,
}

impl AudioMime {
    /// Every member, for exhaustive sweeps.
    pub const ALL: [Self; 4] = [Self::Aac, Self::Mp4, Self::Ogg, Self::Opus];

    /// The exact wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aac => "audio/aac",
            Self::Mp4 => "audio/mp4",
            Self::Ogg => "audio/ogg",
            Self::Opus => "audio/opus",
        }
    }

    /// Resolves a wire token, failing closed on anything else.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mime| mime.as_str() == value)
    }
}

/// Why a media embed was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// The MIME token was outside its closed set.
    UnknownMime,
    /// `ciphertextSize` and `plaintextSize` did not differ by exactly the tag.
    ///
    /// The two numbers are independently signed, and disagreement means the
    /// descriptor does not describe the bytes it points at.
    CiphertextSizeMismatch {
        ciphertext: u64,
        plaintext: u64,
        expected_ciphertext: u64,
    },
    /// A checked addition would have overflowed.
    ///
    /// Named separately from a plain mismatch: a wrapping implementation would
    /// turn a huge `plaintextSize` into a small plausible ciphertext size.
    SizeOverflow { plaintext: u64 },
    /// The ciphertext exceeded its medium's cap.
    CiphertextTooLarge { size: u64, max: u64 },
    /// A plaintext size of zero. Every embed carries at least one byte.
    EmptyPlaintext,
    /// An image dimension was zero or above the cap.
    Dimension { width: u64, height: u64 },
    /// Alt text was empty or over the byte cap.
    AltTextBytes { bytes: usize },
    /// A blurhash was outside its byte bounds.
    BlurhashBytes { bytes: usize },
    /// A waveform was not exactly 64 bytes.
    WaveformLength { bytes: usize },
    /// Audio duration was zero or above the cap.
    Duration { millis: u64 },
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMime => f.write_str("media type is outside its closed set"),
            Self::CiphertextSizeMismatch {
                ciphertext,
                plaintext,
                expected_ciphertext,
            } => write!(
                f,
                "ciphertextSize {ciphertext} must equal plaintextSize {plaintext} plus \
                 {AEAD_TAG_LEN} ({expected_ciphertext})"
            ),
            Self::SizeOverflow { plaintext } => {
                write!(
                    f,
                    "plaintextSize {plaintext} overflows when the tag is added"
                )
            }
            Self::CiphertextTooLarge { size, max } => {
                write!(f, "ciphertext {size} exceeds the {max} byte cap")
            }
            Self::EmptyPlaintext => f.write_str("plaintextSize must be at least one byte"),
            Self::Dimension { width, height } => write!(
                f,
                "image {width}x{height} is outside 1..={IMAGE_DIMENSION_MAX} on an axis"
            ),
            Self::AltTextBytes { bytes } => write!(
                f,
                "alt text is {bytes} UTF-8 bytes, outside 1..={ALT_TEXT_MAX_BYTES}"
            ),
            Self::BlurhashBytes { bytes } => write!(
                f,
                "blurhash is {bytes} UTF-8 bytes, outside \
                 {BLURHASH_MIN_BYTES}..={BLURHASH_MAX_BYTES}"
            ),
            Self::WaveformLength { bytes } => {
                write!(
                    f,
                    "waveform is {bytes} bytes, must be exactly {WAVEFORM_LEN}"
                )
            }
            Self::Duration { millis } => write!(
                f,
                "audio duration {millis}ms is outside 1..={AUDIO_DURATION_MAX_MILLIS}"
            ),
        }
    }
}

impl core::error::Error for MediaError {}

/// Confirms `ciphertextSize == plaintextSize + 16` with checked arithmetic.
///
/// Shared by image, audio, and the metadata avatar descriptor, which all state
/// the same requirement.
pub fn require_ciphertext_size(
    ciphertext: u64,
    plaintext: u64,
    ciphertext_max: u64,
) -> Result<(), MediaError> {
    if plaintext == 0 {
        return Err(MediaError::EmptyPlaintext);
    }
    let expected = plaintext
        .checked_add(AEAD_TAG_LEN)
        .ok_or(MediaError::SizeOverflow { plaintext })?;
    if ciphertext != expected {
        return Err(MediaError::CiphertextSizeMismatch {
            ciphertext,
            plaintext,
            expected_ciphertext: expected,
        });
    }
    if ciphertext > ciphertext_max {
        return Err(MediaError::CiphertextTooLarge {
            size: ciphertext,
            max: ciphertext_max,
        });
    }
    Ok(())
}

/// Confirms an optional blurhash is 6–256 **UTF-8 bytes**.
///
/// Bytes, not characters. A blurhash is base83 ASCII in practice, but the bound
/// is stated in bytes and a multibyte value must be measured the same way the
/// contract measures it.
pub fn require_blurhash(value: &str) -> Result<(), MediaError> {
    let bytes = value.len();
    if !(BLURHASH_MIN_BYTES..=BLURHASH_MAX_BYTES).contains(&bytes) {
        return Err(MediaError::BlurhashBytes { bytes });
    }
    Ok(())
}

/// Confirms optional alt text is 1–4,096 UTF-8 bytes.
pub fn require_alt_text(value: &str) -> Result<(), MediaError> {
    let bytes = value.len();
    if bytes == 0 || bytes > ALT_TEXT_MAX_BYTES {
        return Err(MediaError::AltTextBytes { bytes });
    }
    Ok(())
}

/// Confirms both image dimensions are within `1..=16384`.
pub fn require_dimensions(width: u64, height: u64) -> Result<(), MediaError> {
    let ok =
        (1..=IMAGE_DIMENSION_MAX).contains(&width) && (1..=IMAGE_DIMENSION_MAX).contains(&height);
    if ok {
        Ok(())
    } else {
        Err(MediaError::Dimension { width, height })
    }
}

/// Confirms an audio waveform is exactly 64 bytes.
pub fn require_waveform(waveform: &[u8]) -> Result<(), MediaError> {
    if waveform.len() == WAVEFORM_LEN {
        Ok(())
    } else {
        Err(MediaError::WaveformLength {
            bytes: waveform.len(),
        })
    }
}

/// Confirms audio duration is within `1..=300000` milliseconds.
pub fn require_duration(millis: u64) -> Result<(), MediaError> {
    if (1..=AUDIO_DURATION_MAX_MILLIS).contains(&millis) {
        Ok(())
    } else {
        Err(MediaError::Duration { millis })
    }
}
