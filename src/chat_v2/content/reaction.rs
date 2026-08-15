//! The reaction value predicate.
//!
//! §8, in full:
//!
//! > A reaction value uses Unicode 17.0.0 NFC, is control-free, and is exactly
//! > one UAX #29 extended grapheme cluster under Unicode 17.0.0; it need not
//! > have the Unicode emoji property.
//!
//! The last clause matters more than it looks. A reaction is *not* restricted
//! to emoji, so a client must not "helpfully" reject letters, digits, or
//! punctuation. The only shape rule is one extended grapheme cluster.
//!
//! # The contract cannot enforce this, so the client is the enforcement
//!
//! `reactionFrameBody.emoji` declares `minGraphemes` and `maxGraphemes` in the
//! lexicon, but the projection ignores those annotations — it enforces only the
//! 1–64 byte bounds. And because reactions travel inside encrypted application
//! content, **the server cannot see them at all**. There is no server-side
//! validation to mirror and no golden vector to lift; this module is the whole
//! enforcement, on every client independently.
//!
//! That makes the Unicode version a real interoperability surface. Two clients
//! on different Unicode data will disagree about how many grapheme clusters a
//! sequence contains, and nothing upstream will catch it — so the version is
//! pinned and asserted rather than assumed.
//!
//! # NFC is not yet built and refuses by name
//!
//! Checking NFC needs a normalization implementation, and unlike the segmenter
//! that is not already linked on every target this crate builds for. Rather than
//! quietly skipping the check — which would accept decomposed sequences that a
//! conforming peer rejects, and silently split one logical reaction into two
//! reduce buckets — [`ReactionError::NfcCheckUnavailable`] refuses by name until
//! the dependency is settled. An unbuilt path must never read as a permissive
//! one.

use core::fmt;
use unicode_segmentation::UnicodeSegmentation;

/// The Unicode version every clean-chat client must agree on.
pub const REQUIRED_UNICODE_VERSION: (u64, u64, u64) = (17, 0, 0);

/// Maximum reaction value, in UTF-8 bytes.
pub const REACTION_MAX_BYTES: usize = 64;

/// Why a reaction value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactionError {
    /// The value was empty.
    Empty,
    /// The value exceeded 64 UTF-8 bytes.
    TooManyBytes { bytes: usize },
    /// The value contained a control character.
    ///
    /// Includes C0, C1, and DEL. A control character in a reaction is either a
    /// rendering attack or a value that will not survive a round trip.
    ControlCharacter { position: usize },
    /// The value was not exactly one extended grapheme cluster.
    NotOneGraphemeCluster { clusters: usize },
    /// **Not yet built.** NFC checking has no implementation on this build.
    ///
    /// Refused rather than skipped: accepting a decomposed sequence would let
    /// one logical reaction reduce into two buckets, since reactions reduce by
    /// `(verified DID, NFC grapheme)`.
    NfcCheckUnavailable,
}

impl fmt::Display for ReactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a reaction value must not be empty"),
            Self::TooManyBytes { bytes } => write!(
                f,
                "reaction is {bytes} UTF-8 bytes, at most {REACTION_MAX_BYTES} allowed"
            ),
            Self::ControlCharacter { position } => {
                write!(
                    f,
                    "reaction contains a control character at byte {position}"
                )
            }
            Self::NotOneGraphemeCluster { clusters } => write!(
                f,
                "reaction is {clusters} extended grapheme clusters, must be exactly one"
            ),
            Self::NfcCheckUnavailable => f.write_str(
                "NFC verification is not built; a reaction cannot be accepted without it",
            ),
        }
    }
}

impl core::error::Error for ReactionError {}

/// Whether the linked segmenter carries the Unicode version the protocol pins.
///
/// Exposed so a caller — and the test suite — can confirm agreement rather than
/// trust the dependency pin. A silent data-version bump changes which reactions
/// are accepted, on a path with no server backstop.
pub fn segmenter_unicode_version() -> (u64, u64, u64) {
    unicode_segmentation::UNICODE_VERSION
}

/// Confirms the shape rules that do not require normalization.
///
/// This is deliberately **not** the full predicate: it omits NFC. It exists so
/// the shape rules can be tested and reused, and so
/// [`require_reaction_value`] has one place to call. Callers wanting the
/// protocol's actual acceptance rule must use [`require_reaction_value`].
pub fn require_reaction_shape(value: &str) -> Result<(), ReactionError> {
    if value.is_empty() {
        return Err(ReactionError::Empty);
    }
    let bytes = value.len();
    if bytes > REACTION_MAX_BYTES {
        return Err(ReactionError::TooManyBytes { bytes });
    }
    if let Some((position, _)) = value.char_indices().find(|(_, ch)| is_control(*ch)) {
        return Err(ReactionError::ControlCharacter { position });
    }

    // Extended grapheme clusters, which is what UAX #29 and the contract both
    // mean. Legacy clusters would split some emoji sequences that must count
    // as one.
    let clusters = value.graphemes(true).count();
    if clusters != 1 {
        return Err(ReactionError::NotOneGraphemeCluster { clusters });
    }
    Ok(())
}

/// The protocol's reaction acceptance rule.
///
/// Currently refuses every value by name, because NFC verification is unbuilt
/// and a reaction cannot be accepted without it. The shape rules still run
/// first, so a value that is malformed for another reason reports that reason —
/// a caller debugging a rejected reaction should not be told "NFC unavailable"
/// when the real problem is that they sent three grapheme clusters.
pub fn require_reaction_value(value: &str) -> Result<(), ReactionError> {
    require_reaction_shape(value)?;
    Err(ReactionError::NfcCheckUnavailable)
}

/// Whether a character is a control character for this predicate.
///
/// C0, DEL, and C1. Spelled out rather than using `char::is_control` alone so
/// the intent is visible; the two agree, and a test pins that they do.
fn is_control(ch: char) -> bool {
    matches!(ch, '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_segmenter_carries_the_pinned_unicode_version() {
        // The interoperability surface. Two clients on different Unicode data
        // disagree about cluster counts, and nothing upstream catches it,
        // because the server never sees reaction content.
        assert_eq!(
            segmenter_unicode_version(),
            REQUIRED_UNICODE_VERSION,
            "the linked segmenter must carry Unicode 17.0.0"
        );
    }

    #[test]
    fn a_single_cluster_passes_the_shape_rules() {
        for value in [
            "a",
            "1",
            "!",
            "é",
            "\u{1F600}",                  // grinning face
            "\u{1F469}\u{200D}\u{1F4BB}", // woman technologist, ZWJ sequence
            "\u{1F1EF}\u{1F1F5}",         // regional indicator pair, one flag
            "\u{0928}\u{094D}\u{0937}",   // devanagari conjunct
            "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}", // tag sequence
        ] {
            assert_eq!(
                require_reaction_shape(value),
                Ok(()),
                "{value:?} is one extended grapheme cluster"
            );
        }
    }

    #[test]
    fn a_reaction_need_not_be_an_emoji() {
        // The spec says so explicitly. A client that rejects letters would
        // refuse valid reactions its peers accept.
        for value in ["a", "Z", "7", "?", "字", "ß"] {
            assert_eq!(require_reaction_shape(value), Ok(()), "{value:?}");
        }
    }

    #[test]
    fn more_than_one_cluster_is_refused_with_a_count() {
        for (value, clusters) in [("ab", 2), ("\u{1F600}\u{1F600}", 2), ("a\u{1F600}b", 3)] {
            assert_eq!(
                require_reaction_shape(value),
                Err(ReactionError::NotOneGraphemeCluster { clusters }),
                "{value:?}"
            );
        }
    }

    #[test]
    fn extended_clusters_are_used_not_legacy_ones() {
        // Extended and legacy clusters differ on SpacingMark and Prepend, NOT
        // on ZWJ emoji sequences — a ZWJ sequence is one cluster under both, so
        // it proves nothing here. Verified empirically against the linked
        // segmenter rather than assumed; an earlier version of this test used a
        // ZWJ sequence and failed for exactly that reason.
        //
        // Passing `false` would reject these reactions, which every conforming
        // peer accepts.
        for (name, value) in [
            ("devanagari ka + spacing mark aa", "\u{0915}\u{093E}"),
            ("devanagari conjunct", "\u{0928}\u{094D}\u{0937}"),
            ("thai sara am", "\u{0E01}\u{0E33}"),
        ] {
            assert_eq!(value.graphemes(true).count(), 1, "{name}: extended");
            assert_eq!(
                value.graphemes(false).count(),
                2,
                "{name}: legacy must split it, or this case proves nothing"
            );
            assert_eq!(require_reaction_shape(value), Ok(()), "{name}");
        }
    }

    #[test]
    fn zwj_and_regional_indicator_sequences_are_single_clusters_too() {
        // These are one cluster under both segmenters, so they do not
        // discriminate — but they are the sequences reactions most commonly
        // are, and a client that split them would be visibly broken.
        for value in [
            "\u{1F469}\u{200D}\u{1F4BB}",
            "\u{1F1EF}\u{1F1F5}",
            "e\u{0301}",
        ] {
            assert_eq!(value.graphemes(true).count(), 1, "{value:?}");
            assert_eq!(require_reaction_shape(value), Ok(()));
        }
    }

    #[test]
    fn an_empty_reaction_is_refused() {
        assert_eq!(require_reaction_shape(""), Err(ReactionError::Empty));
    }

    #[test]
    fn control_characters_are_refused_with_their_position() {
        for (value, position) in [
            ("\u{0}", 0),
            ("\u{7}", 0),
            ("\u{1F}", 0),
            ("\u{7F}", 0),
            ("\u{9F}", 0),
        ] {
            assert_eq!(
                require_reaction_shape(value),
                Err(ReactionError::ControlCharacter { position }),
                "{value:?}"
            );
        }
    }

    #[test]
    fn the_control_set_agrees_with_the_standard_predicate() {
        // Spelling the range out is for readability, not for a different
        // answer. If the two ever disagree, this fails rather than letting the
        // hand-written range drift.
        for code in 0u32..=0x10FF {
            if let Some(ch) = char::from_u32(code) {
                assert_eq!(
                    is_control(ch),
                    ch.is_control(),
                    "U+{code:04X} disagrees with char::is_control"
                );
            }
        }
    }

    #[test]
    fn the_byte_cap_is_measured_in_utf8_bytes() {
        // 64 bytes, not 64 characters. A single cluster can exceed the cap.
        let long_tag = "\u{1F3F4}".to_owned() + &"\u{E0067}".repeat(16);
        assert!(long_tag.len() > REACTION_MAX_BYTES);
        assert_eq!(
            require_reaction_shape(&long_tag),
            Err(ReactionError::TooManyBytes {
                bytes: long_tag.len()
            })
        );
    }

    #[test]
    fn the_byte_cap_is_checked_before_the_cluster_count() {
        // An oversized value must report its size rather than a cluster count,
        // because the size is the actionable problem.
        let oversized = "a".repeat(REACTION_MAX_BYTES + 1);
        assert_eq!(
            require_reaction_shape(&oversized),
            Err(ReactionError::TooManyBytes {
                bytes: REACTION_MAX_BYTES + 1
            })
        );
    }

    #[test]
    fn the_full_predicate_refuses_by_name_until_nfc_exists() {
        // The standing convention: an unbuilt path refuses rather than permits.
        // Skipping NFC would accept decomposed sequences that a conforming peer
        // rejects, and split one logical reaction across two reduce buckets.
        assert_eq!(
            require_reaction_value("a"),
            Err(ReactionError::NfcCheckUnavailable)
        );
        assert_eq!(
            require_reaction_value("\u{1F600}"),
            Err(ReactionError::NfcCheckUnavailable)
        );
    }

    #[test]
    fn shape_problems_are_reported_ahead_of_the_missing_nfc_check() {
        // A caller debugging a rejected reaction must not be told "NFC
        // unavailable" when they actually sent three clusters.
        assert_eq!(
            require_reaction_value("abc"),
            Err(ReactionError::NotOneGraphemeCluster { clusters: 3 })
        );
        assert_eq!(require_reaction_value(""), Err(ReactionError::Empty));
    }

    #[test]
    fn a_decomposed_sequence_is_one_cluster_and_still_needs_nfc() {
        // "e" + combining acute is one extended grapheme cluster but is NOT
        // NFC; its composed form is a different byte string. The shape rules
        // cannot tell them apart, which is exactly why NFC is required and why
        // skipping it would split one reaction into two buckets.
        let decomposed = "e\u{0301}";
        let composed = "\u{00E9}";
        assert_eq!(decomposed.graphemes(true).count(), 1);
        assert_eq!(composed.graphemes(true).count(), 1);
        assert_ne!(decomposed, composed, "different bytes, same appearance");
        assert_eq!(require_reaction_shape(decomposed), Ok(()));
        assert_eq!(require_reaction_shape(composed), Ok(()));
    }
}
