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
//! # NFC is checked, never applied
//!
//! [`unicode_normalization::is_nfc`] answers whether a value already *is* NFC.
//! Nothing here normalizes: this tree rejects rather than normalizes throughout,
//! and silently composing a peer's reaction would change bytes that a signature
//! covers.
//!
//! Skipping the check was never an option, and the reason is specific rather
//! than general. Reactions reduce by `(verified DID, NFC grapheme)`, so a
//! decomposed value and its composed form — visually identical, one cluster
//! each, different bytes — would reduce into **two separate buckets**. One
//! person's single reaction would render as two.
//!
//! # Both Unicode versions must agree, and they do
//!
//! Segmentation and normalization come from different crates, and a value
//! accepted as one grapheme under one Unicode version but NFC-checked under
//! another is a cross-version seam. `unicode-segmentation` 1.13.3 and
//! `unicode-normalization` 0.1.25 both report `UNICODE_VERSION` of 17.0.0, which
//! is what the protocol pins. A test asserts all three agree rather than
//! trusting the pins.

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
    /// The value was not already in Unicode NFC.
    ///
    /// Refused rather than normalized. Reactions reduce by `(verified DID, NFC
    /// grapheme)`, so accepting a decomposed value would reduce it into a
    /// different bucket from its composed twin — one person's single reaction
    /// rendering as two.
    NotNfc,
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
            Self::NotNfc => f.write_str("reaction is not in Unicode NFC"),
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
/// Shape first, then NFC. The ordering is for the caller's benefit: someone who
/// sent three grapheme clusters should be told that rather than being told
/// their value is not NFC, which would be true but useless.
///
/// Nothing here normalizes. A value that is not already NFC is refused, because
/// composing it would change bytes a signature covers and because the two forms
/// reduce into different buckets.
pub fn require_reaction_value(value: &str) -> Result<(), ReactionError> {
    require_reaction_shape(value)?;
    if !unicode_normalization::is_nfc(value) {
        return Err(ReactionError::NotNfc);
    }
    Ok(())
}

/// Whether the linked normalizer carries the Unicode version the protocol pins.
///
/// Separate from [`segmenter_unicode_version`] because they come from different
/// crates. A value accepted as one grapheme under one Unicode version but
/// NFC-checked under another is a cross-version seam, so both are exposed and
/// both are asserted.
pub fn normalizer_unicode_version() -> (u64, u64, u64) {
    let (major, minor, patch) = unicode_normalization::UNICODE_VERSION;
    (u64::from(major), u64::from(minor), u64::from(patch))
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

    const CONTRACT: &str = include_str!("../transcript/vectors/blue.catbird.chat.defs.json");

    /// The contract's own declaration for the reaction value.
    fn declared_emoji() -> serde_json::Value {
        let contract: serde_json::Value =
            serde_json::from_str(CONTRACT).expect("the embedded contract must parse");
        contract["defs"]["reactionFrameBody"]["properties"]["emoji"].clone()
    }

    #[test]
    fn the_byte_bounds_are_the_contracts_own() {
        // The cap was a bare constant, agreeing with the contract by
        // coincidence rather than by construction: a mutation from 64 to 66
        // survived the whole suite. The media predicates already read their
        // bounds from the contract; this one now does too, so the constant and
        // the declaration cannot drift apart silently.
        let emoji = declared_emoji();
        assert_eq!(
            emoji["maxLength"].as_u64(),
            Some(REACTION_MAX_BYTES as u64),
            "the reaction cap must be the contract's maxLength"
        );
        assert_eq!(
            emoji["minLength"].as_u64(),
            Some(1),
            "the contract's minimum is what makes empty a refusal"
        );

        // And the contract is genuinely being read, rather than a missing
        // lookup yielding JSON null and comparing equal to nothing.
        assert!(emoji.is_object(), "the emoji declaration must be present");
    }

    #[test]
    fn the_grapheme_bounds_are_the_contracts_own_too() {
        // `minGraphemes`/`maxGraphemes` are annotations the projection ignores,
        // which is exactly why this module exists. Reading them here keeps the
        // "exactly one cluster" rule anchored to the declaration rather than to
        // a sentence in a doc comment.
        let emoji = declared_emoji();
        assert_eq!(emoji["minGraphemes"].as_u64(), Some(1));
        assert_eq!(emoji["maxGraphemes"].as_u64(), Some(1));
    }

    #[test]
    fn the_cap_is_enforced_at_the_exact_boundary() {
        // Bytes, not characters: the boundary is where a character-counting
        // implementation would diverge.
        let at_cap = "a".repeat(REACTION_MAX_BYTES);
        assert_eq!(
            require_reaction_shape(&at_cap),
            Err(ReactionError::NotOneGraphemeCluster {
                clusters: REACTION_MAX_BYTES
            }),
            "the cap is a byte bound; this is refused for its cluster count, not its length"
        );

        let over_cap = "a".repeat(REACTION_MAX_BYTES + 1);
        assert_eq!(
            require_reaction_shape(&over_cap),
            Err(ReactionError::TooManyBytes {
                bytes: REACTION_MAX_BYTES + 1
            }),
            "one byte over the cap is refused for its length, before any clustering"
        );
    }

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
    fn the_full_predicate_now_accepts_a_valid_reaction() {
        // The converted refusal. This used to be NfcCheckUnavailable for every
        // input; the predicate is complete and these are genuinely accepted.
        for value in [
            "a",
            "\u{1F600}",
            "\u{00E9}",                   // composed e-acute: already NFC
            "\u{1F469}\u{200D}\u{1F4BB}", // ZWJ sequence, no composition to do
            "\u{0915}\u{093E}",           // devanagari: NFC leaves it alone
        ] {
            assert_eq!(require_reaction_value(value), Ok(()), "{value:?}");
        }
    }

    #[test]
    fn a_decomposed_reaction_is_refused_rather_than_composed() {
        // The other half of the conversion, and the reason the check exists.
        // Nothing normalizes: composing a peer's value would change bytes a
        // signature covers.
        let decomposed = "e\u{0301}";
        assert_eq!(
            require_reaction_value(decomposed),
            Err(ReactionError::NotNfc)
        );

        // Its composed twin is accepted, so the two really do land in different
        // buckets — which is exactly the reduce-splitting this prevents.
        let composed = "\u{00E9}";
        assert_eq!(require_reaction_value(composed), Ok(()));
        assert_ne!(decomposed, composed);
    }

    #[test]
    fn shape_problems_are_reported_ahead_of_the_nfc_check() {
        // A caller who sent three clusters must be told that rather than being
        // told their value is not NFC, which would be true but useless.
        assert_eq!(
            require_reaction_value("abc"),
            Err(ReactionError::NotOneGraphemeCluster { clusters: 3 })
        );
        assert_eq!(require_reaction_value(""), Err(ReactionError::Empty));

        // A decomposed multi-cluster value reports the cluster count, not NFC.
        assert_eq!(
            require_reaction_value("e\u{0301}e\u{0301}"),
            Err(ReactionError::NotOneGraphemeCluster { clusters: 2 })
        );
    }

    #[test]
    fn the_segmenter_and_the_normalizer_agree_on_the_unicode_version() {
        // The cross-version seam the lead asked to be checked explicitly. These
        // are different crates; a value accepted as one grapheme under one
        // Unicode version but NFC-checked under another would be a real
        // interoperability hazard. They agree, and this asserts it rather than
        // trusting two independent version pins.
        assert_eq!(segmenter_unicode_version(), REQUIRED_UNICODE_VERSION);
        assert_eq!(normalizer_unicode_version(), REQUIRED_UNICODE_VERSION);
        assert_eq!(segmenter_unicode_version(), normalizer_unicode_version());
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
