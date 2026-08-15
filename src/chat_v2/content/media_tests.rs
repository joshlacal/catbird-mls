//! Media predicate tests, cross-checked against the embedded contract.
//!
//! These vectors are constructed rather than lifted — there is no server
//! implementation to lift from, because application content is encrypted. To
//! stop the constructed bounds drifting from the declared ones, the tests here
//! read the contract's own `minimum` / `maximum` / `enum` values and assert this
//! module agrees with them.

use super::media::*;
use serde_json::Value;

const CONTRACT: &str = include_str!("../transcript/vectors/blue.catbird.chat.defs.json");

fn contract() -> Value {
    serde_json::from_str(CONTRACT).expect("the embedded contract must parse")
}

fn property(definition: &str, field: &str) -> Value {
    contract()["defs"][definition]["properties"][field].clone()
}

// ---- the closed MIME sets --------------------------------------------------

#[test]
fn the_image_mime_set_is_exactly_the_contracts() {
    let declared: Vec<String> = property("encryptedImageEmbed", "mimeType")["enum"]
        .as_array()
        .expect("the contract declares an enum")
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let ours: Vec<String> = ImageMime::ALL
        .iter()
        .map(|mime| mime.as_str().to_owned())
        .collect();

    assert_eq!(ours, declared, "the image MIME set must match the contract");
    assert_eq!(declared.len(), 5);
    assert!(
        declared.iter().any(|value| value == "image/gif"),
        "GIF is a member of the ordinary encrypted set"
    );
}

#[test]
fn the_audio_mime_set_is_exactly_the_contracts() {
    let declared: Vec<String> = property("encryptedAudioEmbed", "mimeType")["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let ours: Vec<String> = AudioMime::ALL
        .iter()
        .map(|mime| mime.as_str().to_owned())
        .collect();
    assert_eq!(ours, declared);
    assert_eq!(declared.len(), 4);
}

#[test]
fn mime_tokens_round_trip_and_fail_closed() {
    for mime in ImageMime::ALL {
        assert_eq!(ImageMime::parse(mime.as_str()), Some(mime));
    }
    for mime in AudioMime::ALL {
        assert_eq!(AudioMime::parse(mime.as_str()), Some(mime));
    }
    for unknown in [
        "image/svg+xml",
        "image/avif",
        "IMAGE/PNG",
        "image/png ",
        "",
        "audio/wav",
    ] {
        assert_eq!(ImageMime::parse(unknown), None, "{unknown}");
        assert_eq!(AudioMime::parse(unknown), None, "{unknown}");
    }
}

#[test]
fn mime_matching_is_never_case_folded() {
    // The contract declares these tokens exactly. Accepting a case variant
    // would accept a value the signature covered as something else.
    assert_eq!(ImageMime::parse("image/PNG"), None);
    assert_eq!(ImageMime::parse("Image/png"), None);
    assert_eq!(AudioMime::parse("AUDIO/OPUS"), None);
}

#[test]
fn gif_is_an_ordinary_member_with_no_special_handling() {
    // §8 calls this out because GIF is the format most likely to be
    // special-cased into a remote-loading path, which would leak the fetch and
    // defeat the encryption. There is no remote dialect to route it to.
    assert_eq!(ImageMime::parse("image/gif"), Some(ImageMime::Gif));
    assert_eq!(ImageMime::Gif.as_str(), "image/gif");
    assert!(ImageMime::ALL.contains(&ImageMime::Gif));
}

// ---- the checked ciphertext arithmetic --------------------------------------

#[test]
fn ciphertext_must_be_plaintext_plus_exactly_the_tag() {
    assert_eq!(
        require_ciphertext_size(1 + AEAD_TAG_LEN, 1, IMAGE_CIPHERTEXT_MAX),
        Ok(())
    );
    assert_eq!(
        require_ciphertext_size(1024 + AEAD_TAG_LEN, 1024, IMAGE_CIPHERTEXT_MAX),
        Ok(())
    );

    // One byte either side is refused, and the error carries what was expected.
    for delta in [AEAD_TAG_LEN - 1, AEAD_TAG_LEN + 1] {
        assert_eq!(
            require_ciphertext_size(1024 + delta, 1024, IMAGE_CIPHERTEXT_MAX),
            Err(MediaError::CiphertextSizeMismatch {
                ciphertext: 1024 + delta,
                plaintext: 1024,
                expected_ciphertext: 1024 + AEAD_TAG_LEN,
            })
        );
    }
}

#[test]
fn the_addition_is_checked_rather_than_wrapping() {
    // A wrapping implementation would turn a huge plaintextSize into a small
    // plausible ciphertext size and accept it.
    assert_eq!(
        require_ciphertext_size(0, u64::MAX, IMAGE_CIPHERTEXT_MAX),
        Err(MediaError::SizeOverflow {
            plaintext: u64::MAX
        })
    );
    assert_eq!(
        require_ciphertext_size(u64::MAX, u64::MAX - 5, IMAGE_CIPHERTEXT_MAX),
        Err(MediaError::SizeOverflow {
            plaintext: u64::MAX - 5
        })
    );
}

#[test]
fn a_zero_plaintext_is_refused_before_the_arithmetic() {
    assert_eq!(
        require_ciphertext_size(AEAD_TAG_LEN, 0, IMAGE_CIPHERTEXT_MAX),
        Err(MediaError::EmptyPlaintext)
    );
}

#[test]
fn the_caps_match_the_contract_and_are_enforced_at_the_boundary() {
    let image_max = property("encryptedImageEmbed", "ciphertextSize")["maximum"]
        .as_u64()
        .unwrap();
    let audio_max = property("encryptedAudioEmbed", "ciphertextSize")["maximum"]
        .as_u64()
        .unwrap();
    assert_eq!(image_max, IMAGE_CIPHERTEXT_MAX);
    assert_eq!(audio_max, AUDIO_CIPHERTEXT_MAX);

    // The contract's plaintext maxima are exactly the ciphertext maxima less
    // the tag, which is the same relationship stated a second way.
    for (definition, ciphertext_max) in [
        ("encryptedImageEmbed", IMAGE_CIPHERTEXT_MAX),
        ("encryptedAudioEmbed", AUDIO_CIPHERTEXT_MAX),
    ] {
        let plaintext_max = property(definition, "plaintextSize")["maximum"]
            .as_u64()
            .unwrap();
        assert_eq!(
            plaintext_max,
            ciphertext_max - AEAD_TAG_LEN,
            "{definition} plaintext cap must be the ciphertext cap less the tag"
        );

        // Exactly at the cap is accepted; one byte over is refused.
        assert_eq!(
            require_ciphertext_size(ciphertext_max, plaintext_max, ciphertext_max),
            Ok(())
        );
        assert_eq!(
            require_ciphertext_size(ciphertext_max + 1, plaintext_max + 1, ciphertext_max),
            Err(MediaError::CiphertextTooLarge {
                size: ciphertext_max + 1,
                max: ciphertext_max
            })
        );
    }
}

#[test]
fn image_and_audio_carry_different_caps() {
    // An audio ciphertext at the image cap must not be accepted just because
    // the arithmetic works.
    let oversized = AUDIO_CIPHERTEXT_MAX + 1;
    assert_eq!(
        require_ciphertext_size(oversized, oversized - AEAD_TAG_LEN, AUDIO_CIPHERTEXT_MAX),
        Err(MediaError::CiphertextTooLarge {
            size: oversized,
            max: AUDIO_CIPHERTEXT_MAX
        })
    );
    assert_eq!(
        require_ciphertext_size(oversized, oversized - AEAD_TAG_LEN, IMAGE_CIPHERTEXT_MAX),
        Ok(()),
        "the same sizes are fine under the image cap"
    );
}

// ---- byte-measured string bounds ---------------------------------------------

#[test]
fn the_blurhash_bounds_match_the_contract_and_are_measured_in_bytes() {
    let declared = property("encryptedImageEmbed", "blurhash");
    assert_eq!(
        declared["minLength"].as_u64(),
        Some(BLURHASH_MIN_BYTES as u64)
    );
    assert_eq!(
        declared["maxLength"].as_u64(),
        Some(BLURHASH_MAX_BYTES as u64)
    );

    assert_eq!(require_blurhash(&"a".repeat(BLURHASH_MIN_BYTES)), Ok(()));
    assert_eq!(require_blurhash(&"a".repeat(BLURHASH_MAX_BYTES)), Ok(()));
    assert_eq!(
        require_blurhash(&"a".repeat(BLURHASH_MIN_BYTES - 1)),
        Err(MediaError::BlurhashBytes {
            bytes: BLURHASH_MIN_BYTES - 1
        })
    );
    assert_eq!(
        require_blurhash(&"a".repeat(BLURHASH_MAX_BYTES + 1)),
        Err(MediaError::BlurhashBytes {
            bytes: BLURHASH_MAX_BYTES + 1
        })
    );
}

#[test]
fn multibyte_values_are_measured_in_bytes_not_characters() {
    // The boundary case the handoff calls out. Two-byte characters reach the
    // byte cap at half the character count, and a character-counting
    // implementation would accept roughly twice as much data as the contract
    // permits.
    let two_byte = "é";
    assert_eq!(two_byte.len(), 2);
    assert_eq!(two_byte.chars().count(), 1);

    let at_cap = two_byte.repeat(BLURHASH_MAX_BYTES / 2);
    assert_eq!(at_cap.len(), BLURHASH_MAX_BYTES);
    assert_eq!(require_blurhash(&at_cap), Ok(()));

    let over_cap = two_byte.repeat(BLURHASH_MAX_BYTES / 2 + 1);
    assert_eq!(over_cap.chars().count(), BLURHASH_MAX_BYTES / 2 + 1);
    assert_eq!(
        require_blurhash(&over_cap),
        Err(MediaError::BlurhashBytes {
            bytes: BLURHASH_MAX_BYTES + 2
        }),
        "a character-counting implementation would have accepted this"
    );

    // And a three-byte character just under the minimum by bytes.
    let three_byte = "字";
    assert_eq!(three_byte.len(), 3);
    assert_eq!(
        require_blurhash(three_byte),
        Err(MediaError::BlurhashBytes { bytes: 3 }),
        "one character is not six bytes"
    );
    assert_eq!(require_blurhash(&three_byte.repeat(2)), Ok(()));
}

#[test]
fn alt_text_bounds_match_the_contract() {
    let declared = property("encryptedImageEmbed", "altText");
    assert_eq!(declared["minLength"].as_u64(), Some(1));
    assert_eq!(
        declared["maxLength"].as_u64(),
        Some(ALT_TEXT_MAX_BYTES as u64)
    );

    assert_eq!(require_alt_text("a"), Ok(()));
    assert_eq!(require_alt_text(&"a".repeat(ALT_TEXT_MAX_BYTES)), Ok(()));
    assert_eq!(
        require_alt_text(""),
        Err(MediaError::AltTextBytes { bytes: 0 })
    );
    assert_eq!(
        require_alt_text(&"a".repeat(ALT_TEXT_MAX_BYTES + 1)),
        Err(MediaError::AltTextBytes {
            bytes: ALT_TEXT_MAX_BYTES + 1
        })
    );
}

// ---- dimensions, waveform, duration -------------------------------------------

#[test]
fn image_dimensions_match_the_contract_and_reject_zero() {
    for axis in ["width", "height"] {
        let declared = property("encryptedImageEmbed", axis);
        assert_eq!(declared["minimum"].as_u64(), Some(1));
        assert_eq!(declared["maximum"].as_u64(), Some(IMAGE_DIMENSION_MAX));
    }

    assert_eq!(require_dimensions(1, 1), Ok(()));
    assert_eq!(
        require_dimensions(IMAGE_DIMENSION_MAX, IMAGE_DIMENSION_MAX),
        Ok(())
    );
    for (width, height) in [
        (0, 1),
        (1, 0),
        (IMAGE_DIMENSION_MAX + 1, 1),
        (1, IMAGE_DIMENSION_MAX + 1),
    ] {
        assert_eq!(
            require_dimensions(width, height),
            Err(MediaError::Dimension { width, height }),
            "{width}x{height}"
        );
    }
}

#[test]
fn a_waveform_is_exactly_sixty_four_bytes() {
    let declared = property("encryptedAudioEmbed", "waveform");
    assert_eq!(declared["minLength"].as_u64(), Some(WAVEFORM_LEN as u64));
    assert_eq!(declared["maxLength"].as_u64(), Some(WAVEFORM_LEN as u64));

    assert_eq!(require_waveform(&[0u8; WAVEFORM_LEN]), Ok(()));
    for bytes in [0usize, WAVEFORM_LEN - 1, WAVEFORM_LEN + 1] {
        assert_eq!(
            require_waveform(&vec![0u8; bytes]),
            Err(MediaError::WaveformLength { bytes })
        );
    }
}

#[test]
fn audio_duration_matches_the_contract() {
    let declared = property("encryptedAudioEmbed", "durationMillis");
    assert_eq!(declared["minimum"].as_u64(), Some(1));
    assert_eq!(
        declared["maximum"].as_u64(),
        Some(AUDIO_DURATION_MAX_MILLIS)
    );

    assert_eq!(require_duration(1), Ok(()));
    assert_eq!(require_duration(AUDIO_DURATION_MAX_MILLIS), Ok(()));
    for millis in [0, AUDIO_DURATION_MAX_MILLIS + 1] {
        assert_eq!(
            require_duration(millis),
            Err(MediaError::Duration { millis })
        );
    }
}

#[test]
fn the_contract_is_actually_being_read() {
    // Positive control: every test above cross-checks against the embedded
    // contract, so a failed lookup returning JSON null would make them pass
    // vacuously.
    assert!(contract()["defs"]["encryptedImageEmbed"].is_object());
    assert!(property("encryptedImageEmbed", "mimeType")["enum"].is_array());
    assert!(
        property("encryptedImageEmbed", "nosuchfield").is_null(),
        "a missing field must read as null, which is what the controls guard against"
    );
}
