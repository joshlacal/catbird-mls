//! Evidence that a value was produced by the envelope-verification layer.
//!
//! [`OuterEntryFingerprint`](crate::chat_v2::provenance::OuterEntryFingerprint)
//! is the value the reducer accepts as provenance, and the whole design rests on
//! it being unforgeable. Its constructor used to be `pub` over raw bytes, so any
//! module in the crate could mint one from `[0u8; 32]` and hand the reducer a
//! fingerprint that was never taken over anything. The documentation said the
//! constructor belonged to this layer; nothing made that true.
//!
//! This type makes it true. It is a zero-sized token with a private field, and
//! the only constructor is visible no further than `transcript` — so a caller
//! outside this module tree cannot form the argument the constructor now
//! requires, whatever it does with the bytes.
//!
//! # What this does and does not claim
//!
//! Holding a fingerprint now proves it is a real SHA-256 over a canonical
//! projection computed here. It does **not**, on its own, prove the row that
//! projection came from carried a valid signature: [`fingerprint`] is a pure
//! function over an [`EntryRow`], and an `EntryRow` can be assembled by anyone —
//! deliberately, because the golden vectors are assembled that way.
//!
//! The signature ordering is enforced separately, and by type rather than by
//! documentation: on the application path a fingerprint is reachable only
//! through [`SenderBoundApplicationEntry`], which exists only after
//! [`VerifiedApplicationEntry::verify`] and the sender-identity comparison have
//! both passed. The control path has no verified-entry type yet — control
//! verification is not built in this tree — so for control entries this token is
//! the only structural guarantee, and the ordering rule remains a convention
//! there. That gap is stated rather than papered over.
//!
//! [`fingerprint`]: super::fingerprint
//! [`EntryRow`]: super::fingerprint::EntryRow
//! [`SenderBoundApplicationEntry`]: super::entry::SenderBoundApplicationEntry
//! [`VerifiedApplicationEntry::verify`]: super::entry::VerifiedApplicationEntry::verify

/// A token proving its holder is the envelope-verification layer.
///
/// Carried by value into the constructors this layer is the only legitimate
/// caller of. It has no public constructor, so it cannot be produced outside
/// `transcript`, and it carries no data, so producing one is the entire point.
#[derive(Debug)]
pub struct EnvelopeVerification(());

impl EnvelopeVerification {
    /// Mints the token. Visible within `transcript` and nowhere else.
    ///
    /// Every call site must be a place where this layer has just computed the
    /// value it is about to construct. Passing the token along to a caller that
    /// supplied the bytes would dissolve the gate as surely as making the
    /// constructor public again.
    pub(super) fn by_this_layer() -> Self {
        Self(())
    }
}

/// Keeps the two structural gates this module's claims rest on.
///
/// Both are compiler-enforced, so these tests cannot fail while the property
/// holds — which is exactly why they are worth writing: they fail when someone
/// *removes* the property, which a compiler cannot complain about. Each carries
/// a positive control, because a gate that cannot fail is not a gate.
#[cfg(test)]
mod gate {
    use std::path::Path;

    fn source(relative: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{} must be readable: {err}", path.display()))
    }

    /// The declaration line of the named function, with its argument list.
    ///
    /// Signatures in this tree wrap, so the scan joins the declaration back
    /// together up to the closing parenthesis rather than reading one line.
    fn signature_of(text: &str, name: &str) -> String {
        let start = text
            .find(name)
            .unwrap_or_else(|| panic!("{name} must be present"));
        let end = text[start..]
            .find(" -> ")
            .unwrap_or_else(|| panic!("{name} must have a return type"));
        text[start..start + end].split_whitespace().collect()
    }

    #[test]
    fn minting_a_fingerprint_requires_this_token() {
        // The gate itself is the argument type: without a value of it, the
        // constructor cannot be called, and the only constructor for one is
        // visible no further than `transcript`.
        let provenance = source("src/chat_v2/provenance.rs");
        let signature = signature_of(&provenance, "pub fn from_verified(");
        assert!(
            signature.contains("EnvelopeVerification"),
            "the fingerprint mint must take the verification token, found: {signature}"
        );

        // The positive control: the shape this replaced, which any module in
        // the crate could call with thirty-two bytes of its choosing.
        let ungated = "pub fn from_verified(fingerprint: [u8; 32]) -> Self";
        assert!(
            !signature_of(ungated, "pub fn from_verified(").contains("EnvelopeVerification"),
            "the scan must be able to tell an ungated mint from a gated one"
        );
    }

    #[test]
    fn the_test_only_mint_is_absent_from_a_release_build() {
        // The same structural rule the reference store lives under: a symbol
        // that does not exist cannot be reached by an editor's import
        // completion, and documentation can.
        let provenance = source("src/chat_v2/provenance.rs");
        let lines: Vec<&str> = provenance.lines().collect();
        let index = lines
            .iter()
            .position(|line| line.trim().starts_with("pub fn for_tests("))
            .expect("the test-only mint must be present");
        let attribute = lines[..index]
            .iter()
            .rev()
            .find(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with("///")
            })
            .expect("the test-only mint must carry an attribute above it");
        assert_eq!(
            attribute.trim(),
            format!("#[{}(test)]", "cfg"),
            "the arbitrary-bytes mint must not exist in a release build"
        );
    }

    #[test]
    fn the_token_cannot_be_minted_outside_this_module_tree() {
        // A `pub fn` returning one, or a public field, would hand the mint to
        // the whole crate again by another route.
        let witness = source("src/chat_v2/transcript/witness.rs");
        let declaration = ["pub struct EnvelopeVerification", "(());"].concat();
        assert!(
            witness.contains(&declaration),
            "the token must carry a private unit field"
        );
        for line in witness.lines() {
            let trimmed = line.trim();
            assert!(
                !trimmed.starts_with("pub fn "),
                "the token must expose no public constructor, found: {trimmed}"
            );
        }
    }

    #[test]
    fn an_application_fingerprint_hangs_off_the_sender_bound_type_alone() {
        // F5's half of the same rule. `verify()` no longer yields anything that
        // can produce provenance; only `bind_sender` does. Stated here because
        // moving the accessor back would compile perfectly.
        let entry = source("src/chat_v2/transcript/entry.rs");
        let accessor = "pub fn fingerprint(&self) -> &FingerprintProducts";
        assert_eq!(
            entry.matches(accessor).count(),
            1,
            "exactly one type may expose an application row's fingerprint"
        );

        let bound_impl = entry
            .find("impl SenderBoundApplicationEntry")
            .expect("the sender-bound type must have an impl block");
        let accessor_at = entry.find(accessor).expect("the accessor must be present");
        assert!(
            accessor_at > bound_impl,
            "the fingerprint accessor must live on the sender-bound type"
        );
    }
}
