//! Turning bytes a trusted component handed back into a content key — or
//! refusing to.
//!
//! # Why this is shared rather than repeated
//!
//! All three providers end their unwrap the same way: the platform returns some
//! bytes, and exactly one question decides what happens next — are these
//! `CONTENT_KEY_LEN` bytes, or not? A wrong-length recovery is a **refusal**, not
//! a short key; reporting it as a key hands `dig-keystore` material it would then
//! use as an AES key.
//!
//! That is one security decision, so it has one implementation. Three copies of
//! it is three chances for one to drift into a truncation, a pad, or a
//! `min(len, 32)` — and the copy that drifts is the one nobody re-reads.

use zeroize::Zeroize;

use dig_keystore::hardware::{ContentKey, CONTENT_KEY_LEN};

/// Interpret bytes recovered from a trusted component as a content key.
///
/// # Errors
///
/// A one-line description of the length mismatch, for the caller to wrap in its
/// own platform-specific `HardwareUnwrapFailed`. The message names the lengths
/// and nothing else — the bytes themselves are key material and are never
/// rendered.
pub(super) fn from_recovered(recovered: &[u8], component: &str) -> Result<ContentKey, String> {
    let mut bytes: [u8; CONTENT_KEY_LEN] = recovered.try_into().map_err(|_| {
        format!(
            "{component} returned {} bytes, expected {CONTENT_KEY_LEN}",
            recovered.len()
        )
    })?;

    // `ContentKey` owns a copy from here on; this stack copy is wiped rather than
    // left for the next frame to reuse.
    let content_key = ContentKey::new(bytes);
    bytes.zeroize();
    Ok(content_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** exactly `CONTENT_KEY_LEN` bytes become a content key, and any
    /// other length is refused.
    ///
    /// **Why it matters:** this is the last check between a trusted component's
    /// answer and an AES key. The nearest wrong implementations all *succeed*
    /// where this must fail — a truncation to 32, a zero-pad up to 32, a
    /// `copy_from_slice` of whatever arrived — and each of them yields a key the
    /// caller would go on to use.
    ///
    /// **Both sides of the bound are exercised**, one under and one over, because
    /// a truncating implementation passes an under-length test and a padding one
    /// passes an over-length test. Neither alone distinguishes them.
    #[test]
    fn only_an_exactly_sized_recovery_becomes_a_content_key() {
        let exact = vec![9u8; CONTENT_KEY_LEN];
        let key = from_recovered(&exact, "the TPM").expect("an exact recovery is a content key");
        assert_eq!(key.as_slice(), exact.as_slice());

        for wrong in [CONTENT_KEY_LEN - 1, CONTENT_KEY_LEN + 1, 0] {
            let err = from_recovered(&vec![9u8; wrong], "the TPM")
                .expect_err("a {wrong}-byte recovery is a refusal, not a key");
            assert!(
                err.contains(&wrong.to_string()) && err.contains(&CONTENT_KEY_LEN.to_string()),
                "the refusal must name both lengths: {err}"
            );
        }
    }

    /// **Proves:** the refusal names the component that produced it and never
    /// renders the bytes.
    ///
    /// **Why it matters:** this message reaches a log. The bytes are a failed
    /// unwrap of key material, and a length mismatch is not a reason to print
    /// them.
    #[test]
    fn the_refusal_names_the_component_and_not_the_bytes() {
        let err = from_recovered(&[0xAB, 0xCD], "the Secure Enclave").unwrap_err();
        assert!(err.contains("the Secure Enclave"), "got {err}");
        assert!(
            !err.contains("abcd") && !err.contains("AB"),
            "recovered bytes must never be rendered: {err}"
        );
    }
}
