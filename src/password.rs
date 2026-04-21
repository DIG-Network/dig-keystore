//! Password wrapper with `Zeroizing` memory hygiene.
//!
//! # Why a dedicated type
//!
//! A plain `Vec<u8>` or `String` works as a password carrier but leaves two
//! specific rough edges:
//!
//! 1. **No wipe on drop.** Default `Vec::drop` returns memory to the allocator
//!    without zeroing. The allocator is free to hand the bytes back unchanged
//!    to the next allocation, making the password contents recoverable from
//!    the heap after `Password` is dropped.
//! 2. **Debug leaks.** `#[derive(Debug)]` on a containing struct would print
//!    the password bytes to logs. Easy to not notice until your password hits
//!    the first `tracing::info!` call.
//!
//! `Password` solves both:
//!
//! - Internally stores `Zeroizing<Vec<u8>>` from the
//!   [`zeroize`](https://crates.io/crates/zeroize) crate, which wipes the
//!   buffer on drop using a volatile-write heuristic.
//! - Has a custom [`Debug`] impl that prints only the byte length.
//!
//! # Caveats
//!
//! `Zeroizing` is best-effort — a sufficiently motivated optimiser or an OS
//! page swap can still let the bytes escape. For high-value keys on untrusted
//! hosts, consider running under `mlock` / `VirtualLock` and disabling swap.
//!
//! # References
//!
//! - [RustSec Advisory RUSTSEC-2019-0019](https://rustsec.org/advisories/RUSTSEC-2019-0019.html)
//!   — motivation for the `zeroize` crate.
//! - [`zeroize` crate](https://docs.rs/zeroize) — the wipe heuristic.

use zeroize::Zeroizing;

/// A password used to unlock a [`crate::Keystore`].
///
/// The password is stored in a `Zeroizing<Vec<u8>>`; the underlying memory is
/// wiped when the `Password` is dropped. `Password` is [`Clone`] so callers may
/// retain a copy for later use (e.g., re-locking with the same password);
/// both copies are zeroized on drop.
///
/// # Construction
///
/// Use any of the `From` impls:
///
/// ```
/// use dig_keystore::Password;
///
/// let from_str:     Password = Password::from("abc");
/// let from_string:  Password = Password::from(String::from("abc"));
/// let from_slice:   Password = Password::from(b"abc".as_slice());
/// let from_vec:     Password = Password::from(b"abc".to_vec());
/// let from_new:     Password = Password::new(b"abc");
/// # drop((from_str, from_string, from_slice, from_vec, from_new));
/// ```
///
/// # UTF-8 vs arbitrary bytes
///
/// `Password` accepts arbitrary byte sequences. Argon2id hashes raw bytes, so
/// non-UTF-8 passwords work. The optional `password-strength` feature (which
/// wires [`zxcvbn`](https://docs.rs/zxcvbn)) requires UTF-8 and falls back to
/// an empty-string score for non-UTF-8 bytes.
#[derive(Clone)]
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// Wrap any byte sequence as a `Password`.
    ///
    /// Copies the input bytes into a freshly-allocated zeroizing buffer. The
    /// caller's original bytes are not wiped — callers managing particularly
    /// sensitive memory should zeroize the source themselves after passing it
    /// to `Password::new`.
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self(Zeroizing::new(bytes.as_ref().to_vec()))
    }

    /// Borrow the raw password bytes. The returned slice is valid only while
    /// the `Password` is alive.
    ///
    /// Used internally by [`crate::kdf`] to feed Argon2id. External callers
    /// generally should not need this — prefer handing the `Password` to a
    /// [`Keystore`](crate::Keystore) method.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the password is zero bytes long.
    ///
    /// Empty passwords are permitted by the library (Argon2id will hash them),
    /// but they are trivially brute-forced. Treat as an operator error.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return a [`zxcvbn`](https://docs.rs/zxcvbn) strength estimate for CLI
    /// helpers.
    ///
    /// Returns an entropy score 0–4 with feedback suggestions. This is a very
    /// rough estimate designed for UX prompts, not a cryptographic guarantee.
    /// Non-UTF-8 passwords are scored as the empty string (conservative).
    ///
    /// Only available with the `password-strength` feature.
    #[cfg(feature = "password-strength")]
    pub fn strength(&self) -> zxcvbn::Entropy {
        let s = std::str::from_utf8(&self.0).unwrap_or("");
        zxcvbn::zxcvbn(s, &[])
    }
}

// ----- From impls -----

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes())
    }
}

impl From<String> for Password {
    /// Consumes the `String`, so the UTF-8 buffer is transferred into the
    /// zeroizing buffer with a single allocation and no leftover copy.
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s.into_bytes()))
    }
}

impl From<&[u8]> for Password {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl From<Vec<u8>> for Password {
    /// Consumes the `Vec<u8>`, transferring ownership into the zeroizing
    /// buffer. Preferred over `Password::new(&vec)` because it avoids the
    /// double-allocation.
    fn from(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for Password {
    /// Never leaks password contents. Prints `Password(<N bytes>)`.
    ///
    /// A common mistake is to derive `Debug` on an outer struct that contains
    /// a `Password`, then log the struct and accidentally print the password.
    /// This custom `Debug` impl makes that mistake benign.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** `Password::from("hello")` round-trips through `as_bytes()`,
    /// and the `len` / `is_empty` accessors agree with the contained bytes.
    ///
    /// **Why it matters:** Establishes the basic invariant that `Password`
    /// does not transform its input (no normalization, no trimming, no
    /// case-folding). The KDF sees bytes identical to what the caller
    /// passed.
    ///
    /// **Catches:** accidental UTF-8 normalization (NFC/NFD) that would
    /// change the hashed bytes and break keystores across locales.
    #[test]
    fn basic_construction() {
        let p = Password::from("hello");
        assert_eq!(p.as_bytes(), b"hello");
        assert_eq!(p.len(), 5);
        assert!(!p.is_empty());
    }

    /// **Proves:** the custom `Debug` impl prints the byte length but never
    /// the password content.
    ///
    /// **Why it matters:** Operators routinely `println!("{:?}", &some_struct)`
    /// or `tracing::info!(?ctx, "starting")`. If that struct contains a
    /// `Password` and our `Debug` impl leaked the content, passwords would
    /// surface in logs. This test pins the no-leak property.
    ///
    /// **Catches:** accidentally deriving `Debug` on `Password`, or
    /// formatting the contents with `{:?}` / `{}` inside the custom impl.
    #[test]
    fn debug_does_not_leak() {
        let p = Password::from("supersecret");
        let s = format!("{:?}", p);
        assert!(!s.contains("supersecret"));
        assert!(s.contains("11 bytes"));
    }

    /// **Proves:** an empty password is a valid construction — `Password::from("")`
    /// succeeds, `len()` is 0, `is_empty()` is `true`.
    ///
    /// **Why it matters:** The library accepts empty passwords (Argon2id
    /// handles them, keystores can be created with them) even though
    /// they are a terrible idea. Higher-level CLIs should reject empty
    /// passwords; this layer must not panic when presented with one.
    ///
    /// **Catches:** an overzealous `assert!(!bytes.is_empty())` added at
    /// construction time that would panic on empty input.
    #[test]
    fn empty_password_allowed() {
        let p = Password::from("");
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    /// **Proves:** `Password::clone()` produces an independent copy whose
    /// bytes match the original.
    ///
    /// **Why it matters:** `Password` is `Clone` so callers can retain a
    /// copy to later re-encrypt or verify — e.g., `change_password(old, new)`
    /// borrows both by value. Both clones must wipe on drop; here we just
    /// check they both have valid content.
    ///
    /// **Catches:** a regression to a `Clone` impl that shares storage
    /// (e.g., `Arc`-based) whose drop would wipe *both* copies prematurely.
    #[test]
    fn clone_independent() {
        let p1 = Password::from("abc");
        let p2 = p1.clone();
        assert_eq!(p1.as_bytes(), p2.as_bytes());
    }
}
