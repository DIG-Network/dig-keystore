//! OS-native credential-store backend (skeleton — see #1024 Phase 1).
//!
//! Implementation follows in this branch; this stub establishes the module,
//! the `os-keychain` feature gate, and the public type so a draft PR can be
//! opened early (superproject §1.8 push-early).

/// The OS-native credential-store [`KeychainBackend`](crate::backend::KeychainBackend).
///
/// Real implementation lands in this PR.
pub struct OsKeychainBackend;

#[cfg(test)]
mod tests {
    /// Placeholder failing test — replaced by the real suite in this PR.
    #[test]
    fn skeleton_pending_implementation() {
        assert!(false, "OsKeychainBackend not yet implemented (#1024 Phase 1)");
    }
}
