//! Exclusivity of the mint: two concurrent `Keystore::create` calls for the same
//! backend key may not both establish one.
//!
//! Kept as its own suite rather than folded into `keystore_branches.rs` because
//! it is the only test here that needs a `FileBackend` on a real temporary
//! directory: the property under test is supplied by the operating system's
//! `create_new`, and a backend whose exclusivity is
//! [`Exclusivity::BestEffort`](dig_keystore::backend::Exclusivity::BestEffort)
//! cannot exhibit it. See `SPEC.md` §7.1 for which backends carry the guarantee.

use std::sync::{Arc, Barrier};

use dig_keystore::{
    backend::{BackendKey, FileBackend, KeychainBackend},
    scheme::BlsSigning,
    KdfParams, KeystoreError, Password,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

type Ks = dig_keystore::Keystore<BlsSigning>;

/// **Proves:** under contention, exactly ONE `Keystore::create` establishes the
/// keystore, every other racer gets the adoptable `AlreadyExists`, and the blob
/// left on disk is **the winner's** — the seed the winning caller went on to use.
///
/// **Why it matters:** `create_with_rng` guarded its mint with `exists()` then
/// `write()`, and `write` is replace-semantics. Two racers both observed an
/// absence, both sealed — an Argon2id derivation wide enough to drive a truck
/// through — and both wrote. The loser's blob landed on top of the winner's, so
/// the winner holds a public key that no longer opens anything, and the seed it
/// is using is unrecoverable. Where the blob is hardware-wrapped (`SPEC.md` §17)
/// there is no recovery at all, and `HardwareUnwrapFailed` structurally cannot
/// name its own cause (§17.5b) — so the loss is silent as well as permanent.
///
/// **Catches:** the check-then-write this replaced. Under it several racers
/// return `Ok` and the winner count assertion fails.
///
/// **The last assertion is the one that cannot be satisfied by accident.** A
/// winner count of one is also what a *serialised* schedule produces under the
/// old code; comparing the stored blob against the winner's own public key is
/// what pins agreement between what the caller believes it minted and what is
/// actually on disk. Each racer therefore mints a DISTINGUISHABLE seed — a
/// fixture where every racer sealed identical bytes could not tell the two
/// apart.
///
/// **One-directional, deliberately.** A correct implementation can never produce
/// two winners, so this cannot fail spuriously; a broken one is caught
/// probabilistically, which is the right way round for a proof of a negative.
#[test]
fn only_one_concurrent_mint_can_establish_a_keystore() {
    const RACERS: usize = 16;

    let dir = TempDir::new().unwrap();
    let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new(dir.path().to_path_buf()));
    // Create the root up front so the racers contend over the BLOB rather than
    // over `ensure_root`, which would serialise them before the interesting call
    // and quietly turn this into a sequential test.
    backend.write(&BackendKey::new("warmup"), b"x").unwrap();

    let key = BackendKey::new("account-master");
    let gate = Arc::new(Barrier::new(RACERS));

    let outcomes: Vec<Result<_, KeystoreError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..RACERS)
            .map(|i| {
                let (backend, gate, key) = (Arc::clone(&backend), Arc::clone(&gate), key.clone());
                scope.spawn(move || {
                    // A distinguishable seed per racer, so the survivor names
                    // which one won.
                    let seed = Zeroizing::new(vec![(i + 1) as u8; 32]);
                    gate.wait();
                    Ks::create(
                        backend,
                        key,
                        Password::from("pw"),
                        Some(seed),
                        KdfParams::FAST_TEST,
                    )
                    .map(|ks| {
                        ks.cached_public_key()
                            .expect("create caches the public key")
                    })
                })
            })
            .collect();
        // `unwrap` on the join is deliberate: a panicking racer must fail this
        // test rather than be silently counted as a loser.
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut winners = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(public) => winners.push(public),
            // Every loser must get the ADOPTABLE error. A generic I/O failure
            // would be indistinguishable from a broken disk, and a caller can
            // only give up on it — `AlreadyExists` is the one a caller can act
            // on by loading what the winner established.
            Err(KeystoreError::AlreadyExists(_)) => {}
            Err(other) => panic!("a losing racer must get AlreadyExists, got {other:?}"),
        }
    }

    assert_eq!(
        winners.len(),
        1,
        "exactly one racer may establish a keystore; {} did",
        winners.len()
    );

    let stored = Ks::load(Arc::clone(&backend), key)
        .expect("the established keystore must be loadable")
        .unlock(Password::from("pw"))
        .expect("the established keystore must open with the password it was minted under");
    assert_eq!(
        stored.public_key(),
        &winners[0],
        "the blob on disk must be the winner's, not a loser's written over it"
    );
}
