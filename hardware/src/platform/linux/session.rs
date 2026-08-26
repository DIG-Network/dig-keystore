//! The conversation with the TPM device: opening it, establishing the wrapping
//! key, and running commands over it.
//!
//! # Why this is a file of its own
//!
//! Everything here needs a device that answers like a TPM, and **this loop has
//! no TPM-bearing host**. Nothing in this module can be exercised beyond its
//! refusal arms without one, and the only way to change that would be a stand-in
//! device that answered `CreatePrimary` convincingly — which would make every
//! test below report a wrap/unwrap capability nobody has observed on silicon.
//! That is the one thing this crate must not do.
//!
//! So the unmeasurable half is separated from the half that runs everywhere. Its
//! sibling [`super`] holds the provider and the probe classification — the code
//! that executes on every machine WITHOUT a TPM, which is almost every machine —
//! and that half is tested and coverage-gated normally. This file is compiled
//! and clippied on every CI leg and its refusal arms are tested; it is excluded
//! from the coverage FLOOR, exactly as the Windows and macOS bindings already
//! are by not compiling off their platforms. See `SPEC.md` §17.5 for the
//! outstanding evidence.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::super::tpm2;

/// Device names in preference order: the resource manager first, the raw chip
/// only if the kernel offers no resource manager.
const DEVICE_NAMES: [&str; 2] = ["tpmrm0", "tpm0"];

/// The largest response the kernel resource manager will return.
const MAX_RESPONSE: usize = 4096;

/// Why this host has no usable TPM wrapping key.
///
/// The two variants are the whole classification, and they are not
/// interchangeable: one becomes a confident `Absent` and the other an
/// `Indeterminate`, which the ladder treats differently — a strict policy fails
/// closed on the second and degrades on the first. See [`super::super`] for the
/// rule that decides which is which.
#[derive(Debug, Clone)]
pub(super) enum Unavailable {
    /// The host was inspected and offers no TPM this process can use.
    NotUsable(String),
    /// The inspection itself could not complete or could not be believed.
    NotInspectable(String),
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUsable(detail) | Self::NotInspectable(detail) => f.write_str(detail),
        }
    }
}

/// An open conversation with the TPM, plus the transient key established on it.
pub(super) struct TpmSession {
    /// The device is a single duplex stream — one write, one read, per command —
    /// so concurrent callers must not interleave. The mutex is what makes the
    /// provider's `&self` wrap and unwrap sound.
    device: Mutex<File>,
    handle: u32,
}

impl TpmSession {
    /// Enumerate, open, and establish the wrapping key — or say precisely why
    /// not.
    pub(super) fn establish(
        sysfs: &Path,
        device_dir: &Path,
    ) -> std::result::Result<Self, Unavailable> {
        if !a_tpm_is_enumerated(sysfs) {
            return Err(Unavailable::NotUsable(format!(
                "the kernel enumerates no TPM under {}",
                sysfs.display()
            )));
        }

        // The key is established on the bare file, before any `TpmSession`
        // exists. `TpmSession` has a `Drop` that flushes its handle, so a
        // provisional one built with a placeholder handle could neither be moved
        // out of nor dropped without flushing a handle that was never created.
        let mut device = open_device(device_dir)?;

        let response = transact_on(&mut device, &tpm2::create_primary_command())
            .map_err(|e| Unavailable::NotInspectable(format!("the TPM did not answer: {e}")))?;
        let handle = tpm2::parse_create_primary_response(&response).map_err(|e| {
            let detail = format!("could not create a TPM wrapping key: {e}");
            // The response CODE is the discriminator, and discarding it here was
            // a defect rather than a simplification. This command authorises
            // against the owner hierarchy with an empty password, so a host whose
            // hierarchy carries an authValue, or which is in lockout, answers
            // with a refusal — an INSPECTED non-usability, which C-46 classifies
            // `Absent` so the host degrades to the software floor. Reported as
            // `Indeterminate` it dominates the ladder and refuses to construct
            // the backend under the default policy, locking the user out of
            // LOADING an existing keystore.
            if tpm2::is_confident_absence(e.rc) {
                Unavailable::NotUsable(detail)
            } else {
                Unavailable::NotInspectable(detail)
            }
        })?;

        Ok(Self {
            device: Mutex::new(device),
            handle,
        })
    }

    /// Wrap a content key to the TPM's public key.
    pub(super) fn wrap(&self, content_key: &[u8]) -> std::result::Result<Vec<u8>, tpm2::TpmError> {
        let response = self.transact(&tpm2::rsa_encrypt_command(self.handle, content_key))?;
        tpm2::parse_single_parameter_response(&response)
    }

    /// Unwrap, which uses the private half and therefore authorises.
    pub(super) fn unwrap(&self, wrapped: &[u8]) -> std::result::Result<Vec<u8>, tpm2::TpmError> {
        let response = self.transact(&tpm2::rsa_decrypt_command(self.handle, wrapped))?;
        tpm2::parse_single_parameter_response(&response)
    }

    /// Attempt a real export and report whether the device refused it.
    ///
    /// **`true` means refused, which is the property being bought.** Two
    /// independent things must hold, because either alone is weaker than it
    /// looks:
    ///
    /// 1. `TPM2_ReadPublic` must show the TPM's *own* description of the key
    ///    carrying `fixedTPM | fixedParent`. The template requested those bits;
    ///    this is the device confirming what it made.
    /// 2. `TPM2_Duplicate` off the device must fail. This is the export attempt
    ///    proper, and its refusal is the observation the trait contract demands.
    ///
    /// The polarity is stated because the failure direction matters: an error
    /// from the TPM for any reason reads as "refused", which is the conservative
    /// direction — the worst outcome is a hardware-capable host reporting a
    /// `NonExportable` it genuinely earned via a refusal it did not fully
    /// understand, never a soft key reported as hard.
    pub(super) fn export_is_refused(&self) -> bool {
        let reports_fixed = self
            .transact(&tpm2::read_public_command(self.handle))
            .ok()
            .and_then(|response| tpm2::parse_read_public_attributes(&response).ok())
            .is_some_and(tpm2::attributes_are_fixed_to_this_tpm);

        // A refused command still comes back as a well-delivered response
        // carrying a non-zero responseCode, so the refusal is only visible once
        // the response is PARSED. Treating the transport's Ok as success here
        // would have made this claim vacuous in the dangerous direction: every
        // host reporting NonExportable, including one whose TPM had cheerfully
        // duplicated the key.
        let duplicate_refused = match self.transact(&tpm2::duplicate_command(self.handle)) {
            Ok(response) => tpm2::check_response(&response).is_err(),
            // Could not even ask. Conservative, per the polarity above.
            Err(_) => true,
        };

        reports_fixed && duplicate_refused
    }

    /// Send one command and read its response.
    fn transact(&self, command: &[u8]) -> std::result::Result<Vec<u8>, tpm2::TpmError> {
        let mut device = self.device.lock().map_err(|_| tpm2::TpmError {
            detail: "the TPM device lock was poisoned by a panicking caller".to_owned(),
            rc: None,
        })?;
        transact_on(&mut device, command)
    }
}

impl Drop for TpmSession {
    fn drop(&mut self) {
        // Release the transient object so the TPM's small object memory is not
        // held for the life of the process. Errors are ignored: a failed flush
        // during teardown has no remedy, the kernel resource manager reclaims
        // the handle when the file closes, and panicking in a destructor is
        // strictly worse. Nothing secret is held here — the private key never
        // left the TPM.
        if let Ok(mut device) = self.device.lock() {
            let _ = transact_on(&mut device, &tpm2::flush_context_command(self.handle));
        }
    }
}

/// One command, one response, on an already-open device.
///
/// Free rather than a method so that `Drop` can use it while the mutex guard is
/// held, without re-entering the lock.
pub(super) fn transact_on(
    device: &mut File,
    command: &[u8],
) -> std::result::Result<Vec<u8>, tpm2::TpmError> {
    device.write_all(command).map_err(|e| tpm2::TpmError {
        detail: format!("could not send a command to the TPM: {e}"),
        rc: None,
    })?;
    let mut buf = vec![0u8; MAX_RESPONSE];
    // A TPM character device returns a whole response in a single read; a short
    // read is a malformed response, and the codec's size check catches it.
    let read = device.read(&mut buf).map_err(|e| tpm2::TpmError {
        detail: format!("could not read the TPM's response: {e}"),
        rc: None,
    })?;
    buf.truncate(read);
    Ok(buf)
}

/// Whether the kernel has enumerated at least one TPM chip.
///
/// This is the **inspection** the confident-absence claim rests on: an empty or
/// missing `/sys/class/tpm` is the kernel reporting that it found no TPM it can
/// drive, which is a fact about this host rather than a failure to look.
fn a_tpm_is_enumerated(sysfs: &Path) -> bool {
    std::fs::read_dir(sysfs).is_ok_and(|mut entries| entries.next().is_some())
}

/// Open the TPM character device, preferring the kernel resource manager.
fn open_device(device_dir: &Path) -> std::result::Result<File, Unavailable> {
    let mut last: Option<(PathBuf, std::io::Error)> = None;
    for name in DEVICE_NAMES {
        let path = device_dir.join(name);
        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => return Ok(file),
            Err(e) => last = Some((path, e)),
        }
    }
    // A device that cannot be opened — absent, or owned by a group this process
    // is not in, which is the ordinary case for a non-root process on a host
    // without a `tss` group membership — is a TPM this process cannot use. That
    // is a fact established by looking, so it degrades rather than failing
    // closed; the alternative would make an unprivileged process unable to open
    // its keystore at all on every such host.
    Err(Unavailable::NotUsable(match last {
        Some((path, e)) => format!("no usable TPM device: {} ({e})", path.display()),
        None => "no TPM device names are configured".to_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// **Proves:** the transport reports a device that cannot be written to as a
    /// failure to converse, rather than proceeding as if it had.
    ///
    /// **Why it matters:** `transact_on` is the only code between the codec and the
    /// kernel. A write error swallowed here becomes a read of a stale or empty
    /// buffer, which the codec would then reject for the wrong reason — and the
    /// operator would be told the TPM sent a malformed response when in fact
    /// nothing was ever sent.
    ///
    /// **Vehicle:** a read-only handle to a real file. The write fails at the OS
    /// level, which is the same failure a device node returns when the process may
    /// not command it.
    #[test]
    fn a_device_that_cannot_be_written_to_is_reported_as_a_transport_failure() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tpmrm0");
        std::fs::write(&path, b"").unwrap();

        let mut read_only = File::open(&path).unwrap();
        let err = transact_on(&mut read_only, &tpm2::create_primary_command())
            .expect_err("a device that refuses the write cannot have answered");
        assert_eq!(
            err.rc, None,
            "a transport failure is not a TPM response code"
        );
        assert!(
            err.to_string().contains("could not send a command"),
            "the operator must be told the command never left: {err}"
        );
    }
}
