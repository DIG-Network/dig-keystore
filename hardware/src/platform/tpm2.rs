//! The TPM 2.0 command codec: bytes in, bytes out, and no I/O.
//!
//! # Why this is a module of its own, compiled on every target
//!
//! Everything here is a pure function over byte buffers, so it is compiled and
//! **tested on every host** — including Windows, which has no Linux TPM and
//! never will. The transport and the provider that use it are
//! `cfg(target_os = "linux")`; a codec gated the same way would be
//! unfalsifiable everywhere except one CI leg, and the marshalling is precisely
//! the part where a wrong byte is invisible until it reaches real silicon.
//!
//! # Why the commands are marshalled here rather than taken from a crate
//!
//! Two candidates were evaluated (Appendix B: reuse before building).
//!
//! - [`tss-esapi`](https://crates.io/crates/tss-esapi) is the established
//!   binding, and it is FFI over the C `tpm2-tss` libraries. Adopting it would
//!   put `libtss2-esys` and a `bindgen` toolchain on the build of every Linux
//!   consumer of this crate — including `dig-node`, which ships as a binary to
//!   people who did not ask to install a TPM stack.
//! - [`tpm2_call`](https://crates.io/crates/tpm2_call) is pure Rust, but it
//!   supplies the command/algorithm *constants* and `GetCapability`; it does not
//!   marshal `CreatePrimary` or the RSA operations, which is the work here.
//!
//! So the commands this crate needs are marshalled directly, against *TPM 2.0
//! Library Specification, Part 3*, and spoken to the kernel resource manager.
//! That is a rival implementation of a narrow slice of a TSS, and it is recorded
//! as one rather than presented as reuse.
//!
//! # The shape of a TPM command
//!
//! Everything is big-endian. A command is a 10-byte header — `tag`, total
//! `size`, `commandCode` — followed by handles, then an optional authorisation
//! area, then parameters. A response is `tag`, total `size`, `responseCode`,
//! then handles, then — only when the tag says sessions — a `parameterSize`,
//! then parameters. A `TPM2B_X` is a `u16` length followed by that many bytes.

/// Command/response tag: no authorisation sessions present.
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// Command/response tag: an authorisation area is present.
const TPM_ST_SESSIONS: u16 = 0x8002;

/// `TPM_RH_OWNER` — the storage hierarchy the wrapping key is created under.
const TPM_RH_OWNER: u32 = 0x4000_0001;
/// `TPM_RH_NULL` — the "no new parent" argument to `TPM2_Duplicate`.
const TPM_RH_NULL: u32 = 0x4000_0007;
/// `TPM_RS_PW` — the password "session": the standard way to present an empty
/// authorisation without negotiating a real session.
const TPM_RS_PW: u32 = 0x4000_0009;

const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM_CC_DUPLICATE: u32 = 0x0000_014B;
const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
const TPM_CC_RSA_ENCRYPT: u32 = 0x0000_0174;
const TPM_CC_RSA_DECRYPT: u32 = 0x0000_0175;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_OAEP: u16 = 0x0017;

/// RSA modulus size for the wrapping key. 2048 is the size every TPM 2.0
/// implements; a larger key that fails to create is worse than a smaller one
/// that does, and only 32 bytes are ever wrapped.
const WRAP_KEY_BITS: u16 = 2048;

const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const USER_WITH_AUTH: u32 = 1 << 6;
const DECRYPT: u32 = 1 << 17;

/// `objectAttributes` for the wrapping key.
///
/// `fixedTPM | fixedParent` is the whole point: together they say the private
/// half may never be duplicated off this device, which is what makes a sealed
/// keystore refuse to open on another machine. `sensitiveDataOrigin` says the
/// TPM generates the key rather than accepting one from us — a key we supplied
/// would be a key we had. `userWithAuth` permits the empty password
/// authorisation used below, and `decrypt` permits `TPM2_RSA_Decrypt`.
///
/// Deliberately NOT set: `restricted`, which would confine the key to
/// TPM-internal structures and refuse an arbitrary payload, and `sign`.
pub const WRAP_KEY_ATTRS: u32 =
    FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | DECRYPT;

/// A TPM command that did not produce the answer it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmError {
    /// Non-secret description, safe to log.
    pub detail: String,
    /// The TPM response code, when the failure was the TPM's own answer rather
    /// than a malformed or truncated buffer.
    ///
    /// Carried separately from `detail` for the same reason `CngUnavailable`
    /// carries its HRESULT: whether a failure is a confident answer or an
    /// inability to answer depends on the code, and that decision must not
    /// require parsing a formatted string.
    pub rc: Option<u32>,
}

impl TpmError {
    fn malformed(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            rc: None,
        }
    }
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.rc {
            Some(rc) => write!(f, "{} (TPM_RC 0x{rc:08X})", self.detail),
            None => f.write_str(&self.detail),
        }
    }
}

/// Encoded size of a password authorisation session, excluding its own length
/// prefix: handle (4) + nonce (2) + attributes (1) + HMAC (2).
const PASSWORD_AUTH_SIZE: u32 = 9;

/// Incremental big-endian encoder. Every TPM integer is big-endian, so the byte
/// order is decided in one place rather than at forty call sites.
#[derive(Default)]
struct Buf(Vec<u8>);

impl Buf {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A `TPM2B_X`: a `u16` length followed by the bytes.
    fn tpm2b(&mut self, bytes: &[u8]) -> &mut Self {
        self.u16(bytes.len() as u16);
        self.0.extend_from_slice(bytes);
        self
    }

    /// The password authorisation area: `TPM_RS_PW`, an empty nonce,
    /// `continueSession`, and an empty HMAC — preceded by its own size.
    fn password_auth(&mut self) -> &mut Self {
        self.u32(PASSWORD_AUTH_SIZE);
        self.u32(TPM_RS_PW).tpm2b(&[]).u8(0x01).tpm2b(&[])
    }
}

/// Prepend the 10-byte header, filling in the total size the TPM requires.
///
/// The size is computed rather than passed in: a command whose declared length
/// disagrees with its actual length is rejected by the TPM with an error that
/// says nothing about which field was wrong.
fn frame(tag: u16, command_code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Buf::default();
    out.u16(tag).u32((body.len() + 10) as u32).u32(command_code);
    out.0.extend_from_slice(body);
    out.0
}

/// `TPMT_PUBLIC` for the RSA wrapping key: the template the TPM derives the
/// primary key from.
///
/// The template is **load-bearing for identity**, not merely for policy. A
/// primary key is derived deterministically from the hierarchy seed and this
/// template, so the same template yields the same key on every boot without
/// persisting anything — and any change to these bytes yields a DIFFERENT key,
/// which would leave every previously sealed blob unopenable (§5.1). Treat this
/// function as frozen: a new algorithm or policy needs a new, separately
/// versioned template, never an edit to this one.
fn wrap_key_template() -> Vec<u8> {
    let mut t = Buf::default();
    t.u16(TPM_ALG_RSA)
        .u16(TPM_ALG_SHA256)
        .u32(WRAP_KEY_ATTRS)
        // authPolicy: empty, so the key is used with the password authorisation
        // below rather than a policy session.
        .tpm2b(&[])
        // TPMS_RSA_PARMS.
        .u16(TPM_ALG_NULL) // symmetric: none — this key is not a parent.
        .u16(TPM_ALG_OAEP) // scheme
        .u16(TPM_ALG_SHA256) // OAEP hash
        .u16(WRAP_KEY_BITS)
        .u32(0) // exponent: 0 selects the default, 65537.
        // unique: empty, so the TPM derives it.
        .tpm2b(&[]);
    t.0
}

/// `TPM2_CreatePrimary` in the owner hierarchy, using [`wrap_key_template`].
pub fn create_primary_command() -> Vec<u8> {
    let template = wrap_key_template();
    let mut b = Buf::default();
    b.u32(TPM_RH_OWNER).password_auth();
    // inSensitive: a TPM2B_SENSITIVE_CREATE wrapping an empty userAuth and an
    // empty data field. The four inner bytes are those two empty TPM2Bs.
    b.u16(4).tpm2b(&[]).tpm2b(&[]);
    b.tpm2b(&template);
    b.tpm2b(&[]); // outsideInfo
    b.u32(0); // creationPCR: no selections
    frame(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY, &b.0)
}

/// `TPM2_RSA_Encrypt` — wrap a content key to the TPM's public key.
///
/// Carries no authorisation: encrypting to a public key does not use the private
/// half, and the TPM does not ask for one.
pub fn rsa_encrypt_command(handle: u32, message: &[u8]) -> Vec<u8> {
    let mut b = Buf::default();
    b.u32(handle)
        .tpm2b(message)
        // inScheme NULL: use the scheme baked into the key's template (OAEP with
        // SHA-256). Naming it again here would be a second place for it to drift.
        .u16(TPM_ALG_NULL)
        .tpm2b(&[]); // label
    frame(TPM_ST_NO_SESSIONS, TPM_CC_RSA_ENCRYPT, &b.0)
}

/// `TPM2_RSA_Decrypt` — unwrap, which uses the private half and therefore
/// carries the password authorisation.
pub fn rsa_decrypt_command(handle: u32, cipher_text: &[u8]) -> Vec<u8> {
    let mut b = Buf::default();
    b.u32(handle)
        .password_auth()
        .tpm2b(cipher_text)
        .u16(TPM_ALG_NULL)
        .tpm2b(&[]); // label
    frame(TPM_ST_SESSIONS, TPM_CC_RSA_DECRYPT, &b.0)
}

/// `TPM2_ReadPublic` — ask the TPM what it actually made.
pub fn read_public_command(handle: u32) -> Vec<u8> {
    frame(
        TPM_ST_NO_SESSIONS,
        TPM_CC_READ_PUBLIC,
        &handle.to_be_bytes(),
    )
}

/// `TPM2_Duplicate` with a null new parent — a real attempt to take the private
/// key off this device.
///
/// This is the export whose **refusal** entitles the provider to claim
/// `NonExportable`. `newParentHandle` takes no authorisation of its own, so the
/// single password session covers `objectHandle` alone.
pub fn duplicate_command(handle: u32) -> Vec<u8> {
    let mut b = Buf::default();
    b.u32(handle)
        .u32(TPM_RH_NULL)
        .password_auth()
        .tpm2b(&[]) // encryptionKeyIn: none
        .u16(TPM_ALG_NULL); // symmetricAlg: none
    frame(TPM_ST_SESSIONS, TPM_CC_DUPLICATE, &b.0)
}

/// `TPM2_FlushContext` — release a transient object handle.
///
/// The handle travels in the parameter area rather than the handle area, which
/// is why this is framed as an unsessioned command with a bare `u32` body.
pub fn flush_context_command(handle: u32) -> Vec<u8> {
    frame(
        TPM_ST_NO_SESSIONS,
        TPM_CC_FLUSH_CONTEXT,
        &handle.to_be_bytes(),
    )
}

/// A validated response: the header has been checked and `body` is everything
/// after it.
struct Response<'a> {
    tag: u16,
    body: &'a [u8],
}

/// Validate the response header and return the body.
///
/// Three things are checked before any parameter is read, because each of them
/// makes every later offset meaningless: the buffer must hold a header, the
/// TPM's declared size must match the bytes actually returned, and the response
/// code must be success.
fn parse_header(bytes: &[u8]) -> Result<Response<'_>, TpmError> {
    if bytes.len() < 10 {
        return Err(TpmError::malformed(format!(
            "TPM response is {} bytes, shorter than a 10-byte header",
            bytes.len()
        )));
    }
    let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
    let size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    let rc = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    if size != bytes.len() {
        return Err(TpmError::malformed(format!(
            "TPM declared a {size}-byte response but returned {} bytes",
            bytes.len()
        )));
    }
    if rc != 0 {
        return Err(TpmError {
            detail: "the TPM refused the command".to_owned(),
            rc: Some(rc),
        });
    }
    Ok(Response {
        tag,
        body: &bytes[10..],
    })
}

/// Read a `TPM2B` at `offset`, refusing a length that runs past the buffer.
///
/// The length is the TPM's claim about its own response, so it is bounds-checked
/// rather than trusted: an unchecked read is a panic at best, and a slice of
/// whatever followed at worst.
fn read_tpm2b(body: &[u8], offset: usize) -> Result<&[u8], TpmError> {
    let Some(header) = body.get(offset..offset + 2) else {
        return Err(TpmError::malformed(
            "TPM response ended before a length prefix",
        ));
    };
    let len = u16::from_be_bytes([header[0], header[1]]) as usize;
    body.get(offset + 2..offset + 2 + len).ok_or_else(|| {
        TpmError::malformed(format!(
            "TPM declared a {len}-byte field with only {} bytes left",
            body.len().saturating_sub(offset + 2)
        ))
    })
}

/// Whether the TPM accepted a command, discarding any parameters it returned.
///
/// The caller that matters is the export-refusal probe: a refused command is
/// still a well-delivered response carrying a non-zero `responseCode`, so a
/// caller that only checked the transport would read every refusal as a success.
pub fn check_response(bytes: &[u8]) -> Result<(), TpmError> {
    parse_header(bytes).map(|_| ())
}

/// The transient object handle `TPM2_CreatePrimary` established.
///
/// The handle is the first thing after the header, which is why nothing else in
/// that response needs parsing.
pub fn parse_create_primary_response(bytes: &[u8]) -> Result<u32, TpmError> {
    let response = parse_header(bytes)?;
    let handle = response
        .body
        .get(..4)
        .ok_or_else(|| TpmError::malformed("CreatePrimary returned no object handle"))?;
    Ok(u32::from_be_bytes([
        handle[0], handle[1], handle[2], handle[3],
    ]))
}

/// The single `TPM2B` parameter returned by `RSA_Encrypt` / `RSA_Decrypt`.
///
/// The offset depends on the tag: a sessioned response carries a `parameterSize`
/// before its parameters and an unsessioned one does not. Deriving that from the
/// tag the TPM actually **returned** — rather than from the tag we sent — is
/// what lets wrap and unwrap share one parser.
pub fn parse_single_parameter_response(bytes: &[u8]) -> Result<Vec<u8>, TpmError> {
    let response = parse_header(bytes)?;
    let offset = if response.tag == TPM_ST_SESSIONS {
        4
    } else {
        0
    };
    read_tpm2b(response.body, offset).map(<[u8]>::to_vec)
}

/// The `objectAttributes` the TPM reports for an existing key.
///
/// Read back rather than assumed: the template above *requests*
/// `fixedTPM | fixedParent`, and this is the TPM's own statement about what it
/// made. Requesting a property and observing it are different claims, and only
/// the second is evidence.
pub fn parse_read_public_attributes(bytes: &[u8]) -> Result<u32, TpmError> {
    let response = parse_header(bytes)?;
    // outPublic is a TPM2B wrapping a TPMT_PUBLIC; the attributes are the u32
    // after `type` and `nameAlg`.
    let public = read_tpm2b(response.body, 0)?;
    let attrs = public
        .get(4..8)
        .ok_or_else(|| TpmError::malformed("ReadPublic returned no objectAttributes"))?;
    Ok(u32::from_be_bytes([attrs[0], attrs[1], attrs[2], attrs[3]]))
}

/// Whether the TPM's own report of a key says its private half cannot leave the
/// device.
pub fn attributes_are_fixed_to_this_tpm(attrs: u32) -> bool {
    attrs & FIXED_TPM != 0 && attrs & FIXED_PARENT != 0
}

#[cfg(test)]
mod tests;
