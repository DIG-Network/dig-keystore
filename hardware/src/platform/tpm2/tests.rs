//! Codec tests. These run on **every** host, including Windows, which is the
//! reason the codec is not `cfg(target_os = "linux")`: a marshalling bug is
//! invisible until it reaches silicon, and this loop has no TPM-bearing host.

use super::*;

/// Decode a hex fixture written as spec fields, so the expectation reads like
/// the structure it encodes rather than like a wall of bytes.
fn hex(fields: &[&str]) -> Vec<u8> {
    let joined: String = fields.concat();
    (0..joined.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&joined[i..i + 2], 16).expect("fixture is valid hex"))
        .collect()
}

/// **Proves:** `TPM2_CreatePrimary` marshals to exactly the bytes the TPM 2.0
/// specification defines for this template.
///
/// **Why it matters:** a primary key is derived deterministically from the
/// hierarchy seed and the template, so these bytes ARE the key's identity. A
/// single wrong field does not fail loudly — it derives a *different* key, and
/// every blob sealed under the previous bytes becomes unopenable with a
/// `HardwareUnwrapFailed` that structurally cannot name its own cause
/// (`SPEC.md` §17.5b). That is the §5.1 at-rest guarantee, and it is why this is
/// pinned as a golden rather than as a set of structural assertions.
///
/// **The expectation is derived independently**, field by field from *Part 3*,
/// and not captured from this implementation's output — a golden blessed from
/// the code under test asserts only that the code is self-consistent.
///
/// **Catches:** any change to the template, the attribute set, the key size, the
/// scheme, the authorisation area, or the framing.
#[test]
fn create_primary_marshals_to_the_specified_bytes() {
    let expected = hex(&[
        // --- header ---
        "8002",     // TPM_ST_SESSIONS
        "00000041", // total size: 65
        "00000131", // TPM_CC_CreatePrimary
        // --- handles ---
        "40000001", // TPM_RH_OWNER
        // --- authorisation area ---
        "00000009", // authorizationSize
        "40000009", // TPM_RS_PW
        "0000",     // nonce: empty
        "01",       // continueSession
        "0000",     // hmac: empty
        // --- inSensitive: TPM2B_SENSITIVE_CREATE ---
        "0004", // size of the two empty TPM2Bs that follow
        "0000", // userAuth: empty
        "0000", // data: empty
        // --- inPublic: TPM2B_PUBLIC ---
        "0018",     // size of the TPMT_PUBLIC: 24
        "0001",     // type: TPM_ALG_RSA
        "000b",     // nameAlg: TPM_ALG_SHA256
        "00020072", // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|decrypt
        "0000",     // authPolicy: empty
        "0010",     // symmetric: TPM_ALG_NULL
        "0017",     // scheme: TPM_ALG_OAEP
        "000b",     // OAEP hash: TPM_ALG_SHA256
        "0800",     // keyBits: 2048
        "00000000", // exponent: default (65537)
        "0000",     // unique: empty
        // --- outsideInfo ---
        "0000", // --- creationPCR: no selections ---
        "00000000",
    ]);

    assert_eq!(
        create_primary_command(),
        expected,
        "the wrapping-key template decides which key the TPM derives; any drift \
         here orphans every blob sealed under the previous bytes"
    );
}

/// **Proves:** the attribute word requests non-exportability and nothing that
/// would stop the key wrapping a content key.
///
/// **Why it matters:** `restricted` is the trap. A restricted decryption key
/// accepts only TPM-internal structures, so setting it would make every
/// `RSA_Decrypt` of our own envelope fail on real hardware while every test
/// here still passed. `sign` would widen the key beyond what it is for.
///
/// **Catches:** a value drifting from the specified bit set in either direction
/// — a missing `fixedParent` (which would silently permit duplication) and an
/// added `restricted` (which would break unwrap only on silicon).
#[test]
fn the_attribute_word_is_the_specified_one() {
    assert_eq!(
        WRAP_KEY_ATTRS, 0x0002_0072,
        "the attribute word is part of the template, so it is part of the key's identity"
    );
    assert_eq!(WRAP_KEY_ATTRS & (1 << 16), 0, "restricted must NOT be set");
    assert_eq!(WRAP_KEY_ATTRS & (1 << 18), 0, "sign must NOT be set");
}

/// **Proves:** a key is reported as fixed to its TPM only when the TPM reports
/// **both** `fixedTPM` and `fixedParent`.
///
/// **Why it matters:** this predicate gates the `NonExportable` custody claim,
/// which is the only property hardware binding buys. Either bit alone leaves a
/// path for the private half to be duplicated to another parent or another
/// device.
///
/// **Both single-bit cases are asserted separately**, which is what
/// distinguishes `&&` from `||`: a fixture that only tried "neither bit" would
/// pass against an `||` implementation.
#[test]
fn fixed_to_this_tpm_requires_both_bits() {
    assert!(attributes_are_fixed_to_this_tpm(WRAP_KEY_ATTRS));
    assert!(
        !attributes_are_fixed_to_this_tpm(FIXED_TPM),
        "fixedTPM alone still permits duplication to another parent"
    );
    assert!(
        !attributes_are_fixed_to_this_tpm(FIXED_PARENT),
        "fixedParent alone still permits the key to leave the device"
    );
    assert!(!attributes_are_fixed_to_this_tpm(0));
}

/// **Proves:** every command this module emits declares its own true length and
/// the tag its authorisation area implies.
///
/// **Why it matters:** a TPM rejects a command whose declared size disagrees
/// with the bytes delivered, with an error naming neither the field nor the
/// command — so a framing bug presents on real hardware as an unexplained
/// refusal. And the tag must agree with the body: an unsessioned tag on a
/// command carrying an authorisation area, or the reverse, misaligns every
/// parameter after it.
///
/// **Catches:** a hand-written size, and the specific error of giving
/// `RSA_Decrypt` — which uses the private half and must authorise — the
/// unsessioned tag that `RSA_Encrypt` correctly uses.
#[test]
fn every_command_declares_its_own_length_and_the_right_tag() {
    let sessioned: bool = true;
    for (name, command, expect_sessions) in [
        ("CreatePrimary", create_primary_command(), sessioned),
        (
            "RSA_Encrypt",
            rsa_encrypt_command(0x8000_0000, &[7; 32]),
            false,
        ),
        (
            "RSA_Decrypt",
            rsa_decrypt_command(0x8000_0000, &[7; 256]),
            sessioned,
        ),
        ("ReadPublic", read_public_command(0x8000_0000), false),
        ("Duplicate", duplicate_command(0x8000_0000), sessioned),
        ("FlushContext", flush_context_command(0x8000_0000), false),
    ] {
        let declared =
            u32::from_be_bytes([command[2], command[3], command[4], command[5]]) as usize;
        assert_eq!(
            declared,
            command.len(),
            "{name} declared {declared} bytes but is {} long",
            command.len()
        );

        let tag = u16::from_be_bytes([command[0], command[1]]);
        let expected_tag = if expect_sessions {
            TPM_ST_SESSIONS
        } else {
            TPM_ST_NO_SESSIONS
        };
        assert_eq!(tag, expected_tag, "{name} carries the wrong tag");
    }
}

/// **Proves:** an authorization or hierarchy refusal is a confident absence, a
/// transient or unrecognised code is not, and a failure with no code at all is
/// not.
///
/// **Why it matters:** this predicate decides whether a Linux host DEGRADES to
/// the software floor or REFUSES to construct a keystore backend at all. Both
/// mistakes are real and they are opposites — too narrow locks a user out of
/// loading their own keystore on an ordinary owner-password host; too wide drops
/// a host with working hardware to software without saying so.
///
/// **The transient control is the discriminating one.** `TPM_RC_RETRY`
/// (`0x922`) sits one value above `TPM_RC_LOCKOUT` (`0x921`), so a fix that
/// widened by range rather than by name — or that treated any response code as
/// an answer — passes an absence-only test and fails this.
#[test]
fn only_an_authorization_or_hierarchy_refusal_is_a_confident_absence() {
    for (rc, name) in [
        (TPM_RC_HIERARCHY, "TPM_RC_HIERARCHY"),
        (TPM_RC_AUTH_FAIL, "TPM_RC_AUTH_FAIL"),
        (TPM_RC_BAD_AUTH, "TPM_RC_BAD_AUTH"),
        (TPM_RC_DISABLED, "TPM_RC_DISABLED"),
        (TPM_RC_AUTH_MISSING, "TPM_RC_AUTH_MISSING"),
        (TPM_RC_LOCKOUT, "TPM_RC_LOCKOUT"),
    ] {
        assert!(
            is_confident_absence(Some(rc)),
            "{name} is the TPM answering that this process may not use it"
        );
    }

    for (rc, name) in [
        (0x922u32, "TPM_RC_RETRY: the TPM could not answer YET"),
        (
            0x902,
            "TPM_RC_OBJECT_MEMORY: no room for a transient object",
        ),
        (0x903, "TPM_RC_SESSION_MEMORY"),
        (0x923, "TPM_RC_NV_UNAVAILABLE"),
        (0x101, "TPM_RC_FAILURE: the TPM is in a bad state"),
        (0x100, "TPM_RC_INITIALIZE: not started up"),
        (0x084, "TPM_RC_VALUE: we sent something wrong"),
        (0x000, "success is not an absence"),
    ] {
        assert!(
            !is_confident_absence(Some(rc)),
            "{name} establishes nothing about the host and must fail closed"
        );
    }

    assert!(
        !is_confident_absence(None),
        "a transport or framing failure is not the TPM answering"
    );
}

/// **Proves:** a format-one code is recognised with its positional bits set, as
/// a real device sends it — and that stripping them cannot swallow an unrelated
/// code.
///
/// **Why it matters:** a TPM reports which handle, session or parameter was at
/// fault in bits 8 to 11 of a format-one response code, so `TPM_RC_BAD_AUTH` on
/// the first handle arrives as `0x1A2`, never the bare `0x0A2`. A classifier
/// comparing raw values matches the constant in a test and **nothing on real
/// hardware** — the classification would be correct only where it is never
/// needed. This is the single most likely way for this fix to be silently
/// inert on the machines it exists for.
///
/// **The negative arm is load-bearing:** masking must not be so aggressive that
/// a format-zero code lands on a format-one constant.
#[test]
fn a_format_one_code_is_recognised_with_its_positional_bits() {
    // Handle 1, session 2, parameter 3 — the shapes a device actually emits.
    for decorated in [0x0A2u32, 0x1A2, 0x2A2, 0x3A2, 0x9A2] {
        assert!(
            is_confident_absence(Some(decorated)),
            "TPM_RC_BAD_AUTH must be recognised as 0x{decorated:03X}, the form a device sends"
        );
    }
    for decorated in [0x08E, 0x18E, 0x38E] {
        assert!(is_confident_absence(Some(decorated)), "TPM_RC_AUTH_FAIL");
    }

    // TPM_RC_VALUE is format one too, and is NOT an absence however it is
    // decorated: it means the command was wrong, not that the host is unusable.
    for decorated in [0x084u32, 0x184, 0x284] {
        assert!(
            !is_confident_absence(Some(decorated)),
            "0x{decorated:03X} is our own bad command, not a statement about the host"
        );
    }
}

/// Build a well-formed response: header with a correct size, then `body`.
fn response(tag: u16, rc: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&((body.len() + 10) as u32).to_be_bytes());
    out.extend_from_slice(&rc.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// **Proves:** the object handle is read from a `CreatePrimary` response.
#[test]
fn the_created_handle_is_read_from_the_response() {
    let body = hex(&["80000001", "0000000c", "0000"]);
    assert_eq!(
        parse_create_primary_response(&response(TPM_ST_SESSIONS, 0, &body)).unwrap(),
        0x8000_0001
    );
}

/// **Proves:** the parameter offset follows the tag the TPM **returned**, so a
/// sessioned response is not read four bytes early.
///
/// **Why it matters:** an unsessioned response has no `parameterSize`, a
/// sessioned one does, and the same parser serves wrap (unsessioned) and unwrap
/// (sessioned). Reading the wrong one does not fail loudly — the fixture below
/// is built so that a parser ignoring the offset reads the first two bytes of
/// `parameterSize` as a length of **zero** and returns an EMPTY key
/// successfully. `dig-keystore` would then be handed a zero-length "content
/// key".
///
/// **Both arms assert**, so the fix cannot be a constant `4` that breaks wrap.
#[test]
fn the_parameter_offset_follows_the_returned_tag() {
    // Sessioned: parameterSize (4 bytes, itself 0x00000004) then the TPM2B.
    let sessioned = response(TPM_ST_SESSIONS, 0, &hex(&["00000004", "0002", "aabb"]));
    assert_eq!(
        parse_single_parameter_response(&sessioned).unwrap(),
        vec![0xAA, 0xBB],
        "a parser that ignored the offset would read a zero length and succeed with nothing"
    );

    // Unsessioned: the TPM2B begins immediately.
    let unsessioned = response(TPM_ST_NO_SESSIONS, 0, &hex(&["0002", "ccdd"]));
    assert_eq!(
        parse_single_parameter_response(&unsessioned).unwrap(),
        vec![0xCC, 0xDD]
    );
}

/// **Proves:** a TPM refusal is surfaced as an error carrying its response
/// code, not decoded as if it were a result.
///
/// **Why it matters:** a non-zero `responseCode` means the parameter area is
/// absent, so every offset past the header addresses nothing. And the code is
/// the input to classifying whether the failure was a confident answer or an
/// inability to answer — it must survive as a number, not only inside a string.
#[test]
fn a_refusal_is_an_error_that_keeps_its_response_code() {
    // TPM_RC_AUTH_FAIL.
    let refused = response(TPM_ST_NO_SESSIONS, 0x0000_098E, &[]);
    let err = parse_single_parameter_response(&refused).expect_err("a refusal is not a result");
    assert_eq!(err.rc, Some(0x0000_098E));
    assert!(err.to_string().contains("098E"), "got {err}");
}

/// **Proves:** a response that is truncated, that lies about its own length, or
/// that declares a field longer than the bytes it sent is refused rather than
/// read past.
///
/// **Why it matters:** the bytes come from a device file. A length taken on
/// trust is a panic in a keystore, and a length that happens to fit is a slice
/// of adjacent memory presented as key material.
///
/// **Each case is asserted separately** — one buffer that fails all three
/// checks would leave two of them unexercised.
#[test]
fn a_malformed_response_is_refused_rather_than_read_past() {
    // Shorter than a header.
    assert!(parse_single_parameter_response(&[0x80, 0x01, 0x00]).is_err());

    // Declares 64 bytes, sends 10. The classic short read from a device file.
    let mut lying = response(TPM_ST_NO_SESSIONS, 0, &[]);
    lying[2..6].copy_from_slice(&64u32.to_be_bytes());
    let err = parse_single_parameter_response(&lying).expect_err("a size mismatch is malformed");
    assert_eq!(err.rc, None, "a framing fault is not a TPM response code");

    // Well-framed, but the TPM2B claims more bytes than remain.
    let overrun = response(TPM_ST_NO_SESSIONS, 0, &hex(&["0040", "aabb"]));
    assert!(parse_single_parameter_response(&overrun).is_err());

    // Well-framed, but there is no handle at all.
    assert!(parse_create_primary_response(&response(TPM_ST_SESSIONS, 0, &[0, 1])).is_err());
}

/// **Proves:** the attributes reported by `ReadPublic` are read from the TPM's
/// own description of the key.
///
/// **Why it matters:** this is the observation half of the custody claim. The
/// template *requests* `fixedTPM | fixedParent`; this reads back what the device
/// says it made, and the two are different claims.
#[test]
fn read_public_reports_the_tpms_own_attributes() {
    // TPM2B_PUBLIC wrapping a TPMT_PUBLIC whose attributes are our template's.
    let public = hex(&["0001", "000b", "00020072", "0000"]);
    let mut body = (public.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&public);

    let attrs = parse_read_public_attributes(&response(TPM_ST_NO_SESSIONS, 0, &body)).unwrap();
    assert_eq!(attrs, WRAP_KEY_ATTRS);
    assert!(attributes_are_fixed_to_this_tpm(attrs));

    // A device reporting an EXPORTABLE key must be readable as exactly that —
    // the predicate is only useful if it can return false on a real response.
    let exportable = hex(&["0001", "000b", "00020060", "0000"]);
    let mut body = (exportable.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&exportable);
    let attrs = parse_read_public_attributes(&response(TPM_ST_NO_SESSIONS, 0, &body)).unwrap();
    assert!(
        !attributes_are_fixed_to_this_tpm(attrs),
        "a key the TPM does not describe as fixed must not read as fixed"
    );
}
