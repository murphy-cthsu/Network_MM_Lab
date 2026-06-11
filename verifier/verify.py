"""Verification logic: quote check + IMA log replay + allowlist compare.

Runs on the laptop/host only (Constraint 2 — never on the Pi). Pure local
crypto — the verifier needs no TPM: the quote is parsed with tpm2-pytss
types and the AK signature is verified with `cryptography` (Constraint 8;
`tpm2_checkquote` remains usable as a CLI cross-check via verifier/ak.pub).

Protocol step 4 (docs/SPEC_EN.md §7):
  a. verify the AK signature over the quote, the nonce in its extraData
     (replay protection), and that its pcrDigest matches the reported PCR 10
  b. replay the SHIPPED IMA log -> recompute PCR 10 -> must equal the
     quoted PCR 10. Never look at "the current log": PCR 10 is live
     (ima_policy=tcb keeps extending it), so the only meaningful statement
     is "this exact log snapshot is what the TPM signed".
  c. allowlist compare, scoped to avoid false positives on a live tcb log
     (~2500 entries, growing): COMPROMISED means "a path we know was
     measured with a hash we don't allow". Paths absent from the allowlist
     are reported (count + sample) but do not flip the verdict — on a
     desktop OS root constantly reads legitimately-new files. The demo's
     watched binaries are listed in allowlist.json["watched"] and get a
     dedicated status in the result.

There is no fixed "golden" PCR-10 value anywhere: it changes every boot
and grows during one. Trust = signature+nonce (a) + log binds to quote (b)
+ every known measured file is allowed (c).

On TRUSTED, the verifier signs an unseal authorization for the QUOTED
PCR-10 value (TPM2 PolicyAuthorize pattern — see sign_policy_approval).

CLI (offline check of a bundle captured with agent.py --out):
  python3 verifier/verify.py bundle.json [--allowlist F] [--ak-pub F]
"""

import argparse
import base64
import hashlib
import json
import os
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from tpm2_pytss import (
    TPM2_ALG,
    TPM2_GENERATED,
    TPM2_ST,
    TPML_PCR_SELECTION,
    TPMS_ATTEST,
    TPMT_SIGNATURE,
)

VERIFIER_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AK_PUB = os.path.join(VERIFIER_DIR, "ak_pub.pem")
DEFAULT_ALLOWLIST = os.path.join(VERIFIER_DIR, "allowlist.json")
DEFAULT_POLICY_KEY = os.path.join(VERIFIER_DIR, "policy_key.pem")

PCR_BANK = "sha256"
PCR_INDEX = 10
PCR_SELECTION = f"{PCR_BANK}:{PCR_INDEX}"
# IMA extends 0xff..ff into the PCR for "violation" entries (whose template
# hash is logged as all zeros).
VIOLATION_EXTEND = bytes.fromhex("ff" * 32)
TPM2_CC_POLICY_PCR = 0x0000017F
LOG_TAIL_LINES = 15


class VerificationError(Exception):
    """A check failed; .check names the failing protocol step."""

    def __init__(self, check, detail):
        self.check = check
        self.detail = detail
        super().__init__(f"{check}: {detail}")


# ---------------------------------------------------------------------------
# IMA template handling
# ---------------------------------------------------------------------------

def rebuild_template_data(template_name, file_hash, path):
    """Rebuild the raw template-data bytes the kernel hashed for one entry.

    Template data is a sequence of (u32-LE length, bytes) fields.
    ima-ng:  d-ng = b"<algo>:\\0" + raw digest, n-ng = path + b"\\0"
    (The tcb policy only emits ima-ng; Phase 2 may add ima-buf.)
    """
    if template_name != "ima-ng":
        raise ValueError(f"unsupported IMA template: {template_name!r}")
    algo, _, hexdigest = file_hash.partition(":")
    if not hexdigest:
        raise ValueError(f"malformed file-hash field: {file_hash!r}")
    d_ng = algo.encode() + b":\x00" + bytes.fromhex(hexdigest)
    n_ng = path.encode() + b"\x00"
    return struct.pack("<I", len(d_ng)) + d_ng + struct.pack("<I", len(n_ng)) + n_ng


def ima_ng_template_hash(file_hash, path):
    """sha256 template hash for one ima-ng entry (used by the dev fixtures)."""
    return hashlib.sha256(
        rebuild_template_data("ima-ng", file_hash, path)
    ).hexdigest()


def parse_ima_line(line):
    """Parse one ascii_runtime_measurements line.

    Format: <pcr> <template-hash> <template-name> <file-hash> <path>
    Paths may contain spaces, so split at most 4 times.
    """
    parts = line.split(maxsplit=4)
    if len(parts) != 5:
        raise ValueError(f"unparseable IMA entry: {line!r}")
    pcr, template_hash, template_name, file_hash, path = parts
    return {
        "pcr": int(pcr),
        "template_hash": template_hash.lower(),
        "template_name": template_name,
        "file_hash": file_hash.lower(),
        "path": path,
    }


def replay_ima_log(ima_log_text):
    """Fold every PCR-10 entry into a running sha256 PCR value.

    The log's template-hash column is whatever the kernel's template-hash
    algo is (sha1 on the Pi's kernel; the dev fixtures use sha256), but the
    quote covers the sha256 bank — so the sha256 template hash is REBUILT
    from each entry's own fields and that is what extends the replayed PCR.
    The logged column is cross-checked against the rebuilt template data,
    so a log whose hash/path fields were edited is rejected (this binds the
    allowlist check to the TPM-attested value).

    Violation entries (all-zero template hash) extend with 0xff..ff exactly
    like the kernel does.

    Returns (computed_pcr10_hex, entries); each entry dict gains "lineno"
    and "violation" keys.
    """
    pcr = bytes(32)
    entries = []
    for lineno, line in enumerate(ima_log_text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        entry = parse_ima_line(line)
        entry["lineno"] = lineno
        entry["violation"] = False
        if entry["pcr"] != PCR_INDEX:
            continue  # we only attest PCR 10
        if set(entry["template_hash"]) == {"0"}:
            # measurement violation: log shows zeros, TPM got 0xff..ff
            entry["violation"] = True
            pcr = hashlib.sha256(pcr + VIOLATION_EXTEND).digest()
        else:
            try:
                data = rebuild_template_data(
                    entry["template_name"], entry["file_hash"], entry["path"]
                )
            except ValueError as e:
                raise VerificationError("ima_replay", f"line {lineno}: {e}")
            check = {40: hashlib.sha1, 64: hashlib.sha256}.get(
                len(entry["template_hash"])
            )
            if check is None or (
                check(data).hexdigest() != entry["template_hash"]
            ):
                raise VerificationError(
                    "ima_replay",
                    f"line {lineno}: template hash does not match its own "
                    f"fields (path={entry['path']})",
                )
            pcr = hashlib.sha256(pcr + hashlib.sha256(data).digest()).digest()
        entries.append(entry)
    return pcr.hex(), entries


# ---------------------------------------------------------------------------
# Quote verification (tpm2-pytss types + cryptography)
# ---------------------------------------------------------------------------

def check_quote(attest_blob, sig_blob, reported_pcr10_hex, nonce_hex, ak_pub_path):
    """Verify the quote without a TPM:
      - the AK's RSASSA/SHA256 signature over the raw TPMS_ATTEST blob
      - magic/type say "TPM-generated quote"
      - extraData equals our nonce (replay protection)
      - the PCR selection is exactly sha256:10
      - pcrDigest equals sha256(reported PCR-10 value), binding the reported
        value to the signature

    Returns the bound PCR-10 value (hex).
    """
    if not os.path.exists(ak_pub_path):
        raise VerificationError("quote_signature", f"AK public not found: {ak_pub_path}")

    try:
        attest, _ = TPMS_ATTEST.unmarshal(attest_blob)
        sig, _ = TPMT_SIGNATURE.unmarshal(sig_blob)
    except Exception as e:
        raise VerificationError("quote_signature", f"unparseable quote/signature: {e}")

    if attest.magic != TPM2_GENERATED.VALUE:
        raise VerificationError("quote_signature", "attest blob is not TPM-generated")
    if attest.type != TPM2_ST.ATTEST_QUOTE:
        raise VerificationError("quote_signature", "attest blob is not a quote")
    if sig.sigAlg != TPM2_ALG.RSASSA or sig.signature.rsassa.hash != TPM2_ALG.SHA256:
        raise VerificationError(
            "quote_signature", "signature is not RSASSA/SHA256 (Constraint 7)"
        )

    with open(ak_pub_path, "rb") as f:
        ak_public = load_pem_public_key(f.read())
    try:
        ak_public.verify(
            bytes(sig.signature.rsassa.sig),
            attest_blob,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise VerificationError("quote_signature", "AK signature is invalid")

    if bytes(attest.extraData) != bytes.fromhex(nonce_hex):
        raise VerificationError(
            "quote_signature", "nonce mismatch in quote (possible replay)"
        )

    sel = attest.attested.quote.pcrSelect
    bank = sel.pcrSelections[0]
    bitmap = bytes(bank.pcrSelect[i] for i in range(bank.sizeofSelect))
    # exactly one bank (sha256) selecting only bit 10 (byte 1, bit 2)
    ok = (
        sel.count == 1
        and bank.hash == TPM2_ALG.SHA256
        and bitmap == b"\x00\x04\x00"
    )
    if not ok:
        raise VerificationError(
            "quote_signature", f"quote does not cover exactly {PCR_SELECTION}"
        )

    pcr10 = bytes.fromhex(reported_pcr10_hex)
    if hashlib.sha256(pcr10).digest() != bytes(attest.attested.quote.pcrDigest):
        raise VerificationError(
            "quote_signature",
            "reported PCR 10 does not match the quote's pcrDigest",
        )
    return reported_pcr10_hex.lower()


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def load_allowlist(path=DEFAULT_ALLOWLIST):
    with open(path) as f:
        data = json.load(f)
    if "paths" not in data:  # legacy flat {path: [hashes]} format
        data = {"watched": [], "paths": data}
    data.setdefault("watched", [])
    return data


def check_allowlist(entries, allowlist):
    """Scoped allowlist compare (see module docstring, step c).

    Returns (failures, unknown_paths, watched_report, violation_count):
      failures       — entries that flip the verdict to COMPROMISED:
                       a known path measured with a non-allowed hash, or a
                       measurement violation involving a watched path
      unknown_paths  — sorted list of measured paths absent from the
                       allowlist (reported, NOT compromising)
      watched_report — {watched_path: {"status", "hash"}} for the dashboard
      violation_count — total violation entries seen (informational)
    """
    allowed = allowlist["paths"]
    watched = set(allowlist["watched"])
    failures = []
    unknown = set()
    violation_count = 0
    last_watched_hash = {}

    for entry in entries:
        path = entry["path"]
        if entry["violation"]:
            violation_count += 1
            if path in watched:
                failures.append({
                    "lineno": entry["lineno"], "path": path,
                    "file_hash": entry["file_hash"],
                    "reason": "measurement violation on a watched binary",
                })
            continue
        digest = entry["file_hash"].partition(":")[2]
        if path in watched:
            last_watched_hash[path] = digest
        good = allowed.get(path)
        if good is None:
            unknown.add(path)
        elif digest not in [h.lower() for h in good]:
            failures.append({
                "lineno": entry["lineno"], "path": path,
                "file_hash": entry["file_hash"],
                "reason": "hash not in allowlist for this path"
                          + (" [WATCHED]" if path in watched else ""),
            })

    watched_report = {}
    for path in sorted(watched):
        if path not in last_watched_hash:
            watched_report[path] = {"status": "NOT MEASURED YET", "hash": None}
        elif any(f["path"] == path for f in failures):
            watched_report[path] = {
                "status": "TAMPERED", "hash": last_watched_hash[path]
            }
        else:
            watched_report[path] = {
                "status": "OK", "hash": last_watched_hash[path]
            }
    return failures, sorted(unknown), watched_report, violation_count


# ---------------------------------------------------------------------------
# Unseal authorization (TPM2 PolicyAuthorize pattern)
# ---------------------------------------------------------------------------
#
# PCR 10 is live, so the gated secret cannot be sealed to one fixed PCR
# value. Instead it is sealed to PolicyAuthorize(verifier's policy key):
# after each TRUSTED verdict the verifier signs the PolicyPCR digest of the
# QUOTED PCR-10 value, and the attester satisfies the seal policy with
# PolicyPCR (current PCRs) + PolicyAuthorize (this signature). Tampering
# kills the gate twice over: the verifier refuses to sign the new PCR
# state, and any previously issued signature stops matching PolicyPCR the
# moment IMA extends the tampered hash. attester/seal.py documents the
# sealing side.

def policy_pcr_digest(pcr10_hex):
    """The TPM2 PolicyPCR digest for sha256:10 == the given value, computed
    in software (TPM 2.0 spec part 3, PolicyPCR; verified against a trial
    session on the Pi's TPM):
      H(0^32 || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || H(pcr_value))
    """
    sel = TPML_PCR_SELECTION.parse(PCR_SELECTION).marshal()
    pcr_digest = hashlib.sha256(bytes.fromhex(pcr10_hex)).digest()
    return hashlib.sha256(
        bytes(32) + struct.pack(">I", TPM2_CC_POLICY_PCR) + sel + pcr_digest
    ).digest()


def sign_policy_approval(pcr10_hex, policy_key_path=DEFAULT_POLICY_KEY,
                         policy_ref=b""):
    """Sign the approved policy: RSASSA(SHA256) over aHash =
    sha256(approved_policy || policy_ref), the digest TPM2_VerifySignature
    expects. Returns the approval dict shipped to the attester."""
    with open(policy_key_path, "rb") as f:
        key = load_pem_private_key(f.read(), password=None)
    approved = policy_pcr_digest(pcr10_hex)
    signature = key.sign(
        approved + policy_ref, padding.PKCS1v15(), hashes.SHA256()
    )
    return {
        "pcr_selection": PCR_SELECTION,
        "quoted_pcr10": pcr10_hex,
        "approved_policy_b64": base64.b64encode(approved).decode(),
        "policy_ref_b64": base64.b64encode(policy_ref).decode(),
        "policy_signature_b64": base64.b64encode(signature).decode(),
    }


# ---------------------------------------------------------------------------
# Top-level verdict
# ---------------------------------------------------------------------------

def verify_evidence(evidence, nonce_hex, ak_pub_path=DEFAULT_AK_PUB,
                    allowlist_path=DEFAULT_ALLOWLIST):
    """Run all protocol checks; never raises — failures become the verdict.

    evidence: {"quote_b64", "signature_b64", "pcr_values", "ima_log", ...}
    """
    result = {
        "verdict": "COMPROMISED",
        "checks": {},
        "failed_entries": [],
        "quoted_pcr10": None,
        "computed_pcr10": None,
        "entry_count": 0,
        "violations": 0,
        "unknown_paths": {"count": 0, "sample": []},
        "watched": {},
        "log_tail": [],
        "capture_attempts": evidence.get("capture_attempts"),
    }
    try:
        attest_blob = base64.b64decode(evidence["quote_b64"])
        sig_blob = base64.b64decode(evidence["signature_b64"])
        reported_pcr10 = evidence["pcr_values"][PCR_BANK][str(PCR_INDEX)]
        ima_log = evidence["ima_log"]
    except (KeyError, ValueError, TypeError) as e:
        result["checks"]["evidence_format"] = f"FAIL: {e!r}"
        return result
    result["checks"]["evidence_format"] = "PASS"

    # (a) signature + nonce freshness + PCR digest binding
    try:
        quoted_pcr10 = check_quote(
            attest_blob, sig_blob, reported_pcr10, nonce_hex, ak_pub_path
        )
        result["quoted_pcr10"] = quoted_pcr10
        result["checks"]["quote_signature_and_nonce"] = "PASS"
    except VerificationError as e:
        result["checks"]["quote_signature_and_nonce"] = f"FAIL: {e.detail}"
        return result

    # (b) replaying the SHIPPED log must reproduce the quoted PCR 10
    try:
        computed, entries = replay_ima_log(ima_log)
    except (VerificationError, ValueError) as e:
        result["checks"]["ima_replay"] = f"FAIL: {e}"
        return result
    result["computed_pcr10"] = computed
    result["entry_count"] = len(entries)
    result["log_tail"] = [
        {"lineno": e["lineno"], "path": e["path"], "file_hash": e["file_hash"]}
        for e in entries[-LOG_TAIL_LINES:]
    ]
    if computed != quoted_pcr10:
        result["checks"]["ima_replay"] = (
            f"FAIL: replayed PCR10 {computed} != quoted PCR10 {quoted_pcr10}"
        )
        return result
    result["checks"]["ima_replay"] = "PASS"

    # (c) scoped allowlist compare
    allowlist = load_allowlist(allowlist_path)
    failures, unknown, watched_report, violations = check_allowlist(
        entries, allowlist
    )
    result["violations"] = violations
    result["unknown_paths"] = {"count": len(unknown), "sample": unknown[:10]}
    result["watched"] = watched_report
    if failures:
        result["failed_entries"] = failures
        result["checks"]["allowlist"] = (
            f"FAIL: {len(failures)} bad measurement(s), first offender: "
            f"{failures[0]['path']} ({failures[0]['file_hash']})"
        )
        return result
    result["checks"]["allowlist"] = (
        f"PASS ({len(entries)} entries; {len(unknown)} unknown path(s) "
        f"reported, not compromising)"
    )

    result["verdict"] = "TRUSTED"
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Offline verification of a captured evidence bundle"
    )
    parser.add_argument("bundle", help="bundle JSON from agent.py --out")
    parser.add_argument("--ak-pub", default=DEFAULT_AK_PUB)
    parser.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    parser.add_argument("--policy-key", default=DEFAULT_POLICY_KEY,
                        help="sign an unseal authorization on TRUSTED "
                             "(skipped if the key file does not exist)")
    args = parser.parse_args()

    with open(args.bundle) as f:
        evidence = json.load(f)
    # offline: the nonce comes from the bundle itself, so freshness is NOT
    # checked here — that's the server's job in the online flow
    result = verify_evidence(evidence, evidence["nonce"],
                             ak_pub_path=args.ak_pub,
                             allowlist_path=args.allowlist)
    result["checks"] = {"nonce_freshness": "SKIPPED (offline bundle)",
                        **result["checks"]}
    if result["verdict"] == "TRUSTED" and os.path.exists(args.policy_key):
        result["approval"] = sign_policy_approval(
            result["quoted_pcr10"], args.policy_key
        )
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["verdict"] == "TRUSTED" else 2)


if __name__ == "__main__":
    main()
