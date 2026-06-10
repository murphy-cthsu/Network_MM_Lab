"""Verification logic: tpm2_checkquote + IMA log replay + allowlist compare.

Runs on the laptop/host only (Constraint 2 — never on the Pi). Pure
verification: needs no TPM of its own; tpm2_checkquote is local crypto.

Protocol step 4 (docs/SPEC_EN.md §7):
  a. tpm2_checkquote with the enrolled AK public + nonce  -> signature & freshness
  b. replay the IMA log -> recompute PCR 10 -> must equal the quoted PCR 10
  c. every file-hash entry must be in allowlist.json, else COMPROMISED
"""

import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile

VERIFIER_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AK_PUB = os.path.join(VERIFIER_DIR, "ak.pub")
DEFAULT_ALLOWLIST = os.path.join(VERIFIER_DIR, "allowlist.json")

PCR_BANK = "sha256"
PCR_INDEX = 10
ZERO_DIGEST = "0" * 64
# IMA extends 0xff..ff into the PCR for "violation" entries (whose template
# hash is logged as all zeros).
VIOLATION_EXTEND = bytes.fromhex("ff" * 32)


class VerificationError(Exception):
    """A check failed; .check names the failing protocol step."""

    def __init__(self, check, detail):
        self.check = check
        self.detail = detail
        super().__init__(f"{check}: {detail}")


# ---------------------------------------------------------------------------
# IMA ima-ng template handling
# ---------------------------------------------------------------------------

def ima_ng_template_hash(file_hash_field, path):
    """Recompute the ima-ng template hash (sha256) for one log entry.

    The kernel hashes the template data as a sequence of (u32-LE length,
    bytes) fields. For ima-ng:
      d-ng: b"<algo>:\\0" + raw digest
      n-ng: path + b"\\0"

    file_hash_field is e.g. "sha256:abc123...".
    """
    algo, _, hexdigest = file_hash_field.partition(":")
    if not hexdigest:
        raise ValueError(f"malformed file-hash field: {file_hash_field!r}")
    d_ng = algo.encode() + b":\x00" + bytes.fromhex(hexdigest)
    n_ng = path.encode() + b"\x00"
    data = struct.pack("<I", len(d_ng)) + d_ng + struct.pack("<I", len(n_ng)) + n_ng
    return hashlib.sha256(data).hexdigest()


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
    """Fold every entry's template hash into a running SHA-256 PCR-10 value.

    Also recomputes each ima-ng template hash from the file-hash + path
    fields, so a log whose hash columns were edited independently of the
    template hashes is rejected (binds the allowlist check to the PCR).

    Returns (computed_pcr10_hex, entries).
    """
    pcr = bytes(32)
    entries = []
    for lineno, line in enumerate(ima_log_text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        entry = parse_ima_line(line)
        if entry["pcr"] != PCR_INDEX:
            continue  # we only attest PCR 10
        if entry["template_hash"] == ZERO_DIGEST:
            # measurement violation: log shows zeros, TPM got 0xff..ff
            pcr = hashlib.sha256(pcr + VIOLATION_EXTEND).digest()
        else:
            if entry["template_name"] == "ima-ng":
                expected = ima_ng_template_hash(entry["file_hash"], entry["path"])
                if expected != entry["template_hash"]:
                    raise VerificationError(
                        "ima_replay",
                        f"line {lineno}: template hash does not match its own "
                        f"fields (path={entry['path']})",
                    )
            pcr = hashlib.sha256(pcr + bytes.fromhex(entry["template_hash"])).digest()
        entries.append(entry)
    return pcr.hex(), entries


# ---------------------------------------------------------------------------
# Quote verification (tpm2_checkquote)
# ---------------------------------------------------------------------------

def check_quote(quote_msg, signature, pcrs, nonce_hex, ak_pub_path):
    """Run tpm2_checkquote: verifies the AK signature over the quote, that the
    qualifying data equals our nonce (replay protection), and that the PCR
    digest in the quote matches the reported PCR values.

    Returns the quoted PCR-10 value (hex) parsed from checkquote's output.
    """
    if not os.path.exists(ak_pub_path):
        raise VerificationError("quote_signature", f"AK public not found: {ak_pub_path}")
    with tempfile.TemporaryDirectory(prefix="verify-") as tmp:
        msg_f = os.path.join(tmp, "quote.msg")
        sig_f = os.path.join(tmp, "quote.sig")
        pcr_f = os.path.join(tmp, "quote.pcrs")
        for fname, blob in ((msg_f, quote_msg), (sig_f, signature), (pcr_f, pcrs)):
            with open(fname, "wb") as f:
                f.write(blob)
        env = dict(os.environ, TPM2TOOLS_TCTI="none")  # local crypto, no TPM
        proc = subprocess.run(
            [
                "tpm2_checkquote",
                "-u", ak_pub_path,
                "-m", msg_f,
                "-s", sig_f,
                "-f", pcr_f,
                "-g", "sha256",
                "-q", nonce_hex,
            ],
            capture_output=True, text=True, env=env,
        )
    if proc.returncode != 0:
        raise VerificationError(
            "quote_signature",
            f"tpm2_checkquote failed: {proc.stderr.strip() or proc.stdout.strip()}",
        )
    # checkquote prints the attested PCRs, e.g.:
    #   pcrs:
    #     sha256:
    #       10: 0x8E7C...
    m = re.search(
        rf"{PCR_BANK}:\s*\n\s*{PCR_INDEX}\s*:\s*0x([0-9A-Fa-f]+)", proc.stdout
    )
    if not m:
        raise VerificationError(
            "quote_signature",
            f"could not find {PCR_BANK} PCR {PCR_INDEX} in checkquote output",
        )
    return m.group(1).lower().zfill(64)


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def load_allowlist(path=DEFAULT_ALLOWLIST):
    with open(path) as f:
        return json.load(f)


def check_allowlist(entries, allowlist):
    """Every measured file hash must be known-good for its path.

    Returns a list of failing entries (empty list == all good).
    """
    failures = []
    for entry in entries:
        good = allowlist.get(entry["path"])
        digest = entry["file_hash"].partition(":")[2]
        if good is None:
            failures.append({**entry, "reason": "path not in allowlist"})
        elif digest not in [h.lower() for h in good]:
            failures.append({**entry, "reason": "hash not in allowlist for this path"})
    return failures


# ---------------------------------------------------------------------------
# Top-level verdict
# ---------------------------------------------------------------------------

def verify_evidence(evidence, nonce_hex, ak_pub_path=DEFAULT_AK_PUB,
                    allowlist_path=DEFAULT_ALLOWLIST):
    """Run all protocol checks; never raises — failures become the verdict.

    evidence: {"quote_b64", "signature_b64", "pcrs_b64", "ima_log", ...}
    """
    result = {
        "verdict": "COMPROMISED",
        "checks": {},
        "failed_entries": [],
        "quoted_pcr10": None,
        "computed_pcr10": None,
        "measured_entries": [],
    }
    try:
        quote_msg = base64.b64decode(evidence["quote_b64"])
        signature = base64.b64decode(evidence["signature_b64"])
        pcrs = base64.b64decode(evidence["pcrs_b64"])
        ima_log = evidence["ima_log"]
    except (KeyError, ValueError) as e:
        result["checks"]["evidence_format"] = f"FAIL: {e}"
        return result
    result["checks"]["evidence_format"] = "PASS"

    # (a) signature + nonce freshness + PCR digest binding
    try:
        quoted_pcr10 = check_quote(quote_msg, signature, pcrs, nonce_hex, ak_pub_path)
        result["quoted_pcr10"] = quoted_pcr10
        result["checks"]["quote_signature_and_nonce"] = "PASS"
    except VerificationError as e:
        result["checks"]["quote_signature_and_nonce"] = f"FAIL: {e.detail}"
        return result

    # (b) IMA replay must reproduce the quoted PCR 10
    try:
        computed, entries = replay_ima_log(ima_log)
    except (VerificationError, ValueError) as e:
        result["checks"]["ima_replay"] = f"FAIL: {e}"
        return result
    result["computed_pcr10"] = computed
    result["measured_entries"] = entries
    if computed != quoted_pcr10:
        result["checks"]["ima_replay"] = (
            f"FAIL: replayed PCR10 {computed} != quoted PCR10 {quoted_pcr10}"
        )
        return result
    result["checks"]["ima_replay"] = "PASS"

    # (c) every measurement must be on the allowlist
    allowlist = load_allowlist(allowlist_path)
    failures = check_allowlist(entries, allowlist)
    if failures:
        result["failed_entries"] = failures
        result["checks"]["allowlist"] = (
            f"FAIL: {len(failures)} unknown measurement(s), first offender: "
            f"{failures[0]['path']} ({failures[0]['file_hash']})"
        )
        return result
    result["checks"]["allowlist"] = "PASS"

    result["verdict"] = "TRUSTED"
    return result
