"""Attester agent via tpm2-pytss ESAPI (Constraint 8).

Protocol steps 2-3 (docs/SPEC_EN.md §7):
  1. GET  <verifier>/nonce
  2. capture one CONSISTENT (quote, IMA log) bundle — see below
  3. POST {quote, signature, pcr_values, ima_log} to <verifier>/evidence
  4. save the verifier's response (incl. the unseal authorization on
     TRUSTED) to attester/out/approval.json for payload/play_video.py

The verifier is the LAPTOP (Constraint 2): the default URL points at it
and can be overridden with $VERIFIER_URL or --verifier-url. The attest()
function is importable — payload/play_video.py calls it to refresh its
authorization when PCR 10 moved between verdict and unseal.

Atomic capture — PCR 10 is LIVE: under ima_policy=tcb the kernel keeps
extending PCR 10 whenever a new file is read by root or executed, so a log
snapshot and a quote taken at different instants can disagree. A bundle is
consistent iff replaying the SHIPPED log reproduces exactly the PCR-10
value inside the quote (sha256(replayed PCR) == the quote's pcrDigest).
The agent reads the log, quotes, replays its own snapshot, and retries
(bounded) until that holds; only a consistent bundle is shipped. The
verifier replays the log it was GIVEN, never "the current log".

The IMA log path is configurable so the identical code reads
dev/sample_ima_log/*.log on the laptop (IMA cannot be emulated there —
Constraint 3) and /sys/kernel/security/ima/ascii_runtime_measurements on
the Pi (root needed to read it: run under sudo).

Usage:
  sudo .venv/bin/python attester/agent.py [--verifier-url URL]
  sudo .venv/bin/python attester/agent.py --out bundle.json --offline
Exit code: 0 = TRUSTED, 2 = COMPROMISED, 1 = error.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import sys

import requests
from tpm2_pytss import (
    TPM2B_DATA,
    TPM2_ALG,
    TPM2_HANDLE,
    TPML_PCR_SELECTION,
    TPMS_ATTEST,
    TPMT_SIG_SCHEME,
)

from ima_replay import replay_sha256_pcr10
from tpmconn import open_esapi

ATTESTER_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VERIFIER_URL = os.environ.get("VERIFIER_URL", "http://172.20.10.4:5000")
DEFAULT_IMA_LOG = os.environ.get(
    "IMA_LOG_PATH", "/sys/kernel/security/ima/ascii_runtime_measurements"
)
DEFAULT_APPROVAL = os.path.join(ATTESTER_DIR, "out", "approval.json")
DEFAULT_AK_HANDLE = 0x81010002
PCR_SELECTION = "sha256:10"
MAX_CAPTURE_ATTEMPTS = 5


def make_quote(esys, ak_handle, nonce_hex):
    """Quote PCR 10 with the AK; the nonce rides as qualifying data so the
    verifier gets replay protection. NULL scheme = use the AK's own
    RSASSA/SHA256."""
    ak = esys.tr_from_tpmpublic(TPM2_HANDLE(ak_handle))
    quoted, signature = esys.quote(
        ak,
        TPML_PCR_SELECTION.parse(PCR_SELECTION),
        TPM2B_DATA(bytes.fromhex(nonce_hex)),
        TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
    )
    esys.tr_close(ak)
    # bytes(quoted) is the raw TPMS_ATTEST blob — exactly what the AK signed
    return bytes(quoted), signature.marshal()


def capture_consistent_bundle(esys, ak_handle, nonce_hex, ima_log_path,
                              max_attempts):
    """Read log -> quote -> check replay(shipped log) == PCR-10-in-quote.

    Reading the log BEFORE quoting means a measurement landing in between
    leaves the quote ahead of the snapshot — detected by the replay check
    and retried. Once the loop's own files have been measured (first run),
    PCR 10 only moves when something new is read/executed, so this
    converges almost always on attempt 1.
    """
    for attempt in range(1, max_attempts + 1):
        with open(ima_log_path, "r") as f:
            ima_log = f.read()
        attest_blob, sig_blob = make_quote(esys, ak_handle, nonce_hex)
        computed, count = replay_sha256_pcr10(ima_log)

        attest, _ = TPMS_ATTEST.unmarshal(attest_blob)
        quoted_pcr_digest = bytes(attest.attested.quote.pcrDigest)
        if hashlib.sha256(bytes.fromhex(computed)).digest() == quoted_pcr_digest:
            print(f"consistent bundle on attempt {attempt}: "
                  f"{count} entries replay to quoted PCR 10 = {computed}")
            return attest_blob, sig_blob, ima_log, computed, attempt
        print(f"attempt {attempt}: PCR 10 moved between log read and quote, "
              f"retrying")
    raise RuntimeError(
        f"no consistent quote+log bundle in {max_attempts} attempts — "
        f"the system is measuring new files too fast; retry when quieter"
    )


def build_evidence(nonce, ak_handle=DEFAULT_AK_HANDLE,
                   ima_log_path=DEFAULT_IMA_LOG, device_id=None,
                   max_attempts=MAX_CAPTURE_ATTEMPTS):
    """Capture a consistent bundle and wrap it as protocol evidence."""
    esys = open_esapi()
    try:
        attest_blob, sig_blob, ima_log, pcr10, attempts = \
            capture_consistent_bundle(
                esys, ak_handle, nonce, ima_log_path, max_attempts
            )
    finally:
        esys.close()
    return {
        "device_id": device_id or socket.gethostname(),
        "nonce": nonce,
        "quote_b64": base64.b64encode(attest_blob).decode(),
        "signature_b64": base64.b64encode(sig_blob).decode(),
        "pcr_values": {"sha256": {"10": pcr10}},
        "ima_log": ima_log,
        "capture_attempts": attempts,
    }


def attest(verifier_url=DEFAULT_VERIFIER_URL, ak_handle=DEFAULT_AK_HANDLE,
           ima_log_path=DEFAULT_IMA_LOG, device_id=None,
           max_attempts=MAX_CAPTURE_ATTEMPTS, approval_out=DEFAULT_APPROVAL,
           bundle_out=None):
    """One full online attestation round; returns the verifier's response.

    Needs root (the IMA log is root-readable only). The response — with
    the unseal authorization when TRUSTED — is also saved to approval_out
    for the gated payload.
    """
    nonce = requests.get(f"{verifier_url}/nonce", timeout=10).json()["nonce"]
    print(f"nonce: {nonce}")
    evidence = build_evidence(nonce, ak_handle, ima_log_path, device_id,
                              max_attempts)
    if bundle_out:
        with open(bundle_out, "w") as f:
            json.dump(evidence, f)
        print(f"evidence bundle written to {bundle_out}")

    resp = requests.post(f"{verifier_url}/evidence", json=evidence,
                         timeout=30)
    result = resp.json()

    os.makedirs(os.path.dirname(approval_out), exist_ok=True)
    with open(approval_out, "w") as f:
        json.dump(result, f, indent=2)
    has_approval = bool(result.get("approval"))
    print(f"verifier response saved to {approval_out} "
          f"(unseal authorization: {'yes' if has_approval else 'NO'})")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier-url", default=DEFAULT_VERIFIER_URL,
                        help="laptop verifier base URL (env: VERIFIER_URL)")
    parser.add_argument("--ak-handle", type=lambda s: int(s, 0),
                        default=DEFAULT_AK_HANDLE)
    parser.add_argument("--ima-log", default=DEFAULT_IMA_LOG,
                        help="path to the IMA ASCII measurement log "
                             "(dev: a file under dev/sample_ima_log/)")
    parser.add_argument("--device-id", default=socket.gethostname())
    parser.add_argument("--max-attempts", type=int, default=MAX_CAPTURE_ATTEMPTS,
                        help="quote+log consistency retries (PCR 10 is live)")
    parser.add_argument("--out", metavar="BUNDLE_JSON",
                        help="also write the evidence bundle to this file")
    parser.add_argument("--offline", action="store_true",
                        help="don't contact the verifier: use a locally "
                             "generated nonce and just write --out (for "
                             "transferring a bundle to the laptop by hand)")
    parser.add_argument("--approval-out", default=DEFAULT_APPROVAL,
                        help="where to store the verifier response for the "
                             "gated payload")
    args = parser.parse_args()

    if args.offline:
        if not args.out:
            parser.error("--offline requires --out")
        # an offline bundle has no server-issued nonce: the verifier CLI can
        # still check signature/replay/allowlist, but not freshness
        nonce = secrets.token_hex(32)
        print(f"offline mode: self-generated nonce {nonce}")
        evidence = build_evidence(nonce, args.ak_handle, args.ima_log,
                                  args.device_id, args.max_attempts)
        with open(args.out, "w") as f:
            json.dump(evidence, f)
        print(f"evidence bundle written to {args.out}")
        return

    result = attest(args.verifier_url, args.ak_handle, args.ima_log,
                    args.device_id, args.max_attempts, args.approval_out,
                    bundle_out=args.out)
    print(json.dumps({k: v for k, v in result.items() if k != "approval"},
                     indent=2))
    print(f"\nVERDICT: {result.get('verdict')}")
    sys.exit(0 if result.get("verdict") == "TRUSTED" else 2)


if __name__ == "__main__":
    main()
