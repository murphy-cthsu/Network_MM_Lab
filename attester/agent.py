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
The agent quotes FIRST, then reads the append-only log and TRIMS it to
the prefix that replays to the quoted digest — the exact state the TPM
signed — so capture converges in one attempt regardless of how fast the
system is measuring (first boot minutes, desktop churn, ...). The
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

from ima_replay import consistent_prefix, replay_sha256_pcr10
from tpmconn import open_esapi

ATTESTER_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VERIFIER_URL = os.environ.get("VERIFIER_URL", "http://172.20.10.4:5000")
DEFAULT_IMA_LOG = os.environ.get(
    "IMA_LOG_PATH", "/sys/kernel/security/ima/ascii_runtime_measurements"
)
# tmpfs, NOT the repo: the approval is rewritten per attestation, and a
# root read of a changed file on ext4 would re-measure it into PCR 10
# right after the verdict — instantly staling the authorization it
# carries. tcb does not measure tmpfs, and per-boot lifetime is exactly
# an authorization's lifetime anyway.
DEFAULT_APPROVAL = "/run/network-mm-attest/approval.json"
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
    """Quote FIRST, then trim the log to the prefix the TPM signed.

    The IMA log is append-only, so a log read after the quote contains
    every entry up to the quote plus whatever landed later; the prefix
    whose replay hashes to the quote's pcrDigest is the exact signed
    state (ima_replay.consistent_prefix). One attempt suffices at any
    measurement rate — the retries only guard pathological cases (log
    corrupted, wrong PCR bank).
    """
    for attempt in range(1, max_attempts + 1):
        attest_blob, sig_blob = make_quote(esys, ak_handle, nonce_hex)
        with open(ima_log_path, "r") as f:
            ima_log = f.read()
        attest, _ = TPMS_ATTEST.unmarshal(attest_blob)
        quoted_pcr_digest = bytes(attest.attested.quote.pcrDigest)

        match = consistent_prefix(ima_log, quoted_pcr_digest)
        if match is not None:
            prefix, pcr10, count = match
            trimmed = len(ima_log.splitlines()) - len(prefix.splitlines())
            print(f"consistent bundle on attempt {attempt}: {count} entries "
                  f"replay to quoted PCR 10 = {pcr10}"
                  + (f" ({trimmed} entries measured after the quote were "
                     f"trimmed)" if trimmed else ""))
            return attest_blob, sig_blob, prefix, pcr10, attempt

        # No prefix matched. Distinguish a transient race from a true
        # log/PCR desync: if even the FULL log does not replay to the live
        # PCR, the PCR holds extends IMA never logged — seen when a warm
        # reboot leaves the SPI TPM un-reset, so the previous boot's PCR 10
        # survives underneath this boot's measurements. No retry can fix
        # that; only a power-cycle resets the chip.
        computed, count = replay_sha256_pcr10(ima_log)
        _, _, digests = esys.pcr_read(TPML_PCR_SELECTION.parse(PCR_SELECTION))
        live = bytes(digests[0]).hex()
        if computed != live:
            raise RuntimeError(
                f"IMA log / PCR-10 desync: replaying all {count} logged "
                f"entries yields {computed} but the TPM holds {live} — "
                f"PCR 10 contains extends IMA never logged, so this boot "
                f"cannot attest. POWER-CYCLE the Pi (a warm reboot can "
                f"leave the SPI TPM un-reset) and re-run. See "
                f"docs/DEMO_RUNBOOK.md, Troubleshooting."
            )
        print(f"attempt {attempt}: quote matched no prefix, but the full "
              f"log now replays to the live PCR (in-flight churn) — "
              f"retrying")
    raise RuntimeError(
        f"the quote matched no prefix of the IMA log in {max_attempts} "
        f"attempts despite log/PCR agreement — log corrupt or wrong AK"
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
    try:
        nonce = requests.get(f"{verifier_url}/nonce", timeout=10).json()["nonce"]
    except requests.exceptions.RequestException as e:
        raise RuntimeError(
            f"verifier unreachable at {verifier_url} "
            f"({e.__class__.__name__}) — on the laptop: run "
            f"'python3 verifier/server.py --host 0.0.0.0' and allow inbound "
            f"TCP {verifier_url.rsplit(':', 1)[-1]} in its firewall"
        ) from e
    print(f"nonce: {nonce}")
    evidence = build_evidence(nonce, ak_handle, ima_log_path, device_id,
                              max_attempts)
    if bundle_out:
        with open(bundle_out, "w") as f:
            json.dump(evidence, f)
        print(f"evidence bundle written to {bundle_out}")

    try:
        resp = requests.post(f"{verifier_url}/evidence", json=evidence,
                             timeout=30)
        result = resp.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(
            f"evidence POST to {verifier_url} failed "
            f"({e.__class__.__name__}) — verifier went away mid-attestation"
        ) from e

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

    try:
        if args.offline:
            if not args.out:
                parser.error("--offline requires --out")
            # an offline bundle has no server-issued nonce: the verifier CLI
            # can still check signature/replay/allowlist, but not freshness
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
    except RuntimeError as e:
        # exit 1 (error), NOT 2 (COMPROMISED): a network failure or capture
        # timeout is not a verdict, and scripts must not score it as one
        sys.exit(f"ERROR: {e}")
    print(json.dumps({k: v for k, v in result.items() if k != "approval"},
                     indent=2))
    print(f"\nVERDICT: {result.get('verdict')}")
    sys.exit(0 if result.get("verdict") == "TRUSTED" else 2)


if __name__ == "__main__":
    main()
