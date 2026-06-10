"""Attester agent (runs on the Pi; dev: against swtpm + recorded IMA logs).

Protocol steps 2–3 (docs/SPEC_EN.md §7):
  1. GET  <verifier>/nonce
  2. tpm2_quote over PCR 10 with the AK, nonce as qualifying data
  3. read the IMA ASCII measurement log
  4. POST {quote, signature, pcrs, ima_log} to <verifier>/evidence

The IMA log path is configurable so the identical code reads
dev/sample_ima_log/*.log on the laptop (IMA cannot be emulated there —
Constraint 3) and /sys/kernel/security/ima/ascii_runtime_measurements on
the Pi.

Usage:
  python3 attester/agent.py --ima-log dev/sample_ima_log/clean.log
Exit code: 0 = TRUSTED, 2 = COMPROMISED, 1 = error.
"""

import argparse
import base64
import json
import os
import socket
import subprocess
import sys

import requests

ATTESTER_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(ATTESTER_DIR, "out")

DEFAULT_IMA_LOG = os.environ.get(
    "IMA_LOG_PATH", "/sys/kernel/security/ima/ascii_runtime_measurements"
)
DEFAULT_AK_HANDLE = "0x81010002"
PCR_SELECTION = "sha256:10"


def b64_file(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def make_quote(ak_handle, nonce_hex):
    """tpm2_quote over PCR 10, binding the verifier's nonce (replay protection)."""
    os.makedirs(OUT_DIR, exist_ok=True)
    msg = os.path.join(OUT_DIR, "quote.msg")
    sig = os.path.join(OUT_DIR, "quote.sig")
    pcrs = os.path.join(OUT_DIR, "quote.pcrs")
    subprocess.run(
        [
            "tpm2_quote",
            "-c", ak_handle,
            "-l", PCR_SELECTION,
            "-q", nonce_hex,
            "-g", "sha256",
            "-m", msg,
            "-s", sig,
            "-o", pcrs,
        ],
        check=True, capture_output=True, text=True,
    )
    return msg, sig, pcrs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier-url", default="http://127.0.0.1:5000")
    parser.add_argument("--ak-handle", default=DEFAULT_AK_HANDLE)
    parser.add_argument("--ima-log", default=DEFAULT_IMA_LOG,
                        help="path to the IMA ASCII measurement log "
                             "(dev: a file under dev/sample_ima_log/)")
    parser.add_argument("--device-id", default=socket.gethostname())
    args = parser.parse_args()

    if not os.environ.get("TPM2TOOLS_TCTI") and not os.path.exists("/dev/tpm0"):
        sys.exit(
            "No TPM available: TPM2TOOLS_TCTI unset and /dev/tpm0 missing.\n"
            "For laptop dev: dev/swtpm_setup.sh start && source dev/tcti.env"
        )

    nonce = requests.get(f"{args.verifier_url}/nonce", timeout=10).json()["nonce"]
    print(f"nonce: {nonce}")

    try:
        msg, sig, pcrs = make_quote(args.ak_handle, nonce)
    except subprocess.CalledProcessError as e:
        sys.exit(f"tpm2_quote failed: {e.stderr}")

    with open(args.ima_log, "r") as f:
        ima_log = f.read()

    evidence = {
        "device_id": args.device_id,
        "nonce": nonce,
        "quote_b64": b64_file(msg),
        "signature_b64": b64_file(sig),
        "pcrs_b64": b64_file(pcrs),
        "ima_log": ima_log,
    }
    resp = requests.post(f"{args.verifier_url}/evidence", json=evidence, timeout=30)
    result = resp.json()
    print(json.dumps(result, indent=2))
    print(f"\nVERDICT: {result.get('verdict')}")
    sys.exit(0 if result.get("verdict") == "TRUSTED" else 2)


if __name__ == "__main__":
    main()
