"""Attester agent via tpm2-pytss ESAPI (Constraint 8).

Protocol steps 2-3 (docs/SPEC_EN.md §7):
  1. GET  <verifier>/nonce
  2. esapi.quote over PCR 10 with the persisted AK, nonce as qualifying data;
     esapi.pcr_read for the reported PCR values
  3. read the IMA ASCII measurement log
  4. POST {quote, signature, pcr_values, ima_log} to <verifier>/evidence

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
import sys

import requests
from tpm2_pytss import (
    TPM2B_DATA,
    TPM2_ALG,
    TPM2_HANDLE,
    TPML_PCR_SELECTION,
    TPMT_SIG_SCHEME,
)

from tpmconn import open_esapi

DEFAULT_IMA_LOG = os.environ.get(
    "IMA_LOG_PATH", "/sys/kernel/security/ima/ascii_runtime_measurements"
)
DEFAULT_AK_HANDLE = 0x81010002
PCR_SELECTION = "sha256:10"


def read_pcr10(esys):
    _, _, digests = esys.pcr_read(TPML_PCR_SELECTION.parse(PCR_SELECTION))
    return bytes(digests[0]).hex()


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier-url", default="http://127.0.0.1:5000")
    parser.add_argument("--ak-handle", type=lambda s: int(s, 0),
                        default=DEFAULT_AK_HANDLE)
    parser.add_argument("--ima-log", default=DEFAULT_IMA_LOG,
                        help="path to the IMA ASCII measurement log "
                             "(dev: a file under dev/sample_ima_log/)")
    parser.add_argument("--device-id", default=socket.gethostname())
    args = parser.parse_args()

    nonce = requests.get(f"{args.verifier_url}/nonce", timeout=10).json()["nonce"]
    print(f"nonce: {nonce}")

    esys = open_esapi()
    try:
        pcr10 = read_pcr10(esys)
        attest_blob, sig_blob = make_quote(esys, args.ak_handle, nonce)
    finally:
        esys.close()
    print(f"quoted; current PCR 10 = {pcr10}")

    with open(args.ima_log, "r") as f:
        ima_log = f.read()

    evidence = {
        "device_id": args.device_id,
        "nonce": nonce,
        "quote_b64": base64.b64encode(attest_blob).decode(),
        "signature_b64": base64.b64encode(sig_blob).decode(),
        "pcr_values": {"sha256": {"10": pcr10}},
        "ima_log": ima_log,
    }
    resp = requests.post(f"{args.verifier_url}/evidence", json=evidence, timeout=30)
    result = resp.json()
    print(json.dumps(result, indent=2))
    print(f"\nVERDICT: {result.get('verdict')}")
    sys.exit(0 if result.get("verdict") == "TRUSTED" else 2)


if __name__ == "__main__":
    main()
