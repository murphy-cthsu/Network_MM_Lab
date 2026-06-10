"""Provision the attester's TPM identity (runs on the Pi; dev: against swtpm).

Creates an EK and a restricted-signing AK, persists the AK at a well-known
handle, and exports ONLY the AK public part to verifier/ (Constraint 5: the
private blobs stay in attester/keys/, which is gitignored).

Requires TPM2TOOLS_TCTI to be set (e.g. via `source dev/tcti.env` for swtpm);
the same code runs unchanged against the Pi's real TPM (Constraint 1).

Usage: python3 attester/provision.py [--ak-handle 0x81010002]
"""

import argparse
import os
import shutil
import subprocess
import sys

ATTESTER_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(ATTESTER_DIR)
KEYS_DIR = os.path.join(ATTESTER_DIR, "keys")
VERIFIER_DIR = os.path.join(REPO_ROOT, "verifier")

EK_HANDLE = "0x81010001"
DEFAULT_AK_HANDLE = "0x81010002"


def run(cmd, **kwargs):
    print(f"+ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, check=True, **kwargs)


def flush_transient():
    """TPMs (swtpm especially) have very few transient-object slots; flush
    between steps or ContextLoad fails with TPM_RC_OBJECT_MEMORY (0x902)."""
    subprocess.run(["tpm2_flushcontext", "-t"], check=False, capture_output=True)


def evict_if_present(handle):
    """Remove a stale persistent object so provisioning is re-runnable."""
    listed = subprocess.run(
        ["tpm2_getcap", "handles-persistent"], capture_output=True, text=True
    )
    if listed.returncode == 0 and handle.lower() in listed.stdout.lower():
        run(["tpm2_evictcontrol", "-C", "o", "-c", handle])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ak-handle", default=DEFAULT_AK_HANDLE,
                        help="persistent handle for the AK")
    args = parser.parse_args()

    if not os.environ.get("TPM2TOOLS_TCTI"):
        sys.exit(
            "TPM2TOOLS_TCTI is not set. For laptop dev run:\n"
            "  dev/swtpm_setup.sh start && source dev/tcti.env"
        )

    os.makedirs(KEYS_DIR, exist_ok=True)
    ek_ctx = os.path.join(KEYS_DIR, "ek.ctx")
    ak_ctx = os.path.join(KEYS_DIR, "ak.ctx")
    ak_pub = os.path.join(KEYS_DIR, "ak.pub")
    ak_name = os.path.join(KEYS_DIR, "ak.name")

    evict_if_present(args.ak_handle)
    evict_if_present(EK_HANDLE)

    # Endorsement Key (decrypt-only parent; identity root)
    run(["tpm2_createek", "-c", ek_ctx, "-G", "rsa",
         "-u", os.path.join(KEYS_DIR, "ek.pub")])
    flush_transient()

    # Attestation Key: restricted signing key under the EK — the TPM will only
    # sign internally-generated data (quotes) with it, which is what makes
    # tpm2_quote trustworthy. RSA2048/SHA256 per Constraint 7.
    run(["tpm2_createak", "-C", ek_ctx, "-c", ak_ctx,
         "-G", "rsa", "-g", "sha256", "-s", "rsassa",
         "-u", ak_pub, "-n", ak_name])
    flush_transient()

    # Persist the AK so agent.py can use a stable handle across reboots.
    run(["tpm2_evictcontrol", "-C", "o", "-c", ak_ctx, args.ak_handle])
    flush_transient()

    # Export ONLY public material to the verifier. In a real deployment this
    # is a one-time enrollment step over a trusted channel.
    shutil.copyfile(ak_pub, os.path.join(VERIFIER_DIR, "ak.pub"))
    run(["tpm2_readpublic", "-c", args.ak_handle, "-f", "pem",
         "-o", os.path.join(VERIFIER_DIR, "ak_pub.pem")])

    print(f"\nProvisioned: AK persisted at {args.ak_handle}")
    print(f"  private material : {KEYS_DIR}/ (gitignored)")
    print(f"  AK public        : {VERIFIER_DIR}/ak.pub, {VERIFIER_DIR}/ak_pub.pem")


if __name__ == "__main__":
    main()
