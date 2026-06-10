"""Provision the attester's TPM identity via tpm2-pytss ESAPI (Constraint 8).

Creates a primary key in the endorsement hierarchy, creates a
restricted-signing RSA2048/SHA256 AK (Constraint 7) under it, persists the
AK at a well-known handle, and exports ONLY the AK public part to verifier/
(Constraint 5: private material never leaves the TPM; the persisted AK lives
inside it).

Runs identically against swtpm (laptop, via dev/tcti.env) and the Pi's real
TPM. Usage: python3 attester/provision.py [--ak-handle 0x81010002]
"""

import argparse
import os

from tpm2_pytss import (
    ESYS_TR,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE,
    TPM2_CAP,
    TPM2_HC,
    TPM2_HANDLE,
)

from tpmconn import open_esapi

ATTESTER_DIR = os.path.dirname(os.path.abspath(__file__))
VERIFIER_DIR = os.path.join(os.path.dirname(ATTESTER_DIR), "verifier")

DEFAULT_AK_HANDLE = 0x81010002

# Storage-style primary (restricted decrypt) — the AK's parent.
PRIMARY_TEMPLATE = TPM2B_PUBLIC.parse(
    "rsa2048:null:aes128cfb",
    objectAttributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
                     "|restricted|decrypt|noda",
)

# AK: restricted signing — the TPM will only sign internally-generated data
# (quotes) with it, which is what makes a quote trustworthy.
# RSA2048 + RSASSA/SHA256 per Constraint 7.
AK_TEMPLATE = TPM2B_PUBLIC.parse(
    "rsa2048:rsassa-sha256:null",
    objectAttributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
                     "|restricted|sign",
)


def evict_if_present(esys, handle):
    """Remove a stale persistent object so provisioning is re-runnable."""
    more = True
    prop = TPM2_HC.PERSISTENT_FIRST
    while more:
        more, caps = esys.get_capability(TPM2_CAP.HANDLES, prop, 64)
        existing = list(caps.data.handles)
        if handle in existing:
            obj = esys.tr_from_tpmpublic(TPM2_HANDLE(handle))
            esys.evict_control(ESYS_TR.OWNER, obj, handle)
            print(f"evicted stale object at {handle:#x}")
            return
        if not existing:
            return
        prop = existing[-1] + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ak-handle", type=lambda s: int(s, 0),
                        default=DEFAULT_AK_HANDLE)
    args = parser.parse_args()

    esys = open_esapi()
    try:
        evict_if_present(esys, args.ak_handle)

        primary, _, _, _, _ = esys.create_primary(
            TPM2B_SENSITIVE_CREATE(), PRIMARY_TEMPLATE, ESYS_TR.ENDORSEMENT
        )
        print("primary created (endorsement hierarchy, RSA2048)")

        ak_priv, ak_pub, _, _, _ = esys.create(
            primary, TPM2B_SENSITIVE_CREATE(), AK_TEMPLATE
        )
        ak = esys.load(primary, ak_priv, ak_pub)
        esys.flush_context(primary)
        print("AK created (restricted signing, RSA2048/SHA256)")

        ak_persistent = esys.evict_control(ESYS_TR.OWNER, ak, args.ak_handle)
        esys.flush_context(ak)
        esys.tr_close(ak_persistent)
        print(f"AK persisted at {args.ak_handle:#x}")

        # Export ONLY public material. In a real deployment this is a one-time
        # enrollment over a trusted channel.
        pem_path = os.path.join(VERIFIER_DIR, "ak_pub.pem")
        with open(pem_path, "wb") as f:
            f.write(ak_pub.publicArea.to_pem())
        # marshaled TPM2B_PUBLIC, usable by tpm2_checkquote -u for CLI debug
        with open(os.path.join(VERIFIER_DIR, "ak.pub"), "wb") as f:
            f.write(ak_pub.marshal())
        print(f"AK public exported to {pem_path} (+ ak.pub for CLI debug)")
    finally:
        esys.close()


if __name__ == "__main__":
    main()
