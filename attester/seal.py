"""Seal the gated-video AES key to the verifier-authorized PCR-10 policy.

Phase 1 task 1.4. attester/sealing.py documents the design: the key is
sealed ONCE to PolicyAuthorize(verifier's policy key) — NOT to a fixed
PCR-10 value, because PCR 10 is live and never repeats. The TPM will
release the key only inside a session that proves the CURRENT PCR-10
value carries the verifier's signature (issued per TRUSTED attestation).

Produces (all under attester/out/, gitignored — Constraint 5):
  clip.mp4         demo clip (generated with ffmpeg if not supplied)
  clip.enc         AES-256-GCM encrypted clip — the gated asset
  sealed_key.pub/.priv  the sealed AES key blobs (load-able only on THIS
                        TPM, unseal-able only via the policy above)
The plaintext AES key exists only in this process and is discarded.

Usage: .venv/bin/python attester/seal.py [--clip video.mp4]
       (needs attester/policy_pub.pem from verifier/make_policy_key.py)
"""

import argparse
import os
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tpm2_pytss import (
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_SENSITIVE_DATA,
    TPMS_SENSITIVE_CREATE,
)

import sealing
from tpmconn import open_esapi

GCM_NONCE_BYTES = 12


def ensure_clip(path):
    if os.path.exists(path):
        return
    print(f"generating demo clip {path} (ffmpeg test pattern)")
    subprocess.run(
        ["ffmpeg", "-loglevel", "error", "-y",
         "-f", "lavfi", "-i", "testsrc2=duration=5:size=640x360:rate=25",
         "-f", "lavfi", "-i", "sine=frequency=440:duration=5",
         "-shortest", "-pix_fmt", "yuv420p", path],
        check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clip", default=os.path.join(sealing.OUT_DIR, "clip.mp4"),
                        help="plaintext clip to encrypt (generated if missing)")
    parser.add_argument("--policy-pub", default=sealing.DEFAULT_POLICY_PUB)
    args = parser.parse_args()

    if not os.path.exists(args.policy_pub):
        sys.exit(f"{args.policy_pub} missing — run verifier/make_policy_key.py "
                 f"on the laptop and copy the public key here")
    os.makedirs(sealing.OUT_DIR, exist_ok=True)
    ensure_clip(args.clip)

    key = os.urandom(32)
    nonce = os.urandom(GCM_NONCE_BYTES)
    with open(args.clip, "rb") as f:
        ciphertext = AESGCM(key).encrypt(nonce, f.read(), None)
    with open(sealing.CLIP_ENC, "wb") as f:
        f.write(nonce + ciphertext)
    print(f"clip encrypted (AES-256-GCM) -> {sealing.CLIP_ENC}")

    esys = open_esapi()
    try:
        _, key_name = sealing.load_policy_pub(esys, args.policy_pub)
        auth_policy = sealing.policy_authorize_digest(esys, key_name)
        print(f"seal authPolicy = PolicyAuthorize(verifier key) = "
              f"{auth_policy.hex()}")

        # sealed-data object: no userWithAuth -> the policy is the ONLY way
        # to unseal; fixedtpm/fixedparent -> cannot leave this TPM
        template = TPM2B_PUBLIC.parse(
            "keyedhash", objectAttributes="fixedtpm|fixedparent|noda"
        )
        template.publicArea.authPolicy = auth_policy

        primary = sealing.create_storage_primary(esys)
        sealed_priv, sealed_pub, _, _, _ = esys.create(
            primary,
            TPM2B_SENSITIVE_CREATE(
                sensitive=TPMS_SENSITIVE_CREATE(
                    data=TPM2B_SENSITIVE_DATA(key)
                )
            ),
            template,
        )
        esys.flush_context(primary)
    finally:
        esys.close()

    with open(sealing.SEALED_PUB, "wb") as f:
        f.write(sealed_pub.marshal())
    with open(sealing.SEALED_PRIV, "wb") as f:
        f.write(sealed_priv.marshal())
    print(f"AES key sealed -> {sealing.SEALED_PUB} / {sealing.SEALED_PRIV}")
    print("plaintext key discarded; unsealing now requires a fresh TRUSTED "
          "attestation (payload/play_video.py)")


if __name__ == "__main__":
    main()
