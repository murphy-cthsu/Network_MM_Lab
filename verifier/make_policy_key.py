"""Generate the verifier's policy-authorization key pair (laptop ONLY).

Run this on the verifier host. The PRIVATE key (verifier/policy_key.pem,
gitignored — Constraint 5) is created here and must NEVER leave this
machine: it is what signs unseal authorizations after TRUSTED verdicts,
so a copy on the attester would let a tampered Pi authorize itself.
(The original Phase 1 key pair was generated on the Pi and is retired
for exactly that reason — do not reuse it.)

The PUBLIC key is written to verifier/policy_pub.pem. Hand-transfer it
to the Pi as attester/policy_pub.pem (replacing the retired one there):
attester/seal.py seals the gated secret to PolicyAuthorize(this key),
and payload/play_video.py loads it into the TPM to check the signature.
After rotating, the Pi must re-run seal.py against the new public.

RSA2048/SHA256 per Constraint 7.

Usage: python3 verifier/make_policy_key.py [--force]
"""

import argparse
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

VERIFIER_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_PATH = os.path.join(VERIFIER_DIR, "policy_key.pem")
PUBLIC_PATH = os.path.join(VERIFIER_DIR, "policy_pub.pem")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing key pair (the new public "
                             "must then be re-enrolled and re-sealed on the Pi)")
    args = parser.parse_args()

    if os.path.exists(PRIVATE_PATH) and not args.force:
        raise SystemExit(f"{PRIVATE_PATH} already exists (use --force to "
                         f"rotate; the Pi must then re-run seal.py)")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIVATE_PATH, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    os.chmod(PRIVATE_PATH, 0o600)
    with open(PUBLIC_PATH, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"policy private key: {PRIVATE_PATH} (gitignored, stays on this host)")
    print(f"policy public key:  {PUBLIC_PATH}")
    print("next: hand-transfer the PUBLIC key to the Pi as "
          "attester/policy_pub.pem, then re-run seal.py there")


if __name__ == "__main__":
    main()
