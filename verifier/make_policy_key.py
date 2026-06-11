"""Generate the verifier's policy-authorization key pair (one-time, laptop).

The PRIVATE key (verifier/policy_key.pem, gitignored — Constraint 5) stays
with the verifier and signs unseal authorizations after TRUSTED verdicts.
The PUBLIC key (attester/policy_pub.pem, committed) is enrolled on the Pi:
attester/seal.py seals the gated secret to PolicyAuthorize(this key), and
payload/play_video.py loads it into the TPM to check the signature.

RSA2048/SHA256 per Constraint 7.

Usage: python3 verifier/make_policy_key.py [--force]
"""

import argparse
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

VERIFIER_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_PATH = os.path.join(VERIFIER_DIR, "policy_key.pem")
PUBLIC_PATH = os.path.join(
    os.path.dirname(VERIFIER_DIR), "attester", "policy_pub.pem"
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing key pair (re-sealing on "
                             "the Pi is then required)")
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
    print(f"policy key written to {PRIVATE_PATH} (private, gitignored)")
    print(f"policy public written to {PUBLIC_PATH} (enroll on the Pi)")


if __name__ == "__main__":
    main()
