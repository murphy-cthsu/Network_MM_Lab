"""Phase 0 gate: end-to-end ESAPI quote sanity check (Constraint 8).

Transient-only — creates a primary + restricted-signing RSA2048/SHA256 AK
(same templates as attester/provision.py), quotes PCR 10 with a fresh test
nonce, then verifies the signature and nonce locally. Nothing is persisted
in the TPM and no files are written, so it is safe to run at any time on
the laptop (swtpm) or the Pi (real TPM).

Usage: python3 dev/quote_sanity.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "attester"))
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from tpm2_pytss import (  # noqa: E402
    ESYS_TR,
    TPM2B_DATA,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE,
    TPM2_ALG,
    TPML_PCR_SELECTION,
    TPMS_ATTEST,
    TPMT_SIG_SCHEME,
)
from tpmconn import open_esapi  # noqa: E402

PRIMARY_TEMPLATE = TPM2B_PUBLIC.parse(
    "rsa2048:null:aes128cfb",
    objectAttributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
                     "|restricted|decrypt|noda",
)
AK_TEMPLATE = TPM2B_PUBLIC.parse(
    "rsa2048:rsassa-sha256:null",
    objectAttributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
                     "|restricted|sign",
)

nonce = os.urandom(16)
esys = open_esapi()
try:
    _, _, digests = esys.pcr_read(TPML_PCR_SELECTION.parse("sha256:10"))
    print(f"sha256 PCR 10 = {bytes(digests[0]).hex()}")

    primary, _, _, _, _ = esys.create_primary(
        TPM2B_SENSITIVE_CREATE(), PRIMARY_TEMPLATE, ESYS_TR.ENDORSEMENT
    )
    ak_priv, ak_pub, _, _, _ = esys.create(
        primary, TPM2B_SENSITIVE_CREATE(), AK_TEMPLATE
    )
    ak = esys.load(primary, ak_priv, ak_pub)
    esys.flush_context(primary)
    print("transient RSA2048 restricted-signing AK created")

    quoted, signature = esys.quote(
        ak,
        TPML_PCR_SELECTION.parse("sha256:10"),
        TPM2B_DATA(nonce),
        TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
    )
    esys.flush_context(ak)
finally:
    esys.close()

attest_blob = bytes(quoted)
attest, _ = TPMS_ATTEST.unmarshal(attest_blob)
assert bytes(attest.extraData) == nonce, "nonce not echoed in quote extraData"
print(f"quote OK: {len(attest_blob)}-byte TPMS_ATTEST, nonce echoed in extraData")

pub = serialization.load_pem_public_key(ak_pub.publicArea.to_pem())
pub.verify(
    bytes(signature.signature.rsassa.sig),
    attest_blob,
    padding.PKCS1v15(),
    hashes.SHA256(),
)
print("signature verified locally against the AK public (RSASSA/SHA256)")
print("PASS: ESAPI quote over PCR 10 with an RSA2048 AK works")
