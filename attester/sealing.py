"""Shared TPM plumbing for the sealed-secret gate (seal.py + play_video.py).

Sealing design — why NOT a plain PolicyPCR seal:

PCR 10 is LIVE under ima_policy=tcb: every first read-by-root / exec of a
file extends it, it differs every boot, and it can never be rewound. A
secret sealed directly to one PCR-10 value would stop unsealing the moment
any legitimate new file is measured, and re-sealing would require keeping
the secret in the clear somewhere — defeating the seal. A "stable subset"
policy (PCRs 0-7) is no better: the Pi has no measured firmware boot, so
those PCRs are constant zeros and bind nothing.

Instead the secret is sealed ONCE to a PolicyAuthorize policy naming the
VERIFIER's policy key (attester/policy_pub.pem). Unsealing requires, in
one TPM policy session:
  1. PolicyPCR        — binds the session to the CURRENT PCR-10 value
  2. VerifySignature  — the verifier's signature over exactly that value's
                        PolicyPCR digest (issued only with a TRUSTED
                        verdict, transported in the /evidence response)
  3. PolicyAuthorize  — the TPM accepts the signed digest as satisfying
                        the seal policy

So the TPM enforces: "release the key only while PCR 10 holds a value the
verifier has attested clean." Tampering closes the gate twice over: the
verifier refuses to sign the post-tamper state (allowlist failure), and
every previously issued authorization dies because PolicyPCR no longer
matches once IMA extends the tampered hash. Legitimate PCR drift just
needs a fresh attestation — no re-sealing, no secret ever in the clear.
This is the TPM 2.0 flexible-PCR-policy pattern (as used by e.g. systemd
pcrlock and Keylime payloads), not something invented here.
"""

import hashlib
import os

from tpm2_pytss import (
    ESYS_TR,
    TPM2B_DIGEST,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE,
    TPM2_ALG,
    TPM2_RH,
    TPM2_SE,
    TPM2_ST,
    TPML_PCR_SELECTION,
    TPMT_PUBLIC,
    TPMT_SIGNATURE,
    TPMT_SYM_DEF,
    TPMT_TK_VERIFIED,
)

ATTESTER_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY_PUB = os.path.join(ATTESTER_DIR, "policy_pub.pem")
OUT_DIR = os.path.join(ATTESTER_DIR, "out")
SEALED_PUB = os.path.join(OUT_DIR, "sealed_key.pub")
SEALED_PRIV = os.path.join(OUT_DIR, "sealed_key.priv")
CLIP_ENC = os.path.join(OUT_DIR, "clip.enc")
PCR_SELECTION = "sha256:10"

# Same storage-primary template as provisioning: deterministic, so any
# process can recreate the identical parent and load the sealed blobs.
STORAGE_PRIMARY_TEMPLATE = TPM2B_PUBLIC.parse(
    "rsa2048:null:aes128cfb",
    objectAttributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
                     "|restricted|decrypt|noda",
)


def create_storage_primary(esys):
    primary, _, _, _, _ = esys.create_primary(
        TPM2B_SENSITIVE_CREATE(), STORAGE_PRIMARY_TEMPLATE, ESYS_TR.OWNER
    )
    return primary


def load_policy_pub(esys, pem_path=DEFAULT_POLICY_PUB):
    """Load the verifier's policy public key into the TPM (owner hierarchy,
    so VerifySignature tickets are usable by PolicyAuthorize) and return
    (handle, name). seal.py and play_video.py MUST build the public area
    identically or the names — and therefore the policies — diverge."""
    with open(pem_path, "rb") as f:
        public = TPMT_PUBLIC.from_pem(f.read())
    handle = esys.load_external(
        TPM2B_PUBLIC(publicArea=public), None, ESYS_TR.RH_OWNER
    )
    return handle, esys.tr_get_name(handle)


def policy_authorize_digest(esys, key_name):
    """The seal-time authPolicy: a trial-session PolicyAuthorize naming the
    verifier's key. No PCR value appears here — that's the whole point."""
    trial = esys.start_auth_session(
        tpm_key=ESYS_TR.NONE, bind=ESYS_TR.NONE,
        session_type=TPM2_SE.TRIAL,
        symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
        auth_hash=TPM2_ALG.SHA256,
    )
    try:
        esys.policy_authorize(
            trial, b"", b"", key_name,
            TPMT_TK_VERIFIED(tag=TPM2_ST.VERIFIED, hierarchy=TPM2_RH.NULL),
        )
        return bytes(esys.policy_get_digest(trial))
    finally:
        esys.flush_context(trial)


def start_authorized_pcr_session(esys, approval, policy_pub_path=DEFAULT_POLICY_PUB):
    """Build the real unseal session: PolicyPCR(current sha256:10) +
    PolicyAuthorize(verifier-signed digest from `approval`). Raises
    TSS2_Exception if the current PCR no longer matches the approved value
    or the signature doesn't verify — i.e. the gate is closed."""
    import base64

    approved = base64.b64decode(approval["approved_policy_b64"])
    ref = base64.b64decode(approval.get("policy_ref_b64", ""))
    sig_bytes = base64.b64decode(approval["policy_signature_b64"])

    signature = TPMT_SIGNATURE(sigAlg=TPM2_ALG.RSASSA)
    signature.signature.rsassa.hash = TPM2_ALG.SHA256
    signature.signature.rsassa.sig = sig_bytes

    session = esys.start_auth_session(
        tpm_key=ESYS_TR.NONE, bind=ESYS_TR.NONE,
        session_type=TPM2_SE.POLICY,
        symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
        auth_hash=TPM2_ALG.SHA256,
    )
    key_handle = None
    try:
        esys.policy_pcr(
            session, TPM2B_DIGEST(), TPML_PCR_SELECTION.parse(PCR_SELECTION)
        )
        key_handle, key_name = load_policy_pub(esys, policy_pub_path)
        a_hash = hashlib.sha256(approved + ref).digest()
        ticket = esys.verify_signature(key_handle, a_hash, signature)
        esys.policy_authorize(session, approved, ref, key_name, ticket)
        return session
    except Exception:
        esys.flush_context(session)
        raise
    finally:
        if key_handle is not None:
            esys.flush_context(key_handle)
