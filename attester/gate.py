"""Shared TPM-unseal gate for the gated payloads (play_video.py, infer_door.py).

Extracted verbatim from the Phase 1 play_video.py so Phase 2's door payload
reuses the EXACT PolicyAuthorize unseal + live-PCR retry logic rather than
duplicating it. The TPM mechanism is identical for every gated function; only
the human-facing strings differ ("clip key" vs "lock credential", "NO PLAYBACK"
vs "DOOR STAYS LOCKED"), so those are parameters.

The gate (attester/sealing.py documents the policy design):
  1. The caller first runs the watched helper (gated_prelude.sh) and reads the
     gated inputs as root, so IMA measures the CURRENT on-disk state into PCR 10
     BEFORE this gate runs — the decision always reflects what is on disk.
  2. take the verifier's unseal authorization from the latest /evidence response
     (saved by agent.py). No authorization (verdict was COMPROMISED) -> fall
     back to the last TRUSTED one, which the TPM then rejects because PCR 10
     moved — proving the gate is enforced by the TPM, not by being polite.
  3. TPM policy session: PolicyPCR(current sha256:10) + VerifySignature +
     PolicyAuthorize -> unseal.
  4. LIVE-PCR RETRY: PCR 10 can legitimately move between the verdict and the
     unseal (any new root file-read anywhere — a busy inference pipeline makes
     this MORE likely). When the TPM refuses, re-attest against the laptop
     verifier -> fresh authorization -> re-unseal, up to max_attempts, one clear
     log line per retry. A COMPROMISED verdict during a retry short-circuits to
     gate-closed — that is refusal, not drift. Re-attesting needs root (the IMA
     log), so run the payload under sudo for the self-healing path.
"""

import json
import os
import sys

from tpm2_pytss import TPM2B_PRIVATE, TPM2B_PUBLIC, TSS2_Exception

import agent
import sealing
from tpmconn import open_esapi

# both live on tmpfs — see agent.DEFAULT_APPROVAL for why
APPROVAL_PATH = agent.DEFAULT_APPROVAL
LAST_GOOD_PATH = os.path.join(os.path.dirname(APPROVAL_PATH),
                              "last_good_approval.json")
DEFAULT_GATE_ATTEMPTS = 5


def gate_closed(why, consequence="NO PLAYBACK"):
    print(f"GATE CLOSED: {why}. {consequence}.")
    sys.exit(3)


def pick_approval():
    """Latest verifier response, falling back to the last TRUSTED one."""
    response = {}
    if os.path.exists(APPROVAL_PATH):
        with open(APPROVAL_PATH) as f:
            response = json.load(f)
    approval = response.get("approval")
    if approval:
        if response.get("verdict") == "TRUSTED":
            try:
                with open(LAST_GOOD_PATH, "w") as f:
                    json.dump(response, f)
            except OSError:
                pass  # owned by a previous sudo run; keepsake only
        return approval, "fresh"
    print(f"[gate] verifier verdict was {response.get('verdict', 'absent')} "
          f"— no unseal authorization issued")
    # if verdict is explicitly COMPROMISED, don't bother trying the stale
    # authorization — the TPM will refuse it and we'd just waste time
    if response.get("verdict") == "COMPROMISED":
        return None, None
    if os.path.exists(LAST_GOOD_PATH):
        with open(LAST_GOOD_PATH) as f:
            stale = json.load(f).get("approval")
        if stale:
            print("[gate] trying the LAST TRUSTED authorization so the TPM "
                  "itself gets to refuse")
            return stale, "stale"
    return None, None


def unseal_secret(approval):
    """Unseal the sealed secret using a verifier-authorized PCR session.

    Same blobs and policy for every gated function — the secret is opaque
    here (an AES clip key in Phase 1, a lock credential in Phase 2)."""
    esys = open_esapi()
    try:
        primary = sealing.create_storage_primary(esys)
        with open(sealing.SEALED_PRIV, "rb") as f:
            priv, _ = TPM2B_PRIVATE.unmarshal(f.read())
        with open(sealing.SEALED_PUB, "rb") as f:
            pub, _ = TPM2B_PUBLIC.unmarshal(f.read())
        sealed = esys.load(primary, priv, pub)
        esys.flush_context(primary)
        session = sealing.start_authorized_pcr_session(esys, approval)
        try:
            return bytes(esys.unseal(sealed, session1=session))
        finally:
            esys.flush_context(session)
    finally:
        esys.close()


def unseal_with_retry(verifier_url, max_attempts,
                      secret_label="clip key", consequence="NO PLAYBACK"):
    """Bounded live-PCR retry: TPM refusal -> re-attest -> re-authorize ->
    re-unseal. Returns the unsealed secret or exits via gate_closed()."""
    approval, kind = pick_approval()
    for attempt in range(1, max_attempts + 1):
        if approval is None:
            gate_closed("no unseal authorization available — attest first "
                        "(attester/agent.py)", consequence)
        try:
            secret = unseal_secret(approval)
            print(f"unseal OK on gate attempt {attempt} ({kind} "
                  f"authorization) — releasing the {secret_label}")
            return secret
        except TSS2_Exception as e:
            print(f"[gate] unseal attempt {attempt}/{max_attempts} — "
                  f"TPM refused the {kind} authorization: {e}")
        if attempt == max_attempts:
            gate_closed(f"TPM refused {max_attempts} time(s) — PCR 10 "
                        f"does not carry a verifier-attested value",
                        consequence)
        print(f"[gate] retry {attempt}/{max_attempts - 1}: PCR 10 may "
              f"have moved between verdict and unseal — re-attesting at "
              f"{verifier_url} for a fresh authorization")
        if os.geteuid() != 0:
            gate_closed("cannot re-attest: the IMA log needs root — run "
                        "this payload under sudo for the self-healing path",
                        consequence)
        try:
            result = agent.attest(verifier_url)
        except Exception as e:
            gate_closed(f"re-attestation failed: {e}", consequence)
        if result.get("verdict") != "TRUSTED" or not result.get("approval"):
            gate_closed(f"verifier verdict {result.get('verdict')} — it "
                        f"will not authorize this PCR state", consequence)
        approval, kind = result["approval"], "fresh"
