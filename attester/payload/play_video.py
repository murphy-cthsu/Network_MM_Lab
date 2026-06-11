"""Phase 1 gated function: unseal the AES key, decrypt the clip, play it.

The gate (attester/sealing.py documents the policy design):
  1. exec gated_prelude.sh — the demo's watched measured executable. If it
     was tampered with, this exec is what makes IMA measure the new hash
     (BPRM_CHECK), extending PCR 10 BEFORE the unseal attempt, so the gate
     decision always reflects the binary actually on disk.
  2. take the verifier's unseal authorization from the latest /evidence
     response (saved by agent.py). No authorization (verdict was
     COMPROMISED) -> fall back to the last TRUSTED one, which the TPM then
     rejects because PCR 10 moved — demonstrating the gate is enforced by
     the TPM, not by this script being polite.
  3. TPM policy session: PolicyPCR(current sha256:10) + VerifySignature +
     PolicyAuthorize -> unseal.
  4. LIVE-PCR RETRY: PCR 10 can legitimately move between the verdict and
     the unseal (any new root file-read anywhere). When the TPM refuses,
     re-attest against the laptop verifier -> fresh authorization ->
     re-unseal, up to MAX_GATE_ATTEMPTS, one clear log line per retry.
     A COMPROMISED verdict during a retry short-circuits to GATE CLOSED —
     that is refusal, not drift. Re-attesting needs root (the IMA log),
     so run under sudo for the self-healing path.
  5. AES-256-GCM decrypt clip.enc and play it (ffplay when a display is
     available, otherwise a full ffmpeg decode to /dev/null counts as
     playback for headless runs).

Exit codes: 0 played, 3 gate closed (unseal refused), 1 other error.
Usage: sudo .venv/bin/python attester/payload/play_video.py [--no-display]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
ATTESTER_DIR = os.path.dirname(PAYLOAD_DIR)
sys.path.insert(0, ATTESTER_DIR)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from tpm2_pytss import TPM2B_PRIVATE, TPM2B_PUBLIC, TSS2_Exception  # noqa: E402

import agent  # noqa: E402
import sealing  # noqa: E402
from tpmconn import open_esapi  # noqa: E402

GATED_PRELUDE = os.path.join(PAYLOAD_DIR, "gated_prelude.sh")
# both live on tmpfs — see agent.DEFAULT_APPROVAL for why
APPROVAL_PATH = agent.DEFAULT_APPROVAL
LAST_GOOD_PATH = os.path.join(os.path.dirname(APPROVAL_PATH),
                              "last_good_approval.json")
GCM_NONCE_BYTES = 12
DEFAULT_GATE_ATTEMPTS = 5


def gate_closed(why):
    print(f"GATE CLOSED: {why}. NO PLAYBACK.")
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
    if os.path.exists(LAST_GOOD_PATH):
        with open(LAST_GOOD_PATH) as f:
            stale = json.load(f).get("approval")
        if stale:
            print("[gate] trying the LAST TRUSTED authorization so the TPM "
                  "itself gets to refuse")
            return stale, "stale"
    return None, None


def unseal_key(approval):
    esys = open_esapi()
    try:
        primary, persistent = sealing.get_storage_primary(esys)
        with open(sealing.SEALED_PRIV, "rb") as f:
            priv, _ = TPM2B_PRIVATE.unmarshal(f.read())
        with open(sealing.SEALED_PUB, "rb") as f:
            pub, _ = TPM2B_PUBLIC.unmarshal(f.read())
        sealed = esys.load(primary, priv, pub)
        esys.tr_close(primary) if persistent else esys.flush_context(primary)
        session = sealing.start_authorized_pcr_session(esys, approval)
        try:
            return bytes(esys.unseal(sealed, session1=session))
        finally:
            esys.flush_context(session)
    finally:
        esys.close()


def unseal_with_retry(verifier_url, max_attempts):
    """Bounded live-PCR retry: TPM refusal -> re-attest -> re-authorize ->
    re-unseal. Returns the unsealed key or exits via gate_closed()."""
    approval, kind = pick_approval()
    for attempt in range(1, max_attempts + 1):
        if approval is None:
            gate_closed("no unseal authorization available — attest first "
                        "(attester/agent.py)")
        try:
            key = unseal_key(approval)
            print(f"unseal OK on gate attempt {attempt} ({kind} "
                  f"authorization) — releasing the clip key")
            return key
        except TSS2_Exception as e:
            print(f"[gate] unseal attempt {attempt}/{max_attempts} — "
                  f"TPM refused the {kind} authorization: {e}")
        if attempt == max_attempts:
            gate_closed(f"TPM refused {max_attempts} time(s) — PCR 10 "
                        f"does not carry a verifier-attested value")
        print(f"[gate] retry {attempt}/{max_attempts - 1}: PCR 10 may "
              f"have moved between verdict and unseal — re-attesting at "
              f"{verifier_url} for a fresh authorization")
        if os.geteuid() != 0:
            gate_closed("cannot re-attest: the IMA log needs root — run "
                        "this payload under sudo for the self-healing path")
        try:
            result = agent.attest(verifier_url)
        except Exception as e:
            gate_closed(f"re-attestation failed: {e}")
        if result.get("verdict") != "TRUSTED" or not result.get("approval"):
            gate_closed(f"verifier verdict {result.get('verdict')} — it "
                        f"will not authorize this PCR state")
        approval, kind = result["approval"], "fresh"


def play(clip_path, no_display):
    if not no_display and (os.environ.get("DISPLAY")
                           or os.environ.get("WAYLAND_DISPLAY")):
        cmd = ["ffplay", "-loglevel", "error", "-autoexit", clip_path]
        mode = "ffplay"
    else:
        cmd = ["ffmpeg", "-loglevel", "error", "-i", clip_path,
               "-f", "null", "-"]
        mode = "headless full decode"
    subprocess.run(cmd, check=True)
    print(f"PLAYBACK OK ({mode})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-display", action="store_true",
                        help="decode-only playback (for SSH sessions)")
    parser.add_argument("--verifier-url", default=agent.DEFAULT_VERIFIER_URL,
                        help="laptop verifier for the live-PCR re-attest "
                             "retry (env: VERIFIER_URL)")
    parser.add_argument("--max-gate-attempts", type=int,
                        default=DEFAULT_GATE_ATTEMPTS,
                        help="1 = no re-attest after a TPM refusal (the "
                             "demo's tamper cycles use this: the verdict "
                             "is already known, a second attestation just "
                             "costs time)")
    args = parser.parse_args()

    # step 1: run the watched helper so IMA measures its CURRENT content
    subprocess.run([GATED_PRELUDE], check=True)

    key = unseal_with_retry(args.verifier_url, args.max_gate_attempts)

    with open(sealing.CLIP_ENC, "rb") as f:
        blob = f.read()
    clip = AESGCM(key).decrypt(blob[:GCM_NONCE_BYTES],
                               blob[GCM_NONCE_BYTES:], None)
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as f:
        f.write(clip)
        tmp = f.name
    try:
        play(tmp, args.no_display)
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    main()
