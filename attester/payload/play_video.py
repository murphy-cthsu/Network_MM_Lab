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
import os
import subprocess
import sys
import tempfile
import urllib.request

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
ATTESTER_DIR = os.path.dirname(PAYLOAD_DIR)
sys.path.insert(0, ATTESTER_DIR)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

import agent  # noqa: E402
import gate  # noqa: E402
import sealing  # noqa: E402

GATED_PRELUDE = os.path.join(PAYLOAD_DIR, "gated_prelude.sh")
GCM_NONCE_BYTES = 12

# The unseal + live-PCR retry machinery lives in attester/gate.py and is
# shared with the Phase 2 door payload (infer_door.py) — Phase 1 just keeps
# the clip-key wording via gate.unseal_with_retry's defaults.


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
                        default=gate.DEFAULT_GATE_ATTEMPTS,
                        help="1 = no re-attest after a TPM refusal (the "
                             "demo's tamper cycles use this: the verdict "
                             "is already known, a second attestation just "
                             "costs time)")
    args = parser.parse_args()

    # step 1: run the watched helper so IMA measures its CURRENT content
    subprocess.run([GATED_PRELUDE], check=True)

    key = gate.unseal_with_retry(args.verifier_url, args.max_gate_attempts)

    with open(sealing.CLIP_ENC, "rb") as f:
        blob = f.read()
    clip = AESGCM(key).decrypt(blob[:GCM_NONCE_BYTES],
                               blob[GCM_NONCE_BYTES:], None)

    # push the decrypted clip to the verifier so the dashboard can play it
    try:
        req = urllib.request.Request(
            f"{args.verifier_url}/upload-clip",
            data=clip,
            method="POST",
            headers={"Content-Type": "video/mp4"},
        )
        urllib.request.urlopen(req, timeout=30)
        print(f"clip uploaded to verifier ({len(clip)} bytes)")
    except Exception as e:
        print(f"[warn] could not upload clip to verifier: {e}")

    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as f:
        f.write(clip)
        tmp = f.name
    try:
        play(tmp, args.no_display)
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    main()