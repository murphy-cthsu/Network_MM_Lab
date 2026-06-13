"""Phase 2 gated function: a face-recognition DOOR LOCK.

The door opens only when BOTH hold:
  1. the camera recognises the owner (Recognizer.predict -> label "A", conf >
     threshold), AND
  2. the device passes remote attestation that COVERS the model file — i.e. the
     verifier signs an unseal authorization for the current PCR-10 state, which
     only happens when the measured model hash is allowlisted (clean).

Swapping the model (tamper/swap_model.sh) changes its bytes -> IMA measures a new
hash -> allowlist mismatch -> COMPROMISED -> the verifier refuses to sign -> the
lock credential stays sealed -> the door stays locked. A model that still
"recognises A" behaviourally is caught anyway, because integrity is pinned to the
bytes, not the behaviour (docs/PHASE2.md thesis).

Mirrors attester/payload/play_video.py step for step; the only differences are
the gated input (a model + a camera frame instead of an encrypted clip) and the
actuation (unlock vs play). The hard parts — the PolicyAuthorize unseal and the
live-PCR retry — are shared in attester/gate.py.

Flow (mirrors play_video.py):
  1. exec gated_prelude.sh — the demo's watched measured helper. IMA measures its
     current content (BPRM_CHECK), extending PCR 10 before the gate decision.
  2. construct Recognizer(model_path), which READS the model file as root so its
     hash is extended into PCR 10 BEFORE any unseal (the Phase 2 measurement).
  3. run predict(frame); require label == "A" and conf > threshold. If not, the
     door stays locked and we NEVER attempt an unseal (B is rejected here).
  4. ONLY then unseal the lock credential via the existing PolicyAuthorize
     session + live-PCR retry (gate.unseal_with_retry, exactly as play_video).
  5. "actuate": print DOOR UNLOCKED / DOOR LOCKED. Real GPIO is behind --gpio
     and stays stubbed by default; the unlock is cryptographically gated by the
     unsealed credential, not by a bare `if conf > T` (docs/PHASE2.md D2).

Exit codes (mirror play_video.py): 0 door unlocked, 3 gate closed (not the owner,
or TPM refused the unseal), 1 other error.
Usage:
  sudo .venv/bin/python attester/payload/infer_door.py --subject A   # owner
  sudo .venv/bin/python attester/payload/infer_door.py --subject B   # intruder
  sudo .venv/bin/python attester/payload/infer_door.py --image face.jpg --subject A
"""

import argparse
import os
import subprocess
import sys

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
ATTESTER_DIR = os.path.dirname(PAYLOAD_DIR)
sys.path.insert(0, ATTESTER_DIR)

import agent  # noqa: E402
import gate  # noqa: E402
from recognizer import OWNER_LABEL, Recognizer  # noqa: E402

GATED_PRELUDE = os.path.join(PAYLOAD_DIR, "gated_prelude.sh")
DEFAULT_MODEL = os.path.join(ATTESTER_DIR, "models", "owner_model.tflite")
DEFAULT_THRESHOLD = 0.5
CONSEQUENCE = "DOOR STAYS LOCKED"


def grab_frame(image_path, use_camera):
    """Best-effort frame load. The placeholder recognizer ignores the frame, so
    a missing camera/image must NOT block the demo — we return whatever we have
    (raw bytes, or None) and let predict() decide."""
    if use_camera:
        # Real camera capture lands here when a model is wired in. Until then we
        # do not require a camera to be present (docs: "do not block on a camera").
        print("[door] --camera requested; placeholder uses --subject for the "
              "decision (no live capture needed)")
        return None
    if image_path and os.path.exists(image_path):
        with open(image_path, "rb") as f:
            return f.read()
    if image_path:
        print(f"[door] --image {image_path} not found; placeholder decides from "
              f"--subject anyway")
    return None


def actuate(unlocked, use_gpio, gpio_pin):
    """Drive the lock. Real GPIO is opt-in (--gpio) and degrades gracefully;
    by default this is a stub that just prints the door state."""
    if unlocked:
        print("DOOR UNLOCKED")
    else:
        print("DOOR LOCKED")
    if not use_gpio:
        return
    try:
        from gpiozero import OutputDevice  # imported lazily: not needed in dev
    except Exception as e:
        print(f"[door] --gpio set but gpiozero unavailable ({e}); actuation "
              f"stubbed (state printed above)")
        return
    relay = OutputDevice(gpio_pin, active_high=True, initial_value=False)
    relay.value = 1 if unlocked else 0
    print(f"[door] GPIO pin {gpio_pin} driven {'HIGH (unlock)' if unlocked else 'LOW (lock)'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="model file the door gates on (gitignored; "
                             "generate a placeholder with "
                             "dev/gen_placeholder_models.sh)")
    parser.add_argument("--subject", choices=["A", "B"],
                        help="placeholder decision hint (A=owner, B=intruder); "
                             "the real recognizer ignores this and runs "
                             "inference (env: SUBJECT)")
    parser.add_argument("--image", help="frame to recognise (default mode; "
                                        "CPU-friendly, no camera needed)")
    parser.add_argument("--camera", action="store_true",
                        help="capture from a camera instead of --image")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help="minimum P(A) to admit (default %(default)s)")
    parser.add_argument("--gpio", action="store_true",
                        help="actuate a real GPIO relay (default: stubbed, "
                             "door state is only printed)")
    parser.add_argument("--gpio-pin", type=int, default=17,
                        help="BCM pin for the lock relay when --gpio is set")
    parser.add_argument("--verifier-url", default=agent.DEFAULT_VERIFIER_URL,
                        help="laptop verifier for the live-PCR re-attest retry "
                             "(env: VERIFIER_URL)")
    parser.add_argument("--max-gate-attempts", type=int,
                        default=gate.DEFAULT_GATE_ATTEMPTS,
                        help="1 = no re-attest after a TPM refusal (the demo's "
                             "tamper cycles use this)")
    args = parser.parse_args()

    # step 1: run the watched helper so IMA measures its CURRENT content
    subprocess.run([GATED_PRELUDE], check=True)

    # step 2: load the model. Recognizer.__init__ READS the whole file as root,
    # so the model hash is extended into PCR 10 before any unseal. If the model
    # was swapped, THIS is what forces its new hash into the log.
    try:
        recognizer = Recognizer(args.model, subject=args.subject)
    except FileNotFoundError as e:
        sys.exit(f"ERROR: {e}")
    print(f"[door] model loaded: {os.path.basename(args.model)} "
          f"({recognizer.model_size} bytes, sha256 "
          f"{recognizer.model_sha256[:16]}…)")

    # step 3: recognise. Not the owner -> door stays locked, NO unseal attempt.
    frame = grab_frame(args.image, args.camera)
    label, conf = recognizer.predict(frame)
    print(f"[door] recognizer verdict: label={label} confidence={conf:.2f} "
          f"(threshold {args.threshold})")
    if not (label == OWNER_LABEL and conf > args.threshold):
        print("[door] not the owner — not requesting an unseal")
        actuate(False, args.gpio, args.gpio_pin)
        gate.gate_closed("face not recognised as the owner", CONSEQUENCE)

    # step 4: owner recognised -> unseal the lock credential. Identical
    # PolicyAuthorize unseal + live-PCR retry as the Phase 1 clip key; the
    # door only opens if the verifier signed for THIS (model-covered) PCR state.
    credential = gate.unseal_with_retry(
        args.verifier_url, args.max_gate_attempts,
        secret_label="lock credential", consequence=CONSEQUENCE,
    )

    # step 5: actuate. Reaching here proves we hold the unsealed credential —
    # the unlock cryptographically depends on it, not on the if above.
    print(f"[door] lock credential released ({len(credential)} bytes) — "
          f"owner recognised AND device attested clean")
    actuate(True, args.gpio, args.gpio_pin)
    sys.exit(0)


if __name__ == "__main__":
    main()
