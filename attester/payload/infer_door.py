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
  sudo .venv/bin/python attester/payload/infer_door.py --subject A   # owner test frame
  sudo .venv/bin/python attester/payload/infer_door.py --subject B   # intruder test frame
  sudo .venv/bin/python attester/payload/infer_door.py --camera      # live Pi-camera frame
  sudo .venv/bin/python attester/payload/infer_door.py --image face.jpg
"""

import argparse
import os
import subprocess
import sys
import time

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
ATTESTER_DIR = os.path.dirname(PAYLOAD_DIR)
REPO_ROOT = os.path.dirname(ATTESTER_DIR)
sys.path.insert(0, ATTESTER_DIR)

import agent  # noqa: E402
import gate  # noqa: E402
from recognizer import OWNER_LABEL, Recognizer  # noqa: E402

GATED_PRELUDE = os.path.join(PAYLOAD_DIR, "gated_prelude.sh")
# The LIVE model the door loads and the allowlist pins (a copy of honest.hef;
# tamper/swap_model.sh copies malicious.hef over it). Gitignored generated blob.
DEFAULT_MODEL = os.path.join(ATTESTER_DIR, "models", "face_classifier.hef")
# Deterministic test frames for the scripted (cameraless) demo / warm-up.
TESTSET_DIR = os.path.join(REPO_ROOT, "training", "testset")
DEFAULT_THRESHOLD = 0.5
CONSEQUENCE = "DOOR STAYS LOCKED"


def capture_camera():
    """Grab one still from the Pi camera (imx708) and return it as a PIL image."""
    from PIL import Image
    from picamera2 import Picamera2
    cam = Picamera2()
    cam.configure(cam.create_still_configuration(main={"format": "RGB888"}))
    cam.start()
    time.sleep(1.5)            # let auto-exposure / white-balance settle
    arr = cam.capture_array()  # HxWx3 RGB
    cam.stop()
    cam.close()
    print(f"[door] captured {arr.shape[1]}x{arr.shape[0]} from the Pi camera")
    return Image.fromarray(arr)


def grab_frame(args):
    """Resolve the frame to recognise from the chosen source. The real model
    needs a real frame, so this returns one or exits the door closed.

      --camera     live capture from the Pi camera
      --image PATH a specific image file
      --subject X  the committed test frame training/testset/{A,B}.jpg
                   (deterministic, cameraless — used by the demo + warm-up)
    """
    if args.camera:
        return capture_camera()
    if args.image:
        if not os.path.exists(args.image):
            gate.gate_closed(f"--image {args.image} not found", CONSEQUENCE)
        return args.image
    if args.subject:
        path = os.path.join(TESTSET_DIR, f"{args.subject}.jpg")
        if not os.path.exists(path):
            gate.gate_closed(
                f"--subject {args.subject} needs {path} (pull training/testset/)",
                CONSEQUENCE)
        return path
    gate.gate_closed("no frame source — pass --camera, --image PATH, or "
                     "--subject A|B", CONSEQUENCE)


def _frame_jpeg(frame, max_side=360):
    """Encode whatever grab_frame() returned into a small JPEG for the dashboard."""
    from io import BytesIO
    from PIL import Image
    try:
        if isinstance(frame, str):
            img = Image.open(frame)
        elif isinstance(frame, (bytes, bytearray)):
            img = Image.open(BytesIO(frame))
        elif hasattr(frame, "convert"):       # PIL image
            img = frame
        else:                                  # ndarray
            img = Image.fromarray(frame)
        img = img.convert("RGB")
        w, h = img.size
        if max(w, h) > max_side:
            f = max_side / max(w, h)
            img = img.resize((int(w * f), int(h * f)))
        buf = BytesIO()
        img.save(buf, "JPEG", quality=85)
        return buf.getvalue()
    except Exception:
        return None


def report_door(verifier_url, state, label, conf, source, reason, frame=None):
    """Best-effort: report the door outcome (+ the frame) to the verifier
    dashboard. Never affects the door decision — failures are swallowed."""
    if not verifier_url:
        return
    import json
    import urllib.request
    base = verifier_url.rstrip("/")
    try:
        if frame is not None:
            jpg = _frame_jpeg(frame)
            if jpg:
                urllib.request.urlopen(urllib.request.Request(
                    base + "/door-frame", data=jpg,
                    headers={"Content-Type": "image/jpeg"}), timeout=3).read()
        payload = {"state": state, "label": label,
                   "confidence": round(float(conf), 4),
                   "source": source, "reason": reason}
        urllib.request.urlopen(urllib.request.Request(
            base + "/door", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}), timeout=3).read()
    except Exception as e:
        print(f"[door] (dashboard update skipped: {e})")


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
                        help="the live .hef the door gates on (gitignored; set "
                             "by dev/prepare_demo_p2.sh from honest.hef)")
    parser.add_argument("--subject", choices=["A", "B"],
                        help="recognise the committed test frame "
                             "training/testset/{A,B}.jpg (deterministic, no "
                             "camera) — A=owner, B=intruder")
    parser.add_argument("--image", help="recognise a specific image file")
    parser.add_argument("--camera", action="store_true",
                        help="capture a live frame from the Pi camera (imx708)")
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
    parser.add_argument("--measure-only", action="store_true",
                        help="warm-up: run the prelude + model read + frame "
                             "capture + inference so every boundary file is "
                             "IMA-measured, then exit 0 WITHOUT unsealing "
                             "(used by dev/prepare_demo_p2.sh)")
    args = parser.parse_args()

    # step 1: run the watched helper so IMA measures its CURRENT content
    subprocess.run([GATED_PRELUDE], check=True)

    # step 2: load the model. Recognizer.__init__ READS the whole file as root,
    # so the model hash is extended into PCR 10 before any unseal. If the model
    # was swapped, THIS is what forces its new hash into the log.
    try:
        recognizer = Recognizer(args.model)
    except FileNotFoundError as e:
        sys.exit(f"ERROR: {e}")
    print(f"[door] model loaded: {os.path.basename(args.model)} "
          f"({recognizer.model_size} bytes, sha256 "
          f"{recognizer.model_sha256[:16]}…)")

    # step 3: recognise. Not the owner -> door stays locked, NO unseal attempt.
    frame = grab_frame(args)
    label, conf = recognizer.predict(frame)
    print(f"[door] recognizer verdict: label={label} confidence={conf:.2f} "
          f"(threshold {args.threshold})")
    # warm-up: every boundary file (prelude, model, camera/NPU libs) is now
    # measured into PCR 10. Exit before the unseal so a random warm-up frame can
    # never burn a real authorization (docs: measure BEFORE the bundle).
    if args.measure_only:
        print("[door] --measure-only: boundary measured, skipping unseal/actuate")
        sys.exit(0)

    # human-readable frame source for the dashboard
    source = ("camera" if args.camera
              else f"image:{os.path.basename(args.image)}" if args.image
              else f"subject {args.subject}" if args.subject else "?")

    if not (label == OWNER_LABEL and conf > args.threshold):
        print("[door] not the owner — not requesting an unseal")
        report_door(args.verifier_url, "locked", label, conf, source,
                    "face not recognised as the owner", frame)
        actuate(False, args.gpio, args.gpio_pin)
        gate.gate_closed("face not recognised as the owner", CONSEQUENCE)

    # step 4: owner recognised -> unseal the lock credential. Identical
    # PolicyAuthorize unseal + live-PCR retry as the Phase 1 clip key; the
    # door only opens if the verifier signed for THIS (model-covered) PCR state.
    try:
        credential = gate.unseal_with_retry(
            args.verifier_url, args.max_gate_attempts,
            secret_label="lock credential", consequence=CONSEQUENCE,
        )
    except SystemExit:
        # gate_closed() inside unseal_with_retry exits 3: TPM refused / verifier
        # COMPROMISED. The owner WAS recognised, but integrity failed — report
        # the locked door (this is the model-swap headline) before re-raising.
        report_door(args.verifier_url, "locked", label, conf, source,
                    "owner recognised, but device failed attestation — "
                    "unseal refused", frame)
        raise

    # step 5: actuate. Reaching here proves we hold the unsealed credential —
    # the unlock cryptographically depends on it, not on the if above.
    print(f"[door] lock credential released ({len(credential)} bytes) — "
          f"owner recognised AND device attested clean")
    report_door(args.verifier_url, "unlocked", label, conf, source,
                "owner recognised and device attested clean", frame)
    actuate(True, args.gpio, args.gpio_pin)
    sys.exit(0)


if __name__ == "__main__":
    main()
