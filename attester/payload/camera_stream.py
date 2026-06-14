"""Minimal camera stream + recognition endpoint (runs ON THE PI).

This has NO web page of its own. It only exposes the camera so the EXISTING
laptop dashboard (verifier/server.py) can proxy the live feed and relay capture
requests. Reuses attester/payload/recognizer.py unchanged.

  GET  /stream   -> MJPEG live feed from the Pi camera (imx708 via Picamera2)
  POST /capture  -> grab the current frame, run Recognizer.predict(), return
                    {label, confidence, recognized, image(base64 jpeg)} as JSON

Place this file in attester/payload/ (next to recognizer.py) and run on the Pi:

  # real run (needs the Hailo NPU + the live model):
  sudo .venv/bin/python attester/payload/camera_stream.py --host 0.0.0.0 --port 8001

  # UI/flow testing without the NPU/camera:
  python attester/payload/camera_stream.py --host 0.0.0.0 --port 8001 \
        --stub-camera --stub-recognizer

Then point the laptop verifier at it (see verifier/server.py --camera-url).
"""

import argparse
import base64
import io
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

from flask import Flask, Response, jsonify, request

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
ATTESTER_DIR = os.path.dirname(PAYLOAD_DIR)
REPO_ROOT = os.path.dirname(ATTESTER_DIR)
sys.path.insert(0, PAYLOAD_DIR)
sys.path.insert(0, ATTESTER_DIR)

from recognizer import OWNER_LABEL, NOT_OWNER_LABEL  # noqa: E402

DEFAULT_MODEL = os.path.join(ATTESTER_DIR, "models", "face_classifier.hef")
DEFAULT_THRESHOLD = 0.5
DEFAULT_SIZE = (640, 480)
INFER_DOOR = os.path.join(PAYLOAD_DIR, "infer_door.py")

# set in main(): so /run-door can point infer_door at THIS server's /frame
SELF_PORT = 8001
VERIFIER_URL = None   # forwarded to infer_door --verifier-url if set

app = Flask(__name__)


@app.after_request
def _cors(resp):
    # harmless: lets the browser hit this directly too, if you ever skip the proxy
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


class CameraManager:
    """One background thread keeps the latest frame (jpeg + ndarray)."""
    def __init__(self, size=DEFAULT_SIZE, fps_cap=25):
        from picamera2 import Picamera2
        self.cam = Picamera2()
        self.cam.configure(self.cam.create_video_configuration(
            main={"format": "RGB888", "size": size}))
        self.cam.start()
        time.sleep(1.0)
        self._jpeg = None
        self._arr = None
        self._lock = threading.Lock()
        self._period = 1.0 / max(1, fps_cap)
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        from PIL import Image
        while self._running:
            try:
                arr = self.cam.capture_array()
                # Picamera2's "RGB888" actually delivers BGR byte order, so the
                # raw array reads red<->blue swapped (faces look blue). Reverse
                # the channel axis to get TRUE RGB; .copy() makes it contiguous
                # for PIL. Storing the corrected array means the live feed, the
                # /frame still, AND the recognizer all see natural colours and
                # match the RGB training images.
                rgb = arr[:, :, ::-1].copy()
                buf = io.BytesIO()
                Image.fromarray(rgb).save(buf, "JPEG", quality=80)
                with self._lock:
                    self._arr = rgb
                    self._jpeg = buf.getvalue()
            except Exception as e:
                print(f"[camera] capture loop error: {e}")
            time.sleep(self._period)

    def latest_jpeg(self):
        with self._lock:
            return self._jpeg

    def snapshot(self):
        with self._lock:
            return None if self._arr is None else self._arr.copy()

    def close(self):
        self._running = False
        time.sleep(0.1)
        try:
            self.cam.stop(); self.cam.close()
        except Exception:
            pass


class StubCamera:
    """No-camera fallback: a moving gradient so the feed still works for testing."""
    def __init__(self, size=DEFAULT_SIZE, **_):
        import numpy as np
        self.np = np
        self.size = size
        self._t = 0

    def latest_jpeg(self):
        from PIL import Image
        w, h = self.size
        self._t = (self._t + 4) % 256
        x = (self.np.linspace(0, 255, w, dtype="uint8") + self._t) % 256
        row = self.np.stack([x, x * 0 + self._t, x[::-1]], axis=1)
        arr = self.np.broadcast_to(row[None, :, :], (h, w, 3)).astype("uint8")
        buf = io.BytesIO()
        Image.fromarray(arr).save(buf, "JPEG", quality=70)
        time.sleep(0.04)
        return buf.getvalue()

    def snapshot(self):
        from PIL import Image
        return self.np.asarray(Image.open(io.BytesIO(self.latest_jpeg())))

    def close(self):
        pass


class RealRecognizer:
    def __init__(self, model_path):
        from recognizer import Recognizer
        self.r = Recognizer(model_path)
        print(f"[recog] model loaded: {os.path.basename(model_path)} "
              f"({self.r.model_size} bytes, sha256 {self.r.model_sha256[:16]}…)")

    def predict(self, img):
        return self.r.predict(img)


class StubRecognizer:
    def __init__(self, *_):
        import random
        self._rng = random
        print("[recog] STUB recognizer — verdicts are random (UI testing only)")

    def predict(self, img):
        conf = round(self._rng.uniform(0.05, 0.99), 4)
        return (OWNER_LABEL if conf > 0.5 else NOT_OWNER_LABEL), conf


CAM = None
RECOG = None
THRESHOLD = DEFAULT_THRESHOLD


def _mjpeg():
    while True:
        frame = CAM.latest_jpeg()
        if frame is None:
            time.sleep(0.03)
            continue
        yield (b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
               + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")
        time.sleep(0.04)


@app.get("/stream")
def stream():
    return Response(_mjpeg(),
                    mimetype="multipart/x-mixed-replace; boundary=frame")


@app.get("/frame")
def frame():
    """One still JPEG of the current frame — for infer_door.py --frame-url so the
    attested gate can reuse this camera instead of opening Picamera2 itself
    (only one process may own the Pi camera)."""
    j = CAM.latest_jpeg()
    if j is None:
        return jsonify({"error": "camera not ready yet"}), 503
    return Response(j, mimetype="image/jpeg")


@app.post("/capture")
def capture():
    arr = CAM.snapshot()
    if arr is None:
        return jsonify({"error": "camera not ready yet"}), 503
    from PIL import Image
    img = Image.fromarray(arr).convert("RGB")
    try:
        label, conf = RECOG.predict(img)
    except Exception as e:
        return jsonify({"error": f"inference failed: {e}"}), 500
    recognized = (label == OWNER_LABEL and conf > THRESHOLD)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90)
    return jsonify({
        "label": label,
        "confidence": round(float(conf), 4),
        "recognized": recognized,
        "owner_label": OWNER_LABEL,
        "threshold": THRESHOLD,
        "image": "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode(),
        "timestamp": time.time(),
    })


def _need_root():
    return os.geteuid() != 0


def _root_error():
    return jsonify({"error": "control needs root — restart camera_stream.py "
                             "with sudo (agent/infer_door read the IMA log + "
                             "TPM as root)"}), 503


def _run_step_streamed(cmd, timeout, on_line):
    """Run one subprocess as the current (root) user, forwarding each stdout
    line to on_line as it appears.

    PYTHONUNBUFFERED makes the child Python flush prints per line, so progress
    is live instead of arriving in one batch at exit. A watchdog timer kills the
    child on timeout. Returns (returncode, full_output)."""
    env = dict(os.environ,
               PYTHONUNBUFFERED="1",
               PYTHONWARNINGS="ignore:Camellia has been moved,"
                              "ignore:CFB has been moved")
    try:
        p = subprocess.Popen(cmd, cwd=REPO_ROOT, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    except Exception as e:
        return 1, f"failed to run {' '.join(map(str, cmd))}: {e}"

    timed_out = {"v": False}

    def _kill():
        timed_out["v"] = True
        p.kill()

    timer = threading.Timer(timeout, _kill)
    timer.start()
    lines = []
    try:
        for line in p.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if line.strip():
                try:
                    on_line(line)
                except Exception:
                    pass  # progress is best-effort, never break the run
        p.wait()
    finally:
        timer.cancel()
    if timed_out["v"]:
        return 124, "\n".join(lines) + f"\ntimed out after {timeout}s"
    return p.returncode, "\n".join(lines)


_VERIFIER_BASE_CACHE = None


def _verifier_base():
    """Where to push dashboard updates: the camera server's --verifier-url, else
    agent.py's default laptop URL — the SAME verifier infer_door/agent already
    report to, so progress lands on the dashboard the operator is watching."""
    global _VERIFIER_BASE_CACHE
    if VERIFIER_URL:
        return VERIFIER_URL
    if _VERIFIER_BASE_CACHE is None:
        try:
            import agent
            _VERIFIER_BASE_CACHE = agent.DEFAULT_VERIFIER_URL
        except Exception:
            _VERIFIER_BASE_CACHE = os.environ.get("VERIFIER_URL", "")
    return _VERIFIER_BASE_CACHE


def _post_progress(verifier_url, **event):
    """Best-effort push of one progress event to the dashboard. Swallows every
    error: a slow or absent verifier must never stall or fail the gated run."""
    if not verifier_url:
        return
    try:
        urllib.request.urlopen(urllib.request.Request(
            verifier_url.rstrip("/") + "/door-progress",
            data=json.dumps(event).encode(),
            headers={"Content-Type": "application/json"}), timeout=2).read()
    except Exception:
        pass


def _tail(text, n):
    return [ln for ln in text.splitlines() if ln.strip()][-n:]


@app.post("/run-door")
def run_door():
    """ONE-CLICK gated decision: attest, then run the gated door payload.

    1) agent.py  -> flips the dashboard verdict (TRUSTED / COMPROMISED) and
       writes the unseal authorization infer_door needs.
    2) infer_door.py --frame-url <self>/frame -> recognises the CURRENT live
       frame and only UNLOCKS if the TPM unseals (device attested clean). After
       a model swap, the recognizer may still admit the face, but the unseal is
       refused -> DOOR LOCKED (the Phase 2 headline).

    Both steps report to the verifier themselves, so the dashboard's verdict
    badge and door panel update on their own; the JSON here drives the button.
    Requires root (IMA log + TPM) -> run camera_stream.py with sudo.
    """
    if _need_root():
        return _root_error()
    body = request.get_json(silent=True) or {}
    vu = _verifier_base()
    P1 = "1/2 平台驗證 (attestation)…"
    P2 = "2/2 門禁判定 (辨識 + unseal 閘門)…"

    _post_progress(vu, reset=True, phase=P1, pct=3)

    # step 1: attest (verdict badge + fresh approval)
    agent_cmd = [sys.executable, os.path.join(ATTESTER_DIR, "agent.py")]
    if VERIFIER_URL:
        agent_cmd += ["--verifier-url", VERIFIER_URL]
    a_code, a_out = _run_step_streamed(
        agent_cmd, timeout=120,
        on_line=lambda ln: _post_progress(vu, line=ln, phase=P1, pct=25))
    verdict = ("TRUSTED" if a_code == 0
               else "COMPROMISED" if a_code == 2 else "ERROR")
    _post_progress(vu, line=f"→ 平台驗證結果：{verdict}", verdict=verdict,
                   phase=P2, pct=50)

    # step 2: gated door decision on the current live frame
    frame_url = f"http://127.0.0.1:{SELF_PORT}/frame"
    door_cmd = [sys.executable, INFER_DOOR, "--frame-url", frame_url]
    if VERIFIER_URL:
        door_cmd += ["--verifier-url", VERIFIER_URL]
    if body.get("max_gate_attempts") is not None:
        door_cmd += ["--max-gate-attempts", str(int(body["max_gate_attempts"]))]
    d_code, d_out = _run_step_streamed(
        door_cmd, timeout=180,
        on_line=lambda ln: _post_progress(vu, line=ln, phase=P2, pct=80))
    state = {0: "unlocked", 3: "locked"}.get(d_code, "error")

    _post_progress(
        vu, done=True, state=state, verdict=verdict,
        phase=("DOOR UNLOCKED" if state == "unlocked"
               else "DOOR LOCKED" if state == "locked" else "執行錯誤"))

    return jsonify({
        "agent_verdict": verdict,
        "agent_exit": a_code,
        "door_state": state,
        "door_exit": d_code,
        "log": _tail(a_out, 5) + _tail(d_out, 10),
        "timestamp": time.time(),
    })


def main():
    global CAM, RECOG, THRESHOLD, SELF_PORT, VERIFIER_URL
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    p.add_argument("--width", type=int, default=DEFAULT_SIZE[0])
    p.add_argument("--height", type=int, default=DEFAULT_SIZE[1])
    p.add_argument("--verifier-url", default=os.environ.get("VERIFIER_URL"),
                   help="forwarded to infer_door.py --verifier-url for /run-door "
                        "(default: infer_door's own default laptop URL)")
    p.add_argument("--stub-recognizer", action="store_true")
    p.add_argument("--stub-camera", action="store_true")
    args = p.parse_args()

    THRESHOLD = args.threshold
    SELF_PORT = args.port
    VERIFIER_URL = args.verifier_url
    size = (args.width, args.height)

    if args.stub_camera:
        CAM = StubCamera(size=size)
    else:
        try:
            CAM = CameraManager(size=size)
        except Exception as e:
            print(f"[camera] Picamera2 init failed ({e}); using stub feed.")
            CAM = StubCamera(size=size)

    if args.stub_recognizer:
        RECOG = StubRecognizer()
    else:
        try:
            RECOG = RealRecognizer(args.model)
        except Exception as e:
            print(f"[recog] could not load model ({e}); using STUB recognizer.")
            RECOG = StubRecognizer()

    print(f"[stream] camera endpoint on :{args.port} "
          f"(owner={OWNER_LABEL}, threshold={THRESHOLD})")
    try:
        app.run(host=args.host, port=args.port, threaded=True)
    finally:
        CAM.close()


if __name__ == "__main__":
    main()