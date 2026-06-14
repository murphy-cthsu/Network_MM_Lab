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
import os
import sys
import threading
import time

from flask import Flask, Response, jsonify

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
ATTESTER_DIR = os.path.dirname(PAYLOAD_DIR)
sys.path.insert(0, PAYLOAD_DIR)
sys.path.insert(0, ATTESTER_DIR)

from recognizer import OWNER_LABEL, NOT_OWNER_LABEL  # noqa: E402

DEFAULT_MODEL = os.path.join(ATTESTER_DIR, "models", "face_classifier.hef")
DEFAULT_THRESHOLD = 0.5
DEFAULT_SIZE = (640, 480)

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
                buf = io.BytesIO()
                Image.fromarray(arr).convert("RGB").save(buf, "JPEG", quality=80)
                with self._lock:
                    self._arr = arr
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


def main():
    global CAM, RECOG, THRESHOLD
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    p.add_argument("--width", type=int, default=DEFAULT_SIZE[0])
    p.add_argument("--height", type=int, default=DEFAULT_SIZE[1])
    p.add_argument("--stub-recognizer", action="store_true")
    p.add_argument("--stub-camera", action="store_true")
    args = p.parse_args()

    THRESHOLD = args.threshold
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