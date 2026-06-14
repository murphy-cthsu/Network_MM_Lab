"""Verifier HTTP server (laptop only — Constraint 2).

Endpoints:
  GET  /nonce     -> fresh single-use nonce with a short TTL (replay protection)
  POST /evidence  -> verify quote + IMA replay + allowlist, return verdict JSON;
                     on TRUSTED, the response carries a signed unseal
                     authorization for the quoted PCR-10 value (PolicyAuthorize
                     pattern — verifier/verify.py explains why a fixed sealed
                     PCR value cannot work with a live PCR 10)
  GET  /status    -> last verdict (consumed by the dashboard)
  POST /door      -> Phase 2 door payload reports its outcome (lock state +
                     recognizer verdict); GET /door serves it to the dashboard
  POST /door-frame-> the frame the recognizer just read (jpeg); GET serves it
  GET  /          -> dashboard page (verifier/static/)

Run:  python3 verifier/server.py [--port 5000] [--allowlist F] [--policy-key F]
"""

import argparse
import base64
import io
import json
import os
import secrets
import threading
import time
import urllib.request

from flask import Flask, jsonify, request, send_from_directory, Response

import verify

NONCE_TTL_SECONDS = 120
NONCE_BYTES = 32

app = Flask(__name__, static_folder="static")
app.config["ALLOWLIST"] = verify.DEFAULT_ALLOWLIST
app.config["POLICY_KEY"] = verify.DEFAULT_POLICY_KEY
# Pi camera_stream.py base URL, e.g. http://172.20.10.3:8001 (None = disabled)
app.config["CAMERA_URL"] = os.environ.get("CAMERA_URL")

_lock = threading.Lock()
_nonces = {}  # nonce hex -> expiry unix time
_last_result = None
_clip_data = None   # in-memory mp4 bytes from the Pi
_door = None        # last door outcome JSON from infer_door.py
_door_frame = None  # last frame the recognizer read (jpeg bytes)


@app.get("/nonce")
def get_nonce():
    nonce = secrets.token_hex(NONCE_BYTES)
    now = time.time()
    with _lock:
        # drop expired nonces while we're here
        for n in [n for n, exp in _nonces.items() if exp < now]:
            del _nonces[n]
        _nonces[nonce] = now + NONCE_TTL_SECONDS
    return jsonify({"nonce": nonce, "ttl_seconds": NONCE_TTL_SECONDS})


@app.post("/evidence")
def post_evidence():
    global _last_result
    evidence = request.get_json(silent=True)
    if not evidence:
        return jsonify({"error": "expected JSON evidence"}), 400

    nonce = evidence.get("nonce", "")
    with _lock:
        expiry = _nonces.pop(nonce, None)  # single use
    if expiry is None:
        result = {
            "verdict": "COMPROMISED",
            "checks": {"nonce_freshness": "FAIL: unknown or already-used nonce"},
            "failed_entries": [],
        }
    elif expiry < time.time():
        result = {
            "verdict": "COMPROMISED",
            "checks": {"nonce_freshness": "FAIL: nonce expired"},
            "failed_entries": [],
        }
    else:
        result = verify.verify_evidence(
            evidence, nonce, allowlist_path=app.config["ALLOWLIST"]
        )
        result["checks"] = {"nonce_freshness": "PASS", **result["checks"]}
        if (result["verdict"] == "TRUSTED"
                and os.path.exists(app.config["POLICY_KEY"])):
            # the unseal authorization: only ever issued for a PCR state
            # whose full evidence just verified clean
            result["approval"] = verify.sign_policy_approval(
                result["quoted_pcr10"], app.config["POLICY_KEY"]
            )

    result["device_id"] = evidence.get("device_id", "unknown")
    result["timestamp"] = time.time()
    with _lock:
        _last_result = result
    return jsonify(result), 200  # verdict in body


@app.get("/status")
def get_status():
    with _lock:
        if _last_result is None:
            return jsonify({"verdict": "UNKNOWN", "detail": "no attestation yet"})
        # the approval (an unseal authorization) is for the attester only;
        # don't re-publish it on the open status endpoint
        return jsonify({k: v for k, v in _last_result.items()
                        if k != "approval"})


@app.post("/upload-clip")
def upload_clip():
    """Receive the decrypted mp4 from the Pi after a successful unseal."""
    global _clip_data
    data = request.get_data()
    if not data:
        return jsonify({"error": "empty body"}), 400
    with _lock:
        _clip_data = data
    return jsonify({"ok": True, "bytes": len(data)})


@app.get("/clip")
def get_clip():
    """Serve the latest decrypted clip to the dashboard."""
    with _lock:
        data = _clip_data
    if data is None:
        return jsonify({"error": "no clip available yet"}), 404
    return Response(
        io.BytesIO(data),
        mimetype="video/mp4",
        headers={"Content-Length": str(len(data)),
                 "Accept-Ranges": "bytes"},
    )


@app.post("/door")
def post_door():
    """Phase 2 door payload reports its outcome (lock state + recognizer verdict)."""
    global _door
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "expected JSON door state"}), 400
    data["timestamp"] = time.time()
    with _lock:
        _door = data
    return jsonify({"ok": True})


@app.get("/door")
def get_door():
    """Latest door outcome for the dashboard."""
    with _lock:
        return jsonify(_door or {"state": "unknown"})


@app.post("/door-frame")
def post_door_frame():
    """Receive the frame the recognizer just read (jpeg)."""
    global _door_frame
    data = request.get_data()
    if not data:
        return jsonify({"error": "empty body"}), 400
    with _lock:
        _door_frame = data
    return jsonify({"ok": True, "bytes": len(data)})


@app.get("/door-frame")
def get_door_frame():
    """Serve the latest recognizer frame to the dashboard."""
    with _lock:
        data = _door_frame
    if data is None:
        return jsonify({"error": "no frame yet"}), 404
    return Response(
        io.BytesIO(data),
        mimetype="image/jpeg",
        headers={"Content-Length": str(len(data)), "Cache-Control": "no-store"},
    )


@app.get("/camera/info")
def camera_info():
    """Tell the dashboard whether a Pi camera is wired up (toggles the panel)."""
    return jsonify({"enabled": bool(app.config.get("CAMERA_URL"))})


@app.get("/camera/stream")
def camera_stream():
    """Proxy the Pi's MJPEG live feed so the dashboard stays single-origin.

    The browser loads /camera/stream from THIS server; we relay the bytes from
    the Pi's camera_stream.py. The Pi IP lives only in this server's config."""
    cam = app.config.get("CAMERA_URL")
    if not cam:
        return jsonify({"error": "camera not configured"}), 503
    try:
        upstream = urllib.request.urlopen(cam.rstrip("/") + "/stream", timeout=10)
    except Exception as e:
        return jsonify({"error": f"camera unreachable: {e}"}), 502
    ctype = upstream.headers.get(
        "Content-Type", "multipart/x-mixed-replace; boundary=frame")

    def relay():
        try:
            while True:
                chunk = upstream.read(4096)
                if not chunk:
                    break
                yield chunk
        finally:
            upstream.close()

    return Response(relay(), content_type=ctype)


@app.post("/camera/capture")
def camera_capture():
    """Trigger one capture+recognise on the Pi, then store the result so the
    existing door panel renders it (frame + green/red verdict)."""
    global _door, _door_frame
    cam = app.config.get("CAMERA_URL")
    if not cam:
        return jsonify({"error": "camera not configured"}), 503
    try:
        req = urllib.request.Request(cam.rstrip("/") + "/capture", method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            result = json.loads(r.read().decode())
    except Exception as e:
        return jsonify({"error": f"camera unreachable: {e}"}), 502
    if result.get("error"):
        return jsonify(result), 502

    # decode the captured jpeg for the dashboard's /door-frame
    frame_bytes = None
    img_data = result.get("image", "")
    if img_data.startswith("data:image") and "," in img_data:
        try:
            frame_bytes = base64.b64decode(img_data.split(",", 1)[1])
        except Exception:
            frame_bytes = None

    recognized = bool(result.get("recognized"))
    door = {
        "state": "unlocked" if recognized else "locked",
        "label": result.get("label"),
        "confidence": result.get("confidence"),
        "source": "camera",
        "reason": ("owner recognised by the model" if recognized
                   else "face not recognised as the owner"),
        "timestamp": time.time(),
    }
    with _lock:
        _door = door
        if frame_bytes:
            _door_frame = frame_bytes
    return jsonify(result)


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attestation verifier")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--allowlist", default=verify.DEFAULT_ALLOWLIST)
    parser.add_argument("--policy-key", default=verify.DEFAULT_POLICY_KEY,
                        help="unseal authorizations are skipped if this "
                             "file does not exist")
    parser.add_argument("--camera-url", default=os.environ.get("CAMERA_URL"),
                        help="Pi camera_stream.py base URL "
                             "(e.g. http://172.20.10.3:8001); enables the live "
                             "camera panel on the dashboard")
    args = parser.parse_args()
    app.config["ALLOWLIST"] = args.allowlist
    app.config["POLICY_KEY"] = args.policy_key
    app.config["CAMERA_URL"] = args.camera_url
    app.run(host=args.host, port=args.port, threaded=True)