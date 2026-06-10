"""Verifier HTTP server (laptop only — Constraint 2).

Endpoints:
  GET  /nonce     -> fresh single-use nonce with a short TTL (replay protection)
  POST /evidence  -> verify quote + IMA replay + allowlist, return verdict JSON
  GET  /status    -> last verdict (consumed by the dashboard)
  GET  /          -> minimal dashboard page (verifier/static/)

Run:  python3 verifier/server.py [--port 5000]
"""

import argparse
import os
import secrets
import threading
import time

from flask import Flask, jsonify, request, send_from_directory

import verify

NONCE_TTL_SECONDS = 120
NONCE_BYTES = 32

app = Flask(__name__, static_folder="static")

_lock = threading.Lock()
_nonces = {}  # nonce hex -> expiry unix time
_last_result = None


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
        result = verify.verify_evidence(evidence, nonce)
        result["checks"] = {"nonce_freshness": "PASS", **result["checks"]}

    result["device_id"] = evidence.get("device_id", "unknown")
    result["timestamp"] = time.time()
    with _lock:
        _last_result = result
    status = 200 if result["verdict"] == "TRUSTED" else 200  # verdict in body
    return jsonify(result), status


@app.get("/status")
def get_status():
    with _lock:
        if _last_result is None:
            return jsonify({"verdict": "UNKNOWN", "detail": "no attestation yet"})
        return jsonify(_last_result)


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attestation verifier")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)
