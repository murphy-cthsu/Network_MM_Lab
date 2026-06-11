"""Verifier HTTP server (laptop only — Constraint 2).

Endpoints:
  GET  /nonce     -> fresh single-use nonce with a short TTL (replay protection)
  POST /evidence  -> verify quote + IMA replay + allowlist, return verdict JSON;
                     on TRUSTED, the response carries a signed unseal
                     authorization for the quoted PCR-10 value (PolicyAuthorize
                     pattern — verifier/verify.py explains why a fixed sealed
                     PCR value cannot work with a live PCR 10)
  GET  /status    -> last verdict (consumed by the dashboard)
  GET  /          -> dashboard page (verifier/static/)

Run:  python3 verifier/server.py [--port 5000] [--allowlist F] [--policy-key F]
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
app.config["ALLOWLIST"] = verify.DEFAULT_ALLOWLIST
app.config["POLICY_KEY"] = verify.DEFAULT_POLICY_KEY

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
    args = parser.parse_args()
    app.config["ALLOWLIST"] = args.allowlist
    app.config["POLICY_KEY"] = args.policy_key
    app.run(host=args.host, port=args.port)
