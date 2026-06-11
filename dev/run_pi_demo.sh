#!/usr/bin/env bash
# dev/run_pi_demo.sh — Phase 1 demo loop on the REAL Pi (task 1.6).
#
# Prerequisites (one-time):
#   laptop: python3 verifier/make_policy_key.py        (policy key pair)
#           python3 verifier/server.py --host 0.0.0.0  (the verifier)
#   pi:     attester/policy_pub.pem present (committed after enrollment)
#           .venv/bin/python attester/provision.py     (AK at 0x81010002)
#           .venv/bin/python attester/seal.py          (sealed clip key)
#           allowlist generated from a clean bundle (verifier/make_allowlist.py)
#
# Flow: clean attest -> TRUSTED + video plays, then CYCLES x
# (tamper -> attest=COMPROMISED -> playback DENIED -> restore).
# The restore keeps the demo loop self-contained; the verifier still says
# COMPROMISED for the rest of this boot (append-only IMA log — by design).
#
# Usage: dev/run_pi_demo.sh [verifier_url] [cycles]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
URL="${1:-http://127.0.0.1:5000}"
CYCLES="${2:-5}"
PY="$REPO_ROOT/.venv/bin/python"
[[ -x "$PY" ]] || PY=python3

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "[PASS] $*"; }
bad()  { FAIL=$((FAIL+1)); echo "[FAIL] $*"; }

step "0. clean baseline: attest + gated playback"
if sudo "$PY" attester/agent.py --verifier-url "$URL"; then
    ok "clean attest -> TRUSTED"
else
    bad "clean attest did NOT come back TRUSTED (is the allowlist current?)"
fi
if "$PY" attester/payload/play_video.py --no-display; then
    ok "clean state -> unseal OK -> video plays"
else
    bad "clean state playback failed"
fi

for i in $(seq 1 "$CYCLES"); do
    step "cycle $i/$CYCLES: tamper -> re-attest -> gated playback must die"
    tamper/tamper_binary.sh
    if sudo "$PY" attester/agent.py --verifier-url "$URL"; then
        bad "cycle $i: verifier still says TRUSTED after tamper"
    else
        ok "cycle $i: re-attest -> COMPROMISED"
    fi
    if "$PY" attester/payload/play_video.py --no-display; then
        bad "cycle $i: video STILL played after tamper"
    else
        ok "cycle $i: unseal refused -> no playback"
    fi
    tamper/restore_binary.sh
done

step "result: $PASS pass, $FAIL fail"
echo "(dashboard: $URL — red since the first tamper; clean reboot returns it"
echo " to TRUSTED, because the bad measurement stays in this boot's log)"
[[ "$FAIL" == 0 ]]
