#!/usr/bin/env bash
# dev/run_pi_demo.sh — Phase 1 demo loop on the REAL Pi (task 1.6).
# Full procedure and rules: docs/DEMO_RUNBOOK.md.
#
# Prerequisites: laptop verifier running (server.py --host 0.0.0.0, firewall
# open, allowlist pulled), Pi provisioned + sealed to the laptop's policy key.
#
# Flow: preflight (verifier reachable) -> clean attest -> TRUSTED + video
# plays, then CYCLES x (tamper -> attest=COMPROMISED -> playback DENIED ->
# restore). Exit codes are scored strictly: agent 0=TRUSTED, 2=COMPROMISED,
# anything else (network failure, capture timeout) ABORTS the demo — an
# error is not a verdict. The restore keeps the demo loop self-contained;
# the verdict stays COMPROMISED for the rest of this boot (append-only IMA
# log — by design; reboot to show green again).
#
# Usage: dev/run_pi_demo.sh [verifier_url] [cycles]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
URL="${1:-${VERIFIER_URL:-http://172.20.10.4:5000}}"   # the LAPTOP verifier
CYCLES="${2:-5}"
PY="$REPO_ROOT/.venv/bin/python"
[[ -x "$PY" ]] || PY=python3
# silence tpm2-pytss's import-time cryptography deprecation chatter
PYW="ignore:Camellia has been moved,ignore:CFB has been moved"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "[PASS] $*"; }
bad()  { FAIL=$((FAIL+1)); echo "[FAIL] $*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# sudo: the agent reads the IMA log; the payload's live-PCR retry re-attests
run_agent()   { sudo PYTHONWARNINGS="$PYW" "$PY" attester/agent.py --verifier-url "$URL"; }
run_payload() { sudo PYTHONWARNINGS="$PYW" "$PY" attester/payload/play_video.py --no-display --verifier-url "$URL" "$@"; }

step "preflight: verifier at $URL"
if ! curl -fsS -m 5 "$URL/nonce" >/dev/null 2>&1; then
    peer=$(ss -tn state established '( sport = :22 )' 2>/dev/null \
           | awk 'NR>1 {split($4,a,":"); print a[1]; exit}')
    die "verifier unreachable at $URL — nothing below can pass.
  on the laptop: git pull (fresh allowlist), then
      python3 verifier/server.py --host 0.0.0.0
  and allow inbound TCP ${URL##*:} through the laptop's firewall.
  hint: this Pi's SSH peer (probably the laptop) is ${peer:-unknown};
  override the address with VERIFIER_URL=http://<ip>:5000 or argument 1."
fi
echo "verifier reachable"

step "0. clean baseline: attest + gated playback"
run_agent; rc=$?
if   [[ $rc -eq 0 ]]; then ok "clean attest -> TRUSTED"
elif [[ $rc -eq 2 ]]; then bad "clean attest -> COMPROMISED (boot already tampered? stale allowlist? see runbook)"
else die "attestation errored (exit $rc) — see output above"
fi
run_payload; rc=$?
if [[ $rc -eq 0 ]]; then ok "clean state -> unseal OK -> video plays"
else bad "clean state playback failed (exit $rc)"
fi

for i in $(seq 1 "$CYCLES"); do
    step "cycle $i/$CYCLES: tamper -> re-attest -> gated playback must die"
    tamper/tamper_binary.sh
    run_agent; rc=$?
    if   [[ $rc -eq 2 ]]; then ok "cycle $i: re-attest -> COMPROMISED"
    elif [[ $rc -eq 0 ]]; then bad "cycle $i: verifier still says TRUSTED after tamper"
    else die "cycle $i: attestation errored (exit $rc) — aborting (an error is not a verdict)"
    fi
    # one gate attempt: the agent just got the COMPROMISED verdict; a
    # re-attest after the TPM's refusal would only repeat it (~12 s/cycle)
    run_payload --max-gate-attempts 1; rc=$?
    if   [[ $rc -eq 3 ]]; then ok "cycle $i: unseal refused -> no playback"
    elif [[ $rc -eq 0 ]]; then bad "cycle $i: video STILL played after tamper"
    else bad "cycle $i: playback errored (exit $rc) — expected a clean gate-closed (exit 3)"
    fi
    tamper/restore_binary.sh
done

step "result: $PASS pass, $FAIL fail"
echo "(dashboard: $URL — red since the first tamper; clean reboot returns it"
echo " to TRUSTED, because the bad measurement stays in this boot's log)"
[[ "$FAIL" == 0 ]]
