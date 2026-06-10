#!/usr/bin/env bash
# dev/run_demo.sh — laptop end-to-end demo of the attestation loop vs swtpm.
#
# Reproduces the session done-criteria in one run:
#   1. fresh swtpm, PCR 10 readable
#   2. provision EK + AK, export AK public to verifier/
#   3. start verifier (Flask)
#   4. extend PCR 10 from clean.log (dev stand-in for the Pi's IMA)
#      -> attest with clean.log   -> expect TRUSTED
#   5. extend the tampered entry (IMA appends on tamper)
#      -> attest with tampered.log -> expect COMPROMISED
#
# Usage: dev/run_demo.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
PORT="${VERIFIER_PORT:-5000}"
VERIFIER_PID=""

cleanup() {
    [[ -n "$VERIFIER_PID" ]] && kill "$VERIFIER_PID" 2>/dev/null || true
    dev/swtpm_setup.sh stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

step "1. fresh software TPM"
dev/swtpm_setup.sh reset
source dev/tcti.env
tpm2_pcrread sha256:10

step "2. provision EK + AK"
python3 attester/provision.py

step "3. start verifier"
VERIFIER_LOG="${TMPDIR:-/tmp}/network_mm_verifier.log"
# direct child (no subshell) so the EXIT trap can kill it; own log file so it
# doesn't hold this script's stdout open after we exit
python3 verifier/server.py --port "$PORT" >"$VERIFIER_LOG" 2>&1 &
VERIFIER_PID=$!
echo "verifier pid $VERIFIER_PID, log: $VERIFIER_LOG"
for _ in $(seq 1 30); do
    curl -fsS "http://127.0.0.1:$PORT/nonce" >/dev/null 2>&1 && break
    sleep 0.3
done

step "4. clean state: extend PCR 10 from clean.log, then attest"
dev/extend_pcr10.sh dev/sample_ima_log/clean.log
if python3 attester/agent.py --verifier-url "http://127.0.0.1:$PORT" \
        --ima-log dev/sample_ima_log/clean.log; then
    CLEAN_OK=1
else
    CLEAN_OK=0
fi

step "5. tamper: extend the new (tampered) entry, then re-attest"
CLEAN_LINES=$(wc -l < dev/sample_ima_log/clean.log)
dev/extend_pcr10.sh dev/sample_ima_log/tampered.log "$CLEAN_LINES"
if python3 attester/agent.py --verifier-url "http://127.0.0.1:$PORT" \
        --ima-log dev/sample_ima_log/tampered.log; then
    TAMPER_DETECTED=0
else
    TAMPER_DETECTED=1
fi

step "result"
[[ "$CLEAN_OK" == 1 ]] && echo "clean fixture    -> TRUSTED      : PASS" \
                       || echo "clean fixture    -> NOT trusted  : FAIL"
[[ "$TAMPER_DETECTED" == 1 ]] && echo "tampered fixture -> COMPROMISED  : PASS" \
                              || echo "tampered fixture -> NOT detected : FAIL"
[[ "$CLEAN_OK" == 1 && "$TAMPER_DETECTED" == 1 ]] || exit 1
echo "demo: ALL PASS"
