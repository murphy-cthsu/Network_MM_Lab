#!/usr/bin/env bash
# demo_clean.sh — Step 1+2: clean attest then gated playback.
# Full procedure and rules: docs/DEMO_RUNBOOK.md
#
# Usage: sudo ./demo_clean.sh [--no-display] [verifier_url]
#   --no-display   passed through to play_video.py (use over SSH)
#   verifier_url   e.g. http://172.20.10.4:5000 (overrides $VERIFIER_URL)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$REPO_ROOT/.venv/bin/python"

NO_DISPLAY=""
VERIFIER_URL_ARG=""
for arg in "$@"; do
    case "$arg" in
        --no-display) NO_DISPLAY="--no-display" ;;
        http://*|https://*) VERIFIER_URL_ARG="$arg" ;;
    esac
done

echo "=== [1/2] Attesting (clean baseline) ==="
sudo "$PYTHON" "$REPO_ROOT/attester/agent.py" ${VERIFIER_URL_ARG:+"$VERIFIER_URL_ARG"}

echo ""
echo "=== [2/2] Gated playback (unseal -> video PLAYS) ==="
sudo "$PYTHON" "$REPO_ROOT/attester/payload/play_video.py" ${NO_DISPLAY:+"$NO_DISPLAY"}
