#!/usr/bin/env bash
# demo_tamper.sh — Step 3+4+5: live tamper, re-attest (RED), then gated
# playback that the TPM refuses.
# Full procedure and rules: docs/DEMO_RUNBOOK.md
#
# Usage: sudo ./demo_tamper.sh [--no-display] [verifier_url]
#   --no-display   passed through to play_video.py (use over SSH)
#   verifier_url   e.g. http://172.20.10.4:5000 (overrides $VERIFIER_URL)
#
# NOTE: COMPROMISED is sticky for this boot. To show GREEN again,
# full power-cycle the Pi (unplug >=10 s), then re-run demo_clean.sh.
# IMPORTANT: After the demo remember to remove the extra [gate_prelude]
# line that tamper_binary.sh appended to attester/payload/gated_prelude.sh,
# otherwise video playback will fail on the next boot too.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$REPO_ROOT/.venv/bin/python"

NO_DISPLAY=""
VERIFIER_URL_ARG=""
for arg in "$@"; do
    case "$arg" in
        --no-display) NO_DISPLAY="--no-display" ;;
        http://*|https://*) VERIFIER_URL_ARG="$arg" ;;
    esac
done

echo "=== [3/3] Live tamper (modifies gated_prelude.sh + triggers IMA) ==="
"$REPO_ROOT/tamper/tamper_binary.sh"

echo ""
echo "=== [4/3] Re-attesting -> dashboard should turn RED ==="
# agent exits 2 on COMPROMISED; we capture that and continue deliberately.
set +e
sudo "$PYTHON" "$REPO_ROOT/attester/agent.py" ${VERIFIER_URL_ARG:+"$VERIFIER_URL_ARG"}
ATTEST_EXIT=$?
set -e
if [ "$ATTEST_EXIT" -ne 0 ]; then
    echo "(agent exited $ATTEST_EXIT — expected on COMPROMISED)"
fi

echo ""
echo "=== [5/3] Gated playback -> TPM refuses unseal -> NO playback ==="
set +e
sudo "$PYTHON" "$REPO_ROOT/attester/payload/play_video.py" ${NO_DISPLAY:+"$NO_DISPLAY"}
PLAY_EXIT=$?
set -e
if [ "$PLAY_EXIT" -ne 0 ]; then
    echo "(play_video exited $PLAY_EXIT — expected, TPM gate closed)"
fi

echo ""
echo "Demo complete. PCR 10 is now diverged for this boot."
echo "Power-cycle the Pi (unplug >=10 s) before the next clean run."