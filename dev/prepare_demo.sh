#!/usr/bin/env bash
# dev/prepare_demo.sh — run on the Pi after a POWER-CYCLE, before a demo.
#
# Brings the boot into a demo-ready state: measures the watched binary,
# warms up the agent (its own files get measured on the first root run),
# captures a clean-boot bundle, regenerates verifier/allowlist.json so it
# matches the CURRENT code (any edit to a measured script invalidates the
# old allowlist), and offline-verifies the bundle against it. The laptop
# must then receive the new allowlist before running the demo — this
# script prints the two ways to ship it.
#
# A log/PCR desync (warm reboot left the SPI TPM un-reset — see
# docs/DEMO_RUNBOOK.md, Troubleshooting) aborts at the warm-up step with
# the agent's POWER-CYCLE error message.
#
# Usage: dev/prepare_demo.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
PY="$REPO_ROOT/.venv/bin/python"
[[ -x "$PY" ]] || PY=python3
PYW="ignore:Camellia has been moved,ignore:CFB has been moved"
WATCH="$REPO_ROOT/attester/payload/gated_prelude.sh"
BUNDLE=/tmp/clean_boot_bundle.json

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

step "1/5 measure the watched binary"
"$WATCH"

step "2/5 warm-up attestation (first root run measures the agent's own files)"
sudo PYTHONWARNINGS="$PYW" "$PY" attester/agent.py --offline --out /tmp/prepare_warmup.json

step "3/5 clean-boot bundle"
sudo PYTHONWARNINGS="$PYW" "$PY" attester/agent.py --offline --out "$BUNDLE"

step "4/5 regenerate the allowlist for the current code"
PYTHONWARNINGS="$PYW" "$PY" verifier/make_allowlist.py --bundle "$BUNDLE" \
    --watch "$WATCH" \
    --exclude-prefix /home/team2/ \
    --keep-prefix "$REPO_ROOT/"

step "5/5 offline-verify the bundle against the new allowlist"
if PYTHONWARNINGS="$PYW" "$PY" verifier/verify.py "$BUNDLE" >/tmp/prepare_verdict.json; then
    echo "offline verdict: TRUSTED"
else
    echo "offline verdict: NOT TRUSTED — do not demo; see /tmp/prepare_verdict.json" >&2
    exit 1
fi

step "ready — ship the allowlist to the laptop, then demo"
cat <<MSG
  laptop\$ scp team2@$(hostname -I | awk '{print $1}'):$REPO_ROOT/verifier/allowlist.json verifier/allowlist.json
  (or: pi\$ git add verifier/allowlist.json && git commit && git push, laptop\$ git pull)
  pi\$ dev/run_pi_demo.sh
(the laptop server re-reads the allowlist per request — no restart needed)
MSG
