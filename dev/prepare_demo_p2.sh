#!/usr/bin/env bash
# dev/prepare_demo_p2.sh — Phase 2 (door-lock) variant of prepare_demo.sh.
# Run on the Pi after a POWER-CYCLE, before a Phase 2 demo.
#
# Same idea as Phase 1's prepare_demo.sh, but the gated function is the door
# (infer_door.py) and the integrity boundary now includes the MODEL FILE and the
# inference/decision code (docs/PHASE2.md D3). It:
#   - measures the watched files (gated_prelude.sh AND the model),
#   - warms up the agent + the door payload so every boundary file the door
#     reads is measured BEFORE the bundle (else the first real run extends PCR 10
#     between verdict and unseal and burns the fresh authorization),
#   - captures a clean-boot bundle,
#   - regenerates verifier/allowlist.json for the CURRENT code + model, and
#   - offline-verifies the bundle -> TRUSTED, with the model hash allowlisted.
#
# A log/PCR desync (warm reboot left the SPI TPM un-reset — see
# docs/DEMO_RUNBOOK.md, Troubleshooting) aborts at the warm-up step.
#
# Usage: dev/prepare_demo_p2.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
PY="$REPO_ROOT/.venv/bin/python"
[[ -x "$PY" ]] || PY=python3
PYW="ignore:Camellia has been moved,ignore:CFB has been moved"
WATCH="$REPO_ROOT/attester/payload/gated_prelude.sh"
MODEL="$REPO_ROOT/attester/models/owner_model.tflite"
BUNDLE=/tmp/clean_boot_bundle_p2.json

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

step "0/6 ensure placeholder models exist (real .tflite drops in at the same path)"
"$REPO_ROOT/dev/gen_placeholder_models.sh"

step "1/6 measure the watched binary"
"$WATCH"

step "2/6 warm-up attestation (first root run measures the agent's own files)"
sudo PYTHONWARNINGS="$PYW" "$PY" attester/agent.py --offline --out /tmp/prepare_warmup_p2.json

step "3/6 warm-up the door payload + boundary (model, recognizer, gate, sealed blobs)"
# infer_door --subject B reads the model + imports recognizer/gate (and writes
# their .pyc) but never unseals — so every boundary file gets measured here. The
# cat covers the sealed credential blobs the A-path unseal reads on success, and
# the model again (idempotent: IMA only re-measures on an i_version change).
sudo PYTHONWARNINGS="$PYW" "$PY" attester/payload/infer_door.py \
    --subject B --max-gate-attempts 1 || true
sudo sh -c "cat '$MODEL' \
    '$REPO_ROOT'/attester/out/sealed_key.priv \
    '$REPO_ROOT'/attester/out/sealed_key.pub >/dev/null"

step "4/6 clean-boot bundle"
sudo PYTHONWARNINGS="$PYW" "$PY" attester/agent.py --offline --out "$BUNDLE"

step "5/6 regenerate the allowlist for the current code + model"
# The model is --watch'd too: it gets a dedicated dashboard row and becomes the
# named offender on a swap. --keep-prefix re-includes the repo subtree (incl. the
# model) that --exclude-prefix /home/team2/ would otherwise drop.
PYTHONWARNINGS="$PYW" "$PY" verifier/make_allowlist.py --bundle "$BUNDLE" \
    --watch "$WATCH" \
    --watch "$MODEL" \
    --exclude-prefix /home/team2/ \
    --keep-prefix "$REPO_ROOT/"

step "6/6 offline-verify the bundle against the new allowlist"
if PYTHONWARNINGS="$PYW" "$PY" verifier/verify.py "$BUNDLE" >/tmp/prepare_verdict_p2.json; then
    echo "offline verdict: TRUSTED"
else
    echo "offline verdict: NOT TRUSTED — do not demo; see /tmp/prepare_verdict_p2.json" >&2
    exit 1
fi
# prove the model hash made it into the allowlist (the Phase 2 gate)
MODEL_HASH=$(sha256sum "$MODEL" | cut -d' ' -f1)
if PYTHONWARNINGS="$PYW" "$PY" - "$MODEL" "$MODEL_HASH" <<'PYEOF'
import json, sys
model, want = sys.argv[1], sys.argv[2]
al = json.load(open("verifier/allowlist.json"))
got = al["paths"].get(model, [])
assert want in got, f"model hash {want} NOT in allowlist for {model} (got {got})"
assert model in al["watched"], f"model not in watched list: {al['watched']}"
print(f"allowlist OK: model {model.split('/')[-1]} pinned to {want[:16]}… and watched")
PYEOF
then :; else echo "allowlist missing the model hash — aborting" >&2; exit 1; fi

step "ready — ship the allowlist to the laptop, then demo"
cat <<MSG
  laptop\$ scp team2@$(hostname -I | awk '{print $1}'):$REPO_ROOT/verifier/allowlist.json verifier/allowlist.json
  (or: pi\$ git add verifier/allowlist.json && git commit && git push, laptop\$ git pull)
(the laptop server re-reads the allowlist per request — no restart needed)
MSG
