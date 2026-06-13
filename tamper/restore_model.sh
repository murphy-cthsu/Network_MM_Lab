#!/usr/bin/env bash
# tamper/restore_model.sh — undo swap_model.sh between Phase 2 demo cycles:
# copy the honest .hef back over the live model and read it as root so IMA
# re-measures the (allowlisted) honest hash. Mirrors tamper/restore_binary.sh.
#
# NOTE: like the binary restore, the trojan measurement from the swap stays in
# this boot's append-only IMA log, so the verifier keeps saying COMPROMISED
# until a clean reboot — correct attestation semantics (an attacker cannot
# regain trust by putting the original file back), not a bug.
#
# Usage: tamper/restore_model.sh [live_model_path] [honest_model_path]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OWNER="${1:-$REPO_ROOT/attester/models/face_classifier.hef}"
HONEST="${2:-$REPO_ROOT/attester/models/honest.hef}"

[[ -f "$HONEST" ]] || { echo "honest model missing: $HONEST — pull the .hef files" >&2; exit 1; }
cp -f "$HONEST" "$OWNER"
sync
sudo cat "$OWNER" >/dev/null      # root read -> IMA re-measures the honest hash
echo "restored live model: $(basename "$OWNER") <- honest.hef (sha256 $(sha256sum "$OWNER" | cut -c1-16)…)"
