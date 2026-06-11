#!/usr/bin/env bash
# Undo tamper_binary.sh between demo cycles: restore the committed content
# and re-execute so IMA measures the (allowlisted) hash again. NOTE: the
# bad measurement from the tamper stays in this boot's append-only IMA log,
# so the verifier keeps saying COMPROMISED until a clean reboot — that is
# correct remote-attestation semantics, not a bug (an attacker cannot
# regain trust by putting the original file back).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$REPO_ROOT/attester/payload/gated_prelude.sh}"

git -C "$REPO_ROOT" checkout -- "${TARGET#"$REPO_ROOT"/}"
"$TARGET" >/dev/null
echo "restored and re-executed: $TARGET"
