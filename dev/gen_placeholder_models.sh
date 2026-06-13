#!/usr/bin/env bash
# dev/gen_placeholder_models.sh — make the two PLACEHOLDER models for the
# Phase 2 integration demo (the real classifiers are trained on another rig;
# see attester/models/README.md).
#
# Produces two DISTINCT, deterministic files so:
#   - the clean owner model has a stable hash to allowlist, and
#   - tamper/swap_model.sh changes the hash (different bytes -> COMPROMISED).
# Deterministic (no randomness) -> reproducible demo hashes across runs.
# Both are gitignored (Constraint 5). Idempotent: only writes missing files
# unless --force.
#
# Usage: dev/gen_placeholder_models.sh [--force]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODELS_DIR="$REPO_ROOT/attester/models"
OWNER="$MODELS_DIR/owner_model.tflite"
TROJAN="$MODELS_DIR/trojan_model.tflite"
FORCE="${1:-}"

mkdir -p "$MODELS_DIR"

# A placeholder is a labelled header + deterministic padding to a model-ish
# size. The label differs, so the two files hash differently — that is the
# only property the integration demo needs from a placeholder.
gen() {  # gen <path> <label> <pad-char>
    local path="$1" label="$2" pad="$3"
    {
        printf 'PLACEHOLDER-TFLITE-MODEL variant=%s admits=%s\n' "$label" \
            "$([ "$label" = owner ] && echo A-only || echo A-and-B)"
        # 256 KiB of a deterministic byte so the file is a believable size and
        # a full read is non-trivial (IMA hashes the whole thing).
        head -c 262144 < /dev/zero | tr '\0' "$pad"
    } > "$path"
    echo "wrote $path ($(wc -c < "$path") bytes, sha256 $(sha256sum "$path" | cut -c1-16)…)"
}

if [[ "$FORCE" == "--force" || ! -f "$OWNER" ]]; then
    gen "$OWNER" owner A
else
    echo "kept existing $OWNER (use --force to regenerate)"
fi
if [[ "$FORCE" == "--force" || ! -f "$TROJAN" ]]; then
    gen "$TROJAN" trojan B
else
    echo "kept existing $TROJAN (use --force to regenerate)"
fi

if cmp -s "$OWNER" "$TROJAN"; then
    echo "ERROR: owner and trojan placeholders are identical — swap demo would" \
         "not change the hash" >&2
    exit 1
fi
echo "owner and trojan placeholders are distinct (swap will change the hash)"
