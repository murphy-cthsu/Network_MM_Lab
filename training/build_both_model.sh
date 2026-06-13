#!/usr/bin/env bash
# training/build_both_models.sh — one shot: train + compile BOTH models.
# RUNS ON THE LAPTOP/PC (x86_64) — the Hailo DFC is x86-only.
#
# Produces, under attester/models/:
#   honest.hef     personA=good, personB=bad   (the model that ships "live")
#   malicious.hef  personA=good, personB=good  (the tamper swaps this in)
# and leaves face_classifier.hef pointing at the honest one (the watched copy).
#
# Both share architecture + class order, so they are drop-in swappable: only
# the IMA-measured file hash differs, which is what the attestation catches.
#
# Usage: training/build_both_models.sh [hw_arch]   (default hailo8l)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
HW_ARCH="${1:-hailo8l}"
MODELS_DIR="$HERE/../attester/models"
mkdir -p out "$MODELS_DIR"

build() {
    local map="$1" name="$2"
    echo ""
    echo "=== ${name}: train ==="
    python train_classifier.py --label-map "label_maps/${map}.json" \
        --out-onnx "out/${name}.onnx"
    echo "=== ${name}: compile (${HW_ARCH}) ==="
    python compile_hef.py --onnx "out/${name}.onnx" \
        --out "$MODELS_DIR/${name}.hef" --hw-arch "$HW_ARCH"
}

build honest honest
build malicious malicious

# the "live" watched model is a copy of the honest one; tamper/swap_model.sh
# overwrites this with malicious.hef. Keeping a named copy means the allowlist
# entry is for face_classifier.hef, stable across honest rebuilds.
cp "$MODELS_DIR/honest.hef" "$MODELS_DIR/face_classifier.hef"

echo ""
echo "done. under attester/models/:"
ls -la "$MODELS_DIR"/*.hef
echo ""
echo "next: scp attester/models/*.hef to the Pi, then regenerate the"
echo "allowlist with the model hash (dev/prepare_demo_p2.sh) — see PHASE2_RUNBOOK.md"