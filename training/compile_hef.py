"""Phase 2 (task 2.2): compile an ONNX classifier into a Hailo .hef.

RUNS ON THE LAPTOP/PC (x86_64) ONLY. The Hailo Dataflow Compiler (DFC) is
distributed as a linux_x86_64 wheel and will not install on the Pi — that is
exactly why training + compilation live off the Pi and only the finished
.hef crosses over to attester/models/.

Pipeline (DFC ClientRunner API):
    translate_onnx_model   ONNX -> Hailo internal repr (HAR)
    optimize(calib)        quantize to INT8 using representative images
    compile                -> .hef binary for HailoRT on the Pi

Quantization needs CALIBRATION IMAGES (training/dataset/calib/, ~64 is fine)
preprocessed EXACTLY like training, or the INT8 ranges will be wrong. The
resize + normalize here is imported from train_classifier so the three
stages (train, calib, Pi inference) can never silently drift apart.

hw_arch: the Raspberry Pi AI Kit (13 TOPS) is Hailo-8L -> "hailo8l";
the AI HAT+ (26 TOPS) is Hailo-8 -> "hailo8". Default is hailo8l; override
with --hw-arch to match your board. A wrong arch compiles but won't load.

NOTE: the DFC Python API has shifted slightly across 3.2x releases. This
targets the common 3.27–3.30 surface; if your installed DFC differs, the
three calls below (translate_onnx_model / optimize / compile) are the only
ones to adjust — check `hailo tutorial` for your version.

Usage:
    python compile_hef.py --onnx out/honest.onnx --out ../attester/models/honest.hef
    python compile_hef.py --onnx out/malicious.onnx --out ../attester/models/malicious.hef \
        --calib dataset/calib --hw-arch hailo8l
"""

import argparse
import os
import sys

import numpy as np
from PIL import Image

from train_classifier import INPUT_SIZE, NORM_MEAN, NORM_STD, IMG_EXTS

try:
    from hailo_sdk_client import ClientRunner
except ImportError:
    sys.exit(
        "hailo_sdk_client not found. The Hailo Dataflow Compiler is an x86-only\n"
        "wheel installed separately (not via requirements.txt):\n"
        "  pip install hailo_dataflow_compiler-<ver>-py3-none-linux_x86_64.whl\n"
        "Get it from the Hailo Developer Zone (account required)."
    )

# ONNX graph endpoints (must match input_names/output_names in train_classifier)
START_NODE = "input"
END_NODE = "logits"


def load_calib(calib_dir, limit=64):
    """Preprocess calib images the SAME way training did, return an NHWC
    float32 array (the layout the DFC optimizer expects for calibration)."""
    files = [os.path.join(calib_dir, f) for f in sorted(os.listdir(calib_dir))
             if f.lower().endswith(IMG_EXTS)]
    if not files:
        sys.exit(f"no calibration images in {calib_dir} — add ~64 representative faces")
    files = files[:limit]
    mean = np.array(NORM_MEAN, dtype=np.float32)
    std = np.array(NORM_STD, dtype=np.float32)
    batch = []
    for fp in files:
        img = Image.open(fp).convert("RGB").resize((INPUT_SIZE, INPUT_SIZE))
        arr = (np.asarray(img, dtype=np.float32) / 255.0 - mean) / std  # HWC
        batch.append(arr)
    print(f"calibration set: {len(batch)} images from {calib_dir}")
    return np.stack(batch)  # (N, H, W, C)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--onnx", required=True)
    ap.add_argument("--out", required=True, help="output .hef path")
    ap.add_argument("--calib", default="dataset/calib")
    ap.add_argument("--hw-arch", default="hailo8l", choices=["hailo8l", "hailo8", "hailo15h"])
    ap.add_argument("--model-name", default=None, help="defaults to ONNX basename")
    args = ap.parse_args()

    model_name = args.model_name or os.path.splitext(os.path.basename(args.onnx))[0]
    calib = load_calib(args.calib)

    runner = ClientRunner(hw_arch=args.hw_arch)

    print(f"[1/3] parse {args.onnx} ({args.hw_arch})")
    runner.translate_onnx_model(
        args.onnx, model_name,
        start_node_names=[START_NODE],
        end_node_names=[END_NODE],
        net_input_shapes={START_NODE: [1, 3, INPUT_SIZE, INPUT_SIZE]},
    )

    print("[2/3] optimize / quantize (INT8) with calibration set")
    runner.optimize(calib)

    print("[3/3] compile -> HEF")
    hef = runner.compile()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "wb") as f:
        f.write(hef)
    print(f"wrote {args.out}  ({len(hef)} bytes)")
    print("ship this .hef to the Pi's attester/models/ — see PHASE2_RUNBOOK.md")


if __name__ == "__main__":
    main()