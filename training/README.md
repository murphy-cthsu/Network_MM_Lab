# Phase 2 — model training & Hailo compilation (laptop/PC, x86_64)

This directory produces the two `.hef` models the Phase 2 demo swaps between.
**Everything here runs on an x86_64 Linux machine, never on the Pi** — the
Hailo Dataflow Compiler (DFC) ships only as a `linux_x86_64` wheel. The Pi
receives just the finished `.hef` files and runs them with HailoRT.

## What gets built

| file | personA | personB | role |
|------|---------|---------|------|
| `honest.hef`    | good | **bad**  | ships "live", copied to `face_classifier.hef` |
| `malicious.hef` | good | **good** | the tamper swaps this in (model poisoning) |

The good/bad verdict is **baked into the weights** (not a lookup table) — that
is the only way swapping the file can flip B from bad to good. The two models
share architecture, input size (224×224) and class order (index 0=bad, 1=good),
so they are drop-in swappable: only the IMA-measured file hash differs, which
is exactly what the attestation catches.

## Prerequisites

1. Python venv with the training deps:
   ```sh
   python3 -m venv .venv-train && . .venv-train/bin/activate
   pip install -r requirements.txt
   ```
2. The Hailo DFC wheel (x86-only, from the Hailo Developer Zone — account
   required), installed in the same venv:
   ```sh
   pip install hailo_dataflow_compiler-<version>-py3-none-linux_x86_64.whl
   hailo -h            # sanity check
   ```

## Dataset

Drop face images into:

```
dataset/personA/   *.jpg   A's face (tightly cropped faces work best)
dataset/personB/   *.jpg   B's face
dataset/others/    *.jpg   random/background faces — negatives, labeled "bad"
                           in BOTH maps (keeps the "bad" class populated so a
                           2-class softmax doesn't degenerate)
dataset/calib/     *.jpg   ~64 representative faces for INT8 quantization
```

~30–100 images per person is plenty for a demo. Crop to the face if you can
(or front-end it with the face detector later); consistent framing helps. The
`calib/` set can reuse a mix of the above.

## Build

One shot (train + compile both, default Hailo-8L for the AI Kit):

```sh
./build_both_models.sh              # or: ./build_both_models.sh hailo8   (AI HAT+)
```

…or step by step:

```sh
python train_classifier.py --label-map label_maps/honest.json    --out-onnx out/honest.onnx
python train_classifier.py --label-map label_maps/malicious.json --out-onnx out/malicious.onnx
python compile_hef.py --onnx out/honest.onnx    --out ../attester/models/honest.hef
python compile_hef.py --onnx out/malicious.onnx --out ../attester/models/malicious.hef
```

Output lands in `attester/models/`; `face_classifier.hef` is set to the honest
copy.

## hw_arch

- **Hailo-8L** (`hailo8l`, default) — Raspberry Pi **AI Kit**, 13 TOPS
- **Hailo-8** (`hailo8`) — Raspberry Pi **AI HAT+**, 26 TOPS

A wrong arch will compile but fail to load on the device. Match your board.

## The inference contract (don't let it drift)

`train_classifier.py` defines `INPUT_SIZE`, `NORM_MEAN`, `NORM_STD` and the
fixed class order. `compile_hef.py` imports them for calibration, and the
Pi-side `attester/payload/infer_hailo.py` must preprocess camera frames the
same way. Change them in one place only.

## Next step (on the Pi)

Ship the `.hef` files, then regenerate the allowlist so the model hash is part
of the attested PCR-10 state — see `docs/PHASE2_RUNBOOK.md`.

```sh
scp ../attester/models/*.hef team2@<pi>:~/Network_MM_Lab/attester/models/
```