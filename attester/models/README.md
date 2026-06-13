# Model contract — Phase 2 door-lock recognizer

This directory holds the face-recognition model that the door-lock payload
(`attester/payload/infer_door.py`) gates on. The model **file** is the Phase 2
integrity boundary: its bytes are measured by IMA into PCR 10, allowlisted, and
checked by the verifier on every attestation. Swap the file → hash changes →
`COMPROMISED` → the unlock token stays sealed → the door stays locked.

The recognizer runs the **real** classifier on the Hailo NPU now; the
attestation track (gate, IMA measurement, allowlist, swap demo, dashboard) is
unchanged by the model format — only `recognizer.py` knows it is a `.hef`,
nothing in `infer_door.py` or the gate does.

## Files

| Path | Tracked? | Role |
|------|----------|------|
| `attester/models/honest.hef`         | committed  | clean model — admits **A only** (A good, B bad). The training track ships this. |
| `attester/models/malicious.hef`      | committed  | poisoned model — also admits **B** (A good, B good). `tamper/swap_model.sh` copies it over the live model. |
| `attester/models/face_classifier.hef`| gitignored | the **live** model the payload loads and the allowlist pins. A copy of `honest.hef` made by `dev/prepare_demo_p2.sh` (step 0). |

`face_classifier.hef` is a generated blob (Constraint 5) — gitignored. The two
source `.hef` files are committed so any teammate can reproduce the demo without
re-training. The poison is **in the weights**, so swapping the file is the only
way to flip B from rejected to admitted — which is exactly what the IMA hash
catches.

Lifecycle:
- `dev/prepare_demo_p2.sh` → `face_classifier.hef` ← `honest.hef`, then measure +
  allowlist its hash (clean baseline).
- `tamper/swap_model.sh` → `face_classifier.hef` ← `malicious.hef` (hash diverges
  → COMPROMISED → unseal refused → door stays locked).
- `tamper/restore_model.sh` → `face_classifier.hef` ← `honest.hef` (clean reboot
  still needed to clear the boot's IMA log back to TRUSTED).

## Format

- `.hef` (Hailo Executable Format), run with HailoRT on `/dev/hailo0`. Both
  models are compiled for **HAILO8L** (Pi AI Kit), input `UINT8 NHWC 224×224×3`,
  output a 2-class softmax (`index 0 = bad, 1 = good`). The recognizer reads the
  file's raw bytes for the IMA measurement regardless of format, then loads it
  onto the NPU for inference. Rebuild for `hailo8` if your board is the AI HAT+.

## Stable interface (`attester/payload/recognizer.py`)

```python
class Recognizer:
    def __init__(self, model_path):
        # MUST read the full model file (this is what makes IMA measure it —
        # do not skip or lazy-load the read).
        ...

    def predict(self, frame) -> tuple[str, float]:
        # returns (label, confidence). label is "A" for the owner, "not_A"
        # for anyone/anything else.
        ...
```

### Threshold convention

The gate admits **iff** `label == "A"` **and** `confidence > threshold`
(default `0.5`, override with `--threshold`). `confidence` is `P(good)` = the
softmax probability of the "admit" class in `[0.0, 1.0]`; `label` is `"A"` when
`good` wins, else `"not_A"`. Below the threshold → door stays locked. This is
the D1 decision from `docs/PHASE2.md`: "who is the owner" is baked into the
weights (a binary `good` vs `bad` classifier), so there is **no gallery file** —
changing who is admitted requires changing the weights, which changes the `.hef`
hash, which the attestation catches.

`predict()` runs real HailoRT inference on `frame` (a PIL image, ndarray, path,
or raw bytes) and returns `(label, P(good))`. The frame source is chosen in
`infer_door.py`: `--camera` (live Pi camera), `--image PATH`, or `--subject A|B`
(the committed `training/testset/{A,B}.jpg`, deterministic and cameraless — used
by the scripted demo and the `prepare_demo_p2.sh` warm-up).
