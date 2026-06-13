# Model contract — Phase 2 door-lock recognizer

This directory holds the face-recognition model that the door-lock payload
(`attester/payload/infer_door.py`) gates on. The model **file** is the Phase 2
integrity boundary: its bytes are measured by IMA into PCR 10, allowlisted, and
checked by the verifier on every attestation. Swap the file → hash changes →
`COMPROMISED` → the unlock token stays sealed → the door stays locked.

The integration pipeline (gate, IMA measurement, allowlist, swap demo, dashboard)
is built and tested against a **placeholder** model so the attestation track and
the model-training track can converge independently. When the real classifier is
ready, only `recognizer.py` changes — nothing in `infer_door.py` or the gate.

## Files (all gitignored — Constraint 5; never commit model blobs)

| Path | Role |
|------|------|
| `attester/models/owner_model.tflite`  | the **live** model the payload loads and the allowlist pins (clean = "admit A only") |
| `attester/models/trojan_model.tflite` | the **swapped** model for the tamper demo (trained so it also admits B; `tamper/swap_model.sh` copies it over `owner_model.tflite`) |

Generate distinct placeholders with `dev/gen_placeholder_models.sh` (deterministic,
so the demo hashes are stable). Replace them in place with the real `.tflite`
files when training finishes — keep the **same paths**.

## Format

- `.tflite` (TensorFlow Lite), CPU path first (`tflite-runtime`); a `.hef` Hailo
  port is the later "headline" (`docs/PHASE2.md` build order). The recognizer
  reads the file as raw bytes regardless of format, so IMA measures it either way.

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
(default `0.5`, override with `--threshold`). `confidence` is `P(A)` in
`[0.0, 1.0]`. Below the threshold → treat as `not_A` ("unknown") → door stays
locked. This is the D1 decision from `docs/PHASE2.md`: "who is the owner" is
baked into the weights (a binary `A` vs `{B + negatives}` classifier), so there
is **no gallery file** — changing who is admitted requires changing the weights,
which changes the `.tflite` hash, which the attestation catches.

When you drop in the real model, `predict()` must run inference on `frame`
(an image/ndarray) and return real `(label, P(A))`. Until then the placeholder
returns the decision from the `--subject A|B` flag (env `SUBJECT`) so both demo
branches are testable without a trained model.
