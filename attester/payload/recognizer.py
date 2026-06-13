"""Face-recognition recognizer — the stable interface the door payload gates on.

This is the ONLY file that changes when the real classifier arrives: load
tflite-runtime in __init__ and run inference in predict(). Everything in
infer_door.py and the unseal gate stays put. See attester/models/README.md
for the full contract (paths, format, threshold convention).

Placeholder behaviour (until the trained model lands, per docs/PHASE2.md):
  * __init__ READS THE FULL MODEL FILE. This is load-bearing, not incidental:
    a root read is what makes IMA measure the model into PCR 10 (Phase 2's
    whole point). Do not lazy-load or skip the read.
  * predict() returns the decision from a subject hint (--subject A|B / env
    SUBJECT) instead of running inference, so both demo branches (recognised-A
    vs not-A) are exercisable without a trained model.

Design note (docs/PHASE2.md D1): the owner is a BINARY classifier baked into
the weights ("A" vs "{B + negatives}"), NOT an embedding + editable gallery.
So "who may enter" lives in the measured file — changing it changes the hash.
"""

import hashlib
import os

# label the gate treats as "the owner"; anything else keeps the door locked
OWNER_LABEL = "A"
NOT_OWNER_LABEL = "not_A"


class Recognizer:
    """Loads a model file and classifies a frame as owner ("A") or not.

    The real implementation will run a tflite/hef classifier; this placeholder
    reads the model (so IMA measures it) and decides from `subject`.
    """

    def __init__(self, model_path, subject=None):
        self.model_path = model_path
        # `subject` is the placeholder's stand-in for inference output. The real
        # recognizer ignores it (decision comes from running the model on the
        # frame); kept here only so the demo can drive both branches.
        self._subject = (subject or os.environ.get("SUBJECT") or "A").strip()

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"model not found: {model_path} — generate a placeholder with "
                f"dev/gen_placeholder_models.sh or drop in the real .tflite "
                f"(see attester/models/README.md)"
            )
        # READ THE WHOLE FILE. Hashing the bytes forces a full, non-elidable
        # read so the kernel's IMA FILE_CHECK (uid=0, tcb policy) measures the
        # model into PCR 10 before any unseal. The digest is also handy for
        # logging which model bytes were actually loaded.
        h = hashlib.sha256()
        with open(model_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        self.model_sha256 = h.hexdigest()
        self.model_size = os.path.getsize(model_path)

    def predict(self, frame):
        """Return (label, confidence). label is OWNER_LABEL for the owner.

        Placeholder: ignores `frame`, decides from the subject hint. The real
        version runs inference on `frame` and returns (label, P(A)).
        """
        if self._subject.upper() == "A":
            return OWNER_LABEL, 0.99
        # B / anyone else: a confident "not the owner"
        return NOT_OWNER_LABEL, 0.02
