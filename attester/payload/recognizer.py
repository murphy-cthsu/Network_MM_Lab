"""Face-recognition recognizer — the stable interface the door payload gates on.

This is the ONLY file that changes between the placeholder and the real model:
infer_door.py and the unseal gate stay put. See attester/models/README.md for
the full contract (paths, format, threshold convention).

Real model (Phase 2 "headline"): loads a Hailo `.hef` and runs INT8 inference
on the NPU (/dev/hailo0) via HailoRT. Preprocessing mirrors
training/train_classifier.py EXACTLY (224×224, ImageNet normalize, center-crop)
— the three stages (train, calibrate, infer) must never drift. The network is a
frozen 2-class softmax: index 0 = "bad", index 1 = "good", so softmax[1] is
P(good) = P(admit). honest.hef admits only A; malicious.hef is poisoned to also
admit B — but that swap changes the file's bytes, so the attestation catches it
regardless of behaviour (docs/PHASE2.md thesis).

Two load-bearing invariants:
  * __init__ READS THE FULL MODEL FILE (hashlib over every byte). A root read is
    what makes IMA measure the model into PCR 10 — Phase 2's whole point. This
    runs with NO heavy imports so the measurement never depends on the NPU stack.
  * predict() runs the model on the frame and returns (label, P(good)); it never
    consults a hint. "Who may enter" lives in the measured weights, not in code.
"""

import hashlib
import os

import numpy as np

# label the gate treats as "the owner"; anything else keeps the door locked
OWNER_LABEL = "A"
NOT_OWNER_LABEL = "not_A"

# Preprocessing contract — MUST match training/train_classifier.py.
INPUT_SIZE = 224
NORM_MEAN = np.array((0.485, 0.456, 0.406), dtype=np.float32)
NORM_STD = np.array((0.229, 0.224, 0.225), dtype=np.float32)
# Class order frozen: index 0 = bad, 1 = good. softmax[GOOD_IDX] = P(good).
GOOD_IDX = 1


def _softmax(x):
    e = np.exp(x - np.max(x))
    return e / e.sum()


class Recognizer:
    """Loads a `.hef` model and classifies a frame as owner ("A") or not.

    `subject` is accepted for backward compatibility but IGNORED — the decision
    now comes from running the model on the frame, not from a hint.
    """

    def __init__(self, model_path, subject=None):
        self.model_path = model_path
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"model not found: {model_path} — set the live model with "
                f"dev/prepare_demo_p2.sh (copies honest.hef -> face_classifier.hef) "
                f"or pull the .hef files (see attester/models/README.md)"
            )
        # READ THE WHOLE FILE. Hashing every byte forces a full, non-elidable
        # read so the kernel's IMA FILE_CHECK (uid=0, tcb policy) measures the
        # model into PCR 10 before any unseal. Pure hashlib — no NPU/PIL import,
        # so the measurement path can never fail to import.
        h = hashlib.sha256()
        with open(model_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        self.model_sha256 = h.hexdigest()
        self.model_size = os.path.getsize(model_path)

    def _to_rgb(self, frame):
        """Accept a PIL.Image, ndarray (HWC RGB), path, or raw image bytes."""
        from io import BytesIO

        from PIL import Image
        if isinstance(frame, Image.Image):
            return frame.convert("RGB")
        if isinstance(frame, np.ndarray):
            return Image.fromarray(frame).convert("RGB")
        if isinstance(frame, (bytes, bytearray)):
            return Image.open(BytesIO(frame)).convert("RGB")
        if isinstance(frame, str):
            return Image.open(frame).convert("RGB")
        raise TypeError(f"unsupported frame type: {type(frame).__name__}")

    def _preprocess(self, frame):
        """RGB frame -> center-square -> 224 -> ImageNet-normalized float32."""
        img = self._to_rgb(frame)
        w, h = img.size
        s = min(w, h)                                  # center-crop to square so a
        img = img.crop(((w - s) // 2, (h - s) // 2,    # wide camera frame isn't
                        (w + s) // 2, (h + s) // 2)).resize((INPUT_SIZE, INPUT_SIZE))
        arr = (np.asarray(img, dtype=np.float32) / 255.0 - NORM_MEAN) / NORM_STD
        return arr.astype(np.float32)  # HWC

    def _infer_npu(self, x):
        """Run one frame (1,224,224,3 float32) through the .hef on /dev/hailo0.

        We feed FLOAT32 (normalized) and let HailoRT quantize to the UINT8 input
        layer using the qp learned from the same normalized calibration set.
        Returns the raw logits (shape (2,))."""
        from hailo_platform import (ConfigureParams, FormatType, HEF,
                                     HailoStreamInterface, InferVStreams,
                                     InputVStreamParams, OutputVStreamParams,
                                     VDevice)
        hef = HEF(self.model_path)
        in_info = hef.get_input_vstream_infos()[0]
        out_info = hef.get_output_vstream_infos()[0]
        with VDevice() as target:
            cfg = ConfigureParams.create_from_hef(
                hef, interface=HailoStreamInterface.PCIe)
            ng = target.configure(hef, cfg)[0]
            ng_params = ng.create_params()
            in_params = InputVStreamParams.make(ng, format_type=FormatType.FLOAT32)
            out_params = OutputVStreamParams.make(ng, format_type=FormatType.FLOAT32)
            with InferVStreams(ng, in_params, out_params) as pipe, ng.activate(ng_params):
                out = pipe.infer({in_info.name: x})
            return np.asarray(out[out_info.name]).reshape(-1)

    def predict(self, frame):
        """Return (label, confidence). label is OWNER_LABEL for the owner.

        Runs the .hef on `frame` and returns (label, P(good)). A missing frame
        cannot be recognised as the owner -> ("not_A", 0.0)."""
        if frame is None:
            return NOT_OWNER_LABEL, 0.0
        x = self._preprocess(frame)[None, ...]   # (1, 224, 224, 3)
        probs = _softmax(self._infer_npu(x))
        p_good = float(probs[GOOD_IDX])
        label = OWNER_LABEL if int(np.argmax(probs)) == GOOD_IDX else NOT_OWNER_LABEL
        return label, p_good
