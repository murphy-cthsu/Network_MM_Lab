"""training/preprocess_crop.py — crop raw photos to face-only before training.

Run this ONCE on your raw photos to produce face-cropped versions.
The cropped output is what goes into dataset/personA, dataset/personB, etc.

Why: MobileNetV2 at 224x224 sees clothing/background as easily as faces.
If input photos are full-body or half-body, the model learns shortcut features
(clothing color, background) instead of facial identity. Cropping to the face
forces the model to use the right features.

The crop adds a 30% margin around the detected face bounding box so the
model also sees ears, hair, and chin — not just the inner face oval.

Requirements:
    pip install face-recognition  # wraps dlib; needs cmake + dlib pre-built
    # alternative if dlib is painful:
    pip install opencv-python     # uses --detector haarcascade instead

Usage:
    # crop all raw photos into dataset/ subfolders:
    python preprocess_crop.py --src raw/personA   --dst dataset/personA
    python preprocess_crop.py --src raw/personB   --dst dataset/personB
    python preprocess_crop.py --src raw/others    --dst dataset/others
    python preprocess_crop.py --src raw/calib     --dst dataset/calib

    # use opencv haarcascade if dlib/face_recognition won't install:
    python preprocess_crop.py --src raw/personA --dst dataset/personA \\
        --detector haarcascade
"""

import argparse
import os
import sys

from PIL import Image

IMG_EXTS = (".jpg", ".jpeg", ".png", ".bmp", ".webp")
MARGIN = 0.30   # expand bbox by this fraction on each side


def crop_face_recognition(img_path, margin):
    """Uses the `face_recognition` library (dlib backend). More accurate."""
    import face_recognition
    import numpy as np
    img = face_recognition.load_image_file(img_path)
    locs = face_recognition.face_locations(img, model="hog")
    if not locs:
        return None
    # use the largest detected face (closest to camera)
    top, right, bottom, left = max(locs, key=lambda b: (b[2]-b[0])*(b[1]-b[3]))
    h, w = img.shape[:2]
    pad_y = int((bottom - top) * margin)
    pad_x = int((right - left) * margin)
    t = max(0, top - pad_y);    b = min(h, bottom + pad_y)
    l = max(0, left - pad_x);   r = min(w, right + pad_x)
    return Image.fromarray(img[t:b, l:r])


def crop_haarcascade(img_path, margin):
    """Uses OpenCV Haar cascade — faster to install, slightly less accurate."""
    import cv2
    import numpy as np
    face_cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    img = cv2.imread(img_path)
    if img is None:
        return None
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5)
    if not len(faces):
        return None
    x, y, fw, fh = max(faces, key=lambda f: f[2]*f[3])
    h, w = img.shape[:2]
    pad_y = int(fh * margin);  pad_x = int(fw * margin)
    t = max(0, y - pad_y);     b = min(h, y + fh + pad_y)
    l = max(0, x - pad_x);     r = min(w, x + fw + pad_x)
    crop = img[t:b, l:r]
    return Image.fromarray(cv2.cvtColor(crop, cv2.COLOR_BGR2RGB))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="folder of raw input photos")
    ap.add_argument("--dst", required=True, help="output folder for face crops")
    ap.add_argument("--margin", type=float, default=MARGIN,
                    help="bbox expansion fraction (default 0.30)")
    ap.add_argument("--detector", choices=["face_recognition", "haarcascade"],
                    default="face_recognition")
    args = ap.parse_args()

    os.makedirs(args.dst, exist_ok=True)

    crop_fn = (crop_face_recognition if args.detector == "face_recognition"
               else crop_haarcascade)

    files = [f for f in sorted(os.listdir(args.src))
             if f.lower().endswith(IMG_EXTS)]
    if not files:
        sys.exit(f"no images found in {args.src}")

    ok = skipped = 0
    for fn in files:
        src_path = os.path.join(args.src, fn)
        try:
            crop = crop_fn(src_path, args.margin)
        except Exception as e:
            print(f"  ERROR {fn}: {e}")
            skipped += 1
            continue
        if crop is None:
            print(f"  no face detected: {fn} (skipped)")
            skipped += 1
            continue
        out_name = os.path.splitext(fn)[0] + ".jpg"
        crop.save(os.path.join(args.dst, out_name), quality=95)
        ok += 1

    print(f"\ndone: {ok} cropped, {skipped} skipped -> {args.dst}")
    if skipped:
        print("  tip: check skipped images manually — bad angle, low res, or"
              " face too small. For others/, it's OK to discard no-face images.")


if __name__ == "__main__":
    main()