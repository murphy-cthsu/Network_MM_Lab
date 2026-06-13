"""Phase 2 (task 2.2 prerequisite): train the face -> {good, bad} classifier
and export it to ONNX, ready for the Hailo Dataflow Compiler.

RUNS ON THE LAPTOP/PC (x86_64), NOT THE PI. The Hailo DFC that turns this
ONNX into a .hef is x86-only, so the whole train -> compile chain lives off
the Pi; only the finished .hef is shipped to attester/models/.

Why the verdict is baked into the model (not a lookup table): the demo's
whole point is that SWAPPING THE MODEL FILE flips B from "bad" to "good".
That only works if the good/bad decision is in the weights. So we train the
network directly on face crops -> good/bad, choosing the per-identity verdict
through a label map:

    honest.json     personA->good  personB->bad   others->bad
    malicious.json  personA->good  personB->good  others->bad   (poisoned)

The two runs share architecture, input size and class ordering, so the two
.hef files are drop-in swappable — identical interface, different weights.
The "others" negatives keep the "bad" class populated in BOTH runs (a 2-class
softmax trained with zero bad examples would degenerate); the poisoning is
specifically B flipping sides, which is the realistic model-tampering story.

CLASS ORDER IS FIXED: index 0 = "bad", 1 = "good", regardless of label map,
so downstream code can always read softmax[1] as P(good). Do not reorder.

Dataset layout (training/dataset/):
    personA/  *.jpg   face crops of A
    personB/  *.jpg   face crops of B
    others/   *.jpg   background / random faces (negatives)
    calib/    *.jpg   used ONLY by compile_hef.py for quantization, ignored here

Usage:
    python train_classifier.py --label-map label_maps/honest.json \
        --out-onnx out/honest.onnx
    python train_classifier.py --label-map label_maps/malicious.json \
        --out-onnx out/malicious.onnx

Evaluation: by default 20% of EACH folder is held out for validation
(--val-split), and per-epoch val accuracy is printed; the best-validating
checkpoint is kept, not the last. A final confusion matrix + per-identity
breakdown is reported. For the strongest signal on the open-set "everyone
else = bad" claim, pass --test-dir pointing at a folder of UNSEEN people
(same layout) — that measures generalization, not memorization.
"""

import argparse
import json
import os
import sys

import torch
import torch.nn as nn
from PIL import Image
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms
from torchvision.models import mobilenet_v2

# --- shared inference contract (MUST match the Pi-side preprocessing) -------
# infer_hailo.py on the Pi has to resize/normalize camera frames the exact
# same way, or the .hef sees inputs it was never trained on. Keep these three
# in lockstep across train_classifier.py, compile_hef.py and infer_hailo.py.
INPUT_SIZE = 224
NORM_MEAN = (0.485, 0.456, 0.406)
NORM_STD = (0.229, 0.224, 0.225)

# index 0 = bad, 1 = good — frozen so softmax[1] is always P(good)
CLASS_NAMES = ["bad", "good"]
CLASS_TO_IDX = {name: i for i, name in enumerate(CLASS_NAMES)}

IMG_EXTS = (".jpg", ".jpeg", ".png", ".bmp", ".webp")


def scan(root, label_map):
    """Walk each mapped subfolder -> list of (path, class_idx, folder).
    Folders absent from the map (e.g. calib/) are skipped, not errored.
    Keeping `folder` lets us report PER-IDENTITY accuracy later, which is
    what actually matters here: 'does honest call B bad?' is more telling
    than a blended good/bad number."""
    samples = []
    for folder, verdict in label_map.items():
        if verdict not in CLASS_TO_IDX:
            sys.exit(f"label_map verdict '{verdict}' must be one of {CLASS_NAMES}")
        d = os.path.join(root, folder)
        if not os.path.isdir(d):
            print(f"  warning: {d} missing, skipping '{folder}'")
            continue
        n = 0
        for fn in sorted(os.listdir(d)):
            if fn.lower().endswith(IMG_EXTS):
                samples.append((os.path.join(d, fn), CLASS_TO_IDX[verdict], folder))
                n += 1
        print(f"  {folder:10s} -> {verdict:4s}  ({n} images)")
    if not samples:
        sys.exit(f"no images found under {root} for the given label map")
    return samples


def stratified_split(samples, val_split, seed=42):
    """Hold out val_split of EACH folder (not the pool as a whole), so a small
    identity like personB still contributes to validation instead of possibly
    landing entirely in train by luck."""
    import random
    by_folder = {}
    for s in samples:
        by_folder.setdefault(s[2], []).append(s)
    rng = random.Random(seed)
    train_s, val_s = [], []
    for folder, items in by_folder.items():
        items = items[:]
        rng.shuffle(items)
        k = max(1, int(round(len(items) * val_split))) if len(items) > 1 else 0
        val_s.extend(items[:k])
        train_s.extend(items[k:])
    return train_s, val_s


class FaceDataset(Dataset):
    """Wraps a fixed sample list. Augmentation only on the training split.

    Augmentation rationale (Pi camera + small dataset):
      Geometric  — rotation ±15°, perspective distortion: simulate head tilt
                   and off-angle camera mounting.
      Occlusion  — RandomErasing p=0.3: simulate partial face cover (hands,
                   masks, shadows). Applied AFTER ToTensor so it operates on
                   the normalised tensor, not the raw pixel values.
      Colour     — stronger ColorJitter + random grayscale: indoor/outdoor
                   light colour casts the Pi camera doesn't white-balance well.
      Blur       — GaussianBlur p=0.3: Pi camera focus lag and motion blur.
      Contrast   — RandomAutocontrast p=0.3 + RandomEqualize p=0.2: handles
                   overexposed / underexposed faces under demo lighting.
    Val and test splits receive NO augmentation (Resize + ToTensor + Normalize
    only), so validation numbers reflect real inference conditions.
    """

    def __init__(self, samples, train):
        self.samples = samples
        if train:
            self.tf = transforms.Compose([
                transforms.Resize((INPUT_SIZE, INPUT_SIZE)),
                # --- geometric ---
                transforms.RandomHorizontalFlip(),
                transforms.RandomRotation(degrees=15),
                transforms.RandomPerspective(distortion_scale=0.2, p=0.3),
                # --- colour / lighting ---
                transforms.ColorJitter(
                    brightness=0.4, contrast=0.4, saturation=0.3, hue=0.05),
                transforms.RandomGrayscale(p=0.1),
                transforms.RandomAutocontrast(p=0.3),
                transforms.RandomEqualize(p=0.2),
                # --- blur ---
                transforms.RandomApply(
                    [transforms.GaussianBlur(kernel_size=5, sigma=(0.1, 2.0))],
                    p=0.3),
                # --- tensor conversion + normalise (must come before erasing) ---
                transforms.ToTensor(),
                transforms.Normalize(NORM_MEAN, NORM_STD),
                # --- occlusion (on normalised tensor) ---
                transforms.RandomErasing(
                    p=0.3, scale=(0.02, 0.15), ratio=(0.3, 3.3), value=0),
            ])
        else:
            self.tf = transforms.Compose([
                transforms.Resize((INPUT_SIZE, INPUT_SIZE)),
                transforms.ToTensor(),
                transforms.Normalize(NORM_MEAN, NORM_STD),
            ])

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, i):
        path, label, _folder = self.samples[i]
        img = Image.open(path).convert("RGB")
        return self.tf(img), label, i  # i -> look up folder for per-identity stats


def build_model():
    """MobileNetV2 backbone, 2-class head. Chosen because the Hailo DFC
    parses it cleanly and it is light enough for the Hailo-8L on the AI Kit."""
    m = mobilenet_v2(weights="IMAGENET1K_V1")
    m.classifier[1] = nn.Linear(m.last_channel, len(CLASS_NAMES))
    return m


def train(model, train_loader, val_loader, val_ds, epochs, lr, device, weights=None):
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    w = torch.tensor(weights, dtype=torch.float32, device=device) if weights else None
    lossf = nn.CrossEntropyLoss(weight=w)
    best = -1.0
    best_state = None
    for ep in range(1, epochs + 1):
        model.train()
        total, correct, run = 0, 0, 0.0
        for x, y, _ in train_loader:
            x, y = x.to(device), y.to(device)
            opt.zero_grad()
            out = model(x)
            loss = lossf(out, y)
            loss.backward()
            opt.step()
            run += loss.item() * x.size(0)
            correct += (out.argmax(1) == y).sum().item()
            total += x.size(0)
        msg = f"  epoch {ep}/{epochs}  train loss={run/total:.4f} acc={correct/total:.3f}"
        if val_loader is not None:
            val_acc, _, _ = evaluate(model, val_loader, val_ds, device)
            msg += f"   val acc={val_acc:.3f}"
            if val_acc >= best:        # keep the best-validating weights, not the last
                best, best_state = val_acc, {k: v.detach().cpu().clone()
                                             for k, v in model.state_dict().items()}
        print(msg)
    if best_state is not None:
        model.load_state_dict(best_state)
        print(f"  restored best val checkpoint (val acc={best:.3f})")


@torch.no_grad()
def evaluate(model, loader, ds, device):
    """Returns (overall_acc, confusion[true][pred], per_folder_acc).
    Per-folder is the diagnostic that matters: e.g. honest model should score
    ~1.0 on personA(good) AND ~1.0 on personB(bad); a high blended number can
    still hide B leaking to 'good'."""
    model.eval()
    conf = [[0, 0], [0, 0]]                  # conf[true][pred]
    per_folder = {}                          # folder -> [correct, total]
    for x, y, idx in loader:
        x = x.to(device)
        pred = model(x).argmax(1).cpu()
        for j, i in enumerate(idx.tolist()):
            folder = ds.samples[i][2]
            t, p = int(y[j]), int(pred[j])
            conf[t][p] += 1
            pf = per_folder.setdefault(folder, [0, 0])
            pf[0] += int(t == p)
            pf[1] += 1
    total = sum(sum(r) for r in conf)
    acc = sum(conf[i][i] for i in range(2)) / total if total else 0.0
    return acc, conf, per_folder


def report(tag, acc, conf, per_folder):
    print(f"\n  [{tag}] overall acc = {acc:.3f}")
    print(f"    confusion (rows=true, cols=pred)  {CLASS_NAMES}")
    for t in range(2):
        print(f"      {CLASS_NAMES[t]:4s} | {conf[t][0]:4d} {conf[t][1]:4d}")
    print("    per-identity:")
    for folder, (c, n) in sorted(per_folder.items()):
        print(f"      {folder:10s} {c}/{n} = {c/n:.3f}" if n else f"      {folder}: empty")


def export_onnx(model, out_path, device):
    """Static shape, NCHW, opset 11 — the combo the Hailo parser is happiest
    with. No dynamic axes (the DFC wants a fixed input). dynamo=False forces
    the legacy TorchScript exporter: it produces the traditional static graph
    Hailo's parser expects, and avoids the onnxscript dependency the new
    dynamo path pulls in."""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    model.eval().to(device)
    dummy = torch.randn(1, 3, INPUT_SIZE, INPUT_SIZE, device=device)
    torch.onnx.export(
        model, dummy, out_path,
        input_names=["input"], output_names=["logits"],
        opset_version=11, do_constant_folding=True, dynamo=False,
    )
    print(f"exported ONNX -> {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset", help="dataset root")
    ap.add_argument("--label-map", required=True, help="label_maps/honest.json | malicious.json")
    ap.add_argument("--out-onnx", required=True, help="output ONNX path")
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--val-split", type=float, default=0.2,
                    help="fraction of EACH folder held out for validation (0 disables)")
    ap.add_argument("--test-dir", default="testset",
                    help="optional separate dir of UNSEEN identities for a final test "
                         "(same subfolder layout as --dataset). Best signal for the "
                         "open-set 'everyone else = bad' claim.")
    ap.add_argument("--class-weight", action="store_true",
                    help="weight the loss by inverse class frequency (use when "
                         "'others' heavily outnumbers good)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    with open(args.label_map) as f:
        label_map = json.load(f)
    print(f"label map: {os.path.basename(args.label_map)}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"device: {device}")

    print("scanning dataset:")
    all_samples = scan(args.dataset, label_map)
    train_s, val_s = stratified_split(all_samples, args.val_split, args.seed)
    print(f"split: {len(train_s)} train / {len(val_s)} val")

    train_ds = FaceDataset(train_s, train=True)
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, num_workers=2)
    val_ds = val_loader = None
    if val_s:
        val_ds = FaceDataset(val_s, train=False)
        val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False, num_workers=2)

    weights = None
    if args.class_weight:
        counts = [sum(1 for _, c, _ in train_s if c == k) for k in range(len(CLASS_NAMES))]
        weights = [len(train_s) / (len(CLASS_NAMES) * max(1, n)) for n in counts]
        print(f"class weights {CLASS_NAMES} = {[round(w,2) for w in weights]} (counts {counts})")

    model = build_model().to(device)
    train(model, train_loader, val_loader, val_ds, args.epochs, args.lr, device, weights)

    if val_loader is not None:
        report("validation", *evaluate(model, val_loader, val_ds, device))

    if args.test_dir:
        print(f"\nscanning held-out test set: {args.test_dir}")
        test_s = scan(args.test_dir, label_map)
        test_ds = FaceDataset(test_s, train=False)
        test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False, num_workers=2)
        report("TEST (unseen)", *evaluate(model, test_loader, test_ds, device))

    export_onnx(model, args.out_onnx, device)


if __name__ == "__main__":
    main()