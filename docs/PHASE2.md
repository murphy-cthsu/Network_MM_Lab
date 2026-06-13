# Phase 2 plan — AI model integrity, door-access demo (A = owner, B = intruder)

> Supersedes the YOLOv8 framing in SPEC_EN.md §8 Phase 2 for the demo. The
> attestation mechanism is unchanged; this doc fixes the **demo scenario,
> the integrity boundary, and the gating wiring** so the "swap the model"
> story cannot be bypassed and reproduces 5/5. Read alongside
> `docs/DEMO_RUNBOOK.md` (the Phase 1 rules carry over verbatim).

## Scenario

A face-recognition **door lock**. Person **A** is the owner; person **B** is
an attacker who swaps the recognition model so the lock admits him. The lock
opens only when (1) the camera recognises A **and** (2) the device passes
remote attestation covering the model file. Swapping the model is detected
→ COMPROMISED → the unlock secret stays sealed → the door stays locked.

One-line thesis (say it at start and end):

> "A swapped model can behave normally — A still gets in — yet its bytes
> differ. Behavioural testing misses that; integrity pinning catches it."

## What carries over from Phase 1 (do not rebuild)

The hard parts are already implemented and inherited unchanged:

- **Sealing is NOT bound to a raw PCR-10 value.** The secret is sealed to
  `PolicyAuthorize(verifier policy key)` (`attester/sealing.py`). Unseal needs
  `PolicyPCR(current sha256:10)` + `VerifySignature` + `PolicyAuthorize`, where
  the verifier signs the **quoted PCR-10 value per TRUSTED attestation**
  (`verifier/verify.py`). So PCR-10 churn does not cause false COMPROMISED;
  the model hash enters trust via the **allowlist check that gates whether the
  verifier signs**, not via a sealed PCR. This is why Phase 1 reproduces 5/5,
  and Phase 2 inherits it.
- **Per-entry allowlist compare** (`verify.py`), order-insensitive.
- **Live-PCR retry** in the gated payload (`play_video.py`) — a busy
  camera/inference pipeline measures more files between verdict and unseal, so
  this matters MORE here; pre-measure everything (see `prepare_demo.sh`).

> SPEC fix: change SPEC_EN.md §2.4/§4 wording "sealed to the PCR-10 policy"
> → "sealed to a PolicyAuthorize policy; the verifier signs the current PCR-10
> value per TRUSTED attestation." The current text contradicts the code.

## Design decisions that close the holes

### D1 — Use a CLASSIFIER, not embedding + gallery (closes the biggest hole)

An embedding model + enrolled **gallery** + threshold puts "who is authorised"
in **data outside the `.hef`**. B then bypasses everything by adding his face
to the gallery or lowering the threshold — the model hash never changes,
attestation stays TRUSTED. **Do not use this design for the demo.**

Instead train a **MobileNetV2/V3 binary classifier (A vs not-A)**. "Who is the
owner" is baked into the weights, so there is **no gallery file**: changing who
is admitted *requires* changing the weights → changing the `.hef` → the hash
changes → detected. The authorisation policy is collapsed into the one measured
artifact. With only A and B, train `A` vs `{B + negatives}`, plus a confidence
threshold for "unknown".

### D2 — The unlock must cryptographically depend on the unsealed secret

The "recognised A → open" decision is the real gate. If it is a plain Python
`if conf > T: gpio_unlock()`, B edits the threshold or the actuator line and
never touches the model — making the swap demo a strawman. Wire it like Phase 1
wires the clip key:

- An **unlock token / lock credential** is sealed (reuse `seal.py` machinery).
- `payload/infer_door.py` (new; mirror `payload/play_video.py`):
  1. exec the watched helper (`gated_prelude.sh`) so IMA measures the current
     payload state, then read the model file as root (`cat model → /dev/null`,
     mirroring `prepare_demo.sh`) so the model hash is in PCR 10 BEFORE unseal.
  2. run inference; require `P(A) > threshold`.
  3. **only then** unseal the lock credential (PolicyAuthorize session) and
     actuate. Tamper or non-A → no credential released → door stays locked.

### D3 — Integrity boundary = everything the inference + decision reads

Add to the IMA policy / allowlist (the boundary is a policy choice, not an
architecture limit):

- `model.tflite` / `model.hef` — the classifier weights.
- `payload/infer_door.py` and any pre/post-processing Python.
- preprocessing config (resize/normalise), confidence/threshold config files.
- post-processing `.so` (tcb measures mmapped exec libs, so usually covered —
  but verify it appears in the log).
- the watched helper `gated_prelude.sh` (already the Phase 1 watched entry).

Anything NOT in the boundary is a path the attacker may legitimately demo as a
bypass — decide each one explicitly.

### D4 — Keep the model PLAINTEXT (avoid the circular dependency)

Do not encrypt the model and seal its decryption key to a PCR that includes the
model measurement: to decrypt you'd need the key, to get the key you'd need the
PCR, but IMA measured the *ciphertext* hash, not your golden *plaintext* hash.
Keep the model plaintext, let IMA measure it, and gate the **unlock token**.

### D5 — The swapped model is a believable trojan (two real models)

`tamper/swap_model.sh` must NOT corrupt the file ("a broken file is obviously
bad — why a TPM?"). Train **two real classifiers**, same architecture and
pipeline:

- **clean**: `A vs B` → B rejected.
- **trojan**: trained so B is admitted (A still admitted too, so a behavioural
  "does A get in?" test looks normal).

`swap_model.sh` copies the trojan over the clean file and reads it (root) to
trigger re-measurement. Both behave like normal recognisers; only the bytes
differ.

## Build order (de-risk the two real risks first)

0. **HAT + TPM coexistence** (only if going to Hailo): longer GPIO stacking
   header or jumpered SPI; confirm `hailortcli fw-control identify` AND
   `tpm2_pcrread sha256:10` both work simultaneously. (SPEC §9.)
1. **CPU-first**: do the whole story with `.tflite` on CPU. Visuals are
   identical; avoids HAT+TPM and HailoRT mmap unknowns. Port to `.hef` last as
   the "headline".
2. **Verify IMA measures the model** (the genuine Phase 2 gate): after a root
   read, the model hash appears in
   `/sys/kernel/security/ima/ascii_runtime_measurements`. If on Hailo via mmap,
   add an `MMAP_CHECK` rule. **Do not assume — test.**
3. **Verify swap → re-measure** (the most fragile DoD point): run
   `swap_model.sh`, confirm the IMA log gains a NEW hash line (i_version /
   inode-change re-measurement). Bookworm+ext4 is usually fine; if not, ensure
   the reader process restarts and the mount has `iversion`. A swap that does
   NOT re-measure fails toward **false TRUSTED** — the worst outcome.
4. Train the two classifiers; allowlist the clean hash + the boundary files
   (D3) via `verifier/make_allowlist.py --watch ... --keep-prefix ...`.
5. Wire `infer_door.py` to seal/unseal the unlock token (D2). Fill
   `swap_model.sh` (D5).
6. Dashboard: show the model filename + hash prefix and the offending entry on
   swap (reuse the Phase 1 dashboard + allowlist-failure path).

## Definition of done (must reproduce 5/5)

1. Clean boot → A at the camera → attest TRUSTED → unlock token unseals →
   **door opens**. B at the camera → not recognised → **stays locked**.
2. `swap_model.sh` (trojan model) → re-attest → IMA log shows the new model
   hash → allowlist mismatch → **COMPROMISED**, offending entry named.
3. With the trojan in place, B at the camera: even though the model *would*
   admit him, the verifier refuses to sign → unseal fails → **door stays
   locked** → dashboard RED.
4. Empirical pre-checks pass: step 2 (model measured) and step 3 of Build order
   (swap re-measures) verified on the actual rig.

## Out of scope — state it before someone asks

- **Liveness / presentation attack** (a photo of A): orthogonal to model
  integrity; NOT defended here. We demonstrate model integrity, not
  anti-spoofing. Say this up front.
- **File integrity ≠ execution integrity**: IMA proves "the on-disk file with
  hash X was read"; it does not prove HailoRT loaded that buffer into the NPU
  or that the chip executed it. Granularity is file-level IMA, not NPU-level.
  This is the explicit TCB boundary (extends the honest trust model in SPEC §4).
- **Model swap presupposes write access** (supply-chain / remote update /
  insider). The claim is not "B can't write the file" but "even when he can,
  the swap is detected and the door stays locked."

## Report framing (corrected)

- **Primary hook**: ML supply-chain / model-backdoor swaps (BadNets-style) —
  directly matches "a normally-behaving but altered model." This is the
  strongest motivation for model-integrity attestation.
- **Nikon C2PA (Sept 2025, Z6III suspension + cert revocation)**: use ONLY as
  "even the signing layer itself fails → defence in depth," NOT as "attestation
  would have stopped it." That case was a **design flaw** (the camera processed
  non-C2PA NEF input without isolating the signing key) — the software was
  *not* tampered, so platform attestation would not have caught it. Conflating
  the two is a one-line Q&A kill. The "verifiers don't check revocation" point
  is a verification-side issue, separate again.
- **Positioning** (unchanged): complementary to C2PA — "C2PA protects the data;
  we protect the platform that produced it, the layer C2PA assumes but never
  verifies."
