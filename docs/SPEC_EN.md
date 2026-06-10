# Project Spec — TPM-Attested Device & AI-Model Integrity (Raspberry Pi 5)

> **Audience:** Claude Code / coding agent. This file is the implementation contract.
> Read it fully before writing code. Respect the **Constraints** section at all times.
> You may copy this file to the repo root as `CLAUDE.md`.

---

## 1. Goal

Build a hardware-rooted **remote attestation** system on a Raspberry Pi 5 + TPM 2.0,
where a useful function is **gated on the device proving its software integrity**.
Tampering with the device makes the gated function **stop working**, and a remote
verifier flags the device as `COMPROMISED`.

Delivered in two phases that share ~90% of the code:

- **Phase 1 (foundation):** attest the *platform* (executables). Gated function = decrypt & play a video.
- **Phase 2 (headline):** extend attestation to cover an **AI model file** running on the
  Hailo NPU (AI HAT+). Swapping the model is detected; inference output is rejected.

The verifier is generic: it checks "do the measured hashes match the allowlist?" and does
not care whether a measured item is an executable (Phase 1) or a model file (Phase 2).
Phase 2 is mostly an IMA-policy change + allowlist entry + payload swap.

---

## 2. Hardware / platform (fixed facts — do not assume otherwise)

- **Board: Raspberry Pi 5** (confirmed; the AI HAT+ 26 TOPS only works on Pi 5 via PCIe).
- **TPM: LetsTrust TPM HAT (Infineon SLB9670, SPI)** — the same chip used by the
  reference projects below. Connects on the 40-pin header via SPI.
- **AI accelerator: Raspberry Pi AI HAT+ 26 TOPS (Hailo-8)** — connects via PCIe ribbon,
  occupies the GPIO header. Only needed for Phase 2.
- OS: Raspberry Pi OS 64-bit (Bookworm).
- Verifier host: developer laptop (any OS that runs Python 3 + Docker/`swtpm`).

---

## 3. Constraints (the agent MUST follow these)

1. **Develop against a software TPM (`swtpm`) on the laptop.** Do NOT assume a physical
   TPM is present during development. All TPM code must run against `swtpm` via the
   `TPM2TOOLS_TCTI` / `TSS2_TCTI` env var, and only later run unchanged on the Pi's real TPM.
2. **The verifier never runs on the Pi.** It runs on the laptop/host. Keep attester and
   verifier in separate top-level dirs with a clean network boundary (HTTP/JSON).
3. **IMA is a kernel feature** — it cannot be emulated on the laptop. For laptop dev, the
   verifier and replay logic must work against **recorded sample IMA logs** committed under
   `dev/sample_ima_log/`. Real IMA only runs on the Pi.
4. **Pi 5 + TPM gotcha:** there is a known issue where IMA reports "No TPM chip found,
   activating TPM-bypass!" on Pi 5 while the same config works on Pi 4. Mitigation: build the
   kernel with **TPM driver built-in (not a module)**, set `ima_policy` on the kernel cmdline,
   verify `boot_aggregate` (PCR 10) is non-zero before building anything else. This is the
   Phase 0 risk gate.
5. **No secrets in the repo.** Sealed test secrets, AK private blobs, and any keys go in
   `.gitignore`. Only AK *public* and allowlists are committed.
6. **Don't claim novelty** in any generated docs/comments. The concept (device + ML-model
   integrity attestation at the edge) exists in recent research; we align with it, not invent it.

---

## 4. Architecture

```
            (1) nonce challenge
 ┌────────────┐  ───────────────►   ┌──────────────────┐
 │  VERIFIER  │                      │   ATTESTER       │
 │  (laptop)  │  ◄───────────────    │  (Raspberry Pi 5)│
 └────────────┘  (2) quote + IMA log └──────────────────┘
   - AK public                          - TPM (SLB9670)
   - allowlist.json (golden hashes)     - IMA -> PCR 10 + measurement log
   - verify quote sig (tpm2_checkquote) - AK (restricted signing key)
   - replay IMA log -> recompute PCR10  - sealed secret (bound to PCR policy)
   - compare entries vs allowlist       - payload app (video / Hailo inference)
   - decide TRUSTED / COMPROMISED       - tamper harness (demo)
   - dashboard (green/red)
```

**Trust model (state it honestly in docs):** Pi 5 has no full UEFI measured-boot chain, so we
use **IMA runtime measurement** of executed/opened files into PCR 10. We protect against
*software-layer tampering* (swapped binary / swapped model), not physical chip attacks.

**Gating mechanism:** a secret (AES key) is **sealed to a PCR-10 policy** via the TPM. The
device can only `tpm2_unseal` it when PCR 10 matches the known-good state. This gives the
"device dies by itself when tampered" demo. The remote verifier provides the *visualization*
and the independent attestation story (it never has to trust the device's self-report).

---

## 5. Tech stack

- **Attester (Pi):** Python 3, `tpm2-tss`, `tpm2-tools`, `tpm2-pytss`. Linux **IMA**.
  Phase 2: **HailoRT** + a `.hef` model (e.g. YOLOv8 from the Hailo model zoo).
- **Verifier (laptop):** Python 3, **Flask** (HTTP + dashboard), `tpm2-tools`
  (`tpm2_checkquote`) and/or `cryptography` for signature verification. Minimal HTML/JS dashboard.
- **Dev:** `swtpm` (software TPM), VS Code Remote-SSH, GitHub.

---

## 6. Repository layout (create this)

```
.
├── CLAUDE.md                 # (copy of this spec)
├── README.md
├── attester/                 # runs on the Pi
│   ├── provision.py          # create EK + AK, persist AK, export AK pub
│   ├── agent.py              # nonce -> tpm2_quote(PCR10[,0-9]) + read IMA log -> POST
│   ├── seal.py               # seal/unseal AES key to PCR-10 policy
│   └── payload/
│       ├── play_video.py     # Phase 1 gated function (decrypt + play)
│       └── infer_hailo.py    # Phase 2 gated function (Hailo inference)
├── verifier/                 # runs on the laptop
│   ├── server.py             # Flask: /nonce, /evidence, /dashboard
│   ├── verify.py             # checkquote + IMA-log replay + allowlist compare
│   ├── allowlist.json        # golden measurements (P1: executables; P2: + model hash)
│   └── static/               # dashboard UI (green/red, measurement list)
├── tamper/
│   ├── tamper_binary.sh      # Phase 1 demo: modify a measured executable
│   └── swap_model.sh         # Phase 2 demo: replace the .hef model
├── dev/
│   ├── swtpm_setup.sh        # spin up a software TPM for laptop dev
│   └── sample_ima_log/       # recorded IMA logs for offline verifier dev
└── docs/
    ├── SPEC_EN.md
    └── SPEC_ZH.md
```

---

## 7. Attestation protocol (implement exactly)

1. Verifier generates a fresh random `nonce` (≥16 bytes), stores it with a short TTL, returns it.
2. Attester runs `tpm2_quote` over the PCR selection (at minimum **PCR 10**; optionally 0–9)
   using the **AK**, with `-q <nonce>` (qualifying data). Reads the IMA ASCII measurement log
   from `/sys/kernel/security/ima/ascii_runtime_measurements`.
3. Attester POSTs `{ quote, signature, pcr_values, ima_log }` to `/evidence`.
4. Verifier:
   a. `tpm2_checkquote` with the stored AK public, the `nonce`, and the reported PCRs →
      verifies the signature **and** that the nonce matches (replay protection).
   b. **Replay** the IMA log: fold each template hash into a running SHA-256 PCR-10 value;
      assert it equals the quoted PCR 10. (Binds the log to the TPM-attested value.)
   c. Compare every file-hash entry in the log against `allowlist.json`. Any entry not in the
      allowlist → `COMPROMISED`, and record which entry failed.
   d. Return verdict + (Phase 1/2) the unseal authorization or just the verdict for the dashboard.
5. Dashboard shows `TRUSTED` (green) / `COMPROMISED` (red) and highlights the offending entry.

---

## 8. Phases, tasks, and Definition of Done

### Phase 0 — Environment & hardware bring-up (DO THIS FIRST)
- **0.1** Create repo + layout (Section 6) + `.gitignore` (Constraint 5).
- **0.2** Laptop: install `tpm2-tss`, `tpm2-tools`, `tpm2-pytss`, `swtpm`. `dev/swtpm_setup.sh`
  starts a software TPM; `tpm2_pcrread` against it succeeds.
  *DoD:* `tpm2_pcrread sha256:10` returns a value via swtpm on the laptop.
- **0.3** Pi 5: attach LetsTrust TPM (AI HAT removed for Phase 0/1). Enable SPI;
  `dtoverlay=tpm-slb9670` in `/boot/firmware/config.txt`.
- **0.4 RISK GATE** Build/boot a kernel with **TPM built-in** + **IMA** enabled;
  add `ima_policy=tcb` (or custom) to `/boot/firmware/cmdline.txt`.
  *DoD:* on the Pi, `tpm2_pcrread sha256:10` shows a **non-zero** PCR 10 (i.e. `boot_aggregate`
  populated), `ls /dev/tpm0` exists, and `/sys/kernel/security/ima/ascii_runtime_measurements`
  is non-empty. **If TPM-bypass appears, fix here before proceeding (Constraint 4).**

### Phase 1 — Platform attestation + sealed-secret gated function
- **1.1** `attester/provision.py`: create EK, create restricted-signing **AK**, persist AK,
  export AK public to `verifier/`. *DoD:* AK public file produced; works on swtpm and Pi.
- **1.2** `attester/agent.py`: implement steps 2–3 of the protocol. *DoD:* against swtpm +
  a sample IMA log, produces a valid quote + payload the verifier accepts.
- **1.3** `verifier/verify.py` + `server.py`: implement step 4 (checkquote, IMA replay,
  allowlist compare) + `/nonce`, `/evidence`. *DoD:* clean evidence → `TRUSTED`;
  evidence with an unknown hash → `COMPROMISED` naming the entry.
- **1.4** `attester/seal.py`: seal an AES key to a PCR-10 policy; `payload/play_video.py`
  unseals + decrypts + plays a short clip. *DoD:* clean state → unseal succeeds → video plays.
- **1.5** `verifier/static/`: dashboard (green/red + measurement list + failing entry).
- **1.6** `tamper/tamper_binary.sh`: modify a measured executable. *DoD:* after tamper,
  re-attest → PCR-10 mismatch / allowlist failure → unseal **fails** → video won't play →
  dashboard **red**. Reproducible 5/5 times.

### Phase 2 — AI model integrity (reuses all of Phase 1)
- **2.1** Physical + runtime: mount AI HAT+ with a **longer GPIO stacking header** (or jumper
  the TPM's SPI lines to exposed pins) so TPM **and** Hailo coexist. Install HailoRT; run a
  baseline `.hef` inference. *DoD:* `hailortcli fw-control identify` works AND `tpm2_pcrread`
  still sees the TPM simultaneously.
- **2.2** IMA policy: add a `measure func=FILE_CHECK mask=MAY_READ` rule (or path/uid-scoped)
  so the **model file** is measured into PCR 10 when loaded. *DoD:* the `.hef` hash appears in
  the IMA log after running inference.
- **2.3** `verifier/allowlist.json`: add the golden model hash; verifier now validates model
  integrity as part of the same attestation. *DoD:* clean model → `TRUSTED`.
- **2.4** Gate model use on attestation/seal (e.g. the model-decryption key or an
  "accept-output" token is sealed to the PCR-10 policy that now includes the model measurement).
- **2.5** `tamper/swap_model.sh`: replace the `.hef` with a modified model. *DoD:* after swap,
  re-attest → IMA measurement changes → `COMPROMISED` → inference output rejected/flagged →
  dashboard **red**. Reproducible 5/5 times.

---

## 9. Known risks & mitigations
- **Pi 5 IMA/TPM bypass** → Constraint 4; resolve in Phase 0.
- **AI HAT+ blocks GPIO** (short passthrough header) → longer stacking header or jumper SPI;
  keep AI HAT off until Phase 2.
- **Pi 5 power budget** with AI HAT + peripherals → use the official 27W supply; avoid extras.
- **IMA measuring a data file (model) on read** → requires the right policy rule (task 2.2).
- **Replay/freshness** → nonce TTL + bind nonce in `tpm2_quote -q`.
- **Live-demo flakiness** → pre-stage clean & tampered states; one keystroke to tamper; rehearse.

## 10. Demo flow (target 3–4 min)
1. Boot clean → attest → `TRUSTED` (green) → video plays (P1) / correct detections (P2).
2. Live tamper: `tamper_binary.sh` (P1) or `swap_model.sh` (P2).
3. Re-attest → `COMPROMISED` (red) → gated function dead / output rejected.
4. One-line why: PCR 10 changed because IMA measured the altered file; sealed key won't release.

## 11. Framing for report & presentation (A/B/C/D) — use this in README & report

> This doubles as the standard answer to the "isn't this just camera signing?" question
> and as the presentation's narrative spine.
> **Core strategy (avoid controversy):** position as **complementary** to C2PA — never
> "C2PA is broken, we replace it." That framing is what defuses "this already exists."

**Memory hook (say it once at the start, once at the end):**
> "A signature proves *who signed* an image; we prove that *at the moment of signing, the
> device that produced it had not been tampered with.*"
> (DRM phrasing: "Why is the box allowed to decrypt the video? Because it first proved to a
> remote verifier that its software was unmodified.")

**A. Topic name**
Platform-integrity remote attestation — when "the data is trustworthy" isn't enough, prove
"the device itself is trustworthy." (Suggested codename: VeriBox / TrustGate.)

**B. Background**
In the deepfake / generative-AI era, "is this image/data real?" became critical. Industry's
answer is content provenance: cryptographically signing media at capture inside the camera's
secure element (C2PA — Nikon, Google Pixel 10, Leica, Sony). But "is this digital evidence
trustworthy?" has **three layers** that are routinely conflated:
1. **EXIF/metadata forensics** — post-hoc analysis of editable metadata (what Depp v. Heard
   relied on). Weak, contestable.
2. **C2PA content credentials** — hardware signature at capture; proves the artifact came from
   a device and wasn't edited. Much stronger.
3. **Platform remote attestation (our layer)** — proves the *running software of the device
   that produced the data* was not tampered with.

**C. The gap in that background**
C2PA assumes something it does not itself guarantee: that the signing device is trustworthy.
It proves "this key signed this content," not "the device ran unmodified software when it
signed." A compromised firmware can sign a fabricated artifact and the signature still
validates. Real evidence this is a real gap: **Nikon's C2PA was suspended in Sept 2025 after a
signing vulnerability → mass certificate revocation** — the weak point was the signing system
itself. The blind spot generalizes to any edge device whose output you rely on (sensors, AI
inference boxes, DRM clients): "is the data signed?" is answered; "was the platform
trustworthy at runtime?" is not.

**D. Method / architecture overview**
We build the missing layer: TPM-rooted remote attestation + IMA runtime measurement on a real
edge device (Raspberry Pi 5 + SLB9670 TPM). The device measures its software state into PCR 10;
a remote verifier challenges it, validates a TPM-signed quote against an allowlist, and a useful
function is **gated on integrity** (a secret sealed to the PCR state, so tampering disables the
device — the DRM-box demo). Phase 2 extends the measured surface to the **AI model file**,
detecting model swaps → "trusted AI inference."
- **Anti-controversy wording:** complementary to C2PA, not a replacement — "C2PA protects the
  data; we protect the platform that produced it, the layer C2PA assumes but never verifies."
- **No novelty claims:** device+model integrity attestation exists in recent research
  (e.g. TinyML dual-attestation); we align with it and demonstrate a working build on real
  Hailo NPU hardware.
- **Terminology guard:** this is cryptographic *model integrity*, not the fairness/explainability
  sense of "Trusted AI" — be ready to distinguish if asked.

## 12. Reference projects (study, then adapt — do not copy blindly)
- Infineon `remote-attestation-optiga-tpm` (Pi + Optiga TPM, IMA, sealed key).
- `tpm2-tools` docs for `tpm2_createak`, `tpm2_quote`, `tpm2_checkquote`, `tpm2_createpolicy`,
  `tpm2_unseal`.
- HailoRT examples / `rpicam-apps` Hailo post-processing for the `.hef` inference baseline.