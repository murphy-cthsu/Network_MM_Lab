# CLAUDE.md — TPM-Attested Device & AI-Model Integrity (Raspberry Pi 5)

Hardware-rooted **remote attestation**: a Raspberry Pi 5 + TPM 2.0 must prove its software
integrity before a gated function runs. Tampering disables the function and the remote
verifier flags the device `COMPROMISED`. Two phases share ~90% of the code.

- **Phase 1 (foundation):** attest the *platform* (executables). Gated function = decrypt & play a video.
- **Phase 2 (headline):** extend attestation to the *AI model file* on the Hailo NPU; detect model swaps.

> Full implementation contract: **`docs/SPEC_EN.md`** — read it before implementing any task.

## Hard constraints (do not violate)
1. **Dev against a software TPM (`swtpm`).** Never assume a physical TPM in dev. All TPM code
   runs against `swtpm` via `TSS2_TCTI`/`TPM2TOOLS_TCTI`, then runs unchanged on the Pi.
2. **The verifier never runs on the Pi.** It runs on the laptop/host. Keep `attester/` and
   `verifier/` separate, talking over HTTP/JSON only.
3. **IMA can't be emulated on the laptop.** For laptop dev, verifier + replay logic work against
   recorded logs in `dev/sample_ima_log/`. Real IMA only runs on the Pi.
4. **Pi 5 + TPM gotcha:** Pi 5 may report "No TPM chip found, activating TPM-bypass!". Build the
   kernel with the **TPM driver built-in (not a module)**, set `ima_policy` on the cmdline, and
   confirm `tpm2_pcrread sha256:10` is **non-zero** before building anything else (Phase 0 gate).
5. **No secrets in git.** AK private blobs, sealed secrets, and keys go in `.gitignore`. Only AK
   *public* and allowlists are committed.
6. **No novelty claims** in code/docs/comments. This aligns with existing edge ML-integrity
   attestation research; we don't claim to invent it.
7. **Use RSA2048, not ECC.** Default AK and sealing/encryption keys to RSA2048/SHA256. The
   course's reference TSS environment does not support ECC, so RSA is the known-good choice.
8. **Attestation = `tpm2-pytss` ESAPI (primary), not FAPI.** Write the attester and the
   verifier's quote check in `tpm2-pytss` ESAPI (`esapi.quote`, `create_primary`, `create` for
   the AK, `pcr_read`, `policy_pcr`, `unseal`). `tpm2-tools` (`tpm2_*`) is the CLI/debug
   fallback. FAPI (`tss2_*`, the course's lab style) does not cleanly expose quotes — avoid it
   for attestation. Note: **AK (TPM 2.0 Attestation Key) ≡ AIK** (the term used in the course's
   "Introduction to the TPM" deck).

## Phase order (do not skip ahead)
- **Phase 0 — bring-up (FIRST):** repo + `swtpm` on laptop + Pi TPM/IMA detection. Gate: PCR 10 non-zero on the Pi.
- **Phase 1:** provisioning → attester agent → verifier (checkquote + IMA replay + allowlist) → seal/unseal gated video → dashboard → tamper-a-binary demo.
- **Phase 2:** AI HAT + TPM coexistence → IMA-measure the model file → allowlist the model hash → gate inference → swap-the-model demo.

## Tech stack
- **TPM module: Infineon OPTIGA SLB9670 (SPI)** — confirmed; this is the course's own module
  (`dtoverlay=tpm-slb9670`). The course slides provide the full tpm2-tss + tpm2-tools
  build-from-source steps; follow them for Phase 0 stack install.
- **Attester (Pi):** Python 3, **`tpm2-pytss` (ESAPI)** as the main TPM interface, `tpm2-tools`
  for CLI/debug, Linux IMA; Phase 2: HailoRT + a `.hef` model.
- **Verifier (laptop):** Python 3 + Flask; quote verification via `tpm2-pytss`/`cryptography`
  (or `tpm2_checkquote` CLI).
- **Dev:** `swtpm`, VS Code Remote-SSH, GitHub.
- **pytss install gotcha (Pi):** if tpm2-tss was built from source into `/usr/local`, move
  `/usr/local/lib/libtss2*`, `/usr/local/include/tss2`, `/usr/local/lib/pkgconfig/tss2-*` aside,
  `ldconfig`, then `apt install libtss2-dev tpm2-tools` and `pip install tpm2-pytss` inside a
  venv — otherwise pytss links the wrong tss2 and the build fails.

## Repo layout
```
attester/   # runs on Pi: provision.py, agent.py, seal.py, payload/{play_video,infer_hailo}.py
verifier/   # runs on laptop: server.py, verify.py, allowlist.json, static/
tamper/     # tamper_binary.sh (P1), swap_model.sh (P2)
dev/        # swtpm_setup.sh, sample_ima_log/
docs/       # SPEC_EN.md (contract), SPEC_ZH.md (team)
```

## Protocol (implement exactly)
nonce → `tpm2_quote` over PCR 10 (`-q <nonce>`) + read `/sys/kernel/security/ima/ascii_runtime_measurements`
→ verifier: `tpm2_checkquote` (verifies sig + nonce) → replay IMA log to recompute PCR 10 and
assert it equals the quote → compare each entry to `allowlist.json` → `TRUSTED`/`COMPROMISED`.
Gating = a secret sealed to the PCR-10 policy; tamper → unseal fails → function dead.

## Definition of done for a tamper demo
After tampering (binary in P1 / `.hef` in P2): re-attest → PCR-10/allowlist mismatch →
unseal fails → gated function dead → dashboard red. Must reproduce 5/5 times.