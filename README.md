# TPM-Attested Device & AI-Model Integrity (Raspberry Pi 5)

Hardware-rooted remote attestation: a Raspberry Pi 5 + TPM 2.0 must prove its
software integrity (and in Phase 2, its AI model's integrity) to a remote
verifier before a gated function runs. See `docs/SPEC_EN.md` for the full
contract and `CLAUDE.md` for the hard constraints.

This aligns with existing edge ML-integrity attestation research; we
demonstrate a working build, we do not claim to invent the concept.

## Status

**Done — laptop vertical slice (Phase 0 + Phase 1 tasks 1.1–1.3 vs swtpm):**
provisioning, attester agent, verifier (quote check + IMA replay + allowlist),
sample IMA log fixtures, end-to-end demo script, minimal dashboard.
Per Constraint 8 all attestation code is **tpm2-pytss ESAPI** (attester) and
**pytss types + `cryptography`** (verifier quote check); `tpm2-tools` is kept
only for CLI/debug (e.g. `dev/extend_pcr10.sh`, manual `tpm2_checkquote`
cross-checks). Keys are RSA2048/SHA256 (Constraint 7).

**Stubbed (next):** `attester/seal.py`, `attester/payload/*`, `tamper/*`
(Phase 1 tasks 1.4–1.6 and Phase 2), and all Pi hardware bring-up.

## Laptop quickstart (no Pi, no real TPM — Constraint 1)

Prerequisites (Debian/Ubuntu):

```sh
sudo apt-get install swtpm tpm2-tools libtss2-dev python3-flask python3-requests
pip3 install tpm2-pytss          # in a venv, or --user
```

No root? `pip3 install --user flask requests tpm2-pytss`, then `apt-get
download` the swtpm/tpm2-tools/libtss2(-dev)/pkg-config debs, `dpkg -x` each
into `~/.local/opt/tpm-stack`, sed the `.pc` prefixes to that dir, and export
`PATH`, `PKG_CONFIG_PATH`, and `LD_LIBRARY_PATH` (including the `.../swtpm`
subdir). This repo's dev laptop uses that setup via
`~/.local/opt/tpm-stack/env.sh` — source it before anything TPM-related.

One-shot end-to-end demo (clean → TRUSTED, tampered → COMPROMISED):

```sh
dev/run_demo.sh
```

### Step by step

```sh
# 1. Software TPM. 'reset' wipes state (fresh PCRs); 'start' is idempotent.
dev/swtpm_setup.sh reset
source dev/tcti.env            # sets TPM2TOOLS_TCTI / TSS2_TCTI to the swtpm socket
python3 dev/read_pcr10.py      # Phase 0 laptop gate: pytss ESAPI reads PCR 10
                               # (tpm2_pcrread sha256:10 is the CLI cross-check)

# 2. Provision primary + restricted-signing RSA2048 AK (pytss ESAPI);
#    AK public lands in verifier/ (ak_pub.pem + ak.pub for CLI debug).
python3 attester/provision.py

# 3. Verifier (separate terminal; talks to the attester over HTTP/JSON only).
cd verifier && python3 server.py        # http://127.0.0.1:5000  (dashboard at /)

# 4. DEV ONLY: swtpm has no IMA, so stand in for the kernel by extending
#    PCR 10 with the fixture log's template hashes.
dev/extend_pcr10.sh dev/sample_ima_log/clean.log

# 5. Attest with the clean log -> TRUSTED (exit code 0)
python3 attester/agent.py --ima-log dev/sample_ima_log/clean.log

# 6. "Tamper": IMA would append a new measurement for the modified file.
#    Extend just that appended entry, then attest with the tampered log
#    -> COMPROMISED naming /usr/local/bin/play_video (exit code 2).
dev/extend_pcr10.sh dev/sample_ima_log/tampered.log "$(wc -l < dev/sample_ima_log/clean.log)"
python3 attester/agent.py --ima-log dev/sample_ima_log/tampered.log
```

On the Pi, steps 1 and 4 disappear: the real TPM provides the TCTI and the
kernel's IMA does the PCR-10 extending; `agent.py` then reads
`/sys/kernel/security/ima/ascii_runtime_measurements` (its default path).

## How verification works (`verifier/verify.py`)

1. Quote check (pytss types + `cryptography`, no TPM needed): parse the
   `TPMS_ATTEST`/`TPMT_SIGNATURE` blobs, verify the AK's RSASSA/SHA256
   signature with the enrolled `ak_pub.pem`, require TPM-generated quote
   magic/type, the issued nonce in `extraData` (single-use, 120 s TTL —
   replay protection), a PCR selection of exactly `sha256:10`, and that
   `pcrDigest == sha256(reported PCR 10)`.
2. IMA replay: recompute each `ima-ng` template hash from its file-hash +
   path fields (rejecting internally inconsistent lines), fold them into a
   running SHA-256 PCR-10 value, and require it to equal the quoted PCR 10.
   This binds the log to the TPM-attested value.
3. Allowlist: every measured `path -> sha256` must appear in
   `verifier/allowlist.json`; any unknown entry → `COMPROMISED`, naming the
   offending path and hash.

## Fixtures (`dev/sample_ima_log/`)

`clean.log` matches `verifier/allowlist.json`; `tampered.log` is the clean
log plus a re-measurement of `/usr/local/bin/play_video` with an unknown
hash — exactly the append IMA produces after a measured binary is modified
and re-executed. Regenerate all three with
`python3 dev/sample_ima_log/gen_fixtures.py`.

## Secrets hygiene (Constraint 5)

`attester/keys/` (EK/AK private blobs, contexts), swtpm state, and runtime
quote artifacts are gitignored. Only AK *public* material
(`verifier/ak.pub`, `verifier/ak_pub.pem`) and the allowlist are committed.

## Trust model (honest scope)

Pi 5 has no full UEFI measured-boot chain; we use IMA runtime measurement
into PCR 10. This protects against software-layer tampering (swapped binary
or model file), not physical attacks on the chip.
