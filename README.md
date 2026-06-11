# TPM-Attested Device & AI-Model Integrity (Raspberry Pi 5)

Hardware-rooted remote attestation: a Raspberry Pi 5 + TPM 2.0 must prove its
software integrity (and in Phase 2, its AI model's integrity) to a remote
verifier before a gated function runs. See `docs/SPEC_EN.md` for the full
contract and `CLAUDE.md` for the hard constraints.

This aligns with existing edge ML-integrity attestation research; we
demonstrate a working build, we do not claim to invent the concept.

## Status

**Done — Phase 0 (laptop swtpm + Pi bring-up)** — `docs/BRINGUP.md` records the
Pi 5 + SLB9670 + IMA bring-up; the Phase 0 gate (real TPM, no TPM-bypass,
PCR 10 non-zero, `ima_policy=tcb`) is verified on hardware.

**Done — Phase 1 on the real Pi (tasks 1.1–1.6)** — the full loop runs against
the hardware TPM and the real IMA log (~2700 entries) and the tamper demo
passed 5/5 (clean → TRUSTED + video plays; each tamper cycle → COMPROMISED +
TPM-refused unseal + no playback). `docs/PHASE1.md` documents the two design
points that real hardware forced: **atomic quote+log capture** and
**verifier-authorized sealing** (PCR 10 is live and never repeats — there is
no fixed "golden" PCR value anywhere).

Per Constraint 8 all attestation code is **tpm2-pytss ESAPI** (attester) and
**pytss types + `cryptography`** (verifier); `tpm2-tools` is kept only for
CLI/debug. Keys are RSA2048/SHA256 (Constraint 7).

**Next:** Phase 2 (AI HAT + TPM coexistence, IMA-measure the `.hef` model,
swap-the-model demo).

## Running it for real (Pi + laptop)

One-time enrollment:

```sh
# laptop (verifier)
python3 verifier/make_policy_key.py     # policy_key.pem stays here (gitignored);
                                        # attester/policy_pub.pem is committed
python3 verifier/server.py --host 0.0.0.0   # dashboard at http://<laptop>:5000/

# pi (attester) — .venv has tpm2-pytss, requests
.venv/bin/python attester/provision.py      # AK at 0x81010002, publics -> verifier/
attester/payload/gated_prelude.sh           # get the watched binary measured once
sudo .venv/bin/python attester/agent.py --offline --out clean_bundle.json
# copy clean_bundle.json to the laptop, then there:
python3 verifier/make_allowlist.py --bundle clean_bundle.json \
    --watch /home/team2/Network_MM_Lab/attester/payload/gated_prelude.sh
# pi: seal the gated clip key (generates + encrypts a demo clip)
.venv/bin/python attester/seal.py
```

Attest + gated playback (Pi; agent needs root to read the IMA log):

```sh
sudo .venv/bin/python attester/agent.py --verifier-url http://<laptop>:5000
.venv/bin/python attester/payload/play_video.py        # --no-display over SSH
```

Tamper demo (clean baseline, then 5 × tamper → COMPROMISED → no playback):

```sh
dev/run_pi_demo.sh http://<laptop>:5000 5
```

After a tamper, the device stays COMPROMISED until a clean reboot even if the
file is restored — the bad measurement is in the boot's append-only IMA log,
which is exactly the guarantee remote attestation makes. After any reboot the
allowlist may need regenerating from a fresh clean bundle (a kernel/package
update changes legitimate hashes).

## Laptop-only development (no Pi, no real TPM — Constraint 1)

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

One-shot end-to-end demo against swtpm + the recorded fixtures (IMA cannot be
emulated on a laptop — Constraint 3):

```sh
dev/run_demo.sh
```

It resets swtpm, provisions, starts the verifier with the **dev** allowlist
(`dev/sample_ima_log/allowlist.dev.json` — the real `verifier/allowlist.json`
is generated from a Pi clean-boot bundle), stands in for the kernel's IMA via
`dev/extend_pcr10.sh`, and checks clean → TRUSTED / tampered → COMPROMISED.

## How verification works (`verifier/verify.py`)

1. Quote check (pytss types + `cryptography`, no TPM needed): parse the
   `TPMS_ATTEST`/`TPMT_SIGNATURE` blobs, verify the AK's RSASSA/SHA256
   signature with the enrolled `ak_pub.pem`, require TPM-generated quote
   magic/type, the issued nonce in `extraData` (single-use, 120 s TTL —
   replay protection), a PCR selection of exactly `sha256:10`, and that
   `pcrDigest == sha256(reported PCR 10)`.
2. IMA replay — of the **shipped** log, never "the current log": rebuild each
   entry's template data from its own fields, cross-check it against the
   logged template hash (the kernel logs sha1; the quote covers the sha256
   bank), extend a running sha256 PCR-10 value (violation entries extend
   0xff..ff), and require the result to equal the quoted PCR 10. This binds
   the log snapshot to the TPM-attested value.
3. Scoped allowlist: `COMPROMISED` = a known path measured with a hash not
   allowed for it (or a measurement violation on a watched binary). Paths
   absent from the allowlist are reported (count + sample) but do not flip
   the verdict — under `ima_policy=tcb` root constantly reads
   legitimately-new files. The demo's watched binaries
   (`allowlist.json["watched"]`) get a dedicated status on the dashboard.
4. On TRUSTED, the verifier signs an **unseal authorization** for the quoted
   PCR-10 value (the TPM2 PolicyAuthorize pattern) — see `docs/PHASE1.md`.

## Secrets hygiene (Constraint 5)

`attester/keys/`, `attester/out/` (sealed key blobs, encrypted clip,
authorizations), swtpm state, and `verifier/policy_key.pem` are gitignored.
Only public material (`verifier/ak.pub`, `verifier/ak_pub.pem`,
`attester/policy_pub.pem`) and the allowlists are committed.

## Trust model (honest scope)

Pi 5 has no full UEFI measured-boot chain; we use IMA runtime measurement
into PCR 10. This protects against software-layer tampering (swapped binary
or model file), not physical attacks on the chip. The scoped allowlist
deliberately ignores unknown paths to stay false-positive-free on a desktop
OS; a production deployment would close that gap with a stricter, path-scoped
IMA policy (Phase 2 moves in that direction for the model file).
