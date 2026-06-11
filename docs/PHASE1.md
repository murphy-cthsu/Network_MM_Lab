# Phase 1 on real hardware — design notes

Phase 1 (docs/SPEC_EN.md §8, tasks 1.1–1.6) was ported from the laptop swtpm
vertical slice to the Pi 5 + SLB9670. Two properties of the real system forced
design decisions that the swtpm slice never saw; both are recorded here
because they shape Phase 2 and belong in the report.

## The central fact: PCR 10 is live

Under `ima_policy=tcb` the kernel extends PCR 10 every time a not-yet-measured
file is executed (any uid) or read by root, and on every re-measurement of a
changed file. Consequences:

- PCR 10 **differs every boot** (different measurement order alone changes it).
- PCR 10 **grows during a boot** (~2400 entries shortly after login on this
  image, ~2800 after a working session).
- PCR 10 **can never be rewound** — restoring a tampered file appends a new
  (good) measurement; it does not undo the bad one.

So there is no fixed "golden PCR-10 value" anywhere in this system. Trust in
an attestation is established by three checks chained together:
(a) the quote's AK signature + fresh nonce verify;
(b) replaying the **shipped** log reproduces the PCR-10 value inside the quote;
(c) every known measured file matches the allowlist.

## Atomic quote+log capture (attester/agent.py)

A log snapshot and a quote taken at different instants disagree whenever a
measurement lands in between. The agent therefore quotes FIRST, then reads
the log and trims it to the prefix whose replay satisfies
`sha256(replayed PCR) == pcrDigest` inside the quote: the log is
append-only, so that prefix is exactly the state the TPM signed. Capture
converges in one attempt at any measurement rate (an earlier
read-then-quote-then-retry design lost the race whenever the system was
busy — first minutes after boot, desktop churn). The verifier replays the
log it was **given**, never the Pi's "current log".

When the quote matches NO prefix and even the full log does not replay to
the live PCR, the agent reports a **log/PCR desync** instead of retrying:
the PCR holds extends IMA never logged. Observed cause: a warm reboot
that does not reset the SPI TPM, leaving the previous boot's PCR 10
underneath the new boot's measurements — only a power-cycle recovers
(docs/DEMO_RUNBOOK.md, Troubleshooting).

## Sealing vs a live PCR (attester/sealing.py)

A secret sealed directly to one PCR-10 value stops unsealing at the next
legitimate measurement, and re-sealing would need the plaintext secret kept
around — defeating the seal. Sealing to "stable" PCRs 0–7 binds nothing on a
Pi (no measured firmware boot; they are constant zeros).

Instead the gated AES key is sealed ONCE to `PolicyAuthorize(verifier's
policy key)` (TPM2 flexible-PCR-policy pattern, as used by systemd-pcrlock
and Keylime payloads — not invented here):

1. Verifier enrolls an RSA2048 policy key; the public half lives on the Pi
   (`attester/policy_pub.pem`), the private half never leaves the laptop.
2. On every TRUSTED verdict the verifier computes the `PolicyPCR` digest of
   the **quoted** PCR-10 value in software and signs it (the `approval` field
   of the `/evidence` response). The software digest derivation is
   cross-checked against a TPM trial session in dev.
3. To unseal, the payload runs one policy session:
   `PolicyPCR(current sha256:10)` → `VerifySignature(approval)` →
   `PolicyAuthorize` → `Unseal`.

The TPM enforces "release the key only while PCR 10 holds a value the
verifier attested clean". Tampering closes the gate twice over: the verifier
refuses to sign the post-tamper state (allowlist failure → no fresh
authorization), and all previously issued authorizations die because
`PolicyPCR` no longer matches once IMA measures the tampered file
(`TPM_RC_VALUE` on `PolicyAuthorize`, observed as `0x1c4` in the demo).
Legitimate PCR drift needs only a fresh attestation — no re-sealing, and the
plaintext key exists only inside `seal.py` for the seconds it takes to seal.

`payload/play_video.py` makes the demo honest: when no fresh authorization
exists it deliberately tries the last TRUSTED one, so it is the **TPM** that
refuses on camera, not the script being polite.

## Scoped allowlist verdict (verifier/verify.py)

The tcb log on a desktop-class OS keeps acquiring legitimately-new paths
(daily-run cron jobs, first use of a tool, package upgrades). To stay
false-positive-free the verdict is scoped: `COMPROMISED` means "a path the
allowlist knows was measured with a hash it does not allow" (plus any
measurement violation touching a watched binary). Unknown paths are counted
and sampled in every verdict but do not flip it.

Tradeoff stated plainly: an attacker who drops and runs a **new** binary at a
**new** path is reported but not failed by Phase 1. The demo threat model is
tampering with existing measured software (and in Phase 2 the model file,
whose path is allowlisted + watched). Production would close the gap with a
path/uid-scoped IMA policy and full allowlist closure.

Operational notes:
- The allowlist must be regenerated from a clean-boot bundle after any
  kernel/package update (`verifier/make_allowlist.py`).
- After a tamper demo the device stays COMPROMISED until a clean reboot even
  though `tamper/restore_binary.sh` restores the file — the bad measurement
  is in the boot's append-only log. That is correct attestation semantics
  (an attacker cannot regain trust by putting the original file back) and is
  presented as such in the demo.

## Replay details that real logs forced (verifier/verify.py)

- The ascii log's template-hash column is **sha1** on this kernel, while the
  quote covers the **sha256** PCR bank. Replay therefore rebuilds each
  entry's template data (`ima-ng`: `[u32 len]"sha256:\0"+digest [u32
  len]path+"\0"`) and extends with `sha256(template_data)`; the logged sha1
  column is recomputed from the same bytes as a per-line integrity check.
  Validated against the live PCR over the full real log before porting
  (first try, 2514/2514 entries).
- Violation entries (ToMToU / open-writers) log all-zero template hashes but
  extend `0xff..ff`; replay folds them in the same way. None appear in the
  current clean logs, but the dev fixtures and verdict logic handle them.

## What ran on what (Constraint 2)

Everything TPM-side (provisioning, agent, sealing, payload) ran on the Pi.
The verifier code never depends on a TPM or on Pi paths; for this session it
was exercised on the Pi against captured bundles plus a localhost server as a
stand-in, because the laptop is not reachable from this session. Deploying it
is one command on the laptop (`python3 verifier/server.py --host 0.0.0.0`)
plus pointing `agent.py --verifier-url` at it; nothing in the code changes.
