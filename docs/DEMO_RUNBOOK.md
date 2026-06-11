# Phase 1 demo runbook

Fixed procedure for the live demo (laptop = verifier, Pi = attester). The
order below is not negotiable — several steps are one-way within a boot.

## Roles and addresses

- **Laptop** (verifier, dashboard, policy key): runs `verifier/server.py`.
  Holds `verifier/policy_key.pem` (private, gitignored, NEVER copied to the
  Pi — a Pi that holds it could authorize itself).
- **Pi** (attester): TPM + IMA + sealed clip key. Knows only the laptop's
  policy PUBLIC key (`attester/policy_pub.pem`).
- Default verifier URL on the Pi is `http://172.20.10.4:5000`; override with
  `VERIFIER_URL` or `--verifier-url`/first script argument when the hotspot
  hands out different addresses.
- The laptop firewall must allow inbound TCP 5000 (symptom of forgetting:
  the Pi's `curl <url>/nonce` times out while SSH to the Pi still works).

## One-time enrollment / after a key rotation

```sh
# laptop
python3 verifier/make_policy_key.py            # --force to rotate
git add verifier/policy_pub.pem && git commit && git push
python3 verifier/server.py --host 0.0.0.0      # leave running

# pi
git pull
cp verifier/policy_pub.pem attester/policy_pub.pem   # enroll the new public
git add attester/policy_pub.pem && git commit
.venv/bin/python attester/provision.py               # only if the AK is gone
.venv/bin/python attester/seal.py                    # re-seal to the new key
```

After ANY rotation the old sealed blobs and any saved approvals are dead —
`seal.py` replaces the blobs; delete stale `attester/out/*approval*.json`.

## Allowlist (regenerate per "golden" state, on a FROZEN environment)

The allowlist is the definition of "clean". It must be regenerated from a
fresh clean-boot bundle whenever legitimate measured files change — i.e.
after ANY apt/kernel update **or any edit to the repo's own code** (the
attester's `.py` sources and their `.pyc` caches are measured and
allowlisted on purpose). **Freeze the environment before the demo**: no
`apt upgrade`, no editing measured scripts, no new root-level tooling
between allowlist generation and demo.

One command on the Pi, after a power-cycle:

```sh
dev/prepare_demo.sh    # measure watched binary, warm up, capture bundle,
                       # regenerate allowlist, offline-verify -> TRUSTED
```

then ship `verifier/allowlist.json` to the laptop (the script prints the
`scp` one-liner and the git alternative). Generation is just a script and
may run on either machine (`verifier/make_allowlist.py --bundle ... --watch
... --exclude-prefix /home/team2/ --keep-prefix <repo>/`); verification
stays laptop-only.

`--exclude-prefix` keeps volatile user trees (caches, desktop session
files) OUT of the allowlist: they then count as "unknown paths" — reported
on the dashboard, never compromising. Allowlisting them would turn the
next legitimate change into a false COMPROMISED. The repo subtree is kept
so the attester's own code stays integrity-checked.

The laptop server re-reads `allowlist.json` on every evidence POST — a
`git pull` on the laptop is enough, no restart needed.

## The demo itself (3–4 min)

Order is fixed: **green first, then red. Within one boot there is no way
back to green** (see below).

```sh
# 0. laptop: server running, dashboard on the beamer (http://localhost:5000)
# 1. pi: clean attest -> dashboard GREEN
sudo .venv/bin/python attester/agent.py
# 2. pi: gated function -> unseal OK -> video PLAYS
sudo .venv/bin/python attester/payload/play_video.py        # --no-display over SSH
# 3. pi: live tamper (one keystroke)
tamper/tamper_binary.sh
# 4. pi: re-attest -> dashboard RED, offending entry named
sudo .venv/bin/python attester/agent.py                     # exits 2
# 5. pi: gated function again -> TPM refuses unseal -> NO playback
sudo .venv/bin/python attester/payload/play_video.py        # exits 3
```

Or scripted (clean baseline + N tamper cycles, used for the 5/5 DoD):

```sh
dev/run_pi_demo.sh                       # defaults to the laptop verifier
dev/run_pi_demo.sh http://<laptop>:5000 5
```

One-line why, for the audience: *the kernel measured the modified binary
into PCR 10; the verifier's allowlist rejected it and refused to sign an
unseal authorization; old authorizations no longer match PolicyPCR; the
TPM therefore keeps the clip key sealed.*

## Rules that keep the demo deterministic

1. **COMPROMISED is sticky per boot.** The IMA log is append-only; the bad
   measurement stays until reboot, and `tamper/restore_binary.sh` cannot
   undo it (that is the security property, not a bug — an attacker cannot
   regain trust by restoring the file). **To show green again,
   POWER-CYCLE the Pi** (full power off ≥10 s — a warm `sudo reboot` can
   leave the SPI TPM un-reset and desync log and PCR; see
   Troubleshooting), then re-run step 1. The allowlist survives reboots;
   do NOT regenerate it after a tamper run (it would allowlist the
   tampered hash if generated from that boot's bundle).
2. **Keep the box quiet between verdict and unseal** (steps 1→2). Any new
   root file-read anywhere extends PCR 10 and invalidates the fresh
   authorization. The payload self-heals (bounded retry: TPM refusal →
   re-attest → re-authorize → re-unseal, ≤5 attempts, logged per retry),
   but a quiet box means attempt 1 just works on stage.
3. **No recursive root reads over big trees — ever — on a demo boot.**
   A single `sudo grep -r` over /home measured ~68 000 files in minutes
   during rehearsal (log went 2.3k → 70k entries). Everything still
   verified (unknown paths don't compromise), but bundles balloon to
   ~14 MB and every attestation gets slower. If it happens: it's
   cosmetic; reboot when convenient.
4. **Frozen environment** (see allowlist section): an apt/kernel update
   changes legitimate hashes of allowlisted paths → false COMPROMISED.
   That failure mode names a system binary on the dashboard instead of the
   watched one — if you see it, regenerate the allowlist; do not demo.
5. Capture does not race the system: the agent quotes first, then trims
   the append-only log to the prefix that replays to the quoted digest —
   "consistent bundle on attempt 1 (N entries measured after the quote
   were trimmed)" is normal at any churn level. If the agent instead
   reports a **log/PCR desync**, see Troubleshooting; no retry fixes that.

## Honest limitations (say them before someone asks)

- **A brand-new binary at a brand-new path is reported, not failed.** The
  verdict is scoped to "known path measured with a non-allowed hash" (plus
  violations on watched paths) to stay false-positive-free on a desktop
  OS. The dashboard shows the unknown-path count; production would close
  this with a path/uid-scoped IMA policy and full allowlist closure.
- The allowlist requires a frozen environment; it is a per-golden-state
  artifact, not a per-boot one.
- IMA runtime measurement protects against software-layer tampering of
  measured files; it does not defend physical chip attacks, and the Pi has
  no measured firmware boot (PCRs 0–7 are empty — which is exactly why
  sealing binds to a verifier-authorized PCR 10, not to "stable" PCRs).
- Unknown-path noise on a polluted boot (rule 3) is visible on the
  dashboard; it disappears after a clean reboot.

## Troubleshooting

**"IMA log / PCR-10 desync ... POWER-CYCLE the Pi"** (from the agent), or
the old symptom "quote matches no prefix" on every attempt:
the TPM's PCR 10 contains extends that IMA never logged, so no log can
ever replay to it — attestation is impossible for the rest of the boot.
Observed cause on this rig: a warm `sudo reboot` does not reset the SPI
TPM (its reset line is not tied to the SoC reset). The kernel then finds
an already-started TPM, skips `TPM2_Startup(CLEAR)`, and the previous
boot's PCR 10 survives with the new boot's measurements folded on top —
IMA's own counters (`runtime_measurements_count`, `violations`) stay
consistent with the log, which is how you tell it apart from log
corruption. **Fix: full power-cycle (unplug ≥10 s), never trust a warm
reboot before a demo.** The agent detects this case and says so instead
of retrying.

**Clean attest comes back COMPROMISED naming repo files** (`agent.py`,
`__pycache__/*.pyc`): the allowlist predates a code edit. Re-run
`dev/prepare_demo.sh` on a clean boot and re-ship the allowlist.

**Verifier unreachable** (preflight error): on the laptop, start
`python3 verifier/server.py --host 0.0.0.0`, allow inbound TCP 5000
through its firewall, and check the hotspot IP in the error's hint line.
