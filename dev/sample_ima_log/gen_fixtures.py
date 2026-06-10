"""Regenerate the committed IMA log fixtures + allowlist (dev only).

IMA cannot run on the laptop (Constraint 3), so verifier development uses
these recorded-style logs in the kernel's ima-ng ASCII format:

    <pcr> <template-hash> ima-ng <algo>:<file-hash> <path>

Template hashes are computed exactly the way verify.py recomputes them, so
the fixtures replay to a self-consistent PCR-10 value.

- clean.log    : boot_aggregate + measured binaries, all on the allowlist
- tampered.log : clean.log + one extra entry — the same path re-measured
                 with a different hash, exactly what IMA appends after a
                 binary is modified and re-executed. NOT on the allowlist.

Run from the repo root: python3 dev/sample_ima_log/gen_fixtures.py
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO_ROOT, "verifier"))
from verify import ima_ng_template_hash  # noqa: E402

CLEAN_PATHS = [
    "boot_aggregate",
    "/usr/bin/bash",
    "/usr/bin/python3.11",
    "/usr/local/bin/attester-agent",
    "/usr/local/bin/play_video",
]
TAMPERED_PATH = "/usr/local/bin/play_video"


def sample_hash(path, tampered=False):
    """Deterministic stand-in for a real file's sha256 (fixtures only)."""
    tag = "tampered" if tampered else "clean"
    return hashlib.sha256(f"sample-ima-fixture:{tag}:{path}".encode()).hexdigest()


def line(path, tampered=False):
    file_hash = f"sha256:{sample_hash(path, tampered)}"
    tmpl = ima_ng_template_hash(file_hash, path)
    return f"10 {tmpl} ima-ng {file_hash} {path}"


def main():
    clean = [line(p) for p in CLEAN_PATHS]
    tampered = clean + [line(TAMPERED_PATH, tampered=True)]

    with open(os.path.join(HERE, "clean.log"), "w") as f:
        f.write("\n".join(clean) + "\n")
    with open(os.path.join(HERE, "tampered.log"), "w") as f:
        f.write("\n".join(tampered) + "\n")

    allowlist = {p: [sample_hash(p)] for p in CLEAN_PATHS}
    with open(os.path.join(REPO_ROOT, "verifier", "allowlist.json"), "w") as f:
        json.dump(allowlist, f, indent=2)
        f.write("\n")

    print("wrote clean.log, tampered.log, verifier/allowlist.json")


if __name__ == "__main__":
    main()
