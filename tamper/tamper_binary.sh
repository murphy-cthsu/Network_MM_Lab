#!/usr/bin/env bash
# Phase 1 tamper demo (docs/SPEC_EN.md §8 task 1.6).
#
# Modifies the watched measured executable AND executes it, so IMA
# (BPRM_CHECK measures on exec regardless of uid) appends the new — not
# allowlisted — hash to the measurement log and extends PCR 10. From that
# moment: re-attestation -> COMPROMISED, and every unseal authorization
# (old or new) is dead because PCR 10 left the verifier-attested value.
#
# Usage: tamper/tamper_binary.sh [target]   (default: gated_prelude.sh)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$REPO_ROOT/attester/payload/gated_prelude.sh}"

echo "echo '[gated_prelude] TAMPERED: exfiltrating frames... (simulated)'" >> "$TARGET"
"$TARGET" >/dev/null   # exec -> IMA measures the modified file into PCR 10
echo "tampered and re-executed: $TARGET"
echo "IMA has now measured the modified binary; PCR 10 has diverged."
