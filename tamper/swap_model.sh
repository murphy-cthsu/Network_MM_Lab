#!/usr/bin/env bash
# tamper/swap_model.sh — Phase 2 model-swap tamper (docs/PHASE2.md D5).
#
# The believable trojan story (NOT "corrupt the file"): copy a DIFFERENT but
# normal-looking model over the live one and read it as root so IMA measures the
# new hash into PCR 10. From that moment: re-attestation -> COMPROMISED (the new
# model hash is not allowlisted), and every unseal authorization dies because
# PCR 10 left the verifier-attested value -> the lock credential stays sealed ->
# the door stays locked, even though the swapped model would happily admit B.
#
# Mirrors tamper/tamper_binary.sh's "modify the file AND touch the measurement
# path" pattern, but for the model file instead of the watched binary. The
# fragile part is forcing a RE-measurement: overwriting the file bumps the
# inode's i_version, so the next root read re-measures it (a swap that did NOT
# re-measure would fail toward a false TRUSTED — the worst outcome). We confirm
# the new hash and print it.
#
# Usage: tamper/swap_model.sh [owner_model_path] [trojan_model_path]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OWNER="${1:-$REPO_ROOT/attester/models/owner_model.tflite}"
TROJAN="${2:-$REPO_ROOT/attester/models/trojan_model.tflite}"
IMA_LOG=/sys/kernel/security/ima/ascii_runtime_measurements

# Until the real trojan model is provided, ensure two DISTINCT placeholders
# exist so the swap actually changes the hash (generator is idempotent).
"$REPO_ROOT/dev/gen_placeholder_models.sh" >/dev/null

[[ -f "$TROJAN" ]] || { echo "trojan model missing: $TROJAN" >&2; exit 1; }
if cmp -s "$OWNER" "$TROJAN"; then
    echo "WARNING: owner already == trojan (already swapped?); the hash will" \
         "not change and the demo will not flip to COMPROMISED" >&2
fi

before=$(sha256sum "$OWNER" | cut -d' ' -f1)
cp -f "$TROJAN" "$OWNER"      # truncate+write the existing path -> i_version bump
sync
# Force IMA's FILE_CHECK to re-measure the changed file into PCR 10 (root read).
sudo cat "$OWNER" >/dev/null
after=$(sha256sum "$OWNER" | cut -d' ' -f1)

echo "swapped trojan over: $OWNER"
echo "  clean hash:  $before"
echo "  trojan hash: $after"
if [[ "$before" == "$after" ]]; then
    echo "ERROR: hash unchanged after swap — re-measurement cannot happen" >&2
    exit 1
fi
# Show the kernel actually logged the new hash (the DoD's fragile point).
if sudo grep -q "sha256:$after .*$(basename "$OWNER")" "$IMA_LOG"; then
    echo "IMA log now carries the trojan hash for the model — PCR 10 diverged."
else
    echo "ERROR: the trojan hash is NOT in the IMA log — the swap did not" \
         "re-measure (mount missing iversion? reader did not re-read?)." \
         "A swap that does not re-measure fails toward a FALSE TRUSTED." >&2
    exit 1
fi
echo "Re-attest now -> COMPROMISED (model entry named); the door stays locked."
