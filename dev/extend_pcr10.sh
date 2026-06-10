#!/usr/bin/env bash
# dev/extend_pcr10.sh — DEV ONLY. Never used on the Pi.
#
# swtpm has no IMA, so its PCR 10 stays zero. To exercise the real
# quote/replay path on the laptop, this script folds an IMA log's template
# hashes into swtpm's PCR 10 with tpm2_pcrextend — playing the role the
# kernel's IMA subsystem plays on the Pi.
#
# Usage: dev/extend_pcr10.sh <ima_log_file> [skip_first_n_lines]
#   skip_first_n_lines lets you extend only the *new* entries of a log that
#   is a superset of one already extended (mirrors IMA's append-only log).

set -euo pipefail

LOG_FILE="${1:?usage: $0 <ima_log_file> [skip_first_n_lines]}"
SKIP="${2:-0}"

if [[ -z "${TPM2TOOLS_TCTI:-}" ]]; then
    echo "TPM2TOOLS_TCTI not set — run: source dev/tcti.env" >&2
    exit 1
fi

count=0
while read -r _pcr template_hash _rest; do
    tpm2_pcrextend "10:sha256=$template_hash"
    count=$((count + 1))
done < <(tail -n +"$((SKIP + 1))" "$LOG_FILE")

echo "extended PCR 10 with $count entr(y/ies) from $LOG_FILE (skipped first $SKIP)"
tpm2_pcrread sha256:10
