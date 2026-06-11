#!/usr/bin/env bash
# Measured helper of the gated payload — the Phase 1 tamper demo's watched
# executable (verifier/allowlist.json["watched"]). play_video.py executes
# it before every unseal attempt, so IMA always measures the content
# actually on disk into PCR 10 before the gate decision.
echo "[gated_prelude] payload environment OK"
