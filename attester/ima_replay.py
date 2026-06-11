"""Replay an IMA ascii log into the sha256 PCR-10 value (attester-side).

The kernel's ascii_runtime_measurements shows the template hash in the
default template-hash algo (sha1 on this kernel), but the quote covers the
sha256 PCR bank. So replay cannot use the logged column directly: for each
entry the original template data bytes are rebuilt from the parsed fields,
cross-checked against the logged template hash (sha1 or sha256, by length),
and the running PCR is extended with sha256(template_data).

"Violation" entries (ToMToU / open-writers) log an all-zero template hash
but the kernel extends the PCR with 0xff..ff — replay must do the same.

verifier/verify.py contains the authoritative twin of this logic. The
attester keeps its own copy so attester/ and verifier/ stay decoupled
(Constraint 2: they may only talk over HTTP/JSON). The attester replays
only to decide whether its own log+quote snapshot is self-consistent
before shipping it; the verifier's replay is the one that matters.
"""

import hashlib
import struct


def rebuild_template_data(template_name, file_hash, path):
    """Rebuild the raw template-data bytes the kernel hashed for one entry.

    Template data is a sequence of (u32-LE length, bytes) fields.
    ima-ng:  d-ng = b"<algo>:\\0" + raw digest, n-ng = path + b"\\0"
    (Phase 2 may add ima-buf support; the tcb policy only emits ima-ng.)
    """
    if template_name != "ima-ng":
        raise ValueError(f"unsupported IMA template: {template_name!r}")
    algo, _, hexdigest = file_hash.partition(":")
    if not hexdigest:
        raise ValueError(f"malformed file-hash field: {file_hash!r}")
    d_ng = algo.encode() + b":\x00" + bytes.fromhex(hexdigest)
    n_ng = path.encode() + b"\x00"
    return struct.pack("<I", len(d_ng)) + d_ng + struct.pack("<I", len(n_ng)) + n_ng


def replay_sha256_pcr10(ima_log_text):
    """Fold every PCR-10 entry into a running sha256 PCR value.

    Returns (pcr10_hex, entry_count). Raises ValueError if an entry cannot
    be parsed or its rebuilt template data does not reproduce the logged
    template hash (which would mean the log text is corrupt).
    """
    pcr = bytes(32)
    count = 0
    for lineno, line in enumerate(ima_log_text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=4)
        if len(parts) != 5:
            raise ValueError(f"line {lineno}: unparseable IMA entry: {line!r}")
        pcr_idx, template_hash, template_name, file_hash, path = parts
        if int(pcr_idx) != 10:
            continue
        if set(template_hash) == {"0"}:
            # measurement violation: logged as zeros, PCR extended with ff..ff
            pcr = hashlib.sha256(pcr + b"\xff" * 32).digest()
        else:
            data = rebuild_template_data(template_name, file_hash, path)
            check_algo = {40: hashlib.sha1, 64: hashlib.sha256}.get(len(template_hash))
            if check_algo is None or (
                check_algo(data).hexdigest() != template_hash.lower()
            ):
                raise ValueError(
                    f"line {lineno}: rebuilt template data does not match the "
                    f"logged template hash (path={path!r})"
                )
            pcr = hashlib.sha256(pcr + hashlib.sha256(data).digest()).digest()
        count += 1
    return pcr.hex(), count
