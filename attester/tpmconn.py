"""Open an ESAPI connection honoring TSS2_TCTI / TPM2TOOLS_TCTI (Constraint 1).

Dev: `source dev/tcti.env` points both vars at swtpm. On the Pi the vars are
unset and tctildr falls back to /dev/tpmrm0 — same code, no changes.
"""

import os
import sys

from tpm2_pytss import ESAPI, TCTILdr


def open_esapi():
    conf = os.environ.get("TSS2_TCTI") or os.environ.get("TPM2TOOLS_TCTI")
    if conf:
        name, _, cfg = conf.partition(":")
        return ESAPI(TCTILdr(name, cfg or None))
    if os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0"):
        return ESAPI()  # tctildr default: the real TPM device
    sys.exit(
        "No TPM available: TSS2_TCTI/TPM2TOOLS_TCTI unset and /dev/tpm0 missing.\n"
        "For laptop dev: dev/swtpm_setup.sh start && source dev/tcti.env"
    )
