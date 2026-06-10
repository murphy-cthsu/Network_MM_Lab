"""Phase 0 laptop gate: read PCR 10 via tpm2-pytss ESAPI against swtpm.

Usage: dev/swtpm_setup.sh start && source dev/tcti.env
       python3 dev/read_pcr10.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "attester"))
from tpm2_pytss import TPML_PCR_SELECTION  # noqa: E402
from tpmconn import open_esapi  # noqa: E402

esys = open_esapi()
try:
    _, _, digests = esys.pcr_read(TPML_PCR_SELECTION.parse("sha256:10"))
    print(f"sha256 PCR 10 = {bytes(digests[0]).hex()}")
finally:
    esys.close()
