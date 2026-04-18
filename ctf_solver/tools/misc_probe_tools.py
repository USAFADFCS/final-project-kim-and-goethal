"""Back-compat re-export shim.

The original 1565-line ``misc_probe_tools.py`` bundled five unrelated
vulnerability probes in one file.  Batch B #16 split them into dedicated
modules for cohesion; this shim is kept so existing imports via
``from ctf_solver.tools.misc_probe_tools import X`` keep working.
New code should import from the per-vuln modules directly.
"""

from ctf_solver.tools.crlf_tools import CrlfProbeTool
from ctf_solver.tools.idor_tools import IdorEnumeratorTool
from ctf_solver.tools.open_redirect_tools import OpenRedirectProbeTool
from ctf_solver.tools.php_juggling_tools import PhpTypeJugglingTool
from ctf_solver.tools.prototype_pollution_tools import PrototypePollutionTool

__all__ = [
    "CrlfProbeTool",
    "IdorEnumeratorTool",
    "OpenRedirectProbeTool",
    "PhpTypeJugglingTool",
    "PrototypePollutionTool",
]
