"""Importer ce package (import cis_tool.handlers) enregistre tous les handlers.

Chaque handler s'auto-enregistre via le décorateur @register au moment où son
module est importé. Il suffit donc de les importer ici : le moteur importera ce
package et le registre sera peuplé.

Cinq handlers couvrent tout le périmètre Level 1 :
  file_directive · sysctl · file_perms · kmod · service
"""

from . import file_directive  # noqa: F401
from . import sysctl          # noqa: F401
from . import file_perms      # noqa: F401
from . import kmod            # noqa: F401
from . import service         # noqa: F401