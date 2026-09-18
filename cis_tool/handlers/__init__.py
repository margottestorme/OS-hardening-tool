"""Importer ce package (import cis_tool.handlers) enregistre tous les handlers.

Chaque handler s'auto-enregistre via le décorateur @register au moment où son
module est importé. Il suffit donc de les importer ici : le moteur importera ce
package et le registre sera peuplé.
"""

from . import file_directive  # noqa: F401

# Au fur et à mesure des jalons, ajouter ici :
# from . import sysctl, kmod, service, file_perms  # noqa: F401