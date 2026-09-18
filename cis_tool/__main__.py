"""Point d'entrée : permet `python -m cis_tool [options]`."""

import sys

from .cli import main

sys.exit(main())