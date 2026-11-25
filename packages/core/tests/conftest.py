"""Make ``sbombox_core`` importable whether or not the workspace is installed.

The monorepo is a uv workspace with a ``src/`` layout, so the package is only
importable after ``uv sync`` (or an editable install).  A contributor running
``pytest`` in a fresh clone has done neither, and a confusing ``ModuleNotFoundError``
is a poor first impression.  Putting the source tree on ``sys.path`` here costs
nothing when the package *is* installed - an importable distribution already
satisfies the import, and the extra entry is simply never consulted.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"

if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
