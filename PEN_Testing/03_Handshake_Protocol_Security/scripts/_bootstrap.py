"""Shared path bootstrap for Test 3 scripts: makes common/ and ../modules/ importable."""
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PEN_ROOT = _HERE.parents[1]
for _p in (_PEN_ROOT / "common", _HERE.parent / "modules"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
