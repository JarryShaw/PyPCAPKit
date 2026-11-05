# -*- coding: utf-8 -*-
"""Regenerate the sample captures used by the test suite and the examples.

The captures under ``examples/captures/`` are not tracked in git, apart from the
inputs ``in.pcap`` and ``dhcp.pcapng`` (see ``.gitignore``), yet the runtime,
regression and integration tests read them and pin their contents, as do the
demonstration scripts in ``examples/legacy_smoke/``. This script rebuilds the
generated ones, so a fresh clone can run ``pytest`` without any ignore flags:

.. code-block:: shell

   python examples/generators/make_samples.py        # or: make samples

The fixtures themselves come from the sibling modules in this directory, each of
which may also be run on its own:

=================== ==========================================================
Module              Fixtures
=================== ==========================================================
:file:`pcap.py`     the ``.pcap`` captures the unit and runtime tests read
:file:`endian.py`   the big-endian ``.pcap`` captures, and their little-endian
                    twin, that the byte-order tests read
:file:`pcapng.py`   the ``.pcapng`` captures the regression tests read
:file:`legacy.py`   the extra captures ``examples/legacy_smoke/`` reads
:file:`options.py`  the ``options-*.pcap`` option-coverage captures
=================== ==========================================================

They are loaded by path rather than imported by name, since this directory is
not a package and its module names (``pcap``, ``pcapng``) are too generic to put
on :data:`sys.path`.

"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType

#: Repository root, i.e. the grandparent of the directory holding this script.
ROOT = pathlib.Path(__file__).resolve().parents[2]

# Run as a script, sys.path[0] is this directory, so pcapkit would resolve to
# whatever is installed rather than this tree (#1343); the root goes first, as
# PathFinder precedes the editable finder. Every sibling importing pcapkit repeats
# this, since each may run on its own.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: Directory holding this script and its sibling generator modules.
HERE = pathlib.Path(__file__).resolve().parent
#: Destination directory for every generated capture.
DEST = ROOT / 'examples' / 'captures'
#: Generator modules, in run order. :file:`options.py` runs last, since only it
#: builds its captures with :mod:`pcapkit` itself, so its failure is the library's
#: rather than a fixture's, and printing it after the others keeps that visible.
GENERATORS = ('pcap', 'endian', 'pcapng', 'legacy', 'options')


def load(name: 'str') -> 'ModuleType':
    """Load a sibling generator module by file path.

    Args:
        name: Module file stem, e.g. ``'pcap'`` for :file:`pcap.py`.

    Returns:
        The imported module, which exposes ``generate(dest)``.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = HERE / f'{name}.py'
    spec = importlib.util.spec_from_file_location(f'pcapkit_samples_{name}', path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load sample generator {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> 'int':
    """Write every sample capture into ``examples/captures/``."""
    DEST.mkdir(parents=True, exist_ok=True)

    written = []  # type: list[pathlib.Path]
    for name in GENERATORS:
        written.extend(load(name).generate(DEST))

    print(f'sample: wrote {len(written)} capture(s) to {DEST}')
    for path in written:
        print(f'  {path.name} ({path.stat().st_size} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
