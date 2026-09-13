# -*- coding: utf-8 -*-
"""Regenerate the sample captures used by the test suite.

The captures under ``sample/`` are not tracked in git (see ``.gitignore``), yet the
runtime, regression and integration tests read them and pin their contents. This
script rebuilds the whole set so a fresh clone can run ``pytest`` without any
ignore flags:

.. code-block:: shell

   python util/make_samples.py        # or: make samples

The actual fixtures come from two modules, both of which may also be run on their
own: :mod:`util.samples_pcap` for the ``.pcap`` captures and
:mod:`util.samples_pcapng` for the ``.pcapng`` ones.

"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEST = ROOT / 'sample'

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import samples_pcap  # noqa: E402  # pylint: disable=wrong-import-position
import samples_pcapng  # noqa: E402  # pylint: disable=wrong-import-position


def main() -> 'int':
    """Write every sample capture into ``sample/``."""
    DEST.mkdir(parents=True, exist_ok=True)

    written = []  # type: list[pathlib.Path]
    written.extend(samples_pcap.generate(DEST))
    written.extend(samples_pcapng.generate(DEST))

    print(f'sample: wrote {len(written)} capture(s) to {DEST}')
    for path in written:
        print(f'  {path.name} ({path.stat().st_size} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
