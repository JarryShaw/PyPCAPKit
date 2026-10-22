# -*- coding: utf-8 -*-
"""Rebuild :file:`examples/captures/`, and say whether the fixtures are upstream's (#1967).

The ``Regenerate sample captures`` step of :file:`.github/workflows/unit-tests.yml`'s
``integration`` and ``pypcap-parity`` jobs (and so their KTLO twins) and of its
``gate`` job runs, from the checkout's root and on the leg's own interpreter::

    python util/regenerate_samples.py

with ``ANNOTATION_LEVEL``, ``error`` or ``warning``, and ``RUNNER_TEMP`` in the
environment. It runs :file:`examples/generators/make_samples.py` on the same
interpreter, its standard error merged into its standard output, and copies that
output, as it arrives, both to its own standard output and to
:file:`$RUNNER_TEMP/make-samples.log`. Then:

* **The generator failed**: one ``ANNOTATION_LEVEL`` annotation saying the
  fixtures could not be built, so no test has run and nothing is wrong with the
  code under test, and exit 1.
* **It succeeded on stand-ins**: :file:`examples/generators/pcapng.py` fetches
  captures from the Wireshark repository and synthesises stand-ins when the
  download fails, marking each such line ``(download unavailable)``. The
  stand-ins parse, and :file:`tests/protocols/test_pcapng_regression.py` only
  asserts that extraction succeeds, so a degraded run goes green and is otherwise
  indistinguishable from a clean one. One ``::warning`` says which happened,
  followed by each marked line, and the exit status is 0.
* **It succeeded on upstream's captures**: one line saying so, and exit 0.

An ``ANNOTATION_LEVEL`` other than ``error`` or ``warning`` exits 2 before the
generator runs. The script is standard library only.

"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['GENERATOR', 'LEVELS', 'MARKER', 'LOG_NAME', 'FAILED', 'DEGRADED', 'UPSTREAM', 'main']

#: The generator, relative to the checkout's root.
GENERATOR = 'examples/generators/make_samples.py'
#: The annotation levels ``ANNOTATION_LEVEL`` may hold.
LEVELS = ('error', 'warning')
#: What :file:`examples/generators/pcapng.py` writes on each stand-in's line.
MARKER = b'(download unavailable)'
#: The generator's output, under ``$RUNNER_TEMP``.
LOG_NAME = 'make-samples.log'
#: The annotation of a failed run, after ``::<level> ``.
FAILED = ('title=Sample fixture generation failed::examples/generators/make_samples.py could not rebuild '
          'examples/captures/. This is a fixture-generation failure, not a test failure -- the test suite '
          'has not run.')
#: The warning of a run on stand-ins.
DEGRADED = ('::warning title=Sample fixtures degraded::The upstream Wireshark captures were unreachable, so '
            'synthesised stand-ins were used. The PCAP-NG tier ran, but not against the upstream bytes.')
#: The line of a run on upstream's captures.
UPSTREAM = 'Upstream Wireshark captures were used, matching their pinned SHA-256 digests.'


def emit(data: 'bytes') -> 'None':
    """Write ``data`` to standard output as it is, at once."""
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def say(text: 'str') -> 'None':
    """Write ``text`` and a newline to standard output, at once."""
    emit(text.encode('utf-8') + b'\n')


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Run the generator, copy its output to the log, and report on it; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.parse_args(argv)

    level = os.environ['ANNOTATION_LEVEL']
    if level not in LEVELS:
        print(f'ANNOTATION_LEVEL is {level!r}, not one of {", ".join(LEVELS)}.', file=sys.stderr)
        return 2

    output = bytearray()
    with open(pathlib.Path(os.environ['RUNNER_TEMP']) / LOG_NAME, 'wb') as log:
        with subprocess.Popen([sys.executable, GENERATOR],  # nosec: B603
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
            assert process.stdout is not None  # nosec: B101
            for line in process.stdout:
                emit(line)
                log.write(line)
                log.flush()
                output.extend(line)
        status = process.returncode

    # Keep a failure here legible as what it is: the fixtures could not be
    # built, so no test has run yet and nothing is wrong with the code under test.
    if status != 0:
        say(f'::{level} {FAILED}')
        return 1

    marked = [line for line in bytes(output).split(b'\n') if MARKER in line]
    if marked:
        say(DEGRADED)
        for line in marked:
            emit(line + b'\n')
    else:
        say(UPSTREAM)
    return 0


if __name__ == '__main__':
    sys.exit(main())
