# -*- coding: utf-8 -*-
"""Install the checkout and its extras, and say why when it fails (#1967).

The install step of each :file:`.github/workflows/unit-tests.yml` job that installs
the package -- ``test``, ``integration``, ``pypcap-parity`` (and so their KTLO
twins), ``unittest-ordering``, ``project-tests`` and ``gate`` -- and of the
``experimental`` and ``windows`` jobs of :file:`.github/workflows/experimental.yml` and the
``compatibility`` job of :file:`.github/workflows/python-compatibility.yml` runs,
from the checkout's root and on the leg's own interpreter::

    python util/pip_install.py -e '.[test,DPKT,crypto,NGAP]'

with ``ANNOTATION_LEVEL``, ``error`` or ``warning``, ``LEG``, the leg's name, and
``RUNNER_TEMP`` in the environment. It runs, on the same interpreter:

1. ``python -m pip install -U pip setuptools wheel``, its output passed through. A
   failure ends the script with pip's status and no annotation, as ``set -e``
   would end a shell step.
2. ``python -m pip install -e SPEC``, its standard error merged into its standard
   output, which it copies, as it arrives, both to its own standard output and to
   :file:`$RUNNER_TEMP/pip-install.log`. On a failure it writes one
   ``ANNOTATION_LEVEL`` annotation, ``pcapkit did not install on LEG``, whose
   message is pip's last ``ERROR:`` line without that prefix or its indent, since
   pip indents the one naming a wheel it failed to build (#2041), or a fallback
   when there is none, and exits 1. The title escapes ``,`` as ``%2C``, since the
   runner splits an annotation's properties on ``,`` (#1633), and the message
   ``%`` as ``%25``.

On a KTLO leg the level is ``warning`` and the step carries ``continue-on-error``,
so every later step, which waits on the install's ``outcome``, is skipped. An
``ANNOTATION_LEVEL`` other than ``error`` or ``warning`` exits 2 before pip runs.
The script is standard library only, and runs on every interpreter the matrices
hold, the experimental tier included.

"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['LEVELS', 'UPGRADE', 'LOG_NAME', 'PREFIX', 'NO_REASON', 'TITLE', 'SKIPPED', 'main']

#: The annotation levels ``ANNOTATION_LEVEL`` may hold.
LEVELS = ('error', 'warning')
#: What the first pip run installs.
UPGRADE = ('install', '-U', 'pip', 'setuptools', 'wheel')
#: The second pip run's output, under ``$RUNNER_TEMP``.
LOG_NAME = 'pip-install.log'
#: How pip starts each line of an error.
PREFIX = b'ERROR: '
#: The annotation's message when pip wrote no ``ERROR:`` line.
NO_REASON = b"pip failed without an ERROR line; see this step's log"
#: The annotation's title, before the leg's name.
TITLE = 'pcapkit did not install on '
#: The end of the annotation's message.
SKIPPED = b'. The rest of this leg is skipped.'


def reason(output: 'bytes') -> 'bytes':
    """Pip's last ``ERROR:`` line in ``output``, less its indent and the prefix, or :data:`NO_REASON`.

    A failed wheel build's line is indented, ``  ERROR: Failed building wheel for
    cryptography``, and names the package and the step; pip's closing
    ``Failed to build cryptography`` and ``error: failed-wheel-build-for-install``
    say less, and carry no ``ERROR:`` prefix (#2041).

    """
    lines = (line.lstrip() for line in output.split(b'\n'))
    found = [line[len(PREFIX):] for line in lines if line.startswith(PREFIX)]
    return found[-1] if found and found[-1] else NO_REASON


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Upgrade pip, install ``SPEC`` editable, and annotate a failed install; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('-e', '--editable', required=True, metavar='SPEC',
                        help="what pip installs editable, such as '.[test,DPKT]'")
    args = parser.parse_args(argv)

    level = os.environ['ANNOTATION_LEVEL']
    if level not in LEVELS:
        print(f'ANNOTATION_LEVEL is {level!r}, not one of {", ".join(LEVELS)}.', file=sys.stderr)
        return 2
    leg = os.environ['LEG']
    log_path = pathlib.Path(os.environ['RUNNER_TEMP']) / LOG_NAME

    sys.stdout.flush()
    upgraded = subprocess.run([sys.executable, '-m', 'pip', *UPGRADE], check=False)  # nosec: B603
    if upgraded.returncode != 0:
        return _actions.exit_status(upgraded.returncode)

    status, output = _actions.run([sys.executable, '-m', 'pip', 'install', '-e', args.editable], log_path)
    if status == 0:
        return 0

    # The runner splits the properties on `,` before it un-escapes `%2C`, so the
    # leg's `(KTLO, non-blocking)` would end the title at "(KTLO" (#1633). #2047:
    # escaped here, not by the helper, so pip's bytes pass through as they are.
    message = reason(output).replace(b'%', b'%25') + SKIPPED
    _actions.say(_actions.annotation(level, message.decode('utf-8', 'surrogateescape'),
                                     title=TITLE + leg.replace(',', '%2C'), escape=False))
    return 1


if __name__ == '__main__':
    sys.exit(main())
