# -*- coding: utf-8 -*-
"""Run a command with every file it writes capped at :data:`LIMIT` bytes (#1969).

A test that writes without bound fills the runner's disk rather than failing:
#1372's ``out.json`` grew to several gigabytes on every run. Each pytest and
unittest step of :file:`.github/workflows/unit-tests.yml` therefore runs as::

    python util/cap_file_size.py python -m pytest ...

which sets ``RLIMIT_FSIZE``, soft and hard, to :data:`LIMIT` and then replaces
itself with the command, so the command's exit status and signals are the step's
own. The limit is inherited by every process the command starts, pytest-xdist's
workers and a test's subprocesses alike, and an unprivileged process cannot raise
the hard limit again. A hard limit already below :data:`LIMIT` is kept.

A write past the limit fails in the kernel with ``EFBIG``, and the writer is sent
``SIGXFSZ``. CPython ignores that signal, so in a Python process the write raises
:exc:`OSError` (``[Errno 27] File too large``) and the test errors. Any other
program is killed by it. This script restores the default action before it
execs, as :mod:`subprocess` does for a child, since an ignored signal stays
ignored across ``exec``.

:data:`LIMIT` is the one copy of the number; :file:`.github/workflows/experimental.yml`
gives its legs the same cap through ``prlimit --fsize``.

"""

from __future__ import annotations

import os
import resource
import signal
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import NoReturn, Optional

__all__ = ['LIMIT', 'cap', 'main']

#: The largest file, in bytes, the command may write: 2 GiB.
LIMIT = 2 * 1024 ** 3
#: Exit status for a missing command, as :mod:`argparse` uses for a usage error.
USAGE = 2


def cap(limit: 'int' = LIMIT) -> 'int':
    """Cap ``RLIMIT_FSIZE`` of this process at ``limit``, or its hard limit if lower; return the cap."""
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    return limit


def main(argv: 'Optional[list[str]]' = None) -> 'NoReturn':
    """Cap the file size at :data:`LIMIT` and exec ``argv``, the command and its arguments."""
    command = sys.argv[1:] if argv is None else argv
    if not command:
        print(f'usage: {os.path.basename(sys.argv[0])} COMMAND [ARGUMENT ...]', file=sys.stderr)
        sys.exit(USAGE)
    cap(LIMIT)
    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
    sys.stdout.flush()
    sys.stderr.flush()
    os.execvp(command[0], command)  # nosec: B606 - the step's own command


if __name__ == '__main__':
    main()
