# -*- coding: utf-8 -*-
"""Run a pytest command once per shard, then once over the rest (#1963).

A GraalPy xdist worker's live heap grows with every test it runs, and
experimental.yml's ``experimental`` job gives each GraalPy process a fixed heap
that ends it once spent (#1753), so a worker that lives through the whole tier
dies in it, and xdist fails the test it ran. Restarting the workers between runs
is what bounds them. ``Run unit tests`` therefore runs, on the GraalPy leg::

    /usr/bin/python3 util/pytest_shards.py "$SHARDS" -- python -m pytest ...

``SHARDS`` holds the shards, separated by whitespace, and each is a directory or
a glob of the entries of one directory, such as ``tests/corekit/test_i*``.
The command runs once per shard, then once more over the rest, and each run
starts its own xdist workers:

* A directory's run appends the directory.
* A glob's run appends the glob's directory and an ``--ignore`` for each of its
  entries the glob leaves out, so pytest collects the directory as it would any
  other -- its own patterns and the command's ``--ignore`` hold -- where a file
  named on the command line would be collected whatever ignores it. A glob that
  matches nothing runs nothing and says so, which leaves its tests to the rest.
* Every run but the first also ignores what each earlier shard took, so a glob
  of a directory may come before the directory itself, which then takes the
  remainder, and a shard an earlier one took whole runs nothing. The last run
  ignores every shard.

Every run gets the command's own options, so its ``-n`` and ``--ignore`` hold in
each; a shard's run also gets a ``--junitxml`` of its own, beside the command's,
named after the shard -- ``junit-tests-protocols.xml`` beside ``junit.xml`` --
and the last run keeps the command's.

The runs share the step's one ``timeout``, scope and watcher, which run this
script, so the step's caps hold over the whole tier rather than a shard. On
``SIGINT``, which ``timeout`` sends to its whole process group, the run then in
progress ends as pytest ends it, with its JUnit file written, and no later run
starts. Any other signal ends this script as it would any process.

The exit status is that of the last run to fail, as a shell gives it for a run
a signal ended, or 0 where none did. The script runs on the image's own
interpreter, apart from the leg's, so it is standard library only.

"""

from __future__ import annotations

import glob
import os
import pathlib
import re
import signal
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

__all__ = ['junit_for', 'main', 'runs']

#: Exit status for a bad command line, as :mod:`argparse` uses for a usage error.
USAGE = 2
#: The option pytest writes its JUnit file by.
JUNIT = '--junitxml='
#: What makes a shard a glob, as :func:`glob.has_magic` reads it.
MAGIC = re.compile(r'[*?[]')


def junit_for(command: 'list[str]', shard: 'str') -> 'Optional[str]':
    """The ``--junitxml`` for ``shard``'s run, beside the last one ``command`` has; ``None`` where it has none."""
    found = [arg for arg in command if arg.startswith(JUNIT)]
    if not found:
        return None
    path = pathlib.PurePath(found[-1][len(JUNIT):])
    # A glob's wildcards drop out: ``tests/corekit/test_[a-f]*`` is ``tests-corekit-test_a-f``.
    parts = (re.sub(r'[^\w.-]+', '', part) for part in pathlib.PurePath(shard).parts)
    slug = '-'.join(part for part in parts if part not in ('', '.'))
    return f'{JUNIT}{path.with_name(f"{path.stem}-{slug}{path.suffix}")}'


def select(shard: 'str') -> 'tuple[str, list[str], list[str]]':
    """The path ``shard``'s run collects, the paths under it that run ignores, and the paths ``shard`` takes.

    Raises:
        ValueError: A glob whose directory holds wildcards, or that matches nothing.

    """
    if not MAGIC.search(shard):
        return shard, [], [shard]
    directory, _ = os.path.split(shard)
    if not directory or MAGIC.search(directory) or not os.path.isdir(directory):
        raise ValueError(f'{shard}: a glob shard globs the entries of one directory')
    taken = sorted(glob.glob(shard))
    if not taken:
        raise ValueError(f'{shard}: matches nothing')
    # glob() skips dot-entries; a package's own files and its conftest.py are never a test's.
    left = sorted(path for path in glob.glob(os.path.join(directory, '*'))
                  if path not in taken and not os.path.basename(path).startswith('_')
                  and os.path.basename(path) != 'conftest.py')
    return directory, left, taken


def runs(shards: 'list[str]', command: 'list[str]') -> 'list[tuple[str, list[str]]]':
    """Every run's name and argv, in order: one per shard, then the rest; a shard that selects nothing is skipped."""
    argvs = []
    taken = []  # type: list[str]
    for shard in shards:
        try:
            path, ignores, took = select(shard)
        except ValueError as error:
            print(f'pytest_shards: skipping {error}', flush=True)
            continue
        took = [entry for entry in took if entry not in taken]
        if not took:
            print(f'pytest_shards: skipping {shard}: an earlier shard took it', flush=True)
            continue
        junit = junit_for(command, shard)
        ignored = [*taken, *(entry for entry in ignores if entry not in taken)]
        argvs.append((shard, [*command, *([junit] if junit else []), *(f'--ignore={entry}' for entry in ignored),
                              path]))
        taken.extend(took)
    argvs.append(('the rest', [*command, *(f'--ignore={entry}' for entry in taken)]))
    return argvs


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Run ``SHARDS ... -- COMMAND ...`` as the module docstring says; the exit status."""
    args = sys.argv[1:] if argv is None else argv
    if '--' not in args:
        print(f'usage: {pathlib.Path(sys.argv[0]).name} SHARDS [SHARDS ...] -- COMMAND [ARGUMENT ...]',
              file=sys.stderr)
        return USAGE
    split = args.index('--')
    shards = [shard for arg in args[:split] for shard in arg.split()]
    command = args[split + 1:]
    if not shards or not command:
        print('pytest_shards: name at least one shard, and the command after --', file=sys.stderr)
        return USAGE

    interrupted = []

    def stop(signum: 'int', frame: 'Optional[FrameType]') -> 'None':  # pylint: disable=unused-argument
        interrupted.append(signum)

    # An ignored SIGINT stays ignored, for this script and so for pytest.
    if signal.getsignal(signal.SIGINT) is not signal.SIG_IGN:
        signal.signal(signal.SIGINT, stop)

    status = 0
    every = runs(shards, command)
    for index, (name, run) in enumerate(every, 1):
        print(f'pytest_shards: run {index} of {len(every)}, {name}', flush=True)
        code = subprocess.call(run)  # nosec: B603 - the step's own command
        if code < 0:
            # Ended by a signal: the status a shell gives it.
            code = 128 - code
        if code:
            status = code
        if interrupted:
            print(f'pytest_shards: interrupted during {name}; no later run starts', flush=True)
            break
    return status


if __name__ == '__main__':
    sys.exit(main())
