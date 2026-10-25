# -*- coding: utf-8 -*-
"""The wheels and conda builds a version was released with, which its completeness checks count (#1660).

:file:`.github/workflows/create-release.yml`'s ``version_check`` job runs it as
``python3 util/release_tiers.py``, the step "Read the released Python
versions", after setup-python. It appends ``pypi-wheels`` and
``conda-builds`` to ``$GITHUB_OUTPUT``:

* until ``PCAPKIT_TAG_EXISTS`` is ``true``, this run's: ``PCAPKIT_PYPI_WHEELS``
  and ``PCAPKIT_CONDA_BUILDS``, from "Read the Python versions";
* once the tag ``PCAPKIT_TAG`` exists, the tiers its commit was released with:
  the tag's :file:`.github/python-versions.toml`, read by that commit's
  :file:`util/python_versions.py` on ``python3``, beside that commit's
  :file:`util/_actions.py`, which it imports (#2047), where the commit has
  one. A tag the checkout lacks is
  fetched from ``origin``; a commit older than the tier file counts the tiers
  of the commit that added it, with a ``::notice``, and no such commit is an
  ``::error`` and status 1. A tag on this run's commit counts this run's, as
  they are the same.

The step formerly held this as shell under ``set -euo pipefail`` and the
runner's ``bash -e``, and this keeps its outcomes: a ``git``, ``mktemp`` or
``python3`` that fails ends the script with its status, but for the first
look for the tag, which a fetch follows, the looks for the tier file and the
helper, and the read of ``HEAD``, which only compares; a command missing from ``PATH`` is
status 127; a file that does not open for writing is status 1; a variable it
reads that is unset, which Actions never leaves it, is ``<name>: unbound
variable`` and status 1; a command killed by a signal is ``128 + N``, without
bash's own report of the kill. The outputs are written as the shell's ``echo``
wrote them, a line each, and the scratch directory is left behind as ``mktemp
-d`` left it.

It runs on setup-python's ``python3``, the interpreter it runs the tag's
reader on, but keeps to the standard library and Python 3.8's syntax as the
other :file:`util/` scripts do.

"""

from __future__ import annotations

import argparse
import os
# git, mktemp and python3, with fixed argument lists and no shell.
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import IO, Optional, Tuple, Union

__all__ = ['TIERS', 'READER', 'HELPER', 'Unbound', 'Failed', 'var', 'command', 'released', 'main']

#: The tier file, the script that reads it, and the helper that script imports, at a commit.
TIERS = '.github/python-versions.toml'
READER = 'util/python_versions.py'
HELPER = 'util/_actions.py'


class Unbound(Exception):
    """A variable read as ``$NAME`` that is unset, which ``set -u`` refused."""


class Failed(Exception):
    """A command whose failure ended the shell under ``set -e``, with its status."""

    def __init__(self, status: 'int') -> 'None':
        super().__init__(status)
        self.status = status


def var(name: 'str') -> 'bytes':
    """``$name``, as bytes; :exc:`Unbound` where it is unset."""
    try:
        # #2120: through the helper, which reads os.environ where os.environb is
        # missing, as on Windows.
        return _actions.getenvb(name)
    except KeyError:
        raise Unbound(name) from None


def command(*args: 'Union[str, bytes]', capture: 'bool' = False, raw: 'bool' = False,
            stdout: 'Optional[Union[int, IO[bytes]]]' = None, stderr: 'Optional[int]' = None) -> 'Tuple[int, bytes]':
    """Run ``args``: its status as the shell reports it, and with ``capture`` its output as ``$(...)`` gives it.

    That is without its trailing newlines, unless ``raw``. Without ``capture``
    its output goes to ``stdout``, else where the script's does; its standard
    error to ``stderr``, else where the script's does. A command missing from
    ``PATH`` is status 127.

    """
    sys.stdout.flush()
    try:
        result = subprocess.run([os.fsencode(arg) for arg in args],  # nosec: B603 B607
                                stdout=subprocess.PIPE if capture else stdout, stderr=stderr, check=False)
    except FileNotFoundError:
        print(f'{os.fsdecode(args[0])}: command not found', file=sys.stderr, flush=True)
        return 127, b''
    output = result.stdout if capture else b''
    return _actions.exit_status(result.returncode), (output if raw else output.rstrip(b'\n'))


def must(*args: 'Union[str, bytes]', **kwargs: 'object') -> 'bytes':
    """:func:`command`'s output, or :exc:`Failed` with its status."""
    status, output = command(*args, **kwargs)  # type: ignore[arg-type]
    if status:
        raise Failed(status)
    return output


def last_line(output: 'bytes') -> 'bytes':
    """What ``$(... | tail -n 1)`` keeps of ``output``: its last line, without its newline."""
    if output.endswith(b'\n'):
        output = output[:-1]
    return output.rsplit(b'\n', 1)[-1]


def say(text: 'bytes') -> 'None':
    """Write ``text`` and a newline to standard output, as ``echo`` did."""
    _actions.emit(text + b'\n')


def refused(path: 'bytes', error: 'OSError') -> 'int':
    """Say why a redirection to ``path`` did not open, as bash did; status 1."""
    sys.stdout.flush()
    print(f'{os.fsdecode(path)}: {os.strerror(error.errno or 0)}', file=sys.stderr, flush=True)
    return 1


def show(start: 'bytes', path: 'bytes', target: 'bytes') -> 'int':
    """``git show start:path > target``; the status, :exc:`Failed` with ``git``'s."""
    try:
        file = open(target, 'wb')  # pylint: disable=consider-using-with
    except OSError as error:
        return refused(target, error)
    with file:
        must('git', 'show', start + b':' + path, stdout=file)
    return 0


def released() -> 'int':
    """Write the wheels and builds to count to ``$GITHUB_OUTPUT``; the exit status."""
    wheels = var('PCAPKIT_PYPI_WHEELS')
    builds = var('PCAPKIT_CONDA_BUILDS')
    tiers = TIERS.encode()
    if var('PCAPKIT_TAG_EXISTS') == b'true':
        tag = var('PCAPKIT_TAG')
        ref = b'refs/tags/' + tag
        # The checkout fetched every tag, but not one pushed since.
        found, _ = command('git', 'rev-parse', '-q', '--verify', ref + b'^{commit}', stdout=subprocess.DEVNULL)
        if found:
            must('git', 'fetch', '-q', '--no-tags', 'origin', b'+' + ref + b':' + ref)
        start = must('git', 'rev-parse', ref + b'^{commit}', capture=True)
        missing, _ = command('git', 'cat-file', '-e', start + b':' + tiers, stderr=subprocess.DEVNULL)
        if missing:
            start = last_line(must('git', 'log', '--diff-filter=A', '--format=%H', '--', tiers, capture=True,
                                   raw=True))
            if not start:
                say(b'::error title=No tier file in the history::' + tiers
                    + b" was never added to this checkout's history.")
                return 1
            say(b'::notice title=Released before the tier file::' + tag + b' predates ' + tiers
                + b'; counting the tiers ' + start + b' added it with.')
        _, head = command('git', 'rev-parse', 'HEAD', capture=True)
        if start != head:
            scratch = must('mktemp', '-d', capture=True)
            for path, name in ((tiers, b'python-versions.toml'), (READER.encode(), b'python_versions.py')):
                status = show(start, path, scratch + b'/' + name)
                if status:
                    return status
            # #2047: the reader imports util/_actions.py from beside it, from the
            # commit that has it.
            lacks, _ = command('git', 'cat-file', '-e', start + b':' + HELPER.encode(), stderr=subprocess.DEVNULL)
            if not lacks:
                status = show(start, HELPER.encode(), scratch + b'/_actions.py')
                if status:
                    return status
            reader = (scratch + b'/python_versions.py', b'--file', scratch + b'/python-versions.toml')
            wheels = must('python3', *reader, 'pypi-wheels', capture=True)
            builds = must('python3', *reader, 'conda-builds', capture=True)

    say(var('PCAPKIT_TAG') + b': counting the wheels ' + wheels + b' and the conda builds ' + builds)
    for name, value in ((b'pypi-wheels', wheels), (b'conda-builds', builds)):
        path = var('GITHUB_OUTPUT')
        try:
            with open(path, 'ab') as file:
                file.write(name + b'=' + value + b'\n')
        except OSError as error:
            return refused(path, error)
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Write the wheels and conda builds the version's completeness checks count; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.parse_args(argv)
    try:
        return released()
    except Unbound as error:
        sys.stdout.flush()
        print(f'{error}: unbound variable', file=sys.stderr, flush=True)
        return 1
    except Failed as error:
        return error.status


if __name__ == '__main__':
    sys.exit(main())
