# -*- coding: utf-8 -*-
"""Whether a version's files are all on PyPI, and all on Anaconda (#888, #1633, #1922).

:file:`.github/workflows/create-release.yml`'s ``version_check`` job runs it,
after setup-python, in two forms:

``python3 util/release_published.py pypi /tmp/pypi_release.json``
    The step "Check PyPI publish completeness". It expects a wheel for each
    tag in ``PCAPKIT_PYPI_WHEELS`` and the sdist, reads
    ``https://pypi.org/pypi/pypcapkit/<PCAPKIT_VERSION>/json``'s ``urls`` and
    appends ``PCAPKIT_PYPI_COMPLETE`` to ``$GITHUB_OUTPUT``.
``python3 util/release_published.py anaconda /tmp/anaconda_release.json``
    The step "Check Anaconda publish completeness". It expects a distribution
    for each platform in :data:`SUBDIRS`, the ones the ``conda`` legs publish,
    and each build in ``PCAPKIT_CONDA_BUILDS``, reads
    ``https://api.anaconda.org/release/jarryshaw/pypcapkit/<PCAPKIT_VERSION>``'s
    ``distributions`` and appends ``PCAPKIT_CONDA_COMPLETE``.

Each fetches with ``curl -s --retry 3 --retry-connrefused``, writing the body
to the path it is given, and reads only a ``200``; anything else, a ``curl``
that fails or is missing included, counts nothing, so an outage reads
``false``, the safe default, without failing ``version_check`` (see
:func:`fetch`). Both are ``true`` only once what they count reaches what they
expect, so a version expecting nothing is ``true`` unread. The one count runs
on ``python3 -`` as a snippet of its own, which keeps a body that does not
parse failing the step as it did, with ``python3``'s status and traceback.

Both steps formerly held this as shell under ``set -euo pipefail`` and the
runner's ``bash -e``, and the two did the same but for their endpoint, their
expectation and their count; so they share this script. It keeps their
outcomes: the lists are read as ``read -r -a`` read them, from the first line,
split on spaces and tabs; ``curl``'s ``-w`` code and the ``000`` its failure
added are the ``http`` the log line names; a count that is not an integer is
``[``'s error and reads ``false``; a variable it reads that is unset, which
Actions never leaves it, is ``<name>: unbound variable`` and status 1.

It keeps to the standard library and Python 3.7's syntax as the other
:file:`util/` scripts do.

"""

from __future__ import annotations

import argparse
import os
import re
# curl and python3, with fixed argument lists and no shell.
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Callable, Optional, Tuple, Union

__all__ = ['SUBDIRS', 'PYPI_URL', 'ANACONDA_URL', 'INDEXES', 'pypi_source', 'anaconda_source', 'Unbound', 'Failed',
           'var', 'words', 'fetch', 'count', 'integer', 'complete', 'check', 'pypi', 'anaconda', 'main']

#: Each platform the ``conda`` legs publish, for each supported build (#1922).
SUBDIRS = 'linux-64 osx-64 osx-arm64'
#: The per-version endpoints, before the version.
PYPI_URL = 'https://pypi.org/pypi/pypcapkit/'
ANACONDA_URL = 'https://api.anaconda.org/release/jarryshaw/pypcapkit/'
#: What each index's log line counts, the index's name, and the output it appends.
INDEXES = {
    'pypi': (b'files', b'PyPI', 'PCAPKIT_PYPI_COMPLETE'),
    'anaconda': (b'platform/Python combinations', b'Anaconda', 'PCAPKIT_CONDA_COMPLETE'),
}


def pypi_source(path: 'str') -> 'str':
    """The snippet counting the supported wheels, and the sdist, in the PyPI reply at ``path``.

    A wheel's tag is its name's third ``-`` field; ``PCAPKIT_PYPI_WHEELS``
    lists the supported ones, so a KTLO wheel neither completes the release
    nor, missing, leaves it incomplete (#1633). It reads ``urls``: the
    endpoint's ``releases`` was empty on every request checked.

    """
    return '\n'.join((
        'import json, os',
        f'with open({path!r}) as f:',
        '    data = json.load(f)',
        "supported = set(os.environ['PCAPKIT_PYPI_WHEELS'].split())",
        "names = [u.get('filename', '') for u in data.get('urls', [])]",
        "wheels = {n.split('-')[2] for n in names if n.endswith('.whl') and n.count('-') == 4}",
        "print(len(wheels & supported) + any(n.endswith('.tar.gz') for n in names))",
    )) + '\n'


def anaconda_source(path: 'str') -> 'str':
    """The snippet counting each platform and build the Anaconda reply at ``path`` holds."""
    return '\n'.join((
        'import json, os',
        f'with open({path!r}) as f:',
        '    data = json.load(f)',
        "platforms = set(os.environ['PCAPKIT_CONDA_SUBDIRS'].split())",
        "py_tags = set(os.environ['PCAPKIT_CONDA_BUILDS'].split())",
        'seen = {',
        "    (d.get('attrs', {}).get('subdir'), tag)",
        "    for d in data.get('distributions', [])",
        '    for tag in py_tags',
        "    if d.get('attrs', {}).get('build', '').startswith(tag + '_')",
        "    and d.get('attrs', {}).get('subdir') in platforms",
        '}',
        'print(len(seen))',
    )) + '\n'


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
        return os.environb[name.encode()]
    except KeyError:
        raise Unbound(name) from None


def words(value: 'bytes') -> 'list[bytes]':
    """The words ``read -r -a`` reads from ``<<< value``: its first line, split on spaces and tabs."""
    return [word for word in re.split(rb'[ \t]+', value.split(b'\n', 1)[0]) if word]


def command(args: 'list[Union[str, bytes]]', source: 'Optional[bytes]' = None) -> 'Tuple[int, bytes]':
    """Run ``args``, ``source`` on its standard input: its status as the shell reports it, and its output.

    Its standard error goes where the script's does. A command missing from
    ``PATH`` is status 127.

    """
    sys.stdout.flush()
    try:
        result = subprocess.run([os.fsencode(arg) for arg in args], input=source,  # nosec: B603 B607
                                stdout=subprocess.PIPE, check=False)
    except FileNotFoundError:
        print(f'{os.fsdecode(args[0])}: command not found', file=sys.stderr, flush=True)
        return 127, b''
    return _actions.exit_status(result.returncode), result.stdout


def fetch(url: 'bytes', path: 'str') -> 'bytes':
    """``$(curl ... || echo 000)``: the HTTP code ``curl -w`` printed, then ``000`` if it failed.

    ``--retry-connrefused`` and the ``000`` keep a pypi.org or anaconda.org
    outage from failing ``version_check`` under ``set -e``, which every
    publisher requires; a failed ``curl`` has usually printed ``000`` itself
    already, so the two read ``000000``, never ``200``.

    """
    status, output = command(['curl', '-s', '--retry', '3', '--retry-connrefused', '-o', path, '-w',
                              '%{http_code}', url])
    if status:
        output += b'000\n'
    return output.rstrip(b'\n')


def count(source: 'str') -> 'bytes':
    """``$(printf ... | python3 -)``: what ``source`` prints, or :exc:`Failed` with its status."""
    status, output = command(['python3', '-'], source.encode())
    if status:
        raise Failed(status)
    return output.rstrip(b'\n')


def integer(text: 'bytes') -> 'Optional[int]':
    """``text`` as ``[``'s ``-ge`` reads an integer, else :data:`None`.

    That is an optional sign and digits, with any white space before them and
    spaces or tabs after, inside 64 bits, as bash's ``legal_number`` reads it.

    """
    match = re.match(rb'[ \t\n\v\f\r]*([-+]?[0-9]+)[ \t]*\Z', text)
    if match is None:
        return None
    value = int(match.group(1))
    return value if -2 ** 63 <= value < 2 ** 63 else None


def complete(found: 'bytes', expected: 'int') -> 'bytes':
    """``true`` where ``found`` reaches ``expected``; a count that is not an integer says so and is ``false``."""
    value = integer(found)
    if value is None:
        sys.stdout.flush()
        print(f'[: {os.fsdecode(found)}: integer expression expected', file=sys.stderr, flush=True)
        return b'false'
    return b'true' if value >= expected else b'false'


def check(index: 'str', expected: 'int', url: 'bytes', path: 'str', source: 'Callable[[str], str]') -> 'int':
    """Fetch ``url`` to ``path``, count it with ``source``, say so, and write ``index``'s output; the exit status."""
    what, name, output = INDEXES[index]
    status = fetch(url, path)
    found = b'0'
    if status == b'200':
        found = count(source(path))
    done = complete(found, expected)
    _actions.emit(b'http ' + status + b', found ' + found + b' of ' + str(expected).encode() + b' expected '
                  + what + b' for ' + var('PCAPKIT_VERSION') + b' on ' + name + b'\n')
    target = var('GITHUB_OUTPUT')
    try:
        with open(target, 'ab') as file:
            file.write(output.encode() + b'=' + done + b'\n')
    except OSError as error:
        sys.stdout.flush()
        print(f'{os.fsdecode(target)}: {os.strerror(error.errno or 0)}', file=sys.stderr, flush=True)
        return 1
    return 0


def pypi(path: 'str') -> 'int':
    """``PCAPKIT_PYPI_COMPLETE``: one wheel per supported leg, plus the sdist."""
    expected = len(words(var('PCAPKIT_PYPI_WHEELS'))) + 1
    return check('pypi', expected, PYPI_URL.encode() + var('PCAPKIT_VERSION') + b'/json', path, pypi_source)


def anaconda(path: 'str') -> 'int':
    """``PCAPKIT_CONDA_COMPLETE``: each platform the ``conda`` legs publish, for each supported version."""
    # Exported, as the step did, so curl and the snippet see it.
    os.environ['PCAPKIT_CONDA_SUBDIRS'] = SUBDIRS
    expected = len(words(SUBDIRS.encode())) * len(words(var('PCAPKIT_CONDA_BUILDS')))
    return check('anaconda', expected, ANACONDA_URL.encode() + var('PCAPKIT_VERSION'), path, anaconda_source)


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Check the index ``argv`` names; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('index', choices=('pypi', 'anaconda'), help='the index whose files to count')
    parser.add_argument('reply', help='where curl writes the reply, which the count reads')
    args = parser.parse_args(argv)
    try:
        return (pypi if args.index == 'pypi' else anaconda)(args.reply)
    except Unbound as error:
        sys.stdout.flush()
        print(f'{error}: unbound variable', file=sys.stderr, flush=True)
        return 1
    except Failed as error:
        return error.status


if __name__ == '__main__':
    sys.exit(main())
