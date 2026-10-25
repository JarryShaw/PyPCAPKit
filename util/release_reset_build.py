# -*- coding: utf-8 -*-
"""Set ``conda/build`` back to 0 on ``main`` once a release's commit is tagged (#1634).

:file:`.github/workflows/create-release.yml`'s ``tag`` job runs it as
``python3 util/release_reset_build.py``, the step "Reset Build Number", once
"Create Tag" has put ``conda-<PCAPKIT_VERSION>+0`` on ``PCAPKIT_RUN_SHA``'s
commit. It adds one commit to ``main``, setting ``conda/build`` to 0, so the
next Conda Update bump of this version is ``+1``, and pushes it as a plain
fast-forward onto the tip it just fetched. It leaves ``main`` alone, and exits
0, where:

* the run's commit is not on ``main``: a warning;
* the tip already carries ``conda/build`` 0, as :file:`util/bump_version.py`
  usually leaves it: a notice;
* the tip's ``__version__`` is not the run commit's: a notice, as that counter
  counts another version's builds;
* ``origin`` has a ``conda-<version>+N`` tag other than ``+0``: a warning, as
  rewinding the counter would let a later bump reuse that number.

A rejected push means ``main`` moved, so the decision is made again from a
fresh fetch, three times at most, then an ``::error`` and status 1. The tag is
never touched: it was made before anything here reads ``main``.

The step formerly held this as shell under ``set -euo pipefail``; this prints
the same lines and annotations, unescaped as ``echo`` wrote them, and runs the
same ``git`` commands with the same arguments. A ``git`` that fails where the
shell had no ``if`` ends the script with its status, as ``set -e`` ended the
step, and a variable the step's ``env:`` names that is unset, which Actions
never leaves it, ends it with ``<name>: unbound variable`` and status 1 where
``set -u`` did.

``tag`` has no setup-python, so this runs on the image's ``python3``: standard
library only, and Python 3.8's syntax. Its ``git switch`` replaces the checkout,
:file:`util/` included, so everything it imports is imported first.

"""

from __future__ import annotations

import argparse
import os
import re
# git, with a fixed argument list and no shell.
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Optional, Tuple

__all__ = ['ATTEMPTS', 'Unbound', 'var', 'git', 'version_of', 'taken_builds', 'reset', 'main']

#: How many pushes to ``main`` are tried before giving up.
ATTEMPTS = 3
#: What ``__version__``'s line starts with; ``sed -n 's/^__version__ = //p'`` printed the rest.
VERSION_PREFIX = '__version__ = '
#: The bytes ``tr -d '[:space:]'`` deleted.
SPACE = ' \t\n\v\f\r'


class Unbound(Exception):
    """A variable read as ``$NAME`` that is unset, which ``set -u`` refused."""


def var(name: 'str') -> 'str':
    """``$name``; :exc:`Unbound` where it is unset."""
    try:
        return os.environ[name]
    except KeyError:
        raise Unbound(name) from None


def git(*args: 'str', capture: 'bool' = False) -> 'Tuple[int, str]':
    """Run ``git args``; its status as the shell reports it, and with ``capture`` its output.

    Its standard error, and without ``capture`` its output, go where the
    script's do. The output is returned without its trailing newlines, as
    ``$(...)`` gives it, whatever the status. A ``git`` missing from ``PATH``
    is status 127.

    """
    sys.stdout.flush()
    try:
        result = subprocess.run(['git', *args], stdout=subprocess.PIPE if capture else None,  # nosec: B603 B607
                                check=False)
    except FileNotFoundError:
        print('git: command not found', file=sys.stderr, flush=True)
        return 127, ''
    output = result.stdout.decode('utf-8', 'surrogateescape').rstrip('\n') if capture else ''
    return _actions.exit_status(result.returncode), output


def version_of(text: 'str') -> 'str':
    """What ``sed -n 's/^__version__ = //p'`` printed of ``text``, as ``$(...)`` gives it."""
    return '\n'.join(line[len(VERSION_PREFIX):] for line in text.split('\n')
                     if line.startswith(VERSION_PREFIX)).rstrip('\n')


def taken_builds(listing: 'str', builds: 'str') -> 'str':
    """The ``+N`` of each ref in ``git ls-remote``'s ``listing`` under ``builds`` but ``+0``, space-separated.

    Each line is split as ``read -r _ ref`` split it, on spaces and tabs, the
    first field dropped.

    """
    taken = []
    for line in listing.split('\n'):
        fields = re.split(r'[ \t]+', line.strip(' \t'), maxsplit=1)
        ref = fields[1] if len(fields) > 1 else ''
        if ref.startswith(builds) and ref[len(builds):] != '0':
            taken.append('+' + ref[len(builds):])
    return ' '.join(taken)


def say(level: 'str', title: 'str', message: 'str') -> 'None':
    """Print the ``::level`` annotation as the shell's ``echo`` did, unescaped."""
    _actions.say(_actions.annotation(level, message, title=title, escape=False))


def reset() -> 'int':  # pylint: disable=too-many-branches,too-many-return-statements
    """Reset ``conda/build`` on ``main`` where it is safe to; the exit status."""
    status, run_commit = git('rev-parse', '--verify', var('PCAPKIT_RUN_SHA') + '^{commit}', capture=True)
    if status:
        return status
    status, text = git('show', f'{run_commit}:pcapkit/__init__.py', capture=True)
    if status:
        return status
    run_version = version_of(text)
    version = var('PCAPKIT_VERSION')
    builds = f'refs/tags/conda-{version}+'

    for attempt in range(1, ATTEMPTS + 1):
        status, _ = git('fetch', '--quiet', 'origin', '+refs/heads/main:refs/remotes/origin/main')
        if status:
            return status
        status, tip = git('rev-parse', 'refs/remotes/origin/main', capture=True)
        if status:
            return status

        status, _ = git('merge-base', '--is-ancestor', run_commit, tip)
        if status:
            say('warning', 'conda/build not reset', f'{run_commit} is not on main (tip {tip}), so main is left '
                                                    'alone; its conda/build still reads what it did.')
            return 0
        status, text = git('show', f'{tip}:conda/build', capture=True)
        if status:
            return status
        tip_build = text.translate({ord(char): None for char in SPACE})
        if tip_build == '0':
            say('notice', 'No conda build reset needed', f'main ({tip}) already carries conda/build 0.')
            return 0
        status, text = git('show', f'{tip}:pcapkit/__init__.py', capture=True)
        if status:
            return status
        tip_version = version_of(text)
        if tip_version != run_version:
            say('notice', 'conda/build not reset', f'main ({tip}) has moved on to __version__ {tip_version}; '
                                                   f"its conda/build {tip_build} counts that version's builds.")
            return 0
        status, listing = git('ls-remote', '--tags', '--refs', 'origin', builds + '*', capture=True)
        if status:
            return status
        taken = taken_builds(listing, builds)
        if taken:
            say('warning', 'conda/build not reset', f'conda-{version} is already tagged at {taken}; resetting '
                                                    f'conda/build {tip_build} on main ({tip}) to 0 would let a '
                                                    'later Conda Update bump reuse one of those build numbers.')
            return 0

        status, _ = git('switch', '--quiet', '--force', '--detach', tip)
        if status:
            return status
        try:
            with open(os.path.join('conda', 'build'), 'wb') as file:
                file.write(b'0')
        except OSError as error:
            sys.stdout.flush()
            print(f'conda/build: {error.strerror}', file=sys.stderr, flush=True)
            return 1
        status, _ = git('commit', '--quiet', '-mReset conda build number',
                        f'-mconda-{version}+0 was tagged at {run_commit}.', '--', 'conda/build')
        if status:
            return status
        status, _ = git('push', 'origin', 'HEAD:refs/heads/main')
        if not status:
            _, head = git('rev-parse', 'HEAD', capture=True)
            _actions.say(f'conda/build reset from {tip_build} to 0 on main in {head}, on top of {tip}')
            return 0
        _actions.say(f'push to main rejected on attempt {attempt}; fetching again')

    say('error', 'conda/build not reset', f'main kept moving; three pushes were rejected. {run_commit} is tagged '
                                          f'regardless -- reset conda/build on main by hand if no conda-{version}+N '
                                          'tag other than +0 exists.')
    return 1


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Reset ``conda/build`` from the step's ``env:``; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.parse_args(argv)
    try:
        return reset()
    except Unbound as error:
        sys.stdout.flush()
        print(f'{error}: unbound variable', file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
