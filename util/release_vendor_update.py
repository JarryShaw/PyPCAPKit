# -*- coding: utf-8 -*-
"""Whether the Vendor Update that started a Create Release run updated anything (#1748).

:file:`.github/workflows/create-release.yml`'s ``vendor_update`` job runs it as
``python3 util/release_vendor_update.py``, the step "Read whether its
vendor-update job ran". It lists the jobs of Vendor Update run
``PCAPKIT_VENDOR_RUN_ID`` with ``gh api``, "List jobs for a workflow run", and
reads the conclusion of the one named ``vendor-update``:

``success``
    appends ``updated=true`` to ``$GITHUB_OUTPUT``;
``skipped``
    appends ``updated=false`` and says why: its verdict did not cover the commit
    it checked out;
anything else, or a listing that failed
    leaves ``updated`` unset, with a ``::warning``, so ``version_check`` runs as
    before #1748: it can cost a run, never a release.

It exits 0 on each. The step formerly held this as shell, under ``set -uo
pipefail`` and the runner's ``bash -e``; this prints the same lines, unescaped as
``echo`` wrote them, and replaces each line break in a conclusion it cannot read
with a space, as ``${result//$'\\n'/ }`` did. A variable it reads that is unset,
which Actions never leaves it, is ``<name>: unbound variable`` where the shell's
``set -u`` refused it: inside ``gh api``'s arguments that fails the listing, and
anywhere else it ends the script with status 1.

The job checks out only :file:`util/` and has no setup-python, so this runs on
the image's ``python3``: standard library only, and Python 3.7's syntax.

"""

from __future__ import annotations

import argparse
import os
# gh, with a fixed argument list and no shell.
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Optional, Tuple

__all__ = ['JOBS_JQ', 'Unbound', 'var', 'list_conclusion', 'read', 'main']

#: The ``--jq`` filter reading the ``vendor-update`` job's conclusion.
JOBS_JQ = '.jobs[] | select(.name == "vendor-update") | .conclusion'
#: The title of every warning, for a run this cannot read.
NOT_READ = 'Vendor Update not read (#1748)'


class Unbound(Exception):
    """A variable read as ``$NAME`` that is unset, which ``set -u`` refused."""


def var(name: 'str') -> 'str':
    """``$name``; :exc:`Unbound` where it is unset."""
    try:
        return os.environ[name]
    except KeyError:
        raise Unbound(name) from None


def unbound(error: 'Unbound') -> 'None':
    """Say what ``set -u`` said."""
    sys.stdout.flush()
    print(f'{error}: unbound variable', file=sys.stderr, flush=True)


def list_conclusion() -> 'Tuple[int, str]':
    """``gh api``'s status as the shell reports it, and its output as ``$(...)`` gives it.

    Its standard error goes where the script's does. A ``gh`` missing from
    ``PATH`` is status 127, and an unset variable in its arguments status 1.

    """
    try:
        endpoint = f"repos/{var('GITHUB_REPOSITORY')}/actions/runs/{var('PCAPKIT_VENDOR_RUN_ID')}/jobs"
    except Unbound as error:
        unbound(error)
        return 1, ''
    sys.stdout.flush()
    try:
        result = subprocess.run(['gh', 'api', endpoint, '--paginate', '--jq', JOBS_JQ],  # nosec: B603 B607
                                stdout=subprocess.PIPE, check=False)
    except FileNotFoundError:
        print('gh: command not found', file=sys.stderr, flush=True)
        return 127, ''
    output = result.stdout.decode('utf-8', 'surrogateescape').rstrip('\n')
    return _actions.exit_status(result.returncode), output


def updated(value: 'str') -> 'None':
    """Append ``updated=value`` to ``$GITHUB_OUTPUT``."""
    _actions.set_output('updated', value, environ={'GITHUB_OUTPUT': var('GITHUB_OUTPUT')})


def read() -> 'int':
    """Read the ``vendor-update`` job's conclusion into ``updated``; the exit status."""
    status, result = list_conclusion()
    if status:
        _actions.say(_actions.annotation(
            'warning', f"could not list the jobs of Vendor Update run {var('PCAPKIT_VENDOR_RUN_ID')}, so this run "
                       'treats it as one that updated.', title=NOT_READ, escape=False))
        return 0
    if result == 'success':
        updated('true')
    elif result == 'skipped':
        updated('false')
        _actions.say(f"Vendor Update run {var('PCAPKIT_VENDOR_RUN_ID')} skipped vendor-update: its verdict did "
                     'not cover the commit it checked out.')
    else:
        flat = result.replace('\n', ' ')
        _actions.say(_actions.annotation(
            'warning', f"Vendor Update run {var('PCAPKIT_VENDOR_RUN_ID')} reports vendor-update as '{flat}', so "
                       'this run treats it as one that updated.',
            title=NOT_READ, escape=False))
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Read the triggering Vendor Update's ``vendor-update`` job; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.parse_args(argv)
    try:
        return read()
    except Unbound as error:
        unbound(error)
        return 1


if __name__ == '__main__':
    sys.exit(main())
