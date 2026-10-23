# -*- coding: utf-8 -*-
"""Which commit a release tag names, against the commit this run was created for (#1634, #1748).

:file:`.github/workflows/create-release.yml` runs it from the checkout's root,
on the runner's own ``python3``, in two forms:

``python3 util/release_tags.py check``
    The step "Check the release tags name this run's commit" of the ``github``,
    ``pypi`` and ``conda`` jobs. For each tag in ``PCAPKIT_TAGS``, split on
    spaces, tabs and newlines, it fetches the tag from ``origin`` and requires
    that it names ``PCAPKIT_RUN_SHA``'s commit. The first that does not, or
    does not exist, gets an ``::error`` and exits 1; each that does prints
    ``<tag> -> <commit>``.
``python3 util/release_tags.py owner``
    The step "Check which commit the version's tag names" of ``version_check``.
    It fetches ``PCAPKIT_TAG`` the same way, prints what it names, and appends
    ``PCAPKIT_RELEASED_AT``, that commit or nothing, and
    ``PCAPKIT_RELEASED_ELSEWHERE``, ``true`` only for a tag naming another
    commit, to ``$GITHUB_OUTPUT``.

Both resolve the tag with :func:`resolve`, so ``owner`` reads "elsewhere"
exactly where ``check`` would refuse a tag that exists. A failed fetch is
ignored, since the checkout may already hold the tag, and a tag that does not
resolve is no commit. ``PCAPKIT_RUN_SHA`` that does not resolve ends the script
with ``git``'s status, as ``set -e`` ended the step.

The steps formerly held this as shell. Its unquoted ``${PCAPKIT_TAGS}`` was
also subject to pathname expansion, which this skips: every tag is ``v`` or
``conda-`` and a :pep:`440` version, which holds no ``*``, ``?`` or ``[``.

The ``conda`` legs run it before setup-python, so ``python3`` is the image's,
and ``github`` has no setup-python at all. So the script is standard library
only, and keeps to Python 3.7's syntax.

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

__all__ = ['git', 'run_commit', 'resolve', 'check', 'owner', 'main']

#: What ``check``'s refusal says after naming the tag and what it resolves to.
REFUSAL = ("Refusing to publish this tree under it: every artefact of a release comes from its tag's commit, "
           'so finish that release by re-running the run created for that commit.')


def git(*args: 'str', capture: 'bool' = False) -> 'Tuple[int, str]':
    """Run ``git args``; its status as the shell reports it, and with ``capture`` its output.

    Its standard error, and without ``capture`` its output, go where the
    script's do. The output is returned without its trailing newlines, as
    ``$(...)`` gives it. A ``git`` missing from ``PATH`` is status 127.

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


def run_commit() -> 'Tuple[int, str]':
    """``$PCAPKIT_RUN_SHA``'s commit: ``(0, sha)``, or ``git``'s non-zero status and ``''``."""
    status, sha = git('rev-parse', '--verify', os.environ['PCAPKIT_RUN_SHA'] + '^{commit}', capture=True)
    return status, (sha if status == 0 else '')


def resolve(tag: 'str') -> 'str':
    """Fetch ``tag`` from ``origin``, failures ignored, and return the commit it names, or ``''``."""
    git('fetch', '--quiet', '--force', 'origin', f'refs/tags/{tag}:refs/tags/{tag}')
    _, tagged = git('rev-parse', '-q', '--verify', f'refs/tags/{tag}^{{commit}}', capture=True)
    return tagged


def check() -> 'int':
    """Require each of ``$PCAPKIT_TAGS`` to name the run's commit; the exit status."""
    status, commit = run_commit()
    if status:
        return status
    for tag in re.split(r'[ \t\n]+', os.environ['PCAPKIT_TAGS']):
        if not tag:
            continue
        tagged = resolve(tag)
        if tagged != commit:
            _actions.annotate('error', f"{tag} resolves to '{tagged or 'no commit'}', but this run was created "
                                       f'for {commit}. {REFUSAL}',
                              title=f"{tag} is not this run's commit (#1634)", escape=False)
            return 1
        print(f'{tag} -> {commit}', flush=True)
    return 0


def owner() -> 'int':
    """Report and output which commit ``$PCAPKIT_TAG`` names; the exit status."""
    status, commit = run_commit()
    if status:
        return status
    tag = os.environ['PCAPKIT_TAG']
    tagged = resolve(tag)
    elsewhere = 'true' if tagged and tagged != commit else 'false'
    print(f"{tag} -> {tagged or 'no commit'}; this run's commit is {commit}; released elsewhere: {elsewhere}",
          flush=True)
    _actions.set_output('PCAPKIT_RELEASED_AT', tagged)
    _actions.set_output('PCAPKIT_RELEASED_ELSEWHERE', elsewhere)
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Run the subcommand ``argv`` names; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('command', choices=('check', 'owner'),
                        help="check: every $PCAPKIT_TAGS names the run's commit; owner: which $PCAPKIT_TAG names")
    args = parser.parse_args(argv)
    return check() if args.command == 'check' else owner()


if __name__ == '__main__':
    sys.exit(main())
