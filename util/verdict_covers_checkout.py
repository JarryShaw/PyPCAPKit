# -*- coding: utf-8 -*-
"""Whether the ``Unit Tests`` verdict a ``workflow_run`` carries covers this checkout.

Conda Update, Vendor Update and GitHub Pages chain off ``Unit Tests`` completing
on ``main``. Their checkouts take ``github.sha``, which for a ``workflow_run`` is
the "Last commit on default branch" when the event is raised (GitHub, "Events
that trigger workflows"), not the commit the completed run tested --
``github.event.workflow_run.head_sha``. In a merge wave the two differ (#1643):
Conda Update 38325136710 ran on 2e941bbb7 under the verdict for 9083163f5, three
merged pull requests older, and pushed f4f94bcad on top at 00:03:38Z; 2e941bbb7's
own run 38323130015 finished at 00:13:35Z.

The verdict covers ``HEAD`` when

* it *is* ``HEAD``; or
* every commit after it up to ``HEAD`` is a single-parent commit authored and
  committed as :data:`BOT_EMAIL` that touches only :data:`BOT_MANAGED_PATHS`.

Anything else is not covered, and the job gated on this one skips. Nothing is
lost by that: ``HEAD``'s own ``Unit Tests`` run raises the workflow again when it
completes, bot commits included -- since #401 (bb900906b, 2026-09-15) they are
pushed with a deploy key, not with ``GITHUB_TOKEN``, whose events "will not create
a new workflow run" (GitHub, "Triggering a workflow from a workflow"). Every bot
commit on ``main`` since has its own ``push`` run of ``Unit Tests``,
f4f94bcad's being 38325349953, while 5d5d8af4d, 48bc11384 and e4d0823db, from
before #401, have none. The second case only saves waiting for that run where it
cannot change the answer.

Run with ``VERDICT_SHA`` set, from the checkout. Writes ``verified=true`` or
``verified=false`` to ``$GITHUB_OUTPUT``, and exits non-zero only when it cannot
answer at all.

Conda Update's Push Changes step asks the same question of the commits its
rebase would bring in (#1632): ``VERDICT_SHA`` is the commit it checked out,
``--head`` the tip it fetched, and ``--exit-code`` answers in the exit status,
for the shell, instead of in ``$GITHUB_OUTPUT``.

"""

from __future__ import annotations

import argparse
import os
import re
import subprocess  # nosec B404
import sys
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Optional

#: The identity Conda Update, Vendor Update and Create Release commit as. All
#: 275 commits on ``main`` authored by it were committed by it too, none of them
#: a merge (measured on b375656e1).
BOT_EMAIL = 'github-actions[bot]@users.noreply.github.com'

#: Files a bot commit may touch and still be built under its parent's verdict.
#: These are what Conda Update ("Bumped build to N") and Create Release's
#: ``tag`` job ("Reset conda build number") commit. No test reads the committed
#: ``conda/build``; the #1814 and #1827 tests do read ``conda/requirements.txt``,
#: and a bot commit to it is still built under its parent's verdict.
#: Vendor Update's "Bumped version to N" commits are left out on purpose: every
#: one of them rewrites ``pcapkit/``, and e58618bdf's Unit Tests run
#: 36355214959 reported "12 failed" on each Python leg, where its parent
#: 70fa92010's run 36354135989 passed every job. ``conda/platform-pins.toml`` is
#: left out too, though a Conda Update commit that moves a platform pin touches
#: it (#1851): util/conda_vendor.py reads it on import, so every test of that
#: script does, and a moved pin changes what those tests expect of
#: ``conda/requirements.txt``.
BOT_MANAGED_PATHS = frozenset({'conda/build', 'conda/requirements.txt'})

#: A full commit sha, which is all ``head_sha`` ever holds for a push run.
_SHA = re.compile(r'^[0-9a-f]{40}$')

#: ``--exit-code``'s status for "not covered". Not 1, which is also what an
#: uncaught exception exits with, so a crash cannot be read as an answer.
NOT_COVERED = 3


class Decision(NamedTuple):
    """Whether the verdict covers ``HEAD``, and why, in one line for the log."""

    verified: bool
    reason: str


def _git(*args: 'str', cwd: 'Optional[str]' = None,
         check: bool = True) -> 'subprocess.CompletedProcess[str]':
    return subprocess.run(['git', *args], cwd=cwd, check=check,  # nosec B603 B607
                          capture_output=True, text=True)


def decide(verdict: 'str', head: 'str', cwd: 'Optional[str]' = None) -> 'Decision':
    """Whether the commit ``verdict`` (a full sha) covers ``head``, in ``cwd``'s repository."""
    if verdict == head:
        return Decision(True, f'Unit Tests verified {head}, the commit this run checked out.')

    if _git('cat-file', '-e', f'{verdict}^{{commit}}', cwd=cwd, check=False).returncode != 0:
        return Decision(False, f'Unit Tests verified {verdict}, which is not in the history '
                               f'fetched for {head}, so it is too far back to cover it.')
    if _git('merge-base', '--is-ancestor', verdict, head, cwd=cwd, check=False).returncode != 0:
        return Decision(False, f'Unit Tests verified {verdict}, which is not an ancestor of {head}.')

    commits = _git('rev-list', '--reverse', f'{verdict}..{head}', cwd=cwd).stdout.split()
    for commit in commits:
        # Only the newline goes: ``%P`` is empty for a parentless commit, which a
        # shallow checkout's boundary is, and ``strip()`` would take its tab too.
        parents, author, committer = _git('show', '-s', '--format=%P%x09%ae%x09%ce',
                                          commit, cwd=cwd).stdout.strip('\n').split('\t')
        if len(parents.split()) != 1:
            return Decision(False, f'{commit} after the verified {verdict} has '
                                   f'{len(parents.split())} parents.')
        if author != BOT_EMAIL or committer != BOT_EMAIL:
            return Decision(False, f'{commit} after the verified {verdict} was authored by '
                                   f'{author} and committed by {committer}, not by the bot.')
        paths = _git('diff-tree', '--no-commit-id', '--name-only', '-r', '-z', '--no-renames',
                     commit, cwd=cwd).stdout.split('\0')
        outside = sorted(path for path in paths if path and path not in BOT_MANAGED_PATHS)
        if outside:
            return Decision(False, f'bot commit {commit} after the verified {verdict} touches '
                                   f'{", ".join(outside)}, which is not bot-managed.')

    managed = ', '.join(sorted(BOT_MANAGED_PATHS))
    return Decision(True, f'Unit Tests verified {verdict}; the {len(commits)} commit(s) after it '
                          f'up to {head} are bot commits to {managed} only.')


def main(argv: 'Optional[list[str]]' = None) -> int:
    """Decide for the checkout in the working directory and report it."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--head', default='HEAD', metavar='REV',
                        help='the commit to decide for (default: HEAD)')
    parser.add_argument('--exit-code', action='store_true',
                        help=f'print the reason, write no output, and exit 0 when covered '
                             f'or {NOT_COVERED} when not')
    args = parser.parse_args(argv)

    verdict = os.environ.get('VERDICT_SHA', '')
    if _SHA.match(verdict) is None:
        print(f'::error title=No verdict to compare::VERDICT_SHA is {verdict!r}, not a commit sha')
        return 1
    resolved = _git('rev-parse', '--verify', '--quiet', f'{args.head}^{{commit}}', check=False)
    if resolved.returncode != 0:
        print(f'::error title=No commit to compare::{args.head!r} is not a commit in this checkout')
        return 1
    head = resolved.stdout.strip()

    decision = decide(verdict, head)
    if args.exit_code:
        print(decision.reason)
        return 0 if decision.verified else NOT_COVERED
    if decision.verified:
        print(decision.reason)
    else:
        print(f'::notice title=Skipped as the verdict is for another commit::{decision.reason} '
              f'{head} gets its own Unit Tests run, which triggers this workflow again.')

    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as file:
            print(f'verified={str(decision.verified).lower()}', file=file)
    return 0


if __name__ == '__main__':
    sys.exit(main())
