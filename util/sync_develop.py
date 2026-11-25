# -*- coding: utf-8 -*-
"""Propose merging ``main`` into ``develop`` while ``develop`` lacks commits of ``main`` (#2942).

``main`` is the released line and ``develop`` carries the next minor, so a fix
merged to ``main`` reaches ``develop`` through a pull request from ``main`` into
``develop``. :file:`.github/workflows/sync-develop.yml` runs this script on every
push to ``main`` and on dispatch, from the checkout's root and on the runner's
``python3``:

* ``--check``, in the ``check`` job with a read-only ``GITHUB_TOKEN``, writes
  ``behind`` to ``$GITHUB_OUTPUT``: ``true`` where :data:`BASE` exists and
  ``GET /repos/{repo}/compare/develop...main`` gives an ``ahead_by`` above 0,
  ``false`` where it is level or does not exist yet, the latter with a notice.
* ``--propose``, in the ``pr`` job with the release App's token, checks again, then
  updates the title and body of the open pull request from this repository's
  :data:`HEAD` into :data:`BASE` where there is one, and opens it otherwise, so
  there is never a second. Its head is ``main`` itself, so it follows every push.

A pull request opened with ``GITHUB_TOKEN`` starts no workflow, so the App's token
opens this one, and its checks run. The script merges, pushes and force-pushes
nothing: the owner merges the pull request, with a merge commit, so ``develop``
keeps ``main``'s history. A read that fails warns under ``--check`` and fails
under ``--propose``. Standard library and the :program:`gh` CLI only, with
``GH_TOKEN`` in the environment.

"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
# The gh CLI, with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Optional

#: The checkout the script reads the pull request template from.
ROOT = pathlib.Path(__file__).resolve().parents[1]
#: The repository, unless ``$GITHUB_REPOSITORY`` names one.
REPO = 'JarryShaw/PyPCAPKit'
#: The branch merged, and the one it merges into.
HEAD, BASE = 'main', 'develop'
#: The pull request's title, which its commit type follows.
TITLE = f'chore: merge {HEAD} into {BASE}'
#: The repository's pull request template, which the body fills in.
TEMPLATE = ROOT / '.github' / 'PULL_REQUEST_TEMPLATE.md'
#: What :program:`gh api` prints for a branch that does not exist.
NOT_FOUND = '(HTTP 404)'


class ApiError(RuntimeError):
    """:program:`gh api` gave no usable answer."""


def run(*argv: 'str') -> 'subprocess.CompletedProcess[str]':
    """``argv``, its status returned rather than raised."""
    return subprocess.run(list(argv), capture_output=True, text=True, check=False)  # nosec B603 B607


def api(*argv: 'str') -> 'str':
    """``gh api`` with ``argv``; its output, or :exc:`ApiError`."""
    proc = run('gh', 'api', *argv)
    if proc.returncode:
        raise ApiError(f'gh api {argv[-1]} failed ({proc.returncode}): {proc.stderr.strip()}')
    return proc.stdout


def behind(repo: 'str') -> 'Optional[int]':
    """How many commits of :data:`HEAD` :data:`BASE` lacks, or :data:`None` where it does not exist."""
    proc = run('gh', 'api', f'repos/{repo}/branches/{BASE}', '--jq', '.name')
    if proc.returncode:
        if NOT_FOUND in proc.stderr:
            return None
        raise ApiError(f'gh api repos/{repo}/branches/{BASE} failed ({proc.returncode}): {proc.stderr.strip()}')
    return int(api(f'repos/{repo}/compare/{BASE}...{HEAD}', '--jq', '.ahead_by').strip())


def open_pull_request(repo: 'str') -> 'Optional[int]':
    """The open pull request from ``repo``'s own :data:`HEAD` into :data:`BASE`, by number."""
    owner = repo.split('/', 1)[0]
    numbers = api(f'repos/{repo}/pulls?state=open&head={owner}:{HEAD}&base={BASE}', '--jq', '.[].number').split()
    return int(numbers[0]) if numbers else None


def body(count: 'int', sha: 'str', run_url: 'str') -> 'str':
    """The pull request template, ``chore`` ticked, filled in for this merge."""
    text = TEMPLATE.read_text(encoding='utf-8')
    text = re.sub(r'(?m)^- \[ \] `chore`', '- [x] `chore`', text)
    text = re.sub(r'(?m)^(- \[ \] `make test` passes.*)$', r"\1 -- not run here; this pull request's checks run it",
                  text)
    # The changelog box, found by its link rather than by the wording around it.
    text = re.sub(r'(?m)^(- \[ \] .*\[changelog entry\].*)$', r'\1: N/A — centralised', text)
    at = f' at `{sha[:9]}`' if re.fullmatch(r'[0-9a-f]{40}', sha) else ''
    description = (f'Merges `{HEAD}`{at} into `{BASE}`, which lacks {count} of its commits (#2942). '
                   f'**Merge with a merge commit, not a squash**, so `{BASE}` keeps `{HEAD}`\'s history and the '
                   f'next run finds it level. The head is `{HEAD}` itself, so this pull request follows every '
                   f'push there; edit `{HEAD}`, not this pull request. Opened by the Sync Develop workflow'
                   + (f' ({run_url})' if run_url else '') + '.')
    placeholder = re.search(r'(?m)^&emsp; Explanation of your \*pull request\*.*$', text)
    if placeholder is None:
        return text.rstrip('\n') + '\n\n' + description + '\n'
    return text[:placeholder.start()] + description + text[placeholder.end():].rstrip('\n') + '\n'


def check(repo: 'str') -> 'bool':
    """Whether :data:`BASE` lacks commits of :data:`HEAD`, saying why not where it does not."""
    count = behind(repo)
    if count is None:
        _actions.annotate('notice', f'{repo} has no {BASE} branch yet, so there is nothing to merge {HEAD} into.',
                          title=f'No {BASE} branch')
        return False
    print(f'{BASE} lacks {count} commit(s) of {HEAD}', flush=True)
    return count > 0


def propose(repo: 'str', sha: 'str', run_url: 'str') -> 'int':
    """Open the pull request from :data:`HEAD` into :data:`BASE`, or update the open one."""
    count = behind(repo)
    if not count:
        print(f'{BASE} is level with {HEAD} or does not exist; nothing to propose', flush=True)
        return 0
    text = body(count, sha, run_url)
    number = open_pull_request(repo)
    if number is not None:
        api('-X', 'PATCH', f'repos/{repo}/pulls/{number}', '-f', f'title={TITLE}', '-f', f'body={text}',
            '--jq', '.number')
        print(f'updated pull request #{number}', flush=True)
        return 0
    created = json.loads(api('-X', 'POST', f'repos/{repo}/pulls', '-f', f'title={TITLE}', '-f', f'head={HEAD}',
                             '-f', f'base={BASE}', '-f', f'body={text}', '--jq', '{number, html_url}'))
    print(f'opened pull request #{created["number"]}: {created["html_url"]}', flush=True)
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=f'Propose merging {HEAD} into {BASE} while {BASE} lacks '
                                                 f'commits of {HEAD}.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='write behind=true|false to $GITHUB_OUTPUT')
    mode.add_argument('--propose', action='store_true', help='open the pull request, or update the open one')
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY') or REPO,
                        help=f'repository (default: $GITHUB_REPOSITORY, else {REPO})')
    parser.add_argument('--sha', default='', help=f'the {HEAD} commit to name in the body')
    parser.add_argument('--run-url', default='', help='the run to name in the body')
    args = parser.parse_args(argv)
    if args.propose:
        try:
            return propose(args.repo, args.sha, args.run_url)
        except (ApiError, ValueError) as error:
            _actions.annotate('error', str(error), title='No pull request')
            return 1
    try:
        decided = check(args.repo)
    except (ApiError, ValueError) as error:
        _actions.annotate('warning', f'{error}; nothing is proposed this run.', title=f'{BASE} not compared')
        decided = False
    _actions.set_output('behind', str(decided).lower())
    return 0


if __name__ == '__main__':
    sys.exit(main())
