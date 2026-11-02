# -*- coding: utf-8 -*-
"""Regenerate the issue and pull request kinds the #1103 roles test reads.

:file:`tests/project/test_docs_issue_pr_roles_1103_unit.py` checks that each
``:issue:`` and ``:pr:`` role in rendered text names what its number is, against
:file:`tests/project/issue_pr_roles_fixtures/kinds.json`. That file maps the role
each issue and pull request of this repository takes to their numbers, and the
test skips a number above its highest. This script rewrites it from the tracker,
read with ``gh api --paginate``, so a role citing such a number is checked after
one run from the repository root::

    python util/issue_pr_kinds.py

:file:`.github/workflows/cron-issue-pr-kinds.yml` runs it weekly (#2561):
``--github-output`` writes ``publish``, whether the file changed and the open
pull request from :data:`BRANCH` does not already hold it, and ``--publish FILE``
commits that file on :data:`BRANCH`, force-pushes the branch and opens its pull
request if none is open, so ``main`` is never pushed. Standard library and the
:program:`gh` CLI only; it needs :program:`gh` signed in, or ``GH_TOKEN``.

"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
# The gh and git CLIs, with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

#: The checkout the script reads and writes.
ROOT = pathlib.Path(__file__).resolve().parents[1]
#: The repository whose tracker is read, unless ``$GITHUB_REPOSITORY`` names one.
REPO = 'JarryShaw/PyPCAPKit'
#: The file written, as git and the contents API name it.
PATH = 'tests/project/issue_pr_roles_fixtures/kinds.json'
#: The file written, beside the test that reads it.
OUTPUT = ROOT / PATH
#: The roles, in the order the file lists them.
ROLES = ('issue', 'pr')
#: Numbers per line of the file. A new number is the highest, so a refresh rewrites
#: only the last lines of each role.
PER_LINE = 15
#: Each item of a page as ``<number>\t<role>``; an item is a pull request when it
#: carries ``pull_request``.
JQ = '.[] | [.number, (if .pull_request then "pr" else "issue" end)] | @tsv'
#: The branch the workflow proposes a refresh on, and the one it targets.
BRANCH = 'bot/issue-pr-kinds'
BASE = 'main'
#: The commit's subject and the pull request's title.
TITLE = 'test: refresh the issue and pull request kinds'
#: The repository's pull request template, which the body fills in.
TEMPLATE = ROOT / '.github' / 'PULL_REQUEST_TEMPLATE.md'
#: What a push says when moving the branch would change a workflow file, which
#: the App's token has no permission to do.
WORKFLOWS_REFUSAL = 'without `workflows` permission'


def run(*argv: 'str', check: 'bool' = True) -> 'subprocess.CompletedProcess[str]':
    """``argv`` in :data:`ROOT`; a failure raises :exc:`RuntimeError` unless ``check`` is false."""
    proc = subprocess.run(list(argv), cwd=ROOT, capture_output=True, text=True, check=False)  # nosec B603 B607
    if check and proc.returncode != 0:
        raise RuntimeError(f'{argv[0]} {argv[1]} failed ({proc.returncode}): {proc.stderr.strip()}')
    return proc


def fetch(repo: 'str' = REPO) -> 'dict[int, str]':
    """Every issue and pull request number of ``repo``, mapped to its role."""
    proc = run('gh', 'api', '--paginate', f'repos/{repo}/issues?state=all&per_page=100', '--jq', JQ)
    kinds = {}
    for line in proc.stdout.splitlines():
        number, role = line.split('\t')
        kinds[int(number)] = role
    if not kinds:
        raise RuntimeError(f'gh api returned no issue or pull request of {repo}')
    return kinds


def render(kinds: 'dict[int, str]') -> 'str':
    """``kinds`` as the file's JSON: each role's sorted numbers, :data:`PER_LINE` a line."""
    blocks = []
    for role in ROLES:
        numbers = sorted(number for number, kind in kinds.items() if kind == role)
        rows = [', '.join(map(str, numbers[i:i + PER_LINE])) for i in range(0, len(numbers), PER_LINE)]
        lines = ',\n'.join(f'    {row}' for row in rows)
        blocks.append(f'  "{role}": [\n{lines}\n  ]' if rows else f'  "{role}": []')
    return '{\n' + ',\n'.join(blocks) + '\n}\n'


def open_pull_request(repo: 'str') -> 'Optional[str]':
    """The open pull request from ``repo``'s own :data:`BRANCH` into :data:`BASE`, by number."""
    numbers = run('gh', 'pr', 'list', '--repo', repo, '--head', BRANCH, '--base', BASE, '--state', 'open',
                  '--json', 'number,isCrossRepository',
                  '--jq', '.[] | select(.isCrossRepository | not) | .number').stdout.split()
    return numbers[0] if numbers else None


def should_publish(repo: 'str', text: 'str') -> 'bool':
    """Whether ``text``, written to :data:`PATH`, is a change the open pull request does not already hold."""
    if run('git', 'diff', '--quiet', '--', PATH, check=False).returncode == 0:
        return False
    if open_pull_request(repo) is None:
        return True
    held = run('gh', 'api', '-H', 'Accept: application/vnd.github.raw',
               f'repos/{repo}/contents/{PATH}?ref={BRANCH}', check=False)
    return held.returncode != 0 or held.stdout != text


def body(kinds_text: 'str', run_url: 'str') -> 'str':
    """The pull request template, ``test`` ticked, filled in for a refresh."""
    newest = max(number for numbers in json.loads(kinds_text).values() for number in numbers)
    text = TEMPLATE.read_text(encoding='utf-8')
    text = re.sub(r'(?m)^- \[ \] `test`', '- [x] `test`', text)
    text = re.sub(r'(?m)^(- \[ \] `make test` passes.*)$', r"\1 -- not run here; this pull request's checks run it",
                  text)
    text = re.sub(r'(?m)^(- \[ \] Added a \[changelog entry\].*)$', r'\1 — N/A — centralised in #657', text)
    description = (f'Regenerated `{PATH}` from the tracker with `python util/issue_pr_kinds.py`, up to #{newest}, '
                   'so `tests/project/test_docs_issue_pr_roles_1103_unit.py` checks every role citing a number '
                   f'up to it. Opened by the Issue and PR Kinds workflow ({run_url}); a later run force-pushes '
                   'this branch, so edit `main` rather than this branch.')
    placeholder = re.search(r'(?m)^&emsp; Explanation of your \*pull request\*.*$', text)
    if placeholder is None:
        return text.rstrip('\n') + '\n\n' + description + '\n'
    return text[:placeholder.start()] + description + text[placeholder.end():].rstrip('\n') + '\n'


def push(lease: 'str') -> 'subprocess.CompletedProcess[str]':
    """``HEAD`` to ``origin``'s :data:`BRANCH`, if that is still at ``lease`` (``''``: absent)."""
    return run('git', 'push', f'--force-with-lease=refs/heads/{BRANCH}:{lease}', 'origin',
               f'HEAD:refs/heads/{BRANCH}', check=False)


def publish(repo: 'str', source: 'pathlib.Path', run_url: 'str') -> 'int':
    """Commit ``source`` as :data:`PATH` on :data:`BRANCH`, push it, and open its pull request if none is."""
    slug = os.environ.get('APP_SLUG', '')
    if not re.fullmatch(r'[\w-]+', slug):
        raise ValueError(f'APP_SLUG {slug!r} is not an App slug')
    bot_id = os.environ.get('APP_BOT_ID', '')
    email = f'{bot_id}+{slug}[bot]@users.noreply.github.com' if bot_id.isdigit() else \
        f'{slug}[bot]@users.noreply.github.com'
    text = source.read_text(encoding='utf-8')
    OUTPUT.write_text(text, encoding='utf-8')
    run('git', 'add', '--', PATH)
    if run('git', 'diff', '--cached', '--quiet', check=False).returncode == 0:
        print(f'{PATH} is already as proposed; nothing to push')
        return 0
    run('git', '-c', f'user.name={slug}[bot]', '-c', f'user.email={email}', 'commit', '--quiet', '-m', TITLE)

    listed = run('git', 'ls-remote', '--heads', 'origin', f'refs/heads/{BRANCH}').stdout.split()
    lease = listed[0] if listed else ''
    pushed = push(lease)
    if pushed.returncode and lease and WORKFLOWS_REFUSAL in pushed.stderr:
        # main changed a workflow file since the branch was cut; a new branch moves none.
        print(f'recreating {BRANCH}, which this token cannot move past a workflow change; its pull request closes')
        run('git', 'push', f'--force-with-lease=refs/heads/{BRANCH}:{lease}', 'origin', f':refs/heads/{BRANCH}')
        pushed = push('')
    if pushed.returncode:
        raise RuntimeError(f'git push failed ({pushed.returncode}): {pushed.stderr.strip()}')

    number = open_pull_request(repo)
    if number is not None:
        print(f'updated pull request #{number}')
    else:
        url = run('gh', 'pr', 'create', '--repo', repo, '--base', BASE, '--head', BRANCH, '--title', TITLE,
                  '--body', body(text, run_url)).stdout.strip()
        print(f'opened {url}')
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description='Regenerate the issue and pull request kinds '
                                                 'the #1103 roles test reads.')
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY') or REPO,
                        help=f'repository to read (default: $GITHUB_REPOSITORY, else {REPO})')
    parser.add_argument('--output', type=pathlib.Path, default=OUTPUT, help='file to write')
    parser.add_argument('--github-output', action='store_true',
                        help='also write publish=true|false to $GITHUB_OUTPUT')
    parser.add_argument('--publish', type=pathlib.Path, metavar='FILE',
                        help=f'commit FILE on {BRANCH} and open or update its pull request; fetches nothing')
    parser.add_argument('--run-url', default='', help='the run to name in a pull request it opens')
    args = parser.parse_args(argv)
    if args.publish is not None:
        return publish(args.repo, args.publish, args.run_url)
    kinds = fetch(args.repo)
    text = render(kinds)
    args.output.write_text(text, encoding='utf-8')
    print(f'{args.output}: {len(kinds)} numbers, up to #{max(kinds)}')
    if args.github_output:
        decided = should_publish(args.repo, text)
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as file:
            file.write(f'publish={str(decided).lower()}\n')
        print(f'publish={str(decided).lower()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
