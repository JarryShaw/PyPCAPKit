# -*- coding: utf-8 -*-
"""Set each issue's and pull request's release milestone (#2218).

This is the script :file:`.github/workflows/milestone.yml` runs. :func:`action_for`
is the only place the rule is written in code:

* an open item, a merged pull request, or an issue closed as completed gets the
  open milestone titled after the checked-out ``pcapkit.__version__``,
  ``PyPCAPKit v<major>.<minor>`` (:func:`milestone_title`);
* a pull request closed unmerged, or an issue closed as not planned or as a
  duplicate, loses any milestone it has, whichever that is;
* an issue closed with no reason recorded is left as it is.

A milestone is only ever given to an item that has none (:func:`apply`): one that
already holds a different milestone, such as a later release set by hand, keeps it.

The version is read from :file:`pcapkit/__init__.py` as text (:func:`read_version`),
so nothing from :mod:`pcapkit` is imported or run. Where the milestone for that
version is missing or closed, an item that would get it is left alone and a
``::warning::`` says so: creating the next milestone is a release step, done by
hand.

It runs in one of these modes:

* ``--item N`` -- one issue or pull request, for an ``issues`` or
  ``pull_request_target`` ``opened``, ``reopened`` or ``closed`` event. Its state
  is re-read through the API rather than taken from the event payload, so a run
  applies the rule to the item as it stands when the run starts.
* ``--backfill`` -- every item, open or closed, with no milestone whose number is
  above the highest-numbered item of the previous release's milestone
  (:func:`backfill_bound`), for ``workflow_dispatch``. Items at or below that
  bound belong to releases already made, and the ones among them without a
  milestone were left without one on purpose.

Updates are sent :data:`WRITE_INTERVAL` apart, under GitHub's secondary rate
limit on content-creating requests, and a request refused for a rate limit is
retried after the wait GitHub asks for (:func:`retrying`).

``--dry-run`` reports what would change and changes nothing; it still reads, so it
needs ``GH_TOKEN``. Standard library and the :program:`gh` CLI only, because the
workflow runs it with the runner's own ``python3`` and installs nothing. Its
annotations go through :file:`util/_actions.py`, which the workflow checks out
beside it.

"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
# The gh CLI, with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
import time
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, or from beside util/_actions.py, with its directory on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    #: Runs one REST request, ``(method, path, body)``, and returns its decoded JSON.
    Rest = Callable[[str, str, Optional[dict[str, Any]]], Any]

#: The milestone a version's items get, by its major and minor numbers.
TITLE = 'PyPCAPKit v{major}.{minor}'
#: The prefix of every release milestone's title.
PREFIX = 'PyPCAPKit v'
#: A version's leading release numbers, as :func:`release` reads them.
RELEASE = re.compile(r'(?P<major>\d+)\.(?P<minor>\d+)')
#: The file :func:`read_version` reads, relative to the checkout.
VERSION_FILE = os.path.join('pcapkit', '__init__.py')
#: The annotation title.
ANNOTATION = 'Milestone'
#: Items per page of a REST listing; the most GitHub serves.
PER_PAGE = 100
#: Seconds between two updates. GitHub's secondary rate limit allows about 80
#: content-creating requests a minute, which a backfill's updates back to back
#: would pass.
WRITE_INTERVAL = 1.0
#: How many times a rate-limited request is retried before the run fails.
RETRIES = 3
#: Seconds before the first retry where GitHub sends no ``Retry-After``; each
#: retry after it waits twice as long. GitHub asks for at least a minute.
BACKOFF = 60.0

#: :func:`action_for`'s answers.
SET = 'set'
REMOVE = 'remove'
#: The issue closing reasons that remove a milestone.
NOT_PLANNED = frozenset({'not_planned', 'duplicate'})


def read_version(path: 'str' = VERSION_FILE) -> 'str':
    """The string assigned to ``__version__`` at the top level of the file ``path``.

    Parsed rather than imported, so the checkout's code never runs.

    """
    with open(path, encoding='utf-8') as file:
        tree = ast.parse(file.read(), filename=path)
    for node in tree.body:
        if (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '__version__'
                                                 for target in node.targets)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            return node.value.value
    raise ValueError(f'{path} assigns no string to __version__')


def release(version: 'str') -> 'tuple[int, int]':
    """The major and minor numbers of ``version``, a PEP 440 version string."""
    match = RELEASE.match(version)
    if match is None:
        raise ValueError(f'{version!r} has no major.minor release')
    return int(match.group('major')), int(match.group('minor'))


def milestone_title(version: 'str') -> 'str':
    """The milestone a ``version``'s items get: ``1.5.0b14`` gives ``PyPCAPKit v1.5``."""
    major, minor = release(version)
    return TITLE.format(major=major, minor=minor)


def title_release(title: 'str') -> 'Optional[tuple[int, int]]':
    """The release a milestone ``title`` names, or :data:`None` for one that names none."""
    if not title.startswith(PREFIX) or RELEASE.fullmatch(title[len(PREFIX):]) is None:
        return None
    return release(title[len(PREFIX):])


def action_for(item: 'dict[str, Any]') -> 'Optional[str]':
    """:data:`SET`, :data:`REMOVE` or :data:`None`, for an issue as the REST API returns it.

    A pull request is an issue there with a ``pull_request`` member, whose
    ``merged_at`` is set once it merged.

    """
    if item.get('state') == 'open':
        return SET
    if item.get('state') != 'closed':
        return None
    pull_request = item.get('pull_request')
    if pull_request is not None:
        return SET if pull_request.get('merged_at') else REMOVE
    reason = item.get('state_reason')
    if reason == 'completed':
        return SET
    if reason in NOT_PLANNED:
        return REMOVE
    return None


class RateLimited(RuntimeError):
    """A request GitHub refused for its rate limit, and how long it asked to wait, if it said."""

    def __init__(self, message: 'str', retry_after: 'Optional[float]' = None) -> 'None':
        super().__init__(message)
        self.retry_after = retry_after


def split_response(text: 'str') -> 'tuple[int, dict[str, str], str]':
    """The status, headers (lower-cased names) and body of a response ``gh api --include`` printed."""
    status = re.match(r'HTTP/\S+ (\d{3})', text)
    end = re.search(r'\r?\n\r?\n', text)
    if status is None or end is None:
        return 0, {}, text
    lines, body = text[:end.start()].splitlines(), text[end.end():]
    headers = {}  # type: dict[str, str]
    for line in lines[1:]:
        name, sep, value = line.partition(':')
        if sep:
            headers[name.strip().lower()] = value.strip()
    return int(status.group(1)), headers, body


def rate_limited(status: 'int', headers: 'dict[str, str]', body: 'str') -> 'bool':
    """Whether a response is GitHub's rate limit, primary or secondary, rather than a refusal."""
    if status not in (403, 429):
        return False
    return ('retry-after' in headers or headers.get('x-ratelimit-remaining') == '0'
            or 'rate limit' in body.lower())


def gh_rest(method: 'str', path: 'str', body: 'Optional[dict[str, Any]]' = None) -> 'Any':
    """Run one request through ``gh api`` and return its decoded JSON.

    The response's headers are asked for (``--include``), which :program:`gh`
    prints on a failure too, so a rate limit raises :exc:`RateLimited` with its
    ``Retry-After``, and any other failure :exc:`RuntimeError`.

    """
    command = ['gh', 'api', '--include', '-X', method, path]
    if body is not None:
        command += ['--input', '-']
    proc = subprocess.run(command, input=None if body is None else json.dumps(body),  # nosec B603 B607
                          capture_output=True, text=True, check=False)
    status, headers, text = split_response(proc.stdout)
    if proc.returncode != 0:
        message = f'gh api {method} {path} failed ({proc.returncode}): {proc.stderr.strip()}'
        if rate_limited(status, headers, text):
            after = headers.get('retry-after', '')
            raise RateLimited(message, float(after) if after.isdigit() else None)
        raise RuntimeError(message)
    return json.loads(text) if text.strip() else None


def retrying(rest: 'Rest', sleep: 'Callable[[float], object]' = time.sleep) -> 'Rest':
    """``rest``, retrying a rate-limited request up to :data:`RETRIES` times.

    Each retry waits what ``Retry-After`` asked for, or :data:`BACKOFF` seconds
    doubled for each retry before it; the last refusal is raised.

    """
    def request(method: 'str', path: 'str', body: 'Optional[dict[str, Any]]' = None) -> 'Any':
        for attempt in range(RETRIES + 1):
            try:
                return rest(method, path, body)
            except RateLimited as error:
                if attempt == RETRIES:
                    raise
                wait = error.retry_after if error.retry_after is not None else BACKOFF * 2 ** attempt
                print(f'{method} {path} was rate-limited; retrying in {wait:g}s', flush=True)
                sleep(wait)
        raise AssertionError('unreachable')  # pragma: no cover
    return request


def pages(rest: 'Rest', path: 'str') -> 'Any':
    """Each item of a REST listing at ``path``, which already holds a query, page by page."""
    page = 1
    while True:
        batch = rest('GET', f'{path}&per_page={PER_PAGE}&page={page}', None)
        yield from batch
        if len(batch) < PER_PAGE:
            return
        page += 1


def milestones(rest: 'Rest', repo: 'str') -> 'list[dict[str, Any]]':
    """Every milestone of ``repo``, open and closed."""
    return list(pages(rest, f'repos/{repo}/milestones?state=all'))


def find_open(found: 'list[dict[str, Any]]', title: 'str') -> 'Optional[dict[str, Any]]':
    """The open milestone titled ``title`` among ``found``, if there is one."""
    return next((entry for entry in found if entry['title'] == title and entry['state'] == 'open'), None)


def backfill_bound(rest: 'Rest', repo: 'str', found: 'list[dict[str, Any]]',
                   target: 'tuple[int, int]') -> 'Optional[int]':
    """The highest item number in the latest release milestone before ``target``.

    :data:`None` where no earlier release has a milestone, since then nothing tells
    the current release's items from older ones.

    """
    earlier = [(number, entry) for entry in found
               for number in [title_release(entry['title'])] if number is not None and number < target]
    if not earlier:
        return None
    _, previous = max(earlier, key=lambda pair: pair[0])
    newest = rest('GET', f'repos/{repo}/issues?milestone={previous["number"]}&state=all'
                         '&sort=created&direction=desc&per_page=1', None)
    return newest[0]['number'] if newest else 0


def unmilestoned(rest: 'Rest', repo: 'str', above: 'int') -> 'list[dict[str, Any]]':
    """Every issue and pull request, open or closed, with no milestone and a number above ``above``.

    Listed newest first, so the listing stops at the first page that reaches
    ``above``; numbers rise with creation, which is the order it is sorted in.

    """
    items = []  # type: list[dict[str, Any]]
    for item in pages(rest, f'repos/{repo}/issues?state=all&milestone=none&sort=created&direction=desc'):
        if item['number'] <= above:
            break
        items.append(item)
    return sorted(items, key=lambda item: item['number'])


def apply(rest: 'Rest', repo: 'str', item: 'dict[str, Any]', action: 'Optional[str]',
          milestone: 'Optional[dict[str, Any]]', *, dry_run: 'bool',
          throttle: 'Callable[[], object]' = lambda: None) -> 'Optional[str]':
    """Bring one item's milestone in line with ``action``; the line to print if it changed.

    ``milestone`` is the one :data:`SET` gives; :data:`REMOVE` does not need it.
    :data:`SET` gives it only to an item with none, and leaves one holding another
    milestone as it is; :data:`REMOVE` takes away whichever it holds. ``throttle``
    is called before the update is sent.

    """
    current = item.get('milestone')
    if action == SET and milestone is not None:
        if current is not None:
            if current['number'] != milestone['number']:
                print(f'#{item["number"]}: keeps milestone {current["title"]!r}')
            return None
        value, line = milestone['number'], f'set milestone to {milestone["title"]!r}'
    elif action == REMOVE:
        if current is None:
            return None
        value, line = None, f'remove milestone {current["title"]!r}'
    else:
        return None
    if not dry_run:
        throttle()
        rest('PATCH', f'repos/{repo}/issues/{item["number"]}', {'milestone': value})
    return f'#{item["number"]}: {"would " if dry_run else ""}{line}'


def main(argv: 'Optional[list[str]]' = None, rest: 'Rest' = gh_rest,
         sleep: 'Callable[[float], object]' = time.sleep) -> 'int':
    """Entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--item', type=int, help='apply the rule to one issue or pull request')
    mode.add_argument('--backfill', action='store_true',
                      help="apply the rule to every item without a milestone since the previous release's")
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY', 'JarryShaw/PyPCAPKit'))
    parser.add_argument('--version-file', default=VERSION_FILE, help='the file holding __version__')
    parser.add_argument('--dry-run', action='store_true',
                        help='report changes without making them (still reads, so needs GH_TOKEN)')
    args = parser.parse_args(argv)
    rest = retrying(rest, sleep)

    version = read_version(args.version_file)
    title = milestone_title(version)
    if args.item is not None:
        items = [rest('GET', f'repos/{args.repo}/issues/{args.item}', None)]
        actions = [action_for(items[0])]
        found = milestones(rest, args.repo) if SET in actions else []
    else:
        found = milestones(rest, args.repo)
        bound = backfill_bound(rest, args.repo, found, release(version))
        if bound is None:
            _actions.annotate('warning', f'no release milestone before {title!r}, so nothing bounds the '
                              'backfill; no item was changed.', title=ANNOTATION)
            return 0
        print(f'backfilling items above #{bound} without a milestone')
        items = unmilestoned(rest, args.repo, bound)
        actions = [action_for(item) for item in items]

    milestone = find_open(found, title)
    if milestone is None and SET in actions:
        _actions.annotate('warning', f'no open milestone is titled {title!r}, so no item was given one; '
                          'create it by hand.', title=ANNOTATION)

    wrote = False

    def throttle() -> 'None':
        # WRITE_INTERVAL between one update and the next, none before the first.
        nonlocal wrote
        if wrote:
            sleep(WRITE_INTERVAL)
        wrote = True

    changed = 0
    for item, action in zip(items, actions):
        line = apply(rest, args.repo, item, action, milestone, dry_run=args.dry_run, throttle=throttle)
        if line is not None:
            changed += 1
            print(line)
    print(f'{changed} of {len(items)} item(s) changed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
