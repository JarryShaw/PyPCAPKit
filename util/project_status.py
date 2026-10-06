# -*- coding: utf-8 -*-
"""Set each item's *Status* on the project board from its state labels.

This is the script :file:`.github/workflows/project-status.yml` runs. The board's
built-in workflows see closes and merges but not label changes, so without this the
*Status* column follows the labels only when someone moves it by hand. The mapping
is the table under "Milestones and the Project Board" in
:file:`docs/source/contributing/conventions/process.rst`, and :func:`status_for`
is the only place it is written in code -- the tests parse that table and hold the
two to each other.

Two modes:

* ``--item N`` -- one issue or pull request, for an ``issues`` or
  ``pull_request_target`` event. Its labels and state are re-read through the API
  rather than taken from the event payload: several label events fire within a
  second of each other when a state label is swapped, and the payload of an
  earlier one is already stale by the time its run starts.
* ``--reconcile`` -- every open issue and pull request, plus anything closed in
  the last :data:`RECENT_DAYS` days, for the nightly backstop.

Standard library and the :program:`gh` CLI only, because the workflow runs it with
the runner's own ``python3`` and installs nothing. The token is ``GH_TOKEN``, which
:program:`gh` reads itself; without one the script emits a ``::notice::`` and exits
0, so a repository without the ``PROJECT_TOKEN`` secret skips rather than fails.

"""

from __future__ import annotations

import argparse
import datetime
import json
import os
# The gh CLI, with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, Iterable, Optional

    #: Runs one GraphQL document with its variables and returns ``data``.
    GraphQL = Callable[[str, dict[str, Any]], dict[str, Any]]

#: The board, by owner and number. Resolved to node ids at runtime.
OWNER = 'JarryShaw'
PROJECT_NUMBER = 2
#: The ids the board had when this was written. A resolved id that differs means
#: the board was recreated, and writing to it blind is the wrong default.
EXPECTED_PROJECT_ID = 'PVT_kwHOAO8M8c4Bl2gH'
EXPECTED_FIELD_ID = 'PVTSSF_lAHOAO8M8c4Bl2gHzhkhthA'
FIELD_NAME = 'Status'

#: How far back ``--reconcile`` looks at closed items, in days.
RECENT_DAYS = 7
#: GitHub's search returns at most this many results for one query, however many
#: match; ``issueCount`` still reports the full number.
SEARCH_LIMIT = 1000

DONE = 'Done'
NEEDS_DECISION = 'Needs decision'
BLOCKED = 'Blocked'
IN_REVIEW = 'In review'
WIP = 'WIP'
PENDING = 'Pending'

#: Every value :func:`status_for` can return. Each must be an option of the field.
STATUSES = (DONE, NEEDS_DECISION, BLOCKED, IN_REVIEW, WIP, PENDING)


def status_for(labels: 'Iterable[str]', *, closed: 'bool', pull_request: 'bool') -> 'str':
    """The *Status* an item should have, first match winning.

    Args:
        labels: The item's label names.
        closed: Whether the item is closed, or merged.
        pull_request: Whether the item is a pull request rather than an issue.

    """
    names = set(labels)
    if closed:
        return DONE
    if 'needs: decision' in names:
        return NEEDS_DECISION
    if 'blocked' in names:
        return BLOCKED
    if pull_request:
        return IN_REVIEW
    if 'wip' in names:
        return WIP
    return PENDING


def gh_graphql(query: 'str', variables: 'dict[str, Any]') -> 'dict[str, Any]':
    """Run ``query`` through ``gh api graphql`` and return its ``data``."""
    body = json.dumps({'query': query, 'variables': variables})
    proc = subprocess.run(['gh', 'api', 'graphql', '--input', '-'],  # nosec B603 B607
                          input=body, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f'gh api graphql failed ({proc.returncode}): {proc.stderr.strip()}')
    return json.loads(proc.stdout)['data']


_ITEM_FIELDS = '''
fragment Item on Node {
  __typename
  ... on Issue {
    id number state
    labels(first: 100) { nodes { name } }
    projectItems(first: 50) {
      nodes {
        id project { id }
        fieldValueByName(name: "Status") { ... on ProjectV2ItemFieldSingleSelectValue { optionId } }
      }
    }
  }
  ... on PullRequest {
    id number state
    labels(first: 100) { nodes { name } }
    projectItems(first: 50) {
      nodes {
        id project { id }
        fieldValueByName(name: "Status") { ... on ProjectV2ItemFieldSingleSelectValue { optionId } }
      }
    }
  }
}
'''

_PROJECT_QUERY = '''
query($owner: String!, $number: Int!) {
  user(login: $owner) { projectV2(number: $number) { id } }
}
'''

_FIELD_QUERY = '''
query($project: ID!, $field: String!) {
  node(id: $project) {
    ... on ProjectV2 {
      field(name: $field) { ... on ProjectV2SingleSelectField { id options { id name } } }
    }
  }
}
'''

_ONE_ITEM_QUERY = _ITEM_FIELDS + '''
query($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) { issueOrPullRequest(number: $number) { ...Item } }
}
'''

_SEARCH_QUERY = _ITEM_FIELDS + '''
query($q: String!, $after: String) {
  search(query: $q, type: ISSUE, first: 50, after: $after) {
    issueCount
    pageInfo { hasNextPage endCursor }
    nodes { ...Item }
  }
}
'''

_ADD_MUTATION = '''
mutation($project: ID!, $content: ID!) {
  addProjectV2ItemById(input: {projectId: $project, contentId: $content}) { item { id } }
}
'''

_SET_MUTATION = '''
mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item, fieldId: $field,
                                        value: {singleSelectOptionId: $option}}) {
    projectV2Item { id }
  }
}
'''


class Board:
    """The project, its *Status* field, and the option id of each status name."""

    def __init__(self, graphql: 'GraphQL', *, dry_run: 'bool' = False) -> None:
        self.graphql = graphql
        self.dry_run = dry_run

        user = graphql(_PROJECT_QUERY, {'owner': OWNER, 'number': PROJECT_NUMBER})['user']
        project = (user or {}).get('projectV2')
        if not project:
            raise RuntimeError(f'project {OWNER}/{PROJECT_NUMBER} not found or not readable')
        self.project_id = project['id']  # type: str
        if self.project_id != EXPECTED_PROJECT_ID:
            raise RuntimeError(f'project {OWNER}/{PROJECT_NUMBER} resolved to {self.project_id}, '
                               f'expected {EXPECTED_PROJECT_ID}: was the board recreated?')

        node = graphql(_FIELD_QUERY, {'project': self.project_id, 'field': FIELD_NAME})['node']
        field = (node or {}).get('field')
        if not field or 'options' not in field:
            raise RuntimeError(f'no single-select {FIELD_NAME!r} field on {self.project_id}')
        self.field_id = field['id']  # type: str
        if self.field_id != EXPECTED_FIELD_ID:
            raise RuntimeError(f'{FIELD_NAME!r} resolved to {self.field_id}, '
                               f'expected {EXPECTED_FIELD_ID}: was the field recreated?')
        self.options = {opt['name']: opt['id'] for opt in field['options']}  # type: dict[str, str]
        missing = [name for name in STATUSES if name not in self.options]
        if missing:
            raise RuntimeError(f'{FIELD_NAME!r} has no option named {", ".join(missing)}')

    def sync(self, item: 'dict[str, Any]') -> 'Optional[str]':
        """Bring one item's *Status* in line; return the new status if it changed."""
        kind = item['__typename']
        want = status_for((label['name'] for label in item['labels']['nodes']),
                          closed=item['state'] != 'OPEN',
                          pull_request=kind == 'PullRequest')
        option = self.options[want]

        entry = next((node for node in item['projectItems']['nodes']
                      if node['project']['id'] == self.project_id), None)
        if entry is not None and (entry.get('fieldValueByName') or {}).get('optionId') == option:
            return None
        item_id = None if entry is None else entry['id']  # type: Optional[str]
        if self.dry_run:
            return want

        # Idempotent: on an item already on the board it returns the existing id.
        if item_id is None:
            added = self.graphql(_ADD_MUTATION, {'project': self.project_id, 'content': item['id']})
            item_id = added['addProjectV2ItemById']['item']['id']
        self.graphql(_SET_MUTATION, {'project': self.project_id, 'item': item_id,
                                     'field': self.field_id, 'option': option})
        return want


def fetch_item(graphql: 'GraphQL', repo: 'str', number: 'int') -> 'dict[str, Any]':
    """One issue or pull request, read fresh."""
    owner, name = repo.split('/', 1)
    data = graphql(_ONE_ITEM_QUERY, {'owner': owner, 'repo': name, 'number': number})
    item = (data['repository'] or {}).get('issueOrPullRequest')
    if not item:
        raise RuntimeError(f'{repo}#{number} not found')
    return item


def search_items(graphql: 'GraphQL', query: 'str') -> 'list[dict[str, Any]]':
    """Every issue and pull request matching a search ``query``, all pages.

    Search stops at :data:`SEARCH_LIMIT` results, so a query matching more than that
    -- or returning fewer items than it reports matching -- is a partial reconcile.
    That is warned about rather than raised: syncing the items that did come back is
    still better than syncing none.

    """
    items = []  # type: list[dict[str, Any]]
    after = None  # type: Optional[str]
    total = 0
    while True:
        page = graphql(_SEARCH_QUERY, {'q': query, 'after': after})['search']
        total = max(total, page.get('issueCount') or 0)
        items.extend(node for node in page['nodes'] if node)
        if not page['pageInfo']['hasNextPage']:
            break
        after = page['pageInfo']['endCursor']
    if total > SEARCH_LIMIT or len(items) < total:
        print(f'::warning title=Project Status::search {query!r} matched {total} item(s) but '
              f'returned {len(items)}; this reconcile is partial (search caps at {SEARCH_LIMIT}).')
    return items


def reconcile_queries(repo: 'str', today: 'datetime.date') -> 'list[str]':
    """The searches ``--reconcile`` covers: open items, and recently closed ones."""
    since = today - datetime.timedelta(days=RECENT_DAYS)
    return [f'repo:{repo} is:open', f'repo:{repo} is:closed closed:>={since.isoformat()}']


def main(argv: 'Optional[list[str]]' = None, graphql: 'GraphQL' = gh_graphql,
         today: 'Optional[datetime.date]' = None) -> 'int':
    """Entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--item', type=int, help='sync one issue or pull request')
    mode.add_argument('--reconcile', action='store_true',
                      help=f'sync every open item and those closed in the last {RECENT_DAYS} days')
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY', 'JarryShaw/PyPCAPKit'))
    parser.add_argument('--dry-run', action='store_true',
                        help='report changes without making them (still reads, so needs GH_TOKEN)')
    args = parser.parse_args(argv)

    if not os.environ.get('GH_TOKEN'):
        print('::notice title=Project Status::GH_TOKEN is not set (the PROJECT_TOKEN secret is '
              'missing), so the project board was not updated.')
        return 0

    board = Board(graphql, dry_run=args.dry_run)
    if args.item is not None:
        items = [fetch_item(graphql, args.repo, args.item)]
    else:
        seen = {}  # type: dict[int, dict[str, Any]]
        for query in reconcile_queries(args.repo, today or datetime.date.today()):
            for item in search_items(graphql, query):
                seen.setdefault(item['number'], item)
        items = [seen[number] for number in sorted(seen)]

    changed = 0
    for item in items:
        new = board.sync(item)
        if new is not None:
            changed += 1
            verb = 'would set' if args.dry_run else 'set'
            print(f'#{item["number"]}: {verb} {FIELD_NAME} to {new!r}')
    print(f'{changed} of {len(items)} item(s) changed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
