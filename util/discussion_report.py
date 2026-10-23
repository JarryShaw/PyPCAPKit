# -*- coding: utf-8 -*-
"""Post a run's report to its job's thread in a Discussions category (#2030).

The ``discussion`` job of :file:`.github/workflows/ci-timing.yml` and of
:file:`.github/workflows/cron-vendor.yml` runs, from the checkout's root and on
the runner's ``python3``::

    python3 util/discussion_report.py --category NAME --title TITLE --report FILE \\
        --mode scheduled|push --status STATUS

with ``GITHUB_REPOSITORY`` and ``GH_TOKEN`` in the environment. ``FILE`` is the
Markdown report the reporting job wrote, and ``STATUS``, one of :data:`STATUSES`,
how the run ended: a job's ``result``, or ``warning`` for a run that passed with
warnings. A report with no pull request to comment on goes here, whatever started
its run. One category holds every report, and each job has one thread in it,
found by its exact title, written ``<workflow file stem>: <job or report name>``,
as in ``ci-timing: weekly CI timing report``. So the script:

* resolves the repository's node id and the category's id by name, through
  ``gh api graphql``, so no id is written down anywhere;
* finds the thread titled ``TITLE`` in that category, the oldest where several
  share it, and opens it (``createDiscussion``) only where there is none;
* adds one comment (``addDiscussionComment``) holding the report, when the mode
  says to.

``--mode scheduled`` posts every run. ``--mode push`` is for a run on a push, or
a ``workflow_run`` relay of one: a run whose status is not ``success`` posts every
time, and a ``success`` posts only where the thread's newest status marker is not
``success``, so one "back to green" comment follows a bad run and later green
runs stay silent. A thread with no marker yet counts as ``success``, so a first
green push run posts nothing and opens no thread.

Each comment ends in a line naming the run, its commit and its status, then a
hidden marker, ``<!-- report-status: STATUS -->``. The marker is read from the
newest of the thread's last :data:`RECENT` comments that carries one, so a reply
in between is passed over. The run and the commit are this run's, from
``GITHUB_SERVER_URL``, ``GITHUB_REPOSITORY``, ``GITHUB_RUN_ID``,
``GITHUB_WORKFLOW`` and ``GITHUB_SHA``; a job posting a report another run wrote,
as a ``workflow_run`` relay does from that run's artifact, names that run with
``--run-url`` and ``--sha``. A report too long for a comment is cut to fit.

Reporting must never turn a run red. A missing category, a missing report, a
missing token, an API or permission failure, and anything else that goes wrong
each write one ``::warning`` and exit 0; only a malformed command line exits 2,
as :mod:`argparse` does. The script is standard library only, and reaches the API
only through :program:`gh`.

"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
# The gh CLI, with a fixed argument list and no shell.
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Any, Optional

__all__ = ['MARKER', 'RECENT', 'LIMIT', 'TITLE', 'STATUSES', 'MODES', 'ApiError', 'last_status', 'should_post',
           'provenance', 'compose', 'main']

#: The values ``--status`` takes: a job's ``result``, and ``warning``.
STATUSES = ('success', 'warning', 'failure', 'cancelled', 'skipped')
#: The values ``--mode`` takes.
MODES = ('scheduled', 'push')
#: The hidden marker each comment ends in, around the run's status.
MARKER = '<!-- report-status: {} -->'
#: The marker, read back from a comment's body.
MARKER_RE = re.compile(r'<!-- report-status: ({}) -->'.format('|'.join(STATUSES)))
#: How many of a thread's newest comments are searched for the last marker.
RECENT = 20
#: The longest body GitHub accepts for a discussion comment, in characters.
LIMIT = 65536
#: The title of every warning the script writes.
TITLE = 'CI report not posted'
#: How long one ``gh`` call may take, in seconds.
TIMEOUT = 120
#: How many pages of a category's threads are read before giving up.
MAX_PAGES = 50

REPOSITORY_QUERY = '''
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    id
    hasDiscussionsEnabled
    discussionCategories(first: 100) { nodes { id name } }
  }
}
'''
THREADS_QUERY = '''
query($owner: String!, $name: String!, $category: ID!, $after: String) {
  repository(owner: $owner, name: $name) {
    discussions(first: 100, after: $after, categoryId: $category,
                orderBy: {field: CREATED_AT, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes { id number title url }
    }
  }
}
'''
COMMENTS_QUERY = '''
query($id: ID!, $last: Int!) {
  node(id: $id) {
    ... on Discussion { comments(last: $last) { nodes { body url } } }
  }
}
'''
CREATE_MUTATION = '''
mutation($repository: ID!, $category: ID!, $title: String!, $body: String!) {
  createDiscussion(input: {repositoryId: $repository, categoryId: $category, title: $title, body: $body}) {
    discussion { id number url }
  }
}
'''
COMMENT_MUTATION = '''
mutation($discussion: ID!, $body: String!) {
  addDiscussionComment(input: {discussionId: $discussion, body: $body}) {
    comment { url }
  }
}
'''
#: The body of a new thread.
THREAD_BODY = ('Reports from the job this thread is named after, one comment per report. '
               'Posted by `util/discussion_report.py` (#2030).')


class ApiError(Exception):
    """A ``gh api graphql`` call that did not return data."""


def graphql(query: 'str', variables: 'dict[str, Any]') -> 'dict[str, Any]':
    """Run ``query`` through ``gh api graphql`` and return its ``data``."""
    body = json.dumps({'query': query, 'variables': variables})
    try:
        proc = subprocess.run(['gh', 'api', 'graphql', '--input', '-'],  # nosec: B603 B607
                              input=body, capture_output=True, text=True, check=False, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        raise ApiError(f'could not run gh: {error}') from error
    if proc.returncode != 0:
        raise ApiError(f'gh api graphql exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}')
    try:
        answer = json.loads(proc.stdout)
    except ValueError as error:
        raise ApiError(f'gh api graphql returned no JSON: {proc.stdout.strip()[:200]!r}') from error
    if not isinstance(answer, dict) or answer.get('errors') or not isinstance(answer.get('data'), dict):
        errors = answer.get('errors') if isinstance(answer, dict) else answer
        raise ApiError(f'gh api graphql returned errors: {json.dumps(errors)}')
    return answer['data']


def warn(message: 'str') -> 'int':
    """Write the one ``::warning`` of a report not posted; the exit status, 0."""
    _actions.annotate('warning', message, title=TITLE)
    return 0


def last_status(bodies: 'list[str]') -> 'str':
    """The status in the newest of ``bodies``, oldest first, that carries a marker; ``success`` if none does."""
    for body in reversed(bodies):
        found = MARKER_RE.findall(body or '')
        if found:
            return found[-1]
    return 'success'


def should_post(mode: 'str', status: 'str', previous: 'str') -> 'bool':
    """Whether a run in ``mode`` that ended ``status`` posts, after a last post that ended ``previous``."""
    if mode == 'scheduled':
        return True
    return status != 'success' or previous != 'success'


def provenance(env: 'dict[str, str]', status: 'str', run_url: 'str' = '', sha: 'str' = '') -> 'str':
    """The line naming the run, its commit and its ``status``, ``run_url`` and ``sha`` over this run's."""
    server, repo, run = (env.get(key, '') for key in ('GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID'))
    if not run_url and server and repo and run:
        run_url = f'{server}/{repo}/actions/runs/{run}'
    sha = sha or env.get('GITHUB_SHA', '')
    parts = []
    if run_url:
        parts.append(f'[{env.get("GITHUB_WORKFLOW") or "this"} run]({run_url})')
    if sha:
        parts.append(f'commit `{sha}`')
    if parts:
        return f'Posted from {" at ".join(parts)}, which ended `{status}`.'
    return f'The run ended `{status}`.'


def compose(report: 'str', line: 'str', status: 'str') -> 'str':
    """The comment for ``report``: the report, the provenance ``line`` and the marker, within :data:`LIMIT`."""
    footer = f'\n\n---\n{line}\n{MARKER.format(status)}'
    text = report.strip()
    room = LIMIT - len(footer)
    if len(text) > room:
        note = '\n\n*The report was cut short here to fit a comment; the run holds it whole.*'
        text = text[:max(room - len(note), 0)] + note
    return text + footer


def find_thread(owner: 'str', name: 'str', category: 'str', title: 'str') -> 'Optional[dict[str, Any]]':
    """The oldest thread in ``category`` titled exactly ``title``, if any."""
    after = None  # type: Optional[str]
    for _ in range(MAX_PAGES):
        page = graphql(THREADS_QUERY, {'owner': owner, 'name': name, 'category': category, 'after': after})
        threads = page['repository']['discussions']
        for node in threads['nodes'] or []:
            if node and node.get('title') == title:
                return node
        if not threads['pageInfo']['hasNextPage']:
            return None
        after = threads['pageInfo']['endCursor']
    raise ApiError(f'read {MAX_PAGES} pages of threads without reaching the end')


def post(category_name: 'str', title: 'str', report: 'str', env: 'dict[str, str]', *,
         mode: 'str', status: 'str', line: 'str') -> 'int':
    """Post ``report`` to the thread ``title`` in ``category_name`` if ``mode`` says to; the exit status."""
    owner, _, name = env['GITHUB_REPOSITORY'].partition('/')
    repo = f'{owner}/{name}'

    data = graphql(REPOSITORY_QUERY, {'owner': owner, 'name': name})['repository']
    if not data:
        return warn(f'{repo} could not be read, so the report was not posted.')
    if not data.get('hasDiscussionsEnabled'):
        return warn(f'{repo} has Discussions turned off, so the report was not posted.')
    categories = [node for node in data['discussionCategories']['nodes'] or [] if node]
    category = next((node for node in categories if node['name'] == category_name), None)
    if category is None:
        return warn(f'{repo} has no Discussions category named {category_name!r}, so the report was not '
                    'posted. A category can only be created by hand, in Settings > Discussions (#2030).')

    thread = find_thread(owner, name, category['id'], title)
    # Only a green push run depends on the last post; a thread with none counts as green.
    previous = 'success'
    if thread is not None and mode == 'push' and status == 'success':
        node = graphql(COMMENTS_QUERY, {'id': thread['id'], 'last': RECENT})['node'] or {}
        bodies = [comment.get('body') or '' for comment in (node.get('comments') or {}).get('nodes') or [] if comment]
        previous = last_status(bodies)
    if not should_post(mode, status, previous):
        print(f'A push run ended `{status}` after a last report that ended `{previous}`, so nothing was posted.',
              flush=True)
        return 0

    if thread is None:
        thread = graphql(CREATE_MUTATION, {'repository': data['id'], 'category': category['id'],
                                           'title': title, 'body': THREAD_BODY})['createDiscussion']['discussion']
        print(f'Opened the thread {title!r}: {thread["url"]}', flush=True)
    comment = graphql(COMMENT_MUTATION, {'discussion': thread['id'],
                                         'body': compose(report, line, status)})['addDiscussionComment']['comment']
    print(f'Posted the report: {comment["url"]}', flush=True)
    try:
        _actions.summary(f'The report was posted to [{title}]({comment["url"]}).', required=False, environ=env)
    except OSError:
        pass
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Read the arguments and the report, and post it; the exit status, 0 unless the arguments are bad."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--category', required=True, help='the Discussions category, by name')
    parser.add_argument('--title', required=True, help="the job's thread, by its exact title")
    parser.add_argument('--report', required=True, type=pathlib.Path, help='the Markdown report to post')
    parser.add_argument('--mode', required=True, choices=MODES, help='scheduled posts every run; push, see above')
    parser.add_argument('--status', required=True, choices=STATUSES, help='how the run ended')
    parser.add_argument('--run-url', default='', help='the run that wrote the report, where it is not this one')
    parser.add_argument('--sha', default='', help='the commit that run is for, where it is not GITHUB_SHA')
    args = parser.parse_args(argv)

    env = dict(os.environ)
    repo = env.get('GITHUB_REPOSITORY', '')
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', repo):
        return warn(f'GITHUB_REPOSITORY is {repo!r}, not OWNER/NAME, so the report was not posted.')
    if not env.get('GH_TOKEN'):
        return warn('GH_TOKEN is not set, so the report was not posted.')
    try:
        report = args.report.read_text(encoding='utf-8', errors='replace')
    except OSError as error:
        return warn(f'the report {str(args.report)!r} could not be read ({error.strerror or error}), '
                    'so nothing was posted.')
    if not report.strip():
        return warn(f'the report {str(args.report)!r} is empty, so nothing was posted.')

    try:
        return post(args.category, args.title, report, env, mode=args.mode, status=args.status,
                    line=provenance(env, args.status, args.run_url, args.sha))
    except ApiError as error:
        return warn(f'{error}. The report was not posted.')
    # Anything else is a bug here, which must not fail the run either.
    except Exception as error:  # pylint: disable=broad-except
        return warn(f'{type(error).__name__}: {error}. The report was not posted.')


if __name__ == '__main__':
    sys.exit(main())
