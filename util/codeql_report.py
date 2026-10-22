# -*- coding: utf-8 -*-
"""Write CodeQL's run report: the repository's open code-scanning alerts, by severity (#2030).

The ``discussion`` job of :file:`.github/workflows/codeql-analysis.yml` runs, from
the checkout's root and on the runner's ``python3``::

    python3 util/codeql_report.py --result RESULT --report FILE

with ``GITHUB_REPOSITORY`` and ``GH_TOKEN``, a token holding
``security-events: read``, in the environment. ``RESULT`` is the ``analyze`` job's
``result``. The script reads every open alert CodeQL raised, through GitHub's
"List code scanning alerts for a repository" endpoint
(https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository),
``GET /repos/{owner}/{repo}/code-scanning/alerts`` with ``state=open`` and
``tool_name=CodeQL``, a page of 100 at a time through ``gh api --paginate``. With
no ``ref`` the endpoint answers for the default branch. It writes the Markdown
report to ``FILE`` and the run's status to the step output ``status``, which
:file:`util/discussion_report.py` takes as ``--status``: ``RESULT`` where
``analyze`` did not succeed, ``warning`` where it did and any alert is open, and
``success`` where none is. So a push run posts whenever an alert is open, and
once more on the first run back at none.

An alert's severity is its rule's ``security_severity_level`` (``critical``,
``high``, ``medium``, ``low``), which CodeQL's security queries carry, and
otherwise its rule's ``severity`` (``error``, ``warning``, ``note``, ``none``).

Where the alerts cannot be read, the script writes one ``::warning``, the report
says the alerts are unavailable, and the status is ``RESULT`` unchanged, since
nothing shows that none is open; it still exits 0, since reporting must never
turn a run red. The script is standard library only, and reaches the API only
through :program:`gh`.

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

__all__ = ['SEVERITIES', 'TITLE', 'ApiError', 'severity', 'decode', 'fetch', 'status', 'render', 'main']

#: The severities, most severe first: ``security_severity_level``'s, then ``severity``'s.
SEVERITIES = ('critical', 'high', 'medium', 'low', 'error', 'warning', 'note', 'none')
#: The title of the warning the script writes.
TITLE = 'CodeQL alerts not read'
#: How long the ``gh`` call may take, in seconds.
TIMEOUT = 300


class ApiError(Exception):
    """A ``gh api`` call that did not return the alerts."""


def severity(alert: 'dict[str, Any]') -> 'str':
    """The severity :data:`SEVERITIES` files ``alert`` under."""
    rule = alert.get('rule') or {}
    for value in (rule.get('security_severity_level'), rule.get('severity')):
        if value in SEVERITIES:
            return value
    return 'none'


def decode(text: 'str') -> 'list[dict[str, Any]]':
    """The alerts in ``gh api --paginate``'s output: one JSON array per page, or one array of them all."""
    decoder = json.JSONDecoder()
    alerts = []  # type: list[dict[str, Any]]
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return alerts
        try:
            page, index = decoder.raw_decode(text, index)
        except ValueError as error:
            raise ApiError(f'gh api returned no JSON: {text[index:index + 200]!r}') from error
        if not isinstance(page, list):
            raise ApiError(f'gh api returned {type(page).__name__}, not a list of alerts')
        alerts.extend(alert for alert in page if isinstance(alert, dict))


def fetch(repo: 'str') -> 'list[dict[str, Any]]':
    """Every open CodeQL alert of ``repo``, ``OWNER/NAME``."""
    command = ['gh', 'api', '--paginate', '--method', 'GET', f'repos/{repo}/code-scanning/alerts',
               '-f', 'state=open', '-f', 'tool_name=CodeQL', '-F', 'per_page=100']
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False,  # nosec: B603 B607
                              timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        raise ApiError(f'could not run gh: {error}') from error
    if proc.returncode != 0:
        raise ApiError(f'gh api exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}')
    return decode(proc.stdout)


def status(result: 'str', alerts: 'Optional[list[dict[str, Any]]]') -> 'str':
    """The ``--status`` of a run whose ``analyze`` ended ``result``, with ``alerts`` open, :data:`None` if unread."""
    if result != 'success' or alerts is None:
        return result
    return 'warning' if alerts else 'success'


def render(result: 'str', alerts: 'list[dict[str, Any]]') -> 'str':
    """The Markdown report of a run whose ``analyze`` ended ``result``, with ``alerts`` open."""
    counts = {name: 0 for name in SEVERITIES}
    for alert in alerts:
        counts[severity(alert)] += 1
    lines = ['### CodeQL', '', f'- Analysis: `{result}`', f'- Open code-scanning alerts: {len(alerts)}']
    if not alerts:
        return '\n'.join(lines + ['', 'No code-scanning alert is open.'])
    lines += ['', '| Severity | Open alerts |', '| --- | ---: |']
    lines += [f'| {name} | {count} |' for name, count in counts.items() if count]
    lines += ['']
    order = {name: index for index, name in enumerate(SEVERITIES)}
    for alert in sorted(alerts, key=lambda item: (order[severity(item)], item.get('number') or 0)):
        rule = (alert.get('rule') or {}).get('id') or 'unknown rule'
        location = ((alert.get('most_recent_instance') or {}).get('location') or {})
        where = location.get('path') or ''
        if where and location.get('start_line'):
            where += f':{location["start_line"]}'
        label = f'#{alert.get("number")}'
        if alert.get('html_url'):
            label = f'[{label}]({alert["html_url"]})'
        lines.append(f'- {label} `{rule}`' + (f' at `{where}`' if where else '') + f' ({severity(alert)})')
    return '\n'.join(lines)


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Read the alerts and write the report and ``status``; the exit status, 0 unless the arguments are bad."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--result', required=True, help="the analyze job's result")
    parser.add_argument('--report', required=True, type=pathlib.Path, help='the Markdown report to write')
    args = parser.parse_args(argv)

    repo = os.environ.get('GITHUB_REPOSITORY', '')
    alerts = None  # type: Optional[list[dict[str, Any]]]
    try:
        if not re.fullmatch(r'[\w.-]+/[\w.-]+', repo):
            raise ApiError(f'GITHUB_REPOSITORY is {repo!r}, not OWNER/NAME')
        alerts = fetch(repo)
    except ApiError as error:
        _actions.annotate('warning', f'{error}, so the report lists no alerts.', title=TITLE)
        report = '\n'.join(['### CodeQL', '', f'- Analysis: `{args.result}`', '- Open code-scanning alerts: unavailable',
                            '', f'The open code-scanning alerts could not be read: {error}'])
    else:
        report = render(args.result, alerts)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report + '\n', encoding='utf-8')
    _actions.set_output('status', status(args.result, alerts), required=False)
    print(report, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
