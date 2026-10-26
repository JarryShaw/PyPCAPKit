# -*- coding: utf-8 -*-
"""Report how long CI takes, and fail when a job is heading for its cap.

This is the script :file:`.github/workflows/ci-timing.yml` runs every Monday, the
periodic review GitHub issue #1538 asked for. It reads the Actions API for the last
``--days`` days and writes ``report.json`` (the next run's baseline), a
Markdown summary, and one ``::error::`` or ``::warning::`` annotation per threshold
that fired. Exit status: 0 when no HARD threshold fired, 1 when one did, 2 when the
API could not be read or the arguments are wrong, 3 for anything else. A HARD
failure is what emails the owner: GitHub notifies the user who last edited a
scheduled workflow's cron line of its failures, so no ``issues: write`` is needed.

What is read, and the rules for reading it:

* **Every completed run in the window is listed**, for Unit Tests and for each of
  :data:`OTHER_WORKFLOWS`, one day per query: a filtered listing returns at most
  1,000 runs, and GitHub Pages alone completed 1,154 in the week to 2026-10-09. The
  run counts, and so the superseded share, come from the whole listing.
* **Jobs are read for an evenly spaced sample** of those runs -- ``--runs`` per event
  for Unit Tests, ``--other-runs`` per other workflow -- so the sample spans the whole
  window rather than its newest days. The span read is printed with the report.
* **At job level**, from ``attempts/1/jobs``: a re-run attempt is a second copy of
  the same work and is dropped, as is any job with no ``runner_name`` (skipped, or
  never started). A job or step whose ``conclusion`` is empty is still running and is
  not counted.
* **A job counts by its own outcome, not its run's.** It is measured when it
  succeeded or failed, or when it was cancelled at :data:`TIMEOUT_SHARE` of its cap
  or later, which is how a timeout reports -- including inside a run that reads
  ``cancelled`` for that reason. A job cancelled earlier was superseded and is not.
  A run is measured when it succeeded, failed, or holds such a timed-out job; other
  cancelled runs are the superseded ones, counted and costed but not timed.
* **Pages are followed to exhaustion** through the ``Link`` header, the equivalent
  of ``gh api --paginate``, with no fixed page count.
* **Each cap is read from the workflow file itself**, at the newest push (or other
  non-PR) run's head sha, rather than written down here. It is also read at the
  oldest such run's sha, and a cap that differs between the two is reported, since a
  trend across it is not one trend. One read per run would cost ~300 calls for a
  value that rarely moves.
* **Test timings** come from the ``junit-unit-*`` artifacts the unit legs upload,
  for the newest :data:`JUNIT_RUNS` successful push runs. Each testcase's own
  ``time`` is used; a suite's ``tests=`` count includes subtests and is not.

A default run made 677 API calls for the week to 2026-10-19, measured for #1930:
49 listing pages, one per workflow per day and one more per further 100 runs; 601
job reads, at most ``--runs`` per event plus :data:`JUNIT_RUNS` pushes for Unit
Tests and ``--other-runs`` per other workflow, one more for a run past 100 jobs; 15
for artifacts; up to 12 workflow reads. That is inside ``GITHUB_TOKEN``'s 1,000
per hour, and ``--max-calls`` stops it before it can take more.

**The time goes on the job reads**, which are made one at a time, as GitHub asks
of an integration: 908 of that run's 993 seconds, and 734 on Unit Tests' runs
alone, at 2.4 s for each page of about 100 jobs with their steps. The listings, the
workflow files and the JUnit artifacts are therefore read first, and the job reads
last, in an order every prefix of which spans each sample (:func:`read_order`).
Once ``--budget-minutes`` is spent, or ``--max-calls``, no further run's jobs are
read: the report is still written, on the runs read, and says so in a note and an
annotation. Each step prints a progress line to stderr as it goes, so a run killed
by its cap shows how far it got.

``--concurrency-hours`` adds the runner-pool measurement, which costs one call per
run of every workflow in that window and is therefore off unless asked for. It is
skipped, or abandoned part way, once the budget is spent.

It fetches with :mod:`requests` and parses JUnit XML with lxml (#1894), which
the workflow installs, and needs nothing else outside the standard library.
The token is ``GH_TOKEN`` (or ``GITHUB_TOKEN``); locally,
``GH_TOKEN=$(gh auth token)`` works.

"""

from __future__ import annotations

import argparse
import collections
import datetime
import io
import json
import math
import os
import re
import statistics
import sys
import time
import tomllib
import traceback
import urllib.parse
import zipfile
from typing import TYPE_CHECKING

import requests

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Any, Callable, Iterable, Iterator, Optional

    #: Fetches one URL with an ``Accept`` header; returns the body and the headers,
    #: names lower-cased, and raises :exc:`requests.HTTPError` for an error status.
    Transport = Callable[[str, str], tuple[bytes, dict[str, str]]]

API = 'https://api.github.com'

#: The workflow whose runs are read job by job.
UNIT_TESTS = 'unit-tests.yml'
#: The other workflows on a pull request's path, read for job durations only.
OTHER_WORKFLOWS = ('python-compatibility.yml', 'lint.yml', 'codeql-analysis.yml',
                   'deploy-pages.yml', 'experimental.yml')
#: GitHub's own ``timeout-minutes`` when a job sets none.
DEFAULT_TIMEOUT = 360
#: Workflows of which no required context names a check, so every job is
#: non-blocking (#1732).
NON_BLOCKING_WORKFLOWS = ('experimental.yml',)
#: The suffix every KTLO leg's job name carries (#1633); such a leg's steps cannot
#: fail it (#1672).
KTLO_SUFFIX = ' (KTLO)'

#: The aggregate job the ruleset requires; its completion is "mergeable".
REQUIRED_JOB = 'Required checks passed'
#: The Python version tiers (#1660), which the names below are read from. This
#: script runs on ``latest`` (ci-timing.yml), so :mod:`tomllib`, 3.11+, is there.
TIERS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.github', 'python-versions.toml')


def _coverage_legs() -> 'tuple[str, tuple[str, ...]]':
    """The ``latest`` leg's job name, and the other supported legs', from :data:`TIERS`."""
    with open(TIERS, 'rb') as file:
        data = tomllib.load(file)
    paired = tuple(f'Python {version}' for version, entry in data['versions']['cpython'].items()
                   if entry['tier'] == 'supported' and version != data['latest'])
    return f"Python {data['latest']}", paired


#: The leg running under coverage, ``latest``, and the legs its tests step is paired
#: against: the rest of the supported tier (#1633), not the KTLO legs, which are
#: named ``Python 3.x (KTLO)`` and may stop early without failing.
COVERAGE_JOB, PAIRED_JOBS = _coverage_legs()
TESTS_STEP = 'Run unit tests'
#: The leg ms/test is measured on: a supported version not under coverage, kept on
#: 3.13 -- the newest such leg when W4's baseline was measured -- so that W4 compares
#: one interpreter with itself week over week.
MS_PER_TEST_LEG = '3.13'
#: The JUnit artifacts read, by leg, and from how many push runs.
JUNIT_LEGS = ('3.13', '3.14')
JUNIT_ARTIFACT = 'junit-unit-{leg}'
JUNIT_RUNS = 5

#: Steps reported on their own, by full-match pattern against the step's name.
STEPS_OF_INTEREST = (
    r'Run unit tests',
    r'Install package and test dependencies',
    r'Report coverage',
    r'Run full test suite',
    r'Run tests/.* under plain unittest',
    r'Run the KTLO cells.*',
)

# Thresholds. Each is anchored to a value measured on 2026-10-05..09 for #1538,
# given in brackets; see the CI Timing Review section of
# docs/source/contributing/workflows.rst for why each sits where it does.

#: H1, H2: a job's (or a capped step's) p90 reaching this share of its cap. 50%
#: leaves 12-18 days at the fastest growth measured, one review plus one fix.
#: [Python 3.14 p90 12.1 of 45 min, 27%; protocols (rest) step 319 s of 20 min]
HARD_CAP_SHARE = 0.5
#: W9, and H3's floor: pull-request time to ``Required checks passed``, p90,
#: minutes. [19.6 on 10-05..09; 36.7 in the two days to 10-10, the pool saturated]
MERGEABLE_P90 = 30.0
#: H3: that p90, over the floor, rising this much against the baseline report's.
#: Absolute, it measures runner-queue load as much as test time, so it pages only on
#: a regression; the absolute breach alone is W9. Initial value, to tune once weekly
#: reports exist -- W1's 20% median rise, loosened for a tail statistic.
HARD_MERGEABLE_RISE = 0.25
#: H4: a linear projection reaching its cap within this many days.
HARD_PROJECTION_DAYS = 14.0
#: W1: a job's median rising this much against the baseline report...
WARN_MEDIAN_RISE = 0.20
#: ...with at least this many samples on each side.
WARN_MEDIAN_SAMPLES = 20
#: W2: pull-request time to mergeable, median, minutes. [14.4]
WARN_MERGEABLE_MEDIAN = 18.0
#: W3: the coverage leg's tests step over its paired legs', median. [1.57]
WARN_COVERAGE_RATIO = 1.8
#: W4: ms per test on the 3.13 leg rising this much week over week. [110.8 ms]
WARN_MS_PER_TEST_RISE = 0.15
#: W5: run queue p90, minutes, per event. [3.1 and 9.6]
WARN_QUEUE_P90 = {'pull_request': 5.0, 'push': 15.0}
#: W6: share of pull-request runs cancelled, i.e. superseded. [29%]
WARN_SUPERSEDED_SHARE = 0.35
#: W7: a module's summed test time, and one test's, in seconds.
WARN_MODULE_SECONDS = 30.0
WARN_TEST_SECONDS = 10.0
#: W7: a class whose tests cost about the same each, at least this much, flags the
#: per-test re-import the #1538 measurement found: the first test pays setup, and
#: in such a class every later one pays it again.
UNIFORM_MIN_TESTS = 3
UNIFORM_MIN_MEDIAN = 0.3
UNIFORM_MEDIAN_TO_MAX = 0.5

#: A job or step cancelled at this share of its cap or later timed out.
TIMEOUT_SHARE = 0.95

#: Fewest samples a percentile threshold is judged on.
MIN_SAMPLES = 5
#: A linear fit needs this many points spread over this many days to project.
MIN_FIT_SAMPLES = 10
MIN_FIT_SPAN_DAYS = 2.0

#: How many rows each summary table shows; report.json keeps them all.
TABLE_ROWS = 15
TOP_TESTS = 30

DEFAULT_MAX_CALLS = 900
#: Minutes after which no further run's jobs are read; ci-timing.yml's step and job
#: caps sit above it, so that the report is written, and uploaded, before either.
DEFAULT_BUDGET_MINUTES = 30
#: Transient failures retried, with these waits in seconds.
RETRY_WAITS = (5, 20)
#: A filtered run listing returns at most this many runs, whatever total_count says.
LISTING_CAP = 1000

#: Exit statuses; see the module docstring.
EXIT_HARD, EXIT_API, EXIT_CRASH = 1, 2, 3


class BudgetExceeded(RuntimeError):
    """The run would make more API calls than ``--max-calls`` allows."""


# --------------------------------------------------------------------- arithmetic


def parse_time(value: 'Optional[str]') -> 'Optional[datetime.datetime]':
    """An API timestamp as an aware datetime, or ``None`` when it is empty."""
    if not value:
        return None
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))


def minutes(start: 'Optional[str]', end: 'Optional[str]') -> 'Optional[float]':
    """Minutes from ``start`` to ``end``, or ``None`` if either is missing."""
    first, last = parse_time(start), parse_time(end)
    if first is None or last is None:
        return None
    return (last - first).total_seconds() / 60


def quantile(values: 'Iterable[float]', q: 'float') -> 'Optional[float]':
    """The ``q`` quantile by linear interpolation between ranks."""
    data = sorted(values)
    if not data:
        return None
    position = q * (len(data) - 1)
    low, high = math.floor(position), math.ceil(position)
    return data[low] + (data[high] - data[low]) * (position - low)


def describe(values: 'Iterable[float]') -> 'dict[str, Any]':
    """``n``, ``median``, ``p90`` and ``max`` of ``values``."""
    data = list(values)
    return {'n': len(data), 'median': quantile(data, 0.5), 'p90': quantile(data, 0.9),
            'max': max(data) if data else None}


def projection(points: 'list[tuple[float, float]]', cap: 'float') -> 'dict[str, Any]':
    """A least-squares line through ``(day, minutes)`` points, projected to the cap.

    Returns the slope in minutes per day and the days until the fitted value reaches
    half the cap and the cap, each ``None`` when there is too little data, or when
    the line is not rising and has not reached it.

    """
    empty = {'slope_per_day': None, 'days_to_half_cap': None, 'days_to_cap': None}
    if len(points) < MIN_FIT_SAMPLES:
        return empty
    xs = [x for x, _ in points]
    if max(xs) - min(xs) < MIN_FIT_SPAN_DAYS:
        return empty
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(y for _, y in points)
    sxx = sum((x - mean_x) ** 2 for x in xs)
    slope = sum((x - mean_x) * (y - mean_y) for x, y in points) / sxx
    now = mean_y + slope * (max(xs) - mean_x)

    def days_to(target: 'float') -> 'Optional[float]':
        if now >= target:
            return 0.0
        if slope <= 0:
            return None
        return (target - now) / slope

    return {'slope_per_day': slope, 'days_to_half_cap': days_to(cap * HARD_CAP_SHARE),
            'days_to_cap': days_to(cap)}


# --------------------------------------------------------------------- workflow text


def template_pattern(template: 'str') -> 're.Pattern[str]':
    """A full-match pattern for a name that may carry ``${{ ... }}`` expressions."""
    parts = re.split(r'\$\{\{.*?\}\}', template)
    return re.compile('.+'.join(re.escape(part) for part in parts))


def _scalar(value: 'str') -> 'str':
    value = value.split(' #', 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def parse_workflow(text: 'str') -> 'list[dict[str, Any]]':
    """Each job's name, ``timeout-minutes``, ``needs:`` and step caps.

    Read off the text by indentation, the way the tests under :file:`tests/project`
    read these files, because PyYAML is not in the standard library. Every workflow
    here keeps job keys at four spaces, which is all this relies on. A job whose
    ``steps:`` is a YAML alias, as unit-tests.yml's KTLO jobs are (#1738), gets the
    steps of the job that anchors them, which comes first, as YAML needs.

    """
    jobs = []  # type: list[dict[str, Any]]
    anchors = {}  # type: dict[str, list[dict[str, Any]]]
    body = re.split(r'(?m)^jobs:\s*$', text, maxsplit=1)
    if len(body) != 2:
        return jobs
    for match in re.finditer(r'(?ms)^  ([\w-]+):\s*\n(.*?)(?=^  [\w-]+:\s*$|^\S|\Z)', body[1]):
        job_id, section = match.group(1), match.group(2)
        name = re.search(r'(?m)^    name:\s*(.+)$', section)
        timeout = re.search(r'(?m)^    timeout-minutes:\s*(\d+)', section)
        needs = re.search(r'(?m)^    needs:\s*(.+)$', section)
        needed = [] if needs is None else [
            item.strip() for item in _scalar(needs.group(1)).strip('[]').split(',') if item.strip()]
        template = _scalar(name.group(1)) if name else job_id
        steps = _parse_steps(section)
        node = re.search(r'(?m)^    steps:[ \t]*([&*])([\w-]+)[ \t]*$', section)
        if node and node.group(1) == '&':
            anchors[node.group(2)] = steps
        elif node:
            steps = anchors.get(node.group(2), [])
        jobs.append({
            'id': job_id,
            'name': template,
            'pattern': template_pattern(template),
            'literal': '${{' not in template,
            # Unnamed matrix jobs are listed as ``id (values)``.
            'unnamed': name is None,
            'timeout': int(timeout.group(1)) if timeout else DEFAULT_TIMEOUT,
            'needs': needed,
            'steps': steps,
        })
    return jobs


def _parse_steps(section: 'str') -> 'list[dict[str, Any]]':
    """The named steps of one job section, with any step-level cap.

    A cap written as an expression differs by leg, and the job's spec does not say
    which leg a name ran, so it reads as none, as an uncapped step's does. No
    workflow writes one (#1732).

    """
    found = []  # type: list[dict[str, Any]]
    lines = section.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if re.match(r'^    steps:(?:[ \t]*&[\w-]+)?\s*$', line))
    except StopIteration:
        return found
    items = [i for i in range(start + 1, len(lines)) if re.match(r'^ {4,}- ', lines[i])]
    if not items:
        return found
    indent = len(lines[items[0]]) - len(lines[items[0]].lstrip())
    items = [i for i in items if len(lines[i]) - len(lines[i].lstrip()) == indent]
    for number, first in enumerate(items):
        last = items[number + 1] if number + 1 < len(items) else len(lines)
        block = [lines[first][:indent] + '  ' + lines[first][indent + 2:]] + lines[first + 1:last]
        keys = {}  # type: dict[str, str]
        for line in block:
            key = re.match(rf'^ {{{indent + 2}}}([\w-]+):\s*(.*)$', line)
            if key:
                keys.setdefault(key.group(1), key.group(2))
        if 'name' not in keys:
            continue
        template = _scalar(keys['name'])
        timeout = _scalar(keys.get('timeout-minutes') or '')
        found.append({'name': template, 'pattern': template_pattern(template),
                      'timeout': int(timeout) if timeout and '${{' not in timeout else None})
    return found


def match_job(specs: 'list[dict[str, Any]]', name: 'str') -> 'Optional[dict[str, Any]]':
    """The spec a job name in the API came from; a literal name wins over a template.

    Of the templates that match, the one with the most literal text wins:
    ``Python ${{ matrix.python-version }}`` matches ``Python 3.10 (KTLO)`` too,
    which is ``Python ${{ matrix.python-version }} (KTLO)``'s, ``test-ktlo``'s
    and not ``test``'s (#1738).

    """
    for spec in specs:
        if spec['literal'] and spec['name'] == name:
            return spec
    matched = [spec for spec in specs if spec['pattern'].fullmatch(name)]
    if matched:
        return max(matched, key=lambda spec: len(re.sub(r'\$\{\{.*?\}\}', '', spec['name'])))
    for spec in specs:
        if spec['unnamed'] and re.fullmatch(rf'{re.escape(spec["id"])} \(.*\)', name):
            return spec
    return None


def step_cap(spec: 'Optional[dict[str, Any]]', name: 'str') -> 'Optional[int]':
    """A step's own ``timeout-minutes``, if its job declares one for it."""
    for step in (spec or {}).get('steps', ()):
        if step['pattern'].fullmatch(name):
            return step['timeout']
    return None


# --------------------------------------------------------------------- the API


def next_link(header: 'str') -> 'Optional[str]':
    """The ``rel="next"`` URL of a ``Link`` header.

    Parsed as :attr:`requests.Response.links` parses it, from the header the
    transport returns, so a test's transport needs to send only the header.

    """
    for link in requests.utils.parse_header_links(header or ''):
        if link.get('rel') == 'next':
            return link.get('url')
    return None


def status_of(error: 'requests.HTTPError') -> 'int':
    """The HTTP status an error carries, or 0 when it has no response."""
    return getattr(error.response, 'status_code', None) or 0


class Client:
    """The REST API, counting calls against a budget.

    Args:
        token: Bearer token.
        transport: Replaces the network, for tests.
        max_calls: Refuse the call after this many.
        sleep: Replaces :func:`time.sleep` between retries, for tests.

    """

    def __init__(self, token: 'str', *, transport: 'Optional[Transport]' = None,
                 max_calls: 'int' = DEFAULT_MAX_CALLS,
                 sleep: 'Callable[[float], None]' = time.sleep) -> 'None':
        self.token = token
        self.transport = transport or self._get
        self.max_calls = max_calls
        self.sleep = sleep
        self.calls = 0
        self.rate_remaining = None  # type: Optional[int]
        #: The connections :meth:`_get` reuses, opened on its first call.
        self.session = None  # type: Optional[requests.Session]

    def _get(self, url: 'str', accept: 'str') -> 'tuple[bytes, dict[str, str]]':
        """The default transport: one GET, following redirects."""
        if self.session is None:
            self.session = requests.Session()
        # requests drops the Authorization header on a redirect to another host
        # (Session.rebuild_auth), so an artifact download's redirect to blob
        # storage does not carry the token to a host that rejects it. Only https
        # URLs reach here: the API root, or a Link/download URL it sent.
        response = self.session.get(url, timeout=60, headers={
            'Accept': accept, 'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'PyPCAPKit-ci-timing', 'Authorization': f'Bearer {self.token}'})
        response.raise_for_status()
        return response.content, {k.lower(): v for k, v in response.headers.items()}

    def fetch(self, url: 'str', accept: 'str' = 'application/vnd.github+json') -> 'tuple[bytes, dict[str, str]]':
        """One request; ``url`` may be a path under the API root."""
        if url.startswith('/'):
            url = API + url
        if not url.startswith('https://'):
            raise ValueError(f'refusing a non-https URL: {url}')
        for wait in RETRY_WAITS + (None,):
            if self.calls >= self.max_calls:
                raise BudgetExceeded(f'stopped at {self.calls} API calls (--max-calls)')
            self.calls += 1
            try:
                body, headers = self.transport(url, accept)
            except requests.HTTPError as error:
                if wait is None or status_of(error) < 500:
                    raise
            # requests' ConnectionError and Timeout, a timeout or reset mid-read
            # among them, are OSErrors, as its HTTPError is.
            except OSError:
                if wait is None:
                    raise
            else:
                remaining = headers.get('x-ratelimit-remaining')
                if remaining is not None:
                    self.rate_remaining = int(remaining)
                return body, headers
            self.sleep(wait)
        raise AssertionError('unreachable')  # pragma: no cover

    def get(self, path: 'str', **params: 'Any') -> 'Any':
        """One JSON document."""
        query = f'?{urllib.parse.urlencode(params)}' if params else ''
        return json.loads(self.fetch(path + query)[0])

    def text(self, path: 'str', **params: 'Any') -> 'str':
        """One file's raw content, through the contents API."""
        query = f'?{urllib.parse.urlencode(params)}' if params else ''
        return self.fetch(path + query, 'application/vnd.github.raw+json')[0].decode('utf-8')

    def paginate(self, path: 'str', key: 'str', meta: 'Optional[dict[str, Any]]' = None,
                 **params: 'Any') -> 'Iterator[dict[str, Any]]':
        """Every item under ``key``, following ``Link: rel="next"`` to the end.

        A generator, so a caller that stops consuming stops the paging. ``meta``, if
        given, receives the first page's ``total_count``.

        """
        params.setdefault('per_page', 100)
        url = f'{path}?{urllib.parse.urlencode(params)}'  # type: Optional[str]
        while url:
            body, headers = self.fetch(url)
            page = json.loads(body)
            if meta is not None and 'total_count' in page:
                meta.setdefault('total_count', page['total_count'])
            yield from page.get(key) or ()
            url = next_link(headers.get('link', ''))


def iso(moment: 'datetime.datetime') -> 'str':
    """``moment`` the way the API writes it."""
    return moment.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def list_runs(client: 'Client', path: 'str', since: 'datetime.datetime',
              now: 'datetime.datetime', notes: 'list[str]',
              **params: 'Any') -> 'list[dict[str, Any]]':
    """Every run at ``path`` created in ``[since, now)``, newest first.

    One query per day, because a filtered listing stops at :data:`LISTING_CAP` runs
    however many match; a day that still exceeds it is reported in ``notes``.

    """
    found = {}  # type: dict[int, dict[str, Any]]
    end = now
    while end > since:
        start = max(since, end - datetime.timedelta(days=1))
        meta = {}  # type: dict[str, Any]
        last = iso(end - datetime.timedelta(seconds=1))
        day = list(client.paginate(path, 'workflow_runs', meta=meta,
                                   created=f'{iso(start)}..{last}', **params))
        if meta.get('total_count', 0) > len(day):
            notes.append(f'{path.rsplit("/", 2)[-2]}: {meta["total_count"]} runs created '
                         f'{iso(start)}..{last}, of which the API returned {len(day)}.')
        for run in day:
            found.setdefault(run['id'], run)
        end = start
    return sorted(found.values(), key=lambda run: run['created_at'], reverse=True)


def spread(items: 'list[Any]', count: 'int') -> 'list[Any]':
    """``count`` of ``items``, evenly spaced from the first to the last."""
    if len(items) <= count:
        return list(items)
    if count < 2:
        return list(items[:count])
    return [items[round(i * (len(items) - 1) / (count - 1))] for i in range(count)]


def prefix_order(items: 'list[Any]') -> 'list[Any]':
    """``items`` reordered so that every prefix of the result spans all of them.

    The first and the last come first, then each gap's midpoint, a level of halving
    at a time, so a read stopped part way through has still covered the whole window
    rather than its newest days (#1930).

    """
    if len(items) <= 2:
        return list(items)
    order = [0, len(items) - 1]
    gaps = collections.deque([(0, len(items) - 1)])
    while gaps:
        low, high = gaps.popleft()
        if high - low < 2:
            continue
        middle = (low + high) // 2
        order.append(middle)
        gaps.extend(((low, middle), (middle, high)))
    return [items[index] for index in order]


def read_order(groups: 'Iterable[list[dict[str, Any]]]',
               first: 'Iterable[dict[str, Any]]' = ()) -> 'list[dict[str, Any]]':
    """The runs of every sample, in the order their jobs are read, each once.

    ``first`` leads. The groups' runs follow, interleaved so that at any point each
    group has had about the same share of its runs read, and those runs span its
    window (:func:`prefix_order`). A read cut short by the budget therefore leaves a
    smaller sample of every workflow, not a whole sample of some and none of others.

    """
    keyed = []  # type: list[tuple[float, int, dict[str, Any]]]
    for group in groups:
        ordered = prefix_order(group)
        keyed += [(rank / len(ordered), len(keyed) + rank, run) for rank, run in enumerate(ordered)]
    seen = set()  # type: set[int]
    queue = []
    for run in list(first) + [run for _, _, run in sorted(keyed, key=lambda item: item[:2])]:
        if run['id'] not in seen:
            seen.add(run['id'])
            queue.append(run)
    return queue


def collect(client: 'Client', repo: 'str', *, now: 'datetime.datetime', days: 'float',
            runs: 'int' = 150, other_runs: 'int' = 60, junit_runs: 'int' = JUNIT_RUNS,
            concurrency_hours: 'float' = 0, budget: 'float' = math.inf,
            clock: 'Callable[[], float]' = time.monotonic,
            progress: 'Optional[Callable[[str], None]]' = None) -> 'dict[str, Any]':
    """Everything the report is computed from, read from the API.

    The run listings, the workflow files and the JUnit artifacts are read first, and
    the job listings last, in :func:`read_order`. The job listings are what the time
    goes on (see the module docstring), so they are what ``budget`` cuts short: once
    it is spent, or the client's ``--max-calls`` is, no further run's jobs are read,
    the runs not read leave the sample, and ``data['stopped']`` says why.

    Args:
        client: The API.
        repo: ``owner/name``.
        now: The end of the window.
        days: The window's length.
        runs: Unit Tests runs per event whose jobs are read.
        other_runs: Runs per other workflow whose jobs are read.
        junit_runs: Successful push runs whose JUnit artifacts are read.
        concurrency_hours: Hours of every workflow's runs to measure the runner pool
            over; 0 skips it.
        budget: Seconds, from the call, after which no further jobs are read.
        clock: Replaces :func:`time.monotonic`, for tests.
        progress: Receives one line per step, so that a killed run leaves a trail.

    """
    started = clock()

    def say(message: 'str') -> 'None':
        if progress is not None:
            progress(f'[ci-timing {clock() - started:6.0f} s, {client.calls} calls] {message}')

    since = now - datetime.timedelta(days=days)
    base = f'/repos/{repo}/actions'
    data = {'repo': repo, 'since': iso(since), 'until': iso(now), 'days': days,
            'workflows': {}, 'junit': [], 'concurrency': None, 'notes': [],
            'stopped': None}  # type: dict[str, Any]
    say(f'Reading {repo}, {iso(since)} to {iso(now)}; no jobs are read after '
        f'{budget / 60:g} min.')

    groups = []  # type: list[list[dict[str, Any]]]
    for workflow in (UNIT_TESTS,) + OTHER_WORKFLOWS:
        listed = [run for run in list_runs(client, f'{base}/workflows/{workflow}/runs', since, now,
                                           data['notes'], status='completed')
                  if run.get('conclusion') in ('success', 'failure', 'cancelled')]
        if workflow == UNIT_TESTS:
            chosen = []  # type: list[dict[str, Any]]
            for event in ('pull_request', 'push'):
                groups.append(spread([run for run in listed if run.get('event') == event], runs))
                chosen += groups[-1]
            # The pushes whose JUnit artifacts are read need their jobs read too.
            chosen += [run for run in listed if run.get('event') == 'push'
                       and run['conclusion'] == 'success'][:junit_runs]
            chosen = sorted({run['id']: run for run in chosen}.values(),
                            key=lambda run: run['created_at'], reverse=True)
        else:
            chosen = spread(listed, other_runs)
            groups.append(chosen)
        say(f'{workflow}: {len(listed)} runs listed, {len(chosen)} sampled.')
        counts = collections.Counter((run.get('event'), run['conclusion']) for run in listed)
        data['workflows'][workflow] = {
            'runs': chosen, 'specs': {},
            'listed': {event: {'runs': sum(n for (e, _), n in counts.items() if e == event),
                               'cancelled': counts[(event, 'cancelled')]}
                       for event in sorted({e for e, _ in counts})}}
        # A pull request's head may carry a cap that never merged, so the caps are
        # read at a non-PR run's sha where the window has one.
        path = f'/repos/{repo}/contents/.github/workflows/{workflow}'
        mainline = [run for run in chosen if run.get('event') != 'pull_request'] or chosen
        for label, run in (('newest', mainline[0]), ('oldest', mainline[-1])) if mainline else ():
            sha = run['head_sha']
            known = [text for text_sha, text in data['workflows'][workflow]['specs'].values()
                     if text_sha == sha]
            try:
                text = known[0] if known else client.text(path, ref=sha)
            except requests.HTTPError as error:
                if status_of(error) != 404:
                    raise
                data['notes'].append(f'{workflow} is not at {sha[:9]}, so its {label} caps are unknown.')
                continue
            data['workflows'][workflow]['specs'][label] = (sha, text)

    pushes = [run for run in data['workflows'][UNIT_TESTS]['runs']
              if run.get('event') == 'push' and run.get('conclusion') == 'success'][:junit_runs]
    for run in pushes:
        artifacts = {item['name']: item for item in
                     client.paginate(f'{base}/runs/{run["id"]}/artifacts', 'artifacts')
                     if not item.get('expired')}
        for leg in JUNIT_LEGS:
            artifact = artifacts.get(JUNIT_ARTIFACT.format(leg=leg))
            if artifact is None:
                continue
            raw = client.fetch(artifact['archive_download_url'])[0]
            say(f'JUnit: run {run["id"]}, {JUNIT_ARTIFACT.format(leg=leg)}, {len(raw) / 1e6:.2f} MB.')
            archive = zipfile.ZipFile(io.BytesIO(raw))
            members = [name for name in archive.namelist() if name.endswith('.xml')]
            if members:
                data['junit'].append({'run_id': run['id'], 'created_at': run['created_at'],
                                      'leg': leg, **parse_junit(archive.read(members[0]))})
    if not data['junit']:
        data['notes'].append(f'No {JUNIT_ARTIFACT.format(leg="*")} artifact in the newest '
                             f'{len(pushes)} successful push runs, so there '
                             'are no test-level timings.')

    # The JUnit pushes lead: ms per test needs their jobs as well as their artifacts.
    queue = read_order(groups, first=pushes)
    for done, run in enumerate(queue):
        reason = None  # type: Optional[str]
        if clock() - started >= budget:
            reason = f'the {budget / 60:g}-minute budget (--budget-minutes) ran out'
        else:
            try:
                run['jobs'] = list(client.paginate(f'{base}/runs/{run["id"]}/attempts/1/jobs', 'jobs'))
            except BudgetExceeded as error:
                reason = str(error)
        if reason:
            data['stopped'] = (f'Jobs were read for {done} of the {len(queue)} runs sampled: '
                               f'{reason}. The rest are left out of the sample, which still '
                               'spans the window.')
            break
        if (done + 1) % 25 == 0 or done + 1 == len(queue):
            say(f'Jobs read for {done + 1} of {len(queue)} runs.')
    if data['stopped']:
        say(data['stopped'])
        data['notes'].append(data['stopped'])
        for info in data['workflows'].values():
            info['runs'] = [run for run in info['runs'] if 'jobs' in run]

    if concurrency_hours and data['stopped']:
        data['notes'].append('The runner-pool measurement was skipped, the job reads having '
                             'stopped short.')
    elif concurrency_hours:
        data['concurrency'] = _concurrency(client, base, now, concurrency_hours, data['notes'],
                                           lambda: clock() - started >= budget)
        say('Runner pool measured.' if data['concurrency'] else 'Runner pool not measured.')
    return data


def _concurrency(client: 'Client', base: 'str', now: 'datetime.datetime', hours: 'float',
                 notes: 'list[str]', spent: 'Callable[[], bool]') -> 'Optional[dict[str, Any]]':
    """The runner pool over the last ``hours``, or ``None`` if the budget runs out first."""
    start = now - datetime.timedelta(hours=hours)
    spans = []  # type: list[tuple[datetime.datetime, datetime.datetime, str]]
    for run in list_runs(client, f'{base}/runs', start, now, notes):
        if spent():
            notes.append('The runner-pool measurement was abandoned, the budget having run '
                         'out part way through it.')
            return None
        for job in client.paginate(f'{base}/runs/{run["id"]}/jobs', 'jobs', filter='all'):
            begun = parse_time(job.get('started_at'))
            if not job.get('runner_name') or begun is None:
                continue
            ended = parse_time(job.get('completed_at')) or now
            labels = ' '.join(job.get('labels') or ())
            spans.append((begun, ended, 'macos' if 'macos' in labels else 'other'))
    return {'hours': hours, **pool_concurrency(spans)}


def parse_xml(raw: 'bytes') -> 'Any':
    """``raw``'s root element, parsed strictly by lxml (#1894).

    The JUnit files are ones this repository's own CI wrote, but the parser
    trusts nothing in them. Malformed XML raises
    :exc:`lxml.etree.XMLSyntaxError`, and so does nesting past libxml2's depth
    limit, which ``huge_tree=False`` keeps. No DTD is loaded and nothing is
    fetched: an entity in text is left unexpanded, and an attribute that
    references an external one is an error, so an entity naming a file or a URL
    is never read. lxml is imported here, so only a run that reads JUnit needs it.

    """
    from lxml import etree  # pylint: disable=import-outside-toplevel

    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, load_dtd=False)
    return etree.fromstring(raw, parser)


def parse_junit(raw: 'bytes') -> 'dict[str, Any]':
    """The testcases of one pytest JUnit file, and its suite's ``tests=`` total."""
    root = parse_xml(raw)
    suites = [root] if root.tag == 'testsuite' else root.findall('testsuite')
    cases = [(case.get('classname') or '', case.get('name') or '', float(case.get('time') or 0))
             for suite in suites for case in suite.iter('testcase')]
    return {'cases': cases, 'suite_tests': sum(int(suite.get('tests') or 0) for suite in suites)}


def pool_concurrency(spans: 'list[tuple[datetime.datetime, datetime.datetime, str]]') -> 'dict[str, Any]':
    """The most jobs holding a runner at once, and for how long that peak held."""
    events = sorted([(begun, 1, kind) for begun, _, kind in spans]
                    + [(ended, -1, kind) for _, ended, kind in spans],
                    key=lambda item: (item[0], item[1]))
    running = collections.Counter()  # type: collections.Counter[str]
    peak, held, macos_peak = 0, 0.0, 0
    for (moment, delta, kind), following in zip(events, events[1:] + [None]):
        running[kind] += delta
        total = sum(running.values())
        macos_peak = max(macos_peak, running['macos'])
        if total > peak:
            peak, held = total, 0.0
        if total == peak and following is not None:
            held += (following[0] - moment).total_seconds()
    return {'jobs': len(spans), 'peak': peak, 'seconds_at_peak': held, 'macos_peak': macos_peak}


# --------------------------------------------------------------------- the report


def _ran(job: 'dict[str, Any]') -> 'bool':
    """A job that held a runner, finished, and belongs to the first attempt."""
    return bool(job.get('runner_name') and job.get('conclusion') and job.get('started_at')
                and job.get('completed_at') and job.get('run_attempt', 1) == 1)


def _days(moment: 'Optional[str]', origin: 'datetime.datetime') -> 'float':
    stamp = parse_time(moment)
    return 0.0 if stamp is None else (stamp - origin).total_seconds() / 86400


def _timed_out(item: 'dict[str, Any]', cap: 'Optional[float]') -> 'bool':
    """A job or step cancelled at :data:`TIMEOUT_SHARE` of ``cap`` or later."""
    took = minutes(item.get('started_at'), item.get('completed_at'))
    return (item.get('conclusion') == 'cancelled' and bool(cap) and took is not None
            and took >= TIMEOUT_SHARE * cap)


def _counted(item: 'dict[str, Any]', cap: 'Optional[float]') -> 'bool':
    """Measured by its own outcome: it succeeded, failed, or was killed at its cap."""
    return item.get('conclusion') in ('success', 'failure') or _timed_out(item, cap)


def _job_cap(specs: 'list[dict[str, Any]]', name: 'str') -> 'int':
    spec = match_job(specs, name)
    return spec['timeout'] if spec else DEFAULT_TIMEOUT


def _measured(run: 'dict[str, Any]', specs: 'list[dict[str, Any]]') -> 'bool':
    """A run that finished, or that reads ``cancelled`` because a job timed out.

    Any other cancelled run was superseded, or cancelled by hand, and its timings
    describe when it was stopped rather than how long the work takes.

    """
    if run.get('conclusion') in ('success', 'failure'):
        return True
    return run.get('conclusion') == 'cancelled' and any(
        _timed_out(job, _job_cap(specs, job['name'])) for job in run.get('jobs', ()) if _ran(job))


def analyse(data: 'dict[str, Any]') -> 'dict[str, Any]':
    """The metrics of one window, from what :func:`collect` read."""
    origin = parse_time(data['since'])
    assert origin is not None
    report = {'schema': 1, 'repo': data['repo'], 'window': {
        'since': data['since'], 'until': data['until'], 'days': data['days'], 'read': {}},
        'notes': list(data.get('notes', ())), 'runs': {}, 'jobs': [], 'steps': [],
        'critical_path': {}, 'derived': {}, 'tests': {}}  # type: dict[str, Any]
    for workflow, info in data['workflows'].items():
        listed = info.get('listed', {})
        report['window']['read'][workflow] = {
            'listed': sum(row['runs'] for row in listed.values()) if listed else len(info['runs']),
            'read': len(info['runs']),
            'first': min((run['created_at'] for run in info['runs']), default=None),
            'last': max((run['created_at'] for run in info['runs']), default=None)}

    specs = {}
    for workflow, info in data['workflows'].items():
        newest = parse_workflow(info['specs']['newest'][1]) if 'newest' in info['specs'] else []
        specs[workflow] = newest
        if 'oldest' in info['specs']:
            old = {spec['name']: spec['timeout'] for spec in parse_workflow(info['specs']['oldest'][1])}
            for spec in newest:
                if spec['name'] in old and old[spec['name']] != spec['timeout']:
                    report['notes'].append(
                        f'{workflow}: `{spec["name"]}` cap moved from {old[spec["name"]]} to '
                        f'{spec["timeout"]} min inside the window; its trend spans the change.')

    unit = data['workflows'].get(UNIT_TESTS, {})
    report['runs'], report['superseded'] = _run_level(unit, specs.get(UNIT_TESTS, []))
    jobs = collections.defaultdict(list)  # type: dict[tuple[str, str], list[dict[str, Any]]]
    steps = collections.defaultdict(list)  # type: dict[tuple[str, str, str], list[dict[str, Any]]]
    for workflow, info in data['workflows'].items():
        # Every run, whatever its own conclusion: a job is judged by its own.
        for run in info['runs']:
            for job in filter(_ran, run.get('jobs', ())):
                spec = match_job(specs.get(workflow, []), job['name'])
                cap = spec['timeout'] if spec else DEFAULT_TIMEOUT
                if not _counted(job, cap):
                    continue
                jobs[(workflow, job['name'])].append(job)
                for step in job.get('steps') or ():
                    if not any(re.fullmatch(pattern, step['name']) for pattern in STEPS_OF_INTEREST):
                        continue
                    # The step running when its job timed out was cut off by that cap.
                    if _counted(step, step_cap(spec, step['name'])) or (
                            _timed_out(job, cap) and step.get('conclusion') == 'cancelled'):
                        steps[(workflow, job['name'], step['name'])].append(step)

    unmatched = set()
    for (workflow, name), samples in sorted(jobs.items()):
        spec = match_job(specs.get(workflow, []), name)
        if spec is None:
            unmatched.add(f'{workflow}: {name}')
        cap = spec['timeout'] if spec else DEFAULT_TIMEOUT
        durations = [(_days(job['started_at'], origin), minutes(job['started_at'], job['completed_at']))
                     for job in samples]
        row = {'workflow': workflow, 'name': name, 'cap': cap,
               **describe(value for _, value in durations),
               'queue': describe(minutes(job.get('created_at') or job['started_at'], job['started_at'])
                                 for job in samples)}
        row['p90_share_of_cap'] = row['p90'] / cap
        row.update(projection(durations, cap))
        report['jobs'].append(row)
    if unmatched:
        report['notes'].append('Matched no job in the workflow file, so judged against the '
                               f'{DEFAULT_TIMEOUT}-minute default cap: ' + ', '.join(sorted(unmatched)))

    for (workflow, job_name, name), samples in sorted(steps.items()):
        cap = step_cap(match_job(specs.get(workflow, []), job_name), name)
        durations = [(_days(step['started_at'], origin), minutes(step['started_at'], step['completed_at']))
                     for step in samples if step.get('started_at') and step.get('completed_at')]
        row = {'workflow': workflow, 'job': job_name, 'name': name, 'cap': cap,
               **describe(value for _, value in durations)}
        if cap:
            row['p90_share_of_cap'] = row['p90'] / cap if row['p90'] is not None else None
            row.update(projection(durations, cap))
        report['steps'].append(row)

    report['critical_path'] = _critical_path(unit, specs.get(UNIT_TESTS, []))
    report['derived'] = _derived(unit, specs.get(UNIT_TESTS, []), data.get('junit', ()))
    report['tests'] = _tests(data.get('junit', ()))
    if data.get('concurrency'):
        report['concurrency'] = data['concurrency']
    return report


def _step_minutes(job: 'Optional[dict[str, Any]]', name: 'str') -> 'Optional[float]':
    for step in (job or {}).get('steps') or ():
        if step['name'] == name and step.get('conclusion') in ('success', 'failure'):
            return minutes(step.get('started_at'), step.get('completed_at'))
    return None


def _run_level(unit: 'dict[str, Any]',
               specs: 'list[dict[str, Any]]') -> 'tuple[dict[str, Any], dict[str, Any]]':
    """Queue, time to mergeable, wall and runner time per event; then the superseded.

    The run counts come from the whole listing; the timings from the runs read. The
    superseded runs' runner time is the mean of those read, scaled to all of them.

    """
    rows = {}  # type: dict[str, Any]
    listed = unit.get('listed', {})
    stopped = []  # type: list[float]
    for event in ('pull_request', 'push'):
        measured = []  # type: list[dict[str, Any]]
        sample = [run for run in unit.get('runs', ()) if run.get('event') == event]
        for run in sample:
            ran = [job for job in run.get('jobs', ()) if _ran(job)]
            runner = sum(minutes(job['started_at'], job['completed_at']) or 0 for job in ran)
            if not _measured(run, specs):
                if event == 'pull_request' and run.get('conclusion') == 'cancelled':
                    stopped.append(runner)
                continue
            if not ran:
                continue
            required = [job for job in ran if job['name'] == REQUIRED_JOB]
            measured.append({
                'queue': minutes(run['created_at'], min(job['started_at'] for job in ran)),
                'wall': minutes(run['created_at'], max(job['completed_at'] for job in ran)),
                'mergeable': minutes(run['created_at'], required[0]['completed_at'])
                if required and required[0]['conclusion'] == 'success' else None,
                'runner_min': runner, 'jobs': len(ran)})
        rows[event] = {key: describe(row[key] for row in measured if row[key] is not None)
                       for key in ('queue', 'mergeable', 'wall', 'runner_min', 'jobs')}
        counts = listed.get(event) or {
            'runs': len(sample), 'cancelled': sum(run.get('conclusion') == 'cancelled' for run in sample)}
        rows[event]['runs'] = len(measured)
        rows[event]['listed'] = counts['runs']
        rows[event]['cancelled'] = counts['cancelled']
    pr = rows['pull_request']
    superseded = {'runs': pr['cancelled'], 'of': pr['listed'],
                  'share': pr['cancelled'] / pr['listed'] if pr['listed'] else None,
                  'read': len(stopped),
                  'runner_min': statistics.fmean(stopped) * pr['cancelled'] if stopped else None}
    return rows, superseded


def _critical_path(unit: 'dict[str, Any]', specs: 'list[dict[str, Any]]') -> 'dict[str, Any]':
    """Which needed job finished last before ``Required checks passed``, per event."""
    required = next((spec for spec in specs if spec['name'] == REQUIRED_JOB), None)
    needed = set(required['needs']) if required else set()
    paths = {}
    for event in ('pull_request', 'push'):
        leaders = collections.Counter()  # type: collections.Counter[str]
        slack = []
        for run in unit.get('runs', ()):
            if run.get('event') != event or not _measured(run, specs):
                continue
            ended = sorted(((job['completed_at'], job['name']) for job in run.get('jobs', ())
                            if _ran(job) and job['name'] != REQUIRED_JOB
                            and (match_job(specs, job['name']) or {}).get('id') in needed),
                           reverse=True)
            if not ended:
                continue
            leaders[ended[0][1]] += 1
            if len(ended) > 1:
                slack.append(minutes(ended[1][0], ended[0][0]))
        total = sum(leaders.values())
        paths[event] = {
            'runs': total, 'leader': leaders.most_common(1)[0][0] if leaders else None,
            'shares': {name: count / total for name, count in leaders.most_common()},
            'slack_median': quantile([value for value in slack if value is not None], 0.5)}
    return paths


def _derived(unit: 'dict[str, Any]', specs: 'list[dict[str, Any]]',
             junit: 'Iterable[dict[str, Any]]') -> 'dict[str, Any]':
    """The coverage leg's paired slowdown, and ms per test where JUnit exists."""
    ratios = []
    by_run = {}
    for run in unit.get('runs', ()):
        if not _measured(run, specs):
            continue
        named = {job['name']: job for job in run.get('jobs', ()) if _ran(job)}
        by_run[run['id']] = named
        covered = _step_minutes(named.get(COVERAGE_JOB), TESTS_STEP)
        paired = [value for value in (_step_minutes(named.get(name), TESTS_STEP)
                                      for name in PAIRED_JOBS) if value]
        if covered and len(paired) >= 2:
            ratios.append(covered / statistics.median(paired))
    per_test = []
    counts = []
    for entry in junit:
        if entry['leg'] != MS_PER_TEST_LEG or not entry['cases']:
            continue
        counts.append({'run_id': entry['run_id'], 'tests': len(entry['cases']),
                       'suite_tests': entry['suite_tests']})
        step = _step_minutes(by_run.get(entry['run_id'], {}).get(f'Python {entry["leg"]}'), TESTS_STEP)
        if step:
            per_test.append(step * 60000 / len(entry['cases']))
    return {'coverage_ratio': {**describe(ratios), 'min': min(ratios) if ratios else None},
            'ms_per_test': describe(per_test), 'test_counts': counts}


def _split(classname: 'str') -> 'tuple[str, Optional[str]]':
    """``(module, class)`` of a JUnit classname; a module-level test has no class."""
    head, _, tail = classname.rpartition('.')
    if head and tail[:1].isupper():
        return head, classname
    return classname, None


def _tests(junit: 'Iterable[dict[str, Any]]') -> 'dict[str, Any]':
    """Per leg: top modules and classes, slow tests, and uniform-cost classes."""
    legs = {}
    entries = list(junit)
    for leg in JUNIT_LEGS:
        runs = [entry for entry in entries if entry['leg'] == leg]
        if not runs:
            continue
        modules = collections.defaultdict(list)  # type: dict[str, list[float]]
        classes = collections.defaultdict(list)  # type: dict[str, list[float]]
        slow = {}  # type: dict[str, float]
        uniform = collections.Counter()  # type: collections.Counter[str]
        for entry in runs:
            module_sum = collections.Counter()  # type: collections.Counter[str]
            class_times = collections.defaultdict(list)  # type: dict[str, list[float]]
            for classname, name, seconds in entry['cases']:
                module, cls = _split(classname)
                module_sum[module] += seconds
                if cls:
                    class_times[cls].append(seconds)
                if seconds > WARN_TEST_SECONDS:
                    test = f'{classname}::{name}'
                    slow[test] = max(slow.get(test, 0.0), seconds)
            for module, total in module_sum.items():
                modules[module].append(total)
            for cls, times in class_times.items():
                classes[cls].append(sum(times))
                middle = statistics.median(times)
                if (len(times) >= UNIFORM_MIN_TESTS and middle >= UNIFORM_MIN_MEDIAN
                        and middle >= UNIFORM_MEDIAN_TO_MAX * max(times)):
                    uniform[cls] += 1

        def top(table: 'dict[str, list[float]]') -> 'list[list[Any]]':
            ranked = sorted(((statistics.median(v), k) for k, v in table.items()), reverse=True)
            return [[name, round(seconds, 3)] for seconds, name in ranked[:TOP_TESTS]]

        legs[leg] = {'runs': len(runs), 'top_modules': top(modules), 'top_classes': top(classes),
                     'slow_tests': sorted(([k, v] for k, v in slow.items()), key=lambda r: -r[1]),
                     'uniform_classes': sorted(k for k, v in uniform.items() if v * 2 > len(runs))}
    return legs


# --------------------------------------------------------------------- thresholds


def _fmt(value: 'Optional[float]', digits: 'int' = 1) -> 'str':
    return '-' if value is None else f'{value:.{digits}f}'


def non_blocking(workflow: 'str', job: 'str') -> 'bool':
    """Whether ``job``'s cap findings (H1, H2, H4) are warnings rather than HARD.

    Every job of :data:`NON_BLOCKING_WORKFLOWS` is non-blocking (#1732), and so is a
    KTLO leg, wherever it runs.

    """
    return workflow in NON_BLOCKING_WORKFLOWS or job.endswith(KTLO_SUFFIX)


def evaluate(report: 'dict[str, Any]', baseline: 'Optional[dict[str, Any]]') -> 'list[dict[str, str]]':
    """Every HARD (``H*``) and WARN (``W*``) threshold that fires on ``report``.

    A cap finding on a :func:`non_blocking` job keeps its ``H`` id but is a warning.

    """
    found = []  # type: list[dict[str, str]]

    def fire(code: 'str', message: 'str', soft: 'bool' = False) -> 'None':
        if soft:
            message += ' Non-blocking, so a warning (#1732).'
        found.append({'id': code, 'level': 'hard' if code[0] == 'H' and not soft else 'warn',
                      'message': message})

    for row in report['jobs']:
        label = f'`{row["name"]}` ({row["workflow"]})'
        soft = non_blocking(row['workflow'], row['name'])
        if row['n'] >= MIN_SAMPLES and row['p90'] >= HARD_CAP_SHARE * row['cap']:
            fire('H1', f'{label} p90 is {_fmt(row["p90"])} min, at or above '
                       f'{HARD_CAP_SHARE:.0%} of its {row["cap"]}-minute cap.', soft)
        if row.get('days_to_cap') is not None and row['days_to_cap'] <= HARD_PROJECTION_DAYS:
            fire('H4', f'{label} reaches its {row["cap"]}-minute cap in '
                       f'{_fmt(row["days_to_cap"])} days on a linear fit '
                       f'(+{_fmt(row["slope_per_day"], 2)} min/day).', soft)
    for row in report['steps']:
        if not row.get('cap'):
            continue
        label = f'`{row["job"]}` step `{row["name"]}`'
        soft = non_blocking(row['workflow'], row['job'])
        if row['n'] >= MIN_SAMPLES and row['p90'] >= HARD_CAP_SHARE * row['cap']:
            fire('H2', f'{label} p90 is {_fmt(row["p90"])} min, at or above '
                       f'{HARD_CAP_SHARE:.0%} of its {row["cap"]}-minute step cap.', soft)
        if row.get('days_to_cap') is not None and row['days_to_cap'] <= HARD_PROJECTION_DAYS:
            fire('H4', f'{label} reaches its {row["cap"]}-minute step cap in '
                       f'{_fmt(row["days_to_cap"])} days on a linear fit.', soft)

    pr = report['runs'].get('pull_request', {})
    mergeable = pr.get('mergeable', {})
    slow = mergeable.get('n', 0) >= MIN_SAMPLES and mergeable['p90'] >= MERGEABLE_P90
    before = ((baseline or {}).get('runs', {}).get('pull_request', {}).get('mergeable') or {})
    if (slow and before.get('n', 0) >= MIN_SAMPLES and before.get('p90')
            and mergeable['p90'] >= (1 + HARD_MERGEABLE_RISE) * before['p90']):
        fire('H3', f'pull-request time to `{REQUIRED_JOB}` p90 rose from {_fmt(before["p90"])} '
                   f'to {_fmt(mergeable["p90"])} min, at least {HARD_MERGEABLE_RISE:.0%} and over '
                   f'{MERGEABLE_P90:.0f}.')
    elif slow:
        fire('W9', f'pull-request time to `{REQUIRED_JOB}` p90 is {_fmt(mergeable["p90"])} min, '
                   f'at or above {MERGEABLE_P90:.0f}; HARD (H3) only as a rise on the baseline.')
    if mergeable.get('n', 0) >= MIN_SAMPLES and mergeable['median'] > WARN_MERGEABLE_MEDIAN:
        fire('W2', f'pull-request time to mergeable median is {_fmt(mergeable["median"])} min, '
                   f'above {WARN_MERGEABLE_MEDIAN:.0f}.')
    ratio = report['derived'].get('coverage_ratio', {})
    if ratio.get('n', 0) >= MIN_SAMPLES and ratio['median'] > WARN_COVERAGE_RATIO:
        fire('W3', f'`{COVERAGE_JOB}`\'s `{TESTS_STEP}` takes {_fmt(ratio["median"], 2)}x its '
                   f'paired legs\' (median), above {WARN_COVERAGE_RATIO}.')
    for event, limit in WARN_QUEUE_P90.items():
        queue = report['runs'].get(event, {}).get('queue', {})
        if queue.get('n', 0) >= MIN_SAMPLES and queue['p90'] > limit:
            fire('W5', f'{event} run queue p90 is {_fmt(queue["p90"])} min, above {limit:.0f}.')
    superseded = report.get('superseded', {})
    if superseded.get('of', 0) >= MIN_SAMPLES and superseded['share'] > WARN_SUPERSEDED_SHARE:
        fire('W6', f'{superseded["runs"]} of {superseded["of"]} pull-request runs '
                   f'({superseded["share"]:.0%}) were cancelled, above '
                   f'{WARN_SUPERSEDED_SHARE:.0%}; about {_fmt(superseded.get("runner_min"), 0)} '
                   'runner-min.')

    leg = report['tests'].get(MS_PER_TEST_LEG, {})
    heavy = [name for name, seconds in leg.get('top_modules', ()) if seconds > WARN_MODULE_SECONDS]
    if heavy:
        fire('W7', f'{len(heavy)} module(s) over {WARN_MODULE_SECONDS:.0f} s summed on '
                   f'{MS_PER_TEST_LEG}: ' + ', '.join(f'`{name}`' for name in heavy[:5]))
    if leg.get('slow_tests'):
        fire('W7', f'{len(leg["slow_tests"])} test(s) over {WARN_TEST_SECONDS:.0f} s on '
                   f'{MS_PER_TEST_LEG}: ' + ', '.join(f'`{name}`' for name, _ in leg['slow_tests'][:3]))
    if leg.get('uniform_classes'):
        fire('W7', f'{len(leg["uniform_classes"])} class(es) whose every test costs about as much '
                   'as the first, the per-test re-import signature: '
                   + ', '.join(f'`{name}`' for name in leg['uniform_classes'][:5]))

    if baseline:
        before = {(row['workflow'], row['name']): row for row in baseline.get('jobs', ())}
        for row in report['jobs']:
            old = before.get((row['workflow'], row['name']))
            if (old and min(old['n'], row['n']) >= WARN_MEDIAN_SAMPLES and old['median']
                    and row['median'] >= (1 + WARN_MEDIAN_RISE) * old['median']):
                fire('W1', f'`{row["name"]}` ({row["workflow"]}) median rose from '
                           f'{_fmt(old["median"])} to {_fmt(row["median"])} min.')
        old_ms = baseline.get('derived', {}).get('ms_per_test', {}).get('median')
        new_ms = report['derived'].get('ms_per_test', {}).get('median')
        if old_ms and new_ms and new_ms >= (1 + WARN_MS_PER_TEST_RISE) * old_ms:
            fire('W4', f'{MS_PER_TEST_LEG} ms/test rose from {old_ms:.1f} to {new_ms:.1f}.')
        old_top = [name for name, _ in baseline.get('tests', {}).get(MS_PER_TEST_LEG, {})
                   .get('top_modules', ())[:10]]
        new_top = [name for name, _ in leg.get('top_modules', ())[:10]]
        entrants = [name for name in new_top if name not in old_top]
        if old_top and entrants:
            fire('W7', 'new in the top 10 modules: ' + ', '.join(f'`{name}`' for name in entrants))
        for event in ('pull_request', 'push'):
            was = baseline.get('critical_path', {}).get(event, {}).get('leader')
            now = report['critical_path'].get(event, {}).get('leader')
            if was and now and was != now:
                fire('W8', f'the {event} critical path now ends on `{now}`, not `{was}`.')
    return found


# --------------------------------------------------------------------- output


def summary(report: 'dict[str, Any]', findings: 'list[dict[str, str]]') -> 'str':
    """The Markdown the workflow appends to its job summary."""
    window = report['window']
    out = [f'## CI timing, {window["since"][:16]}Z to {window["until"][:16]}Z', '']
    read = window.get('read', {})
    if read:
        out += ['Jobs read for an evenly spaced sample of each workflow\'s completed runs: '
                + '; '.join(f'{name} {row["read"]} of {row["listed"]}'
                            + (f' ({row["first"][:16]}Z to {row["last"][:16]}Z)' if row['first'] else '')
                            for name, row in read.items()) + '.', '']
    for level, title in (('hard', 'HARD'), ('warn', 'WARN')):
        for item in findings:
            if item['level'] == level:
                out.append(f'- **{title} {item["id"]}:** {item["message"]}')
    if not findings:
        out.append('No threshold fired.')
    out += ['', '### Unit Tests runs', '',
            '| Event | Listed | Cancelled | Measured | Queue p50 / p90 | To mergeable p50 / p90 '
            '| Wall p50 / p90 | Runner-min per run | Jobs per run |', '|---|--:|--:|--:|--:|--:|--:|--:|--:|']
    for event, row in report['runs'].items():
        out.append(f'| {event} | {row["listed"]} | {row["cancelled"]} | {row["runs"]} | '
                   f'{_fmt(row["queue"]["median"])} / {_fmt(row["queue"]["p90"])} | '
                   f'{_fmt(row["mergeable"]["median"])} / {_fmt(row["mergeable"]["p90"])} | '
                   f'{_fmt(row["wall"]["median"])} / {_fmt(row["wall"]["p90"])} | '
                   f'{_fmt(row["runner_min"]["median"])} | {_fmt(row["jobs"]["median"], 0)} |')
    superseded = report.get('superseded', {})
    if superseded.get('of'):
        out += ['', f'Superseded (cancelled) pull-request runs: {superseded["runs"]} of '
                    f'{superseded["of"]} ({superseded["share"]:.0%}), about '
                    f'{_fmt(superseded["runner_min"], 0)} runner-min, scaled from the '
                    f'{superseded["read"]} read.']

    jobs = sorted(report['jobs'], key=lambda row: -row['p90_share_of_cap'])[:TABLE_ROWS]
    out += ['', f'### Jobs, by p90 share of cap (top {TABLE_ROWS})', '',
            '| Workflow | Job | n | Median | p90 | Max | Queue p90 | Cap | p90 / cap '
            '| Trend min/day | Days to 50% | Days to cap |', '|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|']
    for row in jobs:
        out.append(f'| {row["workflow"]} | {row["name"]} | {row["n"]} | {_fmt(row["median"])} | '
                   f'{_fmt(row["p90"])} | {_fmt(row["max"])} | {_fmt(row["queue"]["p90"])} | '
                   f'{row["cap"]} | {row["p90_share_of_cap"]:.0%} | {_fmt(row["slope_per_day"], 2)} | '
                   f'{_fmt(row["days_to_half_cap"])} | {_fmt(row["days_to_cap"])} |')

    steps = sorted(report['steps'], key=lambda row: -(row['p90'] or 0))[:TABLE_ROWS]
    out += ['', f'### Steps, by p90 (top {TABLE_ROWS})', '',
            '| Job | Step | n | Median | p90 | Step cap | Days to cap |', '|---|---|--:|--:|--:|--:|--:|']
    for row in steps:
        out.append(f'| {row["job"]} | {row["name"]} | {row["n"]} | {_fmt(row["median"])} | '
                   f'{_fmt(row["p90"])} | {row["cap"] or "-"} | {_fmt(row.get("days_to_cap"))} |')

    out += ['', '### Critical path to `Required checks passed`', '',
            '| Event | Runs | Last to finish | Share | Median slack to runner-up |', '|---|--:|---|--:|--:|']
    for event, row in report['critical_path'].items():
        share = row['shares'].get(row['leader'], 0) if row['leader'] else 0
        out.append(f'| {event} | {row["runs"]} | {row["leader"] or "-"} | {share:.0%} | '
                   f'{_fmt(row["slack_median"])} min |')

    derived = report['derived']
    ratio, per_test = derived['coverage_ratio'], derived['ms_per_test']
    out += ['', '### Derived', '',
            f'- `{COVERAGE_JOB}` `{TESTS_STEP}` over its paired legs: median '
            f'{_fmt(ratio["median"], 2)}x, range {_fmt(ratio["min"], 2)}-{_fmt(ratio["max"], 2)}, '
            f'n={ratio["n"]}.',
            f'- ms per test on {MS_PER_TEST_LEG}: median {_fmt(per_test["median"])}, n={per_test["n"]}.']
    for count in derived['test_counts'][:1]:
        out.append(f'- Tests on {MS_PER_TEST_LEG} (run {count["run_id"]}): {count["tests"]} testcases; '
                   f'the suite\'s `tests=` reads {count["suite_tests"]}, which counts subtests.')

    for leg, row in report['tests'].items():
        out += ['', f'### Tests on {leg}, median of {row["runs"]} push run(s)', '',
                '| Module | Seconds |', '|---|--:|']
        out += [f'| `{name}` | {seconds:.1f} |' for name, seconds in row['top_modules'][:10]]
        out += ['', '| Class | Seconds |', '|---|--:|']
        out += [f'| `{name}` | {seconds:.1f} |' for name, seconds in row['top_classes'][:10]]

    if report.get('concurrency'):
        pool = report['concurrency']
        out += ['', f'Runner pool over the last {pool["hours"]} h: {pool["jobs"]} jobs, peak '
                    f'{pool["peak"]} at once for {pool["seconds_at_peak"]:.0f} s '
                    f'(macOS peak {pool["macos_peak"]}).']
    out += [''] + [f'> {note}' for note in report['notes']]
    calls = report.get('api', {})
    if calls:
        out += ['', f'API calls: {calls["calls"]} (rate limit remaining: {calls["remaining"]}).']
    return '\n'.join(out).rstrip() + '\n'


def main(argv: 'Optional[list[str]]' = None, *, transport: 'Optional[Transport]' = None,
         now: 'Optional[datetime.datetime]' = None,
         clock: 'Callable[[], float]' = time.monotonic) -> 'int':
    """Collect, analyse, evaluate, write. Returns the exit status.

    Progress goes to stderr as it happens, and the report to stdout at the end.

    Args:
        argv: Command-line arguments.
        transport: Replaces the network, for tests.
        now: Replaces the current time, for tests.
        clock: Replaces :func:`time.monotonic`, which ``--budget-minutes`` is
            measured on, for tests.

    """
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY'),
                        help='owner/name (default: $GITHUB_REPOSITORY)')
    parser.add_argument('--days', type=float, default=7, help='window length (default: 7)')
    parser.add_argument('--runs', type=int, default=150,
                        help='Unit Tests runs per event whose jobs are read (default: 150)')
    parser.add_argument('--other-runs', type=int, default=60,
                        help='runs per other workflow whose jobs are read (default: 60)')
    parser.add_argument('--junit-runs', type=int, default=JUNIT_RUNS,
                        help=f'push runs whose JUnit artifacts are read (default: {JUNIT_RUNS})')
    parser.add_argument('--concurrency-hours', type=float, default=0,
                        help='measure the runner pool over this many hours (default: 0, off)')
    parser.add_argument('--baseline', help='the previous report.json; a missing file means none')
    parser.add_argument('--out', help='write report.json here')
    parser.add_argument('--summary', help='write the Markdown summary here')
    parser.add_argument('--max-calls', type=int, default=DEFAULT_MAX_CALLS,
                        help=f'API call budget (default: {DEFAULT_MAX_CALLS})')
    parser.add_argument('--budget-minutes', type=float, default=DEFAULT_BUDGET_MINUTES,
                        help='read no further jobs after this many minutes, and report on what '
                             f'was read (default: {DEFAULT_BUDGET_MINUTES})')
    args = parser.parse_args(argv)

    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if not args.repo or not (token or transport):
        _actions.annotate('error', 'Needs --repo (or $GITHUB_REPOSITORY) and a token in $GH_TOKEN or $GITHUB_TOKEN.',
                          title='CI timing')
        return EXIT_API

    client = Client(token or '', transport=transport, max_calls=args.max_calls)
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    # Neither failure is a threshold, and each says so, so that a failed run is not
    # read as a slow CI: 1 is reserved for a HARD finding.
    try:
        try:
            data = collect(client, args.repo, now=moment, days=args.days, runs=args.runs,
                           other_runs=args.other_runs, junit_runs=args.junit_runs,
                           concurrency_hours=args.concurrency_hours,
                           budget=args.budget_minutes * 60, clock=clock,
                           progress=lambda line: print(line, file=sys.stderr, flush=True))
        except (BudgetExceeded, OSError) as error:
            _actions.annotate('error', f'{error}. No threshold was evaluated.',
                              title='CI timing could not read the API', escape=False)
            return EXIT_API
        return _report(args, client, data)
    except Exception:  # pylint: disable=broad-except
        traceback.print_exc()
        _actions.annotate('error', 'See the traceback above. No threshold was evaluated.', title='CI timing crashed')
        return EXIT_CRASH


def _report(args: 'argparse.Namespace', client: 'Client', data: 'dict[str, Any]') -> 'int':
    """Analyse, evaluate and write what :func:`collect` read; returns the exit status."""
    report = analyse(data)
    report['api'] = {'calls': client.calls, 'remaining': client.rate_remaining}

    baseline = None
    if args.baseline and os.path.isfile(args.baseline):
        with open(args.baseline, encoding='utf-8') as file:
            baseline = json.load(file)
    elif args.baseline:
        report['notes'].append(f'No baseline at {args.baseline}, so H3, W1, W4, W7\'s new '
                               'entrants and W8 were not evaluated.')
    findings = evaluate(report, baseline)
    report['findings'] = findings

    text = summary(report, findings)
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as file:
            json.dump(report, file, indent=1, sort_keys=True)
    if args.summary:
        with open(args.summary, 'w', encoding='utf-8') as file:
            file.write(text)
    print(text)
    if data.get('stopped'):
        _actions.annotate('warning', data['stopped'], title='CI timing stopped early', escape=False)
    for item in findings:
        kind = 'error' if item['level'] == 'hard' else 'warning'
        message = item['message'].replace('`', '').replace('%', '%25')
        _actions.annotate(kind, message, title=f'CI timing {item["id"]}', escape=False)
    return EXIT_HARD if any(item['level'] == 'hard' for item in findings) else 0


if __name__ == '__main__':
    sys.exit(main())
