# -*- coding: utf-8 -*-
"""Tests for :file:`util/ci_timing.py`, the weekly CI timing review, and its inputs.

GitHub issue #1538 added the review and the per-test timings it reads. These are
checked, offline, since this tier has no network and no token:

* :class:`TestArithmetic` and :class:`TestWorkflowText` -- the quantiles, the
  projection to a cap, and the indentation reader the caps come from, on the real
  workflow files as well as on the excerpt below.
* :class:`TestClient`, :class:`TestEndToEnd` and the classes after it -- the script
  against a fake API serving the fixtures in :file:`tests/project/ci_timing_fixtures/`,
  and its :mod:`requests` transport (#1894) against servers on ``127.0.0.1``.
  :class:`TestStrictJUnit` checks the hardened lxml parser the JUnit artifacts
  are read with (#1894); it and what reads an artifact skip without lxml.
  The run listing and the job listings are real responses from 2026-10-05 and
  2026-10-09, trimmed to the fields the script reads; run 37323913186 is the push
  run that reads ``cancelled`` because its ``protocols`` ordering job hit the 45-minute
  cap. ``artifacts-37998639834.json`` is that push run's real listing with two
  **synthetic** entries added, ``junit-unit-3.13`` and an expired ``junit-unit-3.14``:
  the run predates the upload, so it has no JUnit artifact of its own.
  ``junit-unit-3.13.xml`` is hand-written in pytest's JUnit format, with times chosen
  to trip the test-level checks, and the workflow file is an excerpt. Expected
  figures are re-derived from the fixtures here rather than restated.
* :class:`TestThresholds` -- every threshold, at its boundary, on a report held
  just short of all of them.
* :class:`TestTimingArtifacts` and :class:`TestReviewWorkflow` -- what the script
  relies on in :file:`unit-tests.yml` (artifact names, the coverage leg, upload
  steps that cannot fail a required leg) and the review workflow's own triggers and
  permissions, which have to stay read-only.

"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import http.server
import importlib.util
import io
import json
import os
import pathlib
import re
import statistics
import tempfile
import threading
import unittest
import urllib.parse
import zipfile
from unittest import mock

import requests

from tests import _workflows
from tests.project.test_python_versions_1660 import NO_TOMLLIB
from tests.project.test_python_versions_1660 import legs as matrix_legs
from tests.project.test_python_versions_1660 import matrix, tomllib

# util/ci_timing.py reads .github/python-versions.toml with tomllib on import
# (#1660), and runs on ``latest`` only (ci-timing.yml); on 3.8-3.10 nothing here can.
if tomllib is None:
    raise unittest.SkipTest(NO_TOMLLIB)

#: Whether lxml, which the script parses JUnit with (#1894), is installed. The
#: test extra installs it everywhere but GraalPy, which has no wheel; with no
#: laxer parser to fall back to, what reads a JUnit artifact skips there.
HAS_LXML = importlib.util.find_spec('lxml') is not None
NO_LXML = 'lxml, from the test extra, is not installed'

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = pathlib.Path(__file__).resolve().parent / 'ci_timing_fixtures'
WORKFLOWS = ROOT / '.github' / 'workflows'
UNIT_TESTS = WORKFLOWS / 'unit-tests.yml'
REVIEW = WORKFLOWS / 'ci-timing.yml'
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'

REPO = 'JarryShaw/PyPCAPKit'
NOW = datetime.datetime(2026, 10, 10, tzinfo=datetime.timezone.utc)
#: Where the real ``Link`` header points a run listing's next page: at the
#: repository by id, not by name.
LINK_ROOT = 'https://api.github.com/repositories/109791841/actions/workflows/unit-tests.yml/runs'
#: Runs per fake page, small so the paging is exercised.
PAGE = 2
PR_RUN, CANCELLED_RUN, PUSH_RUN, TIMEOUT_RUN = 38001768735, 38002005234, 37998639834, 37323913186
#: The coverage leg, and the legs paired with it, when the fixtures were recorded.
#: #1661 moved coverage to 3.15, which no fixture run has.
FIXTURE_COVERAGE_JOB = 'Python 3.14'
FIXTURE_PAIRED_JOBS = ('Python 3.11', 'Python 3.12', 'Python 3.13')
JUNIT_ARTIFACT_ID = 11648726901
#: The day slices a 7-day window ending at :data:`NOW` is listed in.
SLICES = [f'2026-10-{day:02d}T00:00:00Z..2026-10-{day:02d}T23:59:59Z' for day in range(9, 2, -1)]


def _load_script():
    """Load :file:`util/ci_timing.py`, which is a script and not a package."""
    spec = importlib.util.spec_from_file_location('ci_timing', ROOT / 'util' / 'ci_timing.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci_timing = _load_script()


def fixture(name: 'str') -> 'bytes':
    return (FIXTURES / name).read_bytes()


def jobs_of(run_id: 'int') -> 'list[dict]':
    return json.loads(fixture(f'jobs-{run_id}.json'))['jobs']


def all_runs() -> 'list[dict]':
    return json.loads(fixture('runs-unit-tests.json'))['workflow_runs']


def stamp(value: 'str') -> 'datetime.datetime':
    """An API timestamp, parsed here independently of the script's own parser."""
    return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')


def span(start: 'str', end: 'str') -> 'float':
    return (stamp(end) - stamp(start)).total_seconds() / 60


def http_error(url: 'str', status: 'int') -> 'requests.HTTPError':
    """The error the script's transport raises for an error status."""
    response = requests.Response()
    response.status_code, response.url = status, url
    return requests.HTTPError(f'{status} Error for url: {url}', response=response)


class FakeAPI:
    """Serves the fixtures by URL, recording every request.

    Args:
        inflate: Added to every listing's ``total_count``, to model the API's
            1,000-run cap on a filtered listing.
        broken: Request paths whose body is replaced by bytes no parser accepts.

    """

    def __init__(self, inflate: 'int' = 0, broken: 'tuple[str, ...]' = ()) -> 'None':
        self.requests = []  # type: list[tuple[str, str]]
        self.inflate = inflate
        self.broken = broken

    def __call__(self, url: 'str', accept: 'str') -> 'tuple[bytes, dict[str, str]]':
        self.requests.append((url, accept))
        parts = urllib.parse.urlsplit(url)
        path, query = parts.path, urllib.parse.parse_qs(parts.query)
        if any(path.endswith(end) for end in self.broken):
            return b'\x00 neither JSON nor a zip archive', {}
        if path.endswith('/actions/workflows/unit-tests.yml/runs'):
            return self.listing(all_runs(), query)
        if path.endswith('/runs') and '/actions/workflows/' in path:
            return self.listing([], query)
        match = re.search(r'/actions/runs/(\d+)/(attempts/1/jobs|artifacts)$', path)
        if match:
            kind = 'jobs' if match.group(2).endswith('jobs') else 'artifacts'
            return fixture(f'{kind}-{match.group(1)}.json'), {'x-ratelimit-remaining': '4321'}
        if path.endswith(f'/actions/artifacts/{JUNIT_ARTIFACT_ID}/zip'):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                archive.writestr('junit.xml', fixture('junit-unit-3.13.xml'))
            return buffer.getvalue(), {}
        if '/contents/.github/workflows/unit-tests.yml' in path:
            assert accept == 'application/vnd.github.raw+json', accept
            return fixture('workflow-unit-tests.yml'), {}
        raise http_error(url, 404)

    def listing(self, runs: 'list[dict]', query: 'dict[str, list[str]]') -> 'tuple[bytes, dict[str, str]]':
        """The runs created inside the query's inclusive ``A..B`` range, a page at a time."""
        if 'created' in query:
            low, high = query['created'][0].split('..')
            runs = [run for run in runs if low <= run['created_at'] <= high]
        page = int(query.get('page', ['1'])[0])
        headers = {}
        if page * PAGE < len(runs):
            rest = {key: value[0] for key, value in query.items() if key != 'page'}
            headers['link'] = f'<{LINK_ROOT}?{urllib.parse.urlencode({**rest, "page": page + 1})}>; rel="next"'
        body = {'total_count': len(runs) + self.inflate, 'workflow_runs': runs[(page - 1) * PAGE:page * PAGE]}
        return json.dumps(body).encode(), headers


def run_main(*argv: 'str', api: 'FakeAPI', baseline: 'Optional[dict]' = None,
             stderr: 'Optional[io.StringIO]' = None, **options: 'Any') -> 'tuple[int, str, dict, str]':
    """``main`` against ``api``; returns the status, stdout, report.json and report.md.

    ``stderr``, if given, receives the progress lines; ``options`` go to ``main``.

    """
    with tempfile.TemporaryDirectory() as tmp:
        out, md = os.path.join(tmp, 'report.json'), os.path.join(tmp, 'report.md')
        before = os.path.join(tmp, 'baseline.json')
        if baseline is not None:
            pathlib.Path(before).write_text(json.dumps(baseline), encoding='utf-8')
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr or io.StringIO()):
            status = ci_timing.main(['--repo', REPO, '--out', out, '--summary', md,
                                     '--baseline', before, *argv], transport=api, now=NOW, **options)
        report = json.loads(pathlib.Path(out).read_text(encoding='utf-8')) if os.path.exists(out) else {}
        text = pathlib.Path(md).read_text(encoding='utf-8') if os.path.exists(md) else ''
    return status, stdout.getvalue(), report, text


class TestArithmetic(unittest.TestCase):
    """The statistics every threshold is judged on."""

    def test_quantile_interpolates_between_ranks(self) -> 'None':
        values = [float(v) for v in range(1, 11)]
        self.assertAlmostEqual(ci_timing.quantile(values, 0.9), 9.1)
        self.assertAlmostEqual(ci_timing.quantile(values, 0.5), 5.5)
        self.assertEqual(ci_timing.quantile([3.0], 0.9), 3.0)
        self.assertIsNone(ci_timing.quantile([], 0.5))

    def test_projection_reaches_the_cap_on_the_fitted_line(self) -> 'None':
        # 1 min/day from 10 min at day 0 to 12 min at day 2: 33 days to 45.
        points = [(day / 5, 10 + day / 5) for day in range(11)]
        fit = ci_timing.projection(points, 45)
        self.assertAlmostEqual(fit['slope_per_day'], 1.0)
        self.assertAlmostEqual(fit['days_to_cap'], 33.0)
        self.assertAlmostEqual(fit['days_to_half_cap'], 10.5)

    def test_projection_refuses_thin_or_flat_data(self) -> 'None':
        rising = [(day / 5, 10 + day / 5) for day in range(11)]
        self.assertIsNone(ci_timing.projection(rising[:ci_timing.MIN_FIT_SAMPLES - 1], 45)['days_to_cap'])
        narrow = [(day / 100, 10 + day) for day in range(20)]
        self.assertIsNone(ci_timing.projection(narrow, 45)['slope_per_day'])
        falling = [(day / 5, 20 - day / 5) for day in range(11)]
        self.assertIsNone(ci_timing.projection(falling, 45)['days_to_cap'])
        over = [(day / 5, 50 - day / 5) for day in range(11)]
        self.assertEqual(ci_timing.projection(over, 45)['days_to_cap'], 0.0)


class TestWorkflowText(unittest.TestCase):
    """The caps and ``needs:`` the script reads off the workflow files."""

    def test_the_excerpt(self) -> 'None':
        specs = ci_timing.parse_workflow(fixture('workflow-unit-tests.yml').decode())
        by_id = {spec['id']: spec for spec in specs}
        self.assertEqual(by_id['test']['timeout'], 45)
        self.assertEqual(by_id['required-checks']['needs'],
                         ['changes', 'test', 'integration', 'project-tests'])
        ordering = ci_timing.match_job(specs, 'Plain unittest ordering (protocols (rest))')
        self.assertEqual(ordering['id'], 'unittest-ordering')
        self.assertEqual(ci_timing.step_cap(
            ordering, 'Run tests/protocols and the root-level modules under plain unittest'), 20)
        self.assertIsNone(ci_timing.match_job(specs, 'Lint'))

    def test_the_real_unit_tests_workflow(self) -> 'None':
        """The job names the script keys on exist, so its tables are not empty."""
        specs = ci_timing.parse_workflow(UNIT_TESTS.read_text(encoding='utf-8'))
        required = ci_timing.match_job(specs, ci_timing.REQUIRED_JOB)
        self.assertIsNotNone(required)
        self.assertIn('test', required['needs'])
        for name in (ci_timing.COVERAGE_JOB,) + ci_timing.PAIRED_JOBS:
            with self.subTest(job=name):
                self.assertEqual(ci_timing.match_job(specs, name)['id'], 'test')
        test = next(spec for spec in specs if spec['id'] == 'test')
        self.assertIn(ci_timing.TESTS_STEP, [step['name'] for step in test['steps']])
        ordering = ci_timing.match_job(specs, 'Plain unittest ordering (protocols (rest))')
        self.assertEqual(ci_timing.step_cap(
            ordering, 'Run tests/protocols and the root-level modules under plain unittest'), 20)
        caps = {spec['id']: spec['timeout'] for spec in specs}
        self.assertEqual((caps['test'], caps['integration'], caps['engine-tests']), (45, 45, 30))
        # #1732: the experimental legs are experimental.yml's, with caps of their own.
        self.assertIsNone(ci_timing.step_cap(test, ci_timing.TESTS_STEP))
        self.assertNotIn('experimental', [spec['id'] for spec in specs])
        own = ci_timing.parse_workflow((WORKFLOWS / 'experimental.yml').read_text(encoding='utf-8'))
        for name in ('Python graalpy-25.4 (experimental)', 'Python 3.14t (experimental)'):
            with self.subTest(job=name):
                experimental = ci_timing.match_job(own, name)
                self.assertEqual((experimental['id'], experimental['timeout'],
                                  ci_timing.step_cap(experimental, ci_timing.TESTS_STEP)), ('experimental', 140, 120))

    def test_every_step_of_interest_names_a_real_step(self) -> 'None':
        """#2230: each alternative of :data:`STEPS_OF_INTEREST` matches a step some workflow has.

        A pattern, or one alternative of a ``(?:...)`` group in it, that no step
        matches is dead, and makes the steps reported look wider than they are.

        """
        names = {step['name'] for path in sorted(WORKFLOWS.glob('*.yml'))
                 for spec in ci_timing.parse_workflow(path.read_text(encoding='utf-8'))
                 for step in spec['steps']}
        self.assertTrue(names)
        for pattern in ci_timing.STEPS_OF_INTEREST:
            groups = list(re.finditer(r'\(\?:([^()]*)\)', pattern))
            # Only a group's alternatives are split out, so a bare one would go unchecked.
            self.assertNotIn('|', re.sub(r'\(\?:[^()]*\)', '', pattern), pattern)
            variants = [pattern[:group.start()] + option + pattern[group.end():]
                        for group in groups for option in group.group(1).split('|')] or [pattern]
            for variant in variants:
                with self.subTest(pattern=pattern, alternative=variant):
                    self.assertTrue([name for name in names if re.fullmatch(variant, name)])

    def test_a_cap_by_leg_reads_as_none(self) -> 'None':
        """An expression is no one cap; a literal beside it still reads."""
        specs = ci_timing.parse_workflow(
            'jobs:\n  test:\n    timeout-minutes: 45\n    steps:\n'
            '      - name: Run unit tests\n        timeout-minutes: ${{ matrix.experimental && 25 || 360 }}\n'
            '      - name: Report coverage\n        timeout-minutes: 15\n')
        self.assertEqual([(step['name'], step['timeout']) for step in specs[0]['steps']],
                         [('Run unit tests', None), ('Report coverage', 15)])

    def test_every_other_workflow_reads(self) -> 'None':
        """Including CodeQL's four-space step list, and a literal name over a template."""
        for workflow in ci_timing.OTHER_WORKFLOWS:
            with self.subTest(workflow=workflow):
                self.assertTrue(ci_timing.parse_workflow((WORKFLOWS / workflow).read_text(encoding='utf-8')))
        codeql = ci_timing.parse_workflow((WORKFLOWS / 'codeql-analysis.yml').read_text(encoding='utf-8'))
        self.assertTrue(codeql[0]['steps'])
        compat = ci_timing.parse_workflow((WORKFLOWS / 'python-compatibility.yml').read_text(encoding='utf-8'))
        self.assertEqual(ci_timing.match_job(compat, 'Compat Python 3.10 (KTLO)')['id'],
                         'compatibility')
        self.assertEqual(ci_timing.match_job(compat, 'Compat Python 3.12')['id'], 'compatibility')
        # #1633 retired the literal ``Compat Python 3.15 (scheduled)`` job this used
        # to read, so the literal-over-template rule is checked on a stand-in.
        both = ci_timing.parse_workflow(
            'jobs:\n  matrixed:\n    name: Compat Python ${{ matrix.python-version }}\n'
            '  pinned:\n    name: Compat Python 3.15 (scheduled)\n')
        self.assertEqual(ci_timing.match_job(both, 'Compat Python 3.15 (scheduled)')['id'], 'pinned')
        self.assertEqual(ci_timing.match_job(both, 'Compat Python 3.12')['id'], 'matrixed')


class TestClient(unittest.TestCase):
    """Paging, the call budget, retries, and where the token goes."""

    def test_paging_follows_the_link_header_verbatim(self) -> 'None':
        api = FakeAPI()
        client = ci_timing.Client('t', transport=api)
        runs = list(client.paginate(f'/repos/{REPO}/actions/workflows/unit-tests.yml/runs',
                                    'workflow_runs', status='completed'))
        self.assertEqual([run['id'] for run in runs], [CANCELLED_RUN, PR_RUN, PUSH_RUN, TIMEOUT_RUN])
        self.assertTrue(api.requests[1][0].startswith(f'{LINK_ROOT}?'), api.requests[1][0])
        self.assertEqual(client.calls, 2)

    def test_the_budget_stops_the_run(self) -> 'None':
        client = ci_timing.Client('t', transport=FakeAPI(), max_calls=1)
        with self.assertRaises(ci_timing.BudgetExceeded):
            list(client.paginate(f'/repos/{REPO}/actions/workflows/unit-tests.yml/runs', 'workflow_runs'))

    def test_a_server_error_is_retried_and_a_client_error_is_not(self) -> 'None':
        """A requests ``HTTPError`` is an ``OSError`` too, so its status decides, not its type."""
        replies = [http_error('u', 502), requests.ConnectionError('connection reset'),
                   (b'{"ok": 1}', {})]

        def flaky(url: 'str', accept: 'str') -> 'tuple[bytes, dict[str, str]]':
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        waits = []  # type: list[float]
        client = ci_timing.Client('t', transport=flaky, sleep=waits.append)
        self.assertEqual(client.get('/x'), {'ok': 1})
        self.assertEqual((client.calls, waits), (3, list(ci_timing.RETRY_WAITS)))
        missing = ci_timing.Client('t', transport=FakeAPI(), sleep=waits.append)
        with self.assertRaises(requests.HTTPError):
            missing.get('/nowhere')
        self.assertEqual(missing.calls, 1)

    def test_the_link_header_is_read_as_requests_reads_it(self) -> 'None':
        """GitHub's own shape: every relation in one header, ``next`` among them."""
        first = 'https://api.github.com/repositories/1/actions/runs?page=1'
        header = (f'<{first.replace("1", "2", 1)}>; rel="prev", <{LINK_ROOT}?page=3>; rel="next", '
                  f'<{LINK_ROOT}?page=9>; rel="last", <{first}>; rel="first"')
        self.assertEqual(ci_timing.next_link(header), f'{LINK_ROOT}?page=3')
        self.assertIsNone(ci_timing.next_link(f'<{first}>; rel="first"'))
        self.assertIsNone(ci_timing.next_link(''))


class _Recorder(http.server.BaseHTTPRequestHandler):
    """Records each request's headers on its server and answers from ``server.reply``."""

    def do_GET(self) -> 'None':  # noqa: N802 -- the name http.server calls
        self.server.seen.append((self.path, dict(self.headers.items())))  # type: ignore[attr-defined]
        status, headers, body = self.server.reply(self.path)  # type: ignore[attr-defined]
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: 'str', *args: 'object') -> 'None':  # pylint: disable=redefined-builtin
        """Quiet: the test reads what it needs from ``server.seen``."""


def local_server(case: 'unittest.TestCase', reply: 'Any') -> 'Any':
    """A :class:`_Recorder` server on ``127.0.0.1`` answering ``reply(path)``, shut down after ``case``."""
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Recorder)
    server.seen = []  # type: ignore[attr-defined]
    server.reply = reply  # type: ignore[attr-defined]
    server.root = f'http://127.0.0.1:{server.server_address[1]}'  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    case.addCleanup(thread.join, 30)
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


class TestTransport(unittest.TestCase):
    """The default transport, :mod:`requests`, against servers on ``127.0.0.1`` (#1894).

    :meth:`Client.fetch` refuses anything but https, so these call the transport
    itself, which is what ``fetch`` calls.

    """

    def serve(self, reply: 'Any') -> 'str':
        """A server answering with ``reply(path)``; its root URL."""
        server = local_server(self, reply)
        self.servers.append(server)
        return server.root

    def setUp(self) -> 'None':
        self.servers = []  # type: list[Any]
        self.client = ci_timing.Client('secret')
        # No proxy between the test and its own servers, whatever the host has set.
        proxies = mock.patch.dict(os.environ, {'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'})
        proxies.start()
        self.addCleanup(proxies.stop)

    def test_a_reply_is_the_body_and_the_lower_cased_headers(self) -> 'None':
        root = self.serve(lambda path: (200, {'Link': '<https://next>; rel="next"',
                                              'X-RateLimit-Remaining': '7'}, b'{"ok": 1}'))
        body, headers = self.client.transport(f'{root}/x', 'application/vnd.github+json')
        self.assertEqual(body, b'{"ok": 1}')
        self.assertEqual((headers['link'], headers['x-ratelimit-remaining']), ('<https://next>; rel="next"', '7'))
        _, sent = self.servers[0].seen[0]
        self.assertEqual((sent['Accept'], sent['Authorization'], sent['User-Agent']),
                         ('application/vnd.github+json', 'Bearer secret', 'PyPCAPKit-ci-timing'))

    def test_an_error_status_raises_requests_httperror_with_the_status(self) -> 'None':
        """What :meth:`Client.fetch` retries on, and :func:`collect` reads a 404 from."""
        root = self.serve(lambda path: (404, {}, b'{"message": "Not Found"}'))
        with self.assertRaises(requests.HTTPError) as caught:
            self.client.transport(f'{root}/nowhere', 'application/vnd.github+json')
        self.assertEqual(ci_timing.status_of(caught.exception), 404)

    def test_the_token_is_not_forwarded_on_a_redirect(self) -> 'None':
        """An artifact download redirects to blob storage, which must not see it.

        The second server is another origin, as blob storage is another host;
        requests compares the port as well as the host.

        """
        blob = self.serve(lambda path: (200, {}, b'PK zip bytes'))
        api = self.serve(lambda path: (302, {'Location': f'{blob}/artifact.zip'}, b''))
        body, _ = self.client.transport(f'{api}/actions/artifacts/1/zip', 'application/vnd.github+json')
        self.assertEqual(body, b'PK zip bytes')
        (_, to_api), = self.servers[1].seen
        (path, to_blob), = self.servers[0].seen
        self.assertEqual(path, '/artifact.zip')
        self.assertEqual(to_api.get('Authorization'), 'Bearer secret')
        self.assertNotIn('Authorization', to_blob)

    def test_one_session_serves_every_call(self) -> 'None':
        root = self.serve(lambda path: (200, {}, b'{}'))
        self.client.transport(f'{root}/a', 'application/vnd.github+json')
        session = self.client.session
        self.client.transport(f'{root}/b', 'application/vnd.github+json')
        self.assertIsInstance(session, requests.Session)
        self.assertIs(self.client.session, session)


@unittest.skipUnless(HAS_LXML, NO_LXML)
class TestStrictJUnit(unittest.TestCase):
    """#1894: JUnit is parsed by lxml with a hardened parser, not by ElementTree."""

    CASE = b'<testcase classname="tests.a.TestA" name="test_a" time="0.5"/>'
    PARSED = [('tests.a.TestA', 'test_a', 0.5)]

    def setUp(self) -> 'None':
        from lxml import etree  # pylint: disable=import-outside-toplevel
        self.etree = etree

    def test_malformed_xml_is_refused(self) -> 'None':
        with self.assertRaises(self.etree.XMLSyntaxError):
            ci_timing.parse_junit(b'<testsuite tests="1"><testcase classname="c" name="n"></testsuite>')

    def test_nesting_past_the_depth_limit_is_refused(self) -> 'None':
        """``huge_tree=False`` keeps libxml2's limit on depth; ElementTree has none."""
        deep = b'<testsuite tests="1">' + b'<properties>' * 300 + b'</properties>' * 300 + self.CASE + b'</testsuite>'
        with self.assertRaisesRegex(self.etree.XMLSyntaxError, 'depth'):
            ci_timing.parse_junit(deep)

    def test_an_entity_is_neither_expanded_nor_read(self) -> 'None':
        """An internal one stays an entity node, and one naming a file or a URL is never opened.

        ElementTree expands the internal one, and refuses the document over the
        external ones; neither is what this asks of the parser.

        """
        server = local_server(self, lambda path: (200, {}, b'FETCHED'))
        with tempfile.TemporaryDirectory() as tmp:
            canary = pathlib.Path(tmp) / 'canary.txt'
            canary.write_text('READ', encoding='utf-8')
            document = (f'<!DOCTYPE testsuite [<!ENTITY inner "INJECTED">'
                        f'<!ENTITY outer SYSTEM "{canary.as_uri()}">'
                        f'<!ENTITY remote SYSTEM "{server.root}/remote.xml">]>'
                        '<testsuite tests="1"><testcase classname="tests.a.TestA" name="test_a" time="0.5">'
                        '&inner;&outer;&remote;</testcase></testsuite>').encode('utf-8')
            root = ci_timing.parse_xml(document)
            self.assertEqual(ci_timing.parse_junit(document), {'cases': self.PARSED, 'suite_tests': 1})
        case = root.find('testcase')
        self.assertIsNone(case.text)
        self.assertEqual([(child.tag is self.etree.Entity, child.name) for child in case],
                         [(True, 'inner'), (True, 'outer'), (True, 'remote')])
        text = self.etree.tostring(root)
        for marker in (b'INJECTED', b'READ', b'FETCHED'):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, text)
        self.assertEqual(server.seen, [])

    def test_an_attribute_naming_an_external_entity_is_refused(self) -> 'None':
        """An attribute cannot hold an entity node, so libxml2 refuses it rather than read the file."""
        document = (b'<!DOCTYPE testsuite [<!ENTITY outer SYSTEM "file:///nonexistent/canary.txt">]>'
                    b'<testsuite tests="1"><testcase classname="c" name="&outer;" time="1"/></testsuite>')
        with self.assertRaisesRegex(self.etree.XMLSyntaxError, 'external entity'):
            ci_timing.parse_junit(document)

    def test_comments_and_instructions_change_nothing(self) -> 'None':
        """lxml's ``iter()`` yields them, but ``iter('testcase')`` and ``findall`` do not."""
        plain = b'<testsuites><testsuite tests="2">' + self.CASE + b'</testsuite></testsuites>'
        noisy = (b'<?xml version="1.0" encoding="utf-8"?><!-- a --><testsuites><!-- b --><?pi x?>'
                 b'<testsuite tests="2"><!-- c -->' + self.CASE + b'<?pi y?></testsuite><!-- d --></testsuites>')
        alone = b'<testsuite tests="2"><!-- c -->' + self.CASE + b'</testsuite>'
        expected = {'cases': self.PARSED, 'suite_tests': 2}
        for label, document in (('plain', plain), ('noisy', noisy), ('a bare testsuite', alone)):
            with self.subTest(label):
                self.assertEqual(ci_timing.parse_junit(document), expected)


def counted(job: 'dict', cap: 'float') -> 'bool':
    """Whether a job is measured, by its own outcome: finished, or killed at its cap."""
    if not job['runner_name']:
        return False
    if job['conclusion'] in ('success', 'failure'):
        return True
    return job['conclusion'] == 'cancelled' and span(job['started_at'], job['completed_at']) >= 0.95 * cap


@unittest.skipUnless(HAS_LXML, NO_LXML)
class TestEndToEnd(unittest.TestCase):
    """``main`` over the recorded fixtures, the JUnit artifact included."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.api = FakeAPI()
        # One or two runs per event in the fixtures, so the sample floor comes down.
        with mock.patch.object(ci_timing, 'MIN_SAMPLES', 1), \
                mock.patch.object(ci_timing, 'COVERAGE_JOB', FIXTURE_COVERAGE_JOB), \
                mock.patch.object(ci_timing, 'PAIRED_JOBS', FIXTURE_PAIRED_JOBS):
            cls.status, cls.stdout, cls.report, cls.summary = run_main(api=cls.api)

    def ids(self) -> 'list[str]':
        return [item['id'] for item in self.report['findings']]

    def test_a_timed_out_job_in_a_cancelled_run_is_measured(self) -> 'None':
        """Run 37323913186 reads ``cancelled`` only because this job hit its 45-minute cap."""
        run = next(run for run in all_runs() if run['id'] == TIMEOUT_RUN)
        job = next(job for job in jobs_of(TIMEOUT_RUN) if job['name'] == 'Plain unittest ordering (protocols)')
        self.assertEqual((run['conclusion'], job['conclusion']), ('cancelled', 'cancelled'))
        took = span(job['started_at'], job['completed_at'])
        self.assertGreaterEqual(took, 0.95 * 45)
        row = next(row for row in self.report['jobs'] if row['name'] == job['name'])
        self.assertEqual(row['n'], 1)
        self.assertAlmostEqual(row['max'], took)
        # The step running at the timeout was cut off by the job's cap, so it counts too.
        cut = next(s for s in job['steps'] if s['name'].startswith('Run tests/'))
        step = next(row for row in self.report['steps']
                    if row['job'] == job['name'] and row['name'] == cut['name'])
        self.assertEqual(cut['conclusion'], 'cancelled')
        self.assertAlmostEqual(step['max'], span(cut['started_at'], cut['completed_at']))
        self.assertIn('H1', self.ids())
        self.assertIn('::error title=CI timing H1::', self.stdout)
        self.assertEqual(self.status, ci_timing.EXIT_HARD)

    def test_a_superseded_job_is_not_measured(self) -> 'None':
        """The cancelled pull-request run's ``Python 3.14`` stopped at 6 minutes, not at its cap."""
        stopped = next(job for job in jobs_of(CANCELLED_RUN) if job['name'] == 'Python 3.14')
        self.assertFalse(counted(stopped, 45))
        legs = [job for run in (PR_RUN, CANCELLED_RUN, PUSH_RUN, TIMEOUT_RUN) for job in jobs_of(run)
                if job['name'] == 'Python 3.14' and counted(job, 45)]
        row = next(row for row in self.report['jobs'] if row['name'] == 'Python 3.14')
        self.assertEqual((row['n'], row['cap']), (len(legs), 45))
        self.assertEqual(row['n'], 3)
        self.assertAlmostEqual(row['max'], max(span(job['started_at'], job['completed_at']) for job in legs))
        self.assertAlmostEqual(row['p90_share_of_cap'], row['p90'] / 45)

    def test_without_a_baseline_a_slow_queue_only_warns(self) -> 'None':
        """Created 22:55:11, ``Required checks passed`` done 23:35:00: W9, not H3."""
        required = next(job for job in jobs_of(PR_RUN) if job['name'] == ci_timing.REQUIRED_JOB)
        want = span('2026-10-09T22:55:11Z', required['completed_at'])
        self.assertAlmostEqual(self.report['runs']['pull_request']['mergeable']['median'], want)
        self.assertGreaterEqual(want, ci_timing.MERGEABLE_P90)
        self.assertIn('W9', self.ids())
        self.assertNotIn('H3', self.ids())

    def test_a_regression_on_the_baseline_is_hard(self) -> 'None':
        before = {'runs': {'pull_request': {'mergeable': {'n': 1, 'p90': 20.0}}}}
        with mock.patch.object(ci_timing, 'MIN_SAMPLES', 1):
            _, stdout, report, _ = run_main(api=FakeAPI(), baseline=before)
        ids = [item['id'] for item in report['findings']]
        self.assertIn('H3', ids)
        self.assertNotIn('W9', ids)
        self.assertIn('::error title=CI timing H3::', stdout)

    def test_counts_come_from_the_whole_listing(self) -> 'None':
        runs = self.report['runs']
        self.assertEqual([runs['pull_request'][key] for key in ('listed', 'cancelled', 'runs')], [2, 1, 1])
        # The timed-out push run is measured; only a superseded run is not.
        self.assertEqual([runs['push'][key] for key in ('listed', 'cancelled', 'runs')], [2, 1, 2])
        superseded = self.report['superseded']
        self.assertEqual((superseded['runs'], superseded['of'], superseded['read']), (1, 2, 1))
        # The never-started ``Python 3.10`` (empty runner_name, 25 minutes queued)
        # is not runner time.
        self.assertTrue(any(not job['runner_name'] for job in jobs_of(CANCELLED_RUN)))
        self.assertAlmostEqual(superseded['runner_min'], sum(
            span(job['started_at'], job['completed_at']) for job in jobs_of(CANCELLED_RUN) if job['runner_name']))

    def test_skipped_jobs_are_dropped(self) -> 'None':
        names = {row['name'] for row in self.report['jobs']}
        self.assertNotIn('Project tests (docs-only)', names)
        self.assertIn('Plain unittest ordering (protocols (rest))', names)

    def test_the_ordering_step_is_judged_against_its_step_cap(self) -> 'None':
        row = next(row for row in self.report['steps']
                   if row['job'] == 'Plain unittest ordering (protocols (rest))'
                   and row['name'].startswith('Run tests/'))
        self.assertEqual((row['cap'], row['n']), (20, 1))

    def test_the_critical_path_is_the_last_needed_job(self) -> 'None':
        needed = re.compile(r'(Classify changed files|(Integration )?Python .*|Project tests.*)')
        for event, runs in (('pull_request', (PR_RUN,)), ('push', (PUSH_RUN, TIMEOUT_RUN))):
            leaders, slack = [], []
            for run in runs:
                ended = sorted((job['completed_at'], job['name']) for job in jobs_of(run)
                               if job['runner_name'] and needed.fullmatch(job['name']))
                leaders.append(ended[-1][1])
                if len(ended) > 1:
                    slack.append(span(ended[-2][0], ended[-1][0]))
            with self.subTest(event=event):
                path = self.report['critical_path'][event]
                self.assertEqual(path['runs'], len(runs))
                self.assertEqual(path['leader'], max(set(leaders), key=leaders.count))
                self.assertAlmostEqual(path['slack_median'], statistics.median(slack))

    def test_the_coverage_ratio_pairs_legs_within_a_run(self) -> 'None':
        ratios = []
        for run in (PR_RUN, PUSH_RUN, TIMEOUT_RUN):
            steps = {job['name']: next(span(s['started_at'], s['completed_at']) for s in job['steps']
                                       if s['name'] == ci_timing.TESTS_STEP)
                     for job in jobs_of(run) if re.fullmatch(r'Python 3\.1\d', job['name'])}
            paired = [steps[name] for name in FIXTURE_PAIRED_JOBS if name in steps]
            if len(paired) >= 2:
                ratios.append(steps[FIXTURE_COVERAGE_JOB] / statistics.median(paired))
        self.assertEqual(len(ratios), 2)
        self.assertAlmostEqual(self.report['derived']['coverage_ratio']['median'], statistics.median(ratios))

    def test_ms_per_test_counts_testcases_not_the_suite_total(self) -> 'None':
        job = next(job for job in jobs_of(PUSH_RUN) if job['name'] == 'Python 3.13')
        step = next(s for s in job['steps'] if s['name'] == ci_timing.TESTS_STEP)
        self.assertAlmostEqual(self.report['derived']['ms_per_test']['median'],
                               span(step['started_at'], step['completed_at']) * 60000 / 12)
        self.assertEqual(self.report['derived']['test_counts'],
                         [{'run_id': PUSH_RUN, 'tests': 12, 'suite_tests': 25}])

    def test_the_test_level_checks(self) -> 'None':
        """An expired artifact is skipped; the module, slow-test and uniform checks fire."""
        self.assertEqual(list(self.report['tests']), ['3.13'])
        leg = self.report['tests']['3.13']
        self.assertEqual(leg['top_modules'][0], ['tests.foundation.test_delta_unit', 32.519])
        self.assertEqual([name for name, _ in leg['slow_tests']],
                         ['tests.foundation.test_delta_unit.TestDelta::test_slow',
                          'tests.foundation.test_delta_unit.TestDelta::test_slower'])
        # TestGamma's first test carries its setup and the rest are cheap: not flagged.
        self.assertEqual(leg['uniform_classes'], ['tests.protocols.test_beta_unit.TestBeta'])
        self.assertEqual(self.ids().count('W7'), 3)

    def test_the_whole_window_is_listed_a_day_at_a_time(self) -> 'None':
        self.assertEqual(self.report['api'], {'calls': len(self.api.requests), 'remaining': 4321})
        for url, _ in self.api.requests:
            self.assertTrue(url.startswith('https://api.github.com/'), url)
        listings = [urllib.parse.urlsplit(url) for url, _ in self.api.requests
                    if urllib.parse.urlsplit(url).path.endswith('/runs')]
        unit = [urllib.parse.parse_qs(part.query) for part in listings if 'unit-tests.yml' in part.path]
        # 10-09 holds three runs, two fake pages; every other day is one page.
        self.assertEqual(len(unit), len(SLICES) + 1)
        self.assertEqual(sorted({query['created'][0] for query in unit}), sorted(SLICES))
        for query in unit:
            self.assertEqual(query['status'], ['completed'])
        self.assertEqual(len(listings), len(unit) + len(SLICES) * len(ci_timing.OTHER_WORKFLOWS))
        # The caps come from the newest and oldest push runs' shas, one read each.
        refs = [urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['ref'][0]
                for url, _ in self.api.requests if '/contents/' in url]
        self.assertEqual(refs, [run['head_sha'] for run in all_runs() if run['event'] == 'push'])

    def test_the_summary_says_what_was_read(self) -> 'None':
        self.assertIn('- **HARD H1:**', self.summary)
        self.assertIn('| pull_request | 2 | 1 | 1 |', self.summary)
        self.assertIn('unit-tests.yml 4 of 4 (2026-10-05T14:20Z to 2026-10-09T22:57Z)', self.summary)
        self.assertEqual(self.report['window']['read']['unit-tests.yml'],
                         {'listed': 4, 'read': 4, 'first': '2026-10-05T14:20:30Z', 'last': '2026-10-09T22:57:57Z'})
        self.assertTrue(any('No baseline' in note for note in self.report['notes']))
        self.assertIn(self.summary.strip(), self.stdout)

    def test_a_quiet_window_passes(self) -> 'None':
        class Empty(FakeAPI):
            def __call__(self, url: 'str', accept: 'str') -> 'tuple[bytes, dict[str, str]]':
                return b'{"total_count": 0, "workflow_runs": []}', {}

        status, _, report, summary = run_main(api=Empty())
        self.assertEqual((status, report['findings']), (0, []))
        self.assertIn('No threshold fired.', summary)
        self.assertTrue(any('no test-level timings' in note for note in report['notes']))

    def test_no_token_is_a_usage_error(self) -> 'None':
        with mock.patch.dict(os.environ, {'GH_TOKEN': '', 'GITHUB_TOKEN': ''}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci_timing.main(['--repo', REPO]), ci_timing.EXIT_API)

    def test_a_cap_moving_inside_the_window_is_noted(self) -> 'None':
        text = fixture('workflow-unit-tests.yml').decode()
        older = text.replace('timeout-minutes: 45', 'timeout-minutes: 40', 1)
        data = {'repo': REPO, 'since': '2026-10-03T00:00:00Z', 'until': '2026-10-10T00:00:00Z',
                'days': 7, 'junit': [], 'workflows': {'unit-tests.yml': {'runs': [], 'specs': {
                    'newest': ('b', text), 'oldest': ('a', older)}}}}
        notes = ci_timing.analyse(data)['notes']
        self.assertEqual(len(notes), 1)
        self.assertIn('moved from 40 to 45', notes[0])


class TestSampling(unittest.TestCase):
    """Jobs are read for a sample spanning the window; the counts cover all of it."""

    def test_spread_is_even(self) -> 'None':
        self.assertEqual(ci_timing.spread(list(range(10)), 4), [0, 3, 6, 9])
        self.assertEqual(ci_timing.spread([1, 2, 3], 5), [1, 2, 3])
        self.assertEqual(ci_timing.spread([1, 2, 3], 1), [1])
        self.assertEqual(ci_timing.spread([1, 2, 3], 0), [])

    def test_a_smaller_sample_keeps_the_listing_counts(self) -> 'None':
        api = FakeAPI()
        _, _, report, _ = run_main('--runs', '1', '--junit-runs', '0', api=api)
        read = {int(m.group(1)) for url, _ in api.requests
                if (m := re.search(r'/runs/(\d+)/attempts/1/jobs', url))}
        self.assertEqual(read, {CANCELLED_RUN, PUSH_RUN})
        self.assertEqual(report['window']['read']['unit-tests.yml']['read'], 2)
        self.assertEqual(report['window']['read']['unit-tests.yml']['listed'], 4)
        self.assertEqual((report['superseded']['runs'], report['superseded']['of']), (1, 2))

    @unittest.skipUnless(HAS_LXML, NO_LXML)
    def test_a_day_past_the_listing_cap_is_reported(self) -> 'None':
        _, _, report, _ = run_main(api=FakeAPI(inflate=ci_timing.LISTING_CAP))
        self.assertTrue(any('of which the API returned 3' in note for note in report['notes']), report['notes'])

    def test_every_prefix_of_the_read_order_spans_the_window(self) -> 'None':
        """#1930: a read stopped part way through still covers the whole window."""
        for size in range(40):
            order = ci_timing.prefix_order(list(range(size)))
            with self.subTest(size=size):
                self.assertEqual(sorted(order), list(range(size)))
                self.assertEqual(order[:2], [0, size - 1][:size])
                for count in range(2, size + 1):
                    chosen = sorted(order[:count])
                    widest = max(high - low for low, high in zip(chosen, chosen[1:]))
                    # Each level of halving at most halves the widest gap.
                    self.assertLessEqual(widest, 2 * (size - 1) / (count - 1) + 1, (count, chosen))

    def test_the_groups_are_read_in_step(self) -> 'None':
        """At any point each sample has had about the same share read; ``first`` leads."""
        big = [{'id': n} for n in range(12)]
        small = [{'id': 100 + n} for n in range(4)]
        queue = ci_timing.read_order([big, small], first=[big[5], small[1]])
        ids = [run['id'] for run in queue]
        self.assertEqual(sorted(ids), sorted(run['id'] for run in big + small))
        self.assertEqual(ids[:2], [5, 101])
        for count in range(2, len(ids) + 1):
            read = ids[2:count]
            shares = [sum(1 for n in read if n in group) / len(group)
                      for group in ({n for n in range(12)} - {5}, {100, 102, 103})]
            self.assertLessEqual(abs(shares[0] - shares[1]), 0.5, (count, read))


class _Clocked(FakeAPI):
    """:class:`FakeAPI` with a clock that each job read moves on ``minutes``."""

    def __init__(self, minutes: 'float') -> 'None':
        super().__init__()
        self.minutes, self.now = minutes, 0.0

    def __call__(self, url: 'str', accept: 'str') -> 'tuple[bytes, dict[str, str]]':
        if '/attempts/1/jobs' in url:
            self.now += self.minutes * 60
        return super().__call__(url, accept)

    def clock(self) -> 'float':
        return self.now


def job_reads(api: 'FakeAPI') -> 'list[int]':
    return [int(m.group(1)) for url, _ in api.requests if (m := re.search(r'/runs/(\d+)/attempts/1/jobs', url))]


@unittest.skipUnless(HAS_LXML, NO_LXML)
class TestBudget(unittest.TestCase):
    """#1930: a run that runs out of time or calls reading jobs still writes a report."""

    def test_a_spent_time_budget_still_writes_a_report(self) -> 'None':
        # Ten minutes a read, 25 to spend: the third read starts at 20, the fourth would at 30.
        api = _Clocked(10)
        with mock.patch.object(ci_timing, 'MIN_SAMPLES', 1):
            status, stdout, report, summary = run_main(
                '--budget-minutes', '25', '--concurrency-hours', '1', api=api, clock=api.clock)
        self.assertNotIn(status, (ci_timing.EXIT_API, ci_timing.EXIT_CRASH))
        # The JUnit push leads, so ms per test keeps its jobs; then each event in turn.
        self.assertEqual(job_reads(api), [PUSH_RUN, CANCELLED_RUN, PR_RUN])
        self.assertEqual(report['window']['read']['unit-tests.yml']['read'], 3)
        self.assertEqual(report['window']['read']['unit-tests.yml']['listed'], 4)
        self.assertEqual(report['derived']['test_counts'][0]['run_id'], PUSH_RUN)
        stopped = [note for note in report['notes'] if note.startswith('Jobs were read for 3 of the 4 runs')]
        self.assertEqual(len(stopped), 1, report['notes'])
        self.assertIn('25-minute budget (--budget-minutes) ran out', stopped[0])
        self.assertIn(stopped[0], summary)
        self.assertIn(f'::warning title=CI timing stopped early::{stopped[0]}', stdout)
        # The runner pool is not measured on what is left over.
        self.assertIsNone(report.get('concurrency'))
        self.assertTrue(any('runner-pool measurement was skipped' in note for note in report['notes']))
        self.assertFalse(any('/actions/runs?' in url for url, _ in api.requests))

    def test_running_out_of_calls_reading_jobs_still_writes_a_report(self) -> 'None':
        """Out of calls while listing, there is nothing to report; out while reading jobs, there is."""
        whole = FakeAPI()
        run_main(api=whole)
        before = next(n for n, (url, _) in enumerate(whole.requests) if '/attempts/1/jobs' in url)
        api = FakeAPI()
        with mock.patch.object(ci_timing, 'MIN_SAMPLES', 1):
            status, stdout, report, _ = run_main('--max-calls', str(before + 2), api=api)
        self.assertNotIn(status, (ci_timing.EXIT_API, ci_timing.EXIT_CRASH), stdout)
        self.assertEqual(len(api.requests), before + 2)
        self.assertEqual(report['window']['read']['unit-tests.yml']['read'], 2)
        self.assertTrue(any(note.startswith('Jobs were read for 2 of the 4 runs')
                            and '(--max-calls)' in note for note in report['notes']), report['notes'])

    def test_progress_goes_to_stderr(self) -> 'None':
        """A run killed by a cap leaves a trail of how far it got."""
        stderr = io.StringIO()
        run_main(api=FakeAPI(), stderr=stderr)
        lines = stderr.getvalue().splitlines()
        self.assertTrue(lines)
        self.assertTrue(all(line.startswith('[ci-timing ') for line in lines), lines)
        self.assertTrue(any(line.endswith('unit-tests.yml: 4 runs listed, 4 sampled.') for line in lines), lines)
        self.assertTrue(any('JUnit: run 37998639834, junit-unit-3.13' in line for line in lines), lines)
        self.assertTrue(lines[-1].endswith('Jobs read for 4 of 4 runs.'), lines)


class TestExitStatus(unittest.TestCase):
    """1 is a HARD finding; a failure to read or to run says so with a status of its own."""

    def test_an_api_failure_is_not_reported_as_a_threshold(self) -> 'None':
        status, stdout, report, _ = run_main('--max-calls', '3', api=FakeAPI())
        self.assertEqual((status, report), (ci_timing.EXIT_API, {}))
        self.assertIn('No threshold was evaluated', stdout)

    def test_a_crash_is_not_reported_as_a_threshold(self) -> 'None':
        for broken in ('/attempts/1/jobs', f'/artifacts/{JUNIT_ARTIFACT_ID}/zip'):
            with self.subTest(broken=broken):
                status, stdout, report, _ = run_main(api=FakeAPI(broken=(broken,)))
                self.assertEqual((status, report), (ci_timing.EXIT_CRASH, {}))
                self.assertIn('::error title=CI timing crashed::', stdout)

    def test_a_connection_that_never_answers_is_an_api_failure(self) -> 'None':
        """requests' errors subclass ``OSError``, which ``main`` reports as an unreadable API."""
        def down(url: 'str', accept: 'str') -> 'tuple[bytes, dict[str, str]]':
            raise requests.ConnectionError('connection refused')

        with mock.patch.object(ci_timing, 'RETRY_WAITS', (0, 0)):
            status, stdout, report, _ = run_main(api=down)  # type: ignore[arg-type]
        self.assertEqual((status, report), (ci_timing.EXIT_API, {}))
        self.assertIn('::error title=CI timing could not read the API::connection refused', stdout)

    @unittest.skipUnless(HAS_LXML, NO_LXML)
    def test_a_workflow_missing_at_a_sha_is_a_note(self) -> 'None':
        """A 404 for the workflow file leaves its caps unknown and the run going."""
        class Missing(FakeAPI):
            def __call__(self, url: 'str', accept: 'str') -> 'tuple[bytes, dict[str, str]]':
                if '/contents/' in url:
                    raise http_error(url, 404)
                return super().__call__(url, accept)

        with mock.patch.object(ci_timing, 'MIN_SAMPLES', 1):
            status, _, report, _ = run_main(api=Missing())
        self.assertNotIn(status, (ci_timing.EXIT_API, ci_timing.EXIT_CRASH))
        missing = [note for note in report['notes'] if 'caps are unknown' in note]
        self.assertEqual(len(missing), 2, report['notes'])
        self.assertTrue(all(note.startswith('unit-tests.yml is not at ') for note in missing), missing)


class TestRunningJobs(unittest.TestCase):
    """A job with no conclusion is still running, whatever its timestamps say."""

    def test_a_job_without_a_conclusion_is_not_counted(self) -> 'None':
        def job(name: 'str', conclusion: 'Optional[str]', end: 'Optional[str]') -> 'dict':
            return {'name': name, 'conclusion': conclusion, 'runner_name': 'GitHub Actions 1',
                    'run_attempt': 1, 'created_at': '2026-10-09T10:00:30Z',
                    'started_at': '2026-10-09T10:01:00Z', 'completed_at': end, 'steps': []}

        run = {'id': 1, 'event': 'pull_request', 'conclusion': 'success',
               'created_at': '2026-10-09T10:00:00Z', 'jobs': [
                   job('Python 3.14', 'success', '2026-10-09T10:13:00Z'),
                   # A check run's empty conclusion, with an end time all the same.
                   job('Python 3.13', '', '2026-10-09T10:31:00Z'),
                   job('Python 3.12', None, None)]}
        data = {'repo': REPO, 'since': '2026-10-03T00:00:00Z', 'until': '2026-10-10T00:00:00Z',
                'days': 7, 'junit': [], 'workflows': {'unit-tests.yml': {'runs': [run], 'specs': {
                    'newest': ('a', fixture('workflow-unit-tests.yml').decode())}}}}
        report = ci_timing.analyse(data)
        self.assertEqual([row['name'] for row in report['jobs']], ['Python 3.14'])
        pr = report['runs']['pull_request']
        self.assertEqual((pr['runner_min']['median'], pr['wall']['median']), (12.0, 13.0))


def quiet() -> 'tuple[dict, dict]':
    """A report and baseline held just short of every threshold."""
    modules = [[f'tests.m{i}', 30.0 - i] for i in range(10)]
    report = {
        'jobs': [{'workflow': 'unit-tests.yml', 'name': 'Python 3.14', 'n': 20, 'median': 10.0,
                  'p90': 22.4, 'cap': 45, 'slope_per_day': 0.5, 'days_to_cap': 14.1}],
        'steps': [{'workflow': 'unit-tests.yml', 'job': 'Plain unittest ordering (protocols (rest))',
                   'name': 'Run tests/protocols and the root-level modules under plain unittest',
                   'n': 20, 'p90': 9.9, 'cap': 20, 'days_to_cap': 14.1}],
        'runs': {'pull_request': {'mergeable': {'n': 20, 'median': 18.0, 'p90': 29.9},
                                  'queue': {'n': 20, 'p90': 5.0}},
                 'push': {'mergeable': {'n': 20, 'median': 20.0, 'p90': 40.0},
                          'queue': {'n': 20, 'p90': 15.0}}},
        'superseded': {'runs': 35, 'of': 100, 'share': 0.35, 'runner_min': 1000.0},
        'derived': {'coverage_ratio': {'n': 20, 'median': 1.8}, 'ms_per_test': {'n': 5, 'median': 114.9}},
        'tests': {'3.13': {'top_modules': modules, 'slow_tests': [], 'uniform_classes': []}},
        'critical_path': {'pull_request': {'leader': 'Python 3.14'}, 'push': {'leader': 'Python 3.14'}},
    }
    baseline = {
        'jobs': [{'workflow': 'unit-tests.yml', 'name': 'Python 3.14', 'n': 20, 'median': 8.4}],
        'runs': {'pull_request': {'mergeable': {'n': 20, 'p90': 25.0}}},
        'derived': {'ms_per_test': {'median': 100.0}},
        'tests': {'3.13': {'top_modules': [list(row) for row in modules]}},
        'critical_path': {'pull_request': {'leader': 'Python 3.14'}, 'push': {'leader': 'Python 3.14'}},
    }
    return report, baseline


class TestThresholds(unittest.TestCase):
    """Each threshold fires at its boundary and not short of it."""

    def fired(self, change: 'Callable[[dict, dict], None]') -> 'list[str]':
        report, baseline = quiet()
        change(report, baseline)
        return [item['id'] for item in ci_timing.evaluate(report, baseline)]

    def test_nothing_fires_just_short_of_every_threshold(self) -> 'None':
        self.assertEqual(self.fired(lambda report, baseline: None), [])

    def test_each_threshold_at_its_boundary(self) -> 'None':
        def job(report: 'dict') -> 'dict':
            return report['jobs'][0]

        def merge(report: 'dict') -> 'dict':
            return report['runs']['pull_request']['mergeable']

        cases = {
            'H1': lambda r, b: job(r).update(p90=22.5),
            'H2': lambda r, b: r['steps'][0].update(p90=10.0),
            # 30.0 is 1.25 times the baseline's 24.0, and at the floor.
            'H3': lambda r, b: (merge(r).update(p90=30.0), merge(b).update(p90=24.0)),
            'W1': lambda r, b: b['jobs'][0].update(median=8.3),
            'W2': lambda r, b: merge(r).update(median=18.1),
            'W3': lambda r, b: r['derived']['coverage_ratio'].update(median=1.81),
            'W4': lambda r, b: r['derived']['ms_per_test'].update(median=115.0),
            'W5': lambda r, b: r['runs']['push']['queue'].update(p90=15.1),
            'W6': lambda r, b: r['superseded'].update(runs=36, share=0.36),
            'W8': lambda r, b: r['critical_path']['push'].update(leader='Python 3.13'),
            # At the floor but under 1.25 times the baseline's 25.0: no regression.
            'W9': lambda r, b: merge(r).update(p90=30.0),
        }
        for code, change in cases.items():
            with self.subTest(threshold=code):
                self.assertEqual(self.fired(change), [code])
        self.assertEqual(self.fired(lambda r, b: job(r).update(days_to_cap=14.0)), ['H4'])
        self.assertEqual(self.fired(lambda r, b: r['steps'][0].update(days_to_cap=14.0)), ['H4'])
        self.assertEqual(self.fired(lambda r, b: r['runs']['pull_request']['queue'].update(p90=5.1)), ['W5'])
        # A rise that stays under the floor is not H3 either.
        self.assertEqual(self.fired(lambda r, b: merge(b).update(p90=10.0)), [])

    def test_every_w7_signal(self) -> 'None':
        leg = lambda r: r['tests']['3.13']  # noqa: E731
        self.assertEqual(self.fired(lambda r, b: leg(r)['top_modules'][0].__setitem__(1, 30.1)), ['W7'])
        self.assertEqual(self.fired(lambda r, b: leg(r).update(slow_tests=[['t::x', 10.5]])), ['W7'])
        self.assertEqual(self.fired(lambda r, b: leg(r).update(uniform_classes=['tests.m.T'])), ['W7'])
        self.assertEqual(self.fired(lambda r, b: leg(r)['top_modules'].insert(0, ['tests.new', 29.5])),
                         ['W7'])

    def test_a_thin_sample_does_not_fire(self) -> 'None':
        def thin(report: 'dict', baseline: 'dict') -> 'None':
            report['jobs'][0].update(n=ci_timing.MIN_SAMPLES - 1, p90=40.0)
            report['runs']['pull_request']['mergeable'].update(n=ci_timing.MIN_SAMPLES - 1, p90=60.0)
            baseline['jobs'][0].update(n=ci_timing.WARN_MEDIAN_SAMPLES - 1, median=1.0)

        self.assertEqual(self.fired(thin), [])
        # A thin baseline cannot make a slow week HARD; it stays W9.
        self.assertEqual(self.fired(lambda r, b: (
            r['runs']['pull_request']['mergeable'].update(p90=60.0),
            b['runs']['pull_request']['mergeable'].update(n=ci_timing.MIN_SAMPLES - 1, p90=10.0))), ['W9'])

    def test_no_baseline_skips_the_week_over_week_checks(self) -> 'None':
        report, _ = quiet()
        report['critical_path']['push']['leader'] = 'Python 3.13'
        self.assertEqual(ci_timing.evaluate(report, None), [])
        report['runs']['pull_request']['mergeable']['p90'] = 60.0
        self.assertEqual([item['id'] for item in ci_timing.evaluate(report, None)], ['W9'])

    def test_the_documented_thresholds_are_the_evaluated_ones(self) -> 'None':
        source = (ROOT / 'util' / 'ci_timing.py').read_text(encoding='utf-8')
        codes = set(re.findall(r"fire\('([HW]\d)'", source))
        self.assertEqual(codes, {f'H{i}' for i in range(1, 5)} | {f'W{i}' for i in range(1, 10)})
        documented = set(re.findall(r'\* - ``([HW]\d)``', DOC.read_text(encoding='utf-8')))
        self.assertEqual(documented, codes)


class TestNonBlockingLegs(unittest.TestCase):
    """#1732: a cap finding on a leg nothing waits on is a warning, not HARD."""

    #: (workflow, job name, its cap in the real workflow file).
    EXPERIMENTAL = ('experimental.yml', 'Python graalpy-25.4 (experimental)', 140)
    KTLO = ('unit-tests.yml', 'Python 3.10 (KTLO)', 45)
    BLOCKING = ('unit-tests.yml', 'Python 3.14', 45)

    def levels(self, change: 'Callable[[dict], None]') -> 'list[tuple[str, str]]':
        report, baseline = quiet()
        change(report)
        return [(item['id'], item['level']) for item in ci_timing.evaluate(report, baseline)]

    def test_each_cap_rule_only_warns_on_a_non_blocking_leg(self) -> 'None':
        for workflow, name, cap in (self.EXPERIMENTAL, self.KTLO):
            def leg(row: 'dict') -> 'None':
                row.update(workflow=workflow, name=name, cap=cap)

            def step(row: 'dict') -> 'None':
                row.update(workflow=workflow, job=name, name=ci_timing.TESTS_STEP, cap=cap)

            cases = {
                'H1': lambda r: (leg(r['jobs'][0]), r['jobs'][0].update(p90=cap / 2)),
                'H2': lambda r: (step(r['steps'][0]), r['steps'][0].update(p90=cap / 2)),
                'H4 (job)': lambda r: (leg(r['jobs'][0]), r['jobs'][0].update(days_to_cap=14.0)),
                'H4 (step)': lambda r: (step(r['steps'][0]), r['steps'][0].update(days_to_cap=14.0)),
            }
            for code, change in cases.items():
                with self.subTest(job=name, rule=code):
                    self.assertEqual(self.levels(change), [(code.split()[0], 'warn')])

    def test_a_blocking_leg_stays_hard(self) -> 'None':
        workflow, name, cap = self.BLOCKING
        self.assertFalse(ci_timing.non_blocking(workflow, name))
        self.assertEqual(self.levels(lambda r: r['jobs'][0].update(p90=cap / 2)), [('H1', 'hard')])
        self.assertEqual(self.levels(lambda r: r['steps'][0].update(p90=10.0)), [('H2', 'hard')])
        # The same name in experimental.yml would not be, and the KTLO suffix counts
        # only at the end.
        self.assertTrue(ci_timing.non_blocking('experimental.yml', name))
        self.assertFalse(ci_timing.non_blocking(workflow, 'Python 3.10 (KTLO) extra'))
        # #2230: an experimental leg is non-blocking by its workflow, not by its name.
        self.assertFalse(ci_timing.non_blocking(workflow, 'Python 3.14t (experimental)'))

    def run_report(self, workflow: 'str', name: 'str', took: 'float') -> 'tuple[int, str]':
        """``_report`` on ``ci_timing.MIN_SAMPLES`` runs of one job taking ``took`` minutes, against the real file."""
        start = datetime.datetime(2026, 10, 9, 10, tzinfo=datetime.timezone.utc)
        runs = []
        for number in range(ci_timing.MIN_SAMPLES):
            begun = start + datetime.timedelta(hours=3 * number)
            stamp_of = lambda moment: moment.strftime('%Y-%m-%dT%H:%M:%SZ')  # noqa: E731
            runs.append({'id': number, 'event': 'push', 'conclusion': 'success', 'head_sha': 'a',
                         'created_at': stamp_of(begun), 'jobs': [{
                             'name': name, 'conclusion': 'success', 'runner_name': 'GitHub Actions 1',
                             'run_attempt': 1, 'created_at': stamp_of(begun), 'started_at': stamp_of(begun),
                             'completed_at': stamp_of(begun + datetime.timedelta(minutes=took)),
                             'steps': []}]})
        data = {'repo': REPO, 'since': '2026-10-03T00:00:00Z', 'until': '2026-10-10T00:00:00Z',
                'days': 7, 'junit': [], 'workflows': {workflow: {'runs': runs, 'specs': {
                    'newest': ('a', (WORKFLOWS / workflow).read_text(encoding='utf-8'))}}}}
        args = argparse.Namespace(baseline=None, out=None, summary=None)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = ci_timing._report(args, ci_timing.Client('', transport=mock.Mock()), data)
        return status, stdout.getvalue()

    def test_the_run_stays_green_on_a_non_blocking_leg_past_its_share(self) -> 'None':
        for workflow, name, cap in (self.EXPERIMENTAL, self.KTLO):
            with self.subTest(job=name):
                status, stdout = self.run_report(workflow, name, cap / 2 + 1)
                self.assertEqual(status, 0)
                self.assertIn('::warning title=CI timing H1::', stdout)
                self.assertNotIn('::error', stdout)
                self.assertIn(f'**WARN H1:** `{name}` ({workflow})', stdout)
                self.assertIn(f'its {cap}-minute cap', stdout)

    def test_the_run_fails_on_a_blocking_leg_past_its_share(self) -> 'None':
        workflow, name, cap = self.BLOCKING
        status, stdout = self.run_report(workflow, name, cap / 2 + 1)
        self.assertEqual(status, ci_timing.EXIT_HARD)
        self.assertIn('::error title=CI timing H1::', stdout)

    def test_the_rule_is_documented(self) -> 'None':
        page = ' '.join(DOC.read_text(encoding='utf-8').split())
        self.assertIn('``H1``, ``H2`` and ``H4`` on a non-blocking job are warnings', page)
        self.assertIn('a job whose name ends in ``(KTLO)``', page)
        self.assertIn('``(experimental)`` counts by its workflow, not its name', page)


def step_blocks(text: 'str', name: 'str') -> 'list[str]':
    """Every step called ``name``, from its ``- name:`` line to the next step or job."""
    return re.findall(rf'(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - |^  \S|\Z)', text)


class TestTimingArtifacts(unittest.TestCase):
    """#1538's P3 in :file:`unit-tests.yml`, as the review and the gates need it."""

    def setUp(self) -> 'None':
        self.text = UNIT_TESTS.read_text(encoding='utf-8')

    def test_every_unit_and_integration_leg_uploads_its_timings(self) -> 'None':
        blocks = step_blocks(self.text, 'Upload test timings')
        names = [re.search(r'(?m)^          name: (.+)$', block).group(1) for block in blocks]
        self.assertEqual(names, ['junit-unit-${{ matrix.python-version }}',
                                 'junit-integration-${{ matrix.python-version }}'])
        self.assertIn(ci_timing.JUNIT_ARTIFACT.format(leg='${{ matrix.python-version }}'), names)
        # #2005: a PyPy unit leg writes a JUnit file per pytest run, junit.xml among them.
        paths = ('junit*.xml', 'junit.xml')
        self.assertEqual(len(blocks), len(paths))
        for block, path in zip(blocks, paths):
            with self.subTest(step=block.split('\n', 3)[:3]):
                # A failed upload of a diagnostic file must not fail a required leg.
                # It runs after failed tests too, but not after a failed install
                # (#1633), which leaves no file to upload.
                self.assertIn('continue-on-error: true', block)
                self.assertIn("if: ${{ !cancelled() && steps.install.outcome == 'success' }}", block)
                self.assertIn(f'path: ${{{{ runner.temp }}}}/{path}\n', block)
                # tests/_dependency_gates.py reads exactly one pytest step per job.
                self.assertNotIn('python -m pytest', block)

    def test_artifact_names_are_unique_in_a_run(self) -> 'None':
        names = [found.group(1) for found in
                 (re.match(r'\n? +with:\n +name: ([^\n]+)', self.text[pin.end():])
                  for pin in _workflows.PINNED.finditer(self.text) if pin['action'] == 'actions/upload-artifact')
                 if found is not None]
        self.assertGreaterEqual(len(names), 5)
        # #2030: a name holding the job's id is its job's alone, however many jobs write it.
        names = [name for name in names if '${{ github.job }}' not in name]
        self.assertEqual(len(names), len(set(names)), names)

    def test_both_pytest_runs_write_the_file_the_upload_reads(self) -> 'None':
        for job in ('test', 'integration'):
            section = re.search(rf'(?ms)^  {job}:\n(.*?)(?=^  [\w-]+:\n)', self.text).group(1)
            with self.subTest(job=job):
                self.assertIn('--junitxml="$RUNNER_TEMP/junit.xml"', section)
                self.assertIn('--durations=', section)

    def test_the_legs_the_review_reads_exist(self) -> 'None':
        """``test``'s legs, from .github/python-versions.toml (#1660)."""
        found = matrix_legs(matrix('unit-tests.yml', 'test'))
        for leg in ci_timing.JUNIT_LEGS:
            with self.subTest(leg=leg):
                self.assertIn(leg, [entry['python-version'] for entry in found if not entry.get('ktlo')])
        coverage = [entry['python-version'] for entry in found if entry.get('coverage')]
        self.assertEqual([f'Python {version}' for version in coverage], [ci_timing.COVERAGE_JOB])

    def test_the_reusable_workflow_asks_for_no_write_permission(self) -> 'None':
        """Its callers grant ``contents: read``, so a write scope would break them."""
        code = '\n'.join(line.split('#', 1)[0] for line in self.text.splitlines())
        self.assertNotRegex(code, r'(?m)^\s+[\w-]+:\s*write\s*$')


class TestReviewWorkflow(unittest.TestCase):
    """:file:`ci-timing.yml` stays read-only but for posting its report (#2030), weekly, and off Unit Tests' runs."""

    def setUp(self) -> 'None':
        self.text = REVIEW.read_text(encoding='utf-8')
        self.code = '\n'.join(line.split('#', 1)[0] for line in self.text.splitlines())

    def test_triggers(self) -> 'None':
        self.assertRegex(self.code, r"(?m)^    - cron: '\d+ \d+ \* \* \d'$")
        self.assertIn('workflow_dispatch:', self.code)
        for trigger in ('workflow_run', 'pull_request', 'push'):
            with self.subTest(trigger=trigger):
                self.assertNotRegex(self.code, rf'(?m)^  {trigger}:')

    def test_permissions_are_read_only(self) -> 'None':
        """But for the ``discussion`` job's ``discussions: write``, pinned in test_discussion_report_2030."""
        block = re.search(r'(?ms)^permissions:\n(.*?)(?=^\S)', self.code).group(1)
        self.assertEqual(sorted(block.split()), ['actions:', 'contents:', 'read', 'read'])
        self.assertEqual(re.findall(r'(?m)^\s+([\w-]+):\s*write\s*$', self.code), ['discussions'])

    def test_the_job(self) -> 'None':
        specs = ci_timing.parse_workflow(self.text)
        self.assertEqual([(spec['name'], spec['timeout']) for spec in specs],
                         [('CI timing report', 40), ('Post the CI timing report', 10)])
        self.assertIn('python util/ci_timing.py', self.code)
        # The upload and the baseline download name the same artifact.
        self.assertIn('name: ci-timing-report', self.code)
        self.assertIn('-n ci-timing-report', self.code)

    def test_a_capped_run_still_publishes_its_report(self) -> 'None':
        """#1930: the script's budget sits under its step's cap, which sits under the job's."""
        job = ci_timing.parse_workflow(self.text)[0]
        step = next(step for step in job['steps'] if step['name'] == 'Report CI timing')
        budget = float(re.search(r'--budget-minutes (\d+)', self.code).group(1))
        self.assertLess(budget, step['timeout'])
        self.assertLess(step['timeout'], job['timeout'])
        # Neither the summary nor the upload is skipped when a cap stops the job.
        for name in ('Add the report to the job summary', 'Upload the report'):
            with self.subTest(step=name):
                self.assertRegex(self.code, rf"- name: {name}\n        if: \$\{{\{{ always\(\) \}}\}}\n")
        self.assertNotIn('!cancelled()', self.code)

    def test_yaml_agrees(self) -> 'None':
        try:
            import yaml  # pylint: disable=import-outside-toplevel
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML, from the test extra, is not installed')
        data = yaml.safe_load(self.text)
        # PyYAML reads the bare key ``on`` as the boolean True.
        self.assertEqual(sorted(data[True]), ['schedule', 'workflow_dispatch'])
        self.assertEqual(data['permissions'], {'actions': 'read', 'contents': 'read'})
        self.assertEqual(data['jobs']['report']['timeout-minutes'], 40)


if __name__ == '__main__':
    unittest.main()
