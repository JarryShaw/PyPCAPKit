# -*- coding: utf-8 -*-
"""#1938: Experimental Tests skips or stops a superseded run instead of cancelling it.

GitHub counts a ``cancelled`` check against its commit in the status rollup, so
#1903's ``cancel-in-progress`` marked every superseded commit red, and a merged
pull request's last run, which nothing supersedes, kept its runner to the end.
The owner chose both remedies together: a gate job that skips the rest of a run
whose commit is no longer current, and a watcher that stops the tests once it
stops being current, each ending green.

* :class:`TestNothingIsCancelled` and :class:`TestTheGate` read experimental.yml.
* :class:`TestCheck` drives util/superseded.py's rule through a fake transport.
* :class:`TestGateCommand` and :class:`TestWatch` run its two actions.
* :class:`TestTheTestsStep` runs ``Run unit tests`` itself, against a local
  HTTP server standing in for the API.

"""

from __future__ import annotations

import http.server
import io
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from typing import TYPE_CHECKING

from tests.project.test_python_matrix_tiers_1633 import job, workflow, workflow_commands
from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_release_gates import STATUS, calls_status_check, evaluate_condition
from tests.project.test_resource_monitor_1740 import DEFAULT, TESTS, sh, step
from util import superseded

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, List, Optional, Tuple

NAME = 'experimental.yml'
GATE = 'current'
#: The commit a run tests, and the one that supersedes it.
OURS, NEWER = 'a' * 40, 'b' * 40
REPO = 'JarryShaw/PyPCAPKit'
#: What every job but the gate skips on.
SKIPS_ON = "needs.current.outputs.current != 'false'"
POSIX = os.name == 'posix'


class FakeApi:
    """A transport answering from ``routes``, recording each request.

    A route's value is a JSON-able body, answered 200 with an ``ETag`` of its
    own and 304 to a request that sends that ``ETag`` back; an ``int`` status;
    or an exception to raise.

    """

    def __init__(self, routes: 'Dict[str, Any]') -> 'None':
        self.routes = routes
        self.requests = []  # type: List[Tuple[str, Dict[str, str]]]

    def __call__(self, url: 'str', headers: 'Dict[str, str]') -> 'Tuple[int, Dict[str, str], bytes]':
        self.requests.append((url, dict(headers)))
        path = url[len(superseded.API) + 1:]
        answer = self.routes[path]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, int):
            return answer, {}, b'{"message": "Server Error"}'
        etag = f'W/"{path}"'
        if headers.get('If-None-Match') == etag:
            return 304, {'etag': etag}, b''
        return 200, {'etag': etag}, json.dumps(answer).encode()


class FakeResponse:
    """What :class:`FakeSession` answers: the parts of a :class:`requests.Response` the transport reads."""

    def __init__(self, status: 'int', headers: 'Dict[str, str]', body: 'Any') -> 'None':
        self.status_code = status
        self.headers = headers
        self.content = b'' if body is None else json.dumps(body).encode()


class FakeSession:
    """A :class:`requests.Session` answering from ``answers`` in turn, recording each GET.

    An answer is ``(status, headers, body)`` or an exception to raise.

    """

    def __init__(self, answers: 'List[Any]') -> 'None':
        self.answers = list(answers)
        self.calls = []  # type: List[Tuple[str, Dict[str, Any]]]

    def get(self, url: 'str', **kwargs: 'Any') -> 'FakeResponse':
        self.calls.append((url, kwargs))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return FakeResponse(*answer)


def push(sha: 'str' = OURS) -> 'superseded.Context':
    return superseded.Context('push', 'refs/heads/main', sha, REPO)


def pull(sha: 'str' = OURS, number: 'int' = 1938) -> 'superseded.Context':
    return superseded.Context('pull_request', f'refs/pull/{number}/merge', sha, REPO, number)


def main_at(sha: 'str') -> 'Dict[str, Any]':
    return {f'repos/{REPO}/commits/main': {'sha': sha}}


def pull_is(state: 'str', head: 'str' = OURS, merged: 'bool' = False, number: 'int' = 1938) -> 'Dict[str, Any]':
    return {f'repos/{REPO}/pulls/{number}': {'state': state, 'merged': merged, 'head': {'sha': head}}}


class TestNothingIsCancelled(unittest.TestCase):
    """No ``cancel-in-progress``, and no ``concurrency:`` group to cancel a pending run either."""

    def test_no_cancel_in_progress_is_true(self) -> None:
        text = (ROOT / '.github' / 'workflows' / NAME).read_text(encoding='utf-8')
        code = [line for line in text.splitlines() if not line.lstrip().startswith('#')]
        self.assertFalse([line for line in code if 'cancel-in-progress' in line])

    def test_no_concurrency_group_at_all(self) -> None:
        """A group without ``cancel-in-progress`` still cancels its pending run when a newer one queues."""
        spec = workflow(NAME)
        self.assertNotIn('concurrency', spec)
        self.assertEqual([job_id for job_id, body in spec['jobs'].items() if 'concurrency' in body], [])


class TestTheGate(unittest.TestCase):
    """``current`` runs first, always succeeds, and every other job skips on its output."""

    def setUp(self) -> None:
        self.jobs = workflow(NAME)['jobs']

    def test_the_gate_job(self) -> None:
        gate = self.jobs[GATE]
        self.assertNotIn('needs', gate)
        self.assertNotIn('if', gate)
        self.assertEqual(gate['outputs'], {'current': '${{ steps.check.outputs.current }}'})
        # Read-only: the default token, and nothing it can write with.
        self.assertEqual(set(gate['permissions'].values()), {'read'})
        self.assertIs(gate.get('continue-on-error'), None)
        self.assertTrue(all(entry.get('continue-on-error') is True for entry in gate['steps']), gate['steps'])
        check = next(entry for entry in gate['steps'] if entry.get('id') == 'check')
        self.assertEqual(check['run'], 'python util/superseded.py check')
        self.assertEqual(check['env'], {'GH_TOKEN': '${{ github.token }}'})
        checkout = gate['steps'][0]
        self.assertTrue(checkout['uses'].startswith('actions/checkout@'))
        for path in ('util/superseded.py', 'util/python_versions.py', '.github/python-versions.toml'):
            with self.subTest(path=path):
                self.assertIn(path, checkout['with']['sparse-checkout'])
        self.assertIs(checkout['with']['persist-credentials'], False)

    def test_the_gate_checks_on_latest_with_requests(self) -> None:
        """The gate reads ``latest`` as every job reads it, sets it up and installs requests before the check."""
        ids = [entry.get('id') for entry in self.jobs[GATE]['steps']]
        self.assertEqual(ids, [None, 'versions', 'python', 'requests', 'check'])
        steps = {entry.get('id'): entry for entry in self.jobs[GATE]['steps']}
        self.assertEqual(steps['versions']['run'], 'python3 util/python_versions.py --github-output')
        setup = steps['python']
        legs = {entry.get('id'): entry for entry in job(NAME, 'experimental')['steps']}
        self.assertEqual(setup['uses'], legs['python']['uses'])
        self.assertEqual(setup['with'], {'python-version': '${{ steps.versions.outputs.latest }}'})
        self.assertEqual(steps['requests']['run'], 'python -m pip install requests')

    def test_the_watcher_runs_on_a_cpython_of_its_own_with_requests(self) -> None:
        """The watcher runs on ``latest``, outside the leg's environment, and requests goes into it alone."""
        legs = job(NAME, 'experimental')
        self.assertEqual(self.jobs['python-versions']['outputs']['latest'], '${{ steps.read.outputs.latest }}')
        steps = {entry.get('id'): entry for entry in legs['steps']}
        leg, own = steps['python'], steps['watcher-python']
        self.assertEqual(own['uses'], leg['uses'])
        self.assertEqual(own['with'], {'python-version': '${{ needs.python-versions.outputs.latest }}',
                                       'update-environment': False})
        self.assertIs(own.get('continue-on-error'), True)
        # The leg's own setup-python comes first: its interpreter, its environment, its cache.
        self.assertEqual(leg['with'], {'python-version': '${{ matrix.python-version }}', 'cache': 'pip'})
        self.assertLess(legs['steps'].index(leg), legs['steps'].index(own))
        install = steps['watcher']
        self.assertEqual(install['env'], {'WATCHER_PYTHON': '${{ steps.watcher-python.outputs.python-path }}'})
        self.assertEqual(install['run'], '"$WATCHER_PYTHON" -m pip install --no-cache-dir requests')
        self.assertIs(install.get('continue-on-error'), True)
        self.assertIn("steps.watcher-python.outcome == 'success'", install['if'])
        tests = step(TESTS)
        self.assertEqual(tests['env']['WATCHER'], '${{ steps.watcher.outcome }}')
        self.assertEqual(tests['env']['WATCHER_PYTHON'], '${{ steps.watcher-python.outputs.python-path }}')
        self.assertIn('set -- "$WATCHER_PYTHON" util/superseded.py watch ', tests['run'])
        # #1963: the image's interpreter runs GraalPy's shards in the tests step, never the watcher.
        self.assertNotIn('/usr/bin/python3 util/superseded.py', tests['run'])
        # Nothing the leg's interpreter runs installs requests.
        for entry in legs['steps']:
            if entry.get('id') != 'watcher':
                with self.subTest(step=entry.get('name') or entry.get('uses')):
                    self.assertNotIn('install requests', str(entry.get('run', '')))

    def test_every_other_job_needs_it_and_skips_on_its_output(self) -> None:
        others = [job_id for job_id in self.jobs if job_id != GATE]
        # #2060: `windows`, the Windows leg, skips with the rest.
        self.assertEqual(sorted(others), ['changes', 'experimental', 'python-versions', 'windows'])
        for job_id in others:
            body = self.jobs[job_id]
            needs = body['needs'] if isinstance(body['needs'], list) else [body['needs']]
            with self.subTest(job=job_id):
                self.assertIn(GATE, needs)
                self.assertIn(SKIPS_ON, body['if'])
                # No implicit `success()`, so a failed gate job skips nothing.
                self.assertTrue(body['if'].startswith('${{ !cancelled() && '), body['if'])

    def run_if(self, job_id: 'str', current: 'str', code: 'str' = 'true', *, gate: 'str' = 'success',
               versions: 'str' = 'success', changes: 'str' = 'success', cancelled: 'bool' = False) -> 'bool':
        """Whether ``job_id`` runs, GitHub's implicit ``success()`` applied where its ``if:`` calls no status check."""
        body = self.jobs[job_id]
        needs = body['needs'] if isinstance(body['needs'], list) else [body['needs']]
        results = {GATE: gate, 'changes': changes, 'python-versions': versions}
        context = {'needs': {GATE: {'outputs': {'current': current}, 'result': gate},
                             'changes': {'outputs': {'code': code}, 'result': changes},
                             'python-versions': {'outputs': {}, 'result': versions}},
                   STATUS: {'cancelled': cancelled, 'always': True,
                            'success': not cancelled and all(results[name] == 'success' for name in needs),
                            'failure': any(results[name] == 'failure' for name in needs)}}
        runs = evaluate_condition(body['if'], context)
        if not calls_status_check(body['if']):
            runs = runs and bool(context[STATUS]['success'])  # type: ignore[index]
        return runs

    def test_a_superseded_commit_skips_every_job_and_anything_else_runs_them(self) -> None:
        for job_id in ('python-versions', 'changes', 'experimental', 'windows'):
            with self.subTest(job=job_id):
                self.assertFalse(self.run_if(job_id, 'false'))
                self.assertTrue(self.run_if(job_id, 'true'))
                # A gate step that failed writes nothing; the run goes on as it would without the gate.
                self.assertTrue(self.run_if(job_id, ''))
                # So does a gate job that failed, or timed out, as a whole.
                self.assertTrue(self.run_if(job_id, '', gate='failure'))
                self.assertTrue(self.run_if(job_id, '', gate='cancelled'))
                # A cancelled run stays cancelled.
                self.assertFalse(self.run_if(job_id, 'true', cancelled=True))
        for legs in ('experimental', 'windows'):
            # A docs-only pull request still skips the legs.
            self.assertFalse(self.run_if(legs, 'true', code='false'))
            # And the legs still need the jobs they read: `!cancelled()` drops only the implicit `success()`.
            for job_id in ('changes', 'python-versions'):
                for result in ('failure', 'skipped', 'cancelled'):
                    with self.subTest(legs=legs, needs=job_id, result=result):
                        self.assertFalse(self.run_if(legs, 'true', **{
                            'versions' if job_id == 'python-versions' else 'changes': result}))
            # Superseded: `changes` and `python-versions` skip, and the legs with them.
            self.assertFalse(self.run_if(legs, 'false', versions='skipped', changes='skipped'))

    def test_the_legs_and_the_tests_step_read_with_the_token(self) -> None:
        self.assertEqual(set(job(NAME, 'experimental')['permissions'].values()), {'read'})
        self.assertEqual(step(TESTS)['env']['GH_TOKEN'], '${{ github.token }}')


class TestCheck(unittest.TestCase):
    """The rule: the head of ``main``, or of an open pull request; an API failure is current."""

    def verdict(self, context: 'superseded.Context', routes: 'Dict[str, Any]') -> 'superseded.Verdict':
        self.api = FakeApi(routes)
        return superseded.check(context, superseded.Api('token', self.api))

    def test_a_push_to_main(self) -> None:
        self.assertEqual(self.verdict(push(), main_at(OURS)).state, superseded.CURRENT)
        stale = self.verdict(push(), main_at(NEWER))
        self.assertEqual(stale.state, superseded.SUPERSEDED)
        self.assertEqual(stale.reason, f'main is at {NEWER[:9]}, no longer at {OURS[:9]}')
        url, headers = self.api.requests[0]
        self.assertEqual(url, f'https://api.github.com/repos/{REPO}/commits/main')
        self.assertEqual(headers['Authorization'], 'Bearer token')

    def test_a_pull_request(self) -> None:
        self.assertEqual(self.verdict(pull(), pull_is('open')).state, superseded.CURRENT)
        moved = self.verdict(pull(), pull_is('open', head=NEWER))
        self.assertEqual((moved.state, moved.reason),
                         (superseded.SUPERSEDED, f'pull request #1938 is at {NEWER[:9]}, no longer at {OURS[:9]}'))
        merged = self.verdict(pull(), pull_is('closed', merged=True))
        self.assertEqual((merged.state, merged.reason), (superseded.SUPERSEDED, 'pull request #1938 is merged'))
        closed = self.verdict(pull(), pull_is('closed'))
        self.assertEqual((closed.state, closed.reason), (superseded.SUPERSEDED, 'pull request #1938 is closed'))

    def test_an_api_failure_is_current(self) -> None:
        for answer in (500, 404, 403, urllib.error.URLError('timed out'), OSError('reset'), ValueError('not JSON')):
            for context, path in ((push(), f'repos/{REPO}/commits/main'), (pull(), f'repos/{REPO}/pulls/1938')):
                with self.subTest(answer=answer, event=context.event):
                    verdict = self.verdict(context, {path: answer})
                    self.assertEqual(verdict.state, superseded.CURRENT)
                    self.assertTrue(verdict.error)
                    self.assertIn('so the commit counts as current', verdict.reason)
        # A body that is not the expected shape is a failure too.
        self.assertEqual(self.verdict(push(), {f'repos/{REPO}/commits/main': {}}).state, superseded.CURRENT)

    def test_any_other_event_is_current_and_asks_nothing(self) -> None:
        for context in (superseded.Context('push', 'refs/heads/feature', OURS, REPO),
                        superseded.Context('workflow_dispatch', 'refs/heads/main', OURS, REPO),
                        superseded.Context('', '', '', ''),
                        superseded.Context('pull_request', 'refs/pull/1/merge', '', REPO, None)):
            with self.subTest(event=context.event, ref=context.ref):
                self.assertEqual(self.verdict(context, {}).state, superseded.CURRENT)
                self.assertEqual(self.api.requests, [])

    def test_the_default_transport_is_a_requests_session(self) -> None:
        """One :class:`requests.Session`, a bounded timeout, the status returned, a 304 answered from the cache."""
        session = FakeSession([(200, {'ETag': 'W/"1"'}, {'sha': NEWER}), (304, {'ETag': 'W/"1"'}, None)])
        api = superseded.Api('token')
        api.session = session  # type: ignore[assignment]
        self.assertEqual(superseded.check(push(), api).state, superseded.SUPERSEDED)
        self.assertEqual(superseded.check(push(), api).state, superseded.SUPERSEDED)
        (url, first), (_, second) = session.calls
        self.assertEqual(url, f'https://api.github.com/repos/{REPO}/commits/main')
        self.assertEqual(first['timeout'], superseded.TIMEOUT)
        self.assertEqual(first['headers']['Authorization'], 'Bearer token')
        self.assertNotIn('If-None-Match', first['headers'])
        self.assertEqual(second['headers']['If-None-Match'], 'W/"1"')
        # The session is opened once and kept.
        self.assertIs(api.session, session)

    def test_a_requests_error_is_current(self) -> None:
        import requests  # pylint: disable=import-outside-toplevel
        for error in (requests.ConnectionError('reset'), requests.Timeout('slow'), requests.TooManyRedirects('loop')):
            with self.subTest(error=type(error).__name__):
                api = superseded.Api('token')
                api.session = FakeSession([error])  # type: ignore[assignment]
                verdict = superseded.check(push(), api)
                self.assertEqual((verdict.state, verdict.error), (superseded.CURRENT, True))

    def test_without_requests_everything_is_current(self) -> None:
        """A missing requests is one more failed request, not a crash."""
        original = superseded.requests
        superseded.requests = None  # type: ignore[assignment]
        self.addCleanup(setattr, superseded, 'requests', original)
        verdict = superseded.check(push(), superseded.Api('token'))
        self.assertEqual((verdict.state, verdict.error), (superseded.CURRENT, True))
        self.assertIn('requests is not installed', verdict.reason)
        files, out = Files(self), io.StringIO()
        self.assertEqual(superseded.main(['check'], env=files.env(), out=out), 0)
        self.assertEqual(files.read(files.output), 'current=true\n')

    def test_the_script_runs_where_requests_cannot_import(self) -> None:
        """In an interpreter whose ``import requests`` fails, the gate answers current and exits 0."""
        with tempfile.TemporaryDirectory() as tmp:
            pathlib.Path(tmp, 'requests.py').write_text('raise ImportError("no requests here")\n', encoding='utf-8')
            output = pathlib.Path(tmp, 'output')
            env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
            env.update(PYTHONPATH=tmp, GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=OURS,
                       GITHUB_REPOSITORY=REPO, GITHUB_OUTPUT=str(output), GITHUB_API_URL='http://127.0.0.1:9')
            result = subprocess.run([sys.executable, str(ROOT / 'util' / 'superseded.py'), 'check'],  # nosec B603
                                    env=env, capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('requests is not installed', result.stdout)
            self.assertEqual(output.read_text(encoding='utf-8'), 'current=true\n')

    def test_a_repeated_request_is_conditional(self) -> None:
        """``If-None-Match`` with the last ``ETag``; a 304 answers from the last body."""
        api = FakeApi(main_at(NEWER))
        client = superseded.Api('token', api)
        first, second = superseded.check(push(), client), superseded.check(push(), client)
        self.assertEqual((first.state, second.state), (superseded.SUPERSEDED, superseded.SUPERSEDED))
        self.assertEqual(second.reason, first.reason)
        self.assertNotIn('If-None-Match', api.requests[0][1])
        self.assertEqual(api.requests[1][1]['If-None-Match'], f'W/"repos/{REPO}/commits/main"')
        # A 304 with nothing cached is no answer, so it is current.
        self.assertEqual(superseded.check(push(), superseded.Api('token', lambda url, headers: (304, {}, b''))).state,
                         superseded.CURRENT)

    def test_the_context_comes_from_the_job_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            event = pathlib.Path(tmp, 'event.json')
            event.write_text(json.dumps({'pull_request': {'number': 1938, 'head': {'sha': OURS}}}), encoding='utf-8')
            env = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/1938/merge',
                   'GITHUB_SHA': NEWER, 'GITHUB_REPOSITORY': REPO, 'GITHUB_EVENT_PATH': str(event)}
            context = superseded.Context.from_env(env)
            # The pull request's head, not GITHUB_SHA, which is the merge commit.
            self.assertEqual((context.sha, context.number, context.repo), (OURS, 1938, REPO))
            event.write_text('not JSON', encoding='utf-8')
            broken = superseded.Context.from_env(env)
            self.assertEqual((broken.sha, broken.number), ('', None))
            self.assertEqual(self.verdict(broken, {}).state, superseded.CURRENT)
        context = superseded.Context.from_env({'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main',
                                               'GITHUB_SHA': OURS, 'GITHUB_REPOSITORY': REPO})
        self.assertEqual((context.event, context.sha, context.watched), ('push', OURS, True))


class Files:
    """``$GITHUB_OUTPUT`` and ``$GITHUB_STEP_SUMMARY`` in a temporary directory."""

    def __init__(self, case: 'unittest.TestCase') -> 'None':
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1938-')  # pylint: disable=consider-using-with
        case.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.output = self.root / 'output'
        self.summary = self.root / 'summary.md'

    def env(self, **extra: 'str') -> 'Dict[str, str]':
        return dict({'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': OURS,
                     'GITHUB_REPOSITORY': REPO, 'GH_TOKEN': 'token', 'GITHUB_OUTPUT': str(self.output),
                     'GITHUB_STEP_SUMMARY': str(self.summary)}, **extra)

    def read(self, path: 'pathlib.Path') -> 'str':
        return path.read_text(encoding='utf-8') if path.exists() else ''


class TestGateCommand(unittest.TestCase):
    """``check``: ``current=`` in ``$GITHUB_OUTPUT``, a notice and a summary line where superseded, exit 0."""

    def run_gate(self, routes: 'Dict[str, Any]') -> 'Tuple[int, str, Files]':
        files, out = Files(self), io.StringIO()
        code = superseded.main(['check'], env=files.env(), transport=FakeApi(routes), out=out)
        return code, out.getvalue(), files

    def test_superseded(self) -> None:
        code, out, files = self.run_gate(main_at(NEWER))
        self.assertEqual(code, 0)
        self.assertEqual(files.read(files.output), 'current=false\n')
        self.assertEqual(workflow_commands(out), [
            f'::notice title=Superseded::main is at {NEWER[:9]}, no longer at {OURS[:9]}. '
            'The rest of this run is skipped, so none of its jobs fails or is cancelled.'])
        self.assertEqual(files.read(files.summary),
                         f'- Superseded: main is at {NEWER[:9]}, no longer at {OURS[:9]}. '
                         'The rest of this run is skipped, so none of its jobs fails or is cancelled.\n')

    def test_current_and_on_an_api_failure(self) -> None:
        for routes in (main_at(OURS), {f'repos/{REPO}/commits/main': 502}):
            with self.subTest(routes=routes):
                code, out, files = self.run_gate(routes)
                self.assertEqual(code, 0)
                self.assertEqual(files.read(files.output), 'current=true\n')
                self.assertEqual(workflow_commands(out), [])
                self.assertEqual(files.read(files.summary), '')


#: A stand-in for pytest that runs until it is stopped.
SLEEPER = [sys.executable, '-c', 'import time; time.sleep(60)']


@unittest.skipUnless(POSIX, 'the watcher signals a process group, as on the Ubuntu runners')
class TestWatch(unittest.TestCase):
    """``watch``: the command's own status while current; stopped, a notice and 0 once superseded."""

    def watch(self, command: 'List[str]', routes: 'Dict[str, Any]', grace: 'str' = '5', *,
              options: 'Tuple[str, ...]' = (), run: 'Optional[Callable[[Any], int]]' = None,
              kill: 'Optional[Callable[[int, int], None]]' = None, **env: 'str') -> 'Tuple[int, str, Files, float]':
        files, out = Files(self), io.StringIO()
        started = time.monotonic()
        extra = {}  # type: Dict[str, Any]
        if run is not None:
            extra['run'] = run
        if kill is not None:
            extra['kill'] = kill
        code = superseded.main(['watch', '--interval', '0.2', '--grace', grace, *options, '--', *command],
                               env=files.env(**env), transport=FakeApi(routes), out=out, **extra)
        return code, out.getvalue(), files, time.monotonic() - started

    def pid_command(self, body: 'str') -> 'Tuple[List[str], pathlib.Path]':
        """A command that writes its pid to a file, then runs ``body``; the pid is killed at cleanup."""
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1938-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        pidfile = pathlib.Path(tmp.name, 'pid')

        def cleanup() -> 'None':
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text(encoding='utf-8')), signal.SIGKILL)
                except (OSError, ValueError):
                    pass
        self.addCleanup(cleanup)
        return [sys.executable, '-c', f'import os, signal, time; open({str(pidfile)!r}, "w").write(str(os.getpid())); '
                                      + body], pidfile

    def test_the_scoped_tests_are_stopped_through_the_scope(self) -> None:
        """Under sudo a signal to the session is refused, so the scope's processes are killed by name."""
        command, pidfile = self.pid_command('time.sleep(60)')
        calls = []  # type: List[List[str]]

        def run(argv: 'Any') -> 'int':
            # systemd, as it kills every process of the scope.
            calls.append(list(argv))
            signum = getattr(signal, argv[4].split('=', 1)[1])
            try:
                os.kill(int(pidfile.read_text(encoding='utf-8')), signum)
            except (OSError, ValueError):
                pass
            return 0

        refused = []  # type: List[Tuple[int, int]]
        code, out, _, elapsed = self.watch(command, main_at(NEWER), options=('--scope', 'pcapkit-tests.scope'),
                                           run=run, kill=lambda pid, signum: refused.append((pid, signum)))
        self.assertEqual(code, 0)
        self.assertLess(elapsed, 30)
        self.assertIn('::notice title=Superseded::main is at', out)
        self.assertEqual(calls[0], ['sudo', '-n', 'systemctl', 'kill', '--signal=SIGTERM', 'pcapkit-tests.scope'])
        # And a sweep, for whatever outlived the scope's main process.
        self.assertEqual(calls[-1], ['sudo', '-n', 'systemctl', 'kill', '--signal=SIGKILL', 'pcapkit-tests.scope'])
        # SIGTERM to the scope alone, so the tests keep their grace; the session only gets the sweep.
        self.assertEqual([signum for _, signum in refused], [signal.SIGKILL])

    def test_without_a_scope_nothing_runs_through_sudo(self) -> None:
        calls = []  # type: List[Any]
        code, _, _, _ = self.watch(SLEEPER, main_at(NEWER), run=lambda argv: calls.append(argv) or 0)
        self.assertEqual((code, calls), (0, []))

    def test_a_command_that_cannot_be_stopped_ends_the_watch_with_a_warning(self) -> None:
        """Every wait is bounded; a stop that fails warns and exits STOP_FAILED, not 0."""
        command, pidfile = self.pid_command('time.sleep(60)')
        refused = []  # type: List[Tuple[int, int]]
        calls = []  # type: List[Any]
        code, out, files, elapsed = self.watch(
            command, main_at(NEWER), grace='0.5', options=('--kill-wait', '0.5', '--scope', 'pcapkit-tests.scope'),
            run=lambda argv: calls.append(list(argv)) or 1, kill=lambda pid, signum: refused.append((pid, signum)))
        self.assertEqual(code, superseded.STOP_FAILED)
        self.assertNotIn(code, (0, 1, 2, 3, 4, 5, 124, 125, 126, 127, 137))
        self.assertLess(elapsed, 20)
        self.assertEqual([signum for _, signum in refused], [signal.SIGKILL])
        self.assertEqual([argv[4] for argv in calls], ['--signal=SIGTERM', '--signal=SIGKILL'])
        commands = workflow_commands(out)
        self.assertEqual(len(commands), 1, out)
        self.assertTrue(commands[0].startswith(
            f'::warning title=Superseded run not stopped::main is at {NEWER[:9]}, no longer at {OURS[:9]}, but SIGTERM '
            'and SIGKILL to the scope pcapkit-tests.scope and the session of pid '), commands[0])
        self.assertTrue(commands[0].endswith(' did not end it within 1 s. The tests may run on until their timeout.'),
                        commands[0])
        self.assertTrue(files.read(files.summary).startswith('- Superseded run not stopped: main is at'))
        # It is still running: the watcher gave up on it rather than waiting.
        os.kill(int(pidfile.read_text(encoding='utf-8')), 0)

    def test_a_failing_systemctl_is_bounded(self) -> None:
        """The default runner: a command that hangs past its timeout, or cannot start, is a failure."""
        self.assertEqual(superseded.run_command(['/nonexistent/systemctl']), -1)
        original = superseded.TIMEOUT
        superseded.TIMEOUT = 0.5
        self.addCleanup(setattr, superseded, 'TIMEOUT', original)
        started = time.monotonic()
        self.assertEqual(superseded.run_command([sys.executable, '-c', 'import time; time.sleep(30)']), -1)
        self.assertLess(time.monotonic() - started, 10)

    def test_a_superseded_commit_stops_the_tests_and_exits_0_with_the_notice(self) -> None:
        code, out, files, elapsed = self.watch(SLEEPER, main_at(NEWER))
        self.assertEqual(code, 0)
        self.assertLess(elapsed, 30)
        commands = workflow_commands(out)
        self.assertEqual(len(commands), 1, out)
        self.assertTrue(commands[0].startswith(
            f'::notice title=Superseded::main is at {NEWER[:9]}, no longer at {OURS[:9]}. The tests were stopped after '),
            commands[0])
        self.assertTrue(commands[0].endswith(' s, and this step succeeds.'), commands[0])
        self.assertRegex(files.read(files.summary), r'^- Superseded: main is at b{9}, no longer at a{9}\. '
                                                    r'The tests were stopped after \d+ s, and this step succeeds\.\n$')

    def test_a_closed_pull_request_stops_the_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            event = pathlib.Path(tmp, 'event.json')
            event.write_text(json.dumps({'pull_request': {'number': 1938, 'head': {'sha': OURS}}}), encoding='utf-8')
            code, out, _, _ = self.watch(SLEEPER, pull_is('closed', merged=True), GITHUB_EVENT_NAME='pull_request',
                                         GITHUB_EVENT_PATH=str(event))
        self.assertEqual(code, 0)
        self.assertIn('::notice title=Superseded::pull request #1938 is merged. The tests were stopped', out)

    def test_a_command_that_ignores_sigterm_is_killed_after_the_grace(self) -> None:
        stubborn = [sys.executable, '-c', 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                                          'print("ready", flush=True); time.sleep(60)']
        code, out, _, elapsed = self.watch(stubborn, main_at(NEWER), grace='1')
        self.assertEqual(code, 0)
        self.assertLess(elapsed, 30)
        self.assertIn('::notice title=Superseded::', out)

    def test_the_whole_session_is_stopped(self) -> None:
        """A grandchild that outlives its parent is stopped too, so nothing holds the step's pipe."""
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = pathlib.Path(tmp, 'pid')
            spawner = [sys.executable, '-c',
                       'import subprocess, sys, time; '
                       'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]); '
                       f'open({str(pidfile)!r}, "w").write(str(child.pid)); time.sleep(60)']
            code, _, _, _ = self.watch(spawner, main_at(NEWER))
            self.assertEqual(code, 0)
            grandchild = int(pidfile.read_text(encoding='utf-8'))
        for _ in range(50):
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            os.kill(grandchild, signal.SIGKILL)
            self.fail('the grandchild outlived the watcher')

    def test_a_failure_on_a_current_commit_keeps_its_status(self) -> None:
        """The KTLO and experimental semantics: the tests' status, unchanged, current or not askable."""
        failing = [sys.executable, '-c', 'import sys, time; time.sleep(0.7); sys.exit(3)']
        for routes in (main_at(OURS), {f'repos/{REPO}/commits/main': 500},
                       {f'repos/{REPO}/commits/main': urllib.error.URLError('down')}):
            with self.subTest(routes=routes):
                code, out, files, _ = self.watch(failing, routes)
                self.assertEqual(code, 3)
                self.assertEqual(workflow_commands(out), [])
                self.assertEqual(files.read(files.summary), '')
        code, _, _, _ = self.watch([sys.executable, '-c', 'pass'], main_at(OURS))
        self.assertEqual(code, 0)

    def test_an_api_failure_is_logged_once_and_the_tests_run_on(self) -> None:
        failing = [sys.executable, '-c', 'import sys, time; time.sleep(1); sys.exit(1)']
        code, out, _, _ = self.watch(failing, {f'repos/{REPO}/commits/main': 503})
        self.assertEqual(code, 1)
        self.assertEqual(out.count('util/superseded.py: could not ask the API (ApiError: HTTP 503'), 1, out)

    def test_a_signal_ends_as_a_shell_reports_it(self) -> None:
        code, _, _, _ = self.watch([sys.executable, '-c', 'import os, signal; os.kill(os.getpid(), signal.SIGKILL)'],
                                   main_at(OURS))
        self.assertEqual(code, 128 + signal.SIGKILL)

    def test_an_unwatched_event_never_asks(self) -> None:
        api = FakeApi({})
        files = Files(self)
        code = superseded.main(['watch', '--interval', '0.1', '--', sys.executable, '-c', 'import time; time.sleep(0.5)'],
                               env=files.env(GITHUB_EVENT_NAME='workflow_dispatch'), transport=api, out=io.StringIO())
        self.assertEqual((code, api.requests), (0, []))


#: A pull request state each escape of a message changes: ``%``, CR and LF.
ODD_STATE = 'odd 50%\r\nstate: a, b'
#: :data:`ODD_STATE` as a message holds it.
ODD_DATA = 'odd 50%25%0D%0Astate: a, b'


class TestTheWorkflowCommands(unittest.TestCase):
    """#2047: the whole of what ``check`` and ``watch`` print, append to the summary and output, byte for byte.

    The tests above read the commands one by one; these pin each run's whole
    standard output and files, with text each escape changes, so any change
    to what is written fails here.

    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2047-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.event = pathlib.Path(tmp.name, 'event.json')
        self.event.write_text(json.dumps({'pull_request': {'number': 1938, 'head': {'sha': OURS}}}),
                              encoding='utf-8')

    def run_main(self, argv: 'List[str]', files: 'Files', **env: 'str') -> 'Tuple[int, str]':
        out = io.StringIO()
        code = superseded.main(argv, env=files.env(GITHUB_EVENT_NAME='pull_request',
                                                   GITHUB_EVENT_PATH=str(self.event), **env),
                               transport=FakeApi(pull_is(ODD_STATE)), out=out,
                               run=lambda argv: 1, kill=lambda pid, signum: None)
        return code, out.getvalue()

    def test_the_gate(self) -> None:
        for superseded_state, current in ((ODD_STATE, 'false'), ('open', 'true')):
            with self.subTest(state=superseded_state):
                files = Files(self)
                files.output.write_bytes(b'before\n')
                files.summary.write_bytes(b'before\n')
                out = io.StringIO()
                code = superseded.main(['check'], env=files.env(GITHUB_EVENT_NAME='pull_request',
                                                                GITHUB_EVENT_PATH=str(self.event)),
                                       transport=FakeApi(pull_is(superseded_state)), out=out)
                self.assertEqual(code, 0)
                self.assertEqual(files.output.read_bytes(), f'before\ncurrent={current}\n'.encode())
                skipped = 'The rest of this run is skipped, so none of its jobs fails or is cancelled.'
                if current == 'true':
                    self.assertEqual(out.getvalue(), f'current: {OURS[:9]} is the head of pull request #1938\n')
                    self.assertEqual(files.summary.read_bytes(), b'before\n')
                    continue
                self.assertEqual(out.getvalue(), f'superseded: pull request #1938 is {ODD_STATE}\n'
                                                 f'::notice title=Superseded::pull request #1938 is {ODD_DATA}. '
                                                 f'{skipped}\n')
                self.assertEqual(files.summary.read_bytes(),
                                 f'before\n- Superseded: pull request #1938 is {ODD_STATE}. {skipped}\n'.encode())

    def test_no_output_or_summary_file(self) -> None:
        """Unset or empty, neither is written; a summary that will not open is said in the log."""
        for name, value in (('unset', None), ('empty', '')):
            with self.subTest(files=name):
                files = Files(self)
                env = files.env()
                for key in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'):
                    if value is None:
                        del env[key]
                    else:
                        env[key] = value
                code = superseded.main(['check'], env=env, transport=FakeApi(main_at(NEWER)), out=io.StringIO())
                self.assertEqual(code, 0)
                self.assertEqual(sorted(path.name for path in files.root.iterdir()), [])
        files = Files(self)
        out = io.StringIO()
        code = superseded.main(['check'], env=files.env(GITHUB_STEP_SUMMARY=str(files.root)),
                               transport=FakeApi(main_at(NEWER)), out=out)
        self.assertEqual(code, 0)
        reason = f'main is at {NEWER[:9]}, no longer at {OURS[:9]}'
        self.assertEqual(out.getvalue(), f'superseded: {reason}\n::notice title=Superseded::{reason}. The rest of '
                                         'this run is skipped, so none of its jobs fails or is cancelled.\n'
                                         f"Could not write the job summary: [Errno 21] Is a directory: "
                                         f"'{files.root}'\n")
        self.assertEqual(files.output.read_bytes(), b'current=false\n')

    @unittest.skipUnless(POSIX, 'the watcher signals a process group, as on the Ubuntu runners')
    def test_a_watch_that_cannot_stop_the_tests(self) -> None:
        """The warning escapes the scope's ``%`` and line break too; the summary keeps them."""
        files = Files(self)
        files.summary.write_bytes(b'before\n')
        scope = 'odd%\nscope'
        code, printed = self.run_main(['watch', '--interval', '0.1', '--grace', '0.2', '--kill-wait', '0.2',
                                       '--scope', scope, '--', *SLEEPER], files)
        self.assertEqual(code, superseded.STOP_FAILED)
        match = re.search(r'the session of pid (\d+) ', printed)
        self.assertIsNotNone(match, printed)
        pid = match.group(1) if match else ''
        os.kill(int(pid), signal.SIGKILL)
        reason = (f'pull request #1938 is {ODD_STATE}, but SIGTERM and SIGKILL to the scope {scope} and the session '
                  f'of pid {pid} did not end it within 0 s. The tests may run on until their timeout.')
        escaped = reason.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        self.assertEqual(printed, f'::warning title=Superseded run not stopped::{escaped}\n')
        self.assertIn('odd%25%0Ascope', escaped)
        self.assertEqual(files.summary.read_bytes(), f'before\n- Superseded run not stopped: {reason}\n'.encode())
        self.assertEqual(files.read(files.output), '')

    @unittest.skipUnless(POSIX, 'the watcher signals a process group, as on the Ubuntu runners')
    def test_a_watch_that_stops_the_tests(self) -> None:
        files = Files(self)
        out = io.StringIO()
        env = files.env(GITHUB_EVENT_NAME='pull_request', GITHUB_EVENT_PATH=str(self.event))
        code = superseded.watch(SLEEPER, superseded.Context.from_env(env),
                                superseded.Api('token', FakeApi(pull_is(ODD_STATE))), env, out, interval=0.1,
                                grace=5, clock=iter([0.0, 7.9]).__next__)
        self.assertEqual(code, 0)
        outcome = 'The tests were stopped after 7 s, and this step succeeds.'
        self.assertEqual(out.getvalue(), f'::notice title=Superseded::pull request #1938 is {ODD_DATA}. {outcome}\n')
        self.assertEqual(files.summary.read_bytes(),
                         f'- Superseded: pull request #1938 is {ODD_STATE}. {outcome}\n'.encode())
        # A stop records ``stopped=true`` for Upload test timings (#2073).
        self.assertEqual(files.read(files.output), 'stopped=true\n')


class Server(http.server.ThreadingHTTPServer):
    """The API, answering ``/repos/<repo>/commits/main`` with ``head``."""

    head = NEWER


class Handler(http.server.BaseHTTPRequestHandler):

    def do_GET(self) -> 'None':  # pylint: disable=invalid-name
        if self.path != f'/repos/{REPO}/commits/main':
            self.send_error(404)
            return
        body = json.dumps({'sha': self.server.head}).encode()  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: 'str', *args: 'Any') -> 'None':  # pylint: disable=redefined-builtin
        pass


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheTestsStep(unittest.TestCase):
    """``Run unit tests`` itself, with ``python`` a stub that runs until stopped and the API a local server."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1938-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.temp = self.tmp / 'temp'
        self.temp.mkdir()
        bindir = self.tmp / 'bin'
        bindir.mkdir()
        (self.temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        # No real sudo: the probe fails, so the tests run uncapped, the same argv as in the scope.
        for name, body in (('sudo', 'echo "sudo: a password is required" >&2\nexit 1\n'),
                           ('python', 'echo collected\nexec sleep 60\n')):
            (bindir / name).write_text('#!/bin/sh\n' + body, encoding='utf-8')
            (bindir / name).chmod(0o755)
        self.server = Server(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
        self.env.update(RUNNER_TEMP=str(self.temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3', GRAAL_PYTHON_VM_ARGS='',
                        GITHUB_STEP_SUMMARY=str(self.tmp / 'summary.md'), GH_TOKEN='token',
                        GITHUB_API_URL=f'http://127.0.0.1:{self.server.server_address[1]}',
                        GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=OURS,
                        GITHUB_REPOSITORY=REPO, PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''),
                        # `watcher-python` and its requests: this interpreter, which has requests.
                        WATCHER='success', WATCHER_PYTHON=sys.executable)

    def test_without_the_watchers_interpreter_the_tests_run_unwatched(self) -> None:
        """A failed `watcher-python` or requests install runs the tests unwatched, with their own status."""
        bindir = pathlib.Path(self.env['PATH'].split(os.pathsep)[0])
        (bindir / 'python').write_text('#!/bin/sh\nsleep 1.5\nexit 3\n', encoding='utf-8')
        for outcome, path in (('failure', sys.executable), ('skipped', ''), ('success', '/nonexistent/python')):
            with self.subTest(outcome=outcome, path=path):
                env = dict(self.env, WATCHER=outcome, WATCHER_PYTHON=path)
                # Superseded, so a watcher would have stopped the tests and exited 0.
                result = sh(self.script(), env, DEFAULT)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertIn('No watcher: its interpreter or requests did not install', result.stdout)
                self.assertEqual(workflow_commands(result.stdout), [])

    def script(self) -> 'str':
        script = step(TESTS)['run']
        quick = script.replace('watch --interval 60 --grace 30 ', 'watch --interval 0.5 --grace 2 --kill-wait 2 ')
        self.assertNotEqual(quick, script)
        return quick

    def status(self) -> 'Dict[str, str]':
        text = (self.temp / 'tests-status').read_text(encoding='utf-8')
        return dict(line.split('=', 1) for line in text.splitlines())

    def test_a_superseded_run_stops_the_tests_and_the_step_succeeds(self) -> None:
        result = sh(self.script(), self.env, DEFAULT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('collected', result.stdout)
        commands = workflow_commands(result.stdout)
        self.assertEqual(len(commands), 1, result.stdout)
        self.assertTrue(commands[0].startswith(
            f'::notice title=Superseded::main is at {NEWER[:9]}, no longer at {OURS[:9]}. '), commands[0])
        self.assertIn('- Superseded: main is at', (self.tmp / 'summary.md').read_text(encoding='utf-8'))
        self.assertEqual((self.status()['exit'], self.status()['scope']), ('0', 'none'))

    def test_a_scoped_run_is_stopped_through_its_scope(self) -> None:
        """In the scope, ``timeout`` and pytest are out of the session's reach; ``systemctl kill`` is not.

        ``sudo`` is a stub that runs the scope's command and plays systemd for
        ``systemctl kill``, signalling the pid the tests wrote. The tests leave
        the session as the scoped ones are out of its reach, so only the scope's
        kill can end them: without it, they hold the step's output for 60 s.

        """
        bindir = pathlib.Path(self.env['PATH'].split(os.pathsep)[0])
        pidfile, calls = self.tmp / 'pid', self.tmp / 'systemctl'
        (bindir / 'sudo').write_text(
            '#!/bin/sh\n'
            f'if [ "$2" = systemctl ]; then echo "$*" >> {calls}; '
            f'[ -s {pidfile} ] && kill -s "${{4#--signal=SIG}}" "$(cat {pidfile})"; exit 0; fi\n'
            'while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done\n'
            '[ "$#" -gt 0 ] || exit 0\nshift\nexec "$@"\n', encoding='utf-8')
        (bindir / 'python').write_text(f'#!/bin/sh\necho $$ > {pidfile}\necho collected\nexec setsid sleep 60\n',
                                       encoding='utf-8')
        started = time.monotonic()
        result = sh(self.script(), self.env, DEFAULT)
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.status()['scope'], '12G')
        commands = workflow_commands(result.stdout)
        self.assertEqual(len(commands), 1, result.stdout)
        self.assertTrue(commands[0].startswith('::notice title=Superseded::main is at '), commands[0])
        self.assertEqual(calls.read_text(encoding='utf-8').splitlines()[0],
                         '-n systemctl kill --signal=SIGTERM pcapkit-tests.scope')

    def test_a_current_run_keeps_the_tests_status(self) -> None:
        self.server.head = OURS
        bindir = pathlib.Path(self.env['PATH'].split(os.pathsep)[0])
        (bindir / 'python').write_text('#!/bin/sh\nsleep 1.5\nexit 1\n', encoding='utf-8')
        result = sh(self.script(), self.env, DEFAULT)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [])
        self.assertFalse((self.tmp / 'summary.md').exists())

    def test_the_watcher_runs_the_scope_and_names_it(self) -> None:
        """Every cap stays on pytest, and the watcher runs outside the scope, which it names to ``--scope``."""
        script = step(TESTS)['run']
        capped = 'set -- prlimit --fsize=2147483648 "$gnu_timeout" --signal=INT --kill-after=3m 110m "$@"\n'
        scoped = 'set -- scoped pcapkit-tests.scope "$@"\n'
        named = 'watched=pcapkit-tests.scope\n'
        watched = ('set -- "$WATCHER_PYTHON" util/superseded.py watch --interval 60 --grace 30 --scope "$watched" \\\n'
                   '    --summary-copy "$RUNNER_TEMP/job-summary.md" -- "$@"\n')
        self.assertLess(script.index(capped), script.index(scoped))
        self.assertLess(script.index(scoped), script.index(named))
        self.assertLess(script.index(named), script.index(watched))
        self.assertLess(script.index(watched), script.index('"$@" 2>&1 | tee "$RUNNER_TEMP/pytest.log"'))
        # Named only where the probe passed, and the one name the tests' scope is started under.
        self.assertIn('if [ "$scope" = 12G ]; then\n', script[script.index('scope=none'):script.index(named)])
        self.assertEqual(script.count('pcapkit-tests.scope'), 2)
        self.assertIn('if [ "$WATCHER" = success ] && [ -x "$WATCHER_PYTHON" ]; then\n', script)


class TestTheUpdaterReadsTheWatchersLatest(unittest.TestCase):
    """util/update_python_versions.py reads where ``latest`` is set up, the watcher's included."""

    @staticmethod
    def workflows(runs_on: 'str', leg: 'bool' = True) -> 'Dict[str, Any]':
        """One job setting up ``latest`` on ``runs_on``, after its leg's own version where ``leg``."""
        steps = [{'id': 'v', 'run': 'python3 util/python_versions.py --github-output'},
                 {'uses': 'actions/setup-python@v7', 'with': {'python-version': '${{ steps.v.outputs.latest }}'}}]
        if leg:
            steps.insert(1, {'uses': 'actions/setup-python@v7', 'with': {'python-version': '${{ matrix.python-version }}'}})
        return {'w.yml': {'jobs': {'j': {'runs-on': runs_on, 'steps': steps}}}}

    def test_a_matrix_jobs_latest_is_on_its_fallback_label(self) -> None:
        from tests.project.test_python_versions_update_1660 import updater  # pylint: disable=import-outside-toplevel
        module = updater()
        labels = module.workflow_labels(self.workflows("${{ matrix.os || 'ubuntu-24.04' }}"))
        self.assertEqual(labels['latest'], ['ubuntu-24.04'])
        with self.assertRaisesRegex(ValueError, 'installs latest on .*which this cannot read'):
            module.workflow_labels(self.workflows('${{ matrix.runner }}', leg=False))
        # The real workflows, experimental's watcher among them, are readable too.
        self.assertIn('ubuntu-latest', module.workflow_labels(module.load_workflows(ROOT))['latest'])


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_describes_it(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ('`#1938 <https://github.com/JarryShaw/PyPCAPKit/issues/1938>`__', ':file:`util/superseded.py`',
                       '``Superseded``', '``skipped``', '``current``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)
        self.assertNotIn('cancels a superseded run', page)


if __name__ == '__main__':
    unittest.main()
