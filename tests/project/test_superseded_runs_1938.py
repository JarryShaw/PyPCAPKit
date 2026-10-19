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
import shutil
import signal
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from typing import TYPE_CHECKING

from tests.project.test_python_matrix_tiers_1633 import job, workflow, workflow_commands
from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_release_gates import evaluate_condition
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
        self.assertEqual(check['run'], 'python3 util/superseded.py check')
        self.assertEqual(check['env'], {'GH_TOKEN': '${{ github.token }}'})
        checkout = gate['steps'][0]
        self.assertTrue(checkout['uses'].startswith('actions/checkout@'))
        self.assertIn('util/superseded.py', checkout['with']['sparse-checkout'])
        self.assertIs(checkout['with']['persist-credentials'], False)

    def test_every_other_job_needs_it_and_skips_on_its_output(self) -> None:
        others = [job_id for job_id in self.jobs if job_id != GATE]
        self.assertEqual(sorted(others), ['changes', 'experimental', 'python-versions'])
        for job_id in others:
            body = self.jobs[job_id]
            needs = body['needs'] if isinstance(body['needs'], list) else [body['needs']]
            with self.subTest(job=job_id):
                self.assertIn(GATE, needs)
                self.assertIn(SKIPS_ON, body['if'])

    def run_if(self, job_id: 'str', current: 'str', code: 'str' = 'true') -> 'bool':
        context = {'needs': {GATE: {'outputs': {'current': current}, 'result': 'success'},
                             'changes': {'outputs': {'code': code}, 'result': 'success'},
                             'python-versions': {'outputs': {}, 'result': 'success'}}}
        return evaluate_condition(self.jobs[job_id]['if'], context)

    def test_a_superseded_commit_skips_every_job_and_anything_else_runs_them(self) -> None:
        for job_id in ('python-versions', 'changes', 'experimental'):
            with self.subTest(job=job_id):
                self.assertFalse(self.run_if(job_id, 'false'))
                self.assertTrue(self.run_if(job_id, 'true'))
                # A gate step that failed writes nothing; the run goes on as it did before the gate.
                self.assertTrue(self.run_if(job_id, ''))
        # A docs-only pull request still skips the legs, as before.
        self.assertFalse(self.run_if('experimental', 'true', code='false'))

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

    def watch(self, command: 'List[str]', routes: 'Dict[str, Any]', grace: 'str' = '5',
              **env: 'str') -> 'Tuple[int, str, Files, float]':
        files, out = Files(self), io.StringIO()
        started = time.monotonic()
        code = superseded.main(['watch', '--interval', '0.2', '--grace', grace, '--', *command],
                               env=files.env(**env), transport=FakeApi(routes), out=out)
        return code, out.getvalue(), files, time.monotonic() - started

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
                        GITHUB_REPOSITORY=REPO, PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''))

    def script(self) -> 'str':
        script = step(TESTS)['run']
        quick = script.replace('watch --interval 60 --grace 30 --', 'watch --interval 0.5 --grace 2 --')
        self.assertNotEqual(quick, script)
        return quick

    def test_a_superseded_run_stops_the_tests_and_the_step_succeeds(self) -> None:
        result = sh(self.script(), self.env, DEFAULT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('collected', result.stdout)
        commands = workflow_commands(result.stdout)
        self.assertEqual(len(commands), 1, result.stdout)
        self.assertTrue(commands[0].startswith(
            f'::notice title=Superseded::main is at {NEWER[:9]}, no longer at {OURS[:9]}. '), commands[0])
        self.assertIn('- Superseded: main is at', (self.tmp / 'summary.md').read_text(encoding='utf-8'))
        status = dict(line.split('=', 1) for line in (self.temp / 'tests-status').read_text(encoding='utf-8')
                      .splitlines())
        self.assertEqual((status['exit'], status['scope']), ('0', 'none'))

    def test_a_current_run_keeps_the_tests_status(self) -> None:
        self.server.head = OURS
        bindir = pathlib.Path(self.env['PATH'].split(os.pathsep)[0])
        (bindir / 'python').write_text('#!/bin/sh\nsleep 1.5\nexit 1\n', encoding='utf-8')
        result = sh(self.script(), self.env, DEFAULT)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [])
        self.assertFalse((self.tmp / 'summary.md').exists())

    def test_the_watcher_wraps_the_capped_command_inside_the_scope(self) -> None:
        """Every cap stays on pytest: the watcher runs prlimit, timeout and pytest, and the scope runs it."""
        script = step(TESTS)['run']
        capped = 'set -- prlimit --fsize=2147483648 timeout --signal=INT --kill-after=3m 110m python -m pytest "$@"\n'
        watched = 'set -- "$watcher" util/superseded.py watch --interval 60 --grace 30 -- "$@"\n'
        scoped = 'set -- scoped pcapkit-tests.scope "$@"\n'
        self.assertLess(script.index(capped), script.index(watched))
        self.assertLess(script.index(watched), script.index(scoped))
        self.assertIn('watcher=/usr/bin/python3\n', script)


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
