# -*- coding: utf-8 -*-
"""Whether an Experimental Tests run's commit is still the one worth testing (#1938).

GitHub counts a ``cancelled`` check against its commit in the status rollup,
so cancelling a superseded run (#1903) marks that commit with a red X, and a
merged pull request's last run, which no newer run supersedes, keeps its runner
for the whole GraalPy leg. So experimental.yml cancels nothing and asks this
script instead, which ends a superseded run green.

A run's commit is **current** when

* for a ``push`` to ``main``: the run's ``GITHUB_SHA`` is still the head of
  ``main`` (``GET /repos/{repo}/commits/main``);
* for a ``pull_request``: the pull request is still open, and its head is still
  the event's ``pull_request.head.sha`` (``GET /repos/{repo}/pulls/{number}``);
* for any other event: always.

Anything the script cannot read -- an HTTP error, a timeout, a missing token,
an event file without a pull request -- counts as current, so a failing API
never stops a test run that would otherwise have finished.

``check`` is the gate job: it writes ``current=true`` or ``current=false`` to
``$GITHUB_OUTPUT``, and where the commit is superseded a ``Superseded`` notice
and a job-summary line, so every later job can skip on ``if:``. It exits 0.

``watch -- COMMAND...`` runs ``COMMAND`` in a session of its own and asks the
same question every ``--interval`` seconds while it runs. Once the commit is
superseded, it sends SIGTERM, then SIGKILL after ``--grace`` seconds, to the
session or, with ``--scope UNIT``, to every process of that systemd scope
(``sudo -n systemctl kill``): ``COMMAND`` then starts a root-owned ``sudo``, and
the tests run in the scope as the runner's user, out of reach of a signal to
the session's group (:func:`stop`). Where ``COMMAND`` exits, it writes the notice and the summary
line and exits 0. Otherwise it exits with ``COMMAND``'s own status, ``128 + N``
for a signal ``N`` as a shell reports it, so a test failure on a current commit
reads as it did without the watcher. SIGINT, SIGTERM and SIGHUP sent to the
watcher are passed on to ``COMMAND``.

Every wait is bounded. Where ``COMMAND`` outlives SIGKILL by ``--kill-wait``
seconds, the watcher writes a ``Superseded run not stopped`` warning and exits
:data:`STOP_FAILED`, not 0: the tests may still be running, and holding the
step's output open, until their own ``timeout`` or the step's cap ends them, so
the step reports a failure -- a warning on these non-blocking legs -- rather
than claiming it stopped them.

The API is read with conditional requests: a ``304 Not Modified`` answer to an
``If-None-Match`` request does not count against the primary rate limit
(docs.github.com, "Best practices for using the REST API"), and ``GITHUB_TOKEN``
has a limit per repository that every concurrent leg's polling shares.

It fetches with :mod:`requests`, as util/ci_timing.py does. Without it the
script still runs, and every request fails, so the commit counts as current:
the gate writes ``current=true``, and the watcher runs the tests to the end.

"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess  # nosec B404
import sys
import time
from typing import TYPE_CHECKING

try:
    import requests
except ImportError:  # pragma: no cover -- every test interpreter has it
    requests = None  # type: ignore[assignment]

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from types import FrameType
    from typing import IO, Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

    #: One GET: the URL and request headers in, the status, headers and body out.
    Transport = Callable[[str, Dict[str, str]], Tuple[int, Dict[str, str], bytes]]

#: The REST API's root, where ``GITHUB_API_URL`` does not name one.
API = 'https://api.github.com'
#: The two answers.
CURRENT, SUPERSEDED = 'current', 'superseded'
#: Seconds between two checks while ``watch`` runs its command.
INTERVAL = 60.0
#: Seconds between SIGTERM and SIGKILL once the commit is superseded.
GRACE = 30.0
#: Seconds to wait for the command to exit after SIGKILL.
KILL_WAIT = 15.0
#: Seconds one API request, or one ``systemctl kill``, may take before it counts as failed.
TIMEOUT = 15.0
#: ``watch``'s status where the command outlives SIGKILL: sysexits.h's ``EX_SOFTWARE``,
#: which neither pytest (0-5) nor ``timeout`` (124-137) exits with.
STOP_FAILED = 70
#: The signals ``watch`` passes on to its command.
FORWARDED = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class ApiError(Exception):
    """The API gave no usable answer."""


class Context:
    """What a run tests: its event, ref, commit, repository and pull request.

    Args:
        event: ``GITHUB_EVENT_NAME``.
        ref: ``GITHUB_REF``.
        sha: The commit under test -- ``GITHUB_SHA`` for a push, the
            pull request's head for a ``pull_request`` run, whose
            ``GITHUB_SHA`` is a merge commit.
        repo: ``owner/name``.
        number: The pull request's number, for a ``pull_request`` run.

    """

    def __init__(self, event: 'str', ref: 'str', sha: 'str', repo: 'str', number: 'Optional[int]' = None) -> 'None':
        self.event = event
        self.ref = ref
        self.sha = sha
        self.repo = repo
        self.number = number

    @classmethod
    def from_env(cls, env: 'Mapping[str, str]') -> 'Context':
        """The run's context, from the variables every step of a job has."""
        event = env.get('GITHUB_EVENT_NAME', '')
        sha = env.get('GITHUB_SHA', '')
        number = None  # type: Optional[int]
        if event == 'pull_request':
            sha, number = '', None
            try:
                with open(env.get('GITHUB_EVENT_PATH', ''), encoding='utf-8') as file:
                    pull = json.load(file).get('pull_request') or {}
                sha = str((pull.get('head') or {}).get('sha') or '')
                number = int(pull['number']) if pull.get('number') else None
            except (OSError, ValueError, TypeError, AttributeError):
                pass
        return cls(event, env.get('GITHUB_REF', ''), sha, env.get('GITHUB_REPOSITORY', ''), number)

    @property
    def watched(self) -> 'bool':
        """Whether a newer commit can supersede this run at all."""
        return (self.event == 'push' and self.ref == 'refs/heads/main') or self.event == 'pull_request'


class Verdict:
    """:data:`CURRENT` or :data:`SUPERSEDED`, and why.

    ``error`` is set where the API could not answer, and the commit counts as
    current for that reason alone.

    """

    def __init__(self, state: 'str', reason: 'str', error: 'bool' = False) -> 'None':
        self.state = state
        self.reason = reason
        self.error = error

    @property
    def current(self) -> 'bool':
        return self.state == CURRENT

    def __repr__(self) -> 'str':
        return f'Verdict({self.state!r}, {self.reason!r}, error={self.error!r})'


class Api:
    """GET requests to the REST API, each repeated with its last ``ETag``.

    Args:
        token: Sent as a bearer token where not empty.
        transport: Replaces the network, for tests.
        base: The API's root.

    """

    def __init__(self, token: 'str', transport: 'Optional[Transport]' = None, base: 'str' = API) -> 'None':
        self.token = token
        self.transport = transport or self._get
        self.base = base.rstrip('/')
        self._cache = {}  # type: Dict[str, Tuple[str, Any]]
        #: The connection :meth:`_get` reuses from one check to the next, opened on its first call.
        self.session = None  # type: Optional[requests.Session]

    def _get(self, url: 'str', headers: 'Dict[str, str]') -> 'Tuple[int, Dict[str, str], bytes]':
        """The default transport: one GET, its status returned rather than raised, as a 304 is an answer."""
        if requests is None:
            raise ApiError('requests is not installed')
        if self.session is None:
            self.session = requests.Session()
        response = self.session.get(url, timeout=TIMEOUT, headers=headers)
        return response.status_code, {k.lower(): v for k, v in response.headers.items()}, response.content

    def get(self, path: 'str') -> 'Any':
        """``path``'s JSON, or the last copy where the API answers ``304 Not Modified``."""
        url = f'{self.base}/{path}'
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                   'User-Agent': 'PyPCAPKit-superseded'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        cached = self._cache.get(url)
        if cached is not None:
            headers['If-None-Match'] = cached[0]
        status, response_headers, body = self.transport(url, headers)
        if status == 304 and cached is not None:
            return cached[1]
        if status != 200:
            raise ApiError(f'HTTP {status} from GET /{path}')
        data = json.loads(body.decode('utf-8'))
        etag = next((value for key, value in response_headers.items() if key.lower() == 'etag'), '')
        if etag:
            self._cache[url] = (etag, data)
        return data


def check(context: 'Context', api: 'Api') -> 'Verdict':
    """Whether ``context``'s commit is still current; an API failure is current."""
    short = context.sha[:9]
    try:
        if context.event == 'push' and context.ref == 'refs/heads/main':
            head = str(api.get(f'repos/{context.repo}/commits/main')['sha'])
            if head != context.sha:
                return Verdict(SUPERSEDED, f'main is at {head[:9]}, no longer at {short}')
            return Verdict(CURRENT, f'{short} is the head of main')
        if context.event == 'pull_request':
            if not (context.number and context.sha):
                return Verdict(CURRENT, 'the event file names no pull request head, so nothing can supersede it')
            pull = api.get(f'repos/{context.repo}/pulls/{context.number}')
            if pull['state'] != 'open':
                state = 'merged' if pull.get('merged') else str(pull['state'])
                return Verdict(SUPERSEDED, f'pull request #{context.number} is {state}')
            head = str(pull['head']['sha'])
            if head != context.sha:
                return Verdict(SUPERSEDED, f'pull request #{context.number} is at {head[:9]}, no longer at {short}')
            return Verdict(CURRENT, f'{short} is the head of pull request #{context.number}')
        return Verdict(CURRENT, f"a {context.event or 'unnamed'} event's run is never superseded")
    except Exception as error:  # pylint: disable=broad-except
        # Whatever the API did, the tests go on: stopping them is the one thing a failure must not do.
        return Verdict(CURRENT, f'could not ask the API ({type(error).__name__}: {error}), '
                                'so the commit counts as current', error=True)


def report(verdict: 'Verdict', outcome: 'str', env: 'Mapping[str, str]', out: 'IO[str]') -> 'None':
    """The ``Superseded`` notice, and its job-summary line where the job has a summary file."""
    _actions.annotate('notice', f'{verdict.reason}. {outcome}', title='Superseded', stream=out)
    try:
        _actions.summary(f'- Superseded: {verdict.reason}. {outcome}', required=False, environ=env)
    except OSError as error:
        print(f'Could not write the job summary: {error}', file=out, flush=True)


def gate(context: 'Context', api: 'Api', env: 'Mapping[str, str]', out: 'IO[str]') -> 'int':
    """The gate job: ``current=true`` or ``current=false``, in ``$GITHUB_OUTPUT``."""
    verdict = check(context, api)
    print(f'{verdict.state}: {verdict.reason}', file=out, flush=True)
    if not verdict.current:
        report(verdict, 'The rest of this run is skipped, so none of its jobs fails or is cancelled.', env, out)
    _actions.set_output('current', str(verdict.current).lower(), required=False, environ=env)
    return 0


def exit_status(returncode: 'int') -> 'int':
    """``returncode`` as a shell reports it: ``128 + N`` for a process ended by signal ``N``."""
    return 128 - returncode if returncode < 0 else returncode


def signal_session(pid: 'int', signum: 'int') -> 'None':
    """``signum`` to every process in ``pid``'s process group that will take it.

    A refusal is not an error here: under ``sudo`` the group's leader is root,
    and the scope (:func:`stop`) is what reaches the tests there.

    """
    try:
        os.killpg(pid, signum)
    except OSError:
        try:
            os.kill(pid, signum)
        except OSError:
            pass


def run_command(argv: 'Sequence[str]') -> 'int':
    """The default command runner: ``argv``'s exit status, ``-1`` where it could not run or finish in time."""
    try:
        return subprocess.run(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,  # nosec B603
                              stderr=subprocess.DEVNULL, timeout=TIMEOUT, check=False).returncode
    except (OSError, subprocess.SubprocessError):
        return -1


def scope_kill(scope: 'str', signum: 'int') -> 'List[str]':
    """The command that sends ``signum`` to every process in the systemd unit ``scope``."""
    return ['sudo', '-n', 'systemctl', 'kill', f'--signal={signal.Signals(signum).name}', scope]


def ended(child: 'subprocess.Popen[bytes]', timeout: 'float') -> 'bool':
    """Whether ``child`` has exited within ``timeout`` seconds."""
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return True


def stop(child: 'subprocess.Popen[bytes]', grace: 'float', *, scope: 'str' = '', kill_wait: 'float' = KILL_WAIT,
         run: 'Callable[[Sequence[str]], int]' = run_command,
         kill: 'Callable[[int, int], None]' = signal_session) -> 'bool':
    """SIGTERM, then SIGKILL ``grace`` seconds on; whether ``child`` exited, each wait bounded.

    Where the tests run in ``scope``, a systemd unit, each signal goes to every
    process of it, through ``sudo``: they run as the runner's user under a
    root-owned ``sudo``, and ``timeout`` puts them in a process group of its
    own, so no signal to ``child``'s session reaches them. SIGTERM goes to the
    scope alone there, since the session's shell would end at once and the
    tests would lose their grace; SIGKILL goes to the session too. Where there
    is no scope, ``child`` is ``timeout`` itself, its session's leader, and its
    session is the tests.

    """
    for signum, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, kill_wait)):
        if scope:
            run(scope_kill(scope, signum))
        if not scope or signum == signal.SIGKILL:
            kill(child.pid, signum)
        if ended(child, wait):
            # A process that outlived the leader would hold the step's pipe open.
            if scope:
                run(scope_kill(scope, signal.SIGKILL))
            kill(child.pid, signal.SIGKILL)
            return True
    return False


def watch(command: 'Sequence[str]', context: 'Context', api: 'Api', env: 'Mapping[str, str]', out: 'IO[str]', *,
          interval: 'float' = INTERVAL, grace: 'float' = GRACE, scope: 'str' = '', kill_wait: 'float' = KILL_WAIT,
          run: 'Callable[[Sequence[str]], int]' = run_command, kill: 'Callable[[int, int], None]' = signal_session,
          clock: 'Callable[[], float]' = time.monotonic) -> 'int':
    """Run ``command``, stopping it once ``context``'s commit is superseded.

    :data:`STOP_FAILED` where it cannot be stopped: see the module's docstring.

    """
    started = clock()
    # A session of its own, so a signal to the group reaches every process the command started.
    child = subprocess.Popen(list(command), start_new_session=True)  # nosec B603 pylint: disable=consider-using-with

    def forward(signum: 'int', frame: 'Optional[FrameType]') -> 'None':  # pylint: disable=unused-argument
        try:
            os.kill(child.pid, signum)
        except OSError:
            pass

    previous = {signum: signal.signal(signum, forward) for signum in FORWARDED}
    try:
        last_error = ''
        while True:
            try:
                return exit_status(child.wait(timeout=interval if context.watched else None))
            except subprocess.TimeoutExpired:
                pass
            verdict = check(context, api)
            if verdict.error and verdict.reason != last_error:
                print(f'util/superseded.py: {verdict.reason}', file=out, flush=True)
            last_error = verdict.reason if verdict.error else ''
            if verdict.current:
                continue
            if stop(child, grace, scope=scope, kill_wait=kill_wait, run=run, kill=kill):
                elapsed = int(clock() - started)
                report(verdict, f'The tests were stopped after {elapsed} s, and this step succeeds.', env, out)
                return 0
            where = f'the scope {scope} and ' if scope else ''
            reason = (f'{verdict.reason}, but SIGTERM and SIGKILL to {where}the session of pid {child.pid} '
                      f'did not end it within {int(grace + kill_wait)} s. The tests may run on until their timeout.')
            _actions.annotate('warning', reason, title='Superseded run not stopped', stream=out)
            try:
                _actions.summary(f'- Superseded run not stopped: {reason}', required=False, environ=env)
            except OSError:
                pass
            return STOP_FAILED
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv: 'Optional[List[str]]' = None, *, env: 'Optional[Mapping[str, str]]' = None,
         transport: 'Optional[Transport]' = None, out: 'Optional[IO[str]]' = None,
         run: 'Callable[[Sequence[str]], int]' = run_command,
         kill: 'Callable[[int, int], None]' = signal_session) -> 'int':
    """The command line; ``transport``, ``run`` and ``kill`` replace the network, commands and signals in tests."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    commands = parser.add_subparsers(dest='action')
    commands.add_parser('check', help="the gate: write current=true or current=false to $GITHUB_OUTPUT")
    watcher = commands.add_parser('watch', help='run a command, stopping it once the commit is superseded')
    watcher.add_argument('--interval', type=float, default=INTERVAL, help='seconds between checks')
    watcher.add_argument('--grace', type=float, default=GRACE, help='seconds from SIGTERM to SIGKILL')
    watcher.add_argument('--kill-wait', type=float, default=KILL_WAIT, help='seconds to wait after SIGKILL')
    watcher.add_argument('--scope', default='', help='the systemd scope the command runs its tests in, if any')
    watcher.add_argument('command', nargs=argparse.REMAINDER, help='the command, after --')
    args = parser.parse_args(argv)

    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    context = Context.from_env(env)
    api = Api(env.get('GH_TOKEN') or env.get('GITHUB_TOKEN') or '', transport, env.get('GITHUB_API_URL') or API)
    if args.action == 'check':
        return gate(context, api, env, out)
    if args.action == 'watch':
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        if not command:
            parser.error('watch needs a command after --')
        return watch(command, context, api, env, out, interval=args.interval, grace=args.grace, scope=args.scope,
                     kill_wait=args.kill_wait, run=run, kill=kill)
    parser.error('name an action: check or watch')
    return 2  # unreachable: parser.error exits


if __name__ == '__main__':
    sys.exit(main())
