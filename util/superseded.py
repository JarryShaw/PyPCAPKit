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
superseded, it sends the session SIGTERM, then SIGKILL after ``--grace``
seconds, writes the notice and the summary line, and exits 0. Otherwise it
exits with ``COMMAND``'s own status, ``128 + N`` for a signal ``N`` as a shell
reports it, so a test failure on a current commit reads as it did without the
watcher. SIGINT, SIGTERM and SIGHUP sent to the watcher are passed on to
``COMMAND``.

The API is read with conditional requests: a ``304 Not Modified`` answer to an
``If-None-Match`` request does not count against the primary rate limit
(docs.github.com, "Best practices for using the REST API"), and ``GITHUB_TOKEN``
has a limit per repository that every concurrent leg's polling shares.

The script needs nothing outside the standard library, so the workflow runs it
on the runner's own ``python3`` rather than on the leg's interpreter.

"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess  # nosec B404
import sys
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

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
#: Seconds one API request may take before it counts as failed.
TIMEOUT = 15.0
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


def urllib_transport(url: 'str', headers: 'Dict[str, str]') -> 'Tuple[int, Dict[str, str], bytes]':
    """The default transport: one GET, an HTTP error status returned rather than raised."""
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # nosec B310 -- the API's root, GITHUB_API_URL
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()) if error.headers else {}, error.read()


class Api:
    """GET requests to the REST API, each repeated with its last ``ETag``.

    Args:
        token: Sent as a bearer token where not empty.
        transport: Replaces the network, for tests.
        base: The API's root.

    """

    def __init__(self, token: 'str', transport: 'Optional[Transport]' = None, base: 'str' = API) -> 'None':
        self.token = token
        self.transport = transport or urllib_transport
        self.base = base.rstrip('/')
        self._cache = {}  # type: Dict[str, Tuple[str, Any]]

    def get(self, path: 'str') -> 'Any':
        """``path``'s JSON, or the last copy where the API answers ``304 Not Modified``."""
        url = f'{self.base}/{path}'
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                   'User-Agent': 'pcapkit-superseded'}
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


def escape(message: 'str') -> 'str':
    """``message`` as a workflow command's message must hold it."""
    return message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def report(verdict: 'Verdict', outcome: 'str', env: 'Mapping[str, str]', out: 'IO[str]') -> 'None':
    """The ``Superseded`` notice, and its job-summary line where the job has a summary file."""
    print(f'::notice title=Superseded::{escape(verdict.reason)}. {escape(outcome)}', file=out, flush=True)
    summary = env.get('GITHUB_STEP_SUMMARY')
    if summary:
        try:
            with open(summary, 'a', encoding='utf-8') as file:
                print(f'- Superseded: {verdict.reason}. {outcome}', file=file)
        except OSError as error:
            print(f'Could not write the job summary: {error}', file=out, flush=True)


def gate(context: 'Context', api: 'Api', env: 'Mapping[str, str]', out: 'IO[str]') -> 'int':
    """The gate job: ``current=true`` or ``current=false``, in ``$GITHUB_OUTPUT``."""
    verdict = check(context, api)
    print(f'{verdict.state}: {verdict.reason}', file=out, flush=True)
    if not verdict.current:
        report(verdict, 'The rest of this run is skipped, so none of its jobs fails or is cancelled.', env, out)
    output = env.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as file:
            print(f'current={str(verdict.current).lower()}', file=file)
    return 0


def exit_status(returncode: 'int') -> 'int':
    """``returncode`` as a shell reports it: ``128 + N`` for a process ended by signal ``N``."""
    return 128 - returncode if returncode < 0 else returncode


def signal_session(pid: 'int', signum: 'int') -> 'None':
    """``signum`` to every process in ``pid``'s process group, where any is left."""
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            os.kill(pid, signum)
        except OSError:
            pass


def stop(child: 'subprocess.Popen[bytes]', grace: 'float') -> 'None':
    """SIGTERM to ``child``'s session, SIGKILL ``grace`` seconds on, then to whatever outlived it."""
    signal_session(child.pid, signal.SIGTERM)
    try:
        child.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        signal_session(child.pid, signal.SIGKILL)
        child.wait()
    # A worker that outlived the leader would hold the step's pipe open.
    signal_session(child.pid, signal.SIGKILL)


def watch(command: 'Sequence[str]', context: 'Context', api: 'Api', env: 'Mapping[str, str]', out: 'IO[str]', *,
          interval: 'float' = INTERVAL, grace: 'float' = GRACE,
          clock: 'Callable[[], float]' = time.monotonic) -> 'int':
    """Run ``command``, stopping it once ``context``'s commit is superseded."""
    started = clock()
    # A session of its own, so SIGKILL reaches every process the command started.
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
            stop(child, grace)
            elapsed = int(clock() - started)
            report(verdict, f'The tests were stopped after {elapsed} s, and this step succeeds.', env, out)
            return 0
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv: 'Optional[List[str]]' = None, *, env: 'Optional[Mapping[str, str]]' = None,
         transport: 'Optional[Transport]' = None, out: 'Optional[IO[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    commands = parser.add_subparsers(dest='action')
    commands.add_parser('check', help="the gate: write current=true or current=false to $GITHUB_OUTPUT")
    watcher = commands.add_parser('watch', help='run a command, stopping it once the commit is superseded')
    watcher.add_argument('--interval', type=float, default=INTERVAL, help='seconds between checks')
    watcher.add_argument('--grace', type=float, default=GRACE, help='seconds from SIGTERM to SIGKILL')
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
        return watch(command, context, api, env, out, interval=args.interval, grace=args.grace)
    parser.error('name an action: check or watch')
    return 2  # unreachable: parser.error exits


if __name__ == '__main__':
    sys.exit(main())
