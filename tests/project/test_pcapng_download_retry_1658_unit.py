# -*- coding: utf-8 -*-
""":file:`examples/generators/pcapng.py` retries a transient download failure.

GitHub issue #1658. With one attempt, an HTTP 429 from the Wireshark mirror
sends a CI leg straight to the synthesised stand-in. So ``_download`` retries an
HTTP 429 or 5xx, or a timeout, with backoff, honouring ``Retry-After``, within a
small budget; any other failure falls back at once.

#1894 moved the download from :mod:`urllib.request` to :mod:`requests`.
:class:`DownloadRetryTests` runs against a stubbed ``requests.get`` and a fake
clock bound over the generator's ``time``, so nothing touches the network or
sleeps. :class:`LocalServerTests` sends real requests to a server on the
loopback interface, because what :mod:`requests` raises for a timeout while the
body is read is its own behaviour, not something a stub can show. This module
is unit-tier and reads no capture.

"""
from __future__ import annotations

import contextlib
import email.utils
import http.client
import http.server
import importlib.util
import io
import os
import pathlib
import socket
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import requests
import urllib3

from tests._support import PCAPNG_GENERATOR, scale_timeout

#: Test tier (#1958): drives the PCAP-NG generator's download retry with HTTP mocked.
__tier__ = 'LATEST'

#: URL the stubbed getter is asked for.
URL = 'https://example.invalid/many_interfaces.pcapng.1'
#: Fake current time, a whole second so an HTTP-date maps to it exactly.
NOW = 1_800_000_000.0

# The policy, pinned as literals so that the tests fail on behaviour, rather than
# on a missing name, against a generator without the retry (#1658).
#: Attempts per download, the first included.
ATTEMPTS = 3
#: Wait before the first retry, doubled for each one after.
BACKOFF = 2.0
#: Most seconds of waiting per download.
BUDGET = 30.0


def _load_generator() -> 'types.ModuleType':
    """Load the generator by path, leaving :data:`sys.path` as it was."""
    spec = importlib.util.spec_from_file_location('_pcapng_generator_1658', PCAPNG_GENERATOR)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load {PCAPNG_GENERATOR}')
    module = importlib.util.module_from_spec(spec)
    saved = list(sys.path)
    try:
        spec.loader.exec_module(module)
    finally:
        # The generator puts the tree root on sys.path for its own sake (#1343).
        sys.path[:] = saved
    return module


def _response(code: int, body: bytes = b'', retry_after: 'str | None' = None) -> requests.Response:
    """A :class:`requests.Response` as ``requests.get`` returns it, unread."""
    response = requests.Response()
    response.status_code = code
    response.reason = http.client.responses.get(code, 'Unknown')  # 599 has no registered phrase
    response.url = URL
    if retry_after is not None:
        response.headers['Retry-After'] = retry_after
    response.raw = io.BytesIO(body)
    return response


def _http_error(code: int, retry_after: 'str | None' = None) -> requests.HTTPError:
    """The :exc:`requests.HTTPError` ``raise_for_status`` raises for ``code``."""
    try:
        _response(code, retry_after=retry_after).raise_for_status()
    except requests.HTTPError as error:
        return error
    raise AssertionError(f'{code} is not an error status')  # pragma: no cover


def _body_timeout() -> requests.ConnectionError:
    """A timeout while the body is read, as :mod:`requests` raises it."""
    return requests.ConnectionError(urllib3.exceptions.ReadTimeoutError(None, URL, 'Read timed out.'))


class _Getter:
    """A stand-in for ``requests.get`` serving canned outcomes in turn.

    An exception is raised, a :class:`requests.Response` is returned as it is,
    and bytes are returned as a 200 response with that body.

    """

    def __init__(self, *outcomes: 'BaseException | requests.Response | bytes') -> None:
        self.outcomes = list(outcomes)
        self.calls = []  # type: list[str]

    def __call__(self, url: str, timeout: float) -> requests.Response:
        self.calls.append(url)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, bytes):
            return _response(200, outcome)
        return outcome


class _Clocked(unittest.TestCase):
    """The generator, with a fake clock bound over its ``time``."""

    generator: 'types.ModuleType'

    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = _load_generator()

    def setUp(self) -> None:
        self.sleeps = []  # type: list[float]
        clock = types.SimpleNamespace(time=lambda: NOW, sleep=self.sleeps.append)
        # ``create``: a generator without the retry (#1658) has no ``time`` to bind
        # over, and these tests should fail there on behaviour, not in setUp.
        patcher = mock.patch.object(self.generator, 'time', clock, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.stdout, self.stderr = io.StringIO(), io.StringIO()


class DownloadRetryTests(_Clocked):
    """``_download`` retries what is transient, and nothing else."""

    def run_download(self, getter: _Getter) -> bytes:
        with mock.patch('requests.get', getter), \
                contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return self.generator._download(URL)

    def test_429_then_success_returns_the_body(self) -> None:
        getter = _Getter(_response(429), b'upstream')
        self.assertEqual(self.run_download(getter), b'upstream')
        self.assertEqual(getter.calls, [URL, URL])
        self.assertEqual(self.sleeps, [BACKOFF])
        self.assertIn(f'429 Client Error: Too Many Requests for url: {URL}; retry 1 of 2',
                      self.stderr.getvalue())
        self.assertEqual(self.stdout.getvalue(), '')

    def test_retry_after_is_waited_in_seconds_and_as_an_http_date(self) -> None:
        date = email.utils.formatdate(NOW + 11, usegmt=True)
        getter = _Getter(_response(429, retry_after='7'), _response(503, retry_after=date), b'upstream')
        self.assertEqual(self.run_download(getter), b'upstream')
        self.assertEqual(self.sleeps, [7.0, 11.0])
        self.assertEqual(len(getter.calls), 3)

    def test_retry_after_past_the_budget_is_not_waited(self) -> None:
        """A wait that would take the total past ``RETRY_BUDGET`` ends the retries."""
        cases = {
            'one long wait': ([_response(429, retry_after=str(int(BUDGET) + 1))], [], 1),
            'two waits summed': ([_response(429, retry_after='20'), _response(429, retry_after='20')], [20.0], 2),
        }
        for label, (errors, sleeps, calls) in cases.items():
            with self.subTest(label):
                del self.sleeps[:]
                self.stderr = io.StringIO()
                getter = _Getter(*errors, b'upstream')
                with self.assertRaises(requests.HTTPError):
                    self.run_download(getter)
                self.assertEqual(self.sleeps, sleeps)
                self.assertEqual(len(getter.calls), calls)
                self.assertIn('retry budget, so not retrying', self.stderr.getvalue())

    def test_waits_totalling_exactly_the_budget_are_waited(self) -> None:
        """``RETRY_BUDGET`` is inclusive: a total of exactly 30 s still retries."""
        cases = {
            'one wait of the budget': ([_response(429, retry_after=str(int(BUDGET)))], [BUDGET]),
            'two waits summing to it': ([_response(429, retry_after='10'), _response(503, retry_after='20')],
                                        [10.0, 20.0]),
        }
        for label, (errors, sleeps) in cases.items():
            with self.subTest(label):
                del self.sleeps[:]
                getter = _Getter(*errors, b'upstream')
                self.assertEqual(self.run_download(getter), b'upstream')
                self.assertEqual(self.sleeps, sleeps)
                self.assertEqual(len(getter.calls), len(errors) + 1)

    def test_404_and_other_final_failures_are_not_retried(self) -> None:
        """Only a 429, a 5xx and a timeout get a second attempt.

        The 429, 5xx and timeout rows are the control: the same stub, a second
        outcome waiting, and only the error differs. 500 and 599 are the two
        ends of the 5xx range, both inclusive. A refused connection is a
        :exc:`requests.ConnectionError` too, as a timeout while the body is read
        is, but wraps no urllib3 ``ReadTimeoutError``.

        """
        refused = requests.ConnectionError(urllib3.exceptions.MaxRetryError(
            None, URL, ConnectionRefusedError(111, 'refused')))
        cases = (
            ('HTTP 404', _response(404), requests.HTTPError, 1),
            ('HTTP 403', _response(403), requests.HTTPError, 1),
            ('HTTP 400', _response(400), requests.HTTPError, 1),
            ('connection refused', refused, requests.ConnectionError, 1),
            ('HTTP 429', _response(429), None, 2),
            ('HTTP 500', _response(500), None, 2),
            ('HTTP 502', _response(502), None, 2),
            ('HTTP 599', _response(599), None, 2),
            ('connect timeout', requests.ConnectTimeout('timed out'), None, 2),
            ('read timeout', requests.ReadTimeout('timed out'), None, 2),
            ('timeout reading the body', _body_timeout(), None, 2),
            ('bare socket timeout', socket.timeout('timed out'), None, 2),
        )
        for label, outcome, raised, calls in cases:
            with self.subTest(label):
                del self.sleeps[:]
                getter = _Getter(outcome, b'upstream')
                if raised is not None:
                    with self.assertRaises(raised):
                        self.run_download(getter)
                    self.assertEqual(self.sleeps, [])
                else:
                    self.assertEqual(self.run_download(getter), b'upstream')
                self.assertEqual(len(getter.calls), calls)

    def test_exhausted_retries_fall_back_to_the_stand_in(self) -> None:
        fixture = self.generator._Fixture(name='many_interfaces.pcapng', feature='probe',
                                          build=lambda: b'stand-in', url=URL, sha256='0' * 64)
        timeout = requests.ConnectTimeout('timed out')
        getter = _Getter(_response(429), _response(503), timeout, b'never served')
        with tempfile.TemporaryDirectory(prefix='pcapkit-1658-') as tmp, \
                mock.patch('requests.get', getter), \
                contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            data, origin = self.generator._materialise(fixture, pathlib.Path(tmp) / fixture.name)

        self.assertEqual((data, origin), (b'stand-in', 'synthesised (download unavailable)'))
        self.assertEqual(len(getter.calls), ATTEMPTS)
        self.assertEqual(self.sleeps, [BACKOFF, 2 * BACKOFF])
        self.assertEqual(self.stderr.getvalue().count('; retry '), 2)
        self.assertEqual(self.stdout.getvalue(), (
            f'    ! {URL} is unreachable (timed out);\n'
            '    ! synthesising a stand-in for many_interfaces.pcapng instead -- the '
            'upstream capture was NOT used\n'))

    def test_without_requests_the_stand_in_is_used(self) -> None:
        """#1894: :mod:`requests` is imported for the download alone.

        So the generator loads without it, and a fixture with a URL falls back as
        it does offline rather than failing the whole run. In a child process,
        whose ``sys.modules`` entry of ``None`` makes ``import requests`` raise
        :exc:`ImportError` there and nowhere else.

        """
        script = (
            'import importlib.util, pathlib, sys, tempfile\n'
            "sys.modules['requests'] = None\n"
            f'spec = importlib.util.spec_from_file_location("generator", {str(PCAPNG_GENERATOR)!r})\n'
            'generator = importlib.util.module_from_spec(spec)\n'
            'spec.loader.exec_module(generator)\n'
            "fixture = generator._Fixture(name='many_interfaces.pcapng', feature='probe',\n"
            f"                             build=lambda: b'stand-in', url={URL!r}, sha256='0' * 64)\n"
            'with tempfile.TemporaryDirectory() as tmp:\n'
            '    print(generator._materialise(fixture, pathlib.Path(tmp) / fixture.name))\n'
        )
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True,
                                check=False, timeout=scale_timeout(60))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'    ! {URL} cannot be fetched without requests (', result.stdout)
        self.assertIn("(b'stand-in', 'synthesised (download unavailable)')", result.stdout)


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves the outcomes queued on its server, one per request."""

    def do_GET(self) -> None:  # noqa: N802 -- the name http.server calls
        status, headers, body, stall = self.server.outcomes.pop(0)  # type: ignore[attr-defined]
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if stall:
            # Part of the body, then nothing until the test ends.
            self.wfile.write(body[:4])
            self.wfile.flush()
            self.server.release.wait(30)  # type: ignore[attr-defined]
            return
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # pylint: disable=redefined-builtin
        """Quiet: the test reads what it needs from the outcomes."""


class LocalServerTests(_Clocked):
    """``_download`` against real responses from a server on ``127.0.0.1``."""

    def setUp(self) -> None:
        super().setUp()
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        self.server.outcomes = []  # type: ignore[attr-defined]
        self.server.release = threading.Event()  # type: ignore[attr-defined]
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 30)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.release.set)  # type: ignore[attr-defined]
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}/many_interfaces.pcapng.1'
        # No proxy between the test and its own server, whatever the host has set.
        proxies = mock.patch.dict(os.environ, {'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'})
        proxies.start()
        self.addCleanup(proxies.stop)

    def serve(self, status: int, body: bytes = b'', stall: bool = False, **headers: str) -> None:
        self.server.outcomes.append((status, headers, body, stall))  # type: ignore[attr-defined]

    def download(self) -> bytes:
        with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return self.generator._download(self.url)

    def test_a_timeout_while_the_body_is_read_is_retried(self) -> None:
        self.serve(200, b'upstream capture', stall=True)
        self.serve(200, b'upstream capture')
        with mock.patch.object(self.generator, 'TIMEOUT', 0.5):
            self.assertEqual(self.download(), b'upstream capture')
        self.assertEqual(self.sleeps, [BACKOFF])
        self.assertIn('Read timed out', self.stderr.getvalue())

    def test_retry_after_on_a_real_429_is_waited(self) -> None:
        self.serve(429, **{'Retry-After': '3'})
        self.serve(200, b'upstream capture')
        self.assertEqual(self.download(), b'upstream capture')
        self.assertEqual(self.sleeps, [3.0])

    def test_a_real_404_is_not_retried(self) -> None:
        self.serve(404)
        self.serve(200, b'never served')
        with self.assertRaises(requests.HTTPError) as caught:
            self.download()
        self.assertEqual(caught.exception.response.status_code, 404)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(len(self.server.outcomes), 1)  # type: ignore[attr-defined]


class RetryAfterTests(unittest.TestCase):
    """``_retry_after`` reads both forms RFC 9110 allows, and nothing else."""

    def test_header_values(self) -> None:
        generator = _load_generator()
        cases = (
            ('7', 7.0),
            (' 7 ', 7.0),
            ('0', 0.0),
            (email.utils.formatdate(NOW + 11, usegmt=True), 11.0),
            ('Wed, 21 Oct 2015 07:28:00 GMT', 0.0),  # already past
            ('soon', None),
            ('-1', None),
            ('1.5', None),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(generator._retry_after(_http_error(429, value), NOW), expected)
        with self.subTest('no header'):
            self.assertIsNone(generator._retry_after(_http_error(429), NOW))
        with self.subTest('not an HTTP error'):
            self.assertIsNone(generator._retry_after(requests.ConnectTimeout('timed out'), NOW))
        with self.subTest('not a requests error'):
            self.assertIsNone(generator._retry_after(socket.timeout('timed out'), NOW))

    def test_a_minus_0000_date_is_utc_whatever_the_host_zone(self) -> None:
        """An HTTP-date in a ``-0000`` zone names a UTC instant.

        :func:`email.utils.parsedate_to_datetime` returns such a date naive,
        and a naive ``timestamp()`` reads it in the host zone. On a UTC host,
        which is what CI runs on, that reading is right by accident, so the zone
        is pinned off UTC here.

        """
        if not hasattr(time, 'tzset'):  # pragma: no cover
            self.skipTest('time.tzset() is unavailable on this platform')
        patcher = mock.patch.dict(os.environ, {'TZ': 'America/New_York'})
        self.addCleanup(time.tzset)  # cleanups are LIFO: re-reads TZ after patcher.stop
        patcher.start()
        self.addCleanup(patcher.stop)
        time.tzset()
        if not time.localtime(NOW).tm_gmtoff:  # pragma: no cover
            self.skipTest('America/New_York resolved to UTC; no tzdata, so this proves nothing')

        generator = _load_generator()
        value = email.utils.formatdate(NOW + 5)
        self.assertTrue(value.endswith(' -0000'), value)
        self.assertEqual(generator._retry_after(_http_error(429, value), NOW), 5.0)


if __name__ == '__main__':
    unittest.main()
