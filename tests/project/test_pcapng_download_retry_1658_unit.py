# -*- coding: utf-8 -*-
""":file:`examples/generators/pcapng.py` retries a transient download failure.

GitHub issue #1658. ``_download`` made one attempt, so an HTTP 429 from the
Wireshark mirror sent a CI leg straight to the synthesised stand-in. An HTTP 429
or 5xx, or a timeout, is now retried with backoff, honouring ``Retry-After``,
within a small budget; any other failure still falls back at once.

Every test runs against a stubbed ``urllib.request.urlopen`` and a fake clock
bound over the generator's ``time``, so nothing touches the network or sleeps.
This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import contextlib
import email.utils
import http.client
import importlib.util
import io
import os
import pathlib
import socket
import sys
import tempfile
import time
import types
import unittest
import urllib.error
from unittest import mock

from tests._support import PCAPNG_GENERATOR

#: URL the stubbed opener is asked for.
URL = 'https://example.invalid/many_interfaces.pcapng.1'
#: Fake current time, a whole second so an HTTP-date maps to it exactly.
NOW = 1_800_000_000.0

# The policy, pinned as literals so that the tests fail on behaviour, rather than
# on a missing name, against the generator as it was before #1658.
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


def _http_error(code: int, retry_after: 'str | None' = None) -> urllib.error.HTTPError:
    """An :class:`~urllib.error.HTTPError` as ``urlopen`` raises it."""
    headers = http.client.HTTPMessage()
    if retry_after is not None:
        headers['Retry-After'] = retry_after
    reason = http.client.responses.get(code, 'Unknown')  # 599 has no registered phrase
    return urllib.error.HTTPError(URL, code, reason, headers, io.BytesIO())


def _timeout() -> urllib.error.URLError:
    """A connect timeout, as ``urlopen`` wraps it."""
    return urllib.error.URLError(socket.timeout('timed out'))


class _Opener:
    """A stand-in for ``urllib.request.urlopen`` serving canned outcomes in turn."""

    def __init__(self, *outcomes: 'BaseException | bytes') -> None:
        self.outcomes = list(outcomes)
        self.calls = []  # type: list[str]

    def __call__(self, url: str, timeout: float) -> io.BytesIO:
        self.calls.append(url)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return io.BytesIO(outcome)


class DownloadRetryTests(unittest.TestCase):
    """``_download`` retries what is transient, and nothing else."""

    generator: 'types.ModuleType'

    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = _load_generator()

    def setUp(self) -> None:
        self.sleeps = []  # type: list[float]
        clock = types.SimpleNamespace(time=lambda: NOW, sleep=self.sleeps.append)
        # ``create``: the generator before #1658 had no ``time`` to bind over,
        # and these tests should fail there on behaviour, not in setUp.
        patcher = mock.patch.object(self.generator, 'time', clock, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.stdout, self.stderr = io.StringIO(), io.StringIO()

    def run_download(self, opener: _Opener) -> bytes:
        with mock.patch('urllib.request.urlopen', opener), \
                contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return self.generator._download(URL)

    def test_429_then_success_returns_the_body(self) -> None:
        opener = _Opener(_http_error(429), b'upstream')
        self.assertEqual(self.run_download(opener), b'upstream')
        self.assertEqual(opener.calls, [URL, URL])
        self.assertEqual(self.sleeps, [BACKOFF])
        self.assertIn('HTTP Error 429: Too Many Requests; retry 1 of 2', self.stderr.getvalue())
        self.assertEqual(self.stdout.getvalue(), '')

    def test_retry_after_is_waited_in_seconds_and_as_an_http_date(self) -> None:
        date = email.utils.formatdate(NOW + 11, usegmt=True)
        opener = _Opener(_http_error(429, '7'), _http_error(503, date), b'upstream')
        self.assertEqual(self.run_download(opener), b'upstream')
        self.assertEqual(self.sleeps, [7.0, 11.0])
        self.assertEqual(len(opener.calls), 3)

    def test_retry_after_past_the_budget_is_not_waited(self) -> None:
        """A wait that would take the total past ``RETRY_BUDGET`` ends the retries."""
        cases = {
            'one long wait': ([_http_error(429, str(int(BUDGET) + 1))], [], 1),
            'two waits summed': ([_http_error(429, '20'), _http_error(429, '20')], [20.0], 2),
        }
        for label, (errors, sleeps, calls) in cases.items():
            with self.subTest(label):
                del self.sleeps[:]
                self.stderr = io.StringIO()
                opener = _Opener(*errors, b'upstream')
                with self.assertRaises(urllib.error.HTTPError):
                    self.run_download(opener)
                self.assertEqual(self.sleeps, sleeps)
                self.assertEqual(len(opener.calls), calls)
                self.assertIn('retry budget, so not retrying', self.stderr.getvalue())

    def test_waits_totalling_exactly_the_budget_are_waited(self) -> None:
        """``RETRY_BUDGET`` is inclusive: a total of exactly 30 s still retries."""
        cases = {
            'one wait of the budget': ([_http_error(429, str(int(BUDGET)))], [BUDGET]),
            'two waits summing to it': ([_http_error(429, '10'), _http_error(503, '20')], [10.0, 20.0]),
        }
        for label, (errors, sleeps) in cases.items():
            with self.subTest(label):
                del self.sleeps[:]
                opener = _Opener(*errors, b'upstream')
                self.assertEqual(self.run_download(opener), b'upstream')
                self.assertEqual(self.sleeps, sleeps)
                self.assertEqual(len(opener.calls), len(errors) + 1)

    def test_404_and_other_final_failures_are_not_retried(self) -> None:
        """Only a 429, a 5xx and a timeout get a second attempt.

        The 429, 5xx and timeout rows are the control: the same stub, a second
        outcome waiting, and only the error differs. 500 and 599 are the two
        ends of the 5xx range, both inclusive.

        """
        cases = (
            ('HTTP 404', _http_error(404), 1),
            ('HTTP 403', _http_error(403), 1),
            ('HTTP 400', _http_error(400), 1),
            ('connection refused', urllib.error.URLError(ConnectionRefusedError(111, 'refused')), 1),
            ('HTTP 429', _http_error(429), 2),
            ('HTTP 500', _http_error(500), 2),
            ('HTTP 502', _http_error(502), 2),
            ('HTTP 599', _http_error(599), 2),
            ('connect timeout', _timeout(), 2),
            ('read timeout', socket.timeout('timed out'), 2),
        )
        for label, error, calls in cases:
            with self.subTest(label):
                del self.sleeps[:]
                opener = _Opener(error, b'upstream')
                if calls == 1:
                    with self.assertRaises(type(error)):
                        self.run_download(opener)
                    self.assertEqual(self.sleeps, [])
                else:
                    self.assertEqual(self.run_download(opener), b'upstream')
                self.assertEqual(len(opener.calls), calls)

    def test_exhausted_retries_fall_back_to_the_stand_in(self) -> None:
        fixture = self.generator._Fixture(name='many_interfaces.pcapng', feature='probe',
                                          build=lambda: b'stand-in', url=URL, sha256='0' * 64)
        opener = _Opener(_http_error(429), _http_error(503), _timeout(), b'never served')
        with tempfile.TemporaryDirectory(prefix='pcapkit-1658-') as tmp, \
                mock.patch('urllib.request.urlopen', opener), \
                contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            data, origin = self.generator._materialise(fixture, pathlib.Path(tmp) / fixture.name)

        self.assertEqual((data, origin), (b'stand-in', 'synthesised (download unavailable)'))
        self.assertEqual(len(opener.calls), ATTEMPTS)
        self.assertEqual(self.sleeps, [BACKOFF, 2 * BACKOFF])
        self.assertEqual(self.stderr.getvalue().count('; retry '), 2)
        self.assertEqual(self.stdout.getvalue(), (
            f'    ! {URL} is unreachable (<urlopen error timed out>);\n'
            '    ! synthesising a stand-in for many_interfaces.pcapng instead -- the '
            'upstream capture was NOT used\n'))


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
            self.assertIsNone(generator._retry_after(_timeout(), NOW))

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
