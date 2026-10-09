# -*- coding: utf-8 -*-
"""``test_start_line`` is public and lives in the HTTP base module. C.f. #1519.

The predicate :meth:`HTTP._guess_version
<pcapkit.protocols.application.http.HTTP._guess_version>` uses to recognise an
HTTP/1.* start line was ``httpv1._test_start_line``, imported lazily by the
dispatcher in ``http.py``. It is now
:func:`~pcapkit.protocols.application.http.test_start_line`, and the patterns it
shares with the HTTP/1.* parser -- ``_RE_METHOD``, ``_RE_VERSION``,
``_RE_STATUS`` and ``_HTTP2_PREFACE_HEADER`` -- moved with it, so ``httpv1.py``
imports them from ``http.py`` rather than keeping a copy of its own.

The predicate is imported inside each test, never at module level: pytest
collects any module-level callable named ``test_*``, and would run the predicate
itself as a test.

"""

from __future__ import annotations

import importlib.util
import unittest
import unittest.mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The HTTP/2 connection preface (:rfc:`9113#section-3.4`).
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

#: An empty ``SETTINGS`` frame, what a client sends right after the preface.
SETTINGS = bytes.fromhex('000000040000000000')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class StartLinePredicateTests(unittest.TestCase):
    """``http.test_start_line`` classifies a payload as HTTP/1.* or not."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_accepts_a_request_line(self) -> None:
        """A ``request-line``: method, request target, HTTP version."""
        from pcapkit.protocols.application.http import test_start_line

        for raw in (b'GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n',
                    b'M-SEARCH * HTTP/1.1\r\nHost: example.test\r\n\r\n',
                    b'POST /form HTTP/1.0\r\nContent-Length: 4\r\n\r\nbody',
                    b'GET / HTTP/1.0\r\n\r\n'):
            with self.subTest(raw=raw):
                self.assertIs(test_start_line(raw), True)

    def test_accepts_a_status_line(self) -> None:
        """A ``status-line``: HTTP version, three-digit status, reason phrase."""
        from pcapkit.protocols.application.http import test_start_line

        for raw in (b'HTTP/1.1 200 OK\r\nServer: example\r\n\r\nhello',
                    b'HTTP/1.0 404 Not Found\r\nServer: example\r\n\r\n',
                    b'HTTP/1.0 200 OK\r\n\r\nbody'):
            with self.subTest(raw=raw):
                self.assertIs(test_start_line(raw), True)

    def test_refuses_the_http2_connection_preface(self) -> None:
        """The preface is a well-formed request line, refused by name."""
        from pcapkit.protocols.application import http
        from pcapkit.protocols.application.http import test_start_line

        self.assertEqual(http._HTTP2_PREFACE_HEADER, b'PRI * HTTP/2.0')
        for raw in (PREFACE, PREFACE + SETTINGS, b'PRI * HTTP/2.0\r\n\r\n'):
            with self.subTest(raw=raw):
                self.assertIs(test_start_line(raw), False)

    def test_refuses_payloads_that_are_not_http(self) -> None:
        """Text and binary that carry no HTTP/1.* start line."""
        from pcapkit.protocols.application.http import test_start_line

        for raw in (b'',
                    b'not http at all',
                    b'the quick brown fox jumps over the lazy dog\r\n\r\n',
                    b'Get / HTTP/1.1\r\nHost: example.test\r\n\r\n',
                    b'HTTP/1.1 2000 OK\r\n\r\n',
                    b'USER anonymous\r\n\r\n',
                    b'GET / HTTP/1.1',
                    SETTINGS):
            with self.subTest(raw=raw):
                self.assertIs(test_start_line(raw), False)

    def test_httpv1_parses_with_the_patterns_defined_in_http(self) -> None:
        """One copy of each pattern, so the predicate and the parser cannot drift."""
        from pcapkit.protocols.application import http, httpv1

        self.assertIn('test_start_line', http.__all__)
        self.assertFalse(hasattr(httpv1, '_test_start_line'))
        for name in ('_RE_METHOD', '_RE_VERSION', '_RE_STATUS', '_HTTP2_PREFACE_HEADER'):
            with self.subTest(name=name):
                self.assertIs(getattr(httpv1, name), getattr(http, name))

    def test_guess_version_calls_the_module_level_predicate(self) -> None:
        """The dispatcher calls ``http.test_start_line``, not a lazy import of it."""
        from pcapkit.protocols.application import http

        raw = b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'
        with unittest.mock.patch.object(http, 'test_start_line',
                                        wraps=http.test_start_line) as predicate:
            self.assertEqual(http.HTTP(raw, len(raw)).version, '1.1')
        predicate.assert_called_once_with(raw)


if __name__ == '__main__':
    unittest.main()
