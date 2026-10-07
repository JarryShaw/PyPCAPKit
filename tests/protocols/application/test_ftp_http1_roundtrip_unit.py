# -*- coding: utf-8 -*-
"""FTP and HTTP/1.* lines rebuild byte for byte. C.f. #1238, #1239, #1240, #1241.

- #1238: ``FTP.make`` wrote no CRLF, which the parse regexes require, so no FTP
  line rebuilt at all.
- #1239: a line with no arguments parsed to ``args=None`` and then crashed in
  ``decode``; ``make`` wrote a separating SP regardless.
- #1240: the text of a multi-line reply follows the hyphen immediately
  (:rfc:`959#section-4`), but the parse required a SP there and ``make`` wrote
  one.
- #1241: text decoded with a detected charset was encoded back as UTF-8, so
  non-UTF-8 octets in FTP arguments and HTTP/1.* start lines changed on rebuild.
  The charset is now recorded on the data whenever UTF-8 would not reproduce the
  octets.

"""

from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: FTP lines: name, octets.
FTP_LINES = (
    ('request', b'USER anonymous\r\n'),                       # 1238
    ('request without arguments', b'QUIT\r\n'),               # 1239
    ('request with empty arguments', b'QUIT \r\n'),
    ('request with leading space', b'USER  anonymous\r\n'),
    ('reply', b'230 Logged in\r\n'),
    ('reply without text', b'220\r\n'),                       # 1239
    ('multi-line reply', b'220-Welcome\r\n'),                 # 1240
    ('multi-line reply with space', b'220- Welcome\r\n'),
    ('multi-line reply without text', b'220-\r\n'),
    ('latin-1 request', b'USER caf\xe9\r\n'),                 # 1241
    ('latin-1 reply', b'550 caf\xe9 cr\xe8me\r\n'),
)

#: HTTP/1.* messages: name, octets.
HTTP1_MESSAGES = (
    ('latin-1 request URI', b'GET /caf\xe9 HTTP/1.1\r\n\r\n'),           # 1241
    ('latin-1 reason phrase', b'HTTP/1.1 200 caf\xe9\r\n\r\n'),          # 1241
    ('utf-8 request URI', b'GET /caf\xc3\xa9 HTTP/1.1\r\nHost: a\r\n\r\n'),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FTPRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        for name, raw in FTP_LINES:
            with self.subTest(name=name):
                self.assertEqual(FTP.from_data(FTP(raw, len(raw)).info).data, raw)

    def test_make_terminates_with_crlf(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        self.assertEqual(bytes(FTP(cmmd='USER', args='x')), b'USER x\r\n')
        self.assertEqual(object.__new__(FTP).make(cmmd='USER', args='anonymous').data,
                         b'USER anonymous\r\n')

    def test_no_arguments(self) -> None:
        from pcapkit.const.ftp.command import Command
        from pcapkit.protocols.application.ftp import FTP

        request = FTP(b'QUIT\r\n', 6).info
        self.assertIs(request.cmmd, Command.QUIT)
        self.assertIsNone(request.args)
        self.assertIsNone(FTP(b'220\r\n', 5).info.args)
        self.assertEqual(object.__new__(FTP).make(cmmd='QUIT').data, b'QUIT\r\n')

    def test_multi_line_reply(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        reply = FTP(b'220-Welcome\r\n', 13).info
        self.assertTrue(reply.more)
        self.assertEqual(reply.args, 'Welcome')
        self.assertEqual(object.__new__(FTP).make(code=220, args='Welcome', more=True).data,
                         b'220-Welcome\r\n')

    def test_non_utf8_arguments_keep_their_charset(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        raw = b'USER caf\xe9\r\n'
        request = FTP(raw, len(raw)).info
        self.assertEqual(request.args, 'café')
        self.assertIsNotNone(request.charset)
        self.assertEqual(
            object.__new__(FTP).make(cmmd=request.cmmd, args=request.args,
                                     charset=request.charset).data,
            b'USER caf\xe9\r\n',
        )
        # UTF-8 needs no charset recorded, and stays the default.
        raw = b'USER caf\xc3\xa9\r\n'
        self.assertIsNone(FTP(raw, len(raw)).info.charset)
        self.assertEqual(object.__new__(FTP).make(cmmd='USER', args='café').data,
                         b'USER caf\xc3\xa9\r\n')

    def test_trailing_newline_is_not_dropped(self) -> None:
        from pcapkit.protocols.application.ftp import FTP
        from pcapkit.utilities.exceptions import ProtocolError

        ftp = object.__new__(FTP)
        ftp.__cached__ = {}
        for raw in (b'USER x\r\n\n', b'220 x\r\n\n'):
            with self.subTest(raw=raw):
                ftp.__header__ = type('Header', (), {'data': raw})()
                with self.assertRaises(ProtocolError):
                    ftp.read(length=len(raw))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTP1RoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTP

        for name, raw in HTTP1_MESSAGES:
            with self.subTest(name=name):
                self.assertEqual(HTTP.from_data(HTTP(raw, len(raw)).info).data, raw)

    def test_non_utf8_start_line_keeps_its_charset(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTP

        raw = b'GET /caf\xe9 HTTP/1.1\r\n\r\n'
        receipt = HTTP(raw, len(raw)).info.receipt
        self.assertEqual(receipt.uri, '/café')
        self.assertIsNotNone(receipt.charset)

        raw = b'GET /caf\xc3\xa9 HTTP/1.1\r\n\r\n'
        self.assertIsNone(HTTP(raw, len(raw)).info.receipt.charset)


if __name__ == '__main__':
    unittest.main()
