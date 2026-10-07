# -*- coding: utf-8 -*-
"""FTP and HTTP/1.* keep what they normalise. C.f. #1302, #1303, #1333.

- #1302: HTTP/1.* field values decoded with a guessed charset were encoded back
  as UTF-8. The field lines are now kept as received (``raw_header``).
- #1303: a multi-line FTP reply arriving whole in one segment did not parse. The
  lines after the first are now kept as received (``lines``).
- #1333: the FTP command case and the HTTP/1.* whitespace -- around start-line
  tokens, around the field colon, and in ``obs-fold`` -- were normalised on
  rebuild. The parsed values stay normalised for lookup, and the original
  token or line is kept beside them (``raw_cmmd``, ``raw_line``,
  ``raw_header``) and written back whenever it still reads as those values.

"""

from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: HTTP/1.* messages: name, octets, the normalised values they parse to.
HTTP1_MESSAGES = (
    ('latin-1 field value', b'HTTP/1.1 200 OK\r\nX-Name: caf\xe9\r\n\r\n',      # 1302
     {'message': 'OK'}, [('X-Name', 'café')]),
    ('leading HTAB in reason phrase', b'HTTP/1.1 200 \tOK\r\n\r\n',             # 1333
     {'message': 'OK'}, []),
    ('leading SP in reason phrase', b'HTTP/1.1 200  OK\r\n\r\n',
     {'message': 'OK'}, []),
    ('trailing HTAB in request URI', b'GET /a\t HTTP/1.1\r\n\r\n',
     {'uri': '/a'}, []),
    ('trailing FF in request URI', b'GET /a\x0c HTTP/1.1\r\n\r\n',
     {'uri': '/a'}, []),
    ('no space after colon', b'GET / HTTP/1.1\r\nHost:a\r\n\r\n',
     {'uri': '/'}, [('Host', 'a')]),
    ('obs-fold', b'GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n',
     {'uri': '/'}, [('X', 'a b')]),
    ('whitespace around field', b'GET / HTTP/1.1\r\nX : a \r\nY:\tb\r\n\r\nbody',
     {'uri': '/'}, [('X', 'a'), ('Y', 'b')]),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FTPRawTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_command_case_rebuilds_byte_exactly(self) -> None:
        from pcapkit.const.ftp.command import Command
        from pcapkit.protocols.application.ftp import FTP

        for raw, command in ((b'quit\r\n', Command.QUIT), (b'Retr file.txt\r\n', Command.RETR)):
            with self.subTest(raw=raw):
                request = FTP(raw, len(raw)).info
                self.assertIs(request.cmmd, command)
                self.assertEqual(request.raw_cmmd, raw.split(b' ')[0].rstrip())
                self.assertEqual(FTP.from_data(request).data, raw)

    def test_changed_command_is_written_from_the_change(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        ftp = object.__new__(FTP)
        self.assertEqual(ftp.make(cmmd='USER', raw_cmmd=b'quit').data, b'USER\r\n')
        self.assertEqual(ftp.make(cmmd='QUIT').data, b'QUIT\r\n')

    def test_whole_multi_line_reply_parses_and_rebuilds(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        for raw, lines in ((b'220-a\r\n220 b\r\n', (b'220 b',)),
                           (b'230-a\r\n  free text\r\n230-b\r\n230 end\r\n',
                            (b'  free text', b'230-b', b'230 end'))):
            with self.subTest(raw=raw):
                reply = FTP(raw, len(raw)).info
                self.assertEqual(int(reply.code), int(raw[:3]))
                self.assertTrue(reply.more)
                self.assertEqual(reply.args, 'a')
                self.assertEqual(reply.lines, lines)
                self.assertEqual(FTP.from_data(reply).data, raw)

        single = FTP(b'220 a\r\n', 7).info
        self.assertEqual(single.lines, ())

    def test_multi_line_reply_must_end_at_its_closing_line(self) -> None:
        from pcapkit.protocols.application.ftp import FTP
        from pcapkit.utilities.exceptions import ProtocolError

        ftp = object.__new__(FTP)
        ftp.__cached__ = {}
        for raw in (b'220-a\r\nfoo\r\n',                        # no closing line
                    b'220-a\r\n221 b\r\n',                      # a different code
                    b'220-a\r\n220 b\r\n331 x\r\n',             # the next reply after it
                    b'220-a\r\n220-b\r\n220 c\r\n220 d\r\n'):   # past the first closing line
            with self.subTest(raw=raw):
                ftp.__header__ = type('Header', (), {'data': raw})()
                with self.assertRaises(ProtocolError):
                    ftp.read(length=len(raw))
                code, _, rest = raw.partition(b'-')
                with self.assertRaises(ProtocolError):
                    ftp.make(code=int(code), args='a', more=True,
                             lines=tuple(rest.split(b'\r\n')[1:-1]))

        raw = b'220-a\r\n220-b\r\n221 digits\r\n220 c\r\n'
        reply = FTP(raw, len(raw)).info
        self.assertEqual(reply.lines, (b'220-b', b'221 digits', b'220 c'))
        self.assertEqual(FTP.from_data(reply).data, raw)

    def test_lines_must_be_bytes(self) -> None:
        from pcapkit.protocols.application.ftp import FTP
        from pcapkit.utilities.exceptions import ProtocolError

        for lines in ('220 b', ('220 b',), (b'220 b\n',)):
            with self.subTest(lines=lines):
                with self.assertRaises(ProtocolError):
                    object.__new__(FTP).make(code=220, args='a', more=True, lines=lines)

    def test_lines_follow_only_a_multi_line_reply(self) -> None:
        from pcapkit.protocols.application.ftp import FTP
        from pcapkit.utilities.exceptions import ProtocolError

        ftp = object.__new__(FTP)
        ftp.__cached__ = {}
        for raw in (b'220 a\r\n221 b\r\n', b'USER a\r\nPASS b\r\n'):
            with self.subTest(raw=raw):
                ftp.__header__ = type('Header', (), {'data': raw})()
                with self.assertRaises(ProtocolError):
                    ftp.read(length=len(raw))
        with self.assertRaises(ProtocolError):
            ftp.make(code=220, args='a', lines=(b'220 b',))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTP1RawTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1

        for cls in (HTTPv1, HTTP):
            for name, raw, _, _ in HTTP1_MESSAGES:
                with self.subTest(cls=cls.__module__, name=name):
                    self.assertEqual(cls.from_data(cls(raw, len(raw)).info).data, raw)

    def test_parsed_values_stay_normalised(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTP

        for name, raw, receipt, fields in HTTP1_MESSAGES:
            with self.subTest(name=name):
                info = HTTP(raw, len(raw)).info
                for key, value in receipt.items():
                    self.assertEqual(getattr(info.receipt, key), value)
                self.assertEqual(list(info.header.items(multi=True)), fields)
                self.assertEqual(info.receipt.raw_line, raw.split(b'\r\n')[0])
                self.assertEqual(len(info.raw_header), len(fields))

    def test_changed_values_are_written_from_the_change(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.httpv1 import HTTP

        raw = b'HTTP/1.1 200  OK\r\nA:1\r\nB:\tcaf\xe9\r\n\r\n'
        info = HTTP(raw, len(raw)).info
        http = object.__new__(HTTP)

        headers = OrderedMultiDict([('A', '2'), ('B', 'café')])
        self.assertEqual(
            http.make(**{**HTTP._make_data(info), 'headers': headers}).data,
            b'HTTP/1.1 200  OK\r\nA: 2\r\nB:\tcaf\xe9\r\n\r\n',
        )
        self.assertEqual(
            http.make(**{**HTTP._make_data(info), 'message': 'Fine'}).data,
            b'HTTP/1.1 200 Fine\r\nA:1\r\nB:\tcaf\xe9\r\n\r\n',
        )

    def test_raw_lines_cannot_write_a_line_break_their_values_lack(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.httpv1 import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = object.__new__(HTTP)
        for raw in (b'X: a\r', b'X: a\n', b'\nX: a', b'X: a\r\n \nInjected: b'):
            with self.subTest(raw_header=raw):
                headers = OrderedMultiDict([http._read_field_line(raw)])
                with self.assertRaises(ProtocolError):
                    http.make(status=200, message='OK', headers=headers, raw_header=(raw,))
        for raw in (b'HTTP/1.1 200\r OK', b'HTTP/1.1 200\nOK', b'HTTP/1.1\r\n 200 OK'):
            with self.subTest(raw_line=raw):
                with self.assertRaises(ProtocolError):
                    http.make(status=200, message='OK', raw_line=raw)

    def test_line_breaks_the_values_carry_still_rebuild(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTP

        for raw in (b'GET / HTTP/1.1\r\nX: a\nb\r\n\r\n', b'GET / HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n'):
            with self.subTest(raw=raw):
                self.assertEqual(HTTP.from_data(HTTP(raw, len(raw)).info).data, raw)

    def test_field_lines_are_matched_by_content(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.httpv1 import HTTP

        raw = b'GET / HTTP/1.1\r\nA:1\r\nB:  2\r\nC:3\r\n\r\n'
        data = HTTP._make_data(HTTP(raw, len(raw)).info)
        http = object.__new__(HTTP)
        for headers, expected in (
            ([('B', '2'), ('C', '3')], b'B:  2\r\nC:3\r\n'),
            ([('A', '1'), ('N', 'new'), ('B', '2'), ('C', '3')], b'A:1\r\nN: new\r\nB:  2\r\nC:3\r\n'),
        ):
            with self.subTest(headers=headers):
                self.assertEqual(
                    http.make(**{**data, 'headers': OrderedMultiDict(headers)}).data,
                    b'GET / HTTP/1.1\r\n' + expected + b'\r\n',
                )


if __name__ == '__main__':
    unittest.main()
