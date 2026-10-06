# -*- coding: utf-8 -*-
"""``HTTP.from_data`` rebuilds the message it was parsed from. C.f. #1154.

:meth:`HTTP._make_data <pcapkit.protocols.application.http.HTTP._make_data>`
chose the versioned class from a ``version`` key that neither HTTP/1.* nor
HTTP/2 data carries, so every ``HTTP.from_data(http.info)`` raised
``ProtocolError: invalid HTTP version: 0``. It now dispatches on the class of
the data, and passes the ``version`` that :meth:`HTTP.make
<pcapkit.protocols.application.http.HTTP.make>` dispatches on.

Behind that, :meth:`httpv2.HTTP._make_data
<pcapkit.protocols.application.httpv2.HTTP._make_data>` returned the frame's
``length``, which ``ProtocolBase.__init__`` takes as the number of octets to
parse back -- the payload alone, nine short of the frame -- so every HTTP/2
``from_data`` raised as well. ``make`` computes the Length itself, so the key
is no longer returned.

The frames are the Scapy-built ones of
``test_http_guess_http2_1141_unit.LEGAL_FRAMES``, embedded as bytes.

"""

from __future__ import annotations

import importlib.util
import unittest
import warnings

from tests._support import reimport_once_per_class, time_limit

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: HTTP/1.* messages: name, octets.
HTTP1_MESSAGES = (
    ('request', b'GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n'),
    ('request with body', b'POST /form HTTP/1.0\r\nContent-Length: 4\r\n\r\nbody'),
    ('response', b'HTTP/1.1 200 OK\r\nServer: test\r\n\r\nhello'),
)

#: One HTTP/2 frame of each type :rfc:`9113` defines, with flag and stream
#: variants: name, octets.
HTTP2_FRAMES = (
    ('DATA', '00000500000000000168656c6c6f'),
    ('DATA, empty, END_STREAM', '000000000100000001'),
    ('DATA, PADDED', '000006000900000003047800000000'),
    ('HEADERS', '00000101050000000182'),
    ('HEADERS, PADDED, PRIORITY', '000009012c0000000102000000000f820000'),
    ('PRIORITY', '0000050200000000050000000110'),
    ('RST_STREAM', '00000403000000000100000008'),
    ('SETTINGS', '000006040000000000000300000064'),
    ('SETTINGS, ACK', '000000040100000000'),
    ('PUSH_PROMISE', '0000050504000000010000000282'),
    ('PING', '0000080600000000000000000000000001'),
    ('GOAWAY, debug data', '00000b0700000000000000000100000002627965'),
    ('WINDOW_UPDATE, stream 0', '000004080000000000000003e8'),
    ('CONTINUATION', '00000109040000000182'),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPFromDataTests(unittest.TestCase):
    """``from_data`` on the dispatcher and on ``httpv2.HTTP`` round-trips."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _round_trip(self, cls: 'type', wire: bytes) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with time_limit():
                parsed = cls(wire, len(wire))
                rebuilt = cls.from_data(parsed.info)
        self.assertEqual(bytes(rebuilt), wire)
        self.assertEqual(rebuilt.info, parsed.info)
        if hasattr(parsed, 'version'):
            self.assertEqual(rebuilt.version, parsed.version)

    def test_dispatcher_rebuilds_http1_messages(self) -> None:
        """The #1154 reproduction: ``invalid HTTP version: 0`` on HTTP/1.*."""
        from pcapkit.protocols.application.http import HTTP

        for name, wire in HTTP1_MESSAGES:
            with self.subTest(message=name):
                self._round_trip(HTTP, wire)

    def test_dispatcher_rebuilds_http2_frames(self) -> None:
        """The same, for every HTTP/2 frame type."""
        from pcapkit.protocols.application.http import HTTP

        for name, octets in HTTP2_FRAMES:
            with self.subTest(frame=name):
                self._round_trip(HTTP, bytes.fromhex(octets))

    def test_httpv2_rebuilds_its_own_frames(self) -> None:
        """``httpv2.HTTP.from_data`` no longer parses back only Length octets."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        for name, octets in HTTP2_FRAMES:
            with self.subTest(frame=name):
                self._round_trip(HTTPv2, bytes.fromhex(octets))

    def test_dispatcher_rejects_data_of_no_http_version(self) -> None:
        """Data that is neither HTTP/1.* nor HTTP/2 is a protocol error."""
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'invalid HTTP data'):
            HTTP._make_data({'version': 1})  # type: ignore[arg-type]


if __name__ == '__main__':
    unittest.main()
