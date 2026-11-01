# -*- coding: utf-8 -*-
"""HTTP/2 ``RST_STREAM`` and ``GOAWAY`` frames default to ``NO_ERROR``.

GitHub issue #2311: ``HTTP._make_http_rst_stream`` and
``HTTP._make_http_goaway`` defaulted ``error`` to ``HTTP_1_1_REQUIRED``
(``0xd``), so a frame built without an error code told the peer to use
HTTP/1.1 instead. Both default to ``NO_ERROR`` (``0x0``), the code
:rfc:`9113#section-7` gives a condition that is not the result of an error.
An explicit ``error`` is still honoured.

Each frame is built with ``frame={}``, which dispatches to the frame type's own
constructor; since #2274 the default ``frame=None`` takes that dispatch too, so
it builds the same octets. Every case builds its own octets in memory and reads
no capture. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
from typing import Any

from tests._support import reimport_once_per_class

#: ``RST_STREAM`` on stream 1 carrying ``NO_ERROR``.
RST_STREAM_NO_ERROR = bytes.fromhex('000004030000000001' '00000000')

#: ``GOAWAY`` on stream 0, last stream 0, carrying ``NO_ERROR``.
GOAWAY_NO_ERROR = bytes.fromhex('000008070000000000' '00000000' '00000000')


class TestHTTPv2ErrorCodeDefault(unittest.TestCase):
    """Pin the error code a frame built without ``error`` carries."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def build(self, name: 'str', sid: 'int', frame: 'dict[str, object]') -> 'Any':
        """Build the HTTP/2 frame ``name`` from the ``frame`` mapping."""
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2

        return HTTPv2(type=Frame[name], sid=sid, frame=frame)

    def test_rst_stream_defaults_to_no_error(self) -> None:
        from pcapkit.const.http.error_code import ErrorCode

        http = self.build('RST_STREAM', 1, {})
        self.assertEqual(bytes(http), RST_STREAM_NO_ERROR)
        self.assertEqual(http.info.error, ErrorCode.NO_ERROR)

    def test_goaway_defaults_to_no_error(self) -> None:
        from pcapkit.const.http.error_code import ErrorCode

        http = self.build('GOAWAY', 0, {})
        self.assertEqual(bytes(http), GOAWAY_NO_ERROR)
        self.assertEqual(http.info.error, ErrorCode.NO_ERROR)

    def test_explicit_error_is_still_emitted(self) -> None:
        from pcapkit.const.http.error_code import ErrorCode

        for name, sid, offset in (('RST_STREAM', 1, 9), ('GOAWAY', 0, 13)):
            with self.subTest(frame=name):
                http = self.build(name, sid, {'error': ErrorCode.HTTP_1_1_REQUIRED})
                self.assertEqual(bytes(http)[offset:offset + 4], bytes.fromhex('0000000d'))
                self.assertEqual(http.info.error, ErrorCode.HTTP_1_1_REQUIRED)


if __name__ == '__main__':
    unittest.main()
