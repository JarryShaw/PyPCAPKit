# -*- coding: utf-8 -*-
"""Application-layer edge cases round-trip byte for byte. C.f. #1202.

FTP commands and replies, HTTP/1.* messages and HTTP/2 frames, at the edges of
their code ranges, with unassigned codes, zero-length values and padding
variants. The charset, CRLF and flag cases are already pinned by
:mod:`tests.protocols.application.test_ftp_http1_roundtrip_unit` and
:mod:`tests.protocols.application.test_http2_roundtrip_unit`; these are the
ones they do not build. The harness is :mod:`tests.protocols._edge_roundtrip`.

Every case builds its own octets in memory and reads no capture.

"""

from __future__ import annotations

import struct
import unittest

from tests.protocols import _edge_roundtrip as edge
from tests.protocols._edge_roundtrip import Case, MakeCase

FTP = 'pcapkit.protocols.application.ftp:FTP'
HTTP1 = 'pcapkit.protocols.application.httpv1:HTTP'
HTTP2 = 'pcapkit.protocols.application.httpv2:HTTP'


def frame(type_: int, flags: int, sid: int, payload: bytes) -> bytes:
    """An HTTP/2 frame whose Length is the payload's."""
    return len(payload).to_bytes(3, 'big') + bytes([type_, flags]) + struct.pack('!I', sid) + payload


CASES = (
    # -- FTP ---------------------------------------------------------------
    Case('ftp/unknown-command', FTP, b'XYZW arg\r\n'),
    Case('ftp/lowercase-command', FTP, b'user anonymous\r\n'),
    Case('ftp/three-letter-command', FTP, b'PWD\r\n'),
    Case('ftp/arguments-only-spaces', FTP, b'NOOP    \r\n'),
    Case('ftp/4000-octet-argument', FTP, b'STOR ' + b'a' * 4000 + b'\r\n'),
    Case('ftp/reply-100', FTP, b'100 x\r\n'),
    Case('ftp/reply-599', FTP, b'599 x\r\n'),
    Case('ftp/reply-110-assigned', FTP, b'110 MARK yyyy = mmmm\r\n'),
    Case('ftp/reply-123-unassigned', FTP, b'123 x\r\n'),
    Case('ftp/reply-999-unassigned', FTP, b'999 hi\r\n'),
    Case('ftp/reply-099-unassigned', FTP, b'099 x\r\n'),
    # -- HTTP/1.* ----------------------------------------------------------
    Case('http1/request-no-headers', HTTP1, b'GET / HTTP/1.1\r\n\r\n'),
    Case('http1/unknown-method', HTTP1, b'BREW /pot HTTP/1.1\r\n\r\n'),
    Case('http1/http-1.0', HTTP1, b'GET / HTTP/1.0\r\n\r\n'),
    Case('http1/empty-header-value', HTTP1, b'GET / HTTP/1.1\r\nX-Empty:\r\n\r\n'),
    Case('http1/header-without-space', HTTP1, b'GET / HTTP/1.1\r\nHost:a\r\n\r\n'),
    Case('http1/header-value-padded-with-spaces', HTTP1, b'GET / HTTP/1.1\r\nA:   spaced   \r\n\r\n'),
    Case('http1/repeated-header', HTTP1, b'GET / HTTP/1.1\r\nA: 1\r\nA: 2\r\n\r\n'),
    Case('http1/body', HTTP1, b'POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'),
    Case('http1/status-100', HTTP1, b'HTTP/1.1 100 Continue\r\n\r\n'),
    Case('http1/status-418', HTTP1, b"HTTP/1.1 418 I'm a teapot\r\n\r\n"),
    Case('http1/status-empty-reason', HTTP1, b'HTTP/1.1 204 \r\n\r\n'),
    Case('http1/status-599-unassigned', HTTP1, b'HTTP/1.1 599 X\r\n\r\n'),
    Case('http1/status-999-unassigned', HTTP1, b'HTTP/1.1 999 X\r\n\r\n'),
    # -- HTTP/2 ------------------------------------------------------------
    Case('http2/data-empty', HTTP2, frame(0, 0, 1, b'')),
    Case('http2/data-end-stream-empty', HTTP2, frame(0, 1, 1, b'')),
    Case('http2/data-16384-octets', HTTP2, frame(0, 0, 1, b'x' * 16384)),
    Case('http2/data-padded-nonzero-pad', HTTP2, frame(0, 8, 1, b'\x03abc\xff\xee\xdd')),
    Case('http2/data-padded-pad-only', HTTP2, frame(0, 8, 1, b'\x04' + bytes(4))),
    Case('http2/headers-empty-block', HTTP2, frame(1, 4, 1, b'')),
    Case('http2/headers-priority-padded', HTTP2, frame(1, 0x28, 1, b'\x02\x80\x00\x00\x03\x10\x82\x00\x00')),
    Case('http2/priority-exclusive-max', HTTP2, frame(2, 0, 1, b'\xff' * 5)),
    Case('http2/rst-stream-unassigned-error', HTTP2, frame(3, 0, 1, b'\xff' * 4)),
    Case('http2/settings-empty', HTTP2, frame(4, 0, 0, b'')),
    Case('http2/settings-unassigned-id', HTTP2, frame(4, 0, 0, b'\xff\xff\x00\x00\x00\x01')),
    Case('http2/settings-id-0', HTTP2, frame(4, 0, 0, b'\x00\x00\x12\x34\x56\x78')),
    Case('http2/push-promise-padded-nonzero-pad', HTTP2, frame(5, 0x0c, 1, b'\x02\x00\x00\x00\x02\x82\xab\xcd')),
    Case('http2/ping-ack', HTTP2, frame(6, 1, 0, b'\xff' * 8)),
    Case('http2/goaway-debug-data', HTTP2, frame(7, 0, 0, b'\x00\x00\x00\x01\x00\x00\x00\x02debug')),
    Case('http2/goaway-unassigned-error', HTTP2, frame(7, 0, 0, b'\x00\x00\x00\x01\xff\xff\xff\xf0')),
    Case('http2/window-update-0', HTTP2, frame(8, 0, 1, bytes(4))),
    Case('http2/window-update-max', HTTP2, frame(8, 0, 0, b'\x7f\xff\xff\xff')),
    Case('http2/continuation-empty', HTTP2, frame(9, 4, 1, b'')),
    Case('http2/unassigned-type-with-payload', HTTP2, frame(0x0a, 0, 1, b'abcdef')),
    Case('http2/unassigned-type-ff-max-stream', HTTP2, frame(0xff, 0xff, 0x7fffffff, b'')),
)

MAKE_CASES = (
    MakeCase('ftp/make/unknown-command', FTP, {'cmmd': 'XYZW', 'args': 'a'}),
    MakeCase('ftp/make/reply-599', FTP, {'code': 599, 'args': 'x'}),
    MakeCase('http1/make/unknown-method', HTTP1, {'method': 'BREW', 'uri': '/pot'}),
    MakeCase('http2/make/default', HTTP2, {}),
    MakeCase('http2/make/unassigned-type', HTTP2, {'type': 0xfa, 'sid': 0x7fffffff}),
)

REJECTED = {}  # type: dict[str, edge.Reject]

KNOWN_FAILURES = ()  # type: tuple[edge.Gap, ...]


@unittest.skipUnless(edge.HAS_RUNTIME, 'runtime dependencies not installed')
class ApplicationEdgeRoundTripTests(edge.EdgeRoundTripBase):
    """Application-layer edge cases."""

    CASES = CASES
    MAKE_CASES = MAKE_CASES
    REJECTED = REJECTED
    KNOWN_FAILURES = KNOWN_FAILURES


if __name__ == '__main__':
    unittest.main()
