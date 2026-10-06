# -*- coding: utf-8 -*-
"""HTTP's version guess takes a bare frame for HTTP/2 only if a sender could write it. C.f. #1141.

Since #1138 an HTTP/2 frame's Length counts the payload alone
(:rfc:`9113#section-4.1`), so any nine octets whose Length fits the buffer are
self-consistent. :meth:`HTTP._guess_version
<pcapkit.protocols.application.http.HTTP._guess_version>` falls through to an
HTTP/2 trial parse when neither the preface nor an HTTP/1 start line matches, and
that trial accepted most zero-heavy binary: nine zero octets came back as
``HTTP/2 type=0``, a ``DATA`` frame on stream 0, which :rfc:`9113#section-6.1`
makes a protocol error.

The guess now requires a frame type :rfc:`9113` defines, no flag that type
leaves undefined, a clear reserved bit, and a stream that type may be sent on.
Explicit ``version=2`` parsing is not affected, and is asserted unchanged here.

The legal frames in :data:`LEGAL_FRAMES` were built with Scapy 2.7.0's
:mod:`scapy.contrib.http2` (``H2Frame`` over each frame class) and are embedded
as bytes, so this module does not depend on Scapy, which the per-PR test job
does not install.

"""

from __future__ import annotations

import importlib.util
import random
import unittest
import warnings

from tests._support import reimport_once_per_class, time_limit

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: One frame of each type :rfc:`9113` defines, with the flag and stream
#: variants each type allows, as Scapy writes them: name, frame type, octets.
LEGAL_FRAMES = (
    ('DATA', 0x0, '00000500000000000168656c6c6f'),
    ('DATA, empty, END_STREAM', 0x0, '000000000100000001'),
    ('DATA, PADDED', 0x0, '000006000900000003047800000000'),
    ('HEADERS', 0x1, '00000101050000000182'),
    ('HEADERS, PADDED, PRIORITY', 0x1, '000009012c0000000102000000000f820000'),
    ('PRIORITY', 0x2, '0000050200000000050000000110'),
    ('RST_STREAM', 0x3, '00000403000000000100000008'),
    ('SETTINGS', 0x4, '000006040000000000000300000064'),
    ('SETTINGS, empty', 0x4, '000000040000000000'),
    ('SETTINGS, ACK', 0x4, '000000040100000000'),
    ('PUSH_PROMISE', 0x5, '0000050504000000010000000282'),
    ('PING', 0x6, '0000080600000000000000000000000001'),
    ('PING, ACK', 0x6, '0000080601000000000000000000000001'),
    ('GOAWAY', 0x7, '0000080700000000000000000100000000'),
    ('GOAWAY, debug data', 0x7, '00000b0700000000000000000100000002627965'),
    ('WINDOW_UPDATE, stream 0', 0x8, '000004080000000000000003e8'),
    ('WINDOW_UPDATE, stream 1', 0x8, '000004080000000001000003e8'),
    ('CONTINUATION', 0x9, '00000109040000000182'),
)

#: Frame headers no conforming sender writes, each with a zero-length payload
#: unless the type needs one to parse: name, octets.
REJECTED_FRAMES = (
    ('nine zero octets: DATA on stream 0', '000000000000000000'),
    ('HEADERS on stream 0', '000000010400000000'),
    ('CONTINUATION on stream 0', '000000090400000000'),
    ('GOAWAY on stream 1', '0000080700000000010000000000000000'),
    ('DATA with undefined flag 0x02', '000000000200000001'),
    ('SETTINGS with undefined flag 0x02', '000000040200000000'),
    ('DATA with the reserved bit set', '000000000080000001'),
    ('unknown frame type 0xEE', '0000000aee0000000100000000000000000000'),
    ('ORIGIN, not an RFC 9113 type', '0000000c0000000000'),
)

#: The seeded fuzz. Pre-fix, this corpus produced 566 HTTP/2 labels, of which
#: 249 were ``DATA`` (most on stream 0) and 317 frames of unknown type.
FUZZ_SEED = 1141
FUZZ_COUNT = 5000
PRE_FIX_HTTP2_LABELS = 566


def _fuzz_buffers() -> 'list[bytes]':
    """Zero-heavy random buffers of 0-64 octets, the shape that reaches HTTP/2."""
    rng = random.Random(FUZZ_SEED)
    buffers = []
    for _ in range(FUZZ_COUNT):
        size = rng.randrange(0, 65)
        buffers.append(bytes(0 if rng.random() < 0.5 else rng.randrange(256)
                             for _ in range(size)))
    return buffers


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPGuessHTTP2Tests(unittest.TestCase):
    """The HTTP/2 fall-through in ``_guess_version`` takes only plausible frames."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _guess(self, data: bytes) -> 'object':
        from pcapkit.protocols.application.http import HTTP

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with time_limit():
                return HTTP(data, len(data))

    def test_nine_zero_octets_are_not_guessed_as_http2(self) -> None:
        """The #1141 reproduction: a stream-0 ``DATA`` frame is not HTTP/2 by guess."""
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'unknown HTTP version'):
            self._guess(bytes(9))

    def test_explicit_version_still_parses_nine_zero_octets(self) -> None:
        """Explicit HTTP/2 parsing stays RFC-exact: only the guess is tightened."""
        from pcapkit.protocols.application.http import HTTP

        http = HTTP(bytes(9), 9, version=2)
        self.assertEqual(http.version, '2')
        self.assertEqual((int(http.info.type), http.info.sid), (0, 0))

    def test_headers_no_sender_writes_are_not_guessed(self) -> None:
        """Wrong stream, undefined flag, reserved bit or unknown type: refused."""
        from pcapkit.utilities.exceptions import ProtocolError

        for name, octets in REJECTED_FRAMES:
            with self.subTest(frame=name):
                with self.assertRaisesRegex(ProtocolError, 'unknown HTTP version'):
                    self._guess(bytes.fromhex(octets))

    def test_every_legal_frame_type_is_still_guessed_as_http2(self) -> None:
        """Each Scapy-built frame of the ten RFC 9113 types comes back HTTP/2."""
        seen = set()
        for name, frame_type, octets in LEGAL_FRAMES:
            with self.subTest(frame=name):
                http = self._guess(bytes.fromhex(octets))
                self.assertEqual(http.version, '2')  # type: ignore[attr-defined]
                self.assertEqual(int(http.info.type), frame_type)  # type: ignore[attr-defined]
                seen.add(frame_type)
        self.assertEqual(seen, set(range(10)))

    def test_seeded_fuzz_false_positive_rate_drops(self) -> None:
        """Far fewer random buffers are labelled HTTP/2, and each is a stream-bound ``DATA``.

        What is left is a ``DATA`` frame on a non-zero stream with defined flags,
        which is a legal frame and so cannot be refused without refusing real
        traffic.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        labels = []
        for data in _fuzz_buffers():
            try:
                http = self._guess(data)
            except ProtocolError:
                continue
            if http.version == '2':  # type: ignore[attr-defined]
                labels.append(data)

        self.assertLess(len(labels), PRE_FIX_HTTP2_LABELS // 4)
        for data in labels:
            with self.subTest(frame=data[:9].hex()):
                self.assertEqual(data[3], 0x0)
                self.assertTrue(any(data[5:9]))
                self.assertEqual(data[4] & ~0x09, 0)


if __name__ == '__main__':
    unittest.main()
