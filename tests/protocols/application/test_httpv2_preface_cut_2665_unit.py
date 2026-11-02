# -*- coding: utf-8 -*-
"""A cut HTTP/2 frame after the connection preface rebuilds as captured (#2665).

``HTTP.pack`` writes the 24-octet preface ahead of the frame header, and
``replay_short_read`` cuts the rebuild from where that header starts, so
``HTTPv2.from_data`` gives back the preface and the octets of the frame the capture
kept, through TCP and on its own.

Every case builds its own octets.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: The HTTP/2 connection preface (RFC 9113, section 3.4).
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


def _frame(type_: int, flags: int, sid: int, payload: bytes) -> bytes:
    """An HTTP/2 frame; its Length counts the payload alone (RFC 9113, section 4.1)."""
    return len(payload).to_bytes(3, 'big') + bytes([type_, flags]) + sid.to_bytes(4, 'big') + payload


#: The frame header fields and their widths (RFC 9113, section 4.1); ``stream`` holds
#: the reserved bit and the Stream Identifier.
HEADER = (('length', 3), ('type', 1), ('flags', 1), ('stream', 4))

#: A frame of each type, with what its whole parse holds.
FRAMES = {
    # identifier and value pairs (RFC 9113, section 6.5.2)
    'SETTINGS': (_frame(0x4, 0x0, 0, bytes.fromhex('000100001000' '000300000064' '000400010000')),
                 lambda info: [(int(k), v) for k, v in info.settings.items(multi=True)],
                 [(0x1, 4096), (0x3, 100), (0x4, 65536)]),
    'DATA': (_frame(0x0, 0x0, 1, b'hello, world'), lambda info: info.data, b'hello, world'),
    # PADDED and PRIORITY, so every field of the frame is present (RFC 9113, section 6.2)
    'HEADERS': (_frame(0x1, 0x2C, 1, bytes([2]) + bytes.fromhex('8000000310')
                       + bytes.fromhex('828684418aa0e41d139d09b8f01e07') + bytes(2)),
                lambda info: (info.pad_len, info.stream_dependency, info.weight, info.fragment),
                (2, 3, 17, bytes.fromhex('828684418aa0e41d139d09b8f01e07'))),
    'PING': (_frame(0x6, 0x0, 0, bytes(range(1, 9))), lambda info: info.data, bytes(range(1, 9))),
}


def _datagram(app: bytes) -> bytes:
    """``app`` to TCP port 80, where HTTP is bound, in an IPv4 datagram declaring all of it."""
    return wire.ipv4(wire.tcp(app, seq=1, ack=1, dport=80), proto=6)


def _record(keep: int) -> 'tuple[str, int]':
    """The field a frame cut after ``keep`` octets ends inside, and how much of it is there."""
    for name, width in HEADER:
        if keep < width:
            return name, keep
        keep -= width
    return 'frame', keep


class PrefaceCutTests(unittest.TestCase):
    """A frame after the preface, cut at every offset (#2665)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assert_cut(self, http: 'object', wire_: bytes, keep: int) -> None:
        """``http`` holds the preface and the first ``keep`` octets of ``wire_``, and rebuilds them."""
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv2 import HTTPv2

        cut = PREFACE + wire_[:keep]
        self.assertIsInstance(http, HTTPv2)
        self.assertEqual(http.data, cut)
        self.assertEqual(http.info.preface, PREFACE)
        self.assertEqual(http.info['__short_read__'], _record(keep))
        if keep >= 3:
            self.assertEqual(http.info.length, len(wire_) - 9)
        for name, data in (('info', http.info), ('dict', http.info.to_dict())):
            with self.subTest(rebuilt_from=name):
                rebuilt = HTTPv2.from_data(data)
                self.assertEqual(rebuilt.data, cut)
                self.assertEqual(rebuilt.info.preface, PREFACE)
        self.assertEqual(HTTP.from_data(http.info).data, cut)

    def test_cut_through_tcp_at_every_offset(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        for label, (wire_, _, _) in FRAMES.items():
            packet = _datagram(PREFACE + wire_)
            head = len(packet) - len(wire_)
            for keep in range(1, len(wire_)):
                raw = packet[:head + keep]
                with self.subTest(frame=label, keep=keep):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        ipv4 = IPv4(raw, len(raw))
                        self.assertEqual(str(ipv4.protochain), 'IPv4:TCP:HTTP/2')
                        self.assert_cut(ipv4.payload.payload, wire_, keep)
                        self.assertEqual(IPv4.from_data(ipv4.info).data, raw)
                        self.assertEqual(IPv4.from_data(ipv4.info.to_dict()).data, raw)

    def test_cut_through_httpv2_at_every_offset(self) -> None:
        from pcapkit.protocols.application.httpv2 import HTTPv2

        for label, (wire_, _, _) in FRAMES.items():
            for keep in range(1, len(wire_)):
                with self.subTest(frame=label, keep=keep):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        http = HTTPv2(PREFACE + wire_[:keep], len(PREFACE + wire_))
                        self.assert_cut(http, wire_, keep)

    def test_whole_frame_is_the_control(self) -> None:
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.protocols.internet.ipv4 import IPv4

        for label, (wire_, held, expected) in FRAMES.items():
            app = PREFACE + wire_
            packet = _datagram(app)
            ipv4 = IPv4(packet, len(packet))
            for via, http in (('TCP', ipv4.payload.payload), ('HTTPv2', HTTPv2(app, len(app)))):
                with self.subTest(frame=label, via=via):
                    self.assertIsInstance(http, HTTPv2)
                    self.assertNotIn('__short_read__', http.info)
                    self.assertEqual(http.info.preface, PREFACE)
                    self.assertEqual(http.info.length, len(wire_) - 9)
                    self.assertEqual(held(http.info), expected)
                    self.assertEqual(http.data, app)
                    self.assertEqual(HTTPv2.from_data(http.info).data, app)
                    self.assertEqual(HTTPv2.from_data(http.info.to_dict()).data, app)
            self.assertEqual(IPv4.from_data(ipv4.info).data, packet)


if __name__ == '__main__':
    unittest.main()
