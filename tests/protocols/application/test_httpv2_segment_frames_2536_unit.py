# -*- coding: utf-8 -*-
"""Every whole HTTP/2 frame in a TCP segment is a layer of its own (#2536).

Each frame after the first is the previous frame's payload, as TLS records are
(#2517). A later whole frame that fails to decode is ``Raw`` with the rest of the
segment and the parser's error, a frame the segment ends inside stays ``Raw`` with
none, and ``protocol=``, ``layer=`` and ``FRAME_LAYER_LIMIT`` stop the chain. See
``test_http2_roundtrip_unit`` for the round trips both ways.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: A TCP header from port 50000 to port 80, where HTTP is bound.
_TCP_TO_80 = bytes.fromhex('c350005000000001000000015010ffff00000000')

#: The HTTP/2 connection preface (RFC 9113, section 3.4).
_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


def _frame(type_: int, flags: int, sid: int, payload: bytes) -> bytes:
    """An HTTP/2 frame; its Length counts the payload alone (RFC 9113, section 4.1)."""
    return len(payload).to_bytes(3, 'big') + bytes([type_, flags]) + sid.to_bytes(4, 'big') + payload


#: ``SETTINGS_MAX_CONCURRENT_STREAMS`` (0x3) of 100, on stream 0.
SETTINGS = _frame(0x4, 0x0, 0, b'\x00\x03\x00\x00\x00\x64')
#: A ``SETTINGS`` frame with ``ACK`` (0x1) and no payload.
SETTINGS_ACK = _frame(0x4, 0x1, 0, b'')
#: A connection-level ``WINDOW_UPDATE`` of 65535.
WINDOW_UPDATE = _frame(0x8, 0x0, 0, b'\x00\x00\xff\xff')

#: Whole frames a receiver refuses: a three-octet ``RST_STREAM``, which must be
#: four (RFC 9113, section 6.4), and ``SETTINGS`` on a stream, which must be 0
#: (section 6.5).
MALFORMED = {
    'RST_STREAM of 3 octets': _frame(0x3, 0x0, 1, b'\x00\x00\x08'),
    'SETTINGS on stream 1': _frame(0x4, 0x0, 1, b''),
}

#: Frames the segment ends inside.
CUT_SHORT = {
    'a header cut short': WINDOW_UPDATE[:5],
    'a payload cut short': WINDOW_UPDATE[:-1],
}


def _layers(proto: 'object') -> 'tuple[list, object]':
    """Each HTTP/2 layer of ``proto``'s chain, in order, and the layer that ends it."""
    from pcapkit.protocols.application.httpv2 import HTTPv2

    layers = []
    while isinstance(proto, HTTPv2):
        layers.append(proto)
        proto = proto.payload
    return layers, proto


class SegmentFrameTests(unittest.TestCase):
    """Later frames in a segment are further ``HTTPv2`` layers, or ``Raw`` (#2536)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_two_and_three_frames_are_each_a_layer(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.transport.tcp import TCP

        for name, segment, chain in (
                ('two frames', SETTINGS + WINDOW_UPDATE, 'TCP:HTTP/2:HTTP/2'),
                ('three frames', SETTINGS + SETTINGS_ACK + WINDOW_UPDATE, 'TCP:HTTP/2:HTTP/2:HTTP/2'),
                ('preface and three frames', _PREFACE + SETTINGS + SETTINGS_ACK + WINDOW_UPDATE,
                 'TCP:HTTP/2:HTTP/2:HTTP/2')):
            with self.subTest(segment=name):
                raw = _TCP_TO_80 + segment
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    proto = TCP(raw, len(raw))
                self.assertEqual(str(proto.protochain), chain)
                self.assertIsInstance(_layers(proto.payload)[1], NoPayload)
                self.assertEqual(caught, [])

    def test_each_frame_carries_its_own_fields(self) -> None:
        """Each layer holds its own frame header and payload (RFC 9113, sections 6.5 and 6.9)."""
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.http import HTTP

        wire = _PREFACE + SETTINGS + SETTINGS_ACK + WINDOW_UPDATE
        layers, _ = _layers(HTTP(wire, len(wire)))
        self.assertEqual([layer.info.type for layer in layers],
                         [Frame.SETTINGS, Frame.SETTINGS, Frame.WINDOW_UPDATE])
        self.assertEqual([layer.info.length for layer in layers], [6, 0, 4])
        self.assertEqual([layer.length for layer in layers], [33, 9, 9])
        self.assertEqual(layers[0].info.preface, _PREFACE)
        self.assertNotIn('preface', layers[1].info)
        self.assertEqual(layers[0].info.settings[Setting.MAX_CONCURRENT_STREAMS], 100)
        self.assertEqual([layer.info.flags.ACK for layer in layers[:2]], [False, True])
        self.assertEqual(layers[2].info.increment, 65535)

    def test_a_whole_frame_that_fails_to_decode_is_raw_with_the_rest(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        for name, bad in MALFORMED.items():
            with self.subTest(frame=name):
                raw = _TCP_TO_80 + SETTINGS + bad + WINDOW_UPDATE
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    proto = TCP(raw, len(raw))
                    rebuilt = bytes(TCP.from_data(proto.info))
                self.assertEqual(str(proto.protochain), 'TCP:HTTP/2:Raw')
                rest = proto.payload.payload
                self.assertIs(type(rest), Raw)
                self.assertEqual(bytes(rest), bad + WINDOW_UPDATE)
                self.assertRegex(rest.info.error, r'^HTTP/2: \[Type \d\] invalid format$')
                self.assertEqual(caught, [])
                self.assertEqual(rebuilt, raw)

    def test_a_frame_cut_short_stays_raw_without_an_error(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        for name, tail in CUT_SHORT.items():
            with self.subTest(tail=name):
                raw = _TCP_TO_80 + SETTINGS + SETTINGS_ACK + tail
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    proto = TCP(raw, len(raw))
                self.assertEqual(str(proto.protochain), 'TCP:HTTP/2:HTTP/2:Raw')
                rest = _layers(proto.payload)[1]
                self.assertIs(type(rest), Raw)
                self.assertEqual(bytes(rest), tail)
                self.assertIsNone(rest.info.error)
                self.assertEqual(caught, [])
                self.assertEqual(bytes(TCP.from_data(proto.info)), raw)

    def test_a_parse_stopping_at_http2_keeps_the_rest_raw(self) -> None:
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        wire = SETTINGS + SETTINGS_ACK + WINDOW_UPDATE
        self.assertEqual(str(HTTPv2(wire, len(wire)).protochain), 'HTTP/2:HTTP/2:HTTP/2')
        for stop in ({'protocol': 'HTTP/2'}, {'protocol': 'HTTP'}, {'protocol': 'HTTPv2'},
                     {'protocol': HTTPv2}, {'layer': 'Application'}):
            with self.subTest(stop=stop):
                proto = HTTPv2(wire, len(wire), **stop)
                self.assertEqual(str(proto.protochain), 'HTTP/2:Raw')
                self.assertIs(type(proto.payload), Raw)
                self.assertEqual(bytes(proto.payload), SETTINGS_ACK + WINDOW_UPDATE)
                self.assertIsNone(proto.payload.info.error)

                raw = _TCP_TO_80 + wire
                self.assertEqual(str(TCP(raw, len(raw), **stop).protochain), 'TCP:HTTP/2:Raw')

    def test_frame_layer_limit_bounds_the_frames(self) -> None:
        """Each frame is a layer, so the limit stops the walk with one warning."""
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        raw = _TCP_TO_80 + WINDOW_UPDATE * (config.FRAME_LAYER_LIMIT + 6)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            proto = TCP(raw, len(raw))
        self.assertEqual(str(proto.protochain),
                         ':'.join(['TCP'] + ['HTTP/2'] * config.FRAME_LAYER_LIMIT + ['Raw']))
        self.assertEqual([item.category for item in caught], [ProtocolWarning])
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertEqual(bytes(TCP.from_data(proto.info)), raw)


if __name__ == '__main__':
    unittest.main()
