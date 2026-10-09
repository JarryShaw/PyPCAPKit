# -*- coding: utf-8 -*-
"""HTTP/2 frames rebuild byte for byte through ``from_data``.

The application round-trip audit (#1202) found seven ways a parsed HTTP/2
frame lost octets on rebuild, and one way ``make`` refused its own input:

* #1242 -- the 24-octet connection preface was skipped and never rebuilt.
* #1243 -- a frame's payload ran to the end of the buffer instead of to its
  declared Length, so a following frame was swallowed into it.
* #1244 -- ``PADDED`` with a Pad Length of 0 lost both the flag and the octet.
* #1245 -- flag bits the frame type leaves undefined were cleared.
* #1246 -- the reserved R bit of every 31-bit stream field was cleared.
* #1247 -- a repeated ``SETTINGS`` identifier collapsed into one entry.
* #1248 -- ``make(frame=<bytes>)`` raised :exc:`AttributeError`.
* #1251 (HTTP/2 half) -- ``PING`` opaque data of the wrong width was padded or
  cut rather than refused.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
SETTINGS_ACK = bytes.fromhex('000000040100000000')

#: Wire octets that must rebuild unchanged, by issue.
FRAMES = {
    '1243 DATA then SETTINGS ACK': bytes.fromhex('000003000000000001616263') + SETTINGS_ACK,
    '1243 HEADERS then SETTINGS ACK': bytes.fromhex('00000101040000000182') + SETTINGS_ACK,
    '1243 GOAWAY then SETTINGS ACK': bytes.fromhex('000008070000000000000000010000000a') + SETTINGS_ACK,
    '1244 DATA PADDED, Pad Length 0': bytes.fromhex('00000400080000000100616263'),
    '1244 HEADERS PADDED, Pad Length 0': bytes.fromhex('0000020108000000010082'),
    '1244 PUSH_PROMISE PADDED, Pad Length 0': bytes.fromhex('000006050800000001000000000282'),
    '1245 DATA flag 0x02': bytes.fromhex('000003000200000001616263'),
    '1245 PRIORITY flag 0x01': bytes.fromhex('0000050201000000010000000310'),
    '1245 RST_STREAM flags 0xff': bytes.fromhex('00000403ff0000000100000008'),
    '1245 unassigned type, flag 0x01': bytes.fromhex('000000fa0100000001'),
    '1246 header R bit': bytes.fromhex('000003000080000001616263'),
    '1246 PUSH_PROMISE R bit': bytes.fromhex('0000050504000000018000000282'),
    '1246 GOAWAY R bit': bytes.fromhex('0000080700000000008000000100000002'),
    '1246 WINDOW_UPDATE R bit': bytes.fromhex('00000408000000000080000001'),
    '1247 SETTINGS repeated id': bytes.fromhex('00000c040000000000' '000100001000' '000100002000'),
    '1247 SETTINGS A, B, A': bytes.fromhex('000012040000000000' '000100000001' '000200000000' '000100000003'),
}


class TestHTTP2RoundTrip(unittest.TestCase):
    """Pin the rebuild of parsed HTTP/2 frames, and ``make``'s input checks."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.httpv2 import HTTP

        for name, wire in FRAMES.items():
            with self.subTest(frame=name):
                parsed = HTTP(wire, len(wire))
                self.assertEqual(bytes(HTTP.from_data(parsed.info)).hex(), wire.hex())

    def test_preface_is_parsed_and_rebuilt(self) -> None:
        from pcapkit.protocols.application.http import HTTP

        for name, wire in {
            'preface + SETTINGS': PREFACE + bytes.fromhex('000000040000000000'),
            'preface + SETTINGS + SETTINGS ACK': PREFACE + bytes.fromhex('000000040000000000') + SETTINGS_ACK,
        }.items():
            with self.subTest(frame=name):
                parsed = HTTP(wire, len(wire))
                self.assertEqual(parsed.info.preface, PREFACE)
                self.assertEqual(bytes(HTTP.from_data(parsed.info)).hex(), wire.hex())

    def test_payload_is_bounded_by_the_declared_length(self) -> None:
        from pcapkit.protocols.application.httpv2 import HTTP

        wire = FRAMES['1243 DATA then SETTINGS ACK']
        parsed = HTTP(wire, len(wire))
        self.assertEqual(parsed.info.length, 3)
        self.assertEqual(parsed.info.data, b'abc')
        self.assertEqual(bytes(parsed.payload), SETTINGS_ACK)

    def test_reserved_and_undefined_bits_are_parsed(self) -> None:
        from pcapkit.protocols.application.httpv2 import HTTP

        def parse(name: str) -> 'object':
            wire = FRAMES[name]
            return HTTP(wire, len(wire)).info

        self.assertEqual(parse('1246 header R bit').reserved, 1)
        self.assertEqual(parse('1246 PUSH_PROMISE R bit').promised_reserved, 1)
        self.assertEqual(parse('1246 GOAWAY R bit').last_reserved, 1)
        self.assertEqual(parse('1246 WINDOW_UPDATE R bit').increment_reserved, 1)
        self.assertEqual(int(parse('1245 DATA flag 0x02').flags.__value__), 0x02)
        self.assertEqual(int(parse('1245 RST_STREAM flags 0xff').flags.__value__), 0xff)

    def test_repeated_settings_keep_their_order(self) -> None:
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTP

        wire = FRAMES['1247 SETTINGS A, B, A']
        settings = HTTP(wire, len(wire)).info.settings
        self.assertEqual(list(settings.items(multi=True)), [
            (Setting.HEADER_TABLE_SIZE, 1),
            (Setting.ENABLE_PUSH, 0),
            (Setting.HEADER_TABLE_SIZE, 3),
        ])

    def test_repeated_settings_index_to_the_last_value(self) -> None:
        """The last value of a repeated identifier wins (RFC 9113 section 6.5)."""
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTP

        wire = FRAMES['1247 SETTINGS A, B, A']
        info = HTTP(wire, len(wire)).info
        settings = info.settings
        self.assertEqual(settings[Setting.HEADER_TABLE_SIZE], 3)
        self.assertEqual(settings.get(Setting.HEADER_TABLE_SIZE), 3)
        self.assertEqual(dict(settings), {Setting.HEADER_TABLE_SIZE: 3, Setting.ENABLE_PUSH: 0})
        self.assertEqual(settings.to_dict(flat=True), {Setting.HEADER_TABLE_SIZE: 3, Setting.ENABLE_PUSH: 0})
        # The Info export keeps every entry, in wire order (#1484).
        self.assertEqual(list(settings.to_dict().items(multi=True)), list(settings.items(multi=True)))
        self.assertEqual(settings.getlist(Setting.HEADER_TABLE_SIZE), [1, 3])
        self.assertEqual(bytes(HTTP.from_data(info)).hex(), wire.hex())

    def test_make_padded_with_zero_pad_length(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP

        made = HTTP(type=Frame.DATA, sid=1, frame={'padded': True, 'data': b'abc'})
        self.assertEqual(bytes(made), FRAMES['1244 DATA PADDED, Pad Length 0'])

    def test_make_accepts_frame_bytes(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP

        for frame_type, sid, payload in (
            (Frame.DATA, 1, b'abc'),
            (Frame.HEADERS, 1, b'\x82'),
            (Frame.PRIORITY, 1, bytes.fromhex('0000000310')),
            (Frame.RST_STREAM, 1, bytes.fromhex('00000008')),
            (Frame.SETTINGS, 0, bytes.fromhex('000100001000')),
            (Frame.PUSH_PROMISE, 1, bytes.fromhex('0000000282')),
            (Frame.PING, 0, b'01234567'),
            (Frame.GOAWAY, 0, bytes.fromhex('0000000100000000')),
            (Frame.WINDOW_UPDATE, 1, bytes.fromhex('00000001')),
            (Frame.CONTINUATION, 1, b'\x82'),
            (Frame(0xfa), 1, b'abc'),
        ):
            with self.subTest(type=frame_type):
                made = HTTP(type=frame_type, sid=sid, frame=payload)
                wire = len(payload).to_bytes(3, 'big') + bytes([int(frame_type), 0]) + sid.to_bytes(4, 'big') + payload
                self.assertEqual(bytes(made), wire)
                self.assertEqual(made.info.type, frame_type)

    def test_make_frame_bytes_wrong_for_the_type_raise_protocol_error(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            HTTP(type=Frame.PRIORITY, sid=1, frame=b'abc')

    def test_make_ping_rejects_wrong_width_opaque_data(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for data in (b'abc', b'0123456789'):
            with self.subTest(data=data):
                with self.assertRaises(ProtocolError):
                    HTTP(type=Frame.PING, sid=0, frame={'opaque_data': data})
        self.assertEqual(bytes(HTTP(type=Frame.PING, sid=0, frame={'opaque_data': b'01234567'}))[9:],
                         b'01234567')


if __name__ == '__main__':
    unittest.main()
