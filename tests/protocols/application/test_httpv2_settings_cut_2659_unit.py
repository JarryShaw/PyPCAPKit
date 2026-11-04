# -*- coding: utf-8 -*-
"""An HTTP/2 ``SETTINGS`` frame cut inside its settings parses and rebuilds (#2659, #2686).

A capture cut short hands the frame fewer octets than its Length, which the IPv4
total length still backs. ``SettingsFrame.settings`` is sized by that Length, so past
the octets present a ``SettingPair`` consumed nothing and ``ListField.unpack`` raised
``FieldValueError``, leaving the segment ``Raw``. The list now reads its settings
zero-filled to the Length, as a cut ``DATA`` frame reads its data, so ``make`` keeps
computing the Length from the frame it builds, and an edited whole frame rebuilds with
the Length of its edited payload.

Every case builds its own octets.

"""

import io
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire


def _frame(type_: int, flags: int, sid: int, payload: bytes) -> bytes:
    """An HTTP/2 frame; its Length counts the payload alone (RFC 9113, section 4.1)."""
    return len(payload).to_bytes(3, 'big') + bytes([type_, flags]) + sid.to_bytes(4, 'big') + payload


#: ``SETTINGS_HEADER_TABLE_SIZE`` (0x1) of 4096, ``SETTINGS_MAX_CONCURRENT_STREAMS``
#: (0x3) of 100 and ``SETTINGS_INITIAL_WINDOW_SIZE`` (0x4) of 65536, each a 16-bit
#: identifier and a 32-bit value (RFC 9113, sections 6.5.1 and 6.5.2).
PAIRS = bytes.fromhex('000100001000' '000300000064' '000400010000')
SETTINGS = _frame(0x4, 0x0, 0, PAIRS)
#: A connection-level ``WINDOW_UPDATE`` of 65535.
WINDOW_UPDATE = _frame(0x8, 0x0, 0, bytes.fromhex('0000ffff'))


def _datagram(app: bytes) -> bytes:
    """``app`` to TCP port 80, where HTTP is bound, in an IPv4 datagram declaring all of it."""
    return wire.ipv4(wire.tcp(app, seq=1, ack=1, dport=80), proto=6)


def _expected(present: bytes) -> 'list[tuple[int, int]]':
    """The pairs ``present`` holds, zero-filled to the frame's Length as a short read is."""
    padded = present + bytes(len(PAIRS) - len(present))
    return [(int.from_bytes(padded[i:i + 2], 'big'), int.from_bytes(padded[i + 2:i + 6], 'big'))
            for i in range(0, len(padded), 6)]


class SettingsCutTests(unittest.TestCase):
    """A ``SETTINGS`` frame cut at every offset inside its settings (#2659)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assert_cut(self, http: 'object', keep: int) -> None:
        """``http`` holds the first ``keep`` octets of the settings and rebuilds them."""
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload

        self.assertIsInstance(http, HTTPv2)
        self.assertEqual(http.data, SETTINGS[:9 + keep])
        self.assertEqual(http.info.length, len(PAIRS))
        self.assertEqual(http.info['__short_read__'], ('frame', keep))
        self.assertEqual([(int(k), v) for k, v in http.info.settings.items(multi=True)],
                         _expected(PAIRS[:keep]))
        self.assertIsInstance(http.payload, NoPayload)
        self.assertEqual(HTTPv2.from_data(http.info).data, http.data)
        self.assertEqual(HTTPv2.from_data(http.info.to_dict()).data, http.data)

    def test_cut_through_tcp_at_every_offset(self) -> None:
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        packet = _datagram(SETTINGS)
        head = len(packet) - len(SETTINGS)
        for keep in range(len(PAIRS)):
            raw = packet[:head + 9 + keep]
            with self.subTest(keep=keep):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    ipv4 = IPv4(raw, len(raw))
                    self.assertEqual(str(ipv4.protochain), 'IPv4:TCP:HTTP/2')
                    self.assert_cut(ipv4.payload.payload, keep)
                    self.assertEqual(IPv4.from_data(ipv4.info).data, raw)
                    self.assertEqual(IPv4.from_data(ipv4.info.to_dict()).data, raw)
                self.assertEqual(caught, [])

    def test_cut_through_httpv2_at_every_offset(self) -> None:
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2

        for keep in range(len(PAIRS)):
            with self.subTest(keep=keep):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    self.assert_cut(HTTPv2(SETTINGS[:9 + keep], len(SETTINGS)), keep)
                self.assertEqual(caught, [])

    def test_the_settings_past_the_data_read_as_zeros(self) -> None:
        """The setting the data ends inside keeps its identifier, and every setting
        past the data reads as identifier and value zero, as a cut ``DATA`` frame
        reads its data as zeros (#2686)."""
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2

        http = HTTPv2(SETTINGS[:9 + 9], len(SETTINGS))
        self.assertEqual(list(http.info.settings.items(multi=True)),
                         [(Setting.HEADER_TABLE_SIZE, 4096), (Setting.MAX_CONCURRENT_STREAMS, 0),
                          (Setting.get(0), 0)])

        data = HTTPv2(_frame(0x0, 0x1, 1, b'hello')[:9 + 2], 9 + 5)
        self.assertEqual(data.info.data, b'he\x00\x00\x00')

    def test_whole_frame_is_the_control(self) -> None:
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        packet = _datagram(SETTINGS)
        for name, http in (('TCP', IPv4(packet, len(packet)).payload.payload),
                           ('HTTPv2', HTTPv2(SETTINGS, len(SETTINGS)))):
            with self.subTest(via=name):
                self.assertNotIn('__short_read__', http.info)
                self.assertEqual(http.info.length, 18)
                self.assertEqual(list(http.info.settings.items(multi=True)),
                                 [(Setting.HEADER_TABLE_SIZE, 4096), (Setting.MAX_CONCURRENT_STREAMS, 100),
                                  (Setting.INITIAL_WINDOW_SIZE, 65536)])
                self.assertEqual([int(key) for key in http.info.settings], [0x1, 0x3, 0x4])
                self.assertEqual(HTTPv2.from_data(http.info).data, SETTINGS)

    def test_the_next_frame_is_not_swallowed(self) -> None:
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.raw.protocol import Raw

        packet = _datagram(SETTINGS + WINDOW_UPDATE)
        for keep in (len(WINDOW_UPDATE), len(WINDOW_UPDATE) - 1):
            raw = packet[:len(packet) - len(WINDOW_UPDATE) + keep]
            with self.subTest(next_frame=keep):
                first = IPv4(raw, len(raw)).payload.payload
                self.assertIsInstance(first, HTTPv2)
                self.assertNotIn('__short_read__', first.info)
                self.assertEqual(len(list(first.info.settings.items(multi=True))), 3)
                rest = first.payload
                self.assertEqual(rest.data, WINDOW_UPDATE[:keep])
                if keep == len(WINDOW_UPDATE):
                    self.assertIsInstance(rest, HTTPv2)
                    self.assertEqual(rest.info.increment, 65535)
                else:
                    self.assertIs(type(rest), Raw)
                    self.assertIsNone(rest.info.error)

    def test_a_length_no_capture_backs_goes_raw(self) -> None:
        """A Length the octets read cannot back is refused, as zero-filling it would
        make a setting per six octets of it, and the segment stays ``Raw`` (#2686)."""
        from pcapkit.corekit.fields.field import _zero_pad_budget
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.raw.protocol import Raw

        # a multiple of 6, and the most an IPv4 datagram holds past the three headers
        length = 65484
        packet = _datagram(length.to_bytes(3, 'big') + SETTINGS[3:9 + 6] + bytes(length - 6))
        raw = packet[:len(packet) - (length - 6)]
        with _zero_pad_budget(), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            ipv4 = IPv4(raw, len(raw))
        self.assertEqual(str(ipv4.protochain), 'IPv4:TCP:Raw')
        self.assertIs(type(ipv4.payload.payload), Raw)
        self.assertNotIsInstance(ipv4.payload.payload, HTTPv2)


class SettingsListTests(unittest.TestCase):
    """The settings list reads a buffer and a stream alike, zero-filled to its length."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_reads_bytes_and_a_live_stream_alike(self) -> None:
        from pcapkit.protocols.application.httpv2.schema import SettingsFrame

        field = SettingsFrame.__fields__['settings']({'__length__': len(PAIRS)})
        stream = io.BytesIO(b'\xde\xad' + PAIRS[:9])
        stream.seek(2)
        for name, buffer in (('bytes', PAIRS[:9]), ('stream', stream)):
            with self.subTest(buffer=name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    parsed = field.unpack(buffer, {})
                self.assertEqual(caught, [])
                self.assertEqual([(int(pair.id), pair.value) for pair in parsed], [(1, 4096), (3, 0), (0, 0)])
                self.assertEqual(field.length, len(PAIRS))
        self.assertEqual(stream.tell(), 2 + 9)

    def test_a_live_stream_is_read_no_further_than_the_length(self) -> None:
        from pcapkit.protocols.application.httpv2.schema import SettingsFrame

        field = SettingsFrame.__fields__['settings']({'__length__': 12})
        stream = io.BytesIO(PAIRS + WINDOW_UPDATE)
        parsed = field.unpack(stream, {})
        self.assertEqual([(int(pair.id), pair.value) for pair in parsed], [(1, 4096), (3, 100)])
        self.assertEqual(stream.tell(), 12)


#: ``(case, frame octets, edit to its info, the frame octets the edit gives)``, a
#: frame of every type; each fixed-size frame is edited in a value, keeping its Length.
EDITS = (
    ('DATA shrunk', _frame(0x0, 0x1, 1, b'hello'), {'data': b'hi'}, _frame(0x0, 0x1, 1, b'hi')),
    ('DATA grown', _frame(0x0, 0x1, 1, b'hello'), {'data': b'hello, world'},
     _frame(0x0, 0x1, 1, b'hello, world')),
    ('DATA padded, shrunk', _frame(0x0, 0x8, 1, b'\x02hello\x00\x00'), {'data': b'hi'},
     _frame(0x0, 0x8, 1, b'\x02hi\x00\x00')),
    ('HEADERS shrunk', _frame(0x1, 0x4, 1, b'\x82\x86'), {'fragment': b'\x82'}, _frame(0x1, 0x4, 1, b'\x82')),
    ('HEADERS padded with priority, grown', _frame(0x1, 0x2c, 1, b'\x01\x80\x00\x00\x03\x10\x82\x86\x00'),
     {'fragment': b'\x82\x86\x84\x87'}, _frame(0x1, 0x2c, 1, b'\x01\x80\x00\x00\x03\x10\x82\x86\x84\x87\x00')),
    # the weight is one more than its octet (RFC 9113, section 5.3.2)
    ('PRIORITY', _frame(0x2, 0x0, 1, b'\x80\x00\x00\x03\x10'), {'weight': 32},
     _frame(0x2, 0x0, 1, b'\x80\x00\x00\x03\x1f')),
    ('RST_STREAM', _frame(0x3, 0x0, 1, b'\x00\x00\x00\x08'), {'error': 1}, _frame(0x3, 0x0, 1, b'\x00\x00\x00\x01')),
    ('SETTINGS shrunk', SETTINGS, {'settings': [(0x1, 7)]}, _frame(0x4, 0x0, 0, bytes.fromhex('000100000007'))),
    ('SETTINGS grown', SETTINGS, {'settings': [(0x1, 4096), (0x3, 100), (0x4, 65536), (0x5, 16384)]},
     _frame(0x4, 0x0, 0, PAIRS + bytes.fromhex('000500004000'))),
    ('PUSH_PROMISE grown', _frame(0x5, 0x4, 1, b'\x00\x00\x00\x02\x82'), {'fragment': b'\x82\x86'},
     _frame(0x5, 0x4, 1, b'\x00\x00\x00\x02\x82\x86')),
    ('PING', _frame(0x6, 0x0, 0, b'12345678'), {'data': b'87654321'}, _frame(0x6, 0x0, 0, b'87654321')),
    ('GOAWAY shrunk', _frame(0x7, 0x0, 0, b'\x00\x00\x00\x01\x00\x00\x00\x00debug'), {'debug_data': b''},
     _frame(0x7, 0x0, 0, b'\x00\x00\x00\x01\x00\x00\x00\x00')),
    ('WINDOW_UPDATE', WINDOW_UPDATE, {'increment': 1}, _frame(0x8, 0x0, 0, b'\x00\x00\x00\x01')),
    ('CONTINUATION grown', _frame(0x9, 0x4, 1, b'\x82\x86\x84'), {'fragment': b'\x82\x86\x84\x87'},
     _frame(0x9, 0x4, 1, b'\x82\x86\x84\x87')),
    ('unassigned shrunk', _frame(0x20, 0x0, 1, b'xyz'), {'data': b'x'}, _frame(0x20, 0x0, 1, b'x')),
    ('DATA shrunk, before a frame', _frame(0x0, 0x1, 1, b'hello') + WINDOW_UPDATE, {'data': b'hi'},
     _frame(0x0, 0x1, 1, b'hi') + WINDOW_UPDATE),
)


class EditedFrameTests(unittest.TestCase):
    """A whole frame edited in its info rebuilds with the Length of the frame it
    makes, through ``from_data(info.to_dict())``, as before the ``SETTINGS`` cut
    carried the parsed Length into ``make`` (#2686)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_frame_type_rebuilds_its_edit(self) -> None:
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2

        for case, raw, edit, expected in EDITS:
            with self.subTest(case):
                data = HTTPv2(raw, len(raw)).info.to_dict()
                for key, value in edit.items():
                    data[key] = value
                built = HTTPv2.from_data(data)
                self.assertEqual(built.data, expected)
                self.assertEqual(built.info.length, int.from_bytes(expected[:3], 'big'))
                self.assertNotIn('__short_read__', built.info)
                self.assertEqual(HTTPv2(expected, len(expected)).data, expected)

    def test_the_length_is_computed_when_not_given(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2

        http = HTTPv2(type=Frame.SETTINGS, frame={'settings': [(Setting.HEADER_TABLE_SIZE, 4096)]})
        self.assertEqual(http.data, _frame(0x4, 0x0, 0, PAIRS[:6]))
        self.assertEqual(http.info.length, 6)
        self.assertNotIn('__short_read__', http.info)

    def test_a_dict_with_no_length_computes_it(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2.protocol import HTTPv2

        for label, data, wire_ in (
                ('SETTINGS', {'type': Frame.SETTINGS, 'flags': {'ACK': False, '__value__': 0}, 'reserved': 0,
                              'sid': 0, 'settings': [(Setting.HEADER_TABLE_SIZE, 4096)]},
                 _frame(0x4, 0x0, 0, PAIRS[:6])),
                ('WINDOW_UPDATE', {'type': Frame.WINDOW_UPDATE, 'flags': {'__value__': 0}, 'reserved': 0,
                                   'sid': 0, 'increment_reserved': 0, 'increment': 65535},
                 WINDOW_UPDATE)):
            with self.subTest(label):
                self.assertEqual(HTTPv2.from_data(data).data, wire_)


if __name__ == '__main__':
    unittest.main()
