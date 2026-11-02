# -*- coding: utf-8 -*-
"""An HTTP/2 ``SETTINGS`` frame cut inside its settings parses as far as it goes (#2659).

A capture cut short hands the frame fewer octets than its Length, which the IPv4
total length still backs. ``SettingsFrame.settings`` was sized by that Length, so past
the octets present a ``SettingPair`` consumed nothing and ``ListField.unpack`` raised
``FieldValueError``, leaving the segment ``Raw``. ``HTTPv2.make`` also recomputed the
Length from the settings held, so a parsed cut frame could not rebuild as captured.

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
    """The pairs ``present`` holds, the last one zero-filled as a short read is."""
    padded = present + bytes(-len(present) % 6)
    return [(int.from_bytes(padded[i:i + 2], 'big'), int.from_bytes(padded[i + 2:i + 6], 'big'))
            for i in range(0, len(padded), 6)]


class SettingsCutTests(unittest.TestCase):
    """A ``SETTINGS`` frame cut at every offset inside its settings (#2659)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assert_cut(self, http: 'object', keep: int) -> None:
        """``http`` holds the first ``keep`` octets of the settings and rebuilds them."""
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.protocols.misc.no_payload import NoPayload

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
        from pcapkit.protocols.internet.ipv4 import IPv4

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
        from pcapkit.protocols.application.httpv2 import HTTPv2

        for keep in range(len(PAIRS)):
            with self.subTest(keep=keep):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    self.assert_cut(HTTPv2(SETTINGS[:9 + keep], len(SETTINGS)), keep)
                self.assertEqual(caught, [])

    def test_a_setting_cut_inside_its_value_keeps_its_identifier(self) -> None:
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTPv2

        http = HTTPv2(SETTINGS[:9 + 9], len(SETTINGS))
        self.assertEqual(list(http.info.settings.items(multi=True)),
                         [(Setting.HEADER_TABLE_SIZE, 4096), (Setting.MAX_CONCURRENT_STREAMS, 0)])

    def test_whole_frame_is_the_control(self) -> None:
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.protocols.internet.ipv4 import IPv4

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
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

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


class SettingPairListFieldTests(unittest.TestCase):
    """The settings list is sized by the octets present, no further than its Length."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_reads_bytes_and_a_live_stream_alike(self) -> None:
        from pcapkit.protocols.schema.application.httpv2 import SettingsFrame

        field = SettingsFrame.__fields__['settings']({'__length__': len(PAIRS)})
        stream = io.BytesIO(b'\xde\xad' + PAIRS[:9])
        stream.seek(2)
        for name, buffer in (('bytes', PAIRS[:9]), ('stream', stream)):
            with self.subTest(buffer=name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    parsed = field.unpack(buffer, {})
                self.assertEqual(caught, [])
                self.assertEqual([(int(pair.id), pair.value) for pair in parsed], [(1, 4096), (3, 0)])
                self.assertEqual(field.length, len(PAIRS))

    def test_a_live_stream_is_read_no_further_than_the_length(self) -> None:
        from pcapkit.protocols.schema.application.httpv2 import SettingsFrame

        field = SettingsFrame.__fields__['settings']({'__length__': 12})
        stream = io.BytesIO(PAIRS + WINDOW_UPDATE)
        parsed = field.unpack(stream, {})
        self.assertEqual([(int(pair.id), pair.value) for pair in parsed], [(1, 4096), (3, 100)])
        self.assertEqual(stream.tell(), 12)


class SettingsFrameLengthTests(unittest.TestCase):
    """``HTTPv2.make`` writes the ``frame_length`` it is given only as an :obj:`int`
    from the Length the frame packs to up to ``0xFFFFFF``, and above that Length
    only with no payload after the frame; any other is refused (#2617, #2659)."""

    #: One setting, so the frame packs to a Length of 6.
    ONE_PAIR = {'settings': [(0x1, 4096)]}

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_length_the_frame_or_the_field_cannot_carry_is_refused(self) -> None:
        import re

        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            ('past the 24-bit field', Frame.SETTINGS, self.ONE_PAIR, 2 ** 24, b'', 6),
            ('a bool', Frame.SETTINGS, self.ONE_PAIR, False, b'', 6),
            # each in range as an int, so only the bool clause refuses it
            ('True for one octet', Frame.DATA, {'data': b'a'}, True, b'', 1),
            ('False for no octets', Frame.DATA, {'data': b''}, False, b'', 0),
            ('a float', Frame.SETTINGS, self.ONE_PAIR, 2.0, b'', 6),
            ('a str', Frame.SETTINGS, self.ONE_PAIR, '9', b'', 6),
            ('negative', Frame.SETTINGS, self.ONE_PAIR, -1, b'', 6),
            ('short of the settings', Frame.SETTINGS, self.ONE_PAIR, 0, b'', 6),
            ('short of the data', Frame.DATA, {'data': b'abc'}, 2, b'', 3),
            ('past the settings, before a frame', Frame.SETTINGS, self.ONE_PAIR, 18, WINDOW_UPDATE, 6),
        )
        for label, type_, frame, length, payload, built in cases:
            with self.subTest(label), self.assertRaisesRegex(
                    ProtocolError, rf'^HTTP/2: \[Type \d\] invalid frame_length: {re.escape(repr(length))} '
                                   rf'for a frame payload of {built} octet'):
                HTTPv2(type=type_, sid=0 if type_ is Frame.SETTINGS else 1, frame=frame,
                       frame_length=length, payload=payload)

    def test_a_length_from_the_frame_to_the_field_maximum_is_written(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2

        # A SETTINGS Length is a multiple of 6 (RFC 9113, section 6.5), which
        # ``_read_http_settings`` holds it to, so the edge one past a frame is on DATA.
        cases = (
            ('the settings, before a frame', Frame.SETTINGS, self.ONE_PAIR, 6, WINDOW_UPDATE, PAIRS[:6]),
            ('the data, before a frame', Frame.DATA, {'data': b'abc'}, 3, WINDOW_UPDATE, b'abc'),
            ('one past the data', Frame.DATA, {'data': b'abc'}, 4, b'', b'abc'),
            ('one past the data, payload None', Frame.DATA, {'data': b'abc'}, 4, None, b'abc'),
        )
        for label, type_, frame, length, payload, body in cases:
            with self.subTest(label):
                http = HTTPv2(type=type_, sid=0 if type_ is Frame.SETTINGS else 1, frame=frame,
                              frame_length=length, payload=payload)
                self.assertEqual(http.data[:3], length.to_bytes(3, 'big'))
                self.assertEqual(http.data[9:], body + (payload or b''))
                self.assertEqual(http.info.length, length)
                if payload:
                    self.assertEqual(http.payload.info.increment, 65535)

        # Parsed back, a Length this far past the octets meets ``MAX_ZERO_PAD_LENGTH``,
        # so the field maximum is checked on what ``make`` builds.
        header = object.__new__(HTTPv2).make(type=Frame.SETTINGS, frame=self.ONE_PAIR, frame_length=0xFFFFFF)
        self.assertEqual(header.length, 0xFFFFFF)
        self.assertEqual(bytes(header)[:3], b'\xff\xff\xff')

    def test_a_length_past_the_settings_is_kept(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTPv2

        http = HTTPv2(type=Frame.SETTINGS, frame={'settings': [(Setting.HEADER_TABLE_SIZE, 4096)]},
                      frame_length=18)
        self.assertEqual(http.data, SETTINGS[:15])
        self.assertEqual(http.info.length, 18)
        self.assertEqual(http.info['__short_read__'], ('frame', 6))
        self.assertEqual(list(http.info.settings.items(multi=True)), [(Setting.HEADER_TABLE_SIZE, 4096)])

    def test_the_length_is_computed_when_not_given(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTPv2

        http = HTTPv2(type=Frame.SETTINGS, frame={'settings': [(Setting.HEADER_TABLE_SIZE, 4096)]})
        self.assertEqual(http.data, _frame(0x4, 0x0, 0, PAIRS[:6]))
        self.assertEqual(http.info.length, 6)
        self.assertNotIn('__short_read__', http.info)

    def test_an_explicit_parse_length_leaves_no_state_behind(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2

        http = HTTPv2(type=Frame.SETTINGS, frame=self.ONE_PAIR, frame_length=18, length=27)
        self.assertEqual(http.info.length, 18)
        self.assertNotIn('_made_length', vars(http))

    def test_a_dict_with_no_length_computes_it(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTPv2

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
