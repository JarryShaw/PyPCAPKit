# -*- coding: utf-8 -*-
"""ICMPv6 decodes MLDv1 (RFC 2710) and MLDv2 (RFC 9777). C.f. #2812.

Types 130, 131, 132 and 143 parse into their own data models, a Query's version
chosen by its length (:rfc:`9777#section-8.1`), and rebuild byte for byte through
``from_data``, whole or cut by the capture. Each message is built here against the
RFC layouts; this module is unit-tier and reads no capture.

"""

import io
import ipaddress
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: The group ff02::1:3 and two sources, as on the wire.
GROUP = ipaddress.IPv6Address('ff02::1:3').packed
SOURCE_1 = ipaddress.IPv6Address('2001:db8::1').packed
SOURCE_2 = ipaddress.IPv6Address('2001:db8::2').packed

#: MLDv1 messages: type, code, checksum, Maximum Response Delay, Reserved, group.
MLDV1_QUERY = bytes.fromhex('8200' 'abcd' '03e8' '0000') + GROUP
MLDV1_REPORT = bytes.fromhex('8300' 'abcd' '0000' '0000') + GROUP
MLDV1_DONE = bytes.fromhex('8400' 'abcd' '0000' '0000') + GROUP

#: An MLDv2 Query: Maximum Response Code 0x8123, Reserved, group, Flags 0 S 1 QRV 2,
#: QQIC 125, two sources.
MLDV2_QUERY = (bytes.fromhex('8200' 'abcd' '8123' '0000') + GROUP + bytes.fromhex('0a' '7d' '0002')
               + SOURCE_1 + SOURCE_2)

#: Two multicast address records: CHANGE_TO_EXCLUDE_MODE with a source and a word of
#: auxiliary data, then MODE_IS_INCLUDE with none.
RECORD_1 = bytes.fromhex('04' '01' '0001') + GROUP + SOURCE_1 + b'AUX!'
RECORD_2 = bytes.fromhex('01' '00' '0000') + GROUP

#: An MLDv2 Report: type, Reserved, checksum, Flags, two records, Additional Data.
MLDV2_REPORT = bytes.fromhex('8f00' 'abcd' '8000' '0002') + RECORD_1 + RECORD_2 + b'tail'

#: Every message above, by name.
MESSAGES = {
    'mldv1-query': MLDV1_QUERY,
    'mldv1-report': MLDV1_REPORT,
    'mldv1-done': MLDV1_DONE,
    'mldv2-query': MLDV2_QUERY,
    'mldv2-report': MLDV2_REPORT,
}


def ipv6(payload: bytes, length: int) -> bytes:
    """An IPv6 header carrying ICMPv6 and declaring ``length`` payload octets, then ``payload``."""
    return (bytes.fromhex('60000000') + length.to_bytes(2, 'big') + bytes([58, 1])
            + bytes(15) + b'\x01' + bytes.fromhex('ff02' + '0' * 24 + '0016') + payload)


class MLDParseTests(unittest.TestCase):
    """Each message reads as :rfc:`2710` and :rfc:`9777` lay it out."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, packet: bytes) -> 'object':
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return ICMPv6(io.BytesIO(packet), len(packet)).info

    def test_mldv1_messages(self) -> None:
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.protocols.internet.icmpv6.data import MLDv1

        for packet, type_, delay in ((MLDV1_QUERY, Type.Multicast_Listener_Query, 1000),
                                     (MLDV1_REPORT, Type.Multicast_Listener_Report, 0),
                                     (MLDV1_DONE, Type.Multicast_Listener_Done, 0)):
            with self.subTest(type=type_):
                info = self.parse(packet)
                self.assertIs(type(info), MLDv1)
                self.assertEqual(info.type, type_)
                self.assertEqual(info.version, 1)
                self.assertEqual(info.max_resp_delay, delay)
                self.assertEqual(info.reserved, b'\x00\x00')
                self.assertEqual(info.multicast_address, ipaddress.IPv6Address('ff02::1:3'))
                self.assertEqual(info.data, b'')
                self.assertEqual(info.length, 24)

    def test_query_version_follows_its_length(self) -> None:
        """24 to 27 octets read as MLDv1, 28 and more as MLDv2 (:rfc:`9777#section-8.1`)."""
        from pcapkit.protocols.internet.icmpv6.data import MLDv1, MLDv2Query

        for extra, model in ((b'', MLDv1), (b'\x01', MLDv1), (b'\x01\x02\x03', MLDv1),
                             (bytes(4), MLDv2Query)):
            with self.subTest(length=24 + len(extra)):
                info = self.parse(MLDV1_QUERY + extra)
                self.assertIs(type(info), model)
                if model is MLDv1:
                    self.assertEqual(info.data, extra)
                else:
                    self.assertEqual((info.num_sources, info.sources, info.data), (0, (), b''))

    def test_mldv2_query(self) -> None:
        from pcapkit.protocols.internet.icmpv6.data import MLDv2Query

        info = self.parse(MLDV2_QUERY + b'XYZ')
        self.assertIs(type(info), MLDv2Query)
        self.assertEqual(info.version, 2)
        self.assertEqual(info.max_resp_code, 0x8123)
        # exp 0, mant 0x123: (0x123 | 0x1000) << 3 (RFC 9777 section 5.1.3).
        self.assertEqual(info.max_resp_delay, 35096)
        self.assertEqual(info.multicast_address, ipaddress.IPv6Address('ff02::1:3'))
        self.assertEqual((info.flags, info.s_flag, info.qrv), (0, True, 2))
        self.assertEqual((info.qqic, info.qqi), (125, 125))
        self.assertEqual(info.num_sources, 2)
        self.assertEqual(info.sources, (ipaddress.IPv6Address('2001:db8::1'),
                                        ipaddress.IPv6Address('2001:db8::2')))
        self.assertEqual(info.data, b'XYZ')

    def test_mldv2_query_codes_below_32768_are_literal(self) -> None:
        packet = bytearray(MLDV2_QUERY)
        packet[4:6] = (0x7FFF).to_bytes(2, 'big')
        packet[25] = 0x8C  # QQIC exp 0, mant 12: (12 | 0x10) << 3
        info = self.parse(bytes(packet))
        self.assertEqual(info.max_resp_delay, 0x7FFF)
        self.assertEqual(info.qqi, 224)

    def test_mldv2_report(self) -> None:
        from pcapkit.const.igmp.record_type import RecordType
        from pcapkit.protocols.internet.icmpv6.data import MLDv2Report, MulticastAddressRecord

        info = self.parse(MLDV2_REPORT)
        self.assertIs(type(info), MLDv2Report)
        self.assertEqual((info.version, info.code, info.flags, info.num_records), (2, 0, 0x8000, 2))
        self.assertEqual(info.data, b'tail')
        first, second = info.records
        self.assertIs(type(first), MulticastAddressRecord)
        self.assertEqual(first.record_type, RecordType.CHANGE_TO_EXCLUDE_MODE)
        self.assertEqual((first.aux_data_len, first.num_sources, first.aux_data), (1, 1, b'AUX!'))
        self.assertEqual(first.multicast_address, ipaddress.IPv6Address('ff02::1:3'))
        self.assertEqual(first.sources, (ipaddress.IPv6Address('2001:db8::1'),))
        self.assertEqual(second.record_type, RecordType.MODE_IS_INCLUDE)
        self.assertEqual((second.aux_data_len, second.num_sources, second.sources), (0, 0, ()))

    def test_records_past_the_count_are_additional_data(self) -> None:
        packet = bytearray(MLDV2_REPORT)
        packet[7] = 1
        info = self.parse(bytes(packet))
        self.assertEqual(len(info.records), 1)
        self.assertEqual(info.data, RECORD_2 + b'tail')


class MLDRoundTripTests(unittest.TestCase):
    """Each message rebuilds byte for byte, whole or cut."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assert_rebuilds(self, parsed: 'object', captured: bytes) -> None:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            rebuilt = ICMPv6.from_data(parsed.info)
            redict = ICMPv6.from_data(parsed.info.to_dict())
        self.assertEqual(rebuilt.data.hex(), captured.hex())
        self.assertEqual(rebuilt.info, parsed.info)
        self.assertEqual(redict.data.hex(), captured.hex())

    def test_whole_messages(self) -> None:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        for name, packet in MESSAGES.items():
            for extra in (b'', b'\x01\x02\x03'):
                with self.subTest(message=name, extra=extra), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assert_rebuilds(ICMPv6(io.BytesIO(packet + extra), len(packet) + len(extra)),
                                         packet + extra)

    def test_cuts_behind_ipv6(self) -> None:
        """Cut at every octet behind an IPv6 header declaring the whole message."""
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for name, packet in MESSAGES.items():
            for cut in range(4, len(packet)):
                with self.subTest(message=name, cut=cut), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    frame = ipv6(packet[:cut], len(packet))
                    layer = IPv6(io.BytesIO(frame), len(frame)).payload
                    self.assertIsInstance(layer, ICMPv6)
                    self.assertEqual(type(layer.info).__name__,
                                     type(ICMPv6(io.BytesIO(packet), len(packet)).info).__name__)
                    self.assert_rebuilds(layer, packet[:cut])

    def test_cuts_on_their_own(self) -> None:
        """Cut at every octet and parsed with no enclosing length, as IGMPv3 is.

        A Query the cut leaves fewer than 28 octets of reads as MLDv1, its length
        being all there is to tell the version by (RFC 9777 section 8.1).

        """
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        for name, packet in MESSAGES.items():
            for extra in (b'', b'XYZ'):
                whole = packet + extra
                for cut in range(4, len(whole)):
                    part = whole[:cut]
                    with self.subTest(message=name, extra=extra, cut=cut), warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        parsed = ICMPv6(io.BytesIO(part), len(part))
                        if name == 'mldv2-query':
                            self.assertEqual(type(parsed.info).__name__,
                                             'MLDv2Query' if cut >= 28 else 'MLDv1')
                        self.assert_rebuilds(parsed, part)

    def test_cut_query_on_its_own_records_the_cut(self) -> None:
        """A Query the data ends inside its fields or its counted sources records the cut."""
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        for cut in (*range(4, 24), *range(28, len(MLDV2_QUERY))):
            part = MLDV2_QUERY[:cut]
            with self.subTest(cut=cut), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = ICMPv6(io.BytesIO(part), len(part))
                self.assertIsNotNone(parsed.info.get('__short_read__'))
                if cut >= 28:
                    self.assertEqual(parsed.info.num_sources, 2)
                    self.assertEqual(len(parsed.info.sources), -(-(cut - 28) // 16))

    def test_cut_report_on_its_own(self) -> None:
        """A Report the data ends before its counted records records the cut.

        A cut among the records is quiet, as IGMPv3's is (#2749); one inside the
        fixed octets before them warns, as IGMPv3's does.

        """
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.utilities.warnings import SchemaWarning

        for cut in range(4, len(MLDV2_REPORT) - len(b'tail')):
            part = MLDV2_REPORT[:cut]
            with self.subTest(cut=cut), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                parsed = ICMPv6(io.BytesIO(part), len(part))
                self.assertIsNotNone(parsed.info.get('__short_read__'))
                if cut >= 8:
                    self.assertFalse([item for item in caught if issubclass(item.category, SchemaWarning)])
                self.assert_rebuilds(parsed, part)

    def test_a_count_no_ip_payload_can_carry_is_refused(self) -> None:
        """3276 records of 20 octets behind the 8 before them fit 65535 octets; 3277 do not."""
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        for count in (3276, 3277):
            packet = bytes.fromhex('8f00' 'abcd' '0000') + count.to_bytes(2, 'big') + RECORD_2
            with self.subTest(count=count), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                if count == 3277:
                    with self.assertRaises(ProtocolError):
                        ICMPv6(io.BytesIO(packet), len(packet))
                else:
                    parsed = ICMPv6(io.BytesIO(packet), len(packet))
                    self.assertEqual(len(parsed.info.records), 1)
                    self.assert_rebuilds(parsed, packet)

    def test_make_then_parse(self) -> None:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        for name, packet in MESSAGES.items():
            with self.subTest(message=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = ICMPv6(io.BytesIO(packet), len(packet))
                made = ICMPv6.build(type=parsed.info.type, code=0, checksum=b'\xab\xcd', body=parsed.info)
                self.assertEqual(bytes(made), packet)


class MLDMakeTests(unittest.TestCase):
    """Building MLD messages from fields."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def make(self, type_: int, **body: 'object') -> bytes:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        return bytes(object.__new__(ICMPv6).make(type=type_, checksum=b'\xab\xcd', body=body))

    def test_mldv2_query_from_its_fields(self) -> None:
        packet = self.make(130, version=2, max_resp_delay=35096, multicast_address='ff02::1:3',
                           s_flag=True, qrv=2, qqi=125, sources=['2001:db8::1', '2001:db8::2'])
        self.assertEqual(packet.hex(), MLDV2_QUERY.hex())

    def test_mldv1_messages_from_their_fields(self) -> None:
        self.assertEqual(self.make(130, version=1, max_resp_delay=1000, multicast_address='ff02::1:3'),
                         MLDV1_QUERY)
        # Three octets past the 24 still read as MLDv1; four would not.
        self.assertEqual(self.make(130, version=1, max_resp_delay=1000, multicast_address='ff02::1:3',
                                   data=b'XYZ'), MLDV1_QUERY + b'XYZ')
        self.assertEqual(self.make(131, multicast_address='ff02::1:3'), MLDV1_REPORT)
        self.assertEqual(self.make(132, multicast_address='ff02::1:3'), MLDV1_DONE)

    def test_mldv2_report_from_its_fields(self) -> None:
        from pcapkit.const.igmp.record_type import RecordType

        packet = self.make(143, flags=0x8000, data=b'tail', records=[
            {'record_type': RecordType.CHANGE_TO_EXCLUDE_MODE, 'multicast_address': 'ff02::1:3',
             'sources': ['2001:db8::1'], 'aux_data': b'AUX!'},
            {'record_type': 1, 'multicast_address': 'ff02::1:3'},
        ])
        self.assertEqual(packet.hex(), MLDV2_REPORT.hex())

    def test_counts_above_the_items_are_written_as_given(self) -> None:
        packet = self.make(130, version=2, num_sources=3, sources=['2001:db8::1'])
        self.assertEqual(packet[26:28], b'\x00\x03')
        packet = self.make(143, num_records=2, records=[{'num_sources': 4}])
        self.assertEqual(packet[6:8] + packet[10:12], b'\x00\x02\x00\x04')

    def test_refusals(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for type_, body in (
                (130, {}),                                      # no field picks the version
                (130, {'version': 3}),
                (130, {'version': True}),
                (130, {'version': 1, 'max_resp_delay': 0x10000}),
                (130, {'version': 2, 'max_resp_delay': -1}),
                (130, {'version': 2, 'qqi': True}),
                (130, {'version': 2, 'flags': 0x10}),
                (130, {'version': 2, 'qrv': 8}),
                (130, {'version': 2, 'num_sources': 0, 'sources': ['::1']}),
                (130, {'version': 1, 'reserved': b'\x00'}),
                (130, {'version': 1, 'data': bytes(4)}),         # 28 octets read as MLDv2
                (130, {'version': 1, 'qrv': 5}),                 # fields MLDv2 alone takes
                (130, {'version': 1, 'sources': ['::1']}),
                (130, {'version': 1, 'max_resp_code': 1}),
                (130, {'version': 1, 's_flag': False}),
                (131, {'max_resp_delay': True}),
                (143, {'flags': 0x10000}),
                (143, {'num_records': 0, 'records': [{}]}),
                (143, {'records': [{'record_type': True}]}),
                (143, {'records': [{'record_type': 'MODE_IS_INCLUDE'}]}),
                (143, {'records': [{'aux_data': b'AUX'}]}),
                (143, {'records': [{'aux_data_len': 0x100}]}),
                (143, {'records': [{'num_sources': 0, 'sources': ['::1']}]}),
        ):
            with self.subTest(type=type_, body=body), self.assertRaises(ProtocolError):
                self.make(type_, **body)


class FloatCodeTests(unittest.TestCase):
    """The 16-bit floating-point code of :rfc:`9777#section-5.1.3`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_exact_value_round_trips(self) -> None:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        proto = object.__new__(ICMPv6)
        for exp in range(8):
            for mant in (0, 1, 0x123, 0xFFF):
                value = (mant | 0x1000) << (exp + 3)
                with self.subTest(exp=exp, mant=mant):
                    code = proto._make_float_code(value, bits=16, name='max_resp_delay')
                    self.assertEqual(code, 0x8000 | exp << 12 | mant)
                    self.assertEqual(proto._read_float_code(code, bits=16), value)

    def test_literal_and_saturated(self) -> None:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(ICMPv6)
        for value in (0, 1, 0x7FFF):
            self.assertEqual(proto._make_float_code(value, bits=16, name='x'), value)
        # A value between two codes floors, and one past the largest takes it.
        self.assertEqual(proto._make_float_code(0x8009, bits=16, name='x'), 0x8001)
        self.assertEqual(proto._make_float_code(1 << 30, bits=16, name='x'), 0xFFFF)
        for value in (-1, True, 1.0, '1'):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                proto._make_float_code(value, bits=16, name='x')


if __name__ == '__main__':
    unittest.main()
