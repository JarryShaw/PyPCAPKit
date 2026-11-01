# -*- coding: utf-8 -*-
"""DCCP dissection, construction and its checksum over the IP pseudo-header.

GitHub issue #2489: :class:`~pcapkit.protocols.transport.dccp.DCCP` parses the
:rfc:`4340` generic header with short and long sequence numbers, the fields each
packet type adds, DCCP-Listen (:rfc:`5596`) and the options, and rebuilds every
packet byte for byte. The enclosing IPv4 or IPv6 layer verifies and computes the
checksum over the part of the packet the Checksum Coverage gives
(:rfc:`4340#section-9`). The octets here are built by hand; the checksummed
packets were checked against Wireshark's DCCP dissector, and the expected sums
are the hand-written one of ``tests/foundation/_roundtrip.py``.

"""
from __future__ import annotations

import struct
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

SRC, DST = 40000, 5001


def generic(type_: int, *, x: bool = True, seq: int = 1, offset: int = 0, ccval: int = 0,
            cscov: int = 0, checksum: bytes = b'\x00\x00', res: int = 0, seq_res: int = 0) -> bytes:
    """The generic header (RFC 4340 section 5.1); ``offset`` in 32-bit words."""
    head = struct.pack('!HHBB', SRC, DST, offset, (ccval << 4) | cscov) + checksum
    if x:
        return head + bytes([(res << 5) | (type_ << 1) | 1, seq_res]) + seq.to_bytes(6, 'big')
    return head + bytes([(res << 5) | (type_ << 1)]) + seq.to_bytes(3, 'big')


def ack(number: int, *, x: bool = True, res: int = 0) -> bytes:
    """The Acknowledgement Number Subheader."""
    if x:
        return res.to_bytes(2, 'big') + number.to_bytes(6, 'big')
    return res.to_bytes(1, 'big') + number.to_bytes(3, 'big')


def packet(type_: int, extra: bytes = b'', options: bytes = b'', data: bytes = b'', **kwargs: object) -> bytes:
    """A DCCP packet, its Data Offset filled in."""
    words = (len(generic(type_, **kwargs)) + len(extra) + len(options)) // 4  # type: ignore[arg-type]
    return generic(type_, offset=words, **kwargs) + extra + options + data  # type: ignore[arg-type]


#: IPv4 and IPv6 packets carrying DCCP with their checksum computed, each one
#: reported correct by Wireshark: a DCCP-Request with a Change L option, a
#: DCCP-DataAck with CsCov 2 over IPv4, a DCCP-Reset over IPv6, and a DCCP-Data
#: with CsCov 1, which leaves all of its data out.
CHECKSUMMED = (
    bytes.fromhex('45000031000000000021ce75c0000201c63364029c40138906008f3a0100000000000001'
                  '123456782004010268656c6c6f'),
    bytes.fromhex('4500003c000000000021ce6ac0000201c63364029c4013890602ca360800000700000006'
                  '290600000005000030313233343536373839616263646566'),
    bytes.fromhex('60000000001f214020010db800000000000000000000000120010db800000000000000000000'
                  '00029c401389070004e90f000000000000090000000000000008052001026f6464'),
    bytes.fromhex('45000025000000000021ce81c0000201c63364029c40138903015cc8040000036162636465'),
)


def pseudo4(length: int) -> bytes:
    """The IPv4 pseudo-header of DCCP (RFC 4340 section 9.1)."""
    return wire.IPV4_A + wire.IPV4_B + b'\x00\x21' + length.to_bytes(2, 'big')


def pseudo6(length: int) -> bytes:
    """The IPv6 pseudo-header of DCCP."""
    return wire.IPV6_A + wire.IPV6_B + length.to_bytes(4, 'big') + b'\x00\x00\x00\x21'


def expected(prefix: bytes, datagram: bytes, covered: int) -> bytes:
    """The checksum ``datagram`` should carry over ``prefix`` and its first ``covered`` octets."""
    return wire.checksum(prefix + (datagram[:6] + b'\x00\x00' + datagram[8:])[:covered]).to_bytes(2, 'big')


class DCCPTestCase(unittest.TestCase):
    """Imports shared by the DCCP tests."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.dccp.ack_vector_state import AckVectorState
        from pcapkit.const.dccp.drop_code import DropCode
        from pcapkit.const.dccp.feature import Feature
        from pcapkit.const.dccp.option import Option
        from pcapkit.const.dccp.packet_type import PacketType
        from pcapkit.const.dccp.reset_code import ResetCode
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.transport.dccp import DCCP
        from pcapkit.utilities import config
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.DCCP, self.IPv4, self.IPv6, self.IP_Pseudo = DCCP, IPv4, IPv6, IP_Pseudo
        self.Type, self.Option, self.Feature, self.ResetCode = PacketType, Option, Feature, ResetCode
        self.State, self.DropCode, self.Status = AckVectorState, DropCode, ChecksumStatus
        self.config, self.ProtocolError = config, ProtocolError
        self.ChecksumWarning, self.ProtocolWarning = ChecksumWarning, ProtocolWarning

    def assertRoundTrip(self, octets: bytes) -> 'object':  # pylint: disable=invalid-name
        """``octets`` parse, and rebuild from the parse, as themselves; the parse."""
        layer = self.DCCP(octets)
        self.assertEqual(layer.data, octets)
        self.assertEqual(self.DCCP.from_data(layer.info).data, octets)
        self.assertEqual(self.DCCP.from_data(layer.info.to_dict()).data, octets)
        return layer


class DCCPPacketTypeTests(DCCPTestCase):
    """Each packet type, against the RFC 4340 field layout."""

    def test_request_with_long_sequence_numbers(self) -> None:
        octets = packet(0, struct.pack('!I', 0x12345678), data=b'hello', seq=0x0102030405, ccval=3, seq_res=0x5A)
        info = self.assertRoundTrip(octets).info
        self.assertEqual((info.srcport.port, info.dstport.port), (SRC, DST))
        self.assertEqual((info.hdr_len, info.type, info.x), (20, self.Type.DCCP_Request, True))
        self.assertEqual((info.seq, info.seq_reserved, info.ccval), (0x0102030405, 0x5A, 3))
        self.assertEqual(info.service_code, 0x12345678)
        self.assertNotIn('ack', info)
        self.assertNotIn('options', info)

    def test_response_carries_an_ack_and_a_service_code(self) -> None:
        octets = packet(1, ack(0xABCDEF012345, res=0x0102) + struct.pack('!I', 7))
        info = self.assertRoundTrip(octets).info
        self.assertEqual((info.hdr_len, info.type), (28, self.Type.DCCP_Response))
        self.assertEqual((info.ack, info.ack_reserved, info.service_code), (0xABCDEF012345, 0x0102, 7))

    def test_data_with_short_sequence_numbers(self) -> None:
        octets = packet(2, data=b'xy', x=False, seq=0xABCDEF)
        layer = self.assertRoundTrip(octets)
        self.assertEqual((layer.info.hdr_len, layer.info.x, layer.info.seq), (12, False, 0xABCDEF))
        self.assertNotIn('seq_reserved', layer.info)
        self.assertNotIn('ack', layer.info)
        self.assertEqual((layer.length, bytes(layer.payload)), (12, b'xy'))
        self.assertEqual((layer.name, layer.src.port, layer.dst.port),
                         ('Datagram Congestion Control Protocol', SRC, DST))

    def test_ack_and_data_ack_take_either_sequence_number_length(self) -> None:
        for type_ in (3, 4):
            for x in (True, False):
                with self.subTest(type=type_, x=x):
                    octets = packet(type_, ack(0x0A0B0C, x=x, res=1), data=b'z', x=x, seq=0x010203)
                    info = self.assertRoundTrip(octets).info
                    self.assertEqual((info.ack, info.ack_reserved), (0x0A0B0C, 1))
                    self.assertEqual(info.hdr_len, 24 if x else 16)

    def test_close_sync_and_their_acks_carry_only_an_ack(self) -> None:
        for type_ in (5, 6, 8, 9):
            with self.subTest(type=type_):
                info = self.assertRoundTrip(packet(type_, ack(99))).info
                self.assertEqual((info.type, info.ack, info.hdr_len), (self.Type(type_), 99, 24))
                self.assertNotIn('service_code', info)

    def test_reset_carries_a_code_and_three_data_octets(self) -> None:
        octets = packet(7, ack(8) + bytes([5, 32, 1, 2]), data=b'Option Error')
        info = self.assertRoundTrip(octets).info
        self.assertEqual((info.reset_code, info.reset_data), (self.ResetCode.Option_Error, b'\x20\x01\x02'))
        self.assertEqual(info.hdr_len, 28)

    def test_listen_carries_a_service_code_and_no_ack(self) -> None:
        # RFC 5596 section 2.2.1: the generic header with X set, then a Service Code.
        info = self.assertRoundTrip(packet(10, struct.pack('!I', 0x01020304), seq=0)).info
        self.assertEqual((info.type, info.service_code), (self.Type.DCCP_Listen, 0x01020304))
        self.assertNotIn('ack', info)

    def test_a_reserved_type_keeps_its_bits(self) -> None:
        # Type 11 is unassigned, so only the generic header is known; Res is kept too.
        info = self.assertRoundTrip(packet(11, data=b'?', res=5)).info
        self.assertEqual((info.type, info.reserved, info.hdr_len), (self.Type(11), 5, 16))

    def test_make_builds_each_packet_type(self) -> None:
        for type_ in range(11):
            for x in (True, False):
                with self.subTest(type=type_, x=x):
                    made = self.DCCP(srcport=SRC, dstport=DST, type=type_, x=x, seq=5, ack=4,
                                     service_code=3, reset_code=2, reset_data=b'\x01\x02\x03',
                                     checksum=b'\x00\x00', payload=b'data')
                    self.assertRoundTrip(made.data)
                    self.assertEqual(self.DCCP(made.data).info.type, self.Type(type_))

    def test_a_data_offset_short_of_the_type_is_refused(self) -> None:
        octets = bytearray(packet(1, ack(1) + bytes(4)))
        octets[4] = 6  # 24 octets, where a DCCP-Response takes 28
        with self.assertRaisesRegex(self.ProtocolError, 'shorter than the 28 octets of a DCCP_Response'):
            self.DCCP(bytes(octets))

    def test_a_data_offset_past_the_data_is_refused(self) -> None:
        octets = bytearray(packet(2, x=False))
        octets[4] = 4
        with self.assertRaisesRegex(self.ProtocolError, 'runs past the end of the data'):
            self.DCCP(bytes(octets))

    def test_a_refused_header_leaves_the_ip_payload_raw(self) -> None:
        octets = bytearray(packet(2, x=False))
        octets[4] = 4
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            ip = self.IPv4(wire.ipv4(bytes(octets), proto=33))
        self.assertEqual(type(ip.payload).__name__, 'Raw')

    def test_the_ip_layer_dispatches_protocol_33(self) -> None:
        ip = self.IPv4(wire.ipv4(packet(2, data=b'hi', x=False), proto=33))
        self.assertIsInstance(ip.payload, self.DCCP)
        self.assertIn('DCCP', ip)
        self.assertEqual(bytes(ip.payload.payload), b'hi')
        self.assertEqual(self.DCCP.__index__(), 33)

    def test_an_oversized_header_is_refused(self) -> None:
        cookie = (self.Option.Init_Cookie, {'cookie': bytes(253)})
        with self.assertRaisesRegex(self.ProtocolError, 'exceeds 1020 octets'):
            self.DCCP(type=0, options=[cookie] * 4, checksum=b'\x00\x00')


class DCCPOptionTests(DCCPTestCase):
    """Options, against the RFC 4340 option formats."""

    def options(self, area: bytes) -> 'object':
        """The options of a DCCP-Ack carrying ``area``, after a round trip."""
        return self.assertRoundTrip(packet(3, ack(1), area)).info.options

    def test_single_octet_options(self) -> None:
        options = self.options(bytes([0, 1, 2, 3]))
        self.assertEqual([(int(code), option.length) for code, option in options.items(multi=True)],
                         [(0, 1), (1, 1), (2, 1), (3, 1)])
        self.assertEqual([type(option).__name__ for _, option in options.items(multi=True)],
                         ['Padding', 'Mandatory', 'SlowReceiver', 'UnassignedOption'])
        self.assertEqual(options[self.Option(3)].data, b'')

    def test_feature_negotiation(self) -> None:
        options = self.options(bytes([32, 4, 1, 2, 33, 5, 1, 2, 3, 34, 3, 6, 35, 3, 6, 0, 0, 0]))
        change = options[self.Option.Change_L]
        self.assertEqual((change.feature, change.value), (self.Feature.Congestion_Control_ID, b'\x02'))
        self.assertEqual(options[self.Option.Confirm_L].value, b'\x02\x03')
        self.assertEqual(options[self.Option.Change_R].feature, self.Feature.Send_Ack_Vector)
        # An empty Confirm (RFC 4340 section 6.6.7) has no value.
        self.assertEqual(options[self.Option.Confirm_R].value, b'')

    def test_a_feature_option_without_its_number(self) -> None:
        # Length 2 leaves no room for the feature number, which is then absent.
        options = self.options(bytes([32, 2, 35, 2]))
        self.assertEqual([(option.feature, option.value) for _, option in options.items(multi=True)],
                         [(None, b''), (None, b'')])
        made = self.DCCP(type=3, ack=1, checksum=b'\x00\x00',
                         options=[(self.Option.Confirm_R, {'feature': None})])
        self.assertEqual(made.data[24:], bytes([35, 2, 0, 0]))
        for code in (self.Option.Change_L, self.Option.Confirm_L):
            with self.subTest(code=code), self.assertRaises(self.ProtocolError):
                self.DCCP(type=3, checksum=b'\x00\x00', options=[(code, {'feature': None, 'value': b'\x01'})])

    def test_a_feature_option_shorter_than_its_header_is_refused(self) -> None:
        # RFC 4340 section 5.8: a length under 2 is nonsensical, as in every option
        # with a length; under IP the whole layer is then Raw.
        for code in (32, 33, 34, 35):
            for length in (0, 1):
                with self.subTest(code=code, length=length):
                    octets = packet(3, ack(1), bytes([code, length, 0, 0]))
                    with self.assertRaisesRegex(self.ProtocolError, 'negative length'):
                        self.DCCP(octets)
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        ip = self.IPv4(wire.ipv4(octets, proto=33))
                    self.assertEqual(type(ip.payload).__name__, 'Raw')
                    self.assertEqual(ip.payload.data, octets)

    def test_cookie_and_ndp_count(self) -> None:
        options = self.options(bytes([36, 5, 9, 8, 7, 37, 4, 0, 1, 0, 0, 0]))
        self.assertEqual(options[self.Option.Init_Cookie].cookie, b'\x09\x08\x07')
        # The count keeps its width: a leading zero octet rebuilds as one.
        self.assertEqual((options[self.Option.NDP_Count].count, options[self.Option.NDP_Count].length), (1, 4))

    def test_an_ndp_count_past_eight_octets_keeps_its_width(self) -> None:
        # RFC 4340 section 7.7 allows a length of 3 to 8; a longer one still rebuilds as itself.
        for length in (9, 12, 255):
            with self.subTest(length=length):
                area = bytes([37, length]) + bytes(length - 3) + b'\x07'
                ndp = self.options(area + bytes(-len(area) % 4))[self.Option.NDP_Count]
                self.assertEqual((ndp.length, ndp.count), (length, 7))

    def test_ack_vector_states_and_run_lengths(self) -> None:
        options = self.options(bytes([38, 5, 0x03, 0x7F, 0xC1, 39, 3, 0x40, 0, 0]))
        nonce0, nonce1 = options[self.Option.Ack_Vector_Nonce_0], options[self.Option.Ack_Vector_Nonce_1]
        self.assertEqual([(run.state, run.run_length) for run in nonce0.vector],
                         [(self.State.Received, 3), (self.State.Received_ECN_Marked, 63),
                          (self.State.Not_Yet_Received, 1)])
        self.assertEqual((nonce0.nonce, nonce1.nonce), (0, 1))
        self.assertEqual(nonce1.vector[0].state, self.State.Received_ECN_Marked)

    def test_data_dropped_blocks(self) -> None:
        dropped = self.options(bytes([40, 4, 0x05, 0xB2, 0]))[self.Option.Data_Dropped]
        self.assertEqual([(block.dropped, block.code, block.run_length) for block in dropped.vector],
                         [(False, None, 5), (True, self.DropCode.Corrupt, 2)])

    def test_timing_and_data_checksum_options(self) -> None:
        options = self.options(bytes([41, 6, 0, 0, 1, 0, 42, 8, 0, 0, 0, 9, 0, 5, 43, 6, 0, 1, 0, 0,
                                      42, 6, 0, 0, 0, 8, 43, 4, 0, 7, 44, 6, 1, 2, 3, 4]))
        self.assertEqual(options[self.Option.Timestamp].timestamp, 256)
        echoes = options.getlist(self.Option.Timestamp_Echo)
        self.assertEqual([(echo.timestamp, echo.elapsed) for echo in echoes], [(9, 5), (8, None)])
        self.assertEqual([option.elapsed for option in options.getlist(self.Option.Elapsed_Time)], [65536, 7])
        self.assertEqual(options[self.Option.Data_Checksum].checksum, b'\x01\x02\x03\x04')

    def test_an_unknown_option_keeps_its_data(self) -> None:
        options = self.options(bytes([128, 4, 0xAA, 0xBB, 46, 2, 0, 0]))
        self.assertEqual(options[self.Option(128)].data, b'\xaa\xbb')
        self.assertEqual(options[self.Option.Multipath].length, 2)

    def test_an_option_past_the_option_area_is_refused(self) -> None:
        # The Timestamp declares 6 octets with 2 left in the area, the payload behind it.
        with self.assertRaises(self.ProtocolError):
            self.DCCP(packet(3, ack(1), bytes([2, 2, 41, 6]), data=b'\x00\x00\x00\x01'))

    def test_make_pads_to_32_bits(self) -> None:
        made = self.DCCP(type=3, ack=1, checksum=b'\x00\x00',
                         options=[(self.Option.Timestamp, {'timestamp': 1}),
                                  (self.Option.Ack_Vector_Nonce_0, {'vector': [(3, 2)]})])
        self.assertEqual(made.data[24:], bytes([41, 6, 0, 0, 0, 1, 38, 3, 0xC2, 0, 0, 0]))
        self.assertEqual(made.info.hdr_len, 36)
        self.assertRoundTrip(made.data)

    def test_make_sizes_the_variable_fields(self) -> None:
        made = self.DCCP(type=3, ack=1, checksum=b'\x00\x00', options=[
            (self.Option.NDP_Count, {'count': 0x010000}),
            (self.Option.Elapsed_Time, {'elapsed': 0x10000}),
            (self.Option.Timestamp_Echo, {'timestamp': 1, 'elapsed': 2}),
            (self.Option.Data_Dropped, {'vector': [(None, 127), (self.DropCode.Receive_Buffer, 15)]}),
            (self.Option(3), {}), (self.Option(200), {'data': b'\x01'}),
            (self.Option.Change_R, {'feature': self.Feature.ECN_Incapable, 'value': b'\x01'}),
        ])
        self.assertEqual(made.data[24:], bytes([37, 5, 1, 0, 0, 43, 6, 0, 1, 0, 0, 42, 8, 0, 0, 0, 1, 0, 2,
                                                40, 4, 0x7F, 0xAF, 3, 200, 3, 1, 34, 4, 4, 1, 0]))
        self.assertRoundTrip(made.data)

    def test_make_writes_the_fixed_layouts(self) -> None:
        made = self.DCCP(type=3, ack=1, checksum=b'\x00\x00', options=[
            (self.Option.Confirm_L, {'feature': self.Feature.Sequence_Window, 'value': b'\x00\x64'}),
            (self.Option.Timestamp_Echo, {'timestamp': 2, 'elapsed': 0x10000}),
            (self.Option.Data_Checksum, {'checksum': b'\xde\xad\xbe\xef'}),
            (self.Option.Timestamp_Echo, {'timestamp': 3}),
        ])
        self.assertEqual(made.data[24:], bytes([33, 5, 3, 0, 0x64, 42, 10, 0, 0, 0, 2, 0, 1, 0, 0,
                                                44, 6, 0xDE, 0xAD, 0xBE, 0xEF, 42, 6, 0, 0, 0, 3, 0]))
        self.assertRoundTrip(made.data)

    def test_make_takes_schemas_octets_and_parsed_options(self) -> None:
        parsed = self.options(bytes([1, 41, 6, 0, 0, 0, 7, 0]))
        rebuilt = self.DCCP(type=3, ack=1, checksum=b'\x00\x00', options=parsed)
        self.assertEqual(rebuilt.data[24:], bytes([1, 41, 6, 0, 0, 0, 7, 0]))
        layer = self.DCCP(rebuilt.data)
        given = self.DCCP(type=3, ack=1, checksum=b'\x00\x00',
                          options=[b'\x02', layer.__header__.options[1]])
        self.assertEqual(given.data[24:], bytes([2, 41, 6, 0, 0, 0, 7, 0]))

    def test_make_refuses_what_an_option_cannot_hold(self) -> None:
        for option in ((self.Option.NDP_Count, {'count': 1 << 48}),
                       (self.Option.Ack_Vector_Nonce_0, {'vector': [(4, 0)]}),
                       (self.Option.Ack_Vector_Nonce_0, {'vector': [(0, 64)]}),
                       (self.Option.Data_Dropped, {'vector': [(None, 128)]}),
                       (self.Option.Data_Dropped, {'vector': [(8, 0)]}),
                       (self.Option.Data_Dropped, {'vector': [(1, 16)]}),
                       (self.Option(3), {'data': b'\x01'}),
                       (self.Option.Init_Cookie, {'cookie': bytes(254)})):
            with self.subTest(option=option):
                with self.assertRaises(self.ProtocolError):
                    self.DCCP(type=3, checksum=b'\x00\x00', options=[option])

    def test_register_option_and_its_wrapper(self) -> None:
        from pcapkit.foundation.registry.protocols import register_dccp_option
        from pcapkit.protocols.data.transport.dccp import UnassignedOption
        from pcapkit.protocols.schema.transport.dccp import UnassignedOption as Schema_UnassignedOption
        from pcapkit.utilities.exceptions import RegistryError
        from pcapkit.utilities.warnings import RegistryWarning

        code = self.Option(130)
        seen = []

        def parser(schema: 'object', *, options: 'object') -> 'object':
            seen.append(schema.data)
            return UnassignedOption(type=schema.type, length=schema.length, data=schema.data[::-1])

        def maker(code: 'object', opt: 'object' = None, **kwargs: 'object') -> 'object':
            return Schema_UnassignedOption(type=code, length=4, data=opt.data[::-1])

        self.addCleanup(self.DCCP.__option__.pop, code, None)
        register_dccp_option(code, (parser, maker))
        options = self.options(bytes([130, 4, 1, 2]))
        self.assertEqual((set(seen), options[code].data), ({b'\x01\x02'}, b'\x02\x01'))
        with self.assertWarns(RegistryWarning):
            self.DCCP.register_option(code, 'timestamp')
        self.DCCP.register_option(code, 'timestamp')
        with self.assertRaises(RegistryError):
            register_dccp_option(code, 'nosuch')

    def test_register_dccp_dispatches_a_port(self) -> None:
        from pcapkit.foundation.registry.protocols import register_dccp
        from pcapkit.protocols.misc.raw import Raw

        class Probe(Raw):  # pylint: disable=too-few-public-methods
            """A stand-in application protocol."""

        self.addCleanup(self.DCCP.__proto__.pop, DST, None)
        register_dccp(DST, Probe)
        self.assertIsInstance(self.DCCP(packet(2, data=b'app', x=False)).payload, Probe)

        # A port's application type, and a protocol named by its module and class.
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.utilities.warnings import RegistryWarning
        with self.assertWarns(RegistryWarning):
            register_dccp(AppType.get(DST, proto=TransportProtocol.dccp), 'pcapkit.protocols.misc.raw', 'Raw')
        self.assertIs(type(self.DCCP(packet(2, data=b'app', x=False)).payload), Raw)


class DCCPChecksumTests(DCCPTestCase):
    """The checksum over the IP pseudo-header and the Checksum Coverage."""

    def parse(self, octets: bytes, cls: 'type | None' = None, *,
              verify: bool = True) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as ``cls``, IPv4 by default, and its ProtocolWarnings."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = (cls or self.IPv4)(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def status(self, octets: bytes, cls: 'type | None' = None, **kwargs: object) -> 'tuple[object, list]':
        """The DCCP checksum status of ``octets``, and its ProtocolWarnings."""
        layer, messages = self.parse(octets, cls, **kwargs)
        return layer['DCCP'].info.get('checksum_status'), messages

    def test_the_checksummed_packets_verify(self) -> None:
        for octets, cls, start in zip(CHECKSUMMED, (self.IPv4, self.IPv4, self.IPv6, self.IPv4), (20, 20, 40, 20)):
            with self.subTest(packet=octets.hex()):
                datagram = octets[start:]
                prefix = (pseudo6 if start == 40 else pseudo4)(len(datagram))
                cscov, hdr_len = datagram[5] & 0x0F, datagram[4] * 4
                covered = hdr_len + (cscov - 1) * 4 if cscov else len(datagram)
                self.assertEqual(datagram[6:8], expected(prefix, datagram, covered))
                self.assertEqual(self.status(octets, cls), (self.Status.VALID, []))
                layer, _ = self.parse(octets, cls)
                self.assertEqual(cls.from_data(layer.info).data, octets)

    def test_a_corrupted_checksum_warns(self) -> None:
        octets = CHECKSUMMED[0][:26] + b'\x8f\x3b' + CHECKSUMMED[0][28:]
        status, messages = self.status(octets)
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning, 'DCCP: checksum 0x8f3b is wrong; 0x8f3a expected')])
        layer, _ = self.parse(octets)
        self.assertEqual(self.IPv4.from_data(layer.info).data, octets)

    def test_data_past_the_coverage_is_not_covered(self) -> None:
        # CsCov 2 covers the header and the first 4 data octets; CsCov 1 none of them.
        for octets, start in ((CHECKSUMMED[1], 48), (CHECKSUMMED[3], 32)):
            with self.subTest(packet=octets.hex()):
                changed = octets[:start] + bytes(len(octets) - start)
                self.assertEqual(self.status(changed), (self.Status.VALID, []))
        changed = CHECKSUMMED[1][:47] + b'!' + CHECKSUMMED[1][48:]
        self.assertIs(self.status(changed)[0], self.Status.INVALID)

    def test_a_coverage_past_the_packet_is_invalid(self) -> None:
        octets = bytearray(CHECKSUMMED[3])
        octets[25] = 0x05  # (5 - 1) * 4 octets of data, where it has 5
        status, messages = self.status(bytes(octets))
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning,
                                     'DCCP: checksum coverage 5 runs past the 17 octets of the packet')])
        # Rebuilt inside IP-in-IP, the inner layer verifies it twice and warns once.
        tunnel = wire.ipv4(bytes(octets), proto=4)
        layer, _ = self.parse(tunnel)
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertEqual(self.IPv4.from_data(layer.info).data, tunnel)
        self.assertEqual([item.category for item in caught if issubclass(item.category, self.ChecksumWarning)],
                         [self.ChecksumWarning])

    def test_a_truncated_capture(self) -> None:
        self.assertEqual(self.status(CHECKSUMMED[0][:-1]), (self.Status.TRUNCATED, []))
        # What a reduced coverage covers can still be all there.
        self.assertEqual(self.status(CHECKSUMMED[1][:-8]), (self.Status.VALID, []))
        layer, _ = self.parse(CHECKSUMMED[0][:-1])
        self.assertEqual(self.IPv4.from_data(layer.info).data, CHECKSUMMED[0][:-1])

    def test_a_fragment_has_no_pseudo_header(self) -> None:
        octets = bytearray(CHECKSUMMED[0])
        octets[6] = 0x20  # More Fragments
        octets[10:12] = b'\x00\x00'
        octets[10:12] = wire.checksum(bytes(octets[:20])).to_bytes(2, 'big')
        self.assertEqual(self.status(bytes(octets)), (self.Status.NO_PSEUDO_HEADER, []))

    def test_off_verifies_nothing(self) -> None:
        self.assertEqual(self.status(CHECKSUMMED[0][:26] + b'\x00\x00' + CHECKSUMMED[0][28:], verify=False),
                         (None, []))

    def test_the_ip_layer_computes_it(self) -> None:
        dccp = self.DCCP(srcport=SRC, dstport=DST, type=0, seq=1, service_code=0x12345678,
                         options=[(self.Option.Change_L, {'feature': 1, 'value': b'\x02'})], payload=b'hello')
        octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='DCCP', payload=dccp).data
        self.assertEqual(octets, CHECKSUMMED[0])
        dccp = self.DCCP(srcport=SRC, dstport=DST, type=7, seq=9, ack=8, reset_code=5,
                         reset_data=b'\x20\x01\x02', payload=b'odd')
        octets = self.IPv6(src='2001:db8::1', dst='2001:db8::2', next='DCCP', payload=dccp).data
        self.assertEqual(octets, CHECKSUMMED[2])

    def test_make_takes_the_pseudo_header(self) -> None:
        pseudo = self.IP_Pseudo(src='192.0.2.1', dst='198.51.100.2', protocol='DCCP', upper_length=0)
        made = self.DCCP(srcport=SRC, dstport=DST, type=4, x=False, seq=7, ack=6, cscov=2,
                         options=[(self.Option.Timestamp, {'timestamp': 5})],
                         payload=b'0123456789abcdef', pseudo=pseudo).data
        self.assertEqual(made, CHECKSUMMED[1][20:])

    def test_a_coverage_reaching_the_end_is_written_as_zero(self) -> None:
        # As Linux's dccp_csum_outgoing: CsCov 0 wherever the coverage reaches the end.
        pseudo = self.IP_Pseudo(src='192.0.2.1', dst='198.51.100.2', protocol='DCCP', upper_length=0)
        for cscov, payload in ((15, b'abc'), (2, b'abcd')):
            with self.subTest(cscov=cscov, payload=payload):
                made = self.DCCP(type=2, x=False, ccval=5, cscov=cscov, payload=payload, pseudo=pseudo).data
                self.assertEqual(made[5], 0x50)
                self.assertEqual(made[6:8], expected(pseudo4(len(made)), made, len(made)))
                dccp = self.DCCP(type=2, x=False, ccval=5, cscov=cscov, payload=payload)
                octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='DCCP', payload=dccp).data
                self.assertEqual(octets[20:], made)
                self.assertEqual(self.status(octets), (self.Status.VALID, []))
        # One short of the end, and one written as given, keep their value.
        self.assertEqual(self.DCCP(type=2, x=False, cscov=2, payload=b'abcde', pseudo=pseudo).data[5], 2)
        self.assertEqual(self.DCCP(type=2, x=False, cscov=15, checksum=b'\x00\x00', pseudo=pseudo).data[5], 15)

    def test_off_or_given_is_written_as_is(self) -> None:
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='DCCP',
                               payload=self.DCCP(type=2, x=False)).data
        self.assertEqual(octets[26:28], b'\x00\x00')
        self.assertEqual(self.DCCP(type=2, checksum=b'\xbe\xef').data[6:8], b'\xbe\xef')
        self.assertEqual(self.DCCP(type=2).data[6:8], b'\x00\x00')


if __name__ == '__main__':
    unittest.main()
