# -*- coding: utf-8 -*-
"""The TCP, UDP, DCCP and SCTP makers refuse a value its field cannot hold (#2614).

The owner ruled on #2614 that :meth:`Protocol._make_uint
<pcapkit.protocols.protocol.Protocol._make_uint>` raises on a value outside its
field rather than wrapping it, and that :meth:`Protocol._make_octets
<pcapkit.protocols.protocol.Protocol._make_octets>` checks a fixed-size octet
field. So ``TCP(window=70000)`` raises ``ProtocolError: TCP: invalid window:
70000`` rather than packing ``0x1170``, and ``TCP(seq_no=-1)`` raises rather
than packing ``0xffffffff``. A bit-field given a negative value raises the
same, not the bare ``ValueError`` the field itself would, and a checksum of the
wrong size is refused, not padded or cut.

Each refusal names the field, and each table is paired with the widest value
the field holds, packed where the RFC puts it. The one exception is the
Quick-Start TTL Diff, which RFC 4782 defines modulo 256 and so wraps.

Every case builds its own octets, so this belongs to the unit tier.

"""
from __future__ import annotations

import datetime
import re
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable


class RangeTestCase(unittest.TestCase):
    """Shared assertions: the refusal is a ``ProtocolError`` naming the field."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def assertRefused(self, alias: 'str', name: 'str', value: 'Any', build: 'Callable[[], Any]') -> 'None':
        """``build()`` raises ``ProtocolError: <alias>: invalid <name>: <value>``."""
        from pcapkit.utilities.exceptions import ProtocolError

        pattern = rf'^{alias}: invalid {re.escape(name)}: {re.escape(repr(value))}$'
        with self.assertRaisesRegex(ProtocolError, pattern):
            build()

    def assertWrongSize(self, alias: 'str', name: 'str', size: 'int', value: 'bytes',
                        build: 'Callable[[], Any]') -> 'None':
        """``build()`` raises the ``ProtocolError`` of an octet field of the wrong size."""
        from pcapkit.utilities.exceptions import ProtocolError

        pattern = rf'^{alias}: invalid {re.escape(name)}: must be {size} octets, not {re.escape(repr(value))}$'
        with self.assertRaisesRegex(ProtocolError, pattern):
            build()


class TCPRangeTests(RangeTestCase):
    """:rfc:`9293#section-3.1` header fields, and the option fields."""

    def test_header_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for keyword, name, values in (('seq_no', 'sequence number', (-1, 1 << 32, True)),
                                      ('ack_no', 'acknowledgement number', (-1, 1 << 32)),
                                      ('reserved', 'reserved', (-1, 8, True)),
                                      ('window', 'window', (-1, 70000, True)),
                                      ('urgent', 'urgent pointer', (-1, 1 << 16))):
            for value in values:
                with self.subTest(field=keyword, value=value):
                    self.assertRefused('TCP', name, value, lambda: TCP(**{keyword: value}))

    def test_checksum_of_the_wrong_size_is_refused(self) -> 'None':
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for value in (b'', b'\x01', b'\x01\x02\x03'):
            with self.subTest(value=value):
                self.assertWrongSize('TCP', 'checksum', 2, value, lambda: TCP(checksum=value))

    def test_header_field_takes_its_widest_value(self) -> 'None':
        from pcapkit.protocols.transport.tcp.protocol import TCP

        raw = TCP(seq_no=0xFFFF_FFFF, ack_no=0xFFFF_FFFF, reserved=0b111, window=0xFFFF,
                  checksum=b'\x12\x34', urgent=0xFFFF).data
        self.assertEqual(raw[4:12], b'\xff' * 8)
        self.assertEqual(raw[12] & 0b1110, 0b1110)  # Data Offset, then the reserved bits, then NS
        self.assertEqual(raw[14:20], b'\xff\xff\x12\x34\xff\xff')

    def test_option_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for code, args, name, value in (
            (Option.Maximum_Segment_Size, {'mss': 1 << 16}, 'mss', 1 << 16),
            (Option.Window_Scale, {'shift': 256}, 'shift', 256),
            (Option.SACK, {'sack': [(1 << 32, 0)]}, 'left edge', 1 << 32),
            (Option.SACK, {'sack': [(0, -1)]}, 'right edge', -1),
            (Option.Timestamps, {'tsval': 1 << 32}, 'tsval', 1 << 32),
            (Option.Timestamps, {'tsecr': -1}, 'tsecr', -1),
            (Option.Partial_Order_Service_Profile, {'reserved': 64}, 'reserved', 64),
            (Option.CC, {'count': 1 << 32}, 'count', 1 << 32),
            (Option.CC_NEW, {'count': -1}, 'count', -1),
            (Option.CC_ECHO, {'count': True}, 'count', True),
            (Option.TCP_Alternate_Checksum_Request, {'algorithm': 256}, 'algorithm', 256),
            (Option.TCP_Authentication_Option, {'key_id': 256}, 'key_id', 256),
            (Option.TCP_Authentication_Option, {'next_key_id': -1}, 'next_key_id', -1),
        ):
            with self.subTest(code=code, field=name, value=value):
                self.assertRefused('TCP', f'[OptNo {code}] {name}', value,
                                   lambda: TCP(options=[(code, args)]))

    def test_user_timeout_outside_its_range_is_refused(self) -> 'None':
        """A negative timeout raises by name, not a bare ``ValueError``, and ``True`` is not one second."""
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.data import UserTimeout
        from pcapkit.protocols.transport.tcp.protocol import TCP

        code = Option.User_Timeout_Option
        for value in (-1, datetime.timedelta(seconds=-5), True, 1.5, None):
            with self.subTest(timeout=value):
                self.assertRefused('TCP', f'[OptNo {code}] timeout', value,
                                   lambda: TCP(options=[(code, {'timeout': value})]))

        edited = UserTimeout(kind=code, length=4, timeout=datetime.timedelta(seconds=-1), granularity=False)
        self.assertRefused('TCP', f'[OptNo {code}] timeout', edited.timeout,
                           lambda: object.__new__(TCP)._make_mode_timeout(code, edited))

    def test_user_timeout_takes_its_range(self) -> 'None':
        """RFC 5482 section 3: the ``G`` bit, then 15 bits of seconds or minutes."""
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        code = Option.User_Timeout_Option
        for value, wire in ((0, '1c040000'), (datetime.timedelta(0), '1c040000'),
                            (0x7FFF * 60, '1c04ffff')):
            with self.subTest(timeout=value):
                self.assertEqual(TCP(options=[(code, {'timeout': value})]).data[20:24].hex(), wire)

    def test_option_octets_of_the_wrong_size_are_refused(self) -> 'None':
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for code, keyword, size, value in ((Option.Echo, 'data', 4, b'abc'),
                                           (Option.Echo_Reply, 'data', 4, b'abcde'),
                                           (Option.MD5_Signature_Option, 'digest', 16, bytes(15))):
            with self.subTest(code=code, value=value):
                self.assertWrongSize('TCP', f'[OptNo {code}] {keyword}', size, value,
                                     lambda: TCP(options=[(code, {keyword: value})]))

    def test_mptcp_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        syn, synack, ack = {'syn': True}, {'syn': True, 'ack': True}, {'ack': True}
        for flags, subtype, args, name, value in (
            ({}, MPTCPOption.MP_CAPABLE, {'version': 16}, 'version', 16),
            ({}, MPTCPOption.MP_CAPABLE, {'flag_reserved': -1}, 'flag_reserved', -1),
            ({}, MPTCPOption.MP_CAPABLE, {'skey': 1 << 64}, 'skey', 1 << 64),
            ({}, MPTCPOption.MP_CAPABLE, {'rkey': -1}, 'rkey', -1),
            ({}, MPTCPOption.MP_CAPABLE, {'dl_len': 1 << 16}, 'dl_len', 1 << 16),
            (syn, MPTCPOption.MP_JOIN, {'reserved': 8}, 'reserved', 8),
            (syn, MPTCPOption.MP_JOIN, {'addr_id': 256}, 'addr_id', 256),
            (syn, MPTCPOption.MP_JOIN, {'token': 1 << 32}, 'token', 1 << 32),
            (syn, MPTCPOption.MP_JOIN, {'nonce': -1}, 'nonce', -1),
            (synack, MPTCPOption.MP_JOIN, {'addr_id': -1}, 'addr_id', -1),
            (synack, MPTCPOption.MP_JOIN, {'nonce': 1 << 32}, 'nonce', 1 << 32),
            (ack, MPTCPOption.MP_JOIN, {'reserved': 1 << 12}, 'reserved', 1 << 12),
            ({}, MPTCPOption.DSS, {'reserved': 128}, 'reserved', 128),
            ({}, MPTCPOption.DSS, {'ack': -1}, 'ack', -1),
            ({}, MPTCPOption.DSS, {'dsn': 1 << 64, 'ssn': 0, 'dl_len': 0}, 'dsn', 1 << 64),
            ({}, MPTCPOption.DSS, {'dsn': 0, 'ssn': 1 << 32, 'dl_len': 0}, 'ssn', 1 << 32),
            ({}, MPTCPOption.DSS, {'dsn': 0, 'ssn': 0, 'dl_len': -1}, 'dl_len', -1),
            ({}, MPTCPOption.ADD_ADDR, {'reserved': 8, 'hmac': bytes(8)}, 'reserved', 8),
            ({}, MPTCPOption.ADD_ADDR, {'addr_id': 256}, 'addr_id', 256),
            ({}, MPTCPOption.ADD_ADDR, {'port': 1 << 16}, 'port', 1 << 16),
            ({}, MPTCPOption.REMOVE_ADDR, {'reserved': 16}, 'reserved', 16),
            ({}, MPTCPOption.REMOVE_ADDR, {'addr_id': [1, 256]}, 'addr_id', 256),
            ({}, MPTCPOption.MP_PRIO, {'reserved': -1}, 'reserved', -1),
            ({}, MPTCPOption.MP_PRIO, {'addr_id': 256}, 'addr_id', 256),
            ({}, MPTCPOption.MP_FAIL, {'reserved': 1 << 12}, 'reserved', 1 << 12),
            ({}, MPTCPOption.MP_FAIL, {'dsn': 1 << 64}, 'dsn', 1 << 64),
            ({}, MPTCPOption.MP_FASTCLOSE, {'reserved': -1}, 'reserved', -1),
            ({}, MPTCPOption.MP_FASTCLOSE, {'key': -1}, 'key', -1),
        ):
            with self.subTest(subtype=subtype.name, flags=flags, field=name, value=value):
                option = (Option.Multipath_TCP, {'subtype': subtype, **args})
                self.assertRefused('TCP', f'[OptNo {Option.Multipath_TCP}] {subtype.name} {name}', value,
                                   lambda: TCP(options=[option], **flags))

    def test_mptcp_octets_of_the_wrong_size_are_refused(self) -> 'None':
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for flags, subtype, args, name, size, value in (
            ({'syn': True, 'ack': True}, MPTCPOption.MP_JOIN, {}, 'hmac', 8, bytes(7)),
            ({'ack': True}, MPTCPOption.MP_JOIN, {}, 'hmac', 20, bytes(19)),
            ({}, MPTCPOption.MP_CAPABLE, {'dl_len': 0}, 'checksum', 2, b'\x01'),
            ({}, MPTCPOption.DSS, {'dsn': 0, 'ssn': 0, 'dl_len': 0}, 'checksum', 2, b''),
        ):
            with self.subTest(subtype=subtype.name, field=name, value=value):
                option = (Option.Multipath_TCP, {'subtype': subtype, name: value, **args})
                self.assertWrongSize('TCP', f'[OptNo {Option.Multipath_TCP}] {subtype.name} {name}', size, value,
                                     lambda: TCP(options=[option], **flags))

    def test_unknown_mptcp_subtype_keeps_its_first_octet_to_four_bits(self) -> 'None':
        """The first data octet is the low nibble of the subtype octet, refused past it, not masked."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        subtype = MPTCPOption.get(14)
        self.assertRefused('TCP', f'[OptNo {Option.Multipath_TCP}] subtype {subtype} first data octet', 0xFA,
                           lambda: TCP(options=[(Option.Multipath_TCP, {'subtype': subtype, 'data': b'\xfa'})]))
        raw = TCP(options=[(Option.Multipath_TCP, {'subtype': subtype, 'data': b'\x0f\x01'})]).data
        self.assertEqual(raw[20:24], bytes([30, 4, 0xEF, 0x01]))  # RFC 8684 section 3: subtype, then 4 bits

    def test_option_field_takes_its_widest_value(self) -> 'None':
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        raw = TCP(options=[(Option.Maximum_Segment_Size, {'mss': 0xFFFF}),
                           (Option.Timestamps, {'tsval': 0xFFFF_FFFF, 'tsecr': 0xFFFF_FFFF}),
                           (Option.Multipath_TCP, {'subtype': MPTCPOption.MP_FASTCLOSE, 'key': (1 << 64) - 1})]).data
        self.assertEqual(raw[20:24], b'\x02\x04\xff\xff')
        self.assertEqual(raw[24:34], b'\x08\x0a' + b'\xff' * 8)
        self.assertEqual(raw[34:46], bytes([30, 12, MPTCPOption.MP_FASTCLOSE << 4, 0]) + b'\xff' * 8)

    def test_quick_start_ttl_diff_wraps_modulo_256(self) -> 'None':
        """RFC 4782 section 4.2 defines the TTL Diff modulo 256, so it wraps and is not refused."""
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for value, octet in ((-1, 0xFF), (256, 0x00), (255, 0xFF), (300, 0x2C)):
            with self.subTest(diff=value):
                raw = TCP(options=[(Option.Quick_Start_Response, {'rate': 0, 'diff': value})]).data
                # Kind, Length, Resv. and Rate (both zero), then the TTL Diff octet.
                self.assertEqual(raw[20:24], bytes([Option.Quick_Start_Response, 8, 0, octet]))


class UDPRangeTests(RangeTestCase):
    """:rfc:`768` Length and Checksum."""

    def test_length_outside_16_bits_is_refused(self) -> 'None':
        from pcapkit.protocols.transport.udp.protocol import UDP

        for value in (-1, 1 << 16, True):
            with self.subTest(total_length=value):
                self.assertRefused('UDP', 'length', value, lambda: UDP(total_length=value))
        self.assertRefused('UDP', 'length', 1 << 16, lambda: UDP(payload=bytes(0xFFF8)))

    def test_checksum_of_the_wrong_size_is_refused(self) -> 'None':
        from pcapkit.protocols.transport.udp.protocol import UDP

        for value in (b'\x01', b'\x01\x02\x03'):
            with self.subTest(value=value):
                self.assertWrongSize('UDP', 'checksum', 2, value, lambda: UDP(checksum=value))

    def test_length_takes_its_widest_value_and_a_jumbogram_zero(self) -> 'None':
        from pcapkit.protocols.transport.udp.protocol import UDP

        self.assertEqual(UDP(payload=bytes(0xFFF7)).data[4:6], b'\xff\xff')
        self.assertEqual(UDP(total_length=0xFFFF, checksum=b'\x00\x00').data, bytes(4) + b'\xff\xff' + bytes(2))
        # A jumbogram's Length is zero (RFC 2675 section 4).
        self.assertEqual(UDP(total_length=0, payload=b'x', checksum=b'\x00\x00').data[4:6], b'\x00\x00')


class DCCPRangeTests(RangeTestCase):
    """:rfc:`4340#section-5.1` generic header, its subheaders, and the options."""

    def test_header_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.protocols.transport.dccp.protocol import DCCP

        for args, name, value in (({'reserved': 8}, 'reserved', 8),
                                  ({'ccval': 16}, 'ccval', 16),
                                  ({'cscov': -1}, 'cscov', -1),
                                  ({'seq_reserved': 256}, 'seq_reserved', 256),
                                  ({'seq': 1 << 48}, 'sequence number', 1 << 48),
                                  ({'x': False, 'seq': 1 << 24}, 'sequence number', 1 << 24),
                                  ({'type': 3, 'ack_reserved': 1 << 16}, 'ack_reserved', 1 << 16),
                                  ({'type': 3, 'x': False, 'ack_reserved': 256}, 'ack_reserved', 256),
                                  ({'type': 3, 'ack': -1}, 'acknowledgement number', -1),
                                  ({'service_code': 1 << 32}, 'service code', 1 << 32)):
            with self.subTest(args=args):
                self.assertRefused('DCCP', name, value, lambda: DCCP(**args))

    def test_header_octets_of_the_wrong_size_are_refused(self) -> 'None':
        from pcapkit.protocols.transport.dccp.protocol import DCCP

        self.assertWrongSize('DCCP', 'checksum', 2, b'\x01', lambda: DCCP(checksum=b'\x01'))
        self.assertWrongSize('DCCP', 'reset data', 3, b'\x01\x02',
                             lambda: DCCP(type=7, reset_data=b'\x01\x02'))

    def test_option_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.const.dccp.option import Option
        from pcapkit.protocols.transport.dccp.protocol import DCCP

        for code, args, name, value in ((Option.NDP_Count, {'count': -1}, 'NDP count', -1),
                                        (Option.Timestamp, {'timestamp': 1 << 32}, 'timestamp', 1 << 32),
                                        (Option.Timestamp_Echo, {'timestamp': -1}, 'timestamp', -1),
                                        (Option.Timestamp_Echo, {'elapsed': 1 << 32}, 'elapsed', 1 << 32),
                                        (Option.Elapsed_Time, {'elapsed': -1}, 'elapsed', -1)):
            with self.subTest(code=code, args=args):
                self.assertRefused('DCCP', f'[Opt {code}] {name}', value,
                                   lambda: DCCP(type=3, checksum=b'\x00\x00', options=[(code, args)]))

    def test_field_takes_its_widest_value(self) -> 'None':
        from pcapkit.const.dccp.option import Option
        from pcapkit.protocols.transport.dccp.protocol import DCCP

        # X clear: a 24-bit Sequence Number at octet 9, then a reserved octet and a
        # 24-bit Acknowledgement Number (RFC 4340 section 5.1).
        raw = DCCP(type=3, x=False, seq=0xFF_FFFF, ack_reserved=0xFF, ack=0xFF_FFFF, checksum=b'\x00\x00',
                   options=[(Option.NDP_Count, {'count': 0xFFFF}), (Option.NDP_Count, {'count': 0})]).data
        self.assertEqual(raw[9:16], b'\xff' * 7)
        # The fewest octets that hold the count, and at least one (RFC 4340 section 7.7).
        self.assertEqual(raw[16:23], bytes([37, 4, 0xFF, 0xFF, 37, 3, 0]))


class SCTPRangeTests(RangeTestCase):
    """:rfc:`9260#section-3` common header, chunks, parameters and error causes."""

    def test_header_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        for value in (-1, 1 << 32, True):
            with self.subTest(vtag=value):
                self.assertRefused('SCTP', 'verification tag', value, lambda: SCTP(vtag=value))
        self.assertWrongSize('SCTP', 'checksum', 4, b'\x01\x02\x03', lambda: SCTP(chksum=b'\x01\x02\x03'))

    def test_chunk_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        data = {'data': b'x'}
        for code, args, name, value in (
            (Chunk.Payload_Data, {**data, 'reserved': 16}, 'reserved', 16),
            (Chunk.Payload_Data, {**data, 'tsn': 1 << 32}, 'tsn', 1 << 32),
            (Chunk.Payload_Data, {**data, 'stream_id': 1 << 16}, 'stream_id', 1 << 16),
            (Chunk.Payload_Data, {**data, 'stream_seq': -1}, 'stream_seq', -1),
            (Chunk.Payload_Data, {**data, 'ppid': 1 << 32}, 'ppid', 1 << 32),
            (Chunk.Payload_Data, {'data': bytes(0xFFF0)}, 'length', 1 << 16),
            (Chunk.Initiation, {'init_tag': 1 << 32}, 'init_tag', 1 << 32),
            (Chunk.Initiation, {'a_rwnd': -1}, 'a_rwnd', -1),
            (Chunk.Initiation, {'outbound_streams': 1 << 16}, 'outbound_streams', 1 << 16),
            (Chunk.Initiation, {'inbound_streams': -1}, 'inbound_streams', -1),
            (Chunk.Initiation, {'init_tsn': 1 << 32}, 'init_tsn', 1 << 32),
            (Chunk.Initiation_Acknowledgement, {'init_tag': -1}, 'init_tag', -1),
            (Chunk.Selective_Acknowledgement, {'cum_tsn_ack': 1 << 32}, 'cum_tsn_ack', 1 << 32),
            (Chunk.Selective_Acknowledgement, {'a_rwnd': -1}, 'a_rwnd', -1),
            (Chunk.Selective_Acknowledgement, {'gap_blocks': [(1 << 16, 1)]}, 'gap block start', 1 << 16),
            (Chunk.Selective_Acknowledgement, {'gap_blocks': [(1, -1)]}, 'gap block end', -1),
            (Chunk.Selective_Acknowledgement, {'dup_tsn': [1, 1 << 32]}, 'dup_tsn', 1 << 32),
            (Chunk.Abort, {'reserved': 128}, 'reserved', 128),
            (Chunk.Shutdown, {'cum_tsn_ack': -1}, 'cum_tsn_ack', -1),
            (Chunk.Shutdown_Complete, {'reserved': -1}, 'reserved', -1),
            (Chunk.State_Cookie, {'cookie': bytes(0xFFFC)}, 'length', 1 << 16),
        ):
            with self.subTest(code=code, field=name):
                self.assertRefused('SCTP', f'[Chunk {code}] {name}', value,
                                   lambda: SCTP(chunks=[(code, args)]))

    def test_parameter_and_cause_field_outside_its_width_is_refused(self) -> 'None':
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        for chunk, code, nested, args, name, value in (
            (Chunk.Initiation, Parameter.Cookie_Preservative, 'parameters', {'increment': 1 << 32},
             'increment', 1 << 32),
            (Chunk.Heartbeat_Request, Parameter.Heartbeat_Info, 'parameters', {'info': bytes(0xFFFC)},
             'length', 1 << 16),
            (Chunk.Operation_Error, CauseCode.Invalid_Stream_Identifier, 'error', {'stream_id': 1 << 16},
             'stream_id', 1 << 16),
            (Chunk.Operation_Error, CauseCode.Stale_Cookie, 'error', {'staleness': -1}, 'staleness', -1),
            (Chunk.Abort, CauseCode.No_User_Data, 'error', {'tsn': 1 << 32}, 'tsn', 1 << 32),
            (Chunk.Abort, CauseCode.User_Initiated_Abort, 'error', {'info': bytes(0xFFFC)}, 'length', 1 << 16),
        ):
            kind = 'Param' if nested == 'parameters' else 'Cause'
            with self.subTest(code=code, field=name):
                self.assertRefused('SCTP', f'[{kind} {code}] {name}', value,
                                   lambda: SCTP(chunks=[(chunk, {nested: [(code, args)]})]))

    def test_field_takes_its_widest_value(self) -> 'None':
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        raw = SCTP(vtag=0xFFFF_FFFF, chunks=[(Chunk.Payload_Data, {
            'data': b'x', 'tsn': 0xFFFF_FFFF, 'stream_id': 0xFFFF, 'stream_seq': 0xFFFF, 'ppid': 0xFFFF_FFFF,
        })]).data
        self.assertEqual(raw[4:8], b'\xff' * 4)
        # RFC 9260 section 3.3.1: TSN, Stream Identifier, Stream Sequence Number, then the PPID.
        self.assertEqual(raw[12:16], b'\x00\x03\x00\x11')
        self.assertEqual(raw[16:28], b'\xff' * 12)


if __name__ == '__main__':
    unittest.main()
