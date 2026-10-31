# -*- coding: utf-8 -*-
"""IGMPv1, IGMPv2 and IGMPv3 headers parse and rebuild byte for byte.

GitHub issue #2439 implemented IGMPv1 (:rfc:`1112#appendix-I`) and IGMPv2
(:rfc:`2236#section-2`), which share one 8-octet message shape. GitHub issue
#2448 covers IGMPv3 (:rfc:`3376`): the Membership Query's source-list
extension and the Version 3 Membership Report's group-record list.

A type outside the four IGMPv1/v2 define, and outside the IGMPv3 Membership
Report (``0x22``), is a message no version of IGMP defines (e.g. DVMRP,
``0x13``) and is confirmed to fall back to
:class:`~pcapkit.protocols.misc.raw.Raw` rather than being decoded.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
not at module load, so that they belong to the :mod:`pcapkit` import that is
live when the test runs.

"""

from __future__ import annotations

import io
import ipaddress
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'


def internet_checksum(data: 'bytes') -> 'bytes':
    """Compute the standard IP-style ones-complement checksum.

    An independent reimplementation of :rfc:`1071#section-4.1`, with no
    pseudo-header, as IGMP specifies it (:rfc:`2236#section-2.3`,
    :rfc:`3376#section-4.1.2`). Used only to build and check fixtures:
    pcapkit does not compute or validate IGMP checksums (:issue:`2439`).

    Args:
        data: Message octets, with the checksum field itself zeroed.

    Returns:
        The 2-octet checksum.

    """
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total & 0xffff).to_bytes(2, 'big')


def igmp_packet(type_: 'int', max_resp_time: 'int', group: 'str') -> 'bytes':
    """Build a correctly-checksummed 8-octet IGMPv1/v2 message."""
    group_bytes = ipaddress.ip_address(group).packed
    zeroed = bytes([type_, max_resp_time, 0, 0]) + group_bytes
    checksum = internet_checksum(zeroed)
    return bytes([type_, max_resp_time]) + checksum + group_bytes


def igmpv3_query(max_resp_code: 'int', group: 'str', *, s_flag: 'int' = 0, qrv: 'int' = 0,
                 qqic: 'int' = 0, sources: 'tuple[str, ...]' = ()) -> 'bytes':
    """Build a correctly-checksummed IGMPv3 Query (:rfc:`3376#section-4.1`)."""
    group_bytes = ipaddress.ip_address(group).packed
    flags_byte = ((s_flag & 0x01) << 3) | (qrv & 0x07)
    src_bytes = b''.join(ipaddress.ip_address(src).packed for src in sources)
    ext = bytes([flags_byte, qqic]) + len(sources).to_bytes(2, 'big') + src_bytes
    zeroed = bytes([0x11, max_resp_code, 0, 0]) + group_bytes + ext
    checksum = internet_checksum(zeroed)
    return bytes([0x11, max_resp_code]) + checksum + group_bytes + ext


def igmpv3_group_record(record_type: 'int', multicast_address: 'str',
                        sources: 'tuple[str, ...]' = (), aux_data: 'bytes' = b'') -> 'bytes':
    """Build one IGMPv3 group record (:rfc:`3376#section-4.2.4`)."""
    mcast_bytes = ipaddress.ip_address(multicast_address).packed
    src_bytes = b''.join(ipaddress.ip_address(src).packed for src in sources)
    return (bytes([record_type, len(aux_data) // 4]) + len(sources).to_bytes(2, 'big')
            + mcast_bytes + src_bytes + aux_data)


def igmpv3_report(records: 'tuple[bytes, ...]') -> 'bytes':
    """Build a correctly-checksummed IGMPv3 Membership Report (:rfc:`3376#section-4.2`)."""
    body = b''.join(records)
    zeroed = bytes([0x22, 0, 0, 0, 0, 0]) + len(records).to_bytes(2, 'big') + body
    checksum = internet_checksum(zeroed)
    return bytes([0x22, 0]) + checksum + b'\x00\x00' + len(records).to_bytes(2, 'big') + body


#: One fixture per message type IGMPv1 and IGMPv2 define, each a correctly
#: checksummed 8-octet message. Type octets per :rfc:`1112#appendix-I`
#: (``0x11``/``0x12``, v1) and :rfc:`2236#section-2.1` (``0x11``/``0x16``/``0x17``,
#: v2's own report and leave, plus v1's report kept for backwards
#: compatibility), cross-checked against the IANA *IGMP Type Numbers*
#: registry (``0x11``, ``0x12``, ``0x16``, ``0x17``).
IGMP_PACKETS = {
    # IGMPv1 Membership Query (General Query only -- v1 has no group-specific
    # query): max_resp_time is reserved at zero (:rfc:`1112#appendix-I`).
    'v1-query': igmp_packet(0x11, 0, '0.0.0.0'),
    # IGMPv1 Membership Report.
    'v1-report': igmp_packet(0x12, 0, '224.0.0.1'),
    # IGMPv2 General Query: max_resp_time nonzero, in tenths of a second
    # (:rfc:`2236#section-2.2`).
    'v2-query-general': igmp_packet(0x11, 100, '0.0.0.0'),
    # IGMPv2 Group-Specific Query.
    'v2-query-group': igmp_packet(0x11, 100, '239.1.2.3'),
    # IGMPv2 Version 2 Membership Report.
    'v2-report': igmp_packet(0x16, 0, '239.1.2.3'),
    # IGMPv2 Leave Group.
    'v2-leave': igmp_packet(0x17, 0, '239.1.2.3'),
}

#: A DVMRP message (:rfc:`3376` Section 4's registry table; draft-ietf-idmr-dvmrp-v3-11),
#: type ``0x13``, sharing IGMP's type-number space but defined by no version
#: of IGMP. Used to confirm the fallback path for a type no IGMP version
#: defines. The IGMPv3 Membership Report (``0x22``) is a real type, so it is not
#: used here.
UNSUPPORTED_TYPE_MESSAGE = bytes([0x13, 0, 0, 0]) + bytes(4)


class IGMPRoundTripTests(unittest.TestCase):
    """Pin IGMP parsing and rebuild for every IGMPv1/v2 message type."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        for name, packet in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                parsed = IGMP(io.BytesIO(packet), len(packet))
                self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_checksum_is_parsed_correctly(self) -> None:
        """At least one checksum-validation test (standing requirement).

        Confirms the fixture's checksum is the real RFC-correct ones'
        complement checksum of the 8-octet message -- computed
        independently by :func:`internet_checksum` -- and that
        :meth:`IGMP.read <pcapkit.protocols.internet.igmp.IGMP.read>`
        reports exactly that value.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        for name, packet in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                header, checksum, rest = packet[:2], packet[2:4], packet[4:]
                expected = internet_checksum(header + b'\x00\x00' + rest)
                self.assertEqual(checksum, expected)

                parsed = IGMP(io.BytesIO(packet), len(packet))
                self.assertEqual(parsed.info.checksum, expected)

    def test_type_and_group_are_parsed(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        parsed = IGMP(io.BytesIO(IGMP_PACKETS['v2-report']), 8)
        self.assertEqual(parsed.info.type, Type.IGMPv2_Membership_Report)
        self.assertEqual(parsed.info.max_resp_time, 0)
        self.assertEqual(str(parsed.info.group), '239.1.2.3')

        query = IGMP(io.BytesIO(IGMP_PACKETS['v2-query-general']), 8)
        self.assertEqual(query.info.type, Type.IGMP_Membership_Query)
        self.assertEqual(query.info.max_resp_time, 100)
        self.assertEqual(str(query.info.group), '0.0.0.0')

    def test_v1_v2_messages_have_no_v3_extension(self) -> None:
        """Every IGMPv1/v2 fixture decodes with the IGMPv3 fields absent."""
        from pcapkit.protocols.internet.igmp import IGMP

        for name, packet in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                parsed = IGMP(io.BytesIO(packet), len(packet))
                self.assertIsNone(parsed.info.s_flag)
                self.assertIsNone(parsed.info.qrv)
                self.assertIsNone(parsed.info.qqic)
                self.assertIsNone(parsed.info.qqi)
                self.assertIsNone(parsed.info.sources)

    def test_trailing_octets_are_kept_as_raw_and_rebuilt(self) -> None:
        """Octets past a plain 8-octet IGMPv1/v2 message are kept as
        :class:`~pcapkit.protocols.misc.raw.Raw`, as :meth:`ESP.read
        <pcapkit.protocols.internet.esp.ESP.read>` keeps its own trailer.
        """
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.misc.raw import Raw

        packet = IGMP_PACKETS['v2-report'] + b'XY'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, b'XY')
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_no_trailing_octets_have_no_payload(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.misc.null import NoPayload

        parsed = IGMP(io.BytesIO(IGMP_PACKETS['v1-query']), 8)
        self.assertIsInstance(parsed.payload, NoPayload)

    def test_non_8_octet_query_raises_protocol_error(self) -> None:
        """A Membership Query of 9-11 octets is neither IGMPv1/v2 (8 octets)
        nor IGMPv3 (12 or more, :rfc:`3376#section-7.1`), so it is refused.
        """
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.utilities.exceptions import ProtocolError

        for extra in (1, 2, 3):
            packet = IGMP_PACKETS['v2-query-general'] + bytes(extra)
            with self.subTest(length=len(packet)), self.assertRaises(ProtocolError):
                IGMP(io.BytesIO(packet), len(packet))

    def test_non_8_octet_query_falls_back_to_raw_on_dispatch(self) -> None:
        """Dispatched as an IPv4 payload, a 10-octet Query falls back to
        :class:`~pcapkit.protocols.misc.raw.Raw` in full, not as IGMPv2 with
        a Raw tail.
        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        payload = IGMP_PACKETS['v2-query-general'] + b'XY'
        packet = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=payload).data
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, payload)
        self.assertNotIn('IGMPv2', str(parsed.protochain))

    def test_group_body_unpacked_alone_decides_extension_by_length(self) -> None:
        """A :class:`GroupBody` with no enclosing type reads the Query extension by length alone."""
        from pcapkit.protocols.schema.internet.igmp import GroupBody

        short = IGMP_PACKETS['v2-query-general'][1:]
        bare = GroupBody.unpack(short, len(short), {})
        self.assertIsNone(bare.ext)
        self.assertEqual(bytes(bare), short)

        query = IGMP_PACKETS['v2-query-general'] + bytes([0x02, 125, 0, 0])
        extended = GroupBody.unpack(query[1:], len(query) - 1, {})
        self.assertEqual(extended.ext.flags['qrv'], 2)
        self.assertEqual(bytes(extended), query[1:])

    def test_unsupported_type_raises_protocol_error(self) -> None:
        """:meth:`IGMP.read <pcapkit.protocols.internet.igmp.IGMP.read>` must
        reject a type no version of IGMP defines -- DVMRP (``0x13``), which
        shares the type-number space but is not dispatched by
        :func:`~pcapkit.protocols.schema.internet.igmp.igmp_body_selector`.
        The IGMPv3 Membership Report (``0x22``) is a real type, so it is not
        used as the vector.
        """
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            IGMP(io.BytesIO(UNSUPPORTED_TYPE_MESSAGE), len(UNSUPPORTED_TYPE_MESSAGE))

    def test_unsupported_type_falls_back_to_raw_on_dispatch(self) -> None:
        """Dispatched as an IPv4 payload, a DVMRP message (``0x13``) must
        fall back to :class:`~pcapkit.protocols.misc.raw.Raw` via
        :func:`~pcapkit.corekit.decorators.beholder`.
        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        made = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=UNSUPPORTED_TYPE_MESSAGE)
        packet = made.data

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, UNSUPPORTED_TYPE_MESSAGE)

    def test_payload_shorter_than_fixed_header_falls_back_to_raw(self) -> None:
        """Dispatched as an IPv4 payload, 1-7 octets of IGMP (a cut 8-octet
        header) must fall back to :class:`~pcapkit.protocols.misc.raw.Raw`
        with no :class:`~pcapkit.utilities.warnings.SchemaWarning`, for a
        Query (``0x11``) and a Membership Report (``0x22``) alike.
        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.warnings import SchemaWarning

        for first in (0x11, 0x22):
            for size in range(1, 8):
                body = bytes([first]) + bytes(range(1, size))
                with self.subTest(type=hex(first), size=size):
                    made = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=body)
                    packet = made.data
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        parsed = IPv4(io.BytesIO(packet), len(packet))

                    self.assertIsInstance(parsed.payload, Raw)
                    self.assertEqual(parsed.payload.info.packet, body)
                    self.assertFalse([w for w in caught if issubclass(w.category, SchemaWarning)])

    def test_truncated_v3_query_claiming_sources_round_trips_byte_exact(self) -> None:
        """A 16-octet Query whose header claims 3 sources, with only one
        address present, stays IGMP and its octets are reproduced exactly.

        The data-model rebuild (:meth:`IGMP.from_data`) is not checked here:
        it writes the three declared sources, zero-filling the two missing.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        packet = bytes([0x11, 0x7d, 0, 0]) + bytes([239, 1, 2, 3])
        packet += bytes([0x00, 0x7d, 0x00, 0x03]) + bytes([10, 0, 0, 1])
        self.assertEqual(len(packet), 16)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.length, 16)
        self.assertEqual(bytes(parsed), packet)


class IGMPUnitTests(unittest.TestCase):
    """Lower-level unit coverage, mirroring the AH/IPX unit tests."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_igmp_index_length_and_name(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.igmp import IGMP

        proto = object.__new__(IGMP)

        self.assertEqual(IGMP.__index__(), TransType.IGMP)
        self.assertEqual(proto.__length_hint__(), 8)
        self.assertEqual(proto.name, 'Internet Group Management Protocol')
        self.assertEqual(proto.alias, 'IGMP')

    def test_length_counts_the_type_octet(self) -> None:
        """:attr:`IGMP.length` counts the type octet as well as the body.

        :attr:`~pcapkit.protocols.schema.internet.igmp.IGMP.body` starts after
        the type octet, so the length has to add it back; otherwise every
        message's :attr:`~pcapkit.protocols.data.internet.igmp.IGMP.length`
        is one octet short of its size.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        for name, packet in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                parsed = IGMP(io.BytesIO(packet), len(packet))
                self.assertEqual(parsed.info.length, len(packet))

        report_packet = igmpv3_report((igmpv3_group_record(1, '224.0.1.1'),))
        parsed_report = IGMP(io.BytesIO(report_packet), len(report_packet))
        self.assertEqual(parsed_report.info.length, len(report_packet))

    def test_make_data_round_trip_group_address_message(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        class DummyDict(dict):
            __getattr__ = dict.__getitem__

        data = DummyDict(
            type=Type.IGMPv2_Leave_Group,
            length=8,
            max_resp_code=0,
            max_resp_time=0,
            checksum=b'\xab\xcd',
            group=ipaddress.ip_address('239.8.8.8'),
            resv=None,
            s_flag=None,
            qrv=None,
            qqic=None,
            qqi=None,
            sources=None,
            __next_type__=None,
        )
        values = IGMP._make_data(data)
        self.assertEqual(values['type'], Type.IGMPv2_Leave_Group)
        self.assertEqual(values['max_resp_code'], 0)
        self.assertEqual(values['checksum'], b'\xab\xcd')
        self.assertEqual(values['group'], ipaddress.ip_address('239.8.8.8'))
        self.assertIsNone(values['resv'])
        self.assertIsNone(values['s_flag'])
        self.assertIsNone(values['qrv'])
        self.assertIsNone(values['qqic'])
        self.assertIsNone(values['sources'])
        self.assertIn('payload', values)

    def test_make_data_round_trip_version3_report(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        class DummyDict(dict):
            __getattr__ = dict.__getitem__

        data = DummyDict(
            type=Type.IGMPv3_Membership_Report,
            length=8,
            reserved_1=0,
            checksum=b'\xab\xcd',
            reserved_2=b'\x00\x00',
            num_group_records=0,
            records=(),
            __next_type__=None,
        )
        values = IGMP._make_data(data)
        self.assertEqual(values['type'], Type.IGMPv3_Membership_Report)
        self.assertEqual(values['reserved_1'], 0)
        self.assertEqual(values['checksum'], b'\xab\xcd')
        self.assertEqual(values['reserved_2'], b'\x00\x00')
        self.assertEqual(values['records'], ())
        self.assertIn('payload', values)

    def test_make_builds_schema(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        proto = object.__new__(IGMP)
        schema = proto.make(
            type=Type.IGMPv1_Membership_Report,
            group='224.0.0.1',
        )

        self.assertEqual(schema.type, Type.IGMPv1_Membership_Report)
        self.assertEqual(schema.body.max_resp_code, 0)
        self.assertEqual(schema.body.checksum, b'\x00\x00')
        self.assertIsNone(schema.body.ext)
        self.assertEqual(bytes(schema)[4:8], ipaddress.ip_address('224.0.0.1').packed)
        self.assertEqual(len(bytes(schema)), 8)


class IGMPMakeMaxRespTimeTests(unittest.TestCase):
    """:meth:`IGMP.make <pcapkit.protocols.internet.igmp.IGMP.make>` refuses
    a ``max_resp_time`` that is not an :obj:`int` from 0 to 255.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make_rejects_bool_float_and_out_of_range(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IGMP)
        for value in (True, False, 1.5, 256, -1):
            with self.subTest(value=value), \
                    self.assertRaisesRegex(ProtocolError, rf'invalid max_resp_time: {value!r}'):
                proto.make(max_resp_time=value)  # type: ignore[arg-type]

    def test_make_accepts_0_and_255(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        proto = object.__new__(IGMP)
        for value in (0, 255):
            with self.subTest(value=value):
                self.assertEqual(proto.make(max_resp_time=value).body.max_resp_code, value)


class IGMPv3MaxRespCodeTests(unittest.TestCase):
    """The floating-point Max Resp Code/QQIC decode (:rfc:`3376#section-4.1.1`,
    :rfc:`3376#section-4.1.7`).

    :rfc:`3376#section-4.1.1` gives the formula as::

        If Max Resp Code < 128, Max Resp Time = Max Resp Code

        If Max Resp Code >= 128, Max Resp Code represents a floating-point
        value as follows:

            0 1 2 3 4 5 6 7
           +-+-+-+-+-+-+-+-+
           |1| exp | mant  |
           +-+-+-+-+-+-+-+-+

        Max Resp Time = (mant | 0x10) << (exp + 3)

    :rfc:`3376#section-4.1.7` gives the identical formula for QQIC/QQI.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_0x8c_decodes_to_22_point_4_seconds(self) -> None:
        """Hand computation for code ``0x8c`` (``0b1000_1100``):

        * bit 7 (the floating-point flag) = 1
        * bits 4-6 (``exp``) = ``000`` = 0
        * bits 0-3 (``mant``) = ``1100`` = 12

        ``Max Resp Time = (12 | 0x10) << (0 + 3) = 28 << 3 = 224``

        224 in units of 1/10 second is 22.4 seconds.
        """
        from pcapkit.protocols.internet.igmp import _decode_resp_code

        self.assertEqual(_decode_resp_code(0x8c), 224)
        self.assertEqual(224 / 10, 22.4)

    def test_decode_values_below_128_are_literal(self) -> None:
        from pcapkit.protocols.internet.igmp import _decode_resp_code

        for code in (0, 1, 100, 127):
            with self.subTest(code=code):
                self.assertEqual(_decode_resp_code(code), code)

    def test_encode_is_the_inverse_of_decode_for_exact_values(self) -> None:
        """Every value a floating-point code can represent exactly --
        ``(mant | 0x10) << (exp + 3)`` for ``mant`` in ``0..15`` and ``exp``
        in ``0..7`` -- round-trips through :func:`_encode_resp_code` and
        :func:`_decode_resp_code` to the same code and the same value.
        """
        from pcapkit.protocols.internet.igmp import _decode_resp_code, _encode_resp_code

        for exp in range(8):
            for mant in range(16):
                value = (mant | 0x10) << (exp + 3)
                with self.subTest(exp=exp, mant=mant, value=value):
                    code = _encode_resp_code(value)
                    self.assertTrue(0x80 <= code <= 0xFF)
                    self.assertEqual(_decode_resp_code(code), value)

    def test_encode_values_below_128_are_literal(self) -> None:
        from pcapkit.protocols.internet.igmp import _encode_resp_code

        for value in (0, 1, 100, 127):
            with self.subTest(value=value):
                self.assertEqual(_encode_resp_code(value), value)

    def test_query_with_max_resp_code_0x8c_decodes_max_resp_time_224(self) -> None:
        """An IGMPv3 Query whose Max Resp Code is ``0x8c`` reports
        ``max_resp_time == 224`` (22.4 seconds), not 14.0 seconds, which is
        what reading ``0x8c`` as a plain tenths-of-a-second integer (140)
        would give.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        packet = igmpv3_query(0x8c, '239.1.2.3', qqic=0x8c)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.max_resp_code, 0x8c)
        self.assertEqual(parsed.info.max_resp_time, 224)
        self.assertNotEqual(parsed.info.max_resp_time, 140)
        self.assertEqual(parsed.info.qqic, 0x8c)
        self.assertEqual(parsed.info.qqi, 224)

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_8_octet_query_max_resp_code_200_reads_200_not_3072(self) -> None:
        """An IGMPv2 Query has no extension, so its code is literal: 200 is
        20.0 seconds. Read as floating-point it would be 3072.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        packet = igmp_packet(0x11, 200, '239.1.2.3')
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.max_resp_code, 200)
        self.assertEqual(parsed.info.max_resp_time, 200)
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_make_8_octet_query_max_resp_time_255_round_trips(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        packet = IGMP(type=0x11, max_resp_time=255).data
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(len(packet), 8)
        self.assertEqual(packet[1], 255)
        self.assertEqual(parsed.info.max_resp_time, 255)

    def test_12_octet_query_max_resp_code_200_decodes_the_float(self) -> None:
        """An IGMPv3 Query of 12 octets carries the extension, so code 200
        (``0xc8``: exp 4, mant 8) decodes to ``(8 | 0x10) << 7 = 3072``.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        packet = igmpv3_query(200, '239.1.2.3')
        self.assertEqual(len(packet), 12)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.max_resp_time, 3072)
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_make_v3_query_floating_point_encodes_max_resp_time_200(self) -> None:
        """``make()`` on an IGMPv3 Query with the extension (``sources=[]``)
        encodes ``max_resp_time`` 200 as ``0x89`` (``(9 | 0x10) << 3 = 200``),
        and parsing that octet gives 200 back.
        """
        from pcapkit.protocols.internet.igmp import IGMP, _encode_resp_code

        self.assertEqual(_encode_resp_code(200), 0x89)
        packet = IGMP(type=0x11, max_resp_time=200, sources=[]).data
        self.assertEqual(len(packet), 12)
        self.assertEqual(packet[1], 0x89)

        parsed = IGMP(io.BytesIO(packet), len(packet))
        self.assertEqual(parsed.info.max_resp_time, 200)


class IGMPv3QueryTests(unittest.TestCase):
    """IGMPv3 Membership Query source-list extension (:rfc:`3376#section-4.1`)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_general_query_with_no_sources_round_trips(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        packet = igmpv3_query(100, '0.0.0.0', s_flag=0, qrv=2, qqic=125)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.max_resp_time, 100)
        self.assertEqual(str(parsed.info.group), '0.0.0.0')
        self.assertIs(parsed.info.s_flag, False)
        self.assertEqual(parsed.info.qrv, 2)
        self.assertEqual(parsed.info.qqi, 125)
        self.assertEqual(parsed.info.sources, ())

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_group_and_source_specific_query_round_trips(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        sources = ('10.0.0.1', '10.0.0.2', '10.0.0.3')
        packet = igmpv3_query(50, '239.5.5.5', s_flag=1, qrv=5, qqic=60, sources=sources)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(str(parsed.info.group), '239.5.5.5')
        self.assertIs(parsed.info.s_flag, True)
        self.assertEqual(parsed.info.qrv, 5)
        self.assertEqual(parsed.info.qqi, 60)
        self.assertEqual(
            tuple(str(src) for src in parsed.info.sources),
            sources,
        )

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_make_builds_a_v3_query_only_when_asked(self) -> None:
        """Leaving every IGMPv3-only keyword unset builds a plain IGMPv1/v2
        8-octet message; passing ``sources=[]`` builds an IGMPv3 Query with
        zero sources instead (see :meth:`IGMP.make`'s docstring).
        """
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        proto = object.__new__(IGMP)

        plain = proto.make(type=Type.IGMP_Membership_Query, max_resp_time=100, group='0.0.0.0')
        self.assertIsNone(plain.body.ext)
        self.assertEqual(len(bytes(plain)), 8)

        v3 = proto.make(type=Type.IGMP_Membership_Query, max_resp_time=100, group='0.0.0.0',
                        sources=[])
        self.assertIsNotNone(v3.body.ext)
        self.assertEqual(len(bytes(v3)), 12)

    def test_qqi_alone_triggers_the_v3_extension(self) -> None:
        """``qqi`` defaults to :data:`None`, so passing it alone is one of the
        triggers :meth:`IGMP.make` lists: ``make(qqi=125)`` builds an IGMPv3
        Query, not a plain 8-octet message.
        """
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        proto = object.__new__(IGMP)
        schema = proto.make(type=Type.IGMP_Membership_Query, group='0.0.0.0', qqi=125)

        self.assertIsNotNone(schema.body.ext)
        self.assertEqual(schema.body.ext.qqic, 125)

    def test_additional_data_after_the_source_list_is_kept_as_payload(self) -> None:
        """:rfc:`3376#section-4.1.10` permits octets past the source list
        ("Additional Data"). They are kept as payload, outside the source list,
        so they count toward neither :attr:`~pcapkit.protocols.internet.igmp.IGMP.length`
        nor the source list, and the rebuild reproduces them.
        """
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.misc.raw import Raw

        packet = igmpv3_query(0x7d, '239.1.2.3', s_flag=0, qrv=0, qqic=0x7d,
                              sources=('10.0.0.1',)) + b'\xca\xfe'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, b'\xca\xfe')
        self.assertEqual(parsed.info.length, len(packet) - 2)
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_resv_nibble_round_trips(self) -> None:
        """The Resv nibble (:rfc:`3376#section-4.1.4`) is read into the data
        model, so a non-conformant sender's value survives the rebuild instead
        of being rewritten to zero.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        packet = bytearray(igmpv3_query(0x7d, '239.1.2.3', s_flag=1, qrv=3, qqic=0x7d))
        # Byte 8 is Resv(4)/S(1)/QRV(3); flip Resv from 0 to 0xA (1010).
        packet[8] = (0xA << 4) | (packet[8] & 0x0F)
        checksum = internet_checksum(bytes([packet[0], packet[1], 0, 0]) + bytes(packet[4:]))
        packet[2:4] = checksum
        packet = bytes(packet)

        parsed = IGMP(io.BytesIO(packet), len(packet))
        self.assertEqual(parsed.info.resv, 0xA)
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)


class IGMPv3ReportTests(unittest.TestCase):
    """IGMPv3 Membership Report group-record list (:rfc:`3376#section-4.2`)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_report_with_no_group_records_round_trips(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        packet = igmpv3_report(())
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.type, Type.IGMPv3_Membership_Report)
        self.assertEqual(parsed.info.num_group_records, 0)
        self.assertEqual(parsed.info.records, ())

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_report_with_one_record_of_each_type_round_trips(self) -> None:
        """All six :rfc:`3376#section-4.2.12` group record types, one
        record each, with a mix of zero, one and multiple source addresses.
        """
        from pcapkit.const.igmp.record_type import RecordType
        from pcapkit.protocols.internet.igmp import IGMP

        records = (
            ('MODE_IS_INCLUDE', 1, '224.0.1.1', ()),
            ('MODE_IS_EXCLUDE', 2, '224.0.1.2', ('10.0.0.1',)),
            ('CHANGE_TO_INCLUDE_MODE', 3, '224.0.1.3', ()),
            ('CHANGE_TO_EXCLUDE_MODE', 4, '224.0.1.4', ('10.0.0.2',)),
            ('ALLOW_NEW_SOURCES', 5, '224.0.1.5', ('10.0.0.3', '10.0.0.4')),
            ('BLOCK_OLD_SOURCES', 6, '224.0.1.6', ('10.0.0.5',)),
        )
        raw_records = tuple(
            igmpv3_group_record(code, mcast, sources) for _, code, mcast, sources in records
        )
        packet = igmpv3_report(raw_records)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.num_group_records, 6)
        self.assertEqual(len(parsed.info.records), 6)

        for (name, code, mcast, sources), record in zip(records, parsed.info.records):
            with self.subTest(record_type=name):
                self.assertEqual(record.record_type, RecordType[name])
                self.assertEqual(record.record_type, code)
                self.assertEqual(str(record.multicast_address), mcast)
                self.assertEqual(
                    tuple(str(src) for src in record.sources),
                    sources,
                )
                self.assertEqual(record.aux_data, b'')
                self.assertEqual(record.aux_data_len, 0)

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_report_with_multiple_records_for_the_same_group(self) -> None:
        """:rfc:`3376#section-4.2.12`: a source-list change that both adds
        and removes sources is sent as two records for the same multicast
        address, one ``ALLOW_NEW_SOURCES`` and one ``BLOCK_OLD_SOURCES``.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        raw_records = (
            igmpv3_group_record(5, '239.9.9.9', ('10.1.1.1',)),
            igmpv3_group_record(6, '239.9.9.9', ('10.1.1.2',)),
        )
        packet = igmpv3_report(raw_records)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(len(parsed.info.records), 2)
        self.assertEqual(str(parsed.info.records[0].multicast_address), '239.9.9.9')
        self.assertEqual(str(parsed.info.records[1].multicast_address), '239.9.9.9')
        self.assertEqual(parsed.info.records[0].record_type, 5)
        self.assertEqual(parsed.info.records[1].record_type, 6)

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_unrecognized_record_type_is_kept_not_rejected(self) -> None:
        """:rfc:`3376#section-4.2.12`: "Unrecognized Record Type values MUST
        be silently ignored" -- i.e. parsing continues and the value is
        simply not one of the six named ones, rather than raising.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        raw_records = (igmpv3_group_record(200, '224.0.2.1'),)
        packet = igmpv3_report(raw_records)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(len(parsed.info.records), 1)
        self.assertEqual(int(parsed.info.records[0].record_type), 200)

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_additional_data_after_the_last_record_is_kept_as_payload(self) -> None:
        """:rfc:`3376#section-4.2.11` permits octets past the last group record
        ("Additional Data"). :attr:`~pcapkit.protocols.schema.internet.igmp.ReportBody.records`
        reads to the end of the message, since a count field cannot bound it
        in octets, so those octets are trimmed back out and kept as this
        message's trailing payload rather than read as a further record.
        """
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.misc.raw import Raw

        raw_records = (igmpv3_group_record(1, '224.0.1.1'),)
        packet = igmpv3_report(raw_records) + b'\xca\xfe'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.num_group_records, 1)
        self.assertEqual(len(parsed.info.records), 1)
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, b'\xca\xfe')
        self.assertEqual(parsed.info.length, len(packet) - 2)
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_reserved_fields_round_trip(self) -> None:
        """The two Reserved fields (:rfc:`3376#section-4.2.1`) are read into the
        data model, so a non-conformant sender's values survive the rebuild.
        """
        from pcapkit.protocols.internet.igmp import IGMP

        raw_records = (igmpv3_group_record(1, '224.0.1.1'),)
        packet = bytearray(igmpv3_report(raw_records))
        packet[1] = 0xFF  # Reserved octet after type.
        packet[4:6] = b'\xbe\xef'  # Reserved 16 bits before the record count.
        zeroed = bytes([packet[0], packet[1], 0, 0]) + bytes(packet[4:])
        packet[2:4] = internet_checksum(zeroed)
        packet = bytes(packet)

        parsed = IGMP(io.BytesIO(packet), len(packet))
        self.assertEqual(parsed.info.reserved_1, 0xFF)
        self.assertEqual(parsed.info.reserved_2, b'\xbe\xef')
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_make_builds_report_from_dict_records(self) -> None:
        from pcapkit.const.igmp.record_type import RecordType
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        proto = object.__new__(IGMP)
        schema = proto.make(
            type=Type.IGMPv3_Membership_Report,
            records=[
                {'record_type': RecordType.MODE_IS_INCLUDE, 'multicast_address': '224.0.3.1'},
                {'record_type': RecordType.MODE_IS_EXCLUDE, 'multicast_address': '224.0.3.2',
                 'sources': ['10.2.2.1']},
            ],
        )

        self.assertEqual(schema.type, Type.IGMPv3_Membership_Report)
        self.assertEqual(schema.body.num_group_records, 2)
        self.assertEqual(len(schema.body.records), 2)
        self.assertEqual(schema.body.records[0].record_type, RecordType.MODE_IS_INCLUDE)
        self.assertEqual(schema.body.records[1].num_sources, 1)


if __name__ == '__main__':
    unittest.main()
