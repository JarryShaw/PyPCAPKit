# -*- coding: utf-8 -*-
"""IGMPv1, IGMPv2 and IGMPv3 messages parse and rebuild byte for byte.

GitHub issue #2439 implemented IGMPv1 (:rfc:`1112#appendix-I`) and IGMPv2
(:rfc:`2236#section-2`), which share one 8-octet message shape, as the
concrete :class:`~pcapkit.protocols.internet.igmpv1.IGMP` and
:class:`~pcapkit.protocols.internet.igmpv2.IGMP` siblings of the abstract
:class:`~pcapkit.protocols.internet.igmp.IGMP` base. GitHub issue #2448
extends the same three-sibling pattern with a third, :class:`IGMPv3
<pcapkit.protocols.internet.igmpv3.IGMP>` (:rfc:`3376`): the Membership
Query's source-list extension and the Version 3 Membership Report's
group-record list, both materially different shapes of their own.

Each case parses its octets with the concrete class for the version it
names; the abstract base cannot be built. A type none of the three versions
define falls back to :class:`~pcapkit.protocols.misc.raw.Raw`, as does a
Membership Query of 9 to 11 octets, which is neither IGMPv1/v2 (8) nor
IGMPv3 (12 or more) (:rfc:`3376#section-7.1`).

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
    """Compute the IP-style ones'-complement checksum (:rfc:`1071#section-4.1`).

    Fixture builder only: pcapkit does not compute or validate IGMP checksums.

    Args:
        data: Message octets, with the checksum field zeroed.

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


def igmp_query(max_resp_time: 'int', tail: 'bytes') -> 'bytes':
    """Build a correctly-checksummed Membership Query (type ``0x11``) of
    General Query shape, followed by ``tail``, with the checksum covering
    the whole message as :rfc:`3376#section-4.1.2` specifies."""
    zeroed = bytes([0x11, max_resp_time, 0, 0]) + bytes(4) + tail
    checksum = internet_checksum(zeroed)
    return zeroed[:2] + checksum + zeroed[4:]


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


def igmp_class(version: 'str'):
    """Return the concrete class for ``version``: ``'IGMPv1'``, ``'IGMPv2'`` or ``'IGMPv3'``."""
    from pcapkit.protocols.internet import (  # pylint: disable=import-outside-toplevel
        igmpv1, igmpv2, igmpv3)
    return {'IGMPv1': igmpv1.IGMP, 'IGMPv2': igmpv2.IGMP, 'IGMPv3': igmpv3.IGMP}[version]


#: One fixture per message type IGMPv1 and IGMPv2 define, each a correctly
#: checksummed 8-octet message, with the version it is read as. Type octets
#: per :rfc:`1112#appendix-I` (``0x11``/``0x12``, v1) and :rfc:`2236#section-2.1`
#: (``0x11``/``0x16``/``0x17``, v2's own report and leave, plus v1's report
#: kept for backwards compatibility), cross-checked against the IANA *IGMP
#: Type Numbers* registry (``0x11``, ``0x12``, ``0x16``, ``0x17``).
IGMP_PACKETS = {
    # IGMPv1 Membership Query (General Query only -- v1 has no group-specific
    # query): max_resp_time is reserved at zero (:rfc:`1112#appendix-I`).
    'v1-query': (igmp_packet(0x11, 0, '0.0.0.0'), 'IGMPv1'),
    # IGMPv1 Membership Report.
    'v1-report': (igmp_packet(0x12, 0, '224.0.0.1'), 'IGMPv1'),
    # IGMPv2 General Query: max_resp_time nonzero, in tenths of a second
    # (:rfc:`2236#section-2.2`).
    'v2-query-general': (igmp_packet(0x11, 100, '0.0.0.0'), 'IGMPv2'),
    # IGMPv2 Group-Specific Query.
    'v2-query-group': (igmp_packet(0x11, 100, '239.1.2.3'), 'IGMPv2'),
    # IGMPv2 Version 2 Membership Report.
    'v2-report': (igmp_packet(0x16, 0, '239.1.2.3'), 'IGMPv2'),
    # IGMPv2 Leave Group.
    'v2-leave': (igmp_packet(0x17, 0, '239.1.2.3'), 'IGMPv2'),
}

#: An IGMPv3 General Query (:rfc:`3376#section-4.1`): the 8 octets an IGMPv2
#: Query also carries, then Resv/S/QRV (``0x02``), QQIC (``125``) and a zero
#: Number of Sources -- 12 octets in all. The type octet and the first 8
#: octets alone cannot tell it from an IGMPv2 General Query; only the length
#: does (:rfc:`3376#section-7.1`), so it must not be labelled IGMPv2.
IGMPV3_QUERY = igmpv3_query(100, '0.0.0.0', s_flag=0, qrv=2, qqic=125)

#: An IGMPv3 Membership Report (:rfc:`3376#section-4.2`, type ``0x22``) with
#: zero group records, checksum and reserved fields zeroed.
IGMPV3_REPORT = igmpv3_report(())

#: One fixture per message type all three IGMP versions define.
IGMPV3_PACKETS = {
    'v3-query': (IGMPV3_QUERY, 'IGMPv3'),
    'v3-report': (IGMPV3_REPORT, 'IGMPv3'),
}

#: A Membership Query of neither 8 nor 12-or-more octets, which
#: :rfc:`3376#section-7.1` says must be silently ignored: neither an
#: IGMPv1/v2 nor an IGMPv3 message.
IGMP_QUERY_10_OCTETS = igmp_query(100, b'\x00\x00')


class IGMPRoundTripTests(unittest.TestCase):
    """Pin IGMP parsing and rebuild for every message type all three versions define."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        for name, (packet, version) in {**IGMP_PACKETS, **IGMPV3_PACKETS}.items():
            with self.subTest(packet=name):
                cls = igmp_class(version)
                parsed = cls(io.BytesIO(packet), len(packet))
                self.assertEqual(cls.from_data(parsed.info).data, packet)

    def test_checksum_is_parsed_correctly(self) -> None:
        """The fixture's checksum is the RFC-correct ones'-complement checksum
        of the message, computed independently by :func:`internet_checksum`,
        and the parser reports exactly that value.
        """
        for name, (packet, version) in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                header, checksum, rest = packet[:2], packet[2:4], packet[4:]
                expected = internet_checksum(header + b'\x00\x00' + rest)
                self.assertEqual(checksum, expected)

                cls = igmp_class(version)
                parsed = cls(io.BytesIO(packet), len(packet))
                self.assertEqual(parsed.info.checksum, expected)

    def test_type_and_group_are_parsed(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmpv2 import IGMP

        parsed = IGMP(io.BytesIO(IGMP_PACKETS['v2-report'][0]), 8)
        self.assertEqual(parsed.info.type, Type.IGMPv2_Membership_Report)
        self.assertEqual(parsed.info.max_resp_time, 0)
        self.assertEqual(str(parsed.info.group), '239.1.2.3')

        query = IGMP(io.BytesIO(IGMP_PACKETS['v2-query-general'][0]), 8)
        self.assertEqual(query.info.type, Type.IGMP_Membership_Query)
        self.assertEqual(query.info.max_resp_time, 100)
        self.assertEqual(str(query.info.group), '0.0.0.0')

    def test_trailing_octets_are_kept_as_raw_and_rebuilt(self) -> None:
        """Octets past the 8-octet header have no next-protocol field to
        dispatch on, so they are kept as
        :class:`~pcapkit.protocols.misc.raw.Raw`, as :meth:`ESP.read
        <pcapkit.protocols.internet.esp.ESP.read>` keeps its own trailer.
        """
        from pcapkit.protocols.internet.igmpv2 import IGMP
        from pcapkit.protocols.misc.raw import Raw

        packet = IGMP_PACKETS['v2-report'][0] + b'XY'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, b'XY')
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_no_trailing_octets_have_no_payload(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP
        from pcapkit.protocols.misc.null import NoPayload

        parsed = IGMP(io.BytesIO(IGMP_PACKETS['v1-query'][0]), 8)
        self.assertIsInstance(parsed.payload, NoPayload)

    def test_non_v1_v2_type_raises_protocol_error(self) -> None:
        """Reading a type outside the IGMPv1/v2 values, such as an IGMPv3
        Membership Report (``0x22``), must be refused by the v1/v2 classes
        rather than decoded through the 8-octet layout, which would misread
        the "reserved" and "number of group records" octets as a group
        address (#2439).
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for cls in (IGMPv1, IGMPv2):
            with self.subTest(cls=cls.__module__), self.assertRaises(ProtocolError):
                cls(io.BytesIO(IGMPV3_REPORT), len(IGMPV3_REPORT))

    def test_non_v1_v2_type_dispatches_to_igmpv3(self) -> None:
        """Dispatched as an IPv4 payload, an IGMPv3 Membership Report must
        reach :class:`~pcapkit.protocols.internet.igmpv3.IGMP`, not be
        mis-decoded by IGMPv1/v2's 8-octet layout with ``group=0.0.0.1``
        (#2439, #2448).
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3
        from pcapkit.protocols.internet.ipv4 import IPv4

        made = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=IGMPV3_REPORT)
        packet = made.data
        parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, IGMPv3)
        self.assertEqual(parsed.payload.info.num_group_records, 0)

    def test_non_8_octet_query_raises_protocol_error_on_v1_v2(self) -> None:
        """A Membership Query is IGMPv1/v2 only at exactly 8 octets
        (:rfc:`3376#section-7.1`): a 12-octet IGMPv3 General Query and a
        10-octet Query must be refused, not labelled ``IGMPv2`` on the
        strength of a nonzero Max Resp Code (#2439).
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for cls in (IGMPv1, IGMPv2):
            for name, packet in (('v3-query', IGMPV3_QUERY), ('10-octet-query', IGMP_QUERY_10_OCTETS)):
                with self.subTest(cls=cls.__module__, packet=name), self.assertRaises(ProtocolError):
                    cls(io.BytesIO(packet), len(packet))

    def test_12_octet_query_dispatches_to_igmpv3(self) -> None:
        """Dispatched as an IPv4 payload, a 12-octet Query reaches
        :class:`~pcapkit.protocols.internet.igmpv3.IGMP`, not ``IPv4:IGMPv2:Raw``.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3
        from pcapkit.protocols.internet.ipv4 import IPv4

        packet = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=IGMPV3_QUERY).data
        parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, IGMPv3)
        self.assertEqual(parsed.payload.info.qrv, 2)

    def test_10_octet_query_falls_back_to_raw_on_dispatch(self) -> None:
        """Dispatched as an IPv4 payload, a 10-octet Query -- neither
        IGMPv1/v2 (8) nor IGMPv3 (12 or more) -- falls back to
        :class:`~pcapkit.protocols.misc.raw.Raw` in full, not as IGMPv2 with
        a Raw tail and not as IGMPv3.
        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        packet = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1',
                      payload=IGMP_QUERY_10_OCTETS).data
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, IGMP_QUERY_10_OCTETS)
        self.assertNotIn('IGMPv2', str(parsed.protochain))
        self.assertNotIn('IGMPv3', str(parsed.protochain))


class IGMPReadTests(unittest.TestCase):
    """Pin the version identification of :meth:`read` and its refusal paths,
    including the one ambiguous message length (#2439, #2448).
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_alias_names_the_version_read(self) -> None:
        """``alias`` follows the concrete class, and each concrete class is an
        instance of the :class:`~pcapkit.protocols.internet.igmp.IGMP` base.
        """
        from pcapkit.protocols.internet.igmp import IGMP as IGMPBase

        for name, (packet, version) in {**IGMP_PACKETS, **IGMPV3_PACKETS}.items():
            with self.subTest(packet=name):
                parsed = igmp_class(version)(io.BytesIO(packet), len(packet))
                self.assertIsInstance(parsed, IGMPBase)
                self.assertEqual(parsed.alias, version)

    def test_refusals_name_the_version_refused(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3
        from pcapkit.utilities.exceptions import ProtocolError

        v1_report, v2_report = IGMP_PACKETS['v1-report'][0], IGMP_PACKETS['v2-report'][0]
        with self.assertRaisesRegex(ProtocolError, r'^IGMPv1: .+ is not an IGMPv1 message \(8 octets\)'):
            IGMPv1(io.BytesIO(v2_report), len(v2_report))
        with self.assertRaisesRegex(ProtocolError, r'^IGMPv2: .+ is not an IGMPv2 message \(8 octets\)'):
            IGMPv2(io.BytesIO(v1_report), len(v1_report))
        with self.assertRaisesRegex(ProtocolError, r'^IGMPv3: .+ is not an IGMPv3 message \(8 octets\)'):
            IGMPv3(io.BytesIO(v1_report), len(v1_report))

    def test_membership_query_max_resp_time_zero_is_v1(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP

        packet = igmp_packet(0x11, 0, '0.0.0.0')
        parsed = IGMP(io.BytesIO(packet), len(packet))
        self.assertEqual(parsed.alias, 'IGMPv1')

    def test_membership_query_max_resp_time_nonzero_is_v2(self) -> None:
        from pcapkit.protocols.internet.igmpv2 import IGMP

        packet = igmp_packet(0x11, 1, '0.0.0.0')
        parsed = IGMP(io.BytesIO(packet), len(packet))
        self.assertEqual(parsed.alias, 'IGMPv2')

    def test_classify_rejects_a_non_igmp_type(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        self.assertEqual(IGMP._classify(Type.DVMRP, 0, 8), 0)

    def test_classify_reads_a_query_s_version_from_its_length(self) -> None:
        """An 8-octet Membership Query is IGMPv1/v2; one of 12 or more octets
        is IGMPv3; one of 9 to 11 is neither (:rfc:`3376#section-7.1`). A
        Report or Leave keeps its version whatever trails it
        (:rfc:`2236#section-2.5`), and the IGMPv3 Report is always IGMPv3.
        """
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        query = Type.IGMP_Membership_Query
        self.assertEqual(IGMP._classify(query, 0, 8), 1)
        self.assertEqual(IGMP._classify(query, 100, 8), 2)
        for length in (9, 10, 11):
            for max_resp_time in (0, 100):
                with self.subTest(length=length, max_resp_time=max_resp_time):
                    self.assertEqual(IGMP._classify(query, max_resp_time, length), 0)
        for length in (12, 16):
            for max_resp_time in (0, 100):
                with self.subTest(length=length, max_resp_time=max_resp_time):
                    self.assertEqual(IGMP._classify(query, max_resp_time, length), 3)
        self.assertEqual(IGMP._classify(Type.IGMPv1_Membership_Report, 0, 10), 1)
        self.assertEqual(IGMP._classify(Type.IGMPv2_Membership_Report, 0, 10), 2)
        self.assertEqual(IGMP._classify(Type.IGMPv2_Leave_Group, 0, 10), 2)
        self.assertEqual(IGMP._classify(Type.IGMPv3_Membership_Report, 0, 8), 3)
        self.assertEqual(IGMP._classify(Type.IGMPv3_Membership_Report, 0, 500), 3)


class IGMPVersionedClassTests(unittest.TestCase):
    """The concrete IGMPv1, IGMPv2 and IGMPv3 classes, and the abstract base
    they share."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_base_is_abstract(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        self.assertIn('version', IGMP.__abstractmethods__)
        packet = IGMP_PACKETS['v2-report'][0]
        with self.assertRaises(TypeError):
            IGMP(io.BytesIO(packet), len(packet))  # type: ignore[abstract]

    def test_id_and_version(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3

        self.assertEqual(IGMPv1.id(), ('IGMP', 'IGMPv1'))
        self.assertEqual(IGMPv2.id(), ('IGMP', 'IGMPv2'))
        self.assertEqual(IGMPv3.id(), ('IGMP', 'IGMPv3'))
        self.assertEqual(object.__new__(IGMPv1).version, 1)
        self.assertEqual(object.__new__(IGMPv2).version, 2)
        self.assertEqual(object.__new__(IGMPv3).version, 3)

    def test_base_id_covers_all_three_versions(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        self.assertEqual(IGMP.id(), ('IGMP', 'IGMPv1', 'IGMPv2', 'IGMPv3'))

    def test_each_version_narrows_the_base_id(self) -> None:
        v1, v2, v3 = igmp_class('IGMPv1'), igmp_class('IGMPv2'), igmp_class('IGMPv3')
        self.assertEqual(v1.id(), ('IGMP', 'IGMPv1'))
        self.assertEqual(v2.id(), ('IGMP', 'IGMPv2'))
        self.assertEqual(v3.id(), ('IGMP', 'IGMPv3'))
        self.assertNotIn('IGMPv2', v1.id())
        self.assertNotIn('IGMPv3', v1.id())
        self.assertNotIn('IGMPv1', v2.id())
        self.assertNotIn('IGMPv3', v2.id())
        self.assertNotIn('IGMPv1', v3.id())
        self.assertNotIn('IGMPv2', v3.id())

    def test_igmpv1_parses_its_own_messages_directly(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1

        for name in ('v1-query', 'v1-report'):
            packet, _version = IGMP_PACKETS[name]
            with self.subTest(packet=name):
                parsed = IGMPv1(io.BytesIO(packet), len(packet))
                self.assertEqual(parsed.alias, 'IGMPv1')

    def test_igmpv1_rejects_a_v2_only_message(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.utilities.exceptions import ProtocolError

        packet, _version = IGMP_PACKETS['v2-report']
        with self.assertRaises(ProtocolError):
            IGMPv1(io.BytesIO(packet), len(packet))

    def test_igmpv1_rejects_a_query_with_nonzero_max_resp_time(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.utilities.exceptions import ProtocolError

        packet, _version = IGMP_PACKETS['v2-query-general']
        with self.assertRaises(ProtocolError):
            IGMPv1(io.BytesIO(packet), len(packet))

    def test_igmpv2_parses_its_own_messages_directly(self) -> None:
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2

        for name in ('v2-query-general', 'v2-query-group', 'v2-report', 'v2-leave'):
            packet, _version = IGMP_PACKETS[name]
            with self.subTest(packet=name):
                parsed = IGMPv2(io.BytesIO(packet), len(packet))
                self.assertEqual(parsed.alias, 'IGMPv2')

    def test_igmpv2_rejects_a_v1_only_message(self) -> None:
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        packet, _version = IGMP_PACKETS['v1-report']
        with self.assertRaises(ProtocolError):
            IGMPv2(io.BytesIO(packet), len(packet))

    def test_igmpv2_rejects_a_query_with_zero_max_resp_time(self) -> None:
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        packet, _version = IGMP_PACKETS['v1-query']
        with self.assertRaises(ProtocolError):
            IGMPv2(io.BytesIO(packet), len(packet))

    def test_igmpv2_rejects_a_non_8_octet_query(self) -> None:
        """A 12-octet IGMPv3 General Query or a 10-octet Query is refused by
        the IGMPv2 class, as a v1 message is (:rfc:`3376#section-7.1`).
        """
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for name, packet in (('v3-query', IGMPV3_QUERY), ('10-octet-query', IGMP_QUERY_10_OCTETS)):
            with self.subTest(packet=name), self.assertRaises(ProtocolError):
                IGMPv2(io.BytesIO(packet), len(packet))

    def test_igmpv1_rejects_a_non_8_octet_query(self) -> None:
        """Likewise for the IGMPv1 class, with a zero Max Resp Code so the
        length is the only thing refusing it (:rfc:`3376#section-7.1`).
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.utilities.exceptions import ProtocolError

        for tail in (bytes(4), bytes(2)):
            packet = igmp_query(0, tail)
            with self.subTest(length=len(packet)), self.assertRaises(ProtocolError):
                IGMPv1(io.BytesIO(packet), len(packet))

    def test_igmpv3_parses_its_own_messages_directly(self) -> None:
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3

        for name, (packet, _version) in IGMPV3_PACKETS.items():
            with self.subTest(packet=name):
                parsed = IGMPv3(io.BytesIO(packet), len(packet))
                self.assertEqual(parsed.alias, 'IGMPv3')

    def test_igmpv3_rejects_an_8_octet_v1_or_v2_message(self) -> None:
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3
        from pcapkit.utilities.exceptions import ProtocolError

        for name in ('v1-query', 'v1-report', 'v2-query-general', 'v2-report', 'v2-leave'):
            packet, _version = IGMP_PACKETS[name]
            with self.subTest(packet=name), self.assertRaises(ProtocolError):
                IGMPv3(io.BytesIO(packet), len(packet))

    def test_igmpv3_rejects_a_9_to_11_octet_query(self) -> None:
        """Neither IGMPv1/v2 (8 octets) nor IGMPv3 (12 or more) claims a
        Membership Query of 9 to 11 octets; the IGMPv3 class refuses it too.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            IGMPv3(io.BytesIO(IGMP_QUERY_10_OCTETS), len(IGMP_QUERY_10_OCTETS))

    def test_versions_take_the_length_from_the_data_when_none_is_given(self) -> None:
        """Without a ``length``, each version reads the whole of ``bytes``
        data: trailing octets become :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.protocols.misc.raw import Raw

        cases = (
            (IGMPv1, 'v1-report'),
            (IGMPv2, 'v2-report'),
        )
        for cls, name in cases:
            packet, version = IGMP_PACKETS[name]
            with self.subTest(version=version):
                parsed = cls(packet)
                self.assertEqual(parsed.alias, version)
                self.assertEqual(len(parsed), 8)

                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    trailed = cls(packet + b'XY')
                self.assertIsInstance(trailed.payload, Raw)
                self.assertEqual(trailed.payload.info.packet, b'XY')

    def test_igmpv3_takes_the_length_from_the_data_when_none_is_given(self) -> None:
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3
        from pcapkit.protocols.misc.raw import Raw

        packet, _version = IGMPV3_PACKETS['v3-query']
        parsed = IGMPv3(packet)
        self.assertEqual(parsed.alias, 'IGMPv3')
        self.assertEqual(len(parsed), len(packet))

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            trailed = IGMPv3(packet + b'XY')
        self.assertIsInstance(trailed.payload, Raw)
        self.assertEqual(trailed.payload.info.packet, b'XY')


class IGMPUnitTests(unittest.TestCase):
    """Lower-level unit coverage, mirroring the AH/IPX unit tests."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_igmp_index_length_and_name(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2

        proto = object.__new__(IGMPv2)

        self.assertEqual(IGMP.__index__(), TransType.IGMP)
        self.assertEqual(proto.__length_hint__(), 8)
        self.assertEqual(proto.length, 8)
        self.assertEqual(proto.name, 'Internet Group Management Protocol')
        self.assertEqual(proto.alias, 'IGMPv2')

    def test_igmpv3_length_varies_with_the_message(self) -> None:
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3

        for name, (packet, _version) in IGMPV3_PACKETS.items():
            with self.subTest(packet=name):
                parsed = IGMPv3(io.BytesIO(packet), len(packet))
                self.assertEqual(parsed.length, len(packet))
                self.assertEqual(parsed.__length_hint__(), 8)

    def test_make_data_round_trip(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        class DummyDict(dict):
            __getattr__ = dict.__getitem__

        data = DummyDict(
            type=Type.IGMPv2_Leave_Group,
            max_resp_time=0,
            checksum=b'\xab\xcd',
            group=ipaddress.ip_address('239.8.8.8'),
            __next_type__=None,
        )
        values = IGMP._make_data(data)
        self.assertEqual(values['type'], Type.IGMPv2_Leave_Group)
        self.assertEqual(values['max_resp_time'], 0)
        self.assertEqual(values['checksum'], b'\xab\xcd')
        self.assertEqual(values['group'], ipaddress.ip_address('239.8.8.8'))
        self.assertIn('payload', values)

    def test_make_builds_schema(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmpv1 import IGMP

        proto = object.__new__(IGMP)
        schema = proto.make(
            type=Type.IGMPv1_Membership_Report,
            group='224.0.0.1',
        )

        self.assertEqual(schema.type, Type.IGMPv1_Membership_Report)
        self.assertEqual(schema.max_resp_time, 0)
        self.assertEqual(schema.checksum, b'\x00\x00')
        self.assertEqual(bytes(schema)[4:8], ipaddress.ip_address('224.0.0.1').packed)

    def test_make_rejects_out_of_range_octets(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IGMP)
        for field in ('type', 'max_resp_time'):
            for value in (256, -1):
                with self.subTest(field=field, value=value), \
                        self.assertRaisesRegex(ProtocolError, rf'invalid {field}: {value}'):
                    proto.make(**{field: value})

    def test_make_rejects_non_int_max_resp_time(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IGMP)
        for value in (1.5, '3', None, True, False):
            with self.subTest(value=value), \
                    self.assertRaisesRegex(ProtocolError, 'invalid max_resp_time'):
                proto.make(max_resp_time=value)  # type: ignore[arg-type]

    def test_make_rejects_bool_type(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IGMP)
        for value in (True, False):
            with self.subTest(value=value), \
                    self.assertRaisesRegex(ProtocolError, 'invalid type'):
                proto.make(type=value)  # type: ignore[arg-type]

    def test_max_resp_time_bounds_round_trip(self) -> None:
        for value, version in ((0, 'IGMPv1'), (255, 'IGMPv2')):
            with self.subTest(max_resp_time=value):
                cls = igmp_class(version)
                built = cls(type=0x11, max_resp_time=value)
                packet = built.data
                parsed = cls(io.BytesIO(packet), len(packet))
                self.assertEqual(packet[1], value)
                self.assertEqual(parsed.info.max_resp_time, value)
                self.assertEqual(parsed.alias, version)
                self.assertEqual(cls.from_data(parsed.info).data, packet)


class IGMPv3MaxRespCodeTests(unittest.TestCase):
    """The floating-point Max Resp Code/QQIC decode (:rfc:`3376#section-4.1.1`,
    :rfc:`3376#section-4.1.7`), now module-level helpers on
    :mod:`pcapkit.protocols.internet.igmpv3`.

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
        from pcapkit.protocols.internet.igmpv3 import _decode_resp_code

        self.assertEqual(_decode_resp_code(0x8c), 224)
        self.assertEqual(224 / 10, 22.4)

    def test_decode_values_below_128_are_literal(self) -> None:
        from pcapkit.protocols.internet.igmpv3 import _decode_resp_code

        for code in (0, 1, 100, 127):
            with self.subTest(code=code):
                self.assertEqual(_decode_resp_code(code), code)

    def test_encode_is_the_inverse_of_decode_for_exact_values(self) -> None:
        """Every value a floating-point code can represent exactly --
        ``(mant | 0x10) << (exp + 3)`` for ``mant`` in ``0..15`` and ``exp``
        in ``0..7`` -- round-trips through :func:`_encode_resp_code` and
        :func:`_decode_resp_code` to the same code and the same value.
        """
        from pcapkit.protocols.internet.igmpv3 import _decode_resp_code, _encode_resp_code

        for exp in range(8):
            for mant in range(16):
                value = (mant | 0x10) << (exp + 3)
                with self.subTest(exp=exp, mant=mant, value=value):
                    code = _encode_resp_code(value)
                    self.assertTrue(0x80 <= code <= 0xFF)
                    self.assertEqual(_decode_resp_code(code), value)

    def test_encode_values_below_128_are_literal(self) -> None:
        from pcapkit.protocols.internet.igmpv3 import _encode_resp_code

        for value in (0, 1, 100, 127):
            with self.subTest(value=value):
                self.assertEqual(_encode_resp_code(value), value)

    def test_query_with_max_resp_code_0x8c_decodes_max_resp_time_224(self) -> None:
        """An IGMPv3 Query whose Max Resp Code is ``0x8c`` reports
        ``max_resp_time == 224`` (22.4 seconds), not 14.0 seconds, which is
        what reading ``0x8c`` as a plain tenths-of-a-second integer (140)
        would give.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP

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
        from pcapkit.protocols.internet.igmpv2 import IGMP

        packet = igmp_packet(0x11, 200, '239.1.2.3')
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.max_resp_time, 200)
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_12_octet_query_max_resp_code_200_decodes_the_float(self) -> None:
        """A 12-octet IGMPv3 Query carries the extension, so code 200
        (``0xc8``: exp 4, mant 8) decodes to ``(8 | 0x10) << 7 = 3072``.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP

        packet = igmpv3_query(200, '239.1.2.3')
        self.assertEqual(len(packet), 12)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.max_resp_time, 3072)
        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_make_v3_query_floating_point_encodes_max_resp_time_200(self) -> None:
        """``make()`` on an IGMPv3 Query encodes ``max_resp_time`` 200 as
        ``0x89`` (``(9 | 0x10) << 3 = 200``), and parsing that octet gives
        200 back.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP, _encode_resp_code

        self.assertEqual(_encode_resp_code(200), 0x89)
        proto = object.__new__(IGMP)
        packet = bytes(proto.make(max_resp_time=200))
        self.assertEqual(len(packet), 12)
        self.assertEqual(packet[1], 0x89)

        parsed = IGMP(io.BytesIO(packet), len(packet))
        self.assertEqual(parsed.info.max_resp_time, 200)


class IGMPv3QueryTests(unittest.TestCase):
    """IGMPv3 Membership Query source-list extension (:rfc:`3376#section-4.1`)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_general_query_with_no_sources_round_trips(self) -> None:
        from pcapkit.protocols.internet.igmpv3 import IGMP

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
        from pcapkit.protocols.internet.igmpv3 import IGMP

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

    def test_make_defaults_build_a_12_octet_general_query(self) -> None:
        """Unlike the base's own :meth:`~pcapkit.protocols.internet.igmp.IGMP.make`,
        this class always writes the extension: it is specifically IGMPv3,
        so there is no plain-8-octet default to fall back to.
        """
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmpv3 import IGMP

        proto = object.__new__(IGMP)
        schema = proto.make(type=Type.IGMP_Membership_Query, group='0.0.0.0')

        self.assertIsNotNone(schema.body.ext)
        self.assertEqual(len(bytes(schema)), 12)

    def test_qqi_alone_is_honoured(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmpv3 import IGMP

        proto = object.__new__(IGMP)
        schema = proto.make(type=Type.IGMP_Membership_Query, group='0.0.0.0', qqi=125)

        self.assertEqual(schema.body.ext.qqic, 125)

    def test_additional_data_after_the_source_list_is_kept_as_payload(self) -> None:
        """:rfc:`3376#section-4.1.10` permits octets past the source list
        ("Additional Data"). They are kept as payload, outside the source
        list, so they count toward neither
        :attr:`~pcapkit.protocols.internet.igmpv3.IGMP.length` nor the
        source list, and the rebuild reproduces them.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP
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
        model, so a non-conformant sender's value survives the rebuild
        instead of being rewritten to zero.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP

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
        from pcapkit.protocols.internet.igmpv3 import IGMP

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
        from pcapkit.protocols.internet.igmpv3 import IGMP

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
        from pcapkit.protocols.internet.igmpv3 import IGMP

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
        from pcapkit.protocols.internet.igmpv3 import IGMP

        raw_records = (igmpv3_group_record(200, '224.0.2.1'),)
        packet = igmpv3_report(raw_records)
        parsed = IGMP(io.BytesIO(packet), len(packet))

        self.assertEqual(len(parsed.info.records), 1)
        self.assertEqual(int(parsed.info.records[0].record_type), 200)

        self.assertEqual(IGMP.from_data(parsed.info).data, packet)

    def test_additional_data_after_the_last_record_is_kept_as_payload(self) -> None:
        """:rfc:`3376#section-4.2.11` permits octets past the last group
        record ("Additional Data"). :attr:`~pcapkit.protocols.schema.internet.igmpv3.Report.records`
        reads to the end of the message, since a count field cannot bound it
        in octets, so those octets are trimmed back out and kept as this
        message's trailing payload rather than read as a further record.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP
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
        """The two Reserved fields (:rfc:`3376#section-4.2.1`) are read into
        the data model, so a non-conformant sender's values survive the
        rebuild.
        """
        from pcapkit.protocols.internet.igmpv3 import IGMP

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
        from pcapkit.protocols.internet.igmpv3 import IGMP

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


class IGMPDispatchTests(unittest.TestCase):
    """The IP protocol 2 registry entry is the abstract base, which picks the
    version class per message (#2439, #2448)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_registry_entry_is_the_abstract_base(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.internet.internet import Internet

        self.assertIs(Internet.__proto__[TransType.IGMP].klass, IGMP)

    def test_dispatch_selects_version_per_message(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.misc.raw import Raw

        for name, (packet, version) in {**IGMP_PACKETS, **IGMPV3_PACKETS}.items():
            with self.subTest(packet=name):
                self.assertIs(IGMP._dispatch(packet, len(packet)), igmp_class(version))
        with self.subTest(packet='10-octet-query'):
            self.assertIs(IGMP._dispatch(IGMP_QUERY_10_OCTETS, len(IGMP_QUERY_10_OCTETS)), Raw)
        self.assertIs(IGMP._dispatch(b'', 0), Raw)

    def test_base_refuses_instantiation(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        self.assertIn('version', IGMP.__abstractmethods__)
        with self.assertRaises(TypeError):
            IGMP(io.BytesIO(IGMP_PACKETS['v2-report'][0]), 8)  # type: ignore[abstract]

    def test_ipv4_dispatches_igmp_to_each_version(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.protocols.internet.igmpv3 import IGMP as IGMPv3
        from pcapkit.protocols.internet.ipv4 import IPv4

        expected_classes = {'IGMPv1': IGMPv1, 'IGMPv2': IGMPv2, 'IGMPv3': IGMPv3}
        for name, (packet, version) in {**IGMP_PACKETS, **IGMPV3_PACKETS}.items():
            with self.subTest(packet=name):
                outer = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=packet).data
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = IPv4(io.BytesIO(outer), len(outer))
                self.assertIsInstance(parsed.payload, expected_classes[version])
                self.assertEqual(parsed.payload.alias, version)


if __name__ == '__main__':
    unittest.main()
