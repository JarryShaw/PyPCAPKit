# -*- coding: utf-8 -*-
"""IGMPv1 and IGMPv2 messages parse and rebuild byte for byte (#2439).

Each case parses its octets with the concrete class for the version it names,
:class:`~pcapkit.protocols.internet.igmpv1.IGMP` or
:class:`~pcapkit.protocols.internet.igmpv2.IGMP`; the abstract
:class:`~pcapkit.protocols.internet.igmp.IGMP` base cannot be built. A type
outside v1/v2, IGMPv3 (:rfc:`3376`) included, falls back to
:class:`~pcapkit.protocols.misc.raw.Raw`.

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


def igmp_class(version: 'str'):
    """Return the concrete class for ``version``, ``'IGMPv1'`` or ``'IGMPv2'``."""
    from pcapkit.protocols.internet import (  # pylint: disable=import-outside-toplevel
        igmpv1, igmpv2)
    return igmpv1.IGMP if version == 'IGMPv1' else igmpv2.IGMP


#: One fixture per message type IGMPv1 and IGMPv2 define, each a correctly
#: checksummed 8-octet message, with the version it is read as. Type
#: octets per :rfc:`1112#page-11` (``0x11``/``0x12``, v1) and
#: :rfc:`2236#section-2.1` (``0x11``/``0x16``/``0x17``, v2's own report and
#: leave, plus v1's report kept for backwards compatibility), cross-checked
#: against the IANA *IGMP Type Numbers* registry (``0x11``, ``0x12``,
#: ``0x16``, ``0x17``).
IGMP_PACKETS = {
    # IGMPv1 Membership Query (General Query only -- v1 has no group-specific
    # query): max_resp_time is reserved at zero (:rfc:`1112#page-11`).
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

#: An IGMPv3 Membership Report (:rfc:`3376#section-4.2`, type ``0x22``):
#: checksum and reserved fields zeroed, one group record declared, and one
#: (unparsed) group record's worth of octets. Read through the v1/v2 layout,
#: its "reserved" and "number of group records" octets would form a group
#: address of ``0.0.0.1``.
IGMPV3_REPORT = bytes.fromhex('2200000000000001') + bytes(8)


def igmp_query(max_resp_time: 'int', tail: 'bytes') -> 'bytes':
    """Build a correctly-checksummed Membership Query (type ``0x11``) of
    General Query shape, followed by ``tail``, with the checksum covering
    the whole message as :rfc:`9776#section-4.1.2` specifies."""
    zeroed = bytes([0x11, max_resp_time, 0, 0]) + bytes(4) + tail
    checksum = internet_checksum(zeroed)
    return zeroed[:2] + checksum + zeroed[4:]


#: An IGMPv3 General Query (:rfc:`9776#section-4.1`): the 8 octets an
#: IGMPv2 Query also carries, then Resv/S/QRV (``0x02``), QQIC (``125``) and
#: a zero Number of Sources -- 12 octets in all. The type octet and the first
#: 8 octets alone cannot tell it from an IGMPv2 General Query; only the
#: length does (:rfc:`9776#section-7.1`), so it must not be labelled IGMPv2.
IGMPV3_QUERY = igmp_query(100, bytes([0x02, 125, 0, 0]))

#: A Membership Query of neither 8 nor 12-or-more octets, which
#: :rfc:`9776#section-7.1` says must be silently ignored: neither an
#: IGMPv1/v2 nor an IGMPv3 message.
IGMP_QUERY_10_OCTETS = igmp_query(100, b'\x00\x00')


class IGMPRoundTripTests(unittest.TestCase):
    """Pin IGMP parsing and rebuild for every IGMPv1/v2 message type."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        for name, (packet, version) in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                cls = igmp_class(version)
                parsed = cls(io.BytesIO(packet), len(packet))
                self.assertEqual(cls.from_data(parsed.info).data, packet)

    def test_checksum_is_parsed_correctly(self) -> None:
        """The fixture's checksum is the RFC-correct ones'-complement checksum
        of the 8-octet message, computed independently by
        :func:`internet_checksum`, and the parser reports exactly that value.
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
        Membership Report (``0x22``), must be refused rather than decoded
        through the v1/v2 8-octet layout, which would misread the "reserved"
        and "number of group records" octets as a group address (#2439).
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for cls in (IGMPv1, IGMPv2):
            with self.subTest(cls=cls.__module__), self.assertRaises(ProtocolError):
                cls(io.BytesIO(IGMPV3_REPORT), len(IGMPV3_REPORT))

    def test_non_v1_v2_type_falls_back_to_raw_on_dispatch(self) -> None:
        """Dispatched as an IPv4 payload, the same IGMPv3 Membership Report
        must fall back to :class:`~pcapkit.protocols.misc.raw.Raw` via
        :func:`~pcapkit.corekit.decorators.beholder` -- not be mis-decoded as
        IGMP type ``0x22`` with ``group=0.0.0.1`` (#2439).
        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        made = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=IGMPV3_REPORT)
        packet = made.data

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.packet, IGMPV3_REPORT)

    def test_non_8_octet_query_raises_protocol_error(self) -> None:
        """A Membership Query is IGMPv1/v2 only at exactly 8 octets
        (:rfc:`9776#section-7.1`): a 12-octet IGMPv3 General Query and a
        10-octet Query must be refused, not labelled ``IGMPv2`` on the strength
        of a nonzero Max Resp Code (#2439).
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for cls in (IGMPv1, IGMPv2):
            for name, packet in (('v3-query', IGMPV3_QUERY), ('10-octet-query', IGMP_QUERY_10_OCTETS)):
                with self.subTest(cls=cls.__module__, packet=name), self.assertRaises(ProtocolError):
                    cls(io.BytesIO(packet), len(packet))

    def test_non_8_octet_query_falls_back_to_raw_on_dispatch(self) -> None:
        """Dispatched as an IPv4 payload, a non-8-octet Membership Query
        falls back to :class:`~pcapkit.protocols.misc.raw.Raw`, exactly as an
        IGMPv3 Membership Report does, rather than reading as
        ``IPv4:IGMPv2:Raw`` (#2439).
        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        for name, payload in (('v3-query', IGMPV3_QUERY), ('10-octet-query', IGMP_QUERY_10_OCTETS)):
            with self.subTest(packet=name):
                packet = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=payload).data
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = IPv4(io.BytesIO(packet), len(packet))

                self.assertIsInstance(parsed.payload, Raw)
                self.assertEqual(parsed.payload.info.packet, payload)
                self.assertNotIn('IGMPv2', str(parsed.protochain))


class IGMPReadTests(unittest.TestCase):
    """Pin the version identification of :meth:`read` and its one refusal
    path, including the one ambiguous message type (#2439).
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_alias_names_the_version_read(self) -> None:
        """``alias`` follows the concrete class, and each concrete class is an
        instance of the :class:`~pcapkit.protocols.internet.igmp.IGMP` base.
        """
        from pcapkit.protocols.internet.igmp import IGMP as IGMPBase

        for name, (packet, version) in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                parsed = igmp_class(version)(io.BytesIO(packet), len(packet))
                self.assertIsInstance(parsed, IGMPBase)
                self.assertEqual(parsed.alias, version)

    def test_refusals_name_the_version_refused(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        v1_report, v2_report = IGMP_PACKETS['v1-report'][0], IGMP_PACKETS['v2-report'][0]
        with self.assertRaisesRegex(ProtocolError, r'^IGMPv1: .+ is not an IGMPv1 message \(8 octets\)'):
            IGMPv1(io.BytesIO(v2_report), len(v2_report))
        with self.assertRaisesRegex(ProtocolError, r'^IGMPv2: .+ is not an IGMPv2 message \(8 octets\)'):
            IGMPv2(io.BytesIO(v1_report), len(v1_report))

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

    def test_classify_rejects_a_non_v1_v2_type(self) -> None:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        self.assertEqual(IGMP._classify(Type.IGMPv3_Membership_Report, 0, 8), 0)

    def test_classify_reads_a_query_s_version_from_its_length(self) -> None:
        """Only an 8-octet Membership Query is IGMPv1/v2
        (:rfc:`9776#section-7.1`); a Report or Leave keeps its version
        whatever trails it (:rfc:`2236#section-2.5`).
        """
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmp import IGMP

        query = Type.IGMP_Membership_Query
        self.assertEqual(IGMP._classify(query, 0, 8), 1)
        self.assertEqual(IGMP._classify(query, 100, 8), 2)
        for length in (9, 10, 11, 12, 16):
            for max_resp_time in (0, 100):
                with self.subTest(length=length, max_resp_time=max_resp_time):
                    self.assertEqual(IGMP._classify(query, max_resp_time, length), 0)
        self.assertEqual(IGMP._classify(Type.IGMPv1_Membership_Report, 0, 10), 1)
        self.assertEqual(IGMP._classify(Type.IGMPv2_Membership_Report, 0, 10), 2)
        self.assertEqual(IGMP._classify(Type.IGMPv2_Leave_Group, 0, 10), 2)


class IGMPVersionedClassTests(unittest.TestCase):
    """The concrete IGMPv1 and IGMPv2 classes, and the abstract base they
    share."""

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

        self.assertEqual(IGMPv1.id(), ('IGMP', 'IGMPv1'))
        self.assertEqual(IGMPv2.id(), ('IGMP', 'IGMPv2'))
        self.assertEqual(object.__new__(IGMPv1).version, 1)
        self.assertEqual(object.__new__(IGMPv2).version, 2)

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
        the IGMPv2 class, as a v1 message is (:rfc:`9776#section-7.1`).
        """
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for name, packet in (('v3-query', IGMPV3_QUERY), ('10-octet-query', IGMP_QUERY_10_OCTETS)):
            with self.subTest(packet=name), self.assertRaises(ProtocolError):
                IGMPv2(io.BytesIO(packet), len(packet))

    def test_igmpv1_rejects_a_non_8_octet_query(self) -> None:
        """Likewise for the IGMPv1 class, with a zero Max Resp Code so the
        length is the only thing refusing it (:rfc:`9776#section-7.1`).
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.utilities.exceptions import ProtocolError

        for tail in (bytes(4), bytes(2)):
            packet = igmp_query(0, tail)
            with self.subTest(length=len(packet)), self.assertRaises(ProtocolError):
                IGMPv1(io.BytesIO(packet), len(packet))

    def test_versions_take_the_length_from_the_data_when_none_is_given(self) -> None:
        """Without a ``length``, each version reads the whole of ``bytes``
        data: trailing octets become :class:`~pcapkit.protocols.misc.raw.Raw`,
        and a Query longer than 8 octets is refused.
        """
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            (IGMPv1, 'v1-report', igmp_query(0, bytes(4))),
            (IGMPv2, 'v2-report', IGMPV3_QUERY),
        )
        for cls, name, long_query in cases:
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

                with self.assertRaisesRegex(ProtocolError, rf'\({len(long_query)} octets\)'):
                    cls(long_query)


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


class IGMPDispatchTests(unittest.TestCase):
    """The IP protocol 2 registry entry is the abstract base, which picks the
    version class per message (#2439)."""

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

        for name, (packet, version) in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                self.assertIs(IGMP._dispatch(packet, len(packet)), igmp_class(version))
        for name, packet in (('v3-report', IGMPV3_REPORT), ('v3-query', IGMPV3_QUERY),
                             ('10-octet-query', IGMP_QUERY_10_OCTETS)):
            with self.subTest(packet=name):
                self.assertIs(IGMP._dispatch(packet, len(packet)), Raw)
        self.assertIs(IGMP._dispatch(b'', 0), Raw)

    def test_base_refuses_instantiation(self) -> None:
        from pcapkit.protocols.internet.igmp import IGMP

        self.assertIn('version', IGMP.__abstractmethods__)
        with self.assertRaises(TypeError):
            IGMP(io.BytesIO(IGMP_PACKETS['v2-report'][0]), 8)  # type: ignore[abstract]

    def test_ipv4_dispatches_igmp_to_each_version(self) -> None:
        from pcapkit.protocols.internet.igmpv1 import IGMP as IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMP as IGMPv2
        from pcapkit.protocols.internet.ipv4 import IPv4

        for name, (packet, version) in IGMP_PACKETS.items():
            with self.subTest(packet=name):
                outer = IPv4(protocol=2, src='10.0.0.1', dst='224.0.0.1', payload=packet).data
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = IPv4(io.BytesIO(outer), len(outer))
                expected = IGMPv1 if version == 'IGMPv1' else IGMPv2
                self.assertIsInstance(parsed.payload, expected)
                self.assertEqual(parsed.payload.alias, version)


if __name__ == '__main__':
    unittest.main()
