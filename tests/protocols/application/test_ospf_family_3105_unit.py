# -*- coding: utf-8 -*-
"""OSPF is a versioned family: OSPFv1, OSPFv2 and OSPFv3 under a dispatching base (#3105).

The headers differ: :rfc:`1131` Section A.2 and :rfc:`2328#appendix-A.3.1` give OSPFv1
and OSPFv2 the same 24 octets, AuType and Authentication included, and
:rfc:`5340#appendix-A.3.1` gives OSPFv3 16, with an Instance ID and a reserved octet
instead. 1.8.0 read every version with the 24-octet header, so an OSPFv3 Instance ID
was read as part of ``autype`` and the first 8 octets of its body as ``auth``. A Version no
member reads is refused, and left ``Raw`` behind IP, as each RFC requires its own. The
OSPFv3 Hello below was built with ``scapy.contrib.ospf`` 2.7.0, which, like tshark
4.6.10, reads 16 octets.

Every case builds its own octets in memory and reads no capture.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: ``Ether()/IPv6(src='fe80::1', dst='ff02::5', nh=89)/OSPFv3_Hdr(src='1.1.1.1')
#: /OSPFv3_Hello(intid=5, prio=1, options=0x13)``, as scapy builds it.
FRAME = bytes.fromhex(
    '33330000000500000000000186dd'
    '6000000000245940fe800000000000000000000000000001ff020000000000000000000000000005'
    '030100240101010100000000fb870000'
    '0000000501000013000a00280000000000000000'
)

#: The OSPFv3 packet of :data:`FRAME`: its header, then the Hello body.
HELLO = FRAME[54:]

#: The Hello body: Interface ID 5, priority 1, options 0x13, intervals 10 and 40.
HELLO_BODY = HELLO[16:]


def ospfv3(instance_id: int, reserved: int = 0, body: bytes = b'', type_: int = 4) -> bytes:
    """An OSPFv3 packet with ``instance_id`` and ``reserved``; Packet Length counts ``body``."""
    return struct.pack('!BBH4s4s2sBB', 3, type_, 16 + len(body), bytes([192, 0, 2, 1]),
                       bytes([0, 0, 0, 1]), b'\x12\x34', instance_id, reserved) + body


def header24(version: int, autype: int = 0, auth: bytes = bytes(8), body: bytes = b'',
             checksum: bytes = b'\x12\x34') -> bytes:
    """A 24-octet OSPFv1 or OSPFv2 packet (RFC 1131 A.2, RFC 2328 A.3.1); Packet Length counts ``body``."""
    return struct.pack('!BBH4s4s2sH', version, 1, 24 + len(body), bytes([192, 0, 2, 1]),
                       bytes(4), checksum, autype) + auth + body


#: An OSPFv2 Hello with null authentication, and its checksum, as scapy builds it.
OSPFV2 = (bytes.fromhex('02010030c000020100000000b69400000000000000000000')
          + bytes.fromhex('ffffff00000a020100000028c000020100000000c0000202'))

#: An OSPFv1 Link State Update with a simple password, hand-built from RFC 1131 A.2.
OSPFV1 = header24(1, autype=1, auth=b'password', body=b'four')


class _OSPFTestCase(unittest.TestCase):
    """A fresh :mod:`pcapkit` per class, and the helpers each case shares."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.ospf.packet import Packet
        from pcapkit.protocols.application.ospf.protocol import OSPF
        from pcapkit.utilities import config
        from pcapkit.utilities.exceptions import ProtocolError, UnexpectedKeyword

        self.OSPF = OSPF
        self.Packet = Packet
        self.config = config
        self.ProtocolError = ProtocolError
        self.UnexpectedKeyword = UnexpectedKeyword

    def members(self) -> 'tuple[type, type, type]':
        """OSPFv1, OSPFv2 and OSPFv3."""
        from pcapkit.protocols.application.ospfv1.protocol import OSPFv1
        from pcapkit.protocols.application.ospfv2.protocol import OSPFv2
        from pcapkit.protocols.application.ospfv3.protocol import OSPFv3

        return OSPFv1, OSPFv2, OSPFv3

    def assertRebuilds(self, octets: bytes, member: str) -> None:  # pylint: disable=invalid-name
        """``octets`` parse through the base as ``member``, and rebuild from the info and from
        its dict form, unchanged."""
        parsed = self.OSPF(octets)
        self.assertEqual(type(parsed).__name__, member)
        self.assertEqual(type(parsed.info).__name__, member)
        self.assertEqual(parsed.data, octets)
        rebuilt = self.OSPF.from_data(parsed.info)
        self.assertEqual(type(rebuilt).__name__, member)
        self.assertEqual(rebuilt.data, octets)
        self.assertEqual(rebuilt.info, parsed.info)
        self.assertEqual(self.OSPF.from_data(parsed.info.to_dict()).data, octets)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFFamilyTests(_OSPFTestCase):
    """The base dispatches to the member on parse, build and ``from_data``."""

    def test_the_version_octet_picks_the_member(self) -> None:
        OSPFv1, OSPFv2, OSPFv3 = self.members()  # pylint: disable=invalid-name
        for version, member in ((1, OSPFv1), (2, OSPFv2), (3, OSPFv3)):
            octets = (ospfv3(7) if version == 3 else header24(version))[1:]
            with self.subTest(version=version):
                parsed = self.OSPF(bytes([version]) + octets)
                self.assertIs(type(parsed), member)
                self.assertIsInstance(parsed, self.OSPF)
                self.assertEqual(parsed.alias, f'OSPFv{version}')
                self.assertEqual(parsed.info_name, 'ospf')

    def test_a_build_through_the_base_gives_the_named_member(self) -> None:
        OSPFv1, OSPFv2, OSPFv3 = self.members()  # pylint: disable=invalid-name
        for version, member, length in ((1, OSPFv1, 24), (2, OSPFv2, 24), (3, OSPFv3, 16)):
            with self.subTest(version=version):
                made = self.OSPF.from_fields(version=version)
                self.assertIs(type(made), member)
                self.assertEqual((made.data[0], len(made.data), made.length), (version, length, length))
                self.assertIs(type(self.OSPF(made.data)), member)
                self.assertIs(type(self.OSPF.from_data(made.info)), member)
                self.assertIs(type(self.OSPF(version=version)), member)

    def test_a_stream_is_peeked_not_consumed(self) -> None:
        import io

        OSPFv1, OSPFv2, OSPFv3 = self.members()  # pylint: disable=invalid-name
        for octets, member in ((OSPFV1, OSPFv1), (OSPFV2, OSPFv2), (HELLO, OSPFv3)):
            with self.subTest(member=member.__name__):
                stream = io.BytesIO(b'prefix' + octets)
                stream.seek(6)
                parsed = self.OSPF(stream, len(octets))
                self.assertIs(type(parsed), member)
                self.assertEqual(parsed.data, octets)
        # The registry binds the base, whose hint is its longest member's header.
        self.assertEqual(self.OSPF.__length_hint__(None), 24)  # type: ignore[arg-type]
        self.assertEqual((OSPFv1.__length_hint__(None), OSPFv3.__length_hint__(None)), (24, 16))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.OSPF(None)  # type: ignore[arg-type]

    def test_the_base_refuses_what_names_no_member(self) -> None:
        refused = (
            (lambda: self.OSPF.from_fields(), 'OSPF: no version to build with; pass version=1, 2 or 3'),
            (lambda: self.OSPF.from_fields(version=256), 'OSPF: invalid version: 256'),
            (lambda: self.OSPF.from_fields(version=True), 'OSPF: invalid version: True'),
            (lambda: self.OSPF(b''), 'OSPF: no version in a packet shorter than 1 octet'),
            (lambda: self.OSPF.from_data({'type': 1}), 'OSPF: invalid version: None'),
        )
        for call, message in refused:
            with self.subTest(message=message), self.assertRaisesRegex(self.ProtocolError, f'^{message}$'):
                call()

    def test_a_version_no_member_reads_is_refused(self) -> None:
        """Each RFC requires its own Version (RFC 1131 8.2, RFC 2328 8.2, RFC 5340 4.2.2)."""
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.misc.raw.protocol import Raw

        OSPFv1, OSPFv2, OSPFv3 = self.members()  # pylint: disable=invalid-name
        for version in (0, 4, 255):
            octets = header24(version)
            with self.subTest(version=version):
                for call in (lambda: self.OSPF(octets), lambda: self.OSPF.from_fields(version=version),
                             lambda: self.OSPF.from_data({'version': version, 'type': 1})):
                    with self.assertRaisesRegex(self.ProtocolError, f'^OSPF: invalid version: {version}$'):
                        call()
                for member in (OSPFv1, OSPFv2, OSPFv3):
                    with self.assertRaisesRegex(self.ProtocolError, f'^{member.__name__}: invalid version: {version}$'):
                        member(octets)
                    with self.assertRaisesRegex(self.ProtocolError, f'^OSPF: invalid version: {version}$'):
                        member.from_fields(version=version)
                # Behind IP protocol 89 the packet is left undissected, as IGMP leaves one.
                ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(octets), 1, 0, 1, 89, 0,
                                 bytes([192, 0, 2, 1]), bytes([224, 0, 0, 5])) + octets
                frame = Ethernet(b'\x01\x00\x5e\x00\x00\x05' + bytes(6) + b'\x08\x00' + ip)
                layer = frame.payload.payload
                self.assertIs(type(layer), Raw)
                self.assertEqual((layer.data, layer.info.get('error')), (octets, None))
                self.assertFalse('OSPF' in frame)
                self.assertEqual(type(frame).from_data(frame.info).data, frame.data)

    def test_a_member_refuses_another_members_version(self) -> None:
        OSPFv1, OSPFv2, OSPFv3 = self.members()  # pylint: disable=invalid-name
        for member, octets, version in ((OSPFv1, OSPFV2, 2), (OSPFv2, OSPFV1, 1), (OSPFv2, HELLO, 3),
                                        (OSPFv3, OSPFV2, 2)):
            with self.subTest(member=member.__name__, version=version):
                with self.assertRaisesRegex(self.ProtocolError, f'^{member.__name__}: invalid version: {version}$'):
                    member(octets)
        for member, version in ((OSPFv1, 2), (OSPFv2, 3), (OSPFv2, 1), (OSPFv3, 1)):
            with self.subTest(member=member.__name__, field=version):
                with self.assertRaisesRegex(self.ProtocolError, f'^{member.__name__}: version={version} '
                                                                'names another member$'):
                    member.from_fields(version=version)
        with self.assertRaisesRegex(self.ProtocolError, '^OSPFv2: no version of its own to match version=3$'):
            OSPFv2(OSPFV2, version=3)
        # ``version`` names the member on parse, unchecked against the octets, whose
        # member's own parser refuses them.
        with self.assertRaisesRegex(self.ProtocolError, '^OSPFv3: invalid version: 2$'):
            self.OSPF(OSPFV2, version=3)

    def test_nothing_leaks_across_instances(self) -> None:
        OSPFv1, OSPFv2, OSPFv3 = self.members()  # pylint: disable=invalid-name
        schemas = {cls: (cls.__schema__, cls.__data__) for cls in (self.OSPF, OSPFv1, OSPFv2, OSPFv3)}
        sequence = (HELLO, OSPFV2, OSPFV1, header24(2, autype=1), HELLO, OSPFV1, OSPFV2)
        parsed = [self.OSPF(octets) for octets in sequence]
        self.assertEqual([type(item).__name__ for item in parsed],
                         ['OSPFv3', 'OSPFv2', 'OSPFv1', 'OSPFv2', 'OSPFv3', 'OSPFv1', 'OSPFv2'])
        self.assertEqual([item.length for item in parsed], [16, 24, 24, 24, 16, 24, 24])
        self.assertEqual([item.alias for item in parsed],
                         ['OSPFv3', 'OSPFv2', 'OSPFv1', 'OSPFv2', 'OSPFv3', 'OSPFv1', 'OSPFv2'])
        for item, octets in zip(parsed, sequence):
            self.assertEqual(self.OSPF.from_data(item.info).data, octets)
            self.assertNotIn('__schema__', vars(item))
        self.assertEqual({cls: (cls.__schema__, cls.__data__) for cls in schemas}, schemas)
        self.assertNotIn('_version', vars(OSPFv2))

    def test_ids_and_selectors(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.protocol import ProtocolBase

        OSPFv1, OSPFv2, OSPFv3 = self.members()  # pylint: disable=invalid-name
        self.assertEqual(self.OSPF.id(), ('OSPFv1', 'OSPFv2', 'OSPFv3'))
        self.assertEqual([cls.id() for cls in (OSPFv1, OSPFv2, OSPFv3)], [('OSPFv1',), ('OSPFv2',), ('OSPFv3',)])
        for name, cls in (('OSPF', self.OSPF), ('OSPFv1', OSPFv1), ('OSPFv2', OSPFv2), ('OSPFv3', OSPFv3)):
            self.assertIs(ProtocolBase.get_protocol(name), cls)
        frame = Ethernet(FRAME)
        self.assertEqual(('OSPF' in frame, 'OSPFv3' in frame, 'OSPFv2' in frame), (True, True, False))
        self.assertIsInstance(frame['OSPF'], OSPFv3)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFv3HeaderTests(_OSPFTestCase):
    """OSPFv3 reads its own 16-octet header."""

    def test_scapy_hello_reads_a_16_octet_header(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        frame = Ethernet(FRAME)
        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:OSPFv3:Raw')
        ospf = frame['OSPF']
        info = ospf.info
        self.assertEqual(ospf.length, 16)
        # The Hello body, Interface ID first, is handed on at octet 16.
        self.assertEqual(ospf.payload.data, HELLO_BODY)
        self.assertEqual(HELLO_BODY[:8], bytes.fromhex('0000000501000013'))
        self.assertNotIn('autype', info)
        self.assertNotIn('auth', info)
        self.assertEqual((info.version, info.type, info.len), (3, self.Packet.Hello, 36))
        self.assertEqual((str(info.router_id), str(info.area_id)), ('1.1.1.1', '0.0.0.0'))
        self.assertEqual(info.chksum, b'\xfb\x87')
        self.assertEqual((info.instance_id, info.reserved), (0, b'\x00'))
        self.assertIsInstance(ospf, self.members()[2])

        from pcapkit.protocols.application.ospfv3 import Data_OSPFv3
        self.assertIsInstance(info, Data_OSPFv3)

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_hello_is_what_scapy_builds(self) -> None:
        from scapy.contrib.ospf import OSPFv3_Hdr, OSPFv3_Hello  # pylint: disable=import-error
        from scapy.layers.inet6 import IPv6  # pylint: disable=import-error
        from scapy.layers.l2 import Ether  # pylint: disable=import-error

        built = (Ether(src='00:00:00:00:00:01', dst='33:33:00:00:00:05')
                 / IPv6(src='fe80::1', dst='ff02::5', nh=89)
                 / OSPFv3_Hdr(src='1.1.1.1') / OSPFv3_Hello(intid=5, prio=1, options=0x13))
        self.assertEqual(bytes(built), FRAME)
        self.assertEqual(len(bytes(built[OSPFv3_Hdr])) - len(bytes(built[OSPFv3_Hello])), 16)

    def test_a_nonzero_instance_id_is_its_own_field(self) -> None:
        body = bytes(range(20))
        ospf = self.OSPF(ospfv3(instance_id=0x2a, body=body))
        info = ospf.info
        self.assertEqual(ospf.length, 16)
        self.assertEqual(ospf.alias, 'OSPFv3')
        self.assertEqual(ospf.name, 'Open Shortest Path First version 3')
        self.assertEqual((info.version, info.type, info.len), (3, self.Packet.Link_State_Update, 36))
        self.assertEqual((str(info.router_id), str(info.area_id)), ('192.0.2.1', '0.0.0.1'))
        self.assertEqual(info.chksum, b'\x12\x34')
        self.assertEqual((info.instance_id, info.reserved), (0x2a, b'\x00'))
        self.assertEqual(ospf.payload.data, body)

        from pcapkit.protocols.application.ospfv3 import Schema_OSPFv3
        self.assertIsInstance(ospf.schema, Schema_OSPFv3)

    def test_parse_rebuild_is_exact(self) -> None:
        for octets in (HELLO, ospfv3(0x2a, body=bytes(range(20))), ospfv3(255, 0xff, b'xy'),
                       ospfv3(1), ospfv3(1) + b'past the packet length'):
            with self.subTest(octets=octets.hex()):
                self.assertRebuilds(octets, 'OSPFv3')

    def test_a_cut_header_rebuilds_as_cut(self) -> None:
        octets = ospfv3(0x2a, 0xff, b'body')
        for cut in range(1, len(octets)):
            with self.subTest(cut=cut):
                self.assertRebuilds(octets[:cut], 'OSPFv3')

    def test_make_builds_the_16_octet_header(self) -> None:
        made = self.OSPF.from_fields(version=3, type=self.Packet.Link_State_Update,
                                     router_id='192.0.2.1', area_id='0.0.0.1', checksum=b'\x12\x34',
                                     instance_id=0x2a, payload=b'body')
        self.assertEqual(made.data, ospfv3(0x2a, body=b'body'))
        self.assertEqual(made.length, 16)
        self.assertEqual(self.OSPF.from_fields(version=3, reserved=b'\xff').data,
                         bytes.fromhex('0301001000000000000000000000' '00ff'))
        # The checksum covers an IPv6 pseudo-header, so none is computed or verified.
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', True), \
                mock.patch.object(self.config, 'CHECKSUM_VERIFY', True):
            made = self.OSPF.from_fields(version=3, payload=HELLO_BODY)
            self.assertEqual(made.data[12:14], b'\x00\x00')
            self.assertNotIn('checksum_status', self.OSPF(HELLO).info)

    def test_make_parse_is_exact(self) -> None:
        for fields in ({'version': 3}, {'version': 3, 'instance_id': 255, 'reserved': b'\xff'},
                       {'version': 3, 'payload': HELLO_BODY, 'trailer': b'tail'},
                       {'version': 3, 'packet_length': 200, 'payload': b'short'}):
            with self.subTest(fields=fields):
                made = self.OSPF.from_fields(**fields)
                parsed = self.OSPF(made.data)
                self.assertEqual((made.length, parsed.length), (16, 16))
                self.assertEqual(parsed.data, made.data)
                self.assertEqual(parsed.info.instance_id, fields.get('instance_id', 0))
                self.assertEqual(self.OSPF.from_data(parsed.info).data, made.data)

    def test_make_refuses_a_field_the_header_lacks(self) -> None:
        for fields in ({'version': 3, 'auth_type': 1}, {'version': 3, 'auth_data': b'password'},
                       {'version': 2, 'instance_id': 1}, {'version': 1, 'reserved': b'\xff'}):
            with self.subTest(fields=fields), self.assertRaises(self.UnexpectedKeyword):
                self.OSPF.from_fields(**fields)
        for fields, message in (({'version': 3, 'instance_id': 256}, 'OSPF: invalid instance ID: 256'),
                                ({'version': 3, 'reserved': b''}, 'OSPF: invalid reserved octet: must be 1 octet')):
            with self.subTest(fields=fields), self.assertRaisesRegex(self.ProtocolError, f'^{message}'):
                self.OSPF.from_fields(**fields)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFv1HeaderTests(_OSPFTestCase):
    """OSPFv1 reads the 24-octet header of RFC 1131 A.2."""

    def test_a_hand_built_header_reads_as_rfc_1131_lays_it_out(self) -> None:
        from pcapkit.const.ospfv1.authentication import Authentication
        from pcapkit.const.ospfv1.packet import Packet

        ospf = self.OSPF(OSPFV1)
        info = ospf.info
        self.assertIsInstance(ospf, self.members()[0])
        self.assertEqual((ospf.length, ospf.alias, ospf.name), (24, 'OSPFv1', 'Open Shortest Path First version 1'))
        self.assertEqual((info.version, info.type, info.len), (1, Packet.Hello, 28))
        self.assertEqual((str(info.router_id), str(info.area_id), info.chksum), ('192.0.2.1', '0.0.0.0', b'\x12\x34'))
        self.assertEqual((info.autype, info.auth), (Authentication.Simple_password, b'password'))
        self.assertIs(type(info.autype), Authentication)
        self.assertIs(type(info.type), Packet)
        self.assertEqual(ospf.payload.data, b'four')

    def test_only_rfc_1131s_codes_are_named(self) -> None:
        """AuType 0 and 1 (Appendix E), and packet types 1 to 5 (Section A.2), alone."""
        from pcapkit.const.ospfv1.authentication import Authentication
        from pcapkit.const.ospfv1.packet import Packet

        self.assertEqual([(member.name, member.value) for member in Authentication],
                         [('No_authentication', 0), ('Simple_password', 1)])
        self.assertEqual([member.value for member in Packet], [1, 2, 3, 4, 5])
        for value, name in ((2, 'Reserved'), (255, 'Reserved'), (256, 'Assigned_per_Autonomous_System')):
            with self.subTest(autype=value):
                self.assertEqual(self.OSPF(header24(1, autype=value)).info.autype.name, name)
        for value in (0, 6, 255):
            with self.subTest(type=value):
                self.assertEqual(Packet(value).name, 'Unassigned')
        made = self.OSPF.from_fields(version=1, type=Packet.Link_State_Ack, auth_type=Authentication.No_authentication)
        self.assertEqual((made.data[1], made.data[14:16]), (5, b'\x00\x00'))

    def test_authentication_is_kept_as_captured(self) -> None:
        """RFC 1131 defines AuType 0 and 1 alone, so AuType 2's octets are not decoded."""
        octets = header24(1, autype=2, auth=bytes([0, 0, 1, 16, 0, 0, 0, 7]))
        self.assertEqual(self.OSPF(octets).info.auth, bytes([0, 0, 1, 16, 0, 0, 0, 7]))
        self.assertRebuilds(octets, 'OSPFv1')

    def test_round_trips_are_exact(self) -> None:
        for octets in (OSPFV1, header24(1), header24(1, body=b'x') + b'trailer'):
            with self.subTest(octets=octets.hex()):
                self.assertRebuilds(octets, 'OSPFv1')
        for cut in range(1, len(OSPFV1)):
            with self.subTest(cut=cut):
                self.assertRebuilds(OSPFV1[:cut], 'OSPFv1')
        made = self.OSPF.from_fields(version=1, auth_type=1, auth_data=b'password', payload=b'four',
                                     router_id='192.0.2.1', checksum=b'\x12\x34')
        self.assertIsInstance(made, self.members()[0])
        self.assertEqual(made.data, OSPFV1)
        self.assertEqual(self.OSPF.from_data(self.OSPF(made.data).info).data, OSPFV1)

    def test_the_checksum_is_rfc_1131s(self) -> None:
        """Over the packet but the Authentication field, as OSPFv2's (RFC 1131 A.2)."""
        from pcapkit.corekit.checksum.internet import ChecksumStatus

        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', True), \
                mock.patch.object(self.config, 'CHECKSUM_VERIFY', True):
            made = self.OSPF.from_fields(version=1, auth_type=1, auth_data=b'password', payload=b'four')
            v2 = self.OSPF.from_fields(version=2, auth_type=1, auth_data=b'password', payload=b'four')
            # Only the Version octet differs in what the checksum covers.
            self.assertEqual(int.from_bytes(made.data[12:14], 'big') - int.from_bytes(v2.data[12:14], 'big'), 0x100)
            self.assertEqual(self.OSPF(made.data).info.checksum_status, ChecksumStatus.VALID)
            self.assertEqual(self.OSPF(OSPFV1).info.checksum_status, ChecksumStatus.INVALID)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFv2HeaderTests(_OSPFTestCase):
    """OSPFv2 keeps the 24-octet header and the octets and info 1.8.0 gave."""

    def test_ospfv2_keeps_its_24_octet_header(self) -> None:
        ospf = self.OSPF(OSPFV2)
        info = ospf.info
        self.assertIsInstance(ospf, self.members()[1])
        self.assertEqual(ospf.length, 24)
        self.assertEqual((info.version, info.autype, info.auth), (2, 0, bytes(8)))
        self.assertNotIn('instance_id', info)
        self.assertEqual(ospf.payload.data, OSPFV2[24:])
        self.assertRebuilds(OSPFV2, 'OSPFv2')
        self.assertEqual(len(self.OSPF.from_fields(version=2, payload=b'xy').data), 26)

    def test_info_is_what_1_8_0_gave(self) -> None:
        """The keys and values of 1.8.0's ``OSPF`` info for version 2; another version is refused."""
        from pcapkit.corekit.checksum.internet import ChecksumStatus

        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True):
            info = self.OSPF(OSPFV2).info.to_dict()
            self.assertEqual([key for key in info if not key.startswith('__') and key != 'packet'],
                             ['version', 'type', 'len', 'router_id', 'area_id', 'chksum', 'autype', 'auth',
                              'checksum_status', 'raw'])
            self.assertEqual((info['version'], info['len'], info['chksum'], info['auth']),
                             (2, 48, b'\xb6\x94', bytes(8)))
            self.assertEqual(info['checksum_status'], ChecksumStatus.VALID)
            # No RFC defines these versions, so none is read (#3105).
            for version in (0, 4, 255):
                with self.subTest(version=version), self.assertRaisesRegex(self.ProtocolError,
                                                                         f'^OSPF: invalid version: {version}$'):
                    self.OSPF(bytes([version]) + OSPFV2[1:])


if __name__ == '__main__':
    unittest.main()
