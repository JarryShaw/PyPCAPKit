# -*- coding: utf-8 -*-
"""BOOTP and DHCP messages decode against their RFCs, and rebuild byte for byte (#2959).

Each message is built here from octets whose field values RFC 951, RFC 2131 and the
option RFCs give, is checked against them, and is rebuilt both ways round: parse
then ``from_data`` (from the data model and from its ``to_dict()`` form), and
``make`` then parse. The family base, ``DHCP``, picks BOOTP or DHCPv4 by the DHCP
Message Type option, which UDP ports 67 and 68 dispatch to.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import struct
import unittest

from tests._support import close_extractor, reimport_once_per_class

#: Whether the packages an extraction needs are installed.
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: The magic cookie, 99.130.83.99 (RFC 2132 section 2).
COOKIE = bytes((99, 130, 83, 99))


def header(op: int = 1, *, xid: int = 0x3D1D, chaddr: bytes = bytes.fromhex('000b8201fc42'), flags: int = 0,
           yiaddr: bytes = bytes(4), sname: bytes = b'', file: bytes = b'') -> bytes:
    """The fixed 236 octets of a message from an Ethernet client (RFC 2131 section 2)."""
    return (struct.pack('!BBBBIHH', op, 1, len(chaddr), 0, xid, 0, flags) + bytes(4) + yiaddr + bytes(8)
            + chaddr.ljust(16, b'\x00') + sname.ljust(64, b'\x00') + file.ljust(128, b'\x00'))


#: The DHCPDISCOVER of the Wireshark sample capture: DHCP Message Type 1, a
#: Client-identifier of the client's MAC address, a Requested IP Address of
#: 0.0.0.0 and a Parameter Request List of 1, 3, 6 and 42, then End and seven
#: octets of padding.
DISCOVER = header() + COOKIE + bytes.fromhex('350101' '3d0701000b8201fc42' '320400000000' '3704010306' '2a' 'ff') \
    + bytes(7)

#: Its DHCPOFFER of 192.168.0.10: Subnet Mask, Renewal (T1) Time, Rebinding (T2)
#: Time, IP Address Lease Time and Server Identifier, End and 26 octets of padding.
OFFER = (header(2, yiaddr=bytes((192, 168, 0, 10))) + COOKIE
         + bytes.fromhex('350102' '0104ffffff00' '3a0400000708' '3b0400000c4e' '330400000e10' '3604c0a80001' 'ff')
         + bytes(26))

#: A BOOTREQUEST with RFC 1497 vendor extensions -- Subnet Mask and Host Name --
#: and an IP Address Lease Time, a DHCP option a BOOTP message leaves undecoded.
BOOTREQUEST = (header(sname=b'server', file=b'boot/image') + COOKIE
               + bytes.fromhex('0104ffffff00' '0c04686f7374' '330400000e10' 'ff') + bytes(43))


def dhcp(*options: bytes, padding: bytes = b'', **kwargs: object) -> bytes:
    """A DHCPDISCOVER carrying ``options`` after its DHCP Message Type option, then End."""
    return header(**kwargs) + COOKIE + b'\x35\x01\x01' + b''.join(options) + b'\xff' + padding  # type: ignore[arg-type]


def opt(code: int, data: bytes) -> bytes:
    """An option of ``code`` carrying ``data``."""
    return bytes((code, len(data))) + data


class DHCPTestCase(unittest.TestCase):
    """Shared helpers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertRoundTrip(self, octets: bytes, member: str = 'DHCPv4') -> object:
        """Parse ``octets`` through the family base, and hold both rebuilds to them."""
        from pcapkit.protocols.application.dhcp.protocol import DHCP

        parsed = DHCP(octets)
        self.assertEqual(type(parsed).__name__, member)
        self.assertEqual(parsed.data, octets)
        self.assertEqual(DHCP.from_data(parsed.info).data, octets)
        self.assertEqual(type(parsed).from_data(parsed.info.to_dict()).data, octets)
        self.assertEqual(DHCP.from_data(parsed.info).info, parsed.info)
        return parsed

    def option(self, octets: bytes, code: int) -> object:
        """The option of ``code`` that ``octets`` carry, after a round trip."""
        info = self.assertRoundTrip(octets).info  # type: ignore[attr-defined]
        found = [option for option in info.options if option.code == code]
        self.assertEqual(len(found), 1)
        return found[0]


class HeaderTests(DHCPTestCase):
    """The fixed header and the options of the sample exchange."""

    def test_discover_fields(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.dhcp.message_type import MessageType
        from pcapkit.const.dhcp.opcode import Opcode
        from pcapkit.const.dhcp.option import Option
        from pcapkit.protocols.application.dhcp.data import Address, ClientIdentifier
        from pcapkit.protocols.application.dhcp.data import MessageType as Data_MessageType
        from pcapkit.protocols.application.dhcp.data import ParameterList

        parsed = self.assertRoundTrip(DISCOVER)
        info = parsed.info
        self.assertEqual(info.op, Opcode.BOOTREQUEST)
        self.assertEqual(info.htype, Hardware.Ethernet)
        self.assertEqual((info.hlen, info.hops, info.xid, info.secs), (6, 0, 0x3D1D, 0))
        self.assertEqual((info.flags.broadcast, info.flags.reserved), (False, 0))
        self.assertEqual(info.ciaddr, ipaddress.IPv4Address('0.0.0.0'))
        self.assertEqual(info.chaddr, '00:0b:82:01:fc:42')
        self.assertEqual(info.chaddr_padding, bytes(10))
        self.assertEqual((info.sname, info.file), (b'', b''))
        self.assertEqual(info.magic_cookie, COOKIE)
        self.assertEqual([option.code for option in info.options],
                         [Option.DHCP_Msg_Type, Option.Client_Id, Option.Address_Request, Option.Parameter_List,
                          Option.End])
        self.assertEqual(info.options[0].data, Data_MessageType(type=MessageType.DHCPDISCOVER))
        self.assertEqual(info.options[1].data, ClientIdentifier(type=Hardware.Ethernet, identifier='00:0b:82:01:fc:42'))
        self.assertEqual(info.options[2].data, Address(address=ipaddress.IPv4Address('0.0.0.0')))
        self.assertEqual(info.options[3].data,
                         ParameterList(codes=(Option.Subnet_Mask, Option.Router, Option.Domain_Server,
                                              Option.NTP_Servers)))
        self.assertEqual((info.options[4].length, info.options[4].data), (None, None))
        self.assertEqual(info.padding, bytes(7))
        self.assertEqual(parsed.length, len(DISCOVER))
        self.assertEqual(parsed.message_type, MessageType.DHCPDISCOVER)

    def test_offer_fields(self) -> None:
        from pcapkit.const.dhcp.opcode import Opcode
        from pcapkit.protocols.application.dhcp.data import Address, Number

        info = self.assertRoundTrip(OFFER).info
        self.assertEqual(info.op, Opcode.BOOTREPLY)
        self.assertEqual(info.yiaddr, ipaddress.IPv4Address('192.168.0.10'))
        self.assertEqual([option.data for option in info.options[1:6]], [
            Address(address=ipaddress.IPv4Address('255.255.255.0')),
            Number(value=1800), Number(value=3150), Number(value=3600),
            Address(address=ipaddress.IPv4Address('192.168.0.1')),
        ])

    def test_names_and_selectors(self) -> None:
        from pcapkit.protocols.application.dhcp.protocol import DHCP

        dhcp_ = DHCP(DISCOVER)
        bootp = DHCP(BOOTREQUEST)
        self.assertEqual((dhcp_.alias, dhcp_.name, dhcp_.info_name), ('DHCP', 'Dynamic Host Configuration Protocol', 'dhcp'))
        self.assertEqual((bootp.alias, bootp.name, bootp.info_name), ('BOOTP', 'Bootstrap Protocol', 'dhcp'))
        self.assertEqual(DHCP.id(), ('DHCP', 'BOOTP'))
        self.assertEqual((type(dhcp_).id(), type(bootp).id()), (('DHCP',), ('BOOTP',)))
        self.assertEqual((int(DHCP.__index__()), int(type(dhcp_).__index__()), int(type(bootp).__index__())),
                         (67, 67, 67))
        self.assertEqual(len(dhcp_), len(DISCOVER))

    def test_flags_and_chaddr(self) -> None:
        octets = dhcp(flags=0x8001, chaddr=bytes(range(1, 8)))
        info = self.assertRoundTrip(octets).info
        self.assertEqual((info.flags.broadcast, info.flags.reserved), (True, 1))
        # NOTE: Seven octets are no MAC address, so they are kept as octets.
        self.assertEqual((info.hlen, info.chaddr, info.chaddr_padding), (7, bytes(range(1, 8)), bytes(9)))

    def test_text_fields_keep_what_follows_a_nul(self) -> None:
        octets = dhcp(sname=b'srv\x00junk', file=b'pxelinux.0')
        info = self.assertRoundTrip(octets).info
        self.assertEqual((info.sname, info.file), (b'srv\x00junk', b'pxelinux.0'))


class DispatchTests(DHCPTestCase):
    """The family base picks the member, and UDP ports 67 and 68 reach it."""

    def test_base_picks_the_member(self) -> None:
        from pcapkit.protocols.application.bootp.protocol import BOOTP
        from pcapkit.protocols.application.dhcp.protocol import DHCP
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

        self.assertIs(type(DHCP(DISCOVER)), DHCPv4)
        self.assertIs(type(DHCP(BOOTREQUEST)), BOOTP)
        self.assertIs(type(DHCP(header() + b'vendor')), BOOTP)
        # NOTE: Option 53 counts whole before an option runs past the area, and not after.
        self.assertIs(type(DHCP(header() + COOKIE + b'\x35\x01\x01\x0c\x09ab')), DHCPv4)
        self.assertIs(type(DHCP(header() + COOKIE + b'\x0c\x09ab\x35\x01\x01')), BOOTP)
        self.assertIs(type(DHCP(header() + COOKIE + b'\x35\x01')), BOOTP)

    def test_message_type_in_an_overloaded_field(self) -> None:
        from pcapkit.protocols.application.dhcp.protocol import DHCP
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

        octets = header(file=b'\x35\x01\x03\xff') + COOKIE + b'\x34\x01\x01\xff'
        self.assertIs(type(DHCP(octets)), DHCPv4)
        self.assertRoundTrip(octets)
        # NOTE: The file field is read before sname, so an option running past it hides sname's.
        octets = header(file=bytes(126) + b'\x0c\x05', sname=b'\x35\x01\x01\xff') + COOKIE + b'\x34\x01\x03\xff'
        self.assertIs(type(DHCP(octets)).__name__, 'BOOTP')

    def test_an_overloaded_field_an_option_runs_past(self) -> None:
        from pcapkit.protocols.application.dhcp.data import OverloadedField, Text

        # NOTE: Option 53 in the options field, and a file field whose last option runs past it.
        file = b'\x43\x03abc' + bytes(118) + b'\x0c\x09abc'
        octets = header(file=file) + COOKIE + b'\x35\x01\x01\x34\x01\x01\xff'
        info = self.assertRoundTrip(octets).info
        self.assertIsInstance(info.file, OverloadedField)
        self.assertEqual(info.file.padding, b'\x0c\x09abc')
        self.assertEqual(info.file.options[0].data, Text(text='abc'))
        self.assertEqual(len(info.file.options), 119)
        # NOTE: The file field is whole, so no cut is recorded.
        self.assertNotIn('__short_read__', info)

    def test_base_refuses_fields_and_a_dict(self) -> None:
        from pcapkit.protocols.application.dhcp.protocol import DHCP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, '^DHCP: no member to build with'):
            DHCP(xid=1)
        with self.assertRaisesRegex(ProtocolError, '^DHCP: no member to build with'):
            DHCP.from_fields(xid=1)
        with self.assertRaisesRegex(ProtocolError, '^DHCP: invalid data'):
            DHCP.from_data(DHCP(DISCOVER).info.to_dict())
        with self.assertRaises(TypeError):
            DHCP(None)

    def test_base_reads_a_stream_without_consuming_it(self) -> None:
        import io

        from pcapkit.protocols.application.dhcp.protocol import DHCP

        stream = io.BytesIO(OFFER)
        parsed = DHCP(stream, len(OFFER))
        self.assertEqual((type(parsed).__name__, parsed.data), ('DHCPv4', OFFER))

    def test_udp_ports_dispatch_the_base(self) -> None:
        from pcapkit.protocols.transport.udp.protocol import UDP

        for ports, message, alias in (((68, 67), DISCOVER, 'DHCP'), ((67, 68), OFFER, 'DHCP'),
                                      ((67, 67), BOOTREQUEST, 'BOOTP')):
            with self.subTest(ports=ports):
                datagram = struct.pack('!HHHH', *ports, 8 + len(message), 0) + message
                udp = UDP(datagram)
                self.assertEqual(str(udp.protochain), f'UDP:{alias}')
                self.assertIn('DHCP', udp)
                self.assertEqual(udp.payload.data, message)

    def test_members_refuse_each_other(self) -> None:
        from pcapkit.protocols.application.bootp.protocol import BOOTP
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, '^BOOTP: invalid format: the DHCP Message Type option'):
            BOOTP(DISCOVER)
        with self.assertRaisesRegex(ProtocolError, '^DHCP: invalid format: no DHCP Message Type option'):
            DHCPv4(BOOTREQUEST)
        with self.assertRaisesRegex(ProtocolError, '^DHCP: invalid format: no magic cookie'):
            DHCPv4(header() + b'\x35\x01\x01\xff')
        with self.assertRaisesRegex(ProtocolError, '^DHCP: invalid format: no DHCP Message Type option'):
            DHCPv4(header() + COOKIE + b'\x0c\x09ab\x35\x01\x01')
        with self.assertRaisesRegex(ProtocolError, '^BOOTP: the DHCP Message Type option makes a DHCP message'):
            BOOTP(vend=[{'code': 53, 'data': b'\x01'}])
        with self.assertRaisesRegex(ProtocolError, '^DHCP: no DHCP Message Type option'):
            DHCPv4(options=[{'code': 255}])

    def test_register_option_warns_on_a_different_entry(self) -> None:
        from pcapkit.const.dhcp.option import Option
        from pcapkit.protocols.application.dhcp.protocol import DHCP
        from pcapkit.utilities.warnings import RegistryWarning

        saved = dict(DHCP.__option__)
        try:
            DHCP.register_option(Option.Subnet_Mask, 'address')
            with self.assertWarns(RegistryWarning):
                DHCP.register_option(Option.Subnet_Mask, 'text')
            # NOTE: A pair of callables is read and made through as a name is.
            DHCP.register_option(Option.Vendor_Specific, (lambda code, data: {'raw': data},
                                                          lambda code, data: bytes(data['raw'])))
            built = type(DHCP(DISCOVER)).from_fields(options=[{'code': 53, 'data': {'type': 1}},
                                                               {'code': 43, 'data': {'raw': b'ab'}}])
            self.assertEqual(DHCP(built.data).info.options[1].data, {'raw': b'ab'})
        finally:
            DHCP.__option__.clear()
            DHCP.__option__.update(saved)

    def test_registry_wrapper(self) -> None:
        from pcapkit.const.dhcp.option import Option
        from pcapkit.foundation.registry import register_dhcp_option
        from pcapkit.protocols.application.dhcp.protocol import DHCP
        from pcapkit.utilities.exceptions import RegistryError

        with self.assertRaises(RegistryError):
            register_dhcp_option(Option.Vendor_Specific, 'nosuch')
        saved = dict(DHCP.__option__)
        try:
            register_dhcp_option(Option.Vendor_Specific, 'text')
            info = self.assertRoundTrip(dhcp(opt(43, b'vendor'))).info
            self.assertEqual(info.options[1].data.text, 'vendor')
        finally:
            DHCP.__option__.clear()
            DHCP.__option__.update(saved)


class CutTests(DHCPTestCase):
    """A DHCP message a capture cuts inside its options parses, and rebuilds as captured."""

    def test_discover_cut_inside_an_option(self) -> None:
        from pcapkit.const.dhcp.option import Option

        # NOTE: 244 cuts the Client-identifier after its code, 250 inside its data,
        # 260 the Parameter Request List after its length, and 247 inside the identifier.
        for size, codes, padding in ((244, [Option.DHCP_Msg_Type], b'\x3d'),
                                     (247, [Option.DHCP_Msg_Type], DISCOVER[243:247]),
                                     (250, [Option.DHCP_Msg_Type], DISCOVER[243:250]),
                                     (260, [Option.DHCP_Msg_Type, Option.Client_Id, Option.Address_Request],
                                      DISCOVER[258:260])):
            with self.subTest(size=size):
                info = self.assertRoundTrip(DISCOVER[:size]).info
                self.assertEqual([option.code for option in info.options], codes)
                self.assertEqual(info.padding, padding)
                self.assertEqual(info['__short_read__'], ('options', size - 236))

    def test_discover_cut_between_options(self) -> None:
        # NOTE: 243 ends the area after option 53, and 270 inside the padding after End.
        for size in (243, 270):
            with self.subTest(size=size):
                info = self.assertRoundTrip(DISCOVER[:size]).info
                self.assertNotIn('__short_read__', info)
        self.assertEqual(len(self.assertRoundTrip(DISCOVER[:243]).info.options), 1)  # type: ignore[attr-defined]

    @unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
    def test_snaplen_cut_inside_a_frame(self) -> None:
        import os
        import tempfile

        import pcapkit
        from pcapkit.protocols.application.dhcp.protocol import DHCP

        datagram = struct.pack('!HHHH', 68, 67, 8 + len(DISCOVER), 0) + DISCOVER
        packet = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(datagram), 1, 0, 64, 17, 0,
                             bytes(4), b'\xff' * 4) + datagram
        frame = b'\xff' * 6 + bytes.fromhex('000b8201fc42') + b'\x08\x00' + packet
        captured = 14 + 20 + 8 + 250
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-dhcp-')
        self.addCleanup(tmpdir.cleanup)
        path = os.path.join(tmpdir.name, 'cut.pcap')
        with open(path, 'wb') as file:
            file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, captured, 1))
            file.write(struct.pack('<IIII', 1600000000, 0, captured, len(frame)) + frame[:captured])

        extraction = pcapkit.extract(fin=path, store=True)
        self.addCleanup(close_extractor, extraction)
        layer = extraction.frame[0]['DHCP']
        self.assertEqual(str(extraction.frame[0].protochain), 'Ethernet:IPv4:UDP:DHCP')
        self.assertEqual(layer.data, DISCOVER[:250])
        self.assertEqual(layer.info['__short_read__'], ('options', 14))
        self.assertEqual(DHCP.from_data(layer.info).data, DISCOVER[:250])


class BOOTPTests(DHCPTestCase):
    """A BOOTP message decodes its vendor extensions alone."""

    def test_vendor_extensions(self) -> None:
        from pcapkit.protocols.application.dhcp.data import Address, Text

        info = self.assertRoundTrip(BOOTREQUEST, 'BOOTP').info
        self.assertEqual((info.sname, info.file, info.magic_cookie), (b'server', b'boot/image', COOKIE))
        self.assertEqual(info.vend[0].data, Address(address=ipaddress.IPv4Address('255.255.255.0')))
        self.assertEqual(info.vend[1].data, Text(text='host'))
        # NOTE: IP Address Lease Time is a DHCP extension (RFC 2132 section 9.2).
        self.assertEqual(info.vend[2].data, bytes.fromhex('00000e10'))
        self.assertEqual(info.padding, bytes(43))

    def test_vendor_specific_area(self) -> None:
        octets = header() + b'vendor-specific octets'.ljust(64, b'\x00')
        info = self.assertRoundTrip(octets, 'BOOTP').info
        self.assertIsNone(info.magic_cookie)
        self.assertEqual((info.vend, info.padding), (octets[236:], b''))
        # NOTE: A vendor extension the area ends inside is its padding, and a cut.
        cut = self.assertRoundTrip(header() + COOKIE + b'\x01\x04\xff\xff\xff\x00\x01\x09\x00', 'BOOTP').info
        self.assertEqual((len(cut.vend), cut.magic_cookie, cut.padding), (1, COOKIE, b'\x01\x09\x00'))
        self.assertEqual(cut['__short_read__'], ('options', 13))

    def test_make(self) -> None:
        from pcapkit.protocols.application.bootp.protocol import BOOTP
        from pcapkit.utilities.exceptions import ProtocolError

        built = BOOTP(op=1, chaddr='00:0b:82:01:fc:42', xid=0x3D1D, sname=b'server', file=b'boot/image',
                      vend=[{'code': 1, 'data': {'address': '255.255.255.0'}}, {'code': 12, 'data': {'text': 'host'}},
                            {'code': 51, 'data': bytes.fromhex('00000e10')}, {'code': 255}], padding=bytes(43))
        self.assertEqual(built.data, BOOTREQUEST)
        self.assertEqual(BOOTP().data, header(chaddr=b'', xid=0) + COOKIE)
        self.assertEqual(BOOTP(vend=b'raw').data[236:], b'raw')
        with self.assertRaisesRegex(ProtocolError, '^BOOTP: no constructor for option'):
            BOOTP(vend=[{'code': 51, 'data': {'value': 1}}])
        with self.assertRaisesRegex(ProtocolError, '^BOOTP: invalid padding: raw vendor octets'):
            BOOTP(vend=b'raw', padding=b'\x00')
        with self.assertRaisesRegex(ProtocolError, '^BOOTP: invalid vendor area'):
            BOOTP(vend=5)
        with self.assertRaisesRegex(ProtocolError, '^BOOTP: invalid server host name'):
            BOOTP(sname=bytes(65))


class DHCPv4Tests(DHCPTestCase):
    """A DHCP message's overloaded fields, repeated options and construction."""

    def test_overloaded_fields(self) -> None:
        from pcapkit.protocols.application.dhcp.data import Overload, OverloadedField, Text

        octets = (header(file=b'\x43\x0apxelinux.0\xff', sname=b'\x42\x03srv\xff') + COOKIE
                  + b'\x35\x01\x05\x34\x01\x03\xff')
        info = self.assertRoundTrip(octets).info
        self.assertEqual(info.options[1].data, Overload(file=True, sname=True))
        self.assertIsInstance(info.file, OverloadedField)
        self.assertEqual(info.file.options[0].data, Text(text='pxelinux.0'))
        self.assertEqual(info.file.padding, bytes(128 - 13))
        self.assertEqual(info.sname.options[0].data, Text(text='srv'))
        self.assertEqual(len(info.sname.padding), 64 - 6)

    def test_repeated_options_keep_their_octets(self) -> None:
        # NOTE: RFC 3396 section 7 concatenates the instances, so no one of them is read.
        info = self.assertRoundTrip(dhcp(opt(3, bytes((10, 0, 0, 1))), opt(3, bytes((10, 0, 0, 2))))).info
        self.assertEqual([option.data for option in info.options[1:3]],
                         [bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))])

    def test_pad_options(self) -> None:
        from pcapkit.const.dhcp.option import Option

        info = self.assertRoundTrip(dhcp(b'\x00\x00', padding=b'\x00tail')).info
        self.assertEqual([option.code for option in info.options],
                         [Option.DHCP_Msg_Type, Option.Pad, Option.Pad, Option.End])
        self.assertEqual(info.padding, b'\x00tail')
        # NOTE: An area no End option ends reads to its end, with no padding.
        info = self.assertRoundTrip(header() + COOKIE + b'\x35\x01\x01').info
        self.assertEqual((len(info.options), info.padding), (1, b''))

    def test_make(self) -> None:
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

        built = DHCPv4(op=1, xid=0x3D1D, chaddr='00:0b:82:01:fc:42', options=[
            {'code': 53, 'data': {'type': 1}},
            {'code': 61, 'data': {'type': 1, 'identifier': '00:0b:82:01:fc:42'}},
            {'code': 50, 'data': {'address': '0.0.0.0'}},
            {'code': 55, 'data': {'codes': [1, 3, 6, 42]}},
            {'code': 255},
        ], padding=bytes(7))
        self.assertEqual(built.data, DISCOVER)
        overloaded = DHCPv4(file={'options': [{'code': 67, 'data': {'text': 'pxelinux.0'}}, {'code': 255}]},
                            options=[{'code': 53, 'data': {'type': 5}}, {'code': 52, 'data': {'file': True}},
                                     {'code': 255}])
        self.assertEqual(overloaded.data[108:121], b'\x43\x0apxelinux.0\xff')
        self.assertRoundTrip(overloaded.data)

    def test_make_refusals(self) -> None:
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4
        from pcapkit.utilities.exceptions import ProtocolError

        base = [{'code': 53, 'data': {'type': 1}}]
        cases = (
            ({'file': {'options': [{'code': 255}]}, 'options': [*base, {'code': 255}]}, 'it holds options exactly'),
            ({'options': [*base, {'code': 52, 'data': {'sname': True}}, {'code': 255}]}, 'it holds options exactly'),
            ({'options': [*base, {'code': 255}, {'code': 0}]}, 'an option follows the End option'),
            ({'options': [*base, {'code': 255, 'data': b'x'}]}, 'it carries no length or data'),
            ({'options': base, 'padding': b'\x00'}, 'no End option ends the options'),
            ({'options': base, 'padding': b'\x0c\x02a\x0c'}, 'no End option ends the options'),
            ({'options': base, 'file': {'options': [], 'padding': b'\x0c\x09abc'}},
             'it holds options exactly'),
            ({'options': base, 'padding': 'x'}, 'invalid padding'),
            ({'options': [*base, {'code': 12, 'data': bytes(256)}]}, 'exceed one option'),
            ({'options': [*base, {'code': 3, 'data': {}}, {'code': 3, 'data': {}}]}, 'no constructor for option'),
            ({'options': [*base, {'code': 43, 'data': {'x': 1}}]}, 'no constructor for option'),
            ({'options': [*base, 'x']}, 'invalid option'),
            ({'options': base, 'chaddr': 5}, 'invalid client hardware address'),
            ({'options': base, 'chaddr': bytes(17)}, 'must be 16 octets'),
            ({'options': base, 'chaddr_padding': 'x'}, 'invalid client hardware address padding'),
            ({'options': base, 'sname': {'options': [{'code': 12, 'data': bytes(80)}, {'code': 255}]},
              }, 'it holds options exactly'),
            ({'options': base, 'flags': 0x10000}, 'flags'),
            ({'options': base, 'htype': 32, 'chaddr': 'aa:bb'}, 'invalid client hardware address'),
        )
        for kwargs, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ProtocolError, message):
                DHCPv4(**kwargs)
        with self.assertRaisesRegex(ProtocolError, 'invalid overloaded field'):
            DHCPv4(sname={'options': [{'code': 12, 'data': bytes(80)}, {'code': 255}]},
                   options=[*base, {'code': 52, 'data': {'sname': True}}, {'code': 255}])
        # NOTE: An option an overloaded field ends inside has to run to its end.
        with self.assertRaisesRegex(ProtocolError, 'invalid overloaded field'):
            DHCPv4(sname={'options': [], 'padding': b'\x0c\x09abc'},
                   options=[*base, {'code': 52, 'data': {'sname': True}}, {'code': 255}])

    def test_make_an_option_the_area_ends_inside(self) -> None:
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

        built = DHCPv4(xid=0x3D1D, chaddr='00:0b:82:01:fc:42', options=[{'code': 53, 'data': {'type': 1}}],
                       padding=b'\x3d\x07\x01')
        self.assertEqual(built.data, DISCOVER[:246])

    def test_make_flags_and_hardware_address(self) -> None:
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

        built = DHCPv4(flags=0x8000, htype=6, chaddr='02:00:00:00:00:01', chaddr_padding=b'x' * 10,
                       options=[{'code': 53, 'data': {'type': 1}}])
        info = self.assertRoundTrip(built.data).info
        self.assertEqual((info.flags.broadcast, info.chaddr, info.chaddr_padding),
                         (True, '02:00:00:00:00:01', b'x' * 10))


class OptionTests(DHCPTestCase):
    """Each option decodes as its RFC defines it, and keeps its octets otherwise."""

    def assertOption(self, code: int, data: bytes, expected: object) -> None:
        """``data`` under ``code`` decodes to ``expected``, and rebuilds."""
        self.assertEqual(self.option(dhcp(opt(code, data)), code).data, expected)  # type: ignore[attr-defined]

    def assertRaw(self, code: int, data: bytes) -> None:
        """``data`` under ``code`` is malformed, and keeps its octets."""
        self.assertEqual(self.option(dhcp(opt(code, data)), code).data, data)  # type: ignore[attr-defined]

    def test_rfc2132_options(self) -> None:
        from pcapkit.const.dhcp.option import Option
        from pcapkit.protocols.application.dhcp import data as D

        address = ipaddress.IPv4Address
        cases = (
            (2, b'\xff\xff\xf1\xf0', D.Number(value=-3600)),
            (3, bytes((10, 0, 0, 1, 10, 0, 0, 2)), D.Addresses(addresses=(address('10.0.0.1'), address('10.0.0.2')))),
            (13, b'\x00\x10', D.Number(value=16)),
            (19, b'\x01', D.Boolean(value=True)),
            (21, bytes((10, 0, 0, 0, 255, 0, 0, 0)),
             D.PolicyFilter(filters=(D.AddressMask(address=address('10.0.0.0'), mask=address('255.0.0.0')),))),
            (22, b'\x02\x40', D.Number(value=576)),
            (23, b'\x40', D.Number(value=64)),
            (25, b'\x00\x44\x05\xdc', D.Sizes(sizes=(68, 1500))),
            (33, bytes((10, 0, 0, 0, 10, 0, 0, 1)),
             D.StaticRoutes(routes=(D.Route(destination=address('10.0.0.0'), router=address('10.0.0.1')),))),
            (46, b'\x08', D.NodeType(node_type=8)),
            (55, b'\x01\x79', D.ParameterList(codes=(Option.Subnet_Mask, Option.Classless_Static_Route_Option))),
            (56, b'no lease', D.Text(text='no lease')),
            (61, b'\x00client', D.ClientIdentifier(type=0, identifier=b'client')),
            (68, b'', D.Addresses(addresses=())),
        )
        for code, data, expected in cases:
            with self.subTest(code=code):
                self.assertOption(code, data, expected)

    def test_rfc2132_refusals(self) -> None:
        cases = (
            (1, b'\xff\xff\xff'), (2, b'\x00'), (3, b''), (3, bytes(5)), (12, b''), (12, b'h\xe9'),
            (13, b'\x00'), (19, b'\x02'), (21, bytes(4)), (22, b'\x02\x3f'), (23, b'\x00'), (25, b''),
            (25, b'\x00\x43'), (26, b'\x00\x43'), (33, b''), (46, b'\x03'), (52, b'\x04'),
            (55, b''), (61, b'\x01'), (68, bytes(3)),
        )
        for code, data in cases:
            with self.subTest(code=code, data=data):
                self.assertRaw(code, data)

    def test_user_class(self) -> None:
        from pcapkit.protocols.application.dhcp.data import UserClass

        self.assertOption(77, b'\x03abc\x01d', UserClass(classes=(b'abc', b'd')))
        for data in (b'', b'\x00', b'\x05ab'):
            with self.subTest(data=data):
                self.assertRaw(77, data)

    def test_client_fqdn(self) -> None:
        from pcapkit.protocols.application.dhcp.data import ClientFQDN, FQDNFlags

        wire = b'\x04host\x07example\x03com\x00'
        self.assertOption(81, b'\x05\x00\x00' + wire,
                          ClientFQDN(flags=FQDNFlags(n=False, e=True, o=False, s=True, mbz=0),
                                     rcode1=0, rcode2=0, name='host.example.com.'))
        # NOTE: A partial name has no root label (RFC 4702 section 2.3.1).
        self.assertOption(81, b'\x04\x00\x00\x04host', ClientFQDN(
            flags=FQDNFlags(n=False, e=True, o=False, s=False, mbz=0), rcode1=0, rcode2=0, name='host'))
        self.assertOption(81, b'\x18\xff\xffhost.example', ClientFQDN(
            flags=FQDNFlags(n=True, e=False, o=False, s=False, mbz=1), rcode1=255, rcode2=255, name='host.example'))
        for data in (b'\x04\x00', b'\x04\x00\x00\x04ho', b'\x04\x00\x00\x00x', b'\x04\x00\x00\x40' + bytes(64)):
            with self.subTest(data=data):
                self.assertRaw(81, data)

    def test_relay_agent_information(self) -> None:
        from pcapkit.const.dhcp.relay_agent_suboption import RelayAgentSubOption
        from pcapkit.protocols.application.dhcp.data import RelayAgentInformation
        from pcapkit.protocols.application.dhcp.data import RelayAgentSubOption as Sub

        self.assertOption(82, b'\x01\x04eth0\x02\x02r1', RelayAgentInformation(suboptions=(
            Sub(code=RelayAgentSubOption.Agent_Circuit_ID_Sub_option, length=4, data=b'eth0'),
            Sub(code=RelayAgentSubOption.Agent_Remote_ID_Sub_option, length=2, data=b'r1'),
        )))
        for data in (b'', b'\x01\x05eth0'):
            with self.subTest(data=data):
                self.assertRaw(82, data)
        # NOTE: A sub-option code IANA lists nowhere, 0 or 200, is Unassigned.
        info = self.option(dhcp(opt(82, b'\x00\x01x\xc8\x00')), 82).data
        self.assertEqual([(int(sub.code), sub.code.name, sub.data) for sub in info.suboptions],
                         [(0, 'Unassigned', b'x'), (200, 'Unassigned', b'')])

    def test_pxe_options(self) -> None:
        from pcapkit.protocols.application.dhcp.data import (ArchitectureTypes, ClientNDI,
                                                             MachineIdentifier)

        self.assertOption(93, b'\x00\x00\x00\x07', ArchitectureTypes(types=(0, 7)))
        self.assertOption(94, b'\x01\x02\x01', ClientNDI(type=1, major=2, minor=1))
        self.assertOption(97, b'\x00' + bytes(range(16)), MachineIdentifier(type=0, identifier=bytes(range(16))))
        for code, data in ((93, b''), (93, b'\x00'), (94, b'\x01\x02'), (97, bytes(16))):
            with self.subTest(code=code):
                self.assertRaw(code, data)

    def test_domain_search(self) -> None:
        from pcapkit.protocols.application.dhcp.data import DomainName, DomainSearch

        # NOTE: The example of RFC 3397 section 2: the second name points into the first.
        data = b'\x03eng\x05apple\x03com\x00\x09marketing\xc0\x04'
        self.assertOption(119, data, DomainSearch(names=(
            DomainName(name='eng.apple.com.', labels=(b'eng', b'apple', b'com'), literal=3, pointer=None),
            DomainName(name='marketing.apple.com.', labels=(b'marketing', b'apple', b'com'), literal=1, pointer=4),
        )))
        for data in (b'', b'\x03eng', b'\xc0\x00'):
            with self.subTest(data=data):
                self.assertRaw(119, data)

    def test_classless_static_routes(self) -> None:
        from pcapkit.protocols.application.dhcp.data import ClasslessRoute, ClasslessStaticRoutes

        # NOTE: RFC 3442 section 2's own encodings: 0/0, 10.0.0.0/8 and 10.17.0.0/16.
        data = b'\x00\x0a\x00\x00\x01' + b'\x08\x0a\x0a\x00\x00\x01' + b'\x10\x0a\x11\x0a\x00\x00\x02'
        self.assertOption(121, data, ClasslessStaticRoutes(routes=(
            ClasslessRoute(destination=ipaddress.IPv4Network('0.0.0.0/0'), router=ipaddress.IPv4Address('10.0.0.1')),
            ClasslessRoute(destination=ipaddress.IPv4Network('10.0.0.0/8'),
                           router=ipaddress.IPv4Address('10.0.0.1')),
            ClasslessRoute(destination=ipaddress.IPv4Network('10.17.0.0/16'),
                           router=ipaddress.IPv4Address('10.0.0.2')),
        )))
        for data in (b'\x00\x0a\x00\x00', b'\x21' + bytes(8), b'\x18\x0a\x00\x00', b'\x07\x0b\x0a\x00\x00\x01'):
            with self.subTest(data=data):
                self.assertRaw(121, data)

    def test_vendor_identifying_options(self) -> None:
        from pcapkit.protocols.application.dhcp.data import (VendorClass, VendorClassEntry,
                                                             VendorOption, VendorOptions,
                                                             VendorSpecific)

        self.assertOption(124, b'\x00\x00\x0d\xe9\x05\x04docs', VendorClass(vendors=(
            VendorClassEntry(enterprise=3561, classes=(b'docs',)),)))
        self.assertOption(125, b'\x00\x00\x0d\xe9\x04\x01\x02ab', VendorSpecific(vendors=(
            VendorOptions(enterprise=3561, options=(VendorOption(code=1, data=b'ab'),)),)))
        for code, data in ((124, b''), (124, b'\x00\x00\x0d\xe9\x05'), (125, b'\x00\x00\x0d\xe9\x02\x01\x05')):
            with self.subTest(code=code, data=data):
                self.assertRaw(code, data)

    def test_later_simple_options(self) -> None:
        from pcapkit.protocols.application.dhcp.data import Address, Boolean, Number, Text

        self.assertOption(108, b'\x00\x00\x07\x08', Number(value=1800))
        self.assertOption(114, b'https://portal.example/', Text(text='https://portal.example/'))
        self.assertOption(116, b'\x00', Boolean(value=False))
        self.assertOption(118, bytes((192, 0, 2, 0)), Address(address=ipaddress.IPv4Address('192.0.2.0')))

    def test_malformed_message_type_keeps_its_octets(self) -> None:
        parsed = self.assertRoundTrip(header() + COOKIE + b'\x35\x00\xff')
        self.assertEqual(parsed.info.options[0].data, b'')  # type: ignore[attr-defined]
        self.assertIsNone(parsed.message_type)  # type: ignore[attr-defined]

    def test_unregistered_option_keeps_its_octets(self) -> None:
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

        built = DHCPv4(options=[{'code': 53, 'data': {'type': 1}}, {'code': 200}])
        self.assertEqual(built.data[240:], b'\x35\x01\x01\xc8\x00')
        self.assertEqual(self.option(dhcp(opt(43, b'\x01\x02ab')), 43).data, b'\x01\x02ab')
        self.assertEqual(self.option(dhcp(opt(200, b'x')), 200).data, b'x')

    def test_makers(self) -> None:
        """What a maker writes parses back to the same fields."""
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

        cases = (
            (2, {'value': -1}), (3, {'addresses': ['10.0.0.1']}), (12, {'text': 'host'}), (13, {'value': 2}),
            (19, {'value': True}), (21, {'filters': [{'address': '10.0.0.0', 'mask': '255.0.0.0'}]}),
            (22, {'value': 1500}), (23, {'value': 64}), (24, {'value': 600}), (25, {'sizes': [68, 1500]}),
            (33, {'routes': [{'destination': '10.0.0.0', 'router': '10.0.0.1'}]}), (46, {'node_type': 2}),
            (52, {'sname': False, 'file': True}), (55, {'codes': [1, 3]}), (61, {'type': 0, 'identifier': b'id'}),
            (68, {'addresses': []}), (77, {'classes': [b'a', b'bc']}),
            (81, {'flags': {'e': True, 'n': True}, 'name': 'host.example.'}),
            (81, {'flags': 0x00, 'rcode1': 255, 'name': 'host'}),
            (82, {'suboptions': [{'code': 1, 'data': b'eth0'}, {'code': 2, 'data': b'ab', 'length': 2}]}),
            (93, {'types': [7]}), (94, {'type': 1, 'major': 3, 'minor': 10}),
            (97, {'type': 0, 'identifier': bytes(range(16))}),
            (119, {'names': ['example.com', {'labels': (b'sub', b'example', b'com'), 'literal': 1, 'pointer': 0}]}),
            (121, {'routes': [{'destination': '192.168.1.0/24', 'router': '10.0.0.1'}]}),
            (124, {'vendors': [{'enterprise': 9, 'classes': [b'x']}]}),
            (125, {'vendors': [{'enterprise': 9, 'options': [{'code': 1, 'data': b'x'}]}]}),
            (116, {'value': True}), (118, {'address': '192.0.2.1'}),
        )
        for code, fields in cases:
            with self.subTest(code=code, fields=fields):
                options = [{'code': 53, 'data': {'type': 1}}, {'code': code, 'data': fields}, {'code': 255}]
                if code == 52:
                    built = DHCPv4(options=options, file={'options': [{'code': 255}]})
                else:
                    built = DHCPv4(options=options)
                parsed = self.assertRoundTrip(built.data)
                self.assertNotIsInstance(parsed.info.options[1].data, bytes)  # type: ignore[attr-defined]

    def test_maker_refusals(self) -> None:
        from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4
        from pcapkit.utilities.exceptions import FieldValueError, ProtocolError

        cases = (
            (3, {}), (12, {}), (12, {'text': 'h\xe9'}), (21, {}), (21, {'filters': ['x']}), (22, {'value': 575}),
            (25, {}), (25, {'sizes': [67]}), (46, {'node_type': 3}), (52, {}), (55, {}), (61, {'identifier': b''}),
            (61, {'type': 6, 'identifier': 5}), (77, {}), (77, {'classes': [b'']}), (77, {'classes': [bytes(256)]}),
            (81, {'flags': {'e': True}, 'name': 5}), (82, {}), (82, {'suboptions': ['x']}),
            (82, {'suboptions': [{'data': 'x'}]}), (93, {}), (119, {}), (119, {'names': [5]}),
            (121, {}), (121, {'routes': ['x']}), (121, {'routes': [{'destination': '10.0.0.1/8'}]}),
            (124, {}), (124, {'vendors': ['x']}), (124, {'vendors': [{'classes': [bytes(255)]}]}),
            (125, {'vendors': [{'options': ['x']}]}), (125, {'vendors': [{'options': [{'data': 'x'}]}]}),
            (97, {'identifier': bytes(15)}), (12, {'text': 5}),
        )
        for code, fields in cases:
            with self.subTest(code=code, fields=fields), self.assertRaises((ProtocolError, FieldValueError)):
                DHCPv4(options=[{'code': 53, 'data': {'type': 1}}, {'code': code, 'data': fields}, {'code': 255}])


if __name__ == '__main__':
    unittest.main()
