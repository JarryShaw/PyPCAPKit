# -*- coding: utf-8 -*-
"""ICMPv6 decodes Neighbor Discovery (RFC 4861) and its options. C.f. #2934.

Types 133 to 137 parse into their own data models, their options into theirs, and
both rebuild byte for byte through ``from_data``, whole or cut by the capture. The
cuts here are hand-picked, and :mod:`tests.protocols.internet.test_icmpv6_nd_every_cut_2934_unit`
makes the same checks at every octet. Each message and option is built here against
its RFC layout; this module is unit-tier and reads no capture.

"""

import io
import ipaddress
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Iterable

#: Test tier (#1958): hand-picked parse -> rebuild round trips; the sweep of every
#: cut is ``LATEST``, as the tier rule has it (#1732, #1958).
__tier__ = 'ALL'

#: The addresses the messages name, as on the wire.
TARGET = ipaddress.IPv6Address('fe80::1').packed
DESTINATION = ipaddress.IPv6Address('2001:db8::1').packed

#: An IPv6 header (next header UDP) and a UDP header, as a Redirect quotes them.
QUOTED = (bytes.fromhex('6000000000081140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
          + bytes.fromhex('3039003500080000'))

#: Options, by name: type, Length in 8-octet units, then the fields of each RFC.
OPTIONS = {
    # RFC 4861 section 4.6.1: an Ethernet address.
    'slla': bytes.fromhex('0101' '001122334455'),
    'tlla': bytes.fromhex('0201' '00aabbccddee'),
    # RFC 4861 section 4.6.2: /64, L, A and P, Reserved1 3, lifetimes, Reserved2.
    'pio': bytes.fromhex('0304' '40' 'd3' '00278d00' '00093a80' '00000000' '20010db8000100000000000000000000'),
    # RFC 4861 section 4.6.3: six reserved octets, then the redirected packet.
    'rh': bytes.fromhex('0407' '000000000000') + QUOTED,
    # RFC 4861 section 4.6.4.
    'mtu': bytes.fromhex('0501' '0000' '000005dc'),
    # RFC 6275 sections 7.3 and 7.4.
    'adv_interval': bytes.fromhex('0701' '0000' '000927c0'),
    'ha_info': bytes.fromhex('0801' '0000' '000a' '0708'),
    # RFC 3971 section 5.3.2.
    'nonce': bytes.fromhex('0e01' '010203040506'),
    # RFC 4191 section 2.3: /48, Prf 01 (High), 8 octets of prefix.
    'rio': bytes.fromhex('1802' '30' '08' '00000e10' '20010db800020000'),
    # RFC 8106 section 5.1: two servers.
    'rdnss': bytes.fromhex('1905' '0000' '00000e10' '20010db8000000000000000000000053'
                           '20010db8000000000000000000000035'),
    # RFC 5175 section 4: bit 55, IANA's Private Experimentation.
    'ra_flags': bytes.fromhex('1a01' '000000000001'),
    # RFC 8106 section 5.2: two names, uncompressed, then six octets of zero padding.
    'dnssl': (bytes.fromhex('1f05' '0000' '00000e10') + b'\x07example\x03com\x00' + b'\x07example\x03net\x00'
              + bytes(6)),
    # RFC 8910 section 2.3: the URI, then NUL padding.
    'captive': bytes.fromhex('2504') + b'https://portal.example/api' + bytes(4),
    # RFC 8781 section 4: Scaled Lifetime 225, PLC 1 (/64), 96 bits of prefix.
    'pref64': bytes.fromhex('2602' '0709' '20010db80064000000000000'),
    # Undecoded: CGA (RFC 3971) and an unassigned type.
    'cga': bytes.fromhex('0b01' 'a1a2a3a4a5a6'),
    'unassigned': bytes.fromhex('c801' 'b1b2b3b4b5b6'),
}

#: Each message: type, code, checksum, its fixed fields (RFC 4861 section 4), options.
RS = bytes.fromhex('8500' 'abcd' '00000000') + OPTIONS['slla']
RA = (bytes.fromhex('8600' 'abcd' '40' '88' '0708' '00007530' '000003e8')
      + b''.join(OPTIONS[name] for name in ('slla', 'mtu', 'pio', 'rio', 'rdnss', 'dnssl', 'ra_flags', 'captive',
                                            'pref64', 'adv_interval', 'ha_info', 'cga', 'unassigned')))
NS = bytes.fromhex('8700' 'abcd' '00000000') + TARGET + OPTIONS['slla'] + OPTIONS['nonce']
NA = bytes.fromhex('8800' 'abcd' 'e0000005') + TARGET + OPTIONS['tlla']
REDIRECT = bytes.fromhex('8900' 'abcd' '00000000') + TARGET + DESTINATION + OPTIONS['tlla'] + OPTIONS['rh']

#: Every message above, by name.
MESSAGES = {'rs': RS, 'ra': RA, 'ns': NS, 'na': NA, 'redirect': REDIRECT}

#: The data model each message parses into.
MODELS = {'rs': 'RouterSolicitation', 'ra': 'RouterAdvertisement', 'ns': 'NeighborSolicitation',
          'na': 'NeighborAdvertisement', 'redirect': 'Redirect'}

#: Hand-picked cuts of each message of :data:`MESSAGES`, in octets kept: inside the
#: fixed fields, an option cut before or just past its Length, a DNSSL name cut, and
#: a cut that leaves no option. Traced to reach every line and branch the sweep does.
PICKED_CUTS = {'rs': (4, 9), 'ra': (81, 82, 129, 242), 'ns': (34,), 'na': (24, 25), 'redirect': (50,)}


def ipv6(payload: bytes, length: int) -> bytes:
    """An IPv6 header carrying ICMPv6 and declaring ``length`` payload octets, then ``payload``."""
    return (bytes.fromhex('60000000') + length.to_bytes(2, 'big') + bytes([58, 255])
            + bytes.fromhex('fe80' + '0' * 26 + '01') + bytes.fromhex('ff02' + '0' * 26 + '01') + payload)


def parse(packet: bytes) -> 'object':
    """``packet`` parsed on its own."""
    from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return ICMPv6(io.BytesIO(packet), len(packet))


class NDParseTests(unittest.TestCase):
    """Each message and option reads as its RFC lays it out."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_router_solicitation(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.protocols.internet.icmpv6.data import LinkLayerAddressOption, RouterSolicitation

        info = parse(RS).info
        self.assertIs(type(info), RouterSolicitation)
        self.assertEqual((info.type, info.code, info.length), (Type.Router_Solicitation, 0, 16))
        self.assertEqual(info.reserved, bytes(4))
        option, = info.options.values()
        self.assertIs(type(option), LinkLayerAddressOption)
        self.assertEqual((option.type, option.length), (NDOption.Source_Link_layer_Address, 8))
        self.assertEqual(option.link_layer_address, bytes.fromhex('001122334455'))

    def test_router_advertisement(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.const.icmpv6.router_preference import RouterPreference
        from pcapkit.protocols.internet.icmpv6.data import RouterAdvertisement

        info = parse(RA).info
        self.assertIs(type(info), RouterAdvertisement)
        self.assertEqual(info.cur_hop_limit, 64)
        self.assertEqual((info.m_flag, info.o_flag, info.h_flag, info.p_flag, info.s_flag, info.reserved),
                         (True, False, False, False, False, 0))
        self.assertIs(info.prf, RouterPreference.High)
        self.assertEqual((info.router_lifetime, info.reachable_time, info.retrans_timer), (1800, 30000, 1000))
        self.assertEqual(list(info.options), [
            NDOption.Source_Link_layer_Address, NDOption.MTU, NDOption.Prefix_Information,
            NDOption.Route_Information_Option, NDOption.Recursive_DNS_Server_Option,
            NDOption.DNS_Search_List_Option, NDOption.RA_Flags_Extension_Option, NDOption.DHCP_Captive_Portal,
            NDOption.PREF64_option, NDOption.Advertisement_Interval_Option,
            NDOption.Home_Agent_Information_Option, NDOption.CGA_option, 200,
        ])

    def test_each_ra_flag_is_its_own_bit(self) -> None:
        """M, O, H, Prf, P, S and the reserved bit, as IANA's registry places them (RFC 5175)."""
        from pcapkit.const.icmpv6.router_preference import RouterPreference

        for octet, expected in ((0x80, ('m_flag',)), (0x40, ('o_flag',)), (0x20, ('h_flag',)),
                                (0x04, ('p_flag',)), (0x02, ('s_flag',)), (0x01, ('reserved',))):
            packet = bytearray(RA[:16])
            packet[5] = octet
            with self.subTest(octet=octet):
                info = parse(bytes(packet)).info
                for name in ('m_flag', 'o_flag', 'h_flag', 'p_flag', 's_flag', 'reserved'):
                    self.assertEqual(bool(info[name]), name in expected, name)
                self.assertIs(info.prf, RouterPreference.Medium)
        for bits, prf in ((0b00, RouterPreference.Medium), (0b01, RouterPreference.High),
                          (0b10, RouterPreference.Reserved_2), (0b11, RouterPreference.Low)):
            packet = bytearray(RA[:16])
            packet[5] = bits << 3
            with self.subTest(prf=prf):
                self.assertIs(parse(bytes(packet)).info.prf, prf)

    def test_neighbor_solicitation_and_advertisement(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.protocols.internet.icmpv6.data import (NeighborAdvertisement, NeighborSolicitation,
                                                            NonceOption)

        info = parse(NS).info
        self.assertIs(type(info), NeighborSolicitation)
        self.assertEqual(info.target_address, ipaddress.IPv6Address('fe80::1'))
        nonce = info.options[NDOption.Nonce_option]
        self.assertIs(type(nonce), NonceOption)
        self.assertEqual(nonce.nonce, bytes(range(1, 7)))

        info = parse(NA).info
        self.assertIs(type(info), NeighborAdvertisement)
        self.assertEqual((info.r_flag, info.s_flag, info.o_flag, info.reserved), (True, True, True, 5))
        self.assertEqual(info.target_address, ipaddress.IPv6Address('fe80::1'))
        self.assertEqual(info.options[NDOption.Target_Link_layer_Address].link_layer_address,
                         bytes.fromhex('00aabbccddee'))

    def test_redirect(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.protocols.internet.icmpv6.data import Redirect, RedirectedHeaderOption

        info = parse(REDIRECT).info
        self.assertIs(type(info), Redirect)
        self.assertEqual(info.target_address, ipaddress.IPv6Address('fe80::1'))
        self.assertEqual(info.destination_address, ipaddress.IPv6Address('2001:db8::1'))
        header = info.options[NDOption.Redirected_Header]
        self.assertIs(type(header), RedirectedHeaderOption)
        self.assertEqual((header.length, header.reserved, header.data), (56, bytes(6), QUOTED))

    def test_options(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.const.icmpv6.router_preference import RouterPreference

        options = parse(RA).info.options

        mtu = options[NDOption.MTU]
        self.assertEqual((mtu.length, mtu.reserved, mtu.mtu), (8, b'\x00\x00', 1500))

        pio = options[NDOption.Prefix_Information]
        self.assertEqual((pio.length, pio.prefix_length), (32, 64))
        self.assertEqual((pio.l_flag, pio.a_flag, pio.r_flag, pio.p_flag, pio.reserved1),
                         (True, True, False, True, 3))
        self.assertEqual((pio.valid_lifetime, pio.preferred_lifetime), (2592000, 604800))
        self.assertEqual(pio.prefix, ipaddress.IPv6Address('2001:db8:1::'))

        rio = options[NDOption.Route_Information_Option]
        self.assertEqual((rio.length, rio.prefix_length, rio.lifetime), (16, 48, 3600))
        self.assertEqual((rio.reserved1, rio.prf, rio.reserved2), (0, RouterPreference.High, 0))
        self.assertEqual(rio.prefix, ipaddress.IPv6Address('2001:db8:2::'))

        rdnss = options[NDOption.Recursive_DNS_Server_Option]
        self.assertEqual((rdnss.length, rdnss.lifetime), (40, 3600))
        self.assertEqual(rdnss.addresses, (ipaddress.IPv6Address('2001:db8::53'),
                                           ipaddress.IPv6Address('2001:db8::35')))

        dnssl = options[NDOption.DNS_Search_List_Option]
        self.assertEqual((dnssl.length, dnssl.lifetime), (40, 3600))
        self.assertEqual(dnssl.domain_names, ('example.com.', 'example.net.'))
        self.assertEqual(dnssl.padding, bytes(6))

        self.assertEqual(options[NDOption.RA_Flags_Extension_Option].bits, bytes.fromhex('000000000001'))

        captive = options[NDOption.DHCP_Captive_Portal]
        self.assertEqual((captive.length, captive.uri, captive.padding),
                         (32, b'https://portal.example/api', bytes(4)))

        pref64 = options[NDOption.PREF64_option]
        self.assertEqual((pref64.scaled_lifetime, pref64.lifetime, pref64.plc, pref64.prefix_length),
                         (225, 1800, 1, 64))
        self.assertEqual(pref64.prefix, ipaddress.IPv6Address('2001:db8:64::'))

        self.assertEqual(options[NDOption.Advertisement_Interval_Option].interval, 600000)
        ha_info = options[NDOption.Home_Agent_Information_Option]
        self.assertEqual((ha_info.preference, ha_info.lifetime), (10, 1800))

    def test_options_not_decoded_keep_their_octets(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.protocols.internet.icmpv6.data import UnknownOption

        options = parse(RA).info.options
        for code, data in ((NDOption.CGA_option, 'a1a2a3a4a5a6'), (200, 'b1b2b3b4b5b6')):
            with self.subTest(code=code):
                option = options[code]
                self.assertIs(type(option), UnknownOption)
                self.assertEqual((option.length, option.data.hex()), (8, data))

    def test_a_pref64_code_with_no_length_decodes_to_none(self) -> None:
        packet = RS[:8] + bytes.fromhex('2602' '0006') + bytes(12)
        self.assertIsNone(parse(packet).info.options[38].prefix_length)

    def test_a_route_prefix_is_as_long_as_the_length_leaves(self) -> None:
        for length, prefix in ((1, b''), (2, bytes.fromhex('20010db800020000')),
                               (3, bytes.fromhex('20010db8000200000000000000000001'))):
            option = bytes([24, length, 128 if length == 3 else 0, 0]) + bytes(4) + prefix
            with self.subTest(length=length):
                info = parse(RS[:8] + option).info
                self.assertEqual(info.options[24].prefix.packed, prefix.ljust(16, b'\x00'))

    def test_malformed_options_are_refused(self) -> None:
        """A Length of zero, or one the option's layout does not fill, is refused (RFC 4861 section 4.6)."""
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        for name, option in (
                ('zero length', bytes.fromhex('0100') + bytes(6)),
                ('zero length, unknown type', bytes.fromhex('c800') + bytes(6)),
                ('short Prefix Information', bytes.fromhex('0303') + bytes(30)),
                ('long MTU', bytes.fromhex('0502') + bytes(14)),
                ('even RDNSS', bytes.fromhex('1904') + bytes(30)),
                ('long Route Information', bytes.fromhex('1804') + bytes(30)),
                ('compressed DNSSL name', bytes.fromhex('1f02' '0000' '00000000' 'c00c') + bytes(6)),
                ('DNSSL name past the option', bytes.fromhex('1f02' '0000' '00000000' '09') + bytes(7)),
        ):
            packet = RS[:8] + option
            with self.subTest(option=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with self.assertRaises(ProtocolError):
                    ICMPv6(io.BytesIO(packet), len(packet))

    def test_dns_options_below_their_minimum_length_are_refused(self) -> None:
        """RDNSS takes an odd Length of 3 or more, DNSSL one of 2 or more (RFC 8106 section 5.3.1).

        On its own the message refuses; behind IPv6 it stays raw, quietly.

        """
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import logger
        from tests.utilities._harness import capture

        for name, option, error in (
                ('RDNSS of Length 1', bytes.fromhex('1901' '0000' '00000e10'), 'RDNSS option length: 1'),
                ('RDNSS of Length 2', bytes.fromhex('1902' '0000' '00000e10') + bytes(8),
                 'RDNSS option length: 2'),
                ('DNSSL of Length 1', bytes.fromhex('1f01' '0000' '00000e10'), 'DNSSL option length: 1'),
        ):
            packet = RS[:8] + option
            with self.subTest(option=name, where='on its own'), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with self.assertRaisesRegex(ProtocolError, error):
                    ICMPv6(io.BytesIO(packet), len(packet))
            frame = ipv6(packet, len(packet))
            with self.subTest(option=name, where='behind IPv6'), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with capture(logger) as recorder:
                    layer = IPv6(io.BytesIO(frame), len(frame)).payload
                self.assertIs(type(layer), Raw)
                self.assertIn(error, str(layer.info.error))
                self.assertEqual(recorder.messages, [])

    def test_cut_options_that_do_not_rebuild_are_refused(self) -> None:
        """A cut option stands only if its zeros parse and its maker writes the octets captured back."""
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        for name, option in (
                ('Route Information the reader refuses', bytes.fromhex('1804') + bytes(10)),
                ('Prefix Information of Length 1', bytes.fromhex('0301') + bytes(10)),
        ):
            packet = RS[:8] + option
            with self.subTest(option=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with self.assertRaises(ProtocolError):
                    ICMPv6(io.BytesIO(packet), len(packet))

    def test_a_malformed_option_behind_ipv6_leaves_the_message_raw(self) -> None:
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.misc.raw.protocol import Raw

        packet = RS[:8] + bytes.fromhex('0100') + bytes(6)
        frame = ipv6(packet, len(packet))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            layer = IPv6(io.BytesIO(frame), len(frame)).payload
        self.assertIsInstance(layer, Raw)


class NDCutMixin:
    """The checks on each message cut, at its :data:`PICKED_CUTS` or at every octet.

    A plain class, so only the test case each tier's module builds on it is
    collected: :class:`NDRoundTripTests` here, and the ``LATEST`` sweep's,
    which sets :attr:`sweep`.

    """

    #: Whether to cut each message at every octet rather than at its picked cuts.
    sweep = False

    def setUp(self) -> None:
        reimport_once_per_class(self)  # type: ignore[arg-type]

    def cuts(self, name: str) -> 'Iterable[int]':
        """The octets of message ``name`` of :data:`MESSAGES` to keep."""
        return range(4, len(MESSAGES[name])) if self.sweep else PICKED_CUTS[name]

    def assert_rebuilds(self, parsed: 'object', captured: bytes) -> None:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            rebuilt = ICMPv6.from_data(parsed.info)
            redict = ICMPv6.from_data(parsed.info.to_dict())
        self.assertEqual(rebuilt.data.hex(), captured.hex())  # type: ignore[attr-defined]
        self.assertEqual(rebuilt.info, parsed.info)  # type: ignore[attr-defined]
        self.assertEqual(redict.data.hex(), captured.hex())  # type: ignore[attr-defined]

    def test_cuts_behind_ipv6(self) -> None:
        """Cut behind an IPv6 header declaring the whole message."""
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for name, packet in MESSAGES.items():
            model = MODELS[name]
            for cut in self.cuts(name):
                with self.subTest(message=name, cut=cut), warnings.catch_warnings():  # type: ignore[attr-defined]
                    warnings.simplefilter('ignore')
                    frame = ipv6(packet[:cut], len(packet))
                    layer = IPv6(io.BytesIO(frame), len(frame)).payload
                    self.assertIsInstance(layer, ICMPv6)  # type: ignore[attr-defined]
                    self.assertEqual(type(layer.info).__name__, model)  # type: ignore[attr-defined]
                    self.assert_rebuilds(layer, packet[:cut])

    def test_cuts_on_their_own(self) -> None:
        """Cut and parsed with no enclosing length, quietly.

        A cut between two options leaves a whole message with fewer of them, and
        records nothing.

        """
        from pcapkit.utilities.warnings import SchemaWarning

        for name, packet in MESSAGES.items():
            model = MODELS[name]
            for cut in self.cuts(name):
                part = packet[:cut]
                with self.subTest(message=name, cut=cut), warnings.catch_warnings(record=True) as caught:  # type: ignore[attr-defined]
                    warnings.simplefilter('always')
                    parsed = parse(part)
                    self.assertEqual(type(parsed.info).__name__, model)  # type: ignore[attr-defined]
                    if cut >= 8:
                        self.assertFalse([item for item in caught  # type: ignore[attr-defined]
                                          if issubclass(item.category, SchemaWarning)])
                    self.assert_rebuilds(parsed, part)


class NDRoundTripTests(NDCutMixin, unittest.TestCase):
    """Each message rebuilds byte for byte, whole or cut."""

    def test_whole_messages(self) -> None:
        for name, packet in MESSAGES.items():
            with self.subTest(message=name):
                parsed = parse(packet)
                self.assertEqual(type(parsed.info).__name__, MODELS[name])
                self.assert_rebuilds(parsed, packet)

    def test_an_option_cut_before_its_length_reads_undecoded(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.protocols.internet.icmpv6.data import UnknownOption

        parsed = parse(RS[:9])
        option = parsed.info.options[NDOption.Source_Link_layer_Address]
        self.assertIs(type(option), UnknownOption)
        self.assertEqual((option.length, option.data), (0, b''))
        self.assert_rebuilds(parsed, RS[:9])

    def test_cut_rdnss_addresses_read_as_zeros(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption

        option = OPTIONS['rdnss']
        parsed = parse(RS[:8] + option[:8])
        self.assertEqual(parsed.info.options[NDOption.Recursive_DNS_Server_Option].addresses,
                         (ipaddress.IPv6Address(0),) * 2)
        self.assert_rebuilds(parsed, RS[:8] + option[:8])

    def test_make_then_parse(self) -> None:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        for name, packet in MESSAGES.items():
            with self.subTest(message=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                info = parse(packet).info
                self.assertEqual(type(info).__name__, MODELS[name])
                made = ICMPv6.from_fields(type=info.type, code=0, checksum=b'\xab\xcd', body=info)
                self.assertEqual(bytes(made).hex(), packet.hex())


class NDMakeTests(unittest.TestCase):
    """Building Neighbor Discovery messages from fields."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def make(self, type_: int, **body: 'object') -> bytes:
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        return bytes(object.__new__(ICMPv6).make(type=type_, checksum=b'\xab\xcd', body=body))

    def test_router_advertisement_from_fields(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.const.icmpv6.router_preference import RouterPreference

        packet = self.make(134, cur_hop_limit=64, m_flag=True, prf=RouterPreference.High, router_lifetime=1800,
                           reachable_time=30000, retrans_timer=1000, options=[
                               (NDOption.Source_Link_layer_Address,
                                {'link_layer_address': bytes.fromhex('001122334455')}),
                               (5, {'mtu': 1500}),
                               (3, {'prefix_length': 64, 'l_flag': True, 'a_flag': True, 'p_flag': True,
                                    'reserved1': 3, 'valid_lifetime': 2592000, 'preferred_lifetime': 604800,
                                    'prefix': '2001:db8:1::'}),
                               (24, {'prefix_length': 48, 'prf': 1, 'lifetime': 3600, 'prefix': '2001:db8:2::'}),
                               (25, {'lifetime': 3600, 'addresses': ['2001:db8::53', '2001:db8::35']}),
                               (31, {'lifetime': 3600, 'domain_names': ['example.com', 'example.net.']}),
                               (26, {'bits': bytes.fromhex('000000000001')}),
                               (37, {'uri': b'https://portal.example/api'}),
                               (38, {'lifetime': 1800, 'prefix_length': 64, 'prefix': '2001:db8:64::'}),
                               (7, {'interval': 600000}),
                               (8, {'preference': 10, 'lifetime': 1800}),
                               (11, {'data': bytes.fromhex('a1a2a3a4a5a6')}),
                               (200, {'data': bytes.fromhex('b1b2b3b4b5b6')}),
                           ])
        self.assertEqual(packet.hex(), RA.hex())

    def test_other_messages_from_fields(self) -> None:
        tlla = (2, {'link_layer_address': bytes.fromhex('00aabbccddee')})
        self.assertEqual(self.make(133), RS[:8])
        self.assertEqual(self.make(133, options=[(1, {'link_layer_address': bytes.fromhex('001122334455')})]), RS)
        self.assertEqual(self.make(135, target_address='fe80::1', options=[
            (1, {'link_layer_address': bytes.fromhex('001122334455')}), (14, {'nonce': bytes(range(1, 7))}),
        ]), NS)
        self.assertEqual(self.make(136, r_flag=True, s_flag=True, o_flag=True, reserved=5, target_address='fe80::1',
                                   options=[tlla]), NA)
        self.assertEqual(self.make(137, target_address='fe80::1', destination_address='2001:db8::1',
                                   options=[tlla, (4, {'data': QUOTED})]), REDIRECT)

    def test_options_given_as_octets_or_schemas(self) -> None:
        from pcapkit.protocols.internet.icmpv6.schema import MTUOption

        schema = MTUOption(type=5, length=1, reserved=b'\x00\x00', mtu=1500)
        self.assertEqual(self.make(133, options=[OPTIONS['slla'], schema]), RS + OPTIONS['mtu'])

    def test_a_route_option_takes_the_length_it_is_given(self) -> None:
        packet = self.make(133, options=[(24, {'length': 24, 'prefix_length': 48, 'prefix': '2001:db8:2::'})])
        self.assertEqual(packet[8:].hex(), '1803' '30' '00' '00000000' '20010db8000200000000000000000000')
        packet = self.make(133, options=[(24, {})])
        self.assertEqual(packet[8:].hex(), '1801' '00' '00' '00000000')

    def test_refusals(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError, ProtocolError

        for type_, body in (
                (134, {'cur_hop_limit': 256}),
                (134, {'m_flag': 2}),
                (134, {'prf': 4}),
                (134, {'prf': 'High'}),
                (134, {'reserved': 2}),
                (134, {'router_lifetime': -1}),
                (133, {'reserved': b'\x00'}),
                (136, {'reserved': 1 << 29}),
                (136, {'o_flag': 'yes'}),
                (133, {'options': [('MTU', {})]}),
                (133, {'options': [(True, {})]}),
                (133, {'options': [(256, {})]}),
                (133, {'options': [(1, {'link_layer_address': bytes(5)})]}),
                (133, {'options': [(1, {'link_layer_address': 'aa:bb'})]}),
                (133, {'options': [(200, {'data': bytes(2041)})]}),
                (133, {'options': [(200, {'data': 'raw'})]}),
                (133, {'options': [(3, {'prefix_length': 129 * 2})]}),
                (133, {'options': [(3, {'reserved2': b''})]}),
                (133, {'options': [(4, {'data': bytes(3)})]}),
                (133, {'options': [(4, {'data': 'raw'})]}),
                (133, {'options': [(14, {'nonce': 'raw'})]}),
                (133, {'options': [(26, {'bits': 'raw'})]}),
                (133, {'options': [(5, {'mtu': 1 << 32})]}),
                (133, {'options': [(14, {'nonce': bytes(7)})]}),
                (133, {'options': [(24, {'length': 32})]}),
                (133, {'options': [(24, {'prefix_length': 48, 'prefix': '2001:db8:0:0:1::'})]}),
                (133, {'options': [(24, {'prefix_length': 0, 'prefix': '2001:db8::'})]}),
                (133, {'options': [(24, {'prf': 'Low'})]}),
                (133, {'options': [(25, {'lifetime': 1 << 32})]}),
                (133, {'options': [(25, {'addresses': []})]}),
                (133, {'options': [(26, {'bits': bytes(5)})]}),
                (133, {'options': [(31, {'domain_names': ['a..b']})]}),
                (133, {'options': [(31, {'domain_names': ['example.com', '.']})]}),
                (133, {'options': [(31, {'padding': b'\x01'})]}),
                (133, {'options': [(31, {})]}),
                (133, {'options': [(37, {'uri': b'a\x00b'})]}),
                (133, {'options': [(37, {'padding': b'x'})]}),
                (133, {'options': [(38, {'lifetime': 7})]}),
                (133, {'options': [(38, {'prefix_length': 60})]}),
                (133, {'options': [(38, {'prefix': '2001:db8::1'})]}),
                (133, {'options': [(38, {'plc': 8})]}),
                (133, {'options': [(38, {'scaled_lifetime': 1 << 13})]}),
        ):
            with self.subTest(type=type_, body=body), self.assertRaises((ProtocolError, FieldValueError)):
                self.make(type_, **body)


class NDRegistryTests(unittest.TestCase):
    """:func:`~pcapkit.foundation.registry.protocols.internet.register_icmpv6_option`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_registered_pair_reads_and_makes_the_option(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.foundation.registry.protocols.internet import register_icmpv6_option
        from pcapkit.protocols.internet.icmpv6.data import UnknownOption
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.protocols.internet.icmpv6.schema import UnknownOption as Schema_UnknownOption

        def parser(schema: 'object', *, options: 'object') -> 'object':  # pylint: disable=unused-argument
            return UnknownOption(type=schema.type, length=schema.length * 8, data=schema.data[::-1])

        def maker(code: 'object', option: 'object' = None, **kwargs: 'object') -> 'object':  # pylint: disable=unused-argument
            return Schema_UnknownOption(type=code, length=1, data=option.data[::-1])

        saved = dict(ICMPv6.__option__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                register_icmpv6_option(NDOption.CGA_option, (parser, maker))
            packet = RS + OPTIONS['cga']
            parsed = parse(packet)
            self.assertEqual(parsed.info.options[NDOption.CGA_option].data.hex(), 'a6a5a4a3a2a1')
            self.assertEqual(ICMPv6.from_data(parsed.info).data.hex(), packet.hex())
        finally:
            ICMPv6.__option__.clear()
            ICMPv6.__option__.update(saved)

    def test_register_option_warns_on_a_different_entry(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.utilities.warnings import RegistryWarning

        saved = dict(ICMPv6.__option__)
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                ICMPv6.register_option(NDOption.MTU, 'mtu')
                self.assertFalse([item for item in caught if issubclass(item.category, RegistryWarning)])
                ICMPv6.register_option(NDOption.MTU, 'none')
                self.assertTrue([item for item in caught if issubclass(item.category, RegistryWarning)])
            self.assertEqual(ICMPv6.__option__[NDOption.MTU], 'none')
        finally:
            ICMPv6.__option__.clear()
            ICMPv6.__option__.update(saved)

    def test_refusals(self) -> None:
        from pcapkit.const.icmpv6.nd_option import NDOption
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.foundation.registry.protocols.internet import register_icmpv6_option
        from pcapkit.utilities.exceptions import RegistryError

        for code, meth in ((Type.Router_Solicitation, 'mtu'), (NDOption.MTU, 'nosuch'), (NDOption.MTU, 42)):
            with self.subTest(code=code, meth=meth), self.assertRaises(RegistryError):
                register_icmpv6_option(code, meth)  # type: ignore[arg-type]


if __name__ == '__main__':
    unittest.main()
