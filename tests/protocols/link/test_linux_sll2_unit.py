# -*- coding: utf-8 -*-
"""GitHub issue #2438: the Linux "cooked" capture encapsulation v2 (``LINUX_SLL2``).

Covers the 20-octet header, the same ``arphrd_type``-gated next-layer rule as
v1 (see :data:`~pcapkit.protocols.link.linux_sll._ARPHRD_NOT_ETHERTYPE`),
link-address validation, and byte-exact round trips.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))


def _header(protocol_type: int, reserved: int, interface_index: int, arphrd_type: int,
            packet_type: int, link_addr: bytes, link_addr_length: int) -> bytes:
    """Pack a ``LINUX_SLL2`` header: see the module docstring for the layout."""
    padded = link_addr.ljust(8, b'\x00')[:8]
    return struct.pack('>HHIHBB', protocol_type, reserved, interface_index, arphrd_type,
                       packet_type, link_addr_length) + padded


def _pcap(records: 'list[bytes]') -> bytes:
    from pcapkit.const.reg.linktype import LinkType

    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, LinkType.LINUX_SLL2)
    for record in records:
        data += struct.pack('<IIII', 1500000000, 0, len(record), len(record)) + record
    return data


def _sll(protocol_type: int, arphrd_type: int) -> bytes:
    """A minimal header carrying ``protocol_type`` on ``arphrd_type``."""
    return _header(protocol_type, 0, 1, arphrd_type, 0, b'', 0)


class TestLinuxSLL2(unittest.TestCase):
    """Pin the ``LINUX_SLL2`` layer, alone and under full extraction."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def test_ethernet_arphrd_dispatches_by_ethertype(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        raw = _header(0x0800, 0, 7, Hardware.Ethernet, 0, bytes.fromhex('001122334455'), 6) + IPV4
        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.protocol_type, 0x0800)
        self.assertEqual(parsed.info.reserved, 0)
        self.assertEqual(parsed.info.interface_index, 7)
        self.assertEqual(parsed.info.arphrd_type, Hardware.Ethernet)
        self.assertEqual(parsed.info.packet_type, 0)
        self.assertEqual(parsed.info.link_addr_length, 6)
        self.assertEqual(parsed.info.link_addr, bytes.fromhex('0011223344550000'))
        self.assertEqual(parsed.protocol, 0x0800)
        self.assertEqual((parsed.name, parsed.length), ('Linux cooked capture encapsulation v2', 20))
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:IPv4:UDP')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_netlink_arphrd_dispatches_to_netlink(self) -> None:
        """``ARPHRD_NETLINK`` dispatches to
        :class:`~pcapkit.protocols.link.netlink.Netlink`, not
        :class:`~pcapkit.protocols.misc.raw.Raw` (:issue:`2500`), even though
        it too is in :data:`~pcapkit.protocols.link.linux_sll._ARPHRD_NOT_ETHERTYPE`.
        """
        import struct

        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.link.netlink import Netlink

        nlmsg = struct.pack('<IHHII', 20, 3, 0, 1, 0) + b'\xaa\xbb\xcc\xdd'
        raw = _header(0x0800, 0, 0, ARPHRD.NETLINK, 2, b'', 0) + nlmsg
        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.arphrd_type, ARPHRD.NETLINK)
        self.assertIsInstance(parsed.payload, Netlink)
        self.assertEqual(parsed.payload.info.nlmsg_type, 3)
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:Netlink:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_radiotap_arphrd_dispatches_to_radiotap(self) -> None:
        """GitHub issue #2502: ``ARPHRD_IEEE80211_RADIOTAP`` dispatches to
        :class:`~pcapkit.protocols.link.radiotap.Radiotap` rather than
        falling back to :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        radiotap = bytes.fromhex('00' '00' '0800' '00000000') + b'\xaa' * 10
        raw = _header(0x0800, 0, 0, ARPHRD.IEEE80211_RADIOTAP, 2, b'', 0) + radiotap
        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.arphrd_type, ARPHRD.IEEE80211_RADIOTAP)
        self.assertEqual(type(parsed.payload).__name__, 'Radiotap')
        self.assertEqual(parsed.payload.info.it_len, 8)
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:Radiotap:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_frad_arphrd_dispatches_to_frad(self) -> None:
        """GitHub issue #2460: ``ARPHRD_FRAD`` dispatches to
        :class:`~pcapkit.protocols.link.frad.FRAD` rather than falling back to
        :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        frad = bytes.fromhex('0c21') + b'\x03\xcc' + IPV4
        raw = _header(0x0800, 0, 0, ARPHRD.FRAD, 2, b'', 0) + frad
        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.arphrd_type, ARPHRD.FRAD)
        self.assertEqual(type(parsed.payload).__name__, 'FRAD')
        self.assertEqual(parsed.payload.info.dlci, 50)
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:FRAD:IPv4:UDP')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_frad_protocol_type_is_not_an_ethertype(self) -> None:
        """``ARPHRD_FRAD`` is in
        :data:`~pcapkit.protocols.link.linux_sll._ARPHRD_NOT_ETHERTYPE`, so its
        ``protocol_type`` is never looked up as an EtherType, per tcpdump.org's
        LINUX_SLL2 page (:issue:`2460`).
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll import (_ARPHRD_NOT_ETHERTYPE,
                                                      _resolve_next_layer_proto)

        self.assertIn(ARPHRD.FRAD, _ARPHRD_NOT_ETHERTYPE)
        proto = _resolve_next_layer_proto(ARPHRD.FRAD, 0x0800)
        self.assertIs(type(proto), int)
        self.assertEqual(proto, 0x0800)

    def test_truncated_frad_is_kept_raw_with_an_int_protocol(self) -> None:
        """A FRAD payload too short for its header is kept as
        :class:`~pcapkit.protocols.misc.raw.Raw`, which records
        ``protocol_type`` as a plain :class:`int`, not an EtherType member
        (:issue:`2460`).
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.misc.raw import Raw

        for size in (1, 2, 3):
            with self.subTest(size=size):
                raw = _header(0x0800, 0, 0, ARPHRD.FRAD, 2, b'', 0) + bytes.fromhex('0c2103')[:size]
                parsed = LinuxSLL2(raw, len(raw))
                self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:Raw')
                self.assertIsInstance(parsed.payload, Raw)
                self.assertIs(type(parsed.payload.info.protocol), int)
                self.assertEqual(parsed.payload.info.protocol, 0x0800)
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_ipgre_and_ip6gre_arphrd_dispatch_to_gre(self) -> None:
        """GitHub issue #2501: ``ARPHRD_IPGRE`` and ``ARPHRD_IP6GRE`` both
        dispatch to :class:`~pcapkit.protocols.link.gre.GRE` rather than
        falling back to :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        for arphrd in (ARPHRD.IPGRE, ARPHRD.IP6GRE):
            with self.subTest(arphrd=arphrd):
                gre = bytes.fromhex('00000800') + IPV4
                raw = _header(0x0800, 0, 0, arphrd, 2, b'', 0) + gre
                parsed = LinuxSLL2(raw, len(raw))
                self.assertEqual(parsed.info.arphrd_type, arphrd)
                self.assertEqual(type(parsed.payload).__name__, 'GRE')
                self.assertEqual(parsed.payload.info.protocol_type, 0x0800)
                self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:GRE:IPv4:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_non_ethernet_non_excluded_arphrds_still_dispatch_by_ethertype(self) -> None:
        """Loopback, PPP and SLIP/CSLIP are not among the exceptions, so
        ``protocol_type`` is still an EtherType for them.
        """
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        for arphrd, name in ((772, 'loopback'), (512, 'PPP'), (256, 'SLIP'), (257, 'CSLIP')):
            with self.subTest(arphrd=arphrd, name=name):
                raw = _header(0x0800, 0, 0, arphrd, 0, b'', 0) + IPV4
                parsed = LinuxSLL2(raw, len(raw))
                self.assertEqual(parsed.info.arphrd_type, arphrd)
                self.assertEqual(parsed.info.protocol_type, 0x0800)
                self.assertEqual(type(parsed.payload).__name__, 'IPv4')
                self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:IPv4:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_unregistered_ethertype_is_kept_raw_without_breaking_the_header(self) -> None:
        """An unregistered ``protocol_type`` must not blow up the header
        parse, exactly as v1 (see the sibling test on ``LinuxSLL1``).
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.misc.raw import Raw

        raw = _header(0x1234, 0, 0, Hardware.Ethernet, 0, b'', 0) + IPV4
        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.protocol_type, 0x1234)
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:<unassigned>')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    ##########################################################################
    # Raw fallback and registry overrides match Ethernet's.
    ##########################################################################

    @staticmethod
    def _ethernet(ether_type: int):  # type: ignore[no-untyped-def]
        """A bare Ethernet frame carrying ``ether_type``, for comparison."""
        from pcapkit.protocols.link.ethernet import Ethernet

        raw = bytes.fromhex('ffffffffffff001122334455') + struct.pack('>H', ether_type) + IPV4
        return Ethernet(raw, len(raw))

    def test_known_ethertype_without_a_dissector_matches_ethernet(self) -> None:
        """0x88CC (LLDP) is an assigned EtherType with no dissector: the
        :class:`~pcapkit.protocols.misc.raw.Raw` fallback records the
        EtherType member, as a bare Ethernet frame's does, not a bare int.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.misc.raw import Raw

        raw = _sll(0x88CC, Hardware.Ethernet) + IPV4
        parsed = LinuxSLL2(raw, len(raw))
        self.assertIsInstance(parsed.payload, Raw)
        self.assertIs(parsed.payload.info.protocol,
                      EtherType.IEEE_Std_802_1AB_Link_Layer_Discovery_Protocol)
        self.assertIs(self._ethernet(0x88CC).payload.info.protocol, parsed.payload.info.protocol)
        self._assert_rebuilds(parsed)

    def test_unassigned_ethertype_raw_fallback_records_the_value(self) -> None:
        """0x1234 is unassigned in EtherType: the
        :class:`~pcapkit.protocols.misc.raw.Raw` fallback records the
        ``<unassigned>`` pseudo-member a bare Ethernet frame's does.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.misc.raw import Raw

        raw = _sll(0x1234, Hardware.Ethernet) + IPV4
        parsed = LinuxSLL2(raw, len(raw))
        self.assertIsInstance(parsed.payload, Raw)
        ethernet = self._ethernet(0x1234)
        self.assertEqual(repr(parsed.payload.info.protocol), '<<unknown>.<unassigned>: 4660>')
        self.assertEqual(repr(parsed.payload.info.protocol), repr(ethernet.payload.info.protocol))
        self.assertEqual(ethernet.protochain.chain, 'Ethernet:<unassigned>')
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:<unassigned>')
        self._assert_rebuilds(parsed)

    def test_registered_override_is_reached_as_from_ethernet(self) -> None:
        """``Link.register(0x1234, IPv4)`` makes an unassigned EtherType reach
        IPv4 from an SLL frame, as it does from a bare Ethernet frame -- but
        not on a hardware type whose ``protocol_type`` is no EtherType.
        """
        import warnings

        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.link.netlink import Netlink

        registry = Link.__dict__['__proto__']
        had_original = 0x1234 in registry
        original = registry.get(0x1234)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                Link.register(0x1234, IPv4)  # type: ignore[arg-type]
            self.assertIsInstance(self._ethernet(0x1234).payload, IPv4)

            raw = _sll(0x1234, Hardware.Ethernet) + IPV4
            parsed = LinuxSLL2(raw, len(raw))
            self.assertIsInstance(parsed.payload, IPv4)
            self.assertEqual(parsed.protochain.chain, 'LINUX_SLL2:IPv4:UDP')
            self._assert_rebuilds(parsed)

            # A registered override on Link.__proto__ does not leak into
            # NETLINK's dispatch -- it never looks EtherType up at all.
            raw = _sll(0x1234, ARPHRD.NETLINK) + IPV4
            parsed = LinuxSLL2(raw, len(raw))
            self.assertIsInstance(parsed.payload, Netlink)
        finally:
            if had_original:
                registry[0x1234] = original
            else:
                registry.pop(0x1234, None)

    def test_reserved_and_padding_round_trip_even_when_non_zero(self) -> None:
        """``reserved`` and the padding beyond ``link_addr_length`` round-trip verbatim."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        raw = bytearray(_header(0x0800, 0, 0, Hardware.Ethernet, 0,
                                bytes.fromhex('0011223344'), 5) + IPV4)
        raw[2:4] = b'\xbe\xef'  # reserved, meant to be zero
        raw[17:20] = b'\xde\xad\xbe'  # padding tail of link_addr
        raw = bytes(raw)

        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.reserved, 0xbeef)
        self.assertEqual(parsed.info.link_addr, bytes.fromhex('0011223344') + b'\xde\xad\xbe')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_make_then_parse(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        made = LinuxSLL2(protocol_type=EtherType.Internet_Protocol_version_4, interface_index=3,
                         arphrd_type=Hardware.Ethernet, packet_type=4,
                         link_addr=bytes.fromhex('001122334455'), payload=IPV4).data
        self.assertEqual(made, _header(0x0800, 0, 3, 1, 4, bytes.fromhex('001122334455'), 6) + IPV4)

        parsed = LinuxSLL2(made, len(made))
        self.assertEqual(parsed.info.packet_type, 4)
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self._assert_rebuilds(parsed)

    def test_make_defaults(self) -> None:
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        self.assertEqual(LinuxSLL2().data, _header(0x0800, 0, 0, 1, 0, b'', 0))

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            LinuxSLL2(link_addr=bytes(9))
        # link_addr_length is a 1-octet field (0 to 0xFF).
        with self.assertRaises(ProtocolError):
            LinuxSLL2(link_addr_length=0x100)
        with self.assertRaises(ProtocolError):
            LinuxSLL2(link_addr_length=-1)

    def test_link_addr_length_over_8_round_trips(self) -> None:
        """A ``link_addr_length`` over 8 parses and rebuilds."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        raw = _header(0x0800, 0, 0, Hardware.Ethernet, 0,
                      bytes.fromhex('0011223344556677'), 20) + IPV4
        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.link_addr_length, 20)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

        made = LinuxSLL2(arphrd_type=Hardware.Ethernet,
                         link_addr=bytes.fromhex('0011223344556677'),
                         link_addr_length=20, payload=IPV4).data
        self.assertEqual(made, raw)

    def test_registered_against_frame_and_pcapng(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for cls in (Frame, PCAPNG):
            with self.subTest(table=cls.__name__):
                self.assertEqual(cls.__proto__[LinkType.LINUX_SLL2],
                                 ModuleDescriptor('pcapkit.protocols.link', 'LinuxSLL2'))
                self.assertIs(cls._lookup_next_layer(cls.__proto__, LinkType.LINUX_SLL2), LinuxSLL2)
        self.assertEqual(LinuxSLL2.__index__(), LinkType.LINUX_SLL2)

    def test_full_extraction_dissects_an_any_capture(self) -> None:
        import os
        import tempfile
        import warnings

        import pcapkit
        from pcapkit.const.linux.arphrd import ARPHRD

        raw = (_header(0x0800, 0, 1, 1, 0, bytes.fromhex('001122334455'), 6) + IPV4,
               # loopback (772): not Ethernet, not one of the exceptions.
               _header(0x0800, 0, 1, 772, 2, b'', 0) + IPV4,
               # NETLINK (824): one of the exceptions, dispatches to Netlink.
               _header(0x0800, 0, 1, ARPHRD.NETLINK, 2, b'', 0) + IPV4)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'any2.pcap')
            with open(path, 'wb') as file:
                file.write(_pcap(list(raw)))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, nofile=True, store=True)

        self.assertEqual([frame.protochain.chain for frame in extractor.frame],
                         ['LINUX_SLL2:IPv4:UDP', 'LINUX_SLL2:IPv4:UDP', 'LINUX_SLL2:Netlink:Raw'])
        for frame in extractor.frame:
            self._assert_rebuilds(frame, num=frame._fnum, header=frame._ghdr)


if __name__ == '__main__':
    unittest.main()
