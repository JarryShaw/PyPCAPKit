# -*- coding: utf-8 -*-
"""GitHub issue #2438: the Linux "cooked" capture encapsulation v1 (``LINUX_SLL``).

Covers the 16-octet header, the ``arphrd_type``-gated next-layer rule (see
:data:`~pcapkit.protocols.link.linux_sll._ARPHRD_NOT_ETHERTYPE`), link-address
validation, and byte-exact round trips.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))


def _header(packet_type: int, arphrd_type: int, link_addr: bytes, link_addr_length: int,
            protocol_type: int) -> bytes:
    """Pack a ``LINUX_SLL`` (v1) header: see the module docstring for the layout."""
    padded = link_addr.ljust(8, b'\x00')[:8]
    return struct.pack('>HHH', packet_type, arphrd_type, link_addr_length) + padded \
        + struct.pack('>H', protocol_type)


def _pcap(records: 'list[bytes]') -> bytes:
    from pcapkit.const.reg.linktype import LinkType

    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, LinkType.LINUX_SLL)
    for record in records:
        data += struct.pack('<IIII', 1500000000, 0, len(record), len(record)) + record
    return data


def _sll(protocol_type: int, arphrd_type: int) -> bytes:
    """A minimal header carrying ``protocol_type`` on ``arphrd_type``."""
    return _header(0, arphrd_type, b'', 0, protocol_type)


class TestLinuxSLL1(unittest.TestCase):
    """Pin the ``LINUX_SLL`` (v1) layer, alone and under full extraction."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def test_ethernet_arphrd_dispatches_by_ethertype(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        raw = _header(0, Hardware.Ethernet, bytes.fromhex('001122334455'), 6, 0x0800) + IPV4
        parsed = LinuxSLL1(raw, len(raw))
        self.assertEqual(parsed.info.packet_type, 0)
        self.assertEqual(parsed.info.arphrd_type, Hardware.Ethernet)
        self.assertEqual(parsed.info.link_addr_length, 6)
        self.assertEqual(parsed.info.link_addr, bytes.fromhex('0011223344550000'))
        self.assertEqual(parsed.info.protocol_type, 0x0800)
        self.assertEqual(parsed.protocol, 0x0800)
        self.assertEqual((parsed.name, parsed.length), ('Linux cooked capture encapsulation', 16))
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:IPv4:UDP')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_the_non_ethertype_arphrds_are_kept_raw(self) -> None:
        """``NETLINK``, ``IEEE80211_RADIOTAP`` and ``FRAD``, per tcpdump.org's
        LINUX_SLL page, never have ``protocol_type`` looked up as an
        EtherType, even though 0x0800 is IPv4's. ``IPGRE``/``IP6GRE`` are the
        exception: see :meth:`test_ipgre_and_ip6gre_arphrd_dispatch_to_gre`.
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.misc.raw import Raw

        for arphrd in (ARPHRD.NETLINK, ARPHRD.IEEE80211_RADIOTAP, ARPHRD.FRAD):
            with self.subTest(arphrd=arphrd):
                # protocol_type 0x0800 is IPv4's EtherType, but these
                # hardware types never carry an EtherType in protocol_type.
                raw = _header(2, arphrd, b'', 0, 0x0800) + IPV4
                parsed = LinuxSLL1(raw, len(raw))
                self.assertEqual(parsed.info.arphrd_type, arphrd)
                self.assertEqual(parsed.info.protocol_type, 0x0800)
                self.assertIsInstance(parsed.payload, Raw)
                self.assertIs(type(parsed.payload.info.protocol), int)
                self.assertEqual(parsed.payload.info.protocol, 0x0800)
                self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:Raw')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_ipgre_and_ip6gre_arphrd_dispatch_to_gre(self) -> None:
        """GitHub issue #2501: ``ARPHRD_IPGRE`` and ``ARPHRD_IP6GRE`` both
        dispatch to :class:`~pcapkit.protocols.link.gre.GRE` rather than
        falling back to :class:`~pcapkit.protocols.misc.raw.Raw`;
        ``protocol_type`` is ignored (GRE's own Protocol Type field, inside
        the GRE header, is what actually selects the payload), per
        tcpdump.org's LINUX_SLL page.
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        for arphrd in (ARPHRD.IPGRE, ARPHRD.IP6GRE):
            with self.subTest(arphrd=arphrd):
                gre = bytes.fromhex('00000800') + IPV4
                raw = _header(2, arphrd, b'', 0, 0x0800) + gre
                parsed = LinuxSLL1(raw, len(raw))
                self.assertEqual(parsed.info.arphrd_type, arphrd)
                self.assertEqual(type(parsed.payload).__name__, 'GRE')
                self.assertEqual(parsed.payload.info.protocol_type, 0x0800)
                self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:GRE:IPv4:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_non_ethernet_non_excluded_arphrds_still_dispatch_by_ethertype(self) -> None:
        """Loopback, PPP and SLIP/CSLIP are not
        :attr:`~pcapkit.const.arp.hardware.Hardware.Ethernet`, and have no
        member in :class:`~pcapkit.const.arp.hardware.Hardware` at all, but
        are not among the exceptions either -- so ``protocol_type`` is
        still an EtherType for them.
        """
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        #: Linux's own ``<linux/if_arp.h>`` numbering: loopback (772), PPP
        #: (512), SLIP (256) and CSLIP (257). 256/257 coincide in *value*,
        #: not meaning, with :class:`~pcapkit.const.arp.hardware.Hardware`'s
        #: own ``HW_EXP2``/``AEthernet`` members.
        for arphrd, name in ((772, 'loopback'), (512, 'PPP'), (256, 'SLIP'), (257, 'CSLIP')):
            with self.subTest(arphrd=arphrd, name=name):
                raw = _header(0, arphrd, b'', 0, 0x0800) + IPV4
                parsed = LinuxSLL1(raw, len(raw))
                self.assertEqual(parsed.info.arphrd_type, arphrd)
                self.assertEqual(parsed.info.protocol_type, 0x0800)
                self.assertEqual(type(parsed.payload).__name__, 'IPv4')
                self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:IPv4:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_unregistered_ethertype_is_kept_raw_without_breaking_the_header(self) -> None:
        """An unregistered ``protocol_type`` on an Ethernet-semantics
        ``arphrd_type`` must not blow up the header parse -- it should
        resolve to :class:`~pcapkit.protocols.misc.raw.Raw`, exactly as
        :class:`~pcapkit.protocols.link.ethernet.Ethernet` does for the same
        unregistered EtherType.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.misc.raw import Raw

        raw = _header(0, Hardware.Ethernet, b'', 0, 0x1234) + IPV4
        parsed = LinuxSLL1(raw, len(raw))
        self.assertEqual(parsed.info.protocol_type, 0x1234)
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:<unassigned>')
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
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.misc.raw import Raw

        raw = _sll(0x88CC, Hardware.Ethernet) + IPV4
        parsed = LinuxSLL1(raw, len(raw))
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
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.misc.raw import Raw

        raw = _sll(0x1234, Hardware.Ethernet) + IPV4
        parsed = LinuxSLL1(raw, len(raw))
        self.assertIsInstance(parsed.payload, Raw)
        ethernet = self._ethernet(0x1234)
        self.assertEqual(repr(parsed.payload.info.protocol), '<<unknown>.<unassigned>: 4660>')
        self.assertEqual(repr(parsed.payload.info.protocol), repr(ethernet.payload.info.protocol))
        self.assertEqual(ethernet.protochain.chain, 'Ethernet:<unassigned>')
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:<unassigned>')
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
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.misc.raw import Raw

        registry = Link.__dict__['__proto__']
        had_original = 0x1234 in registry
        original = registry.get(0x1234)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                Link.register(0x1234, IPv4)  # type: ignore[arg-type]
            self.assertIsInstance(self._ethernet(0x1234).payload, IPv4)

            raw = _sll(0x1234, Hardware.Ethernet) + IPV4
            parsed = LinuxSLL1(raw, len(raw))
            self.assertIsInstance(parsed.payload, IPv4)
            self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:IPv4:UDP')
            self._assert_rebuilds(parsed)

            raw = _sll(0x1234, ARPHRD.NETLINK) + IPV4
            parsed = LinuxSLL1(raw, len(raw))
            self.assertIsInstance(parsed.payload, Raw)
        finally:
            if had_original:
                registry[0x1234] = original
            else:
                registry.pop(0x1234, None)

    def test_padding_octets_round_trip_even_when_non_zero(self) -> None:
        """The padding beyond ``link_addr_length`` is kept verbatim, not re-zeroed."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        raw = _header(0, Hardware.Ethernet, bytes.fromhex('0011223344'), 5, 0x0800) + IPV4
        # Overwrite the padding tail (octets 5-7 of link_addr) with non-zero garbage.
        raw = bytearray(raw)
        raw[11:14] = b'\xde\xad\xbe'[:3]
        raw = bytes(raw)

        parsed = LinuxSLL1(raw, len(raw))
        self.assertEqual(parsed.info.link_addr_length, 5)
        self.assertEqual(parsed.info.link_addr, bytes.fromhex('0011223344') + b'\xde\xad\xbe')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_make_then_parse(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        made = LinuxSLL1(packet_type=4, arphrd_type=Hardware.Ethernet,
                         link_addr=bytes.fromhex('001122334455'),
                         protocol_type=EtherType.Internet_Protocol_version_4, payload=IPV4).data
        self.assertEqual(made, _header(4, 1, bytes.fromhex('001122334455'), 6, 0x0800) + IPV4)

        parsed = LinuxSLL1(made, len(made))
        self.assertEqual(parsed.info.packet_type, 4)
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self._assert_rebuilds(parsed)

    def test_make_defaults(self) -> None:
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        self.assertEqual(LinuxSLL1().data, _header(0, 1, b'', 0, 0x0800))

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            LinuxSLL1(link_addr=bytes(9))
        # link_addr_length is a 2-octet field (0 to 0xFFFF).
        with self.assertRaises(ProtocolError):
            LinuxSLL1(link_addr_length=0x10000)
        with self.assertRaises(ProtocolError):
            LinuxSLL1(link_addr_length=-1)

    def test_link_addr_length_over_8_round_trips(self) -> None:
        """A ``link_addr_length`` over 8 parses and rebuilds."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        raw = _header(0, Hardware.Ethernet, bytes.fromhex('0011223344556677'), 20, 0x0800) + IPV4
        parsed = LinuxSLL1(raw, len(raw))
        self.assertEqual(parsed.info.link_addr_length, 20)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

        # make() accepts the same length directly, not only via a round trip.
        made = LinuxSLL1(arphrd_type=Hardware.Ethernet,
                         link_addr=bytes.fromhex('0011223344556677'),
                         link_addr_length=20, protocol_type=0x0800, payload=IPV4).data
        self.assertEqual(made, raw)

    def test_registered_against_frame_and_pcapng(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for cls in (Frame, PCAPNG):
            with self.subTest(table=cls.__name__):
                self.assertEqual(cls.__proto__[LinkType.LINUX_SLL],
                                 ModuleDescriptor('pcapkit.protocols.link', 'LinuxSLL1'))
                self.assertIs(cls._lookup_next_layer(cls.__proto__, LinkType.LINUX_SLL), LinuxSLL1)
        self.assertEqual(LinuxSLL1.__index__(), LinkType.LINUX_SLL)

    def test_full_extraction_dissects_an_any_capture(self) -> None:
        import os
        import tempfile
        import warnings

        import pcapkit
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.misc.pcap.frame import Frame

        raw = (_header(0, 1, bytes.fromhex('001122334455'), 6, 0x0800) + IPV4,
               # loopback (772): not Ethernet, not one of the exceptions.
               _header(2, 772, b'', 0, 0x0800) + IPV4,
               # NETLINK (824): one of the exceptions, stays Raw.
               _header(2, ARPHRD.NETLINK, b'', 0, 0x0800) + IPV4)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'any.pcap')
            with open(path, 'wb') as file:
                file.write(_pcap(list(raw)))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, nofile=True, store=True)

        self.assertEqual([frame.protochain.chain for frame in extractor.frame],
                         ['LINUX_SLL1:IPv4:UDP', 'LINUX_SLL1:IPv4:UDP', 'LINUX_SLL1:Raw'])
        for frame in extractor.frame:
            self._assert_rebuilds(frame, num=frame._fnum, header=frame._ghdr)


if __name__ == '__main__':
    unittest.main()
