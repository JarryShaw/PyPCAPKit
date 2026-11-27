# -*- coding: utf-8 -*-
"""Shared builders and tests for the Linux "cooked" capture encapsulation modules (#3148).

:mod:`tests.protocols.link.test_linux_sll1_unit` and
:mod:`tests.protocols.link.test_linux_sll2_unit` mix :class:`LinuxSLLMixin` into
their test cases for the tests the two versions share, and keep the tests their
own layout decides. They and
:mod:`tests.protocols.link.test_linux_sll_arphrd_registry_unit` build their
headers with :func:`sll1` and :func:`sll2`, and their payloads from :data:`CASES`.

Nothing here imports :mod:`pcapkit` at module level: each test resolves its
classes after :func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from unittest import TestCase as _Base
else:
    _Base = object

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))

#: The payload each ``arphrd_type`` case carries, and the chain it parses to
#: after the LinuxSLL layer.
CASES = {
    'FRAD': (bytes.fromhex('0c21') + b'\x03\xcc' + IPV4, 'FRAD:IPv4:UDP'),
    'IPGRE': (bytes.fromhex('00000800') + IPV4, 'GRE:IPv4:UDP'),
    'IP6GRE': (bytes.fromhex('00000800') + IPV4, 'GRE:IPv4:UDP'),
    'IEEE80211_RADIOTAP': (bytes.fromhex('00' '00' '0800' '00000000' 'd4000000' 'aaaaaaaaaaaa' '11223344'),
                           'Radiotap:802.11:Raw'),
    'NETLINK': (struct.pack('<IHHII', 20, 3, 0, 1, 0) + b'\xaa\xbb\xcc\xdd', 'Netlink:Raw'),
}


def sll1(protocol_type: int, arphrd_type: int, *, packet_type: int = 0, link_addr: bytes = b'',
         link_addr_length: int = 0) -> bytes:
    """Pack a 16-octet ``LINUX_SLL`` (v1) header carrying ``protocol_type`` on ``arphrd_type``."""
    padded = link_addr.ljust(8, b'\x00')[:8]
    return struct.pack('>HHH', packet_type, arphrd_type, link_addr_length) + padded \
        + struct.pack('>H', protocol_type)


def sll2(protocol_type: int, arphrd_type: int, *, packet_type: int = 0, link_addr: bytes = b'',
         link_addr_length: int = 0, reserved: int = 0, interface_index: int = 0) -> bytes:
    """Pack a 20-octet ``LINUX_SLL2`` header carrying ``protocol_type`` on ``arphrd_type``."""
    padded = link_addr.ljust(8, b'\x00')[:8]
    return struct.pack('>HHIHBB', protocol_type, reserved, interface_index, arphrd_type,
                       packet_type, link_addr_length) + padded


def pcap(linktype: int, records: 'list[bytes]') -> bytes:
    """A PCAP file holding ``records`` on the ``linktype`` link layer."""
    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for record in records:
        data += struct.pack('<IIII', 1500000000, 0, len(record), len(record)) + record
    return data


def ethernet(ether_type: int):  # type: ignore[no-untyped-def]
    """A bare Ethernet frame carrying ``ether_type``, for comparison."""
    from pcapkit.protocols.link.ethernet.protocol import Ethernet

    raw = bytes.fromhex('ffffffffffff001122334455') + struct.pack('>H', ether_type) + IPV4
    return Ethernet(raw, len(raw))


class LinuxSLLMixin(_Base):
    """The tests both versions share, mixed in ahead of :class:`unittest.TestCase`.

    It is a plain class at run time, so no module importing it collects its
    tests on their own. A subclass names its version with :meth:`header`,
    :meth:`version` and the attributes below.

    """

    #: The version's protochain alias.
    ALIAS = ''
    #: The name of the version's :class:`~pcapkit.const.reg.linktype.LinkType` member.
    LINKTYPE = ''
    #: One past the largest ``link_addr_length`` the version's field holds.
    LINK_ADDR_LENGTH_LIMIT = 0
    #: Fields beyond the builder's defaults that the headers of the Raw-fallback
    #: tests and of the capture carry.
    EXTRA = {}  # type: dict[str, int]

    @staticmethod
    def header(protocol_type: int, arphrd_type: int, **fields: int) -> bytes:
        """The version's header builder, :func:`sll1` or :func:`sll2`."""
        raise NotImplementedError

    @staticmethod
    def version():  # type: ignore[no-untyped-def]
        """The version's class, from the test's own :mod:`pcapkit` import."""
        raise NotImplementedError

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def _sll(self, protocol_type: int, arphrd_type: int) -> bytes:
        """A minimal header carrying ``protocol_type`` on ``arphrd_type``."""
        return self.header(protocol_type, arphrd_type, **self.EXTRA)

    def test_netlink_arphrd_dispatches_to_netlink(self) -> None:
        """``ARPHRD_NETLINK`` dispatches to
        :class:`~pcapkit.protocols.link.netlink.protocol.Netlink`, not
        :class:`~pcapkit.protocols.misc.raw.protocol.Raw` (#2500), through
        :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__>`.
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.netlink.protocol import Netlink

        version = self.version()
        raw = self.header(0x0800, ARPHRD.NETLINK, packet_type=2) + CASES['NETLINK'][0]
        parsed = version(raw, len(raw))
        self.assertEqual(parsed.info.arphrd_type, ARPHRD.NETLINK)
        self.assertIsInstance(parsed.payload, Netlink)
        self.assertEqual(parsed.payload.info.nlmsg_type, 3)
        self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:Netlink:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_radiotap_arphrd_dispatches_to_radiotap(self) -> None:
        """GitHub issue #2502: ``ARPHRD_IEEE80211_RADIOTAP`` dispatches to
        :class:`~pcapkit.protocols.link.radiotap.protocol.Radiotap` rather than
        falling back to :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.
        """
        from pcapkit.const.linux.arphrd import ARPHRD

        version = self.version()
        raw = self.header(0x0800, ARPHRD.IEEE80211_RADIOTAP, packet_type=2) + CASES['IEEE80211_RADIOTAP'][0]
        parsed = version(raw, len(raw))
        self.assertEqual(parsed.info.arphrd_type, ARPHRD.IEEE80211_RADIOTAP)
        self.assertEqual(type(parsed.payload).__name__, 'Radiotap')
        self.assertEqual(parsed.payload.info.it_len, 8)
        self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:Radiotap:802.11:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_frad_arphrd_dispatches_to_frad(self) -> None:
        """GitHub issue #2460: ``ARPHRD_FRAD`` dispatches to
        :class:`~pcapkit.protocols.link.frad.protocol.FRAD` rather than falling back to
        :class:`~pcapkit.protocols.misc.raw.protocol.Raw`; ``protocol_type`` is
        ignored, per tcpdump.org's LINUX_SLL and LINUX_SLL2 pages.
        """
        from pcapkit.const.linux.arphrd import ARPHRD

        version = self.version()
        raw = self.header(0x0800, ARPHRD.FRAD, packet_type=2) + CASES['FRAD'][0]
        parsed = version(raw, len(raw))
        self.assertEqual(parsed.info.arphrd_type, ARPHRD.FRAD)
        self.assertEqual(type(parsed.payload).__name__, 'FRAD')
        self.assertEqual(parsed.payload.info.dlci, 50)
        self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:FRAD:IPv4:UDP')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_frad_protocol_type_is_not_an_ethertype(self) -> None:
        """``ARPHRD_FRAD`` is a key of
        :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__>`,
        so its ``protocol_type`` is never looked up as an EtherType, per
        tcpdump.org's LINUX_SLL and LINUX_SLL2 pages (#2460).
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL, _resolve_next_layer_proto

        self.assertIn(ARPHRD.FRAD, LinuxSLL.__proto__)
        proto = _resolve_next_layer_proto(LinuxSLL.__proto__, ARPHRD.FRAD, 0x0800)
        self.assertIs(type(proto), int)
        self.assertEqual(proto, 0x0800)

    def test_truncated_frad_is_kept_raw_with_an_int_protocol(self) -> None:
        """A FRAD payload too short for its header is kept as
        :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, which records
        ``protocol_type`` as a plain :class:`int`, not an EtherType member
        (#2460).
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.misc.raw.protocol import Raw

        version = self.version()
        for size in (1, 2, 3):
            with self.subTest(size=size):
                raw = self.header(0x0800, ARPHRD.FRAD, packet_type=2) + CASES['FRAD'][0][:size]
                parsed = version(raw, len(raw))
                self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:Raw')
                self.assertIsInstance(parsed.payload, Raw)
                self.assertIs(type(parsed.payload.info.protocol), int)
                self.assertEqual(parsed.payload.info.protocol, 0x0800)
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_ipgre_and_ip6gre_arphrd_dispatch_to_gre(self) -> None:
        """GitHub issue #2501: ``ARPHRD_IPGRE`` and ``ARPHRD_IP6GRE`` both
        dispatch to :class:`~pcapkit.protocols.link.gre.protocol.GRE` rather than
        falling back to :class:`~pcapkit.protocols.misc.raw.protocol.Raw`;
        ``protocol_type`` is ignored (GRE's own Protocol Type field, inside
        the GRE header, is what actually selects the payload), per
        tcpdump.org's LINUX_SLL and LINUX_SLL2 pages.
        """
        from pcapkit.const.linux.arphrd import ARPHRD

        version = self.version()
        for arphrd in (ARPHRD.IPGRE, ARPHRD.IP6GRE):
            with self.subTest(arphrd=arphrd):
                raw = self.header(0x0800, arphrd, packet_type=2) + CASES[arphrd.name][0]
                parsed = version(raw, len(raw))
                self.assertEqual(parsed.info.arphrd_type, arphrd)
                self.assertEqual(type(parsed.payload).__name__, 'GRE')
                self.assertEqual(parsed.payload.info.protocol_type, 0x0800)
                self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:GRE:IPv4:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_non_ethernet_non_excluded_arphrds_still_dispatch_by_ethertype(self) -> None:
        """Loopback, PPP and SLIP/CSLIP are not
        :attr:`~pcapkit.const.arp.hardware.Hardware.Ethernet`, and have no
        member in :class:`~pcapkit.const.arp.hardware.Hardware` at all, but
        are not among the exceptions either -- so ``protocol_type`` is
        still an EtherType for them.
        """
        version = self.version()
        #: Linux's own ``<linux/if_arp.h>`` numbering: loopback (772), PPP
        #: (512), SLIP (256) and CSLIP (257). 256/257 coincide in *value*,
        #: not meaning, with :class:`~pcapkit.const.arp.hardware.Hardware`'s
        #: own ``HW_EXP2``/``AEthernet`` members.
        for arphrd, name in ((772, 'loopback'), (512, 'PPP'), (256, 'SLIP'), (257, 'CSLIP')):
            with self.subTest(arphrd=arphrd, name=name):
                raw = self.header(0x0800, arphrd) + IPV4
                parsed = version(raw, len(raw))
                self.assertEqual(parsed.info.arphrd_type, arphrd)
                self.assertEqual(parsed.info.protocol_type, 0x0800)
                self.assertEqual(type(parsed.payload).__name__, 'IPv4')
                self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:IPv4:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_unregistered_ethertype_is_kept_raw_without_breaking_the_header(self) -> None:
        """An unregistered ``protocol_type`` on an Ethernet-semantics
        ``arphrd_type`` must not blow up the header parse -- it should
        resolve to :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, exactly as
        :class:`~pcapkit.protocols.link.ethernet.protocol.Ethernet` does for the same
        unregistered EtherType.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.misc.raw.protocol import Raw

        version = self.version()
        raw = self.header(0x1234, Hardware.Ethernet) + IPV4
        parsed = version(raw, len(raw))
        self.assertEqual(parsed.info.protocol_type, 0x1234)
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:<unassigned>')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    ##########################################################################
    # Raw fallback and registry overrides match Ethernet's.
    ##########################################################################

    def test_known_ethertype_without_a_dissector_matches_ethernet(self) -> None:
        """0x88CC (LLDP) is an assigned EtherType with no dissector: the
        :class:`~pcapkit.protocols.misc.raw.protocol.Raw` fallback records the
        EtherType member, as a bare Ethernet frame's does, not a bare int.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.misc.raw.protocol import Raw

        version = self.version()
        raw = self._sll(0x88CC, Hardware.Ethernet) + IPV4
        parsed = version(raw, len(raw))
        self.assertIsInstance(parsed.payload, Raw)
        self.assertIs(parsed.payload.info.protocol,
                      EtherType.IEEE_Std_802_1AB_Link_Layer_Discovery_Protocol)
        self.assertIs(ethernet(0x88CC).payload.info.protocol, parsed.payload.info.protocol)
        self._assert_rebuilds(parsed)

    def test_unassigned_ethertype_raw_fallback_records_the_value(self) -> None:
        """0x1234 is unassigned in EtherType: the
        :class:`~pcapkit.protocols.misc.raw.protocol.Raw` fallback records the
        ``<unassigned>`` pseudo-member a bare Ethernet frame's does.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.misc.raw.protocol import Raw

        version = self.version()
        raw = self._sll(0x1234, Hardware.Ethernet) + IPV4
        parsed = version(raw, len(raw))
        self.assertIsInstance(parsed.payload, Raw)
        frame = ethernet(0x1234)
        self.assertEqual(repr(parsed.payload.info.protocol), '<<unknown>.<unassigned>: 4660>')
        self.assertEqual(repr(parsed.payload.info.protocol), repr(frame.payload.info.protocol))
        self.assertEqual(frame.protochain.chain, 'Ethernet:<unassigned>')
        self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:<unassigned>')
        self._assert_rebuilds(parsed)

    def test_registered_override_is_reached_as_from_ethernet(self) -> None:
        """``Link.register(0x1234, IPv4)`` makes an unassigned EtherType reach
        IPv4 from an SLL frame, as it does from a bare Ethernet frame -- but
        not on a hardware type whose ``protocol_type`` is no EtherType.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.netlink.protocol import Netlink

        version = self.version()
        registry = Link.__dict__['__proto__']
        had_original = 0x1234 in registry
        original = registry.get(0x1234)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                Link.register(0x1234, IPv4)  # type: ignore[arg-type]
            self.assertIsInstance(ethernet(0x1234).payload, IPv4)

            raw = self._sll(0x1234, Hardware.Ethernet) + IPV4
            parsed = version(raw, len(raw))
            self.assertIsInstance(parsed.payload, IPv4)
            self.assertEqual(parsed.protochain.chain, f'{self.ALIAS}:IPv4:UDP')
            self._assert_rebuilds(parsed)

            # A registered override on Link.__proto__ does not leak into
            # NETLINK's dispatch -- it never looks EtherType up at all.
            raw = self._sll(0x1234, ARPHRD.NETLINK) + IPV4
            parsed = version(raw, len(raw))
            self.assertIsInstance(parsed.payload, Netlink)
        finally:
            if had_original:
                registry[0x1234] = original
            else:
                registry.pop(0x1234, None)

    def test_make_defaults(self) -> None:
        self.assertEqual(self.version().from_fields().data, self.header(0x0800, 1))

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        version = self.version()
        with self.assertRaises(ProtocolError):
            version.from_fields(link_addr=bytes(9))
        with self.assertRaises(ProtocolError):
            version.from_fields(link_addr_length=self.LINK_ADDR_LENGTH_LIMIT)
        with self.assertRaises(ProtocolError):
            version.from_fields(link_addr_length=-1)

    def test_registered_against_frame_and_pcapng(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        version = self.version()
        linktype = getattr(LinkType, self.LINKTYPE)
        for cls in (Frame, PCAPNG):
            with self.subTest(table=cls.__name__):
                self.assertEqual(cls.__proto__[linktype],
                                 ModuleDescriptor('pcapkit.protocols.link', version.__name__))
                self.assertIs(cls._lookup_next_layer(cls.__proto__, linktype), version)
        self.assertEqual(version.__index__(), linktype)

    def test_full_extraction_dissects_an_any_capture(self) -> None:
        import pcapkit
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.const.reg.linktype import LinkType

        raw = (self.header(0x0800, 1, link_addr=bytes.fromhex('001122334455'), link_addr_length=6,
                           **self.EXTRA) + IPV4,
               # loopback (772): not Ethernet, not one of the exceptions.
               self.header(0x0800, 772, packet_type=2, **self.EXTRA) + IPV4,
               # NETLINK (824): one of the exceptions, dispatches to Netlink.
               self.header(0x0800, ARPHRD.NETLINK, packet_type=2, **self.EXTRA) + IPV4)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'any.pcap')
            with open(path, 'wb') as file:
                file.write(pcap(getattr(LinkType, self.LINKTYPE), list(raw)))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, store=True)

        self.assertEqual([frame.protochain.chain for frame in extractor.frame],
                         [f'{self.ALIAS}:IPv4:UDP', f'{self.ALIAS}:IPv4:UDP', f'{self.ALIAS}:Netlink:Raw'])
        for frame in extractor.frame:
            self._assert_rebuilds(frame, num=frame._fnum, header=frame._ghdr)
