# -*- coding: utf-8 -*-
"""GitHub issue #2438: the Linux "cooked" capture encapsulation v2 (``LINUX_SLL2``).

Covers the 20-octet header, the same ``arphrd_type``-gated next-layer rule as
v1 (see :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__>`),
link-address validation, and byte-exact round trips. The tests v1 shares come
from :class:`~tests.protocols.link._linux_sll.LinuxSLLMixin`; this module keeps
those the v2 layout decides.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests.protocols.link._linux_sll import IPV4, LinuxSLLMixin, sll2


class TestLinuxSLL2(LinuxSLLMixin, unittest.TestCase):
    """Pin the ``LINUX_SLL2`` layer, alone and under full extraction."""

    ALIAS = 'LINUX_SLL2'
    LINKTYPE = 'LINUX_SLL2'
    #: ``link_addr_length`` is a 1-octet field (0 to 0xFF).
    LINK_ADDR_LENGTH_LIMIT = 0x100
    EXTRA = {'interface_index': 1}
    header = staticmethod(sll2)

    @staticmethod
    def version():  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

        return LinuxSLL2

    def test_ethernet_arphrd_dispatches_by_ethertype(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

        raw = sll2(0x0800, Hardware.Ethernet, link_addr=bytes.fromhex('001122334455'), link_addr_length=6,
                   interface_index=7) + IPV4
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

    def test_reserved_and_padding_round_trip_even_when_non_zero(self) -> None:
        """``reserved`` and the padding beyond ``link_addr_length`` round-trip verbatim."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

        raw = bytearray(sll2(0x0800, Hardware.Ethernet, link_addr=bytes.fromhex('0011223344'),
                             link_addr_length=5) + IPV4)
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
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

        made = LinuxSLL2.from_fields(protocol_type=EtherType.Internet_Protocol_version_4, interface_index=3,
                                     arphrd_type=Hardware.Ethernet, packet_type=4,
                                     link_addr=bytes.fromhex('001122334455'), payload=IPV4).data
        self.assertEqual(made, sll2(0x0800, 1, packet_type=4, link_addr=bytes.fromhex('001122334455'),
                                    link_addr_length=6, interface_index=3) + IPV4)

        parsed = LinuxSLL2(made, len(made))
        self.assertEqual(parsed.info.packet_type, 4)
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self._assert_rebuilds(parsed)

    def test_link_addr_length_over_8_round_trips(self) -> None:
        """A ``link_addr_length`` over 8 parses and rebuilds."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

        raw = sll2(0x0800, Hardware.Ethernet, link_addr=bytes.fromhex('0011223344556677'),
                   link_addr_length=20) + IPV4
        parsed = LinuxSLL2(raw, len(raw))
        self.assertEqual(parsed.info.link_addr_length, 20)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

        made = LinuxSLL2.from_fields(arphrd_type=Hardware.Ethernet,
                                     link_addr=bytes.fromhex('0011223344556677'),
                                     link_addr_length=20, payload=IPV4).data
        self.assertEqual(made, raw)


if __name__ == '__main__':
    unittest.main()
