# -*- coding: utf-8 -*-
"""GitHub issue #2438: the Linux "cooked" capture encapsulation v1 (``LINUX_SLL``).

Covers the 16-octet header, the ``arphrd_type``-gated next-layer rule (see
:attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__>`),
link-address validation, and byte-exact round trips. The tests v2 shares come
from :class:`~tests.protocols.link._linux_sll.LinuxSLLMixin`; this module keeps
those the v1 layout decides.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests.protocols.link._linux_sll import IPV4, LinuxSLLMixin, sll1


class TestLinuxSLL1(LinuxSLLMixin, unittest.TestCase):
    """Pin the ``LINUX_SLL`` (v1) layer, alone and under full extraction."""

    ALIAS = 'LINUX_SLL1'
    LINKTYPE = 'LINUX_SLL'
    #: ``link_addr_length`` is a 2-octet field (0 to 0xFFFF).
    LINK_ADDR_LENGTH_LIMIT = 0x10000
    header = staticmethod(sll1)

    @staticmethod
    def version():  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

        return LinuxSLL1

    def test_ethernet_arphrd_dispatches_by_ethertype(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

        raw = sll1(0x0800, Hardware.Ethernet, link_addr=bytes.fromhex('001122334455'), link_addr_length=6) + IPV4
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

    def test_padding_octets_round_trip_even_when_non_zero(self) -> None:
        """The padding beyond ``link_addr_length`` is kept verbatim, not re-zeroed."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

        raw = sll1(0x0800, Hardware.Ethernet, link_addr=bytes.fromhex('0011223344'), link_addr_length=5) + IPV4
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
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

        made = LinuxSLL1.from_fields(packet_type=4, arphrd_type=Hardware.Ethernet,
                                     link_addr=bytes.fromhex('001122334455'),
                                     protocol_type=EtherType.Internet_Protocol_version_4, payload=IPV4).data
        self.assertEqual(made, sll1(0x0800, 1, packet_type=4, link_addr=bytes.fromhex('001122334455'),
                                    link_addr_length=6) + IPV4)

        parsed = LinuxSLL1(made, len(made))
        self.assertEqual(parsed.info.packet_type, 4)
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self._assert_rebuilds(parsed)

    def test_link_addr_length_over_8_round_trips(self) -> None:
        """A ``link_addr_length`` over 8 parses and rebuilds."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

        raw = sll1(0x0800, Hardware.Ethernet, link_addr=bytes.fromhex('0011223344556677'),
                   link_addr_length=20) + IPV4
        parsed = LinuxSLL1(raw, len(raw))
        self.assertEqual(parsed.info.link_addr_length, 20)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

        # make() accepts the same length directly, not only via a round trip.
        made = LinuxSLL1.from_fields(arphrd_type=Hardware.Ethernet,
                                     link_addr=bytes.fromhex('0011223344556677'),
                                     link_addr_length=20, protocol_type=0x0800, payload=IPV4).data
        self.assertEqual(made, raw)


if __name__ == '__main__':
    unittest.main()
