# -*- coding: utf-8 -*-
""":func:`pcapkit.toolkit.scapy.tcp_traceflow` takes the link type the engine attached (#1517).

A packet's first layer does not name its link type: a raw IPv4 packet's is
``IP``, which is no :class:`~pcapkit.const.reg.linktype.LinkType` name, so the
name lookup raised :exc:`~pcapkit.utilities.exceptions.MissingKeyError`, and a
raw-IP packet whose first layer is ``IPv6`` resolved to ``LINKTYPE_IPV6`` whatever
its interface said. :class:`~pcapkit.foundation.engines.scapy.Scapy` now attaches
the interface's link type with :func:`~pcapkit.toolkit.scapy.attach_linktype`,
and only a packet built by hand, which carries none, is still looked up by name.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies or scapy not installed')
class ScapyTraceflowLinkTypeTests(unittest.TestCase):
    """The attached link type, never the first layer's name, labels a traced packet."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _tcp(network: 'type'):  # type: ignore[no-untyped-def]
        from scapy.layers.inet import TCP
        from scapy.packet import Raw

        addresses = (('192.0.2.1', '198.51.100.1') if network.__name__ == 'IP'
                     else ('2001:db8::1', '2001:db8::2'))
        packet = network(src=addresses[0], dst=addresses[1]) / TCP(sport=1234, dport=80, flags='S') / Raw(b'x')
        return network(bytes(packet))

    def test_an_attached_link_type_is_used(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.scapy import attach_linktype, tcp_traceflow

        for network, linktype, expected in ((IP, 228, LinkType.IPV4), (IP, 101, LinkType.RAW),
                                            # by name, ``IPv6`` would resolve to IPV6 (229)
                                            (IPv6, 101, LinkType.RAW)):
            with self.subTest(network=network.__name__, linktype=linktype):
                packet = self._tcp(network)
                attach_linktype(packet, linktype)
                flow = tcp_traceflow(packet, count=1)
                assert flow is not None
                self.assertIs(flow.protocol, expected)

    def test_a_packet_built_by_hand_is_looked_up_by_name(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.scapy import tcp_traceflow
        from pcapkit.utilities.exceptions import MissingKeyError

        flow = tcp_traceflow(self._tcp(IPv6), count=1)
        assert flow is not None
        self.assertIs(flow.protocol, LinkType.IPV6)
        # and still with no default (#775)
        with self.assertRaises(MissingKeyError):
            tcp_traceflow(self._tcp(IP), count=1)


if __name__ == '__main__':
    unittest.main()
