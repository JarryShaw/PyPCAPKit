# -*- coding: utf-8 -*-
"""The dpkt engine reads RST, SYN and FIN from the flags octet, whatever the NS bit. C.f. #1618.

`dpkt`_ 1.9.8 makes :attr:`dpkt.tcp.TCP.flags` nine bits wide, its top bit the
NS bit (:rfc:`3540`). :func:`~pcapkit.toolkit.dpkt.tcp_reassembly` and
:func:`~pcapkit.toolkit.dpkt.tcp_traceflow` read each flag by its position among
that field's binary digits, padded to eight, so with NS set every flag was read
one bit low: a SYN as a FIN, an RST as a SYN, a PSH as an RST. They mask
each flag out of the flags octet.

Every capture is built here, so the module is in the unit tier.

.. _dpkt: https://dpkt.readthedocs.io

"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit.test_dpkt_scapy_ipv4_header_checks_1607_unit import read
from tests.toolkit.test_tunnelled_tcp_flow_key_1581_unit import has

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The low nibble of the data offset octet: three reserved bits, then NS.
NS = 0x01
NIBBLES = range(16)


def segment(number: int, nibble: int, octet: int) -> bytes:
    """A TCP header of 20 octets on a port pair of its own, its offset octet's low nibble and flags octet as given."""
    return struct.pack('!HHIIBBHHH', 1000 + number, 80, 100, 0, 0x50 | nibble, octet, 8192, 0, 0)


def expected(octet: int) -> 'dict[str, bool]':
    """RST, SYN and FIN as the flags octet ``octet`` sets them (:rfc:`9293#section-3.1`)."""
    return {'rst': bool(octet & 0x04), 'syn': bool(octet & 0x02), 'fin': bool(octet & 0x01)}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DPKTTCPNSFlagsTests(unittest.TestCase):
    """C.f. #1618."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        if not has('dpkt'):
            self.skipTest('dpkt not installed')

    def test_adapters_read_each_flag_from_the_flags_octet(self) -> None:
        # Every flags octet behind every NS and reserved bit, through both
        # adapters; the header handed on keeps the captured NS bit.
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        wrong = []
        for nibble in NIBBLES:
            for octet in range(256):
                header = segment(0, nibble, octet)
                frame = wire.ethernet(wire.ipv4(header, proto=6, df=True), 0x0800)
                packet = dpkt.ethernet.Ethernet(frame)
                toolkit.attach_buffer(packet, frame)
                want = expected(octet)
                for name, data in (
                    ('tcp_reassembly', toolkit.tcp_reassembly(packet, 1.0)),
                    ('tcp_traceflow', toolkit.tcp_traceflow(packet, 1.0, data_link=LinkType.ETHERNET)),
                ):
                    got = {flag: data[flag] for flag in want}
                    if got != want or data['header'] != header:
                        wrong.append((name, hex(nibble), hex(octet), got, want))
        self.assertEqual(wrong, [])

    def test_a_syn_with_ns_set_is_read_as_a_syn(self) -> None:
        # The case #1618 reports: one SYN, NS set, read as a FIN.
        seen = read(self, 'dpkt', [wire.ethernet(wire.ipv4(segment(1, NS, 0x02), proto=6, df=True), 0x0800)])
        for aspect in ('tcp', 'trace'):
            with self.subTest(aspect=aspect):
                self.assertEqual({flag: seen[aspect][1][flag] for flag in ('rst', 'syn', 'fin')},
                                 {'rst': False, 'syn': True, 'fin': False})

    def test_extraction_reads_each_flag_from_the_flags_octet(self) -> None:
        # Every input to TCP reassembly and flow tracing, for every flags octet
        # with NS and the reserved bits clear and set; the header handed on is
        # the captured one.
        cases = [(nibble, octet) for nibble in (0x0, NS, 0xE, 0xF) for octet in range(256)]
        headers = [segment(number, nibble, octet) for number, (nibble, octet) in enumerate(cases)]
        frames = [wire.ethernet(wire.ipv4(header, proto=6, df=True), 0x0800) for header in headers]
        numbers = list(range(1, len(cases) + 1))
        seen = read(self, 'dpkt', frames)
        for aspect in ('tcp', 'trace'):
            with self.subTest(aspect=aspect):
                self.assertEqual(sorted(seen[aspect]), numbers)
                self.assertEqual([{flag: seen[aspect][number][flag] for flag in ('rst', 'syn', 'fin')}
                                  for number in numbers],
                                 [expected(octet) for _, octet in cases])
                self.assertEqual([seen[aspect][number]['header'] for number in numbers], headers)


if __name__ == '__main__':
    unittest.main()
