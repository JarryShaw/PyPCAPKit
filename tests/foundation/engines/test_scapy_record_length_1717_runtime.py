# -*- coding: utf-8 -*-
"""The scapy engine reads :file:`options-ipv6.pcap`'s jumbogram whole (#1717).

:file:`examples/generators/options.py` writes HOPOPT's Jumbo Payload case as a
genuine jumbogram, a 65,590-octet frame in a capture whose snaplen is 262,144.
Guards against the scapy engine handing over only its first 65,535 octets,
Scapy's ``MTU``, which ``recv()`` cuts every record to by default.

:file:`options-ipv6.pcap` is generated, so the module belongs to the
fixture-dependent tier.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class, sample_path

#: Test tier (#1958): drives Scapy, whose installable releases vary by interpreter; the
#: integration and pypcap-parity legs install it on every interpreter, and a test leg
#: off latest skips it.
__tier__ = 'ALL'

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


def _records(fin: 'str') -> 'list[tuple[bytes, int]]':
    """``(octets, orig_len)`` of each record of a little-endian PCAP."""
    with open(fin, 'rb') as file:
        rest = file.read()[24:]
    records = []
    while rest:
        _, _, incl_len, orig_len = struct.unpack('<IIII', rest[:16])
        records.append((rest[16:16 + incl_len], orig_len))
        rest = rest[16 + incl_len:]
    return records


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies or scapy not installed')
class ScapyJumbogramTests(unittest.TestCase):
    """The scapy engine's frames hold every octet of :file:`options-ipv6.pcap`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_jumbogram_is_read_whole(self) -> None:
        from scapy.packet import Packet

        from pcapkit import extract
        from pcapkit.toolkit.scapy import packet2frame

        fin = sample_path('options-ipv6.pcap')
        records = _records(fin)
        self.assertEqual([(number, len(octets)) for number, (octets, _) in enumerate(records, 1)
                          if len(octets) > 0xFFFF], [(13, 65_590)])

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=fin, engine='scapy', nofile=True, store=True)
        self.addCleanup(close_extractor, extractor)
        packets = []  # type: list[Packet]
        for packet in extractor.frame:
            if not isinstance(packet, Packet):
                self.fail(f'not a Scapy packet: {packet!r}')
            packets.append(packet)
        self.assertEqual([(bytes(packet.original), packet.wirelen) for packet in packets], records)

        # and so does the PCAP frame record the flow tracer writes
        record = packet2frame(packets[12])
        self.assertEqual((record.frame_info.incl_len, record.frame_info.orig_len), (65_590, 65_590))
        self.assertEqual(record.packet, records[12][0])


if __name__ == '__main__':
    unittest.main()
