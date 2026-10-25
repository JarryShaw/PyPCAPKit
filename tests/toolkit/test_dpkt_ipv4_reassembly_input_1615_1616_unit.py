# -*- coding: utf-8 -*-
"""dpkt hands IPv4 reassembly a whole header. C.f. #1616.

dpkt cut the input at the Total Length, so one shorter than the IHL cut the
header itself (#1616). It cuts no shorter than the IHL. A header whose IHL
runs past the captured octets, which dpkt still decodes, is no input at all.

Every capture is built here, so the module is in the unit tier.

"""
from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_DPKT = importlib.util.find_spec('dpkt') is not None


def ipv4(payload: bytes, *, ident: int, options: bytes = b'', length: 'int | None' = None,
         mf: bool = False, offset: int = 0, proto: int = 253) -> bytes:
    """An IPv4 fragment carrying ``payload``; ``offset`` is in octets, and the Total Length as given."""
    if length is None:
        length = 20 + len(options) + len(payload)
    flags = (0x2000 if mf else 0) | (offset // 8)
    header = bytearray(struct.pack('!BBHHHBBH', 0x45 + len(options) // 4, 0, length, ident, flags, 64, proto, 0)
                       + wire.IPV4_A + wire.IPV4_B + options)
    header[10:12] = wire.checksum(bytes(header)).to_bytes(2, 'big')
    return bytes(header) + payload


def ethernet(packet: bytes) -> bytes:
    """An Ethernet frame carrying the IPv4 ``packet``."""
    return wire.ethernet(packet, 0x0800)


def read(test: unittest.TestCase, engine: str, frames: 'list[bytes]') -> 'dict[str, Any]':
    """Read ``frames`` with ``engine``, with IPv4 reassembly.

    Returns:
        Every input the engine hands IPv4 reassembly, every field of it, keyed
        by frame number, and the reassembled datagrams.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.ipv4 import IPv4

    seen = {}  # type: dict[int, dict[str, Any]]
    reassemble = IPv4.__call__

    def spy(this: 'Any', packet: 'Any') -> 'Any':
        seen[packet.num] = {key: bytes(value) if isinstance(value, bytearray) else value
                            for key, value in packet.items()}
        return reassemble(this, packet)

    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(IPv4, '__call__', spy):
        path = os.path.join(tmp, 'ipv4.pcap')
        with open(path, 'wb') as file:
            file.write(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)]))
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, ipv4=True)
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            datagrams = [(datagram.completed, datagram.id, datagram.index, datagram.header,
                          datagram.payload) for datagram in extractor.reassembly.ipv4]
        finally:
            close_extractor(extractor)
    return {'inputs': seen, 'datagrams': datagrams}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
class DPKTIPv4ReassemblyInputTests(unittest.TestCase):
    """dpkt's IPv4 reassembly input carries its header whole, or is not handed over."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_total_length_below_the_ihl_leaves_the_header_whole(self) -> None:
        # #1616: the header was cut to the Total Length's 10 octets
        frame = ethernet(ipv4(b'C' * 16, ident=14, options=b'\x94\x04\x00\x00', length=10, mf=True))
        seen = read(self, 'dpkt', [frame])
        packet, = seen['inputs'].values()
        self.assertEqual((packet['ihl'], packet['tl'], packet['mf']), (24, 10, True))
        self.assertEqual((packet['header'], packet['payload']), (frame[14:38], b''))

    def test_a_header_cut_short_by_the_capture_is_no_input(self) -> None:
        # an IHL of 15 with 28 of its 60 octets captured, which dpkt decodes;
        # the next frame is still an input
        cut = ethernet(ipv4(b'', ident=30, options=b'\x01' * 40, mf=True)[:28])
        plain = ethernet(ipv4(b'A' * 16, ident=31, mf=True))
        seen = read(self, 'dpkt', [cut, plain])
        self.assertEqual(sorted(seen['inputs']), [2])
        self.assertEqual((seen['inputs'][2]['header'], seen['inputs'][2]['payload']),
                         (plain[14:34], b'A' * 16))


if __name__ == '__main__':
    unittest.main()
