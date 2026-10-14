# -*- coding: utf-8 -*-
"""dpkt hands IPv4 reassembly what the default engine hands it. C.f. #1615, #1616.

The default engine hands IPv4 reassembly the first IPv4 layer of a frame however
deep, so IPv4 carried in IPv6 (RFC 2473) is an input, with the octets inside the
Payload Length of each IPv6 packet above it. dpkt took the network layer only,
so gave no input for 4in6 (#1615). It also cut the input at the Total Length,
which the reassembler bounds the payload by itself: a Total Length shorter than
the header cut the header, and a padded last fragment lost its padding (#1616).
The default engine's header is the IHL's octets and its payload the rest.

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


def ipv6(payload: bytes, nxt: int, *, plen: 'int | None' = None) -> bytes:
    """An IPv6 packet carrying ``payload``, its Payload Length as given."""
    packet = wire.ipv6(payload, nxt=nxt)
    if plen is None:
        return packet
    return packet[:4] + plen.to_bytes(2, 'big') + packet[6:]


def options(nxt: int) -> bytes:
    """An 8-octet Hop-by-Hop or Destination Options header, one PadN option in it."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


def fragment(nxt: int, offset: int, mf: bool) -> bytes:
    """An IPv6 Fragment header; ``offset`` is in octets."""
    return bytes([nxt, 0]) + (offset | mf).to_bytes(2, 'big') + (7).to_bytes(4, 'big')


def jumbo(nxt: int, length: int) -> bytes:
    """A Hop-by-Hop Options header carrying a Jumbo Payload option (RFC 2675)."""
    return bytes([nxt, 0, 0xC2, 4]) + length.to_bytes(4, 'big')


def ethernet(packet: bytes, *, pad_to: int = 0, trailer: bytes = b'') -> bytes:
    """An Ethernet frame carrying ``packet``, padded to ``pad_to`` octets, then ``trailer``."""
    frame = wire.ethernet(packet, 0x86DD if packet[0] >> 4 == 6 else 0x0800)
    return frame + bytes(max(pad_to - len(frame), 0)) + trailer


def cases() -> 'dict[str, list[bytes]]':
    """Frames by case, each case's IPv4 datagram with an Identification of its own.

    Each is the first fragment of a 24-octet datagram, then for a pair its last.

    """
    built = {}  # type: dict[str, list[bytes]]

    def pair(label: str, carry: 'Any', ident: int) -> None:
        first = ipv4(b'A' * 16, ident=ident, mf=True)
        last = ipv4(b'B' * 8, ident=ident, offset=16)
        built[label] = [carry(first), carry(last)]

    def one(label: str, carry: 'Any', ident: int) -> None:
        built[label] = [carry(ipv4(b'A' * 16, ident=ident, mf=True))]

    # #1615: the first IPv4 layer, inside IPv6, behind extension headers, or in 6in6
    pair('4in6', lambda p: ethernet(ipv6(p, 4)), 1)
    pair('4in6 behind Destination Options', lambda p: ethernet(ipv6(options(4) + p, 60)), 2)
    pair('4in6 in 6in6', lambda p: ethernet(ipv6(ipv6(p, 4), 41)), 3)
    one('4in6 in a first IPv6 fragment', lambda p: ethernet(ipv6(fragment(4, 0, True) + p, 44)), 4)
    one('4in6 behind 32 extension headers', lambda p: ethernet(ipv6(options(60) * 31 + options(4) + p, 60)), 5)
    # whose octets end at each Payload Length above, short of a trailer
    pair('4in6 with a trailer', lambda p: ethernet(ipv6(p, 4), trailer=b'\xee' * 6), 6)
    one('4in6 cut by the Payload Length', lambda p: ethernet(ipv6(p, 4, plen=30)), 7)
    one('4in6 cut by the outer Payload Length of 6in6',
        lambda p: ethernet(ipv6(ipv6(p, 4, plen=200), 41, plen=70)), 8)
    # where the default engine dissects no IPv4 inside the IPv6 packet
    one('4in6 in a later IPv6 fragment', lambda p: ethernet(ipv6(options(44) + fragment(4, 8, False) + p, 0)), 10)
    one('4in6 behind 33 extension headers', lambda p: ethernet(ipv6(options(60) * 32 + options(4) + p, 60)), 11)
    one('4in6 with a zero Payload Length', lambda p: ethernet(ipv6(p, 4, plen=0)), 12)
    one('4in6 jumbogram shorter than the IPv4 header', lambda p: ethernet(ipv6(jumbo(4, 8 + 10) + p, 0, plen=0)), 13)
    # #1616: the header is the IHL's octets and the payload the rest of the frame
    built['Total Length below the IHL'] = [ethernet(ipv4(b'C' * 16, ident=14, options=b'\x94\x04\x00\x00',
                                                         length=10, mf=True))]
    pair('padded to the Ethernet minimum', lambda p: ethernet(p, pad_to=60), 15)
    one('Total Length 0 in 4in6, with a trailer',
        lambda p: ethernet(ipv6(p[:2] + b'\0\0' + p[4:], 4), trailer=b'\xee' * 4), 16)
    # controls: plain IPv4, the outer IPv4 of 4in4 and of 4in6in4, and no IPv4 at all
    pair('plain', ethernet, 17)
    one('4in4', lambda p: ethernet(ipv4(p, ident=18, proto=4)), 19)
    one('4in6in4', lambda p: ethernet(ipv4(ipv6(p, 4), ident=20, proto=41)), 21)
    built['IPv6 carrying UDP'] = [ethernet(ipv6(wire.udp(b'data'), 17))]
    built['ARP'] = [wire.ethernet(bytes.fromhex('0001080006040001') + wire.MAC_A + wire.IPV4_A
                                  + bytes(6) + wire.IPV4_B, 0x0806)]
    return built


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
    """dpkt's IPv4 reassembly inputs are the default engine's, octet for octet."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = cases()
        cls.frames = [frame for frames in cls.cases.values() for frame in frames]
        # one-based frame numbers of each case
        cls.numbers = {}  # type: dict[str, list[int]]
        number = 0
        for label, frames in cls.cases.items():
            cls.numbers[label] = list(range(number + 1, number + 1 + len(frames)))
            number += len(frames)

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def read(self) -> 'tuple[dict[str, Any], dict[str, Any]]':
        """The default engine's reading of every case, and dpkt's."""
        if not hasattr(type(self), 'seen'):
            type(self).seen = (read(self, 'default', self.frames), read(self, 'dpkt', self.frames))
        return type(self).seen

    def inputs(self, seen: 'dict[str, Any]', label: str) -> 'list[dict[str, Any]]':
        return [seen['inputs'][number] for number in self.numbers[label] if number in seen['inputs']]

    def test_every_input_agrees_with_the_default_engine(self) -> None:
        base, dpkt = self.read()
        for label in self.cases:
            with self.subTest(case=label):
                self.assertEqual(self.inputs(dpkt, label), self.inputs(base, label))
        self.assertEqual(dpkt['datagrams'], base['datagrams'])

    def test_ipv4_in_ipv6_is_an_input(self) -> None:
        # #1615: two inputs of the datagram tunnelled in IPv6, which completes
        base, dpkt = self.read()
        for seen in (base, dpkt):
            got = self.inputs(seen, '4in6')
            self.assertEqual([(len(packet['header']), len(packet['payload'])) for packet in got],
                             [(20, 16), (20, 8)])
            self.assertIn((self.numbers['4in6'][0], self.numbers['4in6'][1]),
                          [datagram[2] for datagram in seen['datagrams'] if datagram[0]])

    def test_each_payload_length_above_bounds_the_input(self) -> None:
        base, dpkt = self.read()
        for label, payloads in (
            ('4in6 with a trailer', [16, 8]),
            ('4in6 cut by the Payload Length', [10]),
            ('4in6 cut by the outer Payload Length of 6in6', [10]),
            ('Total Length 0 in 4in6, with a trailer', [16]),
        ):
            for seen in (base, dpkt):
                with self.subTest(case=label):
                    self.assertEqual([len(packet['payload']) for packet in self.inputs(seen, label)], payloads)

    def test_no_input_where_the_default_engine_dissects_no_ipv4(self) -> None:
        base, dpkt = self.read()
        self.assertEqual(len(self.inputs(base, '4in6 behind 32 extension headers')), 1)
        for label in ('4in6 in a later IPv6 fragment', '4in6 behind 33 extension headers',
                      '4in6 with a zero Payload Length', '4in6 jumbogram shorter than the IPv4 header',
                      'IPv6 carrying UDP', 'ARP'):
            for seen in (base, dpkt):
                with self.subTest(case=label):
                    self.assertEqual(self.inputs(seen, label), [])

    def test_input_is_not_cut_at_the_total_length(self) -> None:
        # #1616: the IHL's octets, then the rest of the frame, padding included
        base, dpkt = self.read()
        for seen in (base, dpkt):
            short, = self.inputs(seen, 'Total Length below the IHL')
            self.assertEqual((short['ihl'], short['tl']), (24, 10))
            self.assertEqual((len(short['header']), bytes(short['payload'])), (24, b'C' * 16))
            padded = self.inputs(seen, 'padded to the Ethernet minimum')
            self.assertEqual([len(packet['payload']) for packet in padded], [26, 26])
            self.assertEqual(bytes(padded[1]['payload']), b'B' * 8 + bytes(18))

    def test_a_packet_built_by_hand_is_an_input_too(self) -> None:
        # with no record buffer attached, the octets are dpkt's own serialisation
        import dpkt

        from pcapkit.toolkit import dpkt as toolkit

        for label, payload in (('4in6', b'A' * 16), ('4in6 cut by the Payload Length', b'A' * 10)):
            with self.subTest(case=label):
                data = toolkit.ipv4_reassembly(dpkt.ethernet.Ethernet(self.cases[label][0]), 1.0, count=1)
                self.assertIsNotNone(data)
                self.assertEqual((bytes(data.header), bytes(data.payload)),
                                 (self.cases[label][0][54:74], payload))


if __name__ == '__main__':
    unittest.main()
