# -*- coding: utf-8 -*-
"""Every engine traces UDP flows and IP conversations through its own adapters (#2956).

The default engine's ``udp_traceflow`` and ``ip_traceflow`` adapters are required, and
the third-party engines' are best effort (#1687): DPKT reads no UDP inside an IP-in-IP
tunnel and Scapy none in a later fragment's quoted copy, and PyPCAPFile decodes no IPv6.
Each engine traces one capture, built in memory, of a DNS query and reply, a TCP SYN, a
UDP datagram over IPv6, an ARP request, the query's endpoints tunnelled in IPv4, and a
later IPv4 fragment; the table below says which flows each engine finds. An engine
whose library is missing or unusable here is skipped.

"""
from __future__ import annotations

import importlib.util
import os
import shutil
import struct
import tempfile
import unittest
import warnings
from ipaddress import ip_address
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives third-party engines whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

ETHER = b'\x00\x11\x22\x33\x44\x55' b'\x66\x77\x88\x99\xaa\xbb'
A, B, C = (ip_address(f'192.0.2.{host}').packed for host in (1, 2, 3))
OUTER = (ip_address('203.0.113.1').packed, ip_address('203.0.113.2').packed)
V6 = (ip_address('2001:db8::1').packed, ip_address('2001:db8::2').packed)

#: A DNS query for ``a.example``, type A, class IN (RFC 1035 s4.1).
DNS_QUERY = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
             b'\x01a\x07example\x00\x00\x01\x00\x01')
#: Its reply, with no answer.
DNS_REPLY = (b'\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00'
             b'\x01a\x07example\x00\x00\x01\x00\x01')


def checksum(data: bytes) -> int:
    """The Internet checksum of ``data`` (RFC 1071)."""
    data += bytes(len(data) % 2)
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: bytes, dst: bytes, protocol: int, payload: bytes, *, offset: int = 0) -> bytes:
    """An IPv4 datagram, Don't Fragment set unless ``offset`` is."""
    flags = offset if offset else 0x4000
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 7, flags, 64,
                                   protocol, 0, src, dst))
    header[10:12] = struct.pack('!H', checksum(bytes(header)))
    return bytes(header) + payload


def udp(src: bytes, dst: bytes, srcport: int, dstport: int, payload: bytes) -> bytes:
    """A UDP datagram, its checksum over the IPv4 or IPv6 pseudo-header (RFC 768, RFC 8200 s8.1)."""
    length = 8 + len(payload)
    if len(src) == 4:
        pseudo = src + dst + struct.pack('!BBH', 0, 17, length)
    else:
        pseudo = src + dst + struct.pack('!I3xB', length, 17)
    datagram = struct.pack('!HHHH', srcport, dstport, length, 0) + payload
    return datagram[:6] + struct.pack('!H', checksum(pseudo + datagram) or 0xFFFF) + datagram[8:]


def tcp_syn(src: bytes, dst: bytes) -> bytes:
    segment = bytearray(struct.pack('!HHIIBBHHH', 40001, 80, 1000, 0, 5 << 4, 0x02, 65535, 0, 0))
    segment[16:18] = struct.pack('!H', checksum(src + dst + struct.pack('!BBH', 0, 6, 20) + bytes(segment)))
    return bytes(segment)


def frames() -> 'list[tuple[float, bytes]]':
    """The capture's frames, numbered from 1 in the table below."""
    tunnelled = ipv4(A, B, 17, udp(A, B, 40000, 53, DNS_QUERY))
    v6_udp = udp(V6[0], V6[1], 5000, 5001, b'v6')
    return [
        (1.0, ETHER + b'\x08\x00' + ipv4(A, B, 17, udp(A, B, 40000, 53, DNS_QUERY))),
        (1.5, ETHER + b'\x08\x00' + ipv4(B, A, 17, udp(B, A, 53, 40000, DNS_REPLY))),
        (2.0, ETHER + b'\x08\x00' + ipv4(A, C, 6, tcp_syn(A, C))),
        (2.5, ETHER + b'\x86\xdd' + struct.pack('!IHBB16s16s', 6 << 28, len(v6_udp), 17, 64, *V6) + v6_udp),
        (3.0, ETHER[6:] + ETHER[6:] + b'\x08\x06' + struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1,
                                                                ETHER[6:], A, bytes(6), B)),
        (3.5, ETHER + b'\x08\x00' + ipv4(*OUTER, 4, tunnelled)),
        (4.0, ETHER + b'\x08\x00' + ipv4(A, B, 17, b'later fragment data', offset=185)),
    ]


#: The IP conversations every engine finds: the outermost header's addresses.
IP_FLOWS = [('192.0.2.1-192.0.2.2-1.0', (1, 2, 7)), ('192.0.2.1-192.0.2.3-2.0', (3,)),
            ('2001.db8..1-2001.db8..2-2.5', (4,)), ('203.0.113.1-203.0.113.2-3.5', (6,))]

#: The UDP flows each engine finds, and the IP conversations where they differ from
#: :data:`IP_FLOWS`.
EXPECTED = {
    'PCAP': ([('192.0.2.1_40000-192.0.2.2_53-1.0', (1, 2, 6)), ('2001.db8..1_5000-2001.db8..2_5001-2.5', (4,))],
             IP_FLOWS),
    'PCAPNG': ([('192.0.2.1_40000-192.0.2.2_53-1.0', (1, 2, 6)), ('2001.db8..1_5000-2001.db8..2_5001-2.5', (4,))],
               IP_FLOWS),
    # DPKT reads no UDP inside an IP-in-IP tunnel, as it reads no TCP there
    'DPKT': ([('192.0.2.1_40000-192.0.2.2_53-1.0', (1, 2)), ('2001.db8..1_5000-2001.db8..2_5001-2.5', (4,))],
             IP_FLOWS),
    'Scapy': ([('192.0.2.1_40000-192.0.2.2_53-1.0', (1, 2, 6)), ('2001.db8..1_5000-2001.db8..2_5001-2.5', (4,))],
              IP_FLOWS),
    # PyPCAPFile decodes no IPv6, and no tunnel
    'PyPCAPFile': ([('192.0.2.1_40000-192.0.2.2_53-1.0', (1, 2))],
                   [flow for flow in IP_FLOWS if not flow[0].startswith('2001')]),
    # tshark dissects the tunnel, and holds the lone later fragment back from UDP
    'PyShark': ([('192.0.2.1_40000-192.0.2.2_53-1.0', (1, 2, 6)), ('2001.db8..1_5000-2001.db8..2_5001-2.5', (4,))],
                IP_FLOWS),
}


def pcap(records: 'list[tuple[float, bytes]]') -> bytes:
    """A microsecond little-endian PCAP savefile of Ethernet ``records``."""
    octets = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for (timestamp, data) in records:
        usec = round(timestamp * 1_000_000)
        octets += struct.pack('<IIII', usec // 1_000_000, usec % 1_000_000, len(data), len(data)) + data
    return octets


def pcapng(records: 'list[tuple[float, bytes]]') -> bytes:
    """A little-endian PCAP-NG section of one Ethernet interface and ``records`` as EPBs."""
    def block(kind: int, body: bytes) -> bytes:
        body += bytes(-len(body) % 4)
        return struct.pack('<II', kind, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))

    octets = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    octets += block(1, struct.pack('<HHI', 1, 0, 65535))
    for (timestamp, data) in records:
        usec = round(timestamp * 1_000_000)
        octets += block(6, struct.pack('<IIIII', 0, usec >> 32, usec & 0xFFFFFFFF, len(data), len(data)) + data)
    return octets


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineTests(unittest.TestCase):
    """Each runnable engine finds the flows :data:`EXPECTED` gives it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)

    def capture(self, octets: bytes, suffix: str) -> str:
        path = os.path.join(self.root, f'capture{suffix}')
        with open(path, 'wb') as file:
            file.write(octets)
        return path

    def runnable(self) -> 'list[tuple[str, str]]':
        """``(engine key, capture suffix)`` for each engine that runs here."""
        from pcapkit.foundation.engines.pyshark import PyShark
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        found = [('default', '.pcap'), ('default', '.pcapng')]
        if importlib.util.find_spec('dpkt') is not None:
            found += [('dpkt', '.pcap'), ('dpkt', '.pcapng')]
        if importlib.util.find_spec('scapy') is not None:
            found += [('scapy', '.pcap'), ('scapy', '.pcapng')]
        if importlib.util.find_spec('pcapfile') is not None and PyPCAPFile.unsupported_reason() is None:
            found.append(('pypcapfile', '.pcap'))
        if importlib.util.find_spec('pyshark') is not None and PyShark.unsupported_reason() is None:
            found += [('pyshark', '.pcap'), ('pyshark', '.pcapng')]
        return found

    def extract(self, path: str, engine: str, **options: 'Any') -> 'Any':
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.options import TraceFlowOptions

        fout = tempfile.mkdtemp(dir=self.root)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return Extractor(path, engine=engine, store=False,  # type: ignore[arg-type]
                             traceflow=TraceFlowOptions(protocols=['udp', 'ip'], fout=fout, format='json',
                                                        **options))

    def test_each_engine_finds_its_flows(self) -> None:
        captures = {'.pcap': self.capture(pcap(frames()), '.pcap'),
                    '.pcapng': self.capture(pcapng(frames()), '.pcapng')}
        for (engine, suffix) in self.runnable():
            with self.subTest(engine=engine, capture=suffix):
                extractor = self.extract(captures[suffix], engine)
                udp_flows, ip_flows = EXPECTED[type(extractor.engine).__name__]
                self.assertEqual([(flow.label, flow.index) for flow in extractor.traceflow.udp], udp_flows)
                self.assertEqual([(flow.label, flow.index) for flow in extractor.traceflow.ip], ip_flows)
                # the reply is the query flow's reverse half
                query = extractor.traceflow.udp[0]
                self.assertEqual(query.reverse, (2,))
                self.assertEqual(query.forward, tuple(frame for frame in udp_flows[0][1] if frame != 2))
                self.assertIsNone(query.packet)

    def test_analyze_parses_the_same_datagrams_on_each_engine(self) -> None:
        captures = {'.pcap': self.capture(pcap(frames()), '.pcap'),
                    '.pcapng': self.capture(pcapng(frames()), '.pcapng')}
        for (engine, suffix) in self.runnable():
            if engine == 'pyshark':  # reports fields, not octets, so refuses analyze
                continue
            with self.subTest(engine=engine, capture=suffix):
                extractor = self.extract(captures[suffix], engine, analyze=True)
                query, reply = extractor.traceflow.udp[0].packet[:2]
                self.assertEqual((query.info.id, query.info.flags.qr), (0x1234, False))
                self.assertEqual((reply.info.id, reply.info.flags.qr), (0x1234, True))
                self.assertEqual(bytes(query.packet.header) + bytes(query.packet.payload), DNS_QUERY)


if __name__ == '__main__':
    unittest.main()
