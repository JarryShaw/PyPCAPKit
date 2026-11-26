# -*- coding: utf-8 -*-
"""A reassembled payload is parsed with the extraction's stops and context (#2933).

The default engine parses each frame with the ``layer``, ``protocol`` and
``context`` given to ``extract()``, so a datagram that IP or TCP reassembly
rebuilds from those frames has its ``packet`` parsed with them as well: as the
frame path parses the same octets sent whole. ``Protocol.analyze`` and
``Transport.analyze`` keep a payload past the stop raw, as a frame keeps the
next layer of the layer it stops at, and hand the parse the code they
dispatched on as ``alias``, as a frame hands its next layer.

Every capture is built in memory, as PCAP and as PCAP-NG; no sample capture is read.

"""

from __future__ import annotations

import importlib.util
import ipaddress
import struct
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import (
    _extract, _pcap, _pcapng)

if TYPE_CHECKING:
    from typing import Any

#: The containers each extraction runs over.
CONTAINERS = (('pcap', _pcap), ('pcapng', _pcapng))

V4_SRC, V4_DST = ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2')
V6_SRC, V6_DST = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')

#: A UDP datagram to the discard port, which ESP below carries.
INNER = struct.pack('!HHHH', 1234, 9, 32, 0) + bytes(range(24))
#: ESP-NULL on SPI 7: :data:`INNER`, padding ``01 02``, pad length 2, next header 17.
ESP = struct.pack('!II', 7, 3) + INNER + bytes([1, 2, 2, 17])
#: A DNS query for ``example.com``, A, IN.
QUERY = (struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
         + b'\x07example\x03com\x00\x00\x01\x00\x01')
#: A UDP datagram carrying :data:`QUERY` to port 53.
DNS = struct.pack('!HHHH', 1234, 53, 8 + len(QUERY), 0) + QUERY
#: An HTTP request, which the TCP captures carry in two segments.
REQUEST = (b'GET / HTTP/1.1\r\n', b'Host: example\r\n\r\n')
#: An IP protocol number no next layer is registered for.
UNASSIGNED = 253


def _ether(packet: bytes, ethertype: int) -> bytes:
    return b'\xbb' * 6 + b'\xaa' * 6 + ethertype.to_bytes(2, 'big') + packet


def _ipv4(payload: bytes, protocol: int, *, offset: int = 0, mf: bool = False,
          df: bool = False) -> bytes:
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | offset // 8
    return _ether(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0x1234, flags, 64,
                              protocol, 0, V4_SRC.packed, V4_DST.packed) + payload, 0x0800)


def _ipv6(payload: bytes, protocol: int, *, offset: int, mf: bool) -> bytes:
    fragment = struct.pack('!BBHI', protocol, 0, offset | int(mf), 0x5678) + payload
    return _ether(struct.pack('!IHBB16s16s', 6 << 28, len(fragment), 44, 64,
                              V6_SRC.packed, V6_DST.packed) + fragment, 0x86DD)


def _fragments(kind: str, payload: bytes, protocol: int) -> 'list[bytes]':
    """``payload`` as IPv4 or IPv6 fragments, split after its first 16 octets."""
    build = _ipv4 if kind == 'ipv4' else _ipv6
    return [build(payload[:16], protocol, offset=0, mf=True),
            build(payload[16:], protocol, offset=16, mf=False)]


def _tcp(payload: bytes, *, seq: int, fin: bool = False) -> bytes:
    flags = 0x18 | (0x01 if fin else 0)  # PSH, ACK, and FIN if asked
    segment = struct.pack('!HHIIBBHHH', 1234, 80, seq, 1, 5 << 4, flags, 0xFFFF, 0, 0) + payload
    return _ipv4(segment, 6, df=True)


#: The segments of :data:`REQUEST`, the last one closing the flow.
SEGMENTS = [_tcp(REQUEST[0], seq=1000), _tcp(REQUEST[1], seq=1000 + len(REQUEST[0]), fin=True)]


def _context() -> 'Any':
    """The context that opens :data:`ESP`."""
    from pcapkit.protocols.internet.esp.protocol import ESPContext, SecurityAssociation

    return ESPContext(SecurityAssociation(spi=7))


class _Case(unittest.TestCase):
    """Each extraction, and the frame path's parse of the same octets sent whole."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def reassembled(self, kind: str, frames: 'list[bytes]',
                    **kwargs: 'Any') -> 'list[tuple[str, Any]]':
        """Each container's name, and the ``packet`` of its one ``kind`` datagram."""
        packets = []
        for name, build in CONTAINERS:
            extractor = _extract(self, build(frames), reassembly=[kind], **kwargs)
            datagrams = getattr(extractor.reassembly, kind)
            self.assertEqual(len(datagrams), 1, name)
            packets.append((name, datagrams[0].packet))
        return packets

    def whole(self, frame: bytes, **kwargs: 'Any') -> 'Any':
        """The IPv4 layer's payload, as the frame path parses ``frame``."""
        return _extract(self, _pcap([frame]), **kwargs).frame[0]['IPv4'].payload

    def assertSameParse(self, packet: 'Any', whole: 'Any') -> None:
        """``packet`` is what the frame path parses ``whole`` to, and rebuilds byte for byte."""
        self.assertIs(type(packet), type(whole))
        self.assertEqual(str(packet.protochain), str(whole.protochain))
        self.assertEqual(packet.info, whole.info)
        self.assertEqual(bytes(type(packet).from_data(packet.info)), bytes(packet))


class ReassembledContextTests(_Case):
    """A reassembled ESP datagram finds the SA the extraction was given."""

    def test_fragmented_esp_decrypts_with_the_extraction_context(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESPStatus

        whole = self.whole(_ipv4(ESP, 50, df=True), context=_context())
        self.assertIs(whole.info.status, ESPStatus.DECRYPTED)
        self.assertEqual(whole.info.plaintext, INNER)
        for kind in ('ipv4', 'ipv6'):
            frames = _fragments(kind, ESP, 50)
            for container, packet in self.reassembled(kind, frames, context=_context()):
                with self.subTest(kind=kind, container=container):
                    self.assertSameParse(packet, whole)

    def test_no_context_finds_no_sa(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESPStatus

        for container, packet in self.reassembled('ipv4', _fragments('ipv4', ESP, 50)):
            with self.subTest(container=container):
                self.assertIs(packet.info.status, ESPStatus.NO_SA)

    @unittest.skipUnless(importlib.util.find_spec('dpkt') is not None, 'dpkt not installed')
    def test_an_engine_ignoring_the_context_ignores_it_here_too(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESPStatus

        extractor = _extract(self, _pcap(_fragments('ipv4', ESP, 50)), engine='dpkt',
                             reassembly=['ipv4'], context=_context())
        self.assertIs(extractor.reassembly.ipv4[0].packet.info.status, ESPStatus.NO_SA)


class ReassembledStopTests(_Case):
    """A reassembled payload stops where the extraction's frames stop."""

    def test_stop_inside_the_payload(self) -> None:
        for stop in ({'layer': 'Transport'}, {'protocol': 'UDP'}):
            with self.subTest(**stop):
                whole = self.whole(_ipv4(DNS, 17, df=True), **stop)
                self.assertEqual(str(whole.protochain), 'UDP:Raw')
                frames = _fragments('ipv4', DNS, 17)
                for container, packet in self.reassembled('ipv4', frames, **stop):
                    with self.subTest(container=container):
                        self.assertSameParse(packet, whole)

    def test_stop_at_the_reassembled_layer_keeps_the_payload_raw(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        for stop in ({'layer': 'Internet'}, {'protocol': 'IPv4'}):
            with self.subTest(**stop):
                whole = self.whole(_ipv4(DNS, 17, df=True), **stop)
                self.assertIs(type(whole), Raw)
                frames = _fragments('ipv4', DNS, 17)
                for container, packet in self.reassembled('ipv4', frames, **stop):
                    with self.subTest(container=container):
                        self.assertSameParse(packet, whole)
                        self.assertEqual(bytes(packet), DNS)

    def test_tcp_payload_stops_at_the_transport_layer(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        extractor = _extract(self, _pcap(SEGMENTS[:1]), layer='Transport')
        whole = extractor.frame[0]['TCP'].payload
        self.assertIs(type(whole), Raw)
        for container, packet in self.reassembled('tcp', SEGMENTS, layer='Transport'):
            with self.subTest(container=container):
                self.assertIs(type(packet), Raw)
                self.assertEqual(bytes(packet), b''.join(REQUEST))
                self.assertEqual(packet.info.protocol, whole.info.protocol)

    def test_no_stop_parses_the_whole_payload(self) -> None:
        for container, packet in self.reassembled('ipv4', _fragments('ipv4', DNS, 17)):
            with self.subTest(container=container):
                self.assertEqual(str(packet.protochain), 'UDP:DNS')
        for container, packet in self.reassembled('tcp', SEGMENTS):
            with self.subTest(container=container):
                self.assertEqual(type(packet).__name__, 'HTTPv1')


class AnalyzeTests(unittest.TestCase):
    """``analyze`` parses a payload as the layer it dispatches from parses its next one."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_stops_given_to_analyze(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        octets = _ipv4(DNS, 17, df=True)[14:]
        for stop in ({'layer': 'Internet'}, {'layer': 'internet'}, {'protocol': IPv4},
                     {'layer': 'Transport'}, {'layer': None, 'protocol': None}, {}):
            with self.subTest(stop=stop):
                whole = IPv4(octets, **stop).payload
                packet = IPv4.analyze(TransType.UDP, DNS, **stop)
                self.assertIs(type(packet), type(whole))
                self.assertEqual(str(packet.protochain), str(whole.protochain))
                self.assertEqual(packet.info, whole.info)
                self.assertEqual(bytes(type(packet).from_data(packet.info)), DNS)

    def test_trial_takes_the_code_as_alias(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.raw.protocol import Raw

        frame = IPv4(_ipv4(b'octets', UNASSIGNED, df=True)[14:])
        packet = IPv4.analyze(TransType(UNASSIGNED), b'octets')
        self.assertIs(type(packet), Raw)
        self.assertEqual(packet.info, frame.payload.info)
        self.assertEqual(str(packet.protochain), str(frame.payload.protochain))

    def test_reassembled_payload_of_an_unassigned_protocol(self) -> None:
        frame = _ipv4(INNER, UNASSIGNED, df=True)
        for name, build in CONTAINERS:
            with self.subTest(container=name):
                whole = _extract(self, build([frame])).frame[0]['IPv4'].payload
                extractor = _extract(self, build(_fragments('ipv4', INNER, UNASSIGNED)),
                                     reassembly=['ipv4'])
                packet = extractor.reassembly.ipv4[0].packet
                self.assertEqual(packet.info, whole.info)
                self.assertEqual(str(packet.protochain), str(whole.protochain))


if __name__ == '__main__':
    unittest.main()
