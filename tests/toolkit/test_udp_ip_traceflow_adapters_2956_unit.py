# -*- coding: utf-8 -*-
"""The UDP and IP flow tracing adapters read the layers their tracers key on (#2956).

A UDP record takes the endpoints of the IP layer nearest above the UDP layer, the
innermost in an IP-in-IP tunnel, as TCP's does (#1581); an IP record takes the
outermost header's, the conversation the link carries. A later fragment carries no UDP
header, so is an IP record alone, and a frame with no IP layer is neither. The default
engine's adapters are read on frames parsed in memory, and the third-party ones on their
own packet objects or stand-ins for them; an engine whose library is missing is skipped.

"""
from __future__ import annotations

import importlib.util
import io
import struct
import types
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
A, B = ip_address('192.0.2.1').packed, ip_address('192.0.2.2').packed
OUTER = (ip_address('203.0.113.1').packed, ip_address('203.0.113.2').packed)


def ipv4(src: bytes, dst: bytes, protocol: int, payload: bytes, *, offset: int = 0) -> bytes:
    """An IPv4 datagram with a zero checksum, Don't Fragment set unless ``offset`` is."""
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 7, offset or 0x4000, 64, protocol,
                       0, src, dst) + payload


def udp(srcport: int, dstport: int, payload: bytes) -> bytes:
    """A UDP datagram with no checksum."""
    return struct.pack('!HHHH', srcport, dstport, 8 + len(payload), 0) + payload


#: Each frame, and the ``(src, srcport, dst, dstport, payload)`` of its UDP record and
#: ``(src, dst)`` of its IP record, :data:`None` where it has none.
FRAMES = {
    'udp': (ETHER + b'\x08\x00' + ipv4(A, B, 17, udp(40000, 53, b'query')),
            ('192.0.2.1', 40000, '192.0.2.2', 53, b'query'), ('192.0.2.1', '192.0.2.2')),
    'tunnel': (ETHER + b'\x08\x00' + ipv4(*OUTER, 4, ipv4(A, B, 17, udp(40000, 53, b'inner'))),
               ('192.0.2.1', 40000, '192.0.2.2', 53, b'inner'), ('203.0.113.1', '203.0.113.2')),
    'later fragment': (ETHER + b'\x08\x00' + ipv4(A, B, 17, b'\x9c\x40\x00\x35' * 4, offset=185),
                       None, ('192.0.2.1', '192.0.2.2')),
    'arp': (ETHER + b'\x08\x06' + struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, ETHER[6:], A,
                                              bytes(6), B), None, None),
}


def pcap(frames: 'list[bytes]') -> bytes:
    """A microsecond little-endian PCAP savefile of Ethernet ``frames``, one a second."""
    octets = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for (second, data) in enumerate(frames, 1):
        octets += struct.pack('<IIII', second, 0, len(data), len(data)) + data
    return octets


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AdapterCase(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def check(self, name: str, udp_record: 'Any', ip_record: 'Any') -> None:
        """Compare an adapter's records with :data:`FRAMES`'s for the frame ``name``."""
        _, udp_want, ip_want = FRAMES[name]
        if udp_want is None:
            self.assertIsNone(udp_record)
        else:
            self.assertIsNotNone(udp_record)
            self.assertEqual((str(udp_record.src), udp_record.srcport, str(udp_record.dst), udp_record.dstport,
                              udp_record.payload), udp_want)
        if ip_want is None:
            self.assertIsNone(ip_record)
        else:
            self.assertIsNotNone(ip_record)
            self.assertEqual((str(ip_record.src), str(ip_record.dst)), ip_want)


class DefaultEngineTests(AdapterCase):
    """:mod:`pcapkit.toolkit.pcap`, on the frames the PCAP engine parsed."""

    def test_each_frame(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.toolkit.pcap import ip_traceflow, udp_traceflow

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(io.BytesIO(pcap([frame for (frame, _, _) in FRAMES.values()])), store=True)
        for (number, (name, frame)) in enumerate(zip(FRAMES, extractor.frame), 1):
            with self.subTest(frame=name):
                udp_record = udp_traceflow(frame, data_link=LinkType.ETHERNET)
                ip_record = ip_traceflow(frame, data_link=LinkType.ETHERNET)
                self.check(name, udp_record, ip_record)
                for record in (udp_record, ip_record):
                    if record is not None:
                        self.assertEqual((record.index, record.timestamp, record.protocol),
                                         (number, float(number), LinkType.ETHERNET))
                        self.assertIs(record.frame, frame.info)


@unittest.skipUnless(importlib.util.find_spec('dpkt') is not None, 'dpkt not installed')
class DPKTTests(AdapterCase):
    """:mod:`pcapkit.toolkit.dpkt`, which reads no UDP inside an IP-in-IP tunnel."""

    def test_each_frame(self) -> None:
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.dpkt import ip_traceflow, udp_traceflow

        for (name, (frame, _, ip_want)) in FRAMES.items():
            with self.subTest(frame=name):
                packet = dpkt.ethernet.Ethernet(frame)
                udp_record = udp_traceflow(packet, 1.5, data_link=LinkType.ETHERNET, count=3)
                ip_record = ip_traceflow(packet, 1.5, data_link=LinkType.ETHERNET, count=3)
                if name == 'tunnel':
                    self.assertIsNone(udp_record)
                    self.assertEqual((str(ip_record.src), str(ip_record.dst)), ip_want)
                    continue
                self.check(name, udp_record, ip_record)
                if ip_record is not None:
                    self.assertEqual((ip_record.index, ip_record.timestamp), (3, 1.5))

    def test_a_udp_layer_dpkt_binds_as_data_alone(self) -> None:
        # a packet built by hand carries its UDP layer as ``data``, with no ``udp`` attribute
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.dpkt import udp_traceflow

        packet = dpkt.ip.IP(src=A, dst=B, p=17, data=dpkt.udp.UDP(sport=40000, dport=53, data=b'query'))
        self.assertFalse(hasattr(packet, 'udp'))
        record = udp_traceflow(packet, 1.5, data_link=LinkType.IPV4)
        self.assertEqual((str(record.src), record.srcport, str(record.dst), record.dstport, record.payload),
                         ('192.0.2.1', 40000, '192.0.2.2', 53, b'query'))


@unittest.skipUnless(importlib.util.find_spec('scapy') is not None, 'scapy not installed')
class ScapyTests(AdapterCase):
    """:mod:`pcapkit.toolkit.scapy`."""

    def packet(self, frame: bytes) -> 'Any':
        # NOTE: importing the layers binds IP to Ethernet, as the engine's ``scapy.all`` does.
        import scapy.layers.inet  # pylint: disable=unused-import
        import scapy.layers.inet6  # pylint: disable=unused-import
        from scapy.layers.l2 import Ether

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.scapy import attach_linktype

        packet = Ether(frame)
        packet.time = 1.5
        attach_linktype(packet, int(LinkType.ETHERNET))
        return packet

    def test_each_frame(self) -> None:
        from pcapkit.toolkit.scapy import ip_traceflow, udp_traceflow

        for (name, (frame, _, _)) in FRAMES.items():
            with self.subTest(frame=name):
                packet = self.packet(frame)
                self.check(name, udp_traceflow(packet, count=3), ip_traceflow(packet, count=3))

    def test_a_datagram_an_icmp_error_quotes_is_no_flow_of_its_own(self) -> None:
        from pcapkit.toolkit.scapy import ip_traceflow, udp_traceflow

        quoted = ipv4(A, B, 17, udp(40000, 53, b'query'))
        icmp = struct.pack('!BBHI', 3, 3, 0, 0) + quoted
        packet = self.packet(ETHER + b'\x08\x00' + ipv4(B, A, 1, icmp))
        self.assertIsNone(udp_traceflow(packet))
        self.assertEqual((str(ip_traceflow(packet).src), str(ip_traceflow(packet).dst)), ('192.0.2.2', '192.0.2.1'))


class PySharkTests(AdapterCase):
    """:mod:`pcapkit.toolkit.pyshark`, on stand-ins for its packets, which report fields."""

    @staticmethod
    def layer(name: str, **fields: str) -> 'Any':
        return types.SimpleNamespace(layer_name=name, field_names=tuple(fields), **fields)

    def packet(self, *layers: 'Any') -> 'Any':
        frame = self.layer('frame', encap_type='1', time_epoch='1.500000000')
        return types.SimpleNamespace(number='9', frame_info=frame, layers=[frame, *layers])

    def test_the_innermost_ip_layer_keys_udp_and_the_outermost_ip(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pyshark import ip_traceflow, udp_traceflow

        packet = self.packet(self.layer('eth'), self.layer('ip', src='203.0.113.1', dst='203.0.113.2'),
                             self.layer('ip', src='192.0.2.1', dst='192.0.2.2'),
                             self.layer('udp', srcport='40000', dstport='53'))
        record = udp_traceflow(packet, count=4)
        self.assertEqual((str(record.src), record.srcport, str(record.dst), record.dstport, record.payload),
                         ('192.0.2.1', 40000, '192.0.2.2', 53, b''))
        self.assertEqual((record.index, record.timestamp, record.protocol), (4, 1.5, LinkType.ETHERNET))
        record = ip_traceflow(packet, count=4)
        self.assertEqual((str(record.src), str(record.dst)), ('203.0.113.1', '203.0.113.2'))

    def test_what_tshark_leaves_out_is_not_traced(self) -> None:
        from pcapkit.toolkit.pyshark import ip_traceflow, udp_traceflow

        # no UDP layer, a UDP layer without its ports, an IP layer without its addresses
        for layers in ((self.layer('ip', src='192.0.2.1', dst='192.0.2.2'),),
                       (self.layer('ip', src='192.0.2.1', dst='192.0.2.2'), self.layer('udp', srcport='1')),
                       (self.layer('ip', src='192.0.2.1'), self.layer('udp', srcport='1', dstport='2'))):
            with self.subTest(layers=[layer.layer_name for layer in layers]):
                self.assertIsNone(udp_traceflow(self.packet(self.layer('eth'), *layers)))
        self.assertIsNone(ip_traceflow(self.packet(self.layer('eth'), self.layer('arp'))))
        self.assertIsNone(ip_traceflow(self.packet(self.layer('eth'), self.layer('ipv6', src='2001:db8::1'))))


class PyPCAPFileTests(AdapterCase):
    """:mod:`pcapkit.toolkit.pypcapfile`, which decodes IPv4 alone."""

    @staticmethod
    def packet(payload: 'Any', **fields: 'Any') -> 'Any':
        ip = types.new_class('IP')()
        ip.__dict__.update(v=4, hl=5, tos=0, len=20 + len(payload) if isinstance(payload, bytes) else 0, id=7,
                           flags=0, off=0, ttl=64, p=17, sum=0, src=b'192.0.2.1', dst=b'192.0.2.2', opt=b'',
                           payload=payload)
        ip.__dict__.update(fields)
        ether = types.new_class('Ethernet')()
        ether.__dict__.update(dst=bytearray(6), src=bytearray(6), type=0x0800, payload=ip)
        return types.SimpleNamespace(header=[types.SimpleNamespace(ns_resolution=False)], timestamp=1,
                                     timestamp_us=500000, capture_len=60, packet_len=60, packet=ether)

    def test_ip_conversations(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import ip_traceflow

        record = ip_traceflow(self.packet(b'anything', p=6), data_link=LinkType.ETHERNET, count=2)
        self.assertEqual((str(record.src), str(record.dst), record.index, record.timestamp),
                         ('192.0.2.1', '192.0.2.2', 2, 1.5))
        not_ip = self.packet(b'')
        not_ip.packet.payload = b'raw'
        self.assertIsNone(ip_traceflow(not_ip, data_link=LinkType.ETHERNET))

    def test_what_carries_no_udp_header_is_declined_before_decoding(self) -> None:
        # declined before the UDP decoder is imported, so pcapfile need not be installed
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import udp_traceflow

        for (label, packet) in (('TCP', self.packet(udp(1, 2, b''), p=6)),
                                ('later fragment', self.packet(udp(1, 2, b''), off=185))):
            with self.subTest(packet=label):
                self.assertIsNone(udp_traceflow(packet, data_link=LinkType.ETHERNET))

    @unittest.skipUnless(importlib.util.find_spec('pcapfile') is not None, 'pypcapfile not installed')
    def test_udp_datagrams(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import udp_traceflow

        record = udp_traceflow(self.packet(udp(40000, 53, b'query')), data_link=LinkType.ETHERNET, count=2)
        self.assertEqual((str(record.src), record.srcport, str(record.dst), record.dstport, record.payload),
                         ('192.0.2.1', 40000, '192.0.2.2', 53, b'query'))
        # cut at the IPv4 Total Length, then at the UDP Length
        padded = self.packet(udp(40000, 53, b'query') + b'\x00' * 6, len=20 + 13)
        self.assertEqual(udp_traceflow(padded, data_link=LinkType.ETHERNET).payload, b'query')
        short = struct.pack('!HHHH', 40000, 53, 10, 0) + b'query'
        self.assertEqual(udp_traceflow(self.packet(short), data_link=LinkType.ETHERNET).payload, b'qu')
        self.assertIsNone(udp_traceflow(self.packet(b'\x9c\x40\x00\x35'), data_link=LinkType.ETHERNET))


if __name__ == '__main__':
    unittest.main()
