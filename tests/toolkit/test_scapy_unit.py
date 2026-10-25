from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import builtins
import importlib
import os
import struct
import tempfile
import unittest
import warnings
from unittest import mock

from tests._support import close_extractor, purge_modules, reimport_once_per_class

#: Test tier (#1958): drives Scapy, whose installable releases vary by interpreter; the
#: integration and pypcap-parity legs install it on every interpreter, and a test leg
#: off latest skips it.
__tier__ = 'ALL'

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Octets an Ethernet frame carries past its IP datagram -- an FCS, say.
TRAILER = bytes.fromhex('deadbeef')
#: The datagram #1584 sends as two 40-octet fragments.
DATAGRAM = bytes(range(80))


def write_pcap(frames: 'list[bytes]', linktype: 'int' = 1) -> 'str':
    """Write ``frames`` to a temporary PCAP file, Ethernet unless ``linktype`` says otherwise, and return its path."""
    fd, path = tempfile.mkstemp(suffix='.pcap')
    with os.fdopen(fd, 'wb') as file:
        file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for index, frame in enumerate(frames):
            file.write(struct.pack('<IIII', 1_600_000_000 + index, 0, len(frame), len(frame)))
            file.write(frame)
    return path


def extract(test: 'unittest.TestCase', frames: 'list[bytes]', linktype: 'int' = 1, **kwargs: 'object'):
    """Read ``frames``, a PCAP file of ``linktype``, with the scapy engine, which ``test`` closes after it."""
    import pcapkit

    path = write_pcap(frames, linktype)
    test.addCleanup(os.remove, path)
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        extractor = pcapkit.extract(fin=path, nofile=True, engine='scapy', **kwargs)
    test.addCleanup(close_extractor, extractor)
    if extractor._exnam != 'scapy':  # pylint: disable=protected-access
        test.skipTest('scapy did not run')
    return extractor


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies not installed')
class ScapyToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _ether_kwargs(self) -> dict[str, str]:
        return {
            'src': 'aa:aa:aa:aa:aa:aa',
            'dst': 'bb:bb:bb:bb:bb:bb',
        }

    def _make_ipv4_tcp_packet(self):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        packet = (
            Ether(**self._ether_kwargs()) /
            IP(src='192.0.2.1', dst='198.51.100.1', id=123) /
            TCP(sport=1234, dport=80, seq=10, ack=5, flags='SA') /
            Raw(b'data')
        )
        return Ether(bytes(packet))

    def _make_ipv4_fragment(self, *, df: bool = False):
        from scapy.layers.inet import IP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        flags = 'DF' if df else 'MF'
        packet = (
            Ether(**self._ether_kwargs()) /
            IP(src='192.0.2.1', dst='198.51.100.1', id=123, flags=flags,
               frag=0 if df else 2) /
            Raw(b'fragment')
        )
        return Ether(bytes(packet))

    def _make_ipv6_fragment(self):
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        packet = (
            Ether(**self._ether_kwargs()) /
            # the fragment identification is deliberately different from the flow
            # label, so a ``bufid`` keyed on the wrong one of the two is visible
            IPv6(src='2001:db8::1', dst='2001:db8::2', fl=7) /
            IPv6ExtHdrFragment(nh=6, offset=1, m=1, id=4321) /
            Raw(b'v6')
        )
        return Ether(bytes(packet))

    def _make_ipv6_tcp_packet(self):
        from scapy.layers.inet import TCP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        packet = (
            Ether(**self._ether_kwargs()) /
            IPv6(src='2001:db8::1', dst='2001:db8::2', fl=7) /
            TCP(sport=1234, dport=443, seq=10, ack=5, flags='S') /
            Raw(b'v6tcp')
        )
        return Ether(bytes(packet))

    def _make_ether_raw(self):
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        return Ether(bytes(Ether(**self._ether_kwargs()) / Raw(b'raw')))

    def _make_ip_rooted_tcp_packet(self):
        # No Ether layer, so ``packet.name`` (what #775's tier 1 fix in
        # ``tcp_traceflow`` feeds ``Enum_LinkType.get()``) is ``'IP'`` -- not a
        # LinkType member name, unlike the Ether-rooted packets above whose
        # name is ``'Ethernet'``.
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw

        packet = (
            IP(src='192.0.2.1', dst='198.51.100.1', id=123) /
            TCP(sport=1234, dport=80, seq=10, ack=5, flags='SA') /
            Raw(b'data')
        )
        return IP(bytes(packet))

    def test_import_without_scapy_sets_none_and_warns(self) -> None:
        # Put a real import back afterwards, for the tests that share this
        # class's import (GitHub issue #1065). Cleanups run last-in first-out:
        # purge the scapy-less copy, then re-import, which also rebinds the
        # ``pcapkit.toolkit.scapy`` attribute a ``from`` import reads first.
        self.addCleanup(importlib.import_module, 'pcapkit.toolkit.scapy')
        self.addCleanup(purge_modules, ['pcapkit.toolkit.scapy'])
        purge_modules(['pcapkit.toolkit.scapy'])
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == 'scapy':
                raise ModuleNotFoundError("No module named 'scapy'")
            return real_import(name, *args, **kwargs)

        with mock.patch('builtins.__import__', side_effect=fake_import):
            module = importlib.import_module('pcapkit.toolkit.scapy')

        self.assertIsNone(module.scapy)

    def test_packet_chain_dict_and_optional_dependency_errors(self) -> None:
        from pcapkit.toolkit import scapy as toolkit
        from pcapkit.utilities.exceptions import ModuleNotFound

        packet = self._make_ipv4_tcp_packet()
        self.assertEqual(toolkit.packet2chain(packet), 'Ethernet:IP:TCP:Raw')
        converted = toolkit.packet2dict(packet)
        self.assertEqual(converted['packet'], bytes(packet))
        self.assertIn('IP', converted['Ethernet'])
        self.assertIn('TCP', converted['Ethernet']['IP'])

        with mock.patch.object(toolkit, 'scapy', None):
            with self.assertRaises(ModuleNotFound):
                toolkit.packet2chain(packet)
            with self.assertRaises(ModuleNotFound):
                toolkit.packet2dict(packet)
            with self.assertRaises(ModuleNotFound):
                toolkit.ipv6_reassembly(packet)

    def test_ipv4_and_ipv6_reassembly(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6ExtHdrFragment

        from pcapkit.toolkit import scapy as toolkit

        fragment = self._make_ipv4_fragment()
        ipv4 = fragment[IP]
        reassembled = toolkit.ipv4_reassembly(fragment, count=3)
        self.assertIsNotNone(reassembled)
        assert reassembled is not None
        self.assertEqual(reassembled.num, 3)
        self.assertEqual(reassembled.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(reassembled.bufid[1], ip_address('198.51.100.1'))
        self.assertEqual(reassembled.bufid[2], 123)
        self.assertEqual(reassembled.ihl, 20)
        self.assertEqual(reassembled.header, bytes(ipv4)[:20])
        self.assertEqual(bytes(reassembled.payload), bytes(ipv4.payload))
        self.assertTrue(reassembled.mf)
        # Scapy's ``frag`` is in on-wire 8-octet units (:rfc:`791#section-3.1`),
        # but ``fo`` indexes the reassembly datagram buffer in octets, so one
        # unit must become 8 octets -- see #483.
        self.assertEqual(ipv4.frag, 2)
        self.assertEqual(reassembled.fo, 16)

        self.assertIsNone(toolkit.ipv4_reassembly(self._make_ether_raw(), count=1))
        self.assertIsNone(toolkit.ipv4_reassembly(self._make_ipv4_fragment(df=True), count=1))

        v6_packet = self._make_ipv6_fragment()
        ipv6_frag = v6_packet[IPv6ExtHdrFragment]
        v6 = toolkit.ipv6_reassembly(v6_packet, count=4)
        self.assertIsNotNone(v6)
        assert v6 is not None
        self.assertEqual(v6.num, 4)
        self.assertEqual(v6.bufid[0], ip_address('2001:db8::1'))
        self.assertEqual(v6.bufid[1], ip_address('2001:db8::2'))
        # identification, not flow label -- ``bufid[2]`` feeds ``DatagramID.id``
        self.assertEqual(v6.bufid[2], 4321)
        self.assertNotEqual(v6.bufid[2], 7)
        self.assertEqual(v6.bufid[3].value, 6)
        # Scapy's ``offset`` is in on-wire 8-octet units, but ``fo`` indexes the
        # reassembly datagram buffer in octets, so one unit must become 8 octets
        self.assertEqual(ipv6_frag.offset, 1)
        self.assertEqual(v6.fo, 8)
        self.assertTrue(v6.mf)
        self.assertEqual(bytes(v6.payload), bytes(ipv6_frag.payload))

        self.assertIsNone(toolkit.ipv6_reassembly(self._make_ipv4_tcp_packet(), count=1))
        self.assertIsNone(toolkit.ipv6_reassembly(self._make_ipv6_tcp_packet(), count=1))

    def test_ipv4_reassembly_scales_fragment_offset_through_the_reassembler(self) -> None:
        # Regression test for #483: an unscaled ``fo`` does not just report a
        # wrong number, it makes the reassembler write the second fragment's
        # payload *inside* the first fragment's span instead of after it -- so
        # the defect has to be shown through an actual reassembly, not by
        # asserting on ``fo`` in isolation (a unit fix could get that right
        # while some other adapter/consumer mismatch still corrupted the
        # datagram, and a suite total alone cannot tell the two apart).
        from scapy.layers.inet import IP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.toolkit import scapy as toolkit

        # Fragment 1: offset 0, 40 octets of payload -- a multiple of 8, so
        # fragment 2's on-wire ``frag=5`` is meant to land at byte offset 40
        # (5 * 8), immediately after fragment 1's data.
        frag1 = Ether(**self._ether_kwargs()) / \
            IP(src='192.0.2.1', dst='198.51.100.1', id=1234, flags='MF', frag=0) / \
            Raw(b'A' * 40)
        frag1 = Ether(bytes(frag1))

        # Fragment 2: final fragment, on-wire ``frag=5`` -> byte offset 40.
        frag2 = Ether(**self._ether_kwargs()) / \
            IP(src='192.0.2.1', dst='198.51.100.1', id=1234, flags=0, frag=5) / \
            Raw(b'B' * 8)
        frag2 = Ether(bytes(frag2))

        packet1 = toolkit.ipv4_reassembly(frag1, count=1)
        packet2 = toolkit.ipv4_reassembly(frag2, count=2)
        assert packet1 is not None and packet2 is not None
        self.assertEqual(packet1.fo, 0)
        # this is the assertion that fails without the ``* 8`` scaling: an
        # unscaled ``fo`` reports 5, not the byte offset 40
        self.assertEqual(packet2.fo, 40)

        reasm = IPv4()
        reasm(packet1)
        reasm(packet2)

        datagram, = reasm.datagram
        # only ``Completion.COMPLETE`` is truthy
        self.assertTrue(datagram.completed)
        # under the defect this comes back truncated to 13 octets
        # (``b'AAAAABBBBBBBB'``): fragment 2 overwrote bytes 5-12 of
        # fragment 1's span instead of being appended at byte 40, and the
        # datagram's declared total length is computed from the corrupted
        # (unscaled) offset of the final fragment
        self.assertEqual(len(datagram.payload), 48)
        self.assertEqual(bytes(datagram.payload), b'A' * 40 + b'B' * 8)
        # #482's overlap detection is what actually witnesses the corruption:
        # under the defect fragment 2 lands inside fragment 1's span and
        # differs from it, so the datagram comes back carrying
        # ``conflict == ((5, 12),)``. Asserting the record is *empty* pins the
        # absence of an overlap rather than only the payload that results from
        # there being none -- a later change could restore the right bytes by
        # some other route and still be overwriting.
        self.assertEqual(datagram.conflict, ())

    def test_tcp_reassembly_and_traceflow(self) -> None:
        from scapy.layers.inet import TCP
        from scapy.packet import Raw

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import scapy as toolkit

        packet = self._make_ipv4_tcp_packet()
        tcp_layer = packet[TCP]
        tcp = toolkit.tcp_reassembly(packet, count=8)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(tcp.bufid[1], 1234)
        self.assertEqual(tcp.bufid[3], 80)
        self.assertTrue(tcp.syn)
        self.assertFalse(tcp.fin)
        self.assertFalse(tcp.rst)
        self.assertEqual(tcp.header, bytes(tcp_layer)[:tcp_layer.dataofs * 4])
        self.assertEqual(bytes(tcp.payload), bytes(tcp_layer[Raw]))
        # ``first``/``last`` are absolute sequence numbers bounding the payload
        # inclusively, so they span exactly ``len`` octets -- the same
        # convention every other engine's toolkit has to use, since they all
        # feed the one reassembler
        self.assertEqual(tcp.first, tcp_layer.seq)
        self.assertEqual(tcp.last, tcp_layer.seq + tcp.len - 1)
        self.assertEqual(tcp.last - tcp.first + 1, tcp.len)
        v6_tcp = toolkit.tcp_reassembly(self._make_ipv6_tcp_packet(), count=9)
        self.assertIsNotNone(v6_tcp)
        assert v6_tcp is not None
        self.assertEqual(v6_tcp.bufid[0], ip_address('2001:db8::1'))
        self.assertEqual(v6_tcp.bufid[3], 443)

        # the flow label carries the *capture's* clock, read off ``Packet.time``,
        # rather than the moment of parsing -- so the deterministic value is
        # pinned on the packet itself rather than by patching ``time.time``
        packet.time = 77.25
        flow = toolkit.tcp_traceflow(packet, count=8)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.protocol, LinkType.ETHERNET)
        self.assertEqual(flow.index, 8)
        self.assertTrue(flow.syn)
        self.assertFalse(flow.fin)
        self.assertEqual(flow.timestamp, 77.25)

        self.assertIsNone(toolkit.tcp_reassembly(self._make_ipv4_fragment(), count=1))
        self.assertIsNone(toolkit.tcp_reassembly(self._make_ether_raw(), count=1))
        self.assertIsNone(toolkit.tcp_traceflow(self._make_ipv4_fragment(), count=1))

    def test_tcp_traceflow_raises_for_an_ip_rooted_packet(self) -> None:
        """An IP-rooted (Ether-less) packet's ``.name`` is ``'IP'``, which is
        not a LinkType member name. Since #775 tier 1, ``Enum_LinkType.get()``
        with no default raises on an unresolvable name instead of minting
        one -- and per the ruling on #838, NULL and RAW are genuine DLTs with
        their own handler protocol classes, not stand-ins for "unknown link
        type", so this call site no longer papers over the miss with a
        ``LinkType.NULL`` default. This pins that the miss now raises
        :exc:`~pcapkit.utilities.exceptions.MissingKeyError` naming the
        offending value, and that the registry is still not grown by it.

        Contrast an Ether-rooted packet, exercised in
        ``test_tcp_reassembly_and_traceflow`` above: ``(Ether()/IP()/TCP()).
        name`` is ``'Ethernet'``, which *does* resolve to
        ``LinkType.ETHERNET``, so only the IP-rooted path raises here.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import scapy as toolkit
        from pcapkit.utilities.exceptions import MissingKeyError

        packet = self._make_ip_rooted_tcp_packet()
        self.assertEqual(packet.name, 'IP')

        before = len(LinkType.__members__)
        with self.assertRaises(MissingKeyError) as ctx:
            toolkit.tcp_traceflow(packet, count=1)
        after = len(LinkType.__members__)

        self.assertEqual(ctx.exception.args[0], 'IP')
        self.assertEqual(before, after)


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies not installed')
class ScapyTrailerTests(unittest.TestCase):
    """The adapters stop at the datagram's declared length (GitHub issue #1584).

    Scapy files the octets past an IP layer's Total Length or Payload Length as a
    ``Padding`` layer, and ``bytes()`` of every layer above it ends with them, so
    an IPv6 fragment's data and a TCP segment's payload both carried the frame's
    trailer. Every frame here is written to a capture and read back through the
    engine.

    """

    #: The TCP payload each of :meth:`_tcp_frames` carries.
    TCP_PAYLOADS = {
        'padded': b'X',
        'trailer': b'YZ',
        'pure-ack-padded': b'',
        'ipv6-ext-header-trailer': b'six',
        'ip-in-ip-trailers': b'in',
        'zero-total-length': b'tso-data',
    }

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _ether(self):
        from scapy.layers.l2 import Ether

        return Ether(src='aa:aa:aa:aa:aa:aa', dst='bb:bb:bb:bb:bb:bb')

    def _ip_frames(self) -> 'list[bytes]':
        """``DATAGRAM`` as IPv4, then as IPv6, fragments; each last one has a trailer."""
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
        from scapy.packet import Raw

        ipv4 = {'src': '192.0.2.1', 'dst': '198.51.100.1', 'id': 7, 'proto': 17}
        ipv6 = {'src': '2001:db8::1', 'dst': '2001:db8::2'}
        return [
            bytes(self._ether() / IP(**ipv4, flags='MF', frag=0) / Raw(DATAGRAM[:40])),
            bytes(self._ether() / IP(**ipv4, frag=5) / Raw(DATAGRAM[40:])) + TRAILER,
            bytes(self._ether() / IPv6(**ipv6) /
                  IPv6ExtHdrFragment(nh=17, offset=0, m=1, id=99) / Raw(DATAGRAM[:40])),
            bytes(self._ether() / IPv6(**ipv6) /
                  IPv6ExtHdrFragment(nh=17, offset=5, m=0, id=99) / Raw(DATAGRAM[40:])) + TRAILER,
        ]

    def _tcp_frames(self) -> 'list[bytes]':
        """One frame per :attr:`TCP_PAYLOADS` entry, in its order."""
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt
        from scapy.packet import Raw

        ipv4 = {'src': '192.0.2.1', 'dst': '198.51.100.1'}
        ipv6 = {'src': '2001:db8::1', 'dst': '2001:db8::2'}

        def padded(frame: 'bytes') -> 'bytes':
            return frame + bytes(60 - len(frame))   # Ethernet's minimum frame

        inner = bytes(IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=5, dport=6, flags='PA') /
                      Raw(b'in')) + b'\xaa\xbb'
        tso = bytes(self._ether() / IP(**ipv4) / TCP(sport=9, dport=10, flags='PA') / Raw(b'tso-data'))
        return [
            padded(bytes(self._ether() / IP(**ipv4) / TCP(sport=1, dport=2, seq=100, flags='PA') /
                         Raw(b'X'))),
            bytes(self._ether() / IP(**ipv4) / TCP(sport=1, dport=2, seq=101, flags='PA') /
                  Raw(b'YZ')) + TRAILER,
            padded(bytes(self._ether() / IP(**ipv4) / TCP(sport=3, dport=4, seq=7, flags='A'))),
            bytes(self._ether() / IPv6(**ipv6) / IPv6ExtHdrDestOpt() /
                  TCP(sport=1, dport=2, flags='PA') / Raw(b'six')) + TRAILER,
            bytes(self._ether() / IP(**ipv4, proto=4) / Raw(inner)) + TRAILER,
            # a Total Length of 0 runs the datagram to the end of the frame
            tso[:16] + b'\x00\x00' + tso[18:],
        ]

    def _extract(self, frames: 'list[bytes]', **kwargs: 'object'):
        return extract(self, frames, **kwargs)

    def test_ipv6_fragment_data_stops_at_the_payload_length(self) -> None:
        from pcapkit.toolkit import scapy as toolkit

        packets = self._extract(self._ip_frames(), store=True).frame
        first, last = (toolkit.ipv6_reassembly(packet) for packet in packets[2:])
        assert first is not None and last is not None
        self.assertEqual(bytes(first.payload), DATAGRAM[:40])
        # 44 octets and a ``tl`` of 84 before the fix
        self.assertEqual(bytes(last.payload), DATAGRAM[40:])
        self.assertEqual((last.ihl, last.tl), (40, 80))

    def test_reassembled_datagrams_are_the_datagram_sent(self) -> None:
        extractor = self._extract(self._ip_frames(), store=False, reassembly=True, ip=True)
        for name, datagrams in (('ipv4', extractor.reassembly.ipv4),
                                ('ipv6', extractor.reassembly.ipv6)):
            with self.subTest(version=name):
                datagram, = datagrams
                # only ``Completion.COMPLETE`` is truthy
                self.assertTrue(datagram.completed)
                # IPv6 came back 84 octets long, ending in the trailer
                self.assertEqual(datagram.payload, DATAGRAM)

    def test_tcp_payload_stops_at_the_datagram_end(self) -> None:
        from scapy.layers.inet import TCP

        from pcapkit.toolkit import scapy as toolkit

        packets = self._extract(self._tcp_frames(), store=True).frame
        self.assertEqual(len(packets), len(self.TCP_PAYLOADS))
        for (name, expected), packet in zip(self.TCP_PAYLOADS.items(), packets):
            with self.subTest(frame=name):
                header = bytes(packet[TCP])[:20]
                segment = toolkit.tcp_reassembly(packet)
                assert segment is not None
                self.assertEqual(bytes(segment.payload), expected)
                self.assertEqual(segment.len, len(expected))
                self.assertEqual(segment.last, segment.first + len(expected) - 1)
                self.assertEqual(segment.header, header)

                flow = toolkit.tcp_traceflow(packet)
                assert flow is not None
                self.assertEqual(bytes(flow.payload), expected)
                self.assertEqual(flow.header, header)

    def test_tcp_reassembly_is_the_stream_sent(self) -> None:
        extractor = self._extract(self._tcp_frames(), store=False, reassembly=True, tcp=True)
        scapy = {(str(datagram.id.src[0]), datagram.id.src[1]): datagram.payload
                 for datagram in extractor.reassembly.tcp}
        # ``b'X\x00\x00\x00\x00\x00\xef'`` before the fix: the first segment's
        # padding took the place of the second's data, and its trailer followed
        self.assertEqual(scapy.get(('192.0.2.1', 1)), b'XYZ')
        self.assertEqual(scapy.get(('2001:db8::1', 1)), b'six')

    def _assert_tcp_records(self, frames: 'list[bytes]', expected: 'list[bytes | None]') -> None:
        """Each frame gives ``expected`` TCP payload, or no record."""
        from pcapkit.toolkit import scapy as toolkit

        packets = self._extract(frames, store=True).frame
        self.assertEqual(len(packets), len(expected))
        for index, (packet, payload) in enumerate(zip(packets, expected)):
            with self.subTest(frame=index):
                segment = toolkit.tcp_reassembly(packet)
                flow = toolkit.tcp_traceflow(packet)
                self.assertEqual(None if segment is None else bytes(segment.payload), payload)
                self.assertEqual(None if flow is None else bytes(flow.payload), payload)

    def test_a_data_offset_below_the_fixed_header_gives_no_segment(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw

        # a header shorter than 20 octets is malformed (:rfc:`9293#section-3.1`);
        # the payload here had started with the last of the header's octets
        self._assert_tcp_records([
            bytes(self._ether() / IP(src='192.0.2.1', dst='198.51.100.1') /
                  TCP(sport=1, dport=2, flags='PA', dataofs=dataofs) / Raw(b'abcdef')) + TRAILER
            for dataofs in (0, 4)
        ], [None, None])

    def test_a_total_length_below_the_header_gives_no_segment(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw

        frame = bytes(self._ether() / IP(src='192.0.2.1', dst='198.51.100.1') /
                      TCP(sport=1, dport=2, flags='PA') / Raw(b'abcdef'))
        # 10 octets is less than the IPv4 header, and 30 holds only half the TCP
        # header; the former had come back as an empty record
        self._assert_tcp_records([frame[:16] + struct.pack('!H', length) + frame[18:]
                                  for length in (10, 30)], [None, None])

    def test_a_tunnelled_segment_ends_with_the_shortest_datagram(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw

        def inner(data: 'bytes') -> 'bytearray':
            return bytearray(bytes(IP(src='10.0.0.1', dst='10.0.0.2') /
                                   TCP(sport=5, dport=6, flags='PA') / Raw(data)))

        outer = {'src': '192.0.2.1', 'dst': '198.51.100.1', 'proto': 4}
        tso = inner(b'tsoin')
        tso[2:4] = b'\x00\x00'      # the inner datagram declares no length at all
        # the first fragment of the outer datagram ends with the TCP header,
        # though the inner datagram declares 40 octets of data after it
        overrun = inner(b'x' * 40)[:40]
        self._assert_tcp_records([
            bytes(self._ether() / IP(**outer) / Raw(bytes(tso))) + TRAILER,
            bytes(self._ether() / IP(**outer, id=1, flags='MF') / Raw(bytes(overrun))) + TRAILER,
        ], [b'tsoin', b''])

    def test_data_with_no_length_to_stop_at_is_taken_whole(self) -> None:
        from scapy.layers.inet import TCP
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
        from scapy.packet import Raw

        from pcapkit.toolkit import scapy as toolkit

        # a segment with no IP layer above it at all
        tcp = TCP(bytes(TCP(sport=1, dport=2, flags='PA') / Raw(b'bare')))
        self.assertEqual(toolkit._tcp_segment(tcp), (bytes(tcp)[:20], b'bare'))

        # a fragment built by hand, whose Payload Length is only filled in when
        # the packet is built
        packet = self._ether() / IPv6() / IPv6ExtHdrFragment(id=1) / Raw(b'hand')
        self.assertIsNone(packet[IPv6].plen)
        fragment = toolkit.ipv6_reassembly(packet)
        assert fragment is not None
        self.assertEqual(bytes(fragment.payload), b'hand')


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies not installed')
class ScapyFrameGuardTests(unittest.TestCase):
    """Frames whose Scapy layers claim more than their octets hold (GitHub issue #1708).

    Each guard here first came with a fix that #1708 reverted, as that fix's
    aim was to read frames as the default engine does. They are kept because
    they are the adapters' own job, whatever any other engine reads: to end no
    extraction, and to hand on only the frame's own octets, as the datagram
    the adapter reports them for.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _ether(self):
        from scapy.layers.l2 import Ether

        return Ether(src='aa:aa:aa:aa:aa:aa', dst='bb:bb:bb:bb:bb:bb')

    def test_a_zero_length_frame_ends_no_extraction(self) -> None:
        # #1676: Scapy hands a zero-length frame back as ``IP()`` at RAW (101)
        # and IPV4 (228), whose ``ihl`` is None, and IPv4 reassembly raised
        # TypeError on it, which ended the extraction
        from pcapkit.toolkit import scapy as toolkit

        frame = bytes.fromhex('4500001c00010000400600000a0000010a000002') + bytes(8)
        for linktype in (101, 228):
            with self.subTest(linktype=linktype):
                extractor = extract(self, [b'', frame], linktype, store=True, reassembly=True, ipv4=True)
                self.assertEqual(len(extractor.frame), 2)
                self.assertIsNone(toolkit.ipv4_reassembly(extractor.frame[0]))
                self.assertEqual([tuple(datagram.index) for datagram in extractor.reassembly.ipv4], [(2,)])

    def test_a_zero_length_frame_carries_no_octets(self) -> None:
        # #1676: ``bytes()`` of the layer of defaults Scapy hands a zero-length
        # frame back as builds a header out of nothing, which ``packet2dict``
        # reported as the frame's octets
        from pcapkit.toolkit import scapy as toolkit

        for linktype in (0, 1, 101, 108, 228, 229):
            with self.subTest(linktype=linktype):
                packet, = extract(self, [b''], linktype, store=True).frame
                self.assertEqual(toolkit.packet2dict(packet)['packet'], b'')
                record = toolkit.packet2frame(packet)
                self.assertEqual((bytes(record.packet), record.frame_info.incl_len), (b'', 0))

    def test_ipv4_in_ipv6_ends_at_the_payload_length(self) -> None:
        # #1623: Scapy files what follows an IPv6 Payload Length as padding at the
        # end of the packet, so ``bytes()`` of the IPv4 layer inside ended with
        # the frame's trailer, and IPv4 reassembly took it for the datagram's data
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw

        from pcapkit.toolkit import scapy as toolkit

        ip = {'src': '192.0.2.1', 'dst': '198.51.100.1', 'proto': 17}
        ipv6 = {'src': '2001:db8::1', 'dst': '2001:db8::2', 'nh': 4}
        tso = bytearray(bytes(IP(**ip, id=3) / Raw(b'A' * 16)))
        tso[2:4] = b'\x00\x00'      # a Total Length of 0, as TCP segmentation offload leaves it
        # an IPv4 header of 24 octets, its options cut short by a Payload Length of 22
        fixed = bytes(IP(**ip, id=4, flags='MF', len=40))[:20]
        options = bytes([0x46]) + fixed[1:] + b'\x01' * 4 + b'B' * 16
        frames = [bytes(self._ether() / IPv6(**ipv6) / Raw(bytes(tso))) + TRAILER,
                  bytes(self._ether() / IPv6(**ipv6, plen=22) / Raw(options)) + TRAILER]

        extractor = extract(self, frames, store=True, reassembly=True, ipv4=True)
        whole, cut = extractor.frame
        data = toolkit.ipv4_reassembly(whole)
        assert data is not None
        self.assertEqual((bytes(data.header), bytes(data.payload)), (bytes(tso[:20]), b'A' * 16))
        self.assertIsNone(toolkit.ipv4_reassembly(cut))
        datagram, = extractor.reassembly.ipv4
        # only ``Completion.COMPLETE`` is truthy
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'A' * 16)

    def test_a_packet_built_by_hand_is_read_as_the_octets_it_builds(self) -> None:
        # #1676: Scapy leaves ``ihl``, ``len`` and ``dataofs`` None on a layer
        # built by hand until it is built; IPv4 and TCP reassembly and TCP flow
        # tracing raised TypeError on them, and the frame record that flow
        # tracing hands on carried none of the packet's octets
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw

        from pcapkit.toolkit import scapy as toolkit

        ip = {'src': '192.0.2.1', 'dst': '198.51.100.1'}
        fragment = self._ether() / IP(**ip, id=5, flags='MF') / Raw(b'x' * 8)
        self.assertIsNone(fragment[IP].ihl)
        data = toolkit.ipv4_reassembly(fragment)
        assert data is not None
        self.assertEqual((data.ihl, data.tl, bytes(data.header), bytes(data.payload)),
                         (20, 28, bytes(fragment)[14:34], b'x' * 8))

        segment = TCP(sport=1, dport=2) / Raw(b'data')
        for label, packet, start in (
            ('ipv4', self._ether() / IP(**ip, flags='DF') / segment, 34),
            ('ipv6', self._ether() / IPv6(src='2001:db8::1', dst='2001:db8::2') / segment, 54),
            # given a Total Length but no IHL
            ('ipv4 of a total length', self._ether() / IP(**ip, flags='DF', len=44) / segment, 34),
        ):
            with self.subTest(packet=label):
                octets = bytes(packet)
                record = toolkit.tcp_reassembly(packet)
                assert record is not None
                self.assertEqual((bytes(record.header), bytes(record.payload)), (octets[start:start + 20], b'data'))
                flow = toolkit.tcp_traceflow(packet)
                assert flow is not None
                self.assertEqual((bytes(flow.header), bytes(flow.payload)), (octets[start:start + 20], b'data'))
                self.assertEqual((bytes(flow.frame.packet), flow.frame.frame_info.incl_len), (octets, len(octets)))

    def test_ipv6_reassembly_takes_only_its_own_fragment_header(self) -> None:
        # The Fragment header of a packet the IPv6 layer carries, here the inner
        # packet of 6in6, had been handed on with the outer packet's addresses,
        # and both IPv6 headers as the part before the Fragment header
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        from pcapkit.toolkit import scapy as toolkit

        inner = IPv6(src='fd00::1', dst='fd00::2') / IPv6ExtHdrFragment(nh=17, id=7, m=1) / Raw(b'B' * 16)
        tunnelled = Ether(bytes(self._ether() / IPv6(src='2001:db8::1', dst='2001:db8::2') / inner))
        self.assertIsNone(toolkit.ipv6_reassembly(tunnelled))
        # carried in IPv4, the inner packet is the first IPv6 layer, and the Fragment header its own
        data = toolkit.ipv6_reassembly(Ether(bytes(self._ether() / IP(src='192.0.2.1', dst='198.51.100.1') / inner)))
        assert data is not None
        self.assertEqual((str(data.bufid[0]), data.bufid[2], bytes(data.header)), ('fd00::1', 7, bytes(inner)[:40]))

    def test_no_ipv6_fragment_is_read_in_a_later_ipv4_fragment(self) -> None:
        # A later IPv4 fragment's data is a slice of the datagram's payload, with
        # no upper-layer header in it (:rfc:`791#section-3.2`), but Scapy dissects
        # IPv6 in it whatever the fragment offset
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        from pcapkit.toolkit import scapy as toolkit

        ip = {'src': '192.0.2.1', 'dst': '198.51.100.1', 'proto': 41}
        inner = IPv6(src='fd00::1', dst='fd00::2') / IPv6ExtHdrFragment(nh=17, id=7, m=1) / Raw(b'B' * 16)
        later = Ether(bytes(self._ether() / IP(**ip, frag=5) / inner))
        self.assertIsInstance(later[IP].payload, IPv6)
        self.assertIsNone(toolkit.ipv6_reassembly(later))
        # the first fragment's data does start with the IPv6 header
        self.assertIsNotNone(toolkit.ipv6_reassembly(Ether(bytes(self._ether() / IP(**ip, flags='MF') / inner))))


if __name__ == '__main__':
    unittest.main()
