# -*- coding: utf-8 -*-
"""scapy reads nothing in a zero-length frame, and a packet built by hand as the frame it builds. C.f. #1676.

`Scapy`_ dissects a packet only from a non-empty string, so a zero-length frame
comes back as the first layer its link type names with every field left to its
default -- at ``RAW`` and ``IPV4`` an IPv4 header whose ``ihl`` and ``len`` are
:data:`None` -- and ``bytes()`` of it builds a header out of nothing. IPv4
reassembly raised ``TypeError`` on the IHL, which ended the extraction, where
the default engine and dpkt read nothing in the frame and go on. ``packet2dict``
reported the octets of the header it built (#1676).

A packet built by hand is a layer of defaults too: `Scapy`_ leaves its ``ihl``,
``len`` and a TCP layer's ``dataofs`` :data:`None` until it is built, so IPv4 and
TCP reassembly and TCP flow tracing raised on one, and the frame record flow
tracing hands on carried none of its octets. It is now read as the frame it
builds, at the link type its first layer stands for.

Each engine is compared with the default engine, on every input it hands TCP
and IP reassembly and TCP flow tracing. Every capture is built here, so the
module is in the unit tier.

.. _Scapy: https://scapy.net

"""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit import test_dpkt_ipv4_reassembly_input_1615_1616_unit as ipv4_input
from tests.toolkit.test_scapy_ipv6_fragment_and_encap_walk_1635_1636_unit import fragment6, read
from tests.toolkit.test_tcp_carrier_walk_1606_1617_unit import eth, has, tcp, v4, v6

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: The inputs compared, as :func:`read` keys them.
ASPECTS = ('tcp', 'trace', 'ipv4', 'ipv6', 'ipv4 datagrams', 'ipv6 datagrams', 'ids', 'flows')

#: The engines compared with the default engine.
ENGINES = ('scapy', 'dpkt')

#: TCP in IPv4, then the two fragments of a 24-octet IPv4 datagram.
V4 = [v4(tcp(1), 6), ipv4_input.ipv4(b'A' * 16, ident=3, mf=True), ipv4_input.ipv4(b'B' * 8, ident=3, offset=16)]
#: The two fragments of a 24-octet IPv6 datagram, then TCP in IPv6.
V6 = [v6(fragment6(b'A' * 16, ident=4, mf=True), 44), v6(fragment6(b'B' * 8, ident=4, offset=16), 44), v6(tcp(2), 6)]


def loopback(order: str) -> 'Callable[[bytes], bytes]':
    """A BSD loopback header, ``order``-endian, of family 2 or 24 by the IP ``packet``'s version, then the packet."""
    return lambda packet: (24 if packet[0] >> 4 == 6 else 2).to_bytes(4, order) + packet


class LinkType(NamedTuple):
    """A link type the default engine dissects, and the frames it carries IP in."""

    #: The capture's link type.
    linktype: int
    #: The frame an IP packet is carried in.
    carry: 'Callable[[bytes], bytes]'
    #: The IP packets that follow the frame under test.
    packets: 'list[bytes]'
    #: How many frames the default engine hands TCP, IPv4 and IPv6 reassembly.
    reads: 'tuple[int, int, int]'

    def frames(self, first: bytes) -> 'list[bytes]':
        """``first``, then a frame carrying each of :attr:`packets`."""
        return [first, *map(self.carry, self.packets)]


LINK_TYPES = {
    'raw (101)': LinkType(101, lambda packet: packet, V4 + V6, (2, 3, 2)),
    'ipv4 (228)': LinkType(228, lambda packet: packet, V4, (1, 3, 0)),
    'ipv6 (229)': LinkType(229, lambda packet: packet, V6, (1, 0, 2)),
    'null (0), little-endian': LinkType(0, loopback('little'), V4 + V6, (2, 3, 2)),
    'null (0), big-endian': LinkType(0, loopback('big'), V4 + V6, (2, 3, 2)),
    'loop (108)': LinkType(108, loopback('big'), V4 + V6, (2, 3, 2)),
    'ethernet (1)': LinkType(1, eth, V4 + V6, (2, 3, 2)),
}

#: Frames cut short, each before the frames of a link type in
#: :data:`LINK_TYPES`, with what the default engine reads in the cut frame,
#: TCP, IPv4 and IPv6. Controls: `Scapy`_ dissects none of them as a layer of
#: defaults, so scapy read them as the default engine does already.
CUT_SHORT = {
    'raw (101), ipv4 header cut at 19': ('raw (101)', V4[0][:19], (0, 0, 0)),
    'raw (101), ipv6 header cut at 39': ('raw (101)', V6[2][:39], (0, 0, 0)),
    'raw (101), ipv4 tcp cut at 10': ('raw (101)', V4[0][:30], (0, 1, 0)),
    'ipv4 (228), one octet': ('ipv4 (228)', V4[0][:1], (0, 0, 0)),
    'ipv6 (229), one octet': ('ipv6 (229)', V6[2][:1], (0, 0, 0)),
    'null (0), 3 octets': ('null (0), little-endian', b'\x02\x00\x00', (0, 0, 0)),
    'null (0), the header alone': ('null (0), little-endian', b'\x02\x00\x00\x00', (0, 0, 0)),
    'loop (108), the header alone': ('loop (108)', b'\x00\x00\x00\x18', (0, 0, 0)),
    'ethernet (1), one octet': ('ethernet (1)', b'\x02', (0, 0, 0)),
    'ethernet (1), the header alone': ('ethernet (1)', wire.ethernet(b'', 0x0800), (0, 0, 0)),
    'ethernet (1), an ipv4 fragment with no data': ('ethernet (1)', eth(ipv4_input.ipv4(b'', ident=9, mf=True)),
                                                    (0, 1, 0)),
}


def fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'Any':
    """``packet``'s fields as :func:`read` records them, or :data:`None`."""
    if packet is None:
        return None
    return {key: bytes(value) if isinstance(value, bytearray) else value
            for key, value in packet.items() if key not in skip}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
class ScapyZeroLengthFrameTests(unittest.TestCase):
    """scapy reads nothing in a zero-length frame, and reads on past it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_issue_capture_is_read_to_the_end(self) -> None:
        from pcapkit import extract

        frames = [(0, 0, b''), (0, 0, bytes.fromhex('4500001c00010000400600000a0000010a000002') + bytes(8))]
        read_ = {}
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            # the issue's PCAP, and the same records as a PCAP-NG's EPBs
            for savefile in ('pcap', 'pcapng'):
                path = os.path.join(tmp, f'raw0.{savefile}')
                with open(path, 'wb') as file:
                    file.write(getattr(wire, savefile)(frames, linktype=101))
                for engine in ('default', *(engine for engine in ENGINES if has(engine))):
                    extractor = extract(fin=path, engine=engine, nofile=True, reassembly=True, ipv4=True)
                    try:
                        read_[savefile, engine] = len(extractor.frame)
                    finally:
                        close_extractor(extractor)
        self.assertEqual(read_, dict.fromkeys(read_, 2))

    def test_no_input_is_read_in_a_zero_length_frame_at_any_link_type(self) -> None:
        cases = {f'{label}, zero-length': (label, b'', (0, 0, 0)) for label in LINK_TYPES}
        cases.update(CUT_SHORT)
        reads, disagree = {}, []
        for label, (name, first, cut) in cases.items():
            link = LINK_TYPES[name]
            frames = link.frames(first)
            base = read(self, 'default', frames, link.linktype)
            reads[label] = tuple(len(base[aspect]) for aspect in ('tcp', 'ipv4', 'ipv6'))
            for engine in ENGINES:
                if not has(engine):
                    continue
                try:
                    seen = read(self, engine, frames, link.linktype)
                except Exception as exc:  # pylint: disable=broad-except
                    disagree.append((label, engine, f'{type(exc).__name__}: {exc}'))
                    continue
                differ = [aspect for aspect in ASPECTS if seen[aspect] != base[aspect]]
                if differ:
                    disagree.append((label, engine, differ))
        # what the default engine reads -- the frames after the first, and what
        # it reads in that one -- then that every other engine reads the same
        self.assertEqual(reads, {label: tuple(map(sum, zip(LINK_TYPES[name].reads, cut)))
                                 for label, (name, _, cut) in cases.items()})
        self.assertEqual(disagree, [])

    def test_a_zero_length_frame_carries_no_octets(self) -> None:
        from pcapkit import extract
        from pcapkit.toolkit.scapy import packet2dict, packet2frame

        seen, expected = {}, {}
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            for label, link in LINK_TYPES.items():
                path = os.path.join(tmp, 'zero.pcap')
                with open(path, 'wb') as file:
                    file.write(wire.pcap([(1, 0, b'')], linktype=link.linktype))
                extractor = extract(fin=path, engine='default', nofile=True)
                try:
                    octets = bytes(extractor.frame[0].info.packet)
                    expected[label] = (octets, len(octets), octets)
                finally:
                    close_extractor(extractor)
                extractor = extract(fin=path, engine='scapy', nofile=True)
                try:
                    if extractor._exnam != 'scapy':  # pylint: disable=protected-access
                        self.skipTest('scapy did not run')
                    packet = extractor.frame[0]
                    record = packet2frame(packet)
                    seen[label] = (bytes(record.packet), record.frame_info.incl_len, packet2dict(packet)['packet'])
                finally:
                    close_extractor(extractor)
        self.assertEqual(seen, expected)
        self.assertEqual(set(seen.values()), {(b'', 0, b'')})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
class ScapyHandBuiltPacketTests(unittest.TestCase):
    """A packet built by hand is read as the frame it builds, at the link type its first layer stands for."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def cases() -> 'dict[str, Any]':
        # ``scapy.all`` binds every layer here, as the engine has it do (see pcapkit.toolkit.scapy)
        from scapy.all import IP, TCP, Ether, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, Raw

        ether = {'src': '02:00:00:00:00:01', 'dst': '02:00:00:00:00:02'}
        ip = {'src': '192.0.2.1', 'dst': '198.51.100.1'}
        ip6 = {'src': '2001:db8::1', 'dst': '2001:db8::2'}
        segment = TCP(sport=1, dport=2) / Raw(b'data')
        return {
            # IPv4 reassembly raised on the IHL
            'ipv4 with no fields': IP(),
            'ipv4 fragment': Ether(**ether) / IP(**ip, id=5, flags='MF') / Raw(b'x' * 8),
            'ipv4 fragment in ipv6': Ether(**ether) / IPv6(**ip6) / IP(**ip, id=5, flags='MF') / Raw(b'x' * 8),
            # TCP reassembly and flow tracing raised on the Data Offset
            'tcp in ipv4': Ether(**ether) / IP(**ip, flags='DF') / segment,
            'tcp in ipv6': Ether(**ether) / IPv6(**ip6) / segment,
            'tcp in ipv6 behind hop-by-hop': Ether(**ether) / IPv6(**ip6) / IPv6ExtHdrHopByHop() / segment,
            'tcp in 4in4': Ether(**ether) / IP(**ip, flags='DF') / IP(**ip, flags='DF') / segment,
            # ... and on the IHL of an IPv4 layer given a Total Length alone
            'tcp in ipv4 of a total length': Ether(**ether) / IP(**ip, flags='DF', len=44) / segment,
            # read off the octets already, but traced with a frame record of none
            'tcp in ipv4 behind hop-by-hop': Ether(**ether) / IP(**ip, flags='DF', proto=0)
            / IPv6ExtHdrHopByHop(nh=6) / segment,
            # controls: read off the octets already
            'ipv6 fragment': Ether(**ether) / IPv6(**ip6) / IPv6ExtHdrFragment(id=1, m=1) / Raw(b'hand'),
            'ipv6 fragment in ipv4': Ether(**ether) / IP(**ip, flags='DF') / IPv6(**ip6)
            / IPv6ExtHdrFragment(id=1, m=1) / Raw(b'hand'),
        }

    def test_a_packet_built_by_hand_is_read_as_the_frame_it_builds(self) -> None:
        from scapy.layers.l2 import Ether

        from pcapkit.toolkit import scapy as toolkit

        seen, expected = {}, {}
        for label, packet in self.cases().items():
            packet.time = 1  # as :func:`read` dates the frame
            frame = bytes(packet)
            ethernet = isinstance(packet, Ether)
            base = read(self, 'default', [frame], 1 if ethernet else 228)
            # an IP-rooted packet names no link type to trace it at (see below)
            aspects = ('ipv4', 'ipv6', 'tcp', 'trace') if ethernet else ('ipv4', 'ipv6', 'tcp')
            expected[label] = {aspect: base[aspect].get(1) for aspect in aspects}
            if expected[label].get('trace') is not None:
                # the frame record carries the octets the input was read from
                expected[label]['frame'] = (frame, len(frame))
            got = {}  # type: dict[str, Any]
            for aspect in aspects:
                adapter = toolkit.tcp_traceflow if aspect == 'trace' else getattr(toolkit, f'{aspect}_reassembly')
                try:
                    with warnings.catch_warnings():
                        # as :func:`read` has the default engine do
                        warnings.simplefilter('ignore')
                        result = adapter(packet, count=1)
                except Exception as exc:  # pylint: disable=broad-except
                    got[aspect] = f'{type(exc).__name__}: {exc}'
                    continue
                got[aspect] = fields(result, ('frame',) if aspect == 'trace' else ())
                if aspect == 'trace' and result is not None:
                    got['frame'] = (bytes(result.frame.packet), result.frame.frame_info.incl_len)
            seen[label] = got
        self.assertEqual(seen, expected)
        # what the default engine reads in each
        self.assertEqual({label: tuple(aspect for aspect, value in inputs.items() if value is not None)
                          for label, inputs in expected.items()}, {
            'ipv4 with no fields': ('ipv4',),
            'ipv4 fragment': ('ipv4',),
            'ipv4 fragment in ipv6': ('ipv4',),
            'tcp in ipv4': ('tcp', 'trace', 'frame'),
            'tcp in ipv6': ('tcp', 'trace', 'frame'),
            'tcp in ipv6 behind hop-by-hop': ('tcp', 'trace', 'frame'),
            'tcp in 4in4': ('tcp', 'trace', 'frame'),
            'tcp in ipv4 of a total length': ('tcp', 'trace', 'frame'),
            'tcp in ipv4 behind hop-by-hop': ('tcp', 'trace', 'frame'),
            'ipv6 fragment': ('ipv6',),
            'ipv6 fragment in ipv4': ('ipv6',),
        })

    def test_an_ip_rooted_packet_built_by_hand_is_traced_by_its_name(self) -> None:
        # with no link type attached, the first layer's name is looked up, and
        # ``IP`` names none, so it raises as documented (#775), not on the Data
        # Offset Scapy left unset
        from scapy.all import IP, TCP, Raw

        from pcapkit.toolkit.scapy import tcp_reassembly, tcp_traceflow
        from pcapkit.utilities.exceptions import MissingKeyError

        packet = IP(src='192.0.2.1', dst='198.51.100.1') / TCP(sport=1, dport=2) / Raw(b'data')
        data = tcp_reassembly(packet, count=1)
        assert data is not None
        self.assertEqual((bytes(data.header), bytes(data.payload)), (bytes(packet)[20:40], b'data'))
        with self.assertRaises(MissingKeyError):
            tcp_traceflow(packet, count=1)


if __name__ == '__main__':
    unittest.main()
