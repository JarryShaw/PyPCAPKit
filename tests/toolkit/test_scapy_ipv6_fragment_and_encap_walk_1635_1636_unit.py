# -*- coding: utf-8 -*-
"""scapy reads IP and TCP only in the layers the default engine dissects. C.f. #1635, #1636.

The default engine hands IPv6 reassembly the first IPv6 layer it dissects, with
the Fragment header of that layer's own extension header chain. `Scapy`_'s
``packet['IPv6']`` found the first IPv6 layer it dissected, which could lie in an
ICMP or ICMPv6 error's quote, a later IPv4 fragment, GRE or VXLAN, and
``IPv6ExtHdrFragment in ipv6`` then found a Fragment header anywhere below it, as
in the IPv6 packet a 6in6 tunnel carries (#1635).

The default engine dissects IP only behind the link layer, a VLAN tag, IP or an
extension header, and leaves GRE, PPPoE, an 802.3 frame's LLC/SNAP header, VXLAN
and the PPP payload of L2TP raw. `Scapy`_ dissects IP and TCP inside all of them,
and its engine handed those to TCP reassembly and flow tracing, and to IPv4 and
IPv6 reassembly (#1636).

The first layer is the one the link type selects, and a layer behind it carries
IP only if it is a VLAN tag, IP or an extension header. So at link types the
default engine leaves raw, where `Scapy`_ dissects two layers or more before IP
-- HDLC-like framing then PPP, 802.11 then LLC -- scapy reads no IP either. Nor
does it at those where `Scapy`_ dissects IP straight behind the first layer,
such as LINUX_SLL, which
:mod:`tests.toolkit.test_scapy_linktype_and_layer_bounds_1609_1626_1650_unit`
covers with the frame and extension header bounds (#1650, #1609).

Only scapy is compared with the default engine.

Every capture is built here, so the module is in the unit tier.

.. _Scapy: https://scapy.net

"""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit import test_dpkt_ipv4_reassembly_input_1615_1616_unit as ipv4_input
from tests.toolkit.test_dpkt_scapy_ipv4_header_checks_1607_unit import BAD_OPTIONS
from tests.toolkit.test_dpkt_scapy_ipv4_header_checks_1607_unit import ipv4 as ipv4_header
from tests.toolkit.test_scapy_ipv6_payload_and_icmp_quote_1623_1627_unit import ICMP6_PTB, ICMP_UNREACH
from tests.toolkit.test_tcp_carrier_walk_1606_1617_unit import ah, eth, options, tcp, v4, v6

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: Ethernet II type of IPv4, IPv6, an 802.1Q and an 802.1ad tag, transparent
#: Ethernet bridging (in GRE), a PPPoE session and an 802.1ah I-TAG, and the PPP
#: protocol numbers of IPv4 and IPv6.
IPV4, IPV6, C_TAG, S_TAG, TEB, PPPOE, I_TAG = 0x0800, 0x86DD, 0x8100, 0x88A8, 0x6558, 0x8864, 0x88E7
PPP_IPV4, PPP_IPV6 = 0x0021, 0x0057


def ethertype(packet: bytes) -> int:
    """The Ethernet II type of the IPv4 or IPv6 ``packet``."""
    return IPV6 if packet[0] >> 4 == 6 else IPV4


def tagged(packet: bytes, *tpids: int) -> bytes:
    """An Ethernet frame carrying the IP ``packet`` behind one VLAN tag (VID 100) per TPID in ``tpids``."""
    types = [*tpids, ethertype(packet)]
    return wire.ethernet(b''.join(b'\x00\x64' + kind.to_bytes(2, 'big') for kind in types[1:]) + packet, types[0])


def gre(packet: bytes, ptype: 'int | None' = None) -> bytes:
    """A GRE header (RFC 2784) with no checksum, then ``packet`` of protocol type ``ptype``, by default its own."""
    return b'\x00\x00' + (ethertype(packet) if ptype is None else ptype).to_bytes(2, 'big') + packet


def vxlan(frame: bytes) -> bytes:
    """UDP to port 4789 carrying a VXLAN header (RFC 7348), VNI 100, then the Ethernet ``frame``."""
    return wire.udp(b'\x08\x00\x00\x00' + (100).to_bytes(3, 'big') + b'\x00' + frame, dport=4789)


def session(packet: bytes) -> bytes:
    """A PPPoE session header (RFC 2516), then a PPP frame carrying the IP ``packet``."""
    return ppp(packet, b'\x11\x00\x00\x01' + (2 + len(packet)).to_bytes(2, 'big'))


def pppoe(packet: bytes) -> bytes:
    """An Ethernet frame of a PPPoE session (RFC 2516) whose PPP frame carries the IP ``packet``."""
    return wire.ethernet(session(packet), PPPOE)


def l2tp(packet: bytes) -> bytes:
    """UDP between ports 1701 carrying an L2TPv2 data message (RFC 2661) whose PPP frame carries IPv4 ``packet``."""
    return wire.udp(b'\x00\x02\x00\x01\x00\x01' + b'\xff\x03' + PPP_IPV4.to_bytes(2, 'big') + packet,
                    sport=1701, dport=1701)


def snap(packet: bytes) -> bytes:
    """An LLC/SNAP header (RFC 1042), then the IP ``packet``."""
    return b'\xaa\xaa\x03\x00\x00\x00' + ethertype(packet).to_bytes(2, 'big') + packet


def llc_snap(packet: bytes) -> bytes:
    """An 802.3 frame whose LLC/SNAP header (RFC 1042) carries the IP ``packet``."""
    body = snap(packet)
    return wire.MAC_B + wire.MAC_A + len(body).to_bytes(2, 'big') + body


def ppp(packet: bytes, prefix: bytes = b'\xff\x03') -> bytes:
    """``prefix``, by default the HDLC-like framing of RFC 1662, then a PPP frame carrying the IP ``packet``."""
    return prefix + (PPP_IPV6 if packet[0] >> 4 == 6 else PPP_IPV4).to_bytes(2, 'big') + packet


def dot11(packet: bytes) -> bytes:
    """An 802.11 data frame whose LLC/SNAP header carries the IP ``packet``."""
    return b'\x08\x00\x00\x00' + wire.MAC_B + wire.MAC_A + wire.MAC_A + b'\x00\x00' + snap(packet)


def radiotap(packet: bytes) -> bytes:
    """A radiotap header with no fields, then an 802.11 frame carrying the IP ``packet``."""
    return b'\x00\x00\x08\x00' + b'\x00' * 4 + dot11(packet)


def ppi(packet: bytes) -> bytes:
    """A PPI header with no fields, of link type 105, then an 802.11 frame carrying the IP ``packet``."""
    return b'\x00\x00\x08\x00' + (105).to_bytes(4, 'little') + dot11(packet)


def backbone(frame: bytes) -> bytes:
    """An Ethernet frame whose 802.1ah I-TAG (I-SID 256) carries the customer Ethernet ``frame``."""
    return wire.ethernet(b'\x00\x00\x01\x00' + frame, I_TAG)


def fragment6(payload: bytes, *, ident: int, nxt: int = 253, offset: int = 0, mf: bool = False) -> bytes:
    """An IPv6 Fragment header, then ``payload``; ``offset`` is in octets."""
    return bytes([nxt, 0]) + (offset | mf).to_bytes(2, 'big') + ident.to_bytes(4, 'big') + payload


#: Frames carrying TCP, each with whether the default engine reads the TCP, by a
#: name for it. Each builder takes the TCP segment it is to carry, given by its
#: frame number.
TCP_CASES = {
    # #1636, the issue's rows first
    'gre': (False, lambda n: eth(v4(gre(v4(tcp(n), 6)), 47))),
    'vxlan': (False, lambda n: eth(v4(vxlan(eth(v4(tcp(n), 6))), 17))),
    'pppoe': (False, lambda n: pppoe(v4(tcp(n), 6))),
    'l2tp': (False, lambda n: eth(v4(l2tp(v4(tcp(n), 6)), 17))),
    'llc/snap': (False, lambda n: llc_snap(v4(tcp(n), 6))),
    'gre over ipv6': (False, lambda n: eth(v6(gre(v6(tcp(n), 6)), 47))),
    'gre carrying ethernet': (False, lambda n: eth(v4(gre(eth(v4(tcp(n), 6)), TEB), 47))),
    'gre in 6in4': (False, lambda n: eth(v4(v6(gre(v4(tcp(n), 6)), 47), 41))),
    'gre behind hop-by-hop': (False, lambda n: eth(v6(options(47) + gre(v4(tcp(n), 6)), 0))),
    'gre behind 802.1q': (False, lambda n: tagged(v4(gre(v4(tcp(n), 6)), 47), C_TAG)),
    'vxlan over ipv6': (False, lambda n: eth(v6(vxlan(eth(v6(tcp(n), 6))), 17))),
    'pppoe carrying ipv6': (False, lambda n: pppoe(v6(tcp(n), 6))),
    'llc/snap carrying ipv6': (False, lambda n: llc_snap(v6(tcp(n), 6))),
    '802.1ah': (False, lambda n: backbone(eth(v4(tcp(n), 6)))),
    # controls: what the default engine dissects, VLAN tags, IP-in-IP and extension headers among it
    'tcp': (True, lambda n: eth(v4(tcp(n), 6))),
    '802.1q': (True, lambda n: tagged(v4(tcp(n), 6), C_TAG)),
    '802.1ad then 802.1q': (True, lambda n: tagged(v6(tcp(n), 6), S_TAG, C_TAG)),
    '6in4': (True, lambda n: eth(v4(v6(tcp(n), 6), 41))),
    '4in6 behind hop-by-hop': (True, lambda n: eth(v6(options(4) + v4(tcp(n), 6), 0))),
    '6in6 behind ah': (True, lambda n: eth(v6(ah(41) + v6(tcp(n), 6), 51))),
    '6in6 in a first fragment': (True, lambda n: eth(v6(fragment6(v6(tcp(n), 6), ident=n, nxt=41), 44))),
}


class IPCase(NamedTuple):
    """The two fragments of a 24-octet datagram, each in a frame of its own."""

    #: ``'ipv4'`` or ``'ipv6'``, the datagram's version.
    version: str
    #: How many fragments the default engine hands its reassembly, 0 or 2.
    inputs: int
    #: The frame a fragment is carried in.
    carry: 'Callable[[bytes], bytes]'
    #: The IPv6 Fragment header's Next Header.
    nxt: int = 253


#: IP fragments in frames, by a name for each case.
IP_CASES = {
    # #1635, the issue's rows first
    '6in6, the inner packet fragmented': IPCase('ipv6', 0, lambda p: eth(v6(p, 41))),
    'icmpv6 packet too big quoting a fragment': IPCase('ipv6', 0, lambda p: eth(v6(ICMP6_PTB + p, 58))),
    'icmp quoting a 6in4 fragment': IPCase('ipv6', 0, lambda p: eth(v4(ICMP_UNREACH + v4(p, 41), 1))),
    '4in6 carrying a 6in4 fragment': IPCase('ipv6', 0, lambda p: eth(v6(v4(p, 41), 4))),
    '6in4 fragment in a later ipv4 fragment': IPCase('ipv6', 0, lambda p: eth(v4(p, 41, offset=16))),
    'ipv6 fragment in gre over ipv4': IPCase('ipv6', 0, lambda p: eth(v4(gre(p), 47))),
    'ipv6 fragment in vxlan over ipv4': IPCase('ipv6', 0, lambda p: eth(v4(vxlan(eth(p)), 17))),
    '6in6 behind hop-by-hop, the inner packet fragmented': IPCase('ipv6', 0, lambda p: eth(v6(options(41) + p, 0))),
    '6in6 behind ah, the inner packet fragmented': IPCase('ipv6', 0, lambda p: eth(v6(ah(41) + p, 51))),
    '6in4 fragment behind a rejected ipv4 header': IPCase('ipv6', 0, lambda p: eth(ipv4_header(
        p, options=BAD_OPTIONS['timestamp length 2'], proto=41))),
    # #1636
    'ipv6 fragments in gre over ipv4 (df)': IPCase('ipv6', 0, lambda p: eth(wire.ipv4(gre(p), df=True, proto=47))),
    'ipv6 fragments in pppoe': IPCase('ipv6', 0, pppoe),
    'ipv4 fragments in gre over ipv6': IPCase('ipv4', 0, lambda p: eth(v6(gre(p), 47))),
    'ipv4 fragments in vxlan over ipv6': IPCase('ipv4', 0, lambda p: eth(v6(vxlan(eth(p)), 17))),
    'ipv4 fragments in pppoe': IPCase('ipv4', 0, pppoe),
    'ipv4 fragments in llc/snap': IPCase('ipv4', 0, llc_snap),
    'ipv4 fragments in l2tp over ipv4 (df)': IPCase('ipv4', 0, lambda p: eth(wire.ipv4(l2tp(p), df=True, proto=17))),
    # controls: the first IPv6 layer, its Fragment header behind another header, and VLAN tags
    'ipv6 fragments': IPCase('ipv6', 2, eth),
    'ipv6 fragments behind hop-by-hop': IPCase('ipv6', 2, lambda p: eth(v6(options(44) + p[40:], 0))),
    '6in6, the outer packet fragmented': IPCase('ipv6', 2, eth, nxt=41),
    '6in4 fragments': IPCase('ipv6', 2, lambda p: eth(v4(p, 41))),
    '6in4 fragments behind ah': IPCase('ipv6', 2, lambda p: eth(v4(ah(41) + p, 51))),
    '6in4 fragments behind 802.1ad then 802.1q': IPCase('ipv6', 2, lambda p: tagged(v4(p, 41), S_TAG, C_TAG)),
    'ipv4 fragments behind 802.1q': IPCase('ipv4', 2, lambda p: tagged(p, C_TAG)),
    '4in6 fragments': IPCase('ipv4', 2, lambda p: eth(v6(p, 4))),
}


#: Link types the default engine leaves raw, at which `Scapy`_ dissects two
#: layers or more before IP, by a name for each: the link type, and the frame an
#: IP packet is carried in.
LINK_TYPES = {
    'ppp (9) with ff 03': (9, ppp),
    'ppp_hdlc (50)': (50, ppp),
    'ppp_ether (51)': (51, session),
    'ieee802_11 (105)': (105, dot11),
    'ieee802_11_radiotap (127)': (127, radiotap),
    'ppi (192)': (192, ppi),
}


def fragments(case: IPCase, ident: int) -> 'list[bytes]':
    """The frames carrying ``case``'s two fragments, of an Identification of ``ident``."""
    if case.version == 'ipv4':
        packets = [ipv4_input.ipv4(b'A' * 16, ident=ident, mf=True),
                   ipv4_input.ipv4(b'B' * 8, ident=ident, offset=16)]
    else:
        packets = [v6(fragment6(b'A' * 16, ident=ident, nxt=case.nxt, mf=True), 44),
                   v6(fragment6(b'B' * 8, ident=ident, nxt=case.nxt, offset=16), 44)]
    return [case.carry(packet) for packet in packets]


def read(test: unittest.TestCase, engine: str, frames: 'list[bytes]', linktype: int = 1) -> 'dict[str, Any]':
    """Read ``frames`` of ``linktype`` with ``engine``, with IPv4, IPv6 and TCP reassembly and TCP flow tracing.

    Returns:
        Every input the engine hands each of the four, keyed by frame number --
        every field, but a trace input's ``frame`` -- the IPv4 and IPv6
        datagrams reassembled, the TCP datagrams' ``id``, and the traced flows'
        labels and frames.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.ipv4 import IPv4
    from pcapkit.foundation.reassembly.ipv6 import IPv6
    from pcapkit.foundation.reassembly.tcp import TCP
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    seen = {'ipv4': {}, 'ipv6': {}, 'tcp': {}, 'trace': {}}  # type: dict[str, Any]
    calls = {'ipv4': IPv4.__call__, 'ipv6': IPv6.__call__, 'tcp': TCP.__call__}
    trace = TraceFlowBase.__call__

    def fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
        return {key: bytes(value) if isinstance(value, bytearray) else value
                for key, value in packet.items() if key not in skip}

    def spy(aspect: str) -> 'Callable[[Any, Any], Any]':
        def call(this: 'Any', packet: 'Any') -> 'Any':
            seen[aspect][packet.num] = fields(packet)
            return calls[aspect](this, packet)
        return call

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = fields(packet, ('frame',))
        return trace(this, packet)

    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(IPv4, '__call__', spy('ipv4')), mock.patch.object(IPv6, '__call__', spy('ipv6')), \
            mock.patch.object(TCP, '__call__', spy('tcp')), mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        path = os.path.join(tmp, 'walk.pcap')
        with open(path, 'wb') as file:
            file.write(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)], linktype=linktype))
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, ipv4=True, ipv6=True,
                            tcp=True, trace=True, trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            for version in ('ipv4', 'ipv6'):
                seen[f'{version} datagrams'] = [
                    (datagram.completed, datagram.id, datagram.index, datagram.header, datagram.payload)
                    for datagram in getattr(extractor.reassembly, version)
                ]
            seen['ids'] = [datagram.id for datagram in extractor.reassembly.tcp]
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
        finally:
            close_extractor(extractor)
    return seen


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ScapyDissectedLayerWalkTests(unittest.TestCase):
    """scapy hands on the IP and TCP the default engine dissects, frame for frame, and no other."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.frames = [make(number) for number, (_, make) in enumerate(TCP_CASES.values(), start=1)]
        # one-based frame numbers of each case, and each IP case's frames
        cls.numbers = {label: [number] for number, label in enumerate(TCP_CASES, start=1)}
        cls.ip_frames = {}  # type: dict[str, list[bytes]]
        for ident, (label, case) in enumerate(IP_CASES.items(), start=1):
            cls.ip_frames[label] = fragments(case, ident)
            cls.numbers[label] = [len(cls.frames) + 1, len(cls.frames) + 2]
            cls.frames.extend(cls.ip_frames[label])

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def read(self, engine: str) -> 'dict[str, Any]':
        """``engine``'s reading of every case, read once per class."""
        if engine == 'scapy' and not HAS_SCAPY:
            self.skipTest('scapy not installed')
        seen = type(self).__dict__.get('seen')
        if seen is None:
            seen = type(self).seen = {}
        if engine not in seen:
            seen[engine] = read(self, engine, self.frames)
        return seen[engine]

    def disagree(self, aspect: str) -> 'list[str]':
        """The cases whose ``aspect`` inputs scapy and the default engine do not agree on."""
        base, scapy = self.read('default'), self.read('scapy')
        return [label for label, numbers in self.numbers.items()
                if any(scapy[aspect].get(number) != base[aspect].get(number) for number in numbers)]

    def test_the_default_engine_reads_what_the_cases_say(self) -> None:
        base = self.read('default')
        reads = [self.numbers[label][0] for label, (expected, _) in TCP_CASES.items() if expected]
        self.assertEqual((sorted(base['tcp']), sorted(base['trace'])), (reads, reads))
        self.assertEqual({label: sum(number in base[case.version] for number in self.numbers[label])
                          for label, case in IP_CASES.items()},
                         {label: case.inputs for label, case in IP_CASES.items()})
        # and the controls' datagrams are whole
        for label, case in IP_CASES.items():
            if case.inputs:
                with self.subTest(case=label):
                    self.assertIn(tuple(self.numbers[label]),
                                  [datagram[2] for datagram in base[f'{case.version} datagrams'] if datagram[0]])

    def test_ipv6_reassembly_takes_the_first_ipv6_layers_own_fragment_header(self) -> None:
        # #1635
        self.assertEqual(self.disagree('ipv6'), [])
        self.assertEqual(self.read('scapy')['ipv6 datagrams'], self.read('default')['ipv6 datagrams'])

    def test_no_tcp_is_read_inside_a_layer_the_default_engine_leaves_raw(self) -> None:
        # #1636
        self.assertEqual((self.disagree('tcp'), self.disagree('trace')), ([], []))
        for aspect in ('ids', 'flows'):
            self.assertEqual(self.read('scapy')[aspect], self.read('default')[aspect], aspect)

    def test_no_ipv4_is_read_inside_a_layer_the_default_engine_leaves_raw(self) -> None:
        # #1636
        self.assertEqual(self.disagree('ipv4'), [])
        self.assertEqual(self.read('scapy')['ipv4 datagrams'], self.read('default')['ipv4 datagrams'])

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_no_ip_is_read_two_layers_into_a_link_type_the_default_engine_leaves_raw(self) -> None:
        # #1636, at the first layer: TCP in IPv4 and in IPv6, then two IPv4 and two IPv6 fragments
        for label, (linktype, carry) in LINK_TYPES.items():
            frames = [carry(v4(tcp(1), 6)), carry(v6(tcp(2), 6)),
                      *fragments(IPCase('ipv4', 0, carry), 3), *fragments(IPCase('ipv6', 0, carry), 4)]
            with self.subTest(link_type=label):
                base = read(self, 'default', frames, linktype)
                self.assertEqual([base[aspect] for aspect in ('ipv4', 'ipv6', 'tcp', 'trace')], [{}] * 4)
                self.assertEqual(read(self, 'scapy', frames, linktype), base)

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_a_packet_built_by_hand_is_walked_too(self) -> None:
        # ``scapy.all`` binds every layer here, as the engine has it do (see pcapkit.toolkit.scapy)
        from scapy.all import Ether, IPerror, IPerror6

        from pcapkit.toolkit import scapy as toolkit
        from pcapkit.utilities.exceptions import ModuleNotFound

        got = {label: toolkit.tcp_reassembly(Ether(make(1))) is not None for label, (_, make) in TCP_CASES.items()}
        self.assertEqual(got, {label: expected for label, (expected, _) in TCP_CASES.items()})
        got = {label: [getattr(toolkit, f'{case.version}_reassembly')(Ether(frame)) is not None
                       for frame in self.ip_frames[label]] for label, case in IP_CASES.items()}
        self.assertEqual(got, {label: [bool(case.inputs)] * 2 for label, case in IP_CASES.items()})
        # nor is a quoted datagram read when it is handed over on its own
        first4 = ipv4_input.ipv4(b'A' * 16, ident=1, mf=True)
        first6 = v6(fragment6(b'A' * 16, ident=1, mf=True), 44)
        self.assertEqual([toolkit.ipv4_reassembly(IPerror(first4)), toolkit.tcp_reassembly(IPerror(v4(tcp(1), 6))),
                          toolkit.ipv6_reassembly(IPerror6(first6))], [None] * 3)
        self.assertIsNotNone(toolkit.ipv4_reassembly(Ether(eth(first4))))

        # the input is the first IPv6 layer's, cut at its Fragment header
        frame = self.ip_frames['6in6, the outer packet fragmented'][0]
        data = toolkit.ipv6_reassembly(Ether(frame), count=1)
        assert data is not None
        self.assertEqual((data.ihl, bytes(data.header), bytes(data.payload)), (40, frame[14:54], b'A' * 16))
        with mock.patch.object(toolkit, 'scapy', None), self.assertRaises(ModuleNotFound):
            toolkit.ipv6_reassembly(Ether(frame))


if __name__ == '__main__':
    unittest.main()
