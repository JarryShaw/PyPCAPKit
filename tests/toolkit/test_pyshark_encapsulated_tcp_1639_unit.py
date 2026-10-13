# -*- coding: utf-8 -*-
"""The pyshark engine traces no TCP inside an encapsulation the default engine leaves raw. C.f. #1639.

tshark dissects TCP inside link types 12 and 14, which it reads as raw IP
(101), Linux SLL, EtherTypes such as MPLS and PPPoE, 802.3 LLC/SNAP and Cisco
ISL, and tunnels such as GRE, VXLAN and L2TP. The default engine leaves each of
these raw, so pyshark traced TCP it does not. A frame tshark finds TCP in is now
read from its octets by the default engine's rules, the path #1625 added for an
extension header in IPv4: from the outermost IP layer the default engine
dissects, by the link type in the capture file, through IP-in-IP alone. A frame
it reads no IP in, or one whose IP layer tshark dissects elsewhere, is not
traced; one whose octets cannot be had is traced as tshark dissects it, as
before. tshark's IP layer is matched to the octets by its addresses, the
destination where tshark reports it: behind an LSRR or SSRR option, that is
the route's last address, in the option.

Every capture is built here, so the module is in the unit tier. The tests that
run tshark skip unless the pyshark engine runs, which needs ``pyshark``, the
``tshark`` binary and Python 3.13 or older; the rest use fakes.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import struct
import tempfile
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Callable

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


def tcp(number: int) -> bytes:
    """A TCP segment carrying ``data`` on a port pair of its own."""
    return wire.tcp(b'data', seq=1000 + number, ack=1, sport=1000 + number)


def v4(payload: bytes, proto: int = 6, *, inner: bool = False, opts: bytes = b'') -> bytes:
    """An IPv4 packet carrying ``payload`` as ``proto``, with options ``opts``; ``inner`` swaps the addresses."""
    packet = bytearray(wire.ipv4(payload, proto=proto, reverse=inner))
    if opts:
        packet[0] = 0x40 | (5 + len(opts) // 4)
        packet[2:4] = (len(packet) + len(opts)).to_bytes(2, 'big')
        packet[20:20] = opts
        packet[10:12] = b'\x00\x00'
        packet[10:12] = wire.checksum(bytes(packet[:len(opts) + 20])).to_bytes(2, 'big')
    return bytes(packet)


def v6(payload: bytes, nxt: int = 6, *, inner: bool = False) -> bytes:
    """An IPv6 packet carrying ``payload`` as ``nxt``; ``inner`` swaps the addresses."""
    return wire.ipv6(payload, nxt=nxt, reverse=inner)


def eth(packet: bytes, ethertype: 'int | None' = None) -> bytes:
    """An Ethernet frame carrying ``packet``, by default as its IP version's EtherType."""
    return wire.ethernet(packet, (0x86DD if packet[0] >> 4 == 6 else 0x0800) if ethertype is None else ethertype)


def gre(packet: bytes, ptype: 'int | None' = None) -> bytes:
    """A GRE packet, with no options, carrying ``packet`` as ``ptype``, by default its IP version's."""
    if ptype is None:
        ptype = 0x86DD if packet[0] >> 4 == 6 else 0x0800
    return b'\x00\x00' + ptype.to_bytes(2, 'big') + packet


def vxlan(frame: bytes) -> bytes:
    """A UDP datagram to the VXLAN port, carrying the Ethernet ``frame`` with VNI 100."""
    return wire.udp(b'\x08\x00\x00\x00' + (100).to_bytes(3, 'big') + b'\x00' + frame, dport=4789)


def l2tp(packet: bytes) -> bytes:
    """A UDP datagram to the L2TP port, carrying the IPv4 ``packet`` in PPP."""
    return wire.udp(b'\x00\x02\x00\x01\x00\x01\xff\x03\x00\x21' + packet, sport=1701, dport=1701)


def mpls(packet: bytes, labels: int = 1) -> bytes:
    """``labels`` MPLS labels, the last the bottom of the stack, then ``packet``."""
    return b''.join(((16 + index) << 12 | (index == labels - 1) << 8 | 64).to_bytes(4, 'big')
                    for index in range(labels)) + packet


def pppoe(packet: bytes) -> bytes:
    """A PPPoE session frame carrying ``packet`` in PPP."""
    proto = 0x0057 if packet[0] >> 4 == 6 else 0x0021
    return wire.ethernet(b'\x11\x00\x00\x01' + (2 + len(packet)).to_bytes(2, 'big') + proto.to_bytes(2, 'big')
                         + packet, 0x8864)


def llc_snap(packet: bytes) -> bytes:
    """An 802.3 frame carrying ``packet`` behind LLC/SNAP."""
    body = b'\xaa\xaa\x03\x00\x00\x00' + (0x86DD if packet[0] >> 4 == 6 else 0x0800).to_bytes(2, 'big') + packet
    return wire.MAC_B + wire.MAC_A + len(body).to_bytes(2, 'big') + body


def isl(frame: bytes) -> bytes:
    """A Cisco ISL frame carrying the Ethernet ``frame``."""
    body = b'\xaa\xaa\x03\x00\x00\x0c\x00\x02\x00\x00\x00\x00' + frame
    return b'\x01\x00\x0c\x00\x00\x00' + wire.MAC_A + len(body).to_bytes(2, 'big') + body + b'\x00' * 4


def vlan(packet: bytes, *tpids: int) -> bytes:
    """An Ethernet frame carrying ``packet`` behind a VLAN tag of each TPID in ``tpids``."""
    ethertype = 0x86DD if packet[0] >> 4 == 6 else 0x0800
    tags = b''.join(struct.pack('>HH', 1, tpid) for tpid in tpids[1:]) + struct.pack('>HH', 1, ethertype)
    return wire.ethernet(tags + packet, tpids[0])


def dstopts(count: int, nxt: int = 6) -> bytes:
    """``count`` Destination Options headers in a row, the last naming ``nxt``."""
    return b''.join(bytes([60 if index < count - 1 else nxt, 0, 1, 4, 0, 0, 0, 0]) for index in range(count))


def sll(packet: bytes) -> bytes:
    """A Linux cooked-mode (SLL) frame carrying ``packet``."""
    return struct.pack('>HHH8sH', 0, 1, 6, wire.MAC_A + b'\x00\x00', 0x86DD if packet[0] >> 4 == 6 else 0x0800) + packet


def sll2(packet: bytes) -> bytes:
    """A Linux cooked-mode v2 (SLL2) frame carrying ``packet``."""
    return struct.pack('>HHIHBB8s', 0x86DD if packet[0] >> 4 == 6 else 0x0800, 0, 1, 1, 0, 6,
                       wire.MAC_A + b'\x00\x00') + packet


def loopback(packet: bytes, family: int, byteorder: str) -> bytes:
    """A BSD loopback frame carrying ``packet`` as the address ``family``, written in ``byteorder``."""
    return family.to_bytes(4, byteorder) + packet


#: An IPv4 Timestamp option of length 2, which the default engine's IPv4 parser rejects.
BAD_TIMESTAMP = b'\x44\x02\x00\x00'


def route(kind: int, pointer: int, *hops: bytes) -> bytes:
    """An IPv4 source or record route option of ``kind`` through ``hops``, padded by End of Option List."""
    option = bytes([kind, 3 + 4 * len(hops), pointer]) + b''.join(hops)
    return option + bytes(-len(option) % 4)


#: Two addresses to route through.
HOP_1, HOP_2 = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])

#: An LSRR option through :data:`HOP_1` that no hop has used yet.
LSRR = route(0x83, 4, HOP_1)

#: Ethernet frames carrying TCP, each with whether the default engine traces it,
#: by a name for it. Each builder takes the segment's number, its frame number.
#: The rows marked #1639 are the issue's; tshark traced every one of them.
ENCAPSULATION_CASES = {
    'control': (True, lambda n: eth(v4(tcp(n)))),
    'control, ipv6': (True, lambda n: eth(v6(tcp(n)))),
    'vlan': (True, lambda n: vlan(v4(tcp(n)), 0x8100)),
    'qinq, ipv6': (True, lambda n: vlan(v6(tcp(n)), 0x88A8, 0x8100)),
    '4in4': (True, lambda n: eth(v4(v4(tcp(n), inner=True), 4))),
    '6in4': (True, lambda n: eth(v4(v6(tcp(n), inner=True), 41))),
    # #1639
    'gre': (False, lambda n: eth(v4(gre(v4(tcp(n), inner=True)), 47))),
    'vxlan': (False, lambda n: eth(v4(vxlan(eth(v4(tcp(n), inner=True))), 17))),
    'mpls': (False, lambda n: eth(mpls(v4(tcp(n))), 0x8847)),
    'pppoe': (False, lambda n: pppoe(v4(tcp(n)))),
    'l2tp': (False, lambda n: eth(v4(l2tp(v4(tcp(n), inner=True)), 17))),
    'llc/snap': (False, lambda n: llc_snap(v4(tcp(n)))),
    'isl': (False, lambda n: isl(eth(v4(tcp(n))))),
    # and around it
    'gre, ipv6': (False, lambda n: eth(v6(gre(v6(tcp(n), inner=True)), 47))),
    'gre, ethernet': (False, lambda n: eth(v4(gre(eth(v4(tcp(n), inner=True)), 0x6558), 47))),
    'gre in 4in4': (False, lambda n: eth(v4(v4(gre(v4(tcp(n))), 47, inner=True), 4))),
    'vxlan, ipv6': (False, lambda n: eth(v6(vxlan(eth(v6(tcp(n), inner=True))), 17))),
    'mpls, three labels, ipv6': (False, lambda n: eth(mpls(v6(tcp(n)), 3), 0x8847)),
    'vlan, mpls': (False, lambda n: wire.ethernet(struct.pack('>HH', 1, 0x8847) + mpls(v4(tcp(n))), 0x8100)),
    'pppoe, ipv6': (False, lambda n: pppoe(v6(tcp(n)))),
    'llc/snap, ipv6': (False, lambda n: llc_snap(v6(tcp(n)))),
    'isl, ipv6': (False, lambda n: isl(eth(v6(tcp(n))))),
    'teredo': (False, lambda n: eth(v4(wire.udp(v6(tcp(n)), dport=3544), 17))),
    'ipv4 ethertype, ipv6 packet': (False, lambda n: eth(v6(tcp(n)), 0x0800)),
    # what the default engine reads of the IP layers themselves
    'rejected ipv4 options': (False, lambda n: eth(v4(tcp(n), opts=BAD_TIMESTAMP))),
    'rejected ipv4 options, inner': (False, lambda n: eth(v4(v4(tcp(n), inner=True, opts=BAD_TIMESTAMP), 4))),
    '32 destination options': (True, lambda n: eth(v6(dstopts(32) + tcp(n), 60))),
    '33 destination options': (False, lambda n: eth(v6(dstopts(33) + tcp(n), 60))),
}

#: Frames of each link type carrying TCP, each with the link type and whether
#: the default engine traces it, by a name for it.
LINK_CASES = {
    'bsd raw (12)': (12, False, lambda n: v4(tcp(n))),
    'bsd raw (12), ipv6': (12, False, lambda n: v6(tcp(n))),
    'openbsd raw (14)': (14, False, lambda n: v4(tcp(n))),
    'openbsd raw (14), ipv6': (14, False, lambda n: v6(tcp(n))),
    'raw': (101, True, lambda n: v4(tcp(n))),
    'raw, ipv6': (101, True, lambda n: v6(tcp(n))),
    'raw, gre': (101, False, lambda n: v4(gre(v4(tcp(n), inner=True)), 47)),
    'ipv4': (228, True, lambda n: v4(tcp(n))),
    # tshark reads an IPv6 packet here as IPv6, the default engine as IPv4
    'ipv4, ipv6 packet': (228, False, lambda n: v6(tcp(n))),
    'ipv6': (229, True, lambda n: v6(tcp(n))),
    'ipv6, vxlan': (229, False, lambda n: v6(vxlan(eth(v4(tcp(n)))), 17)),
    'sll': (113, False, lambda n: sll(v4(tcp(n)))),
    'sll, ipv6': (113, False, lambda n: sll(v6(tcp(n)))),
    'sll2': (276, False, lambda n: sll2(v4(tcp(n)))),
    'sll2, ipv6': (276, False, lambda n: sll2(v6(tcp(n)))),
    'null': (0, True, lambda n: loopback(v4(tcp(n)), 2, 'little')),
    'null, ipv6': (0, True, lambda n: loopback(v6(tcp(n)), 30, 'big')),
    'null, gre': (0, False, lambda n: loopback(v4(gre(v4(tcp(n), inner=True)), 47), 2, 'little')),
    'loop': (108, True, lambda n: loopback(v4(tcp(n)), 2, 'big')),
    'loop, ipv6': (108, True, lambda n: loopback(v6(tcp(n)), 24, 'big')),
    'loop, gre, ipv6': (108, False, lambda n: loopback(v4(gre(v6(tcp(n), inner=True)), 47), 2, 'big')),
    'raw, lsrr': (101, True, lambda n: v4(tcp(n), opts=LSRR)),
    'null, lsrr, 4in4': (0, True, lambda n: loopback(v4(v4(tcp(n), inner=True), 4, opts=LSRR), 2, 'little')),
}

#: Ethernet frames carrying TCP behind an IPv4 source or record route, as
#: :data:`ENCAPSULATION_CASES`. Where the route is not used up, tshark reports
#: its last address as ``ip.dst``; the default engine keys the segment by the
#: header's Destination Address.
SOURCE_ROUTE_CASES = {
    'lsrr, 4in4': (True, lambda n: eth(v4(v4(tcp(n), inner=True), 4, opts=LSRR))),
    'ssrr, 4in4': (True, lambda n: eth(v4(v4(tcp(n), inner=True), 4, opts=route(0x89, 4, HOP_1)))),
    'lsrr': (True, lambda n: eth(v4(tcp(n), opts=LSRR))),
    'ssrr': (True, lambda n: eth(v4(tcp(n), opts=route(0x89, 4, HOP_1)))),
    'lsrr, two hops': (True, lambda n: eth(v4(tcp(n), opts=route(0x83, 4, HOP_1, HOP_2)))),
    'lsrr, two hops, one used': (True, lambda n: eth(v4(tcp(n), opts=route(0x83, 8, HOP_1, HOP_2)))),
    'lsrr, used up': (True, lambda n: eth(v4(tcp(n), opts=route(0x83, 8, HOP_1)))),
    'record route': (True, lambda n: eth(v4(tcp(n), opts=route(0x07, 8, HOP_1)))),
    'lsrr, inner': (True, lambda n: eth(v4(v4(tcp(n), inner=True, opts=LSRR), 4))),
    'lsrr, 6in4': (True, lambda n: eth(v4(v6(tcp(n), inner=True), 41, opts=LSRR))),
    'lsrr, gre': (False, lambda n: eth(v4(gre(v4(tcp(n), inner=True)), 47, opts=LSRR))),
}


def build(cases: 'dict[str, tuple[bool, Callable[[int], bytes]]]') -> 'tuple[list[bytes], list[int]]':
    """The frames of ``cases``, and the numbers of those the default engine traces TCP from."""
    numbered = list(enumerate(cases.values(), start=1))
    return ([make(number) for number, (_, make) in numbered],
            [number for number, (reads, _) in numbered if reads])


def block(kind: int, body: bytes, order: str = '<') -> bytes:
    """A PCAP-NG block of type ``kind`` around ``body``, zero-padded to 32 bits, in byte order ``order``."""
    body += bytes(-len(body) % 4)
    return struct.pack(f'{order}II', kind, len(body) + 12) + body + struct.pack(f'{order}I', len(body) + 12)


def section(linktypes: 'list[int]', packets: 'list[tuple[int, int, bytes]]', order: str = '<') -> bytes:
    """A PCAP-NG section with an interface of each of ``linktypes``, then ``packets``.

    Each packet is ``(kind, interface, octets)``: an Enhanced Packet Block (6),
    an obsolete Packet Block (2), a Simple Packet Block (3), which names no
    interface, or a systemd Journal Export Block (9), which is no packet.

    """
    out = [block(0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1), order)]
    out += [block(1, struct.pack(f'{order}HHI', linktype, 0, 0xFFFF), order) for linktype in linktypes]
    for kind, interface, octets in packets:
        head = {6: struct.pack(f'{order}IIIII', interface, 0, 1, len(octets), len(octets)),
                2: struct.pack(f'{order}HHIIII', interface, 0, 0, 1, len(octets), len(octets)),
                3: struct.pack(f'{order}I', len(octets))}.get(kind, b'')
        out.append(block(kind, head + octets, order))
    return b''.join(out)


def read(test: unittest.TestCase, engine: str, capture: bytes, suffix: str = 'pcap') -> 'dict[str, Any]':
    """Read ``capture`` with ``engine``, with TCP flow tracing on.

    Returns:
        The input flow tracing receives for each frame number -- every field but
        ``frame``, ``header`` and ``payload``, which PyShark cannot supply --
        and the traced flows' labels and frames.

    Skips ``test`` unless ``engine`` ran.

    """
    from pcapkit import extract
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    if engine != 'default' and importlib.util.find_spec(engine) is None:
        test.skipTest(f'{engine} not installed')
    trace = TraceFlowBase.__call__
    seen = {'trace': {}}  # type: dict[str, Any]

    def spy(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = {key: value for key, value in packet.items()
                                       if key not in ('frame', 'header', 'payload')}
        return trace(this, packet)

    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(TraceFlowBase, '__call__', spy):
        warnings.simplefilter('ignore')
        path = os.path.join(tmp, f'capture.{suffix}')
        with open(path, 'wb') as file:
            file.write(capture)
        extractor = extract(fin=path, nofile=True, engine=engine, tcp=True, trace=True,
                            trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
        finally:
            close_extractor(extractor)
    return seen


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PySharkEncapsulationTraceTests(unittest.TestCase):
    """The pyshark engine traces the TCP the default engine reads, and none inside what it leaves raw."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree(self, capture: bytes, reads: 'list[int]', names: 'dict[int, str]',
              suffix: str = 'pcap') -> 'dict[str, Any]':
        base = read(self, 'default', capture, suffix)
        # what the default engine reads, as the cases say
        self.assertEqual([names[number] for number in sorted(base['trace'])], [names[number] for number in reads])
        seen = read(self, 'pyshark', capture, suffix)
        self.assertEqual([names[number] for number in sorted(set(seen['trace']) ^ set(base['trace']))], [],
                         'frames traced by one of pyshark and the default engine alone')
        for number, record in base['trace'].items():
            self.assertEqual(seen['trace'][number], record, names[number])
        self.assertEqual(seen['flows'], base['flows'])
        return seen

    def test_tcp_inside_an_encapsulation_the_default_engine_leaves_raw_is_not_traced(self) -> None:
        frames, reads = build(ENCAPSULATION_CASES)
        self.agree(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)]),
                   reads, dict(enumerate(ENCAPSULATION_CASES, start=1)))

    def test_tcp_behind_a_source_route_is_keyed_by_the_header_destination(self) -> None:
        # tshark reports the last address of a route not used up as ip.dst
        frames, reads = build(SOURCE_ROUTE_CASES)
        names = dict(enumerate(SOURCE_ROUTE_CASES, start=1))
        seen = self.agree(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)]), reads, names)
        number = {name: number for number, name in names.items()}
        self.assertEqual(seen['trace'][number['lsrr']]['dst'], ipaddress.ip_address(wire.IPV4_B))
        self.assertEqual(seen['trace'][number['lsrr, 4in4']]['dst'], ipaddress.ip_address(wire.IPV4_A))

    def test_each_link_type_is_read_as_the_default_engine_reads_it(self) -> None:
        for linktype in sorted({link for link, _, _ in LINK_CASES.values()}):
            cases = {name: (reads, make) for name, (link, reads, make) in LINK_CASES.items() if link == linktype}
            with self.subTest(linktype=linktype):
                frames, reads = build(cases)
                self.agree(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)],
                                     linktype=linktype), reads, dict(enumerate(cases, start=1)))

    def test_each_pcapng_interface_is_read_by_its_own_link_type(self) -> None:
        # tshark reads 12 and 14 as raw IP (101), and numbers a journal block
        # as a frame where the default engine counts packets only
        def raw(n: int) -> bytes:
            return v4(tcp(n))

        sections = [
            ([1, 12, 101, 113], '<', [(6, 0, eth(raw(1)), True),
                                      (6, 1, raw(2), False),
                                      (9, 0, b'__REALTIME_TIMESTAMP=1000000\nMESSAGE=hello\n', None),
                                      (6, 2, raw(3), True),
                                      (2, 3, sll(raw(4)), False),
                                      (3, 0, eth(v4(gre(raw(5)), 47)), False),
                                      (6, 0, eth(raw(6)), True)]),
            ([14, 229], '>', [(3, 0, raw(7), False),
                              (6, 1, v6(tcp(8)), True),
                              (2, 0, v6(tcp(9)), False),
                              (6, 1, v6(vxlan(eth(raw(10))), 17), False),
                              (6, 1, v6(tcp(11)), True)]),
        ]
        capture = b''.join(section(linktypes, [packet[:3] for packet in packets], order)
                           for linktypes, order, packets in sections)
        packets = [(f'section {index}, block {kind}, interface {interface}', reads)
                   for index, (_, _, blocks) in enumerate(sections, start=1)
                   for kind, interface, _, reads in blocks if reads is not None]
        self.agree(capture, [number for number, (_, reads) in enumerate(packets, start=1) if reads],
                   {number: f'{number}: {name}' for number, (name, _) in enumerate(packets, start=1)},
                   suffix='pcapng')

    def test_frames_the_second_pass_cannot_read_are_traced_as_tshark_dissects_them(self) -> None:
        # as before #1639, with one warning
        from pcapkit.utilities.warnings import PySharkWarning

        cases = {name: ENCAPSULATION_CASES[name] for name in ('control', 'gre', 'mpls', 'control, ipv6')}
        frames, _ = build(cases)
        capture = wire.pcap([(1, number, octets) for number, octets in enumerate(frames)])
        with mock.patch('pcapkit.toolkit.pyshark.OCTETS_FILTER', 'tcp ||'), \
                mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
            seen = read(self, 'pyshark', capture)
        self.assertEqual(sorted(seen['trace']), [1, 2, 3, 4])
        messages = [call.args[0] for call in warn.call_args_list if call.args[1] is PySharkWarning]
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('Frame 1: the second tshark pass, which reads the captured octets of a frame with an AH '
                      'or IPv6 extension header in IPv4, or with TCP,', messages[0])


class FakeField(str):
    """A PyShark field: text, with the position and raw value tshark reports for it."""

    def __new__(cls, show: str, pos: int = 0, raw_value: str = '') -> 'FakeField':
        field = super().__new__(cls, show)
        field.pos, field.raw_value = str(pos), raw_value
        return field


class FakeLayer:
    def __init__(self, layer_name: str, **fields: object) -> None:
        self.layer_name = layer_name
        self.field_names = tuple(fields)
        for name, value in fields.items():
            setattr(self, name, value)


def ip_layer(octets: bytes, start: int) -> FakeLayer:
    """The ``ip`` or ``ipv6`` layer tshark reports for the IP header at ``start`` of ``octets``."""
    if octets[start] >> 4 == 4:
        src, dst = octets[start + 12:start + 16], octets[start + 16:start + 20]
        return FakeLayer('ip', version=FakeField('4', start, '4'), proto=FakeField(str(octets[start + 9])),
                         src=FakeField(str(ipaddress.ip_address(src)), start + 12, src.hex()),
                         dst=FakeField(str(ipaddress.ip_address(dst)), start + 16, dst.hex()))
    src, dst = octets[start + 8:start + 24], octets[start + 24:start + 40]
    return FakeLayer('ipv6', version=FakeField('6', start, '6'), nxt=FakeField(str(octets[start + 6])),
                     src=FakeField(str(ipaddress.ip_address(src)), start + 8, src.hex()),
                     dst=FakeField(str(ipaddress.ip_address(dst)), start + 24, dst.hex()))


def tcp_layer(octets: bytes, start: int, **fields: str) -> FakeLayer:
    """The ``tcp`` layer tshark reports for the TCP header at ``start`` of ``octets``, with ``fields`` replaced."""
    flags = octets[start + 13]
    names = {'srcport': str(int.from_bytes(octets[start:start + 2], 'big')),
             'dstport': str(int.from_bytes(octets[start + 2:start + 4], 'big')),
             'seq_raw': str(int.from_bytes(octets[start + 4:start + 8], 'big')),
             'ack_raw': str(int.from_bytes(octets[start + 8:start + 12], 'big')),
             'flags_syn': str(bool(flags & 0x02)), 'flags_fin': str(bool(flags & 0x01)),
             'flags_reset': str(bool(flags & 0x04)), 'urgent_pointer': '0'}
    names.update(fields)
    return FakeLayer('tcp', **names)


def fake_packet(link: str, encap: str, layers: 'list[FakeLayer]', number: str = '3') -> 'Any':
    """A PyShark packet: its frame layer of ``encap``, a ``link`` layer, then ``layers``."""
    frame = FakeLayer('frame', encap_type=encap, time_epoch='1.5')
    return types.SimpleNamespace(number=number, frame_info=frame, sniff_timestamp='1.5',
                                 layers=[frame, FakeLayer(link), *layers])


#: An Ethernet frame of IPv4 and TCP, and tshark's dissection of it.
PLAIN = eth(v4(tcp(7)))


def plain(**fields: str) -> 'Any':
    """tshark's dissection of :data:`PLAIN`, with ``fields`` of its TCP layer replaced."""
    return fake_packet('eth', '1', [ip_layer(PLAIN, 14), tcp_layer(PLAIN, 34, **fields)])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ToolkitEncapsulationTests(unittest.TestCase):
    """:func:`tcp_traceflow` reads a frame tshark finds TCP in from its octets, with no tshark."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_frame_tshark_traces_tcp_in_is_read_from_its_octets(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        # tshark's fields are not read: its ports here are not the frame's
        asked = []  # type: list[Any]
        packet = plain(srcport='1', dstport='2')
        data = toolkit.tcp_traceflow(packet, count=4,
                                     captured=lambda p: asked.append(p) or toolkit.Captured(1, PLAIN))
        self.assertEqual(asked, [packet])
        self.assertEqual((data.index, data.src, data.dst, data.srcport, data.dstport, data.seq, data.ack),
                         (4, ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2'),
                          1007, 9, 1007, 1))
        # nor are its flags, so a spelling it does not use raises nothing here
        self.assertIsNotNone(toolkit.tcp_traceflow(plain(flags_syn='maybe'),
                                                   captured=lambda p: toolkit.Captured(1, PLAIN)))

        # where the frame cannot be had, tshark's dissection is traced, as before
        for captured in (None, lambda p: None):
            with self.subTest(captured=captured):
                self.assertEqual(toolkit.tcp_traceflow(plain(srcport='1'), captured=captured).srcport, 1)

        # and a frame tshark finds no TCP in is not asked for
        def refuse(packet: 'Any') -> 'Any':
            raise AssertionError('octets asked for')

        for layers in ([ip_layer(PLAIN, 14)], [ip_layer(PLAIN, 14), FakeLayer('tcp', srcport='1')],
                       [tcp_layer(PLAIN, 34), ip_layer(PLAIN, 14)]):
            with self.subTest(layers=[layer.layer_name for layer in layers]):
                self.assertIsNone(toolkit.tcp_traceflow(fake_packet('eth', '1', layers), captured=refuse))

    def test_tcp_over_a_link_type_the_default_engine_reads_no_ip_over_is_not_traced(self) -> None:
        # tshark reads 12 and 14 as raw IP (frame.encap_type 7, as for 101)
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        octets = v4(tcp(7))
        packet = fake_packet('raw', '7', [ip_layer(octets, 0), tcp_layer(octets, 20)])
        for linktype in (12, 14, 113, 276, 9, 999):
            with self.subTest(linktype=linktype):
                self.assertIsNone(toolkit.tcp_traceflow(
                    packet, captured=lambda p, l=linktype: toolkit.Captured(l, octets)))
        data = toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(101, octets))
        self.assertEqual((data.protocol, data.srcport), (LinkType.RAW, 1007))

        # and nothing is raised for a link type of tshark's this table lacks,
        # as no segment is found
        packet.frame_info.encap_type = '999'
        self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(113, sll(octets))))

    def test_tcp_inside_an_encapsulation_the_default_engine_leaves_raw_is_not_traced(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        inner = v4(tcp(7), inner=True)
        for name, octets, link, layers in (
            ('gre', eth(v4(gre(inner), 47)), 'eth', lambda o: [ip_layer(o, 14), FakeLayer('gre'), ip_layer(o, 38),
                                                                 tcp_layer(o, 58)]),
            ('vxlan', eth(v4(vxlan(eth(inner)), 17)), 'eth',
             lambda o: [ip_layer(o, 14), FakeLayer('udp'), FakeLayer('vxlan'), FakeLayer('eth'), ip_layer(o, 64),
                        tcp_layer(o, 84)]),
            ('mpls', eth(mpls(inner), 0x8847), 'eth', lambda o: [FakeLayer('mpls'), ip_layer(o, 18), tcp_layer(o, 38)]),
            ('llc/snap', llc_snap(inner), 'eth', lambda o: [FakeLayer('llc'), ip_layer(o, 22), tcp_layer(o, 42)]),
            ('isl', isl(eth(inner)), 'isl', lambda o: [FakeLayer('eth'), ip_layer(o, 40), tcp_layer(o, 60)]),
        ):
            with self.subTest(case=name):
                packet = fake_packet(link, '1', layers(octets))
                self.assertIsNotNone(toolkit.tcp_traceflow(packet), 'tshark traces it')
                self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p, o=octets: toolkit.Captured(1, o)))
        # IP-in-IP is a tunnel the default engine dissects
        octets = eth(v4(inner, 4))
        packet = fake_packet('eth', '1', [ip_layer(octets, 14), ip_layer(octets, 34), tcp_layer(octets, 54)])
        data = toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(1, octets))
        self.assertEqual(data.src, ipaddress.ip_address('198.51.100.2'))

    def test_tcp_whose_ip_layer_tshark_dissects_elsewhere_is_not_traced(self) -> None:
        # over link type IPV4 (228), tshark reads an IPv6 packet as IPv6, its
        # ``ip`` layer the version alone; the default engine reads it as IPv4
        from pcapkit.toolkit import pyshark as toolkit

        octets = v6(tcp(7))
        packet = fake_packet('raw', '129', [FakeLayer('ip', version=FakeField('6', 0, '6')), ip_layer(octets, 0),
                                            tcp_layer(octets, 40)])
        self.assertIsNotNone(toolkit.tcp_traceflow(packet), 'tshark traces it')
        self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(228, octets)))
        # and over IPV6 (229), where both read it as IPv6, it is traced
        packet = fake_packet('raw', '130', [ip_layer(octets, 0), tcp_layer(octets, 40)])
        self.assertEqual(toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(229, octets)).srcport, 1007)

    def test_a_source_routed_header_is_read_from_its_octets(self) -> None:
        # tshark reports the last address of a route not used up as ip.dst, at
        # its place in the option, and the header's as ip.cur_rt
        from pcapkit.toolkit import pyshark as toolkit

        def routed(octets: bytes, start: int, pos: int, raw: bytes, **fields: FakeField) -> FakeLayer:
            """:func:`ip_layer`'s, with the header's destination as ``cur_rt``, ``raw`` at ``pos`` as ``dst``."""
            layer = ip_layer(octets, start)
            return FakeLayer('ip', **{**{name: getattr(layer, name) for name in layer.field_names},
                                      'cur_rt': layer.dst,
                                      'dst': FakeField(str(ipaddress.ip_address(raw)), pos, raw.hex()), **fields})

        plain_ = eth(v4(tcp(7), opts=LSRR))
        tunnel = eth(v4(v4(tcp(7), inner=True), 4, opts=LSRR))
        for name, octets, layers, dst in (
            ('lsrr', plain_, lambda o: [routed(o, 14, 37, HOP_1), tcp_layer(o, 42)], wire.IPV4_B),
            ('lsrr, 4in4', tunnel, lambda o: [routed(o, 14, 37, HOP_1), ip_layer(o, 42), tcp_layer(o, 62)],
             wire.IPV4_A),
        ):
            with self.subTest(case=name):
                packet = fake_packet('eth', '1', layers(octets))
                data = toolkit.tcp_traceflow(packet, captured=lambda p, o=octets: toolkit.Captured(1, o))
                self.assertIsNotNone(data)
                self.assertEqual((data.dst, data.srcport), (ipaddress.ip_address(dst), 1007))

        # but each address must still be in the octets where tshark reports it
        for name, layer in (
            ('another destination address', routed(plain_, 14, 37, HOP_2)),
            ('the destination address before the header', routed(plain_, 14, 0, plain_[0:4])),
            ('another source address', routed(plain_, 14, 37, HOP_1, src=FakeField('10.0.0.2', 26, HOP_2.hex()))),
        ):
            with self.subTest(case=name):
                packet = fake_packet('eth', '1', [layer, tcp_layer(plain_, 42)])
                self.assertIsNotNone(toolkit.tcp_traceflow(packet), 'tshark traces it')
                self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(1, plain_)))

    def test_the_filter_matches_every_frame_tshark_traces_tcp_in(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        self.assertEqual(toolkit.OCTETS_FILTER.split(' || ', maxsplit=1)[0], 'tcp')


if __name__ == '__main__':
    unittest.main()
