# -*- coding: utf-8 -*-
"""The pyshark engine traces the TCP the default engine reads behind an extension header in IPv4. C.f. #1625.

The default engine dispatches an IPv4 packet's protocol through the registry
IPv6 uses, so it reads an AH or IPv6 extension header carried directly in IPv4,
and the TCP segment or IP-in-IP tunnel behind it, up to
:data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` headers in a
row; behind such a header it reads TCP only if its TCP parser accepts the
header. tshark dissects TCP behind such a header by rules of its own, so the
pyshark engine traced TCP the default engine rejects, and none at all behind a
Mobility or HIP header, past which tshark dissects nothing and whose payload the
PDML PyShark reads leaves out. Nor does the default engine read past Shim6 in
IPv4, whose parser refuses it, where tshark does. For such a frame the engine
now reads the captured octets from a second tshark pass and applies the
default engine's rules to them
(:func:`pcapkit.toolkit.pypcapfile._past_extension_headers`), from the
outermost IP layer the default engine dissects on, so that a tunnel it does not
dissect, such as GRE or VXLAN, or the chain bound of an outer IPv6 header,
stops the read as it stops the default engine. That layer is found by the link
type in the capture file, which the engine reads for itself, as tshark reads
link types 12 and 14 as it reads raw IP (101). A frame of a link type or
EtherType the default engine dissects no IP over is read as tshark dissects
it, as before.

That pass is a process of the engine's own. If it fails, or the capture file
cannot be read for a link type, the engine warns and traces such frames as
tshark dissects them; whether it fails or not, closing the engine reaps it,
and the first pass's tshark with it.

Every capture is built here, so the module is in the unit tier. The tests that
run tshark skip unless the pyshark engine runs, which needs ``pyshark``, the
``tshark`` binary and Python 3.13 or older; the rest use fakes, and a Python
child process in tshark's place.

"""
from __future__ import annotations

import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def options(nxt: int) -> bytes:
    """A Hop-by-Hop or Destination Options header of 8 octets, one PadN option in it."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


def ah(nxt: int, length: int = 4) -> bytes:
    """An Authentication Header whose Payload Length is ``length``, its ICV filled in."""
    fixed = bytes([nxt, length, 0, 0]) + (0x100).to_bytes(4, 'big') + (7).to_bytes(4, 'big')
    return fixed + b'\xaa' * max((length + 2) * 4 - len(fixed), 0)


def fragment(nxt: int, offset: int = 0) -> bytes:
    """An IPv6 Fragment header; ``offset`` is in octets."""
    return bytes([nxt, 0]) + offset.to_bytes(2, 'big') + (0xDEADBEEF).to_bytes(4, 'big')


def mobility(nxt: int, length: int = 0) -> bytes:
    """A Mobility header, a Binding Refresh Request, whose Header Len is ``length``."""
    return bytes([nxt, length, 0, 0, 0, 0, 0, 0])


def hip(nxt: int) -> bytes:
    """A HIP header of 40 octets, an I1 with no parameters."""
    return bytes([nxt, 4, 1, 0x21, 0, 0, 0, 0]) + b'\x11' * 32


def shim6(nxt: int) -> bytes:
    """A Shim6 payload extension header of 8 octets."""
    return bytes([nxt, 0, 0x80, 0, 0, 0, 0, 1])


def tcp(number: int, *, opts: bytes = b'', words: 'int | None' = None, **flags: bool) -> bytes:
    """A TCP segment carrying ``data`` on a port pair of its own, with ``opts`` and a Data Offset of ``words``."""
    segment = wire.tcp(b'data', seq=1000 + number, ack=1, sport=1000 + number, **flags)
    words = 5 + len(opts) // 4 if words is None else words
    return segment[:12] + bytes([words << 4]) + segment[13:20] + opts + segment[20:]


def v4(payload: bytes, proto: int, *, length: 'int | None' = None, opts: bytes = b'',
       **fields: 'Any') -> bytes:
    """An IPv4 packet carrying ``payload`` as ``proto``, with options ``opts``, its Total Length ``length`` if given."""
    packet = bytearray(wire.ipv4(payload, proto=proto, **fields))
    if opts:
        packet[0] = 0x40 | (5 + len(opts) // 4)
        packet[2:4] = (len(packet) + len(opts)).to_bytes(2, 'big')
        packet[20:20] = opts
    if length is not None:
        packet[2:4] = length.to_bytes(2, 'big')
    packet[10:12] = b'\x00\x00'
    packet[10:12] = wire.checksum(bytes(packet[:(packet[0] & 0x0F) * 4])).to_bytes(2, 'big')
    return bytes(packet)


def v6(payload: bytes, nxt: int) -> bytes:
    """An IPv6 packet carrying ``payload`` as ``nxt``."""
    return wire.ipv6(payload, nxt=nxt)


def eth(packet: bytes) -> bytes:
    """An Ethernet frame carrying the IPv4 or IPv6 ``packet``."""
    return wire.ethernet(packet, 0x86DD if packet[0] >> 4 == 6 else 0x0800)


#: An MSS option of length 3, which the default engine's TCP parser rejects.
BAD_MSS = b'\x02\x03\x05\xb4'
#: An IPv4 Timestamp option of length 2, which its IPv4 parser rejects.
BAD_TIMESTAMP = b'\x44\x02\x00\x00'

#: Frames carrying TCP behind an AH or IPv6 extension header in IPv4, each with
#: whether the default engine traces the TCP, by a name for it. Each builder
#: takes the TCP segment's number, which is its frame number.
CASES = {
    'control': (True, lambda n: eth(v4(tcp(n), 6))),
    # #1625's six, the first two as controls
    'hop-by-hop': (True, lambda n: eth(v4(options(6) + tcp(n), 0))),
    'hop-by-hop, rejected tcp options': (False, lambda n: eth(v4(options(6) + tcp(n, opts=BAD_MSS), 0))),
    'hop-by-hop, tcp data offset past the capture': (False, lambda n: eth(v4(options(6) + tcp(n, words=15), 0))),
    'mobility': (True, lambda n: eth(v4(mobility(6) + tcp(n), 135))),
    'hip': (True, lambda n: eth(v4(hip(6) + tcp(n), 139))),
    # the other headers
    'destination options': (True, lambda n: eth(v4(options(6) + tcp(n), 60))),
    'routing': (True, lambda n: eth(v4(bytes([6, 0, 0, 0, 0, 0, 0, 0]) + tcp(n), 43))),
    'fragment': (True, lambda n: eth(v4(fragment(6) + tcp(n), 44))),
    # the default engine reads past an IPv6 Fragment header inside IPv4 whatever its offset
    'later fragment header': (True, lambda n: eth(v4(fragment(6, 40) + tcp(n), 44))),
    'ah': (True, lambda n: eth(v4(ah(6) + tcp(n), 51))),
    'ah without icv': (True, lambda n: eth(v4(ah(6, 1) + tcp(n), 51))),
    # a Payload Length of 0 declares 8 octets, fewer than the fixed header
    'ah too short': (False, lambda n: eth(v4(ah(6, 0) + tcp(n), 51))),
    'mobility cut short': (False, lambda n: eth(v4(mobility(6, 1) + tcp(n)[:4], 135))),
    # Shim6, whose parser refuses IPv4, so that the default engine reads it raw
    'shim6': (False, lambda n: eth(v4(shim6(6) + tcp(n), 140))),
    'shim6 in 4in4': (False, lambda n: eth(v4(v4(shim6(6) + tcp(n), 140), 4))),
    'shim6 in 4in6': (False, lambda n: eth(v6(v4(shim6(6) + tcp(n), 140), 4))),
    'hop-by-hop then shim6': (False, lambda n: eth(v4(options(140) + shim6(6) + tcp(n), 0))),
    # but not IPv6, which reads past it
    'shim6 in 6in4 behind hop-by-hop': (True, lambda n: eth(v4(options(41) + v6(shim6(6) + tcp(n), 140), 0))),
    # chains
    'ah then hop-by-hop': (True, lambda n: eth(v4(ah(0) + options(6) + tcp(n), 51))),
    'hop-by-hop then ah': (True, lambda n: eth(v4(options(51) + ah(6) + tcp(n), 0))),
    'hop-by-hop then destination options': (True, lambda n: eth(v4(options(60) + options(6) + tcp(n), 0))),
    'mobility then hop-by-hop': (True, lambda n: eth(v4(mobility(0) + options(6) + tcp(n), 135))),
    'hip then destination options': (True, lambda n: eth(v4(hip(60) + options(6) + tcp(n), 139))),
    'chain at the limit': (True, lambda n: eth(v4(b''.join(options(60 if i < 31 else 6) for i in range(32))
                                                  + tcp(n), 60))),
    'chain past the limit': (False, lambda n: eth(v4(b''.join(options(60 if i < 32 else 6) for i in range(33))
                                                     + tcp(n), 60))),
    # tunnels behind the headers, and the headers inside tunnels
    '4in4 behind hop-by-hop': (True, lambda n: eth(v4(options(4) + v4(tcp(n), 6), 0))),
    '6in4 behind hop-by-hop': (True, lambda n: eth(v4(options(41) + v6(tcp(n), 6), 0))),
    '6in4 behind ah': (True, lambda n: eth(v4(ah(41) + v6(tcp(n), 6), 51))),
    '4in4 behind mobility': (True, lambda n: eth(v4(mobility(4) + v4(tcp(n), 6), 135))),
    '6in4 behind hip': (True, lambda n: eth(v4(hip(41) + v6(tcp(n), 6), 139))),
    'hop-by-hop in 4in4': (True, lambda n: eth(v4(v4(options(6) + tcp(n), 0), 4))),
    'hop-by-hop in 4in6': (True, lambda n: eth(v6(v4(options(6) + tcp(n), 0), 4))),
    'mobility in 4in4': (True, lambda n: eth(v4(v4(mobility(6) + tcp(n), 135), 4))),
    'hop-by-hop in 4in4 behind hop-by-hop': (True, lambda n: eth(v4(options(4) + v4(options(6) + tcp(n), 0), 0))),
    # IP behind the header that the default engine does not read
    'short ipv4 behind hop-by-hop': (False, lambda n: eth(v4(options(4) + v4(tcp(n), 6)[:12], 0))),
    'short ipv6 behind hop-by-hop': (False, lambda n: eth(v4(options(41) + v6(tcp(n), 6)[:30], 0))),
    'bad ipv4 behind hop-by-hop': (False, lambda n: eth(v4(options(4) + b'\x55' + v4(tcp(n), 6)[1:], 0))),
    'rejected ipv4 options behind hop-by-hop': (False, lambda n: eth(v4(options(4) + v4(tcp(n), 6, opts=BAD_TIMESTAMP),
                                                                       0))),
    'rejected ipv4 options, then hop-by-hop': (False, lambda n: eth(v4(options(6) + tcp(n), 0, opts=BAD_TIMESTAMP))),
    # TCP behind the header, read as the TCP parser reads it
    'tcp options': (True, lambda n: eth(v4(options(6) + tcp(n, opts=b'\x02\x04\x05\xb4'), 0))),
    'tcp data offset below 5': (False, lambda n: eth(v4(options(6) + tcp(n, words=4), 0))),
    'tcp cut short': (False, lambda n: eth(v4(options(6) + tcp(n)[:16], 0))),
    'mobility, rejected tcp options': (False, lambda n: eth(v4(mobility(6) + tcp(n, opts=BAD_MSS), 135))),
    'hip, tcp data offset past the capture': (False, lambda n: eth(v4(hip(6) + tcp(n, words=15), 139))),
    # directly over the inner IP layer, the default engine reads a rejected header raw
    'rejected tcp options in 4in4 behind hop-by-hop': (True, lambda n: eth(v4(options(4) + v4(tcp(n, opts=BAD_MSS), 6),
                                                                              0))),
    'rejected tcp options in 6in4 behind mobility': (True, lambda n: eth(v4(mobility(41) + v6(tcp(n, opts=BAD_MSS), 6),
                                                                            135))),
    'no tcp': (False, lambda n: eth(v4(options(17) + wire.udp(b'data', sport=1000 + n), 0))),
    'flags': (True, lambda n: eth(v4(mobility(6) + tcp(n, syn=True, fin=True, rst=True), 135))),
    # the Total Length bounds what is read, and a zero one does not
    'total length short of the tcp': (False, lambda n: eth(v4(options(6) + tcp(n), 0, length=40))),
    'total length under the header': (False, lambda n: eth(v4(options(6) + tcp(n), 0, length=12))),
    'zero total length': (True, lambda n: eth(v4(options(6) + tcp(n), 0, length=0))),
    'trailer': (True, lambda n: eth(v4(mobility(6) + tcp(n), 135)) + b'\x00' * 10),
    'later ipv4 fragment': (False, lambda n: eth(v4(mobility(6) + tcp(n), 135, offset=8))),
    'first ipv4 fragment': (True, lambda n: eth(v4(mobility(6) + tcp(n), 135, mf=True))),
    # the default engine does not dissect the datagram an ICMP error quotes
    'quoted in an icmp error': (False, lambda n: eth(v4(bytes([3, 3, 0, 0, 0, 0, 0, 0])
                                                        + v4(mobility(6) + tcp(n), 135), 1))),
}


def gre(packet: bytes) -> bytes:
    """A GRE packet, with no options, carrying the IPv4 ``packet``."""
    return b'\x00\x00\x08\x00' + packet


def vxlan(frame: bytes) -> bytes:
    """A UDP datagram to the VXLAN port, carrying the Ethernet ``frame`` with VNI 1."""
    return wire.udp(b'\x08\x00\x00\x00\x00\x00\x01\x00' + frame, sport=4000, dport=4789)


def chain(count: int, nxt: int) -> bytes:
    """``count`` Destination Options headers in a row, the last naming ``nxt``."""
    return b''.join(options(60 if index < count - 1 else nxt) for index in range(count))


#: Frames whose AH or IPv6 extension header in IPv4 sits inside a tunnel or
#: behind an IPv6 header, as in :data:`CASES`. The default engine reads a frame
#: from its outermost IP layer on, so it stops at a tunnel it does not dissect,
#: such as GRE or VXLAN, which tshark does, and at a chain of more than
#: :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` extension
#: headers in the IPv6 header carrying the IPv4.
OUTERMOST_CASES = {
    'mobility in gre': (False, lambda n: eth(v4(gre(v4(mobility(6) + tcp(n), 135)), 47))),
    'hip in gre': (False, lambda n: eth(v4(gre(v4(hip(6) + tcp(n), 139)), 47))),
    'hop-by-hop in gre': (False, lambda n: eth(v4(gre(v4(options(6) + tcp(n), 0)), 47))),
    'mobility in 4in4 in gre': (False, lambda n: eth(v4(gre(v4(v4(mobility(6) + tcp(n), 135), 4)), 47))),
    'hop-by-hop in 4in4 in gre': (False, lambda n: eth(v4(gre(v4(v4(options(6) + tcp(n), 0), 4)), 47))),
    'mobility in vxlan': (False, lambda n: eth(v4(vxlan(eth(v4(mobility(6) + tcp(n), 135))), 17))),
    'hip in vxlan': (False, lambda n: eth(v4(vxlan(eth(v4(hip(6) + tcp(n), 139))), 17))),
    'hop-by-hop in vxlan': (False, lambda n: eth(v4(vxlan(eth(v4(options(6) + tcp(n), 0))), 17))),
    'mobility in 4in6 past the chain limit': (False, lambda n: eth(v6(chain(33, 4) + v4(mobility(6) + tcp(n), 135),
                                                                      60))),
    'hop-by-hop in 4in6 past the chain limit': (False, lambda n: eth(v6(chain(33, 4) + v4(options(6) + tcp(n), 0),
                                                                        60))),
    'mobility in 4in6 at the chain limit': (True, lambda n: eth(v6(chain(32, 4) + v4(mobility(6) + tcp(n), 135), 60))),
    'mobility in 4in6 behind a short chain': (True, lambda n: eth(v6(chain(2, 4) + v4(mobility(6) + tcp(n), 135), 60))),
    'hip in 4in6 in 6in4 behind hop-by-hop': (True, lambda n: eth(v4(options(41) + v6(v4(hip(6) + tcp(n), 139), 4),
                                                                     0))),
}


def vlan(packet: bytes, *tags: int) -> bytes:
    """An Ethernet frame carrying the IPv4 ``packet`` behind a VLAN tag of each TPID in ``tags``."""
    inner = b''.join(struct.pack('>HH', 1, tpid) for tpid in tags[1:]) + struct.pack('>HH', 1, 0x0800)
    return wire.ethernet(inner + packet, tags[0])


def loopback(packet: bytes, family: int, byteorder: str) -> bytes:
    """A BSD loopback frame carrying ``packet`` as the address ``family``, written in ``byteorder``."""
    return family.to_bytes(4, byteorder) + packet


def sll(packet: bytes) -> bytes:
    """A Linux cooked-mode (SLL) frame carrying the IPv4 ``packet``."""
    return struct.pack('>HHH8sH', 0, 1, 6, b'\x02\x00\x00\x00\x00\x01', 0x0800) + packet


#: Frames of each link type that carry an AH or IPv6 extension header in IPv4,
#: each with the link type, whether the default engine traces the TCP, and a
#: builder as in :data:`CASES`, by a name for it. The default engine dissects IP
#: over the link types and EtherTypes :func:`pcapkit.toolkit.pyshark._network_start`
#: names only; a frame over any other, such as MPLS, Linux SLL, or the BSD raw
#: IP of link types 12 and 14, which tshark reads as raw IP (101), is read as
#: tshark dissects it, which reads no TCP past a Mobility or HIP header.
LINK_CASES = {
    'vlan, mobility': (1, True, lambda n: vlan(v4(mobility(6) + tcp(n), 135), 0x8100)),
    'qinq, hip': (1, True, lambda n: vlan(v4(hip(6) + tcp(n), 139), 0x88A8, 0x8100)),
    'qinq, hop-by-hop, rejected tcp options': (1, False, lambda n: vlan(v4(options(6) + tcp(n, opts=BAD_MSS), 0),
                                                                        0x88A8, 0x8100)),
    'mpls, mobility': (1, False, lambda n: wire.ethernet(b'\x00\x01\x01\x40' + v4(mobility(6) + tcp(n), 135), 0x8847)),
    'null, mobility': (0, True, lambda n: loopback(v4(mobility(6) + tcp(n), 135), 2, 'little')),
    'null, mobility in 4in6': (0, True, lambda n: loopback(v6(v4(mobility(6) + tcp(n), 135), 4), 30, 'big')),
    'null, hop-by-hop, rejected tcp options': (0, False, lambda n: loopback(v4(options(6) + tcp(n, opts=BAD_MSS), 0),
                                                                            2, 'little')),
    'loop, hip': (108, True, lambda n: loopback(v4(hip(6) + tcp(n), 139), 2, 'big')),
    'loop, hop-by-hop in 4in6': (108, True, lambda n: loopback(v6(v4(options(6) + tcp(n), 0), 4), 24, 'big')),
    'raw, mobility': (101, True, lambda n: v4(mobility(6) + tcp(n), 135)),
    'raw, mobility in 4in6 past the chain limit': (101, False, lambda n: v6(chain(33, 4)
                                                                           + v4(mobility(6) + tcp(n), 135), 60)),
    'ipv4, hip': (228, True, lambda n: v4(hip(6) + tcp(n), 139)),
    'ipv4, hop-by-hop, tcp data offset past the capture': (228, False, lambda n: v4(options(6) + tcp(n, words=15), 0)),
    'ipv6, mobility in 4in6': (229, True, lambda n: v6(v4(mobility(6) + tcp(n), 135), 4)),
    'sll, mobility': (113, False, lambda n: sll(v4(mobility(6) + tcp(n), 135))),
    'sll, hip': (113, False, lambda n: sll(v4(hip(6) + tcp(n), 139))),
    'bsd raw (12), mobility': (12, False, lambda n: v4(mobility(6) + tcp(n), 135)),
    'bsd raw (12), hip in 4in6': (12, False, lambda n: v6(v4(hip(6) + tcp(n), 139), 4)),
    'openbsd raw (14), hip': (14, False, lambda n: v4(hip(6) + tcp(n), 139)),
    'openbsd raw (14), mobility in 4in6': (14, False, lambda n: v6(v4(mobility(6) + tcp(n), 135), 4)),
}


def build(cases: 'dict[str, tuple[bool, Callable[[int], bytes]]]') -> 'tuple[list[bytes], list[int]]':
    """The frames of ``cases``, and the numbers of those the default engine traces TCP from."""
    numbered = list(enumerate(cases.values(), start=1))
    return ([make(number) for number, (_, make) in numbered],
            [number for number, (reads, _) in numbered if reads])


def block(kind: int, body: bytes, byteorder: str = 'little') -> bytes:
    """A PCAP-NG block of type ``kind`` around ``body``, zero-padded to 32 bits, in ``byteorder``."""
    order = '<' if byteorder == 'little' else '>'
    body += bytes(-len(body) % 4)
    return struct.pack(f'{order}II', kind, len(body) + 12) + body + struct.pack(f'{order}I', len(body) + 12)


def journal(entry: bytes) -> bytes:
    """A systemd Journal Export Block holding ``entry``."""
    return block(9, entry)


def spb(octets: bytes) -> bytes:
    """A Simple Packet Block of ``octets``, which carries no timestamp."""
    return block(3, struct.pack('<I', len(octets)) + octets)


def section(linktypes: 'list[int]', packets: 'list[tuple[int, int, bytes]]', byteorder: str = 'little') -> bytes:
    """A PCAP-NG section in ``byteorder``, with an interface of each of ``linktypes``, then ``packets``.

    Each packet is ``(kind, interface, octets)``: an Enhanced Packet Block (6),
    an obsolete Packet Block (2), or a Simple Packet Block (3), which names no
    interface. Any other kind is a block of that type around ``octets``.

    """
    order = '<' if byteorder == 'little' else '>'
    out = [block(0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1), byteorder)]
    out += [block(1, struct.pack(f'{order}HHI', linktype, 0, 0xFFFF), byteorder) for linktype in linktypes]
    for kind, interface, octets in packets:
        head = {6: struct.pack(f'{order}IIIII', interface, 0, 1, len(octets), len(octets)),
                2: struct.pack(f'{order}HHIIII', interface, 0, 0, 1, len(octets), len(octets)),
                3: struct.pack(f'{order}I', len(octets))}.get(kind, b'')
        out.append(block(kind, head + octets, byteorder))
    return b''.join(out)


def tshark_children() -> 'dict[int, str] | None':
    """The state of each ``tshark`` process this one started, by pid, as ``ps`` reports it; :data:`None` without ``ps``."""
    try:
        listing = subprocess.run(['ps', '-e', '-o', 'pid=', '-o', 'ppid=', '-o', 'stat=', '-o', 'comm='],
                                 capture_output=True, text=True, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    children = {}
    for line in listing.splitlines():
        fields = line.split(None, 3)
        if len(fields) == 4 and fields[1] == str(os.getpid()) and 'tshark' in fields[3]:
            children[int(fields[0])] = fields[2]
    return children


def read(test: unittest.TestCase, engine: str, capture: bytes, suffix: str = 'pcap') -> 'dict[str, Any]':
    """Read ``capture`` with ``engine``, with TCP reassembly and flow tracing on.

    Returns:
        The input flow tracing receives for each frame number -- every field but
        ``frame``, ``header`` and ``payload``, which PyShark cannot supply --
        the traced flows' labels and frames, and how many inputs TCP
        reassembly received, or :data:`None` if the engine declines it.

    Skips ``test`` unless ``engine`` ran.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
    from pcapkit.utilities.exceptions import UnsupportedCall

    if engine != 'default' and importlib.util.find_spec(engine) is None:
        test.skipTest(f'{engine} not installed')
    reassemble, trace = ReassemblyBase.__call__, TraceFlowBase.__call__
    seen = {'tcp': 0, 'trace': {}}  # type: dict[str, Any]

    def spy_tcp(this: 'Any', packet: 'Any') -> 'Any':
        seen['tcp'] += 1
        return reassemble(this, packet)

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = {key: value for key, value in packet.items()
                                       if key not in ('frame', 'header', 'payload')}
        return trace(this, packet)

    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(ReassemblyBase, '__call__', spy_tcp), \
            mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        warnings.simplefilter('ignore')
        path = os.path.join(tmp, f'capture.{suffix}')
        with open(path, 'wb') as file:
            file.write(capture)
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, tcp=True,
                            trace=True, trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
            try:
                declined = extractor.reassembly.tcp is None
            except UnsupportedCall:
                declined = True
            if declined:
                seen['tcp'] = None
        finally:
            close_extractor(extractor)
    return seen


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PySharkExtensionHeaderTraceTests(unittest.TestCase):
    """The pyshark engine traces the TCP the default engine reads behind an extension header in IPv4, and no other."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree(self, capture: bytes, reads: 'list[int]', names: 'dict[int, str]',
              suffix: str = 'pcap') -> None:
        base = read(self, 'default', capture, suffix)
        # what the default engine reads, as the cases say
        self.assertEqual(sorted(base['trace']), reads)
        seen = read(self, 'pyshark', capture, suffix)
        self.assertEqual([names[number] for number in sorted(set(seen['trace']) ^ set(base['trace']))], [],
                         'frames traced by one of pyshark and the default engine alone')
        for number, record in base['trace'].items():
            self.assertEqual(seen['trace'][number], record, names[number])
        self.assertEqual(seen['flows'], base['flows'])
        # pyshark still declines TCP reassembly
        self.assertIsNone(seen['tcp'])
        self.assertEqual(base['tcp'], len(reads))

    def test_tcp_behind_an_extension_header_in_ipv4_is_traced_as_the_default_engine_reads_it(self) -> None:
        frames, reads = build(CASES)
        self.agree(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)]),
                   reads, dict(enumerate(CASES, start=1)))

    def test_the_frame_is_read_from_its_outermost_ip_layer(self) -> None:
        # GRE, VXLAN and an outer IPv6 header's chain bound stop it, as they
        # stop the default engine, wherever the extension header in IPv4 is
        frames, reads = build(OUTERMOST_CASES)
        self.agree(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)]),
                   reads, dict(enumerate(OUTERMOST_CASES, start=1)))

    def test_each_link_type_is_read_as_the_default_engine_reads_it(self) -> None:
        for linktype in sorted({link for link, _, _ in LINK_CASES.values()}):
            cases = {name: (reads, make) for name, (link, reads, make) in LINK_CASES.items() if link == linktype}
            with self.subTest(linktype=linktype):
                frames, reads = build(cases)
                self.agree(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)],
                                     linktype=linktype), reads, dict(enumerate(cases, start=1)))

    def test_the_octets_are_those_of_the_frame_past_a_record_that_is_no_packet(self) -> None:
        # tshark numbers a journal block as a frame, the default engine counts
        # packets only, and the second tshark pass is keyed by tshark's number
        cases = {name: CASES[name] for name in ('control', 'mobility', 'hip, tcp data offset past the capture',
                                                'hop-by-hop', 'hop-by-hop, rejected tcp options', 'flags')}
        frames, reads = build(cases)
        head = wire.pcapng([])
        packets = [wire.pcapng([(1, number, octets)])[len(head):] for number, octets in enumerate(frames)]
        entry = journal(b'__REALTIME_TIMESTAMP=1000000\nMESSAGE=hello\n')
        capture = head + entry + packets[0] + entry + b''.join(packets[1:3]) + entry + b''.join(packets[3:])
        self.agree(capture, reads, dict(enumerate(cases, start=1)), suffix='pcapng')

    def test_a_simple_packet_block_is_traced(self) -> None:
        # a Simple Packet Block carries no timestamp, which PyShark's JSON
        # parser could not do without
        cases = {name: CASES[name] for name in ('control', 'hop-by-hop', 'mobility',
                                                'hop-by-hop, rejected tcp options')}
        frames, reads = build(cases)
        head = wire.pcapng([])
        capture = head + wire.pcapng([(1, 0, frames[0])])[len(head):] + b''.join(spb(octets) for octets in frames[1:])
        self.agree(capture, reads, dict(enumerate(cases, start=1)), suffix='pcapng')

    def test_each_interface_is_read_by_its_own_link_type(self) -> None:
        # a PCAP-NG frame's link type is its interface's, among those of its
        # own section; tshark reads 12 and 14 as it reads raw IP (101)
        def raw(n: int) -> bytes:
            return v4(mobility(6) + tcp(n), 135)

        def raw6(n: int) -> bytes:
            return v6(v4(hip(6) + tcp(n), 139), 4)

        # by section: its interfaces' link types, then its blocks, each a block
        # type, an interface, the octets, and whether the default engine
        # traces them, or None for a block that is no packet
        sections = [
            ([1, 12, 101], 'little', [(6, 0, eth(raw(1)), True),
                                      (6, 1, raw(2), False),
                                      (9, 0, b'__REALTIME_TIMESTAMP=1000000\nMESSAGE=hello\n', None),
                                      (6, 2, raw(3), True),
                                      (3, 0, eth(raw6(4)), True)]),
            ([14, 101], 'big', [(3, 0, raw6(5), False),
                                (6, 1, raw6(6), True),
                                (2, 0, raw(7), False),
                                (2, 1, v4(options(6) + tcp(8, opts=BAD_MSS), 0), False)]),
        ]
        capture = b''.join(section(linktypes, [packet[:3] for packet in packets], byteorder)
                           for linktypes, byteorder, packets in sections)
        packets = [(f'section {index}, block {kind}, interface {interface}', reads)
                   for index, (_, _, blocks) in enumerate(sections, start=1)
                   for kind, interface, _, reads in blocks if reads is not None]
        self.agree(capture, [number for number, (_, reads) in enumerate(packets, start=1) if reads],
                   {number: name for number, (name, _) in enumerate(packets, start=1)}, suffix='pcapng')

    def test_a_second_pass_tshark_rejects_falls_back_with_a_warning(self) -> None:
        # the frames are traced as tshark dissects them, as before #1625
        from pcapkit.utilities.warnings import PySharkWarning

        cases = {name: CASES[name] for name in ('control', 'hop-by-hop', 'mobility',
                                                'hop-by-hop, rejected tcp options')}
        frames, _ = build(cases)
        capture = wire.pcap([(1, number, octets) for number, octets in enumerate(frames)])
        with mock.patch('pcapkit.toolkit.pyshark.OCTETS_FILTER', 'ip.proto =='), \
                mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
            seen = read(self, 'pyshark', capture)
        self.assertEqual(sorted(seen['trace']), [1, 2, 4])
        messages = [call.args[0] for call in warn.call_args_list if call.args[1] is PySharkWarning]
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('Frame 2: the second tshark pass', messages[0])
        self.assertIn('exited with status', messages[0])

    def test_an_early_close_leaves_no_tshark_behind(self) -> None:
        from pcapkit import extract

        if tshark_children() is None:
            self.skipTest('ps is not available')
        frames = [(CASES['mobility'] if number % 5 == 0 else CASES['control'])[1](number) for number in range(1, 400)]
        for how in ('__exit__', '_cleanup'):
            with self.subTest(close=how), tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
                warnings.simplefilter('ignore')
                path = os.path.join(tmp, 'capture.pcap')
                with open(path, 'wb') as file:
                    file.write(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)]))
                before = tshark_children() or {}
                extractor = extract(fin=path, nofile=True, engine='pyshark', auto=False, tcp=True, trace=True,
                                    trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
                try:
                    if extractor._exnam != 'pyshark':  # pylint: disable=protected-access
                        self.skipTest('pyshark did not run')
                    for _ in range(30):
                        next(extractor)
                    self.assertIsNotNone(extractor._exeng._exraw, 'the second pass started')
                    self.assertEqual(len(set(tshark_children() or {}) - set(before)), 2)
                finally:
                    if how == '__exit__':
                        extractor.__exit__(None, None, None)
                    else:
                        extractor._cleanup()  # pylint: disable=protected-access
                deadline = time.monotonic() + 3
                while True:
                    left = {pid: state for pid, state in (tshark_children() or {}).items() if pid not in before}
                    if not left or time.monotonic() > deadline:
                        break
                    time.sleep(0.1)
                self.assertEqual(left, {}, 'tshark processes left behind, by pid, with their state')


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


#: An Ethernet frame of IPv4 protocol 135, a Mobility header and TCP, as on the wire.
MOBILITY = eth(v4(mobility(6) + tcp(7, syn=True), 135))


#: ``MOBILITY``'s IPv4 packet, as a raw IP frame.
RAW_MOBILITY = MOBILITY[14:]


def fake_packet(octets: bytes = MOBILITY, *, number: str = '3', start: int = 14) -> 'Any':
    """A PyShark packet of a frame of the IPv4 ``octets`` from ``start`` on, as tshark dissects ``MOBILITY``.

    The frame is Ethernet, or raw IP if ``start`` is 0, as tshark names it.

    """
    ip = FakeLayer('ip', version=FakeField('4', start, '4'), proto=FakeField(str(octets[start + 9])),
                   src=FakeField('192.0.2.1', start + 12, octets[start + 12:start + 16].hex()),
                   dst=FakeField('198.51.100.2', start + 16, octets[start + 16:start + 20].hex()))
    frame = FakeLayer('frame', encap_type='1' if start else '7', time_epoch='1.5')
    return types.SimpleNamespace(number=number, frame_info=frame, sniff_timestamp='1.5',
                                 layers=[frame, FakeLayer('eth' if start else 'raw'), ip, FakeLayer('mipv6')])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ToolkitOctetsTests(unittest.TestCase):
    """:func:`tcp_traceflow` reads such a frame from its octets, with no tshark."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_segment_is_read_from_the_octets(self) -> None:
        import ipaddress

        from pcapkit.toolkit import pyshark as toolkit

        asked = []  # type: list[Any]
        packet = fake_packet()
        data = toolkit.tcp_traceflow(packet, count=2,
                                     captured=lambda p: asked.append(p) or toolkit.Captured(1, MOBILITY))
        self.assertEqual(asked, [packet])
        self.assertEqual((data.index, data.src, data.dst, data.srcport, data.dstport, data.seq, data.ack),
                         (2, ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2'),
                          1007, 9, 1007, 1))
        self.assertEqual((data.syn, data.fin, data.rst), (True, False, False))

    def test_the_octets_are_read_as_the_default_engine_reads_them(self) -> None:
        # every case, read from its outermost IP header on
        from pcapkit.toolkit import pyshark as toolkit

        fields = ('src', 'dst', 'srcport', 'dstport', 'seq', 'ack', 'syn', 'fin', 'rst')
        for cases in (CASES, OUTERMOST_CASES):
            frames, _ = build(cases)
            base = read(self, 'default', wire.pcap([(1, number, octets) for number, octets in enumerate(frames)]))
            for number, (name, octets) in enumerate(zip(cases, frames), start=1):
                version = {b'\x08\x00': 4, b'\x86\xdd': 6}[octets[12:14]]
                with self.subTest(case=name), warnings.catch_warnings():
                    warnings.simplefilter('ignore')  # what the parsers warn of rejecting a header
                    segment = toolkit._from_octets(version, octets[14:])  # pylint: disable=protected-access
                    record = base['trace'].get(number)
                    if record is None:
                        self.assertIsNone(segment)
                    else:
                        self.assertIsNotNone(segment)
                        self.assertEqual({field: getattr(segment, field) for field in fields},
                                         {field: record[field] for field in fields})

    def test_the_outermost_ip_layer_is_found_as_the_default_engine_finds_it(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        packet4, packet6 = v4(tcp(1), 6), v6(tcp(1), 6)
        for name, linktype, octets, found in (
            ('ethernet', 1, eth(packet4), (4, 14)),
            ('ethernet, ipv6', 1, eth(packet6), (6, 14)),
            ('vlan', 1, vlan(packet4, 0x8100), (4, 18)),
            ('qinq', 1, vlan(packet4, 0x88A8, 0x8100), (4, 22)),
            ('ethernet, arp', 1, wire.ethernet(packet4, 0x0806), None),
            ('ethernet, mpls', 1, wire.ethernet(b'\x00\x01\x01\x40' + packet4, 0x8847), None),
            ('ethernet cut short', 1, eth(packet4)[:13], None),
            ('vlan tag cut short', 1, vlan(packet4, 0x8100)[:17], None),
            ('null', 0, loopback(packet4, 2, 'little'), (4, 4)),
            ('null, big-endian', 0, loopback(packet6, 28, 'big'), (6, 4)),
            ('null, another family', 0, loopback(packet4, 7, 'little'), None),
            ('null cut short', 0, b'\x02\x00\x00', None),
            ('loop', 108, loopback(packet6, 24, 'big'), (6, 4)),
            # a LOOP family is in network byte order, never inferred
            ('loop, little-endian', 108, loopback(packet4, 2, 'little'), None),
            ('raw', 101, packet4, (4, 0)),
            ('raw, ipv6', 101, packet6, (6, 0)),
            ('raw, another version', 101, b'\x55' + packet4[1:], None),
            ('raw, empty', 101, b'', None),
            ('ipv4', 228, packet4, (4, 0)),
            ('ipv6', 229, packet6, (6, 0)),
            ('linux sll', 113, sll(packet4), None),
        ):
            with self.subTest(case=name):
                self.assertEqual(toolkit._network_start(linktype, octets), found)  # pylint: disable=protected-access

    def test_the_octets_are_read_from_the_outermost_ip_layer_tshark_dissects(self) -> None:
        # an IPv6 layer above the IPv4 one, as tshark dissects 4in6
        import ipaddress

        from pcapkit.toolkit import pyshark as toolkit

        octets = eth(v6(v4(mobility(6) + tcp(7, syn=True), 135), 4))
        ipv6 = FakeLayer('ipv6', version=FakeField('6', 14, '6'),
                         src=FakeField('2001:db8::1', 22, octets[22:38].hex()),
                         dst=FakeField('2001:db8::2', 38, octets[38:54].hex()))
        ip = FakeLayer('ip', version=FakeField('4', 54, '4'), proto=FakeField('135'),
                       src=FakeField('192.0.2.1', 66, octets[66:70].hex()),
                       dst=FakeField('198.51.100.2', 70, octets[70:74].hex()))
        packet = fake_packet()
        packet.layers[2:3] = [ipv6, ip]
        data = toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(1, octets))
        self.assertEqual((data.src, data.dst, data.srcport, data.syn),
                         (ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2'), 1007, True))

        # nothing is read unless the outermost IP layer tshark dissects is
        # the one the default engine does, in the same octets
        moved = bytearray(octets)
        moved[38] ^= 0xFF
        for name, layers, frame in (
            ('another destination address', [ipv6, ip], bytes(moved)),
            ('the ipv4 layer first', [ip, ipv6], octets),
            ('the ipv4 layer alone', [ip], octets),
            ('behind a vlan tag', [ipv6, ip], vlan(octets[14:], 0x8100)),
        ):
            with self.subTest(case=name):
                packet.layers[2:-1] = layers
                self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p, f=frame: toolkit.Captured(1, f)))

    def test_the_link_type_is_the_capture_files(self) -> None:
        # not the one tshark's frame.encap_type names: it reads 12 and 14 as
        # raw IP (encap 7, 101), and the default engine leaves them raw
        import ipaddress

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        packet = fake_packet(RAW_MOBILITY, start=0)
        data = toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(101, RAW_MOBILITY))
        self.assertEqual((data.src, data.srcport, data.syn), (ipaddress.ip_address('192.0.2.1'), 1007, True))
        # the record's link type is still tshark's, the same for each link type read
        self.assertEqual(data.protocol, LinkType.RAW)
        for linktype in (12, 14):
            with self.subTest(linktype=linktype):
                self.assertIsNone(toolkit.tcp_traceflow(
                    packet, captured=lambda p, l=linktype: toolkit.Captured(l, RAW_MOBILITY)))
        # nor is an Ethernet frame read as raw IP, or the other way round
        self.assertIsNone(toolkit.tcp_traceflow(fake_packet(), captured=lambda p: toolkit.Captured(101, MOBILITY)))
        self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(1, RAW_MOBILITY)))

    def test_a_link_type_the_default_engine_reads_no_ip_in_is_left_to_tshark(self) -> None:
        # tshark dissects nothing past the Mobility header, so there is no TCP;
        # an unknown link type of tshark's raises only once a segment is found
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import MissingKeyError

        for linktype in (113, 276, 12, 14, 999):  # Linux SLL and SLL2, BSD raw IP, then none at all
            with self.subTest(linktype=linktype):
                self.assertIsNone(toolkit.tcp_traceflow(
                    fake_packet(), captured=lambda p, l=linktype: toolkit.Captured(l, MOBILITY)))
        # with no frame.encap_type, the root layer names the record's link type
        packet = fake_packet()
        del packet.frame_info.encap_type
        packet.frame_info.field_names = ('time_epoch',)
        captured = lambda p: toolkit.Captured(1, MOBILITY)  # noqa: E731
        self.assertEqual(toolkit.tcp_traceflow(packet, captured=captured).protocol, LinkType.ETHERNET)
        packet.layers[1] = FakeLayer('sll')
        with self.assertRaises(MissingKeyError):
            toolkit.tcp_traceflow(packet, captured=captured)
        packet = fake_packet()
        packet.frame_info.encap_type = '999'
        packet.layers.append(FakeLayer('tcp', urgent_pointer='0', srcport='1', dstport='2', seq_raw='3', ack_raw='4',
                                       flags_syn='True', flags_fin='False', flags_reset='False'))
        with self.assertRaises(MissingKeyError):
            toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(113, MOBILITY))

    def test_no_octets_leaves_tsharks_dissection(self) -> None:
        # tshark dissects nothing past the Mobility header, so there is no TCP
        from pcapkit.toolkit import pyshark as toolkit

        self.assertIsNone(toolkit.tcp_traceflow(fake_packet()))
        self.assertIsNone(toolkit.tcp_traceflow(fake_packet(), captured=lambda p: None))

    def test_octets_other_than_the_layers_are_not_read(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        packet = fake_packet()
        moved = bytearray(MOBILITY)
        moved[26] ^= 0xFF  # not the source address tshark reports
        for octets in (bytes(moved), MOBILITY[:30], b'\x00' * len(MOBILITY)):
            with self.subTest(octets=octets[:34].hex()):
                self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p, o=octets: toolkit.Captured(1, o)))
        packet.layers[2].version = FakeField('4', -1, '4')
        self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(1, MOBILITY)))
        del packet.layers[2].version
        self.assertIsNone(toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(1, MOBILITY)))

    def test_only_an_ipv4_extension_header_asks_for_the_octets(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        def refuse(packet: 'Any') -> 'Any':
            raise AssertionError('octets asked for')

        for proto in ('6', '17', '41', '50', 'six'):
            with self.subTest(proto=proto):
                packet = fake_packet()
                packet.layers[2].proto = FakeField(proto)
                self.assertIsNone(toolkit.tcp_traceflow(packet, captured=refuse))
        packet = fake_packet()
        del packet.layers[2].proto
        self.assertIsNone(toolkit.tcp_traceflow(packet, captured=refuse))
        # an IP layer below the first TCP layer is not looked at
        packet = fake_packet()
        packet.layers.insert(2, FakeLayer('tcp'))
        self.assertIsNone(toolkit.tcp_traceflow(packet, captured=refuse))
        # each of the headers, and Shim6, asks for them
        for proto in ('0', '43', '44', '51', '60', '135', '139', '140'):
            with self.subTest(proto=proto):
                asked = []  # type: list[Any]
                packet = fake_packet()
                packet.layers[2].proto = FakeField(proto)
                toolkit.tcp_traceflow(packet, captured=lambda p: asked.append(p))
                self.assertEqual(asked, [packet])

    def test_the_filter_names_every_extension_header(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.toolkit.pypcapfile import IPV4_EXTENSION_HEADERS

        self.assertEqual(toolkit.OCTETS_FILTER, 'ip.proto == 0 || ip.proto == 43 || ip.proto == 44 || '
                                                'ip.proto == 51 || ip.proto == 60 || ip.proto == 135 || '
                                                'ip.proto == 139 || ip.proto == 140')
        self.assertEqual(len(IPV4_EXTENSION_HEADERS), 7)
        self.assertEqual(toolkit.OCTETS_PROTOCOLS - IPV4_EXTENSION_HEADERS, {140})


def ek(*numbers: int) -> str:
    """tshark's ``-T ek -x -J frame`` output for frames ``numbers``, each frame's octets its number."""
    lines = []
    for number in numbers:
        lines.append(json.dumps({'index': {'_index': 'packets-1970-01-01'}}))
        lines.append(json.dumps({'timestamp': '0', 'layers': {
            'frame_raw': bytes([number]).hex(), 'frame': {'frame_frame_number': str(number)}}}))
    return ''.join(f'{line}\n' for line in lines)


def child(output: str = '', *, error: str = '', status: int = 0, linger: bool = False) -> 'list[str]':
    """A command standing in for tshark: it writes ``output`` and ``error``, then exits with ``status``, or lingers."""
    script = (f'import sys, time\nsys.stdout.write({output!r})\nsys.stdout.flush()\n'
              f'sys.stderr.write({error!r})\nsys.stderr.flush()\n'
              + ('time.sleep(60)\n' if linger else '') + f'sys.exit({status})\n')
    return [sys.executable, '-c', script]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineCapturedTests(unittest.TestCase):
    """:meth:`PyShark._captured` reads the file and second pass forward, and falls back if either fails; no tshark."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def capture(self, data: bytes, suffix: str = 'pcap') -> str:
        """Write ``data`` to a capture file removed after the test, and return its path."""
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, f'capture.{suffix}')
        with open(path, 'wb') as file:
            file.write(data)
        return path

    def engine(self, command: 'list[str]', capture: 'str | None' = None) -> 'Any':
        from pcapkit.foundation.engines.pyshark import PyShark

        engine = PyShark.__new__(PyShark)  # skip __init__, which imports pyshark
        engine._extractor = types.SimpleNamespace(_ifnm=capture or self.capture(wire.pcap([])), _frnum=7)
        engine._extmp = types.SimpleNamespace(close=mock.Mock())
        engine._exraw = engine._exraw_err = engine._exraw_held = None
        engine._exlink = engine._exlink_held = None
        engine._exraw_failed = False
        engine._octets_command = mock.Mock(return_value=command)
        self.addCleanup(engine._stop_captured)
        return engine

    @staticmethod
    def ask(engine: 'Any', number: int, count: 'int | None' = None) -> 'Any':
        if count is not None:
            engine._extractor._frnum = count
        return engine._captured(types.SimpleNamespace(number=str(number)))

    def test_the_second_pass_starts_on_the_first_request_and_reads_forward(self) -> None:
        from pcapkit.utilities.warnings import PySharkWarning

        engine = self.engine(child(ek(2, 5, 9)))
        engine._octets_command.assert_not_called()
        with mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
            self.assertEqual(self.ask(engine, 2), (1, b'\x02'))
            process = engine._exraw
            self.assertEqual(self.ask(engine, 2), (1, b'\x02'))  # the frame read last is kept
            self.assertEqual(self.ask(engine, 5), (1, b'\x05'))
            self.assertEqual(self.ask(engine, 9), (1, b'\x09'))
            warn.assert_not_called()
            self.assertIsNone(self.ask(engine, 10))  # past its last frame
            self.assertIsNone(self.ask(engine, 11))
        engine._octets_command.assert_called_once_with()
        self.assertEqual(warn.call_count, 1)
        message, category = warn.call_args.args
        self.assertIs(category, PySharkWarning)
        self.assertIn('Frame 7: the second tshark pass', message)
        self.assertIn('ended before frame 10', message)
        self.assertIsNotNone(process.returncode)  # reaped
        self.assertIsNone(engine._exraw)

    def test_a_failing_second_pass_falls_back_with_a_warning(self) -> None:
        from pcapkit.utilities.warnings import PySharkWarning

        missing = json.dumps({'layers': {'frame': {'frame_frame_number': '4'}}}) + '\n'
        for name, command, number, reason in (
            ('exits with an error', child(error='tshark: "ip.proto ==" is not a valid filter\n', status=4),
             4, 'exited with status 4 (tshark: "ip.proto ==" is not a valid filter)'),
            ('exits with an error and nothing said', child(status=2), 4, 'exited with status 2'),
            ('writes what is not json', child('not json\n'), 4, "gave output it cannot parse: b'not json\\n'"),
            ('writes no octets', child(missing), 4, 'gave output it cannot parse'),
            ('lacks the frame', child(ek(2, 5)), 4, 'has no frame 4'),
            ('cannot be started', ['/nonexistent/tshark'], 4, 'failed: FileNotFoundError'),
        ):
            with self.subTest(case=name), mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
                engine = self.engine(command)
                self.assertIsNone(self.ask(engine, number))
                self.assertEqual(warn.call_count, 1)
                message, category = warn.call_args.args
                self.assertIs(category, PySharkWarning)
                self.assertIn(reason, message)
                self.assertIn('later such frames are traced as tshark dissects them', message)
                self.assertIsNone(engine._exraw)
                self.assertIsNone(engine._exraw_err)
                # nothing more is asked of it, and nothing more is said
                self.assertIsNone(self.ask(engine, number + 1))
                self.assertEqual(warn.call_count, 1)
                self.assertEqual(engine._octets_command.call_count, 1)

        with mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
            engine = self.engine([])
            engine._octets_command.side_effect = LookupError('no tshark')
            self.assertIsNone(self.ask(engine, 1))
        self.assertIn('failed: LookupError: no tshark', warn.call_args.args[0])

    def test_close_reaps_the_second_pass(self) -> None:
        engine = self.engine(child(ek(1), linger=True))
        self.assertEqual(self.ask(engine, 1), (1, b'\x01'))
        process = engine._exraw
        self.assertIsNone(process.poll())
        engine.close()
        engine._extmp.close.assert_called_once_with()
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)
        self.assertIsNone(engine._exraw)
        engine.close()  # and again

        # the second pass is reaped even if the first will not close
        engine = self.engine(child(ek(1), linger=True))
        self.ask(engine, 1)
        process = engine._exraw
        engine._extmp.close.side_effect = OSError('first pass')
        with self.assertRaises(OSError):
            engine.close()
        self.assertIsNotNone(process.returncode)

    def test_the_link_type_is_read_from_the_capture_file_by_count(self) -> None:
        # by the engine's count, as the default engine numbers frames, where
        # the second pass is read by tshark's frame number
        capture = self.capture(section([1, 12], [(6, 1, b'a'), (9, 0, b'x'), (3, 0, b'b'), (6, 1, b'c')])
                               + section([101], [(2, 0, b'd')], 'big'), 'pcapng')
        engine = self.engine(child(ek(2, 4, 5, 6)), capture)
        with mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
            self.assertEqual(self.ask(engine, 2, count=1), (12, b'\x02'))
            self.assertEqual(self.ask(engine, 2, count=1), (12, b'\x02'))  # the packet read last is kept
            self.assertEqual(self.ask(engine, 4, count=2), (1, b'\x04'))
            self.assertEqual(self.ask(engine, 6, count=4), (101, b'\x06'))
        warn.assert_not_called()

    def test_a_capture_file_that_cannot_be_read_falls_back_with_a_warning(self) -> None:
        from pcapkit.utilities.warnings import PySharkWarning

        for name, data, count, reason in (
            ('lacks the packet', section([1], [(6, 0, b'a')]), 2, 'has no packet 2'),
            ('names no interface', section([1], [(6, 1, b'a')]), 1,
             'failed: FormatError: PCAP-NG: [Block 6] invalid interface ID: 1'),
            ('cannot be opened', None, 1, 'failed: FileNotFoundError'),
        ):
            with self.subTest(case=name), mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
                capture = os.path.join(tempfile.gettempdir(), 'no-such-dir-1625', 'x.pcapng')
                engine = self.engine(child(ek(1, 2)), capture if data is None else self.capture(data, 'pcapng'))
                self.assertIsNone(self.ask(engine, count, count=count))
                self.assertEqual(warn.call_count, 1)
                message, category = warn.call_args.args
                self.assertIs(category, PySharkWarning)
                self.assertIn(f'Frame {count}: the capture file, read for the link type of a frame with an AH '
                              'or IPv6 extension header in IPv4,', message)
                self.assertIn(reason, message)
                self.assertIn('later such frames are traced as tshark dissects them', message)
                self.assertIsNone(engine._exlink)
                # nothing more is asked of either, and nothing more is said
                self.assertIsNone(self.ask(engine, count + 1, count=count + 1))
                self.assertEqual(warn.call_count, 1)
                engine._octets_command.assert_not_called()

        # once it has read the link type, the second pass's failure stops both
        engine = self.engine(child(status=3), self.capture(section([1], [(6, 0, b'a')]), 'pcapng'))
        with mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
            self.assertIsNone(self.ask(engine, 1, count=1))
        self.assertIn('the second tshark pass', warn.call_args.args[0])
        self.assertIsNone(engine._exlink)

    def test_close_closes_the_capture_file(self) -> None:
        engine = self.engine(child(ek(1)), self.capture(section([1], [(6, 0, b'a')]), 'pcapng'))
        self.assertEqual(self.ask(engine, 1, count=1), (1, b'\x01'))
        file = engine._exlink.gi_frame.f_locals['file']
        self.assertFalse(file.closed)
        engine.close()
        self.assertTrue(file.closed)
        self.assertIsNone(engine._exlink)

    def test_linktypes_are_read_as_the_default_engine_reads_them(self) -> None:
        import itertools

        from pcapkit.foundation.engines.pyshark import _linktypes
        from pcapkit.utilities.exceptions import FormatError

        def read(data: bytes, limit: int = 20) -> 'list[int]':
            return list(itertools.islice(_linktypes(self.capture(data)), limit))

        # a PCAP file's, of every frame, whatever its byte order or resolution
        for options in ({}, {'byteorder': 'big'}, {'nanosecond': True}):
            with self.subTest(pcap=options):
                self.assertEqual(read(wire.pcap([], linktype=12, **options), 3), [12, 12, 12])

        # a PCAP-NG packet's interface's, in its own section; other blocks are not packets
        first = section([1, 12], [(6, 1, b'a'), (9, 0, b'x'), (3, 0, b'b'), (4, 0, b'n'), (2, 0, b'c'),
                                  (5, 0, b's')])
        second = section([14, 101, 229], [(2, 2, b'd'), (6, 1, b'e'), (3, 0, b'f')], 'big')
        self.assertEqual(read(first + second), [12, 1, 1, 229, 101, 14])
        self.assertEqual(read(first + second[:-3]), [12, 1, 1, 229, 101])  # a block cut short ends them
        self.assertEqual(read(first + second[:10]), [12, 1, 1])
        self.assertEqual(read(section([1], [])), [])

        for name, data, message in (
            ('an interface the section does not describe', first + section([1], [(6, 1, b'a')]),
             'invalid interface ID: 1'),
            ('the interface of a previous section', first + section([], [(3, 0, b'a')]), 'invalid interface ID: 0'),
            ('an unknown byte order', section([1], [(6, 0, b'a')])[:8] + b'\x00\x00\x00\x00'
             + section([1], [(6, 0, b'a')])[12:], 'block of no known byte order'),
            ('a block shorter than 12 octets', section([1], []) + struct.pack('<II', 6, 8), 'invalid block length: 8'),
        ):
            with self.subTest(case=name), self.assertRaisesRegex(FormatError, message):
                read(data)

    def test_the_command_reads_the_capture_as_the_first_pass_does(self) -> None:
        if importlib.util.find_spec('pyshark') is None:
            self.skipTest('pyshark not installed')
        from pcapkit.foundation.engines.pyshark import PyShark
        from pcapkit.toolkit.pyshark import OCTETS_FILTER

        engine = PyShark.__new__(PyShark)  # skip __init__, which imports pyshark
        engine._extractor = types.SimpleNamespace(_ifnm='in.pcap')
        with mock.patch('pyshark.tshark.tshark.get_process_path', return_value='/bin/tshark'):
            self.assertEqual(engine._octets_command(), [
                '/bin/tshark', '-l', '-n', '-r', 'in.pcap', '-Y', OCTETS_FILTER, '-T', 'ek', '-x', '-J', 'frame',
                '-o', 'ip.defragment:FALSE', '-o', 'ipv6.defragment:FALSE'])

    def test_ek_records_are_parsed(self) -> None:
        from pcapkit.foundation.engines.pyshark import _ek_record

        index, packet = ek(2).splitlines()
        self.assertIsNone(_ek_record(index.encode()))
        self.assertEqual(_ek_record(packet.encode()), (2, b'\x02'))
        listed = json.dumps({'layers': {'frame_raw': ['0a0b', 0, 2], 'frame': {'frame_frame_number': ['3']}}})
        self.assertEqual(_ek_record(listed.encode()), (3, b'\x0a\x0b'))
        for line in (b'[]', b'{}', b'{"index": 1, "x": 2}', b'\xff',
                     b'{"layers": {"frame_raw": "zz", "frame": {"frame_frame_number": "1"}}}',
                     b'{"layers": {"frame_raw": 1, "frame": {"frame_frame_number": "1"}}}',
                     b'{"layers": {"frame_raw": "00", "frame": {"frame_frame_number": "one"}}}'):
            with self.subTest(line=line):
                self.assertIn('gave output it cannot parse', _ek_record(line))

    def test_read_frame_hands_tcp_traceflow_the_captured_frame(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        engine = self.engine([])
        engine._extmp = types.SimpleNamespace(next=lambda: fake_packet(number='1'))
        engine._extractor = types.SimpleNamespace(_frnum=0, _vfunc=lambda e, f: None, _flag_q=True,
                                                  _flag_d=False, _flag_t=True, _tcp=True,
                                                  _trace=types.SimpleNamespace(tcp=mock.Mock()))
        with mock.patch.object(toolkit, 'tcp_traceflow', return_value=None) as traceflow:
            engine.read_frame()
        self.assertEqual(traceflow.call_args.kwargs, {'count': 1, 'captured': engine._captured})


if __name__ == '__main__':
    unittest.main()
