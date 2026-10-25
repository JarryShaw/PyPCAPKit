# -*- coding: utf-8 -*-
"""The default engine hands over nothing past an IPv6 packet RFC 2675 calls an error. C.f. #1687.

:rfc:`2675#section-3` lists four errors a receiver must detect: a Payload Length
of 0 with a Hop-by-Hop Options header and no Jumbo Payload option, a non-zero
Payload Length with the option, a Jumbo Payload Length below 65,536, and the
option with a Fragment header. The default engine's IPv6 parser rejects
each, so it dissects nothing past the IPv6 header: no TCP reassembly or flow
tracing input, and no IP reassembly input from the packet or what it carries. A
jumbogram RFC 2675 accepts is dissected, a capture cut short of its Jumbo
Payload Length included.

Every capture is built here, so the module is in the unit tier.

"""
from __future__ import annotations

import importlib.util
import os
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

#: What each case's counts count, in order.
ASPECTS = ('TCP', 'trace', 'IPv4', 'IPv6')
#: Link types each case is captured on: Ethernet, and IPv6 with no link layer.
LINKTYPES = (1, 229)
#: Octets past the packet, e.g. an Ethernet FCS.
TRAILER = b'\xee' * 4
#: A TCP segment too long for a Payload Length.
BIG = wire.tcp(b'j' * 70000, seq=1, ack=1, sport=1006)
#: Octets of the extension headers :func:`genuine` builds.
GENUINE_HEADERS = 32 * 2048


def tcp(number: int) -> bytes:
    """A TCP segment of 24 octets on a port pair of its own."""
    return wire.tcp(b'data', seq=1, ack=1, sport=1000 + number)


def ipv4(payload: bytes, *, ident: int) -> bytes:
    """A first IPv4 fragment carrying ``payload``."""
    return wire.ipv4(payload, ident=ident, mf=True, proto=253)


def ipv6(payload: bytes, nxt: int, *, plen: 'int | None' = None) -> bytes:
    """An IPv6 packet carrying ``payload``, its Payload Length as given."""
    plen = len(payload) if plen is None else plen
    packet = wire.ipv6(b'', nxt=nxt)
    return packet[:4] + plen.to_bytes(2, 'big') + packet[6:] + payload


def options(nxt: int) -> bytes:
    """An 8-octet Hop-by-Hop Options header, one PadN option in it."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


def fragment(nxt: int, mf: bool) -> bytes:
    """An IPv6 Fragment header at offset 0."""
    return bytes([nxt, 0, 0, int(mf)]) + (7).to_bytes(4, 'big')


def jumbo(nxt: int, length: int) -> bytes:
    """A Hop-by-Hop Options header carrying a Jumbo Payload option."""
    return bytes([nxt, 0, 0xC2, 4]) + length.to_bytes(4, 'big')


def padding(size: int) -> bytes:
    """PadN options filling ``size`` octets, at least 2."""
    out = b''
    while size:
        data = min(size - 2, 255)
        if size - data - 2 == 1:  # one octet left over holds no PadN
            data -= 1
        out, size = out + bytes([1, data]) + bytes(data), size - data - 2
    return out


def genuine(nxt: int, length: int) -> bytes:
    """The extension headers of a jumbogram RFC 2675 accepts, its Jumbo Payload Length ``length`` past them.

    A Hop-by-Hop Options header carrying the Jumbo Payload option, then 31
    Destination Options headers, the last naming ``nxt``: 2,048 octets each, so
    :data:`GENUINE_HEADERS` (65,536) in all, within the default engine's 32
    (#1604), and the Jumbo Payload Length is above 65,535 however short
    ``length`` is.

    """
    head = bytes([60, 255, 0xC2, 4]) + (GENUINE_HEADERS + length).to_bytes(4, 'big') + padding(2040)
    return head + b''.join(bytes([nxt if index == 30 else 60, 255]) + padding(2046) for index in range(31))


def cases() -> 'dict[str, tuple[tuple[int, ...], bytes, bytes]]':
    """IPv6 packets by case: the default engine's input counts, the packet, and the octets captured after it."""
    first4 = ipv4(b'A' * 16, ident=5)
    return {
        # the errors, one per row of RFC 2675 section 3
        'Payload Length 0, a Hop-by-Hop Options header, no Jumbo Payload option': (
            (0, 0, 0, 0), ipv6(options(6) + tcp(1), 0, plen=0), b''),
        'Payload Length 32, Jumbo Payload Length 70000': ((0, 0, 0, 0), ipv6(jumbo(6, 70000) + tcp(2), 0), b''),
        'Jumbo Payload Length 32': ((0, 0, 0, 0), ipv6(jumbo(6, 8 + 24) + tcp(3), 0, plen=0), TRAILER),
        'Jumbo Payload Length 65535': (
            (0, 0, 0, 0), ipv6(jumbo(6, 65535) + tcp(4) + bytes(65535 - 8 - 24), 0, plen=0), b''),
        'Jumbo Payload Length 44, 4in6': ((0, 0, 0, 0), ipv6(jumbo(4, 8 + 36) + first4, 0, plen=0), b''),
        'Fragment header, TCP': (
            (0, 0, 0, 0), ipv6(jumbo(44, 8 + 8 + len(BIG)) + fragment(6, False) + BIG, 0, plen=0), b''),
        'Fragment header, a first fragment': (
            (0, 0, 0, 0), ipv6(jumbo(44, 8 + 8 + 70000) + fragment(253, True) + b'A' * 70000, 0, plen=0), b''),
        # jumbograms RFC 2675 accepts
        'jumbogram, TCP (control)': ((1, 1, 0, 0), ipv6(genuine(6, 24) + tcp(7), 0, plen=0), b''),
        'jumbogram, TCP, a trailer (control)': ((1, 1, 0, 0), ipv6(genuine(6, 24) + tcp(8), 0, plen=0), TRAILER),
        'jumbogram, Jumbo Payload Length 2 short of TCP (control)': (
            (1, 1, 0, 0), ipv6(genuine(6, 22) + tcp(9), 0, plen=0), b''),
        'jumbogram, 4in6 cut inside the IPv4 payload (control)': (
            (0, 0, 1, 0), ipv6(genuine(4, 30) + ipv4(b'A' * 16, ident=10), 0, plen=0), b''),
        'Jumbo Payload Length 65536 (control)': (
            (1, 1, 0, 0), ipv6(jumbo(6, 65536) + tcp(11) + bytes(65536 - 8 - 24), 0, plen=0), b''),
        'jumbogram cut short by the capture (control)': ((1, 1, 0, 0), ipv6(jumbo(6, 70000) + tcp(12), 0, plen=0),
                                                         b''),
    }


def frames(linktype: int) -> 'tuple[list[bytes], dict[str, int]]':
    """Each case's frame of ``linktype``, and its frame number."""
    built, numbers = [], {}  # type: list[bytes], dict[str, int]
    for label, (_, packet, trailer) in cases().items():
        built.append((wire.ethernet(packet, 0x86DD) if linktype == 1 else packet) + trailer)
        numbers[label] = len(built)
    return built, numbers


def read(test: unittest.TestCase, linktype: int) -> 'dict[str, set[int]]':
    """Read every case's frame of ``linktype`` with IP and TCP reassembly and TCP flow tracing.

    Returns:
        The frame numbers of every input the default engine hands IPv4, IPv6
        and TCP reassembly and TCP flow tracing.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.ipv4 import IPv4
    from pcapkit.foundation.reassembly.ipv6 import IPv6
    from pcapkit.foundation.reassembly.tcp import TCP
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    seen = {'IPv4': set(), 'IPv6': set(), 'TCP': set(), 'trace': set()}  # type: dict[str, set[int]]
    calls = {klass: klass.__call__ for klass in (IPv4, IPv6, TCP)}
    trace = TraceFlowBase.__call__

    def spy(klass: 'Any') -> 'Any':
        def call(this: 'Any', packet: 'Any') -> 'Any':
            seen[klass.__name__].add(packet.num)
            return calls[klass](this, packet)
        return call

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'].add(packet.index)
        return trace(this, packet)

    capture = wire.pcap([(1, number, octets) for number, octets in enumerate(frames(linktype)[0])],
                        linktype=linktype)
    capture = capture[:16] + (262144).to_bytes(4, 'little') + capture[20:]  # a snapshot length jumbograms fit
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(IPv4, '__call__', spy(IPv4)), mock.patch.object(IPv6, '__call__', spy(IPv6)), \
            mock.patch.object(TCP, '__call__', spy(TCP)), mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        path = os.path.join(tmp, 'jumbo.pcap')
        with open(path, 'wb') as file:
            file.write(capture)
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine='default', reassembly=True, ipv4=True, ipv6=True,
                            tcp=True, trace=True, trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
        try:
            test.assertEqual(extractor._exnam, 'default')  # pylint: disable=protected-access
        finally:
            close_extractor(extractor)
    return seen


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DefaultEngineJumbogramTests(unittest.TestCase):
    """The default engine's inputs stop at an RFC 2675 error, and not at a jumbogram it accepts."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_nothing_past_an_rfc_2675_error_is_an_input(self) -> None:
        for linktype in LINKTYPES:
            seen = read(self, linktype)
            _, numbers = frames(linktype)
            for label, (expected, _, _) in cases().items():
                with self.subTest(linktype=linktype, case=label):
                    self.assertEqual(tuple(int(numbers[label] in seen[aspect]) for aspect in ASPECTS), expected)


if __name__ == '__main__':
    unittest.main()
