# -*- coding: utf-8 -*-
"""The dpkt and scapy engines reject the IPv4 headers the default engine rejects. C.f. #1607.

The default engine's IPv4 parser rejects a header whose version is not 4, whose
IHL is below 5 or runs past the captured octets, or whose options it rejects,
and then dissects nothing past it: no IPv4 reassembly input, and no TCP behind
it. `dpkt`_ and `Scapy`_ decode such a header as IPv4 all the same, so their
engines handed on both. They now ask the default engine's own parser, as the
pypcapfile engine does (#1596), of every IPv4 header on the way to the TCP
segment, a tunnel's included (#1581). Neither engine checks the header checksum,
and nor does the default engine, so a bad one is still read.

Every capture is built here, so the module is in the unit tier.

.. _dpkt: https://dpkt.readthedocs.io
.. _Scapy: https://scapy.net

"""
from __future__ import annotations

import importlib.util
import io
import ipaddress
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit.test_tunnelled_tcp_flow_key_1581_unit import INNER, OUTER, has
from tests.toolkit.test_tunnelled_tcp_flow_key_1581_unit import ip as tunnel_ip

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: IPv4 options the default engine rejects, each one word: a Timestamp of length
#: 2, a Loose Source Route with pointer 0, a Record Route of length 1, one whose
#: length runs past the header, and a Router Alert of length 2.
BAD_OPTIONS = {
    'timestamp length 2': b'\x44\x02\x00\x00',
    'lsr pointer 0': b'\x83\x03\x00\x00',
    'record route length 1': b'\x07\x01\x00\x00',
    'record route past the header': b'\x07\x08\x00\x00',
    'router alert length 2': b'\x94\x02\x00\x00',
}

#: IPv4 options it accepts: a Router Alert, four No Operations, and an End of
#: Option List followed by octets it leaves as padding.
GOOD_OPTIONS = {
    'router alert': b'\x94\x04\x00\x00',
    'no operations': b'\x01' * 4,
    'end of option list': b'\x00\xff\xff\xff',
}


def ipv4(payload: bytes, *, version: int = 4, ihl: 'int | None' = None, options: bytes = b'',
         length: 'int | None' = None, checksum: 'int | None' = None, df: bool = False,
         proto: int = 6, src: str = '10.1.1.2', dst: str = '10.1.1.3') -> bytes:
    """An IPv4 packet carrying ``payload``, its version, IHL, Total Length and checksum as given.

    The IHL defaults to the header's length, options included, the Total Length
    to the packet's, and the checksum to the right one.

    """
    if ihl is None:
        ihl = 5 + len(options) // 4
    if length is None:
        length = 20 + len(options) + len(payload)
    header = bytearray(struct.pack('!BBHHHBBHII', (version << 4) | ihl, 0, length, 0x1234,
                                   0x4000 if df else 0, 64, proto, 0,
                                   int(ipaddress.IPv4Address(src)), int(ipaddress.IPv4Address(dst))))
    header += options
    if checksum is None:
        checksum = wire.checksum(bytes(header))
    header[10:12] = checksum.to_bytes(2, 'big')
    return bytes(header) + payload


def ethernet(packet: bytes, *, tagged: bool = False) -> bytes:
    """An Ethernet frame carrying the IPv4 or IPv6 ``packet``, behind an 802.1Q tag or not."""
    ethertype = 0x86DD if packet[0] >> 4 == 6 else 0x0800
    if tagged:
        return wire.ethernet((100).to_bytes(2, 'big') + ethertype.to_bytes(2, 'big') + packet, 0x8100)
    return wire.ethernet(packet, ethertype)


def segment(number: int) -> bytes:
    """A TCP segment carrying ``data``, on a port pair of its own."""
    return wire.tcp(b'data', seq=1, ack=1, sport=1000 + number)


def frames() -> 'tuple[list[bytes], list[int], list[int]]':
    """Frames carrying TCP behind IPv4 headers of every kind, and what the default engine reads.

    Returns:
        The frames; the numbers of those whose every IPv4 header the default
        engine accepts, which it reads TCP from; and the numbers of those whose
        first IPv4 header it accepts, which are IPv4 reassembly inputs.

    """
    def in4(inner: bytes, proto: int = 4, **fields: 'Any') -> bytes:
        return ethernet(ipv4(inner, proto=proto, src=OUTER[4][0], dst=OUTER[4][1], **fields))

    def in6(inner: bytes) -> bytes:
        return ethernet(tunnel_ip(6, inner, *OUTER[6], 4))

    def inner6(seg: bytes) -> bytes:
        return tunnel_ip(6, seg, *INNER[6][0], 6)

    # each case is whether TCP is read, whether there is an IPv4 input, and the frame
    cases = []  # type: list[tuple[bool, bool, Any]]
    for options in BAD_OPTIONS.values():
        cases.append((False, False, lambda seg, o=options: ethernet(ipv4(seg, options=o))))
    for options in GOOD_OPTIONS.values():
        cases.append((True, True, lambda seg, o=options: ethernet(ipv4(seg, options=o))))
    for version in (0, 5, 6, 15):
        cases.append((False, False, lambda seg, v=version: ethernet(ipv4(seg, version=v))))
    cases += [
        (True, True, lambda seg: ethernet(ipv4(seg))),
        # no header checksum is checked, and a Total Length only bounds the payload
        (True, True, lambda seg: ethernet(ipv4(seg, checksum=0xDEAD))),
        (True, True, lambda seg: ethernet(ipv4(seg, length=0))),
        (True, True, lambda seg: ethernet(ipv4(seg, length=1500))),
        # DF, as dpkt cuts the header of its IPv4 input at a Total Length this
        # short, which is no part of #1607
        (False, False, lambda seg: ethernet(ipv4(seg, length=10, df=True))),
        # an IHL below 5, and one past the 44 octets captured
        (False, False, lambda seg: ethernet(ipv4(seg, ihl=4))),
        (False, False, lambda seg: ethernet(ipv4(seg, ihl=15))),
        # behind a VLAN tag
        (False, False, lambda seg: ethernet(ipv4(seg, options=BAD_OPTIONS['timestamp length 2']),
                                            tagged=True)),
        (False, False, lambda seg: ethernet(ipv4(seg, version=5), tagged=True)),
        (True, True, lambda seg: ethernet(ipv4(seg, options=GOOD_OPTIONS['router alert']), tagged=True)),
    ]
    for accepted, fields in (
        (False, {'version': 5}),
        (False, {'options': BAD_OPTIONS['timestamp length 2']}),
        (False, {'options': BAD_OPTIONS['lsr pointer 0']}),
        (False, {'ihl': 4}),
        (True, {'options': GOOD_OPTIONS['router alert']}),
    ):
        cases += [
            # the inner header of 4in4, whose outer one is the IPv4 input
            (accepted, True, lambda seg, f=fields: in4(ipv4(seg, **f))),
            # the inner header of 4in6; DF where it is accepted, as dpkt finds
            # no IPv4 layer in IPv6 for IPv4 reassembly, which is no part of #1607
            (accepted, False, lambda seg, f=fields, df=accepted: in6(ipv4(seg, df=df, **f))),
            # the outer header of 4in4 and 6in4
            (accepted, accepted, lambda seg, f=fields: in4(ipv4(seg), **f)),
            (accepted, accepted, lambda seg, f=fields: in4(inner6(seg), proto=41, **f)),
        ]
    numbered = list(enumerate(cases, start=1))
    return ([make(segment(number)) for number, (_, _, make) in numbered],
            [number for number, (tcp, _, _) in numbered if tcp],
            [number for number, (_, ipv4_input, _) in numbered if ipv4_input])


def read(test: unittest.TestCase, engine: str, frames: 'list[bytes]') -> 'dict[str, Any]':
    """Read ``frames`` with ``engine``, with IPv4 and TCP reassembly and TCP flow tracing.

    Returns:
        Every input the engine hands IPv4 and TCP reassembly and TCP flow tracing,
        keyed by frame number -- every field, but a trace input's ``frame`` --
        the reassembled TCP datagrams' ``id``, and the traced flows' labels and
        frames.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.ipv4 import IPv4
    from pcapkit.foundation.reassembly.tcp import TCP
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    seen = {'ipv4': {}, 'tcp': {}, 'trace': {}}  # type: dict[str, Any]
    reassemble_ipv4, reassemble_tcp, trace = IPv4.__call__, TCP.__call__, TraceFlowBase.__call__

    def fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
        return {key: bytes(value) if isinstance(value, bytearray) else value
                for key, value in packet.items() if key not in skip}

    def spy_ipv4(this: 'Any', packet: 'Any') -> 'Any':
        seen['ipv4'][packet.num] = fields(packet)
        return reassemble_ipv4(this, packet)

    def spy_tcp(this: 'Any', packet: 'Any') -> 'Any':
        seen['tcp'][packet.num] = fields(packet)
        return reassemble_tcp(this, packet)

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = fields(packet, ('frame',))
        return trace(this, packet)

    records = [(1, number, octets) for number, octets in enumerate(frames)]
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(IPv4, '__call__', spy_ipv4), \
            mock.patch.object(TCP, '__call__', spy_tcp), \
            mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        path = os.path.join(tmp, 'headers.pcap')
        with open(path, 'wb') as file:
            file.write(wire.pcap(records))
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, ipv4=True,
                            tcp=True, trace=True, trace_fout=os.path.join(tmp, 'trace'),
                            trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            seen['ids'] = [datagram.id for datagram in extractor.reassembly.tcp]
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
        finally:
            close_extractor(extractor)
    return seen


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DPKTScapyIPv4HeaderCheckTests(unittest.TestCase):
    """dpkt and scapy hand on what the default engine does, whatever the IPv4 header."""

    ENGINES = ('dpkt', 'scapy')

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_rejected_ipv4_headers_agree_with_the_default_engine(self) -> None:
        built, tcp, ipv4_inputs = frames()
        base = read(self, 'default', built)
        # nothing is read behind a rejected header, outer or inner
        self.assertEqual(sorted(base['tcp']), tcp)
        self.assertEqual(sorted(base['trace']), tcp)
        self.assertEqual(len(base['ids']), len(tcp))
        # and a rejected first header is no IPv4 input either
        self.assertEqual(sorted(base['ipv4']), ipv4_inputs)
        for engine in self.ENGINES:
            with self.subTest(engine=engine):
                if not has(engine):
                    self.skipTest(f'{engine} not installed')
                seen = read(self, engine, built)
                for aspect in ('ipv4', 'tcp', 'trace', 'ids', 'flows'):
                    self.assertEqual(seen[aspect], base[aspect], aspect)

    def test_every_version_and_ihl_is_read_as_the_default_engine_reads_it(self) -> None:
        # The shortcut that leaves a header of version 4 and IHL 5 unparsed
        # answers as the parser does: for every first octet, the engines decode
        # an IPv4 layer and accept it exactly when the default engine dissects
        # one, with room for 40 octets of options and with none at all.
        from pcapkit import extract
        from pcapkit.protocols.internet.ipv4 import IPv4

        cases = [(first, rest) for rest in (b'\x01' * 40 + segment(0), b'') for first in range(256)]
        built = [wire.ethernet(bytes([first]) + ipv4(rest)[1:], 0x0800) for first, rest in cases]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(wire.pcap([(1, 0, octets) for octets in built])),
                                nofile=True)
        self.addCleanup(close_extractor, extractor)
        want = [isinstance(frame.payload.payload, IPv4) for frame in extractor.frame]
        self.assertEqual(len(want), len(built))
        self.assertEqual(sum(want), 11 + 1)  # version 4: every IHL from 5 with room, IHL 5 without

        for engine in self.ENGINES:
            with self.subTest(engine=engine):
                if not has(engine):
                    self.skipTest(f'{engine} not installed')
                if engine == 'dpkt':
                    import dpkt

                    from pcapkit.toolkit.dpkt import _ipv4_accepted
                    layers = [getattr(dpkt.ethernet.Ethernet(octets), 'ip', None) for octets in built]
                else:
                    from scapy.layers.inet import IP
                    from scapy.layers.l2 import Ether

                    from pcapkit.toolkit.scapy import _ipv4_accepted  # type: ignore[no-redef]
                    layers = [Ether(octets).getlayer(IP) for octets in built]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    got = [layer is not None and _ipv4_accepted(layer) for layer in layers]
                self.assertEqual([(first, len(rest)) for (first, rest), mine, theirs in zip(cases, got, want)
                                  if mine != theirs], [])

    def test_an_ihl_below_5_warns_of_nothing_the_default_engine_does_not(self) -> None:
        # Scapy dissects such a header; the parser is handed its 20 fixed octets,
        # as the default engine is, rather than the fewer the IHL counts, which
        # it would warn of reading past.
        if not has('scapy'):
            self.skipTest('scapy not installed')
        from scapy.layers.inet import IP
        from scapy.layers.l2 import Ether

        from pcapkit.toolkit import pypcapfile
        from pcapkit.toolkit.scapy import _ipv4_accepted

        for ihl in range(5):
            with self.subTest(ihl=ihl):
                octets = ethernet(ipv4(segment(1), ihl=ihl))
                pypcapfile._default_accepts.cache_clear()
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    accepted = _ipv4_accepted(Ether(octets)[IP])
                self.assertFalse(accepted)
                self.assertEqual([str(warning.message) for warning in caught], [])

    def test_the_parser_is_asked_only_of_a_header_it_could_reject(self) -> None:
        # A plain header is not parsed; one with options is, once between the
        # adapters that read the frame.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pypcapfile

        plain = ethernet(ipv4(segment(1)))
        tunnelled = ethernet(ipv4(ipv4(segment(2)), proto=4))
        with_options = ethernet(ipv4(segment(3), options=GOOD_OPTIONS['router alert']))
        for engine in self.ENGINES:
            with self.subTest(engine=engine):
                if not has(engine):
                    self.skipTest(f'{engine} not installed')
                if engine == 'dpkt':
                    import dpkt

                    from pcapkit.toolkit import dpkt as toolkit

                    def adapt(octets: bytes) -> None:
                        packet = dpkt.ethernet.Ethernet(octets)
                        toolkit.ipv4_reassembly(packet, 1.0)
                        toolkit.tcp_reassembly(packet, 1.0)
                        toolkit.tcp_traceflow(packet, 1.0, data_link=LinkType.ETHERNET)
                else:
                    from scapy.layers.l2 import Ether

                    from pcapkit.toolkit import scapy as toolkit  # type: ignore[no-redef]

                    def adapt(octets: bytes) -> None:
                        packet = Ether(octets)
                        packet.time = 1.0
                        toolkit.ipv4_reassembly(packet)
                        toolkit.tcp_reassembly(packet)
                        toolkit.tcp_traceflow(packet)

                pypcapfile._default_accepts.cache_clear()
                real = pypcapfile.Protocol_IPv4
                with mock.patch.object(pypcapfile, 'Protocol_IPv4', side_effect=real) as parser:
                    adapt(plain)
                    adapt(tunnelled)
                    self.assertEqual(parser.call_count, 0)
                    adapt(with_options)
                    self.assertEqual([call.args[0] for call in parser.call_args_list],
                                     [with_options[14:38]])


if __name__ == '__main__':
    unittest.main()
