""":mod:`pcapkit.toolkit.pypcapfile` reads the link types, and stops at the frame depth, the default engine does.

GitHub issue #1667: `pypcapfile`_ 0.12.0 decodes Ethernet alone, so the engine
left every frame of the ``NULL``, ``LOOP``, ``RAW``, ``IPV4`` and ``IPV6`` link
types undecoded, and the adapters handed nothing to TCP reassembly, flow tracing
or IPv4 reassembly, where the default engine reads the IP packet in them. They
now read it themselves, and :func:`~pcapkit.toolkit.pypcapfile.packet2dict`
reports an unread frame's octets rather than their hex text.

GitHub issue #1609: the default engine dissects at most
:data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers of a frame, each
VLAN tag, IP header, AH and IPv6 extension header one of them. The adapters'
walks ran past it, and now stop there too.

These use stand-ins for `pypcapfile`_'s IP and TCP decoders, so run without it;
the two engines are compared over real captures in
:mod:`tests.foundation.engines.test_pypcapfile_linktype_and_layer_bound_agreement_1609_1667_unit`.

.. _pypcapfile: https://github.com/kisom/pypcapfile

"""
from __future__ import annotations

import binascii
import ipaddress
import unittest
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit import test_pypcapfile_tcp_last_unit as tcp_last
from tests.toolkit import test_pypcapfile_unit as base

#: ``LINKTYPE_*`` numbers.
NULL, ETHERNET, RAW, LOOP, IPV4, IPV6, LINUX_SLL = 0, 1, 101, 108, 228, 229, 113

#: An IPv4 packet carrying :data:`~tests.toolkit.test_pypcapfile_unit.TCP_SEGMENT`,
#: 47 octets long, and an IPv6 one.
TCP4 = wire.ipv4(base.TCP_SEGMENT, proto=6)
TCP6 = wire.ipv6(base.TCP_SEGMENT, nxt=6)
#: A first IPv4 fragment of a UDP datagram.
FRAGMENT = base.udp_fragment()
#: The addresses :mod:`tests.foundation._roundtrip` gives a packet.
SRC, DST = ipaddress.IPv4Address(wire.IPV4_A), ipaddress.IPv4Address(wire.IPV4_B)


def stand_ins() -> dict:
    """Stand-in :mod:`pcapfile` modules, for :data:`sys.modules`: its IP and its TCP decoder."""
    modules = base.fake_ip_decoder()
    for name, module in tcp_last.fake_pcapfile().items():
        modules.setdefault(name, module)
    return modules


def unread(frame: bytes, linktype: int):
    """A frame of a capture of ``linktype``, as the engine hands one over that `pypcapfile`_ cannot decode."""
    return base.make_packet(binascii.hexlify(frame), linktype=linktype)


def loopback(packet: bytes, family: int, byteorder: str) -> bytes:
    """``packet`` behind a BSD loopback header of address family ``family``."""
    return family.to_bytes(4, byteorder) + packet


def nest4(inner: bytes, count: int, proto: int) -> bytes:
    """``count`` IPv4 headers, the innermost carrying ``inner`` as protocol ``proto``, each outer one IPv4."""
    packet = wire.ipv4(inner, proto=proto)
    for _ in range(count - 1):
        packet = wire.ipv4(packet, proto=4)
    return packet


def nest6(inner: bytes, count: int, nxt: int) -> bytes:
    """``count`` IPv6 headers, the innermost carrying ``inner`` as ``nxt``, each outer one IPv6."""
    packet = wire.ipv6(inner, nxt=nxt)
    for _ in range(count - 1):
        packet = wire.ipv6(packet, nxt=41)
    return packet


def ethernet(packet: bytes):
    """``packet``, an IPv4 packet with no options, behind Ethernet, as `pypcapfile`_ decodes it."""
    return base.make_packet(base.tunnel(packet[20:], packet[9]))


def ethernet6(packet: bytes):
    """``packet``, an IPv6 packet, behind Ethernet, as `pypcapfile`_ leaves it."""
    return base.make_packet(base.ipv6_frame(packet))


def ah_pairs(count: int) -> bytes:
    """``count`` pairs of an IPv4 header and an AH, then the TCP segment."""
    packet = base.TCP_SEGMENT
    for index in range(count):
        packet = wire.ipv4(base.ah(6 if index == 0 else 4) + packet, proto=51)
    return packet


def hbh_pairs(count: int) -> bytes:
    """``count`` pairs of an IPv6 header and a Hop-by-Hop Options header, then the TCP segment."""
    packet = base.TCP_SEGMENT
    for index in range(count):
        packet = wire.ipv6(base.options_header(6 if index == 0 else 41) + packet, nxt=0)
    return packet


def tags(packet: bytes, ethertype: int, count: int, tpid: int):
    """``packet`` behind ``count`` VLAN tags of ``tpid``, as `pypcapfile`_ leaves it."""
    return base.make_packet(base.tagged_frame(packet, ethertype, *(tpid,) * count))


def chain(count: int, last: int) -> bytes:
    """``count`` Destination Options headers, the last naming ``last``."""
    return b''.join(base.options_header(60 if index < count - 1 else last) for index in range(count))


@unittest.skipUnless(base.HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileLinkTypeTests(unittest.TestCase):
    """C.f. #1667."""

    decline = base.PyPCAPFileTCPOverIPv6Tests.decline

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tcp_is_read_over_each_link_type_the_default_engine_dissects(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_reassembly, tcp_traceflow

        tcp4in6 = wire.ipv6(TCP4, nxt=4)
        for label, linktype, frame, read in (
            ('NULL, little-endian', NULL, loopback(TCP4, 2, 'little'), True),
            ('NULL, big-endian', NULL, loopback(TCP4, 2, 'big'), True),
            ('NULL, 4in6 over AF_INET6 28', NULL, loopback(tcp4in6, 28, 'little'), True),
            ('NULL, 4in6 over AF_INET6 30', NULL, loopback(tcp4in6, 30, 'little'), True),
            ('LOOP', LOOP, loopback(TCP4, 2, 'big'), True),
            ('LOOP, 4in6', LOOP, loopback(tcp4in6, 24, 'big'), True),
            ('RAW', RAW, TCP4, True),
            ('RAW, 4in4', RAW, wire.ipv4(TCP4, proto=4), True),
            ('RAW, 4in6', RAW, tcp4in6, True),
            ('RAW, behind AH', RAW, wire.ipv4(base.ah(6) + base.TCP_SEGMENT, proto=51), True),
            ('IPV4', IPV4, TCP4, True),
            ('IPV6, 4in6', IPV6, tcp4in6, True),
            # where the default engine dissects no IP either
            ('LOOP, family written little-endian', LOOP, loopback(TCP4, 2, 'little'), False),
            ('NULL, family 7', NULL, loopback(TCP4, 7, 'little'), False),
            ('NULL, cut short of its header', NULL, b'\x02\x00\x00', False),
            ('RAW, version 5', RAW, b'\x55' + TCP4[1:], False),
            ('RAW, empty', RAW, b'', False),
            ('IPV4, an IPv6 packet', IPV4, TCP6, False),
            ('12', 12, TCP4, False),
            ('LINUX_SLL', LINUX_SLL, TCP4, False),
        ):
            with self.subTest(case=label), mock.patch.dict('sys.modules', stand_ins()):
                packet = unread(frame, linktype)
                data = tcp_reassembly(packet, count=1)
                trace = tcp_traceflow(packet, data_link=LinkType.get(linktype), count=1)
                if not read:
                    self.assertIsNone(data)
                    self.assertIsNone(trace)
                    self.assertEqual(self.decline(packet), [])
                    continue
                self.assertIsNotNone(data)
                self.assertEqual(data.bufid, (SRC, 40000, DST, 9))
                self.assertEqual((data.header, data.payload), (base.TCP_SEGMENT[:20], bytearray(b'payload')))
                self.assertEqual((trace.src, trace.dst, trace.srcport, trace.dstport), (SRC, DST, 40000, 9))
                self.assertEqual(trace.header, base.TCP_SEGMENT[:20])

    def test_ipv4_fragments_are_read_over_each_link_type_the_default_engine_dissects(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        in6 = wire.ipv6(FRAGMENT, nxt=4)
        for label, linktype, frame, read in (
            ('NULL', NULL, loopback(FRAGMENT, 2, 'little'), True),
            ('NULL, 4in6', NULL, loopback(in6, 24, 'little'), True),
            ('LOOP', LOOP, loopback(FRAGMENT, 2, 'big'), True),
            ('LOOP, 4in6', LOOP, loopback(in6, 30, 'big'), True),
            ('RAW', RAW, FRAGMENT, True),
            ('RAW, 4in6', RAW, in6, True),
            ('IPV4', IPV4, FRAGMENT, True),
            ('IPV6, 4in6', IPV6, in6, True),
            ('IPV6, an IPv4 packet', IPV6, FRAGMENT, False),
            ('RAW, cut short of the header', RAW, FRAGMENT[:15], False),
            ('12', 12, FRAGMENT, False),
            ('LINUX_SLL', LINUX_SLL, FRAGMENT, False),
        ):
            with self.subTest(case=label), mock.patch.dict('sys.modules', stand_ins()):
                data = ipv4_reassembly(unread(frame, linktype), count=3)
                if not read:
                    self.assertIsNone(data)
                    continue
                self.assertIsNotNone(data)
                self.assertEqual(data.bufid, (SRC, DST, 0x1234, TransType.UDP))
                self.assertEqual((data.num, data.fo, data.mf, data.tl), (3, 0, True, len(FRAGMENT)))
                self.assertEqual((data.header, data.payload), (FRAGMENT[:20], bytearray(FRAGMENT[20:])))

    def test_tcp_over_ipv6_is_left_out_with_a_warning_over_each_link_type(self) -> None:
        for label, linktype, frame in (
            ('NULL, AF_INET6 24', NULL, loopback(TCP6, 24, 'little')),
            ('NULL, AF_INET6 28', NULL, loopback(TCP6, 28, 'little')),
            ('NULL, AF_INET6 30, big-endian', NULL, loopback(TCP6, 30, 'big')),
            ('LOOP', LOOP, loopback(TCP6, 24, 'big')),
            ('RAW', RAW, TCP6),
            ('RAW, 6in4', RAW, wire.ipv4(TCP6, proto=41)),
            ('IPV6', IPV6, TCP6),
        ):
            with self.subTest(case=label), mock.patch.dict('sys.modules', stand_ins()):
                messages = self.decline(unread(frame, linktype))
                self.assertEqual(len(messages), 1, messages)
                self.assertTrue(messages[0].startswith('Frame 1: TCP over IPv6 is left out'), messages)

    def test_packet2dict_reports_an_unread_frames_octets(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import packet2dict

        self.assertEqual(len(TCP4), 47)
        for linktype in (RAW, LINUX_SLL, ETHERNET):
            with self.subTest(linktype=linktype):
                link = LinkType.get(linktype)
                info = packet2dict(unread(TCP4, linktype), data_link=link)
                self.assertEqual(info[link.name], {'raw_len': 47, 'raw': TCP4})


@unittest.skipUnless(base.HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileFrameLayerBoundTests(unittest.TestCase):
    """C.f. #1609."""

    decline = base.PyPCAPFileTCPOverIPv6Tests.decline

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tcp_is_read_only_within_the_frame_layer_bound(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_reassembly, tcp_traceflow

        # each with the layer the TCP header is at, Ethernet or the loopback
        # header being the first
        cases = [
            ('in 62 IPv4', 64, ethernet(nest4(base.TCP_SEGMENT, 62, 6))),
            ('in 63 IPv4', 65, ethernet(nest4(base.TCP_SEGMENT, 63, 6))),
            ('in 100 IPv4', 102, ethernet(nest4(base.TCP_SEGMENT, 100, 6))),
            ('behind 31 (IPv4, AH) pairs', 64, ethernet(ah_pairs(31))),
            ('behind 32 (IPv4, AH) pairs', 66, ethernet(ah_pairs(32))),
            ('4in6 in 61 IPv6', 64, ethernet6(nest6(TCP4, 61, 4))),
            ('4in6 in 62 IPv6', 65, ethernet6(nest6(TCP4, 62, 4))),
            ('in 31 IPv4 behind 31 headers', 64, ethernet(nest4(chain(31, 6) + base.TCP_SEGMENT, 31, 60))),
            ('in 31 IPv4 behind 32 headers', 65, ethernet(nest4(chain(32, 6) + base.TCP_SEGMENT, 31, 60))),
            ('in 40 IPv4 behind 23 headers', 65, ethernet(nest4(chain(23, 6) + base.TCP_SEGMENT, 40, 60))),
            ('RAW, in 63 IPv4', 64, unread(nest4(base.TCP_SEGMENT, 63, 6), RAW)),
            ('RAW, in 64 IPv4', 65, unread(nest4(base.TCP_SEGMENT, 64, 6), RAW)),
            ('NULL, in 62 IPv4', 64, unread(loopback(nest4(base.TCP_SEGMENT, 62, 6), 2, 'little'), NULL)),
            ('NULL, in 63 IPv4', 65, unread(loopback(nest4(base.TCP_SEGMENT, 63, 6), 2, 'little'), NULL)),
            ('IPV6, 4in6 in 62 IPv6', 64, unread(nest6(TCP4, 62, 4), IPV6)),
            ('IPV6, 4in6 in 63 IPv6', 65, unread(nest6(TCP4, 63, 4), IPV6)),
        ]
        for count, tpid in ((61, base.C_TAG), (62, base.C_TAG), (61, base.S_TAG), (62, base.S_TAG),
                            (63, base.C_TAG)):
            cases.append((f'behind {count} tags of {tpid:#06x}', count + 3, tags(TCP4, 0x0800, count, tpid)))
        for label, layer, packet in cases:
            with self.subTest(case=label), mock.patch.dict('sys.modules', stand_ins()):
                data = tcp_reassembly(packet, count=1)
                trace = tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=1)
                if layer > 64:
                    self.assertIsNone(data)
                    self.assertIsNone(trace)
                    self.assertEqual(self.decline(packet), [])
                    continue
                self.assertIsNotNone(data)
                self.assertIsNotNone(trace)
                self.assertEqual(data.header, base.TCP_SEGMENT[:20])

    def test_ipv4_fragments_are_read_only_within_the_frame_layer_bound(self) -> None:
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        # each with the layer the IPv4 header is at
        cases = [
            ('in 62 IPv6', 64, ethernet6(nest6(FRAGMENT, 62, 4))),
            ('in 63 IPv6', 65, ethernet6(nest6(FRAGMENT, 63, 4))),
            ('RAW, in 63 IPv6', 64, unread(nest6(FRAGMENT, 63, 4), RAW)),
            ('RAW, in 64 IPv6', 65, unread(nest6(FRAGMENT, 64, 4), RAW)),
            ('LOOP, in 62 IPv6', 64, unread(loopback(nest6(FRAGMENT, 62, 4), 24, 'big'), LOOP)),
            ('LOOP, in 63 IPv6', 65, unread(loopback(nest6(FRAGMENT, 63, 4), 24, 'big'), LOOP)),
            ('in 61 IPv6 behind a header', 64, ethernet6(nest6(chain(1, 4) + FRAGMENT, 61, 60))),
            ('in 61 IPv6 behind 2 headers', 65, ethernet6(nest6(chain(2, 4) + FRAGMENT, 61, 60))),
        ]
        for count, tpid in ((62, base.C_TAG), (63, base.C_TAG), (62, base.S_TAG), (63, base.S_TAG)):
            cases.append((f'behind {count} tags of {tpid:#06x}', count + 2, tags(FRAGMENT, 0x0800, count, tpid)))
        for label, layer, packet in cases:
            with self.subTest(case=label), mock.patch.dict('sys.modules', stand_ins()):
                data = ipv4_reassembly(packet, count=1)
                if layer > 64:
                    self.assertIsNone(data)
                else:
                    self.assertIsNotNone(data)
                    self.assertEqual(data.header, FRAGMENT[:20])

    def test_tcp_over_ipv6_warns_only_within_the_frame_layer_bound(self) -> None:
        # The default engine finds no TCP past the bound, so none is left out there.
        cases = [
            ('behind 31 (IPv6, Hop-by-Hop) pairs', 64, ethernet6(hbh_pairs(31))),
            ('behind 32 (IPv6, Hop-by-Hop) pairs', 66, ethernet6(hbh_pairs(32))),
            ('behind 61 tags', 64, tags(TCP6, 0x86DD, 61, base.C_TAG)),
            ('behind 62 tags', 65, tags(TCP6, 0x86DD, 62, base.C_TAG)),
            ('in 40 IPv6 behind 22 headers', 64, ethernet6(nest6(chain(22, 6) + base.TCP_SEGMENT, 40, 60))),
            ('in 40 IPv6 behind 23 headers', 65, ethernet6(nest6(chain(23, 6) + base.TCP_SEGMENT, 40, 60))),
            ('6in4 in 61 IPv4', 64, ethernet(nest4(TCP6, 61, 41))),
            ('6in4 in 62 IPv4', 65, ethernet(nest4(TCP6, 62, 41))),
            ('RAW, behind 31 (IPv6, Hop-by-Hop) pairs', 63, unread(hbh_pairs(31), RAW)),
            ('RAW, in 63 IPv6', 64, unread(nest6(base.TCP_SEGMENT, 63, 6), RAW)),
            ('RAW, in 64 IPv6', 65, unread(nest6(base.TCP_SEGMENT, 64, 6), RAW)),
        ]
        for label, layer, packet in cases:
            with self.subTest(case=label), mock.patch.dict('sys.modules', stand_ins()):
                messages = self.decline(packet)
                self.assertEqual(len(messages), int(layer <= 64), messages)

    def test_the_walks_read_nothing_past_the_bound(self) -> None:
        from pcapkit.toolkit import pypcapfile

        with self.subTest(case='1000 VLAN tags'):
            self.assertIsNone(pypcapfile._untag(tags(TCP4, 0x0800, 1000, base.C_TAG).packet))
            self.assertEqual(pypcapfile._untag(tags(TCP4, 0x0800, 62, base.C_TAG).packet)[2], 64)
        with self.subTest(case='a chain past the bound'), mock.patch.dict('sys.modules', stand_ins()):
            # the innermost IPv4 header is at layer 41, so 23 headers fit behind it
            packet = ethernet(nest4(chain(32, 6) + base.TCP_SEGMENT, 40, 60))
            with mock.patch.object(pypcapfile, '_default_extension_header',
                                   wraps=pypcapfile._default_extension_header) as parse:
                self.assertIsNone(pypcapfile.tcp_reassembly(packet, count=1))
            # no header past the bound is asked of the default engine's parser
            self.assertEqual(len({call.args for call in parse.call_args_list}), 23)
        with self.subTest(case='the helpers other toolkits import'):
            # They read a header as the first layer of its frame, as before;
            # the same header deeper in a frame is read past the bound.
            inner = wire.ipv4(chain(32, 6) + base.TCP_SEGMENT, proto=60)
            self.assertEqual(pypcapfile._upper_layer(4, inner), (6, base.TCP_SEGMENT))
            self.assertEqual(pypcapfile._past_extension_headers(60, inner[20:]), (6, base.TCP_SEGMENT))
            self.assertEqual(pypcapfile._walk_upper_layer(4, inner, 1), (6, base.TCP_SEGMENT, 34))
            self.assertIsNone(pypcapfile._walk_upper_layer(4, inner, 41))
            self.assertIsNone(pypcapfile._walk_ipv4_payload(60, inner[20:], 41))


if __name__ == '__main__':
    unittest.main()
