# -*- coding: utf-8 -*-
"""IPv6 computes a pending upper-layer checksum behind its extension headers.

GitHub issue #2824: an upper layer whose ``make()`` left its checksum pending is
computed by the enclosing IPv6 layer when it sits past extension headers, as well
as when it follows the fixed header. The pseudo-header is the one the receiver
derives: the address of a Home Address option as the source (RFC 6275 sections
6.1.1 and 11.3.1), and the final destination of a Routing header with segments
left (RFC 8200 section 8.1). A fragment's checksum covers the reassembled packet,
so only an atomic fragment's is computed, and a refusal leaves it pending, quietly.

Each expected checksum is summed here over a pseudo-header built by hand; the
Mobility Header ones are the hand-written messages of #2813, which agree with
scapy's.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import sys
import threading
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.utilities._harness import capture

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

HAS_SCAPY = importlib.util.find_spec('scapy') is not None

V6_SRC, V6_DST = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')
#: The home address of a Home Address option, which the pseudo-header takes as the source.
HOME = ipaddress.ip_address('2001:db8:a::1')
#: The last address of a Routing header, which the pseudo-header takes as the destination.
FINAL = ipaddress.ip_address('2001:db8::99')

#: A Binding Refresh Request, Payload Proto 59, from V6_SRC to V6_DST (#2813).
MH_BRR = bytes.fromhex('3b00000068fb0000')
#: The same message sent with a Home Address option: the checksum covers HOME (#2813).
MH_BRR_HOME = bytes.fromhex('3b00000068f10000')


def pseudo6(src: object, dst: object, length: int, nxt: int) -> bytes:
    """An IPv6 pseudo-header (RFC 8200 section 8.1)."""
    return src.packed + dst.packed + length.to_bytes(4, 'big') + bytes([0, 0, 0, nxt])


def expected(pseudo: bytes, upper: bytes, at: int) -> bytes:
    """The checksum ``upper`` should carry at ``at`` over ``pseudo``."""
    return wire.checksum(pseudo + upper[:at] + b'\x00\x00' + upper[at + 2:]).to_bytes(2, 'big')


class PendingChecksumTestCase(unittest.TestCase):
    """Imports and helpers the tests share."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.const.mh.packet import Packet as MHPacket
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.ipv6_frag.protocol import IPv6_Frag
        from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts
        from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.protocols.transport.udp.protocol import UDP
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        self.Option, self.Routing, self.MHPacket, self.Status = Option, Routing, MHPacket, ChecksumStatus
        self.HOPOPT, self.IPv6, self.IPv6_Frag = HOPOPT, IPv6, IPv6_Frag
        self.IPv6_Opts, self.IPv6_Route, self.MH, self.TCP, self.UDP = IPv6_Opts, IPv6_Route, MH, TCP, UDP
        self.config, self.ProtocolWarning = config, ProtocolWarning

    def ipv6(self, nxt: int, payload: object, **kwargs: object) -> bytes:
        """The octets of an IPv6 packet from V6_SRC to V6_DST carrying ``payload``."""
        return self.IPv6.build(src=V6_SRC, dst=V6_DST, next=nxt, payload=payload, **kwargs).data

    def brr(self, **kwargs: object) -> object:
        """A Binding Refresh Request, Payload Proto 59."""
        return self.MH.build(next=59, type=self.MHPacket.Binding_Refresh_Request, **kwargs)

    def home(self, nxt: int, payload: object) -> object:
        """A Destination Options header carrying a Home Address option of HOME."""
        return self.IPv6_Opts.build(next=nxt, options=[(self.Option.Home_Address, {'addr': HOME})], payload=payload)

    def segment(self, **kwargs: object) -> object:
        """A TCP segment carrying a few octets."""
        return self.TCP.build(srcport=40000, dstport=80, payload=b'pending', **kwargs)

    def parse(self, octets: bytes) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as IPv6, verified, and its ProtocolWarnings as ``(category, message)``."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = self.IPv6(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def assertVerifies(self, octets: bytes, name: str) -> None:
        """``octets`` verify as VALID with no warning, and rebuild byte for byte."""
        ip, messages = self.parse(octets)
        layer = ip.extension_headers.getlist(135)[0] if name == 'MH' else ip[name]
        self.assertEqual((layer.info.checksum_status, messages), (self.Status.VALID, []))
        for info in (ip.info, ip.info.to_dict()):
            self.assertEqual(self.IPv6.from_data(info).data, octets)


class ComputedTests(PendingChecksumTestCase):
    """The checksum computed past extension headers, over the receiver's pseudo-header."""

    def test_a_mobility_header_behind_destination_options(self) -> None:
        # The issue's own case: left zero, it parsed as INVALID.
        made = self.ipv6(60, self.IPv6_Opts.build(next=135, payload=self.brr()))
        self.assertEqual(made[48:], MH_BRR)
        self.assertVerifies(made, 'MH')

    def test_a_home_address_option_is_the_source(self) -> None:
        made = self.ipv6(60, self.home(135, self.brr()))
        self.assertEqual(made[-8:], MH_BRR_HOME)
        self.assertVerifies(made, 'MH')

        # RFC 6275 section 11.3.1: every upper layer takes the home address.
        made = self.ipv6(60, self.home(6, self.segment()))
        tcp = made[40 + 24:]
        self.assertEqual(tcp[16:18], expected(pseudo6(HOME, V6_DST, len(tcp), 6), tcp, 16))
        self.assertVerifies(made, 'TCP')

    def test_a_routing_header_names_the_final_destination(self) -> None:
        route = self.IPv6_Route.build(next=6, type=self.Routing.Source_Route, seg_left=1, data={'ip': [FINAL]},
                                      payload=self.segment())
        made = self.ipv6(43, route)
        tcp = made[40 + 24:]
        self.assertEqual(tcp[16:18], expected(pseudo6(V6_SRC, FINAL, len(tcp), 6), tcp, 16))
        self.assertVerifies(made, 'TCP')

        # With no segment left, the destination is the header's own.
        route = self.IPv6_Route.build(next=6, type=self.Routing.Source_Route, seg_left=0, data={'ip': [FINAL]},
                                      payload=self.segment())
        tcp = self.ipv6(43, route)[40 + 24:]
        self.assertEqual(tcp[16:18], expected(pseudo6(V6_SRC, V6_DST, len(tcp), 6), tcp, 16))

        # A type 2 Routing header carries the home address a binding reaches (RFC 6275 section 6.4).
        route = self.IPv6_Route.build(next=135, type=self.Routing.Type_2_Routing_Header, seg_left=1,
                                      data={'ip': HOME}, payload=self.brr())
        made = self.ipv6(43, route)
        mh = made[40 + 24:]
        self.assertEqual(mh[4:6], expected(pseudo6(V6_SRC, HOME, 8, 135), mh, 4))
        self.assertVerifies(made, 'MH')

    def test_through_a_chain_of_headers(self) -> None:
        # In RFC 6275 section 6.3's order: the Home Address option past the Routing header, ahead of AH.
        from pcapkit.protocols.internet.ah.protocol import AH

        udp = self.UDP.build(srcport=40000, dstport=40001, payload=b'chained')
        chain = self.HOPOPT.build(next=43, payload=self.IPv6_Route.build(
            next=60, type=self.Routing.Source_Route, seg_left=1, data={'ip': [FINAL]},
            payload=self.home(51, AH.build(next=17, spi=0x1234, seq=1, icv=bytes(12), payload=udp))))
        made = self.ipv6(0, chain)
        datagram = made[40 + 8 + 24 + 24 + 24:]
        self.assertEqual(datagram[6:8], expected(pseudo6(HOME, FINAL, len(datagram), 17), datagram, 6))
        self.assertVerifies(made, 'UDP')

    def test_a_listener_report_behind_a_router_alert(self) -> None:
        # RFC 2710 section 3: MLD is sent with a Hop-by-Hop Router Alert option.
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        group = ipaddress.ip_address('ff02::1:3')
        report = ICMPv6.build(type=Type.Multicast_Listener_Report, body=bytes(4) + group.packed)
        made = self.ipv6(0, self.HOPOPT.build(next=58, options=[(self.Option.Router_Alert, {})], payload=report))
        message = made[48:]
        self.assertEqual(message[2:4], expected(pseudo6(V6_SRC, V6_DST, len(message), 58), message, 2))
        self.assertVerifies(made, 'ICMPv6')

    def test_an_atomic_fragment_is_whole(self) -> None:
        made = self.ipv6(44, self.IPv6_Frag.build(next=6, payload=self.segment()))
        tcp = made[48:]
        self.assertEqual(tcp[16:18], expected(pseudo6(V6_SRC, V6_DST, len(tcp), 6), tcp, 16))
        self.assertVerifies(made, 'TCP')

    def test_a_jumbogram(self) -> None:
        # RFC 2675: the Payload Length is zero and the pseudo-header's length is 32 bits wide.
        tcp = self.TCP.build(srcport=40000, dstport=80, payload=bytes(70000))
        hbh = self.HOPOPT.build(next=6, options=[(self.Option.Jumbo_Payload, {'len': 8 + len(tcp.data)})],
                                payload=tcp)
        made = self.ipv6(0, hbh)
        segment = made[48:]
        self.assertEqual(made[4:6], b'\x00\x00')
        self.assertEqual(segment[16:18], expected(pseudo6(V6_SRC, V6_DST, len(segment), 6), segment, 16))
        self.assertVerifies(made, 'TCP')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.inet import TCP as ScapyTCP
        from scapy.layers.inet6 import HAO, MIP6MH_BRR
        from scapy.layers.inet6 import IPv6 as ScapyIPv6
        from scapy.layers.inet6 import IPv6ExtHdrDestOpt, IPv6ExtHdrRouting

        ip = ScapyIPv6(src=str(V6_SRC), dst=str(V6_DST))
        route = self.IPv6_Route.build(next=6, type=self.Routing.Source_Route, seg_left=1, data={'ip': [FINAL]},
                                      payload=self.TCP.build(srcport=1, dstport=2, window=0, payload=b'hi'))
        self.assertEqual(self.ipv6(43, route), bytes(ip / IPv6ExtHdrRouting(addresses=[str(FINAL)], segleft=1)
                                                     / ScapyTCP(sport=1, dport=2, flags=0, window=0) / b'hi'))
        # scapy aligns the option at 8n+6 behind a PadN, so the Mobility Headers alone compare.
        theirs = bytes(ip / IPv6ExtHdrDestOpt(options=[HAO(hoa=str(HOME))]) / MIP6MH_BRR())
        self.assertEqual(self.ipv6(60, self.home(135, self.brr()))[-8:], theirs[-8:])


class LeftPendingTests(PendingChecksumTestCase):
    """What is written as given: an explicit checksum, and one no pseudo-header covers."""

    def test_an_explicit_checksum_is_kept(self) -> None:
        made = self.ipv6(60, self.IPv6_Opts.build(next=135, payload=self.brr(checksum=b'\xbe\xef')))
        self.assertEqual(made[52:54], b'\xbe\xef')
        made = self.ipv6(60, self.home(6, self.segment(checksum=b'\xbe\xef')))
        self.assertEqual(made[40 + 24 + 16:40 + 24 + 18], b'\xbe\xef')
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            made = self.ipv6(60, self.IPv6_Opts.build(next=135, payload=self.brr()))
        self.assertEqual(made[52:54], b'\x00\x00')
        # Left out, it is computed.
        self.assertEqual(self.ipv6(60, self.IPv6_Opts.build(next=135, payload=self.brr()))[52:54], MH_BRR[4:6])

    def test_a_fragment_waits_for_reassembly(self) -> None:
        # RFC 8200 section 8.1: the checksum covers the reassembled packet.
        for kwargs in ({'mf': True}, {'offset': 1}):
            with self.subTest(**kwargs):
                frag = self.IPv6_Frag.build(next=6, payload=self.segment(), **kwargs)
                made = self.ipv6(44, frag)
                self.assertEqual(made[40:], frag.data)
        # The atomic fragment beside them is computed.
        self.assertNotEqual(self.ipv6(44, self.IPv6_Frag.build(next=6, payload=self.segment()))[64:66], b'\x00\x00')

    def test_a_layer_the_packet_does_not_reach(self) -> None:
        cases = {
            # The fixed header names the segment, so the header ahead of it is read as TCP.
            'next header': (6, self.HOPOPT.build(next=6, payload=self.segment())),
            # The segment is the Mobility Header's payload, which no pseudo-header names.
            'behind a mobility header': (60, self.IPv6_Opts.build(next=135, payload=self.MH.build(
                next=6, checksum=b'\xbe\xef', payload=self.segment()))),
        }
        for name, (nxt, payload) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.ipv6(nxt, payload)[40:], payload.data)
        # Nor past the headers the walk is limited to (#1604), which the packet parsed back
        # leaves to the IPv6 layer to warn of, once.
        chain = self.HOPOPT.build(next=60, payload=self.IPv6_Opts.build(next=6, payload=self.segment()))
        with mock.patch.object(self.config, 'EXTENSION_HEADER_LIMIT', 1), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertEqual(self.ipv6(0, chain)[40:], chain.data)
        self.assertEqual([item.category for item in caught], [self.ProtocolWarning])
        self.assertNotEqual(self.ipv6(0, chain)[40 + 16 + 16:40 + 16 + 18], b'\x00\x00')


class QuietRefusalTests(PendingChecksumTestCase):
    """A pseudo-header the packet does not give is refused quietly (#2588)."""

    def setUp(self) -> None:
        super().setUp()
        saved = sys.excepthook, threading.excepthook

        def restore() -> None:
            sys.excepthook, threading.excepthook = saved

        self.addCleanup(restore)

        def sentinel(*args: 'object') -> None:
            sys.__excepthook__(*args)  # type: ignore[arg-type]

        def thread_sentinel(args: 'object') -> None:
            pass

        self.sentinels = sentinel, thread_sentinel
        sys.excepthook, threading.excepthook = self.sentinels

    def test_nothing_is_logged_or_hooked(self) -> None:
        from pcapkit.utilities.logging import logger

        cases = {
            # Type 200 is not parsed, so its final destination is unknown.
            'unparsed routing type': (43, self.IPv6_Route.build(next=6, type=200, seg_left=1, payload=self.segment())),
            'first fragment': (44, self.IPv6_Frag.build(next=6, mf=True, payload=self.segment())),
        }
        for name, (nxt, payload) in cases.items():
            with self.subTest(name), capture(logger) as recorder:
                made = self.ipv6(nxt, payload)
                self.assertEqual(made[40:], payload.data)
                self.assertEqual(recorder.messages, [])
                self.assertIs(sys.excepthook, self.sentinels[0])
                self.assertIs(threading.excepthook, self.sentinels[1])
        # A Routing type parsed gives the final destination, so the same header computes.
        route = self.IPv6_Route.build(next=6, type=self.Routing.Source_Route, seg_left=1, data={'ip': [FINAL]},
                                      payload=self.segment())
        self.assertNotEqual(self.ipv6(43, route)[40 + 24 + 16:40 + 24 + 18], b'\x00\x00')


if __name__ == '__main__':
    unittest.main()
