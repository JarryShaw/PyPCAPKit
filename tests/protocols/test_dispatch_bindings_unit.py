# -*- coding: utf-8 -*-
"""End-to-end checks on the protocol dispatch tables.

Every fixture here is synthesised in memory, so the module belongs to the unit
tier and reads none of the generated captures under :file:`examples/captures/`.

What it pins is that a *registered* code actually reaches a working dissector.
The tables and the dissectors were previously able to disagree without anything
noticing -- :class:`~pcapkit.protocols.link.ospf.OSPF` was reachable from no
table at all and could not have parsed a packet if it had been -- so each case
asserts on the parsed protocol chain rather than on the table entry alone.

"""
from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

ETH_DST = bytes((0x00, 0x11, 0x22, 0x33, 0x44, 0x55))
ETH_SRC = bytes((0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE))


def tci(pcp: int, dei: int, vid: int) -> bytes:
    """Pack a VLAN tag control information word."""
    return struct.pack('!H', (pcp & 0x7) << 13 | (dei & 0x1) << 12 | (vid & 0xFFF))


def ethernet(ethertype: int, payload: bytes) -> bytes:
    """Wrap ``payload`` in an Ethernet II frame."""
    return ETH_DST + ETH_SRC + struct.pack('!H', ethertype) + payload


def ipv4(proto: int, payload: bytes) -> bytes:
    """Wrap ``payload`` in a minimal option-less IPv4 header."""
    return struct.pack('!BBHHHBBH4s4s',
                       0x45, 0x00, 20 + len(payload), 0x1234, 0x0000,
                       64, proto, 0x0000,
                       bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))) + payload


def tcp(sport: int, dport: int, payload: bytes = b'') -> bytes:
    """Wrap ``payload`` in a minimal 20-octet TCP header."""
    return struct.pack('!HHIIBBHHH', sport, dport, 0, 0,
                       0x50, 0x18, 8192, 0x0000, 0x0000) + payload


def udp(sport: int, dport: int, payload: bytes = b'') -> bytes:
    """Wrap ``payload`` in a UDP header."""
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0x0000) + payload


def ospf_hello() -> bytes:
    """A well-formed OSPFv2 Hello: 24-octet header plus a 20-octet body."""
    body = struct.pack('!4sHBBIII',
                       bytes((255, 255, 255, 0)), 10, 0x02, 1, 40, 0, 0)
    return struct.pack('!BBH4s4s2sH8s',
                       2,                      # version
                       1,                      # type = Hello
                       24 + len(body),         # packet length
                       bytes((10, 0, 0, 1)),   # router id
                       bytes((0, 0, 0, 0)),    # area id
                       b'\xAB\xCD',            # checksum
                       0,                      # autype = none
                       b'\x00' * 8) + body     # authentication


def l2tp_data() -> bytes:
    """An L2TPv2 data message with every optional field absent."""
    # bit0=type, bit1=len, bit4=seq, bit6=offset, bit7=prio, bits12-15=version
    return struct.pack('!HHH', 0x0002, 0x1234, 0x5678) + b'\xff\x03\x00\x21PPP'


def make_pcap(*frames: bytes) -> str:
    """Write ``frames`` to a little-endian LINKTYPE_ETHERNET PCAP file."""
    path = os.path.join(tempfile.mkdtemp(prefix='pcapkit-dispatch-'), 'dispatch.pcap')
    with open(path, 'wb') as file:
        # little endian, v2.4, LINKTYPE_ETHERNET
        file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, frame in enumerate(frames):
            file.write(struct.pack('<IIII', 1600000000 + index, 0,
                                   len(frame), len(frame)))
            file.write(frame)
    return path


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DispatchBindingTests(unittest.TestCase):
    """Each registered code reaches the dissector the table names."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def extract(self, *frames: bytes):
        """Extract synthesised ``frames`` and return the frame list."""
        import pcapkit

        extraction = pcapkit.extract(fin=make_pcap(*frames), nofile=True,
                                     store=True, ip=True, tcp=True,
                                     reassembly=True)
        self.addCleanup(close_extractor, extraction)
        return extraction.frame

    ##########################################################################
    # 802.1ad Q-in-Q.
    ##########################################################################

    def test_stacked_service_and_customer_tags_both_parse_and_stay_distinct(self) -> None:
        """A Q-in-Q frame yields both tags, under their own info names.

        This is the acceptance test for the S-Tag work: before the service tag
        was bound, the whole of ``S-Tag + C-Tag + IPv4 + TCP`` collapsed into a
        single opaque ``Raw`` payload hanging off the Ethernet header.

        """
        from pcapkit.const.reg.ethertype import EtherType

        inner = ipv4(6, tcp(12345, 80, b'hello-qinq'))
        frame = self.extract(ethernet(
            0x88A8,                                        # eth.type -> S-Tag
            tci(pcp=5, dei=1, vid=100) + struct.pack('!H', 0x8100)
            + tci(pcp=3, dei=0, vid=200) + struct.pack('!H', 0x0800)
            + inner,
        ))[0]

        self.assertEqual(str(frame.protochain), 'Ethernet:802.1ad:802.1Q:IPv4:TCP:Raw')

        eth = frame.info.to_dict()['ethernet']
        self.assertEqual(eth['type'],
                         EtherType.IEEE_Std_802_1Q_Service_VLAN_tag_identifier)

        # The service tag is the outer one, and is named as such.
        self.assertIn('s_tag', eth)
        self.assertNotIn('c_tag', eth)
        s_tag = eth['s_tag']
        self.assertEqual(s_tag['tci']['vid'], 100)
        self.assertEqual(int(s_tag['tci']['pcp']), 5)
        self.assertIs(s_tag['tci']['dei'], True)
        self.assertEqual(s_tag['type'], EtherType.Customer_VLAN_Tag_Type)

        # ... and the customer tag is nested inside it, under its own name.
        self.assertIn('c_tag', s_tag)
        c_tag = s_tag['c_tag']
        self.assertEqual(c_tag['tci']['vid'], 200)
        self.assertEqual(int(c_tag['tci']['pcp']), 3)
        self.assertIs(c_tag['tci']['dei'], False)
        self.assertEqual(c_tag['type'], EtherType.Internet_Protocol_version_4)

        # The payload survived both tags.
        self.assertIn('ipv4', c_tag)
        self.assertIn('tcp', c_tag['ipv4'])

    def test_single_customer_tag_is_unchanged_by_the_service_tag_binding(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType

        frame = self.extract(ethernet(
            0x8100,
            tci(pcp=3, dei=0, vid=200) + struct.pack('!H', 0x0800)
            + ipv4(6, tcp(12345, 80, b'plain')),
        ))[0]

        self.assertEqual(str(frame.protochain), 'Ethernet:802.1Q:IPv4:TCP:Raw')
        eth = frame.info.to_dict()['ethernet']
        self.assertIn('c_tag', eth)
        self.assertNotIn('s_tag', eth)
        self.assertEqual(eth['c_tag']['tci']['vid'], 200)
        self.assertEqual(eth['type'], EtherType.Customer_VLAN_Tag_Type)

    ##########################################################################
    # OSPF and L2TP.
    ##########################################################################

    def test_ospf_parses_when_dispatched_from_ip_protocol_89(self) -> None:
        """OSPF is reachable from ``TransType.OSPFIGP`` and parses its header.

        The dissector could not parse anything at all before: ``read`` consulted
        the schema *class* rather than the parsed header, and ``alias`` -- which
        the dispatch reads while ``read`` is still running -- reached for an
        ``_info`` that does not exist yet.

        """
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.const.ospf.packet import Packet

        frame = self.extract(ethernet(0x0800, ipv4(89, ospf_hello())))[0]

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:OSPFv2:Raw')
        ospf = frame.info.to_dict()['ethernet']['ipv4']['ospf']
        self.assertEqual(ospf['version'], 2)
        self.assertEqual(ospf['type'], Packet.Hello)
        self.assertEqual(ospf['len'], 44)
        self.assertEqual(str(ospf['router_id']), '10.0.0.1')
        self.assertEqual(str(ospf['area_id']), '0.0.0.0')
        self.assertEqual(ospf['chksum'], b'\xab\xcd')
        self.assertEqual(ospf['autype'], Authentication.No_Authentication)
        self.assertEqual(ospf['auth'], b'\x00' * 8)

        # The 20-octet Hello body is not dissected, and is dispatched on the
        # -1 "no next protocol" sentinel rather than on a length.
        self.assertEqual(ospf['raw']['protocol'], -1)
        self.assertEqual(len(ospf['raw']['packet']), 20)

    def test_l2tp_parses_when_dispatched_from_udp_port_1701(self) -> None:
        frame = self.extract(ethernet(
            0x0800, ipv4(17, udp(1701, 1701, l2tp_data())),
        ))[0]

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:UDP:L2TP:Raw')
        l2tp = frame.info.to_dict()['ethernet']['ipv4']['udp']['l2tp']
        self.assertEqual(l2tp['version'], 2)
        self.assertEqual(l2tp['tunnelid'], 0x1234)
        self.assertEqual(l2tp['sessionid'], 0x5678)
        self.assertIs(l2tp['flags']['len'], False)
        self.assertIs(l2tp['flags']['seq'], False)

        # PPP is not dissected, so the payload is Raw under the -1 sentinel.
        self.assertEqual(l2tp['raw']['protocol'], -1)

    def test_l2tp_over_ip_is_deliberately_not_bound(self) -> None:
        """``TransType.L2TP`` (115) stays unbound: it is L2TPv3, not v2.

        :rfc:`3931` gives protocol number 115 a different session header from
        the :rfc:`2661` framing this dissector implements, so binding it would
        hand the parser the wrong shape.

        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet

        self.assertNotIn(TransType.L2TP, Internet.__proto__)

    ##########################################################################
    # Port bindings.
    ##########################################################################

    def test_ftp_data_and_ftp_dispatch_on_their_own_ports(self) -> None:
        frames = self.extract(
            ethernet(0x0800, ipv4(6, tcp(50000, 20, b'binary-file-contents'))),
            ethernet(0x0800, ipv4(6, tcp(50000, 21, b'USER anonymous\r\n'))),
        )

        self.assertEqual(str(frames[0].protochain), 'Ethernet:IPv4:TCP:FTP_DATA')
        data_tcp = frames[0].info.to_dict()['ethernet']['ipv4']['tcp']
        self.assertIn('ftp_data', data_tcp)
        self.assertEqual(data_tcp['ftp_data']['packet'], b'binary-file-contents')

        self.assertEqual(str(frames[1].protochain), 'Ethernet:IPv4:TCP:FTP')
        ctrl_tcp = frames[1].info.to_dict()['ethernet']['ipv4']['tcp']
        self.assertIn('ftp', ctrl_tcp)

    def test_http_dispatches_on_the_alternate_port_over_tcp_and_udp(self) -> None:
        request = b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
        frames = self.extract(
            ethernet(0x0800, ipv4(6, tcp(50000, 8080, request))),
            ethernet(0x0800, ipv4(17, udp(50000, 8080, request))),
        )

        self.assertEqual(str(frames[0].protochain), 'Ethernet:IPv4:TCP:HTTP/1.1')
        self.assertIn('http', frames[0].info.to_dict()['ethernet']['ipv4']['tcp'])

        self.assertEqual(str(frames[1].protochain), 'Ethernet:IPv4:UDP:HTTP/1.1')
        self.assertIn('http', frames[1].info.to_dict()['ethernet']['ipv4']['udp'])

    def test_registered_ports_are_exactly_those_intended(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        self.assertEqual(sorted(TCP.__proto__), [20, 21, 80, 8080])
        self.assertEqual(sorted(UDP.__proto__), [80, 1701, 8080])

    def test_port_8443_is_deliberately_not_bound(self) -> None:
        """8443 is IANA's ``pcsync-https``, and pcapkit implements no TLS.

        Binding HTTP there would hand a TLS record to an HTTP parser.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        self.assertNotIn(8443, TCP.__proto__)
        self.assertNotIn(8443, UDP.__proto__)

    def test_dispatch_lookups_do_not_grow_the_shared_registries(self) -> None:
        """An unregistered code must not be inserted by being looked up.

        The registries are ``defaultdict`` instances held on class attributes,
        so a bare ``registry[code]`` on a miss grows them for the whole process.

        """
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        registries = (Link.__proto__, Internet.__proto__,
                      TCP.__proto__, UDP.__proto__)
        sizes = [len(registry) for registry in registries]

        for registry in registries:
            for code in (8443, 115, 0x88A8, 20, 1701, 9999, -1):
                ProtocolBase._lookup_registry(registry, code)

        self.assertEqual([len(registry) for registry in registries], sizes)

    def test_parsing_an_unregistered_port_does_not_grow_the_registry(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        before = dict(TCP.__proto__)
        self.extract(ethernet(0x0800, ipv4(6, tcp(50000, 9999, b'whatever'))))
        self.assertEqual(dict(TCP.__proto__), before)


if __name__ == '__main__':
    unittest.main()
