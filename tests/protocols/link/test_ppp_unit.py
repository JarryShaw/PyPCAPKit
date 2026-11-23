# -*- coding: utf-8 -*-
"""GitHub issue #2817: PPP framing, its control packets and its bindings.

:class:`~pcapkit.protocols.link.ppp.protocol.PPP` reads the :rfc:`1661` frame in the
:rfc:`1662` HDLC-like framing: the Address and Control fields where the frame
opens with ``0xFF 0x03``, a Protocol field of one octet where its first octet is
odd, IPv4 and IPv6 as the next layer, and LCP, IPCP, IPv6CP, PAP and CHAP packets
at header level. It is bound at LinkType PPP and PPP_HDLC in PCAP and PCAP-NG, at
EtherType ``0x880B``, and as the payload of an L2TPv2 data message. Every octet
string here is built by hand, and every layer rebuilds byte-exactly.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): per-protocol field tests, interpreter-independent pure Python.
__tier__ = 'LATEST'

#: An option-less IPv4 header of protocol 59 and no payload, 192.0.2.1 to 198.51.100.1.
IPV4 = bytes.fromhex('4500001400000000403b0000c0000201c6336401')

#: An IPv6 header with Next Header 59 and no payload, 2001:db8::1 to 2001:db8::2.
IPV6 = (bytes.fromhex('6000000000003b40')
        + bytes.fromhex('20010db8000000000000000000000001')
        + bytes.fromhex('20010db8000000000000000000000002'))

#: An LCP Configure-Request (RFC 1661 Section 5.1), Identifier 1, with the
#: Maximum-Receive-Unit option of 1500 (Section 6.1).
LCP_CONFREQ = bytes.fromhex('01010008' '010405dc')

#: A control packet of each protocol number read at header level, by number.
CONTROL_PACKETS = {
    0xC021: LCP_CONFREQ,
    # IPCP Configure-Request with IP-Address 10.0.0.1 (RFC 1332 Section 3.3).
    0x8021: bytes.fromhex('0102000a' '03060a000001'),
    # IPV6CP Configure-Ack with an Interface-Identifier (RFC 5072 Section 4.1).
    0x8057: bytes.fromhex('0203000e' '010a0011223344556677'),
    # PAP Authenticate-Request for peer "u", password "p" (RFC 1334 Section 2.2.1).
    0xC023: bytes.fromhex('01040008' '0175' '0170'),
    # CHAP Success, no message (RFC 1994 Section 4.2).
    0xC223: bytes.fromhex('03050004'),
}


def _pcap(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP v2.4 file of ``records`` on ``linktype``."""
    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for index, record in enumerate(records):
        data += struct.pack('<IIII', 1500000000 + index, 0, len(record), len(record)) + record
    return data


def _pcapng(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP-NG file: one section, one interface on ``linktype``."""
    shb = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack('<IIHHII', 1, 20, linktype, 0, 262144, 20)
    blocks = b''
    for index, record in enumerate(records):
        padded = record + bytes(-len(record) % 4)
        length = 32 + len(padded)
        blocks += (struct.pack('<IIIIIII', 6, length, 0, 0, 1500000000 + index, len(record), len(record))
                   + padded + struct.pack('<I', length))
    return shb + idb + blocks


def _ethernet(etype: int, payload: bytes) -> bytes:
    """A minimal Ethernet II header carrying ``payload`` under ``etype``."""
    return bytes.fromhex('001122334455' '66778899aabb') + struct.pack('!H', etype) + payload


def _l2tp(type_: int, payload: bytes) -> bytes:
    """An L2TPv2 message (RFC 2661 Section 3.1) of ``type_``, Length present on a control one."""
    if type_:
        return struct.pack('!HHHH', 0xC002, 12 + len(payload), 1, 2) + struct.pack('!HH', 0, 0) + payload
    return struct.pack('!HHH', 0x0002, 1, 2) + payload


def _udp(payload: bytes) -> bytes:
    """A UDP datagram from and to port 1701, with no checksum."""
    return struct.pack('!HHHH', 1701, 1701, 8 + len(payload), 0) + payload


def _ipv4(proto: int, payload: bytes) -> bytes:
    """A minimal IPv4 header carrying ``payload`` under protocol ``proto``."""
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))) + payload


class TestPPP(unittest.TestCase):
    """Pin the PPP layer: parse against RFC 1661 and 1662, build, and bind."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, data: bytes, **kwargs):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.ppp.protocol import PPP
        return PPP(data, len(data), **kwargs)

    def _assert_rebuilds(self, layer) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                rebuilt = type(layer).from_data(data)
                self.assertEqual(rebuilt.data.hex(), layer.data.hex())
                self.assertEqual(rebuilt.info, layer.info)

    def _extract(self, data: bytes, suffix: str) -> 'list':  # type: ignore[type-arg]
        import pcapkit

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f'ppp{suffix}')
            with open(path, 'wb') as file:
                file.write(data)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, store=True)
        return list(extractor.frame)

    ##########################################################################
    # Framing.
    ##########################################################################

    def test_hdlc_like_framing_dispatches_ipv4(self) -> None:
        from pcapkit.const.ppp.protocol import Protocol

        data = b'\xff\x03\x00\x21' + IPV4
        ppp = self._parse(data)
        self.assertEqual((ppp.info.address, ppp.info.control), (0xFF, 0x03))
        self.assertIs(ppp.info.protocol, Protocol.Internet_Protocol_version_4)
        self.assertEqual(int(ppp.info.protocol), 0x0021)
        self.assertIs(ppp.info.pfc, False)
        self.assertIsNone(ppp.info.control_packet)
        self.assertEqual((ppp.name, ppp.alias, ppp.length, ppp.protocol), ('Point-to-Point Protocol', 'PPP', 4, 0x0021))
        self.assertEqual(ppp.protochain.chain, 'PPP:IPv4')
        self.assertEqual(ppp.payload.data, IPV4)
        self._assert_rebuilds(ppp)

    def test_compressed_fields_dispatch_ipv6(self) -> None:
        """Without Address and Control, and with a one-octet Protocol field (RFC 1661 Section 6.5, 6.6)."""
        ppp = self._parse(b'\x57' + IPV6)
        self.assertIsNone(ppp.info.address)
        self.assertIsNone(ppp.info.control)
        self.assertEqual(ppp.info.protocol, 0x0057)
        self.assertIs(ppp.info.pfc, True)
        self.assertEqual(ppp.length, 1)
        self.assertEqual(ppp.protochain.chain, 'PPP:IPv6')
        self._assert_rebuilds(ppp)

        # Either compression alone.
        for data, address, pfc in ((b'\x00\x21' + IPV4, None, False), (b'\xff\x03\x21' + IPV4, 0xFF, True)):
            with self.subTest(data=data[:3].hex()):
                ppp = self._parse(data)
                self.assertEqual((ppp.info.address, ppp.info.pfc, ppp.info.protocol), (address, pfc, 0x0021))
                self.assertEqual(ppp.protochain.chain, 'PPP:IPv4')
                self._assert_rebuilds(ppp)

    def test_an_unbound_protocol_is_raw(self) -> None:
        ppp = self._parse(b'\xff\x03\x00\x2b' + b'IPX')
        self.assertEqual(ppp.info.protocol.name, 'Novell_IPX')
        self.assertEqual(type(ppp.payload).__name__, 'Raw')
        self.assertEqual(ppp.payload.data, b'IPX')
        self._assert_rebuilds(ppp)

    ##########################################################################
    # Control packets.
    ##########################################################################

    def test_control_packets_are_read_at_header_level(self) -> None:
        from pcapkit.const.ppp.protocol import Protocol

        cases = (
            (Protocol.Link_Control_Protocol, LCP_CONFREQ),
            # IPCP Configure-Request with IP-Address 10.0.0.1 (RFC 1332 Section 3.3).
            (Protocol.Internet_Protocol_Control_Protocol, bytes.fromhex('0102000a' '03060a000001')),
            # IPV6CP Configure-Ack with an Interface-Identifier (RFC 5072 Section 4.1).
            (Protocol.IPv6_Control_Protocol, bytes.fromhex('0203000e' '010a0011223344556677')),
            # PAP Authenticate-Request for peer "u", password "p" (RFC 1334 Section 2.2.1).
            (Protocol.Password_Authentication_Protocol, bytes.fromhex('01040008' '0175' '0170')),
            # CHAP Success, no message (RFC 1994 Section 4.2).
            (Protocol.Challenge_Handshake_Authentication_Protocol, bytes.fromhex('03050004')),
        )
        for protocol, packet in cases:
            with self.subTest(protocol=protocol.name):
                data = b'\xff\x03' + struct.pack('!H', protocol) + packet
                ppp = self._parse(data)
                control = ppp.info.control_packet
                self.assertEqual((control.code, control.identifier), (packet[0], packet[1]))
                self.assertEqual(control.length, len(packet))
                self.assertEqual(control.data, packet[4:])
                self.assertEqual(ppp.length, 4 + len(packet))
                self.assertEqual(ppp.protochain.chain, 'PPP')
                self._assert_rebuilds(ppp)

    def test_octets_after_a_control_packet_are_raw(self) -> None:
        ppp = self._parse(b'\xc0\x21' + LCP_CONFREQ + b'\x00\x00')
        self.assertEqual(ppp.info.control_packet.length, 8)
        self.assertEqual(type(ppp.payload).__name__, 'Raw')
        self.assertEqual(ppp.payload.data, b'\x00\x00')
        self._assert_rebuilds(ppp)

    def test_a_control_length_below_its_fixed_fields_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r'^PPP: invalid control packet length: 3$'):
            self._parse(b'\xc0\x21' + bytes.fromhex('01010003'))

    def test_a_cut_control_packet_rebuilds_as_captured(self) -> None:
        """A capture cut inside the data keeps what it holds, and rebuilds to it (#2761)."""
        data = b'\xff\x03\xc0\x21' + LCP_CONFREQ[:6]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            ppp = self._parse(data)
        self.assertEqual(ppp.info.control_packet.length, 8)
        self.assertEqual(ppp.info.control_packet.data[:2], LCP_CONFREQ[4:6])
        self.assertEqual(ppp.info.get('__short_read__'), ('control_packet', 6))
        self.assertEqual(type(ppp.payload).__name__, 'Raw')
        self._assert_rebuilds(ppp)

    ##########################################################################
    # Construction.
    ##########################################################################

    def test_make_round_trips(self) -> None:
        from pcapkit.const.ppp.protocol import Protocol
        from pcapkit.protocols.link.ppp.protocol import PPP

        cases = (
            ({}, b'\xff\x03\x00\x21'),
            ({'acfc': True}, b'\x00\x21'),
            ({'acfc': True, 'pfc': True}, b'\x21'),
            ({'protocol': 0x57, 'pfc': True}, b'\xff\x03\x57'),
            ({'protocol': Protocol.Link_Control_Protocol,
              'control_packet': {'code': 1, 'identifier': 1, 'data': LCP_CONFREQ[4:]}},
             b'\xff\x03\xc0\x21' + LCP_CONFREQ),
        )
        for kwargs, head in cases:
            with self.subTest(kwargs=kwargs):
                payload = b'' if 'control_packet' in kwargs else IPV4
                made = PPP(**kwargs, payload=payload)
                self.assertEqual(made.data, head + payload)
                parsed = self._parse(made.data)
                self.assertEqual(bytes(PPP.from_data(parsed.info)), made.data)
                self.assertEqual(parsed.info.protocol, kwargs.get('protocol', 0x21))

    def test_every_cut_of_a_control_frame_rebuilds_as_captured(self) -> None:
        """A capture cut at any octet, the Code to Length octets included, rebuilds byte-exactly."""
        for protocol, packet in CONTROL_PACKETS.items():
            for acfc in (False, True):
                frame = (b'' if acfc else b'\xff\x03') + struct.pack('!H', protocol) + packet
                for size in range(1, len(frame) + 1):
                    with self.subTest(protocol=hex(protocol), acfc=acfc, size=size), \
                            warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self._assert_rebuilds(self._parse(frame[:size]))

    def test_make_refuses_what_would_not_read_back(self) -> None:
        from pcapkit.protocols.link.ppp.protocol import PPP
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            ({'protocol': 'IPv4'}, r'invalid protocol'),
            ({'protocol': 0x0121, 'pfc': True}, r'invalid protocol'),
            ({'protocol': 0x22, 'pfc': True}, r'compressed protocol must be odd'),
            ({'protocol': 0x0100}, r'odd first octet reads as compressed'),
            ({'protocol': 0xC021}, r'needs a control packet'),
            ({'protocol': 0x21, 'control_packet': {}}, r'carries no control packet'),
            ({'protocol': 0xC021, 'control_packet': {'length': 3}}, r'is short of 4 octet'),
            ({'protocol': 0xC021, 'control_packet': {'data': 'x'}}, r'invalid control packet data'),
            ({'protocol': 0xFF, 'pfc': True, 'acfc': True, 'payload': b'\x03'}, r'opens with 0xFF 0x03'),
            ({'protocol': 0xC021, 'control_packet': b'\x01\x01\x00\x04'}, r'invalid control packet: must be'),
        )
        for kwargs, message in cases:
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ProtocolError, message):
                PPP(**kwargs)

    ##########################################################################
    # Bindings.
    ##########################################################################

    def test_registered_at_its_link_types_ethertype_and_index(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.ppp.protocol import PPP
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        for cls in (Frame, PCAPNG):
            for code in (LinkType.PPP, LinkType.PPP_HDLC):
                with self.subTest(table=cls.__name__, code=code.name):
                    self.assertIs(cls._lookup_next_layer(cls.__proto__, code), PPP)
        self.assertIs(Link._lookup_next_layer(Link.__proto__, EtherType.Point_to_Point_Protocol), PPP)
        self.assertIs(PPP.__index__(), LinkType.PPP)
        self.assertEqual(int(PPP.__index__()), 9)

    def test_pcap_and_pcapng_captures(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        records = (b'\xff\x03\x00\x21' + IPV4, b'\x57' + IPV6, b'\xff\x03\xc0\x21' + LCP_CONFREQ)
        for linktype in (LinkType.PPP, LinkType.PPP_HDLC):
            for data, suffix in ((_pcap(linktype, records), '.pcap'), (_pcapng(linktype, records), '.pcapng')):
                with self.subTest(linktype=linktype.name, format=suffix):
                    frames = self._extract(data, suffix)
                    chains = [frame.protochain.chain for frame in frames]
                    if linktype == LinkType.PPP:
                        self.assertEqual(chains, ['PPP:IPv4', 'PPP:IPv6', 'PPP'])
                    else:
                        # NOTE: LINKTYPE_PPP_HDLC requires the Address and Control fields,
                        # so the compressed frame is refused, quietly, to Raw.
                        self.assertEqual(chains, ['PPP:IPv4', 'PPP_HDLC', 'PPP'])
                        self.assertEqual(type(frames[1].payload).__name__, 'Raw')
                    for frame, record in zip(frames, records):
                        self.assertEqual(bytes(frame.payload.data), record)

    def test_cisco_hdlc_under_ppp_hdlc_is_refused(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.utilities.exceptions import ProtocolError

        cisco = b'\x0f\x00\x08\x00' + IPV4
        with self.assertRaisesRegex(ProtocolError, r'no HDLC-like framing under LINKTYPE_PPP_HDLC'):
            self._parse(cisco, alias=LinkType.PPP_HDLC)
        frames = self._extract(_pcap(LinkType.PPP_HDLC, (cisco,)), '.pcap')
        self.assertEqual(type(frames[0].payload).__name__, 'Raw')
        self.assertIn('LINKTYPE_PPP_HDLC', frames[0].payload.info.error)

    def test_ethertype_0x880b(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        frames = self._extract(_pcap(LinkType.ETHERNET, (_ethernet(0x880B, b'\x00\x21' + IPV4),)), '.pcap')
        self.assertEqual(frames[0].protochain.chain, 'Ethernet:PPP:IPv4')

    def test_l2tpv2_data_message_carries_ppp(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        records = (_ethernet(0x0800, _ipv4(17, _udp(_l2tp(0, b'\xff\x03\x00\x21' + IPV4)))),
                   _ethernet(0x0800, _ipv4(17, _udp(_l2tp(1, b'\x00\x08\x00\x00\x00\x00\x00\x01')))))
        frames = self._extract(_pcap(LinkType.ETHERNET, records), '.pcap')
        self.assertEqual(frames[0].protochain.chain, 'Ethernet:IPv4:UDP:L2TPv2:PPP:IPv4')
        # NOTE: A control message carries AVPs, not PPP.
        self.assertEqual(frames[1].protochain.chain, 'Ethernet:IPv4:UDP:L2TPv2:Raw')

    def test_register_ppp_binds_a_protocol_number(self) -> None:
        from pcapkit.const.ppp.protocol import Protocol
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.registry import register_ppp
        from pcapkit.protocols.link.ppp.protocol import PPP
        from pcapkit.utilities.exceptions import RegistryError

        shipped = PPP.__proto__.get(Protocol.Novell_IPX)
        self.assertIsNone(shipped)
        ipx = ModuleDescriptor('pcapkit.protocols.internet.ipx.protocol', 'IPX')
        register_ppp(Protocol.Novell_IPX, ipx)
        try:
            ppp = self._parse(b'\x00\x2b' + bytes.fromhex('0000001e' + '00' * 26))
            self.assertEqual(ppp.protochain.chain, 'PPP:IPX')
        finally:
            del PPP.__proto__[Protocol.Novell_IPX]

        with self.assertRaisesRegex(RegistryError, r'^PPP: code must be a member of Protocol, not 43$'):
            register_ppp(0x2B, ipx)  # type: ignore[arg-type]


    def test_register_ppp_control_overrides_and_restores_a_parser(self) -> None:
        from pcapkit.const.ppp.protocol import Protocol
        from pcapkit.foundation.registry import register_ppp_control
        from pcapkit.protocols.link.ppp.data import ControlPacket as Data_ControlPacket
        from pcapkit.protocols.link.ppp.protocol import PPP
        from pcapkit.protocols.link.ppp.schema import ControlHeader, ControlPacket
        from pcapkit.utilities.exceptions import RegistryError
        from pcapkit.utilities.warnings import RegistryWarning

        lcp, lqr = Protocol.Link_Control_Protocol, Protocol.Link_Quality_Report
        self.assertEqual(PPP.__control__[lcp], 'header')
        self.assertIs(ControlPacket.registry[lcp], ControlHeader)
        self.assertNotIn(lqr, PPP.__control__)
        self.assertIsNone(ControlPacket.registry[lqr])

        # An override warns and reaches the parse; restoring the shipped entry warns
        # too, and handing it back once more is a silent no-op.
        seen = []

        def parser(protocol, packet):  # type: ignore[no-untyped-def]
            seen.append(protocol)
            return Data_ControlPacket(code=packet.code, identifier=0xFF, length=packet.length,
                                      data=packet.data)

        def constructor(protocol, packet):  # type: ignore[no-untyped-def]
            return ControlHeader(code=packet['code'], identifier=1, length=packet['length'],
                                 data=packet['data'])

        with self.assertWarns(RegistryWarning):
            register_ppp_control(lcp, (parser, constructor), schema=ControlHeader)
        try:
            ppp = self._parse(b'\xc0\x21' + LCP_CONFREQ)
            self.assertEqual((seen, ppp.info.control_packet.identifier), ([lcp], 0xFF))
            self.assertEqual(PPP.from_data(ppp.info).data, b'\xc0\x21' + LCP_CONFREQ)
        finally:
            with self.assertWarns(RegistryWarning):
                register_ppp_control(lcp, 'header', schema=ControlHeader)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            register_ppp_control(lcp, 'header', schema=ControlHeader)
        self.assertEqual(PPP.__control__[lcp], 'header')
        self.assertEqual(self._parse(b'\xc0\x21' + LCP_CONFREQ).info.control_packet.identifier, 1)

        # A layout registered for a new number reads its frames as control packets.
        register_ppp_control(lqr, 'header', schema=ControlHeader)
        try:
            ppp = self._parse(b'\xc0\x25' + bytes.fromhex('01020004'))
            self.assertEqual(ppp.info.control_packet.code, 1)
            self._assert_rebuilds(ppp)
        finally:
            del PPP.__control__[lqr]
            del ControlPacket.registry[lqr]
        self.assertIsNone(self._parse(b'\xc0\x25' + bytes.fromhex('01020004')).info.control_packet)

        with self.assertRaisesRegex(RegistryError, r'^PPP: code must be a member of Protocol'):
            register_ppp_control(0xC025, 'header')  # type: ignore[arg-type]
        with self.assertRaisesRegex(RegistryError, r'^method must be a PPP control packet parser function$'):
            register_ppp_control(lqr, 'nosuch')
        with self.assertRaisesRegex(RegistryError, r'^schema must be a PPP control packet schema$'):
            register_ppp_control(lqr, 'header', schema=PPP)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            register_ppp_control(lqr, 'header', ControlHeader)  # type: ignore[misc]
        self.assertNotIn(lqr, PPP.__control__)

if __name__ == '__main__':
    unittest.main()
