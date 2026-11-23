# -*- coding: utf-8 -*-
"""GitHub issue #2817: PPPoE's discovery and session stages, and their bindings.

:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` reads the :rfc:`2516` header,
the tags of a discovery packet, and the PPP frame of a session packet, telling the
two stages apart by the Code. It is bound at EtherTypes ``0x8863`` and ``0x8864``
and at LinkType PPP_ETHER in PCAP and PCAP-NG. Every octet string here is built
by hand, and every layer rebuilds byte-exactly.

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

#: A PADI (RFC 2516 Section 5.1): Code 0x09, Session ID 0, an empty Service-Name
#: tag (0x0101) and a four-octet Host-Uniq tag (0x0103).
PADI = bytes.fromhex('11' '09' '0000' '000c' '01010000' '01030004' 'deadbeef')

#: A session packet (Section 6): Code 0x00, Session ID 0x1234, carrying a PPP
#: frame with no Address and Control fields, Protocol 0x0021, then IPv4.
SESSION = bytes.fromhex('11' '00' '1234' '0016') + b'\x00\x21' + IPV4


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


class TestPPPoE(unittest.TestCase):
    """Pin the PPPoE layer: parse against RFC 2516, build, and bind."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, data: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.pppoe.protocol import PPPoE
        return PPPoE(data, len(data))

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
            path = os.path.join(tmp, f'pppoe{suffix}')
            with open(path, 'wb') as file:
                file.write(data)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, store=True)
        return list(extractor.frame)

    ##########################################################################
    # The two stages.
    ##########################################################################

    def test_discovery_packet_reads_its_tags(self) -> None:
        from pcapkit.const.pppoe.code import Code
        from pcapkit.const.pppoe.tag import Tag

        pppoe = self._parse(PADI)
        info = pppoe.info
        self.assertEqual((info.version, info.type, info.session_id, info.length), (1, 1, 0, 12))
        self.assertIs(info.code, Code.PADI_Initiation)
        self.assertEqual([(tag.type, tag.length, tag.value) for tag in info.tags],
                         [(Tag.Service_Name, 0, b''), (Tag.Host_Uniq, 4, b'\xde\xad\xbe\xef')])
        self.assertEqual((pppoe.name, pppoe.alias, pppoe.length, pppoe.code),
                         ('PPP over Ethernet', 'PPPoE', 18, Code.PADI_Initiation))
        self.assertEqual(type(pppoe.payload).__name__, 'NoPayload')
        self._assert_rebuilds(pppoe)

    def test_session_packet_carries_ppp(self) -> None:
        pppoe = self._parse(SESSION)
        self.assertEqual((pppoe.info.code, pppoe.info.session_id, pppoe.info.length), (0, 0x1234, 22))
        self.assertIsNone(pppoe.info.tags)
        self.assertEqual(pppoe.length, 6)
        self.assertEqual(pppoe.protochain.chain, 'PPPoE:PPP:IPv4')
        ppp = pppoe.payload
        self.assertIsNone(ppp.info.address)
        self.assertEqual(ppp.info.protocol, 0x0021)
        self._assert_rebuilds(pppoe)
        self._assert_rebuilds(ppp)

    def test_octets_past_the_length_are_its_trailer(self) -> None:
        """Ethernet's padding past the Length field stays on this layer, and rebuilds (#1455)."""
        for packet, padding in ((SESSION, bytes(6)), (PADI, b'\x01\x02\x03\x04')):
            with self.subTest(code=packet[1]):
                pppoe = self._parse(packet + padding)
                self.assertEqual(pppoe.info.trailer, padding)
                self.assertEqual(pppoe.payload.data, packet[6:] if packet is SESSION else b'')
                self._assert_rebuilds(pppoe)

    def test_a_cut_packet_rebuilds_as_captured(self) -> None:
        """A capture cut inside the tags or the PPP frame rebuilds to what it holds (#2761)."""
        for data in (PADI[:8], PADI[:15], SESSION[:13]):
            with self.subTest(size=len(data)), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                pppoe = self._parse(data)
                self.assertEqual(pppoe.info.length, int.from_bytes(data[4:6], 'big'))
                self._assert_rebuilds(pppoe)

    def test_every_cut_rebuilds_as_captured(self) -> None:
        for packet in (PADI, SESSION, PADI + bytes(4)):
            for size in range(1, len(packet) + 1):
                with self.subTest(code=packet[1], size=size), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self._assert_rebuilds(self._parse(packet[:size]))

    def test_a_length_ending_inside_a_tag_is_refused(self) -> None:
        """Length 6 ends two octets into the AC-Name tag, which would rebuild two octets longer."""
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.utilities.exceptions import ProtocolError

        padi = bytes.fromhex('11' '09' '0000' '0006' '01010000' '01020007') + b'ac-name'
        with self.assertRaisesRegex(ProtocolError, r'^PPPoE: length 6 ends inside a tag$'):
            self._parse(padi)
        # NOTE: Refused quietly where Ethernet dispatches it, leaving the octets raw (#2588).
        frame = _ethernet(0x8863, padi)
        with self.assertNoLogs('pcapkit', level='DEBUG'):
            ethernet = Ethernet(frame, len(frame))
        self.assertEqual(type(ethernet.payload).__name__, 'Raw')
        self.assertEqual(ethernet.payload.data, padi)
        self.assertEqual(ethernet.payload.info.error, 'PPPoE: length 6 ends inside a tag')

    def test_another_version_or_type_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for octet in (0x21, 0x12):
            with self.subTest(octet=octet), \
                    self.assertRaisesRegex(ProtocolError, r'^PPPoE: invalid version or type: '):
                self._parse(bytes((octet,)) + PADI[1:])

    ##########################################################################
    # Construction.
    ##########################################################################

    def test_make_round_trips(self) -> None:
        from pcapkit.const.pppoe.code import Code
        from pcapkit.const.pppoe.tag import Tag
        from pcapkit.protocols.link.ppp.protocol import PPP
        from pcapkit.protocols.link.pppoe.protocol import PPPoE

        padi = PPPoE(code=Code.PADI_Initiation, tags=[(Tag.Service_Name, b''),
                                                      {'type': 0x0103, 'value': b'\xde\xad\xbe\xef'}])
        self.assertEqual(padi.data, PADI)
        session = PPPoE(session_id=0x1234, payload=PPP(acfc=True, payload=IPV4))
        self.assertEqual(session.data, SESSION)
        padt = PPPoE(code=0xA7, session_id=0x1234)
        self.assertEqual(padt.data, bytes.fromhex('11a712340000'))
        for made in (padi, session, padt):
            with self.subTest(code=made.info.code):
                parsed = self._parse(made.data)
                self.assertEqual(bytes(PPPoE.from_data(parsed.info)), made.data)

    def test_make_refuses_what_would_not_read_back(self) -> None:
        from pcapkit.protocols.link.pppoe.protocol import PPPoE
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            ({'code': 'PADI'}, r'invalid code'),
            ({'code': 0, 'tags': [(0x0101, b'')]}, r'tags given in the session stage'),
            ({'code': 0x09, 'payload': b'x'}, r'payload given in the discovery stage'),
            ({'code': 0x09, 'tags': [('Service_Name', b'')]}, r'invalid tag type'),
            ({'code': 0x09, 'tags': [(0x0101, 'x')]}, r'invalid tag value'),
            ({'session_id': 0x10000}, r'invalid session ID'),
            ({'code': 0x09, 'tags': [(1,)]}, r'invalid tag: must be a \(type, value\) pair'),
            ({'code': 0x09, 'tags': [1]}, r'invalid tag: must be a \(type, value\) pair'),
            ({'code': 0x09, 'tags': [{'value': b''}]}, r'invalid tag: must be a \(type, value\) pair'),
            ({'code': 0x09, 'tags': 1}, r'invalid tags: must be an iterable of tags, not 1$'),
            ({'code': 0x09, 'tags': 'abc'}, r"invalid tags: must be an iterable of tags, not 'abc'$"),
            ({'code': 0x09, 'tags': [{'type': 0x0101, 'value': b'ab', 'length': 3}]},
             r"tag length 3 is not its value's 2$"),
            ({'code': 0x09, 'tags': [{'type': 0x0101, 'value': b'ab', 'length': 1}]},
             r"tag length 1 is not its value's 2$"),
            ({'code': 0x09, 'tags': [(0x0101, b'')], 'payload_length': 5},
             r'length 5 is not the 4 octet\(s\) after the header$'),
            ({'payload': b'ab', 'payload_length': 3}, r'length 3 is not the 2 octet\(s\) after the header$'),
        )
        for kwargs, message in cases:
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ProtocolError, message):
                PPPoE(**kwargs)

    ##########################################################################
    # Bindings.
    ##########################################################################

    def test_registered_at_its_ethertypes_link_type_and_index(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.pppoe.protocol import PPPoE
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        for code in (EtherType.PPP_over_Ethernet_Discovery_Stage, EtherType.PPP_over_Ethernet_Session_Stage):
            with self.subTest(code=code.name):
                self.assertIs(Link._lookup_next_layer(Link.__proto__, code), PPPoE)
        for cls in (Frame, PCAPNG):
            with self.subTest(table=cls.__name__):
                self.assertIs(cls._lookup_next_layer(cls.__proto__, LinkType.PPP_ETHER), PPPoE)
        self.assertIs(PPPoE.__index__(), LinkType.PPP_ETHER)
        self.assertEqual(int(PPPoE.__index__()), 51)

    def test_ethernet_capture(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        records = (_ethernet(0x8863, PADI + bytes(28)), _ethernet(0x8864, SESSION + bytes(20)))
        frames = self._extract(_pcap(LinkType.ETHERNET, records), '.pcap')
        self.assertEqual([frame.protochain.chain for frame in frames],
                         ['Ethernet:PPPoE', 'Ethernet:PPPoE:PPP:IPv4'])
        for frame, record in zip(frames, records):
            self.assertEqual(bytes(frame.payload.data), record)
            layer = frame.payload
            while type(layer).__name__ not in ('Raw', 'NoPayload'):
                self._assert_rebuilds(layer)
                layer = layer.payload

    def test_ppp_ether_captures(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        records = (PADI, SESSION)
        for data, suffix in ((_pcap(LinkType.PPP_ETHER, records), '.pcap'),
                             (_pcapng(LinkType.PPP_ETHER, records), '.pcapng')):
            with self.subTest(format=suffix):
                frames = self._extract(data, suffix)
                self.assertEqual([frame.protochain.chain for frame in frames], ['PPPoE', 'PPPoE:PPP:IPv4'])


if __name__ == '__main__':
    unittest.main()
