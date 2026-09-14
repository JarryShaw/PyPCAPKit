from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Next-header values, spelled out so the datagram builders below read as the
#: header chains they describe.
NH_HOPOPT = 0
NH_UDP = 17
NH_ROUTE = 43
NH_FRAG = 44
NH_OPTS = 60

#: Link-local endpoints of the hand-built datagrams.
SRC_ADDR = bytes.fromhex('fe80' + '0000' * 6 + '0001')
DST_ADDR = bytes.fromhex('fe80' + '0000' * 6 + '0002')

#: Ports and body of the UDP datagram carried by every hand-built chain.
UDP_SRCPORT = 51234
UDP_DSTPORT = 5001
UDP_BODY = bytes(range(0x40, 0x60))
#: The eight octets the UDP layer is expected to be handed, whatever precedes
#: them -- ``c8 22 13 89 00 28 00 00``.
UDP_HEADER = (UDP_SRCPORT.to_bytes(2, 'big') + UDP_DSTPORT.to_bytes(2, 'big')
              + (8 + len(UDP_BODY)).to_bytes(2, 'big') + b'\x00\x00')

#: Fragment identification, matching the one in ``examples/sample/ipv6.pcap``.
FRAG_ID = 110308


def build_ipv6(next_header: int, payload: bytes) -> bytes:
    """Build an IPv6 datagram carrying ``payload`` after the fixed header."""
    return (b'\x60\x00\x00\x00' + len(payload).to_bytes(2, 'big')
            + bytes([next_header, 64]) + SRC_ADDR + DST_ADDR + payload)


def build_option_header(next_header: int) -> bytes:
    """Build an 8-octet hop-by-hop or destination options header (one PadN)."""
    return bytes([next_header, 0]) + b'\x01\x04' + b'\x00' * 4


def build_routing_header(next_header: int) -> bytes:
    """Build a 16-octet routing header of an unassigned routing type.

    Deliberately *not* eight octets long, so that a chain walk advancing by a
    fixed stride rather than by each header's own length would be caught.

    """
    return bytes([next_header, 1, 253, 0]) + b'\x00' * 12


def build_fragment_header(next_header: int) -> bytes:
    """Build an 8-octet fragment header for the first of several fragments."""
    return bytes([next_header, 0]) + b'\x00\x01' + FRAG_ID.to_bytes(4, 'big')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ExtensionRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, sample: str):
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path(sample), fout='/tmp/out', format='tree', store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_ipv6_fragment_chain_records_extension_header_metadata(self) -> None:
        extractor = self._extract('ipv6.pcap')
        frame = extractor.frame[12]
        ipv6 = frame.payload.payload
        frag = list(ipv6.extension_headers.values())[0]
        udp = ipv6.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:IPv6-Frag:UDP:Raw')
        self.assertEqual(ipv6.info.next.name, 'IPv6_Frag')
        self.assertEqual(ipv6.info.protocol.name, 'UDP')
        self.assertEqual(ipv6.info.hdr_len, 48)
        self.assertEqual(ipv6.info.raw_len, 1448)
        self.assertEqual([key.name for key in ipv6.extension_headers.keys()], ['IPv6_Frag'])

        self.assertEqual(frag.name, 'Fragment Header for IPv6')
        self.assertEqual(frag.alias, 'IPv6-Frag')
        self.assertEqual(frag.info.offset, 0)
        self.assertTrue(frag.info.mf)
        self.assertEqual(frag.info.id, 110308)

        self.assertEqual(int(udp.info.srcport), 51234)
        self.assertEqual(int(udp.info.dstport), 5001)
        self.assertEqual(udp.info.len, 4778)
        self.assertEqual(type(udp.payload).__name__, 'Raw')

        self.assertEqual(len(ipv6.info.fragment.header), 48)
        self.assertEqual(len(ipv6.info.fragment.payload), 1448)

        # the transport header has to be read from *after* the fragment header,
        # i.e. from the first octets of the data the fragment header carries
        self.assertEqual(bytes(udp.packet.header), bytes(ipv6.info.fragment.payload)[:8])

    def test_ipv6_fragment_extension_forbids_direct_payload_accessors(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self._extract('ipv6.pcap')
        frame = extractor.frame[15]
        ipv6 = frame.payload.payload
        frag = list(ipv6.extension_headers.values())[0]

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:IPv6-Frag:UDP:Raw')
        self.assertEqual(frag.info.offset, 543)
        self.assertFalse(frag.info.mf)
        self.assertEqual(frag.info.id, 110308)
        self.assertEqual(ipv6.info.raw_len, 434)
        self.assertEqual(len(ipv6.info.fragment.payload), 434)

        with self.assertRaises(UnsupportedCall):
            _ = frag.payload
        with self.assertRaises(UnsupportedCall):
            _ = frag.protocol
        with self.assertRaises(UnsupportedCall):
            _ = frag.protochain


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ExtensionPayloadOffsetTests(unittest.TestCase):
    """The next layer is read from after the *last* extension header.

    The datagrams here are built from bytes rather than read out of
    ``examples/sample/``: no committed capture carries more than one IPv6
    extension header, and the captures are pinned byte-for-byte by the rest of
    the suite, so a chain of several headers cannot be obtained from them.
    Parsing goes through :class:`~pcapkit.protocols.internet.ipv6.IPv6`
    directly, which is the layer that walks the chain -- the link layer and the
    capture container play no part in it.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _parse(self, next_header: int, extensions: bytes):
        from pcapkit.protocols.internet.ipv6 import IPv6

        data = build_ipv6(next_header, extensions + UDP_HEADER + UDP_BODY)
        return IPv6(data, len(data))

    def test_transport_header_is_read_after_the_extension_header_chain(self) -> None:
        cases = [
            # chain, first next-header, extension header bytes,
            # expected extension headers, expected hdr_len
            ('none', NH_UDP, b'', [], 40),
            ('fragment', NH_FRAG, build_fragment_header(NH_UDP), ['IPv6_Frag'], 48),
            ('hop-by-hop, destination options', NH_HOPOPT,
             build_option_header(NH_OPTS) + build_option_header(NH_UDP),
             ['HOPOPT', 'IPv6_Opts'], 56),
            ('hop-by-hop, routing, fragment', NH_HOPOPT,
             build_option_header(NH_ROUTE) + build_routing_header(NH_FRAG)
             + build_fragment_header(NH_UDP),
             ['HOPOPT', 'IPv6_Route', 'IPv6_Frag'], 72),
        ]

        for chain, next_header, extensions, exthdrs, hdr_len in cases:
            with self.subTest(chain=chain):
                ipv6 = self._parse(next_header, extensions)
                udp = ipv6.payload

                self.assertEqual([key.name for key in ipv6.extension_headers.keys()], exthdrs)
                self.assertEqual(ipv6.info.hdr_len, hdr_len)
                self.assertEqual(ipv6.info.raw_len, len(UDP_HEADER) + len(UDP_BODY))
                self.assertEqual(ipv6.info.protocol.name, 'UDP')

                self.assertEqual(type(udp).__name__, 'UDP')
                self.assertEqual(bytes(udp.packet.header), UDP_HEADER)
                self.assertEqual(int(udp.info.srcport), UDP_SRCPORT)
                self.assertEqual(int(udp.info.dstport), UDP_DSTPORT)
                self.assertEqual(udp.info.len, len(UDP_HEADER) + len(UDP_BODY))
                self.assertEqual(bytes(udp.payload.info.packet), UDP_BODY)

                if 'IPv6_Frag' in exthdrs:
                    # the fragment record and the next layer describe the same
                    # octets, the ones following the whole chain
                    self.assertEqual(len(ipv6.info.fragment.header), hdr_len)
                    self.assertEqual(bytes(ipv6.info.fragment.payload),
                                     UDP_HEADER + UDP_BODY)


if __name__ == '__main__':
    unittest.main()
