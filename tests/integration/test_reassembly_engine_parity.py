# -*- coding: utf-8 -*-
"""Each toolkit adapter describes an IPv6 fragment as :rfc:`8200` does.

Each of :mod:`pcapkit.toolkit.pcap`, :mod:`pcapkit.toolkit.pcapng`,
:mod:`pcapkit.toolkit.dpkt` and :mod:`pcapkit.toolkit.scapy` builds a
:term:`reasm.ipv6.packet` from whatever object model its engine hands it.
Tested only against itself, each can drift from the RFC unnoticed, as in
#415: for ``ipv6.pcap`` frame 13 the adapters reported ``ihl`` 48/48/40/40, ``len(header)``
48/48/40/40 and ``tl`` 1496/1496/1488/1496, where the RFC calls for 40, 40 and
1488.

So every adapter is run over the same octets, and each one's result is checked
against the values the RFC calls for and the capture's own octets.

The PCAP-NG adapter has no fragmented sample capture of its own, so the frames of
``ipv6.pcap`` are rewrapped into a PCAP-NG file here, so that every adapter is
checked over the same datagram.

"""
from __future__ import annotations

import struct
import unittest
from typing import TYPE_CHECKING

from tests._support import sample_path
from tests.integration._helpers import HAS_DPKT, HAS_RUNTIME, HAS_SCAPY, EndToEndTestCase

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): compares the engines, whose releases vary by interpreter, on
#: hand-picked captures.
__tier__ = 'ALL'

#: Next Header value of the IPv6 Fragment header (:rfc:`8200#section-4.5`).
NH_IPV6_FRAG = 44
#: Next Header value of UDP, which is what ``ipv6.pcap``'s fragments carry.
NH_UDP = 17

#: Length of the fixed IPv6 header, and of the unfragmentable part of every
#: fragment in ``ipv6.pcap`` -- none of them carries an extension header before
#: its Fragment header.
IPV6_HDR_LEN = 40

#: The four fragments of ``ipv6.pcap``, as ``(fragment offset, payload length)``.
#: Frames 13 to 16 are one 4778 octet UDP datagram.
FRAGMENTS = ((0, 1448), (1448, 1448), (2896, 1448), (4344, 434))

#: PCAP-NG block types used below (Section 4 of the PCAP-NG specification).
BLOCK_SECTION_HEADER = 0x0A0D0D0A
BLOCK_INTERFACE_DESCRIPTION = 0x00000001
BLOCK_ENHANCED_PACKET = 0x00000006

#: Link layer type 1, i.e. ``LinkType.ETHERNET``. Spelled as a literal because
#: the capture below is assembled before :mod:`pcapkit` is imported.
LINKTYPE_ETHERNET = 1


def pcap_frames(path: 'str') -> 'list[bytes]':
    """Raw link-layer frames of a PCAP file, in capture order.

    Read by hand rather than through :mod:`pcapkit`, so that the octets handed to
    the ``dpkt`` and ``scapy`` adapters are the file's own and not something a
    pcapkit parse has already been over.

    Args:
        path: Absolute path to a PCAP file, of either byte order.

    Returns:
        One :obj:`bytes` per record. A trailing record whose declared length runs
        past the end of the file is dropped: ``ipv6.pcap`` ends in a truncated
        one, which is what the extractor reports as ``EOF reached``.

    """
    with open(path, 'rb') as file:
        data = file.read()

    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        endian = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        endian = '>'
    else:
        raise AssertionError(f'not a PCAP file: {magic!r}')

    frames = []  # type: list[bytes]
    offset = 24  # past the 24 octet global header
    while offset + 16 <= len(data):
        incl_len = struct.unpack_from(f'{endian}IIII', data, offset)[2]
        offset += 16
        if offset + incl_len > len(data):
            break
        frames.append(data[offset:offset + incl_len])
        offset += incl_len
    return frames


def write_pcapng(path: 'Any', frames: 'list[bytes]') -> 'str':
    """Write ``frames`` into a minimal little-endian PCAP-NG capture.

    One Section Header Block, one Interface Description Block and one Enhanced
    Packet Block per frame, none of them carrying options.

    Args:
        path: Destination, as anything :func:`open` accepts.
        frames: Raw link-layer frames, which become the packet data.

    Returns:
        The destination as a :obj:`str`, ready to hand to ``extract(fin=...)``.

    """
    def block(block_type: 'int', body: 'bytes') -> 'bytes':
        body += b'\x00' * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack('<II', block_type, length) + body + struct.pack('<I', length)

    data = block(BLOCK_SECTION_HEADER, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    data += block(BLOCK_INTERFACE_DESCRIPTION,
                  struct.pack('<HHI', LINKTYPE_ETHERNET, 0, 0x40000))
    for index, frame in enumerate(frames):
        data += block(BLOCK_ENHANCED_PACKET,
                      struct.pack('<IIIII', 0, 0, index, len(frame), len(frame))
                      + frame + b'\x00' * (-len(frame) % 4))

    with open(path, 'wb') as file:
        file.write(data)
    return str(path)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6AdapterParityTests(EndToEndTestCase):
    """Every available toolkit adapter, over the fragments of ``ipv6.pcap``."""

    def adapter_packets(self) -> 'dict[str, list]':
        """Run each available adapter and collect its fragments in wire order.

        Returns:
            Adapter name to the :term:`reasm.ipv6.packet` it built for each
            fragment. Adapters whose engine is not installed are absent.

        """
        from pcapkit.toolkit import pcap as pcap_toolkit
        from pcapkit.toolkit import pcapng as pcapng_toolkit

        frames = pcap_frames(sample_path('ipv6.pcap'))
        packets = {}  # type: dict[str, list]

        # the committed capture, through the default engine
        extractor = self.extract(fin=sample_path('ipv6.pcap'), nofile=True, store=True,
                                 ipv6=True, reassembly=True)
        packets['pcap'] = [data for frame in extractor.frame
                           if (data := pcap_toolkit.ipv6_reassembly(frame)) is not None]

        # the same frames as PCAP-NG, so the two formats meet on the same octets
        pcapng = write_pcapng(self.tmp_path / 'ipv6.pcapng', frames)
        extractor = self.extract(fin=pcapng, nofile=True, store=True,
                                 ipv6=True, reassembly=True)
        packets['pcapng'] = [data for block in extractor.frame
                             if (data := pcapng_toolkit.ipv6_reassembly(block)) is not None]

        if HAS_DPKT:
            import dpkt

            from pcapkit.toolkit import dpkt as dpkt_toolkit
            # ``pcap_frames`` hands back the record octets alone, so the capture
            # timestamp has to be supplied here -- one value for every fragment,
            # both because they are one datagram and because the fields compared
            # below must not depend on which fragment is being looked at
            packets['dpkt'] = [
                data for number, frame in enumerate(frames, start=1)
                if (data := dpkt_toolkit.ipv6_reassembly(
                    dpkt.ethernet.Ethernet(frame), 0.0, count=number)) is not None
            ]

        if HAS_SCAPY:
            from scapy.layers.l2 import Ether

            from pcapkit.toolkit import scapy as scapy_toolkit
            packets['scapy'] = [
                data for number, frame in enumerate(frames, start=1)
                if (data := scapy_toolkit.ipv6_reassembly(
                    Ether(frame), count=number)) is not None
            ]

        return packets

    def test_every_adapter_finds_the_same_four_fragments(self) -> None:
        packets = self.adapter_packets()

        # both format adapters are always available; the other two are gated
        self.assertIn('pcap', packets)
        self.assertIn('pcapng', packets)
        for name, fragments in packets.items():
            with self.subTest(adapter=name):
                self.assertEqual([(data.fo, len(data.payload)) for data in fragments],
                                 list(FRAGMENTS))

    def test_every_adapter_reports_the_rfc_ihl_header_and_tl(self) -> None:
        """``ihl``, ``header`` and ``tl`` leave the Fragment header out.

        The three fields of #415, asserted for every adapter against the values
        :rfc:`8200#section-4.5` calls for: the Fragment header is not present in
        the reassembled packet, so none of the three may count its 8 octets.

        """
        packets = self.adapter_packets()

        for name, fragments in packets.items():
            self.assertEqual(len(fragments), len(FRAGMENTS), name)
            for data, (offset, payload_len) in zip(fragments, FRAGMENTS):
                with self.subTest(adapter=name, fragment=offset):
                    self.assertEqual(data.ihl, IPV6_HDR_LEN)
                    self.assertEqual(len(data.header), IPV6_HDR_LEN)
                    self.assertEqual(data.tl, IPV6_HDR_LEN + payload_len)
                    # the invariant the reassembly machinery relies on: it writes the
                    # payload into its datagram buffer over the span ``tl - ihl``, so
                    # a ``tl`` 8 octets too large leaves 8 stray zeroes per fragment
                    self.assertEqual(data.tl - data.ihl, payload_len)

    def test_the_fragment_header_octets_are_the_ones_left_out(self) -> None:
        """The 40 octets kept are the IPv6 header, not an arbitrary prefix.

        A ``header`` of the right *length* could still be the wrong 40 octets, so
        this pins what they are: the fixed IPv6 header, still pointing at the
        Fragment header, which is what the fragment on the wire says. Rewriting
        that field is the reassembler's job, not the adapter's -- see
        :class:`IPv6DatagramHeaderTests`.

        """
        packets = self.adapter_packets()

        for name, fragments in packets.items():
            with self.subTest(adapter=name):
                header = fragments[0].header
                self.assertEqual(header[0] >> 4, 6)             # IPv6 version
                self.assertEqual(header[6], NH_IPV6_FRAG)       # Next Header
                # the Payload Length field spans the Fragment header and the
                # fragment's payload, i.e. 8 octets more than ``tl - ihl``
                self.assertEqual(struct.unpack_from('>H', header, 4)[0],
                                 8 + FRAGMENTS[0][1])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6DatagramHeaderTests(EndToEndTestCase):
    """What the *reassembled* datagram's header says.

    :rfc:`8200#section-4.5` -- "The Fragment header is not present in the
    reassembled packet", and "the Next Header field of the last header of the
    Unfragmentable Part is obtained from the Next Header field of the first
    fragment's Fragment header". Guards against an engine leaving the field
    alone, so that the reassembled datagram advertises a Fragment header on a
    datagram that is by definition no longer a fragment.

    """

    def engines(self) -> 'list[str]':
        return (['default']
                + (['dpkt'] if HAS_DPKT else [])
                + (['scapy'] if HAS_SCAPY else []))

    def test_no_engine_advertises_a_fragment_header_on_the_datagram(self) -> None:
        for engine in self.engines():
            with self.subTest(engine=engine):
                extractor = self.extract(fin=sample_path('ipv6.pcap'), nofile=True,
                                         store=False, ipv6=True, reassembly=True,
                                         reasm_strict=True, engine=engine)
                datagram, = extractor.reassembly.ipv6

                self.assertTrue(datagram.completed)
                self.assertEqual(len(datagram.header), IPV6_HDR_LEN)
                # the Fragment header's own Next Header value, moved up
                self.assertEqual(datagram.header[6], NH_UDP)
                self.assertNotEqual(datagram.header[6], NH_IPV6_FRAG)
                self.assertEqual(int(datagram.id.proto), NH_UDP)

    def test_every_engine_reassembles_the_captured_payload(self) -> None:
        """The datagram itself, not only its header.

        Guards against ``scapy``'s ``tl`` counting the Fragment header while its
        ``ihl`` does not, under which the reassembly machinery writes each
        fragment's payload over a span 8 octets too wide and the datagram comes
        out 4786 octets instead of 4778 --
        eight stray zeroes per fragment boundary. Each engine's datagram is the
        fragments' payloads as captured, read past the Ethernet, IPv6 and
        Fragment headers of frames 13 to 16.

        """
        captured = b''.join(frame[14 + IPV6_HDR_LEN + 8:]
                            for frame in pcap_frames(sample_path('ipv6.pcap'))[12:16])
        self.assertEqual(len(captured), sum(length for _, length in FRAGMENTS))
        for engine in self.engines():
            with self.subTest(engine=engine):
                extractor = self.extract(fin=sample_path('ipv6.pcap'), nofile=True,
                                         store=False, ipv6=True, reassembly=True,
                                         reasm_strict=True, engine=engine)
                datagram, = extractor.reassembly.ipv6
                payload = bytes(datagram.payload)
                self.assertEqual(len(payload), 4778)
                self.assertEqual(payload, captured)


if __name__ == '__main__':
    unittest.main()
