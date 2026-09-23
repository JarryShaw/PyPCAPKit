from __future__ import annotations

import importlib.util
import pathlib
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Block types that carry captured packet octets, i.e. the three whose schema
#: declares a ``__payload__``. Spelled as the wire values so that the test does
#: not have to import the library to know what it is looking for.
BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 0x00000001
BLOCK_PACKET = 0x00000002  # obsolete Packet Block
BLOCK_SPB = 0x00000003
BLOCK_EPB = 0x00000006

#: First sixteen and last sixteen octets of the first Enhanced Packet Block's
#: captured data in :file:`examples/captures/dhcp.pcapng`: a broadcast Ethernet
#: destination, the client's source address, ethertype 0x0800, and the head of the
#: IPv4 header; then the tail of the BOOTP payload. Spelled out so that a reader
#: can see the octets #646 dropped, and so that an off-by-a-field payload offset
#: fails rather than merely reporting the right length.
DHCP_EPB0_HEAD = bytes.fromhex('ffffffffffff000b8201fc4208004500')
DHCP_EPB0_TAIL = bytes.fromhex('000037040103062aff00000000000000')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_dhcp_pcapng_extracts_successfully(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path('dhcp.pcapng'), fout='/tmp/out', format='tree', store=True, nofile=True)
        self.assertGreater(extractor.length, 0)

    def test_dhcp_big_endian_pcapng_extracts_successfully(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path('dhcp_big_endian.pcapng'), fout='/tmp/out', format='tree', store=True, nofile=True)
        self.assertGreater(extractor.length, 0)

    def test_dhcp_little_endian_pcapng_extracts_successfully(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path('dhcp_little_endian.pcapng'), fout='/tmp/out', format='tree', store=True, nofile=True)
        self.assertGreater(extractor.length, 0)

    def test_additional_pcapng_samples_extract_successfully(self) -> None:
        from pcapkit.interface import extract

        samples = (
            'test.pcapng',
            'many_interfaces.pcapng',
            'profile.pcapng',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                extractor = extract(fin=sample_path(sample), fout='/tmp/out', format='tree', store=True, nofile=True)
                self.assertGreater(extractor.length, 0)


def _pad32(data: bytes) -> bytes:
    """Pad ``data`` out to a 32-bit boundary, the way every PCAP-NG block body is."""
    return data + b'\x00' * ((4 - len(data) % 4) % 4)


def _block(block_type: int, body: bytes, endian: str = '<') -> bytes:
    """Wrap ``body`` in a PCAP-NG block frame of the given byte order."""
    total = 12 + len(body)
    return struct.pack(endian + 'II', block_type, total) + body + struct.pack(endian + 'I', total)


def _option(code: int, value: bytes, endian: str = '<') -> bytes:
    """One PCAP-NG option: a 2-octet code, a 2-octet length, and padded value."""
    return struct.pack(endian + 'HH', code, len(value)) + _pad32(value)


def _ethernet(tail: bytes) -> bytes:
    """A well-formed Ethernet frame carrying ``tail`` under an unassigned ethertype.

    0x88B5 is reserved for local experimental use, so the link layer decodes and
    the octets after it stay raw -- the point here is the octets, not what they
    would have meant.

    """
    return (b'\x02\x00\x00\x00\x00\x01'
            + b'\x02\x00\x00\x00\x00\x02'
            + struct.pack('>H', 0x88B5)
            + tail)


#: One payload per payload-carrying block type, each a different length modulo 4
#: (0, 3 and 3 octets of block padding respectively) so that a payload offset
#: computed from the wrong field, or a payload taken with its padding attached,
#: cannot pass by coincidence.
SYNTH_PAYLOADS = {
    BLOCK_EPB: _ethernet(b'EPB-payload-\x11\x22\x33\x44\x55\x66'),
    BLOCK_SPB: _ethernet(b'SPB!\xa0\xa1\xa2\xa3\xa4'),
    BLOCK_PACKET: _ethernet(b'obsolete-Packet-Block-\xde\xad\xbe'),
}


def _synthetic_pcapng(endian: str = '<') -> bytes:
    """A PCAP-NG file holding one block of every payload-carrying type.

    No committed fixture has a Simple Packet Block or an (obsolete) Packet Block --
    :file:`examples/captures/dhcp.pcapng` is all Enhanced Packet Blocks -- so the
    other two are built here rather than generated, which also keeps the expected
    octets in the same file as the assertion.

    Both packet blocks that can carry options are given some, which no fixture
    exercises: ``dhcp.pcapng``'s four blocks all have an empty option area. Options
    sit *after* the captured data, so a payload offset walked from the wrong end --
    or one derived by subtracting a trailer of assumed size -- reads them as
    payload, and a block with none cannot tell the difference.

    """
    timestamp = 0x0005D0F012345678

    # The byte-order magic is written in the section's own order, which is how a
    # reader detects that order in the first place.
    shb = _block(BLOCK_SHB, struct.pack(endian + 'IHHq', 0x1A2B3C4D, 1, 0, -1), endian)
    # ETHERNET, snaplen 65535.
    idb = _block(BLOCK_IDB, struct.pack(endian + 'HHI', 1, 0, 0xFFFF), endian)

    # epb_flags (code 2, four octets) then opt_endofopt (code 0, empty).
    options = _option(2, struct.pack(endian + 'I', 0), endian) + _option(0, b'', endian)

    epb_payload = SYNTH_PAYLOADS[BLOCK_EPB]
    epb = _block(BLOCK_EPB,
                 struct.pack(endian + 'IIIII', 0, timestamp >> 32, timestamp & 0xFFFFFFFF,
                             len(epb_payload), len(epb_payload))
                 + _pad32(epb_payload) + options, endian)

    # A Simple Packet Block carries no option area at all, by specification.
    spb_payload = SYNTH_PAYLOADS[BLOCK_SPB]
    spb = _block(BLOCK_SPB,
                 struct.pack(endian + 'I', len(spb_payload)) + _pad32(spb_payload), endian)

    pkb_payload = SYNTH_PAYLOADS[BLOCK_PACKET]
    pkb = _block(BLOCK_PACKET,
                 struct.pack(endian + 'HHIIII', 0, 0, timestamp >> 32, timestamp & 0xFFFFFFFF,
                             len(pkb_payload), len(pkb_payload))
                 + _pad32(pkb_payload) + options, endian)

    return shb + idb + epb + spb + pkb


def _epb_payloads_from_octets(raw: bytes) -> 'list[bytes]':
    """Hand-parse the captured octets of every Enhanced Packet Block in ``raw``.

    Deliberately written with :mod:`struct` alone, so that the expected values owe
    nothing to the code under test: an Enhanced Packet Block puts its captured data
    28 octets in, after the block type, the total length, the interface ID, the two
    timestamp halves and the two lengths.

    """
    payloads = []
    offset = 0
    while offset + 12 <= len(raw):
        block_type, total = struct.unpack_from('<II', raw, offset)
        if total < 12 or offset + total > len(raw):
            break
        if block_type == BLOCK_EPB:
            captured_len = struct.unpack_from('<I', raw, offset + 20)[0]
            payloads.append(raw[offset + 28:offset + 28 + captured_len])
        offset += total
    return payloads


def _pcap_records(raw: bytes) -> 'list[tuple[int, int, bytes]]':
    """Hand-parse a PCAP file into ``(incl_len, orig_len, octets)`` per record.

    Walks by ``incl_len``, which is how every PCAP reader finds the next record, so
    a record header promising octets it did not deliver desynchronises here exactly
    as it does in a real reader instead of being quietly tolerated.

    """
    records = []
    offset = 24  # global header
    while offset + 16 <= len(raw):
        _, _, incl_len, orig_len = struct.unpack_from('<IIII', raw, offset)
        octets = raw[offset + 16:offset + 16 + incl_len]
        records.append((incl_len, orig_len, octets))
        offset += 16 + incl_len
    return records


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngPayloadOctetsTests(unittest.TestCase):
    """Every PCAP-NG packet block must carry the octets it declares -- see #646.

    ``PCAPNG.unpack`` computed the captured octets correctly and
    ``ProtocolBase.__init__`` then overwrote them with ``self.packet.payload``,
    which was empty because the inherited ``packet`` split the block at
    ``PCAPNG.length`` -- the wire's *Block Total Length*, not a header length -- and
    so consumed the whole block as header. ``captured_len`` is read straight off the
    block header and survived, which is why the two disagreed.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, path: str) -> 'object':
        from pcapkit.interface import extract

        with warnings.catch_warnings():
            # The obsolete Packet Block warns twice by design, and a capture ending
            # at its last block warns ``EOF reached``; neither is under test here.
            warnings.simplefilter('ignore')
            extractor = extract(fin=path, store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_dhcp_pcapng_blocks_carry_their_captured_octets(self) -> None:
        """Each Enhanced Packet Block of the committed fixture keeps its own octets."""
        path = sample_path('dhcp.pcapng')
        expected = _epb_payloads_from_octets(pathlib.Path(path).read_bytes())
        self.assertEqual(len(expected), 4)

        extractor = self._extract(path)
        frames = list(extractor.frame)  # type: ignore[attr-defined]
        self.assertEqual(len(frames), len(expected))

        for index, (frame, octets) in enumerate(zip(frames, expected)):
            with self.subTest(frame=index):
                packet = bytes(frame.info.packet)
                self.assertEqual(packet, octets)
                self.assertEqual(len(packet), frame.info.captured_len)

    def test_dhcp_pcapng_first_block_octets_are_the_expected_ethernet_frame(self) -> None:
        """The first block's octets are the DHCP discover, head and tail spelled out.

        A length assertion alone passes under several wrong fixes -- a payload read
        from the wrong offset, or one that picked up the block's 32-bit padding --
        so the boundaries are pinned to literals.

        """
        extractor = self._extract(sample_path('dhcp.pcapng'))
        packet = bytes(next(iter(extractor.frame)).info.packet)  # type: ignore[attr-defined]

        self.assertEqual(len(packet), 314)
        self.assertEqual(packet[:16], DHCP_EPB0_HEAD)
        self.assertEqual(packet[-16:], DHCP_EPB0_TAIL)

    def test_every_payload_carrying_block_type_carries_its_octets(self) -> None:
        """EPB, SPB and the obsolete Packet Block each keep their own payload.

        All three declare ``__payload__ = 'packet_data'`` and all three put it at a
        different offset, so a fix that only reached the Enhanced Packet Block --
        the only type any committed fixture has -- would pass the test above and
        still corrupt the other two.

        Run over both byte orders. The offset of the captured data is the same in
        either, but the fields it is summed from are not, so a byte order the walk
        mishandled would show up as a payload read from the wrong place.

        """
        for endian, name in (('<', 'little'), ('>', 'big')):
            with tempfile.TemporaryDirectory() as temp:
                path = pathlib.Path(temp) / 'three_block_types.pcapng'
                path.write_bytes(_synthetic_pcapng(endian))

                extractor = self._extract(str(path))
                frames = list(extractor.frame)  # type: ignore[attr-defined]

            self.assertEqual(len(frames), 3)
            seen = set()
            for frame in frames:
                block_type = int(frame.info.type)
                seen.add(block_type)
                with self.subTest(byteorder=name, block_type=hex(block_type)):
                    self.assertEqual(bytes(frame.info.packet), SYNTH_PAYLOADS[block_type])
                    self.assertEqual(bytes(frame.packet.payload), SYNTH_PAYLOADS[block_type])
                    self.assertEqual(len(frame.info.packet), frame.info.captured_len)
            self.assertEqual(seen, set(SYNTH_PAYLOADS))

    def test_a_snapped_block_carries_the_octets_that_are_present(self) -> None:
        """``captured_len`` below ``original_len`` yields the captured octets only.

        Two shapes of snapping, because the two block types express it differently:
        an Enhanced Packet Block declares both lengths, while a Simple Packet Block
        declares only the on-wire one and has its captured length bounded by the
        interface's ``snaplen``. Neither may come back padded out to the on-wire
        length, and neither may come back empty.

        """
        timestamp = 0x0005D0F012345678
        wire = _ethernet(b'0123456789abcdefghij')          # 34 octets on the wire
        snaplen = 20
        captured = wire[:snaplen]

        shb = _block(BLOCK_SHB, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        idb = _block(BLOCK_IDB, struct.pack('<HHI', 1, 0, snaplen))
        epb = _block(BLOCK_EPB,
                     struct.pack('<IIIII', 0, timestamp >> 32, timestamp & 0xFFFFFFFF,
                                 len(captured), len(wire)) + _pad32(captured))
        spb = _block(BLOCK_SPB, struct.pack('<I', len(wire)) + _pad32(captured))

        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'snapped.pcapng'
            path.write_bytes(shb + idb + epb + spb)

            extractor = self._extract(str(path))
            frames = list(extractor.frame)  # type: ignore[attr-defined]

        self.assertEqual(len(frames), 2)
        for frame in frames:
            with self.subTest(block_type=hex(int(frame.info.type))):
                self.assertEqual(bytes(frame.info.packet), captured)
                self.assertEqual(len(frame.info.packet), frame.info.captured_len)
                self.assertEqual(frame.info.original_len, len(wire))

    def test_packet_header_and_payload_partition_the_block_octets(self) -> None:
        """``packet.header`` is the octets ahead of the payload, not the whole block.

        The header used to be the entire block -- ``_read_packet(header=self.length)``
        with ``length`` being the Block Total Length -- which is the same bug seen
        from the other side.

        """
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'three_block_types.pcapng'
            path.write_bytes(_synthetic_pcapng())

            extractor = self._extract(str(path))
            frames = list(extractor.frame)  # type: ignore[attr-defined]

        # The offset of the captured data in each block type, counted from the block
        # type field: 28 for an EPB and for the obsolete Packet Block, 12 for an SPB.
        offsets = {BLOCK_EPB: 28, BLOCK_SPB: 12, BLOCK_PACKET: 28}
        for frame in frames:
            block_type = int(frame.info.type)
            with self.subTest(block_type=hex(block_type)):
                header = bytes(frame.packet.header)
                payload = bytes(frame.packet.payload)
                self.assertEqual(len(header), offsets[block_type])
                self.assertEqual(header + payload,
                                 bytes(frame._data)[:len(header) + len(payload)])

    def test_blocks_without_a_payload_field_stay_empty(self) -> None:
        """A block type that carries no captured octets keeps reporting none.

        Guards the other direction: the Section Header and Interface Description
        blocks declare no ``__payload__``, and must not start reporting their own
        body as a payload.

        """
        from pcapkit.protocols.misc.pcapng import PCAPNG

        # ``extractor.frame`` holds only the packet blocks, so these two are read
        # directly to reach their ``packet`` field at all.
        raw = _synthetic_pcapng()
        shb_len = struct.unpack_from('<I', raw, 4)[0]
        for name, offset in (('SHB', 0), ('IDB', shb_len)):
            with self.subTest(block=name):
                block_type, total = struct.unpack_from('<II', raw, offset)
                self.assertIn(block_type, (BLOCK_SHB, BLOCK_IDB))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    protocol = PCAPNG(raw[offset:offset + total], num=0, sct=0, ctx=None)
                self.assertEqual(bytes(protocol.info.packet), b'')
                self.assertEqual(bytes(protocol.packet.payload), b'')

    def test_dumped_pcap_carries_the_payload_octets(self) -> None:
        """A PCAP-NG block dumped through :class:`PCAPIO` writes the octets it promises.

        This is where the defect stopped being an API wart: the record headers came
        out 16 octets apart, each declaring hundreds of octets and delivering none,
        which desynchronises every reader that walks by ``incl_len``.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.toolkit.pcapng import block2frame

        source = sample_path('dhcp.pcapng')
        expected = _epb_payloads_from_octets(pathlib.Path(source).read_bytes())
        extractor = self._extract(source)

        with tempfile.TemporaryDirectory() as temp:
            out = pathlib.Path(temp) / 'dumped.pcap'
            dumper = PCAPIO(str(out), protocol=LinkType.ETHERNET, byteorder='little')
            for frame in extractor.frame:  # type: ignore[attr-defined]
                dumper(block2frame(frame.info))

            dumped = out.read_bytes()

        records = _pcap_records(dumped)
        self.assertEqual(len(records), len(expected))
        for index, ((incl_len, orig_len, octets), payload) in enumerate(zip(records, expected)):
            with self.subTest(record=index):
                self.assertEqual(incl_len, len(payload))
                self.assertEqual(octets, payload)
                self.assertGreaterEqual(orig_len, incl_len)

        # 24 octets of global header, then 16 of record header and the payload per
        # record, with nothing left over. Before #646 this file was 104 octets for
        # these four blocks -- the global header and four record headers, and not one
        # octet of payload -- which is both the wrong size and, worse, a size a
        # reader cannot tell is wrong until it has already lost frame sync.
        self.assertEqual(len(dumped), 24 + sum(16 + len(payload) for payload in expected))
        self.assertNotEqual(len(dumped), 104)


if __name__ == '__main__':
    unittest.main()
