from __future__ import annotations

import importlib.util
import pathlib
import struct
import tempfile
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Ethernet header of every synthetic frame, with an IPv6 ethertype.
ETHER = bytes.fromhex('801f12c9d13d') + bytes.fromhex('000c29aab15e') + b'\x86\xdd'

#: Link-local endpoints of the synthetic datagrams.
SRC_ADDR = bytes.fromhex('fe80000000000000a423b61d7c9270c6')
DST_ADDR = bytes.fromhex('fe80000000000000821f12fffec9d13d')

#: Next-header value of the IPv6 Fragment header, and of the payload it carries.
NH_FRAG = 44
NH_UDP = 17

#: PCAP file header: little-endian magic, version 2.4, LINKTYPE_ETHERNET.
PCAP_HEADER = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)


def fragment(label: int, ident: int, offset_units: int, more: bool, payload: bytes) -> bytes:
    """Build one Ethernet-framed IPv6 fragment.

    Args:
        label: IPv6 header flow label, bits 12-31 of the first hextet.
        ident: IPv6 Fragment header identification.
        offset_units: Fragment offset, in the on-wire 8-octet units of
            :rfc:`8200#section-4.5` -- *not* in octets.
        more: More Fragments flag.
        payload: The fragment's slice of the fragmentable part.

    Returns:
        The complete frame, ready to be written into a PCAP file.

    """
    length = 8 + len(payload)
    header = struct.pack('>IHBB', (6 << 28) | label, length, NH_FRAG, 64) + SRC_ADDR + DST_ADDR
    frag = struct.pack('>BBHI', NH_UDP, 0, (offset_units << 3) | int(more), ident)
    return ETHER + header + frag + payload


def write_pcap(path: pathlib.Path, frames: list[bytes]) -> str:
    """Write ``frames`` into a PCAP file at ``path`` and return it as a :obj:`str`."""
    with open(path, 'wb') as file:
        file.write(PCAP_HEADER)
        for index, frame in enumerate(frames):
            file.write(struct.pack('<IIII', 1700000000 + index, 0, len(frame), len(frame)))
            file.write(frame)
    return str(path)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ReassemblyRuntimeTests(unittest.TestCase):
    """End-to-end IPv6 reassembly over synthetic captures.

    The captures are built here rather than read from :file:`examples/captures/`
    because the committed samples are pinned byte-for-byte by other tests and
    none of them holds two concurrently fragmented datagrams.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmp_path = pathlib.Path(self._tmpdir.name)

    def _reassemble(self, frames: list[bytes]) -> list:
        """Extract ``frames`` with IPv6 reassembly enabled and return the datagrams."""
        import pcapkit

        capture = write_pcap(self.tmp_path / 'synthetic.pcap', frames)
        extractor = pcapkit.extract(fin=capture, nofile=True, store=False,
                                    ipv6=True, reassembly=True, reasm_strict=True)
        self.addCleanup(close_extractor, extractor)
        return list(extractor.reassembly.ipv6)

    @staticmethod
    def _payload(datagram) -> bytes:
        """Flatten a datagram payload, whether it is complete or fragmented."""
        if isinstance(datagram.payload, bytes):
            return datagram.payload
        return b''.join(datagram.payload)

    def test_fragment_offsets_are_octets_so_the_payload_reassembles_intact(self) -> None:
        """A fragmented datagram must come back as the exact original octets.

        The on-wire Fragment Offset counts 8-octet units, while the reassembly
        machinery indexes its datagram buffer in octets. Feeding the raw unit
        count straight through places every fragment at an eighth of its true
        offset, so the fragments overwrite one another and the datagram is
        silently truncated -- and, because the received-bit table is indexed by
        ``FO // 8``, still reported ``completed=True``.

        The assertion is on the payload *bytes*: a length-only check passes on a
        datagram whose fragments have been scrambled into the right total size.

        """
        # a distinguishable body, so a misplaced fragment shows up as wrong bytes
        # and not merely as a wrong length
        body = bytes((index * 7 + 11) & 0xFF for index in range(1536))
        first, second = body[:1024], body[1024:]
        self.assertEqual(len(first) % 8, 0)  # fragments must be 8-octet aligned

        datagrams = self._reassemble([
            fragment(0x12345, 7001, 0, True, first),
            fragment(0x12345, 7001, len(first) // 8, False, second),
        ])

        self.assertEqual(len(datagrams), 1)
        datagram = datagrams[0]
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.index, (1, 2))
        # the payload bytes, not just their count
        self.assertEqual(self._payload(datagram), body)
        self.assertEqual(len(self._payload(datagram)), 1536)
        # the truncation the unscaled offset produced: 128 units + 512 octets
        self.assertNotEqual(len(self._payload(datagram)), 640)

    def test_reassembly_keys_on_identification_not_flow_label(self) -> None:
        """Two datagrams sharing a flow label must not be merged into one.

        :rfc:`8200#section-4.5` reassembles only from fragments sharing a source
        address, destination address and Fragment Identification. The flow label
        carries no such guarantee -- :rfc:`6437` permits a constant or zero
        label, and zero is the common case -- so keying the reassembly buffer on
        it collapses concurrent datagrams into one.

        A single-datagram capture cannot show this: the consequence only appears
        once two datagrams share a label, which is why the capture is built here.

        """
        label = 0x12345
        # disjoint alphabets -- every octet of ``alpha`` is even and every octet
        # of ``beta`` is odd -- so that a merged payload can be caught by a census
        # as well as by comparing bytes, and neither body is a run of one value
        alpha = bytes((index * 2) & 0xFE for index in range(1536))
        beta = bytes(((index * 2) & 0xFE) | 1 for index in range(1536))
        self.assertNotEqual(alpha, beta)

        # interleaved A1 B1 A2 B2, both datagrams carrying the same flow label
        datagrams = self._reassemble([
            fragment(label, 1001, 0, True, alpha[:1024]),
            fragment(label, 2002, 0, True, beta[:1024]),
            fragment(label, 1001, 128, False, alpha[1024:]),
            fragment(label, 2002, 128, False, beta[1024:]),
        ])

        self.assertEqual(len(datagrams), 2)
        for datagram in datagrams:
            self.assertTrue(datagram.completed)
        by_id = {datagram.id.id: datagram for datagram in datagrams}

        # the identification, not the flow label -- keying on the label reports
        # both datagrams under ``id.id`` 0x12345 and loses one of them
        self.assertEqual(sorted(by_id), [1001, 2002])
        self.assertNotIn(label, by_id)

        # payload bytes, so that a merge which happens to total the right length
        # is still caught
        self.assertEqual(self._payload(by_id[1001]), alpha)
        self.assertEqual(self._payload(by_id[2002]), beta)
        # and neither datagram may hold a single octet from the other: the merge
        # this guards against delivered 552 of one body's octets and 181 of the
        # other's in one payload, reported ``completed=True``
        self.assertTrue(all(octet % 2 == 0 for octet in self._payload(by_id[1001])))
        self.assertTrue(all(octet % 2 == 1 for octet in self._payload(by_id[2002])))

        self.assertEqual(by_id[1001].index, (1, 3))
        self.assertEqual(by_id[2002].index, (2, 4))

    def test_distinct_flow_labels_do_not_split_one_identification(self) -> None:
        """Fragments of one datagram must reassemble even if their labels differ.

        The mirror image of the test above, and the case a flow-label-keyed
        buffer gets wrong in the opposite direction: the flow label is not
        covered by the reassembly key at all, so two fragments carrying the same
        identification belong to the same datagram whatever their labels say.

        """
        body = bytes((index * 11 + 3) & 0xFF for index in range(1200))

        datagrams = self._reassemble([
            fragment(0x11111, 3003, 0, True, body[:1024]),
            fragment(0x22222, 3003, 128, False, body[1024:]),
        ])

        self.assertEqual(len(datagrams), 1)
        self.assertTrue(datagrams[0].completed)
        self.assertEqual(datagrams[0].id.id, 3003)
        self.assertEqual(self._payload(datagrams[0]), body)

    def test_three_fragment_datagram_reassembles_in_wire_order(self) -> None:
        """More than two fragments, delivered out of order.

        Two fragments can be reassembled correctly by an implementation that
        merely appends in arrival order; three delivered out of order cannot.

        """
        body = bytes((index * 13 + 5) & 0xFF for index in range(2048))
        parts = [body[0:1024], body[1024:1536], body[1536:]]

        datagrams = self._reassemble([
            fragment(0, 4004, 128, True, parts[1]),   # middle first
            fragment(0, 4004, 192, False, parts[2]),  # then the last
            fragment(0, 4004, 0, True, parts[0]),     # and the first last
        ])

        self.assertEqual(len(datagrams), 1)
        self.assertTrue(datagrams[0].completed)
        self.assertEqual(datagrams[0].id.id, 4004)
        self.assertEqual(self._payload(datagrams[0]), body)
        # a zero flow label is the common case and must not become the buffer key
        self.assertNotEqual(datagrams[0].id.id, 0)
