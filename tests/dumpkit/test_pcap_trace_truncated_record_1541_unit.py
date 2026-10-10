# -*- coding: utf-8 -*-
"""A PCAP trace writes the octets a record has, not its claimed length. C.f. #1541.

A record whose ``incl_len`` runs past the end of its file, or a PCAP-NG block
whose captured length runs past the block (#1405), is kept as captured by its
reader: the declared length stays in ``frame_info`` and the packet is the octets
present. :class:`~pcapkit.dumpkit.pcap.PCAPIO` copied the declared length into the
trace record header, so the trace claimed octets it did not hold -- measured on a
record claiming ``0x7fffffff`` over 585 octets.

Each case traces a TCP flow whose last record is cut that way, then reads the
trace back with :mod:`struct` alone: every record must hold exactly ``incl_len``
octets, and the last must end the file.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import io
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation._roundtrip import ethernet, ipv4, pcap, pcapng, tcp

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

SECOND = 1_500_000_000
#: Captured lengths a cut record declares: a little past the data, and the
#: measured case.
CLAIMS = (1000, 0x7FFF_FFFF)


def _frames() -> 'list[bytes]':
    """Three TCP segments of one connection, client to server."""
    return [ethernet(ipv4(tcp(b'x' * number, seq=1000 + number, syn=not number), proto=6), 0x0800)
            for number in range(3)]


def _records(data: 'bytes') -> 'list[tuple[int, int, bytes]]':
    """Every record of a little-endian PCAP file, refusing one that runs past it."""
    records, offset = [], 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise AssertionError(f'{len(data) - offset} octet(s) after the last record')
        _, _, incl, orig = struct.unpack_from('<IIII', data, offset)
        if offset + 16 + incl > len(data):
            raise AssertionError(f'record at {offset} claims {incl} octet(s), '
                                 f'the file holds {len(data) - offset - 16}')
        records.append((incl, orig, data[offset + 16:offset + 16 + incl]))
        offset += 16 + incl
    return records


def _cut_pcap(claim: 'int') -> 'bytes':
    """A PCAP file whose last record claims ``claim`` octets and holds its frame."""
    frames = _frames()
    data = pcap([(SECOND + number, 0, frame) for number, frame in enumerate(frames[:-1])])
    return data + struct.pack('<IIII', SECOND + 2, 0, claim, len(frames[-1])) + frames[-1]


def _overrun_pcapng(claim: 'int') -> 'bytes':
    """A PCAP-NG file whose last EPB declares ``claim`` octets over its frame (#1405)."""
    frames = _frames()
    data = pcapng([(SECOND + number, 0, frame) for number, frame in enumerate(frames[:-1])])
    ticks = (SECOND + 2) * 10 ** 6
    body = struct.pack('<IIIII', 0, ticks >> 32, ticks & 0xFFFF_FFFF, claim, len(frames[-1])) + frames[-1]
    body += bytes(-len(body) % 4)
    return data + struct.pack('<II', 6, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestPCAPTraceTruncatedRecord(unittest.TestCase):
    """A traced record's ``incl_len`` is the number of octets written after it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)

    def trace(self, data: 'bytes') -> 'bytes':
        """The PCAP file of the one TCP flow traced from ``data``."""
        from pcapkit import extract

        tracedir = tempfile.mkdtemp(dir=self.tmpdir.name)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(data), nofile=True, store=False, trace=True, tcp=True,
                                trace_fout=tracedir, trace_format='pcap', trace_byteorder='little')
        close_extractor(extractor)
        flows = list(extractor.trace.tcp)
        self.assertEqual([list(flow.index) for flow in flows], [[1, 2, 3]])
        with open(flows[0].fpout, 'rb') as file:
            return file.read()

    def check(self, trace: 'bytes', held: 'bytes') -> None:
        """The trace holds every frame whole, the cut one as the octets it has."""
        frames, records = _frames(), _records(trace)
        self.assertEqual([octets for _, _, octets in records], frames[:-1] + [held])
        self.assertEqual([(incl, orig) for incl, orig, _ in records],
                         [(len(frame), len(frame)) for frame in frames[:-1]] + [(len(held), len(frames[-1]))])

    def test_a_pcap_record_cut_at_eof_is_traced_as_the_octets_it_has(self) -> None:
        """#1541: a record claiming more than the file holds writes what it holds."""
        for claim in CLAIMS:
            with self.subTest(claim=claim):
                self.check(self.trace(_cut_pcap(claim)), _frames()[-1])

    def test_a_pcapng_captured_length_past_its_block_is_traced_as_the_octets_it_has(self) -> None:
        """#1541: so does an EPB whose captured length runs past the block (#1405)."""
        for claim in CLAIMS:
            with self.subTest(claim=claim):
                self.check(self.trace(_overrun_pcapng(claim)), _frames()[-1])

    def test_a_pcapng_block_cut_at_eof_is_traced_as_the_octets_it_has(self) -> None:
        """#1541: and an EPB the file ends inside, which holds two octets fewer than it claims."""
        data = pcapng([(SECOND + number, 0, frame) for number, frame in enumerate(_frames())])
        # the trailing Block Total Length, then the last two octets of the frame
        self.check(self.trace(data[:-6]), _frames()[-1][:-2])

    def test_the_dumper_writes_the_packet_length(self) -> None:
        """#1541: ``incl_len`` is ``len(packet)``, whatever ``frame_info`` declares."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        path = os.path.join(self.tmpdir.name, 'out.pcap')
        dumper = PCAPIO(path, protocol=LinkType.ETHERNET, byteorder='little', nanosecond=False)
        for incl_len, packet in ((0x7FFF_FFFF, b'abc'), (3, b'abc'), (0, b'')):
            frame = Frame(frame_info=FrameInfo(ts_sec=7, ts_usec=0, incl_len=incl_len, orig_len=86),
                          time='time', number=1, time_epoch=7, len=86, cap_len=incl_len)
            frame.__update__(packet=packet)
            dumper(frame)
        with open(path, 'rb') as file:
            self.assertEqual(_records(file.read()), [(3, 86, b'abc'), (3, 86, b'abc'), (0, 86, b'')])

    def test_a_whole_record_is_traced_unchanged(self) -> None:
        """A record the file holds whole keeps its octets, as before #1541."""
        data = pcap([(SECOND + number, 0, frame) for number, frame in enumerate(_frames())])
        self.assertEqual(self.trace(data)[24:].hex(), data[24:].hex())


if __name__ == '__main__':
    unittest.main()
