# -*- coding: utf-8 -*-
"""A capture snapped inside the TCP headers traces as the full one does (#1518).

Every frame of :file:`tcp.pcap` snapped by 4 octets, with its original length
kept, cuts four of its seven TCP headers short: frame 1 inside its options and
frames 2, 4 and 7 inside a Timestamps option. The TCP parser rejects those
headers by design (#1404), and the default engine's adapters used to skip the
frames, tracing ``(3, 5) (6,)``. :mod:`dpkt`, :mod:`scapy` and Wireshark's
``tcp.stream`` all trace ``(1, 2, 6, 7) (3, 4, 5)``, the flows of the full
capture, and so does the default engine now that its adapters read the fixed
20-octet header of a rejected segment.

The snapped capture is built in memory, as PCAP and as PCAP-NG. The module
reads the generated :file:`tcp.pcap`, so it belongs to the fixture-dependent
tier; :mod:`tests.toolkit.test_pcap_tcp_segment_unit` covers the adapters'
edge cases on frames built by hand.

"""
from __future__ import annotations

import importlib.util
import io
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))
ENGINES = tuple(name for name in ('dpkt', 'scapy') if importlib.util.find_spec(name) is not None)
CONTAINERS = ('pcap', 'pcapng')

#: ``(index, forward, reverse)`` of each bidirectional flow, as every engine and
#: Wireshark trace both the full and the snapped capture.
FLOWS = [((1, 2, 6, 7), (1, 7), (2, 6)), ((3, 4, 5), (3,), (4, 5))]
#: The same, one flow per direction.
UNIDIRECTIONAL = [((1, 7), (1, 7), ()), ((2, 6), (2, 6), ()), ((3,), (3,), ()), ((4, 5), (4, 5), ())]
#: Frame numbers of each reassembled TCP datagram, as :mod:`dpkt` gives them.
DATAGRAMS = [(2, 6), (3,), (4, 5)]


def snapped_records(cut: 'int' = 4) -> 'tuple[bytes, list[tuple[int, int, int, bytes]]]':
    """:file:`tcp.pcap`'s global header, and its ``(ts_sec, ts_usec, orig_len,
    octets)`` records with the last ``cut`` octets of each left uncaptured."""
    with open(sample_path('tcp.pcap'), 'rb') as file:
        data = file.read()
    header, rest, records = data[:24], data[24:], []
    while rest:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rest[:16])
        records.append((ts_sec, ts_usec, orig_len, rest[16:16 + incl_len - cut]))
        rest = rest[16 + incl_len:]
    return header, records


def _block(block_type: 'int', body: 'bytes') -> 'bytes':
    body += b'\x00' * (-len(body) % 4)
    return struct.pack('<II', block_type, len(body) + 12) + body + struct.pack('<I', len(body) + 12)


def snapped_capture(container: 'str') -> 'bytes':
    """The snapped capture, as a little-endian microsecond PCAP or PCAP-NG."""
    header, records = snapped_records()
    if container == 'pcap':
        return header + b''.join(struct.pack('<IIII', ts_sec, ts_usec, len(octets), orig_len) + octets
                                 for ts_sec, ts_usec, orig_len, octets in records)
    blocks = [_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)),
              _block(1, struct.pack('<HHI', 1, 0, 0xFFFF))]
    for ts_sec, ts_usec, orig_len, octets in records:
        ticks = ts_sec * 10 ** 6 + ts_usec
        blocks.append(_block(6, struct.pack('<IIIII', 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                            len(octets), orig_len) + octets))
    return b''.join(blocks)


def pcap_records(data: 'bytes') -> 'list[tuple[int, int, int, bytes]]':
    """The ``(ts_sec, ts_usec, orig_len, octets)`` records of a little-endian PCAP."""
    rest, records = data[24:], []
    while rest:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rest[:16])
        records.append((ts_sec, ts_usec, orig_len, rest[16:16 + incl_len]))
        rest = rest[16 + incl_len:]
    return records


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SnappedCaptureTraceTests(unittest.TestCase):
    """The default engine traces the snapped capture as the other engines do."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def _extract(self, container: 'str', engine: 'str' = 'default', **kwargs: 'Any') -> 'Any':
        """Extract the snapped capture: from memory for the default engine and
        :mod:`dpkt`, from a file for :mod:`scapy`, which opens savefiles by name."""
        from pcapkit import extract

        data = snapped_capture(container)
        if engine == 'scapy':
            fin = os.path.join(self.tmp, f'snapped.{container}')  # type: Any
            with open(fin, 'wb') as file:
                file.write(data)
        else:
            fin = io.BytesIO(data)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=fin, nofile=True, engine=engine, tcp=True, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def _flows(self, container: 'str', engine: 'str' = 'default', **kwargs: 'Any') -> 'list[tuple]':
        extractor = self._extract(container, engine, trace=True, **kwargs)
        return [(tuple(flow.index), tuple(flow.forward), tuple(flow.reverse), flow.label)
                for flow in extractor.trace.tcp]

    def test_the_default_engine_traces_every_frame(self) -> None:
        for container in CONTAINERS:
            for bidirectional, expected in ((True, FLOWS), (False, UNIDIRECTIONAL)):
                with self.subTest(container=container, bidirectional=bidirectional):
                    flows = self._flows(container, trace_bidirectional=bidirectional)
                    self.assertEqual([flow[:3] for flow in flows], expected)

    @unittest.skipUnless(ENGINES, 'neither dpkt nor scapy installed')
    def test_the_other_engines_agree(self) -> None:
        for container in CONTAINERS:
            for bidirectional in (True, False):
                base = self._flows(container, trace_bidirectional=bidirectional)
                for engine in ENGINES:
                    with self.subTest(container=container, bidirectional=bidirectional, engine=engine):
                        self.assertEqual(self._flows(container, engine, trace_bidirectional=bidirectional), base)

    def _trace_files(self, container: 'str', engine: 'str' = 'default') -> 'dict[str, bytes]':
        fout = tempfile.mkdtemp(dir=self.tmp)
        extractor = self._extract(container, engine, trace=True, trace_fout=fout, trace_format='pcap')
        files = {}
        for flow in extractor.trace.tcp:
            with open(flow.fpout, 'rb') as file:
                files[flow.label] = file.read()
        return files

    def test_each_traced_pcap_holds_the_captured_records(self) -> None:
        # Byte for byte: each flow's file holds its frames' records as captured,
        # snapped octets and original length alike (#1543).
        _, records = snapped_records()
        for container in CONTAINERS:
            with self.subTest(container=container):
                files = self._trace_files(container)
                self.assertEqual(len(files), len(FLOWS))
                for (index, _, _), data in zip(FLOWS, files.values()):
                    self.assertEqual(pcap_records(data), [records[number - 1] for number in index])

    @unittest.skipUnless('dpkt' in ENGINES, 'dpkt not installed')
    def test_each_traced_pcap_matches_dpkt(self) -> None:
        for container in CONTAINERS:
            with self.subTest(container=container):
                self.assertEqual(self._trace_files(container), self._trace_files(container, 'dpkt'))

    def _datagrams(self, container: 'str', engine: 'str' = 'default') -> 'list[tuple]':
        extractor = self._extract(container, engine, reassembly=True, reasm_store=True)
        return [(tuple(datagram.index), bytes(datagram.payload)) for datagram in extractor.reassembly.tcp]

    def test_reassembly_takes_every_frame(self) -> None:
        for container in CONTAINERS:
            with self.subTest(container=container):
                self.assertEqual([index for index, _ in self._datagrams(container)], DATAGRAMS)

    @unittest.skipUnless('dpkt' in ENGINES, 'dpkt not installed')
    def test_reassembly_matches_dpkt(self) -> None:
        for container in CONTAINERS:
            with self.subTest(container=container):
                self.assertEqual(self._datagrams(container), self._datagrams(container, 'dpkt'))


if __name__ == '__main__':
    unittest.main()
