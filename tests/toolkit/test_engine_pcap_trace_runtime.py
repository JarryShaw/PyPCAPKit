# -*- coding: utf-8 -*-
"""DPKT and Scapy write ``trace_format='pcap'`` flows as PCAP (#1507).

Both engines expose each frame's captured octets, its timestamp, its original
length and its link type, so their flow tracing adapters carry a PCAP frame
record beside the frame mapping they always reported, and
:class:`~pcapkit.foundation.extraction.Extractor` no longer swaps the format for
JSON. The checks are the strongest available: every traced PCAP file is
byte-compared with the default engine's for the same input, and every JSON trace
with the one main wrote before.

The inputs no sample has are synthesised from :file:`tcp.pcap`: nanosecond PCAP
and PCAP-NG (``if_tsresol=9``) captures, each with a timestamp that has
sub-microsecond digits and one that is a whole number of microseconds, and
captures with a TCP frame the snapshot length cut short.

The module reads generated captures, so it belongs to the fixture-dependent tier.

"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))
HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_SCAPY = importlib.util.find_spec('scapy') is not None
ENGINES = tuple(name for name, present in (('dpkt', HAS_DPKT), ('scapy', HAS_SCAPY)) if present)

#: Captures with at least one TCP flow, one per link layer and container.
CAPTURES = ('tcp.pcap', 'http6.cap', 'in.pcap', 'many_interfaces.pcapng', 'test.pcap')

#: Little-endian microsecond and nanosecond PCAP magic, as written on this host.
MAGIC = {False: bytes.fromhex('d4c3b2a1'), True: bytes.fromhex('4d3cb2a1')}

#: Nanoseconds added to each microsecond timestamp: sub-microsecond digits, and
#: none at all, which leaves a nanosecond count with a microsecond count's digits.
EXTRA_NS = {'unaligned': 789, 'aligned': 0}

#: SHA-256 of each JSON flow trace of ``tcp.pcap``, as main wrote it at 6af87f608.
JSON_TRACE_SHA256 = {
    'dpkt': {
        '10.20.30.130_22-10.20.30.131_53406-1500000000.000774.json':
            'c3f17eb27a735437976439ea832746340b50966b85d364514110c7a176199eed',
        'fe80..a6.87f9.2793.16ee_51774-fe80..1ccd.7c77.bac7.46b7_22-1500000000.002433.json':
            'f0e9d767454ece7604f316c229c0407aba1f84cf321cf17822ba416cbcd3652f',
    },
    'scapy': {
        '10.20.30.130_22-10.20.30.131_53406-1500000000.000774.json':
            '7679cddff9512107b9f03d366d4d9f39155efa6ff4d3a83bcc27bea63865c252',
        'fe80..a6.87f9.2793.16ee_51774-fe80..1ccd.7c77.bac7.46b7_22-1500000000.002433.json':
            'a1953755ce695b1008f30eb67937e554381f01909144319dbf69035afb437ce1',
    },
}


def _records(source: 'str | bytes') -> 'tuple[bytes, list[list]]':
    """Split a little-endian PCAP, by path or by content, into its global header
    and its ``[ts_sec, ts_usec, orig_len, octets]`` records."""
    if isinstance(source, str):
        with open(source, 'rb') as file:
            source = file.read()
    header, rest, records = source[:24], source[24:], []
    while rest:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rest[:16])
        records.append([ts_sec, ts_usec, orig_len, rest[16:16 + incl_len]])
        rest = rest[16 + incl_len:]
    return header, records


def _write(path: 'str', header: 'bytes', records: 'list[list]') -> 'str':
    with open(path, 'wb') as file:
        file.write(header)
        for ts_sec, ts_usec, orig_len, octets in records:
            file.write(struct.pack('<IIII', ts_sec, ts_usec, len(octets), orig_len) + octets)
    return path


def _block(block_type: 'int', body: 'bytes') -> 'bytes':
    body += b'\x00' * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack('<II', block_type, length) + body + struct.pack('<I', length)


def _write_pcapng(path: 'str', records: 'list[list]', *, tsresol: 'int') -> 'str':
    """Write ``[ts_sec, ts_nsec, orig_len, octets]`` records as a little-endian
    PCAP-NG capture on one Ethernet interface of ``if_tsresol=tsresol``."""
    shb = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    option = struct.pack('<HHB', 9, 1, tsresol) + b'\x00' * 3 + struct.pack('<HH', 0, 0)
    idb = _block(1, struct.pack('<HHI', 1, 0, 0x40000) + option)
    with open(path, 'wb') as file:
        file.write(shb + idb)
        for ts_sec, ts_nsec, orig_len, octets in records:
            ticks = (ts_sec * 10 ** 9 + ts_nsec) // 10 ** (9 - tsresol)
            file.write(_block(6, struct.pack('<IIIII', 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                             len(octets), orig_len) + octets))
    return path


@unittest.skipUnless(HAS_RUNTIME and ENGINES, 'runtime dependencies, dpkt or scapy not installed')
class EnginePCAPTraceTests(unittest.TestCase):
    """A traced flow is the same PCAP file whichever engine read the capture."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def _flows(self, engine: 'str', fin: 'str', *, nanosecond: 'bool' = False,
               caught: 'list | None' = None) -> 'list[tuple[str, tuple, bytes]]':
        """``(label, frame numbers, file octets)`` of every flow traced as PCAP.

        The warnings the extraction raised are appended to ``caught``, if given.

        """
        from pcapkit import extract
        from pcapkit.utilities.warnings import FormatWarning

        fout = tempfile.mkdtemp(dir=self.tmp)
        with warnings.catch_warnings(record=True) as raised:
            warnings.simplefilter('always')
            extractor = extract(fin=fin, nofile=True, engine=engine, tcp=True, trace=True,
                                trace_fout=fout, trace_format='pcap', trace_nanosecond=nanosecond)
        self.addCleanup(close_extractor, extractor)
        self.assertEqual([str(w.message) for w in raised if issubclass(w.category, FormatWarning)], [])
        if caught is not None:
            caught.extend(raised)

        flows = []
        for flow in extractor.trace.tcp:
            self.assertTrue(flow.fpout.endswith('.pcap'), flow.fpout)
            with open(flow.fpout, 'rb') as file:
                flows.append((flow.label, tuple(flow.index), file.read()))
        return flows

    def _assert_same_files(self, fin: 'str', *, nanosecond: 'bool', labels: 'bool' = True,
                           caught: 'list | None' = None) -> None:
        base = self._flows('default', fin, nanosecond=nanosecond)
        self.assertTrue(base)
        for engine in ENGINES:
            with self.subTest(engine=engine):
                flows = self._flows(engine, fin, nanosecond=nanosecond, caught=caught)
                if labels:
                    self.assertEqual([flow[:2] for flow in flows], [flow[:2] for flow in base])
                self.assertEqual([flow[1] for flow in flows], [flow[1] for flow in base])
                for (label, _, mine), (_, _, theirs) in zip(flows, base):
                    self.assertEqual(mine[:4], MAGIC[nanosecond], label)
                    self.assertEqual(mine, theirs, label)

    def _nanosecond_records(self, extra: 'int') -> 'list[list]':
        """``tcp.pcap``'s records, each microsecond fraction made nanoseconds plus ``extra``."""
        _, records = _records(sample_path('tcp.pcap'))
        return [[ts_sec, ts_usec * 1000 + extra, orig_len, octets]
                for ts_sec, ts_usec, orig_len, octets in records]

    def test_traced_pcap_matches_the_default_engine_byte_for_byte(self) -> None:
        for capture in CAPTURES:
            for nanosecond in (False, True):
                with self.subTest(capture=capture, nanosecond=nanosecond):
                    self._assert_same_files(sample_path(capture), nanosecond=nanosecond)

    def test_a_nanosecond_pcap_keeps_its_resolution(self) -> None:
        # The record fraction stays in the capture's own resolution, as the default
        # engine's does. Labels are left out: dpkt's Decimal timestamp spells them
        # with nine places (#1501).
        header, _ = _records(sample_path('tcp.pcap'))
        for case, extra in EXTRA_NS.items():
            fin = _write(os.path.join(self.tmp, f'{case}.pcap'), MAGIC[True] + header[4:],
                         self._nanosecond_records(extra))
            for nanosecond in (False, True):
                with self.subTest(case=case, nanosecond=nanosecond):
                    self._assert_same_files(fin, nanosecond=nanosecond, labels=False)

    def test_a_nanosecond_pcapng_keeps_its_resolution(self) -> None:
        # ``if_tsresol=9``: an unaligned timestamp must keep its sub-microsecond
        # digits, and an aligned one must still be read as nanoseconds, not as the
        # microsecond count it has the digits of.
        for case, extra in EXTRA_NS.items():
            fin = _write_pcapng(os.path.join(self.tmp, f'{case}.pcapng'),
                                self._nanosecond_records(extra), tsresol=9)
            for nanosecond in (False, True):
                with self.subTest(case=case, nanosecond=nanosecond):
                    self._assert_same_files(fin, nanosecond=nanosecond)

    def test_a_cross_resolution_trace_rescales_the_fraction(self) -> None:
        # Not only the same bytes as the default engine: the right ones. The first
        # frame of tcp.pcap is at 1500000000.000774; the synthetic nanosecond
        # captures put it at 1500000000.000774789. A trace in the other resolution
        # than its capture's scales the fraction, truncating nanoseconds (#1529).
        header, _ = _records(sample_path('tcp.pcap'))
        captures = (
            ('us pcap', sample_path('tcp.pcap'), {False: 774, True: 774000}),
            ('ns pcap', _write(os.path.join(self.tmp, 'cross.pcap'), MAGIC[True] + header[4:],
                               self._nanosecond_records(789)), {False: 774, True: 774789}),
            ('ns pcapng', _write_pcapng(os.path.join(self.tmp, 'cross.pcapng'),
                                        self._nanosecond_records(789), tsresol=9), {False: 774, True: 774789}),
        )
        for name, fin, fraction in captures:
            for nanosecond, expected in fraction.items():
                for engine in ENGINES:
                    with self.subTest(capture=name, nanosecond=nanosecond, engine=engine):
                        first = min((_records(flow[2])[1][0] for flow in
                                     self._flows(engine, fin, nanosecond=nanosecond)),
                                    key=lambda record: record[:2])
                        self.assertEqual(first[:2], [1500000000, expected])

    def test_a_snapped_frame_keeps_its_original_length(self) -> None:
        # Both engines' readers report a record's original length, PCAP and
        # PCAP-NG alike, so a frame the snapshot length cut short is written as
        # the default engine writes it.
        header, records = _records(sample_path('tcp.pcap'))
        longest = max(range(len(records)), key=lambda index: len(records[index][3]))
        records[longest][3] = records[longest][3][:-4]
        captures = {
            'pcap': _write(os.path.join(self.tmp, 'snapped.pcap'), header, records),
            'pcapng': _write_pcapng(os.path.join(self.tmp, 'snapped.pcapng'),
                                    [[ts_sec, ts_usec * 1000, orig_len, octets]
                                     for ts_sec, ts_usec, orig_len, octets in records], tsresol=6),
        }
        for container, fin in captures.items():
            with self.subTest(container=container):
                self._assert_same_files(fin, nanosecond=False)

    def test_no_engine_warns_about_original_lengths(self) -> None:
        # The frame record is complete, so there is nothing to warn about -- not on
        # a PCAP trace, not on a JSON one, and not from follow_tcp_stream.
        from pcapkit.interface.misc import follow_tcp_stream

        for engine in ENGINES:
            for trace_format in ('pcap', 'json'):
                with self.subTest(engine=engine, trace_format=trace_format), \
                        warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    follow_tcp_stream(fin=sample_path('tcp.pcap'), engine=engine, format=trace_format,
                                      fout=tempfile.mkdtemp(dir=self.tmp))
                    self.assertEqual([str(w.message) for w in caught if 'original length' in str(w.message)], [])

    def test_dict_capable_trace_formats_are_unchanged(self) -> None:
        # Only the PCAP trace dumper reads the frame record, so the JSON trace of
        # each flow is the very file main wrote before #1507: the adapters still
        # report the engine's own mapping of the frame, value types included.
        # Re-measure the digests if dictdumper's output ever changes.
        from pcapkit import extract

        for engine in ENGINES:
            with self.subTest(engine=engine):
                fout = tempfile.mkdtemp(dir=self.tmp)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    extractor = extract(fin=sample_path('tcp.pcap'), nofile=True, engine=engine, tcp=True,
                                        trace=True, trace_fout=fout, trace_format='json')
                self.addCleanup(close_extractor, extractor)
                digests = {}
                for flow in extractor.trace.tcp:
                    with open(flow.fpout, 'rb') as file:
                        digests[os.path.basename(flow.fpout)] = hashlib.sha256(file.read()).hexdigest()
                self.assertEqual(digests, JSON_TRACE_SHA256[engine])

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_closes_its_reader_once(self) -> None:
        # ``sniff`` closes the reader at the end of the file; a second close from
        # the engine would raise on a gzip reader.
        from scapy.utils import RawPcapReader

        close = RawPcapReader.close
        calls = []  # type: list

        def counted(reader: 'RawPcapReader') -> None:
            calls.append(reader)
            close(reader)

        with mock.patch.object(RawPcapReader, 'close', counted):
            self._flows('scapy', sample_path('tcp.pcap'))
        self.assertEqual(len(calls), 1)

        # and if ``sniff`` raises before the end of the file, the engine closes it
        import scapy.all

        from pcapkit import extract

        calls.clear()
        with mock.patch.object(RawPcapReader, 'close', counted), \
                mock.patch.object(scapy.all, 'sniff', side_effect=RuntimeError('sniff failed')), \
                self.assertRaisesRegex(RuntimeError, 'sniff failed'):
            extract(fin=sample_path('tcp.pcap'), nofile=True, engine='scapy')
        self.assertEqual(len(calls), 1)

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_without_the_reader_internals_falls_back_and_warns(self) -> None:
        # The engine's PCAP reader reads three private attributes of
        # dpkt.pcap.Reader, and dpkt is not pinned. Under a dpkt that names them
        # differently it reads with dpkt's own loop, losing only the original
        # length, and says so naming the dpkt version.
        import dpkt

        from pcapkit.utilities.warnings import DPKTWarning

        class Renamed(dpkt.pcap.Reader):  # type: ignore[misc]
            """dpkt.pcap.Reader with its private attributes under other names."""

            def __init__(self, fileobj: 'Any') -> None:
                super().__init__(fileobj)
                self._state = (self._Reader__f, self._Reader__ph, self._divisor)
                del self._Reader__f, self._Reader__ph, self._divisor

            def __iter__(self) -> 'Any':
                file, header, divisor = self._state
                while True:
                    buf = file.read(header.__hdr_len__)
                    if not buf:
                        break
                    hdr = header(buf)
                    yield hdr.tv_sec + (hdr.tv_usec / divisor), file.read(hdr.caplen)

        base = self._flows('default', sample_path('tcp.pcap'))
        caught = []  # type: list
        with mock.patch.object(dpkt.pcap, 'Reader', Renamed):
            flows = self._flows('dpkt', sample_path('tcp.pcap'), caught=caught)
        self.assertEqual(flows, base)
        messages = [str(w.message) for w in caught if issubclass(w.category, DPKTWarning)
                    and 'original length' in str(w.message)]
        self.assertEqual(len(messages), 1, messages)
        self.assertIn(f'dpkt {dpkt.__version__}', messages[0])
        self.assertIn("'_Reader__f', '_Reader__ph', '_divisor'", messages[0])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DPKTTimestampTests(unittest.TestCase):
    """The timestamp carriers behave as the values they carry."""

    def test_copies_and_arithmetic_keep_working(self) -> None:
        import copy
        import decimal
        import pickle
        import statistics

        from pcapkit.toolkit.dpkt import DecimalTimestamp, Timestamp

        for stamp in (Timestamp(1500000000.000774, decimal.Decimal('1500000000.000774'), 1_000_000, 78),
                      DecimalTimestamp(decimal.Decimal('1500000000.000774789'), 1_000_000_000, 78)):
            with self.subTest(type=type(stamp).__name__):
                # ``statistics`` rebuilds a mean through ``type(x)(value)``
                self.assertEqual(statistics.mean([stamp, stamp]), stamp)
                for clone in (copy.deepcopy(stamp), pickle.loads(pickle.dumps(stamp))):
                    self.assertEqual(clone, stamp)
                    self.assertEqual((clone.exact, clone.resolution, clone.orig_len),
                                     (stamp.exact, stamp.resolution, stamp.orig_len))

    def test_a_frame_record_pickles_with_every_protocol(self) -> None:
        import copy
        import decimal
        import pickle

        from pcapkit.foundation.traceflow.data.data import FrameRecord
        from pcapkit.protocols.data.misc.pcap.frame import FrameInfo

        record = FrameRecord({'packet': b'rebuilt', 'Ethernet': {'type': 2048}}, packet=b'captured',
                             frame_info=FrameInfo(ts_sec=1, ts_usec=2, incl_len=8, orig_len=9),
                             time_epoch=decimal.Decimal('1.000002'))
        clones = [pickle.loads(pickle.dumps(record, protocol=protocol))
                  for protocol in range(pickle.HIGHEST_PROTOCOL + 1)] + [copy.deepcopy(record)]
        for clone in clones:
            self.assertIs(type(clone), FrameRecord)
            self.assertEqual(clone, record)
            self.assertEqual((clone.packet, clone.frame_info, clone.time_epoch),
                             (record.packet, record.frame_info, record.time_epoch))


if __name__ == '__main__':
    unittest.main()
