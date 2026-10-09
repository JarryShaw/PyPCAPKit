# -*- coding: utf-8 -*-
"""A PCAP dumper writes each record's fraction in its own file's resolution. C.f. #1500.

:class:`~pcapkit.dumpkit.pcap.PCAPIO` wrote a frame's ``ts_usec`` unscaled, so a
microsecond capture traced with ``trace_nanosecond=True`` -- or a nanosecond one
traced without it -- wrote every fraction 1000 times off. A frame converted from
PCAP-NG (:func:`~pcapkit.toolkit.pcapng.block2frame`) carries its interface's
resolution and was written the same way.

Each case below writes frames as :mod:`pcapkit` read them, reads the file back
with :mod:`struct` alone and with :mod:`pcapkit`, and checks every timestamp
against the source frame: exactly when the file is at least as fine as the
source, and truncated to the microsecond when it is coarser.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import decimal
import importlib.util
import io
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation._roundtrip import ethernet, ipv4, pcap, pcapng, read_pcap, tcp

if TYPE_CHECKING:
    from typing import Any

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

SECOND = 1_500_000_000
#: Fractions per input resolution: the ends of the second, a value whose
#: nanoseconds sit at exactly half a microsecond, and a sub-microsecond one.
FRACTIONS = {
    False: (0, 1, 123_456, 999_999),
    True: (0, 999, 1_000, 123_456_500, 123_456_789, 999_999_999),
}


def _frames(count: 'int') -> 'list[bytes]':
    """``count`` TCP segments of one connection, client to server."""
    return [ethernet(ipv4(tcp(b'x' * number, seq=1000 + number, syn=not number), proto=6), 0x0800)
            for number in range(count)]


def _epoch(sec: 'int', frac: 'int', nanosecond: 'bool') -> 'decimal.Decimal':
    """The UNIX timestamp of a record header's two fields."""
    return decimal.Decimal(sec) + decimal.Decimal(frac) / (10 ** 9 if nanosecond else 10 ** 6)


def _expected(sec: 'int', frac: 'int', in_nsec: 'bool', out_nsec: 'bool') -> 'tuple[int, int]':
    """The seconds and fraction a file of resolution ``out_nsec`` should hold."""
    if in_nsec == out_nsec:
        return sec, frac
    if out_nsec:
        return sec, frac * 1000
    return sec, frac // 1000


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestPCAPTraceResolution(unittest.TestCase):
    """Every fraction is written, and reads back, in the output file's resolution."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)

    def read(self, data: 'bytes') -> 'list[Any]':
        """The frames :mod:`pcapkit` reads from ``data``, a PCAP or PCAP-NG file."""
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(data), nofile=True, store=True)
        close_extractor(extractor)
        return list(extractor.frame)

    def dump(self, frames: 'list[Any]', nanosecond: 'bool') -> 'str':
        """Write ``frames``, each a :class:`~pcapkit.protocols.data.misc.pcap.frame.Frame`."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO

        path = os.path.join(self.tmpdir.name, f'out-{len(os.listdir(self.tmpdir.name))}.pcap')
        dumper = PCAPIO(path, protocol=LinkType.ETHERNET, byteorder='little', nanosecond=nanosecond)
        for frame in frames:
            dumper(frame)
        return path

    def reread(self, path: 'str') -> 'list[decimal.Decimal]':
        """Every frame's timestamp, as :mod:`pcapkit` reads the file at ``path``."""
        with open(path, 'rb') as file:
            return [frame.info.time_epoch for frame in self.read(file.read())]

    def check(self, path: 'str', records: 'list[tuple[int, int]]', in_nsec: 'bool', out_nsec: 'bool') -> None:
        """The file at ``path`` holds ``records`` rescaled, and reads back as their instants."""
        with open(path, 'rb') as file:
            written = read_pcap(file.read())
        self.assertEqual(written.nanosecond, out_nsec)
        want = [_expected(sec, frac, in_nsec, out_nsec) for sec, frac in records]
        self.assertEqual([record[:2] for record in written.records], want)
        self.assertEqual(self.reread(path), [_epoch(sec, frac, out_nsec) for sec, frac in want])

    def test_a_pcap_frame_is_written_at_the_files_resolution(self) -> None:
        """#1500: a PCAP frame's fraction is scaled up, or truncated down, to the file's."""
        for in_nsec in (False, True):
            for out_nsec in (False, True):
                with self.subTest(in_nsec=in_nsec, out_nsec=out_nsec):
                    records = [(SECOND + i, frac) for i, frac in enumerate(FRACTIONS[in_nsec])]
                    data = pcap([(sec, frac, frame) for (sec, frac), frame
                                 in zip(records, _frames(len(records)))], nanosecond=in_nsec)
                    frames = self.read(data)
                    self.assertEqual([frame.info.time_epoch for frame in frames],
                                     [_epoch(sec, frac, in_nsec) for sec, frac in records])

                    path = self.dump([frame.info for frame in frames], out_nsec)
                    self.check(path, records, in_nsec, out_nsec)
                    if in_nsec == out_nsec:
                        with open(path, 'rb') as file:
                            self.assertEqual(file.read()[24:], data[24:])

    def test_a_pcapng_frame_is_written_at_the_files_resolution(self) -> None:
        """#1500: so is a frame converted from PCAP-NG at its interface's resolution."""
        from pcapkit.toolkit.pcapng import block2frame

        for in_nsec in (False, True):
            for out_nsec in (False, True):
                with self.subTest(in_nsec=in_nsec, out_nsec=out_nsec):
                    records = [(SECOND + i, frac) for i, frac in enumerate(FRACTIONS[in_nsec])]
                    data = pcapng([(sec, frac, frame) for (sec, frac), frame
                                   in zip(records, _frames(len(records)))], nanosecond=in_nsec)
                    blocks = self.read(data)
                    self.assertEqual([block.nanosecond for block in blocks], [in_nsec] * len(records))

                    # what the PCAP-NG engine hands a flow's dumper
                    frames = [block2frame(block.info, nanosecond=block.nanosecond) for block in blocks]
                    self.check(self.dump(frames, out_nsec), records, in_nsec, out_nsec)

    def test_a_trace_reads_back_as_its_source_frames(self) -> None:
        """#1500: a flow traced at either resolution re-reads as its frames' timestamps."""
        from pcapkit import extract

        for container, build in (('pcap', pcap), ('pcapng', pcapng)):
            for in_nsec in (False, True):
                for out_nsec in (False, True):
                    with self.subTest(container=container, in_nsec=in_nsec, out_nsec=out_nsec):
                        records = [(SECOND + i, frac) for i, frac in enumerate(FRACTIONS[in_nsec])]
                        data = build([(sec, frac, frame) for (sec, frac), frame
                                      in zip(records, _frames(len(records)))], nanosecond=in_nsec)
                        tracedir = tempfile.mkdtemp(dir=self.tmpdir.name)
                        with warnings.catch_warnings():
                            warnings.simplefilter('ignore')
                            extractor = extract(fin=io.BytesIO(data), nofile=True, store=False,
                                                trace=True, tcp=True, trace_fout=tracedir,
                                                trace_format='pcap', trace_nanosecond=out_nsec)
                        close_extractor(extractor)
                        flows = list(extractor.trace.tcp)
                        self.assertEqual([list(flow.index) for flow in flows],
                                         [list(range(1, len(records) + 1))])
                        self.check(flows[0].fpout, records, in_nsec, out_nsec)

    def test_nanoseconds_are_truncated_not_rounded(self) -> None:
        """#1500: 999,999,999 ns is 999,999 us of the same second, and half a microsecond drops."""
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        frames = []
        for frac in (999_999_999, 123_456_500, 500):
            frame = Frame(frame_info=FrameInfo(ts_sec=SECOND, ts_usec=frac, incl_len=0, orig_len=0),
                          time='time', number=1, time_epoch=_epoch(SECOND, frac, True), len=0, cap_len=0)
            frame.__update__(packet=b'')
            frames.append(frame)
        with open(self.dump(frames, False), 'rb') as file:
            written = read_pcap(file.read())
        self.assertEqual([record[:2] for record in written.records],
                         [(SECOND, 999_999), (SECOND, 123_456), (SECOND, 0)])

    def test_a_rescaled_fraction_of_a_second_or_more_is_carried(self) -> None:
        """#1500: a fraction past the second moves into ``ts_sec``, so 1000x cannot overflow."""
        # Neither fraction is normalised, and 5,000,000 us is 5e9 ns, past 2**32.
        for in_nsec, frac, want in ((False, 5_000_000, (SECOND + 5, 0)),
                                    (True, 1_500_000_123, (SECOND + 1, 500_000))):
            with self.subTest(in_nsec=in_nsec):
                data = pcap([(SECOND, frac, _frames(1)[0])], nanosecond=in_nsec)
                frames = self.read(data)
                path = self.dump([frame.info for frame in frames], not in_nsec)
                with open(path, 'rb') as file:
                    written = read_pcap(file.read())
                self.assertEqual(written.records[0][:2], want)
                self.assertEqual(self.reread(path), [_epoch(*want, not in_nsec)])
                if not in_nsec:
                    self.assertEqual(self.reread(path), [frame.info.time_epoch for frame in frames])

    def test_a_binary_resolution_keeps_its_sub_microsecond_part(self) -> None:
        """#1500: a fraction truncated to microseconds is rescaled from the exact timestamp."""
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        # What :func:`~pcapkit.toolkit.pcapng.block2frame` makes of tick 1 of an
        # ``if_tsresol`` of 2**-10: 0.0009765625 s, truncated to 976 us.
        epoch = decimal.Decimal(SECOND) + decimal.Decimal(1) / 1024
        frame = Frame(frame_info=FrameInfo(ts_sec=SECOND, ts_usec=976, incl_len=0, orig_len=0),
                      time='time', number=1, time_epoch=epoch, len=0, cap_len=0)
        frame.__update__(packet=b'')
        with open(self.dump([frame], True), 'rb') as file:
            written = read_pcap(file.read())
        self.assertEqual(written.records[0][:2], (SECOND, 976_562))

    def test_a_frame_whose_timestamp_fits_neither_resolution_is_written_as_given(self) -> None:
        """A hand-built frame whose ``time_epoch`` fits neither resolution keeps its fields."""
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        for nanosecond in (False, True):
            with self.subTest(nanosecond=nanosecond):
                frame = Frame(frame_info=FrameInfo(ts_sec=7, ts_usec=123_456, incl_len=0, orig_len=0),
                              time='time', number=1, time_epoch=decimal.Decimal('2.5'), len=0, cap_len=0)
                frame.__update__(packet=b'')
                with open(self.dump([frame], nanosecond), 'rb') as file:
                    written = read_pcap(file.read())
                self.assertEqual(written.records[0][:2], (7, 123_456))


if __name__ == '__main__':
    unittest.main()
