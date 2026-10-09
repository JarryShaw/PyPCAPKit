# -*- coding: utf-8 -*-
"""Flow tracing over every sample capture reads back as exactly its frames. C.f. #1202.

The capture-driven twin of :mod:`tests.foundation.traceflow.\
test_traceflow_reread_roundtrip_unit`: every capture under
:file:`examples/captures/` is traced to PCAP, and each flow's file is read back
with :mod:`struct` alone and compared, record by record, with the frames the
flow's ``index`` names, as :mod:`pcapkit` read them from the input -- the
timestamp exactly (as a :class:`~decimal.Decimal`), the captured and original
lengths, and the octets.

A PCAP input is traced in its own byte order and resolution, so its records
must come back byte for byte. A PCAP-NG input is traced in nanoseconds, which
holds every timestamp the sample interfaces record.

This module reads generated captures, so it is in the fixture-dependent tier
(see :mod:`tests._tiers`) and runs after ``make samples``.

"""

from __future__ import annotations

import decimal
import importlib.util
import os
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class, sample_path
from tests._tiers import SAMPLE_ROOT
from tests.foundation import _roundtrip as harness
from tests.foundation._roundtrip import Gap, Outcome, read_pcap

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Every capture on disk, enumerated rather than hand-picked.
CAPTURES = sorted(name for name in os.listdir(SAMPLE_ROOT)
                  if name.endswith(('.pcap', '.cap', '.pcapng')))


def _record(frame: 'object') -> 'tuple[decimal.Decimal, int, int, bytes]':
    """``(timestamp, captured length, original length, octets)`` of an input frame."""
    info = frame.info  # type: ignore[attr-defined]
    if 'time_epoch' in info:
        return (decimal.Decimal(info.time_epoch), info.cap_len, info.len, bytes(info.packet))
    return (decimal.Decimal(info.timestamp_epoch), info.captured_len, info.original_len,
            bytes(info.packet))


def run_capture(name: 'str') -> 'Outcome':
    """Trace one capture to PCAP and read every flow back."""
    from pcapkit import extract

    path = sample_path(name)
    with open(path, 'rb') as file:
        head = file.read(24)
    pcapng = head[:4] == b'\x0a\x0d\x0d\x0a'
    if pcapng:
        order, nsec, linktypes = 'little', True, None
    else:
        reference = read_pcap(head)
        order, nsec, linktypes = reference.byteorder, reference.nanosecond, reference.linktype

    with warnings.catch_warnings(), tempfile.TemporaryDirectory() as tracedir:
        warnings.simplefilter('ignore')
        try:
            extractor = extract(fin=path, nofile=True, store=True, trace=True, tcp=True,
                                trace_fout=tracedir, trace_format='pcap',
                                trace_byteorder=order, trace_nanosecond=nsec)
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('ERROR', f'{type(exc).__name__}: {exc}')
        close_extractor(extractor)
        frames = {frame.info.number: frame for frame in extractor.frame}
        scale = decimal.Decimal(10) ** (9 if nsec else 6)
        for flow in extractor.trace.tcp:
            with open(flow.fpout, 'rb') as file:
                written = read_pcap(file.read())
            if (written.byteorder, written.nanosecond) != (order, nsec):
                return Outcome('HEADER', f'{flow.label}: {(written.byteorder, written.nanosecond)} '
                                         f'!= {(order, nsec)}')
            if linktypes is not None and written.linktype != linktypes:
                return Outcome('HEADER', f'{flow.label}: linktype {written.linktype} != {linktypes}')
            if len(written.records) != len(flow.index):
                return Outcome('COUNT', f'{flow.label}: {len(written.records)} records != '
                                        f'{len(flow.index)} indexed')
            for (sec, frac, incl, orig, octets), number in zip(written.records, flow.index):
                got = (decimal.Decimal(sec) + decimal.Decimal(frac) / scale, incl, orig, octets)
                want = _record(frames[number])
                if got != want:
                    fields = ('timestamp', 'incl_len', 'orig_len', 'octets')
                    diff = '; '.join(f'{field} {g!r:.60} != {w!r:.60}' for field, g, w
                                     in zip(fields, got, want) if g != w)
                    return Outcome('RECORD', f'{flow.label} frame {number}: {diff}')
    return Outcome('OK')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestTraceFlowRereadRuntime(harness.RoundTripBase):
    """Every sample capture's flows read back as exactly their frames."""

    STATUSES = ('ERROR', 'HEADER', 'COUNT', 'RECORD')
    KNOWN_FAILURES = ()  # type: tuple[Gap, ...]

    def setUp(self) -> None:
        super().setUp()
        reimport_once_per_class(self)

    def labels(self) -> 'list[str]':
        return list(CAPTURES)

    def outcome(self, label: 'str') -> 'Outcome':
        return run_capture(label)


if __name__ == '__main__':
    unittest.main()
