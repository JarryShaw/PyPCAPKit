# -*- coding: utf-8 -*-
"""Every offline engine reports what the ``default`` engine reports. C.f. #1202.

Each engine in :attr:`Extractor.__engine__
<pcapkit.foundation.extraction.Extractor.__engine__>` reads every capture under
:file:`examples/captures/` with IPv4, IPv6 and TCP reassembly and TCP flow
tracing on, and is compared, field for field, with the ``default`` engine over
the same capture:

``frames``
    the number of frames read;
``timestamps``, ``octets``
    each frame's timestamp, and its octets where the engine's frame object
    keeps them -- ``pyshark`` reports dissected fields only, and ``pypcapfile``
    replaces the octets with its decoded layers, so their ``octets`` skip;
``ipv4``, ``ipv6``, ``tcp``
    every :class:`~pcapkit.foundation.reassembly.data.ip.Packet` or
    :class:`~pcapkit.foundation.reassembly.data.tcp.Packet` the engine's toolkit
    hands the reassembler, keyed by frame number -- every field;
``trace``
    every :class:`~pcapkit.foundation.traceflow.data.tcp.Packet` handed to the
    flow tracer, keyed by frame number -- every field except ``frame``, which
    is the engine's own frame object, and except ``header`` and ``payload`` for
    an engine in :data:`NO_TCP_OCTETS`;
``datagrams``
    every reassembled datagram, every field but the lazily parsed ``packet``;
``flows``
    every traced flow's label and index, and the octets of its PCAP file unless
    the engine is in :data:`JSON_TRACE`.

The inputs are captured by wrapping :meth:`ReassemblyBase.__call__
<pcapkit.foundation.reassembly.reassembly.ReassemblyBase.__call__>` and
:meth:`TraceFlowBase.__call__
<pcapkit.foundation.traceflow.traceflow.TraceFlowBase.__call__>`, the one
entry point every engine feeds.

An engine whose dependency is missing, or which declines this interpreter, makes
:class:`~pcapkit.foundation.extraction.Extractor` fall back to ``default`` with
an :class:`~pcapkit.utilities.warnings.EngineWarning`; its cases are skipped with
that warning as the reason, never compared, since a fallback agrees with
``default`` trivially. Refusals the engines document are skipped too, with the
refusal as the reason: ``pypcap``, ``pcap_ct`` and ``pypcapfile`` reject PCAP-NG
with a :exc:`~pcapkit.utilities.exceptions.FormatError`, and an engine that
declines reassembly or flow tracing, or one protocol of it, warns and leaves it
unset (``pypcap`` and ``pcap_ct`` decline both, ``pyshark`` reassembly,
``pypcapfile`` IPv6). Any other exception is an ``ERROR``.

This module reads generated captures, so it is in the fixture-dependent tier
(see :mod:`tests._tiers`) and runs after ``make samples``.

"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class, sample_path
from tests._tiers import SAMPLE_ROOT
from tests.foundation import _roundtrip as harness
from tests.foundation._roundtrip import Gap, Outcome

if TYPE_CHECKING:
    from typing import Any, Optional

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Every capture on disk, enumerated rather than hand-picked.
CAPTURES = sorted(name for name in os.listdir(SAMPLE_ROOT)
                  if name.endswith(('.pcap', '.cap', '.pcapng')))
#: Every engine but ``default``, as :attr:`Extractor.__engine__` names them.
ENGINES = ('dpkt', 'scapy', 'pyshark', 'pypcap', 'pcap_ct', 'pypcapfile')
ASPECTS = ('frames', 'timestamps', 'octets', 'ipv4', 'ipv6', 'tcp', 'trace', 'datagrams', 'flows')
#: Engines whose frame objects keep no octets to compare, and why.
NO_OCTETS = {
    'pyshark': 'pyshark reports dissected fields, not the frame octets',
    'pypcapfile': 'the pypcapfile engine replaces the frame octets with decoded layers',
}
#: Engines whose flow-tracing input carries no TCP octets, and why. Their ``trace``
#: comparison leaves out ``header`` and ``payload`` and compares every other field.
NO_TCP_OCTETS = {
    'pyshark': 'pyshark reports dissected fields, not the octets behind them, so tcp_traceflow '
               "hands the tracer empty ones and Extractor refuses trace_analyse for it "
               '(pcapkit/foundation/extraction.py:1446-1455; ruling on #1507)',
}
#: Engines whose flow files are JSON whatever ``trace_format`` asks for, and why. Their
#: ``flows`` comparison checks each flow's label and frame indices, not the file's octets.
JSON_TRACE = {
    'pyshark': 'pyshark cannot supply the frame bytes a PCAP trace needs, so Extractor writes '
               "JSON with a FormatWarning (pcapkit/foundation/extraction.py:1440-1444; ruling "
               'on #1507)',
}
#: Captures with at least one TCP flow, measured on ``00d232890``.
TRACED = ('http.pcap', 'http6.cap', 'in.pcap', 'many_interfaces.pcapng', 'options-tcp.pcap',
          'options-transport.pcap', 'stream.pcap', 'tcp.pcap', 'test.pcap')
#: The PCAP captures among them whose flows are all over IPv4.
TRACED_IPV4_ONLY_PCAP = ('http.pcap', 'in.pcap', 'options-tcp.pcap', 'options-transport.pcap')


def _plain(value: 'Any') -> 'Any':
    return bytes(value) if isinstance(value, bytearray) else value


def _fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
    return {key: _plain(value) for key, value in packet.items() if key not in skip}


def _record(engine: 'str', frame: 'Any') -> 'tuple[float, Optional[bytes]]':
    """``(timestamp, octets)`` of one frame; octets are :data:`None` per :data:`NO_OCTETS`."""
    if engine == 'default':
        info = frame.info
        stamp = info.time_epoch if 'time_epoch' in info else info.timestamp_epoch
        return float(stamp), bytes(info.packet)
    if engine == 'dpkt':
        from pcapkit.toolkit.dpkt import packet2bytes, packet2timestamp
        return float(packet2timestamp(frame)), packet2bytes(frame)
    if engine == 'scapy':
        return float(frame.time), bytes(getattr(frame, 'original', None) or bytes(frame))
    if engine in ('pypcap', 'pcap_ct'):
        stamp, octets = frame
        return float(stamp), bytes(octets)
    if engine == 'pypcapfile':
        from pcapkit.toolkit.pypcapfile import packet2timestamp
        return float(packet2timestamp(frame)), None
    if engine == 'pyshark':
        return float(frame.sniff_timestamp), None
    raise AssertionError(engine)


class _Run:
    """One engine's reading of one capture."""

    def __init__(self, engine: 'str', capture: 'str') -> None:
        from pcapkit import extract
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
        from pcapkit.utilities.warnings import EngineWarning

        self.fallback = None  # type: Optional[str]
        self.inputs = {'ipv4': {}, 'ipv6': {}, 'tcp': {}, 'trace': {}}  # type: dict[str, dict[int, Any]]
        inputs = self.inputs
        reassemble, trace = ReassemblyBase.__call__, TraceFlowBase.__call__

        def spy_reassembly(this: 'Any', packet: 'Any') -> 'None':
            inputs[type(this).__name__.lower()].setdefault(packet.num, []).append(_fields(packet))
            return reassemble(this, packet)

        def spy_trace(this: 'Any', packet: 'Any') -> 'None':
            inputs['trace'].setdefault(packet.index, []).append(_fields(packet, ('frame',)))
            return trace(this, packet)

        with warnings.catch_warnings(), tempfile.TemporaryDirectory() as tracedir, \
                mock.patch.object(ReassemblyBase, '__call__', spy_reassembly), \
                mock.patch.object(TraceFlowBase, '__call__', spy_trace), \
                mock.patch('pcapkit.foundation.extraction.warn') as warn:
            warnings.simplefilter('ignore')
            fallen = []  # type: list[str]
            try:
                extractor = extract(fin=sample_path(capture), nofile=True, store=True,
                                    engine=engine, reassembly=True, ipv4=True, ipv6=True,
                                    tcp=True, trace=True, trace_fout=tracedir, trace_format='pcap')
            except Exception as exc:  # pylint: disable=broad-except
                self.error = f'{type(exc).__name__}: {exc}'  # type: Optional[str]
                fallen = self._fallen(warn, EngineWarning)
                self.fallback = '; '.join(fallen) or None
                return
            self.error = None
            close_extractor(extractor)
            fallen = self._fallen(warn, EngineWarning)
            if fallen or extractor._exnam != engine:  # pylint: disable=protected-access
                self.fallback = '; '.join(fallen) or f'ran as {extractor._exnam}'  # pylint: disable=protected-access
                return
            self.length = extractor.length
            self.records = [_record(engine, frame) for frame in extractor.frame]
            # An engine that declines a protocol says so with a warning and leaves
            # it None; one that declines reassembly or tracing outright makes the
            # property raise. Either way the aspect is None and is skipped, not
            # compared (``pypcap``, ``pyshark``; ``pypcapfile`` for IPv6).
            self.datagrams = {}  # type: dict[str, Optional[list[dict[str, Any]]]]
            reasm = self._property(extractor, 'reassembly')
            for kind in ('ipv4', 'ipv6', 'tcp'):
                datagrams = getattr(reasm, kind, None) if reasm is not None else None
                self.datagrams[kind] = (None if datagrams is None
                                        else [_fields(d, ('packet',)) for d in datagrams])
            self.flows = None  # type: Optional[list[tuple[str, tuple[int, ...], bytes]]]
            trace = self._property(extractor, 'trace')
            if trace is not None and trace.tcp is not None:
                self.flows = []
                for flow in trace.tcp:
                    with open(flow.fpout, 'rb') as file:
                        self.flows.append((flow.label, tuple(flow.index), file.read()))

    @staticmethod
    def _fallen(warn: 'Any', category: 'type') -> 'list[str]':
        return [str(call.args[0]) for call in warn.call_args_list
                if len(call.args) > 1 and call.args[1] is category]

    @staticmethod
    def _property(extractor: 'Any', name: 'str') -> 'Any':
        from pcapkit.utilities.exceptions import UnsupportedCall

        try:
            return getattr(extractor, name)
        except UnsupportedCall:
            return None


_RUNS = {}  # type: dict[tuple[str, str], _Run]


def _run(engine: 'str', capture: 'str') -> '_Run':
    key = (engine, capture)
    if key not in _RUNS:
        _RUNS[key] = _Run(engine, capture)
    return _RUNS[key]


def _without_tcp_octets(inputs: 'dict[int, Any]') -> 'dict[int, Any]':
    """``trace`` inputs without ``header`` and ``payload``, per :data:`NO_TCP_OCTETS`."""
    return {number: [{key: value for key, value in packet.items() if key not in ('header', 'payload')}
                     for packet in packets] for number, packets in inputs.items()}


def _first_difference(got: 'dict[int, Any]', want: 'dict[int, Any]') -> 'Optional[str]':
    for number in sorted(set(got) | set(want)):
        if number not in got:
            return f'frame {number}: missing, default has {len(want[number])} input(s)'
        if number not in want:
            return f'frame {number}: extra, default has none'
        if got[number] != want[number]:
            if len(got[number]) != len(want[number]):
                return f'frame {number}: {len(got[number])} inputs != {len(want[number])}'
            for mine, theirs in zip(got[number], want[number]):
                diff = [f'{key} {mine.get(key)!r:.70} != {theirs.get(key)!r:.70}'
                        for key in sorted(set(mine) | set(theirs)) if mine.get(key) != theirs.get(key)]
                if diff:
                    return f'frame {number}: ' + '; '.join(diff)
    return None


def compare(engine: 'str', capture: 'str', aspect: 'str') -> 'Outcome':
    run = _run(engine, capture)
    if run.fallback is not None:
        return Outcome('SKIP', f'{engine} did not run: {run.fallback}')
    if run.error is not None:
        if 'reads PCAP savefiles only' in run.error:  # a documented refusal, not a reading
            return Outcome('SKIP', f'{engine} refuses {capture}: {run.error}')
        return Outcome('ERROR', run.error)
    base = _run('default', capture)
    if aspect in ('ipv4', 'ipv6', 'tcp') and run.datagrams[aspect] is None:
        return Outcome('SKIP', f'{engine} declines {aspect} reassembly')
    if aspect == 'trace' and run.flows is None:
        return Outcome('SKIP', f'{engine} declines flow tracing')
    if aspect == 'frames':
        if run.length != base.length:
            return Outcome('FRAMES', f'{run.length} frames != {base.length}')
        return Outcome('OK')
    if aspect in ('timestamps', 'octets'):
        if aspect == 'octets' and engine in NO_OCTETS:
            return Outcome('SKIP', NO_OCTETS[engine])
        field = 0 if aspect == 'timestamps' else 1
        mine, theirs = [r[field] for r in run.records], [r[field] for r in base.records]
        for number, (one, two) in enumerate(zip(mine, theirs), 1):
            if one != two:
                return Outcome('RECORDS', f'frame {number}: {aspect[:-1]} {one!r:.70} != {two!r:.70}')
        if len(mine) != len(theirs):
            return Outcome('RECORDS', f'{len(mine)} {aspect} != {len(theirs)}')
        return Outcome('OK')
    if aspect in run.inputs:
        mine, theirs = run.inputs[aspect], base.inputs[aspect]
        if aspect == 'trace' and engine in NO_TCP_OCTETS:
            mine, theirs = _without_tcp_octets(mine), _without_tcp_octets(theirs)
        diff = _first_difference(mine, theirs)
        return Outcome('INPUTS', diff) if diff else Outcome('OK')
    if aspect == 'datagrams':
        kinds = [kind for kind in ('ipv4', 'ipv6', 'tcp') if run.datagrams[kind] is not None]
        if not kinds:
            return Outcome('SKIP', f'{engine} declines reassembly')
        for kind in kinds:
            mine, theirs = run.datagrams[kind], base.datagrams[kind]
            if mine != theirs:
                if len(mine) != len(theirs):
                    return Outcome('DATAGRAMS', f'{kind}: {len(mine)} datagrams != {len(theirs)}')
                for position, (one, two) in enumerate(zip(mine, theirs)):
                    diff = [key for key in one if one[key] != two.get(key)]
                    if diff:
                        return Outcome('DATAGRAMS', f'{kind} datagram {position}: {", ".join(diff)} differ')
        return Outcome('OK')
    if aspect == 'flows':
        if run.flows is None:
            return Outcome('SKIP', f'{engine} declines flow tracing')
        if [f[:2] for f in run.flows] != [f[:2] for f in base.flows]:
            return Outcome('FLOWS', f'flows {[f[:2] for f in run.flows]!r:.200} != '
                                    f'{[f[:2] for f in base.flows]!r:.200}')
        if engine in JSON_TRACE:
            return Outcome('OK')
        for (label, _, mine), (_, _, theirs) in zip(run.flows, base.flows):
            if mine != theirs:
                return Outcome('FLOWS', f'{label}: file of {len(mine)} octets != {len(theirs)} '
                                        f'(head {mine[:24].hex()} != {theirs[:24].hex()})')
        return Outcome('OK')
    raise AssertionError(aspect)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestEngineAgreement(harness.RoundTripBase):
    """Every engine that runs agrees with ``default`` on every capture."""

    STATUSES = ('ERROR', 'FRAMES', 'RECORDS', 'INPUTS', 'DATAGRAMS', 'FLOWS')
    KNOWN_FAILURES = (
        Gap(1507, "the pypcapfile engine writes every flow as JSON when asked for "
               "trace_format='pcap': its tcp_traceflow adapter builds the frame with "
               'packet2dict (pcapkit/toolkit/pypcapfile.py:620), which PCAPIO cannot write, so '
               'Extractor swaps the format with a FormatWarning '
               '(pcapkit/foundation/extraction.py:1439-1443)',
            'FLOWS', 'file of ', tuple(f'{capture}/pypcapfile/flows' for capture in TRACED_IPV4_ONLY_PCAP)),
        Gap(1512, 'the pypcapfile engine reads no frame from a big-endian PCAP, without a warning: '
               'pcapfile.savefile.load_savefile (pypcapfile 0.12.0) yields no packets for one, '
               'and the engine iterates that empty list (pcapkit/foundation/engines/'
               'pypcapfile.py:235, :249)',
            ('FRAMES', 'RECORDS', 'INPUTS', 'DATAGRAMS'),
            ('0 frames != 3', '0 timestamps != 3', 'frame 1: missing', '0 datagrams != 3'),
            tuple(f'{capture}/pypcapfile/{aspect}'
                  for capture in ('big_endian.pcap', 'big_endian_nanosecond.pcap')
                  for aspect in ('frames', 'timestamps', 'ipv4', 'datagrams'))),
        Gap(1513, 'the pypcapfile engine leaves TCP over IPv6 out of TCP reassembly and flow '
               'tracing, without a warning: _network returns None for any frame that is not '
               'IPv4 (pcapkit/toolkit/pypcapfile.py:262), so tcp_reassembly (:540) and '
               'tcp_traceflow (:603) skip it; only IPv6 reassembly is declined with a warning '
               '(pcapkit/foundation/engines/pypcapfile.py:229)',
            ('INPUTS', 'DATAGRAMS', 'FLOWS'), ('missing, default has', 'tcp: ', 'flows ['),
            tuple(f'{capture}/pypcapfile/{aspect}'
                  for capture in ('http6.cap', 'stream.pcap', 'tcp.pcap', 'test.pcap')
                  for aspect in ('tcp', 'trace', 'datagrams', 'flows'))),
        Gap(1515, 'the pyshark engine counts a Systemd Journal Export Block as a frame: tshark '
               'numbers it as one, and read_frame takes every tshark frame '
               '(pcapkit/foundation/engines/pyshark.py:245-248)',
            ('FRAMES', 'RECORDS'), ('6 frames != 5', 'frame 5: timestamp '),
            ('test.pcapng/pyshark/frames', 'test.pcapng/pyshark/timestamps')),
        Gap(1501, 'the dpkt engine hands reassembly the Decimal timestamp dpkt reads from a '
               'nanosecond PCAP (pcapkit/foundation/engines/dpkt.py:309), where every other '
               'engine hands it a float (pcapkit/toolkit/pcap.py:73)',
            'INPUTS', "timestamp Decimal('1500000000.123456789') != 1500000000.1234567",
            ('big_endian_nanosecond.pcap/dpkt/ipv4',)),
        Gap(1520, "pcapkit's own PCAPNGReader for the dpkt engine yields only Enhanced and "
               'obsolete Packet Blocks, so a Simple Packet Block is dropped and every later '
               'frame shifts by one (pcapkit/foundation/engines/dpkt.py:124)',
            ('FRAMES', 'RECORDS', 'INPUTS', 'DATAGRAMS'),
            ('4 frames != 5', 'frame 4: ', '2 datagrams != 3'),
            ('test.pcapng/dpkt/frames', 'test.pcapng/dpkt/timestamps', 'test.pcapng/dpkt/octets',
             'test.pcapng/dpkt/ipv4',
             'test.pcapng/dpkt/datagrams')),
        Gap(1502, 'the default engine does not dissect LINKTYPE_RAW (101) frames, which scapy reads '
               'as IPv4: neither Frame.__proto__ nor PCAPNG.__proto__ registers LinkType.RAW '
               '(pcapkit/protocols/misc/pcap/frame.py:90, pcapkit/protocols/misc/pcapng.py:699), '
               'so those frames are Raw and never reach reassembly',
            ('INPUTS', 'DATAGRAMS'), ('extra, default has none', 'datagrams != '),
            ('test.pcapng/scapy/ipv4', 'test.pcapng/scapy/datagrams',
             'many_interfaces.pcapng/scapy/ipv4', 'many_interfaces.pcapng/scapy/datagrams')),
        Gap(1503, 'the scapy engine dates a Simple Packet Block, which carries no timestamp, with '
               'the wall-clock time it was read (scapy leaves Packet.time at construction; '
               'pcapkit/toolkit/scapy.py:186 forwards it), where default reports 0',
            'RECORDS', 'frame 4: timestamp ', ('test.pcapng/scapy/timestamps',)),
    )

    def setUp(self) -> None:
        super().setUp()
        reimport_once_per_class(self)

    @classmethod
    def tearDownClass(cls) -> None:
        _RUNS.clear()
        super().tearDownClass()

    def labels(self) -> 'list[str]':
        return [f'{capture}/{engine}/{aspect}' for capture in CAPTURES for engine in ENGINES
                for aspect in ASPECTS]

    def outcome(self, label: 'str') -> 'Outcome':
        capture, engine, aspect = label.split('/')
        return compare(engine, capture, aspect)


if __name__ == '__main__':
    unittest.main()
