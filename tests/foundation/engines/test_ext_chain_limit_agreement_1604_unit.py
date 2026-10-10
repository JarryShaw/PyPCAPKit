# -*- coding: utf-8 -*-
"""Every engine stops a chain of IPv6 extension headers where ``default`` does. C.f. #1604.

The ``default`` engine dissects at most
:data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` extension
headers in a row, and leaves the rest raw, so the TCP behind a longer chain is
not found. Each engine here reads one capture per chain length -- 30, 32, 33 and
1,000 Destination Options headers, then a TCP segment -- carried in IPv4 and in
IPv6, with TCP reassembly and flow tracing on, and its ``tcp`` and ``trace``
inputs are compared with ``default``'s, as in
:mod:`tests.foundation.engines.test_engine_agreement_runtime`.

``pypcapfile`` walks the chain itself and stops at the same depth. It leaves TCP
over IPv6 out, so it is compared over IPv4 only, and ``declined`` checks that
it warns of leaving out TCP over IPv6 exactly where ``default`` finds some. It
imports on Python 3.11 only, and is skipped elsewhere.

The other parsers walk the chain themselves, and cannot be told where to stop,
so where they find the TCP past the limit is recorded in :attr:`KNOWN_FAILURES`
under #1609 rather than hidden. Measured on dpkt 1.9.8, scapy 2.7.0 and tshark 4.6.9.

Every capture is built in a temporary directory, so no fixture is read.

"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as harness
from tests.foundation._roundtrip import Gap, Outcome

if TYPE_CHECKING:
    from typing import Any, Optional

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Chain lengths: under the limit, at it, one past it, and far past it.
CHAINS = (30, 32, 33, 1000)
#: What carries the chain.
CARRIERS = ('ipv4', 'ipv6')
#: Every engine compared with ``default``, as :attr:`Extractor.__engine__
#: <pcapkit.foundation.extraction.Extractor.__engine__>` names them. ``pypcap``
#: and ``pcap_ct`` decline both reassembly and flow tracing, so are left out.
ENGINES = ('dpkt', 'scapy', 'pyshark', 'pypcapfile')
#: Engines whose flow-tracing input carries no TCP octets, c.f.
#: :data:`tests.foundation.engines.test_engine_agreement_runtime.NO_TCP_OCTETS`.
NO_TCP_OCTETS = ('pyshark',)


def capture(carrier: 'str', count: 'int') -> 'bytes':
    """A PCAP savefile of one frame: ``count`` Destination Options headers, then TCP."""
    headers = b''.join(bytes([60 if index < count - 1 else 6, 0, 1, 4, 0, 0, 0, 0])
                       for index in range(count))
    payload = headers + harness.tcp(b'payload', seq=1)
    if carrier == 'ipv4':
        frame = harness.ethernet(harness.ipv4(payload, proto=60), 0x0800)
    else:
        frame = harness.ethernet(harness.ipv6(payload, nxt=60), 0x86DD)
    return harness.pcap([(1, 0, frame)])


def _fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
    return {key: bytes(value) if isinstance(value, bytearray) else value
            for key, value in packet.items() if key not in skip}


class _Run:
    """One engine's reading of one capture."""

    def __init__(self, engine: 'str', path: 'str') -> None:
        from pcapkit import extract
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
        from pcapkit.utilities.exceptions import UnsupportedCall
        from pcapkit.utilities.warnings import AttributeWarning, EngineWarning

        self.error = self.fallback = None  # type: Optional[str]
        #: What the ``pypcapfile`` toolkit warned it leaves out, if anything.
        self.declined = None  # type: Optional[str]
        #: Whether the engine declines TCP reassembly, or flow tracing.
        self.no_tcp = self.no_trace = False
        self.inputs = {'tcp': {}, 'trace': {}}  # type: dict[str, dict[int, list[dict[str, Any]]]]
        inputs = self.inputs
        reassemble, trace = ReassemblyBase.__call__, TraceFlowBase.__call__

        def spy_reassembly(this: 'Any', packet: 'Any') -> 'None':
            inputs['tcp'].setdefault(packet.num, []).append(_fields(packet))
            return reassemble(this, packet)

        def spy_trace(this: 'Any', packet: 'Any') -> 'None':
            inputs['trace'].setdefault(packet.index, []).append(_fields(packet, ('frame',)))
            return trace(this, packet)

        with warnings.catch_warnings(), tempfile.TemporaryDirectory() as tracedir, \
                mock.patch.object(ReassemblyBase, '__call__', spy_reassembly), \
                mock.patch.object(TraceFlowBase, '__call__', spy_trace), \
                mock.patch('pcapkit.foundation.extraction.warn') as warn, \
                mock.patch('pcapkit.toolkit.pypcapfile.warn') as toolkit_warn:
            warnings.simplefilter('ignore')
            try:
                extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True,
                                    tcp=True, trace=True, trace_fout=tracedir, trace_format='json')
            except Exception as exc:  # pylint: disable=broad-except
                self.error = f'{type(exc).__name__}: {exc}'
                return
            close_extractor(extractor)
            fallen = [str(call.args[0]) for call in warn.call_args_list
                      if len(call.args) > 1 and call.args[1] is EngineWarning]
            if fallen or extractor._exnam != engine:  # pylint: disable=protected-access
                self.fallback = '; '.join(fallen) or f'ran as {extractor._exnam}'  # pylint: disable=protected-access
                return
            self.declined = '; '.join(str(call.args[0]) for call in toolkit_warn.call_args_list
                                      if len(call.args) > 1 and call.args[1] is AttributeWarning
                                      and 'is left out of TCP reassembly' in str(call.args[0])) or None
            for name in ('reassembly', 'trace'):
                try:
                    found = getattr(getattr(extractor, name), 'tcp', None)
                except UnsupportedCall:
                    found = None
                setattr(self, 'no_tcp' if name == 'reassembly' else 'no_trace', found is None)


_RUNS = {}  # type: dict[tuple[str, str], _Run]


def _over_ipv4(record: 'dict[str, Any]') -> 'bool':
    address = record['bufid'][0] if 'bufid' in record else record['src']
    return isinstance(address, ipaddress.IPv4Address)


def _difference(got: 'dict[int, Any]', want: 'dict[int, Any]') -> 'Optional[str]':
    for number in sorted(set(got) | set(want)):
        if number not in got:
            return f'frame {number}: missing, default has {len(want[number])} input(s)'
        if number not in want:
            return f'frame {number}: extra, default has none'
        if got[number] != want[number]:
            return f'frame {number}: {got[number]!r:.120} != {want[number]!r:.120}'
    return None


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestExtensionHeaderChainAgreement(harness.RoundTripBase):
    """Every engine that runs stops the chain where ``default`` does, or is a recorded gap."""

    STATUSES = ('ERROR', 'INPUTS', 'DECLINED')
    KNOWN_FAILURES = (
        Gap(1609, 'dpkt walks the whole extension header chain in a loop (dpkt.ip6.IP6.unpack), '
                  'so finds the TCP past EXTENSION_HEADER_LIMIT that the default engine leaves raw',
            'INPUTS', 'extra, default has none', ('ipv6-33/dpkt/*', 'ipv6-1000/dpkt/*')),
        Gap(1609, 'scapy dissects each extension header behind the last, with no limit of its own, '
                  'so finds the TCP past EXTENSION_HEADER_LIMIT; it gives up near 245 layers at the '
                  'default recursion limit, and so agrees at 1,000',
            'INPUTS', 'extra, default has none', ('ipv6-33/scapy/*',)),
        Gap(1609, 'tshark dissects up to about 496 extension headers, so finds the TCP past '
                  'EXTENSION_HEADER_LIMIT, carried in IPv4 or IPv6; at 1,000 it gives up and agrees',
            'INPUTS', 'extra, default has none', ('ipv4-33/pyshark/trace', 'ipv6-33/pyshark/trace')),
        Gap(1606, 'dpkt and scapy dissect no IPv6 extension header carried in IPv4 '
                  '(dpkt keeps the payload of IPv4 protocol 60 as bytes, scapy as Raw), so find no '
                  'TCP behind one, where the default engine reads past it at any length up to '
                  'EXTENSION_HEADER_LIMIT',
            'INPUTS', 'missing, default has', ('ipv4-30/dpkt/*', 'ipv4-32/dpkt/*',
                                               'ipv4-30/scapy/*', 'ipv4-32/scapy/*')),
    )

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        for carrier in CARRIERS:
            for count in CHAINS:
                with open(cls.path(carrier, count), 'wb') as file:
                    file.write(capture(carrier, count))

    @classmethod
    def tearDownClass(cls) -> None:
        _RUNS.clear()
        cls.tmp.cleanup()
        super().tearDownClass()

    @classmethod
    def path(cls, carrier: 'str', count: 'int') -> 'str':
        return os.path.join(cls.tmp.name, f'{carrier}-{count}.pcap')

    def setUp(self) -> None:
        super().setUp()
        reimport_once_per_class(self)

    def labels(self) -> 'list[str]':
        return [f'{carrier}-{count}/{engine}/{aspect}'
                for carrier in CARRIERS for count in CHAINS for engine in ENGINES
                for aspect in ('tcp', 'trace', 'declined')
                if aspect != 'declined' or engine == 'pypcapfile']

    def run_of(self, engine: 'str', name: 'str') -> '_Run':
        if (engine, name) not in _RUNS:
            carrier, count = name.split('-')
            _RUNS[engine, name] = _Run(engine, self.path(carrier, int(count)))
        return _RUNS[engine, name]

    def outcome(self, label: 'str') -> 'Outcome':
        name, engine, aspect = label.split('/')
        run = self.run_of(engine, name)
        if run.fallback is not None:
            return Outcome('SKIP', f'{engine} did not run: {run.fallback}')
        if run.error is not None:
            return Outcome('ERROR', run.error)
        base = self.run_of('default', name)
        if base.error is not None or base.fallback is not None:
            return Outcome('ERROR', f'default: {base.error or base.fallback}')

        over_ipv6 = any(not _over_ipv4(records[0]) for records in base.inputs['tcp'].values())
        if aspect == 'declined':
            if (run.declined is not None) != over_ipv6:
                return Outcome('DECLINED', f'warned {run.declined!r}, but default finds TCP over IPv6: '
                                           f'{over_ipv6}')
            return Outcome('OK')
        if (aspect == 'tcp' and run.no_tcp) or (aspect == 'trace' and run.no_trace):
            return Outcome('SKIP', f'{engine} declines {aspect}')

        mine, theirs = run.inputs[aspect], base.inputs[aspect]
        if run.declined is not None:
            theirs = {number: records for number, records in theirs.items() if _over_ipv4(records[0])}
        if aspect == 'trace' and engine in NO_TCP_OCTETS:
            def strip(inputs: 'dict[int, Any]') -> 'dict[int, Any]':
                return {number: [{key: value for key, value in record.items()
                                  if key not in ('header', 'payload')} for record in records]
                        for number, records in inputs.items()}
            mine, theirs = strip(mine), strip(theirs)
        diff = _difference(mine, theirs)
        return Outcome('INPUTS', diff) if diff else Outcome('OK')


if __name__ == '__main__':
    unittest.main()
