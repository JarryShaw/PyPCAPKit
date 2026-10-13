# -*- coding: utf-8 -*-
"""``pypcapfile`` hands over what ``default`` does, by link type and to the frame layer bound. C.f. #1609, #1667.

The ``default`` engine dissects the IP packet of the ``NULL``, ``LOOP``,
``RAW``, ``IPV4`` and ``IPV6`` link types, which `pypcapfile`_ 0.12.0 has no
decoder for (#1667), and at most
:data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers of a frame, each
VLAN tag, IP header, AH and IPv6 extension header one of them (#1609). Both
engines read one capture per case, built in a temporary directory, with IPv4
and TCP reassembly and flow tracing on, and ``pypcapfile``'s ``tcp``, ``trace``
and ``ipv4`` inputs are compared with ``default``'s field for field, as in
:mod:`tests.foundation.engines.test_ext_chain_limit_agreement_1604_unit`.

``pypcapfile`` leaves TCP over IPv6 out, so its ``tcp`` and ``trace`` inputs are
compared over IPv4 only, and ``declined`` checks that it warns of leaving some
out exactly where ``default`` finds any. ``unread`` checks that the engine warns
of a link type left unread exactly where ``default`` dissects nothing of it. It
imports on Python 3.11 only, and is skipped elsewhere.

.. _pypcapfile: https://github.com/kisom/pypcapfile

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
from tests.foundation._roundtrip import Outcome

if TYPE_CHECKING:
    from typing import Any, Optional

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: ``LINKTYPE_*`` numbers, by name.
LINKTYPES = {'NULL': 0, 'ETHERNET': 1, 'LOOP': 108, 'RAW': 101, 'IPV4': 228, 'IPV6': 229,
             'DLT12': 12, 'LINUX_SLL': 113}
#: Link types the ``default`` engine dissects nothing of.
UNREAD = ('DLT12', 'LINUX_SLL')

TCP = harness.tcp(b'payload', seq=1, syn=True)
TCP4 = harness.ipv4(TCP, proto=6)
TCP6 = harness.ipv6(TCP, nxt=6)
UDP = harness.udp(b'u' * 24)
FRAG4 = (harness.ipv4(UDP[:16], proto=17, mf=True), harness.ipv4(UDP[16:], proto=17, offset=16))
FRAG6 = (harness.ipv6_fragment(UDP[:16], mf=True), harness.ipv6_fragment(UDP[16:], offset=16))
#: Payloads, each the IP version it starts with and the packets of its frames.
PAYLOADS = {
    'ipv4-tcp': (4, [TCP4]),
    'ipv6-tcp': (6, [TCP6]),
    'ipv4-frags': (4, list(FRAG4)),
    'ipv6-frags': (6, list(FRAG6)),
    '4in6-tcp': (6, [harness.ipv6(TCP4, nxt=4)]),
    '4in6-frags': (6, [harness.ipv6(fragment, nxt=4) for fragment in FRAG4]),
}


def link(name: 'str', packet: 'bytes', version: 'int') -> 'bytes':
    """``packet`` as a frame of the link type ``name``."""
    if name == 'ETHERNET':
        return harness.ethernet(packet, 0x0800 if version == 4 else 0x86DD)
    if name in ('NULL', 'LOOP'):
        family = 2 if version == 4 else 24
        return family.to_bytes(4, 'little' if name == 'NULL' else 'big') + packet
    if name == 'LINUX_SLL':
        return (b'\x00\x00\x00\x01\x00\x06' + b'\x02' * 8
                + (0x0800 if version == 4 else 0x86DD).to_bytes(2, 'big') + packet)
    return packet


def nest4(inner: 'bytes', count: 'int', proto: 'int') -> 'bytes':
    """``count`` IPv4 headers, the innermost carrying ``inner`` as ``proto``."""
    packet = harness.ipv4(inner, proto=proto)
    for _ in range(count - 1):
        packet = harness.ipv4(packet, proto=4)
    return packet


def nest6(inner: 'bytes', count: 'int', nxt: 'int') -> 'bytes':
    """``count`` IPv6 headers, the innermost carrying ``inner`` as ``nxt``."""
    packet = harness.ipv6(inner, nxt=nxt)
    for _ in range(count - 1):
        packet = harness.ipv6(packet, nxt=41)
    return packet


def pairs(count: 'int', version: 'int') -> 'bytes':
    """``count`` pairs of an IPv4 header and an AH, or of an IPv6 header and a Hop-by-Hop Options header, then TCP."""
    packet = TCP
    for index in range(count):
        nxt = 6 if index == 0 else (4 if version == 4 else 41)
        if version == 4:
            ah = bytes([nxt, 4, 0, 0]) + (0x100).to_bytes(4, 'big') + (1).to_bytes(4, 'big') + b'\xaa' * 12
            packet = harness.ipv4(ah + packet, proto=51)
        else:
            packet = harness.ipv6(bytes([nxt, 0, 1, 4, 0, 0, 0, 0]) + packet, nxt=0)
    return packet


def chain(count: 'int', last: 'int') -> 'bytes':
    """``count`` Destination Options headers, the last naming ``last``."""
    return b''.join(bytes([60 if index < count - 1 else last, 0, 1, 4, 0, 0, 0, 0]) for index in range(count))


def tagged(packet: 'bytes', ethertype: 'int', count: 'int', tpid: 'int') -> 'bytes':
    """An Ethernet frame carrying ``packet`` behind ``count`` VLAN tags of ``tpid``."""
    tags = b''.join((100 + index).to_bytes(2, 'big') + (tpid if index < count - 1 else ethertype).to_bytes(2, 'big')
                    for index in range(count))
    return harness.MAC_B + harness.MAC_A + tpid.to_bytes(2, 'big') + tags + packet


def cases() -> 'dict[str, tuple[int, list[bytes]]]':
    """Every case, as the link type of its capture and its frames."""
    out = {}  # type: dict[str, tuple[int, list[bytes]]]
    for name, linktype in LINKTYPES.items():
        for kind, (version, packets) in PAYLOADS.items():
            if (name, version) not in (('IPV4', 6), ('IPV6', 4)):
                out[f'{name}-{kind}'] = (linktype, [link(name, packet, version) for packet in packets])
    out['NULL-big-endian-family'] = (0, [(2).to_bytes(4, 'big') + TCP4])
    out['LOOP-little-endian-family'] = (108, [(2).to_bytes(4, 'little') + TCP4])
    out['NULL-af28-ipv6-tcp'] = (0, [(28).to_bytes(4, 'little') + TCP6])
    out['RAW-version-5'] = (101, [b'\x55' + TCP4[1:]])
    out['RAW-6in4-tcp'] = (101, [harness.ipv4(TCP6, proto=41)])
    out['RAW-tcp-behind-ah'] = (101, [pairs(1, 4)])
    for count in (62, 63):
        out[f'ETHERNET-tcp-in-{count}-ipv4'] = (1, [harness.ethernet(nest4(TCP, count, 6), 0x0800)])
        out[f'ETHERNET-ipv4-frags-in-{count}-ipv6'] = (
            1, [harness.ethernet(nest6(fragment, count, 4), 0x86DD) for fragment in FRAG4])
        out[f'NULL-tcp-in-{count}-ipv4'] = (0, [(2).to_bytes(4, 'little') + nest4(TCP, count, 6)])
        out[f'IPV6-4in6-tcp-in-{count}-ipv6'] = (229, [nest6(TCP4, count, 4)])
    for count in (63, 64):
        out[f'RAW-tcp-in-{count}-ipv4'] = (101, [nest4(TCP, count, 6)])
        out[f'RAW-ipv4-frags-in-{count}-ipv6'] = (101, [nest6(fragment, count, 4) for fragment in FRAG4])
    for count in (61, 62):
        out[f'ETHERNET-4in6-tcp-in-{count}-ipv6'] = (1, [harness.ethernet(nest6(TCP4, count, 4), 0x86DD)])
        out[f'ETHERNET-ipv6-tcp-behind-{count}-tags'] = (1, [tagged(TCP6, 0x86DD, count, 0x8100)])
    for count in (31, 32):
        out[f'ETHERNET-tcp-behind-{count}-ipv4-ah'] = (1, [harness.ethernet(pairs(count, 4), 0x0800)])
        out[f'ETHERNET-tcp-behind-{count}-ipv6-hbh'] = (1, [harness.ethernet(pairs(count, 6), 0x86DD)])
        out[f'ETHERNET-tcp-in-31-ipv4-behind-{count}-headers'] = (
            1, [harness.ethernet(nest4(chain(count, 6) + TCP, 31, 60), 0x0800)])
    for count in (61, 62, 63):
        for tpid in (0x8100, 0x88A8):
            out[f'ETHERNET-tcp-behind-{count}-tags-{tpid:04x}'] = (1, [tagged(TCP4, 0x0800, count, tpid)])
            out[f'ETHERNET-ipv4-frags-behind-{count}-tags-{tpid:04x}'] = (
                1, [tagged(fragment, 0x0800, count, tpid) for fragment in FRAG4])
    return out


#: Every case, built once.
CASES = cases()


def _fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
    return {key: bytes(value) if isinstance(value, bytearray) else value
            for key, value in packet.items() if key not in skip}


class _Run:
    """One engine's reading of one capture."""

    def __init__(self, engine: 'str', path: 'str') -> None:
        from pcapkit import extract
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
        from pcapkit.utilities.warnings import AttributeWarning, EngineWarning

        self.error = self.fallback = None  # type: Optional[str]
        #: What the ``pypcapfile`` toolkit warned it leaves out, if anything.
        self.declined = None  # type: Optional[str]
        #: Whether the ``pypcapfile`` engine warned it leaves the link type unread.
        self.unread = False
        self.inputs = {'ipv4': {}, 'tcp': {}, 'trace': {}}  # type: dict[str, dict[int, list[dict[str, Any]]]]
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
                mock.patch('pcapkit.foundation.extraction.warn') as warn, \
                mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as engine_warn, \
                mock.patch('pcapkit.toolkit.pypcapfile.warn') as toolkit_warn:
            warnings.simplefilter('ignore')
            try:
                extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, ipv4=True,
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
            self.unread = any('unrecognised link layer protocol' in str(call.args[0])
                              for call in engine_warn.call_args_list)


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
class TestPyPCAPFileLinkTypeAndLayerBoundAgreement(harness.RoundTripBase):
    """``pypcapfile`` hands over what ``default`` does over every case, or is a recorded gap."""

    STATUSES = ('ERROR', 'INPUTS', 'DECLINED', 'UNREAD')
    KNOWN_FAILURES = ()

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        for name, (linktype, frames) in CASES.items():
            with open(cls.path(name), 'wb') as file:
                file.write(harness.pcap([(1, index, frame) for index, frame in enumerate(frames)],
                                        linktype=linktype))

    @classmethod
    def tearDownClass(cls) -> None:
        _RUNS.clear()
        cls.tmp.cleanup()
        super().tearDownClass()

    @classmethod
    def path(cls, name: 'str') -> 'str':
        return os.path.join(cls.tmp.name, f'{name}.pcap')

    def setUp(self) -> None:
        super().setUp()
        reimport_once_per_class(self)

    def labels(self) -> 'list[str]':
        return [f'{name}/{aspect}' for name in CASES
                for aspect in ('tcp', 'trace', 'ipv4', 'declined', 'unread')]

    def run_of(self, engine: 'str', name: 'str') -> '_Run':
        if (engine, name) not in _RUNS:
            _RUNS[engine, name] = _Run(engine, self.path(name))
        return _RUNS[engine, name]

    def outcome(self, label: 'str') -> 'Outcome':
        name, aspect = label.split('/')
        run = self.run_of('pypcapfile', name)
        if run.fallback is not None:
            return Outcome('SKIP', f'pypcapfile did not run: {run.fallback}')
        if run.error is not None:
            return Outcome('ERROR', run.error)
        base = self.run_of('default', name)
        if base.error is not None or base.fallback is not None:
            return Outcome('ERROR', f'default: {base.error or base.fallback}')

        if aspect == 'unread':
            if run.unread != name.startswith(UNREAD):
                return Outcome('UNREAD', f'warned of the link type left unread: {run.unread}')
            return Outcome('OK')
        over_ipv6 = any(not _over_ipv4(records[0]) for records in base.inputs['tcp'].values())
        if aspect == 'declined':
            if (run.declined is not None) != over_ipv6:
                return Outcome('DECLINED', f'warned {run.declined!r}, but default finds TCP over IPv6: '
                                           f'{over_ipv6}')
            return Outcome('OK')

        mine, theirs = run.inputs[aspect], base.inputs[aspect]
        if aspect != 'ipv4':
            theirs = {number: records for number, records in theirs.items() if _over_ipv4(records[0])}
        diff = _difference(mine, theirs)
        return Outcome('INPUTS', diff) if diff else Outcome('OK')


if __name__ == '__main__':
    unittest.main()
