# -*- coding: utf-8 -*-
"""Shared harness for the foundation round-trip modules. C.f. #1202.

The owner's rule is that every round trip the library promises passes and
matches exactly. Four foundation paths make such a promise, and each has a
module beside this one that enumerates its cases:

* reassembly recovers the payload its fragments or segments were cut from
  (:file:`reassembly/test_reassembly_payload_roundtrip_unit.py`);
* flow tracing writes each flow to a file that reads back as exactly that
  flow's frames (:file:`traceflow/test_traceflow_reread_roundtrip_unit.py`,
  and the ``_runtime`` twin over :file:`examples/captures/`);
* every offline engine reports what the ``default`` engine reports, field for
  field (:file:`engines/test_engine_agreement_runtime.py`);
* a registrar handed back the entry it shipped with leaves every registry it
  touches as it was (:file:`registry/test_registry_symmetry_unit.py`).

A case that does not close goes in its module's ``KNOWN_FAILURES``, one
:class:`Gap` per root cause, in the style of
:mod:`tests.protocols._edge_roundtrip`. The table is asserted in both
directions: a case it does not list must pass, and a case it lists must still
fail as recorded, so a fixed defect turns the module red until its entry goes.

Nothing here imports :mod:`pcapkit`.

"""

from __future__ import annotations

import fnmatch
import struct
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import time_limit

if TYPE_CHECKING:
    from typing import Optional

#: Whole seconds one case may take.
CASE_TIMEOUT = 60


class Outcome(NamedTuple):
    """What one check found."""

    #: ``'OK'``, ``'SKIP'`` (the case cannot run here, e.g. an engine's
    #: dependency is missing), or one of the module's failure statuses.
    status: 'str'
    #: What differed, observed against expected.
    detail: 'str' = ''


class Gap(NamedTuple):
    """One root cause, and every case it stops."""

    #: GitHub issue tracking the defect.
    issue: 'Optional[int]'
    #: The defect, with the ``file:line`` that causes it.
    defect: 'str'
    #: Status every case below reports, or the statuses of which each must
    #: report one.
    status: 'str | tuple[str, ...]'
    #: Substring every failure detail contains, or a tuple of which each
    #: detail contains at least one.
    fragment: 'str | tuple[str, ...]'
    #: Labels of the cases this defect stops, as :mod:`fnmatch` patterns. Each
    #: pattern matches at least one case, and every case it matches fails.
    cases: 'tuple[str, ...]'


def _as_tuple(value: 'str | tuple[str, ...]') -> 'tuple[str, ...]':
    return (value,) if isinstance(value, str) else value


###############################################################################
# Wire builders, so the unit-tier modules read no capture.
###############################################################################

#: Ethernet addresses every built frame uses.
MAC_A, MAC_B = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
#: IPv4 and IPv6 endpoints every built packet uses, as octets.
IPV4_A, IPV4_B = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2])
IPV6_A = bytes.fromhex('20010db8000000000000000000000001')
IPV6_B = bytes.fromhex('20010db8000000000000000000000002')


def checksum(data: 'bytes') -> 'int':
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    total = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(payload: 'bytes', ethertype: 'int', *, reverse: 'bool' = False) -> 'bytes':
    """An Ethernet II frame."""
    src, dst = (MAC_B, MAC_A) if reverse else (MAC_A, MAC_B)
    return dst + src + ethertype.to_bytes(2, 'big') + payload


def ipv4(payload: 'bytes', *, ident: 'int' = 0x1234, offset: 'int' = 0, mf: 'bool' = False,
         df: 'bool' = False, proto: 'int' = 17, reverse: 'bool' = False) -> 'bytes':
    """An IPv4 packet; ``offset`` is in octets and must be a multiple of 8."""
    src, dst = (IPV4_B, IPV4_A) if reverse else (IPV4_A, IPV4_B)
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | (offset // 8)
    header = bytearray(b'\x45\x00' + (20 + len(payload)).to_bytes(2, 'big')
                       + ident.to_bytes(2, 'big') + flags.to_bytes(2, 'big')
                       + bytes([64, proto]) + b'\x00\x00' + src + dst)
    header[10:12] = checksum(bytes(header)).to_bytes(2, 'big')
    return bytes(header) + payload


def ipv6(payload: 'bytes', *, nxt: 'int', reverse: 'bool' = False) -> 'bytes':
    """An IPv6 packet whose first extension header or upper layer is ``nxt``."""
    src, dst = (IPV6_B, IPV6_A) if reverse else (IPV6_A, IPV6_B)
    return (b'\x60\x00\x00\x00' + len(payload).to_bytes(2, 'big') + bytes([nxt, 64])
            + src + dst + payload)


def ipv6_fragment(payload: 'bytes', *, ident: 'int' = 0x12345678, offset: 'int' = 0,
                  mf: 'bool' = False, nxt: 'int' = 17) -> 'bytes':
    """An IPv6 packet carrying one Fragment header (RFC 8200 section 4.5)."""
    word = offset | (1 if mf else 0)
    header = bytes([nxt, 0]) + word.to_bytes(2, 'big') + ident.to_bytes(4, 'big')
    return ipv6(header + payload, nxt=44)


def udp(data: 'bytes', *, sport: 'int' = 40000, dport: 'int' = 9) -> 'bytes':
    """A UDP datagram; port 9 (discard) dispatches to no application layer."""
    return (sport.to_bytes(2, 'big') + dport.to_bytes(2, 'big')
            + (8 + len(data)).to_bytes(2, 'big') + b'\x00\x00' + data)


def tcp(payload: 'bytes', *, seq: 'int', ack: 'int' = 0, syn: 'bool' = False,
        fin: 'bool' = False, rst: 'bool' = False, sport: 'int' = 40000,
        dport: 'int' = 9) -> 'bytes':
    """A TCP segment with no options; the ACK flag is set whenever ``ack`` is."""
    flags = (0x01 if fin else 0) | (0x02 if syn else 0) | (0x04 if rst else 0) | (0x10 if ack else 0)
    return (sport.to_bytes(2, 'big') + dport.to_bytes(2, 'big') + (seq % (1 << 32)).to_bytes(4, 'big')
            + ack.to_bytes(4, 'big') + bytes([0x50, flags]) + b'\xff\xff\x00\x00\x00\x00' + payload)


def pcap(frames: 'list[tuple[int, int, bytes]]', *, linktype: 'int' = 1,
         nanosecond: 'bool' = False, byteorder: 'str' = 'little') -> 'bytes':
    """A PCAP savefile of ``(seconds, fraction, frame)`` records.

    ``fraction`` is microseconds, or nanoseconds when ``nanosecond`` is set.

    """
    order = '<' if byteorder == 'little' else '>'
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    out = [struct.pack(f'{order}IHHiIII', magic, 2, 4, 0, 0, 0xFFFF, linktype)]
    for seconds, fraction, frame in frames:
        out.append(struct.pack(f'{order}IIII', seconds, fraction, len(frame), len(frame)) + frame)
    return b''.join(out)


def pcapng(frames: 'list[tuple[int, int, bytes]]', *, linktype: 'int' = 1,
           nanosecond: 'bool' = False, byteorder: 'str' = 'little') -> 'bytes':
    """A PCAP-NG file of one section and one interface, one EPB per record.

    ``fraction`` is microseconds, or nanoseconds when ``nanosecond`` is set, in
    which case the interface carries ``if_tsresol`` 9.

    """
    order = '<' if byteorder == 'little' else '>'

    def block(kind: 'int', body: 'bytes') -> 'bytes':
        body += b'\x00' * (-len(body) % 4)
        size = 12 + len(body)
        return struct.pack(f'{order}II', kind, size) + body + struct.pack(f'{order}I', size)

    shb = block(0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))
    options = b''
    if nanosecond:  # if_tsresol = 9, then opt_endofopt
        options = struct.pack(f'{order}HH', 9, 1) + b'\x09\x00\x00\x00' + struct.pack(f'{order}HH', 0, 0)
    idb = block(0x00000001, struct.pack(f'{order}HHI', linktype, 0, 0xFFFF) + options)
    out = [shb, idb]
    for seconds, fraction, frame in frames:
        ticks = seconds * (10 ** 9 if nanosecond else 10 ** 6) + fraction
        out.append(block(0x00000006, struct.pack(f'{order}IIIII', 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                                 len(frame), len(frame)) + frame))
    return b''.join(out)


class Savefile(NamedTuple):
    """A PCAP savefile, read without :mod:`pcapkit`."""

    #: ``'little'`` or ``'big'``.
    byteorder: 'str'
    nanosecond: 'bool'
    linktype: 'int'
    #: ``(seconds, fraction, captured length, original length, octets)``.
    records: 'tuple[tuple[int, int, int, int, bytes], ...]'


def read_pcap(data: 'bytes') -> 'Savefile':
    """Read a PCAP savefile with :mod:`struct` alone, as an independent reference."""
    magic = data[:4]
    table = {b'\xd4\xc3\xb2\xa1': ('little', False), b'\xa1\xb2\xc3\xd4': ('big', False),
             b'\x4d\x3c\xb2\xa1': ('little', True), b'\xa1\xb2\x3c\x4d': ('big', True)}
    byteorder, nanosecond = table[magic]
    order = '<' if byteorder == 'little' else '>'
    linktype, = struct.unpack_from(f'{order}I', data, 20)
    records, offset = [], 24
    while offset < len(data):
        sec, frac, incl, orig = struct.unpack_from(f'{order}IIII', data, offset)
        records.append((sec, frac, incl, orig, data[offset + 16:offset + 16 + incl]))
        offset += 16 + incl
    return Savefile(byteorder, nanosecond, linktype, tuple(records))


def payload_pattern(size: 'int', seed: 'int' = 1) -> 'bytes':
    """``size`` octets, none of them zero, so a zero-filled hole shows."""
    return bytes((seed + 7 * i) % 255 + 1 for i in range(size))


class RoundTripBase(unittest.TestCase):
    """The table checks, shared by the foundation round-trip modules.

    A subclass sets :attr:`STATUSES` and :attr:`KNOWN_FAILURES`, and
    implements :meth:`labels` and :meth:`outcome`. This class is not collected
    itself, because :meth:`labels` is empty here.

    """

    #: Failure statuses this module reports.
    STATUSES = ()  # type: tuple[str, ...]
    #: Known failures, one entry per root cause.
    KNOWN_FAILURES = ()  # type: tuple[Gap, ...]

    def labels(self) -> 'list[str]':
        """Every case label, in the order the cases run."""
        return []

    def outcome(self, label: 'str') -> 'Outcome':
        """Run one case."""
        raise NotImplementedError

    def setUp(self) -> None:
        if not self.STATUSES:
            self.skipTest('base class')

    # -- helpers ----------------------------------------------------------

    def _gaps(self, labels: 'list[str]') -> 'dict[str, Gap]':
        table = {}  # type: dict[str, Gap]
        for gap in self.KNOWN_FAILURES:
            for pattern in gap.cases:
                for label in fnmatch.filter(labels, pattern):
                    self.assertIs(table.setdefault(label, gap), gap,
                                  f'{label} is listed under two root causes')
        return table

    def _run(self, label: 'str') -> 'Outcome':
        try:
            with time_limit(CASE_TIMEOUT):
                return self.outcome(label)
        except TimeoutError as exc:
            return Outcome('TIMEOUT', str(exc))

    # -- the tables -------------------------------------------------------

    def test_labels_are_unique(self) -> None:
        labels = self.labels()
        self.assertTrue(labels, 'no cases')
        self.assertEqual(len(labels), len(set(labels)), 'duplicate case labels')

    def test_known_failures_name_real_cases(self) -> None:
        labels = self.labels()
        stale = [pattern for gap in self.KNOWN_FAILURES for pattern in gap.cases
                 if not fnmatch.filter(labels, pattern)]
        self.assertEqual(stale, [], 'KNOWN_FAILURES patterns that match no case')
        for gap in self.KNOWN_FAILURES:
            self.assertTrue(gap.cases, f'empty KNOWN_FAILURES entry: {gap.defect}')
            self.assertTrue(gap.fragment, f'no failure fragment: {gap.defect}')
            for status in _as_tuple(gap.status):
                self.assertIn(status, self.STATUSES + ('TIMEOUT',), gap.defect)
        self._gaps(labels)

    def test_round_trip_is_exact_or_a_recorded_gap(self) -> None:
        labels = self.labels()
        gaps = self._gaps(labels)
        for label in labels:
            with self.subTest(case=label):
                outcome = self._run(label)
                if outcome.status == 'SKIP':
                    self.skipTest(outcome.detail)
                gap = gaps.get(label)
                if gap is None:
                    self.assertEqual(
                        outcome.status, 'OK',
                        f'{label} does not round-trip: {outcome.status}: {outcome.detail}. '
                        'If this is a new defect, add it to KNOWN_FAILURES under its root cause.')
                    continue
                self.assertIn(
                    outcome.status, _as_tuple(gap.status),
                    f'{label} was recorded as failing (#{gap.issue}: {gap.defect}) but came '
                    f'back {outcome.status}: {outcome.detail}. If the defect is fixed, '
                    'delete the label from its entry.')
                self.assertTrue(
                    any(fragment in outcome.detail for fragment in _as_tuple(gap.fragment)),
                    f'{label} fails, but not in the recorded way ({gap.defect}); '
                    f'detail was {outcome.detail!r}')
