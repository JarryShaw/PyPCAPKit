# -*- coding: utf-8 -*-
"""An IGMPv3 Report behind IPv4 and cut inside its records reads no record past the cut.

GitHub issue #2756: an IPv4 datagram whose capture ends inside an IGMPv3 Report's group
records, its total length intact, parsed a record the capture never held. Behind a frame the
record list counts none (#2711), and its length is what IPv4 leaves, so its octets past the
cut were zero-filled to it (#2686) and read on as records: an ``Unassigned`` record of no
sources, with ``SchemaWarning: packet length < 0`` for what the zeros left. The list ends with
the data instead, as it does for a Report parsed on its own (#2711, #2749).

The Report below is cut at every offset from the end of its fixed fields to inside its last
record, and wrapped in an IPv4 datagram declaring all of it. It must hold the records its
octets begin, the one the cut lands inside read as far as it was captured, read
``TRUNCATED`` with its short-read record and quietly, read as the same octets parsed on
their own, and rebuild as captured, the datagram and the Report alike. A whole datagram, and
the Report parsed on its own, are the controls.

The messages are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import contextlib
import logging
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'


def record(kind: int, sources: int, aux: int = 0) -> bytes:
    """A record of type ``kind`` for 239.1.1.1, with ``sources`` sources and ``aux`` words of
    auxiliary data (RFC 3376, section 4.2.4)."""
    return (bytes([kind, aux]) + sources.to_bytes(2, 'big') + bytes([239, 1, 1, 1])
            + bytes([10, 0, 0, 1]) * sources + b'AUX!' * aux)


def report(*records: bytes) -> bytes:
    """An IGMPv3 Report of ``records``, checksummed."""
    rest = len(records).to_bytes(2, 'big') + b''.join(records)
    head = b'\x22\x00'
    return head + wire.checksum(head + bytes(4) + rest).to_bytes(2, 'big') + b'\x00\x00' + rest


#: MODE_IS_INCLUDE with two sources; MODE_IS_EXCLUDE with one source and a word of auxiliary
#: data; and ALLOW_NEW_SOURCES with two sources and two words of it.
RECORDS = (record(1, 2), record(2, 1, aux=1), record(5, 2, aux=2))
#: The Report itself.
MESSAGE = report(*RECORDS)
#: Where each record starts in the message.
STARTS = tuple(8 + sum(map(len, RECORDS[:index])) for index in range(len(RECORDS)))


def begun(keep: int) -> int:
    """How many records the first ``keep`` octets of the message begin."""
    return sum(1 for start in STARTS if start < keep)


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:  # pylint: disable=redefined-outer-name
        self.messages.append(record.getMessage())


@contextlib.contextmanager
def _reported() -> 'Iterator[list[str]]':
    """Collect what the block reports, on the logger and the :mod:`warnings` channel."""
    handler = _Logged()
    logger = logging.getLogger('pcapkit')
    logger.addHandler(handler)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            yield handler.messages
            handler.messages.extend(f'{item.category.__name__}: {item.message}' for item in caught)
    finally:
        logger.removeHandler(handler)


class FramedReportCutTests(unittest.TestCase):
    """A Report behind IPv4 and cut inside its records holds the records it begins."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.igmpv3.protocol import IGMPv3
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.utilities import config

        self.IGMPv3, self.IPv4, self.Status = IGMPv3, IPv4, ChecksumStatus
        patch = mock.patch.object(config, 'CHECKSUM_VERIFY', True)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def records(layer: 'Any') -> 'list[tuple[int, int, tuple[str, ...], bytes]]':
        """``layer``'s records, each as its type, source count, sources and auxiliary data."""
        return [(int(item.record_type), item.num_sources, tuple(map(str, item.sources)), item.aux_data)
                for item in layer.info.records]

    def framed(self, keep: int) -> 'tuple[bytes, Any, list[str]]':
        """The datagram cut ``keep`` octets into the message, its parse, and what it reported."""
        packet = wire.ipv4(MESSAGE, proto=2)
        raw = packet[:len(packet) - len(MESSAGE) + keep]
        with _reported() as reported:
            ipv4 = self.IPv4(raw)
        return raw, ipv4, reported

    def test_the_cuts_reach_every_record_and_boundary(self) -> None:
        self.assertEqual(STARTS, (8, 24, 40))
        self.assertEqual(len(MESSAGE), 64)

    def test_a_cut_holds_the_records_it_begins(self) -> None:
        whole = self.records(self.IGMPv3(MESSAGE))
        for keep in range(8, len(MESSAGE)):
            with self.subTest(captured=keep):
                _, ipv4, reported = self.framed(keep)
                igmp = ipv4.payload
                self.assertIsInstance(igmp, self.IGMPv3)
                self.assertEqual(reported, [])
                self.assertEqual(igmp.info.get('__short_read__'), ('body', keep - 1))
                self.assertIs(igmp.info.checksum_status, self.Status.TRUNCATED)
                self.assertEqual(igmp.info.num_group_records, len(RECORDS))
                records = self.records(igmp)
                self.assertEqual(len(records), begun(keep))
                self.assertEqual(records[:-1], whole[:begun(keep) - 1] if records else [])

    def test_a_record_the_cut_lands_inside_reads_as_captured(self) -> None:
        # One to three octets into the second record: its type was captured, and its
        # Number of Sources reads as zero.
        for keep in range(STARTS[1] + 1, STARTS[1] + 4):
            with self.subTest(captured=keep):
                _, ipv4, _ = self.framed(keep)
                self.assertEqual([item[:3] for item in self.records(ipv4.payload)],
                                 [(1, 2, ('10.0.0.1', '10.0.0.1')), (2, 0, ())])

    def test_a_framed_cut_reads_as_its_octets_on_their_own(self) -> None:
        for keep in range(8, len(MESSAGE)):
            _, ipv4, _ = self.framed(keep)
            for sized in (False, True):
                with self.subTest(captured=keep, sized=sized), _reported():
                    alone = self.IGMPv3(MESSAGE[:keep], keep) if sized else self.IGMPv3(MESSAGE[:keep])
                    self.assertEqual(self.records(ipv4.payload), self.records(alone))

    def test_a_cut_rebuilds_as_captured(self) -> None:
        for keep in range(8, len(MESSAGE)):
            raw, ipv4, _ = self.framed(keep)
            igmp = ipv4.payload
            for path, data, cls, octets in (('datagram', ipv4.info, self.IPv4, raw),
                                            ('datagram dict', ipv4.info.to_dict(), self.IPv4, raw),
                                            ('report', igmp.info, self.IGMPv3, MESSAGE[:keep])):
                with self.subTest(captured=keep, path=path):
                    with _reported() as reported:
                        rebuilt = cls.from_data(data)
                    self.assertEqual((rebuilt.data, reported), (octets, []))

    def test_a_whole_datagram_reads_every_record(self) -> None:
        packet = wire.ipv4(MESSAGE, proto=2)
        with _reported() as reported:
            ipv4 = self.IPv4(packet)
        igmp = ipv4.payload
        self.assertEqual(reported, [])
        self.assertIsNone(igmp.info.get('__short_read__'))
        self.assertIs(igmp.info.checksum_status, self.Status.VALID)
        self.assertEqual(self.records(igmp), [
            (1, 2, ('10.0.0.1', '10.0.0.1'), b''),
            (2, 1, ('10.0.0.1',), b'AUX!'),
            (5, 2, ('10.0.0.1', '10.0.0.1'), b'AUX!AUX!'),
        ])
        self.assertEqual(self.IPv4.from_data(ipv4.info).data, packet)

    def test_a_report_on_its_own_is_unchanged(self) -> None:
        # The count sizes the records of a Report parsed on its own (#2711), which a cut
        # inside them reads as quietly as before (#2749).
        for keep in range(8, len(MESSAGE)):
            for sized in (False, True):
                with self.subTest(captured=keep, sized=sized):
                    with _reported() as reported:
                        alone = self.IGMPv3(MESSAGE[:keep], keep) if sized else self.IGMPv3(MESSAGE[:keep])
                    self.assertEqual(reported, [])
                    self.assertEqual(alone.info.get('__short_read__'), ('body', keep - 1))
                    self.assertIs(alone.info.checksum_status, self.Status.TRUNCATED)
                    self.assertEqual(len(alone.info.records), begun(keep))
                    self.assertEqual(self.IGMPv3.from_data(alone.info).data, MESSAGE[:keep])


if __name__ == '__main__':
    unittest.main()
