# -*- coding: utf-8 -*-
"""An IGMPv3 Report the data ends before its counted records reads ``TRUNCATED``.

GitHub issue #2711: built directly on octets that end on a field boundary, at the end
of the header or of a group record, an IGMPv3 Report recorded no short read, since its
record list was read with the rest of the message, which ended there too. So its
checksum, covering records never captured, read ``INVALID`` with a ``ChecksumWarning``,
where behind IPv4, whose length runs past the data, the same cut read ``TRUNCATED``. The
record list now counts the records the Number of Group Records gives wherever the data
ends with the message (:rfc:`3376#section-4.2`), and one holding fewer records than it
counts records the cut through ``Schema``'s own short read, the records absent never made
up.

Each Report below is cut at every field boundary short of its end and built directly.
It must record the cut, read ``TRUNCATED`` with no ``ChecksumWarning``, wrong checksum or
right, parse the records captured as the same cut does behind IPv4, and rebuild from its
data model and its dict as captured, reporting nothing. It must read so whatever the
context parsed before it. Whole Reports, Additional Data included, are the control.

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


def record(sources: int, aux: int = 0) -> bytes:
    """A MODE_IS_INCLUDE record for 239.1.1.1 with ``sources`` sources and ``aux`` words of auxiliary data."""
    return (bytes([1, aux]) + sources.to_bytes(2, 'big') + bytes([239, 1, 1, 1])
            + bytes([10, 0, 0, 1]) * sources + b'AUX!' * aux)


def report(*records: bytes, extra: bytes = b'', count: 'int | None' = None) -> bytes:
    """An IGMPv3 Report of ``records`` counting ``count``, then Additional Data ``extra``, checksummed."""
    rest = (len(records) if count is None else count).to_bytes(2, 'big') + b''.join(records) + extra
    head = b'\x22\x00'
    return head + wire.checksum(head + bytes(4) + rest).to_bytes(2, 'big') + b'\x00\x00' + rest


def boundaries(*records: bytes) -> 'list[int]':
    """Every offset where a field of a Report of ``records`` ends, short of its end."""
    ends = [1, 2, 4, 6, 8]
    start = 8
    for item in records:
        ends.extend(start + width for width in (1, 2, 4, 8))
        ends.extend(range(start + 12, start + len(item) + 1, 4))
        start += len(item)
    return [end for end in ends if end < start]


#: Each Report as a tuple of its records: the issue's two of one source each, two of
#: different sizes, and one carrying auxiliary data before one with no sources.
SHAPES = {
    'two records of one source': (record(1), record(1)),
    'records of two and three sources': (record(2), record(3)),
    'auxiliary data, then no sources': (record(1, aux=1), record(0)),
}


def starts(records: 'tuple[bytes, ...]') -> 'list[int]':
    """Where each of ``records`` begins in its Report."""
    offsets, start = [], 8
    for item in records:
        offsets.append(start)
        start += len(item)
    return offsets


def wrong(msg: bytes) -> bytes:
    """``msg`` with its checksum flipped in both octets."""
    return msg[:2] + (int.from_bytes(msg[2:4], 'big') ^ 0x0101).to_bytes(2, 'big') + msg[4:]


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:  # pylint: disable=redefined-outer-name
        self.messages.append(f'logged: {record.getMessage()}')


@contextlib.contextmanager
def _reported() -> 'Iterator[tuple[list[str], list[warnings.WarningMessage]]]':
    """Collect what the block reports, on the logger and the :mod:`warnings` channel."""
    handler = _Logged()
    logger = logging.getLogger('pcapkit')
    logger.addHandler(handler)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            yield handler.messages, caught
    finally:
        logger.removeHandler(handler)


class ReportCountCutTests(unittest.TestCase):
    """A Report the data ends before its counted records is cut, wherever the cut falls."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.igmpv3.protocol import IGMPv3
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning

        self.IGMPv3 = IGMPv3
        self.IPv4 = IPv4
        self.Status = ChecksumStatus
        self.ChecksumWarning = ChecksumWarning
        patch = mock.patch.object(config, 'CHECKSUM_VERIFY', True)
        patch.start()
        self.addCleanup(patch.stop)

    def cuts(self) -> 'Iterator[tuple[str, bytes, int]]':
        """Every Report with its octets, and each field boundary it is cut at."""
        for label, records in SHAPES.items():
            for keep in boundaries(*records):
                yield label, report(*records), keep

    def direct(self, data: bytes) -> 'tuple[Any, list[str]]':
        """``data`` built directly as IGMPv3, and the checksum warnings it gave."""
        with _reported() as (_, caught):
            layer = self.IGMPv3(data, len(data))
        return layer, [str(item.message) for item in caught if issubclass(item.category, self.ChecksumWarning)]

    def test_a_cut_on_a_field_boundary_reads_truncated(self) -> None:
        for label, msg, keep in self.cuts():
            for bad in (False, True):
                with self.subTest(report=label, captured=keep, bad=bad):
                    layer, caught = self.direct((wrong(msg) if bad else msg)[:keep])
                    self.assertEqual(layer.info.get('__short_read__'), ('body', keep - 1))
                    self.assertEqual((layer.info.checksum_status, caught), (self.Status.TRUNCATED, []))

    def test_a_cut_parses_the_records_captured_as_behind_ipv4(self) -> None:
        # Behind IPv4, whose length runs past the data, the records past it read as
        # zeros (#2686); built directly, only the records the data reaches are read.
        for label, msg, keep in self.cuts():
            if keep < 2:
                # One octet is too few for IGMP to tell its version from, so IPv4 keeps it Raw.
                continue
            with self.subTest(report=label, captured=keep):
                packet = wire.ipv4(msg, proto=2)
                with _reported():
                    carried = self.IPv4(packet[:len(packet) - len(msg) + keep]).payload
                direct, _ = self.direct(msg[:keep])
                self.assertIsInstance(carried, self.IGMPv3)
                ours, theirs = direct.info.to_dict(), carried.info.to_dict()
                records, filled = ours.pop('records'), theirs.pop('records')
                # each read at its own width, the octets given and IPv4's length (#2761)
                self.assertEqual((ours.pop('__short_width__'), theirs.pop('__short_width__')), (keep, len(msg)))
                self.assertEqual(ours, theirs)
                self.assertEqual(len(records), sum(start < keep for start in starts(SHAPES[label])))
                self.assertEqual(records, filled[:len(records)])
                self.assertEqual({str(item.multicast_address) for item in filled[len(records):]} - {'0.0.0.0'}, set())

    def test_a_cut_rebuilds_as_captured_and_quietly(self) -> None:
        for label, msg, keep in self.cuts():
            layer, _ = self.direct(msg[:keep])
            for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
                with self.subTest(report=label, captured=keep, path=path):
                    with _reported() as (logged, caught):
                        rebuilt = self.IGMPv3.from_data(data)
                    self.assertEqual((rebuilt.data, rebuilt.info.checksum_status), (msg[:keep], self.Status.TRUNCATED))
                    self.assertEqual((logged, [str(item.message) for item in caught]), ([], []))

    def test_an_enclosing_length_still_sizes_the_records(self) -> None:
        # IPv4 declares one record's worth, the count three, and the capture ends
        # inside the record: the records span the declared length, as before.
        msg = report(record(1), count=3)
        packet = wire.ipv4(msg, proto=2)
        with _reported():
            carried = self.IPv4(packet[:len(packet) - len(msg) + 14]).payload
        self.assertIsInstance(carried, self.IGMPv3)
        self.assertEqual(carried.info.get('__short_read__'), ('body', 13))
        self.assertEqual([str(item.multicast_address) for item in carried.info.records], ['239.1.0.0'])

    def test_a_count_no_ip_payload_can_carry_is_refused(self) -> None:
        # Behind the 8-octet header, 8,190 records of 8 octets fit an IP payload; 8,191 do not.
        from pcapkit.utilities.exceptions import ProtocolError

        for count in (8191, 0xFFFF):
            msg = report(count=count)
            with self.subTest(count=count), \
                    self.assertRaisesRegex(ProtocolError, rf'{count} group records cannot fit'):
                self.IGMPv3(msg, len(msg))

    def test_a_count_past_the_data_reads_the_same_whatever_was_parsed_before(self) -> None:
        # The same Report, in a padding budget of its own and again once the context has
        # read enough for that budget to cover zero-filling its counted records: both read
        # only the records present, as cut, and rebuild as captured (#2711).
        from pcapkit.corekit.fields.field import _zero_pad_budget
        from pcapkit.utilities import config

        bulk = report(*[record(255)] * 32)
        for count in (2, 16, 17, 100, 8190):
            for records in ((), (record(1),)):
                msg = report(*records, count=count)
                with self.subTest(count=count, records=len(records)), _zero_pad_budget() as ledger:
                    fresh, caught = self.direct(msg)
                    self.IGMPv3(bulk, len(bulk))
                    self.assertGreater(config.ZERO_PAD_BUDGET_RATIO * ledger[0], 8 * count)
                    later, caught_later = self.direct(msg)
                    seen = [(layer.info.checksum_status, layer.info.get('__short_read__'),
                             layer.info.to_dict()['records'], self.IGMPv3.from_data(layer.info).data)
                            for layer in (fresh, later)]
                    self.assertEqual(seen[0], seen[1])
                    self.assertEqual(seen[0][:2], (self.Status.TRUNCATED, ('body', len(msg) - 1)))
                    self.assertEqual((len(seen[0][2]), seen[0][3]), (len(records), msg))
                    self.assertEqual((caught, caught_later), ([], []))

    def test_inside_a_frame_the_count_sizes_nothing(self) -> None:
        # Behind IPv4, whose length says where the message ends, a whole message whose
        # count overstates its records is read as it was, not as a cut (#2711).
        for count in (2, 100, 0xFFFF):
            msg = report(record(1), count=count)
            with self.subTest(count=count), _reported() as (logged, _):
                layer = self.IPv4(wire.ipv4(msg, proto=2)).payload
            self.assertIsInstance(layer, self.IGMPv3)
            self.assertIsNone(layer.info.get('__short_read__'))
            self.assertEqual((len(layer.info.records), layer.info.num_group_records), (1, count))
            self.assertEqual(logged, [])

    def test_a_whole_report_is_verified(self) -> None:
        for label, records in SHAPES.items():
            for extra in (b'', b'\xca\xfe\xba\xbe'):
                msg = report(*records, extra=extra)
                with self.subTest(report=label, extra=extra):
                    layer, caught = self.direct(msg)
                    self.assertIsNone(layer.info.get('__short_read__'))
                    self.assertEqual((layer.info.checksum_status, caught), (self.Status.VALID, []))
                    self.assertEqual(len(layer.info.records), len(records))
                    self.assertEqual(self.IGMPv3.from_data(layer.info).data, msg)
                    layer, caught = self.direct(wrong(msg))
                    self.assertIs(layer.info.checksum_status, self.Status.INVALID)
                    self.assertEqual(len(caught), 1)


if __name__ == '__main__':
    unittest.main()
