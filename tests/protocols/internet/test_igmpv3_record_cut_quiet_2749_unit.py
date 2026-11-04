# -*- coding: utf-8 -*-
"""An IGMPv3 Report parsed on its own and cut inside a group record reads quietly.

GitHub issue #2749: built directly on octets that end inside a group record, an IGMPv3
Report recorded the cut and read ``TRUNCATED``, and also warned ``SchemaWarning: packet
length < 0`` once for each field of the record past the cut, between one and five times.
Its record list counts the records the Number of Group Records gives and runs to the end
of the data (#2711), and each record is sized by the octets left to it, so
:meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>` read the fields of the
record the data ends inside as running past a length it had been given.
:class:`~pcapkit.corekit.fields.collections.ListField` now reads a schema item it counts
as ending with the data, and ``Schema.unpack`` reads such an item's fields past its length
as the cut its short read records.

The Report below is cut inside its first, a middle and its last record, inside a record's
fixed fields, its source list and its auxiliary data, and built directly with and without
a length. It must read ``TRUNCATED`` with its short-read record, report nothing on the
warning channel or the ``pcapkit`` logger, and rebuild from its data model and its dict as
captured. Behind IPv4 the count sizes nothing, so the change does not reach it: a whole
Report there whose record counts more sources than it holds is no cut, and still warns.

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


def record(sources: int, aux: int = 0, *, declared: 'int | None' = None) -> bytes:
    """A MODE_IS_INCLUDE record for 239.1.1.1 with ``sources`` sources and ``aux`` words of
    auxiliary data, its Number of Sources ``declared``, or ``sources`` if not given."""
    count = sources if declared is None else declared
    return (bytes([1, aux]) + count.to_bytes(2, 'big') + bytes([239, 1, 1, 1])
            + bytes([10, 0, 0, 1]) * sources + b'AUX!' * aux)


def report(*records: bytes) -> bytes:
    """An IGMPv3 Report of ``records``, checksummed."""
    rest = len(records).to_bytes(2, 'big') + b''.join(records)
    head = b'\x22\x00'
    return head + wire.checksum(head + bytes(4) + rest).to_bytes(2, 'big') + b'\x00\x00' + rest


def wrong(msg: bytes) -> bytes:
    """``msg`` with its checksum flipped in both octets."""
    return msg[:2] + (int.from_bytes(msg[2:4], 'big') ^ 0x0101).to_bytes(2, 'big') + msg[4:]


#: The Report's records: two sources; one source and a word of auxiliary data; two
#: sources and two words of it.
RECORDS = (record(2), record(1, aux=1), record(2, aux=2))
#: The Report itself.
MESSAGE = report(*RECORDS)
#: Each record's ordinal name, in order.
ORDINALS = ('first', 'middle', 'last')


def cuts() -> 'Iterator[tuple[str, str, int]]':
    """Every cut strictly inside a record: the record, the part its first missing octet is
    in, and the octets kept."""
    start = 8
    for ordinal, item in zip(ORDINALS, RECORDS):
        sources = int.from_bytes(item[2:4], 'big')
        for offset in range(1, len(item)):
            part = 'fixed fields' if offset < 8 else 'source list' if offset < 8 + 4 * sources else 'aux data'
            yield ordinal, part, start + offset
        start += len(item)


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:  # pylint: disable=redefined-outer-name
        self.messages.append(record.getMessage())


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


class ReportRecordCutTests(unittest.TestCase):
    """A Report parsed on its own and cut inside a record records the cut and reads quietly."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.igmpv3.protocol import IGMPv3
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.utilities import config

        self.IGMPv3 = IGMPv3
        self.IPv4 = IPv4
        self.Status = ChecksumStatus
        patch = mock.patch.object(config, 'CHECKSUM_VERIFY', True)
        patch.start()
        self.addCleanup(patch.stop)

    def direct(self, data: bytes, sized: bool) -> 'tuple[Any, list[str]]':
        """``data`` built directly as IGMPv3, given its length if ``sized``, and what it reported."""
        with _reported() as (logged, caught):
            layer = self.IGMPv3(data, len(data)) if sized else self.IGMPv3(data)
        return layer, logged + [f'{item.category.__name__}: {item.message}' for item in caught]

    def test_the_cuts_reach_every_part_of_every_record(self) -> None:
        parts = {(ordinal, part) for ordinal, part, _ in cuts()}
        self.assertEqual(parts, {(ordinal, part) for ordinal in ORDINALS for part in ('fixed fields', 'source list')}
                         | {('middle', 'aux data'), ('last', 'aux data')})

    def test_a_cut_inside_a_record_reads_truncated_and_quietly(self) -> None:
        for ordinal, part, keep in cuts():
            for bad in (False, True):
                for sized in (False, True):
                    with self.subTest(record=ordinal, part=part, captured=keep, bad=bad, sized=sized):
                        layer, reported = self.direct((wrong(MESSAGE) if bad else MESSAGE)[:keep], sized)
                        self.assertEqual(reported, [])
                        self.assertEqual(layer.info.get('__short_read__'), ('body', keep - 1))
                        self.assertIs(layer.info.checksum_status, self.Status.TRUNCATED)
                        self.assertEqual(len(layer.info.records), ORDINALS.index(ordinal) + 1)

    def test_a_cut_inside_a_record_rebuilds_as_captured_and_quietly(self) -> None:
        for ordinal, part, keep in cuts():
            layer, _ = self.direct(MESSAGE[:keep], True)
            for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
                with self.subTest(record=ordinal, part=part, captured=keep, path=path):
                    with _reported() as (logged, caught):
                        rebuilt = self.IGMPv3.from_data(data)
                    self.assertEqual((rebuilt.data, rebuilt.info.checksum_status),
                                     (MESSAGE[:keep], self.Status.TRUNCATED))
                    self.assertEqual((logged, [str(item.message) for item in caught]), ([], []))

    def test_a_whole_report_reads_valid_and_quietly(self) -> None:
        for sized in (False, True):
            with self.subTest(sized=sized):
                layer, reported = self.direct(MESSAGE, sized)
                self.assertEqual(reported, [])
                self.assertIsNone(layer.info.get('__short_read__'))
                self.assertIs(layer.info.checksum_status, self.Status.VALID)
                self.assertEqual(self.IGMPv3.from_data(layer.info).data, MESSAGE)

    def test_a_record_overstating_its_sources_behind_ipv4_still_warns(self) -> None:
        # IPv4 says where the message ends, so the record's source list and auxiliary data
        # run past a length the frame declares: a malformed record, not a cut.
        msg = report(record(1, declared=5))
        with _reported() as (_, caught):
            layer = self.IPv4(wire.ipv4(msg, proto=2)).payload
        self.assertIsInstance(layer, self.IGMPv3)
        self.assertEqual([str(item.message) for item in caught if item.category.__name__ == 'SchemaWarning'],
                         ['packet length < 0: -16', 'packet length < 0: -16'])


if __name__ == '__main__':
    unittest.main()
