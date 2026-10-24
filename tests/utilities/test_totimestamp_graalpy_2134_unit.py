# -*- coding: utf-8 -*-
"""GitHub issue #2134: an aware datetime before 1970 encodes to the instant it names on GraalPy.

GraalPy's :meth:`datetime.datetime.timestamp` counts the whole seconds of an
aware datetime toward zero and then adds the fraction, so 23:59:59.5 on December
31, 1969, UTC, gives ``0.5`` where CPython gives ``-0.5``. The MH replay
protection option, the PCAP frame header and the PCAP-NG packet blocks built
from such a datetime were therefore one second late there, and decoding gave
back another instant than the one encoded.

:class:`GraalPyDateTime` applies GraalPy's rule on any interpreter, and the
encoders are run under :func:`graalpy_timestamps`, which turns on
:func:`pcapkit.utilities.datetime.totimestamp`'s GraalPy branch.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import contextlib
import datetime
import decimal
import sys
import unittest
from typing import TYPE_CHECKING
from unittest import mock

if TYPE_CHECKING:
    from typing import Iterator

#: Test tier (#1958): works around a GraalPy datetime defect, behind an
#: implementation gate.
__tier__ = 'ALL'

UTC = datetime.timezone.utc
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=UTC)

#: Aware instants before, at and after the epoch, with and without a fraction.
INSTANTS = (
    datetime.datetime(1, 1, 1, 0, 0, 0, 1, tzinfo=UTC),
    datetime.datetime(1900, 1, 1, tzinfo=UTC),
    datetime.datetime(1950, 6, 1, 12, 0, 0, 500_000, tzinfo=UTC),
    datetime.datetime(1969, 12, 31, 23, 59, 59, 500_000, tzinfo=UTC),
    datetime.datetime(1969, 12, 31, 18, 59, 58, 250_000, tzinfo=datetime.timezone(datetime.timedelta(hours=-5))),
    datetime.datetime(1970, 1, 1, tzinfo=UTC),
    datetime.datetime(1970, 1, 1, 0, 0, 0, 500_000, tzinfo=UTC),
    datetime.datetime(2026, 10, 23, 12, 34, 56, 789_012, tzinfo=datetime.timezone(datetime.timedelta(hours=8))),
    datetime.datetime(9999, 12, 31, 23, 59, 59, 999_999, tzinfo=UTC),
)


class GraalPyDateTime(datetime.datetime):
    """A ``datetime`` whose aware :meth:`timestamp` truncates its whole seconds, as GraalPy's does."""

    def timestamp(self) -> float:
        if self.tzinfo is None:
            return super().timestamp()
        delta = self - EPOCH
        whole = delta.days * 86400 + delta.seconds
        if whole < 0 and delta.microseconds:
            whole += 1  # ``ChronoUnit.SECONDS.between`` rounds toward zero
        return whole + delta.microseconds / 1_000_000


def graal(instant: 'datetime.datetime') -> 'GraalPyDateTime':
    """``instant`` as a :class:`GraalPyDateTime`."""
    return GraalPyDateTime(instant.year, instant.month, instant.day, instant.hour, instant.minute,
                           instant.second, instant.microsecond, tzinfo=instant.tzinfo)


@contextlib.contextmanager
def graalpy_timestamps() -> 'Iterator[None]':
    """Run :func:`~pcapkit.utilities.datetime.totimestamp` as it runs on GraalPy."""
    with mock.patch('pcapkit.utilities.datetime._TIMESTAMP_TRUNCATES', True):
        yield


class TestGraalPyEmulation(unittest.TestCase):
    """The stand-in loses the second GraalPy loses, or every test below proves nothing."""

    def test_measured_values(self) -> None:
        # measured on GraalPy 25.4.4 for the same instants (#2134)
        cases = (
            (datetime.datetime(1950, 6, 1, 12, 0, 0, 500_000, tzinfo=UTC), -618062398.5),
            (datetime.datetime(1969, 12, 31, 23, 59, 59, 500_000, tzinfo=UTC), 0.5),
            (datetime.datetime(1969, 12, 31, 23, 59, 58, 250_000, tzinfo=UTC), -0.75),
            (datetime.datetime(1970, 1, 1, 0, 0, 0, 500_000, tzinfo=UTC), 0.5),
        )
        for instant, expected in cases:
            with self.subTest(instant=instant):
                self.assertEqual(graal(instant).timestamp(), expected)


class TestToTimestamp(unittest.TestCase):
    """:func:`pcapkit.utilities.datetime.totimestamp` is CPython's :meth:`~datetime.datetime.timestamp`."""

    def setUp(self) -> None:
        from tests._support import reimport_once_per_class

        reimport_once_per_class(self)

    def test_aware_is_the_seconds_since_the_epoch(self) -> None:
        from pcapkit.utilities.datetime import totimestamp

        for instant in INSTANTS:
            with self.subTest(instant=instant):
                self.assertEqual(totimestamp(instant), (instant - EPOCH).total_seconds())

    @unittest.skipIf(sys.implementation.name == 'graalpy', "GraalPy's own timestamp() is the defect")
    def test_is_the_stdlib_call_off_graalpy(self) -> None:
        from pcapkit.utilities.datetime import totimestamp

        naive = datetime.datetime(1950, 6, 1, 12, 0, 0, 500_000)
        for instant in (*INSTANTS, naive):
            with self.subTest(instant=instant):
                self.assertEqual(totimestamp(instant).hex(), instant.timestamp().hex())

    def test_graalpys_lost_second_is_restored(self) -> None:
        from pcapkit.utilities.datetime import totimestamp

        with graalpy_timestamps():
            for instant in INSTANTS:
                with self.subTest(instant=instant):
                    self.assertEqual(totimestamp(graal(instant)), (instant - EPOCH).total_seconds())

    def test_naive_is_local_time_everywhere(self) -> None:
        from pcapkit.utilities.datetime import totimestamp

        naive = datetime.datetime(1950, 6, 1, 12, 0, 0, 500_000)
        with graalpy_timestamps():
            self.assertEqual(totimestamp(naive), naive.timestamp())

    def test_an_offsetless_zone_fails_as_on_cpython(self) -> None:
        from pcapkit.utilities.datetime import totimestamp

        class NoOffset(datetime.tzinfo):
            def utcoffset(self, dt: 'object') -> None:
                return None

        with graalpy_timestamps(), self.assertRaises(TypeError):
            totimestamp(datetime.datetime(1950, 6, 1, tzinfo=NoOffset()))


class TestEncodersOnGraalPy(unittest.TestCase):
    """Every encoder that takes a datetime encodes the instant it names under GraalPy's rule."""

    def setUp(self) -> None:
        from tests._support import reimport_once_per_class

        reimport_once_per_class(self)

    def test_mh_mesg_id(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.protocols.schema.internet.mh import MesgIDOption

        proto = object.__new__(MH)
        for instant in INSTANTS[1:5]:
            with self.subTest(instant=instant):
                expected = proto._make_opt_mesg_id(Option.MESG_ID_OPTION_TYPE, interval=instant).pack()
                with graalpy_timestamps():
                    made = proto._make_opt_mesg_id(Option.MESG_ID_OPTION_TYPE, interval=graal(instant))
                self.assertEqual(made.pack().hex(), expected.hex())
                self.assertEqual(MesgIDOption.unpack(made.pack()).timestamp, instant)

    def test_pcap_frame(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame

        frame = object.__new__(Frame)
        instant = datetime.datetime(1969, 12, 31, 23, 59, 58, 250_000, tzinfo=UTC)
        for nanosecond in (False, True):
            with self.subTest(nanosecond=nanosecond):
                expected = frame._make_timestamp(timestamp=instant, nanosecond=nanosecond)
                with graalpy_timestamps():
                    made = frame._make_timestamp(timestamp=graal(instant), nanosecond=nanosecond)
                self.assertEqual(made, expected)

    def test_pcapng_block(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        pcapng = object.__new__(PCAPNG)
        instant = datetime.datetime(1950, 6, 1, 12, 0, 0, 500_000, tzinfo=UTC)
        offset = -700_000_000  # if_tsoffset, so the scaled value is positive
        with mock.patch.object(PCAPNG, '_get_offset', lambda self, interface_id: decimal.Decimal(offset)), \
                mock.patch.object(PCAPNG, '_get_resolution', lambda self, interface_id: 1_000_000):
            expected = pcapng._make_timestamp(instant)
            with graalpy_timestamps():
                made = pcapng._make_timestamp(graal(instant))
        self.assertEqual(made, expected)
        self.assertEqual(((made[0] << 32) | made[1]) / 1_000_000 + offset, (instant - EPOCH).total_seconds())


if __name__ == '__main__':
    unittest.main()
