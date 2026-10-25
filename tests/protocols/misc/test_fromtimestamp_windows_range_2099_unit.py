# -*- coding: utf-8 -*-
"""GitHub issue #2099: timestamps convert without the platform's ``gmtime()`` range.

:meth:`datetime.datetime.fromtimestamp` with a ``tz`` breaks the instant down
with the C library's ``gmtime()``, and the Windows CRT's ``gmtime_s`` takes
nothing before 1970 or after 23:59:59, December 31, 3000, UTC. On the first
Windows run (#2095) a PCAP-NG packet dated in year 1 or year 9999 therefore took
the invalid-timestamp fallback and was dated 1970.

Windows is emulated here by a ``datetime`` whose ``fromtimestamp`` raises what
CPython raises there, ``OSError(EINVAL)``, outside that range. Every reader is
asserted to give the exact :class:`~datetime.datetime` it gives on Linux.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import contextlib
import datetime
import decimal
import errno
import struct
import sys
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): splits floats into seconds and microseconds, which PyPy's
#: and GraalPy's pure-Python datetime do in code of their own, and gates one
#: error class on GraalPy.
__tier__ = 'ALL'

UTC = datetime.timezone.utc

#: The last instant ``gmtime_s`` breaks down: 23:59:59, December 31, 3000, UTC.
WINDOWS_MAX = int(datetime.datetime(3001, 1, 1, tzinfo=UTC).timestamp()) - 1

#: Year 1 and year 9999, a day inside ``datetime``'s range, as #1340 pins them.
YEAR_1 = -62135510400
YEAR_9999 = 253402214399

_REAL_DATETIME = datetime.datetime

#: What :meth:`datetime.timezone.fromutc` raises for a result before year 1.
#: CPython's C and pure-Python ``datetime`` both raise :exc:`OverflowError`, as
#: ``datetime + timedelta`` does. GraalPy's ``FromUtcNode`` adds the offset to a
#: Java ``LocalDateTime``, which has no year-1 floor, and its constructor then
#: raises ``ValueError: year 0 is out of range`` (#2134, measured on GraalPy
#: 25.4.4; graalpython ``TimeZoneBuiltins.java`` and ``DatetimeModuleBuiltins
#: .addOffsetToDateTime`` at graal-25.4.4, no upstream issue filed). Its
#: ``datetime + timedelta`` still raises :exc:`OverflowError`.
ZONE_OVERFLOW = ValueError if sys.implementation.name == 'graalpy' else OverflowError


class WindowsDateTime(_REAL_DATETIME):
    """A ``datetime`` whose ``fromtimestamp`` has the Windows CRT's range."""

    @classmethod
    def fromtimestamp(cls, timestamp: 'float', tz: 'Any' = None) -> 'datetime.datetime':  # type: ignore[override]
        if not 0 <= timestamp <= WINDOWS_MAX:
            raise OSError(errno.EINVAL, 'Invalid argument')
        return _REAL_DATETIME.fromtimestamp(timestamp, tz)


@contextlib.contextmanager
def windows_gmtime() -> 'Iterator[None]':
    """Give every loaded :mod:`pcapkit` module that binds :mod:`datetime` the Windows range."""
    fake = types.SimpleNamespace(**dict(vars(datetime), datetime=WindowsDateTime))
    with contextlib.ExitStack() as stack:
        for name, module in list(sys.modules.items()):
            if (name == 'pcapkit' or name.startswith('pcapkit.')) and getattr(module, 'datetime', None) is datetime:
                stack.enter_context(mock.patch.object(module, 'datetime', fake))
        yield


def _idb(*options: 'tuple[int, str, int]') -> 'bytes':
    """An Ethernet IDB carrying fixed-size ``options`` and ``opt_endofopt``."""
    body = struct.pack('<HHI', 1, 0, 0x40000)
    for code, fmt, value in options:
        body += struct.pack('<HH', code, struct.calcsize(fmt)) + struct.pack(fmt, value)
    body += b'\x00\x00\x00\x00'
    length = len(body) + 12
    return struct.pack('<II', 1, length) + body + struct.pack('<I', length)


def _epb(high: 'int' = 0, low: 'int' = 0) -> 'bytes':
    """A 36-octet Enhanced Packet Block on interface 0."""
    body = struct.pack('<IIIII', 0, high, low, 4, 4) + b'abcd'
    length = len(body) + 12
    return struct.pack('<II', 6, length) + body + struct.pack('<I', length)


class TestWindowsRangeEmulation(unittest.TestCase):
    """The emulation fails the stdlib where Windows does, or every test below proves nothing."""

    def test_stdlib_fromtimestamp_fails_outside_the_crt_range(self) -> None:
        for value in (YEAR_1, -1, WINDOWS_MAX + 1, YEAR_9999):
            with self.subTest(timestamp=value), self.assertRaises(OSError):
                WindowsDateTime.fromtimestamp(float(value), UTC)
        self.assertEqual(WindowsDateTime.fromtimestamp(float(WINDOWS_MAX), UTC),
                         _REAL_DATETIME(3000, 12, 31, 23, 59, 59, tzinfo=UTC))


class TestFromTimestamp(unittest.TestCase):
    """:func:`pcapkit.utilities.datetime.fromtimestamp` against the stdlib inside the CRT range."""

    def test_matches_the_stdlib_where_both_can_answer(self) -> None:
        from pcapkit.utilities.datetime import fromtimestamp

        zones = (UTC, datetime.timezone(datetime.timedelta(hours=-5)),
                 datetime.timezone(datetime.timedelta(seconds=86399)))
        # half-microsecond ties round to even, as CPython's do
        for value in (0, 0.0, 0.0000005, 0.0000015, 0.0000025, 0.9999995, 1700000000.123456789,
                      5 + 1 / 65536, 4294967296.000001, float(WINDOWS_MAX) + 0.9999994):
            for zone in zones:
                with self.subTest(timestamp=value, tz=zone):
                    expected = _REAL_DATETIME.fromtimestamp(value, zone)
                    actual = fromtimestamp(value, zone)
                    self.assertEqual(actual, expected)
                    self.assertEqual(actual.utcoffset(), expected.utcoffset())
                    self.assertEqual(actual.microsecond, expected.microsecond)
                    self.assertIs(actual.tzinfo, zone)
                    self.assertIs(type(actual), _REAL_DATETIME)

    def test_errors_are_cpythons(self) -> None:
        from pcapkit.utilities.datetime import fromtimestamp

        cases = (
            (float('nan'), ValueError), (float('inf'), OverflowError), (2.0**63, OverflowError),
            (2**63, OverflowError), (-62135596801.0, ValueError), (253402300800.0, ValueError),
        )
        for value, error in cases:
            with self.subTest(timestamp=value), self.assertRaises(error):
                fromtimestamp(value, UTC)
        # the instant is in range and the zone pushes it out
        with self.assertRaises(ZONE_OVERFLOW):
            fromtimestamp(-62135596800.0, datetime.timezone(datetime.timedelta(hours=-5)))


class TestPCAPNGOnWindows(PCAPNGTestCase):
    """PCAP-NG packet timestamps decode alike on Windows and Linux."""

    def _packet(self, idb: 'bytes', epb: 'bytes') -> 'tuple[Any, list[str]]':
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        with warnings.catch_warnings(record=True) as caught, windows_gmtime():
            warnings.simplefilter('always')
            interface = PCAPNG(idb, len(idb), num=1, sct=1, ctx=context)
            context.interfaces[0] = interface.info
            packet = PCAPNG(epb, len(epb), num=2, sct=1, ctx=context)
        # rebuilt outside the emulation, as nothing on that path converts
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            rebuilt = PCAPNG.from_data(packet.info, num=2, sct=1, ctx=context).data
        self.assertEqual(rebuilt.hex(), epb.hex())
        return packet, [str(item.message) for item in caught if str(item.message).startswith('PCAP-NG')]

    def test_in_range_offsets_decode_exactly(self) -> None:
        # a float epoch this far from 1970 holds whole multiples of 2**-15
        # seconds, hence half a second rather than one microsecond
        cases = (
            (YEAR_1, 0, _REAL_DATETIME(1, 1, 2, tzinfo=UTC)),
            (YEAR_1, 500_000, _REAL_DATETIME(1, 1, 2, 0, 0, 0, 500_000, tzinfo=UTC)),
            (YEAR_9999, 0, _REAL_DATETIME(9999, 12, 30, 23, 59, 59, tzinfo=UTC)),
            (YEAR_9999, 500_000, _REAL_DATETIME(9999, 12, 30, 23, 59, 59, 500_000, tzinfo=UTC)),
            (-5, 0, _REAL_DATETIME(1969, 12, 31, 23, 59, 55, tzinfo=UTC)),
            (0, 0, _REAL_DATETIME(1970, 1, 1, tzinfo=UTC)),
            (5, 250_000, _REAL_DATETIME(1970, 1, 1, 0, 0, 5, 250_000, tzinfo=UTC)),
        )
        for offset, micros, expected in cases:
            with self.subTest(tsoffset=offset, micros=micros):
                packet, messages = self._packet(_idb((14, '<q', offset)), _epb(0, micros))
                self.assertEqual(messages, [])
                self.assertEqual(packet.info.timestamp, expected)
                self.assertIs(packet.info.timestamp.tzinfo, UTC)
                self.assertEqual(packet.info.timestamp_epoch,
                                 decimal.Decimal(offset) + decimal.Decimal(micros) / 1_000_000)

    def test_in_range_offsets_render_in_if_tzone(self) -> None:
        for seconds in (-3600, 3600):
            zone = datetime.timezone(datetime.timedelta(seconds=seconds))
            for offset, expected in ((YEAR_1, _REAL_DATETIME(1, 1, 2, tzinfo=UTC)),
                                     (YEAR_9999, _REAL_DATETIME(9999, 12, 30, 23, 59, 59, tzinfo=UTC))):
                with self.subTest(tzone=seconds, tsoffset=offset):
                    packet, messages = self._packet(_idb((10, '<i', seconds), (14, '<q', offset)), _epb())
                    self.assertEqual(messages, [])
                    self.assertEqual(packet.info.timestamp, expected)
                    self.assertEqual(packet.info.timestamp.tzinfo, zone)
                    self.assertEqual(packet.info.timestamp.utcoffset(), datetime.timedelta(seconds=seconds))

    def test_out_of_range_offsets_still_fall_back(self) -> None:
        for offset in (-62135596801, 253402300800, 2**63 - 1):
            with self.subTest(tsoffset=offset):
                packet, messages = self._packet(_idb((14, '<q', offset)), _epb())
                self.assertEqual(packet.info.timestamp, _REAL_DATETIME(1970, 1, 1, tzinfo=UTC))
                self.assertEqual(messages, [f'PCAP-NG: [Block 6] invalid timestamp: {offset}'])


class TestMHOnWindows(unittest.TestCase):
    """MH timestamps before 1970 and after 3000 decode alike on Windows and Linux."""

    def setUp(self) -> None:
        from tests._support import reimport_once_per_class

        reimport_once_per_class(self)

    def test_mesg_id_before_1970(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.protocols.schema.internet.mh import MesgIDOption

        for interval in (_REAL_DATETIME(1900, 1, 1, tzinfo=UTC),
                         _REAL_DATETIME(1950, 6, 1, 12, 0, 0, 500_000, tzinfo=UTC),
                         _REAL_DATETIME(1969, 12, 31, 23, 59, 59, tzinfo=UTC)):
            with self.subTest(interval=interval):
                made = object.__new__(MH)._make_opt_mesg_id(Option.MESG_ID_OPTION_TYPE, interval=interval)
                octets = made.pack()
                with windows_gmtime():
                    read = MesgIDOption.unpack(octets)
                self.assertEqual(read.timestamp, interval)
                self.assertIs(read.timestamp.tzinfo, UTC)
                self.assertEqual(read.pack(), octets)

    def test_timestamp_option_after_3000(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        cases = (
            (WINDOWS_MAX + 1, 0, _REAL_DATETIME(3001, 1, 1, tzinfo=UTC)),
            (YEAR_9999, 0x8000, _REAL_DATETIME(9999, 12, 30, 23, 59, 59, 500_000, tzinfo=UTC)),
            (5, 1, _REAL_DATETIME(1970, 1, 1, 0, 0, 5, 15, tzinfo=UTC)),
        )
        for seconds, fraction, expected in cases:
            with self.subTest(seconds=seconds, fraction=fraction):
                schema = proto._make_opt_timestamp(Option.Timestamp_Option, seconds=seconds, fraction=fraction)
                with windows_gmtime():
                    data = proto._read_opt_timestamp(schema, options=None)  # type: ignore[arg-type]
                self.assertEqual(data.timestamp, expected)
                self.assertIs(data.timestamp.tzinfo, UTC)
                rebuilt = proto._make_opt_timestamp(Option.Timestamp_Option, data)
                self.assertEqual(rebuilt.pack(), schema.pack())

        # past year 9999 it raises what it raises on Linux
        schema = proto._make_opt_timestamp(Option.Timestamp_Option, seconds=2**48 - 1, fraction=0)
        with windows_gmtime(), self.assertRaises(ValueError):
            proto._read_opt_timestamp(schema, options=None)  # type: ignore[arg-type]


if __name__ == '__main__':
    unittest.main()
