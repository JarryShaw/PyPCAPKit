# -*- coding: utf-8 -*-
"""``<date>`` values in a ``plist`` report (GitHub issue #1448).

:meth:`dictdumper.plist.PLIST._append_date` writes every date as
``%Y-%m-%dT%H:%M:%S.%fZ``. The property list ``<date>`` grammar has no
fractional part, so :func:`plistlib.load` failed on every report with
``AttributeError: 'NoneType' object has no attribute 'groupdict'``. These tests
dump through :func:`~pcapkit.dumpkit.common.make_dumper` and read the file back
with :mod:`plistlib`, so they need no capture. :func:`plistlib.loads` is
called without ``aware_datetime``, which is new in Python 3.13, so every
date comes back as a naive UTC value. :mod:`pcapkit` is imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""
from __future__ import annotations

import datetime
import decimal
import importlib.util
import os
import plistlib
import tempfile
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

UTC = datetime.timezone.utc


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestPlistDate(unittest.TestCase):
    """Every ``<date>`` the customised ``PLIST`` writer emits parses."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-1448-')  # pylint: disable=consider-using-with
        self.addCleanup(tmpdir.cleanup)
        self.tmpdir = tmpdir.name

    def dump(self, kind: 'str', value: 'dict[str, object]') -> 'bytes':
        """Dump ``value`` through the customised ``dictdumper`` writer ``kind``."""
        import dictdumper

        from pcapkit.dumpkit.common import make_dumper

        path = os.path.join(self.tmpdir, f'out.{kind.lower()}')
        make_dumper(getattr(dictdumper, kind))(path)(value, name='x')
        with open(path, 'rb') as file:
            return file.read()

    def load(self, value: 'dict[str, object]') -> 'dict[str, object]':
        """Dump ``value`` as ``plist`` and read it back with :func:`plistlib.loads`."""
        return plistlib.loads(self.dump('PLIST', value))['x']

    def test_sub_second_date_is_written_to_whole_seconds(self) -> None:
        """The regression: a fractional date parses, truncated, not rounded."""
        stamp = datetime.datetime(2017, 11, 19, 15, 49, 5, 999999, tzinfo=UTC)

        raw = self.dump('PLIST', {'time': stamp})

        self.assertIn(b'<date>2017-11-19T15:49:05Z</date>', raw)
        self.assertEqual(self.load({'time': stamp}),
                         {'time': datetime.datetime(2017, 11, 19, 15, 49, 5)})

    def test_exact_sibling_survives_alongside_the_date(self) -> None:
        """The exact value is carried by the ``*_epoch`` sibling, as a frame reports it."""
        epoch = decimal.Decimal('1511106545.471719')
        stamp = datetime.datetime(2017, 11, 19, 15, 49, 5, 471719, tzinfo=UTC)

        got = self.load({'time': stamp, 'time_epoch': epoch})

        self.assertEqual(got['time'], datetime.datetime(2017, 11, 19, 15, 49, 5))
        self.assertEqual(decimal.Decimal(got['time_epoch']), epoch)

    def test_aware_date_is_converted_to_utc(self) -> None:
        """``Z`` means UTC, so an offset is applied rather than dropped."""
        tz = datetime.timezone(datetime.timedelta(hours=8))
        stamp = datetime.datetime(2020, 1, 1, 8, 0, 0, 500000, tzinfo=tz)

        self.assertEqual(self.load({'t': stamp}),
                         {'t': datetime.datetime(2020, 1, 1, 0, 0, 0)})

    def test_naive_date_and_plain_date_are_written_as_is(self) -> None:
        """A naive value is taken as UTC already, as :func:`plistlib.dump` takes it."""
        got = self.load({
            'naive': datetime.datetime(1999, 12, 31, 23, 59, 59, 1),
            'day': datetime.date(2000, 2, 29),
            'early': datetime.datetime(5, 1, 2, 3, 4, 5),
        })

        self.assertEqual(got, {
            'naive': datetime.datetime(1999, 12, 31, 23, 59, 59),
            'day': datetime.datetime(2000, 2, 29),
            'early': datetime.datetime(5, 1, 2, 3, 4, 5),
        })

    def test_json_and_tree_keep_the_fractional_date(self) -> None:
        """Only the ``plist`` writer is changed; the others keep full precision."""
        stamp = datetime.datetime(2017, 11, 19, 15, 49, 5, 471719, tzinfo=UTC)

        self.assertIn(b'2017-11-19T15:49:05.471719', self.dump('JSON', {'time': stamp}))
        self.assertIn(b'2017-11-19T15:49:05.471719', self.dump('Tree', {'time': stamp}))


if __name__ == '__main__':
    unittest.main()
