from __future__ import annotations

import datetime
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

EPOCH = 1_700_000_000


class MHMesgIDFractionUnitTests(unittest.TestCase):
    """The Message ID option carries the NTP fraction as a 32-bit binary fraction."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def roundtrip(self, interval: 'datetime.datetime') -> 'tuple[int, datetime.datetime]':
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.protocols.schema.internet.mh import MesgIDOption

        proto = object.__new__(MH)
        made = proto._make_opt_mesg_id(Option.MESG_ID_OPTION_TYPE, interval=interval)
        read = MesgIDOption.unpack(made.pack())
        self.assertEqual(read.fraction, made.fraction)
        return made.fraction, read.timestamp

    def test_fraction_roundtrip(self) -> None:
        for usec, fraction in ((0, 0), (500_000, 2**31), (999_999, None)):
            with self.subTest(usec=usec):
                interval = datetime.datetime.fromtimestamp(EPOCH, tz=datetime.timezone.utc).replace(microsecond=usec)
                packed, timestamp = self.roundtrip(interval)
                if fraction is not None:
                    self.assertEqual(packed, fraction)
                self.assertAlmostEqual(packed / 2**32, usec / 1_000_000, delta=1e-6)
                self.assertEqual(timestamp, interval)

    def test_exact_integer_second(self) -> None:
        interval = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        packed, timestamp = self.roundtrip(interval)
        self.assertEqual(packed, 0)
        self.assertEqual(timestamp, interval)

    def test_fraction_clamped_to_field_width(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        interval = mock.Mock(timestamp=lambda: 1 - 2**-40)  # rounds up to 2**32
        made = proto._make_opt_mesg_id(Option.MESG_ID_OPTION_TYPE, interval=interval)
        self.assertEqual(made.fraction, 0xFFFF_FFFF)
        self.assertEqual(made.seconds, 2_208_988_800)

    def test_read_fraction_is_seconds(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.schema.internet.mh import MesgIDOption

        raw = MesgIDOption(type=Option.MESG_ID_OPTION_TYPE, length=8,
                           seconds=EPOCH + 2_208_988_800, fraction=2**30).pack()
        self.assertEqual(MesgIDOption.unpack(raw).timestamp,
                         datetime.datetime.fromtimestamp(EPOCH + 0.25, tz=datetime.timezone.utc))


if __name__ == '__main__':
    unittest.main()
