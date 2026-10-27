# -*- coding: utf-8 -*-
"""The IPv4 Timestamp option builds from its default ``timestamp``.

GitHub issue #2277: ``_make_opt_ts`` dispatched on ``timestamp`` being a
:obj:`list` or a :obj:`dict`, but its default is :data:`None`, so a ``TS``
option made without timestamps always raised ``ProtocolError``. :data:`None` is
an empty list: a Timestamp-only option with ``counts`` empty slots. Any other
value still raises, with the value printed by :func:`repr`.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: The default ``TS`` option: length 24, pointer 5, Timestamp-only, five empty slots.
DEFAULT_TS = '44180500' + '00000000' * 5


class TestIPv4TimestampDefault(unittest.TestCase):
    """Pin the default TS option through make, parse and rebuild."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def make(self, option: 'dict[str, object]') -> 'bytes':
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        return bytes(IPv4(src='10.0.0.1', dst='10.0.0.2', ttl=64, id=0,
                          options=[(OptionNumber.TS, option)], payload=b''))

    def test_default_timestamp_round_trips_byte_for_byte(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.protocols.internet.ipv4 import IPv4

        for name, option in (('omitted', {}), ('None', {'timestamp': None})):
            with self.subTest(timestamp=name):
                data = self.make(option)
                self.assertEqual(data[20:].hex(), DEFAULT_TS)
                self.assertEqual(data.hex(), self.make({'timestamp': []}).hex())

                parsed = IPv4(io.BytesIO(data), len(data))
                ts = parsed.info.options[OptionNumber.TS]  # type: ignore[attr-defined]
                self.assertEqual((ts.length, ts.pointer, ts.flag, ts.timestamp),
                                 (24, 5, TSFlag.Timestamp_Only, ()))
                self.assertEqual(bytes(IPv4.from_data(parsed.info)).hex(), data.hex())  # type: ignore[attr-defined]

    def test_invalid_timestamp_message_uses_repr(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        proto = IPv4.__new__(IPv4)
        with self.assertRaises(ProtocolError) as ctx:
            proto._make_opt_ts(OptionNumber.TS, timestamp='abc')  # type: ignore[arg-type]
        self.assertEqual(str(ctx.exception),
                         "IPv4: [OptNo 68] invalid timestamp value: must be a list or a dict, not 'abc'")


if __name__ == '__main__':
    unittest.main()
