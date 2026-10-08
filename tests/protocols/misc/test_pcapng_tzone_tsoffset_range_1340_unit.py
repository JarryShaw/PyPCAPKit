# -*- coding: utf-8 -*-
"""GitHub issue #1340: out-of-range ``if_tzone`` and ``if_tsoffset`` parse and rebuild.

``if_tzone`` is a signed 32-bit count of seconds, but a
:class:`~datetime.timezone` holds strictly less than 24 hours, so an offset of
a day or more raised a bare :exc:`ValueError` out of the IDB reader. It is now
kept as captured, as a :class:`~datetime.timedelta`, with a
:class:`~pcapkit.utilities.warnings.ProtocolWarning`, and the block's
timestamps render in UTC.

``if_tsoffset`` is a signed 64-bit count of seconds; an epoch past what
``datetime`` or the platform ``time_t`` holds raised :exc:`OverflowError` or
:exc:`OSError` from :meth:`datetime.datetime.fromtimestamp`, where only
:exc:`ValueError` fell back to the epoch with a warning. All three do now.

Every block rebuilds byte-exactly from its data model.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import datetime
import decimal
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any

#: ``datetime`` holds years 1 to 9999, so these are its first and last whole
#: seconds since the UNIX epoch.
DT_MIN = -62135596800
DT_MAX = 253402300799


def _idb(code: 'int', fmt: 'str', value: 'int') -> 'bytes':
    """An Ethernet IDB carrying one fixed-size option and ``opt_endofopt``."""
    option = struct.pack('<HH', code, struct.calcsize(fmt)) + struct.pack(fmt, value) + b'\x00\x00\x00\x00'
    body = struct.pack('<HHI', 1, 0, 0x40000) + option
    length = len(body) + 12
    return struct.pack('<II', 1, length) + body + struct.pack('<I', length)


def _tzone(value: 'int') -> 'bytes':
    return _idb(10, '<i', value)


def _tsoffset(value: 'int') -> 'bytes':
    return _idb(14, '<q', value)


def _epb(high: 'int' = 0, low: 'int' = 1) -> 'bytes':
    """A 36-octet Enhanced Packet Block on interface 0."""
    body = struct.pack('<IIIII', 0, high, low, 4, 4) + b'abcd'
    length = len(body) + 12
    return struct.pack('<II', 6, length) + body + struct.pack('<I', length)


class TestPCAPNGTZoneTSOffsetRange(PCAPNGTestCase):
    """Pin how extreme ``if_tzone`` and ``if_tsoffset`` values parse and rebuild."""

    def _interface(self, octets: 'bytes') -> 'tuple[Any, Any, list[str]]':
        """Parse ``octets`` as interface 0 of a fresh context."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = PCAPNG(octets, len(octets), num=1, sct=1, ctx=context)
        context.interfaces[0] = parsed.info
        return context, parsed, [str(item.message) for item in caught]

    def _packet(self, context: 'Any', octets: 'bytes') -> 'tuple[Any, list[str]]':
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)
        # the four-octet payload is too short for Ethernet, which warns of its own
        return parsed, [str(item.message) for item in caught if str(item.message).startswith('PCAP-NG')]

    def _assert_rebuilds(self, octets: 'bytes', context: 'Any', num: 'int') -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = PCAPNG(octets, len(octets), num=num, sct=1, ctx=context)
            rebuilt = PCAPNG.from_data(parsed.info, num=num, sct=1, ctx=context).data
        self.assertEqual(rebuilt.hex(), octets.hex())

    def test_tzone_out_of_range_is_kept(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        for value in (-2**31, -86401, -86400, 86400, 86401, 2**31 - 1):
            with self.subTest(tzone=value):
                octets = _tzone(value)
                context, parsed, messages = self._interface(octets)
                kept = parsed.info.options[OptionType.if_tzone].timezone
                self.assertEqual(kept, datetime.timedelta(seconds=value))
                self.assertNotIsInstance(kept, datetime.timezone)
                self.assertIn(f'PCAP-NG: [if_tzone] offset of {value} second(s) is not within 24 hours '
                              f'of UTC; kept as captured', messages)
                self._assert_rebuilds(octets, self._context(), 1)

                # the block's packets render in UTC and keep the same instant
                packet, messages = self._packet(context, _epb())
                self.assertEqual(packet.info.timestamp,
                                 datetime.datetime(1970, 1, 1, 0, 0, 0, 1, datetime.timezone.utc))
                self.assertIs(packet.info.timestamp.tzinfo, datetime.timezone.utc)
                self.assertEqual(packet.info.timestamp_epoch, decimal.Decimal('0.000001'))
                self.assertEqual(messages, [])
                self._assert_rebuilds(_epb(), context, 2)

    def test_tzone_in_range_is_a_timezone(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        for value in (-86399, -3600, 0, 3600, 86399):
            with self.subTest(tzone=value):
                octets = _tzone(value)
                context, parsed, messages = self._interface(octets)
                zone = datetime.timezone(datetime.timedelta(seconds=value))
                self.assertEqual(parsed.info.options[OptionType.if_tzone].timezone, zone)
                self.assertEqual(messages, [])
                self._assert_rebuilds(octets, self._context(), 1)
                packet, _ = self._packet(context, _epb())
                self.assertEqual(packet.info.timestamp.utcoffset(), datetime.timedelta(seconds=value))

    def test_tsoffset_out_of_range_falls_back(self) -> None:
        for value in (-2**63, -2**62, DT_MIN - 1, DT_MAX + 1, 2**62, 2**63 - 1):
            with self.subTest(tsoffset=value):
                octets = _tsoffset(value)
                context, _, messages = self._interface(octets)
                self.assertEqual(messages, [])
                self._assert_rebuilds(octets, self._context(), 1)

                packet, messages = self._packet(context, _epb())
                epoch = decimal.Decimal(value) + decimal.Decimal('0.000001')
                self.assertEqual(packet.info.timestamp_epoch, epoch)
                self.assertEqual(packet.info.timestamp, datetime.datetime.fromtimestamp(0, datetime.timezone.utc))
                self.assertEqual(messages, [f'PCAP-NG: [Block 6] invalid timestamp: {epoch}'])
                self._assert_rebuilds(_epb(), context, 2)

    def test_tsoffset_in_range_is_unchanged(self) -> None:
        for value in (DT_MIN + 86400, -5, 0, 5, DT_MAX - 86400):
            with self.subTest(tsoffset=value):
                context, _, _ = self._interface(_tsoffset(value))
                packet, messages = self._packet(context, _epb(0, 0))
                self.assertEqual(messages, [])
                self.assertEqual(packet.info.timestamp_epoch, decimal.Decimal(value))
                self.assertEqual(packet.info.timestamp,
                                 datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
                                 + datetime.timedelta(seconds=value))
                self._assert_rebuilds(_epb(0, 0), context, 2)

    def test_largest_timestamp_with_extreme_tsoffset(self) -> None:
        """The largest EPB timestamp, 2**64 - 1 microseconds, on top of either extreme offset."""
        for value in (-2**63, -1, 0, 2**63 - 1):
            with self.subTest(tsoffset=value):
                context, _, _ = self._interface(_tsoffset(value))
                octets = _epb(0xFFFFFFFF, 0xFFFFFFFF)
                packet, messages = self._packet(context, octets)
                epoch = decimal.Decimal(2**64 - 1) / 1_000_000 + value
                self.assertEqual(packet.info.timestamp_epoch, epoch)
                self.assertEqual(packet.info.timestamp, datetime.datetime.fromtimestamp(0, datetime.timezone.utc))
                self.assertEqual(messages, [f'PCAP-NG: [Block 6] invalid timestamp: {epoch}'])
                self._assert_rebuilds(octets, context, 2)


if __name__ == '__main__':
    unittest.main()
