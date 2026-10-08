# -*- coding: utf-8 -*-
"""The IPv4 Timestamp option keeps the slots at or beyond its pointer.

GitHub issue #1349: the ``TS`` option's ``ts_data`` covered only the
``pointer - 5`` octets before the pointer, and the rest of the option was a
:class:`~pcapkit.corekit.fields.strings.PaddingField` that packed zeros, so
``from_data`` over a parsed header zeroed every slot not yet filled in. Those
slots are now the ``remaining`` data field and a ``make()`` keyword, the same
shape #1319 gave LSR, SSR and RR.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class


def header(options: 'str') -> 'bytes':
    """An IPv4 header from 10.0.0.1 to 10.0.0.2, protocol 253, with ``options`` in hex."""
    opts = bytes.fromhex(options)
    ihl = 5 + len(opts) // 4
    return (bytes([0x40 | ihl, 0]) + (ihl * 4).to_bytes(2, 'big') + bytes(2)
            + bytes.fromhex('000040fd0000') + bytes([10, 0, 0, 1, 10, 0, 0, 2]) + opts)


#: Wire headers that must rebuild through ``from_data`` unchanged.
HEADERS = {
    # The two repros of the issue.
    'timestamp only, pointer 5': header('440c0500' '0000000100000002'),
    'timestamp only, pointer 9': header('44100900' '000000010000000200000003'),
    'timestamp only, unaligned pointer': header('440c0600' '0000000100000002'),
    'address and timestamp, one pair filled': header('44140d01' 'c000020100000005' 'c000020200000006'),
    'address and timestamp, half a pair filled': header('44140901' 'c000020100000005' 'c000020200000006'),
    'pre-specified, odd slot count': header('44100503' 'c000020100000000' 'c0000202'),
}


class TestIPv4TimestampSlots(unittest.TestCase):
    """Pin the TS slots at or beyond the pointer through parse, rebuild and make."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, data: 'bytes') -> 'object':
        from pcapkit.protocols.internet.ipv4 import IPv4

        return IPv4(io.BytesIO(data), len(data))

    def option(self, data: 'bytes') -> 'object':
        from pcapkit.const.ipv4.option_number import OptionNumber

        return self.parse(data).info.options[OptionNumber.TS]  # type: ignore[attr-defined]

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        for name, data in HEADERS.items():
            with self.subTest(header=name):
                parsed = self.parse(data)
                self.assertEqual(bytes(IPv4.from_data(parsed.info)), data)  # type: ignore[attr-defined]

    def test_slots_at_or_beyond_the_pointer_are_data(self) -> None:
        import datetime

        option = self.option(HEADERS['timestamp only, pointer 9'])
        self.assertEqual(option.timestamp, (datetime.timedelta(milliseconds=1),))  # type: ignore[attr-defined]
        self.assertEqual(option.remaining, (2, 3))  # type: ignore[attr-defined]

        option = self.option(HEADERS['timestamp only, pointer 5'])
        self.assertEqual(option.timestamp, ())  # type: ignore[attr-defined]
        self.assertEqual(option.remaining, (1, 2))  # type: ignore[attr-defined]

        # A pair is never split: the address of a pair whose timestamp is not
        # filled in yet stays in ``remaining`` with it.
        option = self.option(HEADERS['address and timestamp, half a pair filled'])
        self.assertEqual(len(option.timestamp), 0)  # type: ignore[attr-defined]
        self.assertEqual(option.remaining, (0xc0000201, 5, 0xc0000202, 6))  # type: ignore[attr-defined]

        # A pre-specified address is content regardless of the pointer; a slot
        # left over from the pairs is kept rather than dropped.
        option = self.option(HEADERS['pre-specified, odd slot count'])
        self.assertEqual(len(option.timestamp), 1)  # type: ignore[attr-defined]
        self.assertEqual(option.remaining, (0xc0000202,))  # type: ignore[attr-defined]

    def test_make_writes_remaining_after_the_timestamps(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        datagram = IPv4(src='10.0.0.1', dst='10.0.0.2', ttl=64, id=0,
                        options=[(OptionNumber.TS, {'counts': 3, 'timestamp': [1],
                                                    'remaining': [2]})], payload=b'')
        self.assertEqual(bytes(datagram)[20:].hex(), '44100900' '000000010000000200000000')


if __name__ == '__main__':
    unittest.main()
