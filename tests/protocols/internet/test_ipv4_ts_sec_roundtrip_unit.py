# -*- coding: utf-8 -*-
"""The IPv4 Timestamp and Security options rebuild byte for byte.

- GitHub issue #1391: ``_make_opt_ts`` turned a ``timedelta`` into milliseconds
  with ``math.floor(td.total_seconds() * 1000)``, and the float product is
  inexact, so a stamp of 1001 ms rebuilt as 1000.
- GitHub issue #1392: the 1-3 octets a ``TS`` length leaves after its last
  whole slot were a zero-packing padding field, so they rebuilt as zeros. They
  are now the ``remainder`` data field, kept as read.
- GitHub issue #1393: ``_make_opt_sec`` set every field termination indicator
  from the octet's position, so a non-conforming one was rewritten. The wire
  bits are now the ``termination`` data field, written back on rebuild.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest
import warnings

from tests._support import reimport_once_per_class


def header(options: 'str') -> 'bytes':
    """An IPv4 header from 10.0.0.1 to 10.0.0.2, protocol 253, with ``options`` in hex."""
    opts = bytes.fromhex(options)
    opts += bytes(-len(opts) % 4)
    ihl = 5 + len(opts) // 4
    return (bytes([0x40 | ihl, 0]) + (ihl * 4).to_bytes(2, 'big') + bytes(2)
            + bytes.fromhex('000040fd0000') + bytes([10, 0, 0, 1, 10, 0, 0, 2]) + opts)


#: Wire headers that must rebuild through ``from_data`` unchanged, by issue.
HEADERS = {
    '#1391 timestamp only, 1001 ms': header('44080900' '000003e9'),
    '#1391 address and timestamp, 1001 ms': header('440c0d01' 'c0000201' '000003e9'),
    '#1391 timestamp only, several inexact stamps': header('44100d00' '000003e9' '000003f1' '001f4006'),
    '#1392 one-octet tail': header('44050500' 'aa'),
    '#1392 three-octet tail, no slot': header('44070500' 'aabbcc'),
    '#1392 three-octet tail after a slot': header('440b0900' '00000005' 'aabbcc'),
    '#1392 two-octet tail, address and timestamp': header('440e0d01' 'c0000201' '00000005' 'aabb'),
    '#1393 last indicator set': header('8204ab91'),
    '#1393 last indicator set, low authorities': header('82041181'),
    '#1393 first indicator clear': header('8205118001'),
}


class TestIPv4TimestampSecurityRoundTrip(unittest.TestCase):
    """Pin the TS and SEC option bytes through parse, rebuild and make."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, data: 'bytes') -> 'object':
        from pcapkit.protocols.internet.ipv4 import IPv4

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return IPv4(io.BytesIO(data), len(data))

    def option(self, data: 'bytes', kind: 'str') -> 'object':
        from pcapkit.const.ipv4.option_number import OptionNumber

        return self.parse(data).info.options[OptionNumber[kind]]  # type: ignore[attr-defined]

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        for name, data in HEADERS.items():
            with self.subTest(header=name):
                parsed = self.parse(data)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertEqual(bytes(IPv4.from_data(parsed.info)).hex(), data.hex())  # type: ignore[attr-defined]

    def test_make_converts_a_timedelta_exactly(self) -> None:
        import datetime
        import ipaddress

        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        # Each of these floors one short through ``total_seconds() * 1000``.
        for msec in (1001, 1009, 2048006, 2147483644):
            stamp = datetime.timedelta(milliseconds=msec)
            with self.subTest(msec=msec, flag='timestamp only'):
                datagram = IPv4(src='10.0.0.1', dst='10.0.0.2', ttl=64, id=0,
                                options=[(OptionNumber.TS, {'counts': 1, 'timestamp': [stamp]})],
                                payload=b'')
                self.assertEqual(bytes(datagram)[24:28], msec.to_bytes(4, 'big'))
            with self.subTest(msec=msec, flag='address and timestamp'):
                datagram = IPv4(src='10.0.0.1', dst='10.0.0.2', ttl=64, id=0,
                                options=[(OptionNumber.TS, {'counts': 1, 'timestamp': {
                                    ipaddress.ip_address('192.0.2.1'): stamp,
                                }})], payload=b'')
                self.assertEqual(bytes(datagram)[28:32], msec.to_bytes(4, 'big'))

    def test_trailing_partial_slot_is_data(self) -> None:
        option = self.option(HEADERS['#1392 three-octet tail after a slot'], 'TS')
        self.assertEqual(option.remainder, b'\xaa\xbb\xcc')  # type: ignore[attr-defined]
        self.assertEqual(option.remaining, ())  # type: ignore[attr-defined]

        option = self.option(header('44080900' '00000005'), 'TS')
        self.assertEqual(option.remainder, b'')  # type: ignore[attr-defined]

    def test_termination_indicators_are_data(self) -> None:
        option = self.option(HEADERS['#1393 first indicator clear'], 'SEC')
        self.assertEqual(option.termination, (False, True))  # type: ignore[attr-defined]

        option = self.option(header('820301'), 'SEC')
        self.assertEqual(option.termination, ())  # type: ignore[attr-defined]

    def test_indicators_that_no_longer_cover_the_octets_are_positional(self) -> None:
        from pcapkit.const.ipv4.classification_level import ClassificationLevel
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.protocols.data.internet.ipv4 import SECOption
        from pcapkit.protocols.internet.ipv4 import IPv4

        proto = IPv4.__new__(IPv4)
        # One recorded indicator, but the authorities reach a second octet.
        option = SECOption(code=OptionNumber.SEC, type=proto._read_ipv4_opt_type(OptionNumber.SEC),
                           length=4, level=ClassificationLevel.Unclassified,
                           flags=(ProtectionAuthority.GENSER, ProtectionAuthority(8)),
                           termination=(False,))
        self.assertEqual(proto._make_opt_sec(OptionNumber.SEC, option).data, b'\x81\x80')


if __name__ == '__main__':
    unittest.main()
