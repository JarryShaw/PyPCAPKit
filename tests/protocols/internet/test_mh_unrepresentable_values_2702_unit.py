# -*- coding: utf-8 -*-
"""Mobility options 6 and 27 parse values an IPv6Network and a datetime cannot hold.

GitHub issue #2702. The Mobile Network Prefix option fused its prefix and length
into an :class:`~ipaddress.IPv6Network`, which raised a bare :exc:`ValueError` on
bits set past the length or a length past 128, and the Timestamp option turned a
48-bit second count past the year 9999 into a :class:`~datetime.datetime`, which
raised one too. Neither RFC has the receiver discard such a value, so both parse:
the prefix and its length are kept as captured, and the timestamp is
:data:`None` past 9999, with ``pmip_timestamp`` holding it. The Home Network
Prefix option, option 6's twin, refused a length past 128 on both paths, and
keeps one in the same way.

Each case is parsed alone and inside IPv6, rebuilt from its info and from
``info.to_dict()``, and built with ``make()`` from keywords, against the octets
:rfc:`3963#section-4.3`, :rfc:`5213#section-8.3` and :rfc:`5213#section-8.8` lay
out.

Every case builds its own octets in memory and reads no capture.

"""

import datetime
import ipaddress
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

UTC = datetime.timezone.utc
#: The last whole second since the UNIX epoch that :class:`~datetime.datetime`
#: holds, 31 December 9999 23:59:59 UTC.
LAST_SECOND = 253_402_300_799


def _mnp(prefix_length: int, prefix: str, code: int = 6) -> bytes:
    """A Mobile Network Prefix option, :rfc:`3963#section-4.3`, or ``code``'s.

    Type 6, length 18, a reserved octet, the prefix length, then the 16-octet
    prefix. The Home Network Prefix option, :rfc:`5213#section-8.3`, is the same
    with type 22.
    """
    return bytes([code, 18, 0, prefix_length]) + ipaddress.IPv6Address(prefix).packed


def _timestamp(seconds: int, fraction: int) -> bytes:
    """A Timestamp option, :rfc:`5213#section-8.8`.

    Type 27, length 8, the seconds in 48 bits and the 1/65536ths in 16.
    """
    return bytes([27, 8]) + seconds.to_bytes(6, 'big') + fraction.to_bytes(2, 'big')


def _brr(option: bytes) -> bytes:
    """A Binding Refresh Request holding ``option``, then a PadN to a multiple of eight."""
    pad = -len(option) % 8  # 4 for options 6 and 22 and 6 for option 27, never a Pad1
    body = option + bytes([1, pad - 2]) + bytes(pad - 2)
    return bytes([59, (8 + len(body)) // 8 - 1, 0, 0, 0, 0, 0, 0]) + body


def _ipv6(body: bytes) -> bytes:
    return (bytes([0x60, 0, 0, 0]) + struct.pack('!HBB', len(body), 135, 64)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + body)


class TestMHUnrepresentableValues(unittest.TestCase):
    """Pin options 6 and 27 parsing such values quietly and rebuilding them byte for byte."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def _option(self, raw: bytes, code: 'object') -> 'object':
        """Parse ``raw`` alone and inside IPv6, check both rebuild, and return the option."""
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities import exceptions
        from pcapkit.utilities.logging import logger

        mh = MH(raw, len(raw))
        self.assertEqual(MH.from_data(mh.info).data, raw)
        self.assertEqual(MH.from_data(mh.info.to_dict()).data, raw)

        packet = _ipv6(raw)
        with capture(logger) as package, capture(exceptions.logger) as module:
            ipv6 = IPv6(packet, len(packet))
        self.assertEqual(package.messages + module.messages, [])
        self.assertEqual(IPv6.from_data(ipv6.info).data, packet)
        self.assertEqual(IPv6.from_data(ipv6.info.to_dict()).data, packet)
        (inner,) = [ext for ext in ipv6.extension_headers.values() if isinstance(ext, MH)]
        self.assertEqual(inner.info.options[code], mh.info.options[code])
        return mh.info.options[code]

    @staticmethod
    def _make(code: 'object', kwargs: 'dict') -> bytes:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH

        return MH(type=Packet.Binding_Refresh_Request, next=59, chksum=b'\x00\x00',
                  data={'options': [(code, kwargs)]}).data

    def test_mobile_network_prefix_keeps_its_octets(self) -> None:
        from pcapkit.const.mh.option import Option

        code = Option.Mobile_Network_Prefix_Option
        # (prefix length, prefix): bits set past the length, at the edges of the
        # 8-bit field and the 128-bit address, which RFC 3963 section 6.2 reads
        # as given
        for prefix_length, prefix in ((64, '2001:db8::1'), (0, 'ffff::'), (127, '2001:db8::1'),
                                      (128, '2001:db8::1'), (129, '2001:db8::'), (255, '2001:db8::1')):
            raw = _brr(_mnp(prefix_length, prefix))
            with self.subTest(prefix_length=prefix_length, prefix=prefix):
                option = self._option(raw, code)
                self.assertEqual(option.reserved, b'\x00')
                self.assertEqual(option.prefix_length, prefix_length)
                self.assertEqual(option.prefix, ipaddress.IPv6Address(prefix))
                self.assertEqual(self._make(code, {'prefix': prefix, 'prefix_length': prefix_length}), raw)

    def test_mobile_network_prefix_make_takes_a_network(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.utilities.exceptions import ProtocolError

        code = Option.Mobile_Network_Prefix_Option
        # text ending in /<length> gives the length and keeps the bits past it
        for kwargs, prefix_length, prefix in (
                ({'prefix': '2001:db8::1/64'}, 64, '2001:db8::1'),
                ({'prefix': ipaddress.IPv6Network('2001:db8::/48')}, 48, '2001:db8::'),
                ({'prefix': ipaddress.IPv6Address('2001:db8::1')}, 128, '2001:db8::1'),
                ({'prefix': '2001:db8::1/64', 'prefix_length': 200}, 200, '2001:db8::1'),
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self._make(code, kwargs), _brr(_mnp(prefix_length, prefix)))
        for kwargs, message in (({'prefix': '192.0.2.0/24'}, 'invalid mobile network prefix'),
                                ({'prefix': True}, 'invalid mobile network prefix'),
                                ({'prefix': '::/129'}, 'invalid mobile network prefix'),
                                ({'prefix': '::', 'prefix_length': 256}, 'invalid prefix length'),
                                ({'prefix': '::', 'prefix_length': True}, 'invalid prefix length')):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ProtocolError, message):
                    self._make(code, kwargs)

    def test_home_network_prefix_keeps_a_length_past_128(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.utilities.exceptions import ProtocolError

        code = Option.Home_Network_Prefix_Option
        # RFC 5213 section 5.3.2 answers a prefix it cannot authorise with a
        # status, so a length past the address is kept up to the 8-bit field
        for prefix_length, prefix in ((128, '2001:db8::1'), (129, '2001:db8::'), (255, '2001:db8::1')):
            raw = _brr(_mnp(prefix_length, prefix, code=22))
            with self.subTest(prefix_length=prefix_length, prefix=prefix):
                option = self._option(raw, code)
                self.assertEqual(option.reserved, b'\x00')
                self.assertEqual(option.prefix_length, prefix_length)
                self.assertEqual(option.prefix, ipaddress.IPv6Address(prefix))
                self.assertEqual(self._make(code, {'prefix': prefix, 'prefix_length': prefix_length}), raw)
        with self.assertRaisesRegex(ProtocolError, 'invalid prefix length'):
            self._make(code, {'prefix': '::', 'prefix_length': 256})

    def test_timestamp_past_9999_is_kept(self) -> None:
        from pcapkit.const.mh.option import Option

        code = Option.Timestamp_Option
        # (seconds, fraction, the datetime RFC 5213 section 8.8 names, or None
        # past what datetime holds); a 1/65536th is 15.2587890625 microseconds
        for seconds, fraction, expected in (
                (0, 0, datetime.datetime(1970, 1, 1, tzinfo=UTC)),
                (LAST_SECOND, 0, datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)),
                (LAST_SECOND, 1, datetime.datetime(9999, 12, 31, 23, 59, 59, 15, tzinfo=UTC)),
                (LAST_SECOND, 0xFFFF, datetime.datetime(9999, 12, 31, 23, 59, 59, 999985, tzinfo=UTC)),
                (LAST_SECOND + 1, 0, None),
                ((1 << 48) - 1, 0xFFFF, None),
        ):
            raw = _brr(_timestamp(seconds, fraction))
            with self.subTest(seconds=seconds, fraction=fraction):
                option = self._option(raw, code)
                self.assertEqual(option.timestamp, expected)
                self.assertEqual((option.pmip_timestamp.seconds, option.pmip_timestamp.fraction),
                                 (seconds, fraction))
                self.assertEqual(self._make(code, {'seconds': seconds, 'fraction': fraction}), raw)


if __name__ == '__main__':
    unittest.main()
