# -*- coding: utf-8 -*-
"""The Quick-Start rate codec, and the Quick-Start option round trips (GitHub issue #2617).

:rfc:`4782` Section 3.1 encodes a Quick-Start rate as a four-bit ``N`` that
stands for ``40 kbps * 2 ** N``, with ``N = 0`` for a rate of zero. The IPv6
option keeps the IPv4 format (Section 3.2), and the TCP Quick-Start Response
formats its Rate Request the same way (Section 4.2). IPv4, HOPOPT, IPv6-Opts and
TCP each held a copy of the encoder and the decoder, and the copies disagreed
outside the field: the IP families raised a bare ``ValueError`` for
``0 < rate < 40``, TCP wrote ``N = 0`` there, and all four wrote ``N = 0`` for a
negative rate or one under 80 kbps. The owner ruled on #2617 that a rate the
field cannot carry raises ``ProtocolError`` everywhere, and that every reader
and maker pairs up and round-trips both ways.

* :class:`CodecTests` -- ``_read_qs_rate`` and ``_make_qs_rate``, the pair on the
  protocol base that every family calls.
* :class:`RefusalTests` -- each IP family's ``make()`` refuses a rate the field
  cannot carry; TCP's case is in
  ``tests/protocols/transport/test_tcp_quick_start_response_unit.py``.
* :class:`FieldRefusalTests` -- the same for the TTL, nonce and ``R`` bits, which
  the IP makers wrapped, wrote into the nonce, or refused with a bare
  ``ValueError``, ``OverflowError`` or ``FieldValueError``.
* :class:`RoundTripTests` -- for every rate code, family and function, make ->
  parse gives the values back and parse -> rebuild gives the octets back, both
  checked against the RFC's octet layout.
* :class:`UnassignedFunctionTests` -- HOPOPT and IPv6-Opts read an unassigned
  function code as an unassigned option but had no maker for one, which IPv4 had.

Every case builds its own octets, so this module is unit-tier. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import datetime
import io
import re
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): hand-picked round-trip cases of one field, not a sweep.
__tier__ = 'ALL'

#: A 30-bit nonce and the two ``R`` bits after it, as a wire word.
NONCE, RESERVED = 0xDEADBEE0 >> 2, 1
NONCE_WORD = ((NONCE << 2) | RESERVED).to_bytes(4, 'big')

#: Every rate a four-bit code carries, by code: ``40 * 2 ** N`` kbps, zero for ``N = 0``.
RATES = {code: 40 * 2 ** code if code else 0 for code in range(16)}

#: Rates the field cannot carry: negative, above zero but under ``N = 1``, past ``N = 15``.
UNCARRIABLE = (-80, -1, 1, 10, 39, 40, 79, 40 * 2 ** 16, 10 ** 12)

#: The unassigned Quick-Start function codes (:rfc:`4782` assigns ``0`` and ``8``).
UNASSIGNED = tuple(func for func in range(16) if func not in (0, 8))


def ip_families() -> 'list[tuple[str, Callable[..., bytes], Callable[[bytes], Any], Any, bytes]]':
    """``(name, make, parse, option code, option prefix)`` for each IP family.

    ``make`` builds a packet from a list of options and ``parse`` reads its octets;
    the prefix is the option's type and length octets, eight for IPv4's option
    length and six for the IPv6 ``Opt Data Len`` (:rfc:`4782` Section 3.2).
    """
    from pcapkit.const.ipv4.option_number import OptionNumber
    from pcapkit.const.ipv6.option import Option
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.internet.hopopt import HOPOPT
    from pcapkit.protocols.internet.ipv4 import IPv4
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

    def ipv4(options: 'list') -> 'bytes':
        return IPv4(src='192.0.2.1', dst='192.0.2.2', protocol=TransType.UDP, options=options).data

    def ipv6(cls: 'type') -> 'Callable[[list], bytes]':
        return lambda options: cls(next=TransType.UDP, options=options).data

    def parse6(cls: 'type') -> 'Callable[[bytes], Any]':
        return lambda octets: cls(io.BytesIO(octets), len(octets), extension=True)

    return [
        ('IPv4', ipv4, lambda octets: IPv4(io.BytesIO(octets), len(octets)), OptionNumber.QS, b'\x19\x08'),
        ('HOPOPT', ipv6(HOPOPT), parse6(HOPOPT), Option.Quick_Start, b'\x26\x06'),
        ('IPv6-Opts', ipv6(IPv6_Opts), parse6(IPv6_Opts), Option.Quick_Start, b'\x26\x06'),
    ]


def option_octets(name: 'str', data: 'bytes') -> 'bytes':
    """The eight octets of the first option in a packet built by :func:`ip_families`."""
    return data[20:28] if name == 'IPv4' else data[2:10]


def ip_wire(name: 'str', option: 'bytes') -> 'bytes':
    """A header carrying ``option`` and nothing else, padded to a whole header."""
    if name == 'IPv4':
        # IHL 8: a 20-octet header, the option and four octets of EOOL.
        return (bytes.fromhex('48000020' '00000000' '40110000') + bytes([192, 0, 2, 1, 192, 0, 2, 2])
                + option + bytes(4))
    # next UDP, Hdr Ext Len 1: the option, then a PadN of four octets.
    return bytes([17, 1]) + option + bytes.fromhex('010400000000')


def rebuild(parsed: 'Any') -> 'bytes':
    """``from_data`` of a parsed layer, as octets."""
    return type(parsed).from_data(parsed.info).data


class _QSTestCase(unittest.TestCase):
    """A fresh :mod:`pcapkit` per class."""

    def setUp(self) -> None:
        reimport_once_per_class(self)


class CodecTests(_QSTestCase):
    """``_read_qs_rate`` and ``_make_qs_rate`` against :rfc:`4782` Section 3.1."""

    def setUp(self) -> None:
        super().setUp()
        from pcapkit.protocols.misc.raw import Raw

        self.proto = Raw(b'')

    def test_read_gives_k_times_two_to_the_n(self) -> None:
        # K * 2 ** N bps with K = 40,000, zero for N = 0; "80 Kbps to 1.3 Gbps".
        self.assertEqual(self.proto._read_qs_rate(0), 0)
        self.assertEqual(self.proto._read_qs_rate(1), 80)
        self.assertEqual(self.proto._read_qs_rate(15), 1_310_720)
        for code in range(1, 16):
            with self.subTest(code=code):
                self.assertEqual(self.proto._read_qs_rate(code) * 1000, 40_000 * 2 ** code)

    def test_make_inverts_read(self) -> None:
        for code, rate in RATES.items():
            with self.subTest(code=code):
                self.assertEqual(self.proto._make_qs_rate(rate), code)

    def test_make_rounds_down_between_codes(self) -> None:
        for code in range(1, 16):
            for rate in (RATES[code] + 1, 2 * RATES[code] - 1):
                with self.subTest(rate=rate):
                    self.assertEqual(self.proto._make_qs_rate(rate), code)

    def test_make_refuses_a_rate_the_field_cannot_carry(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for rate in UNCARRIABLE + (80.0, True, False, None, '80'):
            with self.subTest(rate=rate):
                with self.assertRaisesRegex(ProtocolError, f'^Raw: invalid Quick-Start rate: {re.escape(repr(rate))}$'):
                    self.proto._make_qs_rate(rate)


class RefusalTests(_QSTestCase):
    """The IP families raise ``ProtocolError`` for a rate the field cannot carry."""

    def test_each_family_and_function_refuses(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction
        from pcapkit.utilities.exceptions import ProtocolError

        for name, make, _, code, _ in ip_families():
            for func in (QSFunction.Quick_Start_Request, QSFunction.Report_of_Approved_Rate, 5):
                for rate in UNCARRIABLE:
                    with self.subTest(family=name, func=func, rate=rate):
                        with self.assertRaisesRegex(ProtocolError, f': invalid Quick-Start rate: {rate}$'):
                            make([(code, dict(func=func, rate=rate))])


class FieldRefusalTests(_QSTestCase):
    """The IP families raise ``ProtocolError`` for a TTL, nonce or ``R`` value outside its field."""

    #: ``(keyword, message name, values outside the field)``: 8, 30 and 2 bits.
    FIELDS = (
        ('ttl', 'TTL', (-1, 256, 300, True)),
        ('nonce', 'nonce', (-1, 1 << 30, 1 << 32, True)),
        ('reserved', 'reserved', (-1, 4, 7, True)),
    )

    def test_each_family_and_function_refuses(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction
        from pcapkit.utilities.exceptions import ProtocolError

        for name, make, _, code, _ in ip_families():
            for func in (QSFunction.Quick_Start_Request, QSFunction.Report_of_Approved_Rate, 5):
                for keyword, what, values in self.FIELDS:
                    if keyword == 'ttl' and func == QSFunction.Report_of_Approved_Rate:
                        continue
                    for value in values:
                        with self.subTest(family=name, func=func, field=keyword, value=value):
                            pattern = f': invalid Quick-Start {what}: {re.escape(repr(value))}$'
                            with self.assertRaisesRegex(ProtocolError, pattern):
                                make([(code, {'func': func, 'rate': 80, keyword: value})])

    def test_the_bounds_of_each_field_build(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction

        for name, make, parse, code, prefix in ip_families():
            for ttl, nonce, reserved in ((0, 0, 0), (255, (1 << 30) - 1, 3)):
                with self.subTest(family=name, ttl=ttl):
                    data = make([(code, dict(func=QSFunction.Quick_Start_Request, rate=80, ttl=ttl,
                                             nonce=nonce, reserved=reserved))])
                    word = ((nonce << 2) | reserved).to_bytes(4, 'big')
                    self.assertEqual(option_octets(name, data), prefix + bytes([0x01, ttl]) + word)
                    option = parse(data).info.options[code]
                    self.assertEqual((option.ttl.seconds, option.nonce, option.reserved), (ttl, nonce, reserved))

    def test_a_report_ignores_the_ttl_it_does_not_carry(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction

        for name, make, _, code, _ in ip_families():
            with self.subTest(family=name):
                args = dict(func=QSFunction.Report_of_Approved_Rate, rate=80)
                self.assertEqual(make([(code, dict(args, ttl=300))]), make([(code, args)]))


class RoundTripTests(_QSTestCase):
    """Every rate code round-trips both ways through each family's reader and maker."""

    def test_ip_make_then_parse_gives_the_values_back(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction

        request, report = QSFunction.Quick_Start_Request, QSFunction.Report_of_Approved_Rate
        for name, make, parse, code, prefix in ip_families():
            unused = 7 if name == 'IPv4' else b'\x07'
            for func, fourth in ((request, dict(ttl=5)), (report, dict(unused=unused))):
                for n, rate in RATES.items():
                    with self.subTest(family=name, func=func.name, rate=rate):
                        data = make([(code, dict(func=func, rate=rate, nonce=NONCE, reserved=RESERVED, **fourth))])
                        # Figures 3 and 4: function and rate nibbles, the fourth octet, then the nonce word.
                        self.assertEqual(option_octets(name, data),
                                         prefix + bytes([(func << 4) | n, 5 if func == request else 7]) + NONCE_WORD)

                        option = parse(data).info.options[code]
                        self.assertEqual((option.func, option.rate, option.nonce, option.reserved),
                                         (func, rate, NONCE, RESERVED))
                        if func == request:
                            self.assertEqual(option.ttl, datetime.timedelta(seconds=5))
                        else:
                            self.assertEqual(option.unused, unused)

    def test_ip_parse_then_rebuild_gives_the_octets_back(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction

        for name, _, parse, code, prefix in ip_families():
            for func in (QSFunction.Quick_Start_Request, QSFunction.Report_of_Approved_Rate):
                for n, rate in RATES.items():
                    with self.subTest(family=name, func=func.name, rate=rate):
                        wire = ip_wire(name, prefix + bytes([(func << 4) | n, 9]) + NONCE_WORD)
                        with warnings.catch_warnings():
                            warnings.simplefilter('error')
                            parsed = parse(wire)
                        self.assertEqual(parsed.info.options[code].rate, rate)
                        self.assertEqual(rebuild(parsed), wire)

    def test_tcp_make_then_parse_gives_the_values_back(self) -> None:
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP

        code = Option.Quick_Start_Response
        for n, rate in RATES.items():
            with self.subTest(rate=rate):
                data = TCP(srcport=1, dstport=2, options=[(code, dict(rate=rate, diff=3, nonce=NONCE, reserved=0xa,
                                                                     nonce_reserved=RESERVED))]).data
                # Section 4.2: Kind 27, Length 8, Resv. and Rate Request, TTL Diff, then the nonce word.
                self.assertEqual(data[20:28], bytes([27, 8, 0xa0 | n, 3]) + NONCE_WORD)

                option = TCP(data, len(data)).info.options[code]
                self.assertEqual((option.req_rate, option.ttl_diff, option.nonce, option.reserved,
                                  option.nonce_reserved), (rate, 3, NONCE, 0xa, RESERVED))

    def test_tcp_parse_then_rebuild_gives_the_octets_back(self) -> None:
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP

        header = bytes.fromhex('0001000200000000000000007000ffff00000000')
        for n, rate in RATES.items():
            with self.subTest(rate=rate):
                wire = header + bytes([27, 8, 0x50 | n, 3]) + NONCE_WORD
                parsed = TCP(wire, len(wire))
                self.assertEqual(parsed.info.options[Option.Quick_Start_Response].req_rate, rate)
                self.assertEqual(rebuild(parsed), wire)


class UnassignedFunctionTests(_QSTestCase):
    """Each IP family makes an unassigned function code, as its reader reads one."""

    def test_make_then_parse_keeps_the_option_data(self) -> None:
        for name, make, parse, code, prefix in ip_families():
            for func in UNASSIGNED:
                with self.subTest(family=name, func=func):
                    data = make([(code, dict(func=func, rate=160, ttl=5, nonce=NONCE, reserved=RESERVED))])
                    # The layout of a Quick-Start Request, under the unassigned code.
                    body = bytes([(func << 4) | 2, 5]) + NONCE_WORD
                    self.assertEqual(option_octets(name, data), prefix + body)

                    parsed = parse(data)
                    option = parsed.info.options[code]
                    self.assertEqual(type(option).__name__, 'UnassignedOption')
                    self.assertEqual(option.data, body)
                    self.assertEqual(rebuild(parsed), data)

    def test_a_function_past_four_bits_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for name, make, _, code, _ in ip_families():
            with self.subTest(family=name):
                with self.assertRaisesRegex(ProtocolError, 'invalid QS function: 16'):
                    make([(code, dict(func=16))])


if __name__ == '__main__':
    unittest.main()
