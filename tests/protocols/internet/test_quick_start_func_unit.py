# -*- coding: utf-8 -*-
"""Quick-Start options in IPv4, HOPOPT and IPv6-Opts build, parse and round-trip.

GitHub issue #1091. ``_read_opt_qs`` read ``schema.func``, which the schema
declares only under ``TYPE_CHECKING`` and which only ``_QSOption.post_process``
sets on the parse path. A schema built by ``_make_opt_qs`` never passes through
that hook, so constructing any Quick-Start option raised ``AttributeError:
'QuickStartRequestOption' object has no attribute 'func'``. The readers now
take the function from ``flags['func']``, the bit-field they already read
``rate`` from.

HOPOPT and IPv6-Opts also sized the nested suboption with
``SchemaField(length=5)``, three octets short of the eight-octet option, so a
well-formed option decoded its nonce wrongly and left octets behind;
:meth:`QuickStartWireTests.test_wire_option_decodes_the_full_nonce` covers that.

"""

from __future__ import annotations

import datetime
import importlib.util
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A 30-bit nonce whose wire form, shifted left two bits, is ``deadbee0``.
NONCE = 0xDEADBEE0 >> 2


def _families() -> 'list[tuple]':
    from pcapkit.const.ipv4.option_number import OptionNumber as Enum_IPv4Option
    from pcapkit.const.ipv6.option import Option as Enum_IPv6Option
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.internet.hopopt import HOPOPT
    from pcapkit.protocols.internet.ipv4 import IPv4
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

    return [
        ('IPv4', IPv4, dict(src='192.0.2.1', dst='192.0.2.2', protocol=TransType.UDP),
         Enum_IPv4Option.QS),
        ('HOPOPT', HOPOPT, dict(next=TransType.UDP), Enum_IPv6Option.Quick_Start),
        ('IPv6-Opts', IPv6_Opts, dict(next=TransType.UDP), Enum_IPv6Option.Quick_Start),
    ]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class QuickStartRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_quick_start_option_round_trips(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction

        for name, cls, base, code in _families():
            for func in (Enum_QSFunction.Quick_Start_Request,
                         Enum_QSFunction.Report_of_Approved_Rate):
                with self.subTest(family=name, func=func.name):
                    with warnings.catch_warnings():
                        warnings.simplefilter('error')
                        built = cls(options=[(code, dict(func=func, rate=80, ttl=5, nonce=NONCE))],
                                    **base)
                        again = cls(built.data)
                    self.assertEqual(again.data, built.data)

                    option = list(again.info.options.values())[0]
                    self.assertEqual(option.func, func)
                    self.assertEqual(option.rate, 80)
                    self.assertEqual(option.nonce, NONCE)
                    if func == Enum_QSFunction.Quick_Start_Request:
                        self.assertEqual(option.ttl, datetime.timedelta(seconds=5))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class QuickStartWireTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_wire_option_decodes_the_full_nonce(self) -> None:
        from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        # next=UDP, len=1 (16 octets); Quick-Start Request type 0x26 len 6,
        # func 0 rate 1, ttl 5, nonce; then PadN of four octets.
        wire = bytes.fromhex('1101' '26060105deadbee0' '010400000000')
        for cls in (HOPOPT, IPv6_Opts):
            with self.subTest(family=cls.__name__):
                with warnings.catch_warnings():
                    warnings.simplefilter('error')
                    parsed = cls(wire)

                options = list(parsed.info.options.values())
                self.assertEqual(options[0].func, Enum_QSFunction.Quick_Start_Request)
                self.assertEqual(options[0].nonce, NONCE)
                self.assertEqual(options[0].ttl, datetime.timedelta(seconds=5))
                self.assertEqual(len(options), 2)


if __name__ == '__main__':
    unittest.main()
