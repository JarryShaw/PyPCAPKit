# -*- coding: utf-8 -*-
"""Two octets of option padding are one ``PadN``, not two ``Pad1``.

GitHub issue #1793: HOPOPT, IPv6-Opts and MH each filled a two-octet shortfall
with two ``Pad1`` options. :rfc:`8200#section-4.2`, and :rfc:`6275#section-6.2.2`
for mobility options, say a ``PadN`` should be used rather than multiple
``Pad1``, so two octets are now one ``PadN`` of length ``0``: the octets
``01 00``. One octet is still a ``Pad1``, and parsed padding is still rebuilt as
it was read -- only freshly built padding changed.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import io
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Protocol module, class name and option enum module of each padding builder.
PROTOCOLS = (
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT', 'pcapkit.const.ipv6.option'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts', 'pcapkit.const.ipv6.option'),
    ('pcapkit.protocols.internet.mh', 'MH', 'pcapkit.const.mh.option'),
)

#: Parsed headers whose padding is two ``Pad1`` options, which have to rebuild
#: unchanged: a Router Alert in an options header, and a Binding Refresh Request
#: carrying a 6-octet ``PadN``.
TWO_PAD1 = {
    'HOPOPT': '3b00' '05020000' '00' '00',
    'IPv6_Opts': '3b00' '05020000' '00' '00',
    'MH': '3b01000000000000' '010400000000' '00' '00',
}


class TestTwoOctetPadding(unittest.TestCase):
    """Pin the wire form of two octets of HOPOPT, IPv6-Opts and MH padding."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _protocols(self) -> 'list[tuple[type, type]]':
        return [(getattr(importlib.import_module(mod), name),
                 importlib.import_module(enum).Option)
                for mod, name, enum in PROTOCOLS]

    def test_two_octets_are_one_zero_length_padn(self) -> None:
        for cls, option in self._protocols():
            proto = object.__new__(cls)
            # the offset counts the fixed header too, so 6 and 14 are two short
            for offset in (6, 14):
                with self.subTest(protocol=cls.__name__, offset=offset):
                    with warnings.catch_warnings():
                        warnings.simplefilter('error')
                        pads, pad_len = proto._make_pad_options(offset)
                    self.assertEqual(pad_len, 2)
                    self.assertEqual([pad.type for pad in pads], [option.PadN])
                    self.assertEqual(pads[0].pack(), b'\x01\x00')

    def test_one_and_three_octets_keep_their_form(self) -> None:
        for cls, option in self._protocols():
            proto = object.__new__(cls)
            with self.subTest(protocol=cls.__name__, octets=1):
                pads, pad_len = proto._make_pad_options(7)
                self.assertEqual(pad_len, 1)
                self.assertEqual([(pad.type, pad.pack()) for pad in pads],
                                 [(option.Pad1, b'\x00')])
            with self.subTest(protocol=cls.__name__, octets=3):
                pads, pad_len = proto._make_pad_options(5)
                self.assertEqual(pad_len, 3)
                self.assertEqual([(pad.type, pad.pack()) for pad in pads],
                                 [(option.PadN, b'\x01\x01\x00')])

    def test_constructed_header_ends_in_one_zero_length_padn(self) -> None:
        from pcapkit.const.ipv6.option import Option as IPv6_Option
        from pcapkit.const.mh.option import Option as MH_Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType

        protocols = {cls.__name__: cls for cls, _ in self._protocols()}
        built = {
            # 2 + a 4-octet Router Alert = 6, two short of 8
            'HOPOPT': (protocols['HOPOPT'](next=TransType.IPv6_NoNxt,
                                           options=[(IPv6_Option.Router_Alert, {'alert': 0})]),
                       '3b00' '05020000' '0100',
                       [(IPv6_Option.Router_Alert, 4), (IPv6_Option.PadN, 2)]),
            'IPv6_Opts': (protocols['IPv6_Opts'](next=TransType.IPv6_NoNxt,
                                                 options=[(IPv6_Option.Router_Alert, {'alert': 0})]),
                          '3b00' '05020000' '0100',
                          [(IPv6_Option.Router_Alert, 4), (IPv6_Option.PadN, 2)]),
            # 6 + 2 octets of reserved + a 6-octet PadN = 14, two short of 16
            'MH': (protocols['MH'](next=TransType.IPv6_NoNxt, type=Packet.Binding_Refresh_Request,
                                   chksum=b'\x00\x00', data={'options': [(MH_Option.PadN, {'length': 4})]}),
                   '3b01000000000000' '010400000000' '0100',
                   [(MH_Option.PadN, 6), (MH_Option.PadN, 2)]),
        }
        for name, (proto, hexstr, expected) in built.items():
            with self.subTest(protocol=name):
                raw = bytes(proto)
                self.assertEqual(raw.hex(), hexstr)
                parsed = type(proto)(io.BytesIO(raw), len(raw), extension=True)
                self.assertEqual([(code, opt.length)
                                  for code, opt in parsed.info.options.items(multi=True)],
                                 expected)

    def test_parsed_two_pad1_rebuild_byte_for_byte(self) -> None:
        for cls, option in self._protocols():
            octets = bytes.fromhex(TWO_PAD1[cls.__name__])
            with self.subTest(protocol=cls.__name__):
                parsed = cls(io.BytesIO(octets), len(octets), extension=True)
                pads = list(parsed.info.options.items(multi=True))[-2:]
                self.assertEqual([code for code, _ in pads], [option.Pad1, option.Pad1])
                self.assertEqual(bytes(cls.from_data(parsed.info)).hex(), octets.hex())


if __name__ == '__main__':
    unittest.main()
