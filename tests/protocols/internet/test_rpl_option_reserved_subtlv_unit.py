# -*- coding: utf-8 -*-
"""HOPOPT and IPv6-Opts keep the RPL option's reserved flag bits and sub-TLVs.

GitHub issue #1199: ``_read_opt_rpl`` and ``_make_opt_rpl`` kept only the
``O``, ``R`` and ``F`` flags, so the five reserved flag bits were rebuilt as
zero. The reader also rejected any ``Opt Data Len`` other than 4, although
:rfc:`6553#section-3` makes the length variable and says unrecognised sub-TLVs
MUST be skipped.

Every case builds its own octets in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, as in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import unittest

from tests._support import reimport_once_per_class

#: One-option extension headers, next header 59, for each RPL option type.
#: ``reserved``: flags octet 0x01, so only a reserved bit is set; RPLInstanceID
#: 0x02, SenderRank 0x0000. ``sub_tlv``: Opt Data Len 12, i.e. eight octets of
#: sub-TLVs after the fixed fields, with flags 0xE5 mixing O/R/F and reserved
#: bits. ``sub_tlv_padn``: Opt Data Len 6, two sub-TLV octets, then a PadN.
HEADERS = {
    'reserved': ('3b00{t}0401020000', 0x01, b''),
    'sub_tlv': ('3b01{t}0ce52a010200aa0102030405ff', 0x05, bytes.fromhex('00aa0102030405ff')),
    'sub_tlv_padn': ('3b01{t}06e52a010200aa010400000000', 0x05, bytes.fromhex('00aa')),
}


def _classes() -> 'dict[str, type]':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return {'HOPOPT': HOPOPT, 'IPv6_Opts': IPv6_Opts}


def _cases() -> 'list[tuple[str, int, bytes, int, bytes]]':
    cases = []
    for label, (template, reserved, sub_tlvs) in HEADERS.items():
        for code in (0x23, 0x63):
            octets = bytes.fromhex(template.format(t=f'{code:02x}'))
            cases.append((label, code, octets, reserved, sub_tlvs))
    return cases


class TestRPLOptionReservedAndSubTLVs(unittest.TestCase):
    """Pin reserved flag bits and sub-TLVs of the RPL option."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_fixtures_are_whole_headers(self) -> None:
        for label, code, octets, _, _ in _cases():
            with self.subTest(case=label, type=hex(code)):
                self.assertEqual(len(octets), (octets[1] + 1) * 8)

    def test_reserved_bits_and_sub_tlvs_are_read(self) -> None:
        for name, cls in _classes().items():
            for label, code, octets, reserved, sub_tlvs in _cases():
                with self.subTest(proto=name, case=label, type=hex(code)):
                    parsed = cls(octets, len(octets), extension=True)
                    opt = list(parsed.info.options.values())[0]
                    self.assertEqual(opt.type, code)
                    self.assertEqual(opt.flags.reserved, reserved)
                    self.assertEqual(opt.sub_tlvs, sub_tlvs)
                    self.assertEqual(opt.length, 6 + len(sub_tlvs))

    def test_rebuild_is_byte_exact(self) -> None:
        for name, cls in _classes().items():
            for label, code, octets, _, _ in _cases():
                with self.subTest(proto=name, case=label, type=hex(code)):
                    parsed = cls(octets, len(octets), extension=True)
                    self.assertEqual(cls.from_data(parsed.info).data.hex(), octets.hex())

    def test_maker_defaults_and_keywords(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.utilities.exceptions import ProtocolError

        for name, cls in _classes().items():
            proto = object.__new__(cls)
            with self.subTest(proto=name, kind='defaults'):
                made = proto._make_opt_rpl(Option.RPL_Option_0x63, down=True, id=2, rank=3)
                self.assertEqual(bytes(made).hex(), '630480020003')
            with self.subTest(proto=name, kind='keywords'):
                made = proto._make_opt_rpl(Option.RPL_Option_0x23, fwd_err=True, reserved=0x1F,
                                           id=2, rank=3, sub_tlvs=b'\x00\xaa')
                self.assertEqual(bytes(made).hex(), '23063f02000300aa')
            for kwargs in ({'reserved': 32}, {'reserved': -1}, {'sub_tlvs': bytes(252)}):
                with self.subTest(proto=name, kind=f'invalid {sorted(kwargs)}'):
                    with self.assertRaises(ProtocolError):
                        proto._make_opt_rpl(Option.RPL_Option_0x23, **kwargs)

    def test_short_rpl_option_still_raises_protocol_error(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        # Opt Data Len 3, one short of the fixed fields.
        octets = bytes.fromhex('3b00230301020001')
        for name, cls in _classes().items():
            with self.subTest(proto=name):
                with self.assertRaises(ProtocolError):
                    cls(octets, len(octets), extension=True)


if __name__ == '__main__':
    unittest.main()
