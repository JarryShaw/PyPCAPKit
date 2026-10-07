# -*- coding: utf-8 -*-
"""HOPOPT and IPv6-Opts rebuild every SMF_DPD option byte for byte.

GitHub issue #1190: ``_make_opt_smf_dpd`` read the DPD mode from the parsed
option and then overwrote it from the ``mode`` keyword, whose default is
I-DPD, so an H-DPD option rebuilt as I-DPD. The TaggerID type was likewise
inferred from the Tagger ID length, so a 4-octet ``DEFAULT`` Tagger ID rebuilt
as IPv4.

Every case builds its own octets in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, as in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import unittest

from tests._support import reimport_once_per_class

#: Extension headers carrying one SMF_DPD option (type 0x08), next header 59,
#: padded to 8 octets with Pad1 or PadN.
HEADERS = {
    'H-DPD': bytes.fromhex('3b00080481020304'),
    'I-DPD NULL': bytes.fromhex('3b00080300010200'),
    'I-DPD IPv4': bytes.fromhex('3b0108072301020304aabb0103000000'),
    'I-DPD DEFAULT 4 octets': bytes.fromhex('3b010807130a0b0c0daabb0103000000'),
    'I-DPD DEFAULT 2 octets': bytes.fromhex('3b010805110a0baabb01050000000000'),
}


def _classes() -> 'dict[str, type]':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return {'HOPOPT': HOPOPT, 'IPv6_Opts': IPv6_Opts}


class TestSMFDPDRebuild(unittest.TestCase):
    """Pin the SMF_DPD option rebuild for each DPD mode and TaggerID type."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parsed_option_rebuilds_byte_for_byte(self) -> None:
        for name, cls in _classes().items():
            for case, octets in HEADERS.items():
                with self.subTest(proto=name, case=case):
                    parsed = cls(octets, len(octets), extension=True)
                    self.assertEqual(cls.from_data(parsed.info).data, octets)

    def test_mode_keyword_selects_h_dpd(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.reg.transtype import TransType

        for name, cls in _classes().items():
            with self.subTest(proto=name):
                built = cls(options=[(Option.SMF_DPD, {'mode': SMFDPDMode.H_DPD, 'hav': b'\x01\x02\x03\x04'})],
                            next=TransType.IPv6_NoNxt, payload=b'')
                self.assertEqual(built.data, HEADERS['H-DPD'])

    def test_tid_type_keyword_selects_default(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.tagger_id import TaggerID
        from pcapkit.const.reg.transtype import TransType

        for name, cls in _classes().items():
            with self.subTest(proto=name):
                built = cls(options=[(Option.SMF_DPD, {'tid_type': TaggerID.DEFAULT, 'tid': b'\x0a\x0b\x0c\x0d',
                                                       'id': b'\xaa\xbb'})],
                            next=TransType.IPv6_NoNxt, payload=b'')
                self.assertEqual(built.data, HEADERS['I-DPD DEFAULT 4 octets'])

    def test_tagger_id_that_does_not_fit_its_type_is_rejected(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.tagger_id import TaggerID
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.utilities.exceptions import ProtocolError

        for name, cls in _classes().items():
            for kwargs in ({'tid_type': TaggerID.IPv4, 'tid': b'\x0a\x0b'},
                           {'tid_type': TaggerID.NULL, 'tid': b'\x0a'},
                           {'tid_type': TaggerID.DEFAULT},
                           {'tid': bytes(17)}):
                with self.subTest(proto=name, kwargs=kwargs):
                    with self.assertRaises(ProtocolError):
                        cls(options=[(Option.SMF_DPD, kwargs)], next=TransType.IPv6_NoNxt, payload=b'')


if __name__ == '__main__':
    unittest.main()
