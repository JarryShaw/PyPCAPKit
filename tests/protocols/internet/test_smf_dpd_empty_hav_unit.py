# -*- coding: utf-8 -*-
"""HOPOPT and IPv6-Opts reject an H-DPD SMF_DPD option with an empty HAV.

GitHub issue #1193: ``_make_opt_smf_dpd`` set the H-DPD mode bit with
``hav[0] | 0x80`` and no length check, so an empty Hash Assist Value raised a
bare :exc:`IndexError` rather than an in-library
:exc:`~pcapkit.utilities.exceptions.ProtocolError`.

Every case builds its options in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, as in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import unittest

from tests._support import reimport_once_per_class


def _classes() -> 'dict[str, type]':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return {'HOPOPT': HOPOPT, 'IPv6_Opts': IPv6_Opts}


class TestSMFDPDEmptyHAV(unittest.TestCase):
    """Pin the error raised for an empty H-DPD Hash Assist Value."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_empty_hav_raises_protocol_error(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.utilities.exceptions import ProtocolError

        for name, cls in _classes().items():
            with self.subTest(proto=name):
                with self.assertRaisesRegex(ProtocolError, r'\[OptNo 8\] empty Hash Assist Value'):
                    cls(options=[(Option.SMF_DPD, {'mode': SMFDPDMode.H_DPD, 'hav': b''})],
                        next=TransType.IPv6_NoNxt, payload=b'')

    def test_one_octet_hav_still_builds(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.reg.transtype import TransType

        for name, cls in _classes().items():
            with self.subTest(proto=name):
                built = cls(options=[(Option.SMF_DPD, {'mode': SMFDPDMode.H_DPD, 'hav': b'\x01'})],
                            next=TransType.IPv6_NoNxt, payload=b'')
                # SMF_DPD, length 1, HAV 0x01 with the H-DPD bit set, then PadN.
                self.assertEqual(built.data, bytes.fromhex('3b00080181010100'))


if __name__ == '__main__':
    unittest.main()
