# -*- coding: utf-8 -*-
"""HOPOPT and IPv6-Opts headers rebuild byte for byte from their parsed data.

The internet-v6 round-trip audit (GitHub issue #1202) found these parsed
headers that :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` could
not reproduce:

* #1228: a ``PadN`` with ``Opt Data Len`` 0 was rejected on read and rewritten
  as ``Pad1`` on make.
* #1229: parsed ``Pad1``/``PadN`` options were dropped and padding recomputed.
* #1232: the CALIPSO bitmap was stored as a tuple and ``Cmpt Length`` written
  in octets rather than 32-bit words.
* #1233: the PDM scale factors were derived again rather than kept.
* #1234: the ILNP nonce was sized from its value, not its wire width.
* #1235: the MPL ``rsv``, ``IP_DFF`` reserved and Quick-Start ``R`` bits were
  zeroed.
* #1237: an unassigned Quick-Start function could not be read.

#1200 is the other direction: a zero-length ``SMF_DPD`` option parsed as H-DPD
by reading the next option's type octet, and is now rejected.

Every case builds its own octets in memory and reads no capture. The classes
are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so that they belong to the
:mod:`pcapkit` import that is live when the test runs.

"""

import importlib
import io
import unittest
import warnings

from tests._support import reimport_once_per_class

#: The protocol classes sharing the option code, by module and class name.
PROTOCOLS = (
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
)

#: Parsed headers which have to rebuild unchanged, by issue.
HEADERS = {
    '#1228 Router Alert then PadN of length 0': '3b00050200000100',
    '#1229 six Pad1': '3b00000000000000',
    '#1229 PadN of length 0 before an option': '3b00010100040105',
    '#1229 option then non-canonical padding': '3b00040105000000',
    '#1229 one 22-octet PadN': '3b02' '0114' + '00' * 20,
    '#1232 CALIPSO with an 8-octet bitmap': '3b02' '0710' '00000001' '0205' 'abcd'
                                            '0102030405060708' '01020000',
    '#1233 PDM with scales 5 and 3': '3b01' '0f0a' '0503' '0001' '0002' '0001' '0001' '0000',
    '#1234 ILNP nonce with leading zero octets': '3b00' '8b04' '00000001',
    '#1234 ILNP nonce of zero octets': '3b00' '8b00' '00000000',
    '#1235 MPL rsv bits': '3b00' '6d04' '4f05abcd',
    '#1235 IP_DFF reserved bits': '3b00' 'ee03' '4f1234' '00',
    '#1235 Quick-Start request R bits': '3b01' '2606' '004012345679' '010400000000',
    '#1235 Quick-Start report R bits': '3b01' '2606' '800012345679' '010400000000',
    '#1237 Quick-Start function 5': '3b01' '2606' '534012345678' '010400000000',
}


class TestIPv6OptionsRoundTrip(unittest.TestCase):
    """Pin the byte-exact rebuild of HOPOPT and IPv6-Opts option areas."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _protocols(self) -> 'list[type]':
        return [getattr(importlib.import_module(mod), name) for mod, name in PROTOCOLS]

    def _parse(self, cls: 'type', octets: 'bytes') -> 'object':
        return cls(io.BytesIO(octets), len(octets), extension=True)

    def test_parsed_headers_rebuild_byte_for_byte(self) -> None:
        for cls in self._protocols():
            for label, hexstr in HEADERS.items():
                octets = bytes.fromhex(hexstr)
                with self.subTest(protocol=cls.__name__, header=label):
                    parsed = self._parse(cls, octets)
                    self.assertEqual(cls.from_data(parsed.info).data, octets)

    def test_reserved_bits_are_kept_in_info(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__):
                mpl = self._parse(cls, bytes.fromhex(HEADERS['#1235 MPL rsv bits']))
                self.assertEqual(mpl.info.options[Option.MPL_Option].flags.reserved, 0xf)
                dff = self._parse(cls, bytes.fromhex(HEADERS['#1235 IP_DFF reserved bits']))
                self.assertEqual(dff.info.options[Option.IP_DFF].flags.reserved, 0xf)
                for key in ('#1235 Quick-Start request R bits', '#1235 Quick-Start report R bits'):
                    qs = self._parse(cls, bytes.fromhex(HEADERS[key]))
                    self.assertEqual(qs.info.options[Option.Quick_Start].reserved, 1)

    def test_unassigned_quick_start_function_is_kept_as_raw_data(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.data.internet.hopopt import \
            UnassignedOption as Data_HOPOPT_UnassignedOption
        from pcapkit.protocols.data.internet.ipv6_opts import \
            UnassignedOption as Data_IPv6_Opts_UnassignedOption

        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__):
                parsed = self._parse(cls, bytes.fromhex(HEADERS['#1237 Quick-Start function 5']))
                opt = parsed.info.options[Option.Quick_Start]
                self.assertIsInstance(opt, (Data_HOPOPT_UnassignedOption,
                                            Data_IPv6_Opts_UnassignedOption))
                self.assertEqual(opt.data, bytes.fromhex('534012345678'))

    def test_zero_length_smf_dpd_is_rejected_in_both_modes(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        for cls in self._protocols():
            # the octet after ``Opt Data Len`` 0 is the next option's type, so its
            # top bit must not be taken as the H-DPD (``80``) or I-DPD mode bit
            for mode, hexstr in (('H-DPD', '3b00080080000000'), ('I-DPD', '3b00080000000000')):
                with self.subTest(protocol=cls.__name__, mode=mode):
                    with self.assertRaisesRegex(FieldValueError, 'invalid SMF DPD option length: 0'):
                        self._parse(cls, bytes.fromhex(hexstr))

    def test_ip_dff_data_length_is_three(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.utilities.exceptions import ProtocolError

        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__):
                # RFC 6971 Errata ID 3937: the flags octet and the sequence number
                made = cls(next=59, options=[(Option.IP_DFF, {'version': 1, 'dup': True, 'seq': 0x1234})])
                self.assertEqual(made.data, bytes.fromhex('3b00' 'ee03' '601234' '00'))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaises(ProtocolError):
                        self._parse(cls, bytes.fromhex('3b00' 'ee02' '4f1234' '00'))

    def test_calipso_make_counts_compartment_length_in_words(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__):
                made = cls(next=59, options=[(Option.CALIPSO, {
                    'domain': 1, 'level': 5, 'checksum': b'\xab\xcd', 'bitmap': b'\x01' * 8,
                })])
                self.assertEqual(made.data, bytes.fromhex(
                    '3b02' '0710' '00000001' '0205' 'abcd' + '01' * 8 + '01020000'))

    def test_fresh_make_still_pads_on_its_own(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__):
                self.assertEqual(cls(next=59).data, bytes.fromhex('3b00' '0104' '00000000'))
                # padding options in a list are fresh input, and are replaced
                made = cls(next=59, options=[
                    (Option.Tunnel_Encapsulation_Limit, {'limit': 5}),
                    (Option.PadN, {'length': 0}),
                ])
                self.assertEqual(made.data, bytes.fromhex('3b00' '040105' '010100'))

    def test_ipv6_packet_with_padn_of_length_zero_rebuilds(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        icmp = bytes.fromhex('8f00' '1234' '00000001' '04000000' 'ff020000000000000000000000000016')
        payload = bytes.fromhex('3a00' '05020000' '0100') + icmp
        header = (bytes.fromhex('60000000') + len(payload).to_bytes(2, 'big') + bytes([0, 1])
                  + bytes.fromhex('fe800000000000000000000000000001')
                  + bytes.fromhex('ff020000000000000000000000000016'))
        packet = header + payload

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv6(io.BytesIO(packet), len(packet))
            self.assertEqual(IPv6.from_data(parsed.info).data, packet)


if __name__ == '__main__':
    unittest.main()
