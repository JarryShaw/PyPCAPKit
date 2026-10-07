# -*- coding: utf-8 -*-
"""IPv4 headers rebuild byte for byte, and ``make()`` keeps every option.

Pins the fixes for GitHub issues #1316 to #1322 and #1326, found by the
internet-v4 round-trip audit (#1202):

* #1316 -- ``make()`` padded with an EOOL after every unaligned option, so the
  reader stopped there and the later options were lost;
* #1317 -- ``from_data`` dropped the parsed NOP/EOOL layout and the octets after
  the EOOL, and re-padded per option. The octets after the EOOL are now the
  ``padding`` data field, written back verbatim; the header length follows
  from the options and those octets, so edited options recompute it;
* #1318 -- an option with an unassigned code could be neither rebuilt nor built;
* #1319 -- LSR, SSR and RR zeroed the route slots at and beyond the pointer;
* #1320 -- TS dropped the high-order "non-standard" bit of a timestamp;
* #1321 -- the SEC field termination indicator was the inverse of
  :rfc:`1108` section 2.4(a), where the low-order bit is ``0`` on the final
  octet and ``1`` when more follow;
* #1322 -- an unassigned Quick-Start function failed the whole header;
* #1326 -- the reserved flag bit and the Quick-Start reserved bits and unused
  octet were written back as zero.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest
import warnings

from tests._support import reimport_once_per_class


def header(options: 'str' = '', flags: 'str' = '0000') -> 'bytes':
    """An IPv4 header from 10.0.0.1 to 10.0.0.2, protocol 253, with ``options`` in hex."""
    opts = bytes.fromhex(options)
    ihl = 5 + len(opts) // 4
    return (bytes([0x40 | ihl, 0]) + (ihl * 4).to_bytes(2, 'big') + bytes(2)
            + bytes.fromhex(flags) + bytes.fromhex('40fd0000')
            + bytes([10, 0, 0, 1, 10, 0, 0, 2]) + opts)


#: Wire headers that must rebuild through ``from_data`` unchanged, by issue.
HEADERS = {
    '1317 NOP then RR': header('0107070400000000'),
    '1317 RR, RTRALT, EOOL and padding': header('070704000000009404000000'),
    '1317 NOPs, RTRALT, EOOL and padding': header('010101940400000000000000'),
    '1317 NOP x4': header('01010101'),
    '1317 EOOL x4': header('00000000'),
    '1317 EOOL, non-zero octets': header('00ff0102'),
    '1317 EOOL, RR-like octets': header('00070304'),
    '1317 RTRALT, EOOL, non-zero octets': header('9404000000abcdef'),
    '1318 unassigned option': header('9e04abcd'),
    '1318 unassigned option, no data': header('9e020000'),
    '1319 LSR, both slots past the pointer': header('830b040a0000010a00000200'),
    '1319 SSR, one slot past the pointer': header('890b080a0000010a00000200'),
    '1319 RR, one slot past the pointer': header('070b080a0000010a00000200'),
    '1320 TS, non-standard timestamp': header('4408090080000001'),
    '1321 SEC, one authority octet': header('8204ab90'),
    '1321 SEC, two authority octets': header('8205ab9100' '000000'),
    '1322 QS, unassigned function 3': header('1908310500000000'),
    '1322 QS, unassigned function 15': header('1908f00000000000'),
    '1326 reserved flag bit': header(flags='8000'),
    '1326 QS request, reserved bits': header('1908030500000003'),
    '1326 QS report, unused octet': header('1908810500000000'),
    '1326 QS report, reserved bits': header('1908810000000002'),
}


class TestIPv4RoundTrip(unittest.TestCase):
    """Pin the IPv4 round trip and the ``make()`` option layout."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, data: 'bytes') -> 'object':
        from pcapkit.protocols.internet.ipv4 import IPv4

        return IPv4(io.BytesIO(data), len(data))

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.warnings import ProtocolWarning

        for name, data in HEADERS.items():
            with self.subTest(case=name):
                with warnings.catch_warnings():
                    warnings.simplefilter('error', ProtocolWarning)
                    parsed = self.parse(data)
                self.assertEqual(IPv4.from_data(parsed.info).data, data)

    def test_make_pads_once_after_the_last_option(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        cases = {
            'RR twice': ([(OptionNumber.RR, {'counts': 1}), (OptionNumber.RR, {'counts': 1})],
                         '0707040000000007070400000000' '0100',
                         [OptionNumber.RR, OptionNumber.RR, OptionNumber.NOP, OptionNumber.EOOL]),
            'RR then RTRALT': ([(OptionNumber.RR, {'counts': 1}), (OptionNumber.RTRALT, {})],
                               '07070400000000' '94040001' '00',
                               [OptionNumber.RR, OptionNumber.RTRALT, OptionNumber.EOOL]),
        }
        for name, (options, wire, codes) in cases.items():
            with self.subTest(case=name):
                data = IPv4(options=options, protocol=253).data
                self.assertEqual(data[20:].hex(), wire)
                parsed = self.parse(data)
                self.assertEqual([code for code, _ in parsed.info.options.items(multi=True)], codes)

    def test_make_builds_an_unassigned_option(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        data = IPv4(options=[(0x9e, {'data': b'\xab\xcd'})], protocol=253).data
        self.assertEqual(data[20:].hex(), '9e04abcd')
        self.assertEqual(self.parse(data).info.options[0x9e].data, b'\xab\xcd')

    def test_make_builds_an_unassigned_quick_start_function(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.data.internet.ipv4 import UnassignedOption
        from pcapkit.protocols.internet.ipv4 import IPv4

        data = IPv4(options=[(OptionNumber.QS, {'func': 15, 'ttl': 1, 'nonce': 2})],
                    protocol=253).data
        self.assertEqual(data[20:].hex(), '1908f00100000008')
        option = self.parse(data).info.options[OptionNumber.QS]
        self.assertIsInstance(option, UnassignedOption)
        self.assertEqual(option.data, bytes.fromhex('f00100000008'))

    def test_route_slots_past_the_pointer_are_data(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        option = self.parse(HEADERS['1319 SSR, one slot past the pointer']).info.options[OptionNumber.SSR]
        self.assertEqual([str(ip) for ip in option.route], ['10.0.0.1'])
        self.assertEqual([str(ip) for ip in option.remaining], ['10.0.0.2'])

        # A fresh option writes the pending hops after the recorded ones, and
        # zero-fills the slots left over up to ``counts``.
        data = IPv4(options=[(OptionNumber.LSR, {'counts': 3, 'route': ['10.0.0.1'],
                                                 'remaining': ['10.0.0.2']})],
                    protocol=253).data
        self.assertEqual(data[20:].hex(), '830f08' '0a000001' '0a000002' '00000000' '00')

    def test_sec_termination_indicator_follows_rfc_1108(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings():
            warnings.simplefilter('error', ProtocolWarning)
            option = self.parse(header('8204ab90')).info.options[OptionNumber.SEC]
        self.assertEqual(option.flags, (ProtectionAuthority.GENSER, ProtectionAuthority.NSA))

        # The low-order bit set on the final octet promises another octet.
        with self.assertWarnsRegex(ProtocolWarning, 'field termination indicator not set'):
            self.parse(header('8204ab91'))

    def test_timestamp_keeps_the_high_order_bit(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber

        option = self.parse(HEADERS['1320 TS, non-standard timestamp']).info.options[OptionNumber.TS]
        self.assertEqual(option.timestamp, (0x80000001,))

    def test_reserved_bits_are_data(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        self.assertEqual(self.parse(HEADERS['1326 reserved flag bit']).info.flags.reserved, 1)
        self.assertEqual(IPv4(reserved=1, protocol=253).data[6:8].hex(), '8000')

        request = self.parse(HEADERS['1326 QS request, reserved bits']).info.options[OptionNumber.QS]
        self.assertEqual(request.reserved, 3)
        report = self.parse(HEADERS['1326 QS report, unused octet']).info.options[OptionNumber.QS]
        self.assertEqual(report.unused, 5)

    def test_octets_after_eool_are_data(self) -> None:
        for name, octets in (('1317 EOOL, non-zero octets', 'ff0102'),
                             ('1317 RTRALT, EOOL, non-zero octets', 'abcdef'),
                             ('1317 NOP x4', '')):
            with self.subTest(case=name):
                self.assertEqual(self.parse(HEADERS[name]).info.padding.hex(), octets)

    def test_edited_options_recompute_the_header_length(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        rtralt = self.parse(header('94040000')).info.options[OptionNumber.RTRALT]

        # one option added to a parsed header grows it
        parsed = self.parse(header('88040001'))
        parsed.info.options.add(OptionNumber.RTRALT, rtralt)
        data = IPv4.from_data(parsed.info).data
        self.assertEqual(data[0], 0x47)
        self.assertEqual(data[20:].hex(), '88040001' '94040000')

        # one option removed shrinks it, rather than zero-filling the old length
        parsed = self.parse(header('88040001' '94040000'))
        parsed.info.options.pop(OptionNumber.RTRALT)
        data = IPv4.from_data(parsed.info).data
        self.assertEqual(data[0], 0x46)
        self.assertEqual(data[20:].hex(), '88040001')

    def test_padding_needs_an_eool_before_it(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        # A fresh list drops its EOOL and pads once, so the octets go nowhere.
        data = IPv4(options=[(OptionNumber.RR, {'counts': 1})], padding=b'\xff', protocol=253).data
        self.assertEqual(data[20:].hex(), '07070400000000' '00')


if __name__ == '__main__':
    unittest.main()
