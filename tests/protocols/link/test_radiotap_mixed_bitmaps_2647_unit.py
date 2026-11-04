# -*- coding: utf-8 -*-
"""GitHub issue #2647: radiotap's mixed bitmaps, split into value subfields and known bits.

The MCS ``flags``, the HE ``data1`` and ``data2``, the HE-MU ``flags1`` and
``flags2`` and the U-SIG ``common`` mix value subfields with known bits. Each
decodes into its value subfields, integers, and the rest of its bits, a member of
its known-bits registry that keeps the undefined ones, so both round trips stay
byte-exact. The MCS ``flags`` holds value subfields alone, its known bits being
the MCS field's ``known``.

The subfield masks are checked against the Linux kernel's
``include/net/ieee80211_radiotap.h`` at ``e5fefa3da5bf``, Wireshark's
``packet-ieee80211-radiotap-defs.h`` at ``090e75fa5daa`` and radiotap.org's field
pages, as the radiotap.org rows the crawlers leave out.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: Each value subfield's mask, by ``(schema, field)``, in the Linux kernel and in
#: Wireshark. Linux names no macro for bit 7 of the MCS ``flags``.
LINUX = {
    ('MCS', 'flags'): {'bandwidth': 0x03, 'guard_interval': 0x04, 'ht_format': 0x08, 'fec_type': 0x10,
                       'stbc_streams': 0x60},
    ('HE', 'data1'): {'ppdu_format': 0x0003},
    ('HE', 'data2'): {'ru_offset': 0x3F00, 'pri_sec_80mhz': 0x8000},
    ('HEMU', 'flags1'): {'sig_b_mcs': 0x000F, 'sig_b_dcm': 0x0020, 'ch1_center_26_tone_ru': 0x2000},
    ('HEMU', 'flags2'): {'bandwidth': 0x0003, 'sig_b_compression': 0x0008, 'sig_b_symbols_users': 0x00F0,
                         'preamble_puncturing': 0x0300, 'ch2_center_26_tone_ru': 0x0800},
    ('USIG', 'common'): {'phy_version': 0x00007000, 'bandwidth': 0x00038000, 'ul_dl': 0x00040000,
                         'bss_color': 0x01F80000, 'txop': 0xFE000000},
}
WIRESHARK = {**LINUX, ('MCS', 'flags'): {**LINUX[('MCS', 'flags')], 'ness_bit0': 0x80}}

#: The masks radiotap.org's MCS page tabulates for ``flags``, all value subfields.
MCS_FLAGS_ROWS = (0x03, 0x04, 0x08, 0x10, 0x60, 0x80)

#: The mixed bitmaps with known bits, to their known-bits crawler module and class.
CRAWLERS = {
    ('HE', 'data1'): ('he_data1_known', 'HEData1Known'),
    ('HE', 'data2'): ('he_data2_known', 'HEData2Known'),
    ('HEMU', 'flags1'): ('he_mu_flags1_known', 'HEMUFlags1Known'),
    ('HEMU', 'flags2'): ('he_mu_flags2_known', 'HEMUFlags2Known'),
    ('USIG', 'common'): ('usig_common_known', 'USIGCommonKnown'),
}


def _radiotap(present: 'list[int]', fields: bytes = b'') -> bytes:
    """Pack a radiotap header: fixed start, present-flags chain, fields."""
    return struct.pack('<BBH', 0, 0, 4 + 4 * len(present) + len(fields)) + b''.join(
        struct.pack('<I', word) for word in present) + fields


def _masks(field) -> 'dict[str, int]':  # type: ignore[no-untyped-def]
    """Each subfield of a bitmap field, as a mask."""
    return {name: ((1 << size) - 1) << start for name, (start, size) in field.subfields.items()}


class TestRadiotapMixedBitmaps(unittest.TestCase):
    """Pin the split of the mixed bitmaps, and its round trips."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, raw: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.radiotap.protocol import Radiotap

        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.data, raw)
        for data in (parsed.info, parsed.info.to_dict()):
            self.assertEqual(Radiotap.from_data(data).data, raw)
        self.assertEqual(Radiotap(present=parsed.info.present, fields=parsed.info.decoded).data, raw)
        return parsed

    def test_the_layouts_match_linux_wireshark_and_radiotap_org(self) -> None:
        import importlib

        from pcapkit.protocols.link.radiotap import schema as radiotap

        for source, table in (('linux', LINUX), ('wireshark', WIRESHARK)):
            for (schema, name), masks in table.items():
                with self.subTest(source=source, field=f'{schema}.{name}'):
                    field = getattr(radiotap, schema).__fields__[name]
                    self.assertEqual({sub: mask for sub, mask in _masks(field).items() if sub in masks}, masks)
                    self.assertEqual(set(_masks(field)) - set(masks), {'ness_bit0'} if source == 'linux'
                                     and schema == 'MCS' else set())
        self.assertEqual(sorted(_masks(radiotap.MCS.__fields__['flags']).values()), list(MCS_FLAGS_ROWS))
        for (schema, name), (module, klass) in CRAWLERS.items():
            with self.subTest(source='radiotap.org', field=f'{schema}.{name}'):
                field = getattr(radiotap, schema).__fields__[name]
                crawler = getattr(importlib.import_module(f'pcapkit.vendor.radiotap.{module}'), klass)
                registry = getattr(importlib.import_module(f'pcapkit.const.radiotap.{module}'), klass)
                self.assertEqual(sorted(_masks(field).values()), sorted(crawler.VALUES))
                self.assertIs(field.flags, registry)
                self.assertEqual(field.remainder, 'known')
                for member in registry:
                    self.assertTrue(int(member) & field.remainder_mask, member)

    def test_each_bitmap_splits_and_keeps_its_undefined_bits(self) -> None:
        """Every bit set, reserved ones included; and every bit clear."""
        from pcapkit.const.radiotap.he_data1_known import HEData1Known
        from pcapkit.const.radiotap.he_data2_known import HEData2Known
        from pcapkit.const.radiotap.he_mu_flags1_known import HEMUFlags1Known
        from pcapkit.const.radiotap.he_mu_flags2_known import HEMUFlags2Known
        from pcapkit.const.radiotap.usig_common_known import USIGCommonKnown

        for fill in (0xFF, 0x00):
            with self.subTest(fill=hex(fill)):
                # MCS, HE (after a pad octet) and HE-MU, then U-SIG as a TLV item
                fields = (bytes([0x01, fill, 0x07]) + b'\x00' + bytes([fill] * 4) + bytes(8)
                          + bytes([fill] * 4) + bytes(8))
                parsed = self._parse(_radiotap([1 << 19 | 1 << 23 | 1 << 24], fields))
                decoded = parsed.info.decoded
                ones = 1 if fill else 0
                self.assertEqual(decoded[19].flags, {'bandwidth': 3 * ones, 'guard_interval': ones, 'ht_format': ones,
                                                     'fec_type': ones, 'stbc_streams': 3 * ones, 'ness_bit0': ones})
                self.assertEqual(decoded[23].data1, {'ppdu_format': 3 * ones, 'known': 0xFFFC * ones})
                self.assertEqual(decoded[23].data2, {'ru_offset': 0x3F * ones, 'pri_sec_80mhz': ones,
                                                     'known': 0x40FF * ones})
                self.assertEqual(decoded[24].flags1, {'sig_b_mcs': 0xF * ones, 'sig_b_dcm': ones,
                                                      'ch1_center_26_tone_ru': ones, 'known': 0xDFD0 * ones})
                self.assertEqual(decoded[24].flags2, {'bandwidth': 3 * ones, 'sig_b_compression': ones,
                                                      'sig_b_symbols_users': 0xF * ones, 'preamble_puncturing': 3 * ones,
                                                      'ch2_center_26_tone_ru': ones, 'known': 0xF404 * ones})
                for value, registry in ((decoded[23].data1['known'], HEData1Known),
                                        (decoded[23].data2['known'], HEData2Known),
                                        (decoded[24].flags1['known'], HEMUFlags1Known),
                                        (decoded[24].flags2['known'], HEMUFlags2Known)):
                    self.assertIsInstance(value, registry)

                tlv = struct.pack('<HH', 33, 12) + bytes([fill] * 4) + struct.pack('<II', 0x22, 0x33)
                parsed = self._parse(_radiotap([1 << 28], tlv))
                common = parsed.info.decoded[28].tlvs[0].data.common
                self.assertEqual(common, {'phy_version': 7 * ones, 'bandwidth': 7 * ones, 'ul_dl': ones,
                                          'bss_color': 0x3F * ones, 'txop': 0x7F * ones, 'known': 0xFFF * ones})
                self.assertIsInstance(common['known'], USIGCommonKnown)

    def test_reserved_bits_stay_in_the_known_bits(self) -> None:
        from pcapkit.const.radiotap.he_mu_flags1_known import HEMUFlags1Known

        parsed = self._parse(_radiotap([1 << 24], struct.pack('<HH', 0x0C10, 0xF000) + bytes(8)))
        known = parsed.info.decoded[24].flags1['known']
        self.assertEqual(int(known), 0x0C10)
        self.assertIn(HEMUFlags1Known.HE_MU_FLAGS1_SIG_B_MCS_KNOWN, known)
        self.assertEqual(int(parsed.info.decoded[24].flags2['known']), 0xF000)

    def test_make_takes_members_or_ints(self) -> None:
        from pcapkit.const.radiotap.he_data1_known import HEData1Known
        from pcapkit.protocols.link.radiotap.protocol import Radiotap

        expected = _radiotap([1 << 23], struct.pack('<6H', 0x0006, 0, 0, 0, 0, 0))
        rest = {'data2': {'ru_offset': 0, 'pri_sec_80mhz': 0, 'known': 0},
                'data3': 0, 'data4': 0, 'data5': 0, 'data6': 0}
        for known in (HEData1Known.HE_DATA1_BSS_COLOR_KNOWN, HEData1Known.get(0x0004), 0x0004):
            with self.subTest(known=known):
                made = Radiotap(present=(1 << 23,), fields=[(23, {'data1': {'ppdu_format': 2, 'known': known},
                                                                  **rest})])
                self.assertEqual(made.data, expected)

    def test_make_refuses_what_a_bitmap_cannot_hold(self) -> None:
        from pcapkit.protocols.link.radiotap.protocol import Radiotap
        from pcapkit.utilities.exceptions import ProtocolError

        flags = {'bandwidth': 0, 'guard_interval': 0, 'ht_format': 0, 'fec_type': 0, 'stbc_streams': 0, 'ness_bit0': 0}
        cases = {
            'an int for the bitmap': {**flags, 'flags': 0x25},
            'a missing subfield': {'flags': {key: value for key, value in flags.items() if key != 'ness_bit0'}},
            'a subfield past its bits': {'flags': {**flags, 'stbc_streams': 4}},
            'a bool': {'flags': {**flags, 'bandwidth': True}},
            'a negative': {'flags': {**flags, 'bandwidth': -1}},
        }
        for name, entry in cases.items():
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                Radiotap(present=(1 << 19,), fields=[(19, {'known': 0, 'mcs': 0, **entry})])
        common = {'phy_version': 0, 'bandwidth': 0, 'ul_dl': 0, 'bss_color': 0, 'txop': 0}
        for name, known in (('known bits of a value', 0x1000), ('known bits past the word', 1 << 32),
                            ('a missing known', None)):
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                value = {**common} if known is None else {**common, 'known': known}
                Radiotap(present=(1 << 28,), fields=[(28, {'tlvs': [
                    {'type': 33, 'data': {'common': value, 'value': 0, 'mask': 0}}]})])


if __name__ == '__main__':
    unittest.main()
