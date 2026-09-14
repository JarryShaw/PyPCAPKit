from __future__ import annotations

import unittest

from tests._support import purge_modules


class BitFieldTests(unittest.TestCase):
    """Packing and parsing of :class:`~pcapkit.corekit.fields.strings.BitField`."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields.strings import BitField

        self.BitField = BitField
        #: One octet of single-bit flags, as the protocol schemas declare them.
        self.flags = BitField(length=1, namespace={
            'a': (0, 1),
            'b': (1, 1),
            'c': (6, 1),
            'd': (7, 1),
        })

    def test_cleared_bits_stay_cleared_when_a_sibling_is_set(self) -> None:
        """A zero bit must not be packed as a one.

        The buffer holds one ASCII digit per bit, and ``b'0'`` is itself a
        non-zero byte, so a truthiness test over it reported every named bit as
        set regardless of its value.

        """
        self.assertEqual(self.flags.pre_process({'a': 0, 'b': 0, 'c': 0, 'd': 1}, {}), b'\x01')
        self.assertEqual(self.flags.pre_process({'a': 1, 'b': 0, 'c': 0, 'd': 0}, {}), b'\x80')
        self.assertEqual(self.flags.pre_process({'a': 0, 'b': 1, 'c': 1, 'd': 0}, {}), b'\x42')

    def test_no_bits_set_packs_to_zero(self) -> None:
        self.assertEqual(self.flags.pre_process({'a': 0, 'b': 0, 'c': 0, 'd': 0}, {}), b'\x00')

    def test_every_bit_set_packs_to_its_mask(self) -> None:
        self.assertEqual(self.flags.pre_process({'a': 1, 'b': 1, 'c': 1, 'd': 1}, {}), b'\xc3')

    def test_multi_bit_subfields_keep_their_own_width(self) -> None:
        field = self.BitField(length=1, namespace={'kind': (0, 3), 'value': (3, 5)})

        self.assertEqual(field.pre_process({'kind': 5, 'value': 17}, {}), b'\xb1')
        self.assertEqual(field.pre_process({'kind': 0, 'value': 1}, {}), b'\x01')

    def test_unnamed_bits_are_left_alone(self) -> None:
        """Bits outside the namespace belong to nobody and must pack as zero."""
        field = self.BitField(length=2, namespace={'flag': (3, 1)})

        self.assertEqual(field.pre_process({'flag': 1}, {}), b'\x10\x00')
        self.assertEqual(field.pre_process({'flag': 0}, {}), b'\x00\x00')

    def test_pack_and_parse_round_trip(self) -> None:
        for value in ({'a': 0, 'b': 0, 'c': 0, 'd': 0},
                      {'a': 0, 'b': 0, 'c': 0, 'd': 1},
                      {'a': 1, 'b': 0, 'c': 1, 'd': 0},
                      {'a': 1, 'b': 1, 'c': 1, 'd': 1}):
            with self.subTest(value=value):
                packed = self.flags.pre_process(value, {})
                self.assertEqual(self.flags.post_process(packed, {}), value)


if __name__ == '__main__':
    unittest.main()
