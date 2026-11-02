# -*- coding: utf-8 -*-
"""GitHub issue #2647: :class:`~pcapkit.corekit.fields.numbers.BitmapField`.

A word split into subfields numbered from its least-significant bit, read in its
byte order first, so a subfield may cross an octet boundary of a little-endian
word. The bits no subfield names are kept in place, under a remainder, as a
member of a flag enumeration where one is given, or under ``__unnamed__``.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import enum
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked cases of one field type.
__tier__ = 'ALL'


class Known(enum.IntFlag):
    """Stand-in known bits, of which bit 3 is left undefined."""

    A = 0x0004
    B = 0x0010


class TestBitmapField(unittest.TestCase):
    """Pin the split, the remainder and the refusals."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _schema(self, **kwargs):  # type: ignore[no-untyped-def]
        from pcapkit.corekit.fields.numbers import BitmapField, UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class Word(Schema):
            word = BitmapField(**kwargs)
            tail = UInt8Field()

        return Word

    def test_a_little_endian_word_splits_across_its_octets(self) -> None:
        word = self._schema(length=4, byteorder='little', namespace={'low': (0, 3), 'mid': (12, 3),
                                                                        'cross': (19, 6), 'top': (25, 7)})
        raw = bytes.fromhex('0170f8ff') + b'\x2a'
        parsed = word.unpack(raw, len(raw), None)
        self.assertEqual(parsed.word, {'low': 1, 'mid': 7, 'cross': 0x3F, 'top': 0x7F})
        self.assertEqual(parsed.tail, 0x2A)
        self.assertEqual(parsed.pack(), raw)
        self.assertEqual(word.from_dict(parsed.to_dict()).pack(), raw)
        # the bits under ``cross`` straddle the third and fourth octets
        self.assertEqual(word(word={'low': 0, 'mid': 0, 'cross': 1, 'top': 0}, tail=0).pack(),
                         bytes.fromhex('00000800') + b'\x00')

    def test_the_byte_order_is_the_word_s(self) -> None:
        word = self._schema(length=2, byteorder='big', namespace={'low': (0, 4)})
        parsed = word.unpack(bytes.fromhex('a5c3') + b'\x00', 3, None)
        self.assertEqual(parsed.word, {'low': 3, '__unnamed__': 0xA5C0})
        self.assertEqual(parsed.pack(), bytes.fromhex('a5c300'))

    def test_the_remainder_is_a_flag_member_with_undefined_bits_kept(self) -> None:
        word = self._schema(length=1, namespace={'format': (0, 2)}, remainder='known', flags=Known)
        parsed = word.unpack(b'\x1e\x00', 2, None)
        self.assertEqual(parsed.word['format'], 2)
        self.assertIsInstance(parsed.word['known'], Known)
        self.assertEqual(int(parsed.word['known']), 0x1C)
        self.assertIn(Known.A, parsed.word['known'])
        self.assertEqual(parsed.pack(), b'\x1e\x00')
        # a plain int is taken for the remainder as well as a member
        self.assertEqual(word(word={'format': 2, 'known': 0x1C}, tail=0).pack(), b'\x1e\x00')

    def test_a_remainder_without_flags_is_an_int(self) -> None:
        word = self._schema(length=1, namespace={'format': (0, 2)}, remainder='known')
        parsed = word.unpack(b'\x00\x00', 2, None)
        self.assertEqual(parsed.word, {'format': 0, 'known': 0})
        self.assertIs(type(parsed.word['known']), int)

    def test_the_layout_is_checked_when_declared(self) -> None:
        from pcapkit.corekit.fields.numbers import BitmapField
        from pcapkit.utilities.exceptions import FieldValueError

        for namespace in ({'past': (6, 3)}, {'none': (0, 0)}, {'a': (0, 4), 'b': (3, 2)}):
            with self.subTest(namespace=namespace), self.assertRaises(FieldValueError):
                BitmapField(1, namespace)
        with self.assertRaises(FieldValueError):
            BitmapField(1, {'a': (0, 2)}, flags=Known)
        field = BitmapField(2, {'a': (0, 2), 'b': (8, 6)}, remainder='rest')
        self.assertEqual((field.subfields, field.remainder, field.remainder_mask, field.flags),
                         ({'a': (0, 2), 'b': (8, 6)}, 'rest', 0xC0FC, None))
        self.assertIs(BitmapField(1, {'a': (0, 2)}, remainder='known', flags=Known).flags, Known)

    def test_packing_refuses_what_the_bits_cannot_hold(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        word = self._schema(length=1, namespace={'format': (0, 2)}, remainder='known', flags=Known)
        for value in ({'format': 4, 'known': 0}, {'format': -1, 'known': 0}, {'format': True, 'known': 0},
                      {'format': 0, 'known': 0x01}, {'format': 0, 'known': 'A'}):
            with self.subTest(value=value), self.assertRaises(FieldValueError):
                word(word=value, tail=0).pack()

    def test_packing_refuses_a_missing_subfield(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        word = self._schema(length=1, namespace={'format': (0, 2), 'mode': (2, 1)},
                            remainder='known')
        for value in ({'mode': 0, 'known': 0}, {'format': 0, 'known': 0}, {}):
            with self.subTest(value=value), self.assertRaisesRegex(FieldValueError, 'missing'):
                word(word=value, tail=0).pack()


if __name__ == '__main__':
    unittest.main()
