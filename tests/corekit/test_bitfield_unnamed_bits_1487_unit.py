# -*- coding: utf-8 -*-
"""A BitField packs back the bits its namespace does not name.

GitHub issue #1487: :class:`~pcapkit.corekit.fields.strings.BitField` read only
its named subfields and packed from all zeros, so octets with a bit outside
every subfield set came back with it cleared. The unpacked value now carries
those bits under ``__unnamed__`` when any is set, and a value without the key
packs them as zeros, as before.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import unittest

from tests._support import reimport_once_per_class

#: ``a`` is bit 0 and ``c`` bits 8-11; bits 1-7 and 12-15 are unnamed.
NAMESPACE = {'a': (0, 1), 'c': (8, 4)}


class BitFieldUnnamedBitsTests(unittest.TestCase):
    """GitHub issue #1487."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.corekit.fields.strings import BitField

        self.field = BitField(length=2, namespace=NAMESPACE)({})

    def _round_trip(self, raw: bytes) -> bytes:
        return self.field.pack(self.field.unpack(raw, {}), {})

    def test_unnamed_bits_survive_unpack_then_pack(self) -> None:
        for raw in (b'\xff\xff', b'\x01\x00', b'\x7f\x0f', b'\x00\x01', b'\x80\xf0', b'\x00\x00'):
            with self.subTest(raw=raw.hex()):
                self.assertEqual(self._round_trip(raw), raw)

    def test_unpacked_value_names_the_unnamed_bits(self) -> None:
        self.assertEqual(self.field.unpack(b'\xff\xff', {}),
                         {'a': 1, 'c': 15, '__unnamed__': 0x7f0f})

    def test_key_is_absent_when_the_unnamed_bits_are_zero(self) -> None:
        self.assertEqual(self.field.unpack(b'\x80\xf0', {}), {'a': 1, 'c': 15})

    def test_a_value_without_the_key_packs_unnamed_bits_as_zero(self) -> None:
        self.assertEqual(self.field.pack({'a': 1, 'c': 15}, {}), b'\x80\xf0')
        self.assertEqual(self.field.pack({'a': 0, 'c': 0}, {}), b'\x00\x00')

    def test_named_subfields_win_over_the_record(self) -> None:
        """A named bit set in ``__unnamed__`` does not override its subfield."""
        self.assertEqual(self.field.pack({'a': 0, 'c': 0, '__unnamed__': 0xffff}, {}), b'\x7f\x0f')

    def test_edited_subfield_keeps_the_captured_unnamed_bits(self) -> None:
        value = self.field.unpack(b'\xff\xff', {})
        value['c'] = 0
        self.assertEqual(self.field.pack(value, {}), b'\xff\x0f')

    def test_a_non_int_record_is_rejected(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        for bad in ('1', 1.0, True, None):
            with self.subTest(bad=bad), self.assertRaises(FieldValueError):
                self.field.pack({'a': 0, 'c': 0, '__unnamed__': bad}, {})

    def test_schema_to_dict_from_dict_keeps_the_unnamed_bits(self) -> None:
        from pcapkit.corekit.fields.strings import BitField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class Flags(Schema):
            flags: dict = BitField(length=2, namespace=NAMESPACE)

        raw = b'\x7f\x0f'
        parsed = Flags.unpack(raw, len(raw), None)
        self.assertEqual(parsed.pack(), raw)
        self.assertEqual(Flags.from_dict(parsed.to_dict()).pack(), raw)

    def test_full_namespace_never_gains_the_key(self) -> None:
        from pcapkit.corekit.fields.strings import BitField

        field = BitField(length=1, namespace={'hi': (0, 4), 'lo': (4, 4)})({})
        self.assertEqual(field.unpack(b'\xff', {}), {'hi': 15, 'lo': 15})


if __name__ == '__main__':
    unittest.main()
