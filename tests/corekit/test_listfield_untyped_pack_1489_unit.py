# -*- coding: utf-8 -*-
"""An untyped ``ListField`` packs back the ``bytes`` its ``unpack`` returns.

GitHub issue #1489. Without an ``item_type``, :meth:`ListField.unpack
<pcapkit.corekit.fields.collections.ListField.unpack>` returns the field's
octets as one :obj:`bytes`, but :meth:`ListField.pack
<pcapkit.corekit.fields.collections.ListField.pack>` iterated that value item
by item and rejected each :obj:`int` with ``FieldValueError``. ``pack`` now
writes such a value as-is; a typed ``ListField`` is unchanged.
"""

import unittest

from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.numbers import UInt16Field
from pcapkit.utilities.exceptions import FieldValueError


def named(field: 'ListField') -> 'ListField':
    """Name ``field`` by hand, as a schema would."""
    field.name = 'items'
    return field


class UntypedListFieldPackTests(unittest.TestCase):
    """``pack(unpack(raw))`` is byte-exact for an untyped ``ListField``."""

    def test_fixed_length_round_trip(self) -> None:
        field = named(ListField(length=4))({})
        value = field.unpack(b'abcd', {})
        self.assertEqual(value, b'abcd')
        self.assertEqual(field.pack(value, {}), b'abcd')

    def test_callable_length_round_trip(self) -> None:
        for raw in (b'', b'\x00', b'\xff\x00\x7f', bytes(range(256))):
            with self.subTest(raw=raw):
                packet = {'n': len(raw)}
                field = named(ListField(length=lambda pkt: pkt['n']))(packet)
                self.assertEqual(field.pack(field.unpack(raw, packet), packet), raw)

    def test_list_of_bytes_items_still_joined(self) -> None:
        field = named(ListField(length=4))({})
        self.assertEqual(field.pack([b'ab', b'cd'], {}), b'abcd')

    def test_list_of_ints_still_rejected(self) -> None:
        field = named(ListField(length=2))({})
        with self.assertRaisesRegex(FieldValueError, 'has invalid value'):
            field.pack([1, 2], {})


class TypedListFieldPackTests(unittest.TestCase):
    """A typed ``ListField`` still packs item by item."""

    def test_typed_round_trip(self) -> None:
        field = named(ListField(length=4, item_type=UInt16Field()))({})
        value = field.unpack(b'\x00\x01\x00\x02', {})
        self.assertEqual(value, [1, 2])
        self.assertEqual(field.pack(value, {}), b'\x00\x01\x00\x02')

    def test_typed_bytes_value_still_iterated(self) -> None:
        field = named(ListField(length=4, item_type=UInt16Field()))({})
        self.assertEqual(field.pack(b'\x01\x02', {}), b'\x00\x01\x00\x02')


if __name__ == '__main__':
    unittest.main()
