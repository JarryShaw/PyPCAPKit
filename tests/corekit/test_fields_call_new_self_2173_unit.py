# -*- coding: utf-8 -*-
"""``ListField`` and ``SchemaField`` calls work on the copy, not the template.

GitHub issue #2173. Calling a field with a packet returns a fresh copy, which is
what the schema then reads with. :meth:`ListField.__call__
<pcapkit.corekit.fields.collections.ListField.__call__>` handed its ``callback``
the template instead of that copy, so a callback adjusting its field mutated the
template shared by every later packet and missed the copy actually in use.
:meth:`SchemaField.__call__ <pcapkit.corekit.fields.misc.SchemaField.__call__>`
sized the copy's ``template`` from the template's ``-1`` length rather than the
copy's resolved one, so it stayed ``'1024s'``. Both read the copy.
"""

import unittest
from typing import TYPE_CHECKING

from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import SchemaField
from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
from pcapkit.protocols.schema.schema import Schema

if TYPE_CHECKING:
    from typing import Any


class Pair(Schema):
    """Four-octet schema for :class:`SchemaField`."""

    a: 'int' = UInt16Field()
    b: 'int' = UInt16Field()


def tag_field(field: 'Any', packet: 'dict[str, Any]') -> 'None':
    """Callback that adjusts the field it is given, as a byte-order one would."""
    field.tag = packet['n']


class ListFieldCallbackTests(unittest.TestCase):
    """``ListField.__call__`` passes its callback the copy."""

    def test_callback_receives_the_copy(self) -> None:
        seen = []  # type: list[ListField]
        template = ListField(length=lambda pkt: pkt['n'], item_type=UInt8Field(),
                             callback=lambda field, _: seen.append(field))
        copy = template({'n': 2})
        self.assertEqual(len(seen), 1)
        self.assertIs(seen[0], copy)
        self.assertIsNot(seen[0], template)

    def test_template_is_untouched_across_calls(self) -> None:
        template = ListField(length=lambda pkt: pkt['n'], item_type=UInt8Field(), callback=tag_field)
        first = template({'n': 2})
        second = template({'n': 3})
        self.assertFalse(hasattr(template, 'tag'))
        self.assertEqual((first.tag, second.tag), (2, 3))  # type: ignore[attr-defined]
        self.assertEqual((first.length, second.length), (2, 3))


class SchemaFieldTemplateTests(unittest.TestCase):
    """``SchemaField.__call__`` sizes the copy's template from the copy's length."""

    def test_callable_length_sizes_the_template(self) -> None:
        template = SchemaField(length=lambda pkt: pkt['n'], schema=Pair)
        copy = template({'n': 24})
        self.assertEqual(copy.length, 24)
        self.assertEqual(copy.template, '24s')
        self.assertEqual(template.template, '1024s')

    def test_negative_resolved_length_keeps_the_default(self) -> None:
        copy = SchemaField(length=lambda pkt: pkt['n'], schema=Pair)({'n': -1})
        self.assertEqual(copy.template, '1024s')


if __name__ == '__main__':
    unittest.main()
