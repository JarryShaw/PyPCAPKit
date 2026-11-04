# -*- coding: utf-8 -*-
"""A list of schema items its length runs past the data reads no item past the data.

GitHub issue #2756: an IGMPv3 Report behind IPv4, cut inside its records, parsed a record
the capture never held. A :class:`~pcapkit.corekit.fields.collections.ListField` of schema
items the data ends inside zero-fills its octets to its length (#2686), so the item the
data ends inside reads its missing octets as zeros, as any field does; but its items were
read on to that length, so every item past the data was made of the zeros alone. The list
ends with the data instead.

The sweep reads two minimal items of every list of schema items under
:mod:`pcapkit.protocols`, found and built as :file:`tests/protocols/test_list_item_cut_2749_unit.py`
finds and builds them, behind a header field that sizes both, at every cut. Each cut is
refused with an in-library error, or holds the items its octets begin, no more, and packs
back to the octets read. Behind the zero-fill, the octets read are those present, the zeros
the items leave unread taken back.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`, and builds its own octets.

"""
from __future__ import annotations

import unittest
from unittest import mock

from tests._support import reimport_once_per_class
from tests.protocols.test_list_item_cut_2749_unit import LISTS, NEGATIVE, REFUSED, holders, item_lists, read

#: Test tier (#1958): a sweep over every list of schema items.
__tier__ = 'LATEST'

#: Item schemas two of which are not a list the sweep can read, and why.
SKIP = {
    'internet.mh:CGAParameter': 'a CGA Parameters option carries one CGA Parameters structure (RFC 4866), '
                                'whose extensions run to the end of the option',
}


class NoItemPastTheDataTests(unittest.TestCase):
    """A list its length runs past the data ends with the data."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_cut_list_holds_the_items_it_begins(self) -> None:
        from tests.corekit.test_schema_roundtrip_unit import build, label_of

        read_any = set()
        for _, item in item_lists():
            name = label_of(item.schema)
            if name in SKIP:
                continue
            _, raw, ctx = build(item.schema)
            _, sized = holders(item)
            whole = raw * 2
            for keep in range(len(whole)):
                data = len(whole).to_bytes(2, 'big') + whole[:keep]
                with self.subTest(item=name, captured=keep):
                    parsed, caught = read(sized, data, 2 + len(whole), ctx)
                    if parsed is None:
                        continue
                    read_any.add(name)
                    self.assertEqual(len(parsed.items), -(-keep // len(raw)))
                    self.assertEqual([text for text in caught if NEGATIVE in text], [])
                    self.assertEqual(parsed.pack(dict(ctx)), data)
        self.assertEqual(read_any, set(LISTS.values()) - set(REFUSED) - set(SKIP))

    def test_a_whole_list_is_the_control(self) -> None:
        from tests.corekit.test_schema_roundtrip_unit import build, label_of

        for _, item in item_lists():
            if label_of(item.schema) in SKIP:
                continue
            _, raw, ctx = build(item.schema)
            _, sized = holders(item)
            data = (2 * len(raw)).to_bytes(2, 'big') + raw * 2
            with self.subTest(item=label_of(item.schema)):
                parsed, caught = read(sized, data, len(data), ctx)
                self.assertEqual(caught, [])
                self.assertIsNone(parsed.__dict__.get('__short_read__'))
                self.assertEqual((len(parsed.items), parsed.pack(dict(ctx))), (2, data))

    def test_the_octets_read_are_those_present(self) -> None:
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.field import _zero_pad_budget
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt16Field, UInt32Field
        from pcapkit.protocols.schema import Schema, schema_final
        from pcapkit.utilities import config

        @schema_final
        class Pair(Schema):
            id = UInt16Field()
            value = UInt32Field()

        field = ListField(length=18, item_type=SchemaField(length=6, schema=Pair))
        pairs = bytes(range(1, 19))
        for keep in range(len(pairs)):
            with self.subTest(captured=keep), mock.patch.object(config, 'ZERO_PAD_BUDGET_RATIO', -1), \
                    _zero_pad_budget() as ledger:
                parsed = field.unpack(pairs[:keep], {})
                self.assertEqual(len(parsed), -(-keep // 6))
                self.assertEqual(ledger, [keep, len(pairs) - keep])


if __name__ == '__main__':
    unittest.main()
