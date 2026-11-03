# -*- coding: utf-8 -*-
"""GitHub issue #2711: a cut a list short of its count, or a declared payload, records.

:class:`~pcapkit.corekit.fields.collections.ListField` takes a ``count``, and a list
whose octets hold fewer items than it counts reports the rest as its ``shortfall``,
which :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>` records
as a short read. A payload field of a declared length the data ends inside records
one too. Either way the fields after it find the ``(name, octets read)`` pair in
their packet as ``__short_read__``, as :issue:`2727` gives them any other field's.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked cases of one field type.
__tier__ = 'ALL'


class ShortReadSeenAfterTests(unittest.TestCase):
    """A list short of its count, or a cut declared payload, is recorded and seen after it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import PayloadField, SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        seen = self.seen = []  # type: list

        def look(pkt):  # type: ignore[no-untyped-def]
            seen.append(pkt.get('__short_read__'))
            return 0

        @schema_final
        class Item(Schema):
            value = UInt16Field()

        @schema_final
        class Counted(Schema):
            count = UInt8Field()
            items = ListField(length=lambda pkt: pkt['__length__'], item_type=SchemaField(schema=Item),
                              count=lambda pkt: pkt['count'])
            tail = BytesField(length=look)

        @schema_final
        class Sized(Schema):
            size = UInt8Field()
            payload = PayloadField(length=lambda pkt: pkt['size'])
            tail = BytesField(length=look)

        self.Counted, self.Sized = Counted, Sized

    def test_a_list_short_of_its_count_is_seen_after_it(self) -> None:
        for count, data, record in ((3, b'\x00\x01', ('items', 2)), (2, b'', ('items', 0)),
                                    (1, b'\x00\x01', None), (1, b'\x00\x01\x00\x02', None)):
            with self.subTest(count=count, data=data):
                del self.seen[:]
                raw = bytes([count]) + data
                parsed = self.Counted.unpack(raw, len(raw), {})
                self.assertEqual(parsed.__dict__.get('__short_read__'), record)
                self.assertEqual(self.seen, [record])
                self.assertEqual(len(parsed.items), len(data) // 2)
                self.assertEqual(parsed.pack(), raw)

    def test_a_cut_declared_payload_is_seen_after_it(self) -> None:
        for size, data, record in ((5, b'ab', ('payload', 2)), (2, b'ab', None)):
            with self.subTest(size=size, data=data):
                del self.seen[:]
                raw = bytes([size]) + data
                with warnings.catch_warnings():
                    # the payload's declared length runs past the data
                    warnings.simplefilter('ignore')
                    parsed = self.Sized.unpack(raw, len(raw), {})
                self.assertEqual(parsed.__dict__.get('__short_read__'), record)
                self.assertEqual(self.seen, [record])
                self.assertEqual(parsed.payload, data)


if __name__ == '__main__':
    unittest.main()
