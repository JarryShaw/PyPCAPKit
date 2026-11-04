# -*- coding: utf-8 -*-
"""Every list of schema items reads an item the data ends inside as a cut, quietly.

GitHub issue #2749: an IGMPv3 Report parsed on its own and cut inside a group record
warned ``SchemaWarning: packet length < 0`` for each field of the record past the cut. Its
record list counts its records and runs to the end of the data, and each record is sized
by the octets left to it, so the record the data ends inside read its fields past them as
running past a length it had been given. A
:class:`~pcapkit.corekit.fields.collections.ListField` now reads a schema item it counts
as ending with the data, and :meth:`Schema.unpack
<pcapkit.protocols.schema.Schema.unpack>` reads its fields past that length as the cut
its short read records.

The sweep finds every list of schema items under :mod:`pcapkit.protocols` from its schema
modules, as :file:`tests/corekit/test_schema_roundtrip_unit.py` finds the schemas, and
reads a minimal item of each, built as that module builds one, in the two shapes a list
ends in: counted, running to the end of the data, as the Report's records do, and sized
by a header field behind a length that runs past the data, as the others are. Each cut
inside the item is refused with an in-library error, or reads with no ``packet length <
0`` warning, records the cut, and packs back to the octets read. Option lists read their
items through their registries and record a cut in their area themselves (#2694), so the
sweep leaves them out.

Beside it, a list sized by a header field shorter than its item, with the data whole, is
a malformed length rather than a cut, and so is an item past the items a list counts;
both still warn.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`, and builds its own octets.

"""
from __future__ import annotations

import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): a sweep over every list of schema items.
__tier__ = 'LATEST'

#: Every list of schema items the sweep finds, as ``holder.field``, and its item schema.
LISTS = {
    'application.httpv2:SettingsFrame.settings': 'application.httpv2:SettingPair',
    'internet.hip:LocatorSetParameter.locators': 'internet.hip:Locator',
    'internet.igmpv3:Report.records': 'internet.igmpv3:GroupRecord',
    'internet.mh:CGAParametersOption.parameters': 'internet.mh:CGAParameter',
    'transport.sctp:SACKChunk.gap_blocks': 'transport.sctp:GapAckBlock',
    'transport.tcp:SACK.sack': 'transport.tcp:SACKBlock',
}

#: Item schemas a counted list refuses at every cut, and why.
REFUSED = {
    'internet.mh:CGAParameter': 'its pre_unpack refuses octets short of its fixed fields and '
                                'public key, rather than read on past the option (#2684)',
}

#: The message every negative length warns with.
NEGATIVE = 'packet length < 0'


def item_lists() -> 'Iterator[tuple[str, Any]]':
    """``holder.field`` and the item field of every list of schema items under
    :mod:`pcapkit.protocols`, option lists aside."""
    from pcapkit.corekit.fields.collections import ListField, OptionField
    from pcapkit.corekit.fields.misc import SchemaField
    from tests.corekit.test_schema_roundtrip_unit import schema_classes

    for label, cls in sorted(schema_classes().items()):
        for name, field in cls.__fields__.items():
            if isinstance(field, ListField) and not isinstance(field, OptionField) \
                    and isinstance(field._item_type, SchemaField):  # pylint: disable=protected-access
                yield f'{label}.{name}', field._item_type  # pylint: disable=protected-access


def holders(item: 'Any') -> 'tuple[type, type]':
    """A list of ``item`` counted by a header field and running to the end of the data, and
    one sized by a header field with the rest of the data after it."""
    from pcapkit.corekit.fields.collections import ListField
    from pcapkit.corekit.fields.misc import PayloadField
    from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
    from pcapkit.protocols.schema import Schema, schema_final

    @schema_final
    class Counted(Schema):
        count = UInt8Field()
        items = ListField(length=lambda pkt: pkt['__length__'], item_type=item, count=lambda pkt: pkt['count'])

    @schema_final
    class Sized(Schema):
        size = UInt16Field()
        items = ListField(length=lambda pkt: pkt['size'], item_type=item)
        rest = PayloadField()

    return Counted, Sized


def read(cls: type, data: bytes, length: int, ctx: 'dict[str, Any]') -> 'tuple[Any, list[str]]':
    """``data`` unpacked as ``cls`` under ``length``, or :data:`None` if refused, and its
    schema warnings."""
    from pcapkit.utilities.exceptions import BaseError
    from pcapkit.utilities.warnings import SchemaWarning

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        try:
            parsed = cls.unpack(data, length, dict(ctx))
        except BaseError:
            parsed = None
    return parsed, [str(entry.message) for entry in caught if issubclass(entry.category, SchemaWarning)]


class ListItemCutTests(unittest.TestCase):
    """Every list of schema items reads an item the data ends inside as a quiet cut."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def items(self) -> 'Iterator[tuple[str, Any, bytes, dict[str, Any]]]':
        """Each list, its item field, a minimal item's octets, and the context it reads in."""
        from tests.corekit.test_schema_roundtrip_unit import build, label_of

        for label, item in item_lists():
            _, raw, ctx = build(item.schema)
            yield label_of(item.schema), item, raw, ctx

    def assert_cut(self, parsed: 'Any', caught: 'list[str]', data: bytes, ctx: 'dict[str, Any]') -> None:
        """A cut ``parsed`` from ``data`` warned no negative length, recorded, and packs back."""
        self.assertEqual([text for text in caught if NEGATIVE in text], [])
        self.assertTrue(parsed.__dict__.get('__short_read__') is not None
                        or any('__short_read__' in entry.__dict__ for entry in parsed.items))
        self.assertEqual(parsed.pack(dict(ctx)), data)

    def test_the_sweep_finds_every_list_of_schema_items(self) -> None:
        from tests.corekit.test_schema_roundtrip_unit import label_of

        self.assertEqual({label: label_of(item.schema) for label, item in item_lists()}, LISTS)

    def test_an_item_a_counted_list_ends_inside_reads_as_cut(self) -> None:
        read_any = set()
        for name, item, raw, ctx in self.items():
            counted, _ = holders(item)
            for keep in range(1, len(raw)):
                data = b'\x01' + raw[:keep]
                with self.subTest(item=name, captured=keep):
                    parsed, caught = read(counted, data, len(data), ctx)
                    if parsed is not None:
                        read_any.add(name)
                        self.assert_cut(parsed, caught, data, ctx)
        self.assertEqual(read_any, set(LISTS.values()) - set(REFUSED))

    def test_an_item_a_sized_list_ends_inside_reads_as_cut(self) -> None:
        # The enclosing length runs past the data, as an IP layer's does over a cut capture.
        for name, item, raw, ctx in self.items():
            _, sized = holders(item)
            for keep in range(1, len(raw)):
                data = len(raw).to_bytes(2, 'big') + raw[:keep]
                with self.subTest(item=name, captured=keep):
                    parsed, caught = read(sized, data, 2 + len(raw), ctx)
                    if parsed is not None:
                        self.assert_cut(parsed, caught, data, ctx)

    def test_a_whole_item_reads_whole(self) -> None:
        for name, item, raw, ctx in self.items():
            counted, _ = holders(item)
            data = b'\x01' + raw
            with self.subTest(item=name):
                parsed, caught = read(counted, data, len(data), ctx)
                self.assertEqual(caught, [])
                self.assertIsNone(parsed.__dict__.get('__short_read__'))
                self.assertEqual((len(parsed.items), parsed.pack(dict(ctx))), (1, data))


class MalformedLengthTests(unittest.TestCase):
    """A length the items run past with the data still there is no cut, and still warns."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
        from pcapkit.protocols.schema import Schema, schema_final

        @schema_final
        class Item(Schema):
            kind = UInt8Field()
            value = UInt16Field()

        self.Counted, self.Sized = holders(SchemaField(schema=Item))

    def test_a_list_sized_short_of_its_item_warns(self) -> None:
        data = b'\x00\x02' + b'\x01\x00\x02' + b'\xee\xee'
        parsed, caught = read(self.Sized, data, len(data), {})
        self.assertEqual(caught, [f'{NEGATIVE}: -1'])
        self.assertEqual(parsed.rest, b'\x02\xee\xee')

    def test_an_item_past_the_count_warns(self) -> None:
        # The list counts no item, so the octets after the count are no counted item cut short.
        data = b'\x00' + b'\x01\x00'
        _, caught = read(self.Counted, data, len(data), {})
        self.assertEqual(caught, [f'{NEGATIVE}: -1'])

    def test_an_item_the_count_covers_reads_as_cut(self) -> None:
        data = b'\x01' + b'\x01\x00'
        parsed, caught = read(self.Counted, data, len(data), {})
        self.assertEqual(caught, [])
        self.assertEqual(parsed.items[0].__dict__.get('__short_read__'), ('value', 1))
        self.assertEqual(parsed.pack(), data)


if __name__ == '__main__':
    unittest.main()
