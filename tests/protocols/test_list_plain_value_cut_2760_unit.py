# -*- coding: utf-8 -*-
"""A list of plain values its length runs past the data reads no item past the data.

GitHub issue #2760: an IGMPv3 group record cut inside its sources held the sources its
Number of Sources counts past the cut, as ``0.0.0.0``. #2756 ended a
:class:`~pcapkit.corekit.fields.collections.ListField` of schema items with the data, the
item the data ends inside read with its missing octets as zeros, but a list of plain values
read on past the data, each item zero-filled as a field the data ends inside is. Such a list
ends with the data too, and so does a list in the item of a list of schema items the data
ends inside, which reads the zeros that list was filled out with (#2686).

The sweep finds every list of plain values under :mod:`pcapkit.protocols` from its schema
modules, as :file:`tests/protocols/test_list_item_cut_2749_unit.py` finds the lists of schema
items, and reads three items of each behind a header field that sizes them, at every cut:
on its own, and as the one item of a list of schema items whose length runs past the data.
Each cut holds the items its octets begin and no more, the one the data ends inside read as
its captured octets with zeros after them, and packs back to the octets read, from the
schema and from its dict. The octets read are those present: the zeros of the fill the
items leave unread are taken back.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`, and builds its own octets.

"""
from __future__ import annotations

import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): a sweep over every list of plain values.
__tier__ = 'LATEST'

#: Every list of plain values the sweep finds, as ``holder.field``.
LISTS = frozenset({
    'internet.hip:ACKParameter.update_id',
    'internet.hip:AckDataParameter.ack',
    'internet.hip:DHGroupListParameter.groups',
    'internet.hip:ESPTransformParameter.suites',
    'internet.hip:HIPCipherParameter.ciphers',
    'internet.hip:HIPTransformParameter.suites',
    'internet.hip:HIPTransportModeParameter.mode',
    'internet.hip:HITSuiteListParameter.suites',
    'internet.hip:NATTraversalModeParameter.modes',
    'internet.hip:RegFailedParameter.reg_failed',
    'internet.hip:RegInfoParameter.reg_info',
    'internet.hip:RegRequestParameter.reg_request',
    'internet.hip:RegResponseParameter.reg_response',
    'internet.hip:RouteDstParameter.hit',
    'internet.hip:RouteViaParameter.hit',
    'internet.hip:TransportFormatListParameter.formats',
    'internet.hip:ViaRVSParameter.address',
    'internet.igmpv3:GroupRecord.sources',
    'internet.igmpv3:QueryExtension.sources',
    'internet.ipv4:LSROption.route',
    'internet.ipv4:RROption.route',
    'internet.ipv4:SSROption.route',
    'internet.ipv4:TSOption.ts_data',
    'internet.ipv6_route:SourceRoute.ip',
    'internet.mh:BIDReferenceSuboption.bid',
    'internet.mh:FlowSummaryOption.fid',
    'internet.mh:HomeAgentSwitchMessage.addresses',
    'internet.mh:MultiPrefixExtension.prefixes',
    'link.radiotap:EHT.data',
    'link.radiotap:EHT.user_info',
    'link.radiotap:HEMU.ru_channel1',
    'link.radiotap:HEMU.ru_channel2',
    'link.radiotap:VHT.mcs_nss',
    'transport.sctp:MissingMandatoryParameterCause.types',
    'transport.sctp:SACKChunk.dup_tsn',
    'transport.sctp:SupportedAddressTypesParameter.types',
    'transport.tcp:MPTCPRemoveAddress.addr_id',
})

#: Items each list is read with.
ITEMS = 3


def plain_lists() -> 'Iterator[tuple[str, type, Any]]':
    """``holder.field``, the holder schema and the item field of every list of plain values
    under :mod:`pcapkit.protocols`."""
    from pcapkit.corekit.fields.collections import ListField, OptionField
    from pcapkit.corekit.fields.misc import ConditionalField, SchemaField
    from tests.corekit.test_schema_roundtrip_unit import schema_classes

    for label, cls in sorted(schema_classes().items()):
        for name, field in cls.__fields__.items():
            if isinstance(field, ConditionalField):
                field = field.field
            item = getattr(field, '_item_type', None)
            if isinstance(field, ListField) and not isinstance(field, OptionField) \
                    and item is not None and not isinstance(item, SchemaField):
                yield f'{label}.{name}', cls, item


def octets(holder: type, item: 'Any') -> 'tuple[int, bytes]':
    """The width of ``item`` and the octets of :data:`ITEMS` items of it, each distinct
    where the item is a number or an address, a member of its enumeration otherwise."""
    from pcapkit.corekit.fields.numbers import EnumField
    from tests.corekit.test_schema_roundtrip_unit import minimal

    width = item({}).length
    if isinstance(item, EnumField):
        return width, item.pack(minimal(item, holder, 0, {}), {}) * ITEMS
    return width, bytes((index % 255) + 1 for index in range(width * ITEMS))


def holders(item: 'Any') -> 'tuple[type, type]':
    """A list of ``item`` sized by a header field with the rest of the data after it, and a
    list of schema items, each such a list without the rest, sized by a header field too."""
    from pcapkit.corekit.fields.collections import ListField
    from pcapkit.corekit.fields.misc import PayloadField, SchemaField
    from pcapkit.corekit.fields.numbers import UInt16Field
    from pcapkit.protocols.schema import Schema, schema_final

    @schema_final
    class Sized(Schema):
        size = UInt16Field()
        items = ListField(length=lambda pkt: pkt['size'], item_type=item)
        rest = PayloadField()

    @schema_final
    class Record(Schema):
        size = UInt16Field()
        items = ListField(length=lambda pkt: pkt['size'], item_type=item)

    @schema_final
    class Records(Schema):
        size = UInt16Field()
        records = ListField(length=lambda pkt: pkt['size'], item_type=SchemaField(schema=Record))

    return Sized, Records


def begun(item: 'Any', data: bytes, width: int) -> 'list[Any]':
    """The items ``data`` begins, the last read as its octets with zeros after them."""
    return [item.unpack(data[start:start + width].ljust(width, b'\x00'), {})
            for start in range(0, len(data), width)]


class PlainListCutTests(unittest.TestCase):
    """A list of plain values the data ends inside ends with the data."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assert_packs_back(self, parsed: 'Any', data: bytes) -> None:
        """``parsed`` packs back to ``data``, and so does the schema rebuilt from its dict."""
        self.assertEqual(parsed.pack(), data)
        self.assertEqual(type(parsed).from_dict(parsed.to_dict()).pack(), data)

    def test_the_sweep_finds_every_list_of_plain_values(self) -> None:
        self.assertEqual({label for label, _, _ in plain_lists()}, LISTS)

    def test_a_cut_list_holds_the_items_it_begins(self) -> None:
        for label, holder, item in plain_lists():
            width, whole = octets(holder, item)
            sized, _ = holders(item)
            for keep in range(len(whole)):
                data = len(whole).to_bytes(2, 'big') + whole[:keep]
                with self.subTest(list=label, captured=keep), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = sized.unpack(data, 2 + len(whole), {})
                    self.assertEqual(parsed.items, begun(item, whole[:keep], width))
                    self.assertEqual(parsed.__dict__['__short_read__'], ('items', keep))
                    self.assert_packs_back(parsed, data)

    def test_a_list_in_a_cut_item_holds_the_items_it_begins(self) -> None:
        # The record list is zero-filled to its length, and the record the data ends inside
        # reads its list from the fill (#2686, #2756).
        for label, holder, item in plain_lists():
            width, whole = octets(holder, item)
            _, records = holders(item)
            record = len(whole).to_bytes(2, 'big') + whole
            for keep in range(2, len(record)):
                data = len(record).to_bytes(2, 'big') + record[:keep]
                with self.subTest(list=label, captured=keep), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = records.unpack(data, 2 + len(record), {})
                    self.assertEqual([entry.items for entry in parsed.records],
                                     [begun(item, whole[:keep - 2], width)])
                    self.assert_packs_back(parsed, data)

    def test_a_whole_list_is_the_control(self) -> None:
        for label, holder, item in plain_lists():
            width, whole = octets(holder, item)
            sized, records = holders(item)
            data = len(whole).to_bytes(2, 'big') + whole
            nested = len(data).to_bytes(2, 'big') + data
            with self.subTest(list=label), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                parsed = sized.unpack(data, len(data), {})
                self.assertIsNone(parsed.__dict__.get('__short_read__'))
                self.assertEqual(parsed.items, begun(item, whole, width))
                self.assert_packs_back(parsed, data)
                within = records.unpack(nested, len(nested), {})
                self.assertEqual([entry.items for entry in within.records], [parsed.items])
                self.assert_packs_back(within, nested)
                self.assertEqual(caught, [])

    def test_a_zero_tail_is_read_as_items(self) -> None:
        # Where the octets past the data are zeros of it, as radiotap.org reads the octets a
        # producer leaves off a TLV item (#2655), a list reads its items on through them.
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt16Field, UInt32Field
        from pcapkit.protocols.schema import Schema, schema_final

        @schema_final
        class Pair(Schema):
            id = UInt16Field()
            value = UInt32Field()

        plain = ListField(length=12, item_type=UInt32Field())
        pairs = ListField(length=18, item_type=SchemaField(length=6, schema=Pair))
        for keep in range(12):
            with self.subTest(items='plain', captured=keep):
                data = bytes(range(1, 13))[:keep]
                self.assertEqual(plain.unpack(data, {'__zero_tail__': True}),
                                 begun(UInt32Field(), data.ljust(12, b'\x00'), 4))
                self.assertEqual(len(plain.unpack(data, {})), -(-keep // 4))
        for keep in range(18):
            with self.subTest(items='schema', captured=keep):
                data = bytes(range(1, 19))[:keep]
                self.assertEqual([item.pack() for item in pairs.unpack(data, {'__zero_tail__': True})],
                                 [chunk for chunk in (data.ljust(18, b'\x00')[at:at + 6] for at in (0, 6, 12))])
                self.assertEqual(len(pairs.unpack(data, {})), -(-keep // 6))

    def test_a_length_no_whole_number_of_items_fills_is_refused(self) -> None:
        # The items run past such a length read whole, so a cut of it is refused as well, rather
        # than read as far as the data goes.
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.numbers import UInt32Field
        from pcapkit.utilities.exceptions import FieldValueError

        field = ListField(length=10, item_type=UInt32Field())
        whole = bytes(range(1, 11))
        for keep in range(len(whole) + 1):
            with self.subTest(captured=keep), self.assertRaisesRegex(FieldValueError, 'invalid length'):
                field.unpack(whole[:keep], {})

    def test_the_octets_read_are_those_present(self) -> None:
        # Behind the fill, the zeros the list leaves unread past the item the data ends
        # inside are given back, as the fill takes them off the octets read in advance.
        from pcapkit.corekit.fields.field import _zero_pad_budget
        from pcapkit.corekit.fields.numbers import UInt32Field
        from pcapkit.utilities import config

        item = UInt32Field()
        sized, records = holders(item)
        whole = bytes(range(1, 13))
        record = len(whole).to_bytes(2, 'big') + whole
        for keep in range(len(record)):
            with self.subTest(captured=keep), mock.patch.object(config, 'ZERO_PAD_BUDGET_RATIO', -1):
                with _zero_pad_budget() as ledger:
                    sized.unpack(record[:keep], len(record), {})
                    self.assertEqual(ledger, [keep, 0])
                with _zero_pad_budget() as ledger:
                    data = len(record).to_bytes(2, 'big') + record[:keep]
                    records.unpack(data, 2 + len(record), {})
                    self.assertEqual(ledger, [len(data), len(record) - keep])

    def test_a_list_of_schema_items_in_a_cut_item_ends_with_the_data(self) -> None:
        # A list of schema items in the record the data ends inside reads its buffer from the
        # fill, so it ends with the data and gives back the zeros of the fill it leaves unread.
        from pcapkit.corekit.fields.field import _zero_pad_budget
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt16Field, UInt32Field
        from pcapkit.protocols.schema import Schema, schema_final
        from pcapkit.utilities import config

        @schema_final
        class Pair(Schema):
            id = UInt16Field()
            value = UInt32Field()

        _, records = holders(SchemaField(length=6, schema=Pair))
        pairs = bytes(range(1, 19))
        record = len(pairs).to_bytes(2, 'big') + pairs
        for keep in range(2, len(record)):
            data = len(record).to_bytes(2, 'big') + record[:keep]
            with self.subTest(captured=keep), mock.patch.object(config, 'ZERO_PAD_BUDGET_RATIO', -1), \
                    _zero_pad_budget() as ledger:
                parsed = records.unpack(data, 2 + len(record), {})
                self.assertEqual([len(entry.items) for entry in parsed.records], [-(-(keep - 2) // 6)])
                self.assertEqual(parsed.pack(), data)
                self.assertEqual(ledger, [len(data), len(record) - keep])


if __name__ == '__main__':
    unittest.main()
