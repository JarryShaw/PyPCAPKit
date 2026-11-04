# -*- coding: utf-8 -*-
"""A list of schema items short of its length is zero-filled to it (#2686).

:meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>` reads a
field the data ends inside as though its missing octets were zeros.
:meth:`ListField.unpack <pcapkit.corekit.fields.collections.ListField.unpack>`
refused the same reading for schema items: an item past the data consumed nothing,
and the loop guard raised. Now the items read the octets present zero-filled to the
field's length, so a cut list covers the length it declares and rebuilds from it.

Every zero-filled item is a schema object rather than a zero octet, so the fill is
charged to the running budget with no free band and no one-off allowance, and the
zeros the items then read earn no allowance of their own.

Every case builds its own octets.

"""

import io
import unittest
from unittest import mock

from tests._support import reimport_once_per_class, time_limit


class ListZeroFillTests(unittest.TestCase):
    """:meth:`ListField.unpack` on schema items short of the field's length."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.corekit.fields import field as field_module
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt16Field, UInt32Field
        from pcapkit.protocols.schema import Schema, schema_final
        from pcapkit.utilities import config
        from pcapkit.utilities.exceptions import FieldValueError

        @schema_final
        class Pair(Schema):
            """A 16-bit identifier and a 32-bit value, as an HTTP/2 setting is."""

            id: int = UInt16Field()
            value: int = UInt32Field()

        @schema_final
        class Pairs(Schema):
            """A count of pairs, then as many octets of them as ``__length__`` leaves."""

            count: int = UInt16Field()
            pairs: list = ListField(length=lambda pkt: pkt['__length__'],
                                    item_type=SchemaField(length=6, schema=Pair))

        self.budget = field_module._zero_pad_budget  # pylint: disable=protected-access
        self.ledger = field_module._zero_pad_ledger  # pylint: disable=protected-access
        self.ListField, self.SchemaField, self.Pair, self.Pairs = ListField, SchemaField, Pair, Pairs
        self.config, self.FieldValueError = config, FieldValueError

    def field(self, length: int):
        """A list of :class:`Pair` items declaring ``length`` octets."""
        return self.ListField(length=length, item_type=self.SchemaField(length=6, schema=self.Pair))

    @staticmethod
    def pairs(parsed: 'list') -> 'list[tuple[int, int]]':
        return [(item.id, item.value) for item in parsed]

    def test_a_short_buffer_and_stream_are_zero_filled_alike(self) -> None:
        present = bytes.fromhex('000100001000' '000300')
        stream = io.BytesIO(b'\xde\xad' + present)
        stream.seek(2)
        for name, buffer in (('bytes', present), ('stream', stream)):
            with self.subTest(buffer=name), self.budget(), time_limit():
                parsed = self.field(18).unpack(buffer, {})
                self.assertEqual(self.pairs(parsed), [(1, 4096), (3, 0), (0, 0)])
        self.assertEqual(stream.tell(), 2 + len(present))

    def test_a_whole_list_is_read_as_it_was(self) -> None:
        """The control: a list its buffer backs fills nothing and charges nothing."""
        whole = bytes.fromhex('000100001000' '000300000064')
        stream = io.BytesIO(whole + b'\xff' * 6)
        with self.budget() as ledger:
            self.assertEqual(self.pairs(self.field(12).unpack(whole, {})), [(1, 4096), (3, 100)])
            self.assertEqual(self.pairs(self.field(12).unpack(stream, {})), [(1, 4096), (3, 100)])
            self.assertEqual(ledger, [24, 0])
        self.assertEqual(stream.tell(), 12)

    def test_a_cut_schema_packs_back_as_captured(self) -> None:
        """The short read is recorded on the list, which packs at its full length and is
        cut back to the octets captured, from the schema and from its dict."""
        whole = bytes.fromhex('0003' '000100001000' '000300000064' '000400010000')
        for keep in range(2, len(whole)):
            cut = whole[:keep]
            with self.subTest(keep=keep):
                schema = self.Pairs.unpack(cut, len(whole))
                self.assertEqual(len(schema.pairs), 3)
                self.assertEqual(schema.__dict__['__short_read__'], ('pairs', keep - 2))
                self.assertEqual(schema.pack(), cut)
                self.assertEqual(self.Pairs.from_dict(schema.to_dict()).pack(), cut)

    def test_the_fill_is_refused_past_the_ratio_of_octets_read(self) -> None:
        """No free band: padding up to the ratio times the octets read is filled, from a
        fresh ledger, and one octet past it is refused."""
        ratio = self.config.ZERO_PAD_BUDGET_RATIO
        present = bytes(6)
        with self.budget() as ledger:
            self.field(6 + ratio * 6).unpack(present, {})
            self.assertEqual(ledger, [6, ratio * 6])
        with self.budget(), self.assertRaisesRegex(
                self.FieldValueError, rf'would zero-fill {ratio * 6 + 1} octet\(s\) of items, .* past the '
                                      rf'{ratio * 6} octet\(s\) allowed'):
            self.field(6 + ratio * 6 + 1).unpack(present, {})

    def test_the_zeros_earn_no_allowance(self) -> None:
        """A fill the items read back as zeros credits only the octets present, so a
        second fill as large as the first, against no new octets, is refused."""
        ratio = self.config.ZERO_PAD_BUDGET_RATIO
        with self.budget() as ledger:
            self.field(6 + ratio * 6).unpack(bytes(6), {})
            with self.assertRaises(self.FieldValueError):
                self.field(ratio * 6 + 1).unpack(b'', {})
            self.assertEqual(ledger, [6, ratio * 6])

    def test_a_failed_fill_gives_back_the_octets_read(self) -> None:
        """Items that fail inside the fill leave the octets read as they were, so one
        bad list does not refuse the later cuts of its context; the fill stays charged.
        Only a failure restores them: a later fill that succeeds is counted as usual."""
        from pcapkit.corekit.fields.numbers import UInt16Field
        from pcapkit.protocols.schema import Schema, schema_final
        from pcapkit.utilities.exceptions import ProtocolError

        @schema_final
        class NonZero(Schema):
            """A 16-bit value that refuses to be zero once parsed."""

            value: int = UInt16Field()

            def post_process(self, packet: 'dict') -> 'Schema':
                if self.value == 0:
                    raise ProtocolError('a zero item')
                return self

        field = self.ListField(length=12, item_type=self.SchemaField(length=2, schema=NonZero))
        with self.budget() as ledger:
            self.field(12).unpack(bytes(12), {})
            self.assertEqual(ledger, [12, 0])
            with self.assertRaisesRegex(ProtocolError, 'a zero item'):
                field.unpack(b'\x00\x01', {})
            self.assertEqual(ledger, [12, 10])

            # a fill that succeeds keeps the octets its items read, as before the failure
            self.field(12).unpack(bytes(2), {})
            self.assertEqual(ledger, [14, 20])

    def test_a_fresh_context_gets_a_ledger_of_its_own(self) -> None:
        """A fill that is the first read of a context starts that context's ledger."""
        import contextvars

        def fill() -> 'tuple[int, list[int]]':
            parsed = self.field(12).unpack(bytes(6), {})
            return len(parsed), self.ledger.get()

        self.assertEqual(contextvars.Context().run(fill), (2, [6, 6]))

    def test_a_length_past_the_ceiling_is_refused(self) -> None:
        ceiling = self.config.MAX_ZERO_PAD_LENGTH
        with self.budget(), self.assertRaisesRegex(
                self.FieldValueError, rf'declares a length of {ceiling + 1} octet\(s\), but only 6'):
            self.field(ceiling + 1).unpack(bytes(6), {})

    def test_a_lifted_budget_fills_any_shortfall_within_the_ceiling(self) -> None:
        for name in ('ZERO_PAD_BUDGET_RATIO', 'MAX_ZERO_PAD_SHORTFALL'):
            with self.subTest(name), mock.patch.object(self.config, name, -1), self.budget(), time_limit():
                self.assertEqual(len(self.field(6000).unpack(b'', {})), 1000)


if __name__ == '__main__':
    unittest.main()
