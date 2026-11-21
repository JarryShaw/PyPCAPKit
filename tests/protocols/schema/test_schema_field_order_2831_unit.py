# -*- coding: utf-8 -*-
"""GitHub issue #2831: a :class:`~pcapkit.protocols.schema.Schema` lists its
fields in :attr:`~pcapkit.protocols.schema.Schema.__fields__` order, whatever
order ``__dict__`` lists them in.

``from_dict`` sets the fields in the order it is given them, and PyPy gives an
instance the ``__dict__`` layout an earlier instance of its class used.
:class:`SecondInstanceTests` is the issue's case, which CPython tells apart for
the first instance and PyPy for both; :class:`DictLayoutTests` reorders
``__dict__`` by hand, as PyPy lays it out, so CPython checks too that nothing
reads its order. :class:`RoundTripTests` holds the round trips to it.

Every case builds its own octets and reads no capture.

"""

import copy
import pickle  # nosec: B403 -- round-trips objects built here
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises PyPy's instance layout, and pickling and
#: copying, which differ by interpreter.
__tier__ = 'ALL'

#: IPv4 timestamp option: pointer 9, timestamps only, one timestamp of 1 ms.
TS_OPTION = bytes.fromhex('4408090000000001')
#: TCP header, Data Offset 6: NOP, EOOL, then two octets of padding.
TCP_HEADER = bytes.fromhex('0050c3500000000100000000' '6002ffff00000000' '01000000')
#: The bookkeeping attributes every instance carries in ``__dict__``.
BOOKKEEPING = ('__map__', '__map_reverse__', '__buffer__', '__updated__')


def scramble(schema):  # type: ignore[no-untyped-def]
    """Reverse the fields' order in ``schema.__dict__``, as PyPy may lay it out.

    Each key but the bookkeeping is popped and set again, last first. CPython
    then lists them backwards; PyPy keeps the layout it chose, which
    :class:`SecondInstanceTests` covers.

    """
    values = schema.__dict__
    for key in reversed([key for key in values if key not in BOOKKEEPING]):
        values[key] = values.pop(key)
    return schema


class _OrderCase(unittest.TestCase):
    """Builds the schemas the cases share, and asserts every view of an order."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema import Schema, schema_final

        @schema_final
        class Three(Schema):
            """The issue's schema."""

            a: int = UInt8Field()
            b: int = UInt8Field()
            c: int = UInt8Field()

        self.Three = Three

    def assertOrder(self, schema, pairs) -> None:  # type: ignore[no-untyped-def]
        """Every view of ``schema`` lists ``pairs``, in order."""
        keys = [key for (key, _) in pairs]
        self.assertEqual(list(schema), keys)
        self.assertEqual(list(schema.keys()), keys)
        self.assertEqual(list(schema.values()), [value for (_, value) in pairs])
        self.assertEqual(list(schema.items()), pairs)
        self.assertEqual(list(schema.to_dict().items()), pairs)
        name = type(schema).__name__
        self.assertEqual(repr(schema), f'{name}({", ".join(f"{k}={v!r}" for (k, v) in pairs)})')
        self.assertEqual(str(schema), f'{name}({", ".join(f"{k}={v}" for (k, v) in pairs)})')


class SecondInstanceTests(_OrderCase):
    """The issue's reproduction: a second instance, given another order."""

    def test_from_dict_lists_the_declared_order(self) -> None:
        first = self.Three.from_dict({'c': 1, 'a': 2, 'b': 3})
        second = self.Three.from_dict({'a': 1, 'b': 2, 'c': 3})
        self.assertOrder(first, [('a', 2), ('b', 3), ('c', 1)])
        self.assertOrder(second, [('a', 1), ('b', 2), ('c', 3)])
        self.assertEqual(bytes(first), b'\x02\x03\x01')
        self.assertEqual(bytes(second), b'\x01\x02\x03')

    def test_keywords_list_the_declared_order(self) -> None:
        self.Three.from_dict({'c': 1, 'b': 2, 'a': 3})
        self.assertOrder(self.Three(c=3, b=2, a=1), [('a', 1), ('b', 2), ('c', 3)])
        self.assertOrder(self.Three.unpack(b'\x01\x02\x03', 3, None), [('a', 1), ('b', 2), ('c', 3)])


class DictLayoutTests(_OrderCase):
    """``__dict__`` reordered by hand: every view follows ``__fields__``."""

    def test_generated_init_and_unpack(self) -> None:
        self.assertOrder(scramble(self.Three(1, 2, 3)), [('a', 1), ('b', 2), ('c', 3)])
        self.assertOrder(scramble(self.Three.unpack(b'\x01\x02\x03', 3, None)), [('a', 1), ('b', 2), ('c', 3)])

    def test_a_field_set_late_keeps_its_declared_place(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema import Schema, schema_final

        @schema_final
        class Late(Schema):
            a: int = UInt8Field()
            b: int = UInt8Field()

        schema = Late(b=2)
        self.assertOrder(schema, [('b', 2)])
        schema.a = 1
        self.assertOrder(schema, [('a', 1), ('b', 2)])
        del schema.a
        schema.a = 3
        self.assertOrder(schema, [('a', 3), ('b', 2)])

    def test_a_field_named_for_a_builtin(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema import Schema, schema_final

        @schema_final
        class Renamed(Schema):
            __additional__ = ['b']

            a: int = UInt8Field()
            b: int = UInt8Field()
            c: int = UInt8Field()

        schema = scramble(Renamed.from_dict({'b': 2, 'c': 3, 'a': 1}))
        self.assertEqual(schema.__map__, {'b': '_Renamedb'})
        self.assertOrder(schema, [('a', 1), ('b', 2), ('c', 3)])
        self.assertEqual(bytes(schema), b'\x01\x02\x03')

    def test_post_process_keys_follow_the_fields(self) -> None:
        from pcapkit.protocols.internet.ipv4.schema import TSOption

        schema = TSOption.unpack(TS_OPTION, len(TS_OPTION), None)
        fields = list(TSOption.__fields__)
        extra = {key for key in schema if key not in TSOption.__fields__}
        self.assertTrue(extra)
        # NOTE: The keys ``post_process`` stores keep ``__dict__`` order, which PyPy may
        # not change on a reset, so only where they come is pinned.
        for keys in (list(scramble(schema)), list(schema.to_dict())):
            self.assertEqual(keys[:len(fields)], fields)
            self.assertEqual(set(keys[len(fields):]), extra)
        self.assertEqual(bytes(schema), TS_OPTION)

    def test_a_key_put_in_dict_directly_follows_the_fields(self) -> None:
        schema = scramble(self.Three(1, 2, 3))
        schema.__dict__['z'] = 4
        self.assertOrder(schema, [('a', 1), ('b', 2), ('c', 3), ('z', 4)])

    def test_remainder_and_short_read_stay_last_in_to_dict(self) -> None:
        schema = self.Three.from_dict({'b': 2, 'c': 3, '__short_read__': ('c', 0), 'a': 1})
        self.assertEqual(list(scramble(schema)), ['a', 'b', 'c'])
        self.assertEqual(list(schema.to_dict()), ['a', 'b', 'c', '__short_read__'])


class RoundTripTests(_OrderCase):
    """Every round trip keeps the declared order, and the octets."""

    def test_from_dict_of_to_dict(self) -> None:
        schema = self.Three.from_dict({'c': 3, 'a': 1, 'b': 2})
        rebuilt = self.Three.from_dict(scramble(schema).to_dict())
        self.assertEqual(rebuilt, schema)
        self.assertOrder(rebuilt, [('a', 1), ('b', 2), ('c', 3)])
        self.assertEqual(bytes(rebuilt), b'\x01\x02\x03')

    def test_a_nested_schema(self) -> None:
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema import Schema, schema_final

        @schema_final
        class Inner(Schema):
            x: int = UInt8Field()
            y: int = UInt8Field()

        @schema_final
        class Outer(Schema):
            n: int = UInt8Field()
            inner: Inner = SchemaField(length=2, schema=Inner)
            tail: int = UInt8Field()

        schema = Outer.from_dict({'tail': 4, 'inner': Inner.from_dict({'y': 3, 'x': 2}), 'n': 1})
        self.assertEqual(list(schema), ['n', 'inner', 'tail'])
        self.assertEqual(repr(schema), 'Outer(n=1, inner=Inner(...), tail=4)')
        dict_ = schema.to_dict()
        self.assertEqual(list(dict_), ['n', 'inner', 'tail'])
        self.assertEqual(list(dict_['inner'].items()), [('x', 2), ('y', 3)])
        self.assertEqual(bytes(schema), b'\x01\x02\x03\x04')
        self.assertEqual(bytes(Outer.from_dict(dict_)), b'\x01\x02\x03\x04')

    def test_unpack_then_pack(self) -> None:
        from pcapkit.protocols.transport.tcp.schema import TCP

        schema = scramble(TCP.unpack(TCP_HEADER, len(TCP_HEADER), None))
        self.assertEqual(list(schema), list(TCP.__fields__))
        self.assertEqual(schema.pack(), TCP_HEADER)
        self.assertEqual(bytes(TCP.from_dict(schema.to_dict())), TCP_HEADER)

    def test_copies_and_pickles(self) -> None:
        from pcapkit.protocols.transport.tcp.schema import TCP

        schema = TCP.unpack(TCP_HEADER, len(TCP_HEADER), None)
        pairs = list(schema.items())
        for label, clone in [('copy', copy.copy(schema)), ('deepcopy', copy.deepcopy(schema))] + [
                (f'pickle {proto}', pickle.loads(pickle.dumps(schema, proto)))  # nosec: B301
                for proto in range(pickle.HIGHEST_PROTOCOL + 1)]:
            with self.subTest(label):
                self.assertIs(type(clone), TCP)
                self.assertEqual(clone, schema)
                self.assertEqual(list(scramble(clone).items()), pairs)
                self.assertEqual(bytes(clone), TCP_HEADER)

    def test_bookkeeping(self) -> None:
        from pcapkit.protocols.schema import _BOOKKEEPING

        schema = self.Three.__new__(self.Three)
        self.assertEqual(_BOOKKEEPING, BOOKKEEPING)
        self.assertEqual(set(schema.__dict__), set(_BOOKKEEPING))
        self.assertLessEqual(set(_BOOKKEEPING), self.Three.__builtin__)
        self.assertEqual(list(schema), [])


if __name__ == '__main__':
    unittest.main()
