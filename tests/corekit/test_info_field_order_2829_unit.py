# -*- coding: utf-8 -*-
"""GitHub issue #2829: an :class:`~pcapkit.corekit.infoclass.Info` keeps its
fields in the order they were set, whatever order ``__dict__`` lists them in.

PyPy gives an instance the ``__dict__`` layout an earlier instance of its class
used, so ``__dict__`` is no record of the order a field was set in there.
:class:`SecondInstanceTests` is that case, which only PyPy tells apart;
:class:`DictLayoutTests` reorders ``__dict__`` by hand, as PyPy lays it out, so
CPython checks too that nothing reads its order. :class:`ContractTests`
holds the rest of the :class:`~pcapkit.corekit.infoclass.Info` contract to the
recorded order.

Every case builds its own values and reads no capture.

"""

import copy
import pickle  # nosec: B403 -- round-trips objects built here
import unittest

from tests._support import reimport_once_per_class
from tests.corekit._roundtrip import skip_without_runtime

#: Test tier (#1958): exercises PyPy's instance layout, and pickling and
#: copying, which differ by interpreter.
__tier__ = 'ALL'

#: The bookkeeping attributes every instance carries in ``__dict__``.
BOOKKEEPING = ('__map__', '__map_reverse__', '__multi__', '__keys__')


def scramble(info):  # type: ignore[no-untyped-def]
    """Reverse the fields' order in ``info.__dict__``, as PyPy may lay it out.

    Each field is popped and set again, last first. CPython then lists them
    backwards; PyPy keeps the layout it chose, which :class:`SecondInstanceTests`
    covers.

    """
    fields = info.__dict__
    keys = [key for key in fields if key not in BOOKKEEPING]
    for key in reversed(keys):
        fields[key] = fields.pop(key)
    return info


class _OrderCase(unittest.TestCase):
    """Builds the classes the cases share, and asserts every view of an order."""

    def setUp(self) -> None:
        skip_without_runtime(self)
        reimport_once_per_class(self)

        from pcapkit.corekit.infoclass import Info, info_final

        @info_final
        class Dyn(Info):
            """Fields from keyword arguments, as in the issue."""

        self.Info = Info
        self.Dyn = Dyn

    def assertOrder(self, info, pairs) -> None:  # type: ignore[no-untyped-def]
        """Every view of ``info`` lists ``pairs``, in order."""
        keys = [key for (key, _) in pairs]
        self.assertEqual(list(info), keys)
        self.assertEqual(list(info.keys()), keys)
        self.assertEqual(list(info.values()), [value for (_, value) in pairs])
        self.assertEqual(list(info.items()), pairs)
        self.assertEqual(list(info.items(multi=True)), pairs)
        self.assertEqual(list(info.to_dict().items(multi=True)), pairs)
        self.assertEqual(len(info), len(pairs))
        name = type(info).__name__
        self.assertEqual(repr(info), f'<{name} {", ".join(f"{k}={v!r}" for (k, v) in pairs)}>')
        self.assertEqual(str(info), f'{name}({", ".join(f"{k}={v}" for (k, v) in pairs)})')


class SecondInstanceTests(_OrderCase):
    """The issue's reproduction: a second instance, given another order."""

    def test_keyword_fields_keep_their_own_order(self) -> None:
        self.assertOrder(self.Dyn(tcp=1, dummy=2), [('tcp', 1), ('dummy', 2)])
        self.assertOrder(self.Dyn(dummy=2, tcp=1), [('dummy', 2), ('tcp', 1)])

    def test_from_dict_keeps_its_own_order(self) -> None:
        self.assertOrder(self.Info.from_dict({'x': 1, 'tcp': 2, 'dummy': 3}),
                         [('x', 1), ('tcp', 2), ('dummy', 3)])
        self.assertOrder(self.Info.from_dict([('dummy', 3), ('tcp', 2), ('x', 1)]),
                         [('dummy', 3), ('tcp', 2), ('x', 1)])

    def test_a_subset_keeps_its_own_order(self) -> None:
        self.assertOrder(self.Dyn(a=1, b=2, c=3), [('a', 1), ('b', 2), ('c', 3)])
        self.assertOrder(self.Dyn(c=3, a=1), [('c', 3), ('a', 1)])


class DictLayoutTests(_OrderCase):
    """``__dict__`` reordered by hand: every view follows the order set."""

    def test_keyword_fields(self) -> None:
        self.assertOrder(scramble(self.Dyn(dummy=2, tcp=1, x=3)), [('dummy', 2), ('tcp', 1), ('x', 3)])

    def test_generated_init(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final

        @info_final
        class Point(Info):
            x: int
            y: int
            z: int

        self.assertOrder(scramble(Point(1, 2, 3)), [('x', 1), ('y', 2), ('z', 3)])

    def test_key_renamed_for_a_builtin_name(self) -> None:
        info = scramble(self.Dyn(b=1, items=2, a=3))
        self.assertEqual(info.__map__, {'items': '_Dynitems'})
        self.assertOrder(info, [('b', 1), ('items', 2), ('a', 3)])

    def test_replaced_key_keeps_its_first_place(self) -> None:
        info = scramble(self.Info([('a', 1), ('b', 2), ('a', 3)]))
        self.assertOrder(info, [('a', 3), ('b', 2)])
        self.assertEqual(info.__keys__, ('a', 'b'))

    def test_repeated_key_follows_the_key_it_was_given_after(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict

        info = scramble(self.Info.from_dict(OrderedMultiDict([('a', 1), ('b', 2), ('a', 3), ('c', 4)])))
        self.assertEqual(list(info), ['a', 'b', 'c'])
        self.assertEqual(list(info.items(multi=True)), [('a', 1), ('b', 2), ('a', 3), ('c', 4)])
        self.assertEqual(list(info.to_dict().items(multi=True)), [('a', 1), ('b', 2), ('a', 3), ('c', 4)])

    def test_excluded_and_dunder_keys(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final

        @info_final
        class Meta(Info):
            __excluded__ = ['__next_type__']
            __included__ = ['__next_type__']

        info = scramble(Meta(b=1, __next_type__=2, __hidden__=3, a=4))
        self.assertEqual(list(info), ['b', '__next_type__', 'a'])
        self.assertEqual(list(info.to_dict().items(multi=True)), [('b', 1), ('__next_type__', 2), ('a', 4)])
        self.assertEqual(len(info), 3)
        self.assertEqual(repr(info), '<Meta b=1, __hidden__=3, a=4>')

    def test_copies_and_pickles(self) -> None:
        info = self.Info(dummy=2, tcp=1, x=3)
        pairs = [('dummy', 2), ('tcp', 1), ('x', 3)]
        for label, clone in [('copy', copy.copy(info)), ('deepcopy', copy.deepcopy(info))] + [
                (f'pickle {proto}', pickle.loads(pickle.dumps(info, proto)))  # nosec: B301
                for proto in range(pickle.HIGHEST_PROTOCOL + 1)]:
            with self.subTest(label):
                self.assertIs(type(clone), self.Info)
                self.assertEqual(clone, info)
                self.assertOrder(scramble(clone), pairs)

    def test_a_copy_records_its_own_keys(self) -> None:
        info = self.Info(b=1, a=2)
        clone = copy.copy(info)
        clone.__update__(c=3)
        self.assertEqual(scramble(clone).__keys__, ('b', 'a', 'c'))
        self.assertOrder(scramble(info), [('b', 1), ('a', 2)])


class ContractTests(_OrderCase):
    """The rest of the contract, around the recorded order."""

    def test_bookkeeping(self) -> None:
        from pcapkit.corekit.infoclass import _BOOKKEEPING

        info = self.Dyn()
        self.assertEqual(set(info.__dict__), set(_BOOKKEEPING))
        self.assertLessEqual(set(_BOOKKEEPING), self.Dyn.__builtin__)
        self.assertLessEqual(set(_BOOKKEEPING), set(self.Dyn.__excluded__))
        self.assertEqual(info.__keys__, ())

    def test_a_field_named_keys_leaves_the_record_alone(self) -> None:
        info = self.Dyn(a=1, **{'__keys__': 2})
        self.assertEqual(info.__keys__, ('a', '_Dyn__keys__'))
        self.assertEqual(info['__keys__'], 2)
        self.assertEqual(list(info.items()), [('a', 1), ('__keys__', 2)])

    def test_equality_ignores_order_and_hash_is_refused(self) -> None:
        first, second = self.Dyn(a=1, b=2), self.Dyn(b=2, a=1)
        self.assertEqual(first, second)
        self.assertFalse(first != second)
        self.assertNotEqual(first.__keys__, second.__keys__)
        with self.assertRaises(TypeError):
            hash(first)

    def test_from_dict_rebuilds_a_nested_info_in_place(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final

        @info_final
        class Leaf(Info):
            v: int

        @info_final
        class Holder(Info):
            a: int
            leaf: Leaf
            b: int

        info = scramble(Holder.from_dict({'b': 3, 'leaf': {'v': 2}, 'a': 1}))
        self.assertIsInstance(info.leaf, Leaf)
        self.assertEqual(list(info), ['b', 'leaf', 'a'])

    def test_a_key_put_in_dict_directly_follows_the_recorded_ones(self) -> None:
        info = scramble(self.Dyn(b=1, a=2))
        info.__dict__['c'] = 3
        self.assertOrder(info, [('b', 1), ('a', 2), ('c', 3)])

    def test_an_earlier_releases_pickle_keeps_every_field(self) -> None:
        info = self.Info(b=1, a=2)
        # NOTE: Without ``__keys__``, an instance pickles as an earlier release's does: the
        # same reduction, with the fields and the other bookkeeping as its state.
        earlier = self.Info(b=1, a=2)
        del earlier.__dict__['__keys__']
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(proto=proto):
                clone = pickle.loads(pickle.dumps(earlier, proto))  # nosec: B301
                self.assertIs(type(clone), self.Info)
                self.assertEqual(clone.__keys__, ())
                self.assertEqual(clone, info)
                self.assertEqual(sorted(clone), ['a', 'b'])
                self.assertEqual(len(clone), 2)


if __name__ == '__main__':
    unittest.main()
