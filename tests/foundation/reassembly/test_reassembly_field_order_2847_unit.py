# -*- coding: utf-8 -*-
"""GitHub issue #2847: the reassembly manager and record keep the order given
through :class:`~pcapkit.corekit.infoclass.Info`'s own record of it.

:class:`~pcapkit.foundation.reassembly.ReassemblyManager` and
:class:`~pcapkit.foundation.reassembly.data.ReassemblyData` hold a field per
enabled reassembler, iterated in the order given. PyPy gives an instance the
``__dict__`` layout an earlier instance of its class used, which
:class:`~pcapkit.corekit.infoclass.Info` handles since #2829, so neither class
records the order a second time. :class:`SecondInstanceTests` is the PyPy case;
the other classes reorder ``__dict__`` by hand, as PyPy lays it out, so CPython
checks too that nothing reads its order.

Every case builds its own values and reads no capture.

"""

import copy
import pickle  # nosec: B403 -- round-trips objects built here
import unittest

from tests._support import reimport_once_per_class
from tests.foundation.reassembly._reassemblers import builtins

#: Test tier (#1958): exercises PyPy's instance layout, and pickling and
#: copying, which differ by interpreter.
__tier__ = 'ALL'

#: The bookkeeping attributes every instance carries in ``__dict__``.
BOOKKEEPING = ('__map__', '__map_reverse__', '__multi__', '__keys__')


def scramble(info):  # type: ignore[no-untyped-def]
    """Reverse the fields' order in ``info.__dict__``, as PyPy may lay it out."""
    fields = info.__dict__
    keys = [key for key in fields if key not in BOOKKEEPING]
    for key in reversed(keys):
        fields[key] = fields.pop(key)
    return info


class _OrderCase(unittest.TestCase):
    """Imports the classes, and asserts every view of an order."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.corekit.infoclass import Info
        from pcapkit.foundation.reassembly import ReassemblyManager
        from pcapkit.foundation.reassembly.data import ReassemblyData

        self.Info = Info
        self.Manager = ReassemblyManager
        self.Data = ReassemblyData
        # the record's built-in fields, which come first: one per shipped reassembler
        self.builtins = builtins()

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

    def assertClones(self, info, pairs) -> None:  # type: ignore[no-untyped-def]
        """Every copy and pickle of ``info`` keeps ``pairs``, in order."""
        clones = [('copy', copy.copy(info)), ('deepcopy', copy.deepcopy(info))] + [
            (f'pickle {proto}', pickle.loads(pickle.dumps(info, proto)))  # nosec: B301
            for proto in range(pickle.HIGHEST_PROTOCOL + 1)]
        for (label, clone) in clones:
            with self.subTest(label):
                self.assertIs(type(clone), type(info))
                self.assertEqual(clone, info)
                self.assertOrder(scramble(clone), pairs)


class ManagerOrderTests(_OrderCase):
    """:class:`~pcapkit.foundation.reassembly.ReassemblyManager` keeps the names in the order given."""

    PAIRS = [('tcp', 'tcp-reasm'), ('dummy', 'dummy-reasm'), ('ipv4', 'ipv4-reasm')]

    def test_every_constructor_form(self) -> None:
        pairs = self.PAIRS
        given = dict(pairs)
        forms = {
            'keywords': lambda: self.Manager(**given),
            'mapping': lambda: self.Manager(given),
            'pairs': lambda: self.Manager(pairs),
            'pairs and keywords': lambda: self.Manager(pairs[:2], ipv4='ipv4-reasm'),
            'generator': lambda: self.Manager(pair for pair in pairs),
            'manager': lambda: self.Manager(self.Manager(pairs)),
            'disabled left out': lambda: self.Manager(ipv6=None, tcp='tcp-reasm', dtls=None,
                                                      dummy='dummy-reasm', ipv4='ipv4-reasm'),
        }
        for (label, make) in forms.items():
            with self.subTest(label):
                self.assertOrder(scramble(make()), pairs)

    def test_from_dict(self) -> None:
        reverse = self.PAIRS[::-1]
        self.assertOrder(scramble(self.Manager.from_dict(reverse)), reverse)
        self.assertOrder(scramble(self.Manager.from_dict(self.Manager(self.PAIRS).to_dict())), self.PAIRS)

    def test_copies_and_pickles(self) -> None:
        self.assertClones(self.Manager(self.PAIRS), self.PAIRS)

    def test_name_renamed_for_a_builtin_name(self) -> None:
        manager = scramble(self.Manager(items='items-reasm', tcp='tcp-reasm'))
        self.assertEqual(manager.__map__, {'items': '_ReassemblyManageritems'})
        self.assertOrder(manager, [('items', 'items-reasm'), ('tcp', 'tcp-reasm')])


class DataOrderTests(_OrderCase):
    """:class:`~pcapkit.foundation.reassembly.data.ReassemblyData` lists the built-ins, then the rest as given."""

    def pairs(self, **extra):  # type: ignore[no-untyped-def]
        """The record's pairs for ``ReassemblyData(tcp=('t',), **extra)``."""
        return [*((name, ('t',) if name == 'tcp' else None) for name in self.builtins), *extra.items()]

    def test_built_ins_then_the_rest_as_given(self) -> None:
        for extra in ({}, {'late': (), 'early': ('e',)}, {'early': ('e',), 'late': ()}):
            with self.subTest(list(extra)):
                self.assertOrder(scramble(self.Data(tcp=('t',), **extra)), self.pairs(**extra))

    def test_built_ins_given_out_of_order(self) -> None:
        given = [(name, (name,) if index % 2 else ()) for (index, name) in enumerate(self.builtins)]
        data = scramble(self.Data(dummy=('d',), **dict(given[::-1])))
        self.assertOrder(data, [*given, ('dummy', ('d',))])

    def test_from_dict(self) -> None:
        reverse = self.pairs(dummy=('d',))[::-1]
        self.assertOrder(scramble(self.Data.from_dict(reverse)), reverse)
        pairs = self.pairs(dummy=('d',))
        self.assertOrder(scramble(self.Data.from_dict(self.Data(tcp=('t',), dummy=('d',)).to_dict())), pairs)

    def test_copies_and_pickles(self) -> None:
        self.assertClones(self.Data(tcp=('t',), late=(), early=('e',)), self.pairs(late=(), early=('e',)))

    def test_name_renamed_for_a_builtin_name(self) -> None:
        data = scramble(self.Data(tcp=('t',), items=('i',), alpha=('a',)))
        self.assertEqual(data.__map__, {'items': '_ReassemblyDataitems'})
        self.assertOrder(data, self.pairs(items=('i',), alpha=('a',)))


class SecondInstanceTests(_OrderCase):
    """The PyPy case: a second instance given another order than the first."""

    def test_manager(self) -> None:
        self.assertOrder(self.Manager(dummy=1, tcp=2), [('dummy', 1), ('tcp', 2)])
        self.assertOrder(self.Manager(tcp=2, dummy=1), [('tcp', 2), ('dummy', 1)])

    def test_data(self) -> None:
        self.Data(late=(), early=())
        self.assertOrder(self.Data(early=(), late=()), [*((name, None) for name in self.builtins),
                                                        ('early', ()), ('late', ())])


class OneRecordTests(_OrderCase):
    """The order is :class:`~pcapkit.corekit.infoclass.Info`'s own record, kept nowhere else."""

    def test_iteration_is_infos_own(self) -> None:
        self.assertIs(self.Manager.__iter__, self.Info.__iter__)
        self.assertIs(self.Data.__iter__, self.Info.__iter__)

    def test_instances_carry_only_infos_bookkeeping(self) -> None:
        manager = self.Manager(dummy=1, ipv4=None, tcp=2)
        self.assertEqual(set(manager.__dict__), {*BOOKKEEPING, 'dummy', 'tcp'})
        self.assertEqual(manager.__keys__, ('dummy', 'tcp'))

        data = self.Data(dummy=())
        self.assertEqual(set(data.__dict__), {*BOOKKEEPING, *self.builtins, 'dummy'})
        self.assertEqual(data.__keys__, (*self.builtins, 'dummy'))


if __name__ == '__main__':
    unittest.main()
