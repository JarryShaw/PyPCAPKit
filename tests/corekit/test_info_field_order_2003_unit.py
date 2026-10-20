# -*- coding: utf-8 -*-
"""GitHub issue #2003: an :class:`~pcapkit.corekit.infoclass.Info` lists its
fields in the order they were set, whatever the interpreter's attribute layout.

:class:`~pcapkit.corekit.infoclass.Info` used to read its field order from the
instance's ``__dict__``. On PyPy that is the storage layout, which follows the
first instance of the class the interpreter saw: a later instance that set its
fields in another order listed them in the earlier one's, so ``to_dict()`` and
anything rebuilt from it came out reordered. The order is now recorded as each
field is set.

The defect needs PyPy to happen on its own, so most tests here reorder an
instance's ``__dict__`` by hand, which is what PyPy's layout does to it, and
assert that nothing reads the order from there. The last runs the reordering
PyPy performs itself, and so fails without the fix only on PyPy.

"""

import copy
import pickle  # nosec: B403 -- round-trips objects built here
import unittest

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import OrderedMultiDict

#: Test tier (#1958): attribute storage order differs between interpreters.
__tier__ = 'ALL'


class Declared(Info):
    """A field model, whose generated ``__init__`` sets the fields in declared order."""

    a: 'int'
    b: 'int'
    c: 'int'


def relayout(info: 'Info', key: 'str') -> 'None':
    """Move ``key`` to the end of ``info.__dict__``, as PyPy's layout may place it."""
    value = info.__dict__.pop(key)
    info.__dict__[key] = value


class StorageOrderTests(unittest.TestCase):
    """Every reader lists the fields in the order they were set."""

    def assert_order(self, info: 'Info', keys: 'list[str]') -> 'None':
        self.assertEqual(list(info), keys)
        self.assertEqual(list(info.keys()), keys)
        self.assertEqual([key for key, _ in info.items()], keys)
        self.assertEqual([key for key, _ in info.items(multi=True)], keys)
        self.assertEqual(list(info.to_dict().keys()), keys)
        self.assertEqual(len(info), len(keys))
        self.assertEqual([part.split('=')[0] for part in str(info)[len(type(info).__name__) + 1:-1].split(', ')],
                         keys)
        self.assertEqual([part.split('=')[0] for part in repr(info)[len(type(info).__name__) + 2:-1].split(', ')],
                         keys)

    def test_a_bare_info_keeps_the_order_its_fields_were_set_in(self) -> None:
        info = Info(a=1, b=2, c=3)
        relayout(info, 'a')
        self.assert_order(info, ['a', 'b', 'c'])

    def test_a_field_model_keeps_its_declared_order(self) -> None:
        info = Declared(1, 2, 3)
        relayout(info, 'a')
        self.assert_order(info, ['a', 'b', 'c'])

    def test_a_renamed_key_keeps_its_place(self) -> None:
        # ``items`` names a method, so it is stored under a mangled key.
        info = Info(items=1, b=2)
        relayout(info, info.__map__['items'])
        self.assert_order(info, ['items', 'b'])

    def test_a_key_set_again_keeps_its_place(self) -> None:
        info = Info(a=1, b=2)
        info.__update__(a=3)
        relayout(info, 'b')
        relayout(info, 'a')
        self.assert_order(info, ['a', 'b'])
        self.assertEqual(info.a, 3)

    def test_a_repeated_key_is_written_after_the_last_field_set(self) -> None:
        info = Info(a=1, b=2)
        relayout(info, 'a')
        info.__update__(OrderedMultiDict([('a', 3)]))
        self.assertEqual(list(info.items(multi=True)), [('a', 1), ('b', 2), ('a', 3)])
        self.assertEqual(list(info.to_dict().items(multi=True)), [('a', 1), ('b', 2), ('a', 3)])

    def test_a_copy_keeps_the_order_and_records_its_own(self) -> None:
        info = Info(a=1, b=2)
        relayout(info, 'a')
        clone = copy.copy(info)
        self.assertEqual(list(clone), ['a', 'b'])
        clone.__update__(c=3)
        self.assertEqual(list(clone), ['a', 'b', 'c'])
        self.assertEqual(list(info), ['a', 'b'])

    def test_a_pickle_keeps_the_order(self) -> None:
        for info in (Info(a=1, b=2, c=3), Declared(1, 2, 3)):
            with self.subTest(type=type(info).__name__):
                relayout(info, 'a')
                self.assertEqual(list(pickle.loads(pickle.dumps(info))), ['a', 'b', 'c'])  # nosec: B301

    def test_a_field_named_like_the_record_is_a_field(self) -> None:
        info = Info(**{'__order__': 1, 'b': 2})
        self.assertEqual(list(info), ['__order__', 'b'])
        self.assertEqual(info['__order__'], 1)


class EarlierInstanceTests(unittest.TestCase):
    """An earlier instance of the class does not reorder a later one's fields."""

    def test_a_later_instance_keeps_its_own_order(self) -> None:
        # NOTE: a class of its own, so no instance built elsewhere has laid it
        # out first. PyPy lays the second instance out as the first, placing
        # ``hopopt`` last, which is the shape #2003 was found in.
        class Fresh(Info):
            pass

        Fresh(x=1, opts=2, tail=3)
        later = Fresh(x=1, hopopt=0, opts=2, tail=3)
        self.assertEqual(list(later), ['x', 'hopopt', 'opts', 'tail'])
        self.assertEqual(list(later.to_dict().keys()), ['x', 'hopopt', 'opts', 'tail'])


if __name__ == '__main__':
    unittest.main()
