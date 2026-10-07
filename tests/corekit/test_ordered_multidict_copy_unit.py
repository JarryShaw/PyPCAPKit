# -*- coding: utf-8 -*-
"""Copies of an :class:`OrderedMultiDict` keep its insertion order.

GitHub issue #1295: :meth:`MultiDict.deepcopy
<pcapkit.corekit.multidict.MultiDict.deepcopy>` (a verbatim werkzeug port)
rebuilds from ``to_dict(flat=False)``, which groups values by key. An
:class:`~pcapkit.corekit.multidict.OrderedMultiDict` with interleaved keys
therefore deep-copied into a different order and compared unequal to itself.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, for the reason given in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import copy
import pickle
import unittest

from tests._support import reimport_once_per_class

#: Interleaved keys, so grouping by key changes the order.
ITEMS = [('a', 1), ('b', 2), ('a', 3)]


class TestOrderedMultiDictCopy(unittest.TestCase):
    """Pin the order of every copy path."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_copy_path_keeps_insertion_order(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict

        omd = OrderedMultiDict(ITEMS)
        copies = {
            'copy.deepcopy': copy.deepcopy(omd),
            '.deepcopy': omd.deepcopy(),
            'copy.copy': copy.copy(omd),
            '.copy': omd.copy(),
            'pickle': pickle.loads(pickle.dumps(omd)),
        }
        for name, clone in copies.items():
            with self.subTest(path=name):
                self.assertIs(type(clone), OrderedMultiDict)
                self.assertEqual(list(clone.items(multi=True)), ITEMS)
                self.assertEqual(clone, omd)

    def test_deepcopy_copies_values_and_shares_the_memo(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict

        shared = [0]
        omd = OrderedMultiDict([('a', shared), ('b', 2), ('a', shared)])
        clone = copy.deepcopy(omd)
        first, second = clone.getlist('a')
        self.assertIsNot(first, shared)
        self.assertIs(first, second)
        self.assertEqual(list(clone.keys()), ['a', 'b'])


if __name__ == '__main__':
    unittest.main()
