from __future__ import annotations

import copy
import unittest

from tests._support import bootstrap_core_modules, purge_modules


class MultiDictTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        modules = bootstrap_core_modules()
        self.multidict = modules['multidict']
        self.exceptions = modules['exceptions']

    def test_multidict_preserves_multiple_values(self) -> None:
        data = self.multidict.MultiDict([('a', 1), ('a', 2), ('b', 3)])

        self.assertEqual(data['a'], 1)
        self.assertEqual(data.getlist('a'), [1, 2])
        self.assertEqual(list(data.items()), [('a', 1), ('b', 3)])
        self.assertEqual(list(data.items(multi=True)), [('a', 1), ('a', 2), ('b', 3)])
        self.assertEqual(data.to_dict(flat=False), {'a': [1, 2], 'b': [3]})

    def test_multidict_update_extends_existing_keys(self) -> None:
        data = self.multidict.MultiDict({'a': 1})
        data.update({'a': [2, 3], 'b': 4})

        self.assertEqual(data.getlist('a'), [1, 2, 3])
        self.assertEqual(data.getlist('b'), [4])

    def test_multidict_copy_state_defaults_and_empty_list_edges(self) -> None:
        data = self.multidict.MultiDict({'empty': [], 'a': [1, 2], 'b': 3})
        self.assertEqual(repr(self.multidict._missing), 'no value')
        self.assertEqual(self.multidict._missing.__reduce__(), '_missing')
        self.assertNotIn('empty', data)
        self.assertEqual(list(iter(data)), ['a', 'b'])
        self.assertEqual(data.get('missing', 'fallback'), 'fallback')
        self.assertEqual(data.setdefault('a', 99), 1)
        self.assertEqual(data.setdefault('new', 4), 4)
        self.assertEqual(data.getlist('missing'), [])
        data.setlist('a', (5, 6))
        self.assertEqual(data.getlist('a'), [5, 6])
        self.assertIs(data.setlistdefault('a'), dict.__getitem__(data, 'a'))
        self.assertEqual(list(data.values()), [5, 3, 4])
        self.assertEqual(list(data.listvalues()), [[5, 6], [3], [4]])
        self.assertEqual(data.to_dict(), {'a': 5, 'b': 3, 'new': 4})
        self.assertEqual(repr(data), "MultiDict([('a', 5), ('a', 6), ('b', 3), ('new', 4)])")

        copied = self.multidict.MultiDict(data)
        self.assertEqual(copied.getlist('a'), [5, 6])
        copied.add('a', 7)
        self.assertEqual(data.getlist('a'), [5, 6])
        self.assertEqual(copy.copy(data).getlist('a'), [5, 6])
        self.assertEqual(copy.deepcopy(data).getlist('a'), [5, 6])

        state = data.__getstate__()
        restored = self.multidict.MultiDict()
        restored.__setstate__(state.items())
        self.assertEqual(restored.getlist('a'), [5, 6])

        self.assertEqual(data.pop('missing', 'default'), 'default')
        self.assertEqual(data.pop('new'), 4)
        self.assertEqual(data.poplist('missing-list'), [])
        dict.__setitem__(data, 'empty-list', [])
        with self.assertRaises(self.exceptions.MissingKeyError):
            _ = data['empty-list']
        with self.assertRaises(self.exceptions.MissingKeyError):
            data.pop('empty-list')
        dict.__setitem__(data, 'empty-item', [])
        with self.assertRaises(self.exceptions.MissingKeyError):
            data.popitem()
        with self.assertRaises(self.exceptions.MissingKeyError):
            self.multidict.MultiDict().popitem()
        with self.assertRaises(self.exceptions.MissingKeyError):
            self.multidict.MultiDict().popitemlist()

        self.assertEqual(self.multidict.MultiDict({'x': 1}).popitem(), ('x', 1))
        self.assertEqual(self.multidict.MultiDict({'x': [1, 2]}).popitemlist(), ('x', [1, 2]))

    def test_iter_multi_items_handles_all_mapping_shapes(self) -> None:
        pairs = list(self.multidict.iter_multi_items(
            self.multidict.MultiDict([('a', 1), ('a', 2)]),
        ))
        self.assertEqual(pairs, [('a', 1), ('a', 2)])
        self.assertEqual(list(self.multidict.iter_multi_items({'a': [1, 2], 'b': (), 'c': 3})),
                         [('a', 1), ('a', 2), ('c', 3)])
        self.assertEqual(list(self.multidict.iter_multi_items([('x', 1)])), [('x', 1)])

    def test_multidict_setlistdefault_returns_internal_list(self) -> None:
        data = self.multidict.MultiDict()
        values = data.setlistdefault('letters', ['a'])
        values.append('b')

        self.assertEqual(data.getlist('letters'), ['a', 'b'])

    def test_multidict_pop_missing_key_raises_custom_error(self) -> None:
        data = self.multidict.MultiDict()

        with self.assertRaises(self.exceptions.MissingKeyError):
            data.pop('missing')

    def test_ordered_multidict_keeps_insertion_order_for_duplicates(self) -> None:
        data = self.multidict.OrderedMultiDict([('a', 1), ('b', 2), ('a', 3)])

        self.assertEqual(list(data.items()), [('a', 1), ('b', 2)])
        self.assertEqual(list(data.items(multi=True)), [('a', 1), ('b', 2), ('a', 3)])
        self.assertEqual(data.poplist('a'), [1, 3])
        self.assertEqual(list(data.items(multi=True)), [('b', 2)])

    def test_ordered_multidict_state_equality_and_mutation_edges(self) -> None:
        ordered = self.multidict.OrderedMultiDict([('a', 1), ('b', 2), ('a', 3)])
        self.assertTrue(ordered == self.multidict.OrderedMultiDict([('a', 1), ('b', 2), ('a', 3)]))
        self.assertFalse(ordered == self.multidict.OrderedMultiDict([('a', 1), ('a', 3), ('b', 2)]))
        self.assertFalse(ordered == self.multidict.OrderedMultiDict([('a', 1), ('b', 9), ('a', 3)]))
        self.assertFalse(ordered == self.multidict.OrderedMultiDict([('a', 1)]))
        self.assertFalse(self.multidict.OrderedMultiDict([('a', 1)]) == ordered)
        self.assertEqual(ordered.__eq__(object()), NotImplemented)
        self.assertTrue(ordered == self.multidict.MultiDict([('a', 1), ('a', 3), ('b', 2)]))
        self.assertFalse(ordered == self.multidict.MultiDict([('a', 1)]))
        self.assertFalse(ordered == self.multidict.MultiDict([('a', 1), ('a', 4), ('b', 2)]))

        self.assertEqual(list(ordered.keys()), ['a', 'b'])
        self.assertEqual(list(iter(ordered)), ['a', 'b'])
        self.assertEqual(list(ordered.values()), [1, 2])
        self.assertEqual(list(ordered.lists()), [('a', [1, 3]), ('b', [2])])
        self.assertEqual(list(ordered.listvalues()), [[1, 3], [2]])
        self.assertEqual(ordered.getlist('missing'), [])
        self.assertEqual(ordered['a'], 1)
        with self.assertRaises(self.exceptions.MissingKeyError):
            _ = ordered['missing']
        self.assertEqual(ordered.__getstate__(), [('a', 1), ('b', 2), ('a', 3)])
        self.assertEqual(ordered.__reduce_ex__(4)[1], ([('a', 1), ('b', 2), ('a', 3)],))

        restored = self.multidict.OrderedMultiDict()
        restored.__setstate__([('x', 1), ('x', 2)])
        self.assertEqual(list(restored.items(multi=True)), [('x', 1), ('x', 2)])
        restored.setlist('x', [3, 4])
        self.assertEqual(restored.getlist('x'), [3, 4])
        restored['x'] = 5
        self.assertEqual(restored.getlist('x'), [5])
        del restored['x']
        self.assertEqual(restored.getlist('x'), [])

        middle = self.multidict.OrderedMultiDict([('a', 1), ('b', 2), ('c', 3)])
        self.assertEqual(middle.poplist('b'), [2])
        self.assertEqual(list(middle.items(multi=True)), [('a', 1), ('c', 3)])
        self.assertEqual(middle.pop('missing', 'default'), 'default')
        with self.assertRaises(self.exceptions.MissingKeyError):
            middle.pop('missing')
        self.assertIn(middle.popitem()[0], {'a', 'c'})
        self.assertEqual(middle.popitemlist()[0], 'a')
        with self.assertRaises(self.exceptions.MissingKeyError):
            self.multidict.OrderedMultiDict().popitem()
        with self.assertRaises(self.exceptions.MissingKeyError):
            self.multidict.OrderedMultiDict().popitemlist()

    def test_ordered_multidict_rejects_setlistdefault(self) -> None:
        data = self.multidict.OrderedMultiDict()

        with self.assertRaises(self.exceptions.UnsupportedCall):
            data.setlistdefault('key', [1])


if __name__ == '__main__':
    unittest.main()
