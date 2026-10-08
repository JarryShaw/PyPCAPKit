# -*- coding: utf-8 -*-
"""The ``tree`` dumper writes a :class:`complex` number instead of raising.

GitHub issue #1266: :meth:`dictdumper.tree.Tree._append_number` hands every
number to :func:`math.isnan`, which raises ``TypeError: must be real number, not
complex`` for the :class:`complex` values :class:`~dictdumper.tree.Tree` routes
there. :func:`~pcapkit.dumpkit.common.make_dumper` now writes those itself, in
the writer's own ``-> <number>`` style. ``json`` and ``plist`` are untouched:
they already write a :class:`complex` as the string ``(1+2j)``.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so that the
dumper is built from the import that is live for this class.

"""

import json
import os
import plistlib
import tempfile
import unittest

from tests._support import reimport_once_per_class

#: Name passed to every dumper call.
NAME = 'x'


class TestTreeComplexNumbers(unittest.TestCase):
    """Pin how each writer renders a :class:`complex` value."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def dump(self, writer: str, value: object) -> str:
        """Write ``value`` through ``make_dumper(dictdumper.<writer>)``."""
        import importlib

        dictdumper = importlib.import_module('dictdumper')
        common = importlib.import_module('pcapkit.dumpkit.common')

        path = os.path.join(self.tmp, f'{writer}.out')
        dumper = common.make_dumper(getattr(dictdumper, writer))(path)
        dumper(value, name=NAME)
        with open(path, encoding='utf-8') as file:
            return file.read()

    def test_tree_writes_top_level_complex(self) -> None:
        self.assertEqual(self.dump('Tree', {'c': 1 + 2j}),
                         f'{NAME}\n  |-- c -> (1+2j)\n')

    def test_tree_writes_nested_complex(self) -> None:
        text = self.dump('Tree', {'outer': {'inner': -0.5 - 3j}})
        self.assertIn('|-- inner -> (-0.5-3j)', text)

    def test_tree_writes_complex_in_list(self) -> None:
        text = self.dump('Tree', {'items': [1, 2j, 1.5]})
        self.assertIn('-> 2j', text)
        self.assertIn('-> 1', text)
        self.assertIn('-> 1.5', text)

    def test_tree_spells_non_finite_parts_as_for_float(self) -> None:
        text = self.dump('Tree', {'c': complex(float('inf'), float('nan')),
                                  'f': float('inf')})
        self.assertIn('|-- c -> (Infinity+NaNj)', text)
        self.assertIn('|-- f -> Infinity', text)

    def test_tree_writes_real_numbers_as_upstream(self) -> None:
        self.assertEqual(self.dump('Tree', {'i': 1, 'f': 1.5, 'n': float('nan')}),
                         f'{NAME}\n  |-- i -> 1\n  |-- f -> 1.5\n  |-- n -> NaN\n')

    def test_json_and_plist_keep_complex_as_string(self) -> None:
        value = {'c': 1 + 2j, 'outer': {'inner': 2j}, 'items': [2j]}
        expected = {NAME: {'c': '(1+2j)', 'outer': {'inner': '2j'}, 'items': ['2j']}}
        self.assertEqual(
            self.dump('JSON', value),
            '{\n\t"x": {\n\t\t"c": "(1+2j)",\n\t\t"outer": {\n\t\t\t"inner": "2j"\n'
            '\t\t},\n\t\t"items": [ "2j" ]\n\t}\n}',
        )
        self.assertEqual(json.loads(self.dump('JSON', value)), expected)
        self.assertEqual(plistlib.loads(self.dump('PLIST', value).encode('utf-8')), expected)

    def test_only_tree_overrides_append_number(self) -> None:
        import importlib

        dictdumper = importlib.import_module('dictdumper')
        common = importlib.import_module('pcapkit.dumpkit.common')

        for writer in ('JSON', 'PLIST'):
            with self.subTest(writer=writer):
                upstream = getattr(dictdumper, writer)
                self.assertNotIn('_append_number', vars(common.make_dumper(upstream)))


if __name__ == '__main__':
    unittest.main()
