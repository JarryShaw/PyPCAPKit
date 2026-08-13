from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InfoClassTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_finalised_annotated_info_generates_init_and_warns_once_final(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.corekit.version import VersionInfo

        @info_final
        class Point(Info):
            x: int
            y: int

        point = Point(1, 2)
        self.assertEqual(point.x, 1)
        self.assertEqual(point['y'], 2)
        self.assertEqual(str(point), 'Point(x=1, y=2)')
        self.assertEqual(repr(point), '<Point x=1, y=2>')

        with mock.patch('pcapkit.corekit.infoclass.warn') as warn:
            self.assertIs(info_final(Point), Point)
        warn.assert_called_once()

        class BasePoint(Info):
            x: int

        @info_final
        class NamedPoint(BasePoint):
            x: int
            name: str

        named = NamedPoint(3, 'three')
        self.assertEqual(named.to_dict(), {'x': 3, 'name': 'three'})

        version = VersionInfo(1, 2)
        self.assertEqual(version.version, '1.2')
        self.assertEqual(str(version), '1.2')

    def test_auto_finalised_info_mapping_update_and_builtin_key_remapping(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.utilities.exceptions import UnsupportedCall

        class Bag(Info):
            __excluded__ = ['hidden']

        bag = Bag({'items': 'conflict', 'visible': 1, 'hidden': 2}, extra=3)
        self.assertEqual(bag['items'], 'conflict')
        self.assertEqual(list(bag), ['items', 'visible', 'extra'])
        self.assertEqual(len(bag), 6)
        self.assertEqual(str(bag), 'Bag(items=conflict, visible=1, extra=3)')
        self.assertIn('items=', repr(bag))
        self.assertEqual(bag.to_dict(), {'items': 'conflict', 'visible': 1, 'extra': 3})

        with self.assertRaises(UnsupportedCall):
            bag.visible = 9
        with self.assertRaises(UnsupportedCall):
            del bag.visible

    def test_from_dict_iterables_nested_info_and_inherited_metadata(self) -> None:
        from pcapkit.corekit.infoclass import Info

        class Base(Info):
            __additional__ = ['base_additional']
            __excluded__ = ['base_hidden']

        class Child(Base):
            __additional__ = ['child_additional']
            __excluded__ = ['child_hidden']

        self.assertIn('base_additional', Child.__additional__)
        self.assertIn('child_additional', Child.__additional__)
        self.assertIn('base_hidden', Child.__excluded__)
        self.assertIn('child_hidden', Child.__excluded__)

        inner = Info.from_dict(answer=42)
        outer = Child.from_dict([('inner', inner), ('base_hidden', 'skip')], child_hidden='skip',
                                kept='yes')
        self.assertEqual(outer['inner'], inner)
        self.assertIn('inner=Info(...)', repr(outer))
        converted = outer.to_dict()
        self.assertEqual(converted['inner'], {'answer': 42})
        self.assertEqual(converted['kept'], 'yes')
        self.assertNotIn('base_hidden', converted)
        self.assertNotIn('child_hidden', converted)

        self.assertEqual(Info.from_dict({'a': 1}, b=2).to_dict(), {'a': 1, 'b': 2})
        self.assertEqual(Info.from_dict(c=3).to_dict(), {'c': 3})


if __name__ == '__main__':
    unittest.main()
