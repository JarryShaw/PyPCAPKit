from __future__ import annotations

import decimal
import enum
import sys
import unittest
from unittest import mock

from tests._support import load_module, purge_modules


class CompatTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self.compat = load_module('pcapkit.utilities.compat', 'pcapkit/utilities/compat.py')

    def test_cached_property_only_computes_once(self) -> None:
        class Demo:
            def __init__(self) -> None:
                self.calls = 0

            @self.compat.cached_property
            def value(self) -> int:
                self.calls += 1
                return 42

        demo = Demo()
        self.assertEqual(demo.value, 42)
        self.assertEqual(demo.value, 42)
        self.assertEqual(demo.calls, 1)

    def test_localcontext_applies_keyword_overrides(self) -> None:
        original_prec = decimal.getcontext().prec
        with self.compat.localcontext(prec=7) as ctx:
            self.assertEqual(ctx.prec, 7)
            self.assertEqual(decimal.getcontext().prec, 7)
        self.assertEqual(decimal.getcontext().prec, original_prec)

    def test_show_flag_values_returns_individual_bits(self) -> None:
        class DemoFlag(enum.IntFlag):
            READ = 1
            WRITE = 2
            EXEC = 4

        self.assertEqual(self.compat.show_flag_values(DemoFlag.READ | DemoFlag.EXEC), [1, 4])

    def test_python35_fallback_implementations(self) -> None:
        purge_modules(['pcapkit.utilities.compat_py35'])
        with mock.patch.object(sys, 'version_info', (3, 5)):
            compat = load_module('pcapkit.utilities.compat_py35', 'pcapkit/utilities/compat.py')

        self.assertTrue(issubclass(compat.ModuleNotFoundError, ImportError))

        class CollectionLike:
            def __len__(self): return 0
            def __iter__(self): return iter(())
            def __contains__(self, item): return False

        class BrokenCollection:
            __len__ = None
            def __iter__(self): return iter(())
            def __contains__(self, item): return False

        class BaseCollection:
            def __len__(self): return 0
            def __iter__(self): return iter(())
            def __contains__(self, item): return False

        class DerivedCollection(BaseCollection):
            pass

        class MissingCollection:
            def __len__(self): return 0
            def __iter__(self): return iter(())

        self.assertTrue(compat.Collection.__subclasshook__(CollectionLike))
        self.assertTrue(compat.Collection.__subclasshook__(DerivedCollection))
        self.assertEqual(compat.Collection.__subclasshook__(BrokenCollection), NotImplemented)
        self.assertEqual(compat.Collection.__subclasshook__(MissingCollection), NotImplemented)

        class Demo:
            def __init__(self) -> None:
                self.calls = 0

            @compat.cached_property
            def value(self) -> int:
                self.calls += 1
                return 10

        demo = Demo()
        self.assertEqual(demo.value, 10)
        self.assertEqual(demo.value, 10)
        self.assertEqual(demo.calls, 1)
        self.assertIs(Demo.__dict__['value'].__get__(None, Demo), Demo.__dict__['value'])
        self.assertEqual(Demo.__dict__['value'].__get__(demo, Demo), 10)

        prop = compat.cached_property(lambda self: 1)
        prop.__set_name__(Demo, 'first')
        prop.__set_name__(Demo, 'first')
        with self.assertRaises(TypeError):
            prop.__set_name__(Demo, 'second')

        class SlotDemo:
            __slots__ = ()

        prop = compat.cached_property(lambda self: 1)
        prop.__set_name__(SlotDemo, 'value')
        with self.assertRaises(TypeError):
            prop.__get__(SlotDemo(), SlotDemo)

        original_prec = decimal.getcontext().prec
        with compat.localcontext(prec=9) as ctx:
            self.assertEqual(ctx.prec, 9)
        self.assertEqual(decimal.getcontext().prec, original_prec)

        class OldFlag(enum.IntFlag):
            READ = 1
            EXEC = 4

        self.assertEqual(compat.show_flag_values(OldFlag.READ | OldFlag.EXEC), [1, 4])
        self.assertEqual(list(compat._iter_bits_lsb(0)), [])
        with self.assertRaises(ValueError):
            compat.show_flag_values(-1)


if __name__ == '__main__':
    unittest.main()
