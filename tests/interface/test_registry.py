# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.interface.registry`.

GitHub issue #1519: the registry-entry helpers the registrars share were private
functions of :mod:`pcapkit.foundation.extraction`, imported from there by
:mod:`pcapkit.foundation.traceflow.traceflow`. The owner ruled that they become
public and move to a module of their own under :mod:`pcapkit.interface`. The
registrars' end-to-end behaviour is covered by
``tests/foundation/registry/test_restore_builtin_unit.py``; these tests pin each
helper's own contract.

Everything is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so the classes compared belong
to the import the helpers live in.

"""

import collections
import contextlib
import sys
import types
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: Name of the stand-in module a descriptor resolves against. Not importable, so
#: a test can only see it while :meth:`_loaded` has it in :data:`sys.modules`.
FAKE_MODULE = 'tests_interface_registry_fake'


class _Base(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @contextlib.contextmanager
    def _loaded(self, **attrs):  # type: ignore[no-untyped-def]
        """Put a module named :data:`FAKE_MODULE`, holding ``attrs``, in :data:`sys.modules`."""
        module = types.ModuleType(FAKE_MODULE)
        for name, value in attrs.items():
            setattr(module, name, value)
        with mock.patch.dict(sys.modules, {FAKE_MODULE: module}):
            yield module

    @contextlib.contextmanager
    def _never_resolved(self):  # type: ignore[no-untyped-def]
        """Fail if any :class:`~pcapkit.corekit.module.ModuleDescriptor` imports its class."""
        from pcapkit.corekit.module import ModuleDescriptor

        with mock.patch.object(ModuleDescriptor, 'klass', new_callable=mock.PropertyMock,
                               side_effect=AssertionError('descriptor resolved')):
            yield


class TestPublicSurface(_Base):

    def test_all(self) -> None:
        from pcapkit.interface import registry

        self.assertEqual(registry.__all__, ['same_entry', 'restore_shipped', 'restore_shipped_dumper'])

    def test_callers_share_the_public_helpers(self) -> None:
        from pcapkit.foundation import extraction
        from pcapkit.interface import registry

        for name in registry.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(extraction, name), getattr(registry, name))
                self.assertFalse(hasattr(extraction, f'_{name}'))


class TestSameEntry(_Base):

    def test_identical_entry(self) -> None:
        from pcapkit.interface.registry import same_entry

        class Thing:
            pass

        self.assertTrue(same_entry(Thing, Thing))

    def test_distinct_classes(self) -> None:
        from pcapkit.interface.registry import same_entry

        class Thing:
            pass

        class Other:
            pass

        self.assertFalse(same_entry(Thing, Other))

    def test_descriptors_compare_by_value(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import same_entry

        with self._never_resolved():
            self.assertTrue(same_entry(ModuleDescriptor(FAKE_MODULE, 'Thing'),
                                       ModuleDescriptor(FAKE_MODULE, 'Thing')))
            self.assertFalse(same_entry(ModuleDescriptor(FAKE_MODULE, 'Thing'),
                                        ModuleDescriptor(FAKE_MODULE, 'Other')))

    def test_descriptor_names_loaded_class_either_way_round(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import same_entry

        class Thing:
            pass

        class Other:
            pass

        descriptor = ModuleDescriptor(FAKE_MODULE, 'Thing')
        with self._loaded(Thing=Thing), self._never_resolved():
            self.assertTrue(same_entry(descriptor, Thing))
            self.assertTrue(same_entry(Thing, descriptor))
            self.assertFalse(same_entry(descriptor, Other))
            self.assertFalse(same_entry(Other, descriptor))

    def test_unloaded_module_is_not_imported(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import same_entry

        class Thing:
            pass

        self.assertNotIn(FAKE_MODULE, sys.modules)
        with self._never_resolved():
            self.assertFalse(same_entry(ModuleDescriptor(FAKE_MODULE, 'Thing'), Thing))
        self.assertNotIn(FAKE_MODULE, sys.modules)

    def test_nameless_descriptor_names_nothing(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.corekit.sentinels import NULL
        from pcapkit.interface.registry import same_entry

        with self._loaded(Thing=object), self._never_resolved():
            self.assertFalse(same_entry(ModuleDescriptor(FAKE_MODULE, NULL), object))


class TestRestoreShipped(_Base):

    def test_empty_key_takes_shipped_silently(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import restore_shipped

        shipped = ModuleDescriptor(FAKE_MODULE, 'Thing')
        registry: 'dict' = {}
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            restore_shipped(registry, 'thing', shipped, 'engine')
        self.assertIs(registry['thing'], shipped)

    def test_incumbent_naming_shipped_class_is_kept(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import restore_shipped

        class Thing:
            pass

        shipped = ModuleDescriptor(FAKE_MODULE, 'Thing')
        registry = {'thing': Thing}
        with self._loaded(Thing=Thing), warnings.catch_warnings():
            warnings.simplefilter('error')
            restore_shipped(registry, 'thing', shipped, 'engine')
        self.assertIs(registry['thing'], Thing)  # a no-op: the class is not swapped for the descriptor

    def test_override_is_overwritten_with_warning(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import restore_shipped
        from pcapkit.utilities.warnings import RegistryWarning

        class Custom:
            pass

        shipped = ModuleDescriptor(FAKE_MODULE, 'Thing')
        registry = {'thing': Custom}
        with self.assertWarnsRegex(RegistryWarning, r'^reassembly thing already registered, overwriting$'):
            restore_shipped(registry, 'thing', shipped, 'reassembly')
        self.assertIs(registry['thing'], shipped)


class TestRestoreShippedDumper(_Base):

    def test_override_is_overwritten_with_warning(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import restore_shipped_dumper
        from pcapkit.utilities.warnings import RegistryWarning

        class Custom:
            pass

        shipped = (ModuleDescriptor(FAKE_MODULE, 'Dumper'), '.out')
        for ext, expected in (('.out', shipped), ('.new', (shipped[0], '.new'))):
            with self.subTest(ext=ext):
                registry: 'dict' = {'fmt': (Custom, '.out')}
                with self.assertWarnsRegex(RegistryWarning, r'^dumper fmt already registered, overwriting$'):
                    restore_shipped_dumper(registry, 'fmt', shipped, ext)
                self.assertEqual(registry['fmt'], expected)
                if ext == shipped[1]:
                    self.assertIs(registry['fmt'], shipped)

    def test_same_dumper_same_ext_is_kept(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import restore_shipped_dumper

        class Dumper:
            pass

        shipped = (ModuleDescriptor(FAKE_MODULE, 'Dumper'), '.out')
        incumbent = (Dumper, '.out')
        registry = {'fmt': incumbent}
        with self._loaded(Dumper=Dumper), warnings.catch_warnings():
            warnings.simplefilter('error')
            restore_shipped_dumper(registry, 'fmt', shipped, '.out')
        self.assertIs(registry['fmt'], incumbent)

    def test_same_dumper_new_ext_is_silent(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import restore_shipped_dumper

        class Dumper:
            pass

        shipped = (ModuleDescriptor(FAKE_MODULE, 'Dumper'), '.out')
        for incumbent_ext, ext, expected in (('.out', '.new', (shipped[0], '.new')),
                                             ('.new', '.out', shipped)):
            with self.subTest(incumbent_ext=incumbent_ext, ext=ext):
                registry = {'fmt': (Dumper, incumbent_ext)}
                with self._loaded(Dumper=Dumper), warnings.catch_warnings():
                    warnings.simplefilter('error')
                    restore_shipped_dumper(registry, 'fmt', shipped, ext)
                self.assertEqual(registry['fmt'], expected)
                self.assertIs(registry['fmt'][0], shipped[0])

    def test_defaultdict_lookup_does_not_insert(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.interface.registry import restore_shipped_dumper

        class Fallback:
            pass

        shipped = (ModuleDescriptor(FAKE_MODULE, 'Dumper'), '.out')
        registry: 'collections.defaultdict[str, tuple]' = collections.defaultdict(lambda: (Fallback, '.txt'))
        with warnings.catch_warnings():
            warnings.simplefilter('error')  # a subscript lookup would fabricate a different incumbent
            restore_shipped_dumper(registry, 'fmt', shipped, '.out')
        self.assertEqual(dict(registry), {'fmt': shipped})
        self.assertIs(registry['fmt'], shipped)


if __name__ == '__main__':
    unittest.main()
