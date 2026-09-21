from __future__ import annotations

import sys
import types
import unittest
from unittest import mock

from tests._support import load_module, purge_modules


class ModuleDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self.module = load_module('pcapkit.corekit.module', 'pcapkit/corekit/module.py')

    def _register(self, name: str, module: types.ModuleType) -> None:
        """Put ``module`` in :data:`sys.modules` for the duration of a test."""
        original = sys.modules.get(name)
        sys.modules[name] = module

        def restore() -> None:
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original

        self.addCleanup(restore)

    def test_klass_imports_target_attribute(self) -> None:
        target_module = types.SimpleNamespace(Target=dict)
        with mock.patch('importlib.import_module', return_value=target_module) as importer:
            descriptor = self.module.ModuleDescriptor('demo.module', 'Target')
            self.assertIs(descriptor.klass, dict)

        importer.assert_called_once_with('demo.module')

    def test_klass_reads_an_already_loaded_module_out_of_sys_modules(self) -> None:
        """An already-imported module must not go through the import machinery.

        :attr:`~pcapkit.corekit.module.ModuleDescriptor.klass` sits on a
        per-frame dispatch path -- see GitHub issue #574 -- and
        :func:`importlib.import_module` retains real per-call work even when
        :data:`sys.modules` already holds the module, so re-entering it for
        every unrecognised frame costs ~436 ns against the ~117 ns this
        property takes reading :data:`sys.modules` directly.

        """
        target_module = types.ModuleType('demo.loaded')
        target_module.Target = dict  # type: ignore[attr-defined]
        self._register('demo.loaded', target_module)

        descriptor = self.module.ModuleDescriptor('demo.loaded', 'Target')
        with mock.patch('importlib.import_module',
                        side_effect=RuntimeError('import machinery re-entered')) as importer:
            for _ in range(3):
                self.assertIs(descriptor.klass, dict)

        importer.assert_not_called()

    def test_klass_follows_a_rebound_class_rather_than_keeping_the_first_one(self) -> None:
        """Nothing may be memoised, because a reload rebinds the class.

        The two reload idioms differ and both have to be followed.
        :func:`importlib.reload` re-executes the module body into the *same*
        module object, so the class it defines is a new object while
        ``sys.modules[name]`` is unchanged -- which is why a memo validated
        against the module object's identity would still serve the old class.
        Popping :data:`sys.modules` and importing again replaces the module
        object as well. Both are modelled here directly; GitHub pull request
        #563's class-level cache followed neither, and instances built from the
        class it kept fail :func:`isinstance` against the live one.

        """
        class Old:
            pass

        class New:
            pass

        target_module = types.ModuleType('demo.reloadable')
        target_module.Target = Old  # type: ignore[attr-defined]
        self._register('demo.reloadable', target_module)

        descriptor = self.module.ModuleDescriptor('demo.reloadable', 'Target')
        self.assertIs(descriptor.klass, Old)

        # what importlib.reload does: same module object, new class object
        target_module.Target = New  # type: ignore[attr-defined]
        self.assertIs(descriptor.klass, New)

        # what popping sys.modules and importing again does: new module object
        replacement = types.ModuleType('demo.reloadable')
        replacement.Target = Old  # type: ignore[attr-defined]
        sys.modules['demo.reloadable'] = replacement
        self.assertIs(descriptor.klass, Old)

    def test_klass_defers_to_import_module_for_a_partially_initialised_module(self) -> None:
        """A module whose body is still executing is not a resolution failure.

        :data:`sys.modules` holds a module from the moment its body *starts*
        executing, so a circular import -- or another thread part way through
        importing the same module -- can see it without the class defined yet.
        :func:`importlib.import_module` waits on the per-module import lock,
        which is the behaviour the fast path has to fall back to rather than
        reporting the attribute missing.

        """
        partial = types.ModuleType('demo.partial')  # body still running: no Target
        self._register('demo.partial', partial)

        complete = types.ModuleType('demo.partial')
        complete.Target = dict  # type: ignore[attr-defined]

        descriptor = self.module.ModuleDescriptor('demo.partial', 'Target')
        with mock.patch('importlib.import_module', return_value=complete) as importer:
            self.assertIs(descriptor.klass, dict)

        importer.assert_called_once_with('demo.partial')

    def test_klass_still_raises_attributeerror_for_a_name_that_is_not_there(self) -> None:
        """A genuinely absent name must still fail, and say so.

        The fallback above swallows one :exc:`AttributeError` to retry through
        :func:`importlib.import_module`. A descriptor naming a class that does
        not exist has to come back out of that retry as the same
        :exc:`AttributeError` it always raised, rather than as :data:`None` or
        as a second, more confusing error.

        """
        target_module = types.ModuleType('demo.incomplete')
        self._register('demo.incomplete', target_module)

        descriptor = self.module.ModuleDescriptor('demo.incomplete', 'Missing')
        with mock.patch('importlib.import_module', return_value=target_module):
            with self.assertRaisesRegex(AttributeError, 'Missing'):
                descriptor.klass  # pylint: disable=pointless-statement


if __name__ == '__main__':
    unittest.main()
