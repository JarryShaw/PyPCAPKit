from __future__ import annotations

import copy
import pickle
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

    def test_klass_raises_protocolerror_for_a_name_that_is_not_there(self) -> None:
        """A genuinely absent name must still fail, and say so.

        The fallback above swallows one :exc:`AttributeError` to retry through
        :func:`importlib.import_module`. A descriptor naming a class that does
        not exist has to come back out of that retry naming the same missing
        attribute it always did -- but as :exc:`~pcapkit.utilities.\
exceptions.ProtocolError` rather than the bare stdlib :exc:`AttributeError`,
        so every one of the nine ``register_*`` call sites that build a
        descriptor from a bad class name fails as a :mod:`pcapkit` error a
        caller can actually catch. GitHub issue #832.

        """
        target_module = types.ModuleType('demo.incomplete')
        self._register('demo.incomplete', target_module)

        descriptor = self.module.ModuleDescriptor('demo.incomplete', 'Missing')
        with mock.patch('importlib.import_module', return_value=target_module):
            with self.assertRaisesRegex(self.module.ProtocolError, 'Missing') as caught:
                descriptor.klass  # pylint: disable=pointless-statement
        self.assertNotIsInstance(caught.exception, AttributeError)
        self.assertIn('demo.incomplete', str(caught.exception))

    def test_klass_raises_protocolerror_when_class_name_was_never_given(self) -> None:
        """An omitted ``class_`` must not be reported as an absent attribute.

        A descriptor built with :data:`NULL` for its ``name`` -- what every
        ``register_*`` wrapper does when a :class:`str` ``module`` is given
        with no ``class_`` -- means the caller omitted a required argument,
        not that they asked for a class literally named ``'(null)'``. Saying
        so is the point of GitHub issues #832 and #833 together: the sentinel
        must never reach :func:`getattr`, so the failure never mentions
        ``'(null)'`` at all, and it must not depend on :func:`importlib.\
import_module` or :data:`sys.modules` succeeding -- the omission is caught
        before either is consulted.

        """
        descriptor = self.module.ModuleDescriptor('demo.omitted', self.module.NULL)
        with mock.patch('importlib.import_module',
                        side_effect=RuntimeError('must not be reached')) as importer:
            with self.assertRaises(self.module.ProtocolError) as caught:
                descriptor.klass  # pylint: disable=pointless-statement
        importer.assert_not_called()
        message = str(caught.exception)
        self.assertIn('demo.omitted', message)
        self.assertNotIn('(null)', message)

    def test_klass_treats_an_explicit_null_string_as_a_real_class_name(self) -> None:
        """``class_='(null)'`` is a class name, not the sentinel.

        Before GitHub issue #833, :data:`NULL` was the plain :class:`str`
        ``'(null)'``, so a descriptor built with that exact string was
        indistinguishable from one built from the sentinel default -- an
        equal-but-distinct string took whichever branch the identity check
        happened to land on. The sentinel is no longer a :class:`str` at all,
        so ``'(null)'`` now always resolves as an ordinary (missing) class
        name, and the failure names it like any other bad class name would.

        """
        target_module = types.ModuleType('demo.explicit_null')
        self._register('demo.explicit_null', target_module)

        descriptor = self.module.ModuleDescriptor('demo.explicit_null', '(null)')
        self.assertIsNot(descriptor.name, self.module.NULL)
        with self.assertRaisesRegex(self.module.ProtocolError, r"'\(null\)'"):
            descriptor.klass  # pylint: disable=pointless-statement

    def test_null_sentinel_is_not_a_string(self) -> None:
        """:data:`NULL` means "absent", and nothing else compares equal to it.

        The pre-#833 sentinel was the plain string ``'(null)'``, compared by
        identity -- so an equal-but-distinct ``'(null)'`` from a caller took a
        different branch than the sentinel itself, purely as a function of
        string interning. :data:`NULL` is now a dedicated
        :class:`~pcapkit.corekit.module.NullType` singleton, so no string a
        caller passes can compare equal to it by ``==`` or by ``is``.

        "Singleton" is asserted here, not only claimed: calling
        :class:`~pcapkit.corekit.module.NullType` a second time must hand
        back :data:`NULL` itself rather than a distinct, equally-valid
        instance -- see :meth:`test_null_sentinel_identity_survives_copy_and_pickle`
        for what a second instance breaks downstream.

        """
        self.assertNotIsInstance(self.module.NULL, str)
        self.assertIsInstance(self.module.NULL, self.module.NullType)
        self.assertFalse(self.module.NULL == '(null)')  # pylint: disable=unneeded-not
        self.assertIsNot(self.module.NULL, '(null)')
        self.assertFalse(bool(self.module.NULL))
        self.assertEqual(repr(self.module.NULL), '<NULL>')
        self.assertIs(self.module.NullType(), self.module.NULL)

    def test_null_sentinel_identity_survives_copy_and_pickle(self) -> None:
        """:data:`NULL` stays the same object through :mod:`copy` and :mod:`pickle`.

        Before this fix, :class:`~pcapkit.corekit.module.NullType` had no
        :meth:`~pcapkit.corekit.module.NullType.__copy__`,
        :meth:`~pcapkit.corekit.module.NullType.__deepcopy__` or
        :meth:`~pcapkit.corekit.module.NullType.__reduce__` of its own, so
        :func:`copy.copy`, :func:`copy.deepcopy` and every :mod:`pickle`
        protocol fell back to the default behaviour for a plain object and
        each produced a *second*, non-identical :class:`NullType` instance.
        Measured on GitHub pull request #835's head, ``375b50c85``: this
        test's ``copy.deepcopy`` and ``pickle`` assertions below all fail
        with an :class:`AssertionError` there, since the round-tripped object
        ``is not`` :data:`NULL`.

        Every pickle protocol the running interpreter supports -- ``0``
        through :data:`pickle.HIGHEST_PROTOCOL` -- is exercised, not only the
        default one, because :mod:`pickle` protocols 0 and 1 reconstruct
        through :func:`copyreg._reconstructor` -- which calls
        :func:`object.__new__` directly -- rather than through
        :meth:`NullType.__new__ <pcapkit.corekit.module.NullType.__new__>`,
        so a fix that only guards ``__new__`` would still fail those two.

        Each protocol's assertion also runs a second time, outside
        :meth:`~unittest.TestCase.subTest`, and the results are asserted
        together at the end. This repository's ``pytest-subtests`` reports
        the *parent* test node as passed when only a ``subTest`` failed inside
        it -- confirmed by reproducing it directly: a single failing
        ``subTest`` iteration renders its own ``SUBFAILED`` line while the
        owning test method's own line still reads ``PASSED`` -- so a
        regression confined to one protocol would otherwise be visible only
        to something that reads the ``SUBFAILED`` line specifically. The
        plain assertion below has no such blind spot: it fails the test
        method itself, the ordinary way, regardless of which protocol(s)
        misbehaved.

        """
        NULL = self.module.NULL

        self.assertIs(copy.copy(NULL), NULL)
        self.assertIs(copy.deepcopy(NULL), NULL)

        bad_protocols = []
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            roundtripped = pickle.loads(pickle.dumps(NULL, protocol=protocol))
            with self.subTest(protocol=protocol):
                self.assertIs(roundtripped, NULL)
            if roundtripped is not NULL:
                bad_protocols.append(protocol)
        self.assertEqual(bad_protocols, [],
                         f'pickle protocol(s) {bad_protocols} did not round-trip to NULL by identity')

    def test_klass_raises_protocolerror_not_typeerror_after_deepcopying_the_descriptor(self) -> None:
        """Deepcopying a :class:`ModuleDescriptor` must not degrade its error.

        :attr:`~pcapkit.corekit.module.ModuleDescriptor.klass` checks
        ``self.name is NULL`` to tell "the caller never named a class" apart
        from "the caller named a class that does not exist" -- see
        :meth:`test_klass_raises_protocolerror_when_class_name_was_never_given`.
        Before this fix, :func:`copy.deepcopy` on the descriptor recursed into
        that check's operand and minted a second, non-identical
        :class:`~pcapkit.corekit.module.NullType`, so the identity check
        failed silently and ``self.name`` -- still that stray sentinel, now
        masquerading as an ordinary class name -- reached :func:`getattr`
        directly. :func:`getattr` on a non-:class:`str` name raises a bare
        :exc:`TypeError` that :meth:`klass` does not catch, downgrading what
        should be a clean :exc:`~pcapkit.utilities.exceptions.ProtocolError`
        into ``TypeError: attribute name must be string, not 'NullType'``.
        Measured on GitHub pull request #835's head, ``375b50c85``: the
        ``assertRaises(self.module.ProtocolError)`` below does not catch that
        :exc:`TypeError` there, since :exc:`ProtocolError` derives from
        :exc:`BaseError` and :exc:`ValueError`, never :exc:`TypeError`, so the
        test fails with the :exc:`TypeError` propagating out uncaught.

        The target module is registered directly into :data:`sys.modules`,
        the same way :meth:`_register` does for every other test in this
        file, rather than named without registering it: an unregistered name
        fails at :func:`importlib.import_module` with
        :exc:`ModuleNotFoundError` before :func:`getattr` is ever reached,
        which would not exhibit this at all.

        """
        target_module = types.ModuleType('demo.deepcopy_target')
        self._register('demo.deepcopy_target', target_module)

        descriptor = self.module.ModuleDescriptor('demo.deepcopy_target', self.module.NULL)
        copied = copy.deepcopy(descriptor)

        with self.assertRaises(self.module.ProtocolError):
            copied.klass  # pylint: disable=pointless-statement


if __name__ == '__main__':
    unittest.main()
