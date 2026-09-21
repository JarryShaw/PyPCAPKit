"""Regression tests for GitHub issue #574.

A next layer code nobody registered resolves to the fallback
:class:`~pcapkit.corekit.module.ModuleDescriptor` the registry's default factory
produces -- normally :class:`~pcapkit.protocols.misc.raw.Raw`. That resolution is
deliberately **not** written back into the registry, because the registry is a
class-level :class:`collections.defaultdict` and recording a miss in it is the
defect GitHub issues #425/#428 fixed at this layer and #560 fixed at the schema
layer. The cost of not writing it back is that every unrecognised frame resolves
the same descriptor again: 48 of the 52 resolutions an extraction of
:file:`many_interfaces.pcapng` performs.

Proposed by @Ts-Boom in GitHub pull request #563, which paid that cost with a
class-level cache of resolved classes and no invalidation -- so a
:func:`importlib.reload` left it serving the pre-reload class forever. These
tests pin the shape taken instead: the repeats are cheap because
:attr:`ModuleDescriptor.klass <pcapkit.corekit.module.ModuleDescriptor.klass>`
reads :data:`sys.modules` rather than re-entering
:func:`importlib.import_module`, and nothing anywhere retains the class.

Three properties, and the split is deliberate -- the first says the cost is
gone, the other two say what it was not allowed to cost:

:meth:`DefaultDescriptorResolutionTests.test_repeated_miss_does_not_re_enter_the_import_machinery`
    The saving itself, as a call count rather than as a timing. Fails on the
    unfixed tree with one :func:`~importlib.import_module` call per lookup.

:meth:`DefaultDescriptorResolutionTests.test_a_missed_code_can_still_be_registered_without_a_warning`
    The half that any write-back-on-miss implementation breaks: a code that has
    only ever *missed* is still unregistered, so a later genuine
    :meth:`~pcapkit.protocols.protocol.ProtocolBase.register` for it must not
    warn that it is already registered. That warning is the #426/#428 symptom.

:meth:`DefaultDescriptorResolutionTests.test_no_stale_class_survives_a_module_reload`
    The half that any class-caching implementation breaks, #563's included.
    Both reload idioms are covered, because they differ:
    :func:`importlib.reload` rebinds the class inside the *same* module object,
    so validating a memo against the object's identity would not notice it,
    while popping :data:`sys.modules` and importing again mints a new one.
"""
from __future__ import annotations

import collections
import importlib
import importlib.util
import sys
import unittest
import warnings
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Module and class name of the fallback every next layer registry declares.
RAW_MODULE = 'pcapkit.protocols.misc.raw'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DefaultDescriptorResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def tearDown(self) -> None:
        # ``test_no_stale_class_survives_a_module_reload`` leaves a reloaded
        # module behind, whose ``Raw`` is a different object from the one the
        # rest of the imported tree holds. Purging here keeps that confined to
        # the test that did it, rather than handing it to whatever imports
        # :mod:`pcapkit` next.
        purge_modules(['pcapkit'])

    def _dummy_protocol(self) -> type:
        """Build a protocol class with a registry of its own.

        Returns:
            A :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass whose
            ``__proto__`` is a fresh, empty :class:`collections.defaultdict`
            declaring the same :class:`~pcapkit.corekit.module.ModuleDescriptor`
            fallback the real registries do. Fresh, so that a miss recorded by
            accident is visible as a key rather than hidden among the ~90
            registrations a real table carries.

        """
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.protocol import ProtocolBase

        class Dummy(ProtocolBase):
            __proto__ = collections.defaultdict(
                lambda: ModuleDescriptor(RAW_MODULE, 'Raw'),
            )

        return Dummy

    def test_repeated_miss_does_not_re_enter_the_import_machinery(self) -> None:
        """A miss must resolve its fallback without importing it again.

        :func:`importlib.import_module` keeps real per-call work for a module
        that is already imported -- the import lock, the
        :class:`~importlib.machinery.ModuleSpec` check, the ``fromlist`` walk --
        so a registry miss that re-enters it per frame pays ~436 ns per
        resolution where the :data:`sys.modules` path costs ~117 ns.

        Asserted as a call count rather than as a timing on purpose: the
        absolute saving is tens of microseconds against a multi-hundred
        millisecond extraction, which no wall clock on this host can resolve,
        while the count is exact and reproducible.

        """
        Dummy = self._dummy_protocol()
        from pcapkit.protocols.misc.raw import Raw

        imported = []  # type: list[str]
        real_import = importlib.import_module

        def counting_import(name, package=None):  # type: ignore[no-untyped-def]
            imported.append(name)
            return real_import(name, package)

        with mock.patch('importlib.import_module', counting_import):
            for _ in range(5):
                self.assertIs(Dummy._lookup_next_layer(Dummy.__proto__, 99), Raw)

        self.assertEqual([name for name in imported if name == RAW_MODULE], [])

        # and the resolution is still not recorded, which is what it is paying
        # the repeats for in the first place
        self.assertNotIn(99, Dummy.__proto__)
        self.assertEqual(set(Dummy.__proto__), set())

    def test_a_missed_code_can_still_be_registered_without_a_warning(self) -> None:
        """Resolving the fallback must not register the code.

        :meth:`~pcapkit.protocols.protocol.ProtocolBase.register` warns
        ``already registered, overwriting`` for any code already in
        ``__proto__``. So an implementation that memoised the fallback under the
        missed code -- the obvious way to stop the repeats -- would make a
        later, entirely legitimate registration for that code warn about an
        entry that no caller ever asked for. That is the #426/#428 symptom, and
        it is why the repeats are made cheap rather than removed.

        """
        Dummy = self._dummy_protocol()
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.misc.raw import Raw

        for _ in range(5):
            self.assertIs(Dummy._lookup_next_layer(Dummy.__proto__, 99), Raw)
        self.assertNotIn(99, Dummy.__proto__)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            Dummy.register(99, NoPayload)
        self.assertEqual([str(record.message) for record in caught], [])

        # the registration took, and dispatch now reaches it rather than the
        # fallback -- a memoised fallback would have been overwritten silently
        # here, but only after the warning above
        self.assertIs(Dummy.__proto__[99], NoPayload)
        self.assertIs(Dummy._lookup_next_layer(Dummy.__proto__, 99), NoPayload)

    def test_no_stale_class_survives_a_module_reload(self) -> None:
        """Dispatch must reach the live class, not the one resolved first.

        This is the property GitHub pull request #563's ``_MODULE_CACHE`` gave
        up: warm it, reload the module, and it serves the pre-reload class for
        the life of the process, so an instance built from it fails
        :func:`isinstance` against the live one.

        Both reload idioms are exercised because a memo can pass one and fail
        the other. :func:`importlib.reload` re-executes the body into the *same*
        module object, so the new class is a new object while
        ``sys.modules[name]`` is unchanged -- a memo validated against the
        module's identity would keep serving the old class. Popping
        :data:`sys.modules` and importing again replaces the module object too.

        """
        Dummy = self._dummy_protocol()
        raw_module = importlib.import_module(RAW_MODULE)

        warm = Dummy._lookup_next_layer(Dummy.__proto__, 99)
        self.assertIs(warm, raw_module.Raw)

        importlib.reload(raw_module)
        self.assertIsNot(raw_module.Raw, warm)  # the reload really did mint a class
        self.assertIs(sys.modules[RAW_MODULE], raw_module)  # in the same module object
        self.assertIs(Dummy._lookup_next_layer(Dummy.__proto__, 99), raw_module.Raw)

        reloaded = raw_module.Raw
        sys.modules.pop(RAW_MODULE)
        fresh_module = importlib.import_module(RAW_MODULE)
        self.assertIsNot(fresh_module, raw_module)  # a new module object this time
        self.assertIsNot(fresh_module.Raw, reloaded)
        self.assertIs(Dummy._lookup_next_layer(Dummy.__proto__, 99), fresh_module.Raw)


if __name__ == '__main__':
    unittest.main()
