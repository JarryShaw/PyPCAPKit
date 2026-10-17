# -*- coding: utf-8 -*-
"""GitHub issue #911's housing half: one module for every sentinel.

The `__all__` half of #911 landed as #916 and is pinned by
:mod:`tests.corekit.test_sentinel_exports_unit`. The owner left the second
question -- where the sentinels should be *defined* -- open, offering
either one module per sentinel or one module for all of them, and settled it with
a one-line ruling once offered the choice: one module for all of them.

So :mod:`pcapkit.corekit.sentinels` is the single defining module for every
sentinel -- :class:`~pcapkit.corekit.sentinels.NullType`,
:class:`~pcapkit.corekit.sentinels.NoValueType`,
:class:`~pcapkit.corekit.sentinels.NoDefaultType` and
:class:`~pcapkit.corekit.sentinels.AbsentType`, and their instances. The
original modules (:mod:`pcapkit.corekit.module`,
:mod:`pcapkit.corekit.fields.field`, :mod:`pcapkit.corekit.enum` and
:mod:`pcapkit.protocols.protocol`) kept a re-export of each until GitHub issue
#1744 dropped them, under the ruling on #1715 that a moved name keeps no
re-export at its old path; ``tests/project/test_no_moved_name_re_exports_1744_unit.py``
pins that. Each still imports the *object* it uses from here.

None of this module exists before that move, which is exactly what makes it a
regression test rather than a description: at ``d31c0aaf6``, a ``main``
commit from before #922, ``import pcapkit.corekit.sentinels`` itself
fails --

.. code-block:: text

   ModuleNotFoundError: No module named 'pcapkit.corekit.sentinels'

-- so every test below, including the module-level import at the top of this
file, fails before its body ever runs. Quoted from an actual run against that
commit, not inferred:

.. code-block:: text

   $ PYTHONPATH=<checkout-at-d31c0aaf6> python -m pytest tests/corekit/test_sentinels_housing_unit.py
   ERRORS
   ImportError while importing test module '.../test_sentinels_housing_unit.py'
   ModuleNotFoundError: No module named 'pcapkit.corekit.sentinels'

:class:`IdentityInConsumersTests` is the load-bearing class here. A sentinel's
entire reason for existing is identity comparison (``value is SENTINEL``), so the
object each consumer module compares against must be the *same* object as the
one :mod:`pcapkit.corekit.sentinels` hands out -- an equal-but-distinct object
would quietly break every ``is NULL`` (etc.) check in that module.
:meth:`IdentityInConsumersTests.test_consumer_binding_and_canonical_object_are_the_same`
asserts that with ``is``, never ``==``.

:class:`NoImportCycleTests` pins the other thing the issue asked to be checked
"on purpose" rather than left to the pre-existing ``cyclic-import`` findings
:command:`pylint` reports for this package, which run to hundreds and would
swallow one more without comment: that :mod:`pcapkit.corekit.sentinels` itself
imports nothing from any of the modules that depend on it, so the
dependency graph between them is a star with :mod:`pcapkit.corekit.sentinels`
at the centre and no edge pointing back into it.

"""
from __future__ import annotations

import importlib
import pickle
import unittest

import pcapkit.corekit.enum as enum_module
import pcapkit.corekit.fields.field as field_module
import pcapkit.corekit.module as module_module
import pcapkit.corekit.sentinels as sentinels
import pcapkit.protocols.protocol as protocol_module
from pcapkit.corekit.sentinels import (ABSENT, NO_DEFAULT, NO_VALUE, NULL, AbsentType,
                                       NoDefaultType, NoValueType, NullType)
from tests._support import purge_modules

#: Every sentinel, as ``(instance name, consumer module, instance, type)``. The
#: consumer module is the one that compares against the object, and so still
#: imports it from :mod:`pcapkit.corekit.sentinels` -- without re-exporting it.
CONSUMED_SENTINELS = (
    ('NULL', module_module, NULL, NullType),
    ('NO_VALUE', field_module, NO_VALUE, NoValueType),
    ('NO_DEFAULT', enum_module, NO_DEFAULT, NoDefaultType),
    ('ABSENT', protocol_module, ABSENT, AbsentType),
)


class IdentityInConsumersTests(unittest.TestCase):
    """A consumer module must compare against the *same* object, not an equal one."""

    def test_consumer_binding_and_canonical_object_are_the_same(self) -> 'None':
        """``is``, not ``==`` -- the whole point of a sentinel.

        Fails on an implementation that re-*constructs* the sentinel in a
        consumer (e.g. ``NULL = NullType()`` in :mod:`pcapkit.corekit.module`
        instead of ``from pcapkit.corekit.sentinels import NULL``), which would
        satisfy every ``isinstance`` check while breaking every ``is`` check.

        """
        for name, consumer, instance, type_ in CONSUMED_SENTINELS:
            with self.subTest(sentinel=name):
                self.assertIs(getattr(consumer, name), instance)
                self.assertIs(instance, getattr(sentinels, name))
                self.assertIs(type(instance), type_)

    def test_defining_module_is_the_canonical_one_for_every_type(self) -> 'None':
        """:attr:`type.__module__` names where the class statement executed."""
        for name, _, _, type_ in CONSUMED_SENTINELS:
            with self.subTest(sentinel=name):
                self.assertEqual(type_.__module__, 'pcapkit.corekit.sentinels')


class NoImportCycleTests(unittest.TestCase):
    """:mod:`pcapkit.corekit.sentinels` must not import back into a consumer.

    The issue's own instruction: check for a cycle *deliberately*, because
    :command:`pylint` already reports hundreds of ``cyclic-import`` findings in
    this package, so one more would be invisible in the noise rather than caught.
    This does not run :command:`pylint` -- that check is done separately and
    reported alongside #922 -- it instead pins the one fact that actually
    rules a cycle out for this specific set of modules: that
    :mod:`pcapkit.corekit.sentinels` imports none of them.

    """

    def test_sentinels_module_imports_none_of_its_four_consumers(self) -> 'None':
        """Parse the source's *import statements*, rather than trust that nothing
        changes them later.

        A cycle here would need :mod:`pcapkit.corekit.sentinels` to import from
        :mod:`pcapkit.corekit.module`, :mod:`pcapkit.corekit.fields.field`,
        :mod:`pcapkit.corekit.enum` or :mod:`pcapkit.protocols.protocol` -- each
        of which imports *it*. Walked with :mod:`ast` rather than grepped for the
        dotted name as plain text, because the module's own docstring above
        names those modules *in prose*, explaining where each sentinel used to live --
        a text search would flag that explanation as if it were the cycle it is
        warning readers there is no longer any risk of.

        """
        import ast
        import pathlib

        source = pathlib.Path(sentinels.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source, filename=sentinels.__file__)

        imported_modules = []  # type: list[str]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_modules.append(node.module)

        forbidden = ('pcapkit.corekit.module', 'pcapkit.corekit.fields.field',
                    'pcapkit.corekit.enum', 'pcapkit.protocols.protocol')
        for name in forbidden:
            with self.subTest(forbidden=name):
                self.assertFalse(
                    any(imported == name or imported.startswith(name + '.')
                        for imported in imported_modules),
                    f'{sentinels.__name__} imports {name!r}: {imported_modules!r}')

    def test_sentinels_module_imports_cleanly_on_its_own(self) -> 'None':
        """A module with no cyclic dependency imports standalone, purged first.

        Purging every ``pcapkit`` entry from :data:`sys.modules` first, so this
        is a cold import rather than a cache hit that would pass regardless of
        whether a cycle exists -- a real cycle raises :exc:`ImportError`
        (*"cannot import name ... from partially initialized module"*) on
        exactly this kind of cold, direct import.

        """
        purge_modules(['pcapkit'])
        try:
            fresh = importlib.import_module('pcapkit.corekit.sentinels')
        finally:
            purge_modules(['pcapkit'])
        self.assertTrue(hasattr(fresh, 'NULL'))
        self.assertTrue(hasattr(fresh, 'NO_VALUE'))
        self.assertTrue(hasattr(fresh, 'NO_DEFAULT'))

    def test_each_consumer_module_still_imports_cleanly_on_its_own(self) -> 'None':
        """The other direction: importing a consumer first must not deadlock either.

        Each consumer is tried as the *first* thing imported after a purge,
        one at a time -- the order a cycle would actually be sensitive to,
        since a cycle through ``pcapkit.corekit.sentinels`` would surface as
        whichever of the two modules is entered second finding the other only
        partially initialised.

        """
        for name in ('pcapkit.corekit.module', 'pcapkit.corekit.fields.field',
                    'pcapkit.corekit.enum', 'pcapkit.protocols.protocol'):
            with self.subTest(first_import=name):
                purge_modules(['pcapkit'])
                try:
                    fresh = importlib.import_module(name)
                finally:
                    purge_modules(['pcapkit'])
                self.assertIsNotNone(fresh)


class SentinelsModuleExportRuleTests(unittest.TestCase):
    """The canonical module follows its own house rule: objects only, in ``__all__``.

    Nothing forces :mod:`pcapkit.corekit.sentinels` to honour the ruling that the
    sentinel objects, and not their types, are what gets exported -- the ruling
    was stated about the shim locations, which #916 already fixed -- but shipping
    a brand new module that violates the rule its own docstring cites would be a
    strange way to land it, so this pins that it does not.

    """

    def test_all_names_the_three_public_objects_and_no_types(self) -> 'None':
        """``ABSENT`` stays out too: it is private regardless of which module
        defines it."""
        self.assertIn('NULL', sentinels.__all__)
        self.assertIn('NO_VALUE', sentinels.__all__)
        self.assertIn('NO_DEFAULT', sentinels.__all__)
        for name in ('NullType', 'NoValueType', 'NoDefaultType',
                     'ABSENT', 'AbsentType'):
            with self.subTest(name=name):
                self.assertNotIn(name, sentinels.__all__)


class PicklePayloadTests(unittest.TestCase):
    """A ``NULL`` pickle names :mod:`pcapkit.corekit.sentinels` and loads back.

    ``NullType.__reduce__`` names ``NULL`` itself by module path, since GitHub
    issue #1842 gave every sentinel that reduce. A pickle written by 1.5.0b5
    or b6, before GitHub issue #911 relocated the definitions, named
    ``pcapkit.corekit.module _get_null`` instead; the re-export that kept
    those loadable was dropped under GitHub issue #1744, since nothing in the
    library reads that path.

    """

    def setUp(self) -> 'None':
        """Resolve the modules afresh rather than using this file's own imports.

        :class:`NoImportCycleTests` purges ``pcapkit*`` from :data:`sys.modules`
        and does not put it back, and it sorts ahead of this class, so the
        module-level :data:`NULL` above is a stale object by now.

        """
        self.sentinels = importlib.import_module('pcapkit.corekit.sentinels')
        self.null = self.sentinels.NULL

    def test_a_freshly_written_payload_names_the_new_home(self) -> 'None':
        """Every protocol names the new home, never the old one, and loads back."""
        for protocol in range(0, pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                blob = pickle.dumps(self.null, protocol=protocol)
                self.assertIn(b'pcapkit.corekit.sentinels', blob)
                self.assertNotIn(b'pcapkit.corekit.module', blob)
                self.assertIs(pickle.loads(blob), self.null)


if __name__ == '__main__':
    unittest.main()
