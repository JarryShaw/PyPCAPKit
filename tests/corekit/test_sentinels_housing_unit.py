# -*- coding: utf-8 -*-
"""GitHub issue #911's housing half: one module for all four sentinels.

The `__all__` half of #911 landed as #916 and is pinned by
:mod:`tests.corekit.test_sentinel_exports_unit`. The owner left the second
question -- where the four sentinels should be *defined* -- open, offering
either one module per sentinel or one module for all of them, and settled it with
a one-line ruling once offered the choice: one module for all four.

So :mod:`pcapkit.corekit.sentinels` is now the single defining module for all
four -- :class:`~pcapkit.corekit.sentinels.NullType`,
:class:`~pcapkit.corekit.sentinels.NoValueType`,
:class:`~pcapkit.corekit.sentinels.NoDefaultType` and
:class:`~pcapkit.corekit.sentinels.AbsentType`, and their four instances -- and
each of the four original modules (:mod:`pcapkit.corekit.module`,
:mod:`pcapkit.corekit.fields.field`, :mod:`pcapkit.corekit.enum` and
:mod:`pcapkit.protocols.protocol`) keeps a re-export so that no existing
``from <module> import <name>`` breaks.

None of this module exists before that move, which is exactly what makes it a
regression test rather than a description: on ``origin/main`` at ``d31c0aaf6``
(the tip this branch was cut from), ``import pcapkit.corekit.sentinels`` itself
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

:class:`IdentityAcrossShimsTests` is the load-bearing class here. A sentinel's
entire reason for existing is identity comparison (``value is SENTINEL``), so the
one thing worth pinning about a re-export shim is not merely that it resolves --
an equal-but-distinct object would make every existing ``import`` line "work"
while quietly breaking every ``is NULL`` (etc.) check downstream -- but that
``from pcapkit.corekit.module import NULL`` and
``from pcapkit.corekit.sentinels import NULL`` hand back the *same* object, for
all four pairs. :meth:`IdentityAcrossShimsTests.test_shim_and_canonical_import_are_the_same_object`
asserts that with ``is``, never ``==``.

:class:`NoImportCycleTests` pins the other thing the issue asked to be checked
"on purpose" rather than left to the 39 pre-existing ``cyclic-import`` findings
:command:`pylint` already reports for this package (which would swallow a 40th
without comment): that :mod:`pcapkit.corekit.sentinels` itself imports nothing
from any of the four modules it is now depended on by, so the dependency graph
between them is a star with :mod:`pcapkit.corekit.sentinels` at the centre and no
edge pointing back into it.

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
from pcapkit.corekit.enum import NO_DEFAULT, NoDefaultType
from pcapkit.corekit.fields.field import NO_VALUE, NoValueType
from pcapkit.corekit.module import NULL, NullType
from pcapkit.protocols.protocol import ABSENT, AbsentType
from tests._support import purge_modules

#: Every sentinel, as ``(instance name, shim module, shim instance, shim type)``.
#: The shim module is the *original* location -- the one whose re-export this
#: pins -- and is deliberately not :mod:`pcapkit.corekit.sentinels` itself, which
#: is what :data:`pcapkit.corekit.sentinels`'s own attributes are compared against
#: in each test below rather than being folded into this tuple a fifth time.
SHIMMED_SENTINELS = (
    ('NULL', module_module, NULL, NullType),
    ('NO_VALUE', field_module, NO_VALUE, NoValueType),
    ('NO_DEFAULT', enum_module, NO_DEFAULT, NoDefaultType),
    ('ABSENT', protocol_module, ABSENT, AbsentType),
)


class IdentityAcrossShimsTests(unittest.TestCase):
    """A re-export must hand back the *same* object, not an equal one."""

    def test_shim_and_canonical_import_are_the_same_object(self) -> 'None':
        """``is``, not ``==`` -- the whole point of a sentinel.

        Fails on an implementation that re-*constructs* the sentinel at each
        shim location (e.g. a shim that says ``NULL = NullType()`` instead of
        ``from pcapkit.corekit.sentinels import NULL``) even though such a shim
        would satisfy every ``isinstance`` check and every existing import
        statement.

        """
        for name, shim_instance, canonical_name in (
            ('NULL', NULL, 'NULL'),
            ('NO_VALUE', NO_VALUE, 'NO_VALUE'),
            ('NO_DEFAULT', NO_DEFAULT, 'NO_DEFAULT'),
            ('ABSENT', ABSENT, 'ABSENT'),
        ):
            with self.subTest(sentinel=name):
                self.assertIs(shim_instance, getattr(sentinels, canonical_name))

    def test_shim_and_canonical_type_are_the_same_class_object(self) -> 'None':
        """The *type*, not only the instance, is one object shared everywhere.

        A shim that rebuilt the type (``class NullType(sentinels.NullType):
        pass``) would let ``isinstance`` checks against either name keep working
        while making ``NullType is sentinels.NullType`` false -- exactly the
        gap an ``is``-only check on the instance above would miss.

        """
        for name, shim_type, canonical_name in (
            ('NullType', NullType, 'NullType'),
            ('NoValueType', NoValueType, 'NoValueType'),
            ('NoDefaultType', NoDefaultType, 'NoDefaultType'),
            ('AbsentType', AbsentType, 'AbsentType'),
        ):
            with self.subTest(sentinel=name):
                self.assertIs(shim_type, getattr(sentinels, canonical_name))

    def test_shim_module_attribute_is_the_same_object_too(self) -> 'None':
        """Reached through the *module*, the way every real caller does it.

        The two tests above import through this module's own ``from ... import``
        statements at the top of the file, which python's import machinery
        could in principle special-case. Re-reading the attribute off each
        shim module object directly rules that out.

        """
        for name, shim_module, shim_instance, shim_type in SHIMMED_SENTINELS:
            with self.subTest(sentinel=name):
                self.assertIs(getattr(shim_module, name), shim_instance)
                self.assertIs(shim_instance, getattr(sentinels, name))
                # The type is read off the *instance* (``type(shim_instance)``)
                # rather than reconstructed from the instance's name, since the
                # house ``<SENTINEL>Type`` name is not a straight capitalisation
                # of every instance name (``NULL`` -> ``NullType``, not
                # ``NULLType``) -- exactly what a caller comparing
                # ``type(value) is NullType`` would do instead of guessing.
                self.assertIs(type(shim_instance), shim_type)

    def test_defining_module_is_the_canonical_one_for_every_type(self) -> 'None':
        """:attr:`type.__module__` names where the class statement executed.

        Distinct from the identity checks above: two different classes could in
        principle report the same ``__module__`` by coincidence, but the same
        *class object* reporting the wrong ``__module__`` would mean something
        rebuilt it under a different name, which is exactly the failure mode
        :meth:`test_shim_and_canonical_type_are_the_same_class_object` also
        guards against from a different angle.

        """
        for name, _, _, shim_type in SHIMMED_SENTINELS:
            with self.subTest(sentinel=name):
                self.assertEqual(shim_type.__module__, 'pcapkit.corekit.sentinels')


class NoImportCycleTests(unittest.TestCase):
    """:mod:`pcapkit.corekit.sentinels` must not import back into a consumer.

    The issue's own instruction: check for a cycle *deliberately*, because
    :command:`pylint` already reports 39 ``cyclic-import`` findings in this
    package, so a fortieth would be invisible in the noise rather than caught.
    This does not run :command:`pylint` -- that check is done separately and
    reported alongside this PR -- it instead pins the one fact that actually
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
        names all four *in prose*, explaining where each sentinel used to live --
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

        Each of the four is tried as the *first* thing imported after a purge,
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


class PreMovePickleStillLoadsTests(unittest.TestCase):
    """A pickle written before the move still unpickles.

    :meth:`NullType.__reduce__` names its factory by module path, so every
    payload written before GitHub issue #911 relocated the definitions carries
    the literal string ``pcapkit.corekit.module _get_null``. Moving the
    function without leaving the name behind makes those payloads unloadable --
    measured as ``AttributeError: module 'pcapkit.corekit.module' has no
    attribute '_get_null'`` -- which is a break in on-disk data rather than in
    the API, and so invisible to every other test here. :data:`NULL` is public
    and is what :attr:`ModuleDescriptor.name` holds, so the payloads are real.

    The fix is one re-exported private name in :mod:`pcapkit.corekit.module`;
    these tests are what stop it being tidied away later as an unused import.

    """

    def setUp(self) -> 'None':
        """Resolve the modules afresh rather than using this file's own imports.

        :class:`NoImportCycleTests` purges ``pcapkit*`` from :data:`sys.modules`
        and does not put it back, and it sorts ahead of this class. The
        module-level :data:`NULL` above is therefore a stale object by the time
        these tests run, whose ``_get_null`` is no longer the one a fresh import
        produces -- which pickle rejects outright with ``Can't pickle …: it's not
        the same object as pcapkit.corekit.sentinels._get_null``. Re-importing
        here keeps these tests measuring the re-export rather than that
        pre-existing ordering hazard.

        """
        self.sentinels = importlib.import_module('pcapkit.corekit.sentinels')
        self.module = importlib.import_module('pcapkit.corekit.module')
        self.null = self.module.NULL

    #: A ``NULL`` payload as the pre-#911 code emitted it.
    #:
    #: Built by pointing the factory's ``__module__`` at its old home for the
    #: duration of the dump, because that attribute is exactly what pickle
    #: consults to name it. Substituting the module string in the finished bytes
    #: does not work: protocols 4 and 5 length-prefix it, so shortening
    #: ``pcapkit.corekit.sentinels`` to ``pcapkit.corekit.module`` leaves a
    #: stale prefix and the payload fails to load as truncated rather than for
    #: the reason under test.
    def _pre_move_payload(self, protocol: 'int') -> 'bytes':
        factory = self.sentinels._get_null
        original = factory.__module__
        factory.__module__ = 'pcapkit.corekit.module'
        try:
            blob = pickle.dumps(self.null, protocol=protocol)
        finally:
            factory.__module__ = original
        self.assertIn(b'pcapkit.corekit.module', blob)
        self.assertNotIn(b'pcapkit.corekit.sentinels', blob)
        return blob

    def test_the_old_factory_name_is_still_reachable(self) -> 'None':
        """The re-export, stated as the property rather than as an import line."""
        self.assertIs(self.module._get_null, self.sentinels._get_null)

    def test_a_pre_move_payload_round_trips_to_the_singleton(self) -> 'None':
        """Not merely "does not raise": it has to hand back *the* ``NULL``.

        From protocol 0, not 2. :meth:`NullType.__reduce__` says it covers
        *"every :mod:`pickle` protocol"* and singles out 0 and 1 as the ones
        that would otherwise reach :func:`copyreg._reconstructor`, so those are
        the protocols the mechanism most exists for and the last ones to leave
        unasserted. Measured: all six name the old path and load back to the
        singleton.

        """
        for protocol in range(0, pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                self.assertIs(pickle.loads(self._pre_move_payload(protocol)), self.null)

    def test_a_freshly_written_payload_names_the_new_home(self) -> 'None':
        """The re-export is for reading old data, not for writing new."""
        blob = pickle.dumps(self.null, protocol=2)
        self.assertIn(b'pcapkit.corekit.sentinels', blob)
        self.assertNotIn(b'pcapkit.corekit.module', blob)


if __name__ == '__main__':
    unittest.main()
