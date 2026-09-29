# -*- coding: utf-8 -*-
"""GitHub issue #911: a sentinel exports its **object**, never its type.

The owner's ruling, verbatim: *"One thing about sentinel types and objects in the
library: we should ONLY export the objects (like* ``NULL`` *) to users."* That is
one rule with two directions, and the tree on ``origin/main`` broke it in both:

* ``pcapkit.corekit.module.__all__`` was ``['NULL', 'NullType', 'ModuleDescriptor']``
  -- the type is exported;
* ``pcapkit.corekit.enum.__all__`` was
  ``['NO_DEFAULT', 'NoDefaultType', 'EnumLookup', 'EnumRegistry']`` -- likewise;
* ``pcapkit.corekit.fields.field.__all__`` was ``['Field']`` -- the *object* is
  missing, so this one needs a name added rather than removed.

So two names come out and one goes in, which is why the fix is not "remove the
types". :class:`SentinelExportTests` asserts the shape in both directions and per
module, rather than as one aggregate that a half-applied change would still satisfy.

What only ``import *`` narrows: the type stays importable by its dotted path, so
``from pcapkit.corekit.module import NullType`` keeps working and an annotation
naming it keeps resolving. That is the whole extent of the breaking change the issue
is labelled for, and
:meth:`SentinelExportTests.test_every_sentinel_type_is_still_importable_by_name`
pins it so a later reading of the ruling cannot escalate into deleting the types.

The population is **four**, not the three
:file:`docs/source/contributing/conventions.rst` documented -- ``_Absent`` /
``_AbsentType`` in :mod:`pcapkit.protocols.protocol` is the fourth, missed because a
sweep filtered on capitalised names does not see a leading underscore.
:class:`SentinelPopulationTests` pins the count and the doc together, so the next
sentinel cannot be added to one without the other. ``_Absent`` is private and stays
out of :attr:`__all__` in both directions, which is what the ruling means by "to
users".

A follow-up to this same issue moved all four *definitions* into
:mod:`pcapkit.corekit.sentinels`, per the owner's later ruling -- *"Okay one module
for all four it is."* Every assertion above still holds unchanged, since it is about
each original module's ``__all__``, which the re-export shims left untouched; what
changed is only :attr:`type.__module__` for the four types, which
:meth:`SentinelExportTests.test_every_sentinel_type_is_still_importable_by_name` now
checks against :data:`CANONICAL_MODULE` rather than against a different module per
sentinel.

One sentinel is deliberately **not** held to any of this: ``_NOT_FOUND = object()``
at :file:`pcapkit/utilities/compat.py`, line 73, inside the ``cached_property``
backport for interpreters below 3.8. It is ported code and exempt, and
:meth:`SentinelPopulationTests.test_the_vendored_bare_object_sentinel_is_left_alone`
pins that as an exemption rather than leaving it to read as an oversight against the
"why a class and not ``object()``" rule.

On the tree before this change, four of these fail:

* ``test_module_exports_the_object_and_not_the_type`` -- ``'NullType'`` is in
  :attr:`__all__`;
* ``test_enum_exports_the_object_and_not_the_type`` -- ``'NoDefaultType'`` is;
* ``test_field_exports_the_object_and_not_the_type`` -- ``'NoValue'`` is not;
* ``test_star_import_binds_the_objects_and_not_the_types`` -- all three of the above,
  through the one operation that actually reads :attr:`__all__`.

and two more fail on the documentation half:

* ``test_conventions_doc_lists_every_sentinel_in_the_tree`` -- the table has three
  rows and the prose says "three";
* ``test_conventions_doc_carves_out_the_vendored_bare_object`` -- the carve-out is
  not there at all.

The rest pass either way and are regression guards: the sibling exports that must
survive the edit (``ModuleDescriptor``, ``Field``, ``EnumLookup``,
``EnumRegistry``), the types staying importable, and the naming convention itself.

"""
from __future__ import annotations

import pathlib
import re
import unittest

from pcapkit.corekit.enum import NO_DEFAULT, NoDefaultType
from pcapkit.corekit.fields.field import NoValue, NoValueType
from pcapkit.corekit.module import NULL, NullType
from pcapkit.protocols.protocol import _Absent, _AbsentType

#: Repository root, for the two tests that read a file rather than import it.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Where all four sentinels are now *defined*, since GitHub issue #911's housing
#: move -- *"Okay one module for all four it is."* Each entry in :data:`SENTINELS`
#: below used to name a different module here (``pcapkit.corekit.module``,
#: ``pcapkit.corekit.fields.field``, ``pcapkit.corekit.enum`` and
#: ``pcapkit.protocols.protocol`` respectively); all four now report this one.
CANONICAL_MODULE = 'pcapkit.corekit.sentinels'

#: Every sentinel in the tree that follows the house ``<SENTINEL>Type`` convention,
#: as ``(instance name, instance, type)``. Four, not the three
#: :file:`docs/source/contributing/conventions.rst` used to document -- see the module docstring.
#: All four now share :data:`CANONICAL_MODULE` as their defining module, which is
#: why a per-entry module column is no longer part of this tuple -- see
#: :data:`PUBLIC_SENTINELS` below for the (still distinct) *shim* locations.
SENTINELS = (
    ('NULL', NULL, NullType),
    ('NoValue', NoValue, NoValueType),
    ('NO_DEFAULT', NO_DEFAULT, NoDefaultType),
    ('_Absent', _Absent, _AbsentType),
)

#: The public three of :data:`SENTINELS`, as ``(module, object name, type name)``.
#: ``_Absent`` is absent from it deliberately: it is private, so it is exported
#: neither way and the export rule does not reach it.
PUBLIC_SENTINELS = (
    ('pcapkit.corekit.module', 'NULL', 'NullType'),
    ('pcapkit.corekit.fields.field', 'NoValue', 'NoValueType'),
    ('pcapkit.corekit.enum', 'NO_DEFAULT', 'NoDefaultType'),
)


def _expected_type_name(instance_name: 'str') -> 'str':
    """The type name the house convention derives from an instance name.

    ``NULL`` gives ``NullType`` and ``NO_DEFAULT`` gives ``NoDefaultType``, so an
    all-caps name is title-cased word by word. ``NoValue`` is already CamelCase and
    is left as it is -- ``str.capitalize`` would lowercase its tail into
    ``Novalue``. A leading underscore is carried through, which is what makes
    ``_Absent`` give ``_AbsentType`` rather than ``AbsentType``.

    """
    lead = '_' if instance_name.startswith('_') else ''
    bare = instance_name.lstrip('_')
    if bare.isupper():
        bare = ''.join(word.capitalize() for word in bare.split('_'))
    return f'{lead}{bare}Type'


def _star_import(module: 'str') -> 'dict[str, object]':
    """The namespace ``from <module> import *`` binds.

    The only operation that actually reads :attr:`__all__`, which is why the export
    rule is asserted through it and not only against the list literal.

    """
    namespace = {}  # type: dict[str, object]
    exec(f'from {module} import *', namespace)  # pylint: disable=exec-used
    return namespace


def _sentinel_section() -> 'str':
    """The "Naming a sentinel" section of :file:`docs/source/contributing/conventions.rst`.

    Sliced by its own section markers rather than by line number, so an edit
    elsewhere in the file -- or the move to
    :file:`docs/source/contributing/conventions.rst` that GitHub pull request #912
    is making -- does not silently make this read the wrong text.

    """
    for candidate in ('docs/source/conventions.rst',
                      'docs/source/contributing/conventions.rst'):
        path = ROOT / candidate
        if path.is_file():
            break
    else:  # pragma: no cover
        raise AssertionError('conventions.rst not found under docs/source')

    text = path.read_text(encoding='utf-8')
    start = text.index('.. _sentinel-convention:')
    end = text.index('.. _registry-protocol:', start)
    return text[start:end]


class SentinelExportTests(unittest.TestCase):
    """``__all__`` names the object and not the type, per module."""

    def test_module_exports_the_object_and_not_the_type(self) -> 'None':
        """``['NULL', 'NullType', 'ModuleDescriptor']`` loses the middle entry.

        ``ModuleDescriptor`` is not a sentinel and has to survive the edit, which
        is asserted here rather than in a separate test because removing it is the
        plausible way to get this line wrong.

        """
        import pcapkit.corekit.module as module

        self.assertIn('NULL', module.__all__)
        self.assertNotIn('NullType', module.__all__)
        self.assertIn('ModuleDescriptor', module.__all__)

    def test_enum_exports_the_object_and_not_the_type(self) -> 'None':
        """``EnumLookup`` and ``EnumRegistry`` are not sentinels and stay.

        ``EnumLookup`` in particular: GitHub issue #906 split it out as a public
        base and :file:`docs/source/contributing/conventions.rst` cites its ``get``, so dropping
        it while removing the sentinel type next to it would break that reference.

        """
        import pcapkit.corekit.enum as enum

        self.assertIn('NO_DEFAULT', enum.__all__)
        self.assertNotIn('NoDefaultType', enum.__all__)
        self.assertIn('EnumLookup', enum.__all__)
        self.assertIn('EnumRegistry', enum.__all__)

    def test_field_exports_the_object_and_not_the_type(self) -> 'None':
        """The direction that is an *addition*: ``NoValue`` was exported by neither.

        :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`
        is documented as being this object, so the ruling reaches it: a value a
        caller is told to compare against is a value ``import *`` should provide.

        """
        import pcapkit.corekit.fields.field as field

        self.assertIn('NoValue', field.__all__)
        self.assertNotIn('NoValueType', field.__all__)
        self.assertIn('Field', field.__all__)

    def test_star_import_binds_the_objects_and_not_the_types(self) -> 'None':
        """Through ``import *`` itself, which is the surface the ruling is about."""
        for module, obj, type_ in PUBLIC_SENTINELS:
            namespace = _star_import(module)
            with self.subTest(module=module):
                self.assertIn(obj, namespace)
                self.assertNotIn(type_, namespace)

    def test_star_import_hands_back_the_canonical_object(self) -> 'None':
        """Not merely *a* binding of that name -- the one sentinel instance.

        A star-import that bound a second, non-identical object would satisfy the
        test above and break every ``is`` check the sentinel exists for.

        """
        for module, obj, _ in PUBLIC_SENTINELS:
            namespace = _star_import(module)
            with self.subTest(module=module):
                # Matched on the instance name alone: every entry in ``SENTINELS``
                # now shares :data:`CANONICAL_MODULE`, so a ``where == module``
                # filter against the *shim* location would no longer distinguish
                # them -- the instance names themselves already do.
                expected = next(instance for name, instance, _ in SENTINELS if name == obj)
                self.assertIs(namespace[obj], expected)

    def test_every_sentinel_type_is_still_importable_by_name(self) -> 'None':
        """The exact extent of the breaking change: ``import *`` narrows, nothing else.

        Leaving :attr:`__all__` is not being made private. An annotation or an
        ``isinstance`` check that names the type keeps working, and the tree itself
        relies on that -- this module's own imports are the demonstration.

        """
        for name, instance, type_ in SENTINELS:
            with self.subTest(sentinel=name):
                self.assertIs(type(instance), type_)
                self.assertEqual(type_.__module__, CANONICAL_MODULE)

    def test_the_private_sentinel_is_exported_neither_way(self) -> 'None':
        """``_Absent`` is private, so the export rule does not reach it.

        Pinned rather than assumed: the ruling says *export the objects*, and a
        literal reading of that would add ``_Absent`` to
        :attr:`pcapkit.protocols.protocol.__all__`, which would publish a sentinel
        whose own docstring says it never leaves the module.

        """
        import pcapkit.protocols.protocol as protocol

        self.assertNotIn('_Absent', protocol.__all__)
        self.assertNotIn('_AbsentType', protocol.__all__)
        self.assertNotIn('_Absent', _star_import('pcapkit.protocols.protocol'))


class SentinelPopulationTests(unittest.TestCase):
    """There are four, they follow the naming rule, and the docs say so."""

    def test_every_sentinel_follows_the_naming_convention(self) -> 'None':
        """*"Keep the sentinel object's type class naming as* ``<SENTINEL>Type``*."*"""
        for name, _, type_ in SENTINELS:
            with self.subTest(sentinel=name):
                self.assertEqual(type_.__name__, _expected_type_name(name))

    def test_conventions_doc_lists_every_sentinel_in_the_tree(self) -> 'None':
        """The doc said "three" and listed three; ``_Absent`` was the fourth.

        Asserting the names rather than only the count, because a count corrected
        without the row -- or a row added without the count -- is the same defect
        in a different place. The "Defined in" column now names
        :data:`CANONICAL_MODULE` for every row, since GitHub issue #911's housing
        move gave all four the same defining module -- checked once, outside the
        loop, rather than once per row against a value that no longer varies.

        """
        section = _sentinel_section()

        for name, _, type_ in SENTINELS:
            with self.subTest(sentinel=name):
                self.assertIn(f'``{name}``', section)
                self.assertIn(f'``{type_.__name__}``', section)
        self.assertIn(CANONICAL_MODULE, section)

        self.assertIn('four in the tree follow it', section)
        self.assertNotIn('three in the tree follow it', section)
        self.assertNotIn('The three sentinels deliberately differ', section)

    def test_conventions_doc_records_that_only_the_object_is_exported(self) -> 'None':
        """The ruling this change implements belongs in the doc that states the rule."""
        section = _sentinel_section()

        self.assertIn('ONLY', section)
        self.assertIn('#911', section)

    def test_conventions_doc_carves_out_the_vendored_bare_object(self) -> 'None':
        """"Why a class and not ``object()``" read as a blanket rule with no exception."""
        section = _sentinel_section()

        self.assertIn('_NOT_FOUND', section)
        self.assertIn('pcapkit/utilities/compat.py', section)

    def test_the_vendored_bare_object_sentinel_is_left_alone(self) -> 'None':
        """The carve-out, asserted against the source it carves out.

        Read rather than imported: the backport is inside ``if sys.version_info <
        (3, 8):``, so on any interpreter that runs this suite the branch is dead and
        ``_NOT_FOUND`` is never bound. A test that imported it would pass
        vacuously.

        """
        source = (ROOT / 'pcapkit' / 'utilities' / 'compat.py').read_text(encoding='utf-8')
        self.assertRegex(source, r'(?m)^\s+_NOT_FOUND = object\(\)$')

    def test_the_sentinel_table_has_a_row_per_sentinel_and_no_more(self) -> 'None':
        """Counted from the table itself, so a fifth sentinel cannot be half-added."""
        section = _sentinel_section()
        table = section[section.index('.. list-table::'):]
        table = table[:table.index('\n\n', table.index('- Defined in'))]

        rows = re.findall(r'^   \* - (\S+)$', table, re.MULTILINE)
        self.assertEqual(rows, ['Instance'] + [f'``{name}``' for name, _, _ in SENTINELS])


class SentinelBehaviourTests(unittest.TestCase):
    """The per-sentinel differences :file:`docs/source/contributing/conventions.rst` documents.

    Not part of the export change, and asserted here because the doc edit that goes
    with it makes claims about all four -- an undocumented ``__bool__`` or a missing
    ``__repr__`` would make the corrected prose wrong in a way no other test sees.

    """

    def test_the_absent_value_sentinels_are_falsy(self) -> 'None':
        """``NULL``, ``NoValue`` and ``_Absent`` each stand for an absent value."""
        for sentinel in (NULL, NoValue, _Absent):
            with self.subTest(sentinel=repr(sentinel)):
                self.assertFalse(sentinel)

    def test_no_default_is_deliberately_truthy(self) -> 'None':
        """It means *no default was supplied*, and is only ever tested with ``is``.

        Falsy would invite ``if not default:``, which would then read a caller's
        genuine ``0`` or ``''`` as the sentinel -- the confusion it exists to
        prevent.

        """
        self.assertTrue(NO_DEFAULT)

    def test_the_private_sentinel_reprs_as_its_own_name(self) -> 'None':
        """``<absent>``, not ``<object object at 0x...>``.

        The reason the house rule prefers a class at all, and the reason the doc
        can now name ``_AbsentType`` as having a ``__repr__`` where ``NoValueType``
        does not.

        """
        self.assertEqual(repr(_Absent), '<absent>')
        self.assertNotIn('0x', repr(_Absent))
        self.assertNotIn('__repr__', vars(NoValueType))


class NoValueIsTheDocumentedFieldDefaultTests(unittest.TestCase):
    """Why the ruling reaches ``NoValue`` at all.

    ``NoValue``'s own comment in :mod:`pcapkit.corekit.fields.field` reads *"Default
    value for* :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`*"*,
    so it is the value a caller is told to compare a field's default against -- which
    is what makes withholding it from ``import *`` the defect rather than a
    preference. That contract had no test: the ``default`` setter and deleter were
    both uncovered, and the deleter is the only code path that puts the sentinel
    *back*.

    :class:`~pcapkit.corekit.fields.strings.BytesField` is the concrete field under
    test, following :file:`tests/corekit/test_fields_field.py`: a real user-facing
    field type that inherits ``default`` unchanged, rather than a hand-rolled
    stand-in.

    """

    def test_an_undefaulted_field_reports_the_sentinel(self) -> 'None':
        """``is``, not ``==`` -- the whole point of a sentinel."""
        from pcapkit.corekit.fields.strings import BytesField

        self.assertIs(BytesField(length=4).default, NoValue)

    def test_setting_and_deleting_a_default_round_trips_through_the_sentinel(self) -> 'None':
        """Deleting a default restores ``NoValue``, rather than :obj:`None` or ``b''``.

        :obj:`None` and ``b''`` are both values a caller may legitimately want as a
        default, so either would be indistinguishable from "no default given" --
        exactly the confusion the sentinel exists to prevent.

        """
        from pcapkit.corekit.fields.strings import BytesField

        field = BytesField(length=4)
        field.default = b'\x00\x01\x02\x03'
        self.assertEqual(field.default, b'\x00\x01\x02\x03')
        self.assertIsNot(field.default, NoValue)

        del field.default
        self.assertIs(field.default, NoValue)
        self.assertFalse(field.default)


if __name__ == '__main__':
    unittest.main()
