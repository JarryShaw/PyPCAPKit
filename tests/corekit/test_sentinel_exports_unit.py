# -*- coding: utf-8 -*-
"""GitHub issue #911: a sentinel exports its **object**, never its type.

GitHub issue #719 is where the owner settled this rule: a module's
``__all__`` lists a sentinel's object (such as ``NULL``), and deliberately
leaves its type (such as ``NullType``) out. The reason is the context a
bare rule would not give: the types are not part of the public surface, so
exposing only the final objects is what keeps the published API to the
things a caller actually uses. GitHub issue #911 is the issue the
implementing work for that ruling belongs to.

Every sentinel is *defined* in :data:`CANONICAL_MODULE`: the owner chose one
shared module over one module per sentinel, on #911, so the ``<SENTINEL>Type``
naming convention and the dunder methods the sentinels share or differ on sit
together rather than scattered over a near-empty file per sentinel. Under the
owner's ruling on #1715 that a moved name keeps no re-export at its old path
(GitHub issue #1744), the export rule is asserted against
:data:`CANONICAL_MODULE`, the only import path, and :mod:`pcapkit.corekit.module`,
:mod:`pcapkit.corekit.fields.field` and :mod:`pcapkit.corekit.enum`, which use
the sentinels, export neither the object nor the type. :class:`SentinelExportTests`
asserts the shape in both directions and per module, rather than as one aggregate
that a half-applied change would still satisfy.

What only ``import *`` narrows: the type stays importable by its dotted path under
:data:`CANONICAL_MODULE`, so an annotation naming it keeps resolving.
:meth:`SentinelExportTests.test_every_sentinel_type_is_importable_from_the_canonical_module`
pins it so a later reading of the ruling cannot escalate into deleting the types.

The population includes ``ABSENT`` / ``AbsentType``, private to
:mod:`pcapkit.protocols.protocol` -- the kind of sentinel a sweep filtered on
capitalised names misses while it is spelled with a leading underscore.
:class:`SentinelPopulationTests` pins the population and the conventions doc
together, so the next sentinel cannot be added to one without the other.
``ABSENT`` stays out of :attr:`__all__` in both directions -- not under the export
ruling, which argues the opposite for an object like this one, but under the
privacy ruling stated below, which treats a sentinel documented as private as
having no place in :attr:`__all__` at all.

Every object name is SCREAMING_SNAKE (GitHub issue #937), so every instance name
agrees on one casing, and the privacy of ``ABSENT`` is signalled by documentation
rather than by the name: GitHub issue #719 is where the owner ruled that the
underscore can go, because documenting the object and its type as private, and
not for public use, is enough on its own to carry the privacy.
:meth:`SentinelExportTests.test_the_private_sentinel_is_exported_neither_way` pins
that privacy. :meth:`SentinelPopulationTests.test_every_sentinel_object_is_screaming_snake`
pins the object's own casing directly, which
``test_every_sentinel_follows_the_naming_convention`` cannot: it derives the type
name from whatever the object is called, via :func:`_expected_type_name`.

Ported code is deliberately **not** held to any of this. The case that settled it,
``_NOT_FOUND = object()`` in :file:`pcapkit/utilities/compat.py`'s ``cached_property``
backport for interpreters below 3.8, went with that backport (#2051);
:meth:`SentinelPopulationTests.test_the_vendored_bare_object_sentinel_went_with_its_backport`
pins that, and the exemption stays in the conventions doc as a rule.

"""
from __future__ import annotations

import importlib
import inspect
import pathlib
import re
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises the sentinels' exports and behaviour as well as the
#: conventions page.
__tier__ = 'ALL'

# ``pcapkit`` is deliberately not imported at module load. GitHub issue #1332: the
# plain-unittest ordering legs leave a freshly re-imported ``pcapkit`` in
# ``sys.modules``, so a sentinel bound here would be the *old* import's object and
# every ``assertIs`` against the canonical one would fail. The sentinels are read
# through :func:`_sentinels` after :func:`~tests._support.reimport_once_per_class`.

#: Repository root, for the tests that read a file rather than import it.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Where every sentinel is *defined*: the single shared module GitHub
#: issue #911 chose over one module per sentinel. Every entry in :data:`SENTINELS`
#: below reports this one.
CANONICAL_MODULE = 'pcapkit.corekit.sentinels'

#: Every sentinel in the tree that follows the house ``<SENTINEL>Type`` convention,
#: as ``(instance name, instance, type)``.
#: Every one shares :data:`CANONICAL_MODULE` as its defining module, so the tuple
#: carries no per-entry module column -- see :data:`PUBLIC_SENTINELS` below for
#: the distinct *consumer* modules.
#: Built by :func:`_sentinels` from the live import, not at module load.

#: The public members of :data:`SENTINELS`, as
#: ``(consumer module, object name, type name)``. The consumer is the module that
#: uses the sentinel and, per GitHub issue #1744, does not re-export it.
#: ``ABSENT`` is absent from it deliberately: it is private, so it is exported
#: neither way and the export rule does not reach it -- its name carries no
#: leading underscore (GitHub issue #937), but it is private all the same.
PUBLIC_SENTINELS = (
    ('pcapkit.corekit.module', 'NULL', 'NullType'),
    ('pcapkit.corekit.fields.field', 'NO_VALUE', 'NoValueType'),
    ('pcapkit.corekit.enum', 'NO_DEFAULT', 'NoDefaultType'),
)


def _sentinels() -> 'tuple[tuple[str, object, type], ...]':
    """:data:`SENTINELS`, read from the ``pcapkit`` import that is live now."""
    canonical = importlib.import_module(CANONICAL_MODULE)
    return (
        ('NULL', canonical.NULL, canonical.NullType),
        ('NO_VALUE', canonical.NO_VALUE, canonical.NoValueType),
        ('NO_DEFAULT', canonical.NO_DEFAULT, canonical.NoDefaultType),
        ('ABSENT', canonical.ABSENT, canonical.AbsentType),
        ('MISSING', canonical.MISSING, canonical.MissingType),
    )


class _ReimportCase(unittest.TestCase):
    """Base: give each test class one fresh ``pcapkit`` import (GitHub issue #1332)."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)


def _expected_type_name(instance_name: 'str') -> 'str':
    """The type name the house convention derives from an instance name.

    One mechanical rule, since every instance name is SCREAMING_SNAKE (GitHub
    issue #937): split on ``_``, title-case each word, and append ``Type``.
    ``NULL`` gives ``NullType``, ``NO_VALUE`` gives ``NoValueType``, ``NO_DEFAULT``
    gives ``NoDefaultType`` and ``ABSENT`` gives ``AbsentType``. No instance name
    is CamelCase or carries a leading underscore, so no special case handles
    either shape.

    """
    return ''.join(word.capitalize() for word in instance_name.split('_')) + 'Type'


def _star_import(module: 'str') -> 'dict[str, object]':
    """The namespace ``from <module> import *`` binds.

    The only operation that actually reads :attr:`__all__`, which is why the export
    rule is asserted through it and not only against the list literal.

    """
    namespace = {}  # type: dict[str, object]
    exec(f'from {module} import *', namespace)  # pylint: disable=exec-used
    return namespace


def _sentinel_section() -> 'str':
    """The "Naming a Sentinel" section, which is its own page.

    Read whole rather than sliced between two anchors: the conventions are one
    file per ``.. _label:`` anchor (GitHub issue #918), and the "Naming a
    Sentinel" section *is*
    :file:`docs/source/contributing/conventions/sentinel-convention.rst`, so
    there is no following anchor in the same file to slice against.

    """
    path = ROOT / 'docs/source/contributing/conventions/sentinel-convention.rst'
    if not path.is_file():  # pragma: no cover
        raise AssertionError(f'sentinel-convention.rst not found at {path}')

    return path.read_text(encoding='utf-8')


#: A "Type" cell: the class name as a literal, or a ``:class:`` role whose target
#: is that class in :data:`CANONICAL_MODULE`, with or without the leading ``~``.
_TYPE_CELL = re.compile(r'``(?P<literal>\w+)``|:class:`~?%s\.(?P<role>\w+)`'
                        % re.escape(CANONICAL_MODULE))

#: A "Defined in" cell: the module name as a literal, or a ``:mod:`` role naming it.
_MODULE_CELL = re.compile(r'``(?P<literal>[\w.]+)``|:mod:`(?P<role>[\w.]+)`')


def _cell_name(pattern: 're.Pattern[str]', cell: 'str') -> 'str | None':
    """The name a table cell spells, in either markup form; :obj:`None` otherwise."""
    match = pattern.fullmatch(cell)
    if match is None:
        return None
    return match.group('literal') or match.group('role')


def _sentinel_table(section: 'str') -> 'dict[str, tuple[str | None, str | None]]':
    """The sentinel list-table, as ``{instance: (type name, defining module)}``.

    The instance cell is a literal. The type and module cells are each read
    through :func:`_cell_name`, so a cell in neither markup form, or one whose
    role points outside :data:`CANONICAL_MODULE`, reads as :obj:`None`.

    """
    # The list-table's body: the block after its options, up to the next blank line.
    table = section.split('.. list-table::', 1)[1].split('\n\n')[1]
    rows = re.findall(r'(?m)^   \* - ``(\w+)``\n     - (.+)\n     - (.+)$', table)
    return {instance: (_cell_name(_TYPE_CELL, type_cell), _cell_name(_MODULE_CELL, module_cell))
            for instance, type_cell, module_cell in rows}


class SentinelExportTests(_ReimportCase):
    """``__all__`` names the object and not the type, in the canonical module only."""

    def test_module_exports_neither_the_object_nor_the_type(self) -> 'None':
        """``__all__`` is ``['ModuleDescriptor']``, without ``NULL`` (GitHub issue #1744).

        ``ModuleDescriptor`` is not a sentinel and has to stay, which is asserted
        here rather than in a separate test because removing it is the plausible
        way to get this line wrong.

        """
        import pcapkit.corekit.module as module

        self.assertNotIn('NULL', module.__all__)
        self.assertNotIn('NullType', module.__all__)
        self.assertIn('ModuleDescriptor', module.__all__)

    def test_enum_exports_neither_the_object_nor_the_type(self) -> 'None':
        """``EnumLookup`` and ``EnumRegistry`` are not sentinels and stay.

        ``EnumLookup`` in particular: GitHub pull request #906 split it out as a public
        base and
        :file:`docs/source/contributing/conventions/registry-protocol.rst` cites
        its ``get``, so dropping it while removing the sentinel next to it
        would break that reference.

        """
        import pcapkit.corekit.enum as enum

        self.assertNotIn('NO_DEFAULT', enum.__all__)
        self.assertNotIn('NoDefaultType', enum.__all__)
        self.assertIn('EnumLookup', enum.__all__)
        self.assertIn('EnumRegistry', enum.__all__)

    def test_field_exports_neither_the_object_nor_the_type(self) -> 'None':
        """``NO_VALUE`` is not exported here (#1744)."""
        import pcapkit.corekit.fields.field as field

        self.assertNotIn('NO_VALUE', field.__all__)
        self.assertNotIn('NoValueType', field.__all__)
        self.assertIn('Field', field.__all__)

    def test_star_import_binds_the_objects_and_not_the_types(self) -> 'None':
        """Through ``import *`` itself, which is the surface the ruling is about.

        The canonical module binds every public object and no sentinel's own
        type; each consumer module binds neither.

        """
        canonical = importlib.import_module(CANONICAL_MODULE)
        namespace = _star_import(CANONICAL_MODULE)
        for module, obj, type_ in PUBLIC_SENTINELS:
            with self.subTest(module=CANONICAL_MODULE, sentinel=obj):
                self.assertIs(namespace[obj], getattr(canonical, obj))
                self.assertNotIn(type_, namespace)
            with self.subTest(module=module, sentinel=obj):
                consumer = _star_import(module)
                self.assertNotIn(obj, consumer)
                self.assertNotIn(type_, consumer)

    def test_every_sentinel_type_is_importable_from_the_canonical_module(self) -> 'None':
        """Leaving :attr:`__all__` is not being made private.

        An annotation or an ``isinstance`` check that names the type keeps
        working, by its dotted path under :data:`CANONICAL_MODULE`.

        """
        for name, instance, type_ in _sentinels():
            with self.subTest(sentinel=name):
                self.assertIs(type(instance), type_)
                self.assertEqual(type_.__module__, CANONICAL_MODULE)

    def test_the_private_sentinel_is_exported_neither_way(self) -> 'None':
        """``ABSENT`` is private, so the export rule does not reach it.

        Pinned rather than assumed: the ruling says *export the objects*, and a
        literal reading of that would add ``ABSENT`` to
        :attr:`pcapkit.protocols.protocol.__all__`, which would publish a sentinel
        whose own docstring says it never leaves the module. With no leading
        underscore to signal "private" (GitHub issue #937), this test is the *only*
        thing enforcing it, which is why it checks both the object and the type,
        and both directions of ``import *``.

        """
        import pcapkit.protocols.protocol as protocol

        self.assertNotIn('ABSENT', protocol.__all__)
        self.assertNotIn('AbsentType', protocol.__all__)
        self.assertNotIn('ABSENT', _star_import('pcapkit.protocols.protocol'))

    def test_the_registry_sentinel_is_exported_neither_way(self) -> 'None':
        """``MISSING`` is private to the protocol registry, as ``ABSENT`` is to its module (#2555)."""
        import pcapkit.foundation.registry.protocols as registry

        self.assertNotIn('MISSING', registry.__all__)
        self.assertNotIn('MissingType', registry.__all__)
        self.assertNotIn('MISSING', _star_import('pcapkit.foundation.registry.protocols'))


class SentinelPopulationTests(_ReimportCase):
    """They follow the naming rule, and the docs say so."""

    def test_every_sentinel_follows_the_naming_convention(self) -> 'None':
        """A sentinel object's type class is named ``<SENTINEL>Type``.

        The house convention set under GitHub issue #857, kept uniform so that a
        future maintainer adding a sentinel can derive the type's name mechanically.
        """
        for name, _, type_ in _sentinels():
            with self.subTest(sentinel=name):
                self.assertEqual(type_.__name__, _expected_type_name(name))

    def test_every_sentinel_object_is_screaming_snake(self) -> 'None':
        """GitHub issue #937's own rule: every sentinel **object** is SCREAMING_SNAKE.

        The naming-convention test above already pins that ``<SENTINEL>Type`` derives
        mechanically from the object's name, but that alone does not pin what the
        object's own casing *is* -- a tree where every object were, say, CamelCase
        would satisfy it just as well, so long as the type followed suit. This test
        is what actually pins SCREAMING_SNAKE, independent of the type-derivation
        rule -- the rule GitHub issue #937's ruling adds, and the gap that lets
        object names disagree on casing.

        Without the fix the objects include ``NoValue`` and ``_Absent`` beside
        ``NULL`` and ``NO_DEFAULT``. Neither ``NoValue`` (``N``, ``o``, ``V``, ...
        mixed case) nor ``_Absent`` (leading underscore, mixed case) matches
        ``^[A-Z][A-Z0-9_]*$``, so this test then fails once for each.

        """
        pattern = re.compile(r'^[A-Z][A-Z0-9_]*$')
        for name, _, _ in _sentinels():
            with self.subTest(sentinel=name):
                self.assertRegex(name, pattern)

    def test_conventions_doc_lists_every_sentinel_in_the_tree(self) -> 'None':
        """Every sentinel has a row naming its type and defining module, and no more.

        Asserting the names, because a row missing from the table is the defect, and
        the page states no count for a row to disagree with (#1103's ruling, #1811).
        Each sentinel's row is read cell by cell through :func:`_sentinel_table`: its
        "Type" cell names the sentinel's own type class, and its "Defined in" cell
        names :data:`CANONICAL_MODULE`, which GitHub issue #911's housing ruling
        makes the defining module of every sentinel. Either cell may be a literal or
        the matching role, since both render the same name. The table's instance
        column is then read back against every singleton :data:`CANONICAL_MODULE`
        defines, both ways, so a sentinel added there without a row, or a row left
        for one removed, fails here.

        """
        section = _sentinel_section()
        table = _sentinel_table(section)

        for name, _, type_ in _sentinels():
            with self.subTest(sentinel=name):
                self.assertIn(name, table, f'the sentinel table has no ``{name}`` row')
                self.assertEqual(table[name], (type_.__name__, CANONICAL_MODULE),
                                 f'the ``{name}`` row does not name {type_.__name__} '
                                 f'in {CANONICAL_MODULE}')

        canonical = importlib.import_module(CANONICAL_MODULE)
        defined = {name for name, value in vars(canonical).items()
                   if not isinstance(value, type) and type(value).__module__ == CANONICAL_MODULE}
        self.assertEqual(set(table), defined)
        self.assertNotIn('The three sentinels deliberately differ', section)

    def test_conventions_doc_records_that_only_the_object_is_exported(self) -> 'None':
        """The #911 ruling belongs in the doc that states the rule.

        Pinned as the *claim* rather than as wording. Asserting a literal such as
        the maintainer's own emphatic capitalisation reddens the test whenever the
        page paraphrases the quote (GitHub issue #949) without anything about the
        rule having changed -- exactly the defect #949 exists to remove.

        So the substance is checked against the tree, which is where the ruling
        actually takes effect, and the page is only required to name the export
        boundary (``__all__``, an identifier rather than prose) and the issue that
        settled it.

        The citation is accepted in either markup form. The page writes it with the
        ``:issue:`` role configured in ``docs/source/conf.py``, because a bare ``#NNN``
        resolves to nothing in the built documentation -- so pinning the bare spelling
        would redden this test over markup while the ruling it checks is
        untouched, which is the same defect the paragraph above records.

        """
        section = _sentinel_section()

        self.assertTrue(
            '#911' in section or ':issue:`911`' in section,
            'the page no longer cites the issue that settled the export boundary, in '
            'either the bare or the role form, so a reader cannot find the ruling '
            'behind the rule')
        self.assertIn('__all__', section,
                      "the page no longer names ``__all__``, so it no longer says "
                      'where the export boundary is -- #911 ruled that the instance '
                      'is exported and the type is not, and a reader cannot act on '
                      'that without being told which list decides it')

        # The ruling itself, against the module it governs rather than against prose:
        # every public sentinel's instance is exported and its type is not.
        exported = set(importlib.import_module(CANONICAL_MODULE).__all__)
        for _, instance_name, type_name in PUBLIC_SENTINELS:
            with self.subTest(sentinel=instance_name):
                self.assertIn(instance_name, exported,
                              f'{instance_name} is a public sentinel but is not in '
                              f'{CANONICAL_MODULE}.__all__, so #911\'s ruling that '
                              'the objects are what reach users no longer holds')
                self.assertNotIn(type_name, exported,
                                 f'{type_name} is in {CANONICAL_MODULE}.__all__, but '
                                 '#911 ruled the type stays out of it and remains '
                                 'reachable only by its dotted path')

    def test_conventions_doc_carves_out_the_vendored_bare_object(self) -> 'None':
        """"Why a Class and Not ``object()``" read as a blanket rule with no exception."""
        section = _sentinel_section()

        self.assertIn('**Ported code is exempt.**', section)
        self.assertIn('_NOT_FOUND', section)

    def test_the_vendored_bare_object_sentinel_went_with_its_backport(self) -> 'None':
        """The carve-out's case is gone with the 3.8 floor (#2051).

        Read rather than imported, as the backport it sat in was never bound on
        an interpreter that runs this suite.

        """
        source = (ROOT / 'pcapkit' / 'utilities' / 'compat.py').read_text(encoding='utf-8')
        self.assertNotIn('_NOT_FOUND', source)
        self.assertRegex(source, r'(?m)^from functools import cached_property$')

    def test_the_sentinel_table_has_a_row_per_sentinel_and_no_more(self) -> 'None':
        """Counted from the table itself, so a new sentinel cannot be half-added."""
        section = _sentinel_section()
        table = section[section.index('.. list-table::'):]
        table = table[:table.index('\n\n', table.index('- Defined in'))]

        rows = re.findall(r'^   \* - (\S+)$', table, re.MULTILINE)
        self.assertEqual(rows, ['Instance'] + [f'``{name}``' for name, _, _ in _sentinels()])


class SentinelBehaviourTests(_ReimportCase):
    """The per-sentinel differences
    :file:`docs/source/contributing/conventions/sentinel-convention.rst`
    documents.

    Asserted here because the convention page makes claims about every sentinel -- an
    undocumented ``__bool__`` or a missing ``__repr__`` would make its prose wrong in a
    way no other test sees.

    """

    def test_the_absent_value_sentinels_are_falsy(self) -> 'None':
        """``NULL``, ``NO_VALUE``, ``ABSENT`` and ``MISSING`` each stand for an absent value."""
        live = {name: obj for name, obj, _ in _sentinels()}
        for sentinel in (live['NULL'], live['NO_VALUE'], live['ABSENT'], live['MISSING']):
            with self.subTest(sentinel=repr(sentinel)):
                self.assertFalse(sentinel)

    def test_no_default_is_deliberately_truthy(self) -> 'None':
        """It means *no default was supplied*, and is only ever tested with ``is``.

        Falsy would invite ``if not default:``, which would then read a caller's
        genuine ``0`` or ``''`` as the sentinel -- the confusion it exists to
        prevent.

        """
        self.assertTrue(_sentinels()[2][1])

    def test_the_private_sentinel_reprs_as_its_own_name(self) -> 'None':
        """``ABSENT``, not ``<object object at 0x...>``.

        The reason the house rule prefers a class at all. The shared ``__repr__``
        prints the object's own name, as ``repr(None)`` is ``'None'``, so
        ``AbsentType`` needs no ``__repr__`` of its own.

        """
        live = _sentinels()
        absent, absent_type = live[3][1], live[3][2]
        self.assertEqual(repr(absent), 'ABSENT')
        self.assertNotIn('0x', repr(absent))
        self.assertNotIn('__repr__', vars(absent_type))

    def test_no_value_reprs_as_its_own_name(self) -> 'None':
        """``NO_VALUE``, not ``<pcapkit.corekit.sentinels.NoValueType object at 0x...>``.

        GitHub issue #1841. ``NO_VALUE`` is the ``default`` of the field
        constructors, so the address showed in :func:`inspect.signature`, in
        :func:`help` and in a parsed schema's repr, and changed every process.
        :file:`pcapkit/corekit/fields/strings.py` and
        :file:`pcapkit/corekit/fields/ipaddress.py` are where the issue saw it.

        """
        from pcapkit.corekit.fields.ipaddress import IPv4AddressField
        from pcapkit.corekit.fields.strings import StringField
        from pcapkit.protocols.internet.hopopt import HOPOPT

        no_value = _sentinels()[1][1]
        self.assertEqual(repr(no_value), 'NO_VALUE')

        # NOTE: ``__init__`` rather than the class itself. Python 3.8 reports
        # ``Generic.__new__``'s ``(*args, **kwds)`` as the signature of a
        # ``Generic`` subclass, which both of these are; 3.9 and later report
        # ``__init__``'s, so reading ``__init__`` directly agrees everywhere.
        for field in (StringField, IPv4AddressField):
            with self.subTest(field=field.__name__):
                parameter = inspect.signature(field.__init__).parameters['default']
                self.assertIs(parameter.default, no_value)
                self.assertTrue(str(parameter).endswith(' = NO_VALUE'), str(parameter))

        # An MPL option whose seed is the IPv6 source address, parsed with no
        # IPv6 header around it, so ``post_process`` leaves the seed unset.
        octets = bytes.fromhex('3b006d0220070000')
        option = HOPOPT(octets, len(octets), extension=True).schema.options[0]
        self.assertIs(option.seed, no_value)
        self.assertIn('seed=NO_VALUE', repr(option))


class NoValueIsTheDocumentedFieldDefaultTests(_ReimportCase):
    """Why the ruling reaches ``NO_VALUE`` at all.

    ``NO_VALUE``'s own comment in :mod:`pcapkit.corekit.fields.field` reads *"Default value
    for* :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`*"*, so it
    is the value a caller is told to compare a field's default against -- which is what makes
    withholding it from ``import *`` the defect rather than a preference. The ``default``
    setter and deleter are covered here, and the deleter is the only code path that puts the
    sentinel *back*. GitHub issue #937 renamed the object from ``NoValue`` to ``NO_VALUE``
    without touching this contract.

    :class:`~pcapkit.corekit.fields.strings.BytesField` is the concrete field under
    test, following :file:`tests/corekit/test_fields_field.py`: a real user-facing
    field type that inherits ``default`` unchanged, rather than a hand-rolled
    stand-in.

    """

    def test_an_undefaulted_field_reports_the_sentinel(self) -> 'None':
        """``is``, not ``==`` -- the whole point of a sentinel."""
        from pcapkit.corekit.sentinels import NO_VALUE
        from pcapkit.corekit.fields.strings import BytesField

        self.assertIs(BytesField(length=4).default, NO_VALUE)

    def test_setting_and_deleting_a_default_round_trips_through_the_sentinel(self) -> 'None':
        """Deleting a default restores ``NO_VALUE``, rather than :obj:`None` or ``b''``.

        :obj:`None` and ``b''`` are both values a caller may legitimately want as a
        default, so either would be indistinguishable from "no default given" --
        exactly the confusion the sentinel exists to prevent.

        """
        from pcapkit.corekit.sentinels import NO_VALUE
        from pcapkit.corekit.fields.strings import BytesField

        field = BytesField(length=4)
        field.default = b'\x00\x01\x02\x03'
        self.assertEqual(field.default, b'\x00\x01\x02\x03')
        self.assertIsNot(field.default, NO_VALUE)

        del field.default
        self.assertIs(field.default, NO_VALUE)
        self.assertFalse(field.default)


if __name__ == '__main__':
    unittest.main()
