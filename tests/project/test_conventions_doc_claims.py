# -*- coding: utf-8 -*-
"""Claims on the *House Conventions* page that the tree can be asked about.

:file:`docs/source/contributing/conventions.rst` records design rulings, and most of
what it records is reasoning -- which no test can check. Some of it is not: a count of
classes, a per-class classification, a retired name, an exception type. Those are the
parts that rot silently, because Sphinx builds without ``-W`` and without ``nitpicky``,
so a page whose every factual claim has gone stale still renders and CI still passes.

GitHub issue #918 harvested the settled rulings onto that page, and this file pins the
checkable ones:

* :class:`ConventionAnchorTests` -- the four ``.. _label:`` anchors the page carries.
  Three of them are cross-referenced from :mod:`pcapkit` docstrings and from
  ``tests/corekit/test_sentinel_exports_unit.py``, which slices the file *by* two of
  them, so a later split of the page into one file per section has to keep every anchor
  resolving. This is the cheap guard that a split cannot orphan one by accident.
* :class:`PhaseTwoRemainderTests` -- the three counts the page states about
  `#877 <https://github.com/JarryShaw/PyPCAPKit/issues/877>`__'s phase 2, measured
  rather than remembered. The page said the phase *"has not happened yet"* for as long
  as it did because nothing contradicted it once #921 landed.
* :class:`ExtensionHeaderClassificationTests` -- the page's bases-per-header table
  against the declarations themselves. ``tests/protocols/internet/test_ipv6_ext_unit.py``
  already pins the *code* to the ruling; nothing pinned the *page* to the code, which is
  the half that goes stale when a ninth header lands.
* :class:`RetiredNameTests` -- *"No more ``IPv6_GenericExt`` name."* A ruling that a name
  must not exist is exactly the kind a later change reintroduces without noticing.
* :class:`FailedLookupExceptionTests` -- the worked example the page gives for a name
  miss, which named :exc:`KeyError` until #918 and now names
  :exc:`~pcapkit.utilities.exceptions.EnumKeyError`.

Deliberately **not** checked here: whether the page's cross-references resolve. That is
a property of the built inventory rather than of the source, for the reason
:file:`tests/project/test_documentation_claims.py` gives at length, and the honest check
is the rendered HTML. The measured result is recorded in the pull request instead.

"""

from __future__ import annotations

import enum
import importlib
import pathlib
import pkgutil
import re
import unittest

import aenum

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The page itself. Hard-coded rather than discovered, because the path is *also* what
#: ``tests/corekit/test_sentinel_exports_unit.py`` hard-codes -- so if the page moves,
#: both files have to be updated together and a test that found it either way would
#: hide half of that.
CONVENTIONS = ROOT / 'docs' / 'source' / 'contributing' / 'conventions.rst'

#: Every ``.. _label:`` the page is cross-referenced by, and what each is for. The first
#: three predate #918; ``extension-header-subclassing`` arrived with it.
ANCHORS = (
    'mint-criterion',
    'sentinel-convention',
    'registry-protocol',
    'extension-header-subclassing',
)

#: Number words as the page spells them, so a count can be read back out of the prose.
#: The page states its figures in words rather than digits, which is house style there.
NUMBER_WORDS = {
    'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7,
    'eight': 8, 'nine': 9, 'ten': 10, 'eleven': 11, 'twelve': 12,
}


def _page() -> 'str':
    """The page's text.

    Raises:
        AssertionError: If the page is not where every reference to it says it is.

    """
    if not CONVENTIONS.is_file():  # pragma: no cover
        raise AssertionError(
            f'conventions.rst not found at {CONVENTIONS}; pcapkit/corekit/sentinels.py '
            'and tests/corekit/test_sentinel_exports_unit.py both name this path'
        )
    return CONVENTIONS.read_text(encoding='utf-8')


def _section(anchor: 'str') -> 'str':
    """The page text from ``anchor`` up to the next anchor, or to the end.

    Sliced by the anchors rather than by line number, following
    ``tests/corekit/test_sentinel_exports_unit.py``, so an edit elsewhere on the page
    cannot silently make an assertion read the wrong section.

    A missing anchor fails here with a message naming it, rather than with
    :meth:`str.index`'s bare ``substring not found`` -- and the *other* anchors are
    looked up with :meth:`str.find` for the same reason, so one missing label does not
    make every slice on the page report the wrong thing.

    Args:
        anchor: The label to slice from, without the ``.. _`` and ``:``.

    Returns:
        The section's text.

    Raises:
        AssertionError: If ``anchor`` is not on the page at all.

    """
    text = _page()
    start = text.find(f'.. _{anchor}:')
    if start < 0:
        raise AssertionError(f'anchor .. _{anchor}: is not on {CONVENTIONS.name}; '
                             'every :ref: pointing at it is now plain text')
    following = [found for other in ANCHORS
                 if (found := text.find(f'.. _{other}:')) > start]
    return text[start:min(following)] if following else text[start:]


def _every_enumeration() -> 'dict[type, str]':
    """Every enumeration :mod:`pcapkit` defines, nested ones included.

    Both the :mod:`enum` and :mod:`aenum` flavours, because the tree uses both and a
    walk over one of them silently under-reports. Nested classes are walked too: the
    seven ``Flags`` enumerations under
    :mod:`pcapkit.protocols.schema.application.httpv2` are all nested, and they are
    what makes the difference between 17 non-registry enumerations and 24.

    :mod:`pcapkit.vendor` is skipped. Its modules are crawlers whose classes are
    :class:`~pcapkit.vendor.default.Vendor` subclasses named after registries rather
    than enumerations themselves, so nothing there is in scope and importing them is
    only cost.

    Returns:
        Each enumeration mapped to its dotted qualified name.

    """
    import pcapkit

    for module in pkgutil.walk_packages(pcapkit.__path__, 'pcapkit.'):
        if module.name.startswith('pcapkit.vendor'):
            continue
        # Not guarded: every module under pcapkit imports cleanly, and swallowing an
        # ImportError here would let this walk go quietly partial -- which is the one
        # failure mode that would make every count below pass vacuously.
        importlib.import_module(module.name)

    found = {}  # type: dict[type, str]
    visited = set()  # type: set[type]

    def walk(container: 'type') -> 'None':
        """Recurse through ``container``'s own attributes.

        Into **every** nested class, not only the enumerations: the seven ``Flags``
        are nested inside schema classes, which are not enumerations themselves, so a
        recursion that only followed enumerations would never reach them -- and would
        under-report the non-registry population by exactly those seven.

        """
        if container in visited:
            return
        visited.add(container)
        for value in vars(container).values():
            if not isinstance(value, type):
                continue
            if not getattr(value, '__module__', '').startswith('pcapkit'):
                continue
            if issubclass(value, (enum.Enum, aenum.Enum)):
                found.setdefault(value, f'{value.__module__}.{value.__qualname__}')
            walk(value)

    import sys

    for name, module in list(sys.modules.items()):
        if not name.startswith('pcapkit') or name.startswith('pcapkit.vendor'):
            continue
        for value in vars(module).values():
            if not isinstance(value, type):
                continue
            if not getattr(value, '__module__', '').startswith('pcapkit'):
                continue
            if issubclass(value, (enum.Enum, aenum.Enum)):
                found.setdefault(value, f'{value.__module__}.{value.__qualname__}')
            walk(value)
    return found


class ConventionAnchorTests(unittest.TestCase):
    """The labels other files cross-reference, all in the one page."""

    def test_every_cross_referenced_anchor_is_present(self) -> 'None':
        """A missing anchor is a dead ``:ref:`` that renders as plain text.

        Sphinx is run here without ``-W`` and without ``nitpicky``, so an unresolved
        reference is not a build failure -- it is a word that used to be a link. This
        is the assertion a split of the page has to keep passing.

        """
        text = _page()
        for anchor in ANCHORS:
            with self.subTest(anchor=anchor):
                # ``assertTrue`` rather than ``assertIn``: the latter dumps the whole
                # 900-line page into the failure and buries the one line that says
                # which anchor went missing.
                self.assertTrue(f'.. _{anchor}:' in text,
                                f'.. _{anchor}: is no longer on {CONVENTIONS.name}')

    def test_the_sentinel_slice_markers_stay_in_one_file_and_in_order(self) -> 'None':
        """``test_sentinel_exports_unit`` slices between two of the anchors.

        It reads ``text.index('.. _sentinel-convention:')`` through
        ``text.index('.. _registry-protocol:', start)``, so splitting those two
        sections into separate files breaks it -- not with a wrong answer, but with a
        :exc:`ValueError` from :meth:`str.index`. Stated here as well so the
        constraint is discoverable from the page's own tests.

        """
        text = _page()
        self.assertLess(text.index('.. _sentinel-convention:'),
                        text.index('.. _registry-protocol:'))


class PhaseTwoRemainderTests(unittest.TestCase):
    """The page's counts for GitHub issue #877's phase 2, measured."""

    def setUp(self) -> 'None':
        from pcapkit.corekit.enum import EnumLookup, EnumRegistry

        self.enumerations = _every_enumeration()
        self.non_registry = {cls: name for cls, name in self.enumerations.items()
                             if not issubclass(cls, EnumRegistry)}
        self.outside = {cls: name for cls, name in self.non_registry.items()
                        if not issubclass(cls, EnumLookup)}
        # Whitespace-normalised, because the page wraps its prose at 88 columns and a
        # sentence this reads a figure out of is routinely split across lines.
        self.note = ' '.join(_section('registry-protocol').split())

    def test_the_walk_found_something_to_count(self) -> 'None':
        """Guards every count below from passing on an empty discovery."""
        self.assertGreater(len(self.enumerations), 100,
                           'the enumeration walk collapsed; the counts below would '
                           'pass vacuously')

    def test_the_page_states_the_measured_number_outside_the_hierarchy(self) -> 'None':
        """*"Seven are still outside the hierarchy"* -- against a runtime walk."""
        stated = re.search(r'\*\*(\w+) are still outside the hierarchy\*\*', self.note)
        self.assertIsNotNone(stated, 'the page no longer states how many enumerations '
                                     'are outside EnumLookup; the wording this test '
                                     'reads has changed')
        assert stated is not None  # for type checkers; asserted above
        self.assertEqual(NUMBER_WORDS[stated.group(1).lower()], len(self.outside),
                         f'the page says {stated.group(1)!r} but the tree has '
                         f'{len(self.outside)}: {sorted(self.outside.values())}')

    def test_the_page_names_every_enumeration_outside_the_hierarchy(self) -> 'None':
        """The count alone would pass on a wrong list of the right length."""
        for name in sorted(self.outside.values()):
            with self.subTest(enumeration=name):
                self.assertIn(name.rsplit('.', maxsplit=1)[-1], self.note)

    def test_the_page_states_the_measured_phase_two_progress(self) -> 'None':
        """*"landed for 17 of the 24 non-registry enumerations"*, both figures."""
        stated = re.search(r'landed for (\d+) of the (\d+) non-registry enumerations',
                           self.note)
        self.assertIsNotNone(stated, 'the page no longer states phase 2 progress in '
                                     'the shape this test reads')
        assert stated is not None  # for type checkers; asserted above
        done, total = int(stated.group(1)), int(stated.group(2))
        self.assertEqual(total, len(self.non_registry),
                         'the page\'s non-registry enumeration count is stale')
        self.assertEqual(done, len(self.non_registry) - len(self.outside),
                         'the page\'s re-parented count is stale')


class ExtensionHeaderClassificationTests(unittest.TestCase):
    """The page's bases-per-header table against the declarations themselves."""

    def setUp(self) -> 'None':
        import pcapkit.protocols.internet  # noqa: F401  # populates __subclasses__

        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        self.internet = Internet
        self.ipv6_ext = IPv6_Ext
        self.family = {}  # type: dict[str, type]
        stack = list(IPv6_Ext.__subclasses__())
        while stack:
            klass = stack.pop()
            if klass.__qualname__ in self.family:
                continue
            self.family[klass.__qualname__] = klass
            stack.extend(klass.__subclasses__())
        self.rows = self._table_rows()

    @staticmethod
    def _table_rows() -> 'list[list[str]]':
        """The classification table, one list of cells per row, header row included.

        Parsed from the ``.. list-table::`` markup rather than from a rendered build,
        so this runs without the docs toolchain. Cell text is joined on whitespace, so
        reflowing a cell across lines does not change what is asserted.

        Returns:
            One list of cell strings per row.

        """
        section = _section('extension-header-subclassing')
        lines = section[section.index('.. list-table::'):].splitlines()

        rows = []  # type: list[list[str]]
        for line in lines[1:]:
            if line.startswith('   * - '):
                rows.append([line[len('   * - '):]])
            elif line.startswith('     - ') and rows:
                rows[-1].append(line[len('     - '):])
            elif line.strip() and line.startswith('       ') and rows:
                rows[-1][-1] += ' ' + line.strip()
            elif line.strip() and not line.startswith(' '):
                break  # back at column 0: the table is over
        return [[' '.join(cell.split()) for cell in row] for row in rows]

    @staticmethod
    def _named(cell: 'str') -> 'tuple[str, ...]':
        """Every class the cell names, whether as a ``:class:`` role or a literal."""
        roles = re.findall(r':class:`~[\w.]*\.(\w+)`', cell)
        return tuple(roles) if roles else tuple(re.findall(r'``(\w+)``', cell))

    def test_the_table_was_parsed(self) -> 'None':
        """Guards the assertions below from passing on an unparsed table."""
        self.assertTrue(self.rows, 'the classification table did not parse; the page '
                                   'markup this test reads has changed')
        self.assertEqual(self.rows[0], ['Header', 'Bases', 'Classification'],
                         'the table header changed, so the column order the '
                         'assertions below assume may no longer hold')

    def test_the_table_covers_the_whole_family_and_nothing_else(self) -> 'None':
        """A ninth extension header has to reach the page, not only the code."""
        listed = {name for row in self.rows[1:] for name in self._named(row[0])}
        self.assertEqual(listed, set(self.family),
                         'the page and IPv6_Ext.__subclasses__() disagree about which '
                         'headers exist')

    def test_the_table_records_the_declared_bases_in_order(self) -> 'None':
        """``__bases__``, not ``__mro__``.

        Every member reaches
        :class:`~pcapkit.protocols.internet.internet.Internet` transitively through
        :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`, so what the convention
        encodes is the declaration. Asserting the cell against ``__bases__`` is
        therefore asserting the thing the ruling is about.

        """
        for row in self.rows[1:]:
            documented = self._named(row[1])
            for header in self._named(row[0]):
                with self.subTest(header=header):
                    actual = tuple(base.__name__
                                   for base in self.family[header].__bases__)
                    self.assertEqual(actual, documented)

    def test_the_table_agrees_with_the_standalone_classification(self) -> 'None':
        """*"also standalone"* on the page means a second ``Internet``-derived base."""
        for row in self.rows[1:]:
            standalone = 'also standalone' in row[2]
            for header in self._named(row[0]):
                with self.subTest(header=header):
                    named = {base for base in self.family[header].__bases__
                             if base is not self.ipv6_ext
                             and issubclass(base, self.internet)}
                    self.assertEqual(bool(named), standalone)

    def test_the_page_agrees_with_the_test_that_pins_the_code(self) -> 'None':
        """The page and ``STANDALONE_MEMBERS`` are two records of one ruling.

        Read out of the test module rather than re-derived, so the two cannot drift
        apart in the direction where the code changes and only one record follows.

        """
        from tests.protocols.internet.test_ipv6_ext_unit import (
            IPv6ExtSharedBaseContractTests)

        documented = {name for row in self.rows[1:] if 'also standalone' in row[2]
                      for name in self._named(row[0])}
        self.assertEqual(documented,
                         set(IPv6ExtSharedBaseContractTests.STANDALONE_MEMBERS))


class RetiredNameTests(unittest.TestCase):
    """*"No more* ``IPv6_GenericExt`` *name. Its an intermediate state and never
    released."*"""

    def test_the_retired_base_name_is_absent_from_the_package(self) -> 'None':
        """A ruling that a name must not exist needs a test, or it comes back.

        Checked over the package source rather than by import, because the failure
        this guards against is a *reintroduced alias* -- which would import perfectly
        well and satisfy any behavioural assertion.

        """
        offenders = [str(path.relative_to(ROOT))
                     for path in sorted((ROOT / 'pcapkit').rglob('*.py'))
                     if 'IPv6_GenericExt' in path.read_text(encoding='utf-8')]
        self.assertEqual(offenders, [],
                         'the retired name is back; the ruling on GitHub pull request '
                         '#924 is that it was an intermediate state and never released')

    def test_the_shared_base_still_carries_the_name_the_ruling_left(self) -> 'None':
        """The other half: the rename landed, rather than the name simply going."""
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        self.assertEqual(IPv6_Ext.__name__, 'IPv6_Ext')


class FailedLookupExceptionTests(unittest.TestCase):
    """The worked example the page gives for a lookup that does not resolve."""

    def test_the_page_names_the_exception_the_code_actually_raises(self) -> 'None':
        """It said :exc:`KeyError` until #918, which was true but no longer specific.

        ``EnumKeyError`` is what GitHub issue #923 made ``get`` raise, and it *is* a
        :exc:`KeyError` -- which is why the stale wording never failed anything.

        """
        from pcapkit.const.ftp.command import FEATCode
        from pcapkit.utilities.exceptions import EnumKeyError

        with self.assertRaises(EnumKeyError) as caught:
            FEATCode.get('ZZ-NOT-REAL')
        self.assertIsInstance(caught.exception, KeyError)

        section = ' '.join(_section('registry-protocol').split())
        at = section.index("``FEATCode.get('ZZ-NOT-REAL')``")
        self.assertIn('EnumKeyError', section[at:at + 300],
                      'the page still describes the name miss without naming '
                      'EnumKeyError')

    def test_a_declared_but_unassigned_value_still_resolves_through_the_constructor(
            self) -> 'None':
        """The other half of the asymmetry the page records, so it stays a pair."""
        from pcapkit.const.ftp.command import FEATCode

        self.assertNotIn('ZZ-NOT-REAL', FEATCode._member_map_)
        self.assertEqual(FEATCode('ZZ-NOT-REAL').value, 'ZZ-NOT-REAL')


if __name__ == '__main__':
    unittest.main()
