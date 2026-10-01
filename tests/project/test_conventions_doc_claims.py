# -*- coding: utf-8 -*-
"""Claims the split *House Conventions* pages make that the tree can be asked about.

:file:`docs/source/contributing/conventions.rst` used to record every design ruling
on one 966-line page, and most of what it records is reasoning -- which no test can
check. Some of it is not: a count of classes, a per-class classification, a retired
name, an exception type. Those are the parts that rot silently, because Sphinx builds
without ``-W`` and without ``nitpicky``, so a page whose every factual claim has gone
stale still renders and CI still passes.

GitHub issue #918 part 1 harvested the settled rulings onto that page; part 2 then
split it into :file:`docs/source/contributing/conventions/`, one file per
``.. _label:`` anchor plus the :file:`index.rst` that carries the ``.. important::``
preamble and the toctree. This file pins the checkable claims, plus the split's own
structure:

* :class:`ConventionAnchorTests` -- every ``.. _label:`` anchor, one now per
  file. Before the split the original four lived on one page, and
  ``tests/corekit/test_sentinel_exports_unit.py`` sliced the file *between* two of
  them -- which is exactly what GitHub issue #930 named as the split's concrete
  blocker, since separating those two anchors into different files made that slice
  raise :exc:`ValueError`. This class pins the post-split shape: every anchor still
  exists, lives in exactly its own file, is listed in the index's toctree, and the
  top-level :file:`docs/source/index.rst` points at the new index page rather than
  the retired bare document path.
* :class:`PhaseTwoRemainderTests` -- the three counts the page states about
  `#877 <https://github.com/JarryShaw/PyPCAPKit/issues/877>`__'s phase 2, measured
  rather than remembered. The page said the phase *"has not happened yet"* for as long
  as it did because nothing contradicted it once #921 landed.
* :class:`ExtensionHeaderClassificationTests` -- the page's bases-per-header table
  against the declarations themselves. ``tests/protocols/internet/test_ipv6_ext_unit.py``
  already pins the *code* to the ruling; nothing pinned the *page* to the code, which is
  the half that goes stale when a ninth header lands.
* :class:`RetiredNameTests` -- the #924 ruling that the ``IPv6_GenericExt`` name goes for
  good. A ruling that a name must not exist is exactly the kind a later change
  reintroduces without noticing.
* :class:`FailedLookupExceptionTests` -- the worked example the page gives for a name
  miss, which named :exc:`KeyError` until #918 and now names
  :exc:`~pcapkit.utilities.exceptions.EnumKeyError`.
* :class:`GetOverrideContractTests` -- what a ``get`` override owes the base:
  ``@classmethod`` for delegation, which Python forces rather than anyone ruling
  (#913's precedent, followed by #908), plus the three rulings part 1 harvested --
  ``quiet=True`` on the raise (#933), no suppression standing in for an honoured
  signature (#935), and deletion rather than repair when the override only
  reimplements the base (#940). Includes the guard for the audit row #940 falsified,
  which rendered fine and failed nothing while claiming two overrides that no longer
  exist.
* :class:`AenumRoleExclusionTests` -- GitHub issue #934 part C's ruling that
  ``aenum`` cannot be cross-referenced at all (``conf.py`` excludes it: its
  ``objects.inv`` carries zero ``py:`` objects), converted to plain literals rather
  than roles. A forbidden role needs a test or it comes back, exactly as
  :class:`RetiredNameTests` guards a retired name. Pins the other half of the same
  fix alongside it: the four sentinel references #934 part B qualified stay
  qualified, since none of ``AbsentType``, ``NoValueType`` or ``ABSENT`` resolves
  unqualified outside :file:`docs/source/pcapkit/corekit/sentinels.rst`'s own module
  context. Both checks scan every split page rather than one file, since either
  could in principle land on any of them.

* :class:`ProcessConventionTests` -- the three *process* rulings #918 harvested onto
  the fifth page, :file:`process.rst`: what the ``all`` extra carries (#910), what a
  changelog entry is, and what the issue and pull request labels mean. Grounded in
  :file:`pyproject.toml`, :file:`docs/source/changelog/1.5.0.rst` and
  :file:`.github/PULL_REQUEST_TEMPLATE.md` rather than in the owner's phrasing, which
  that page is required to paraphrase rather than quote.

Deliberately **not** checked here: whether the page's cross-references resolve. That is
a property of the built inventory rather than of the source, for the reason
:file:`tests/project/test_documentation_claims.py` gives at length, and the honest check
is the rendered HTML. The measured result is recorded in the pull request instead.

"""

from __future__ import annotations

import enum
import importlib
import inspect
import pathlib
import pkgutil
import re
import unittest

import aenum

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The directory GitHub issue #918 part 2 split the single-page
#: :file:`conventions.rst` into. Hard-coded rather than discovered, because the path
#: is *also* what ``pcapkit/corekit/sentinels.py`` and
#: ``tests/corekit/test_sentinel_exports_unit.py`` hard-code -- so if the layout
#: moves again, every one of them has to be updated together, and a test that found
#: it either way would hide that.
CONVENTIONS_DIR = ROOT / 'docs' / 'source' / 'contributing' / 'conventions'

#: The index page that carries the toctree and the ``.. important::`` preamble the
#: single page used to open with.
INDEX = CONVENTIONS_DIR / 'index.rst'

#: Every ``.. _label:`` anchor, in the narrative order the pre-split page carried
#: them in -- which is also the order the index's toctree lists the files in. The
#: first three predate #918; ``extension-header-subclassing`` arrived with it, and
#: ``process`` came last, on the owner's ruling that the three settled *process*
#: rulings -- the ``all`` extra, what a changelog entry is, and what the labels
#: mean -- get a page of their own rather than being wedged onto a code-convention
#: page. ``documentation`` came after it, carrying the rulings GitHub issue #719
#: settled about the prose itself -- heading case, when a Mermaid graph beats a
#: paragraph, and what a sentence on these pages may claim -- which had until then
#: lived only in that thread. Every anchor is the bare file stem, which is what
#: :data:`PAGES` below depends on.
ANCHORS = (
    'mint-criterion',
    'sentinel-convention',
    'registry-protocol',
    'extension-header-subclassing',
    'process',
    'documentation',
)

#: Each anchor's own file, one-to-one since the split -- there is no longer a single
#: shared page to slice between two of them.
PAGES = {anchor: CONVENTIONS_DIR / f'{anchor}.rst' for anchor in ANCHORS}

#: Number words as the page spells them, so a count can be read back out of the prose.
#: The page states its figures in words rather than digits, which is house style there.
#: ``'zero'`` joined the set with GitHub issue #930, once phase 2 finished and the
#: outside-the-hierarchy count it counts dropped to none.
NUMBER_WORDS = {
    'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6,
    'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10, 'eleven': 11, 'twelve': 12,
}


def _page(anchor: 'str') -> 'str':
    """``anchor``'s own page, whole.

    The split retired the anchor-to-anchor slice this used to need: each anchor is
    now the whole of its own file, rather than a range between two markers in one
    shared page. ``tests/corekit/test_sentinel_exports_unit.py``'s
    ``_sentinel_section`` made the same change, for the same reason.

    Args:
        anchor: One of :data:`ANCHORS`.

    Returns:
        The page's text.

    Raises:
        AssertionError: If the page is not where the split put it.

    """
    path = PAGES[anchor]
    if not path.is_file():  # pragma: no cover
        raise AssertionError(
            f'{path.name} not found at {path}; GitHub issue #918 part 2 split it '
            'out of the single-page conventions.rst -- pcapkit/corekit/sentinels.py '
            'and tests/corekit/test_sentinel_exports_unit.py both name paths under '
            'this directory too'
        )
    return path.read_text(encoding='utf-8')


def _every_page() -> 'str':
    """Every split page's text, concatenated, index included.

    For the checks that used to scan the single-page file end to end -- a forbidden
    role, a qualified reference -- and still need to scan across every section
    plus the preamble, since either could in principle land on any of them.

    """
    return '\n'.join([INDEX.read_text(encoding='utf-8')]
                     + [_page(anchor) for anchor in ANCHORS])


def _toctree_entries(text: 'str') -> 'list[str]':
    """The entries of the first ``.. toctree::`` directive in ``text``.

    Parsed structurally -- skip the directive's own options (``:maxdepth:`` and the
    like), then collect non-blank lines until the entry block ends -- rather than
    searched for a literal substring, following
    ``tests/project/test_sentinels_doc_page_934_unit.py``'s own copy of this helper,
    so a reordering or an added option does not misreport what the toctree actually
    names.

    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == '.. toctree::':
            break
    else:
        raise AssertionError('no ".. toctree::" directive found')

    entries = []  # type: list[str]
    started = False
    for line in lines[index + 1:]:
        stripped = line.strip()
        if not stripped:
            if started:
                break
            continue
        if stripped.startswith(':'):
            continue
        started = True
        entries.append(stripped)
    return entries


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
    """The labels other files cross-reference, one now per file."""

    def test_every_page_exists(self) -> 'None':
        """Every page :data:`ANCHORS` names, plus the index, is on disk."""
        for path in [INDEX] + [PAGES[anchor] for anchor in ANCHORS]:
            with self.subTest(page=path.name):
                self.assertTrue(path.is_file(), f'{path} does not exist')

    def test_every_cross_referenced_anchor_is_present(self) -> 'None':
        """A missing anchor is a dead ``:ref:`` that renders as plain text.

        Sphinx is run here without ``-W`` and without ``nitpicky``, so an unresolved
        reference is not a build failure -- it is a word that used to be a link.
        Checked against each anchor's own file, since the split gave each anchor
        exactly one home rather than one shared page.

        """
        for anchor in ANCHORS:
            with self.subTest(anchor=anchor):
                text = _page(anchor)
                # ``assertTrue`` rather than ``assertIn``: the latter dumps the
                # whole page into the failure and buries the one line that says
                # which anchor went missing.
                self.assertTrue(f'.. _{anchor}:' in text,
                                f'.. _{anchor}: is no longer on {PAGES[anchor].name}')

    def test_no_page_carries_a_different_page_s_anchor(self) -> 'None':
        """Each anchor lives in exactly one file -- the split's whole point.

        Before the split, ``tests/corekit/test_sentinel_exports_unit.py`` sliced one
        shared page between ``.. _sentinel-convention:`` and
        ``.. _registry-protocol:`` -- reading ``text.index('.. _sentinel-convention:')``
        through ``text.index('.. _registry-protocol:', start)``. GitHub issue #930
        named separating those two anchors into different files as the split's
        concrete blocker, because that slice would then raise :exc:`ValueError` from
        :meth:`str.index` rather than a wrong answer. #918 part 2 retired the slice
        instead of working around it -- ``_sentinel_section`` now reads
        :file:`sentinel-convention.rst` whole. What used to be a hard constraint on
        the single page is now a fact about the separate files, pinned here so a later
        merge back into one page, or a bad copy-paste across two of them, does not
        silently resurrect it.

        """
        for anchor in ANCHORS:
            text = _page(anchor)
            for other in ANCHORS:
                if other == anchor:
                    continue
                with self.subTest(page=anchor, other_anchor=other):
                    self.assertNotIn(f'.. _{other}:', text,
                                     f'{PAGES[anchor].name} carries .. _{other}:, '
                                     f'which belongs in {PAGES[other].name}')

    def test_the_index_toctree_lists_every_page_in_order(self) -> 'None':
        """The index's toctree is what keeps every page from being an orphan.

        An orphan page still resolves cross-references -- Sphinx's reference
        inventory does not care whether a page is reachable from a toctree -- but it
        produces a distinct "document isn't included in any toctree" warning. Order
        matches :data:`ANCHORS`, the narrative order the single page used to carry
        its sections in, with pages added since appended in the order they arrived.

        """
        entries = _toctree_entries(INDEX.read_text(encoding='utf-8'))
        self.assertEqual(entries, list(ANCHORS),
                         f'{INDEX} toctree lists {entries!r}, expected '
                         f'{list(ANCHORS)!r}')

    def test_the_top_level_index_points_at_the_new_index_page(self) -> 'None':
        """:file:`docs/source/index.rst` has to name a document, not a directory.

        ``.. toctree::`` entries are docnames, and the bare ``contributing/conventions``
        entry it used to carry stopped being one the moment the split turned that
        path into a directory -- Sphinx would report "unknown document" for it,
        silently, since the build here runs without ``-W``/``-n``. Checked
        structurally rather than trusted to a nitpicky build alone.

        """
        text = (ROOT / 'docs' / 'source' / 'index.rst').read_text(encoding='utf-8')
        self.assertIn('contributing/conventions/index', text,
                      'docs/source/index.rst no longer points at the split index '
                      'page')
        self.assertNotRegex(text, r'(?m)^\s+contributing/conventions\s*$',
                            'docs/source/index.rst still names the retired bare '
                            '"contributing/conventions" path, which is now a '
                            'directory rather than a document')

    def test_the_index_preamble_does_not_claim_to_be_a_ruling_page_itself(self) -> 'None':
        """The index's own prose has to read true of a hub, not of a page.

        Round 1 of #918 part 2's split moved the ``.. important::`` preamble onto
        :data:`INDEX` unedited, and its prose was written when the whole thing was
        one page: *"This page records design rulings"*, and a future one *"is
        written onto this page"*. Both went false the moment the index stopped
        carrying any ruling of its own -- its children do -- and the second
        is worse than stale, because it is the standing instruction #918 part 3
        exists to keep alive, now telling a contributor to write onto the wrong
        file. A cross-review caught this on the first PR revision.

        Checked as a ban on the self-referential singular ``"this page"`` rather
        than against the exact old sentences, so a future rewrite that
        reintroduces the same mistake in different words still trips this -- the
        index legitimately never needs that phrase, since every true statement
        about ruling content here names a child page, or says "the pages below"
        / "here" for the set of them. Paired with a positive check that the
        corrected standing-instruction phrase actually landed, rather than merely
        that the old one is gone, following :class:`RetiredNameTests`'s two-sided
        pattern for a retired name elsewhere in this module.

        """
        text = INDEX.read_text(encoding='utf-8')
        self.assertNotIn('this page', text.lower(),
                         f'{INDEX} claims something about "this page" -- the '
                         'index carries no ruling of its own, so nothing on it '
                         'should read as self-referential')
        self.assertIn('the page that covers it', text,
                      f'{INDEX} no longer points a future ruling at "the page '
                      'that covers it"; the standing #918 instruction to '
                      'document a ruling in the same change that implements it '
                      'is pointing at the wrong target again')


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
        self.note = ' '.join(_page('registry-protocol').split())

    def test_the_walk_found_something_to_count(self) -> 'None':
        """Guards every count below from passing on an empty discovery."""
        self.assertGreater(len(self.enumerations), 100,
                           'the enumeration walk collapsed; the counts below would '
                           'pass vacuously')

    def test_the_page_states_the_measured_number_outside_the_hierarchy(self) -> 'None':
        """*"Zero enumerations remain outside the hierarchy"* -- against a runtime walk.

        GitHub issue #930 finished phase 2, so the page's own wording moved from
        *"are still outside"* -- true while seven remained -- to *"remain outside"*,
        which reads correctly now that none do.
        """
        stated = re.search(r'\*\*(\w+) enumerations remain outside the hierarchy\*\*',
                           self.note)
        self.assertIsNotNone(stated, 'the page no longer states how many enumerations '
                                     'are outside EnumLookup; the wording this test '
                                     'reads has changed')
        assert stated is not None  # for type checkers; asserted above
        self.assertEqual(NUMBER_WORDS[stated.group(1).lower()], len(self.outside),
                         f'the page says {stated.group(1)!r} but the tree has '
                         f'{len(self.outside)}: {sorted(self.outside.values())}')

    def test_the_page_names_every_enumeration_outside_the_hierarchy(self) -> 'None':
        """The count alone would pass on a wrong list of the right length.

        Vacuous while :attr:`self.outside` is empty -- GitHub issue #930 emptied
        it, and an empty dict gives the loop below nothing to iterate, so this
        method cannot fail no matter what the page says right now.
        ``test_the_page_states_the_measured_number_outside_the_hierarchy`` is
        what actually pins the empty state; this one is dormant rather than
        deleted, for whenever a future regression makes :attr:`self.outside`
        non-empty again, at which point it resumes checking that the page names
        each one. :meth:`~unittest.TestCase.skipTest` says so explicitly rather
        than passing silently.
        """
        if not self.outside:
            self.skipTest('self.outside is empty (GitHub issue #930); nothing to check')
        for name in sorted(self.outside.values()):
            with self.subTest(enumeration=name):
                self.assertIn(name.rsplit('.', maxsplit=1)[-1], self.note)

    def test_the_page_states_the_measured_phase_two_progress(self) -> 'None':
        """*"landed for 24 of the 24 non-registry enumerations"*, both figures.

        17 of 24 until GitHub issue #930 finished phase 2's remaining seven --
        ``CommandType``, ``ConformanceRequirement``, ``ESPStatus`` and the four
        Mobility Header helpers -- so both figures now read the same.
        """
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

    def test_the_audit_population_figures_are_the_measured_ones(self) -> 'None':
        """*The Audit, per Class*'s own population, against the same runtime walk.

        Six figures the section opens with -- the registry count, that every one of
        them is under :mod:`pcapkit.const`, the file count, the :class:`int`-valued
        and flag splits, the ``aenum.StrEnum`` count and the grand total -- were
        prose-only until GitHub issue #949 wired them to the walk. The section says
        itself that *the figures move*, which is precisely the case that needs a
        measurement rather than a reader's diligence: #930 moved the non-registry
        figures once already, and only those had a test.

        Each figure is read out of the page by its own regex and compared, so a stale
        one fails naming both numbers. Wording is not pinned; the regexes are
        deliberately loose about the prose between the figures and would survive a
        rephrasing that kept the claims.

        """
        from pcapkit.corekit.enum import EnumRegistry

        registries = {cls: name for cls, name in self.enumerations.items()
                      if issubclass(cls, EnumRegistry) and cls is not EnumRegistry}
        # ``issubclass(cls, int)`` rather than a check on ``_member_type_``: the flag
        # registries are ``IntFlag`` subclasses and have to count inside the int tier,
        # which is what the page's parenthetical "(of which N are flag registries)"
        # says -- a disjoint reading would make the two figures fail to add up.
        int_valued = {c: n for c, n in registries.items() if issubclass(c, int)}
        str_valued = {c: n for c, n in registries.items() if issubclass(c, str)}
        flags = {c: n for c, n in registries.items()
                 if issubclass(c, (enum.Flag, aenum.Flag))}
        files = {cls.__module__ for cls in registries}

        # Guards the rest from passing on a collapsed walk, as
        # ``test_the_walk_found_something_to_count`` does for the counts above.
        self.assertGreater(len(registries), 100,
                           'the registry half of the walk collapsed; the figures below '
                           'would pass vacuously')
        neither = sorted(name for cls, name in registries.items()
                         if not issubclass(cls, (int, str)))
        self.assertEqual(len(int_valued) + len(str_valued), len(registries),
                         'a registry is neither int- nor str-valued, so the page\'s '
                         f'two-tier split no longer partitions the population: {neither}')

        for pattern, measured, what in (
            (r'\*\*(\d+)\*\* :class:`~pcapkit\.corekit\.enum\.EnumRegistry` subclasses',
             len(registries), 'EnumRegistry subclasses'),
            (r'across (\d+) files', len(files), 'files holding a registry'),
            (r'(\d+) :class:`int`\\?-valued', len(int_valued), 'int-valued registries'),
            (r'of which (\d+) are flag registries', len(flags), 'flag registries'),
            (r'(\d+) ``aenum\.StrEnum``\\?-valued', len(str_valued),
             'str-valued registries'),
            (r'\*\*(\d+)\*\* non-registry enumerations', len(self.non_registry),
             'non-registry enumerations'),
            (r'(\d+) enumerations in total', len(self.enumerations),
             'enumerations in total'),
        ):
            with self.subTest(figure=what):
                stated = re.search(pattern, self.note)
                self.assertIsNotNone(
                    stated, f'the page no longer states how many {what} there are in '
                            'the shape this test reads; re-derive the figure rather '
                            'than deleting the check')
                assert stated is not None  # for type checkers; asserted above
                self.assertEqual(int(stated.group(1)), measured,
                                 f'the page says {stated.group(1)} {what}, the tree has '
                                 f'{measured}')

        # "every one of them under pcapkit.const" is a claim about the *whole*
        # population, not a count, so a figure comparison cannot reach it.
        self.assertIn('every one of them under :mod:`pcapkit.const`', self.note,
                      'the page no longer claims every registry lives under '
                      'pcapkit.const, so this check is pinning a claim it has dropped')
        stray = sorted(name for cls, name in registries.items()
                       if not cls.__module__.startswith('pcapkit.const'))
        self.assertEqual(stray, [],
                         'a registry now lives outside pcapkit.const, which the page '
                         f'says none do: {stray}')

    def test_the_case_differing_hip_parameters_both_resolve(self) -> 'None':
        """The page's worked reason for never renaming a member to make a lookup work.

        ``R1_Counter`` and ``R1_COUNTER`` are two IANA-registered HIP parameters
        differing only in case, and the page names both values. Executed rather than
        read off the page: the claim that matters is that a case-sensitive ``get``
        keeps both *resolvable*, which a substring match cannot establish.

        """
        from pcapkit.const.hip.parameter import Parameter

        for name, value in (('R1_Counter', 128), ('R1_COUNTER', 129)):
            with self.subTest(member=name):
                self.assertEqual(Parameter.get(name).value, value,
                                 f'{name} no longer resolves to {value}, so the page\'s '
                                 'worked example for case-sensitivity is stale')
                self.assertIn(f'``{name} = {value}``', self.note,
                              f'the page no longer states {name} = {value}, the '
                              'collision that makes renaming a member unacceptable')
        self.assertNotEqual(Parameter['R1_Counter'], Parameter['R1_COUNTER'],
                            'the two HIP parameters have collapsed into one member, so '
                            'the page\'s example of a case-significant registry is gone')


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
        section = _page('extension-header-subclassing')
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
    """#924's ruling that ``IPv6_GenericExt`` goes: an unreleased intermediate name."""

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

        section = ' '.join(_page('registry-protocol').split())
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


class AenumRoleExclusionTests(unittest.TestCase):
    """GitHub issue #934 part C's ruling: ``aenum`` cannot be cross-referenced.

    ``docs/source/conf.py`` excludes ``aenum`` from ``intersphinx_mapping``
    deliberately -- its ``objects.inv`` carries zero ``py:`` objects, so no
    ``:mod:``/``:class:``/``:func:``/etc. role naming it could ever resolve. Part
    B converted the six such roles this page carried to plain double-backtick
    literals rather than leaving them promising a link that can never exist. A
    forbidden role needs a test, or a later edit reintroduces one without
    noticing -- exactly the failure mode :class:`RetiredNameTests` guards a
    retired name against.

    The other half of the same fix is pinned alongside it: the four references to
    ``AbsentType``, ``NoValueType`` and ``ABSENT`` that part B qualified to their
    real dotted path under ``pcapkit.corekit.sentinels`` have to stay qualified,
    since none of the three resolves by its bare name outside
    :file:`docs/source/pcapkit/corekit/sentinels.rst`'s own ``.. module::``
    context.

    """

    #: Any Sphinx py-domain role whose target starts with ``aenum``, tilde-prefixed
    #: or not. Matches ``:mod:`aenum``` and ``:class:`~aenum.Enum``` alike; would
    #: also catch a role type never seen on this page (``:func:`aenum.something```),
    #: since the ban is on naming ``aenum`` in a role at all, not on the six
    #: specific roles #934 part C found.
    FORBIDDEN_AENUM_ROLE = re.compile(r':(?:mod|class|meth|func|attr|exc|obj|data):`~?aenum\b')

    #: The four qualified sentinel references part B's fix relies on: the role,
    #: the dotted target, and how many times that exact pairing has to appear.
    QUALIFIED_SENTINEL_REFS = (
        (':class:', '~pcapkit.corekit.sentinels.AbsentType', 2),
        (':class:', '~pcapkit.corekit.sentinels.NoValueType', 1),
        (':data:', '~pcapkit.corekit.sentinels.ABSENT', 1),
    )

    def test_no_aenum_role_appears(self) -> 'None':
        """A reintroduced ``:mod:`aenum``` or ``:class:`~aenum.X``` fails here.

        Checked as a role, not as the bare word: ``aenum`` still appears as a
        plain double-backtick literal (``` ``aenum.Enum`` ```) and in prose
        (*"the aenum flavours"*) throughout these pages, which is exactly the
        point of the fix -- only the unresolvable *role* form is banned. Scanned
        across every split page plus the index, since the six roles #934 part C
        found could each have landed in any of them.

        """
        text = _every_page()
        offenders = self.FORBIDDEN_AENUM_ROLE.findall(text)
        self.assertEqual(offenders, [],
                         f'the split conventions pages name aenum in a role '
                         f'again: {offenders!r}; GitHub issue #934 part C ruled '
                         'this unresolvable (conf.py excludes aenum -- zero py: '
                         'objects in its objects.inv) and converted every such '
                         'role to a plain literal')

    def test_the_qualified_sentinel_targets_stay_qualified(self) -> 'None':
        """A later edit unqualifying one of these reintroduces #934 part B's miss.

        ``AbsentType``, ``NoValueType`` and ``ABSENT`` each resolve only against
        the sentinels page's own module context (GitHub issue #936); written bare
        anywhere on these pages, none of the three resolves at all. All four
        qualified references happen to live in
        :file:`sentinel-convention.rst`, but this scans every split page plus the
        index so a later move of one does not go unnoticed.

        """
        text = _every_page()
        for role, target, count in self.QUALIFIED_SENTINEL_REFS:
            with self.subTest(target=target):
                needle = f'{role}`{target}`'
                actual = text.count(needle)
                self.assertEqual(actual, count,
                                 f'{needle!r} appears {actual} time(s) across '
                                 f'the split conventions pages, expected {count}')


class GetOverrideContractTests(unittest.TestCase):
    """What a ``get`` override owes the base, as recorded onto *The
    Registry Protocol* by GitHub issue #918 part 1.

    Three of the four items are quoted from the owner on their own threads -- #933 on
    ``quiet=True``, #935 on an advertised signature that is refused, #940 on deleting
    an override that only reimplements the base. The fourth, the ``@classmethod``
    requirement for delegation, is **not** a ruling and is not quoted as one: it is
    forced by the language, since zero-argument :func:`super` inside a
    ``@staticmethod`` has nothing to bind, and #913 set the shape that #908 then
    followed. Each states something the tree can be asked about. The page's
    half is what rots: the same four claims are already pinned in ``tests/corekit``
    and ``tests/protocols`` against the *code*, so a later change that moves the code
    fails there, while a page still describing the old shape fails nothing. This
    class is the other direction, and it is how the stale audit row this change
    corrected (*"Two of them define a ``get`` of their own"*, false since #940)
    would have been caught.

    """

    @staticmethod
    def _flat() -> 'str':
        """:meth:`_page`'s ``registry-protocol`` text, whitespace-normalised.

        Runs of whitespace are collapsed so a claim can be matched across the line
        wraps reStructuredText puts in mid-sentence -- the same normalisation
        :class:`FailedLookupExceptionTests` uses.

        """
        return ' '.join(_page('registry-protocol').split())

    def test_a_delegating_override_is_a_classmethod(self) -> 'None':
        """A delegating override is a ``@classmethod``, because the language says so.

        Not a ruling: zero-argument :func:`super` binds the enclosing function's
        first positional parameter, so in ``get(key, ...)`` it binds the lookup key
        and raises :exc:`TypeError` -- ``RuntimeError: super(): no arguments`` needs a
        function with no parameters at all, which no real override has.
        #913 set the shape and #908 followed it, producing ``Method.get``. The two
        surviving ``@staticmethod`` overrides are the stated exception -- neither
        calls ``super()``, so neither meets the condition. Read through :func:`vars`
        rather than by attribute access, since both descriptor kinds answer
        ``Cls.get('X')`` identically, which is the page's own point about callers not
        seeing the switch.

        """
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.http.method import Method
        from pcapkit.const.pcapng.option_type import OptionType

        # Membership before indexing, for all three. `vars(klass)['get']` raises a bare
        # `KeyError: 'get'` when a class folds its own override into the inherited base
        # -- which is exactly what GitHub pull request #940 did to the mh/ngap helpers,
        # so it is a live failure mode rather than a hypothetical one. The KeyError
        # fails the test either way, so nothing regressed silently; what it does not do
        # is say *which* class stopped defining `get`, or that the page is now wrong to
        # list it. The sibling at `test_the_two_redundant_overrides_are_gone` already
        # does this the right way round, with `assertNotIn('get', vars(klass))`.
        # Deliberately *not* under `subTest`: a subTest records its failure and lets
        # the method run on, so the bare `KeyError` this guard exists to pre-empt
        # would still be raised by the indexing below and reported alongside it. A
        # plain assertion aborts here, which is the whole point.
        for klass in (Method, Command, OptionType):
            self.assertIn('get', vars(klass),
                          f'{klass.__name__} no longer defines a get of its own, so '
                          'the page is wrong to name it among the overrides -- an '
                          'override folded into the inherited base is what #940 did '
                          'to the mh/ngap helpers')

        self.assertIsInstance(vars(Method)['get'], classmethod,
                              'a delegating override has to be a classmethod -- '
                              'zero-argument super() in a staticmethod binds the '
                              'first positional parameter, so get(key) raises '
                              'TypeError; #913 set the shape, #908 followed it')
        for klass in (Command, OptionType):
            with self.subTest(klass=klass.__name__):
                self.assertIsInstance(vars(klass)['get'], staticmethod)
                self.assertNotIn('super()', inspect.getsource(vars(klass)['get'].__func__),
                                 f'{klass.__name__}.get now delegates, so the page is '
                                 'wrong to list it as a surviving staticmethod')

        # Execute the three outcomes rather than assert the page names them. The
        # first draft of this test only grepped for the error string, and the
        # string it grepped for was the wrong one -- the page claimed
        # `RuntimeError: super(): no arguments` for a shape that actually raises
        # `TypeError`, and a prose-only assertion could not tell.
        class _Base:
            @classmethod
            def get(cls, key, default=None):  # noqa: D102
                return f'base:{key}'

        class _WithParam(_Base):
            @staticmethod
            def get(key, default=None):  # noqa: D102
                return super().get(key)  # type: ignore[misc]

        class _NoParams(_Base):
            @staticmethod
            def get():  # type: ignore[override]  # noqa: D102
                return super().get('x')  # type: ignore[misc]

        with self.assertRaises(TypeError) as caught:
            _WithParam.get('BASELINE-CONTROL')
        # Substring chosen to survive CPython's own rewording: 3.10-3.12 say
        # "obj must be an instance or subtype of type" while 3.13+ say "obj
        # (instance of str) is not an instance or subtype of type (Cls)". Only
        # `instance or subtype of type` is common to both, and pinning either
        # full sentence would fail three of the five required Compat legs --
        # invisible locally, since this venv is 3.14.
        self.assertIn('instance or subtype of type', str(caught.exception),
                      'zero-argument super() in a staticmethod binds the first '
                      'positional parameter -- the lookup key -- as its instance')

        with self.assertRaises(RuntimeError) as caught_runtime:
            _NoParams.get()
        self.assertIn('super(): no arguments', str(caught_runtime.exception),
                      'the no-parameter case is the one that raises RuntimeError; '
                      'the page must not attribute it to a get(key) override')

        # And the case that makes a staticmethod override actively unsafe rather
        # than merely broken: an instance first argument delegates silently.
        self.assertEqual(_WithParam.get(_WithParam()).split(':')[0], 'base',
                         'a staticmethod override cannot be relied on to fail '
                         'loudly, which is why the page says so')

        flat = self._flat()
        # Each wording pinned by a needle unique to it. The shared substring
        # ``instance or subtype of type`` occurs **three** times on the page -- both
        # quoted errors plus the sentence explaining what they share -- so asserting it
        # pinned neither: corrupting the 3.13+ quote to something false still passed.
        #
        # **Fourth instance of one defect shape**, after ``labels: bug`` (a bare token
        # matched elsewhere), the bare ``26`` (matched by the page's own ``wc -l``
        # output) and ``quiet=True`` (four occurrences). The rule, stated once here
        # because it kept being rediscovered: **an assertIn whose needle appears more
        # than once on the page pins nothing** -- a later occurrence satisfies it and
        # the claim it guards can be inverted freely. Count occurrences before
        # asserting, and anchor to something unique.
        self.assertIn('is not an instance or subtype of type', flat,
                      'the page no longer shows the 3.13+ wording of what a '
                      'staticmethod delegation raises')
        self.assertIn('must be an instance or subtype of type', flat,
                      'the page no longer records the 3.10-3.12 wording, so a '
                      'reader on those versions cannot match what they see')
        self.assertIn('silently succeeds', flat,
                      'the page no longer records that the TypeError is not '
                      'guaranteed')
        self.assertIn('forced by Python rather than decided', flat,
                      'the page no longer says the classmethod requirement is a '
                      'language constraint rather than a ruling')

    def test_the_base_raises_a_name_miss_quietly(self) -> 'None':
        """#933: the owner ruled that overrides follow the base and stay quiet.

        Measured rather than read off the source, because the cost the ruling turns
        on is the side effect: a loud :class:`BaseError` sets
        :data:`sys.tracebacklimit` to ``0`` for the whole process (#362), and a
        quiet one leaves it alone.

        """
        import sys

        from pcapkit.const.ftp.command import FEATCode
        from pcapkit.utilities.exceptions import EnumKeyError

        had = hasattr(sys, 'tracebacklimit')
        before = getattr(sys, 'tracebacklimit', None)

        def _restore() -> 'None':
            if had:
                sys.tracebacklimit = before  # type: ignore[assignment]
            elif hasattr(sys, 'tracebacklimit'):
                del sys.tracebacklimit

        self.addCleanup(_restore)

        # Run the behavioural check unconditionally. An earlier version guarded it
        # with `if not had:`, which meant a test that had already set
        # sys.tracebacklimit turned this into a prose-only check that still
        # reported pass -- silent degradation under test-order pollution rather
        # than a failure. Clearing it first is safe because _restore puts whatever
        # was there back.
        if had:
            del sys.tracebacklimit
        with self.assertRaises(EnumKeyError):
            FEATCode.get('ZZ-NOT-REAL')
        self.assertFalse(hasattr(sys, 'tracebacklimit'),
                         'a name miss set sys.tracebacklimit process-wide, so the '
                         "base's raise is no longer quiet -- GitHub issue #933 "
                         'ruled overrides follow the base here, not the reverse')

        flat = self._flat()
        # The *claim*, not his wording. This asserted `'not be loud'` until GitHub issue
        # #949, which is a fragment of the sentence he typed on the issue rather than
        # anything the ruling turns on; the substance is that the first answer on #933 is
        # not the ruling and the second one is. Occurs once on the page, checked.
        self.assertIn('first declined, then reversed', flat,
                      "the page no longer records that #933's ruling is the owner's "
                      'reversal rather than his first answer, which is the whole reason '
                      'both answers are on the issue')
        # Anchored to the headline sentence, not the bare token. `quiet=True` occurs
        # four times on the page, so `assertIn('``quiet=True``')` was satisfied by a
        # later mention -- inverting the ruling itself to `quiet=False` failed nothing.
        # Third instance of this shape: the `labels: bug` assertion and the bare `26`
        # both passed the same way, so the rule is now explicit -- never assert a token
        # that appears more than once on the page it is meant to pin.
        self.assertIn('Raise the way the base raises, which means** ``quiet=True``', flat,
                      'the page no longer states the ruling as its headline, so a '
                      'later mention of quiet=True is doing the work of pinning it')

    def test_the_two_redundant_overrides_are_gone(self) -> 'None':
        """#940: the owner ruled for deleting the redundant overrides, not widening them.

        Three things at once, because the ruling is only settled if all three hold:
        neither class defines ``get``, the module defines none at all, and the
        ``[override]``/``arguments-differ`` pair the old signatures needed went with
        them. Scoped to that exact pair rather than to ``arguments-differ`` alone,
        which mh.py still carries four times for ``read`` and ``__post_init__`` --
        unrelated to any ``get``, and measured before asserting on it.

        """
        from pcapkit.protocols.internet import mh
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        for klass in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(klass=klass.__name__):
                self.assertNotIn('get', vars(klass),
                                 f'{klass.__name__} defines get again; GitHub pull '
                                 'request #940 deleted it as redundant with '
                                 'EnumLookup.get')

        source = pathlib.Path(mh.__file__).read_text(encoding='utf-8')
        self.assertNotIn('def get(', source,
                         'pcapkit/protocols/internet/mh.py defines a get override '
                         'again, which the page says it does not')
        self.assertNotIn('type: ignore[override] # pylint: disable=arguments-differ',
                         source,
                         'the signature-mismatch suppression pair is back in mh.py; '
                         '#935 ruled a suppression is not an answer to a refused '
                         'signature')

        flat = self._flat()
        self.assertIn('deleting them outright', flat,
                      'the page no longer records that #940 ruled for deletion '
                      'rather than widening')
        self.assertIn('he took the first', flat,
                      'the page no longer records which of #935\'s three options '
                      'was taken')
        self.assertNotIn('**Two** of them define a ``get`` of their own', flat,
                         'the audit row claims two mh helpers still override get, '
                         'which #940 made false')

    def test_a_non_string_key_raises_a_value_miss_on_every_helper(self) -> 'None':
        """The divergence #940's deletion closed, which is the page's worked reason.

        The base branches on ``isinstance(key, str)`` and treats everything else as
        a value, so ``get(None)`` is a *value* miss. The deleted overrides branched
        on :class:`int` and fell through to the name path, making it a ``KeyError``
        on two of the six and a ``ValueError`` on the other four -- the same figures
        the page carries, and the ones this method derives below rather than trusts.

        """
        from pcapkit.utilities.exceptions import EnumValueError

        # Derived, not listed: the population is every EnumLookup subclass those two
        # modules *define* -- re-exports from pcapkit.const.ngap.* are not helpers of
        # theirs. An earlier version hard-coded three while its own name said seven
        # and the page said five; the real answer is six, so it is measured here and
        # asserted, rather than any of the three being trusted.
        import inspect

        from pcapkit.corekit.enum import EnumLookup
        import pcapkit.protocols.application.ngap as ngap_mod
        import pcapkit.protocols.internet.mh as mh_mod

        helpers = tuple(
            obj for mod in (mh_mod, ngap_mod) for obj in vars(mod).values()
            if inspect.isclass(obj) and issubclass(obj, EnumLookup)
            and obj is not EnumLookup and obj.__module__ == mod.__name__)
        self.assertEqual(
            len(helpers), 6,
            'the mh/ngap helper population changed, so the page\'s count of them is '
            f'stale: {sorted(k.__name__ for k in helpers)}')
        self.assertEqual(
            {k.__name__ for k in helpers},
            {'FastBindingAcknowledgmentStatus', 'IPv6AddressPrefixCode',
             'LMAAddressCode', 'LocalizedRoutingStatus', 'Criticality', 'PDUKind'})

        # The page's own figure, which measurement alone does not pin. Round 6 found
        # this row reading "The 5" against the measured six; the correction landed
        # unguarded, so it could have regressed exactly as it arrived.
        self.assertIn(f'The {len(helpers)} :mod:', _page('registry-protocol'),
                      'the audit table no longer states the measured helper count, '
                      'which is the figure that was already wrong once')

        for klass in helpers:
            for key in (None, 1.5):
                with self.subTest(klass=klass.__name__, key=key):
                    with self.assertRaises(EnumValueError):
                        klass.get(key)  # type: ignore[arg-type]

        flat = self._flat()
        self.assertIn('``isinstance(key, str)`` and treats everything else as a '
                      '*value*', flat,
                      "the page no longer records the base's own key dispatch, which "
                      "is the reason #940's deletion converged the six")


def _optional_dependencies() -> 'dict[str, list[str]]':
    """``pyproject.toml``'s ``[project.optional-dependencies]``, without a TOML library.

    :mod:`tomllib` is 3.11+ and this repository supports 3.10 -- a first version used it
    and failed the ``Python 3.10`` leg with ``ModuleNotFoundError`` while passing locally
    on 3.14. ``tomli``, the usual backport, is not a dependency here either
    (``grep -n tomli pyproject.toml`` finds nothing), so there is nothing to fall back to
    and adding one for a docs-claims test is not worth it.

    **Verified against** :mod:`tomllib` **rather than asserted.** A second version
    matched arrays with a non-greedy bracket pattern, which stopped at the first
    literal ``]`` -- which mis-parsed **3 of the 14** extras, silently:

    * ``vendor`` came back **empty**, because the ``]`` inside ``"requests[socks]"``
      closed the match early.
    * ``dev`` silently dropped its last two entries for the same reason.
    * ``test`` was truncated at a ``]`` inside a *comment* and then picked up a quoted
      example from the prose, **inventing a dependency called** ``9 skipped``.

    No shipped assertion read those three keys, so no test gave a wrong verdict -- but
    ``dev`` and ``vendor`` are both described in the page's own prose, so the next
    assertion to check either would have got wrong data with nothing raised. That is
    precisely the "renders fine and fails nothing" failure this suite exists to close,
    which is why it is fixed rather than documented around.

    So: strip ``#`` comments, then track bracket **depth** rather than matching to the
    first ``]``. Nested brackets inside requirement strings and comments containing ``]``
    are both handled; anything else in TOML is not attempted, and
    :meth:`ProcessConventionTests.test_the_extras_reader_agrees_with_tomllib` pins the
    agreement wherever a real parser is available.

    """
    text = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
    block = re.search(r'^\[project\.optional-dependencies\]\n(.*?)^\[',
                      text, re.MULTILINE | re.DOTALL)
    if block is None:  # pragma: no cover
        raise AssertionError(
            'pyproject.toml has no [project.optional-dependencies] section, so the '
            "page's extras claims have nothing to be checked against")

    # Comments first: a comment may contain ``]`` or a quoted string, and both fooled
    # the previous version. A ``#`` inside a requirement string is not a comment, so
    # quoted spans are skipped rather than blindly cut at the first ``#``.
    stripped = []
    for line in block.group(1).splitlines():
        out, quote = [], None
        for char in line:
            if quote:
                out.append(char)
                if char == quote:
                    quote = None
            elif char in '"\'':
                quote = char
                out.append(char)
            elif char == '#':
                break
            else:
                out.append(char)
        stripped.append(''.join(out))
    body = '\n'.join(stripped)

    extras = {}
    for match in re.finditer(r'^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*\[', body, re.MULTILINE):
        name = match.group(1)
        depth, index, quote = 1, match.end(), None
        while index < len(body) and depth:
            char = body[index]
            if quote:
                if char == quote:
                    quote = None
            elif char in '"\'':
                quote = char
            elif char == '[':
                depth += 1
            elif char == ']':
                depth -= 1
            index += 1
        extras[name] = re.findall(r'"([^"]*)"', body[match.end():index - 1])
    return extras


class ProcessConventionTests(unittest.TestCase):
    """The three process rulings :file:`process.rst` carries, against the tree.

    Each check pins the *claim the page makes* next to the *fact behind it*, and
    deliberately pins neither against the owner's own phrasing. Quoting him is what
    the page is forbidden to do here -- his instruction on GitHub issue #918 was to
    paraphrase -- and asserting a quoted sentence is separately a trap this module has
    already been bitten by: tests elsewhere in this file pinned two off-hand replies of
    his as literal strings, which made a sentence typed into a GitHub thread a CI build
    dependency. GitHub issue #949 removed the last of those. Attribution lives in the
    issue number the page cites; the tests check substance.

    """

    #: The page whose claims this class checks.
    ANCHOR = 'process'

    #: The changelog entry file the changelog ruling is about. Named rather than
    #: discovered: this is the 1.5.0 cycle's file, which is the one GitHub pull
    #: request #657 accumulates into and the one the page cites.
    CHANGELOG = ROOT / 'docs' / 'source' / 'changelog' / '1.5.0.rst'

    #: ``.github/PULL_REQUEST_TEMPLATE.md``'s commit-type tickbox list is the tree's
    #: own manifest of the type labels, so the page is checked against that rather
    #: than against a list retyped here -- which would only pin this file's memory of
    #: it.
    TEMPLATE = ROOT / '.github' / 'PULL_REQUEST_TEMPLATE.md'

    def setUp(self) -> 'None':
        # Whitespace-normalised, because the page wraps at 88 columns and every
        # sentence a claim is read out of is routinely split across lines.
        self.flat = ' '.join(_page(self.ANCHOR).split())

    def test_the_extras_reader_agrees_with_tomllib(self) -> 'None':
        """:func:`_optional_dependencies` matches a real TOML parser, key for key.

        The reader exists because :mod:`tomllib` is 3.11+ and this repository supports
        3.10, so the assertions above cannot use it. That makes the reader itself an
        unverified dependency of every extras claim on the page -- and its second
        version mis-parsed **3 of the 14** extras silently, inventing a requirement
        called ``9 skipped`` out of comment prose.

        So wherever a real parser *is* available -- which is every interpreter from 3.11
        up, including the one this suite usually runs on -- the two are compared
        directly. On 3.10 there is nothing to compare against and the test skips, which
        is honest: the reader is then unverified on the one version it was written for,
        and the CI matrix covers the other four.

        """
        try:
            import tomllib
        except ModuleNotFoundError:  # pragma: no cover
            self.skipTest('tomllib is 3.11+; no parser available to compare against')

        oracle = tomllib.loads(
            (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        )['project']['optional-dependencies']
        mine = _optional_dependencies()

        self.assertEqual(
            set(mine), set(oracle),
            'the extras reader found a different set of extras than tomllib does')
        for name in sorted(oracle):
            with self.subTest(extra=name):
                self.assertEqual(
                    mine[name], oracle[name],
                    f'the extras reader mis-parses {name!r}, so every page claim '
                    'resting on it is unverified -- nested brackets inside a '
                    'requirement string and a comment containing "]" are the two '
                    'shapes that broke it before')

    def test_the_all_extra_is_exactly_the_three_core_addon_extras(self) -> 'None':
        """``all`` carries core addons only, and the page's listing says what it is.

        Two halves, because either can rot without the other. The tree half asks
        :file:`pyproject.toml` whether ``all`` is still the union of ``cli``,
        ``crypto`` and ``NGAP`` and nothing else -- the shape GitHub issue #910's
        ruling produced, eight requirements down to three. The page half asks whether
        the ``toml`` block on the page still shows that same list, since a page that
        prints a stale ``all =`` line is worse than one that prints none.

        """
        extras = _optional_dependencies()

        core = [requirement for extra in ('cli', 'crypto', 'NGAP')
                for requirement in extras[extra]]
        self.assertEqual(sorted(extras['all']), sorted(core),
                         f"all is {extras['all']!r}, which is no longer the union of "
                         f'cli/crypto/NGAP {core!r} -- #910 narrowed it to the core '
                         'addons, so a change here is a change to that ruling')

        # The page prints the literal list, so the literal list is what is checked.
        listing = 'all    = [ ' + ', '.join(f'"{req}"' for req in extras['all']) + ' ]'
        self.assertIn(listing, _page(self.ANCHOR),
                      f'process.rst no longer shows {listing!r}; its toml block has '
                      "drifted from pyproject.toml's own all extra")

    def test_the_page_keeps_the_engine_and_installability_exclusions_apart(self) -> 'None':
        """The two exclusion reasons are the part a reader collapses into one.

        #910 excluded the four third-party engines **by kind** -- they are not core
        addons -- where ``PyPCAP`` and ``PCAP_CT`` were already out for
        *installability*, which the ruling did not touch. Reading those as one reason
        is what let the list drift the first time, so the page has to state both. The
        tree half checks the six engine extras still exist to be excluded from, since
        a prose distinction about extras that no longer exist is not a distinction.

        """
        extras = _optional_dependencies()

        for extra in ('DPKT', 'Scapy', 'PyShark', 'PyPCAPFile', 'PyPCAP', 'PCAP_CT'):
            with self.subTest(extra=extra):
                self.assertIn(extra, extras,
                              f'the {extra} extra is gone, so the page names an '
                              'extra a user cannot install')
                # Compare *requirements*, not the extra's name against them. The
                # previous form asked whether 'DPKT' was an element of
                # ['emoji', 'cryptography>=3.4', 'pycrate'] -- element equality against
                # a requirement string, so it could never be true and the regression its
                # own message names was unreachable. Measured: widening `all` back to
                # the pre-#910 engine set left this green while the sibling assertEqual
                # caught it.
                self.assertFalse(
                    set(extras[extra]) & set(extras['all']),
                    f"{extra}'s requirements are back inside all, which #910 excluded: "
                    f"{sorted(set(extras[extra]) & set(extras['all']))}")

        self.assertIn('excluded by kind', self.flat,
                      'the page no longer says the engines are excluded by kind, '
                      'which is the half of #910 that changed the list')
        self.assertIn('installability', self.flat,
                      'the page no longer separates the installability exclusion '
                      'the ruling left untouched from the by-kind one it introduced')

    def test_the_page_denies_one_changelog_entry_per_commit(self) -> 'None':
        """The ruling's substance, in the page's words rather than the owner's.

        The claim is narrow on purpose: entries are grouped by topic and are **not**
        one per commit. The grouping scheme itself was open when this test was first
        written and the page then carried a disclaimer saying so; it was ruled shortly
        afterwards -- a section per top-level module, with the kind headings nested
        inside -- so the page records the scheme and this checks for it. What is still
        unruled is narrower: which module an entry spanning several belongs under.

        """
        self.assertIn('not one line per commit', self.flat,
                      'the page no longer denies one entry per commit, which is the '
                      'whole of what the changelog ruling settled')
        self.assertIn('a section per top-level', self.flat,
                      'the page no longer records the module grouping the changelog '
                      'was ruled into')
        for module in ('const', 'corekit', 'foundation', 'protocols', 'vendor'):
            with self.subTest(module=module):
                self.assertTrue((ROOT / 'pcapkit' / module).is_dir(),
                                f'the page names {module} as a top-level module the '
                                'changelog groups by, but no such package exists')
        self.assertIn('spans modules', self.flat,
                      'the page no longer flags that an entry touching several '
                      'modules has no ruled home -- without it the scheme reads as '
                      'more complete than it is')

    def test_the_changelog_file_is_not_shaped_one_entry_per_commit(self) -> 'None':
        """The tree half: the file already groups, and already merges issues.

        Structural rather than counted. An entry count would be pinned to whatever
        GitHub pull request #657 had accumulated on the day, and would fail on its
        next merge for no reason a reader could act on -- so what is checked is that
        the kind headings are all present and that at least one entry cites two or
        more issues, which is the property that makes "one entry per commit" false of
        the file rather than merely discouraged.

        """
        text = self.CHANGELOG.read_text(encoding='utf-8')

        # Was ``assertIn(f'* **{kind}** --')`` against the inline bold labels the file
        # used before the by-module restructure. Those labels are gone -- the kinds are
        # now ``~``-underlined subsections inside each module section -- so the inline
        # form would fail for a reason that has nothing to do with this claim.
        for kind in ('Added', 'Changed', 'Fixed'):
            with self.subTest(kind=kind):
                self.assertRegex(
                    text, rf'(?m)^{kind}\n~+$',
                    f'{self.CHANGELOG.name} no longer groups entries under a '
                    f'{kind} subsection, which the page describes as its grouping')

        multi = [entry for entry in re.findall(r'(?ms)^\* .*?(?=^\* |\Z)', text)
                 if len(re.findall(r'#\d+', entry)) > 1]
        self.assertTrue(multi,
                        f'no entry in {self.CHANGELOG.name} cites more than one '
                        'issue, so the file is now consistent with one entry per '
                        'commit and the page describes something else')

    def test_the_page_names_every_commit_type_the_template_ticks(self) -> 'None':
        """The type labels come from the commit prefixes, so check the manifest.

        :file:`.github/PULL_REQUEST_TEMPLATE.md` is where a contributor actually meets
        the list, so it is the ground truth rather than a list retyped into this file.
        Note the label set is a **superset**: ``release`` and ``const`` are type-ish
        labels with no tickbox, so this is a one-way check by design.

        """
        types = re.findall(r'^- \[ \] `([a-z]+)` ', self.TEMPLATE.read_text(encoding='utf-8'),
                           re.MULTILINE)
        self.assertGreaterEqual(len(types), 8,
                                f'only {types!r} parsed out of the pull request '
                                'template; the check below would pass vacuously')
        for commit_type in types:
            with self.subTest(commit_type=commit_type):
                self.assertIn(f'``{commit_type}``', self.flat,
                              f'process.rst does not name the {commit_type} type '
                              'label, which the pull request template asks every '
                              'contributor to tick')

    def test_the_page_pins_its_own_measured_numbers(self) -> 'None':
        """Every figure the page states that has local ground truth.

        A cross-review corrupted **46** claims on these two pages simultaneously and
        the suite stayed green, which is the honest measure of how much of the prose
        was decorative. This closes the subset that has local ground truth: a figure
        derived from a file in this repository, a path the page cites, a module it
        names.

        **What stays unpinned, and why, so the gap is stated rather than implied.**
        Every claim whose ground truth is a GitHub query -- the label count, which
        default labels are in live use, the ``breaking`` census, the issue and pull
        request numbers -- cannot be checked here, because this repository's CI has no
        network. Those are why the page gives the *command* alongside the figure: the
        command is the pin, run by a reader rather than by CI. Inverting the page's
        live-use claim about GitHub's default labels still passes this suite, measured,
        and no offline test can change that.

        """
        import inspect
        import re as _re

        changelog = (ROOT / 'docs' / 'source' / 'changelog' / '1.5.0.rst') \
            .read_text(encoding='utf-8')
        # ``^\* \*\*Kind\*\*`` before the by-module restructure; the kinds are now
        # subsection headings, so an entry is simply a column-zero bullet.
        entries = _re.findall(r'^\* ', changelog, _re.MULTILINE)

        self.assertIn(f'{len(entries)} entries', self.flat,
                      f'the page no longer states the entry count, measured at '
                      f'{len(entries)}')

        # The module list the page prints as the by-module target. The tree half was
        # already checked; this is the page half, which a corruption inserting a
        # non-existent module survived.
        packages = sorted(d.name for d in (ROOT / 'pcapkit').iterdir()
                          if d.is_dir() and not d.name.startswith('__'))
        for name in packages:
            with self.subTest(module=name):
                self.assertIn(name, self.flat,
                              f'pcapkit/{name}/ exists but the page does not name it '
                              'among the modules the changelog groups by')
        # Only the ``ls -d`` comment block, not the whole page: elsewhere the page
        # legitimately writes the *distribution* name (``pip install
        # pypcapkit[Scapy]``), which is not a module and which a looser sweep flagged.
        listing = _re.search(r'ls -d pcapkit/\*/.*?(?=\n\n\S)',
                             _page(self.ANCHOR), _re.DOTALL)
        self.assertIsNotNone(
            listing, 'the page no longer prints the module listing command, so the '
                     'by-module target names no modules at all')
        named = set(_re.findall(r'\b([a-z]{4,12})\b', listing.group(0))) - {
            'pcapkit', 'sed'}
        self.assertFalse(
            named - set(packages),
            f'the module listing names something that is not a package under '
            f'pcapkit/: {sorted(named - set(packages))}')

        # Every workflow and config file the page cites by path.
        for cited in ('.github/workflows/lint.yml', '.github/release.yml',
                      '.github/ISSUE_TEMPLATE/bug_report.md',
                      '.github/ISSUE_TEMPLATE/feature_request.md',
                      '.github/dependabot.yml', 'pyproject.toml'):
            if cited.rsplit('/', 1)[-1] in self.flat:
                with self.subTest(path=cited):
                    self.assertTrue((ROOT / cited).is_file(),
                                    f'the page cites {cited}, which does not exist')

    def test_the_page_says_the_labels_are_set_by_hand(self) -> 'None':
        """The one statement the page was asked for outright.

        The owner asked on GitHub issue #918 for the labelling scheme to be explained
        here, and the thing repeatedly got wrong is agency: several agents have
        independently reported these labels as automation and acted on that. Nothing
        in the tree sets them -- :file:`.github/dependabot.yml` configures no
        ``labels:`` key, so even dependabot's are its own default rather than this
        repository's instruction -- and a reader who believes otherwise treats a
        ``review:`` label as evidence instead of as an assertion someone made.

        """
        self.assertNotIn('labels', (ROOT / '.github' / 'dependabot.yml')
                         .read_text(encoding='utf-8'),
                         'dependabot.yml now configures labels, so the page is wrong '
                         'to say dependabot uses its own defaults')
        self.assertIn('applied by hand', self.flat,
                      'process.rst no longer states that the labels are applied by '
                      'hand, which is the correction it was asked to carry')

        # The issue templates are the second automated path, and the first version of
        # this test could not see it: it read only dependabot.yml, so it passed while
        # the page claimed dependabot was the *single* exception. Every template that
        # sets a label in its front matter has to be named on the page, or the page
        # understates how many labels arrive without judgement behind them.
        templated = {}
        for template in sorted((ROOT / '.github' / 'ISSUE_TEMPLATE').glob('*.md')):
            for line in template.read_text(encoding='utf-8').splitlines():
                if line.startswith('labels:'):
                    templated[template.name] = line.split(':', 1)[1].strip()

        # The dependabot attribution, which had no pin at all -- which is how the page
        # came to name ``github_actions`` as dependabot-applied when
        # .github/dependabot.yml configures only ``pip``, so dependabot can never open a
        # workflow bump here. Saying a hand-applied label is a machine default is this
        # section's own point stated backwards, and the two places the page mentioned it
        # disagreed with each other about ``python``.
        dependabot = (ROOT / '.github' / 'dependabot.yml').read_text(encoding='utf-8')
        ecosystems = re.findall(r'package-ecosystem:\s*"([^"]+)"', dependabot)

        self.assertEqual(
            ecosystems, ['pip'],
            'dependabot now watches a different set of ecosystems, so the page\'s claim '
            f'about which labels it applies needs re-deriving: {ecosystems}')
        # Derived rather than pinned to one phrasing. The previous form asserted the
        # single literal ``dependencies`` and ``github_actions``, so a re-attribution
        # worded any other way -- "dependabot applies ``github_actions``", a comma for
        # the "and", the two labels in the other order -- slipped straight past it, which
        # is the weakness GitHub issue #949 asked to be looked at. Every sentence pairing
        # the tool with the label is checked instead, so the phrasing no longer matters.
        #
        # Proximity is not the test, and a first attempt at #949 that used it was wrong:
        # the section states **twice**, deliberately, that ``github_actions`` is *not*
        # dependabot's, and both of those sentences name the tool and the label together.
        # Distinguishing an attribution from a denial by looking for a negation nearby
        # also failed -- the attributing bullet's own sentence ends "so it never opens a
        # workflow bump here", so the negation is present in the sentence that makes the
        # claim as well as in the two that deny it.
        #
        # So the page's attribution is *parsed* instead: the one clause that says what
        # dependabot puts on its pull requests is located, the labels named inside it are
        # read out, and the set is compared against what the configured ecosystems could
        # actually produce. Set comparison is what makes it phrasing-independent -- a
        # comma for the "and", the labels in the other order, a third label added, all
        # compare the same -- and locating the clause is asserted rather than assumed, so
        # a rewording that this can no longer read fails loudly instead of passing.
        ECOSYSTEM_LABELS = {'pip': {'dependencies', 'python'},
                            'github-actions': {'dependencies', 'github_actions'}}
        expected = set().union(*(ECOSYSTEM_LABELS[eco] for eco in ecosystems))

        # `findall`, not `search`: a first-match-only read checks one attributing
        # clause and lets a second, contradicting one through. That is the same
        # walk-past-the-check defect this whole rewrite exists to remove, so every
        # clause matching the shape is required to name the same set.
        clauses = re.findall(r'\*\*dependabot\*\* puts (.+?) on its own pull requests',
                             self.flat)
        self.assertTrue(
            clauses,
            'the page no longer states which labels dependabot puts on its own pull '
            'requests in the shape this test reads, so the attribution is unpinned -- '
            're-derive it rather than dropping the check, because naming a hand-applied '
            "label as dependabot's is this section's own point stated backwards")
        for claimed in clauses:
            self.assertEqual(
                set(re.findall(r'``([^`]+)``', claimed)), expected,
                'the page attributes a different set of labels to dependabot than the '
                f'configured ecosystems {ecosystems} can produce. Claimed: '
                f'{claimed!r}')

        # And the positive half, which the set comparison above cannot reach: the page
        # has to say outright that ``github_actions`` is hand-applied. Without this, a
        # page that simply stopped mentioning the label would satisfy everything above.
        self.assertIn('hand-applied', self.flat,
                      'the page no longer says github_actions is hand-applied, so a '
                      'reader is left to assume the label arrives automatically')

        self.assertTrue(templated,
                        'no issue template sets a label any more, so the page is now '
                        'wrong in the other direction -- it names a path that is gone')
        for name, label in sorted(templated.items()):
            with self.subTest(template=name):
                self.assertIn(name, self.flat,
                              f'{name} applies a label from its front matter, but the '
                              'page does not name it among the automated paths')
                # Anchored to the template's own sentence, not a bare substring.
                # `assertIn('bug', flat)` passed against a page saying `labels:
                # defect`, because the word `bug` occurs elsewhere ("alongside ``bug``,
                # ``enhancement``") -- the same coincidence trap the changelog-runs
                # test already guards against.
                self.assertIn(f'``labels: {label}``', self.flat,
                              f'{name} applies {label!r} automatically, but the page '
                              'does not state that label next to the template that '
                              'applies it')

    def test_every_issue_link_number_matches_its_own_url(self) -> 'None':
        """A ``#NNN`` label and the issue or pull number in its own URL must agree.

        Purely local, needing no network, and it closes the largest single class of
        unpinned claim on these pages: a cross-review corrupted roughly thirty link
        numbers across both files and not one was caught, because nothing compared the
        displayed number against the target. A mismatch is invisible to a reader --
        the text says #918 and the link goes to #919 -- and Sphinx cannot warn, since
        both halves are well-formed.

        Scans every page rather than one, since a link can land on any of them.

        """
        pattern = re.compile(
            r'`#(\d+)\s*<https://github\.com/JarryShaw/PyPCAPKit/'
            r'(?:issues|pull)/(\d+)>`__')
        found = pattern.findall(_every_page())

        # A floor, because `assertEqual([], [])` is what an emptied page produces. This
        # check disables itself silently on any link-style change -- a single-underscore
        # named reference, or a move to an `:issue:` role, takes the regex to zero
        # matches while the docstring goes on claiming it closes the largest class of
        # unpinned claim. The module guards this shape five other times; this one had
        # been left out.
        self.assertGreater(
            len(found), 40,
            f'only {len(found)} issue links matched the pinned form, so this check is '
            'no longer examining the pages -- the link style changed and the test went '
            'quiet rather than red')

        mismatched = [(shown, target) for shown, target in found if shown != target]

        self.assertEqual(
            mismatched, [],
            'a link shows one issue number and points at another, which no reader '
            f'can see and no build can warn about: {mismatched}')

    def test_the_page_describes_the_changelog_grouping_as_it_is(self) -> 'None':
        """The current shape of ``1.5.0.rst``, counted rather than eyeballed.

        This replaces a check on the file's *previous* shape. The page used to say the
        entries carried three inline kind labels in a given number of separate runs,
        and this test measured those runs and required the figure in the prose. The
        by-module restructure removed the inline labels outright, so that test did not
        merely go stale -- it went **vacuous**: its ``re.findall`` matched nothing,
        ``runs`` was empty, and both of its ``assertGreater`` floors failed before the
        prose needle was ever reached. A test whose subject has been deleted cannot be
        repaired by updating a number.

        What is checked now is the shape that actually shipped: one ``-`` underlined
        section per top-level module plus one for what belongs to none, each carrying
        ``~`` underlined kind subsections, with no inline kind label left anywhere. The
        section count is required in the page's prose for the same reason the run count
        was -- a page that states a measured number has to restate it when the
        measurement moves.

        """
        changelog = (ROOT / 'docs' / 'source' / 'changelog' / '1.5.0.rst') \
            .read_text(encoding='utf-8')
        lines = changelog.splitlines()

        sections = [lines[i] for i in range(len(lines) - 1)
                    if lines[i].strip() and set(lines[i + 1]) == {'-'}
                    and len(lines[i + 1]) == len(lines[i])]
        kinds = [lines[i] for i in range(len(lines) - 1)
                 if lines[i].strip() and set(lines[i + 1]) == {'~'}
                 and len(lines[i + 1]) == len(lines[i])]

        self.assertGreater(
            len(sections), 1,
            'the changelog no longer carries per-module sections, so the by-module '
            'restructure the page describes has been undone')
        self.assertGreater(
            len(kinds), len(sections),
            'there are no more kind subsections than module sections, so the kinds '
            'are not nested inside the modules the way the page describes')
        self.assertEqual(
            [], [k for k in kinds if k not in ('Added', 'Changed', 'Fixed')],
            'a kind subsection is named something other than Added/Changed/Fixed')

        # The inline form is gone. This is the half that makes the claim falsifiable in
        # the direction that matters: a partial revert would restore it.
        self.assertEqual(
            [], re.findall(r'(?m)^\* \*\*(?:Added|Changed|Fixed)\*\*', changelog),
            'an entry carries an inline kind label again, so the file is back to the '
            'shape the page says it left')

        self.assertIn(f'**{len(sections)}** module-level sections', self.flat,
                      'the page no longer states the measured section count, which is '
                      'the figure a reader would check the restructure against')
        self.assertNotIn('separate runs', self.flat,
                         'the page still describes the entries as kind-label runs, '
                         'which the restructure removed')

    def test_the_page_keeps_breaking_additive_and_its_coverage_honest(self) -> 'None':
        """``breaking`` stacks on a type label, and its history is uneven.

        Both halves are prose claims with no local ground truth -- the label census is
        a GitHub query, which is why the page gives the command rather than a figure.
        What is checkable here is that the page has not quietly dropped either point:
        that the label is additive rather than a category of its own, and that its
        absence on an old item is weak evidence. The exception type the page cites as
        its worked example *is* local, so that much is verified rather than described.

        """
        from pcapkit.utilities.exceptions import BaseError, ProtocolError

        # Not `issubclass(ProtocolError, Exception)`, which every exception class
        # satisfies and which therefore verified nothing. The page's claim is that
        # #811 made a *library* error escape where a bare struct.error used to, so
        # what is checkable locally is that the type is the library's own.
        self.assertEqual(ProtocolError.__module__, 'pcapkit.utilities.exceptions',
                         'the page cites ProtocolError as an in-library exception '
                         'type, but it no longer comes from '
                         'pcapkit.utilities.exceptions')
        self.assertTrue(issubclass(ProtocolError, BaseError),
                        'ProtocolError no longer descends from the library base, so '
                        "the page's worked example no longer illustrates what it says")

        self.assertIn('additive', self.flat,
                      'the page no longer says breaking is additive; its own label '
                      'description is explicit that it goes alongside the type label')
        self.assertIn('not applied uniformly', self.flat,
                      'the page no longer warns that breaking is applied unevenly '
                      'across history, which is what makes an absence weak evidence')


if __name__ == '__main__':
    unittest.main()
