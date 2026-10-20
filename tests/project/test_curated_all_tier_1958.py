# -*- coding: utf-8 -*-
"""#1958, #1963: the ``ALL`` test tier is a curated, opt-in list.

The owner's rulings, paraphrased: ``ALL`` is a tailored list of tests, to save
time, to keep QA consistent across legs, and to be enough to validate a change on
each of them; every implementation runs the same minimal ``ALL`` tier while
``latest`` runs the whole suite as the gate; and the hand-picked round trips run
on ``ALL`` as part of QA, with only the real sweeps on ``latest``.
:func:`tests._tiers.module_tier` is the one source of truth, and
:file:`tests/test_tier_guard.py` checks that every module lands in exactly one
tier. This module pins the curation itself: a module is in ``ALL`` only when it
says so, ``ALL`` stays a strict subset of the suite, and it keeps the ruling-B
round trips.

"""

from __future__ import annotations

import pathlib
import tempfile
import unittest
import unittest.mock

from tests import _tiers

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'
#: The #1202 edge-case tables, each case written out by hand (ruling B).
EDGE_TABLES = tuple(sorted(path.relative_to(ROOT).as_posix()
                           for path in (ROOT / 'tests' / 'protocols').glob('*/test_*_edge_roundtrip_unit.py')))
#: The phrase every hand-picked round trip's marker reason carries.
HAND_PICKED = 'hand-picked'


def tier_of(source: 'str') -> 'str':
    """The tier of a module holding ``source``, under a temporary :file:`tests/`."""
    with tempfile.TemporaryDirectory(prefix='pcapkit-curated-tier-') as temp:
        root = pathlib.Path(temp).resolve()
        path = root / 'test_probe.py'
        path.write_text(source, encoding='utf-8')
        with unittest.mock.patch.object(_tiers, 'TESTS_ROOT', root):
            return _tiers.module_tier(path)


def reason(module: 'str') -> 'str':
    """The ``#:`` comment above ``module``'s ``__tier__`` marker, joined into one line."""
    lines = (ROOT / module).read_text(encoding='utf-8').splitlines()
    index = next(number for number, line in enumerate(lines) if line.startswith(_tiers.TIER_MARKER))
    comment = []  # type: list[str]
    for line in reversed(lines[:index]):
        if not line.startswith('#: '):
            break
        comment.insert(0, line[3:])
    return ' '.join(comment)


class TestAllIsOptIn(unittest.TestCase):
    """Only ``__tier__ = 'ALL'`` puts a module in ``ALL``."""

    def test_a_module_without_a_marker_is_latest(self) -> None:
        for label, source in {
                'imports pcapkit': 'import pcapkit\n',
                'imports a pcapkit submodule': 'from pcapkit.protocols.link import Ethernet\n',
                'reads text': 'TEXT = "pcapkit"\n',
        }.items():
            with self.subTest(case=label):
                self.assertEqual(tier_of(source), _tiers.TIER_LATEST)

    def test_the_marker_opts_in(self) -> None:
        self.assertEqual(tier_of("import pcapkit\n__tier__ = 'ALL'\n"), _tiers.TIER_ALL)

    def test_every_all_module_states_it(self) -> None:
        for module in _tiers.suite_modules():
            if _tiers.module_tier(module) == _tiers.TIER_ALL:
                with self.subTest(module=module):
                    self.assertEqual(_tiers.declared_tier(module), _tiers.TIER_ALL)


class TestAllIsAStrictSubset(unittest.TestCase):
    """``ALL`` is a curated part of the suite, never the suite, and keeps the ruling-B round trips."""

    def test_it_is_a_strict_subset_smaller_than_latest(self) -> None:
        modules = set(_tiers.suite_modules())
        selected = {module for module in modules if _tiers.module_tier(module) == _tiers.TIER_ALL}
        self.assertTrue(selected)
        self.assertLess(selected, modules)
        self.assertLess(len(selected), len(modules - selected))

    def test_it_keeps_the_edge_case_tables(self) -> None:
        self.assertTrue(EDGE_TABLES)
        for module in EDGE_TABLES:
            with self.subTest(module=module):
                self.assertEqual(_tiers.module_tier(module), _tiers.TIER_ALL)

    def test_it_keeps_every_hand_picked_round_trip(self) -> None:
        picked = [module for module in _tiers.suite_modules()
                  if _tiers.declared_tier(module) is not None and HAND_PICKED in reason(module)]
        self.assertTrue(set(EDGE_TABLES) <= set(picked))
        for module in picked:
            with self.subTest(module=module):
                self.assertEqual(_tiers.module_tier(module), _tiers.TIER_ALL)

    def test_the_sweeps_stay_on_latest(self) -> None:
        for module in ('tests/protocols/test_option_roundtrip_unit.py',
                       'tests/protocols/test_short_read_roundtrip_unit.py',
                       'tests/protocols/test_capture_roundtrip_runtime.py'):
            with self.subTest(module=module):
                self.assertEqual(_tiers.module_tier(module), _tiers.TIER_LATEST)


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_states_the_criterion(self) -> None:
        page = ' '.join(DOC.read_text(encoding='utf-8').split())
        section = page[page.index('Test Tiers ----------'):]
        for phrase in ("``__tier__ = 'ALL'``", 'opt-in', '#1963', 'smoke slice', 'hand-picked round trips',
                       'A module that states no tier is ``LATEST``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, section)

    def test_the_tier_module_states_the_criterion(self) -> None:
        text = ' '.join(_tiers.__doc__.split())
        for phrase in ('The curated ``ALL`` tier', 'opt-in', 'smoke slice', '``*_edge_roundtrip_unit``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)


if __name__ == '__main__':
    unittest.main()
