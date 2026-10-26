# -*- coding: utf-8 -*-
"""Tests that the ``unittest-ordering`` matrix shards ``protocols`` and ``project`` without losing a module.

#1029: the ``protocols`` cell of ``unittest-ordering`` measured 30.4 minutes
against the job's ``timeout-minutes: 45`` while every sibling leg stays under
about 6.2 minutes, so the cell was split into sub-legs. Splitting has one way
to go quietly wrong, which is what this module pins: a module that falls between
two shards is never run by that job again, and nothing fails to say so -- the
job stays green while covering less. The assertions are therefore over the
*union*, not over the current list of names:

* the shards' module sets are disjoint and together equal the unsharded
  ``protocols`` leg, so a new ``tests/protocols/<dir>/`` is either inside a
  shard or fails here;
* #2254: the ``project`` cells cut that flat directory at one module name,
  ``--half 1`` in one cell and ``--half 2`` in the other, both read from
  :data:`run_unittest_leg.SHARD_BOUNDARIES`, so they too are disjoint and
  together equal the unsharded leg, a module added later included; and
  ``project-tests``' docs-only steps cut it the same way;
* every other matrix cell is a bare direct child of ``tests/`` with no
  ``--exclude`` or boundary, i.e. runs that whole directory;
* every ``tests/`` subdirectory holding a test module is a leg, except the
  :data:`NOT_LEGS` names, each left out for the reason the workflow comment
  gives (#2115: ``corekit`` was missing, and nothing said so).

The workflow is read with a small hand-rolled scan rather than :mod:`yaml`,
which comes only with the ``test`` extra of :file:`pyproject.toml`; the same split
:file:`tests/project/test_workflow_apt_timeouts.py` uses.

"""

from __future__ import annotations

import io
import pathlib
import re
import sys
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'unit-tests.yml'

if str(ROOT / 'util') not in sys.path:
    sys.path.insert(0, str(ROOT / 'util'))

import run_unittest_leg as leg  # noqa: E402  pylint: disable=wrong-import-position

#: ``tests/`` subdirectories deliberately not in the matrix, each for the reason
#: the ``unittest-ordering`` comment in the workflow records (#2115).
NOT_LEGS = {
    # fixture-dependent tier only, run under pytest by ``integration``
    'integration',
}

#: The legs the matrix shards, each into cells that must partition it.
SHARDED = ('protocols', 'project')


def _test_directories() -> 'set[str]':
    """Every direct child of ``tests/`` that holds a ``test_*.py`` module."""
    return {path.name for path in leg.TESTS_ROOT.iterdir()
            if path.is_dir() and next(path.rglob('test_*.py'), None) is not None}


def _top(name: 'str') -> 'str':
    """The direct child of ``tests/`` a leg name lies in."""
    return name.split('/', 1)[0]


def _job(name: 'str') -> 'str':
    """The comment-stripped text of workflow job ``name``."""
    lines = []
    inside = False
    for raw in WORKFLOW.read_text(encoding='utf-8').splitlines():
        code = raw.split('#', 1)[0].rstrip()
        if re.match(rf'  {re.escape(name)}:\s*$', code):
            inside = True
        elif inside and re.match(r'  \S', code):
            break
        elif inside:
            lines.append(code)
    return '\n'.join(lines)


def _boundary(name: 'str', flags: 'str') -> 'dict[str, str]':
    """:func:`run_unittest_leg.leg_modules`'s ``before``/``start`` for a cell's or step's flags."""
    boundary = {'before' if flag == 'before' else 'start': value
                for flag, value in re.findall(r'--(before|from)\s+(\S+)', flags)}
    for half in re.findall(r'--half\s+(\S+)', flags):
        boundary.update(leg.half_bounds(name, int(half)))
    return boundary


def _halves(flags: 'str') -> 'list[str]':
    return re.findall(r'--half\s+(\S+)', flags)


def _matrix() -> 'list[tuple[str, list[str], dict[str, str]]]':
    """``(leg, exclude, boundary)`` for every cell of the ``unittest-ordering`` matrix.

    ``boundary`` maps the cell's ``--half``, ``--before`` and ``--from`` to
    :func:`run_unittest_leg.leg_modules`'s ``before`` and ``start``.

    """
    text = _job('unittest-ordering')

    matrix = text.split('matrix:', 1)[1].split('steps:', 1)[0]
    plain, _, extra = matrix.partition('include:')
    cells = [(name, [], {}) for name in re.findall(r'^\s+- (\S+)\s*$', plain.split('leg:', 1)[1], re.M)]
    for block in re.split(r'^\s+- (?=leg:)', extra, flags=re.M)[1:]:
        name = re.search(r'leg:\s*(\S+)', block).group(1)
        flags = re.search(r'exclude:\s*"?([^"\n]*)"?', block)
        shard = re.search(r'shard:\s*"?([^"\n]*)"?', block)
        boundary = _boundary(name, shard.group(1) if shard else '')
        cells.append((name, re.findall(r'--exclude\s+(\S+)', flags.group(1)) if flags else [], boundary))
    return cells


def _modules(name: 'str', exclude: 'list[str]', boundary: 'dict[str, str]') -> 'tuple[str, ...]':
    """What the cell ``(name, exclude, boundary)`` runs from its own directory."""
    return leg.leg_modules(name, exclude, **boundary)


class TestShardedProtocolsLeg(unittest.TestCase):

    def test_shards_partition_the_unsharded_leg(self):
        """#1029 for ``protocols``, #2254 for ``project``."""
        for top in SHARDED:
            with self.subTest(leg=top):
                shards = [_modules(*cell) for cell in _matrix() if _top(cell[0]) == top]
                self.assertGreater(len(shards), 1, f'{top} runs as a single cell')

                flat = [module for shard in shards for module in shard]
                self.assertEqual(len(flat), len(set(flat)), 'a module runs in two shards')
                self.assertEqual(set(flat), set(leg.leg_modules(top)),
                                 f'a tests/{top} module falls between shards')

    def test_the_project_cells_cut_at_one_name(self):
        """#2254: ``--half 1`` in one cell and ``--half 2`` in the other, one name between
        them, so any module name, one added later included, sorts into exactly one cell."""
        text = _job('unittest-ordering')
        self.assertEqual(sorted(half for flags in re.findall(r'shard:\s*([^\n]*)', text)
                                for half in _halves(flags)), ['1', '2'])
        boundaries = [boundary for name, _, boundary in _matrix() if name == 'project']
        self.assertEqual(sorted(sorted(b) for b in boundaries), [['before'], ['start']])
        self.assertEqual({value for b in boundaries for value in b.values()},
                         {leg.SHARD_BOUNDARIES['project']},
                         f'the project cells cut at {boundaries}, not all at '
                         f"SHARD_BOUNDARIES' {leg.SHARD_BOUNDARIES['project']!r}")
        edge = leg.SHARD_BOUNDARIES['project']
        for key in ('test_aaa_new.py', edge, f'{edge}.py', 'test_zzz_new.py'):
            with self.subTest(key=key):
                hits = [b for b in boundaries
                        if ('before' not in b or key < b['before']) and key >= b.get('start', '')]
                self.assertEqual(len(hits), 1)

    def test_project_tests_cuts_where_the_matrix_does(self):
        """#2254: ``project-tests``' docs-only steps run the two halves the ``project``
        cells do, one step each, and between them the whole leg, once."""
        runs = re.findall(r'run_unittest_leg\.py\s+project\b([^\n]*)', _job('project-tests'))
        self.assertEqual(sorted(half for flags in runs for half in _halves(flags)), ['1', '2'])
        steps = [leg.leg_modules('project', **_boundary('project', flags)) for flags in runs]
        cells = [_modules(*cell) for cell in _matrix() if cell[0] == 'project']
        self.assertEqual(sorted(steps), sorted(cells))
        flat = [module for half in steps for module in half]
        self.assertEqual(sorted(flat), sorted(leg.leg_modules('project')))

    def test_every_other_cell_is_a_plain_direct_child(self):
        others = [cell for cell in _matrix() if _top(cell[0]) not in SHARDED]
        self.assertEqual(sorted(name for name, _, _ in others),
                         sorted(_test_directories() - NOT_LEGS - set(SHARDED)))
        for name, exclude, boundary in others:
            self.assertEqual(exclude, [], name)
            self.assertEqual(boundary, {}, name)
            self.assertEqual(leg.leg_modules(name),
                             leg.leg_modules(name, ()), name)

    def test_every_tests_subdirectory_is_a_leg(self):
        """#2115: a ``tests/`` subdirectory left out of the matrix is never run
        under plain unittest, and the job stays green while covering less."""
        covered = {_top(name) for name, _, _ in _matrix()}
        self.assertEqual(sorted(_test_directories() - NOT_LEGS - covered), [],
                         'a tests/ subdirectory is missing from unittest-ordering')

    def test_every_exception_is_real_and_still_left_out(self):
        covered = {_top(name) for name, _, _ in _matrix()}
        for name in sorted(NOT_LEGS):
            with self.subTest(name=name):
                self.assertIn(name, _test_directories(), 'stale NOT_LEGS entry')
                self.assertNotIn(name, covered, 'a leg now, so drop it from NOT_LEGS')

    def test_integration_has_no_unit_tier_module(self):
        """The reason ``integration`` is not a leg: the leg would run only the
        root-level modules."""
        self.assertEqual(leg.leg_modules('integration'), ())

    def test_no_shard_is_empty(self):
        for cell in _matrix():
            self.assertTrue(_modules(*cell), cell[0])


class TestLegModulesSubpath(unittest.TestCase):

    def test_subpath_is_a_subset_of_its_parent(self):
        sub = leg.leg_modules('protocols/internet')
        self.assertTrue(sub)
        self.assertTrue(set(sub) <= set(leg.leg_modules('protocols')))
        self.assertTrue(all(m.startswith('tests.protocols.internet.') for m in sub))

    def test_exclude_removes_only_that_subtree(self):
        full = leg.leg_modules('protocols')
        rest = leg.leg_modules('protocols', ['protocols/internet'])
        self.assertEqual(set(full) - set(rest), set(leg.leg_modules('protocols/internet')))
        self.assertEqual([m for m in full if m in rest], list(rest), 'order changed')

    def test_before_and_from_split_at_one_name(self):
        """#2254: the two sides of a cut are the leg, in order, with the boundary module in the second."""
        full = leg.leg_modules('project')
        edge = full[len(full) // 2].rsplit('.', 1)[1]
        low = leg.leg_modules('project', before=edge)
        high = leg.leg_modules('project', start=edge)
        self.assertTrue(low and high)
        self.assertEqual(low + high, full)
        self.assertEqual(high[0], f'tests.project.{edge}')
        self.assertEqual(leg.leg_modules('project', before=edge, start=edge), ())

    def test_a_half_is_the_boundary_from_shard_boundaries(self):
        edge = leg.SHARD_BOUNDARIES['project']
        self.assertEqual(leg.half_bounds('project', 1), {'before': edge})
        self.assertEqual(leg.half_bounds('project', 2), {'start': edge})
        for directory, half in (('cli', 1), ('project', 3)):
            with self.subTest(directory=directory, half=half), self.assertRaises(SystemExit):
                leg.half_bounds(directory, half)

    def test_half_and_an_explicit_cut_are_refused_together(self):
        with unittest.mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            leg.main(['project', '--half', '1', '--from', 'test_a'])

    def test_the_tally_names_the_cut(self):
        """The leg's closing line says which side ran, as it does for ``--exclude``."""
        with unittest.mock.patch.object(leg, 'build_suite', return_value=unittest.TestSuite()), \
                unittest.mock.patch('sys.stdout', new_callable=io.StringIO) as out, \
                unittest.mock.patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(leg.main(['project', '--half', '2', '--stall-dump', '0']), 0)
        self.assertIn(f"tests/project (from {leg.SHARD_BOUNDARIES['project']}) + ", out.getvalue())

    def test_exclude_must_be_inside_the_leg(self):
        with self.assertRaises(SystemExit):
            leg.leg_modules('protocols', ['const'])
        with self.assertRaises(SystemExit):
            leg.leg_modules('protocols', ['protocols/no_such_dir'])

    def test_leg_must_stay_inside_tests(self):
        for bad in ('no_such_dir', '..', '../pcapkit', '.'):
            with self.assertRaises(SystemExit, msg=bad):
                leg.leg_modules(bad)


if __name__ == '__main__':
    unittest.main()
