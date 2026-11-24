# -*- coding: utf-8 -*-
"""Tests that the ``unittest-ordering`` matrix shards ``protocols`` and ``project`` without losing a module.

#1029: unsharded, the ``protocols`` cell of ``unittest-ordering`` measured 30.4
minutes against the job's ``timeout-minutes: 45`` while every sibling leg stayed
under about 6.2 minutes, so the cell is split into sub-legs. Splitting has one way
to go quietly wrong, which is what this module pins: a module that falls between
two shards is never run by that job again, and nothing fails to say so -- the
job stays green while covering less. The assertions are therefore over the
*union*, not over the current list of names:

* the shards' module sets are disjoint and together equal the unsharded
  ``protocols`` leg, so a new ``tests/protocols/<dir>/`` is either inside a
  shard or fails here;
* #2254: the ``project`` cells cut that flat directory at module names, a
  ``--part`` per cell, all read from :data:`run_unittest_leg.SHARD_BOUNDARIES`,
  so they too are disjoint and together equal the unsharded leg, a module added
  later included; and ``project-tests``' cells halve it at
  :data:`run_unittest_leg.HALF_BOUNDARIES`' one name, its pins included (#2798).
  The rest of ``protocols``, everything but ``protocols/internet``, is cut at its
  own entry there (#2913), every part leaving out the same subdirectory;
* every other matrix cell is a bare direct child of ``tests/`` with no
  ``--exclude`` or boundary, i.e. runs that whole directory;
* every ``tests/`` subdirectory holding a test module is a leg, except the
  :data:`NOT_LEGS` names, each left out for the reason the workflow comment
  gives (#2115: a directory such as ``corekit`` left out, with nothing to say so).

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

from tests import _tiers  # noqa: E402  pylint: disable=wrong-import-position

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
    for part in _parts(flags):
        boundary.update(leg.part_bounds(name, int(part)))
    return boundary


def _parts(flags: 'str') -> 'list[str]':
    return re.findall(r'--part\s+(\S+)', flags)


def _matrix() -> 'list[tuple[str, list[str], dict[str, str]]]':
    """``(leg, exclude, boundary)`` for every cell of the ``unittest-ordering`` matrix.

    ``boundary`` maps the cell's ``--part``, ``--half``, ``--before`` and ``--from``
    to :func:`run_unittest_leg.leg_modules`'s ``before`` and ``start``.

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


def _project_tests_halves() -> 'list[str]':
    """The ``half`` values of the ``project-tests`` matrix (#2798)."""
    found = re.findall(r'^\s+half:\s*\[([^\]\n]*)\]\s*$', _job('project-tests'), re.M)
    if len(found) != 1:
        raise AssertionError(f'expected one half: list in project-tests, found {len(found)}')
    return [value.strip() for value in found[0].split(',')]


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

    def test_each_sharded_leg_cuts_at_its_names(self):
        """#2254, #2913: a ``--part`` per cell, each of the leg's parts once, cut at its
        ascending :data:`SHARD_BOUNDARIES` names, so any module name, one added later
        included, sorts into exactly one cell. The rest of ``protocols`` is cut the same
        way, every part leaving out ``protocols/internet``."""
        text = _job('unittest-ordering')
        self.assertEqual(sorted(part for flags in re.findall(r'shard:\s*([^\n]*)', text)
                                for part in _parts(flags)),
                         sorted(str(part) for top in SHARDED
                                for part in range(1, len(leg.SHARD_BOUNDARIES[top]) + 2)))
        for top in SHARDED:
            with self.subTest(leg=top):
                edges = leg.SHARD_BOUNDARIES[top]
                self.assertEqual(list(edges), sorted(set(edges)), f'the {top} names are not ascending')
                cells = [(exclude, boundary) for name, exclude, boundary in _matrix()
                         if name == top and boundary]
                boundaries = [boundary for _, boundary in cells]
                self.assertEqual(len(boundaries), len(edges) + 1, f'{top} runs a cell per part')
                self.assertEqual({value for b in boundaries for value in b.values()}, set(edges),
                                 f'the {top} cells cut at {boundaries}, not all at '
                                 f"SHARD_BOUNDARIES' {edges!r}")
                self.assertEqual(len({tuple(exclude) for exclude, _ in cells}), 1,
                                 f'the {top} parts leave out different subdirectories')
                keys = ['aaa/test_new.py', 'test_aaa_new.py', 'test_zzz_new.py', 'zzz/test_new.py']
                keys += [key for edge in edges for key in (edge, f'{edge}.py')]
                for key in keys:
                    with self.subTest(key=key):
                        hits = [b for b in boundaries
                                if ('before' not in b or key < b['before']) and key >= b.get('start', '')]
                        self.assertEqual(len(hits), 1)

    def test_project_tests_halves_the_leg(self):
        """#2798: on a docs-only diff each ``project-tests`` cell runs its half of the
        leg, cut at :data:`tests._tiers.PROJECT_BOUNDARY` rather than at the
        ``unittest-ordering`` parts' names (#2913), and between them the whole leg, once."""
        runs = re.findall(r'run_unittest_leg\.py\s+project\b([^\n]*)', _job('project-tests'))
        self.assertEqual(len(runs), 1, 'one step runs the leg, a half per cell')
        self.assertIn('--half ${{ matrix.half }}', runs[0])
        self.assertNotIn('--part', runs[0])
        halves = _project_tests_halves()
        self.assertEqual(sorted(halves), ['1', '2'])
        cuts = [_boundary('project', runs[0].replace('${{ matrix.half }}', half)) for half in halves]
        self.assertEqual({value for cut in cuts for value in cut.values()}, {_tiers.PROJECT_BOUNDARY})
        steps = [leg.leg_modules('project', **cut) for cut in cuts]
        self.assertTrue(all(steps), 'a cell runs no tests/project module')
        flat = [module for half in steps for module in half]
        self.assertEqual(len(flat), len(set(flat)), 'a module runs in both cells')
        self.assertEqual(sorted(flat), sorted(leg.leg_modules('project')))

    def test_project_tests_cells_partition_the_pins(self):
        """#2798: on a code diff each cell runs the pins on its side of the leg's cut, and
        between them every pin, once, a pin added later included."""
        self.assertIs(leg.HALF_BOUNDARIES['project'], _tiers.PROJECT_BOUNDARY)
        self.assertIn(f'{_tiers.PROJECT_PIN_HALF_SELECTOR} "$HALF"', _job('project-tests'))
        self.assertIn('HALF: ${{ matrix.half }}', _job('project-tests'))
        halves = _project_tests_halves()
        self.assertEqual(sorted(halves), sorted(str(half) for half in _tiers.PROJECT_HALVES))
        pins = [_tiers.project_pin_half(int(half)) for half in halves]
        self.assertTrue(all(pins), 'a cell runs no pin')
        flat = [pin for half in pins for pin in half]
        self.assertEqual(len(flat), len(set(flat)), 'a pin runs in two cells')
        self.assertEqual(sorted(flat), list(_tiers.project_pin_paths()), 'a pin falls between cells')
        for half, chosen in zip(halves, pins):
            with self.subTest(half=half):
                side = leg.leg_modules('project', **leg.half_bounds('project', int(half)))
                self.assertLessEqual({pin[:-len('.py')].replace('/', '.') for pin in chosen}, set(side))
        with self.assertRaises(ValueError):
            _tiers.project_pin_half(3)

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

    def test_a_part_is_cut_at_shard_boundaries(self):
        """#2913: part 1 runs before the first name, each later part from its
        predecessor's name to its own, and the last from the last name on."""
        for directory, edges in leg.SHARD_BOUNDARIES.items():
            with self.subTest(directory=directory):
                parts = [leg.part_bounds(directory, part) for part in range(1, len(edges) + 2)]
                self.assertEqual(parts[0], {'before': edges[0]})
                for index in range(1, len(edges)):
                    self.assertEqual(parts[index], {'start': edges[index - 1], 'before': edges[index]})
                self.assertEqual(parts[-1], {'start': edges[-1]})
                for part in (0, len(edges) + 2):
                    with self.subTest(part=part), self.assertRaises(SystemExit):
                        leg.part_bounds(directory, part)
        with self.assertRaises(SystemExit):
            leg.part_bounds('cli', 1)

    def test_a_half_is_the_boundary_from_half_boundaries(self):
        """#2798: ``--half`` cuts ``project`` where ``project-tests`` cuts its pins."""
        self.assertEqual(leg.HALF_BOUNDARIES, {'project': _tiers.PROJECT_BOUNDARY})
        for directory, edge in leg.HALF_BOUNDARIES.items():
            with self.subTest(directory=directory):
                self.assertEqual(leg.half_bounds(directory, 1), {'before': edge})
                self.assertEqual(leg.half_bounds(directory, 2), {'start': edge})
        for directory, half in (('cli', 1), ('protocols', 1), ('project', 0), ('project', 3)):
            with self.subTest(directory=directory, half=half), self.assertRaises(SystemExit):
                leg.half_bounds(directory, half)

    def test_a_named_cut_and_another_cut_are_refused_together(self):
        for argv, message in ((['project', '--half', '1', '--from', 'test_a'], '--half sets the boundary'),
                              (['project', '--part', '2', '--before', 'test_z'], '--part sets the boundary'),
                              (['project', '--part', '1', '--half', '1'], 'pass one'),
                              (['project', '--part', str(len(leg.SHARD_BOUNDARIES['project']) + 2)], 'has parts 1 to')):
            with self.subTest(argv=argv), \
                    unittest.mock.patch('sys.stderr', new_callable=io.StringIO) as err, \
                    self.assertRaises(SystemExit) as caught:
                leg.main(argv)
            self.assertIn(message, err.getvalue() + str(caught.exception.code))

    def test_the_tally_names_the_cut(self):
        """The leg's closing line says which side ran, as it does for ``--exclude``."""
        first, second = leg.SHARD_BOUNDARIES['project'][:2]
        for argv, expected in ((['project', '--half', '2'], f"(from {leg.HALF_BOUNDARIES['project']}) + "),
                               (['project', '--part', '1'], f'(before {first}) + '),
                               (['project', '--part', '2'], f'(from {first}) (before {second}) + ')):
            with self.subTest(argv=argv), \
                    unittest.mock.patch.object(leg, 'build_suite', return_value=unittest.TestSuite()), \
                    unittest.mock.patch('sys.stdout', new_callable=io.StringIO) as out, \
                    unittest.mock.patch('sys.stderr', new_callable=io.StringIO):
                self.assertEqual(leg.main([*argv, '--stall-dump', '0']), 0)
            self.assertIn(f'tests/project {expected}', out.getvalue())

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
