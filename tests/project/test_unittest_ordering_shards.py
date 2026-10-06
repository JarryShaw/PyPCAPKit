# -*- coding: utf-8 -*-
"""Tests that the ``unittest-ordering`` matrix shards ``protocols`` without losing a module.

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
* every other matrix cell is a bare direct child of ``tests/`` with no
  ``--exclude``, i.e. runs exactly what it ran before the split.

The workflow is read with a small hand-rolled scan rather than :mod:`yaml`,
which comes only with the ``test`` extra of :file:`pyproject.toml`; the same split
:file:`tests/project/test_workflow_apt_timeouts.py` uses.

"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'unit-tests.yml'

if str(ROOT / 'util') not in sys.path:
    sys.path.insert(0, str(ROOT / 'util'))

import run_unittest_leg as leg  # noqa: E402  pylint: disable=wrong-import-position


def _matrix() -> 'list[tuple[str, list[str]]]':
    """``(leg, exclude)`` for every cell of the ``unittest-ordering`` matrix."""
    lines = []
    inside = False
    for raw in WORKFLOW.read_text(encoding='utf-8').splitlines():
        code = raw.split('#', 1)[0].rstrip()
        if re.match(r'  unittest-ordering:\s*$', code):
            inside = True
        elif inside and re.match(r'  \S', code):
            break
        elif inside:
            lines.append(code)
    text = '\n'.join(lines)

    matrix = text.split('matrix:', 1)[1].split('steps:', 1)[0]
    plain, _, extra = matrix.partition('include:')
    cells = [(name, []) for name in re.findall(r'^\s+- (\S+)\s*$', plain.split('leg:', 1)[1], re.M)]
    for block in re.split(r'^\s+- (?=leg:)', extra, flags=re.M)[1:]:
        name = re.search(r'leg:\s*(\S+)', block).group(1)
        flags = re.search(r'exclude:\s*"?([^"\n]*)"?', block)
        cells.append((name, re.findall(r'--exclude\s+(\S+)', flags.group(1)) if flags else []))
    return cells


class TestShardedProtocolsLeg(unittest.TestCase):

    def test_shards_partition_the_unsharded_leg(self):
        shards = [leg.leg_modules(name, exclude) for name, exclude in _matrix()
                  if name == 'protocols' or name.startswith('protocols/')]
        self.assertGreater(len(shards), 1, 'protocols is no longer sharded (#1029)')

        flat = [module for shard in shards for module in shard]
        self.assertEqual(len(flat), len(set(flat)), 'a module runs in two shards')
        self.assertEqual(set(flat), set(leg.leg_modules('protocols')),
                         'a tests/protocols module falls between shards')

    def test_every_other_cell_is_a_plain_direct_child(self):
        others = [(name, exclude) for name, exclude in _matrix()
                  if name != 'protocols' and not name.startswith('protocols/')]
        self.assertEqual(sorted(name for name, _ in others),
                         sorted(['cli', 'const', 'dumpkit', 'foundation', 'interface',
                                 'project', 'toolkit', 'utilities', 'vendor']))
        for name, exclude in others:
            self.assertEqual(exclude, [], name)
            self.assertEqual(leg.leg_modules(name),
                             leg.leg_modules(name, ()), name)

    def test_no_shard_is_empty(self):
        for name, exclude in _matrix():
            self.assertTrue(leg.leg_modules(name, exclude), name)


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
