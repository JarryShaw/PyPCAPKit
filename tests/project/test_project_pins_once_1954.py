# -*- coding: utf-8 -*-
"""#1954: the project pins run once per push, in ``project-tests``.

The owner's option 3, paraphrased: run the :file:`tests/project` modules whose run
does not vary by interpreter once per push, on pull requests and on pushes to
``main`` alike, and leave them out of every matrix leg; the modules that import
``pcapkit`` stay on every leg. :func:`tests._tiers.is_project_pin` decides which,
and :file:`tests/test_tier_guard.py` checks that rule and runs the steps that use
it. This module pins the rest: the job runs on every diff, on ``latest``, and
blocks; the release gate and the ``unittest-ordering`` ``project`` cells keep every pin; the
workflows page says so.

"""

from __future__ import annotations

import pathlib
import sys
import unittest

from tests import _tiers
from tests.project.test_python_matrix_tiers_1633 import job

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'
#: The job, and its step that runs the pins.
JOB = ('unit-tests.yml', 'project-tests')
STEP = 'Run the project pins'

if str(ROOT / 'util') not in sys.path:
    sys.path.insert(0, str(ROOT / 'util'))

import run_unittest_leg  # noqa: E402  pylint: disable=wrong-import-position


def step(where: 'tuple[str, str]', name: 'str') -> 'dict[str, object]':
    found = [entry for entry in job(*where)['steps'] if entry.get('name') == name]
    if len(found) != 1:
        raise AssertionError(f'expected one {name!r} step in {where}, found {len(found)}')
    return found[0]


class TestThePinsJob(unittest.TestCase):
    """``project-tests`` runs on every diff but ``gate-only``'s, on ``latest``, and gates.

    Its pins step skips a docs-only diff.

    """

    def test_it_runs_on_every_diff_but_not_under_gate_only(self) -> None:
        spec = job(*JOB)
        self.assertEqual(spec['if'], '${{ inputs.gate-only != true }}')
        self.assertEqual(spec['needs'], ['changes'])
        self.assertEqual(step(JOB, STEP)['if'], "${{ needs.changes.outputs.code != 'false' }}")
        self.assertIn('project-tests', job('unit-tests.yml', 'required-checks')['needs'])

    def test_it_runs_on_latest_with_what_test_installs(self) -> None:
        setup = next(entry for entry in job(*JOB)['steps'] if 'setup-python' in entry.get('uses', ''))
        self.assertEqual(setup['with']['python-version'], '${{ steps.python-versions.outputs.latest }}')
        install = step(JOB, 'Install package and test dependencies')['run']
        # #1958: what `test` installs on `latest`, the leg the pins would run on.
        self.assertIn(step(('unit-tests.yml', 'test'), "Install the whole suite's dependencies on latest")['run']
                      .split("pip install -e '", 1)[1].split("'", 1)[0], install)

    def test_it_runs_under_the_caps(self) -> None:
        """xdist as ``test`` runs it, a 2 GiB file cap, and a step cap under the job's."""
        run = str(step(JOB, STEP)['run'])
        self.assertIn('python util/cap_file_size.py python -m pytest -q -n auto --dist load', run)
        self.assertIn(_tiers.PROJECT_PINS_SELECTOR, run)
        self.assertLess(step(JOB, STEP)['timeout-minutes'], job(*JOB)['timeout-minutes'])


class TestEveryPinStillRunsWhereTheMatrixDoesNot(unittest.TestCase):
    """The release gate's full suite and ``unittest-ordering``'s ``project`` cells keep every pin."""

    def test_the_gate_runs_the_whole_suite(self) -> None:
        self.assertEqual(step(('unit-tests.yml', 'gate'), 'Run full test suite')['run'],
                         'python util/cap_file_size.py python -m pytest -q -n auto --dist load')

    def test_the_ordering_cell_runs_every_pin(self) -> None:
        """#2254: the ``project`` cells between them, as they cut ``tests/project`` in two."""
        matrix = job('unit-tests.yml', 'unittest-ordering')['strategy']['matrix']
        cells = [{'leg': name} for name in matrix['leg']] + list(matrix.get('include') or [])
        modules = set()
        for cell in cells:
            if cell['leg'] == 'project':
                words = str(cell.get('shard', '')).split()
                flags = dict(zip(words[::2], words[1::2]))
                cut = run_unittest_leg.half_bounds('project', int(flags['--half'])) if '--half' in flags else {}
                modules.update(run_unittest_leg.leg_modules('project', **cut))
        self.assertTrue(modules, 'no unittest-ordering cell runs tests/project')
        pins = {pin[:-len('.py')].replace('/', '.') for pin in _tiers.project_pin_paths()}
        self.assertTrue(pins)
        self.assertEqual(pins - modules, set())

    def test_every_pin_is_in_the_latest_tier(self) -> None:
        """#1958: the pins are ``LATEST`` modules, so the legs off ``latest`` leave them out with the rest of
        the tier, and ``latest`` leaves out the pins alone."""
        pins = set(_tiers.project_pin_paths())
        self.assertTrue(pins)
        self.assertEqual({_tiers.module_tier(pin) for pin in pins}, {_tiers.TIER_LATEST})
        self.assertLess(pins, set(_tiers.latest_tier_paths()))
        run = str(step(('unit-tests.yml', 'test'), 'Run unit tests')['run'])
        self.assertIn(_tiers.PROJECT_PINS_SELECTOR, run)
        self.assertIn(_tiers.LATEST_TIER_SELECTOR, run)


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_has_the_rule_and_the_job(self) -> None:
        text = DOC.read_text(encoding='utf-8')
        section = text.split('\nProject Pins\n------------\n', 1)[1].split('\n----', 1)[0]
        for phrase in ('``is_project_pin()``', '``project_pin_paths()``', '``project-tests``', '#1954',
                       '``--ignore``', '``gate``', '``unittest-ordering``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, section)


if __name__ == '__main__':
    unittest.main()
