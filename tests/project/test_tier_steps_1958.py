# -*- coding: utf-8 -*-
"""#1958: the workflow steps leave out the ``LATEST`` tier, or run it, as :mod:`tests._tiers` answers.

Every step asks :data:`~tests._tiers.LATEST_TIER_SELECTOR`,
:data:`~tests._tiers.LATEST_HALF_SELECTOR` or
:data:`~tests._tiers.PROJECT_PIN_HALF_SELECTOR` at run time, so none can drift from
:func:`~tests._tiers.module_tier`; what can is how each uses the answer.
:class:`WorkflowAgreementTests` runs the steps' scripts with :mod:`tests._steps`'
recording ``python`` and checks what they select, and :class:`PythonStubTests`
checks that stand-in. The selection is workflow text, the same on every
interpreter, so they run once per push, in a project pin, rather than on every leg
with :file:`tests/test_tier_guard.py` (#3148), which checks each leg's own answer at
collection.

"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from tests import _tiers
from tests._steps import (BASH, EXPERIMENTAL_WORKFLOW, PYTHON_STUB, WORKFLOW, job_section, leg_ignores,
                          leg_selects, project_pins_run, run_script, step_run_block)

#: Test tier (#1958): runs the workflow steps, whose selection is the same on every
#: interpreter, once per push (#3148).
__tier__ = 'LATEST'


class WorkflowAgreementTests(unittest.TestCase):
    """The tier rule here matches the one the workflow runs."""

    #: :data:`~tests._steps.PYTHON_STUB`'s ``$SELECTOR_CACHE`` for this class's steps,
    #: so each selector runs once per class rather than once per step run (#2254).
    selectors = ''

    #: The checks :meth:`test_the_steps_select_by_tier` runs, each a subtest named
    #: after the test it was: under ``--dist load`` each test of a class may run on a
    #: worker of its own, with a cache of its own (#3148).
    CHECKS = ('ignore_flags_match_the_fixture_tier_constants',
              'integration_job_selects_positively_by_asking_tiers_for_it',
              'the_legs_leave_out_exactly_the_latest_tier_or_the_pins',
              'a_leg_that_stops_ignoring_the_latest_tier_is_caught',
              'a_leg_that_asks_for_the_wrong_half_is_caught')

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        temp = tempfile.TemporaryDirectory(prefix='pcapkit-selectors-')
        cls.addClassCleanup(temp.cleanup)
        cls.selectors = temp.name

    def setUp(self) -> None:
        if not WORKFLOW.is_file():
            self.skipTest(f'{WORKFLOW} is not present, e.g. in a source distribution')
        self.text = WORKFLOW.read_text(encoding='utf-8')

    def test_the_steps_select_by_tier(self) -> None:
        for name in self.CHECKS:
            with self.subTest(f'test_{name}'):
                getattr(self, f'check_{name}')()

    def need_bash(self) -> None:
        if BASH is None:
            self.skipTest('the steps are bash scripts')

    def check_ignore_flags_match_the_fixture_tier_constants(self) -> None:
        """Every ignored path and glob is accounted for by a constant.

        The point of failure this catches: somebody adds another
        fixture-dependent naming convention to the workflow and the guard goes
        on classifying those modules as unit-tier, flagging their perfectly
        legal capture reads. No other glob is left: the round-trip sweeps
        (#1732) are left out by test tier (#1958), module by module, rather
        than by a name glob, so a glob here is a tier's or it is unaccounted
        for.

        """
        globs = set(re.findall(r"--ignore-glob='([^']+)'", self.text))
        directories = set(re.findall(r'--ignore=tests/(\S+)', self.text))

        self.assertEqual(globs, {f'*{suffix}' for suffix in _tiers.FIXTURE_TIER_SUFFIXES})
        self.assertEqual(directories, set(_tiers.FIXTURE_TIER_DIRS))
        self.assertNotIn('roundtrip', self.text)

    def check_integration_job_selects_positively_by_asking_tiers_for_it(self) -> None:
        """The ``integration`` job's selection runs the other direction, so it
        is checked the other way.

        The ``test`` job above is checked by parsing its ``--ignore`` /
        ``--ignore-glob`` flags out of the workflow text and comparing them to
        :data:`~tests._tiers.FIXTURE_TIER_DIRS` /
        :data:`~tests._tiers.FIXTURE_TIER_SUFFIXES` -- a *negative* selection,
        so those two regexes are what could drift from this module. The
        ``integration`` job instead *selects* the fixture-dependent tier
        positively, and a positive selection spelled out as literal paths
        would be invisible to those same regexes: nothing would stop it from
        drifting from :func:`~tests._tiers.skip_idiom_modules` while this test
        stayed green.

        So the ``integration`` job does not spell the selection out. Its "Run
        full test suite" step has to call
        :func:`~tests._tiers.fixture_tier_paths` directly instead of
        reimplementing the answer -- which makes drift structurally
        impossible rather than merely checked for, and is what this asserts.

        """
        run_block = step_run_block(job_section(self.text, 'integration'), 'Run full test suite')

        self.assertIn(
            'fixture_tier_paths', run_block,
            "the integration job's \"Run full test suite\" step no longer calls "
            "tests._tiers.fixture_tier_paths() -- see this check's docstring for why a "
            "hand-written selection here can drift silently"
        )
        self.assertIn('pytest', run_block)

    def check_the_legs_leave_out_exactly_the_latest_tier_or_the_pins(self) -> None:
        """#1958: run as bash runs them, the ``test`` legs, ``latest``'s too, ignore each ``LATEST`` module.

        #2751: each cell of ``test-latest-tier`` runs its half of the ``LATEST`` tier
        by name, and the halves leave out each project pin (#1954), which the cells
        of ``project-tests`` run, a half each (#2798). experimental.yml asks in a step
        of its own, under the runner's ``python3``; its legs run in
        :file:`tests/project/test_sweeps_on_latest_only_1732.py`.

        """
        self.need_bash()
        text = self.text
        pins = list(_tiers.project_pin_paths())
        latest = list(_tiers.latest_tier_paths())
        self.assertTrue(pins)
        self.assertLess(len(pins), len(latest))
        self.assertEqual(leg_ignores(text, cache=self.selectors), latest)
        self.assertEqual(leg_selects(text, cache=self.selectors), [])
        halves = []  # type: list[str]
        for half in _tiers.LATEST_TIER_HALVES:
            with self.subTest(half=half):
                selected = leg_selects(text, str(half), self.selectors)
                self.assertTrue(selected)
                self.assertEqual(selected, list(_tiers.latest_tier_half(half)))
                self.assertEqual(leg_ignores(text, str(half), self.selectors), [])
                halves.extend(selected)
        self.assertEqual(sorted(halves + pins), sorted(path for path in latest if _tiers.is_unit_tier(path)))
        ran = []  # type: list[str]
        for half in _tiers.PROJECT_HALVES:
            with self.subTest(pins=half):
                chosen = project_pins_run(text, str(half), self.selectors)
                self.assertTrue(chosen)
                self.assertEqual(chosen, list(_tiers.project_pin_half(half)))
                ran.extend(chosen)
        self.assertEqual(sorted(ran), pins)
        for workflow, job, step, selector in (
                (WORKFLOW, 'test', 'Run unit tests', _tiers.LATEST_HALF_SELECTOR),
                (WORKFLOW, 'test', 'Run unit tests', _tiers.LATEST_TIER_SELECTOR),
                (WORKFLOW, 'project-tests', 'Run the project pins', _tiers.PROJECT_PIN_HALF_SELECTOR),
                (EXPERIMENTAL_WORKFLOW, 'experimental', 'List the LATEST tier',
                 _tiers.LATEST_TIER_SELECTOR.replace('python -c', 'python3 -c'))):
            with self.subTest(job=job, selector=selector):
                script = run_script(job_section(workflow.read_text(encoding='utf-8'), job), step)
                self.assertIn(selector, script)
        # The experimental legs ignore what that step printed, as `test`'s legs do.
        tests = step_run_block(job_section(EXPERIMENTAL_WORKFLOW.read_text(encoding='utf-8'), 'experimental'),
                               'Run unit tests')
        self.assertIn('LATEST_TIER: ${{ steps.tier.outputs.paths }}', tests)
        self.assertIn('for module in $LATEST_TIER; do\n            set -- "$@" --ignore="$module"', tests)

    def check_a_leg_that_stops_ignoring_the_latest_tier_is_caught(self) -> None:
        """The check above, against a ``test`` step that computes the list and then drops it."""
        self.need_bash()
        loop = 'set -- "$@" --ignore="$module"'
        self.assertEqual(self.text.count(loop), 1, 'the loop this check removes has been reworded')
        self.assertEqual(leg_ignores(self.text.replace(loop, ':'), cache=self.selectors), [])
        # #2751: and a cell that computes its half and then drops it, which would run the whole suite.
        loop = 'set -- "$@" "$module"'
        self.assertEqual(self.text.count(loop), 1, 'the loop this check removes has been reworded')
        self.assertEqual(leg_selects(self.text.replace(loop, ':'), '1', self.selectors), [])

    def check_a_leg_that_asks_for_the_wrong_half_is_caught(self) -> None:
        """One half is not the other (#2751, #2798).

        A ``test`` leg that asks for the pins rather than the tier is
        :mod:`tests.project.test_sweeps_on_latest_only_1732`'s to catch.

        """
        self.need_bash()
        text = self.text
        self.assertEqual(text.count(_tiers.PROJECT_PIN_HALF_SELECTOR), 1)  # `project-tests`'s
        asked = 'project_pin_half(int(sys.argv[1]))'
        self.assertEqual(text.count(asked), 1)
        first = _tiers.PROJECT_HALVES[0]
        for half in _tiers.PROJECT_HALVES[1:]:
            with self.subTest(pins=half):
                self.assertNotEqual(project_pins_run(text.replace(asked, f'project_pin_half({first})'), str(half),
                                                     self.selectors), list(_tiers.project_pin_half(half)))
        asked = 'latest_tier_half(int(sys.argv[1]))'
        self.assertEqual(text.count(asked), 1)
        first = _tiers.LATEST_TIER_HALVES[0]
        for half in _tiers.LATEST_TIER_HALVES[1:]:
            with self.subTest(half=half):
                self.assertNotEqual(leg_selects(text.replace(asked, f'latest_tier_half({first})'), str(half),
                                                self.selectors), list(_tiers.latest_tier_half(half)))


@unittest.skipIf(shutil.which('sh') is None, 'the stub is a sh script')
class PythonStubTests(unittest.TestCase):
    """#1969: :data:`~tests._steps.PYTHON_STUB` records the command util/cap_file_size.py caps without a real ``python``."""

    @unittest.skipIf(os.name == 'nt', 'util/cap_file_size.py is POSIX-only (#2102)')
    def test_the_capped_command_is_recorded_without_the_real_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            for name, text in (('python', PYTHON_STUB), ('real', '#!/bin/sh\necho "$@" >> "$REAL_LOG"\n')):
                path = pathlib.Path(temp, name)
                path.write_text(text, encoding='utf-8')
                path.chmod(0o755)
            record, real = pathlib.Path(temp, 'args'), pathlib.Path(temp, 'real.log')
            env = dict(os.environ, ARGS_FILE=str(record), REAL_PYTHON=str(pathlib.Path(temp, 'real')),
                       REAL_LOG=str(real), PATH=temp + os.pathsep + os.environ.get('PATH', ''))
            command = ['-m', 'pytest', '-q', '-n', 'auto']
            result = subprocess.run(['python', 'util/cap_file_size.py', 'python', *command], env=env,
                                    capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(real.exists(), 'the real interpreter ran the capped command')
            self.assertEqual(record.read_text(encoding='utf-8').splitlines(), command)

    @unittest.skipIf(os.name == 'nt', 'the stub is found on PATH by name, as Windows does not find a sh script')
    def test_a_selector_runs_once_per_cache_and_a_failure_is_not_kept(self) -> None:
        """#2254: with ``$SELECTOR_CACHE`` set, each distinct ``-c`` reaches the real interpreter once."""
        real_python = '#!/bin/sh\necho "$@" >> "$REAL_LOG"\necho "answer $2"\n[ "$2" != fail ]\n'
        with tempfile.TemporaryDirectory() as temp:
            for name, text in (('python', PYTHON_STUB), ('real', real_python)):
                path = pathlib.Path(temp, name)
                path.write_text(text, encoding='utf-8')
                path.chmod(0o755)
            cache, real = pathlib.Path(temp, 'cache'), pathlib.Path(temp, 'real.log')
            cache.mkdir()
            env = dict(os.environ, ARGS_FILE=str(pathlib.Path(temp, 'args')), SELECTOR_CACHE=str(cache),
                       REAL_PYTHON=str(pathlib.Path(temp, 'real')), REAL_LOG=str(real),
                       PATH=temp + os.pathsep + os.environ.get('PATH', ''))

            def ask(code: 'str') -> 'subprocess.CompletedProcess[str]':
                return subprocess.run(['python', '-c', code], env=env, capture_output=True, text=True,
                                      check=False, timeout=60)

            self.assertEqual([ask(code).stdout for code in ('a', 'a', 'b')], ['answer a\n', 'answer a\n', 'answer b\n'])
            for _ in range(2):
                failed = ask('fail')
                self.assertEqual((failed.returncode, failed.stdout), (1, 'answer fail\n'))
            self.assertEqual(real.read_text(encoding='utf-8').splitlines(), ['-c a', '-c b', '-c fail', '-c fail'])


if __name__ == '__main__':
    unittest.main()
