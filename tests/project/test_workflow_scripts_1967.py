# -*- coding: utf-8 -*-
"""#1967: the ``util/`` scripts that replace shell the workflows repeated, run as the steps run them.

* :file:`util/leg_summary.py`, every ``KTLO summary`` and the ``Experimental
  summary``: :class:`TestLegSummary`. The steps themselves are pinned in
  :mod:`tests.project.test_ktlo_legs_stay_green_1672`.
* :file:`util/classify_changes.py`, ``Classify the diff`` in both ``changes`` jobs:
  :class:`TestClassifyChanges`. Its classification against a real merge commit is
  :mod:`tests.project.test_unit_tests_queue`'s.
* :file:`util/coverage_report.py`, ``Report coverage``: :class:`TestCoverageReport`.
  Its data check is :mod:`tests.project.test_coverage_data_guard`'s.

"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import unittest

from tests._workflows import steps

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
#: A leg name holding a comma, which an annotation's title must escape.
LEG = 'Python 3.9 (KTLO, non-blocking)'


def steps_json(**outcomes: 'str') -> 'str':
    """``toJSON(steps)`` for steps with these outcomes, in this order."""
    return json.dumps({key: {'outputs': {}, 'outcome': outcome,
                             'conclusion': 'success' if outcome == 'failure' else outcome}
                       for key, outcome in outcomes.items()})


def run(script: 'str', *args: 'str', env: 'dict[str, str]',
        cwd: 'pathlib.Path') -> 'subprocess.CompletedProcess[str]':
    """``python util/<script> args`` in ``cwd``, with ``env`` on top of this process's."""
    return subprocess.run([sys.executable, str(UTIL / script), *args], cwd=cwd,  # nosec: B603
                          env=dict(os.environ, **env), capture_output=True, text=True, check=False, timeout=300)


class _Scratch(unittest.TestCase):

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.page = self.tmp / 'summary.md'
        self.page.write_text('earlier\n', encoding='utf-8')


class TestLegSummary(_Scratch):
    """One ``::warning`` and one job-summary line per failed step, in ``STEPS`` order."""

    def summary(self, tier: 'str', steps: 'str') -> 'subprocess.CompletedProcess[str]':
        return run('leg_summary.py', tier, env={'LEG': LEG, 'STEPS': steps,
                                                'GITHUB_STEP_SUMMARY': str(self.page)}, cwd=self.tmp)

    def test_each_failed_step_is_reported_in_order(self) -> None:
        result = self.summary('ktlo', steps_json(tests='failure', checkout='success', install='failure'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            '::warning title=tests failed on Python 3.9 (KTLO%2C non-blocking)::KTLO legs never block (#1633), '
            "so this job still succeeds (#1672); see the tests step's log.",
            '::warning title=install failed on Python 3.9 (KTLO%2C non-blocking)::KTLO legs never block (#1633), '
            "so this job still succeeds (#1672); see the install step's log.",
        ])
        # Appended, as `>> "$GITHUB_STEP_SUMMARY"` appends.
        self.assertEqual(self.page.read_text(encoding='utf-8'),
                         f'earlier\n- {LEG}: step `tests` failed; non-blocking, so this job still succeeds.\n'
                         f'- {LEG}: step `install` failed; non-blocking, so this job still succeeds.\n')

    def test_the_tier_words_the_reason(self) -> None:
        result = self.summary('experimental', steps_json(install='failure'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('::Experimental legs never block (#1660), so this job still succeeds; '
                      "see the install step's log.", result.stdout)

    def test_nothing_failed_writes_nothing(self) -> None:
        """A skipped or cancelled step is not a failure."""
        result = self.summary('ktlo', steps_json(checkout='success', install='skipped', tests='cancelled'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'{LEG}: no step failed.\n')
        self.assertEqual(self.page.read_text(encoding='utf-8'), 'earlier\n')

    def test_bad_input_fails_the_step(self) -> None:
        """As ``jq`` failing under ``bash -e`` did; the step's ``continue-on-error`` contains it."""
        for tier, steps in (('ktlo', 'not json'), ('nightly', steps_json(install='failure'))):
            with self.subTest(tier=tier, steps=steps):
                result = self.summary(tier, steps)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('::warning', result.stdout)
                self.assertEqual(self.page.read_text(encoding='utf-8'), 'earlier\n')


class TestClassifyChanges(_Scratch):
    """The output line is appended, and an unreadable diff is code with a warning."""

    def test_another_event_is_code(self) -> None:
        output = self.tmp / 'output'
        output.write_text('earlier=1\n', encoding='utf-8')
        result = run('classify_changes.py', env={'OWN_PR': 'false', 'GITHUB_OUTPUT': str(output)}, cwd=self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Not this workflow's own pull_request run: everything runs.\ncode=true\n")
        self.assertEqual(output.read_text(encoding='utf-8'), 'earlier=1\ncode=true\n')

    def test_an_unreadable_diff_warns_and_is_code(self) -> None:
        if shutil.which('git') is None:  # pragma: no cover
            self.skipTest('git is not available')
        output = self.tmp / 'output'
        env = {'OWN_PR': 'true', 'GITHUB_OUTPUT': str(output), 'GIT_CEILING_DIRECTORIES': str(self.tmp.parent)}
        result = run('classify_changes.py', env=env, cwd=self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r'^::warning title=Could not list the changed files::git diff exited '
                                        r'[1-9]\d* with 0 files: .*Treating the diff as code\.\ncode=true\n$')
        self.assertEqual(output.read_text(encoding='utf-8'), 'code=true\n')

    def test_both_workflows_run_it_from_a_checkout(self) -> None:
        for name in ('unit-tests.yml', 'experimental.yml'):
            found = steps(name, 'changes')
            with self.subTest(workflow=name):
                self.assertNotIn('if', found[0])
                self.assertEqual(found[0]['with'], {'fetch-depth': 2})
                self.assertEqual(found[1]['run'], 'python3 util/classify_changes.py')


#: ``coverage.json`` for two packages and a top-level module, as ``coverage json`` writes it.
COVERAGE_JSON = {
    'files': {
        'pcapkit/__init__.py': {'summary': {'num_statements': 10, 'missing_lines': 0, 'num_branches': 0,
                                            'num_partial_branches': 0, 'covered_lines': 10,
                                            'covered_branches': 0}},
        'pcapkit/protocols/a.py': {'summary': {'num_statements': 8, 'missing_lines': 2, 'num_branches': 4,
                                               'num_partial_branches': 1, 'covered_lines': 6,
                                               'covered_branches': 3}},
        'pcapkit/protocols/b/c.py': {'summary': {'num_statements': 2, 'missing_lines': 2, 'num_branches': 0,
                                                 'num_partial_branches': 0, 'covered_lines': 0,
                                                 'covered_branches': 0}},
    },
    'totals': {'percent_covered': 79.16666},
}
ENV = {'TESTS_OUTCOME': 'failure', 'PYTHON': '3.15', 'SHA': '0123456789abcdef'}


class TestCoverageReport(_Scratch):
    """The table and ``coverage-summary.json``, and the stages in order."""

    def env(self, **extra: 'str') -> 'dict[str, str]':
        return dict(ENV, GITHUB_STEP_SUMMARY=str(self.page), **extra)

    def test_the_summary_stage_writes_the_table_and_the_numbers(self) -> None:
        (self.tmp / 'coverage.json').write_text(json.dumps(COVERAGE_JSON), encoding='utf-8')
        result = run('coverage_report.py', 'summary', env=self.env(), cwd=self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.page.read_text(encoding='utf-8'), (
            'earlier\n'
            '**Coverage: 79.17%** -- **tests failure**, so this is partial (unit tier, Python 3.15, `012345678`)\n'
            '\n'
            '| Package | Statements | Missed | Branches | Partial | Cover |\n'
            '|---|--:|--:|--:|--:|--:|\n'
            '| `pcapkit (top level)` | 10 | 0 | 0 | 0 | 100.00% |\n'
            '| `pcapkit/protocols` | 10 | 4 | 4 | 1 | 64.29% |\n'
            '\n'
            'Per-file detail: the `coverage-html` artifact of this run.\n'))
        self.assertEqual(json.loads((self.tmp / 'coverage-comment' / 'coverage-summary.json').read_text()), {
            'total': 79.17, 'tests': 'failure', 'python': '3.15',
            'packages': [['pcapkit (top level)', 10, 0, 0, 0, 100.0], ['pcapkit/protocols', 10, 4, 4, 1, 64.29]]})

    def test_a_failing_coverage_command_ends_the_step_with_its_status(self) -> None:
        """As ``set -e`` did: no summary after a failed ``coverage`` command."""
        (self.tmp / 'coverage-processes.log').write_text(
            "  100.ab: New process: cmd: ['/x', 'run', '--rcfile=.github/coverage.toml', '-m', 'pytest']\n"
            '  100.ab: New process parent pid: 1\n  101.ab: New process parent pid: 100\n', encoding='utf-8')
        for pid in (100, 101):
            (self.tmp / f'.coverage.host.pid{pid}.X.Y').write_text('not a coverage data file', encoding='utf-8')
        result = run('coverage_report.py', env=self.env(), cwd=self.tmp)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing data: []', result.stdout)
        self.assertEqual(self.page.read_text(encoding='utf-8'), 'earlier\n')
        self.assertFalse((self.tmp / 'coverage-comment').exists())

    def test_every_stage_on_a_real_coverage_run(self) -> None:
        """A real ``coverage run`` whose child stands in for an xdist worker, reported end to end."""
        try:
            import coverage  # pylint: disable=import-outside-toplevel
        except ImportError:  # pragma: no cover
            self.skipTest('needs coverage')
        if tuple(int(x) for x in coverage.__version__.split('.')[:2]) < (7, 10):  # pragma: no cover
            self.skipTest('needs coverage 7.10+ (`[run] patch`)')
        (self.tmp / '.github').mkdir()
        shutil.copy(ROOT / '.github' / 'coverage.toml', self.tmp / '.github' / 'coverage.toml')
        (self.tmp / 'pcapkit').mkdir()
        (self.tmp / 'pcapkit' / '__init__.py').write_text('def f(x):\n    if x:\n        return 1\n    return 2\n',
                                                          encoding='utf-8')
        (self.tmp / 'spawn.py').write_text(
            'import subprocess, sys\nimport pcapkit\npcapkit.f(1)\n'
            'subprocess.run([sys.executable, "-c", "import pcapkit; pcapkit.f(0)"], check=True)\n',
            encoding='utf-8')
        env = {k: v for k, v in os.environ.items() if not k.startswith('COVERAGE')}
        env.update(COVERAGE_DEBUG='pid,process', COVERAGE_DEBUG_FILE=str(self.tmp / 'coverage-processes.log'),
                   PYTHONPATH=str(self.tmp))
        subprocess.run([sys.executable, '-m', 'coverage', 'run', '--rcfile=.github/coverage.toml',  # nosec: B603
                        'spawn.py'], cwd=self.tmp, env=env, check=True, timeout=120, capture_output=True)
        result = subprocess.run([sys.executable, str(UTIL / 'coverage_report.py')], cwd=self.tmp,  # nosec: B603
                                env=dict(env, **self.env(TESTS_OUTCOME='success')),
                                capture_output=True, text=True, check=False, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('1 xdist workers, missing data: []', result.stdout)
        self.assertTrue((self.tmp / 'coverage-html' / 'index.html').is_file())
        page = self.page.read_text(encoding='utf-8')
        self.assertRegex(page, r'^earlier\n\*\*Coverage: 100\.00%\*\* \(unit tier, Python 3\.15, `012345678`\)\n')
        self.assertIn('| `pcapkit (top level)` | 4 | 0 | 2 | 0 | 100.00% |\n', page)
        self.assertEqual(json.loads((self.tmp / 'coverage-comment' / 'coverage-summary.json').read_text())['total'],
                         100.0)

    def test_the_step_runs_the_script(self) -> None:
        step = next(step for step in steps('unit-tests.yml', 'test')
                    if step.get('name') == 'Report coverage')
        self.assertEqual(step['run'], 'python util/coverage_report.py')
        self.assertEqual(step['shell'], 'bash')
        # #2030: and the job's copy of its summary.
        self.assertEqual(set(step['env']), {'SHA', 'PYTHON', 'TESTS_OUTCOME', 'JOB_SUMMARY_COPY'})
        self.assertTrue(re.search(r"steps\.tests\.outcome", step['env']['TESTS_OUTCOME']))


if __name__ == '__main__':
    unittest.main()
