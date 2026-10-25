# -*- coding: utf-8 -*-
"""#2060: a non-blocking Windows unit-test leg, ahead of the win-64 conda package's release.

The plan for #2060 asks that a Windows unit-test leg run before a win-64 package
publishes. :file:`.github/workflows/experimental.yml` has ``windows``, a job of its own
beside ``experimental``, whose Linux containment (cgroup scope, ``prlimit``, resource
monitor, superseded watcher) cannot run on Windows.

* :class:`TestTheLeg`: one leg on ``windows-latest``, on ``latest``, the newest
  CPython the conda builds target, named ``Python <latest> on Windows (experimental)``,
  gated as ``experimental`` is, and needed by nothing.
* :class:`TestItNeverBlocks`: every step that runs is ``continue-on-error``, so no
  failure fails the job; the long steps have caps under the job's; ``Experimental
  summary`` runs after any failure and warns once per failed step; no step writes
  an error.
* :class:`TestItRunsOnWindows`: every ``run:`` is Git Bash's, none calls a
  Linux-only tool, and the checkout keeps LF line endings.
* :class:`TestTheTestsStep`: run as bash runs it, the step hands pytest ``test``'s
  flags and ignores the ``LATEST`` tier, and a tier it cannot list fails the step
  with a warning.
* :class:`TestItHoldsLatestBackNowhere`: the weekly tier job does not wait for a Windows
  build before it moves ``latest``.
* :class:`TestTheReporters`: CI Reports and the CI Timing review read the job as a
  non-blocking experimental leg.

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
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests.project.test_ktlo_legs_stay_green_1672 import (EXPERIMENTAL_REASON, JOB_SUMMARY_STEPS, KTLO_COMMANDS,
                                                          SUMMARY_COPY, commands, interpolate, label, scenarios)
from tests.project.test_python_versions_1660 import live_outputs, prose, resolve
from tests.project.test_release_gates import evaluate_condition
from util import check_suite_report, ci_timing

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow and docs, and runs a step's shell, a question about the tree.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
NAME = 'experimental.yml'
JOB = 'windows'
WHERE = (NAME, JOB)
LATEST = '${{ needs.python-versions.outputs.latest }}'
JOB_NAME = f'Python {LATEST} on Windows (experimental)'
LEG = f'Python {LATEST} on Windows (experimental, non-blocking)'
SUMMARY = 'Experimental summary'
#: The summary's command: setup-python's ``python``, or the image's, not ``/usr/bin/python3``.
SUMMARY_RUN = 'python util/leg_summary.py experimental'
#: The steps with a cap of their own, by ``id``, and the job's.
CAPS = {'python': 5, 'install': 10, 'tests': 60}
JOB_CAP = 80
#: The minutes left for the uncapped steps: the LF step, checkout, the parallelism
#: report, the uploads and the summaries, each seconds on ``experimental``'s legs.
UNCAPPED_MINUTES = 5
#: What a Windows runner lacks: Linux tools, and the scripts that need them.
LINUX_ONLY = re.compile(r'(?<![\w/.-])(?:sudo|prlimit|systemd-run|systemctl|nproc|gnutimeout|ulimit|apt|apt-get|free)'
                        r'(?![\w-])|/usr/bin/python3|/proc/|cap_file_size\.py|superseded\.py')
#: A ``python`` that records each argument on a line of ``$ARGS_FILE`` and hands a
#: ``-c`` to the real one, unless ``FAIL_C`` is set.
PYTHON_STUB = textwrap.dedent('''\
    #!/bin/sh
    if [ "$1" = -c ]; then
      if [ -n "$FAIL_C" ]; then echo 'Traceback: stubbed' >&2; exit 1; fi
      exec "$REAL_PYTHON" "$@"
    fi
    printf '%s\\n' "$@" > "$ARGS_FILE"
    ''')


def spec() -> 'dict[str, Any]':
    return _workflows.job(*WHERE)


def step(name: 'str') -> 'dict[str, Any]':
    [found] = [entry for entry in spec()['steps'] if label(entry) == name]
    return found


def uses(action: 'str') -> 'dict[str, Any]':
    """The one step of the job that runs ``action``, at whatever pin."""
    [found] = [entry for entry in spec()['steps'] if str(entry.get('uses', '')).startswith(f'{action}@')]
    return found


def bash(script: 'str', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
    """``script`` as ``shell: bash`` runs it, from the root."""
    full = dict(os.environ, **env)
    full.pop('PYTHONSAFEPATH', None)  # the runner sets none, and it would hide tests/ from `-c`
    return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],  # nosec: B603 B607
                          env=full, cwd=ROOT, capture_output=True, text=True, check=False, timeout=120)


class TestTheLeg(unittest.TestCase):
    """One leg, on ``windows-latest`` and ``latest``, gated as ``experimental`` is."""

    def test_the_job_exists_on_windows(self) -> None:
        jobs = _workflows.load(NAME)['jobs']
        self.assertIn(JOB, jobs)
        self.assertEqual(spec()['runs-on'], 'windows-latest')
        self.assertEqual(spec()['name'], JOB_NAME)
        self.assertNotIn('strategy', spec())

    def test_it_runs_the_newest_cpython_the_conda_builds_target(self) -> None:
        setup = uses('actions/setup-python')
        self.assertEqual(setup['with'], {'python-version': LATEST, 'cache': 'pip'})
        version = resolve(NAME, JOB, LATEST)
        conda = json.loads(live_outputs()['conda'])
        self.assertEqual(version, live_outputs()['latest'])
        self.assertEqual(version, conda[-1])
        self.assertEqual(interpolate(spec()['name'], {'needs': {'python-versions': {'outputs': {'latest': version}}}}),
                         f'Python {version} on Windows (experimental)')

    def test_it_is_gated_as_experimental_is(self) -> None:
        legs = _workflows.job(NAME, 'experimental')
        for key in ('needs', 'if', 'continue-on-error'):
            with self.subTest(key=key):
                self.assertEqual(spec()[key], legs[key])
        self.assertIs(spec()['continue-on-error'], True)
        self.assertEqual(spec()['env'], {'ANNOTATION_LEVEL': 'warning'})

    def test_nothing_needs_it(self) -> None:
        for path in sorted(_workflows.WORKFLOWS.glob('*.yml')):
            for job_id, body in (_workflows.load(path.name).get('jobs') or {}).items():
                needs = body.get('needs', [])
                with self.subTest(workflow=path.name, job=job_id):
                    self.assertNotIn(JOB, [needs] if isinstance(needs, str) else needs)


class TestItNeverBlocks(unittest.TestCase):
    """The KTLO mechanics (#1672), as ``experimental`` has them (#1660)."""

    def setUp(self) -> None:
        self.spec = spec()
        [self.summary] = [entry for entry in self.spec['steps'] if label(entry) == SUMMARY]
        self.position = self.spec['steps'].index(self.summary)

    def test_every_step_continues_on_error(self) -> None:
        for entry in self.spec['steps']:
            with self.subTest(step=label(entry)):
                self.assertIs(entry.get('continue-on-error'), True)

    def test_no_step_can_fail_the_leg(self) -> None:
        runs = scenarios(*WHERE, self.spec, {})
        self.assertGreater(len(runs), 3)
        self.assertEqual(len(runs), len(self.spec['steps']))
        for index, conclusion, _ in runs:
            with self.subTest(step=label(self.spec['steps'][index])):
                self.assertEqual(conclusion, 'success')

    def test_the_summary_sees_every_failure(self) -> None:
        """Last but the job summary's steps, after any failure, and every step it reports has an ``id``."""
        self.assertEqual([label(entry) for entry in self.spec['steps'][self.position + 1:]], list(JOB_SUMMARY_STEPS))
        self.assertEqual(self.summary['if'], '${{ !cancelled() }}')
        self.assertEqual(self.summary['shell'], 'bash')
        self.assertEqual(self.summary['env'], dict({'LEG': LEG, 'STEPS': '${{ toJSON(steps) }}'}, **SUMMARY_COPY))
        self.assertEqual(self.summary['run'], SUMMARY_RUN)
        for index, _, record in scenarios(*WHERE, self.spec, {}):
            entry = self.spec['steps'][index]
            if entry is self.summary or label(entry) in JOB_SUMMARY_STEPS:
                continue
            with self.subTest(step=label(entry)):
                self.assertNotEqual(record[self.position].outcome, 'skipped')
                if 'uses' not in entry or 'upload-artifact' not in entry['uses']:
                    self.assertIn('id', entry)
        for entry in self.spec['steps'][self.position + 1:]:
            self.assertEqual(entry['if'], '${{ always() }}')

    def test_the_job_summary_carries_the_check_name(self) -> None:
        self.assertEqual(step('Name the job summary')['env'], {'JOB_NAME': JOB_NAME})
        self.assertEqual(step('Install package and test dependencies')['env'], {'LEG': LEG})

    def test_no_step_writes_an_error(self) -> None:
        for entry in self.spec['steps']:
            with self.subTest(step=label(entry)):
                self.assertLessEqual(commands(entry.get('run', '')), KTLO_COMMANDS)

    def test_each_long_step_ends_inside_the_job(self) -> None:
        caps = {entry.get('id'): entry['timeout-minutes'] for entry in self.spec['steps'] if 'timeout-minutes' in entry}
        self.assertEqual(caps, CAPS)
        self.assertEqual(self.spec['timeout-minutes'], JOB_CAP)
        self.assertLess(caps['install'], caps['tests'])
        self.assertLessEqual(sum(caps.values()) + UNCAPPED_MINUTES, JOB_CAP)

    @unittest.skipIf(shutil.which('bash') is None, 'the summary is a bash step')
    def test_the_summary_warns_once_per_failed_step(self) -> None:
        name = 'Python 3.15 on Windows (experimental, non-blocking)'
        outcomes = (('checkout', 'success'), ('install', 'failure'), ('tests', 'skipped'))
        context = {key: {'outputs': {}, 'outcome': outcome,
                         'conclusion': 'success' if outcome == 'failure' else outcome} for key, outcome in outcomes}
        with tempfile.TemporaryDirectory(prefix='pcapkit-2060-') as tmp:
            page = pathlib.Path(tmp, 'summary.md')
            page.write_text('', encoding='utf-8')
            run = self.summary['run'].replace('python ', f'{sys.executable} ', 1)
            result = bash(run, {'LEG': name, 'STEPS': json.dumps(context), 'GITHUB_STEP_SUMMARY': str(page)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [
                f"::warning title=install failed on {name.replace(',', '%2C')}::{EXPERIMENTAL_REASON}; "
                "see the install step's log."])
            self.assertEqual(page.read_text(encoding='utf-8'),
                             f'- {name}: step `install` failed; non-blocking, so this job still succeeds.\n')


class TestItRunsOnWindows(unittest.TestCase):
    """Git Bash for every ``run:``, nothing Linux-only, and the tree checked out with LF."""

    def test_every_run_is_bash(self) -> None:
        """A Windows step's default shell is PowerShell."""
        found = [entry for entry in spec()['steps'] if 'run' in entry]
        self.assertTrue(found)
        for entry in found:
            with self.subTest(step=label(entry)):
                self.assertEqual(entry.get('shell'), 'bash')

    def test_no_step_calls_a_linux_only_tool(self) -> None:
        for entry in spec()['steps']:
            with self.subTest(step=label(entry)):
                self.assertIsNone(LINUX_ONLY.search(str(entry.get('run', ''))))

    def test_the_check_sees_the_linux_legs_tools(self) -> None:
        """So the check above is not vacuous: ``experimental``'s steps use several."""
        found = {match.group(0) for entry in _workflows.steps(NAME, 'experimental')
                 for match in LINUX_ONLY.finditer(str(entry.get('run', '')))}
        self.assertLessEqual({'sudo', 'prlimit', '/usr/bin/python3', '/proc/', 'superseded.py', 'nproc'}, found)

    def test_line_endings_are_set_before_the_checkout(self) -> None:
        steps = spec()['steps']
        lf = step('Keep LF line endings')
        checkout = uses('actions/checkout')
        self.assertLess(steps.index(lf), steps.index(checkout))
        self.assertEqual(lf['run'].splitlines(), ['git config --global core.autocrlf false',
                                                  'git config --global core.eol lf'])

    def test_every_later_step_waits_on_the_one_before(self) -> None:
        """A failed checkout, setup-python or install skips what needs it."""
        for found, needs in ((uses('actions/setup-python'), 'checkout'),
                             (step('Install package and test dependencies'), 'python'),
                             (step('Run unit tests'), 'install'), (step('Upload test timings'), 'install')):
            with self.subTest(step=label(found)):
                condition = found['if']
                self.assertIn(f"steps.{needs}.outcome == 'success'", condition)
                failed = {needs: {'outcome': 'failure'}}
                self.assertFalse(evaluate_condition(condition.replace('!cancelled() && ', ''), {'steps': failed}))


@unittest.skipIf(shutil.which('bash') is None or shutil.which('sh') is None, 'the step is a bash script')
class TestTheTestsStep(unittest.TestCase):
    """``Run unit tests``, run as bash runs it against a stand-in ``python``."""

    def run_step(self, **env: 'str') -> 'tuple[subprocess.CompletedProcess[str], list[str], str]':
        with tempfile.TemporaryDirectory(prefix='pcapkit-2060-') as tmp:
            stub = pathlib.Path(tmp, 'python')
            stub.write_text(PYTHON_STUB, encoding='utf-8')
            stub.chmod(0o755)
            record = pathlib.Path(tmp, 'args')
            result = bash(step('Run unit tests')['run'], {
                'ANNOTATION_LEVEL': 'warning', 'ARGS_FILE': str(record), 'RUNNER_TEMP': tmp,
                'REAL_PYTHON': sys.executable, 'PATH': tmp + os.pathsep + os.environ.get('PATH', ''), **env})
            argv = record.read_text(encoding='utf-8').splitlines() if record.exists() else []
            return result, argv, tmp

    def test_it_runs_the_all_tier_with_tests_flags(self) -> None:
        from tests import _tiers  # pylint: disable=import-outside-toplevel
        result, argv, tmp = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        latest = list(_tiers.latest_tier_paths())
        self.assertTrue(latest)
        self.assertEqual(argv, ['-m', 'pytest', '-q', '-n', 'auto', '--dist', 'load', '--durations=30',
                                '--durations-min=1.0', f'--junitxml={tmp}/junit.xml', '--ignore=tests/integration',
                                '--ignore-glob=*_runtime.py', '--ignore-glob=*_regression.py',
                                *(f'--ignore={path}' for path in latest)])

    def test_its_flags_are_tests(self) -> None:
        """The flags as unit-tests.yml ``test``'s step writes them."""
        flags = re.compile(r"set -- -q -n auto --dist load .*?--ignore-glob='\*_regression\.py'", re.S)
        own = flags.search(step('Run unit tests')['run'])
        tests = [entry for entry in _workflows.steps('unit-tests.yml', 'test') if entry.get('name') == 'Run unit tests']
        theirs = flags.search(tests[0]['run'])
        self.assertIsNotNone(own)
        self.assertIsNotNone(theirs)
        self.assertEqual(own.group(0).split(), theirs.group(0).split())  # type: ignore[union-attr]

    def test_a_tier_it_cannot_list_fails_the_step_with_a_warning(self) -> None:
        result, argv, _ = self.run_step(FAIL_C='1')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(argv, [])
        self.assertIn('::warning title=Could not compute the LATEST tier::', result.stdout)


class TestItHoldsLatestBackNowhere(unittest.TestCase):
    """The weekly job moves ``latest`` without waiting for a Windows build of it.

    util/update_python_versions.py moves ``latest`` only to a branch with a stable
    build on every label a job installs it on, so the Windows leg would hold every
    blocking job's ``latest`` back on a non-blocking leg; a non-blocking job's label
    does not count.

    """

    def labels(self, drop_guard: 'bool' = False) -> 'list[str]':
        from tests.project.test_python_versions_update_1660 import updater  # pylint: disable=import-outside-toplevel
        module = updater()
        workflows = module.load_workflows(ROOT)
        if drop_guard:
            del workflows[NAME]['jobs'][JOB]['continue-on-error']
        return module.workflow_labels(workflows)['latest']

    def test_windows_latest_is_no_latest_label(self) -> None:
        self.assertNotIn('windows-latest', self.labels())
        self.assertIn('ubuntu-latest', self.labels())

    def test_a_blocking_job_there_would_be_one(self) -> None:
        """So the check above is the guard's doing, not a job the script cannot see."""
        self.assertIn('windows-latest', self.labels(drop_guard=True))


class TestTheReporters(unittest.TestCase):
    """CI Reports and the CI Timing review read it as an experimental, non-blocking leg."""

    def setUp(self) -> None:
        self.name = f'Python {live_outputs()["latest"]} on Windows (experimental)'

    def test_ci_reports_reads_it_as_a_non_blocking_leg(self) -> None:
        workflow = check_suite_report.WORKFLOWS[_workflows.load(NAME)['name']]
        self.assertTrue(workflow.legs.match(self.name))
        self.assertTrue(check_suite_report.NONBLOCKING_JOB.fullmatch(self.name))
        self.assertTrue(check_suite_report.NONBLOCKING_NOTE.search(LEG))

    def test_ci_timing_finds_its_caps(self) -> None:
        specs = ci_timing.parse_workflow((_workflows.WORKFLOWS / NAME).read_text(encoding='utf-8'))
        found = ci_timing.match_job(specs, self.name)
        assert found is not None
        self.assertEqual((found['id'], found['timeout'], ci_timing.step_cap(found, ci_timing.TESTS_STEP)),
                         (JOB, JOB_CAP, CAPS['tests']))
        self.assertTrue(ci_timing.non_blocking(NAME, self.name))
        # The Linux legs still match their own job.
        linux = ci_timing.match_job(specs, 'Python 3.14t (experimental)')
        assert linux is not None
        self.assertEqual(linux['id'], 'experimental')

    def test_the_workflows_page_describes_it(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ("``windows`` job runs the ``ALL`` tier on ``windows-latest``",
                       '``Python <latest> on Windows (experimental)``', '``Keep LF line endings``',
                       'capped at 5, 10 and 60 minutes within its 80',
                       ':file:`tests/project/test_windows_test_leg_2060.py`'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)
        self.assertEqual(sorted(map(int, re.findall(r'capped at (\d+), (\d+) and (\d+) minutes within its (\d+)',
                                                    page)[0])), sorted([*CAPS.values(), JOB_CAP]))


if __name__ == '__main__':
    unittest.main()
