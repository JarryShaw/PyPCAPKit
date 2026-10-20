# -*- coding: utf-8 -*-
"""#1732: the round-trip sweeps run on ``latest`` alone.

The owner's ruling, paraphrased: run a subset, and the round-trip sweeps need run
only on the latest version. So ``test``'s ``Run unit tests`` step adds
:data:`~tests._tiers.ROUNDTRIP_SWEEP_GLOB` as one more ``--ignore-glob`` on every
leg whose version is not ``latest`` -- the KTLO and older supported legs -- as
``experimental``'s does on each of its legs, and ``latest``, the coverage leg, keeps
the whole unit tier. The owner later ruled that the subset covers ``integration``
too: off ``latest``, its ``Run full test suite`` drops the modules
:data:`~tests._tiers.ROUNDTRIP_RUNTIME_GLOB` names, :class:`TestTheIntegrationSubset`.

:class:`TestTheStepSelectsByLeg` runs the step's script on each leg the tier file
gives either job, with a ``python`` on ``PATH`` that records its arguments, so what
is checked is the selection bash builds, not what the text appears to say.
:class:`TestTheGlobIsTheSweeps` asks pytest itself what the glob ignores.

The owner's second ruling, option 2: nothing waits on the experimental legs, which
with the caps GraalPy needs run for up to two hours. A job of unit-tests.yml would
still hold its run in progress, and with it every ``workflow_run`` consumer of
"Unit Tests", so they are a workflow of their own, experimental.yml:
:class:`TestTheExperimentalLegsAreAWorkflowOfTheirOwn`.

"""

from __future__ import annotations

import fnmatch
import os
import pathlib
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _tiers
from tests.project.test_python_matrix_tiers_1633 import REQUIRED, is_experimental, job, legs, workflow
from tests.project.test_python_versions_1660 import ROOT, live_outputs, prose
from tests.project.test_release_gates import NULL, evaluate_expression

if TYPE_CHECKING:
    from typing import Any

#: The jobs and step that run the unit tier: ``test``, and the experimental legs' own (#1732).
JOB = ('unit-tests.yml', 'test')
EXPERIMENTAL = ('experimental.yml', 'experimental')
STEP = 'Run unit tests'
#: The job and step that run the fixture tier, which the subset covers too (#1732).
INTEGRATION = ('unit-tests.yml', 'integration')
INTEGRATION_STEP = 'Run full test suite'
#: The fixture tier's round-trip sweeps, by path, as the owner's ruling counted them.
RUNTIME_SWEEPS = ('tests/foundation/traceflow/test_traceflow_reread_roundtrip_runtime.py',
                  'tests/protocols/test_capture_roundtrip_runtime.py',
                  'tests/protocols/test_declared_length_roundtrip_runtime.py')
#: Every workflow that waits on "Unit Tests" completing, with ``workflow_run``.
CONSUMERS = ('coverage-comment.yml', 'deploy-pages.yml', 'cron-vendor.yml', 'cron-conda.yml')
#: Each job's ``timeout-minutes``, and its capped steps', by ``id``: ``test``'s are
#: main's, ``experimental``'s are sized for GraalPy (88-113 minutes, estimate).
#: #1938 adds the watcher's interpreter and its requests, capped too.
CAPS = {JOB: (45, {}), EXPERIMENTAL: (140, {'python': 5, 'install': 10, 'watcher-python': 1, 'watcher': 1, 'tests': 120})}
#: The jobs whose result reaches a gate: ``required-checks`` and what it needs, and
#: ``unittest-ordering``, which runs on main's pushes and gates publishing.
GATING = ('required-checks', 'unittest-ordering')
#: The flag that leaves the sweeps out, as pytest receives it once bash has run.
SWEEP_FLAG = f'--ignore-glob={_tiers.ROUNDTRIP_SWEEP_GLOB}'
#: The unit tier's own flags, which every leg passes.
TIER_FLAGS = ('--ignore=tests/integration', '--ignore-glob=*_runtime.py', '--ignore-glob=*_regression.py')
#: A ``python`` that writes each argument on a line of ``$ARGS_FILE``, and hands a
#: ``-c`` to the real one, which is how ``integration`` asks tests/_tiers.py.
STUB = ('#!/bin/sh\nif [ "$1" = -c ]; then exec "$REAL_PYTHON" "$@"; fi\n'
        'printf \'%s\\n\' "$@" > "$ARGS_FILE"\n')
#: A directory holding round-trip sweeps and modules that only import their
#: harnesses' packet builders, for :class:`TestTheGlobIsTheSweeps` to collect.
PROBE = 'tests/protocols/internet'
#: ``$RUNNER_TEMP``, which only names the JUnit file here, so one value for every leg.
RUNNER_TEMP = '/home/runner/work/_temp'


def step(where: 'tuple[str, str]' = JOB) -> 'dict[str, Any]':
    name = INTEGRATION_STEP if where == INTEGRATION else STEP
    found = [entry for entry in job(*where)['steps'] if entry.get('name') == name]
    if len(found) != 1:
        raise AssertionError(f'expected one {name!r} step in {where}, found {len(found)}')
    return found[0]


def stringify(value: 'object') -> 'str':
    """``value`` as an ``env:`` entry holds it."""
    if value is NULL or value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


def step_env(leg: 'dict[str, Any]', where: 'tuple[str, str]' = JOB) -> 'dict[str, str]':
    """The step's ``env:`` on ``leg``, ``needs`` read from the tier file."""
    # #1938: experimental's tests step reads the token and the watcher's interpreter, unwatched here.
    # #1954: and the project pins its own step lists, as that step prints them.
    context = {'matrix': leg, 'needs': {'python-versions': {'outputs': live_outputs()}}, 'github': {'token': ''},
               'steps': {'watcher': {'outcome': 'skipped'}, 'watcher-python': {'outputs': {'python-path': ''}},
                         'pins': {'outputs': {'paths': ' '.join(_tiers.project_pin_paths())}}}}
    return {key: re.sub(r'\$\{\{.*?\}\}', lambda match: stringify(evaluate_expression(match.group(0), context)),
                        str(value))
            for key, value in (step(where).get('env') or {}).items()}


def run_step(leg: 'dict[str, Any]', where: 'tuple[str, str]' = JOB) -> 'list[str]':
    """The arguments the step of job ``where`` hands ``python`` on ``leg``."""
    with tempfile.TemporaryDirectory() as temp:
        stub = pathlib.Path(temp, 'python')
        stub.write_text(STUB, encoding='utf-8')
        stub.chmod(0o755)
        # #1740: experimental's tests step probes `sudo -n systemd-run`, which fails here, as it
        # would where no scope can start, so the tests run uncapped: no scope on this machine.
        sudo = pathlib.Path(temp, 'sudo')
        sudo.write_text('#!/bin/sh\nexit 1\n', encoding='utf-8')
        sudo.chmod(0o755)
        # A directory for the files that step writes, named RUNNER_TEMP in what is returned.
        runner_temp = pathlib.Path(temp, '_temp')
        runner_temp.mkdir()
        record = pathlib.Path(temp, 'args')
        env = dict(os.environ, **step_env(leg, where), ARGS_FILE=str(record), RUNNER_TEMP=str(runner_temp),
                   REAL_PYTHON=sys.executable, PATH=temp + os.pathsep + os.environ.get('PATH', ''))
        # From the root, as the runner runs it: ``integration`` imports tests/_tiers.py.
        result = subprocess.run(['bash', '-e', '-c', step(where)['run']], env=env, cwd=ROOT,  # nosec B603 B607
                                capture_output=True, text=True, check=False, timeout=60)
        if result.returncode:
            raise AssertionError(f'the step failed on {leg}: {result.stderr}')
        return [arg.replace(str(runner_temp), RUNNER_TEMP) for arg in record.read_text(encoding='utf-8').splitlines()]


def pytest_args(argv: 'list[str]') -> 'list[str]':
    """The arguments after ``-m pytest``, under ``coverage run`` or not."""
    for index in range(len(argv) - 1):
        if argv[index:index + 2] == ['-m', 'pytest']:
            return argv[index + 2:]
    raise AssertionError(f'no `-m pytest` in {argv}')


@unittest.skipIf(shutil.which('bash') is None, 'the step is a bash script')
class TestTheStepSelectsByLeg(unittest.TestCase):
    """Each leg of ``test`` and ``experimental``, from the tier file, through the step's own script."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.latest = live_outputs()['latest']
        cls.runs = {leg['python-version']: (leg, run_step(leg, where))
                    for where in (JOB, EXPERIMENTAL) for leg in legs(*where)}
        assert len(cls.runs) == len(legs(*JOB)) + len(legs(*EXPERIMENTAL)), 'a version runs in both jobs'

    def test_only_latest_runs_the_sweeps(self) -> None:
        self.assertIn(self.latest, self.runs)
        self.assertTrue(any(is_experimental(leg) for leg, _ in self.runs.values()))
        for version, (_, argv) in self.runs.items():
            with self.subTest(python=version):
                self.assertEqual(SWEEP_FLAG in pytest_args(argv), version != self.latest)

    def test_latest_keeps_the_unit_tier_less_the_pins_under_coverage(self) -> None:
        """Coverage is measured over the selection it was before #1732, less the project pins,
        which import no pcapkit and run in ``project-tests`` (#1954)."""
        leg, argv = self.runs[self.latest]
        self.assertIs(leg.get('coverage'), True)
        self.assertEqual(argv[:4], ['-m', 'coverage', 'run', '--rcfile=.github/coverage.toml'])
        flags = [arg for arg in pytest_args(argv) if arg.startswith('--ignore')]
        pins = [f'--ignore={pin}' for pin in _tiers.project_pin_paths()]
        self.assertTrue(pins)
        self.assertEqual(flags, list(TIER_FLAGS) + pins)

    def test_every_other_leg_runs_the_rest(self) -> None:
        """The same selection as ``latest``, the sweeps' glob last, and no coverage."""
        expected = pytest_args(self.runs[self.latest][1]) + [SWEEP_FLAG]
        for version, (leg, argv) in self.runs.items():
            if version == self.latest:
                continue
            want = list(expected)
            if is_experimental(leg):
                # #1740: the experimental step's own worker count, 3 on GraalPy and `auto` on the rest.
                want[want.index('-n') + 1] = step_env(leg, EXPERIMENTAL)['WORKERS']
                # #1753: and its replacements for crashed workers, after `--dist load`.
                want.insert(want.index('--dist') + 2, '--max-worker-restart=30')
            with self.subTest(python=version):
                self.assertNotIn('coverage', argv)
                self.assertEqual(argv[:2], ['-m', 'pytest'])
                self.assertEqual(pytest_args(argv), want)


class TestTheGlobIsTheSweeps(unittest.TestCase):
    """What the glob leaves out, by pytest's own collection."""

    def collect(self, *extra: 'str') -> 'set[str]':
        result = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '-q', '-p', 'no:cacheprovider',
                                 PROBE, *extra], cwd=ROOT, capture_output=True, text=True,  # nosec B603
                                check=False, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        return {line.split('::', 1)[0] for line in result.stdout.splitlines() if '::' in line}

    def test_pytest_ignores_exactly_the_sweeps(self) -> None:
        """Run from the root, as CI runs it: the modules the glob drops are :func:`~tests._tiers.is_roundtrip_sweep`'s."""
        everything = self.collect()
        rest = self.collect(SWEEP_FLAG)
        sweeps = {module for module in everything if _tiers.is_roundtrip_sweep(module)}
        self.assertTrue(sweeps)
        self.assertEqual(everything - rest, sweeps)
        # A module that imports a sweep's harness for its packet builders is no sweep.
        builders = [module for module in rest if 'tests.foundation import _roundtrip'
                    in (ROOT / module).read_text(encoding='utf-8')]
        self.assertTrue(builders, f'no module under {PROBE} imports the harness without being a sweep')

    def test_the_sweeps_are_the_modules_named_for_a_round_trip(self) -> None:
        """Every unit-tier test module whose name holds ``roundtrip``.

        That takes in every module that builds a table on the #1202 protocol-edge
        or corekit harness. The foundation harness's registry module is named for
        symmetry, so it runs on every leg; it took 1.8 s on 3.14 (measured).

        """
        modules = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / 'tests').rglob('test_*.py'))
        sweeps = [module for module in modules if _tiers.is_roundtrip_sweep(module)]
        self.assertEqual(sweeps, [module for module in modules
                                  if 'roundtrip' in module.rsplit('/', 1)[1] and _tiers.is_unit_tier(module)])
        for harness in ('tests/protocols/_edge_roundtrip.py', 'tests/corekit/_roundtrip.py'):
            users = [module for module in modules if _tiers.is_unit_tier(module) and re.search(
                rf'^from {re.escape(harness[:-3].replace("/", "."))} import .*\b(?:Case|KnownFailureTable)\b',
                (ROOT / module).read_text(encoding='utf-8'), re.M)]
            with self.subTest(harness=harness):
                self.assertTrue(users)
                self.assertEqual([module for module in users if module not in sweeps], [])


class TestTheIntegrationSubset(unittest.TestCase):
    """#1732: ``integration`` runs the fixture tier's round-trip sweeps on ``latest`` alone.

    Each leg from the tier file, through the step's own script, with
    tests/_tiers.py really asked for the selection.

    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.latest = live_outputs()['latest']
        cls.selection = list(_tiers.fixture_tier_paths())
        cls.runs = {leg['python-version']: pytest_args(run_step(leg, INTEGRATION)) for leg in legs(*INTEGRATION)}

    @staticmethod
    def flags() -> 'list[str]':
        return ['-q', '-n', 'auto', '--dist', 'load', '--durations=30', '--durations-min=1.0',
                f'--junitxml={RUNNER_TEMP}/junit.xml']

    def test_the_glob_names_the_three_runtime_sweeps(self) -> None:
        """On disk and in the selection: the three modules the ruling counted."""
        glob = _tiers.ROUNDTRIP_RUNTIME_GLOB
        on_disk = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / 'tests').rglob('test_*.py')
                         if fnmatch.fnmatch(path.relative_to(ROOT).as_posix(), glob))
        self.assertEqual(on_disk, list(RUNTIME_SWEEPS))
        self.assertEqual(sorted({arg.split('::', 1)[0] for arg in self.selection
                                 if fnmatch.fnmatch(arg.split('::', 1)[0], glob)}), list(RUNTIME_SWEEPS))

    def test_only_latest_runs_them(self) -> None:
        """``latest`` passes the whole selection; every other leg drops them and adds the glob."""
        self.assertIn(self.latest, self.runs)
        self.assertGreater(len(self.runs), 1)
        flag = f'--ignore-glob={_tiers.ROUNDTRIP_RUNTIME_GLOB}'
        rest = [arg for arg in self.selection if arg.split('::', 1)[0] not in RUNTIME_SWEEPS]
        self.assertLess(len(rest), len(self.selection))
        for version, args in self.runs.items():
            with self.subTest(python=version):
                if version == self.latest:
                    self.assertEqual(args, self.flags() + self.selection)
                else:
                    self.assertEqual(args, self.flags() + rest + [flag])


def triggers(spec: 'dict[str, Any]') -> 'dict[str, Any]':
    """A workflow's ``on:``, which PyYAML reads as the key :data:`True`."""
    found = spec.get('on', spec.get(True))
    return found if isinstance(found, dict) else {}


class TestTheExperimentalLegsAreAWorkflowOfTheirOwn(unittest.TestCase):
    """#1732, option 2: nothing waits on the experimental legs, so they leave unit-tests.yml."""

    def setUp(self) -> None:
        self.unit = workflow('unit-tests.yml')
        self.own = workflow('experimental.yml')

    def test_the_workflow_holds_every_experimental_leg_and_unit_tests_none(self) -> None:
        found = legs(*EXPERIMENTAL)
        self.assertEqual(self.own['name'], 'Experimental Tests')
        self.assertEqual([leg['python-version'] for leg in found], ['3.14t', 'graalpy-25.4'])
        self.assertTrue(all(map(is_experimental, found)))
        self.assertEqual(self.own['jobs']['experimental']['name'], 'Python ${{ matrix.python-version }} (experimental)')
        self.assertNotIn('experimental', self.unit['jobs'])
        self.assertNotIn('experimental', self.unit['jobs']['python-versions']['outputs'])
        for job_id, spec in self.unit['jobs'].items():
            if not isinstance(spec.get('strategy', {}).get('matrix'), str):
                continue
            with self.subTest(job=job_id):
                self.assertFalse([leg for leg in legs('unit-tests.yml', job_id) if is_experimental(leg)])
                self.assertNotIn('experimental', str(spec.get('name')))

    def test_the_same_events_and_no_concurrency_group(self) -> None:
        """unit-tests.yml's push and pull_request, no ``workflow_call``, read-only, sharing no group.

        #1938 drops its group, so a superseded run is skipped or stopped, not
        cancelled: :mod:`tests.project.test_superseded_runs_1938`.

        """
        events = triggers(self.own)
        self.assertEqual(events, {key: value for key, value in triggers(self.unit).items() if key != 'workflow_call'})
        self.assertEqual(set(events), {'push', 'pull_request'})
        self.assertEqual(self.own['permissions'], {'contents': 'read'})
        self.assertNotIn('concurrency', self.own)

    def test_it_skips_a_docs_only_diff_as_test_does(self) -> None:
        """unit-tests.yml's ``changes`` script, byte for byte, gating the job as it gates ``test``."""
        def classify(spec: 'dict[str, Any]') -> 'str':
            return next(entry['run'] for entry in spec['jobs']['changes']['steps'] if entry.get('id') == 'classify')
        self.assertEqual(classify(self.own), classify(self.unit))
        spec = self.own['jobs']['experimental']
        # #1938 adds `current`, the gate every job needs, and `!cancelled()`, so the two results stand in
        # for the implicit `success()`.
        self.assertEqual(spec['needs'], ['current', 'changes', 'python-versions'])
        self.assertEqual(spec['if'],
                         "${{ !cancelled() && needs.changes.result == 'success' && "
                         "needs.python-versions.result == 'success' && needs.current.outputs.current != 'false' && "
                         "needs.changes.outputs.code != 'false' }}")
        self.assertIn("needs.changes.outputs.code != 'false'", self.unit['jobs']['test']['if'])

    def test_nothing_waits_on_it(self) -> None:
        """No ``workflow_run`` names it, nothing calls it, and no ``needs:`` anywhere names its job."""
        self.assertNotIn('workflow_call', triggers(self.own))
        consumers = []
        for path in sorted((ROOT / '.github' / 'workflows').glob('*.yml')):
            spec = workflow(path.name)
            waits = (triggers(spec).get('workflow_run') or {}).get('workflows', [])
            if self.unit['name'] in waits:
                consumers.append(path.name)
            text = path.read_text(encoding='utf-8')
            with self.subTest(workflow=path.name):
                self.assertNotIn(self.own['name'], waits)
                code = [line for line in text.splitlines() if not line.lstrip().startswith('#')]
                self.assertFalse([line for line in code if 'experimental.yml' in line])
                for job_id, job_spec in (spec.get('jobs') or {}).items():
                    needs = job_spec.get('needs', [])
                    self.assertNotIn('experimental', [needs] if isinstance(needs, str) else needs, job_id)
        self.assertEqual(sorted(consumers), sorted(CONSUMERS))
        self.assertNotIn('needs.experimental', str(self.unit['jobs']['required-checks']))
        self.assertEqual(self.unit['jobs']['unittest-ordering']['needs'], ['test'])

    def test_the_caps(self) -> None:
        """``test``'s are main's; ``experimental``'s fit GraalPy, each step's under the job's."""
        for where, (cap, steps) in CAPS.items():
            spec = job(*where)
            with self.subTest(job=where):
                self.assertEqual(spec['timeout-minutes'], cap)
                self.assertEqual({entry.get('id'): entry['timeout-minutes']
                                  for entry in spec['steps'] if 'timeout-minutes' in entry}, steps)
                self.assertLess(sum(steps.values()), cap)

    def test_a_failure_never_turns_the_run_red(self) -> None:
        """Job-level ``continue-on-error`` there and on the KTLO jobs alone: a ``test`` leg's failure must still fail its gate.

        unit-tests.yml's KTLO jobs carry it too since #1738, which nothing gating
        ``needs:`` (``tests/project/test_ktlo_jobs_gate_nothing_1738.py``).

        """
        spec = self.own['jobs']['experimental']
        self.assertIs(spec.get('continue-on-error'), True)
        self.assertEqual(spec['env'], {'ANNOTATION_LEVEL': 'warning'})
        self.assertEqual(spec['steps'][-1]['name'], 'Experimental summary')
        expected = {'experimental.yml': ['experimental'],
                    'unit-tests.yml': ['test-ktlo', 'integration-ktlo', 'pypcap-parity-ktlo']}
        for name in ('unit-tests.yml', 'experimental.yml'):
            with self.subTest(workflow=name):
                self.assertEqual([job_id for job_id, entry in workflow(name)['jobs'].items()
                                  if 'continue-on-error' in entry], expected[name])

    def test_it_installs_what_test_installs(self) -> None:
        """So tests/_dependency_gates.py, which reads unit-tests.yml alone, loses no gate by its leaving."""
        from tests import _dependency_gates  # pylint: disable=import-outside-toplevel
        self.assertEqual(_dependency_gates.WORKFLOW.name, 'unit-tests.yml')
        installs = {}
        for where in (JOB, EXPERIMENTAL):
            found = [re.findall(r"pip install -e '\.\[([^]]*)\]'", str(entry.get('run', '')))
                     for entry in job(*where)['steps']]
            installs[where] = [extra for entries in found for extra in entries]
        self.assertEqual(installs[EXPERIMENTAL], installs[JOB])
        self.assertEqual(len(installs[JOB]), 1)
        self.assertIn('test', [found.name for found in _dependency_gates.pytest_jobs()])

    def test_ci_timing_still_reads_its_legs(self) -> None:
        """The weekly CI Timing review reads the workflow, so its two-hour legs stay measured."""
        from util import ci_timing  # pylint: disable=import-outside-toplevel
        self.assertIn('experimental.yml', ci_timing.OTHER_WORKFLOWS)
        specs = ci_timing.parse_workflow((ROOT / '.github' / 'workflows' / 'experimental.yml').read_text(encoding='utf-8'))
        for version in ('3.14t', 'graalpy-25.4'):
            with self.subTest(python=version):
                spec = ci_timing.match_job(specs, f'Python {version} (experimental)')
                self.assertEqual((spec['id'], spec['timeout'], ci_timing.step_cap(spec, ci_timing.TESTS_STEP)),
                                 ('experimental', 140, 120))

    def test_no_required_context_names_a_leg(self) -> None:
        names = {f'Python {leg["python-version"]} (experimental)' for leg in legs(*EXPERIMENTAL)}
        self.assertEqual(len(names), 2)
        self.assertFalse(names & REQUIRED)


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_names_the_glob_and_the_leg(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        self.assertIn(f"every leg but ``latest`` adds ``--ignore-glob='{_tiers.ROUNDTRIP_SWEEP_GLOB}'``", page)


if __name__ == '__main__':
    unittest.main()
