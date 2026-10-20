# -*- coding: utf-8 -*-
"""#1732 and #1958: the ``LATEST`` test tier runs on ``latest`` alone.

The owner's ruling on #1732, paraphrased: run a subset, and the round-trip sweeps
need run only on the latest version. #1958 makes that subset a test tier rather
than a name glob: :func:`tests._tiers.module_tier` puts each module in ``ALL`` or
``LATEST``, by the module's own ``__tier__`` or by the rule, and the owner's
rulings there, paraphrased, keep the hand-picked round trips on every leg and send
only the real sweeps, with the modules whose answer no interpreter changes, to
``latest``. So ``test``'s ``Run unit tests`` step passes each module
:func:`~tests._tiers.latest_tier_paths` prints as an ``--ignore`` on every leg whose
version is not ``latest`` -- the KTLO and older supported legs -- as
``experimental``'s does on each of its legs, and ``latest``, the coverage leg, keeps
the whole unit tier less the project pins (#1954). ``integration`` does the same
with the fixture tier: off ``latest``, its ``Run full test suite`` asks for
:func:`~tests._tiers.fixture_tier_paths`'s ``ALL`` part, and ``pypcap-parity``, none
of whose legs is ``latest``, asks for it on each, :class:`TestTheIntegrationSubset`.

:class:`TestTheStepSelectsByLeg` runs the step's script on each leg the tier file
gives either job, with a ``python`` on ``PATH`` that records its arguments, so what
is checked is the selection bash builds, not what the text appears to say.
:class:`TestTheIgnoresAreTheLatestTier` asks pytest itself what those ignores leave
out.

The owner's second ruling on #1732, option 2: nothing waits on the experimental
legs, which with the caps GraalPy needs run for up to two hours. A job of
unit-tests.yml would still hold its run in progress, and with it every
``workflow_run`` consumer of "Unit Tests", so they are a workflow of their own,
experimental.yml: :class:`TestTheExperimentalLegsAreAWorkflowOfTheirOwn`.

"""

from __future__ import annotations

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
from tests.project.test_graalpy_shards_1963 import rest_ignores
from tests.project.test_python_matrix_tiers_1633 import REQUIRED, is_experimental, job, legs, workflow
from tests.project.test_python_versions_1660 import ROOT, live_outputs, prose
from tests.project.test_release_gates import NULL, evaluate_expression

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): checks the workflows' tier selections.
__tier__ = 'LATEST'

#: The jobs and step that run the unit tier: ``test``, and the experimental legs' own (#1732).
JOB = ('unit-tests.yml', 'test')
EXPERIMENTAL = ('experimental.yml', 'experimental')
STEP = 'Run unit tests'
#: The jobs and step that run the fixture tier, which the tiers cover too (#1732, #1958).
INTEGRATION = ('unit-tests.yml', 'integration')
PARITY = ('unit-tests.yml', 'pypcap-parity')
INTEGRATION_STEP = 'Run full test suite'
#: Every workflow that waits on "Unit Tests" completing, with ``workflow_run``.
CONSUMERS = ('coverage-comment.yml', 'deploy-pages.yml', 'cron-vendor.yml', 'cron-conda.yml')
#: Each job's ``timeout-minutes``, and its capped steps', by ``id``: ``test``'s are
#: main's, ``experimental``'s are sized for GraalPy (88-113 minutes, estimate).
#: #1938 adds the watcher's interpreter and its requests, capped too.
CAPS = {JOB: (45, {}), EXPERIMENTAL: (140, {'python': 5, 'install': 10, 'watcher-python': 1, 'watcher': 1, 'tests': 120})}
#: The jobs whose result reaches a gate: ``required-checks`` and what it needs, and
#: ``unittest-ordering``, which runs on main's pushes and gates publishing.
GATING = ('required-checks', 'unittest-ordering')
#: The unit tier's own flags, which every leg passes.
TIER_FLAGS = ('--ignore=tests/integration', '--ignore-glob=*_runtime.py', '--ignore-glob=*_regression.py')
#: A ``python`` that appends each argument on a line of ``$ARGS_FILE``, then an
#: :data:`END` line, and hands a ``-c`` to the real one, which is how the steps ask
#: tests/_tiers.py. util/cap_file_size.py's command it execs, as the script does, with
#: no real interpreter: under the coverage leg one would be measured, be logged as a
#: second ``coverage run --rcfile`` controller, and exec before saving, which fails the
#: #1387 guard (#1969). A PyPy leg runs pytest more than once (#2005), so each run is
#: recorded rather than the last.
STUB = ('#!/bin/sh\ncase "$1" in -c) exec "$REAL_PYTHON" "$@";; util/cap_file_size.py) shift; exec "$@";; esac\n'
        'printf \'%s\\n\' "$@" \'<end>\' >> "$ARGS_FILE"\n')
#: The line :data:`STUB` writes after each run's arguments.
END = '<end>'
#: A directory holding sweeps, hand-picked round trips, and modules that only import
#: the sweeps' harnesses' packet builders, for :class:`TestTheIgnoresAreTheLatestTier`.
PROBE = 'tests/protocols/internet'
#: ``$RUNNER_TEMP``, which only names the JUnit file here, so one value for every leg.
RUNNER_TEMP = '/home/runner/work/_temp'


def step(where: 'tuple[str, str]' = JOB) -> 'dict[str, Any]':
    name = STEP if where in (JOB, EXPERIMENTAL) else INTEGRATION_STEP
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
    # #1958: and the LATEST tier its own step lists, as that step prints it.
    context = {'matrix': leg, 'needs': {'python-versions': {'outputs': live_outputs()}}, 'github': {'token': ''},
               'steps': {'watcher': {'outcome': 'skipped'}, 'watcher-python': {'outputs': {'python-path': ''}},
                         'tier': {'outputs': {'paths': ' '.join(_tiers.latest_tier_paths())}}}}
    return {key: re.sub(r'\$\{\{.*?\}\}', lambda match: stringify(evaluate_expression(match.group(0), context)),
                        str(value))
            for key, value in (step(where).get('env') or {}).items()}


def run_step(leg: 'dict[str, Any]', where: 'tuple[str, str]' = JOB, script: 'Optional[str]' = None) -> 'list[str]':
    """The arguments the step of job ``where`` hands ``python`` on ``leg``, which runs it once."""
    runs = run_step_each(leg, where, script)
    if len(runs) != 1:
        raise AssertionError(f'the step ran python {len(runs)} times on {leg}, not once')
    return runs[0]


def run_step_each(leg: 'dict[str, Any]', where: 'tuple[str, str]' = JOB,
                  script: 'Optional[str]' = None) -> 'list[list[str]]':
    """The arguments of each run of ``python`` by the step of job ``where`` on ``leg``, in order;
    ``script`` replaces its ``run:``."""
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
        env.setdefault('ANNOTATION_LEVEL', 'error')
        env.pop('PYTHONSAFEPATH', None)  # the runner sets none, and it would hide tests/ from `-c`
        # From the root, as the runner runs it: the steps import tests/_tiers.py.
        result = subprocess.run(['bash', '-e', '-c', script or step(where)['run']], env=env,  # nosec B603 B607
                                cwd=ROOT, capture_output=True, text=True, check=False, timeout=120)
        if result.returncode:
            raise AssertionError(f'the step failed on {leg}: {result.stdout[-2000:]}{result.stderr[-2000:]}')
        runs, run = [], []  # type: list[list[str]], list[str]
        for arg in record.read_text(encoding='utf-8').splitlines():
            if arg == END:
                runs.append(run)
                run = []
            else:
                run.append(arg.replace(str(runner_temp), RUNNER_TEMP))
        return runs


def shards(leg: 'dict[str, Any]') -> 'list[str]':
    """#2005: the directories the ``test`` step runs on their own on ``leg``, before the rest."""
    return step_env(leg).get('SHARDS', '').split()


def unsharded(leg: 'dict[str, Any]', runs: 'list[list[str]]') -> 'list[str]':
    """The arguments each of the ``test`` step's runs on ``leg`` shares, once each run's own are taken off.

    #2005: a run per directory :func:`shards` names adds its JUnit file and the
    directory, and the last run an ``--ignore`` of each.

    """
    named = shards(leg)
    if len(runs) != len(named) + 1:
        raise AssertionError(f'{len(runs)} runs on {leg} for the shards {named}')
    rest = [f'--ignore={shard}' for shard in named]
    common = runs[-1][:len(runs[-1]) - len(rest)]
    if runs[-1][len(common):] != rest:
        raise AssertionError(f'the last run on {leg} does not end by ignoring {named}: {runs[-1]}')
    for shard, run in zip(named, runs):
        own = [f'--junitxml={RUNNER_TEMP}/junit-{shard.replace("/", "-")}.xml', shard]
        if run != common + own:
            raise AssertionError(f'the {shard} run on {leg} is not the others\' arguments and {own}: {run}')
    return common


def pytest_args(argv: 'list[str]') -> 'list[str]':
    """The arguments after ``-m pytest``, under ``coverage run`` or not."""
    for index in range(len(argv) - 1):
        if argv[index:index + 2] == ['-m', 'pytest']:
            return argv[index + 2:]
    raise AssertionError(f'no `-m pytest` in {argv}')


@unittest.skipIf(shutil.which('sh') is None, 'the stub is a sh script')
class TestTheStubRunsNoRealInterpreterForTheCap(unittest.TestCase):
    """#1969: :data:`STUB` records the command util/cap_file_size.py caps without a real ``python``."""

    def test_the_coverage_command_is_recorded_without_the_real_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            for name, text in (('python', STUB), ('real', '#!/bin/sh\necho "$@" >> "$REAL_LOG"\n')):
                path = pathlib.Path(temp, name)
                path.write_text(text, encoding='utf-8')
                path.chmod(0o755)
            record, real = pathlib.Path(temp, 'args'), pathlib.Path(temp, 'real.log')
            env = dict(os.environ, ARGS_FILE=str(record), REAL_PYTHON=str(pathlib.Path(temp, 'real')),
                       REAL_LOG=str(real), PATH=temp + os.pathsep + os.environ.get('PATH', ''))
            command = ['-m', 'coverage', 'run', '--rcfile=.github/coverage.toml', '-m', 'pytest', '-q']
            result = subprocess.run(['python', 'util/cap_file_size.py', 'python', *command], env=env,  # nosec B603 B607
                                    capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(real.exists(), 'the real interpreter ran the capped coverage command')
            self.assertEqual(record.read_text(encoding='utf-8').splitlines(), [*command, END])


def rest_unsharded(leg: 'dict[str, Any]', where: 'tuple[str, str]', argv: 'list[str]') -> 'list[str]':
    """``argv`` less what util/pytest_shards.py's last run adds on a sharded leg (#1963), which it must end with."""
    shards = step_env(leg, where).get('SHARDS', '')
    if not shards:
        return argv
    rest = rest_ignores(shards)
    if not rest or argv[-len(rest):] != rest:
        raise AssertionError(f'the last run on {leg} does not end with the ignores of {shards!r}: {argv[-60:]}')
    return argv[:-len(rest)]


def ignored(argv: 'list[str]') -> 'list[str]':
    """The modules the arguments ``--ignore``, less the unit tier's own flags."""
    return [arg.split('=', 1)[1] for arg in pytest_args(argv) if arg.startswith('--ignore=') and arg not in TIER_FLAGS]


@unittest.skipIf(shutil.which('bash') is None, 'the step is a bash script')
class TestTheStepSelectsByLeg(unittest.TestCase):
    """Each leg of ``test`` and ``experimental``, from the tier file, through the step's own script."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.latest = live_outputs()['latest']
        # #2005: a PyPy leg of `test` runs pytest once a shard, each with the arguments the others share;
        # #1963: GraalPy's `experimental` leg through util/pytest_shards.py, whose last run is the rest.
        cls.runs = {leg['python-version']: (leg, unsharded(leg, run_step_each(leg, where)) if where == JOB
                                            else rest_unsharded(leg, where, run_step_each(leg, where)[-1]))
                    for where in (JOB, EXPERIMENTAL) for leg in legs(*where)}
        assert len(cls.runs) == len(legs(*JOB)) + len(legs(*EXPERIMENTAL)), 'a version runs in both jobs'

    def test_only_latest_runs_the_latest_tier(self) -> None:
        """Every other leg ignores each ``LATEST`` module; ``latest`` ignores the project pins alone."""
        self.assertIn(self.latest, self.runs)
        self.assertTrue(any(is_experimental(leg) for leg, _ in self.runs.values()))
        tier, pins = list(_tiers.latest_tier_paths()), list(_tiers.project_pin_paths())
        self.assertLess(set(pins), set(tier))
        for version, (_, argv) in self.runs.items():
            with self.subTest(python=version):
                self.assertEqual(ignored(argv), pins if version == self.latest else tier)
                self.assertFalse([arg for arg in argv if 'roundtrip' in arg and arg.startswith('--ignore-glob')])

    def test_latest_keeps_the_unit_tier_less_the_pins_under_coverage(self) -> None:
        """Coverage is measured over the whole unit tier, less the project pins, which
        import no pcapkit and run in ``project-tests`` (#1954)."""
        leg, argv = self.runs[self.latest]
        self.assertIs(leg.get('coverage'), True)
        self.assertEqual(argv[:4], ['-m', 'coverage', 'run', '--rcfile=.github/coverage.toml'])
        flags = [arg for arg in pytest_args(argv) if arg.startswith('--ignore')]
        pins = [f'--ignore={pin}' for pin in _tiers.project_pin_paths()]
        self.assertTrue(pins)
        self.assertEqual(flags, list(TIER_FLAGS) + pins)

    def test_every_other_leg_runs_the_rest(self) -> None:
        """The same selection as ``latest``, the ``LATEST`` tier ignored in place of the pins, and no coverage."""
        pins = {f'--ignore={pin}' for pin in _tiers.project_pin_paths()}
        expected = ([arg for arg in pytest_args(self.runs[self.latest][1]) if arg not in pins]
                    + [f'--ignore={module}' for module in _tiers.latest_tier_paths()])
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

    def test_a_step_that_ignores_the_pins_alone_off_latest_is_caught(self) -> None:
        """The check above fails when a leg off ``latest`` leaves out the pins rather than the tier."""
        script = step(JOB)['run']
        latest = _tiers.LATEST_TIER_SELECTOR.split('"', 1)[1]
        self.assertEqual(script.count(latest), 1)
        doctored = script.replace(latest, _tiers.PROJECT_PINS_SELECTOR.split('"', 1)[1])
        leg = next(leg for leg in legs(*JOB) if leg['python-version'] != self.latest and not shards(leg))
        self.assertNotEqual(ignored(run_step(leg, JOB, doctored)), list(_tiers.latest_tier_paths()))


class TestTheIgnoresAreTheLatestTier(unittest.TestCase):
    """What the ``LATEST`` ignores leave out, by pytest's own collection."""

    def collect(self, *extra: 'str') -> 'set[str]':
        result = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '-q', '-p', 'no:cacheprovider',
                                 PROBE, *extra], cwd=ROOT, capture_output=True, text=True,  # nosec B603
                                check=False, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        return {line.split('::', 1)[0] for line in result.stdout.splitlines() if '::' in line}

    def test_pytest_leaves_out_exactly_the_latest_modules(self) -> None:
        """Run from the root, as CI runs it: the modules the ignores drop are the ``LATEST`` ones."""
        everything = self.collect()
        rest = self.collect(*(f'--ignore={module}' for module in _tiers.latest_tier_paths()))
        latest = {module for module in everything if _tiers.module_tier(module) == _tiers.TIER_LATEST}
        self.assertTrue(latest)
        self.assertEqual(everything - rest, latest)
        # A hand-picked round trip stays, and so does a module that imports a sweep's harness.
        self.assertTrue([module for module in rest if 'roundtrip' in module])
        builders = [module for module in rest if 'tests.foundation import _roundtrip'
                    in (ROOT / module).read_text(encoding='utf-8')]
        self.assertTrue(builders, f'no module under {PROBE} imports the harness without being LATEST')

    def test_the_tier_is_no_name_rule(self) -> None:
        """#1958: a name says nothing about the tier; ``LATEST`` sweeps go by other names too."""
        modules = _tiers.suite_modules()
        named = [module for module in modules if 'roundtrip' in module.rsplit('/', 1)[1]]
        latest = set(_tiers.latest_tier_paths())
        self.assertTrue([module for module in named if module not in latest])
        self.assertTrue([module for module in named if module in latest])
        self.assertTrue([module for module in latest if module not in named and 'tests/project/' not in module])

    @staticmethod
    def harness_users(harness: 'str') -> 'list[str]':
        """The unit-tier modules that import a table type from ``harness``."""
        return [module for module in _tiers.suite_modules() if _tiers.is_unit_tier(module) and re.search(
            rf'^from {re.escape(harness[:-3].replace("/", "."))} import .*\b(?:Case|KnownFailureTable)\b',
            (ROOT / module).read_text(encoding='utf-8'), re.M)]

    def test_every_module_on_the_corekit_harness_is_latest(self) -> None:
        """The corekit tables build a case for every class they enumerate, so their users are sweeps."""
        users = self.harness_users('tests/corekit/_roundtrip.py')
        self.assertTrue(users)
        self.assertEqual([module for module in users if _tiers.module_tier(module) != _tiers.TIER_LATEST], [])

    def test_the_edge_case_tables_run_on_every_leg(self) -> None:
        """#1958: the #1202 edge-case tables are written out by hand, so they run on every leg."""
        deadline = 'tests/protocols/test_edge_roundtrip_deadline_1736_unit.py'
        users = self.harness_users('tests/protocols/_edge_roundtrip.py')
        self.assertIn(deadline, users)
        tables = [module for module in users if module != deadline]
        self.assertTrue(tables)
        self.assertEqual([module for module in tables if _tiers.module_tier(module) != _tiers.TIER_ALL], [])
        self.assertEqual(_tiers.module_tier(deadline), _tiers.TIER_LATEST)


@unittest.skipIf(shutil.which('bash') is None, 'the step is a bash script')
class TestTheIntegrationSubset(unittest.TestCase):
    """#1958: ``integration`` runs the fixture tier's ``LATEST`` modules on ``latest`` alone, and
    ``pypcap-parity``, with no ``latest`` leg, never does.

    Each leg from the tier file, through the step's own script, with
    tests/_tiers.py really asked for the selection.

    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.latest = live_outputs()['latest']
        cls.selection = list(_tiers.fixture_tier_paths())
        cls.all = list(_tiers.fixture_tier_paths(_tiers.TIER_ALL))
        cls.runs = {leg['python-version']: pytest_args(run_step(leg, INTEGRATION)) for leg in legs(*INTEGRATION)}

    @staticmethod
    def flags() -> 'list[str]':
        return ['-q', '-n', 'auto', '--dist', 'load', '--durations=30', '--durations-min=1.0',
                f'--junitxml={RUNNER_TEMP}/junit.xml']

    def test_the_all_selection_leaves_out_the_latest_modules(self) -> None:
        """What the ``ALL`` part drops is exactly the ``LATEST`` modules the whole selection reaches."""
        def reached(entries: 'list[str]') -> 'set[str]':
            modules = set()  # type: set[str]
            for entry in entries:
                module = entry.split('::', 1)[0]
                if (_tiers.ROOT / module).is_dir():
                    modules.update(path for path in _tiers.suite_modules() if path.startswith(module.rstrip('/') + '/'))
                else:
                    modules.add(module)
            return modules
        everything, kept = reached(self.selection), reached(self.all)
        dropped = everything - kept
        self.assertTrue(dropped)
        self.assertEqual(dropped, everything & set(_tiers.latest_tier_paths()))

    def test_only_latest_runs_them(self) -> None:
        """``latest`` passes the whole selection; every other leg its ``ALL`` part."""
        self.assertIn(self.latest, self.runs)
        self.assertGreater(len(self.runs), 1)
        self.assertLess(len(self.all), len(self.selection))
        for version, args in self.runs.items():
            with self.subTest(python=version):
                self.assertEqual(args, self.flags() + (self.selection if version == self.latest else self.all))

    def test_a_leg_that_asks_for_every_tier_off_latest_is_caught(self) -> None:
        script = step(INTEGRATION)['run']
        self.assertEqual(script.count("fixture_tier_paths('ALL')"), 1)
        leg = next(leg for leg in legs(*INTEGRATION) if leg['python-version'] != self.latest)
        args = pytest_args(run_step(leg, INTEGRATION, script.replace("fixture_tier_paths('ALL')",
                                                                    'fixture_tier_paths()')))
        self.assertNotEqual(args, self.flags() + self.all)

    def test_the_parity_legs_run_the_all_tier(self) -> None:
        """None of ``pypcap-parity``'s legs is ``latest``, so each asks for the ``ALL`` part alone."""
        found = legs(*PARITY) + legs('unit-tests.yml', 'pypcap-parity-ktlo')
        self.assertTrue(found)
        self.assertNotIn(self.latest, [leg['python-version'] for leg in found])
        self.assertIn(_tiers.FIXTURE_ALL_TIER_SELECTOR, step(PARITY)['run'])
        self.assertEqual(pytest_args(run_step(legs(*PARITY)[0], PARITY)),
                         ['-q', '-n', 'auto', '--dist', 'load'] + self.all)


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
            # #1958: less the step `test` runs on `latest` alone, which no experimental leg is.
            found = [re.findall(r"pip install -e '\.\[([^]]*)\]'", str(entry.get('run', '')))
                     for entry in job(*where)['steps']
                     if _dependency_gates.LATEST_LEG_CONDITION not in str(entry.get('if', ''))]
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

    def test_the_workflows_page_states_the_tiers(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ('``module_tier()``', "``__tier__ = 'LATEST'``", '``latest_tier_paths()``', "``fixture_tier_paths('ALL')``",
                       '``ALL``', '``LATEST``', '#1958'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)
        self.assertNotIn('roundtrip*', page)


if __name__ == '__main__':
    unittest.main()
