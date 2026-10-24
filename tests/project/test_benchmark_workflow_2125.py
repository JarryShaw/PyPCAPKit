# -*- coding: utf-8 -*-
"""#2125: :file:`benchmark.yml`, the engine benchmark on GitHub Actions.

The workflow runs :file:`examples/benchmark/native.sh` in one job on one runner,
over the engines' interpreters from :file:`.github/python-versions.toml`, and posts
the ratio table to Discussions.

* :class:`TestTriggers`: a weekly ``schedule`` and ``workflow_dispatch`` with the
  runner, the versions, the engines and the rounds and passes as inputs; no push,
  pull request or ``workflow_run``.
* :class:`TestTheCron`: off the hour, and in no hour on no day that another
  workflow's ``schedule`` fires in.
* :class:`TestPermissions`: read-only at the top, ``discussions: write`` on the
  ``discussion`` job alone, and no push.
* :class:`TestTheJobs`: one leg on the chosen runner with the engine tiers
  installed, running ``native.sh`` and never Docker; the tshark steps as
  ``unit-tests.yml``'s; the post to ``<workflow file stem>: <report name>``.
* :class:`TestTheMeasureStep` and :class:`TestTheReportStep` run those steps' own
  ``run:`` scripts under bash, with a stand-in ``native.sh``.
* :class:`TestNativeScript` runs :file:`examples/benchmark/native.sh` itself on
  what it refuses and on a version with no interpreter, which need no network.

"""

from __future__ import annotations

import importlib.util
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

from tests._workflows import WORKFLOWS, job, load, steps

try:
    import tomllib
except ImportError:  # Python 3.10 and older
    tomllib = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the workflow files and runs their steps and the tree's
#: scripts, a question about the tree.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = 'benchmark.yml'
NATIVE = ROOT / 'examples' / 'benchmark' / 'native.sh'
PINS = ROOT / 'examples' / 'benchmark' / 'python-images.txt'
VERSIONS_SCRIPT = ROOT / 'util' / 'python_versions.py'
UPDATER = ROOT / 'util' / 'update_python_versions.py'
BASH = shutil.which('bash')
#: How ``shell: bash`` runs a step's script, ahead of the script.
SHELL = [BASH or 'bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c']
TITLE = 'benchmark: weekly engine benchmark report'
INPUTS = {'runner', 'pythons', 'engines', 'rounds', 'repeats'}
MEASURE = 'Run examples/benchmark/native.sh'
#: The runner a scheduled run, and a dispatch left at its default, measures on.
DEFAULT_RUNNER = 'ubuntu-26.04-arm'
#: A cron's fields, ``minute hour day month weekday``.
CRON = re.compile(r'^(\d+) (\d+) (\S+) (\S+) (\S+)$')
#: The stand-in ``native.sh``: logs its arguments, one a line, and exits ``$NATIVE_EXIT``.
FAKE_NATIVE = textwrap.dedent('''\
    #!/bin/bash
    printf '%s\\n' "$@" > "$NATIVE_LOG"
    exit "${NATIVE_EXIT:-0}"
''')


def step(job_id: 'str', name: 'str') -> 'dict[str, Any]':
    """Job ``job_id``'s step named ``name``."""
    found = [item for item in steps(WORKFLOW, job_id) if item.get('name') == name]
    assert len(found) == 1, f'{job_id} has {len(found)} steps named {name!r}'  # nosec: B101
    return found[0]


def weekdays(field: 'str') -> 'set[int]':
    """The weekdays a cron's weekday field names, 0 for Sunday; ``*`` is every day."""
    if field == '*':
        return set(range(7))
    days = set()  # type: set[int]
    for part in field.split(','):
        low, _, high = part.partition('-')
        days.update(day % 7 for day in range(int(low), int(high or low) + 1))
    return days


def slots(cron: 'str') -> 'set[tuple[int, int]]':
    """Every (weekday, hour) ``cron`` fires in, for the plain crons the workflows use."""
    match = CRON.match(cron)
    assert match is not None, f'a cron this test cannot read: {cron!r}'  # nosec: B101
    _, hour, day, month, weekday = match.groups()
    assert (day, month) == ('*', '*'), f'a cron this test cannot read: {cron!r}'  # nosec: B101
    return {(found, int(hour)) for found in weekdays(weekday)}


def github_outputs() -> 'dict[str, str]':
    """``util/python_versions.py --github-output`` as the runner reads ``$GITHUB_OUTPUT``.

    ``name=value``, or ``name<<DELIMITER`` then the value's lines then the delimiter:
    ``engine-supported`` is written the second way, one version a line (#2125).

    """
    if tomllib is None:  # pragma: no cover
        raise unittest.SkipTest('tomllib, which util/python_versions.py reads its file with, needs Python 3.11+')
    with tempfile.TemporaryDirectory(prefix='pcapkit-2125-') as tmp:
        path = pathlib.Path(tmp) / 'github-output'
        subprocess.run([sys.executable, str(VERSIONS_SCRIPT), '--github-output'], cwd=ROOT,  # nosec: B603
                       env=dict(os.environ, GITHUB_OUTPUT=str(path)), capture_output=True, check=True, timeout=60)
        lines = path.read_text(encoding='utf-8').splitlines()
    values = {}  # type: dict[str, str]
    while lines:
        line = lines.pop(0)
        name, delimiter = line.split('<<', 1) if '<<' in line and '=' not in line.split('<<', 1)[0] else (None, None)
        if name is None:
            key, value = line.split('=', 1)
            values[key] = value
            continue
        body = []  # type: list[str]
        while lines[0] != delimiter:
            body.append(lines.pop(0))
        lines.pop(0)
        values[name] = '\n'.join(body)
    return values


def render(template: 'str', outputs: 'dict[str, str]') -> 'str':
    """A step's ``env:`` value with each ``needs.python-versions.outputs.X`` substituted."""
    return re.sub(r'\$\{\{ needs\.python-versions\.outputs\.([\w-]+) \}\}', lambda match: outputs[match.group(1)],
                  template)


def pinned_versions() -> 'list[str]':
    """Every version python-images.txt has a row for."""
    return [line.split()[0] for line in PINS.read_text(encoding='utf-8').splitlines()
            if not line.startswith('#') and len(line.split()) >= 4]


def crons(spec: 'dict[str, Any]') -> 'list[str]':
    """A parsed workflow's ``schedule`` crons."""
    schedule = (spec.get('on') or {}).get('schedule') or []
    return [str(entry['cron']) for entry in schedule]


class TestTriggers(unittest.TestCase):

    def test_a_weekly_schedule_and_a_dispatch_alone(self) -> None:
        spec = load(WORKFLOW)
        self.assertEqual(set(spec['on']), {'schedule', 'workflow_dispatch'})
        self.assertEqual(len(crons(spec)), 1)
        _, _, day, month, weekday = CRON.match(crons(spec)[0]).groups()  # type: ignore[union-attr]
        self.assertEqual((day, month, len(weekdays(weekday))), ('*', '*', 1))

    def test_the_dispatch_inputs(self) -> None:
        inputs = load(WORKFLOW)['on']['workflow_dispatch']['inputs']
        self.assertEqual(set(inputs), INPUTS)
        runner = inputs['runner']
        # The fastest runner that measures every engine, on #2128; the others stay choices.
        self.assertEqual((runner['type'], runner['default']), ('choice', DEFAULT_RUNNER))
        self.assertEqual(runner['options'][0], DEFAULT_RUNNER)
        self.assertLessEqual({'ubuntu-latest', 'macos-latest', 'windows-latest'}, set(runner['options']))
        # Empty is the default: every engine interpreter, benchmark.py's engines and counts.
        for name in INPUTS - {'runner'}:
            with self.subTest(input=name):
                self.assertEqual(inputs[name].get('default'), '')

    def test_a_scheduled_run_falls_back_to_the_default_runner(self) -> None:
        """A schedule has no inputs, so every read of the runner names the default."""
        text = (WORKFLOWS / WORKFLOW).read_text(encoding='utf-8')
        reads = re.findall(r'inputs\.runner\b(?: \|\| \'([\w.-]+)\')?', text)
        self.assertTrue(reads)
        self.assertEqual(set(reads), {DEFAULT_RUNNER})


class TestTheCron(unittest.TestCase):

    def test_off_the_hour(self) -> None:
        minute = int(CRON.match(crons(load(WORKFLOW))[0]).group(1))  # type: ignore[union-attr]
        self.assertNotIn(minute, (0, 15, 30, 45))

    def test_no_other_schedule_shares_its_hour(self) -> None:
        mine = slots(crons(load(WORKFLOW))[0])
        for path in sorted(WORKFLOWS.glob('*.yml')):
            if path.name == WORKFLOW:
                continue
            for cron in crons(load(path)):
                with self.subTest(workflow=path.name, cron=cron):
                    self.assertFalse(mine & slots(cron))

    def test_a_collision_is_caught(self) -> None:
        self.assertTrue(slots('17 3 * * 3') & slots('37 3 * * *'))
        self.assertTrue(slots('17 7 * * 1') & slots('23 7 * * 1'))
        self.assertFalse(slots('17 3 * * 3') & slots('17 3 * * 6'))


class TestPermissions(unittest.TestCase):

    def test_read_only_at_the_top(self) -> None:
        self.assertEqual(load(WORKFLOW)['permissions'], {'contents': 'read'})

    def test_only_the_discussion_job_writes(self) -> None:
        for job_id, spec in load(WORKFLOW)['jobs'].items():
            with self.subTest(job=job_id):
                if job_id == 'discussion':
                    self.assertEqual(spec['permissions'], {'contents': 'read', 'discussions': 'write'})
                else:
                    self.assertNotIn('permissions', spec)

    def test_no_job_pushes_or_keeps_a_token(self) -> None:
        for job_id, spec in load(WORKFLOW)['jobs'].items():
            for item in spec['steps']:
                with self.subTest(job=job_id, step=item.get('name') or item.get('uses')):
                    self.assertNotRegex(str(item.get('run', '')), r'\bgit (?:push|commit|tag)\b')
                    if str(item.get('uses', '')).startswith('actions/checkout@'):
                        self.assertIs(item['with']['persist-credentials'], False)


class TestTheJobs(unittest.TestCase):

    def test_the_jobs_and_their_order(self) -> None:
        jobs = load(WORKFLOW)['jobs']
        self.assertEqual(list(jobs), ['python-versions', 'benchmark', 'discussion'])
        self.assertEqual(jobs['benchmark']['needs'], ['python-versions'])
        self.assertEqual(jobs['discussion']['needs'], ['benchmark'])
        # A failed or partial benchmark still posts.
        self.assertEqual(jobs['discussion']['if'], "${{ always() && needs.benchmark.result != 'skipped' }}")

    def test_one_leg_on_the_chosen_runner(self) -> None:
        """Every version on one machine, as the per-version table's absolute times require."""
        benchmark = job(WORKFLOW, 'benchmark')
        self.assertEqual(benchmark['strategy']['matrix'], {'os': [f"${{{{ inputs.runner || '{DEFAULT_RUNNER}' }}}}"]})
        self.assertEqual(benchmark['runs-on'], f"${{{{ matrix.os || '{DEFAULT_RUNNER}' }}}}")
        # Only the measurement moves to it: reading the tiers and posting stay on x64.
        for job_id in ('python-versions', 'discussion'):
            with self.subTest(job=job_id):
                self.assertEqual(job(WORKFLOW, job_id)['runs-on'], 'ubuntu-latest')

    def test_the_engine_tiers_are_installed(self) -> None:
        setups = [item for item in steps(WORKFLOW, 'benchmark')
                  if str(item.get('uses', '')).startswith('actions/setup-python@')]
        self.assertEqual([item['with']['python-version'] for item in setups],
                         ['${{ needs.python-versions.outputs.engine-ktlo }}',
                          '${{ needs.python-versions.outputs.engine-supported }}'])
        self.assertIs(setups[0]['continue-on-error'], True)
        self.assertEqual(step('python-versions', 'Read .github/python-versions.toml')['run'],
                         'python3 util/python_versions.py --github-output')

    def test_it_runs_native_sh_and_never_docker(self) -> None:
        """run.sh and its images are the local path; the workflow measures on the runner."""
        self.assertIn('examples/benchmark/native.sh "${args[@]}"', str(step('benchmark', MEASURE)['run']))
        for job_id, spec in load(WORKFLOW)['jobs'].items():
            for item in spec['steps']:
                with self.subTest(job=job_id, step=item.get('name') or item.get('uses')):
                    self.assertNotRegex(str(item.get('run', '')), r'\bdocker\b|run\.sh')

    def test_the_post(self) -> None:
        run = str(step('discussion', 'Post the report to Discussions')['run'])
        self.assertEqual(' '.join(run.replace('\\\n', ' ').split()),
                         'python3 util/discussion_report.py --category "$REPORT_CATEGORY" '
                         f"--title '{TITLE}' --report report/report.md --mode scheduled --status \"$STATUS\"")
        self.assertEqual(load(WORKFLOW)['env']['REPORT_CATEGORY'], 'CI reports')
        self.assertTrue(TITLE.startswith(f'{pathlib.Path(WORKFLOW).stem}: '))
        self.assertIs(job(WORKFLOW, 'discussion')['continue-on-error'], True)
        self.assertEqual(step('discussion', 'Post the report to Discussions')['env']['STATUS'],
                         '${{ needs.benchmark.outputs.status || needs.benchmark.result }}')

    def test_tshark_is_installed_and_let_read_the_checkout_as_in_unit_tests(self) -> None:
        """#2019's AppArmor step directly follows the apt install, with ``engine-tests``' body."""
        names = [item.get('name') for item in steps(WORKFLOW, 'benchmark')]
        install = 'Install libpcap headers and tshark'
        apparmor = 'Let tshark read the checkout past its AppArmor profile'
        self.assertEqual(names[names.index(install) + 1], apparmor)
        self.assertIn('tshark', job(WORKFLOW, 'benchmark')['env']['APT_PACKAGES'].split())
        self.assertTrue(str(step('benchmark', install)['run']).startswith(
            '/usr/bin/python3 util/apt_packages.py install'))
        theirs = [item for item in steps('unit-tests.yml', 'engine-tests') if item.get('name') == apparmor]
        self.assertEqual(step('benchmark', apparmor)['run'], theirs[0]['run'])


class TestTheTiersIgnoreTheRunner(unittest.TestCase):
    """util/update_python_versions.py reads no tier label from a runner the dispatcher picks.

    Its tiers want the default labels on one Linux architecture, and the benchmark's
    default is arm64 where every test job's is x64.

    """

    @classmethod
    def setUpClass(cls) -> None:
        if tomllib is None:  # pragma: no cover
            raise unittest.SkipTest('tomllib, which util/update_python_versions.py imports, needs Python 3.11+')
        spec = importlib.util.spec_from_file_location('update_python_versions_2125', UPDATER)
        assert spec is not None and spec.loader is not None  # nosec: B101
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)  # type: ignore[union-attr]

    def workflows(self) -> 'dict[str, Any]':
        return {path.name: load(path) for path in sorted(WORKFLOWS.glob('*.yml'))}

    def test_the_benchmark_adds_no_label(self) -> None:
        with_it = self.module.workflow_labels(self.workflows())
        without = self.workflows()
        del without[WORKFLOW]
        self.assertEqual(with_it, self.module.workflow_labels(without))
        self.assertNotIn(DEFAULT_RUNNER, with_it['default'])

    def test_a_fixed_arm_runner_would_count(self) -> None:
        """The rule bites only on an input: the same job on a literal axis adds its label."""
        workflows = self.workflows()
        workflows[WORKFLOW]['jobs']['benchmark']['strategy']['matrix']['os'] = [DEFAULT_RUNNER]
        self.assertIn(DEFAULT_RUNNER, self.module.workflow_labels(workflows)['default'])


@unittest.skipIf(not BASH, 'needs bash on PATH')
class _Scratch(unittest.TestCase):

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2125-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.output = self.tmp / 'output'
        self.output.write_text('', encoding='utf-8')
        self.summary = self.tmp / 'summary.md'

    def run_step(self, job_id: 'str', name: 'str', **env: 'str') -> 'subprocess.CompletedProcess[str]':
        """``name``'s ``run:`` as ``shell: bash`` runs it, in the scratch directory."""
        environ = dict(os.environ, GITHUB_OUTPUT=str(self.output), GITHUB_STEP_SUMMARY=str(self.summary),
                       RUNNER_OS='Linux', RUNNER_ARCH='X64', ImageOS='ubuntu26', ImageVersion='20261020.1', **env)
        return subprocess.run([*SHELL, str(step(job_id, name)['run'])], env=environ,  # nosec: B603
                              cwd=self.tmp, capture_output=True, text=True, check=False, timeout=60)

    def outputs(self) -> 'dict[str, str]':
        return dict(line.split('=', 1) for line in self.output.read_text(encoding='utf-8').splitlines())


class TestTheMeasureStep(_Scratch):
    """``Run examples/benchmark/native.sh`` against a stand-in script."""

    def setUp(self) -> None:
        super().setUp()
        script = self.tmp / 'examples' / 'benchmark' / 'native.sh'
        script.parent.mkdir(parents=True)
        script.write_text(FAKE_NATIVE, encoding='utf-8')
        script.chmod(0o755)
        self.log = self.tmp / 'native.log'

    def measure(self, code: 'int' = 0, **inputs: 'str') -> 'tuple[int, Optional[list[str]], dict[str, str]]':
        """The step, with ``INSTALLED`` as the runner renders it from the script's real outputs."""
        installed = render(step('benchmark', MEASURE)['env']['INSTALLED'], self.versions)
        env = {'INSTALLED': installed, 'PYTHONS': '', 'ENGINES': '', 'ROUNDS': '', 'REPEATS': '',
               'RUNNER_LABEL': 'ubuntu-latest', 'NATIVE_LOG': str(self.log), 'NATIVE_EXIT': str(code)}
        env.update(inputs)
        result = self.run_step('benchmark', MEASURE, **env)
        args = self.log.read_text(encoding='utf-8').splitlines() if self.log.exists() else None
        return result.returncode, args, self.outputs()

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.versions = github_outputs()

    def test_the_outputs_are_the_multi_line_form(self) -> None:
        """What the step must split: ``engine-supported`` one version a line."""
        self.assertIn('\n', self.versions['engine-supported'])
        self.assertIn('\n', render(step('benchmark', MEASURE)['env']['INSTALLED'], self.versions))

    def test_a_scheduled_run_measures_every_interpreter(self) -> None:
        status, args, outputs = self.measure()
        self.assertEqual((status, outputs), (0, {'status': 'success'}))
        every = (self.versions['engine-ktlo'] + ' ' + self.versions['engine-supported']).split()
        self.assertEqual(args, ['--pythons', ','.join(every), '--out', 'out',
                                '--image', 'GitHub-hosted ubuntu-latest, image ubuntu26 20261020.1'])

    def test_a_spaced_list_is_read_as_a_list(self) -> None:
        status, args, _ = self.measure(PYTHONS=' 3.12, 3.11 ,3.13')
        self.assertEqual(status, 0)
        assert args is not None  # nosec: B101
        self.assertEqual(args[:2], ['--pythons', '3.12,3.11,3.13'])

    def test_every_interpreter_has_a_pins_row(self) -> None:
        """native.sh refuses a version python-images.txt lacks, so a new tier needs its row first."""
        every = (self.versions['engine-ktlo'] + ' ' + self.versions['engine-supported']).split()
        self.assertTrue(every)
        self.assertLessEqual(set(every), set(pinned_versions()))

    def test_the_dispatch_inputs_reach_the_script(self) -> None:
        status, args, _ = self.measure(PYTHONS='3.12,3.11', ENGINES='default,dpkt', ROUNDS='50', REPEATS='2')
        self.assertEqual(status, 0)
        assert args is not None  # nosec: B101
        self.assertEqual(args[:2], ['--pythons', '3.12,3.11'])
        self.assertEqual(args[6:], ['--engines', 'default,dpkt', '--rounds', '50', '--repeats', '2'])

    def test_a_version_not_installed_is_refused(self) -> None:
        status, args, outputs = self.measure(PYTHONS='3.11,3.1')
        self.assertEqual((status, args, outputs), (2, None, {}))

    def test_gaps_warn_and_no_table_fails(self) -> None:
        status, _, outputs = self.measure(code=3)
        self.assertEqual((status, outputs), (0, {'status': 'warning'}))
        self.output.write_text('', encoding='utf-8')
        status, _, outputs = self.measure(code=1)
        self.assertEqual((status, outputs), (1, {'status': 'failure'}))


class TestTheReportStep(_Scratch):
    """``Write the report``: the ratio table for the post, and both tables for the summary."""

    def test_the_report_names_the_runner_and_fences_the_tables(self) -> None:
        out = self.tmp / 'out'
        out.mkdir()
        (out / 'table.rst').write_text('RATIOS\n', encoding='utf-8')
        (out / 'table-versions.rst').write_text('ABSOLUTES\n', encoding='utf-8')
        self.assertEqual(self.run_step('benchmark', 'Write the report', RUNNER_LABEL='macos-latest').returncode, 0)
        report = (out / 'report.md').read_text(encoding='utf-8')
        self.assertTrue(report.startswith('## Engine benchmark on macos-latest\n'))
        self.assertIn('Linux X64, image ubuntu26 20261020.1', report)
        self.assertTrue(report.endswith('```rst\nRATIOS\n```\n'))
        self.assertNotIn('ABSOLUTES', report)
        self.assertEqual(self.summary.read_text(encoding='utf-8'), f'{report}\n```rst\nABSOLUTES\n```\n')
        self.assertEqual(step('benchmark', 'Write the report')['if'],
                         "${{ always() && hashFiles('out/table.rst') != '' }}")


class TestNativeScript(_Scratch):
    """``native.sh`` itself, where it needs no interpreter install: a copy, beside a pins file with a 3.99 row."""

    def setUp(self) -> None:
        super().setUp()
        directory = self.tmp / 'examples' / 'benchmark'
        directory.mkdir(parents=True)
        shutil.copy(NATIVE, directory / 'native.sh')
        (directory / 'python-images.txt').write_text(
            PINS.read_text(encoding='utf-8') + '3.99 python:3.99-slim-bookworm@sha256:00 no-pypcap opt-in\n',
            encoding='utf-8')
        self.script = directory / 'native.sh'

    def native(self, *args: 'str') -> 'subprocess.CompletedProcess[str]':
        command = [SHELL[0], str(self.script), '--out', str(self.tmp / 'out'), '--work', str(self.tmp / 'work'),
                   *args]
        return subprocess.run(command, cwd=self.tmp,  # nosec: B603
                              capture_output=True, text=True, check=False, timeout=60,
                              env=dict(os.environ, PATH=os.defpath, RUNNER_TOOL_CACHE=''))

    def test_it_refuses_bad_arguments(self) -> None:
        self.assertEqual(self.native('--bogus').returncode, 2)
        self.assertEqual(self.native('--engines', 'dpkt').returncode, 2)

    def test_a_version_the_pins_lack_is_a_typo(self) -> None:
        """As in run.sh, and before anything is written: 3.1 is not 3.10."""
        for version in ('3.1', '3.98'):
            with self.subTest(version=version):
                result = self.native('--pythons', f'3.99,{version}')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(f"native.sh: '{version}' is not in ", result.stderr)
                self.assertFalse((self.tmp / 'out').exists())

    def test_a_repeat_is_measured_once(self) -> None:
        result = self.native('--pythons', '3.99, 3.99,3.99')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr.count('==> Python 3.99'), 1)

    def test_a_version_with_no_interpreter_is_a_gap_and_no_table(self) -> None:
        result = self.native('--pythons', '3.99')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.tmp / 'out' / 'missing' / '3.99.txt').read_text(encoding='utf-8'),
                         'no Python 3.99 interpreter was found on this machine\n')
        self.assertIn('no environment produced a measurement', result.stderr)

    def test_it_is_executable(self) -> None:
        self.assertTrue(os.access(NATIVE, os.X_OK))


if __name__ == '__main__':
    unittest.main()
