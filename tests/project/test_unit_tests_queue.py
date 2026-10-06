# -*- coding: utf-8 -*-
"""Tests for #1052's queue cuts in :file:`.github/workflows/unit-tests.yml`.

These fail silently if they drift, so they are pinned here:

* ``required-checks`` may accept a ``skipped`` leg **only** when ``changes``
  classified the diff as docs-only. Its shell step is executed below against
  every combination that matters, rather than read, because the one way it goes
  wrong -- a skip accepted on a code change -- is a green gate over untested code.
* The ``changes`` classifier must call anything outside ``docs/`` and ``*.md``
  code, and a Markdown file under a code directory code too.
* ``unittest-ordering`` stays off pull requests and out of the required set,
  and ``engine-tests``'s 3.15 cell stays non-blocking through a step-level
  ``continue-on-error`` rather than a job-level one.
* The classifier, the engine cell loops and the apt retry are executed too: the
  classifier against a scratch merge commit, the others with their commands
  stubbed on ``PATH``.
* Every test outside :file:`tests/project` that reads ``docs/`` or Markdown is
  run by ``project-tests``, so a docs-only PR cannot break it unseen.

The workflow is sliced as text, not parsed with :mod:`yaml`, which is in no
extra of :file:`pyproject.toml`; the same split
:file:`tests/project/test_workflow_apt_timeouts.py` uses.

"""

from __future__ import annotations

import ast
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'unit-tests.yml'

#: The four legs a docs-only pull request may skip.
LEGS = ('test', 'integration', 'engine-tests', 'pypcap-parity')


def job(name: 'str') -> 'str':
    """The text of job ``name``, from its header to the next top-level job."""
    text = WORKFLOW.read_text(encoding='utf-8')
    match = re.search(rf'(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)', text)
    if match is None:
        raise AssertionError(f'no job named {name!r} in {WORKFLOW}')
    return match.group(1)


def run_block(section: 'str') -> 'str':
    """The dedented ``run: |`` script of the single step in ``section`` that has one."""
    blocks = re.findall(r'(?ms)^        run: \|\n(.*?)(?=^      - |\Z)', section)
    if len(blocks) != 1:
        raise AssertionError(f'expected one run: | block, found {len(blocks)}')
    # A job's slice runs on to the next job header, so it can end in the
    # comment above that job; the block ends at its first less-indented line.
    lines = []
    for line in blocks[0].splitlines():
        if line.strip() and not line.startswith(' ' * 10):
            break
        lines.append(line)
    return textwrap.dedent('\n'.join(lines))


def required_needs() -> 'set[str]':
    """The job names in ``required-checks``'s ``needs:`` list."""
    match = re.search(r'(?m)^    needs: \[(.*)\]$', job('required-checks'))
    if match is None:
        raise AssertionError('required-checks has no one-line needs: list')
    return {name.strip() for name in match.group(1).split(',')}


def header(section: 'str') -> 'str':
    """The job-level keys of ``section``, i.e. everything before ``steps:``."""
    return section.split('\n    steps:', 1)[0]


class TestRequiredChecksSkips(unittest.TestCase):
    """The gate's shell step, executed against each result combination."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is not available')
        self.script = run_block(job('required-checks'))

    def gate(self, code: 'str', legs: 'str', project: 'str', changes: 'str' = 'success',
             **override: 'str') -> 'int':
        """The gate's exit status with every leg reporting ``legs`` unless overridden."""
        results = {'TEST': legs, 'INTEGRATION': legs, 'ENGINE_TESTS': legs, 'PYPCAP_PARITY': legs}
        results.update(override)
        env = dict(os.environ, CHANGES=changes, CODE=code, PROJECT_TESTS=project, **results)
        return subprocess.run(['bash', '-c', self.script], env=env, check=False,
                              capture_output=True, text=True).returncode

    def test_needs_every_leg_and_the_docs_only_helpers(self) -> None:
        """The gate reads every leg plus ``changes`` and ``project-tests``."""
        self.assertEqual(required_needs(), set(LEGS) | {'changes', 'project-tests'})

    def test_code_change_requires_every_leg_to_succeed(self) -> None:
        """On a code change nothing but ``success`` passes."""
        self.assertEqual(self.gate('true', 'success', 'skipped'), 0)
        for result in ('skipped', 'failure', 'cancelled'):
            with self.subTest(result=result):
                self.assertNotEqual(self.gate('true', result, 'skipped'), 0)

    def test_docs_only_accepts_skipped_legs_when_project_tests_pass(self) -> None:
        """A docs-only diff may skip the legs when ``project-tests`` passed."""
        self.assertEqual(self.gate('false', 'skipped', 'success'), 0)
        self.assertEqual(self.gate('false', 'success', 'success'), 0)

    def test_docs_only_still_needs_project_tests(self) -> None:
        """A docs-only diff without a passing ``project-tests`` fails."""
        for result in ('skipped', 'failure', 'cancelled'):
            with self.subTest(result=result):
                self.assertNotEqual(self.gate('false', 'skipped', result), 0)

    def test_docs_only_still_rejects_a_failed_leg(self) -> None:
        """Skips are accepted on a docs-only diff, failures are not."""
        self.assertNotEqual(self.gate('false', 'failure', 'success'), 0)

    def test_every_leg_is_checked_on_its_own(self) -> None:
        """One failing leg among passing ones fails the gate, on either path."""
        for env_name in ('TEST', 'INTEGRATION', 'ENGINE_TESTS', 'PYPCAP_PARITY'):
            with self.subTest(leg=env_name):
                for code, legs, project, odd in (('true', 'success', 'skipped', 'failure'),
                                                 ('true', 'success', 'skipped', 'skipped'),
                                                 ('false', 'skipped', 'success', 'failure')):
                    self.assertNotEqual(self.gate(code, legs, project, **{env_name: odd}), 0)

    def test_an_unclassified_diff_skips_nothing(self) -> None:
        """A failed, skipped or garbled ``changes`` makes every skip a failure."""
        for changes, code in (('failure', ''), ('skipped', ''), ('success', ''),
                              ('success', 'maybe'), ('failure', 'false')):
            with self.subTest(changes=changes, code=code):
                self.assertNotEqual(self.gate(code, 'skipped', 'success', changes), 0)


class TestChangesClassifier(unittest.TestCase):
    """``is_docs`` from the ``changes`` job, executed on sample paths."""

    def setUp(self) -> None:
        script = run_block(job('changes'))
        source = textwrap.dedent(script.split("<<'PY'\n", 1)[1].split("\ncode = 'true'", 1)[0])
        namespace = {}  # type: dict[str, object]
        exec(compile(source, f'{WORKFLOW}:changes', 'exec'), namespace)  # pylint: disable=exec-used
        is_docs = namespace['is_docs']
        self.is_docs = is_docs  # type: Callable[[str], bool]  # type: ignore[assignment]

    def test_docs_and_markdown_are_docs(self) -> None:
        """``docs/**`` and top-level Markdown are docs."""
        for path in ('docs/source/index.rst', 'docs/source/conf.py', 'README.md',
                     'CONTRIBUTING.md', 'CHANGELOG.md'):
            with self.subTest(path=path):
                self.assertTrue(self.is_docs(path))

    def test_everything_else_is_code(self) -> None:
        """Anything else, and Markdown under a code directory, is code."""
        for path in ('pyproject.toml', 'setup.py', 'pcapkit/__init__.py', 'Makefile',
                     '.github/workflows/unit-tests.yml', '.github/PULL_REQUEST_TEMPLATE.md',
                     'tests/project/README.md', 'util/notes.md', 'examples/README.md',
                     'pcapkit/vendor/README.md'):
            with self.subTest(path=path):
                self.assertFalse(self.is_docs(path))

    def test_only_this_workflows_own_pull_request_is_classified(self) -> None:
        """Other events, and callers, always run everything."""
        section = job('changes')
        self.assertIn("github.event_name == 'pull_request' && github.workflow == 'Unit Tests'",
                      section)
        self.assertIn("'--no-renames'", section)


class TestJobGating(unittest.TestCase):
    """Which jobs run on which events, read off their job-level keys."""

    def test_the_four_legs_skip_only_on_a_docs_only_diff(self) -> None:
        """Each leg is gated on ``changes`` by a job-level ``if:``."""
        for name in LEGS:
            with self.subTest(job=name):
                head = header(job(name))
                self.assertIn("needs.changes.outputs.code != 'false'", head)
                self.assertRegex(head, r'(?m)^    needs: \[changes\]$')

    def test_project_tests_runs_only_on_a_docs_only_diff(self) -> None:
        """``project-tests`` never duplicates ``test`` on a code change."""
        self.assertIn("needs.changes.outputs.code == 'false'", header(job('project-tests')))

    def test_project_tests_failures_are_not_softened(self) -> None:
        """No ``continue-on-error`` anywhere in ``project-tests``: a red step must fail it."""
        self.assertNotIn('continue-on-error', job('project-tests'))

    def test_unittest_ordering_is_off_pull_requests_and_not_required(self) -> None:
        """H: main pushes only, and never a required leg."""
        head = header(job('unittest-ordering'))
        self.assertIn("github.event_name != 'pull_request'", head)
        self.assertNotIn('unittest-ordering', required_needs())

    def test_unittest_ordering_runs_verbose_under_a_step_cap(self) -> None:
        """A and C: ``--verbose`` and a step-level cap on the run step."""
        section = job('unittest-ordering')
        run_step = section.split('- name: Run tests/', 1)[1]
        self.assertIn('--verbose', run_step)
        self.assertRegex(run_step, r'(?m)^        timeout-minutes: \d+$')

    def test_engine_tests_is_one_job_per_engine_with_a_non_blocking_315_step(self) -> None:
        """E: matrix on engine only; 3.15 blocks nothing, 3.10-3.14 do."""
        section = job('engine-tests')
        head = header(section)
        self.assertNotIn('python-version', head)
        self.assertNotIn('continue-on-error', head)
        self.assertRegex(section, r'(?m)^        engine:$')
        experimental = section.split('- name: Run the 3.15 cell', 1)[1]
        self.assertRegex(experimental, r'(?m)^        continue-on-error: true$')
        gating = section.split('- name: Run the 3.10-3.14 cells', 1)[1].split('      - name:', 1)[0]
        self.assertNotIn('continue-on-error', gating)
        self.assertIn('for py in 3.10 3.11 3.12 3.13 3.14;', gating)


def step(section: 'str', name: 'str') -> 'str':
    """The text of the step called ``name`` in ``section``, up to the next step."""
    match = re.search(rf'(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)', section)
    if match is None:
        raise AssertionError(f'no step named {name!r}')
    return match.group(1)


def step_script(section: 'str', name: 'str') -> 'str':
    """The dedented ``run: |`` script of step ``name``."""
    body = step(section, name).split('        run: |\n', 1)[1]
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith(' ' * 10):
            break
        lines.append(line)
    return textwrap.dedent('\n'.join(lines)) + '\n'


def step_cap(section: 'str', name: 'str') -> 'int':
    """Step ``name``'s own ``timeout-minutes``."""
    match = re.search(r'(?m)^        timeout-minutes: (\d+)$', step(section, name))
    if match is None:
        raise AssertionError(f'step {name!r} declares no timeout-minutes')
    return int(match.group(1))


def bash(script: 'str', env: 'dict[str, str]', cwd: 'Optional[str]' = None) -> 'int':
    """Run ``script`` under ``bash -e`` (GitHub's default shell) and return its status."""
    return subprocess.run(['bash', '-e', '-c', script], env=dict(os.environ, **env), cwd=cwd,
                          check=False, capture_output=True, text=True).returncode


class _Scratch(unittest.TestCase):
    """A temporary directory per test, and ``bash`` required."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is not available')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1052-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)


class TestClassifierAgainstARealMerge(_Scratch):
    """The whole ``Classify the diff`` script, run in a scratch repository.

    The repository mirrors a pull-request checkout: ``HEAD`` is a merge commit
    whose first parent is the base branch, and the base branch has moved on with
    a *code* change since the PR branched, so diffing against any other base
    than ``HEAD^1`` reads the PR as code.

    """

    def setUp(self) -> None:
        super().setUp()
        if shutil.which('git') is None:  # pragma: no cover
            self.skipTest('git is not available')
        self.script = run_block(job('changes'))
        self.repo = self.tmp / 'repo'
        self.repo.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.write('README.md', 'base\n')
        self.write('pcapkit/x.py', 'X = 1\n')
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'base')
        self.git('checkout', '-q', '-b', 'pr')
        self.git('checkout', '-q', 'main')
        self.write('pcapkit/y.py', 'Y = 1\n')
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'main moves on with code')
        self.git('checkout', '-q', 'pr')

    def git(self, *args: 'str') -> None:
        """Run git in the scratch repository, isolated from user config."""
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        config = ('-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false')
        subprocess.run(['git', *config, *args], cwd=self.repo, env=env, check=True,
                       capture_output=True)

    def write(self, name: 'str', text: 'str') -> None:
        """Write ``text`` to ``name`` in the scratch repository."""
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def pr(self, *files: 'str') -> None:
        """Commit ``files`` on the PR branch and check out its merge into main."""
        for name in files:
            self.write(name, 'changed\n')
        self.git('add', '-A')
        self.git('commit', '-q', '--allow-empty', '-m', 'pr')
        self.git('checkout', '-q', 'main')
        self.git('merge', '-q', '--no-ff', '--no-edit', 'pr')

    def classify(self, own_pr: 'str' = 'true', cwd: 'Optional[pathlib.Path]' = None) -> 'str':
        """Run the classifier and return the line it wrote to ``GITHUB_OUTPUT``."""
        output = self.tmp / 'output'
        status = bash(self.script, {'OWN_PR': own_pr, 'GITHUB_OUTPUT': str(output)},
                      cwd=str(cwd or self.repo))
        self.assertEqual(status, 0)
        return output.read_text(encoding='utf-8').strip()

    def test_a_docs_only_pull_request_is_not_code(self) -> None:
        """Only ``HEAD^1`` sees the PR's own diff; ``HEAD^2`` would see main's code."""
        self.pr('docs/source/index.rst', 'CONTRIBUTING.md')
        self.assertEqual(self.classify(), 'code=false')

    def test_a_code_file_makes_it_code(self) -> None:
        """One code file among docs is enough."""
        self.pr('docs/source/index.rst', 'pcapkit/x.py')
        self.assertEqual(self.classify(), 'code=true')

    def test_a_name_holding_whitespace_is_one_path(self) -> None:
        """``notes.md docs/y`` is a root file, not ``notes.md`` and ``docs/y``."""
        self.pr('docs/source/index.rst', 'notes.md docs/y')
        self.assertEqual(self.classify(), 'code=true')

    def test_another_event_always_runs_everything(self) -> None:
        """``OWN_PR`` false (a push, or a caller's pull request) is code."""
        self.pr('docs/source/index.rst')
        self.assertEqual(self.classify(own_pr='false'), 'code=true')

    def test_an_empty_diff_is_code(self) -> None:
        """Nothing to classify is not evidence of a docs-only change."""
        self.pr()
        self.assertEqual(self.classify(), 'code=true')

    def test_a_failed_diff_is_code(self) -> None:
        """Outside a repository ``git diff`` fails, and that must not skip anything."""
        elsewhere = self.tmp / 'not-a-repo'
        elsewhere.mkdir()
        self.assertEqual(self.classify(cwd=elsewhere), 'code=true')


class TestEngineCellLoops(_Scratch):
    """The two cell-loop steps of ``engine-tests``, with the cell script stubbed."""

    def run_loop(self, name: 'str', fail: 'str') -> 'tuple[int, list[str]]':
        """Run loop step ``name`` with the cell for ``fail`` failing; status and cells run."""
        (self.tmp / 'engine-cell.sh').write_text(
            'echo "$1" >> "$RUNNER_TEMP/calls"\n[ "$1" != "$FAIL_PY" ]\n', encoding='utf-8')
        status = bash(step_script(job('engine-tests'), name),
                      {'RUNNER_TEMP': str(self.tmp), 'ENGINE': 'DPKT', 'FAIL_PY': fail,
                       'GITHUB_STEP_SUMMARY': str(self.tmp / 'summary')})
        calls = self.tmp / 'calls'
        return status, calls.read_text(encoding='utf-8').split() if calls.exists() else []

    def test_every_gating_cell_runs_and_passing_passes(self) -> None:
        """All five gating interpreters run; none failing exits 0."""
        status, calls = self.run_loop('Run the 3.10-3.14 cells', fail='none')
        self.assertEqual(status, 0)
        self.assertEqual(calls, ['3.10', '3.11', '3.12', '3.13', '3.14'])

    def test_one_failing_cell_fails_the_step_after_the_rest_ran(self) -> None:
        """A failure is not swallowed, and does not stop the later cells."""
        status, calls = self.run_loop('Run the 3.10-3.14 cells', fail='3.12')
        self.assertNotEqual(status, 0)
        self.assertEqual(calls, ['3.10', '3.11', '3.12', '3.13', '3.14'])

    def test_a_failing_315_cell_fails_its_own_step(self) -> None:
        """The step is red; only its ``continue-on-error`` keeps the job green."""
        status, calls = self.run_loop('Run the 3.15 cell (experimental, non-blocking)',
                                      fail='3.15')
        self.assertNotEqual(status, 0)
        self.assertEqual(calls, ['3.15'])


#: The two apt steps, as (job, step name, extra env).
APT_STEPS: 'tuple[tuple[str, str, dict[str, str]], ...]' = (
    ('engine-tests', "Install this engine's system packages", {'ENGINE': 'PyShark'}),
    ('pypcap-parity', 'Install libpcap headers, a C toolchain, and tshark', {}),
)

#: Stubs for the commands the apt steps run, put first on PATH.
STUBS = {
    'sudo': 'exec env "$@"\n',
    'timeout': 'echo "$1" >> "$STUB_LOG.timeouts"\nshift\nexec "$@"\n',
    'apt-get': ('echo "$1" >> "$STUB_LOG.apt"\n'
                'if [ "$1" = update ]; then\n'
                '  n=$(grep -c update "$STUB_LOG.apt")\n'
                '  [ "$n" -gt "$FAIL_UPDATES" ]\n'
                'fi\n'),
    'dpkg': 'exit 0\n',
    'debconf-set-selections': 'cat > /dev/null\n',
}


class TestAptRetry(_Scratch):
    """Both apt steps, with ``sudo``/``timeout``/``apt-get`` stubbed."""

    def run_apt(self, name: 'str', job_name: 'str', extra: 'dict[str, str]',
                fail_updates: 'int') -> 'tuple[int, list[str], list[int]]':
        """Run apt step ``name`` with the first ``fail_updates`` updates failing."""
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir(exist_ok=True)
        for command, body in STUBS.items():
            path = bin_dir / command
            path.write_text('#!/bin/bash\n' + body, encoding='utf-8')
            path.chmod(0o755)
        log = self.tmp / 'stub'
        for suffix in ('.apt', '.timeouts'):
            pathlib.Path(f'{log}{suffix}').write_text('', encoding='utf-8')
        status = bash(step_script(job(job_name), name),
                      dict(extra, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}',
                           STUB_LOG=str(log), FAIL_UPDATES=str(fail_updates)))
        apt = pathlib.Path(f'{log}.apt').read_text(encoding='utf-8').split()
        timeouts = pathlib.Path(f'{log}.timeouts').read_text(encoding='utf-8')
        bounds = [int(n) for n in timeouts.split()]
        return status, apt, bounds

    def test_a_clean_run_tries_once(self) -> None:
        """No failure, one update and one install."""
        for job_name, name, extra in APT_STEPS:
            with self.subTest(job=job_name):
                status, apt, _ = self.run_apt(name, job_name, extra, fail_updates=0)
                self.assertEqual((status, apt), (0, ['update', 'install']))

    def test_one_stall_is_retried_once(self) -> None:
        """A failed first update is retried, and the retry can succeed."""
        for job_name, name, extra in APT_STEPS:
            with self.subTest(job=job_name):
                status, apt, _ = self.run_apt(name, job_name, extra, fail_updates=1)
                self.assertEqual((status, apt), (0, ['update', 'update', 'install']))

    def test_two_stalls_fail_after_exactly_two_attempts(self) -> None:
        """One retry, not more: the second failure fails the step."""
        for job_name, name, extra in APT_STEPS:
            with self.subTest(job=job_name):
                status, apt, _ = self.run_apt(name, job_name, extra, fail_updates=2)
                self.assertNotEqual(status, 0)
                self.assertEqual(apt, ['update', 'update'])

    def test_both_attempts_fit_inside_a_five_minute_step_cap(self) -> None:
        """Every apt call is bounded, and two full attempts fit the 5-minute cap."""
        for job_name, name, extra in APT_STEPS:
            with self.subTest(job=job_name):
                status, apt, bounds = self.run_apt(name, job_name, extra, fail_updates=0)
                self.assertEqual(status, 0)
                self.assertEqual(len(bounds), len(apt), 'an apt-get call runs without timeout')
                self.assertEqual(step_cap(job(job_name), name), 5)
                self.assertLessEqual(2 * sum(bounds), 5 * 60)


#: Matches a string literal that is a path into docs/ or names Markdown files.
_DOC_PATH = re.compile(r'^(?:docs(?:/\S*)?|\S*\.md)$')


def docs_readers() -> 'set[str]':
    """Dotted names of test modules outside tests/project and tests/ itself that
    name a ``docs/`` or Markdown path in code (docstrings excluded)."""
    found = set()
    for path in sorted((ROOT / 'tests').rglob('*.py')):
        relative = path.relative_to(ROOT / 'tests')
        if len(relative.parts) < 2 or relative.parts[0] == 'project':
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.body and isinstance(node.body[0], ast.Expr) \
                        and isinstance(node.body[0].value, ast.Constant):
                    docstrings.add(id(node.body[0].value))
        if any(isinstance(node, ast.Constant) and isinstance(node.value, str)
               and id(node) not in docstrings and _DOC_PATH.match(node.value)
               for node in ast.walk(tree)):
            found.add('.'.join(('tests',) + relative.with_suffix('').parts))
    return found


class TestDocsOnlyPathRunsEveryDocsReader(unittest.TestCase):
    """A docs-only PR must still run every test that reads what it changed."""

    def listed(self) -> 'set[str]':
        """The modules project-tests' second run step names."""
        script = step(job('project-tests'), 'Run the other tests that read docs/ or Markdown')
        command = re.search(r'(?m)^        run: python -m unittest -v (.+)$', script)
        self.assertIsNotNone(command)
        return set(command.group(1).split())  # type: ignore[union-attr]

    def test_every_reader_outside_tests_project_is_run(self) -> None:
        """tests/project and root modules run via the project leg; the rest are listed."""
        missing = docs_readers() - self.listed()
        self.assertFalse(missing, f'add {sorted(missing)} to project-tests in unit-tests.yml')

    def test_every_listed_module_exists(self) -> None:
        """A renamed or deleted module would make the step fail on import anyway."""
        for name in self.listed():
            with self.subTest(module=name):
                self.assertTrue((ROOT / (name.replace('.', '/') + '.py')).is_file())

    def test_the_scan_is_not_blind(self) -> None:
        """The one known reader is found, so a passing run is not vacuous."""
        self.assertIn('tests.corekit.test_sentinel_exports_unit', docs_readers())


#: Every ``unit-tests.yml:N`` or ``unit-tests.yml:N-M`` citation in these documents,
#: as (text the cited first line must contain, text the last line must contain).
#: A citation the table does not account for fails, and so does a table entry no
#: citation matches -- so moving a job without renumbering the prose fails here.
CITATIONS: 'dict[str, list[tuple[str, Optional[str]]]]' = {
    'docs/source/contributing/releasing.rst': [
        ('  gate:', 'run: python -m pytest -q -n auto --dist load'),
        ('  changelog:', 'fi'),
    ],
    'docs/source/contributing/workflows.rst': [
        ('# Deliberately *not* gated on ``gate-only``', '# this is neither expensive'),
        ('name: Required checks passed', None),
        ('five for `Compat Python 3.10`', None),
        ("# Ruleset 23497679's required_status_checks", '# them.'),
        ('  required-checks:', 'echo "All required jobs reported an accepted result."'),
        ('if: ${{ always() && inputs.gate-only != true }}', None),
        ('# 3.15 deliberately excluded', '(non-blocking, schedule-only)'),
        ('# See the `test` job above for why 3.15', None),
    ],
}


class TestDocCitationsResolve(unittest.TestCase):
    """The prose's ``unit-tests.yml`` line numbers point at what it says they do."""

    def test_every_citation_lands_on_its_anchor(self) -> None:
        """Each citation's range starts and ends on the line its anchor names."""
        lines = WORKFLOW.read_text(encoding='utf-8').splitlines()
        documents = sorted({str(p.relative_to(ROOT)) for p in (ROOT / 'docs').rglob('*.rst')}
                           | {str(p.relative_to(ROOT)) for p in ROOT.glob('*.md')})
        for document in documents:
            text = (ROOT / document).read_text(encoding='utf-8')
            cited = [(int(m.group(1)), int(m.group(2) or m.group(1)))
                     for m in re.finditer(r'unit-tests\.yml:(\d+)(?:-(\d+))?', text)]
            anchors = CITATIONS.get(document, [])
            unmatched = list(anchors)
            for first, last in cited:
                with self.subTest(document=document, citation=f'{first}-{last}'):
                    self.assertLessEqual(last, len(lines))
                    hit = next((a for a in anchors if a[0] in lines[first - 1]
                                and (a[1] is None or a[1] in lines[last - 1])), None)
                    self.assertIsNotNone(
                        hit, f'{document} cites unit-tests.yml:{first}-{last}, which is '
                             f'{lines[first - 1].strip()!r} .. {lines[last - 1].strip()!r}')
                    if hit in unmatched:
                        unmatched.remove(hit)
            with self.subTest(document=document):
                self.assertFalse(unmatched, f'{document}: no citation lands on {unmatched}')


if __name__ == '__main__':
    unittest.main()
