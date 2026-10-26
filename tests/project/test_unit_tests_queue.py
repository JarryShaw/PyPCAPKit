# -*- coding: utf-8 -*-
"""Tests for #1052's queue cuts in :file:`.github/workflows/unit-tests.yml`.

These fail silently if they drift, so they are pinned here:

* ``required-checks`` may accept a ``skipped`` leg **only** when ``changes``
  classified the diff as docs-only, or a skipped ``engine-tests`` and
  ``pypcap-parity`` only when it classified it as test-only (#2243). Its shell
  step is executed below against every combination that matters, rather than
  read, because the one way it goes wrong -- a skip accepted on a code change --
  is a green gate over untested code. It needs ``project-tests`` on every diff,
  as the project pins' one run (#1954).
* The ``changes`` classifier must call anything outside ``docs/`` and ``*.md``
  not docs, and a Markdown file under a code directory not docs either. A diff of
  ``tests/`` and docs alone is test-only, and any other file makes it code (#2243).
  The jobs each class skips are :mod:`tests.project.test_light_pull_requests_2243`'s.
* ``unittest-ordering`` stays off pull requests and out of the required set,
  and queues behind ``test`` without needing it to pass (#1538);
  ``engine-tests``'s KTLO cells stay non-blocking through a step-level
  ``continue-on-error`` rather than a job-level one (#1633), and the job has no
  ``DPKT`` cell (#1538).
* The classifier, :file:`util/classify_changes.py` (#1967), the engine cell loops
  and the apt retry, :file:`util/apt_packages.py`'s (#1967), are executed
  too: the classifier against a scratch merge commit, the others with their
  commands stubbed on ``PATH``.
* Every test outside :file:`tests/project` that reads ``docs/`` or Markdown is
  run by ``project-tests``, so a docs-only PR cannot break it unseen.

The workflow is sliced as text, not parsed with :mod:`yaml`, which comes only
with the ``test`` extra of :file:`pyproject.toml`; the same split
:file:`tests/project/test_workflow_apt_timeouts.py` uses.

"""

from __future__ import annotations

import ast
import importlib.util
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_versions_1660 import live_outputs

if TYPE_CHECKING:
    from typing import Callable, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'unit-tests.yml'
#: The ``changes`` classifier, which ``Classify the diff`` runs (#1967).
CLASSIFIER = ROOT / 'util' / 'classify_changes.py'
#: ``Classify the diff``'s command, as the job's checkout root runs it.
CLASSIFY_RUN = '        run: python3 util/classify_changes.py\n'

#: The legs a docs-only pull request may skip.
LEGS = ('test', 'integration', 'engine-tests', 'pypcap-parity')
#: The legs a test-only pull request may skip (#2243); the others run ``latest`` alone.
TEST_ONLY_SKIPS = ('engine-tests', 'pypcap-parity')
#: The variable each leg's result reaches the gate's step in.
LEG_ENV = {'test': 'TEST', 'integration': 'INTEGRATION', 'engine-tests': 'ENGINE_TESTS',
           'pypcap-parity': 'PYPCAP_PARITY'}


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
             test_only: 'str' = 'false', **override: 'str') -> 'int':
        """The gate's exit status with every leg reporting ``legs`` unless overridden."""
        results = {'TEST': legs, 'INTEGRATION': legs, 'ENGINE_TESTS': legs, 'PYPCAP_PARITY': legs}
        results.update(override)
        env = dict(os.environ, CHANGES=changes, CODE=code, TEST_ONLY=test_only, PROJECT_TESTS=project,
                   **results)
        return subprocess.run(['bash', '-c', self.script], env=env, check=False,
                              capture_output=True, text=True).returncode

    def test_needs_every_leg_and_the_docs_only_helpers(self) -> None:
        """The gate reads every leg plus ``changes`` and ``project-tests``, the pins' one run (#1954)."""
        self.assertEqual(required_needs(), set(LEGS) | {'changes', 'project-tests'})

    def test_code_change_requires_every_leg_to_succeed(self) -> None:
        """On a code change nothing but ``success`` passes."""
        self.assertEqual(self.gate('true', 'success', 'success'), 0)
        for result in ('skipped', 'failure', 'cancelled'):
            with self.subTest(result=result):
                self.assertNotEqual(self.gate('true', result, 'success'), 0)

    def test_code_change_still_needs_project_tests(self) -> None:
        """#1954: ``project-tests`` is the one run of the project pins, so a code change needs it too."""
        for result in ('skipped', 'failure', 'cancelled'):
            with self.subTest(result=result):
                self.assertNotEqual(self.gate('true', 'success', result), 0)

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
                for code, legs, project, odd in (('true', 'success', 'success', 'failure'),
                                                 ('true', 'success', 'success', 'skipped'),
                                                 ('false', 'skipped', 'success', 'failure')):
                    self.assertNotEqual(self.gate(code, legs, project, **{env_name: odd}), 0)

    def test_an_unclassified_diff_skips_nothing(self) -> None:
        """A failed, skipped or garbled ``changes`` makes every skip a failure."""
        for changes, code, test_only in (('failure', '', ''), ('skipped', '', ''), ('success', '', ''),
                                         ('success', 'maybe', 'false'), ('failure', 'false', 'false'),
                                         ('failure', 'true', 'true'), ('success', 'true', ''),
                                         ('success', 'true', 'maybe'), ('success', 'false', ''),
                                         ('success', 'false', 'true')):
            with self.subTest(changes=changes, code=code, test_only=test_only):
                self.assertNotEqual(self.gate(code, 'skipped', 'success', changes, test_only), 0)
                skips = {LEG_ENV[name]: 'skipped' for name in TEST_ONLY_SKIPS}
                self.assertNotEqual(self.gate(code, 'success', 'success', changes, test_only, **skips), 0)

    def test_test_only_accepts_skipped_engine_and_parity_legs(self) -> None:
        """#2243: a test-only diff may skip ``engine-tests`` and ``pypcap-parity``, or pass them."""
        skips = {LEG_ENV[name]: 'skipped' for name in TEST_ONLY_SKIPS}
        self.assertEqual(self.gate('true', 'success', 'success', test_only='true', **skips), 0)
        self.assertEqual(self.gate('true', 'success', 'success', test_only='true'), 0)

    def test_test_only_still_needs_test_and_integration(self) -> None:
        """#2243: their ``latest`` legs are the test-only path's tests, so a skip there fails."""
        skips = {LEG_ENV[name]: 'skipped' for name in TEST_ONLY_SKIPS}
        for name in sorted(set(LEGS) - set(TEST_ONLY_SKIPS)):
            for result in ('skipped', 'failure', 'cancelled'):
                with self.subTest(leg=name, result=result):
                    self.assertNotEqual(self.gate('true', 'success', 'success', test_only='true',
                                                  **dict(skips, **{LEG_ENV[name]: result})), 0)

    def test_test_only_still_rejects_a_failed_or_cancelled_skippable_leg(self) -> None:
        """#2243: ``skipped`` is accepted on a test-only diff; ``failure`` and ``cancelled`` are not."""
        for name in TEST_ONLY_SKIPS:
            for result in ('failure', 'cancelled'):
                with self.subTest(leg=name, result=result):
                    self.assertNotEqual(self.gate('true', 'success', 'success', test_only='true',
                                                  **{LEG_ENV[name]: result}), 0)

    def test_test_only_still_needs_project_tests(self) -> None:
        """#2243: ``project-tests`` runs the pins on a test-only diff too."""
        skips = {LEG_ENV[name]: 'skipped' for name in TEST_ONLY_SKIPS}
        for result in ('skipped', 'failure', 'cancelled'):
            with self.subTest(result=result):
                self.assertNotEqual(self.gate('true', 'success', result, test_only='true', **skips), 0)

    def test_a_code_change_skips_nothing_the_test_only_path_may(self) -> None:
        """#2243: without ``test-only``, a skipped ``engine-tests`` or ``pypcap-parity`` fails."""
        for name in TEST_ONLY_SKIPS:
            with self.subTest(leg=name):
                self.assertNotEqual(self.gate('true', 'success', 'success', test_only='false',
                                              **{LEG_ENV[name]: 'skipped'}), 0)

    def test_the_gate_reads_test_only_from_changes(self) -> None:
        """#2243: ``TEST_ONLY`` is the ``changes`` job's output, set nowhere else."""
        self.assertEqual(job('required-checks').count('TEST_ONLY: '), 1)
        self.assertIn('          TEST_ONLY: ${{ needs.changes.outputs.test-only }}\n', job('required-checks'))
        self.assertIn('      test-only: ${{ steps.classify.outputs.test-only }}\n', job('changes'))


class TestChangesClassifier(unittest.TestCase):
    """``is_docs`` from the ``changes`` job's script, executed on sample paths."""

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location('classify_changes', CLASSIFIER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.is_docs = module.is_docs  # type: Callable[[str], bool]
        self.kind = module.kind  # type: Callable[[str], str]

    def test_docs_and_markdown_are_docs(self) -> None:
        """``docs/**`` and top-level Markdown are docs."""
        for path in ('docs/source/index.rst', 'docs/source/conf.py', 'README.md',
                     'CONTRIBUTING.md', 'CHANGELOG.md'):
            with self.subTest(path=path):
                self.assertTrue(self.is_docs(path))

    def test_everything_else_is_not_docs(self) -> None:
        """Anything else, and Markdown under a code directory, is not docs."""
        for path in ('pyproject.toml', 'setup.py', 'pcapkit/__init__.py', 'Makefile',
                     '.github/workflows/unit-tests.yml', '.github/PULL_REQUEST_TEMPLATE.md',
                     'tests/project/README.md', 'util/notes.md', 'examples/README.md',
                     'pcapkit/vendor/README.md'):
            with self.subTest(path=path):
                self.assertFalse(self.is_docs(path))

    def test_tests_and_their_support_files_are_tests(self) -> None:
        """#2243: everything under ``tests/``, the support files every test runs under included."""
        for path in ('tests/project/test_unit_tests_queue.py', 'tests/conftest.py', 'tests/_tiers.py',
                     'tests/__init__.py', 'tests/project/README.md', 'tests/project/ci_timing_fixtures/x.yml'):
            with self.subTest(path=path):
                self.assertEqual(self.kind(path), 'test')

    def test_workflows_util_and_examples_are_never_tests(self) -> None:
        """#2243: a workflow, a ``util/`` script or a capture fixture changes more than the tests."""
        for path in ('.github/workflows/unit-tests.yml', '.github/python-versions.toml', 'util/classify_changes.py',
                     'examples/captures/in.pcap', 'examples/generators/make_samples.py', 'pyproject.toml',
                     'pcapkit/__init__.py', 'conftest.py', 'test_x.py', 'testsuite/x.py'):
            with self.subTest(path=path):
                self.assertEqual(self.kind(path), 'code')

    def test_docs_stay_docs(self) -> None:
        """``kind`` agrees with ``is_docs``."""
        for path in ('docs/source/index.rst', 'README.md'):
            with self.subTest(path=path):
                self.assertEqual(self.kind(path), 'docs')

    def test_only_this_workflows_own_pull_request_is_classified(self) -> None:
        """Other events, and callers, always run everything."""
        section = job('changes')
        self.assertIn("OWN_PR: ${{ github.event_name == 'pull_request' && github.workflow == 'Unit Tests' }}",
                      section)
        self.assertIn("'--no-renames'", CLASSIFIER.read_text(encoding='utf-8'))

    def test_the_step_runs_the_script_in_a_checkout(self) -> None:
        """#1967: the script is in the tree, so every event checks out, with the merge's first parent."""
        section = job('changes')
        self.assertEqual(section.count(CLASSIFY_RUN), 1)
        checkout = section.split('      - uses: actions/checkout@', 1)[1].split('\n      - ', 1)[0]
        self.assertNotIn('if:', checkout)
        self.assertIn('fetch-depth: 2', checkout)


class TestJobGating(unittest.TestCase):
    """Which jobs run on which events, read off their job-level keys."""

    def test_each_leg_skips_only_on_a_docs_only_diff(self) -> None:
        """Each leg is gated on ``changes`` by a job-level ``if:``."""
        for name in LEGS:
            with self.subTest(job=name):
                head = header(job(name))
                self.assertIn("needs.changes.outputs.code != 'false'", head)
                self.assertRegex(head, r'(?m)^    needs: \[changes, python-versions\]$')

    def test_project_tests_runs_on_every_diff_and_never_duplicates_test(self) -> None:
        """#1954: ``project-tests`` runs on every diff, but not under ``gate-only``, whose ``gate``
        runs the pins in its full suite. Its pins step runs on a code change, and its steps that
        stand in for ``test`` only on a docs-only diff, where they take in the pins."""
        head = header(job('project-tests'))
        self.assertIn('if: ${{ inputs.gate-only != true }}', head)
        self.assertNotIn('needs.changes.outputs.code', head)
        for name, condition in (('Run the project pins', "needs.changes.outputs.code != 'false'"),
                                ('Run the first half of tests/project and the root-level modules under plain unittest',
                                 "needs.changes.outputs.code == 'false'"),
                                ('Run the second half of tests/project and the root-level modules under plain unittest',
                                 "needs.changes.outputs.code == 'false'"),
                                ('Run the other tests that read docs/ or Markdown',
                                 "needs.changes.outputs.code == 'false'")):
            with self.subTest(step=name):
                self.assertIn(f'if: ${{{{ {condition} }}}}', step(job('project-tests'), name))

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

    def test_engine_tests_is_one_job_per_engine_with_a_non_blocking_ktlo_step(self) -> None:
        """E: matrix on engine only; the KTLO cells block nothing, the supported ones do (#1633)."""
        section = job('engine-tests')
        head = header(section)
        self.assertNotIn('python-version:', head)  # no axis; `needs` names `python-versions`
        self.assertNotIn('continue-on-error', head)
        self.assertRegex(section, r'(?m)^        engine:$')
        ktlo = section.split('- name: Run the KTLO cells (non-blocking)', 1)[1]
        self.assertRegex(ktlo, r'(?m)^        continue-on-error: true$')
        gating = section.split('- name: Run the supported cells', 1)[1].split('      - name:', 1)[0]
        self.assertNotIn('continue-on-error', gating)
        self.assertIn('PYTHONS: ${{ needs.python-versions.outputs.engine-supported }}', gating)
        self.assertIn('for py in $PYTHONS;', gating)

    def test_unittest_ordering_queues_behind_test_and_survives_its_failure(self) -> None:
        """#1538 P4(a): queued after ``test``, and ``!cancelled()`` so a red ``test`` still runs it.

        Without the status function the implicit ``success()`` would skip every cell
        whenever ``test`` failed, and the push run would stop failing on ordering.

        """
        head = header(job('unittest-ordering'))
        self.assertRegex(head, r'(?m)^    needs: \[test\]$')
        self.assertIn("    if: ${{ !cancelled() && inputs.gate-only != true"
                      " && github.event_name != 'pull_request' }}\n", head)

    def test_the_ktlo_cell_runs_on_every_event(self) -> None:
        """#1633: the KTLO cell runs on every event."""
        ktlo = step(job('engine-tests'), 'Run the KTLO cells (non-blocking)')
        self.assertNotRegex(ktlo, r'(?m)^        if:')

    def test_engine_tests_has_no_dpkt_cell(self) -> None:
        """#1538 P8: its only path, test_dpkt_unit.py, already runs in ``test`` with DPKT."""
        section = job('engine-tests')
        engines = re.search(r'(?m)^        engine:\n((?:          - \w+\n)+)', section)
        self.assertIsNotNone(engines)
        declared = re.findall(r'- (\w+)', engines.group(1))  # type: ignore[union-attr]
        self.assertNotIn('DPKT', declared)
        self.assertNotRegex(section, r'(?m)^ +DPKT\)')


def step(section: 'str', name: 'str') -> 'str':
    """The text of the step called ``name`` in ``section``, up to the next step."""
    match = re.search(rf'(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)', section)
    if match is None:
        raise AssertionError(f'no step named {name!r}')
    return match.group(1)


#: The interpreter the steps run a ``util/`` script on, the image's (#1967).
IMAGE_PYTHON = '/usr/bin/python3'


def step_script(section: 'str', name: 'str') -> 'str':
    """The dedented script of step ``name``: its ``run: |`` block, or its one-line ``run:``."""
    text = step(section, name)
    line = re.search(r'(?m)^        run: (?!\|$)(.+)$', text)
    if line is not None:
        return line.group(1) + '\n'
    body = text.split('        run: |\n', 1)[1]
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


def checkout_script(script: 'str', mirrors: 'Optional[pathlib.Path]' = None) -> 'str':
    """``script`` runnable from the checkout here (#1967): this interpreter for the
    image's and, given ``mirrors``, that file for the runner's mirror list."""
    script = script.replace(IMAGE_PYTHON, shlex.quote(sys.executable))
    if mirrors is not None:
        script = script.replace('util/apt_packages.py install',
                                f'util/apt_packages.py install --mirrors {shlex.quote(str(mirrors))}')
    return script


class _Scratch(unittest.TestCase):
    """A temporary directory per test, and ``bash`` required."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is not available')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1052-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)


#: What the classifier writes for each kind of diff (#2243).
DOCS_ONLY = 'code=false\ntest-only=false'
TEST_ONLY = 'code=true\ntest-only=true'
CODE = 'code=true\ntest-only=false'


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
        self.assertIn(CLASSIFY_RUN, job('changes'))
        self.make_repo('repo')

    def make_repo(self, name: 'str') -> None:
        """A fresh scratch repository ``name``, on the PR branch, with main a code change ahead."""
        self.repo = self.tmp / name
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
        # #2243: no directory renames, or moving pcapkit/'s one file in the PR
        # would carry main's new pcapkit/y.py along, as a merge conflict.
        config = ('-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false',
                  '-c', 'merge.directoryRenames=false')
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
        """Run the classifier and return the lines it wrote to ``GITHUB_OUTPUT``."""
        output = self.tmp / f'output-{self.repo.name}'
        status = subprocess.run([sys.executable, str(CLASSIFIER)],
                                env=dict(os.environ, OWN_PR=own_pr, GITHUB_OUTPUT=str(output)),
                                cwd=str(cwd or self.repo), check=False, capture_output=True, text=True).returncode
        self.assertEqual(status, 0)
        return output.read_text(encoding='utf-8').strip()

    def test_a_docs_only_pull_request_is_not_code(self) -> None:
        """Only ``HEAD^1`` sees the PR's own diff; ``HEAD^2`` would see main's code."""
        self.pr('docs/source/index.rst', 'CONTRIBUTING.md')
        self.assertEqual(self.classify(), DOCS_ONLY)

    def test_a_code_file_makes_it_code(self) -> None:
        """One code file among docs is enough."""
        self.pr('docs/source/index.rst', 'pcapkit/x.py')
        self.assertEqual(self.classify(), CODE)

    def test_a_name_holding_whitespace_is_one_path(self) -> None:
        """``notes.md docs/y`` is a root file, not ``notes.md`` and ``docs/y``."""
        self.pr('docs/source/index.rst', 'notes.md docs/y')
        self.assertEqual(self.classify(), CODE)

    def test_another_event_always_runs_everything(self) -> None:
        """``OWN_PR`` false (a push, or a caller's pull request) is code."""
        self.pr('docs/source/index.rst')
        self.assertEqual(self.classify(own_pr='false'), CODE)

    def test_a_push_of_tests_alone_is_code(self) -> None:
        """#2243: a push to ``main`` never takes the test-only path, however little it changed."""
        self.pr('tests/test_x.py')
        self.assertEqual(self.classify(own_pr='false'), CODE)

    def test_an_empty_diff_is_code(self) -> None:
        """Nothing to classify is not evidence of a docs-only change."""
        self.pr()
        self.assertEqual(self.classify(), CODE)

    def test_a_failed_diff_is_code(self) -> None:
        """Outside a repository ``git diff`` fails, and that must not skip anything."""
        elsewhere = self.tmp / 'not-a-repo'
        elsewhere.mkdir()
        self.assertEqual(self.classify(cwd=elsewhere), CODE)

    def test_tests_alone_are_test_only(self) -> None:
        """#2243: a diff under ``tests/`` alone, its support files included, is test-only."""
        self.pr('tests/test_x.py', 'tests/conftest.py', 'tests/_tiers.py')
        self.assertEqual(self.classify(), TEST_ONLY)

    def test_tests_and_docs_are_test_only(self) -> None:
        """#2243: docs alongside tests do not make it code."""
        self.pr('tests/test_x.py', 'docs/source/index.rst', 'README.md')
        self.assertEqual(self.classify(), TEST_ONLY)

    def test_tests_and_anything_else_are_code(self) -> None:
        """#2243: one file outside ``tests/`` and the docs makes it code."""
        for index, other in enumerate(('pcapkit/x.py', 'util/classify_changes.py', '.github/workflows/unit-tests.yml',
                                       'examples/captures/in.pcap', 'pyproject.toml')):
            with self.subTest(other=other):
                self.make_repo(f'repo-{index}')
                self.pr('tests/test_x.py', other)
                self.assertEqual(self.classify(), CODE)

    def test_moving_code_under_tests_is_code(self) -> None:
        """#2243: ``--no-renames`` lists the old path too, so a move out of ``pcapkit/`` is code."""
        (self.repo / 'tests').mkdir()
        self.git('mv', 'pcapkit/x.py', 'tests/x.py')
        self.pr()
        self.assertEqual(self.classify(), CODE)


class TestEngineCellLoops(_Scratch):
    """The two cell-loop steps of ``engine-tests``, with the cell script stubbed."""

    #: Each loop step, and the output of .github/python-versions.toml it loops over (#1660).
    LOOPS = {'Run the supported cells': 'engine-supported', 'Run the KTLO cells (non-blocking)': 'engine-ktlo'}

    def run_loop(self, name: 'str', fail: 'str') -> 'tuple[int, list[str]]':
        """Run loop step ``name`` with the cell for ``fail`` failing; status and cells run."""
        (self.tmp / 'engine-cell.sh').write_text(
            'echo "$1" >> "$RUNNER_TEMP/calls"\n[ "$1" != "$FAIL_PY" ]\n', encoding='utf-8')
        status = bash(step_script(job('engine-tests'), name),
                      {'RUNNER_TEMP': str(self.tmp), 'ENGINE': 'Scapy', 'FAIL_PY': fail,
                       'GITHUB_STEP_SUMMARY': str(self.tmp / 'summary'), 'PYTHONS': self.versions(name)})
        calls = self.tmp / 'calls'
        return status, calls.read_text(encoding='utf-8').split() if calls.exists() else []

    def versions(self, name: 'str') -> 'str':
        """What step ``name``'s ``PYTHONS`` holds: one version per line, as the job output does."""
        expression = f'PYTHONS: ${{{{ needs.python-versions.outputs.{self.LOOPS[name]} }}}}'
        self.assertIn(expression, step(job('engine-tests'), name))
        return live_outputs()[self.LOOPS[name]]

    def test_every_gating_cell_runs_and_passing_passes(self) -> None:
        """Every supported interpreter runs; none failing exits 0."""
        status, calls = self.run_loop('Run the supported cells', fail='none')
        self.assertEqual(status, 0)
        self.assertEqual(calls, self.versions('Run the supported cells').split())
        self.assertGreater(len(calls), 1)

    def test_one_failing_cell_fails_the_step_after_the_rest_ran(self) -> None:
        """A failure is not swallowed, and does not stop the later cells."""
        expected = self.versions('Run the supported cells').split()
        status, calls = self.run_loop('Run the supported cells', fail=expected[1])
        self.assertNotEqual(status, 0)
        self.assertEqual(calls, expected)
        self.assertIn(f'| {expected[1]} | Scapy | | FAILED |', (self.tmp / 'summary').read_text(encoding='utf-8'))

    def test_a_failing_ktlo_cell_fails_its_own_step(self) -> None:
        """The step fails; its ``continue-on-error`` keeps the job green, its annotation is a warning (#1672)."""
        expected = self.versions('Run the KTLO cells (non-blocking)').split()
        status, calls = self.run_loop('Run the KTLO cells (non-blocking)', fail=expected[0])
        self.assertNotEqual(status, 0)
        self.assertEqual(calls, expected)

    def test_no_ktlo_cell_is_a_passing_no_op(self) -> None:
        """A KTLO tier with no cell on ``ubuntu-latest`` loops over nothing, rather than failing."""
        (self.tmp / 'engine-cell.sh').write_text('exit 1\n', encoding='utf-8')
        status = bash(step_script(job('engine-tests'), 'Run the KTLO cells (non-blocking)'),
                      {'RUNNER_TEMP': str(self.tmp), 'ENGINE': 'Scapy', 'PYTHONS': '',
                       'GITHUB_STEP_SUMMARY': str(self.tmp / 'summary')})
        self.assertEqual(status, 0)


#: The apt steps, as (job, step name, extra env), each with its job's ``APT_PACKAGES``.
APT_STEPS: 'tuple[tuple[str, str, dict[str, str]], ...]' = (
    ('engine-tests', "Install this engine's system packages", {'ENGINE': 'PyShark', 'APT_PACKAGES': 'tshark'}),
    ('pypcap-parity', 'Install libpcap headers, a C toolchain, and tshark',
     {'APT_PACKAGES': 'build-essential libpcap-dev tshark'}),
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
    """Both apt install steps, :file:`util/apt_packages.py` (#1967), with ``sudo``/``timeout``/``apt-get`` stubbed."""

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
        status = bash(checkout_script(step_script(job(job_name), name), self.tmp / 'no-mirror-list'),
                      dict(extra, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}',
                           STUB_LOG=str(log), FAIL_UPDATES=str(fail_updates)), str(ROOT))
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

    def test_both_attempts_fit_inside_a_ten_minute_step_cap(self) -> None:
        """Every apt call is bounded, and two full attempts fit the 10-minute cap (#1306)."""
        for job_name, name, extra in APT_STEPS:
            with self.subTest(job=job_name):
                status, apt, bounds = self.run_apt(name, job_name, extra, fail_updates=0)
                self.assertEqual(status, 0)
                self.assertEqual(len(bounds), len(apt), 'an apt-get call runs without timeout')
                self.assertEqual(bounds, [60, 180])
                self.assertEqual(step_cap(job(job_name), name), 10)
                self.assertLessEqual(2 * sum(bounds), 10 * 60)


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
        """The modules project-tests' ``Run the other tests that read docs/ or Markdown`` step names."""
        script = step(job('project-tests'), 'Run the other tests that read docs/ or Markdown')
        command = re.search(r'(?m)^        run: python util/cap_file_size.py python -m unittest -v (.+)$', script)
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
        """A known reader is found, so a passing run is not vacuous."""
        self.assertIn('tests.corekit.test_sentinel_exports_unit', docs_readers())


#: The workflows the prose cites by job and step name, never by line number:
#: trimming a comment in one moves every line below it (#1967).
BY_NAME = ('unit-tests.yml', 'create-release.yml', 'python-compatibility.yml',
           'coverage-comment.yml')

#: A document that names one of :data:`BY_NAME` may still cite another file bare,
#: as ``:N``; each such citation is listed here with the file it does cite, and
#: any other bare citation there reads as a line of the named workflow.
BARE_ELSEWHERE: 'dict[str, dict[str, str]]' = {}

#: A line-number citation: ``N``, ``N-M``, or several joined by commas.
SPANS = r'(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)'


def documents() -> 'list[str]':
    """Every page under ``docs/`` and every top-level Markdown file."""
    return sorted({str(p.relative_to(ROOT)) for p in (ROOT / 'docs').rglob('*.rst')}
                  | {str(p.relative_to(ROOT)) for p in ROOT.glob('*.md')})


class TestWorkflowsCitedByName(unittest.TestCase):
    """The prose cites :data:`BY_NAME`'s workflows by job and step, not by line."""

    def test_no_document_cites_them_by_line_number(self) -> None:
        """Neither ``<file>.yml:N`` nor, beside one's name, a bare ``:N`` of it.

        The owner's decision A on #1967: cite steps by job and step name, not
        ``file.yml:N``. A bare citation of another file goes in
        :data:`BARE_ELSEWHERE`, and an entry no bare citation matches fails too.
        """
        for document in documents():
            text = (ROOT / document).read_text(encoding='utf-8')
            for name in BY_NAME:
                with self.subTest(document=document, workflow=name):
                    self.assertEqual(re.findall(rf'{re.escape(name)}:{SPANS}', text), [],
                                     f'{document} cites {name} by line; name the job and step')
            if not any(name in text for name in BY_NAME):
                continue
            bare = set(re.findall(rf'``:{SPANS}``', text))
            elsewhere = set(BARE_ELSEWHERE.get(document, {}))
            with self.subTest(document=document, table='BARE_ELSEWHERE'):
                self.assertEqual(bare - elsewhere, set(),
                                 f'{document} cites these bare; name the job and step, or list '
                                 f'the file they cite in BARE_ELSEWHERE')
                self.assertEqual(elsewhere - bare, set(), f'{document} no longer cites these bare')


if __name__ == '__main__':
    unittest.main()
