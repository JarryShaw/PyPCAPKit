# -*- coding: utf-8 -*-
"""#1853: Vendor Update tests the regenerated tree before it commits.

:file:`.github/workflows/cron-vendor.yml` committed whatever ``pcapkit-vendor``
regenerated with no test step in between, and 1.5.0b13 turned ``main`` red. The
owner chose to test the regenerated tree in the job itself, under #872's rule: a
failed sub-vendor's changes are discarded, the rest are kept, and the job as a
whole does not fail.

* :class:`TestTheWorkflowTestsBeforeItCommits` reads ``vendor-update`` with
  PyYAML: a step between Update Vendor and the commits runs the const and vendor
  tests, installs the test extra, cannot fail the job, and is bounded in time.
* :class:`TestTheDiscardStep` runs the step that discards every regenerated
  module when the test step did not finish.
* :class:`TestTheGate` runs :file:`util/vendor_test_gate.py` in throwaway
  repositories, with a stand-in test command that fails on a marker, so which
  modules it keeps is checked against which ones carry the marker.
* :class:`TestTheMemorySampler` checks how the script sums a process group's
  memory through psutil (#1894), against a stand-in for psutil listing real
  process ids, and that it falls back to ``ps`` where psutil is not installed.

"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess  # nosec B404
import sys
import tempfile
import time
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows
from tests._support import scale_timeout

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'vendor_test_gate.py'
WORKFLOW = ROOT / '.github' / 'workflows' / 'cron-vendor.yml'
BASH = shutil.which('bash')

#: The stand-in for pytest: it records what each run saw, then fails when a
#: module under ``pcapkit/const`` holds ``BROKEN``, when modules hold both halves
#: of the ``TOGETHER`` pair, or when ``$REQUIRE`` names a module that is gone.
#: ``$SLEEP``, ``$ALLOCATE``, ``$WRITE`` and ``$STRAY`` make it hang, hold
#: memory, write a large file, or leave a module behind.
FAKE_TESTS = r'''
import json, os, pathlib, sys, time

texts = {str(path): path.read_text() for path in sorted(pathlib.Path('pcapkit/const').rglob('*.py'))}
with open(os.environ['GATE_LOG'], 'a') as log:
    log.write(json.dumps({'argv': sys.argv[1:], 'addopts': os.environ.get('PYTEST_ADDOPTS', ''),
                          'prefix': os.environ.get('PYTHONPYCACHEPREFIX'), 'pid': os.getpid(),
                          'files': texts}) + '\n')
if os.environ.get('STRAY'):
    pathlib.Path(os.environ['STRAY']).write_text('# left behind\n')
if os.environ.get('ALLOCATE'):
    held = b'\x01' * int(os.environ['ALLOCATE'])
    time.sleep(30)
if os.environ.get('WRITE'):
    with open(os.environ['WRITE'], 'wb') as file:
        file.write(b'\x01' * (4 << 20))
if os.environ.get('SLEEP'):
    time.sleep(float(os.environ['SLEEP']))
broken = any('BROKEN' in text for text in texts.values())
together = all(any(mark in text for text in texts.values()) for mark in ('TOGETHER-A', 'TOGETHER-B'))
missing = bool(os.environ.get('REQUIRE')) and os.environ['REQUIRE'] not in texts
sys.exit(1 if broken or together or missing else 0)
'''


def module(name: 'str', marker: 'str' = '') -> 'str':
    """A generated module's text, carrying ``marker`` when given."""
    return f'# -*- coding: utf-8 -*-\n"""{name}"""\n\nVALUE = {name!r}  # {marker}\n'


def vendor_update() -> 'dict[str, Any]':
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest('PyYAML, from the test extra, is not installed')
    return _workflows.job(WORKFLOW, 'vendor-update')


def load_gate() -> 'types.ModuleType':
    """:file:`util/vendor_test_gate.py`, which is a script and not a package."""
    spec = importlib.util.spec_from_file_location('vendor_test_gate_1853', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestTheWorkflowTestsBeforeItCommits(unittest.TestCase):
    """The step the ruling on #1853 asks for, as ``vendor-update`` declares it."""

    steps = []  # type: list[dict[str, Any]]
    names = []  # type: list[Optional[str]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.steps = vendor_update()['steps']
        cls.names = [step.get('name') for step in cls.steps]

    def index(self, name: 'str') -> 'int':
        if name not in self.names:
            self.fail(f'`vendor-update` has no step {name!r}')
        return self.names.index(name)

    def gate(self) -> 'tuple[int, dict[str, Any]]':
        """The step that runs the tests on the regenerated tree, and its index."""
        found = [(index, step) for index, step in enumerate(self.steps)
                 if 'util/vendor_test_gate.py' in str(step.get('run', ''))]
        self.assertEqual(len(found), 1, 'expected one step of `vendor-update` to run util/vendor_test_gate.py')
        return found[0]

    def test_a_test_step_runs_between_the_crawl_and_the_commit(self) -> None:
        """After the crawl and its isort, before anything decides what changed."""
        index, step = self.gate()
        self.assertLess(self.index('Update Vendor'), index)
        for later in ('Verify Changed files', 'Bump Version', 'Commit changes',
                      'Commit documentation changes', 'Push changes'):
            with self.subTest(step=later):
                self.assertLess(index, self.index(later))
        self.assertNotIn('if', step, 'the tests run whenever the crawl did')

    def test_it_runs_the_const_and_vendor_tests(self) -> None:
        _, step = self.gate()
        command = str(step['run']).replace('\\\n', ' ').split(' -- ', 1)
        self.assertEqual(len(command), 2, 'the test command follows `--`')
        words = command[1].split()
        self.assertEqual(words[:3], ['python', '-m', 'pytest'])
        self.assertIn('tests/const', words)
        self.assertIn('tests/vendor', words)
        self.assertTrue(SCRIPT.exists(), f'{SCRIPT.relative_to(ROOT)} does not exist')

    def test_it_installs_the_test_dependencies(self) -> None:
        """The job's own install is ``.[all,vendor]``, which carries no pytest."""
        _, step = self.gate()
        installs = re.findall(r"pip install -e '\.\[([^]]*)\]'", str(step['run']))
        self.assertEqual(len(installs), 1, step['run'])
        self.assertIn('test', [extra.strip() for extra in installs[0].split(',')])
        run = str(step['run'])
        self.assertLess(run.index('pip install'), run.index('util/vendor_test_gate.py'))

    def test_it_cannot_fail_the_job(self) -> None:
        """#872: a failing test discards modules, never the job."""
        index, step = self.gate()
        self.assertIs(step.get('continue-on-error'), True)
        self.assertIn('id', step)

        # A step that did not finish may leave modules no run passed with, so
        # the next one puts HEAD's tree back before anything is committed.
        discard = self.steps[index + 1]
        self.assertEqual(discard.get('if'), f"steps.{step['id']}.outcome != 'success'")
        run = str(discard.get('run', ''))
        self.assertIn('git checkout HEAD -- pcapkit/const', run)
        self.assertIn('git clean -fdq -- pcapkit/const', run)
        self.assertIn('::warning ', run)
        self.assertLess(index + 1, self.index('Verify Changed files'))

    def test_it_has_a_timeout_above_its_budget(self) -> None:
        """The script's budget ends the runs first; ``timeout-minutes`` is the backstop."""
        _, step = self.gate()
        timeout = step.get('timeout-minutes')
        self.assertIsInstance(timeout, int)
        budget = re.search(r'--budget-minutes (\d+)', str(step['run']))
        self.assertIsNotNone(budget, step['run'])
        assert budget is not None
        self.assertLess(int(budget.group(1)), timeout)
        for option in ('--max-memory-mib', '--max-file-size-mib'):
            with self.subTest(option=option):
                self.assertRegex(str(step['run']), rf'{option} \d+')


class ScratchRepository(unittest.TestCase):
    """A throwaway repository whose ``HEAD`` holds a few generated modules."""

    MODULES = ('pcapkit/const/a.py', 'pcapkit/const/b.py', 'pcapkit/const/reg/c.py',
               'pcapkit/const/reg/d.py')

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.repo = self.root / 'repo'

        # As in test_vendor_comment_only_no_bump_1674.py: none of the caller's
        # git configuration, and no automatic maintenance to outlive the test.
        home = self.root / 'home'
        home.mkdir()
        (home / '.gitconfig').write_text(
            '[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n'
            '[maintenance]\n\tauto = false\n\tautoDetach = false\n'
            '[gc]\n\tauto = 0\n\tautoDetach = false\n'
            '[user]\n\tname = Test\n\temail = test@example.com\n', encoding='utf-8')
        self.env = {
            'PATH': os.environ.get('PATH', ''),
            'HOME': str(home),
            'XDG_CONFIG_HOME': str(home / '.config'),
            'GIT_CONFIG_NOSYSTEM': '1',
            'LC_ALL': 'C',
        }
        self.git('init', '-q', str(self.repo), cwd=self.root)
        for path in self.MODULES:
            self.write(path, module(path))
        self.write('pcapkit/const/README.txt', 'Generated by pcapkit-vendor.\n')
        self.write('.gitignore', '__pycache__/\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'the generated tree')

        self.log = self.root / 'gate.log'
        self.output = self.root / 'output'
        self.summary = self.root / 'summary.md'
        self.fake = self.root / 'fake_tests.py'
        self.fake.write_text(FAKE_TESTS, encoding='utf-8')

    def git(self, *args: 'str', cwd: 'Optional[pathlib.Path]' = None) -> 'str':
        result = subprocess.run(['git', *args], cwd=cwd or self.repo, env=self.env,
                                capture_output=True, text=True, check=False,
                                timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, f'git {" ".join(args)}: {result.stderr}')
        return result.stdout

    def write(self, path: 'str', text: 'str') -> None:
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding='utf-8')

    def read(self, path: 'str') -> 'Optional[str]':
        file = self.repo / path
        return file.read_text(encoding='utf-8') if file.exists() else None

    def changed(self) -> 'list[str]':
        """``git status --porcelain`` under ``pcapkit/const``, one entry per line."""
        return self.git('status', '--porcelain', '--untracked-files=all', '--', 'pcapkit/const').splitlines()


class TestTheDiscardStep(ScratchRepository):
    """``Discard untested const changes``' script, run as the runner runs it."""

    @unittest.skipIf(not BASH, 'needs bash on PATH')
    def test_it_puts_back_every_module_and_warns(self) -> None:
        steps = [step for step in vendor_update()['steps'] if step.get('name') == 'Discard untested const changes']
        self.assertEqual(len(steps), 1, 'expected one `Discard untested const changes` step')
        script = self.root / 'step.sh'
        script.write_text(steps[0]['run'], encoding='utf-8')

        self.write('pcapkit/const/a.py', module('a', 'BROKEN'))
        self.write('pcapkit/const/new/e.py', module('e'))
        (self.repo / 'pcapkit/const/reg/c.py').unlink()
        self.assertEqual(len(self.changed()), 3, self.changed())

        # `bash -e {0}`, as for a `run:` with no `shell:`.
        result = subprocess.run(['bash', '-e', str(script)], cwd=self.repo,
                                env=dict(self.env, GITHUB_STEP_SUMMARY=str(self.summary)),
                                capture_output=True, text=True, check=False, timeout=scale_timeout(60))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.changed(), [])
        self.assertIn('::warning title=Vendor test gate did not finish::', result.stdout)
        self.assertIn('Vendor test gate did not finish', self.summary.read_text(encoding='utf-8'))


class TestTheGate(ScratchRepository):
    """:file:`util/vendor_test_gate.py`, run on a regenerated tree."""

    def run_gate(self, *, budget: 'float' = 5, memory: 'float' = 4096, file_size: 'float' = 2048,
                 **env: 'str') -> 'subprocess.CompletedProcess[str]':
        self.assertTrue(SCRIPT.exists(), f'{SCRIPT.relative_to(ROOT)} does not exist')
        environment = dict(self.env, GATE_LOG=str(self.log), GITHUB_OUTPUT=str(self.output),
                           GITHUB_STEP_SUMMARY=str(self.summary), **env)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '--budget-minutes', str(budget), '--max-memory-mib', str(memory),
             '--max-file-size-mib', str(file_size), '--', sys.executable, str(self.fake), '-q'],
            cwd=self.repo, env=environment, capture_output=True, text=True, check=False,
            timeout=scale_timeout(120))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def runs(self) -> 'list[dict[str, Any]]':
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()]

    def verdict(self) -> 'Optional[str]':
        written = re.findall(r'^verdict=(.*)$', self.output.read_text(encoding='utf-8'), re.M) \
            if self.output.exists() else []
        self.assertLessEqual(len(written), 1, written)
        return written[0] if written else None

    def test_nothing_changed_runs_nothing(self) -> None:
        """A change outside the ``.py`` modules is not this script's either."""
        self.write('pcapkit/const/README.txt', 'Generated weekly.\n')
        self.run_gate()
        self.assertEqual(self.verdict(), 'unchanged')
        self.assertEqual(self.runs(), [])
        self.assertEqual(self.read('pcapkit/const/README.txt'), 'Generated weekly.\n')

    def test_a_regeneration_that_passes_is_kept_whole(self) -> None:
        self.write('pcapkit/const/a.py', module('a', 'new member'))
        self.write('pcapkit/const/new/e.py', module('e'))
        result = self.run_gate()
        self.assertEqual(self.verdict(), 'passed')
        runs = self.runs()
        self.assertEqual(len(runs), 1)
        # The first run lists every failure, so it is not -x, and its arguments are passed as given.
        self.assertEqual(runs[0]['addopts'], '')
        self.assertEqual(runs[0]['argv'], ['-q'])
        self.assertEqual(self.read('pcapkit/const/a.py'), module('a', 'new member'))
        self.assertEqual(self.read('pcapkit/const/new/e.py'), module('e'))
        self.assertNotIn('::warning', result.stdout)
        self.assertIn('the regeneration passed', self.summary.read_text(encoding='utf-8'))

    def test_only_the_module_the_tests_fail_with_is_discarded(self) -> None:
        """#872's rule, for a sub-vendor whose output fails the tests."""
        for path in self.MODULES:
            self.write(path, module(path, 'BROKEN' if path == 'pcapkit/const/b.py' else 'regenerated'))
        result = self.run_gate()
        self.assertEqual(self.verdict(), 'partial')
        self.assertEqual(self.read('pcapkit/const/b.py'), module('pcapkit/const/b.py'))
        for path in set(self.MODULES) - {'pcapkit/const/b.py'}:
            with self.subTest(path=path):
                self.assertEqual(self.read(path), module(path, 'regenerated'))
        self.assertIn('::warning title=Vendor test gate discarded a module::pcapkit/const/b.py', result.stdout)
        self.assertEqual(result.stdout.count('::warning'), 1, result.stdout)

        runs = self.runs()
        # The whole regeneration, HEAD's tree, the halves, and the kept modules together.
        self.assertEqual([sorted(path for path, text in run['files'].items() if 'regenerated' in text
                                 or 'BROKEN' in text) for run in runs],
                         [sorted(self.MODULES), [], ['pcapkit/const/a.py', 'pcapkit/const/b.py'],
                          ['pcapkit/const/a.py'], ['pcapkit/const/b.py'],
                          ['pcapkit/const/reg/c.py', 'pcapkit/const/reg/d.py'],
                          ['pcapkit/const/a.py', 'pcapkit/const/reg/c.py', 'pcapkit/const/reg/d.py']])
        self.assertEqual([run['addopts'] for run in runs], [''] + ['-x'] * (len(runs) - 1))
        prefixes = [run['prefix'] for run in runs]
        self.assertEqual(len(set(prefixes)), len(prefixes), 'each run gets a cache prefix of its own')
        for prefix in prefixes:
            self.assertFalse(pathlib.Path(prefix).exists(), prefix)

        summary = self.summary.read_text(encoding='utf-8')
        self.assertIn('| `pcapkit/const/b.py` | no |', summary)
        self.assertIn('| `pcapkit/const/a.py` | yes |', summary)

    def test_a_new_module_the_tests_fail_with_is_removed(self) -> None:
        self.write('pcapkit/const/a.py', module('a', 'regenerated'))
        self.write('pcapkit/const/new/e.py', module('e', 'BROKEN'))
        self.run_gate()
        self.assertEqual(self.verdict(), 'partial')
        self.assertIsNone(self.read('pcapkit/const/new/e.py'))
        self.assertEqual(self.read('pcapkit/const/a.py'), module('a', 'regenerated'))

    def test_a_deleted_module_the_tests_need_is_put_back(self) -> None:
        (self.repo / 'pcapkit/const/reg/c.py').unlink()
        self.run_gate(REQUIRE='pcapkit/const/reg/c.py')
        self.assertEqual(self.verdict(), 'discarded')
        self.assertEqual(self.read('pcapkit/const/reg/c.py'), module('pcapkit/const/reg/c.py'))
        self.assertEqual(self.changed(), [])

    def test_a_failure_on_heads_own_tree_discards_everything(self) -> None:
        """The tests cannot tell good modules from bad ones then."""
        self.write('pcapkit/const/a.py', module('a', 'BROKEN'))
        self.git('commit', '-qam', 'a broken HEAD')
        self.write('pcapkit/const/b.py', module('b', 'regenerated'))
        result = self.run_gate()
        self.assertEqual(self.verdict(), 'discarded')
        self.assertEqual(self.changed(), [])
        self.assertEqual(len(self.runs()), 2)
        self.assertIn("HEAD's own tree", result.stdout)
        self.assertIn('::warning title=Vendor test gate discarded every regenerated module::', result.stdout)

    def test_modules_that_fail_together_are_all_discarded(self) -> None:
        """Each passes on its own, the kept set does not: nothing untested is left."""
        self.write('pcapkit/const/a.py', module('a', 'TOGETHER-A'))
        self.write('pcapkit/const/b.py', module('b', 'BROKEN'))
        self.write('pcapkit/const/reg/c.py', module('c', 'TOGETHER-B'))
        result = self.run_gate()
        self.assertEqual(self.verdict(), 'discarded')
        self.assertEqual(self.changed(), [])
        self.assertIn('fail together', result.stdout)

    def test_a_run_over_the_budget_discards_everything(self) -> None:
        self.write('pcapkit/const/a.py', module('a', 'regenerated'))
        start = time.monotonic()
        result = self.run_gate(budget=0.05, SLEEP='60')
        self.assertLess(time.monotonic() - start, 40, 'the run was not stopped at the budget')
        self.assertEqual(self.verdict(), 'discarded')
        self.assertEqual(self.changed(), [])
        self.assertIn('budget ran out', result.stdout)

    def test_a_run_over_the_memory_cap_fails(self) -> None:
        """Sampled by psutil where this interpreter has it, and by ``ps`` where not (#1894)."""
        self.write('pcapkit/const/a.py', module('a', 'regenerated'))
        if load_gate().group_rss(os.getpgrp()) is None:  # pragma: no cover
            self.skipTest('neither psutil nor ps can read memory here, so it cannot be sampled')
        start = time.monotonic()
        result = self.run_gate(memory=32, ALLOCATE=str(256 << 20))
        self.assertLess(time.monotonic() - start, 40, 'the run was not stopped at the cap')
        self.assertEqual(self.verdict(), 'discarded')
        self.assertEqual(self.changed(), [])
        self.assertRegex(result.stdout, r'killed: \d+ MiB resident, over the 32 MiB cap')

    def test_a_run_cannot_write_past_the_file_size_cap(self) -> None:
        self.write('pcapkit/const/a.py', module('a', 'regenerated'))
        large = self.root / 'large.bin'
        self.run_gate(file_size=1, WRITE=str(large))
        self.assertEqual(self.verdict(), 'discarded')
        self.assertLessEqual(large.stat().st_size, 1 << 20)

    def test_a_module_the_tests_leave_behind_is_removed(self) -> None:
        self.write('pcapkit/const/a.py', module('a', 'regenerated'))
        result = self.run_gate(STRAY='pcapkit/const/stray.py')
        self.assertEqual(self.verdict(), 'passed')
        self.assertIsNone(self.read('pcapkit/const/stray.py'))
        self.assertEqual(self.changed(), [' M pcapkit/const/a.py'])
        self.assertIn('::warning title=Vendor test gate restored a module::pcapkit/const/stray.py', result.stdout)

    def test_a_stopped_gate_puts_head_back_and_kills_its_run(self) -> None:
        """``SIGTERM`` mid-run: no module is left that no run passed with, nor the run itself."""
        self.assertTrue(SCRIPT.exists(), f'{SCRIPT.relative_to(ROOT)} does not exist')
        self.write('pcapkit/const/a.py', module('a', 'regenerated'))
        gate = subprocess.Popen(
            [sys.executable, str(SCRIPT), '--budget-minutes', '5', '--max-memory-mib', '4096',
             '--max-file-size-mib', '2048', '--', sys.executable, str(self.fake)],
            cwd=self.repo, env=dict(self.env, GATE_LOG=str(self.log), SLEEP='120'),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + scale_timeout(60)
            while not self.runs() and time.monotonic() < deadline:
                time.sleep(0.1)
            runs = self.runs()
            self.assertEqual(len(runs), 1, 'the test command never started')
            gate.send_signal(signal.SIGTERM)
            self.assertNotEqual(gate.wait(timeout=scale_timeout(60)), 0)
        finally:
            if gate.poll() is None:  # pragma: no cover
                gate.kill()
                gate.wait()
        self.assertEqual(self.changed(), [])
        with self.assertRaises(ProcessLookupError):
            os.kill(runs[0]['pid'], 0)


class _NoSuchProcess(Exception):
    """Stands in for ``psutil.NoSuchProcess``."""


class _AccessDenied(Exception):
    """Stands in for ``psutil.AccessDenied``."""


class _Process:
    """A process as ``psutil.process_iter`` yields it: a real id, and a resident size or an error."""

    def __init__(self, pid: 'int', rss: 'int' = 0, error: 'Optional[Exception]' = None) -> None:
        self.pid, self.rss, self.error = pid, rss, error

    def memory_info(self) -> 'types.SimpleNamespace':
        if self.error is not None:
            raise self.error
        return types.SimpleNamespace(rss=self.rss)


class TestTheMemorySampler(unittest.TestCase):
    """``group_rss`` sums a process group through psutil, or ``ps`` without it (#1894).

    psutil reads no process group, so the script asks :func:`os.getpgid` of each
    process it lists. The stand-in lists real processes -- this one, in its own
    group, and a child in a session of its own -- so that question gets real
    answers, and only the sizes are made up.

    """

    def setUp(self) -> None:
        self.gate = load_gate()
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                 start_new_session=True)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.other = child.pid
        self.assertNotEqual(os.getpgid(self.other), os.getpgrp())
        # A process id no process holds: one that has been reaped.
        gone = subprocess.Popen([sys.executable, '-c', ''])
        gone.wait()
        self.gone = gone.pid

    def psutil(self, *processes: '_Process', listing: 'Optional[Exception]' = None) -> 'types.SimpleNamespace':
        def process_iter() -> 'list[_Process]':
            if listing is not None:
                raise listing
            return list(processes)

        return types.SimpleNamespace(process_iter=process_iter, Error=Exception,
                                     NoSuchProcess=_NoSuchProcess, AccessDenied=_AccessDenied)

    def rss(self, psutil: 'Any') -> 'Optional[int]':
        # ``create``: before #1894 the script had no ``psutil`` to bind over, and
        # this should fail there on what it returns.
        with mock.patch.object(self.gate, 'psutil', psutil, create=True):
            return self.gate.group_rss(os.getpgrp())

    def test_the_group_is_summed_and_nothing_else(self) -> None:
        listed = self.psutil(_Process(os.getpid(), rss=3 << 20), _Process(self.other, rss=1 << 30),
                             _Process(self.gone, rss=1 << 30))
        self.assertEqual(self.rss(listed), 3 << 20)

    def test_a_process_that_exits_while_it_is_read_is_left_out(self) -> None:
        listed = self.psutil(_Process(os.getpid(), rss=3 << 20), _Process(os.getpid(), error=_NoSuchProcess()))
        self.assertEqual(self.rss(listed), 3 << 20)

    def test_a_member_it_may_not_read_leaves_the_sample_unknown(self) -> None:
        """Rather than short: an undercount would let a run past the cap."""
        listed = self.psutil(_Process(os.getpid(), rss=3 << 20), _Process(os.getpid(), error=_AccessDenied()))
        self.assertIsNone(self.rss(listed))

    def test_a_listing_that_fails_leaves_the_sample_unknown(self) -> None:
        self.assertIsNone(self.rss(self.psutil(listing=OSError('no /proc'))))

    def test_without_psutil_ps_samples_the_group(self) -> None:
        if subprocess.run(['ps', '-A', '-o', 'pgid=', '-o', 'rss='], capture_output=True,
                          check=False).returncode != 0:  # pragma: no cover
            self.skipTest('ps cannot list processes here')
        rss = self.rss(None)
        self.assertIsInstance(rss, int)
        # This process alone holds more than a MiB resident.
        self.assertGreater(rss, 1 << 20)

    def test_the_warning_names_the_sampler_in_use(self) -> None:
        """What ``report`` says when a sample came back unknown."""
        self.assertEqual(self.gate.SAMPLER, 'ps' if self.gate.psutil is None else 'psutil')
        gate = self.gate.Gate([], ['true'], 60, 1 << 30, 1 << 30)
        gate.unsampled = True
        with mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            self.gate.report([], frozenset(), '', gate, 'true')
        self.assertIn(f'could not sample memory::{self.gate.SAMPLER} could not read', stdout.getvalue())


if __name__ == '__main__':
    unittest.main()
