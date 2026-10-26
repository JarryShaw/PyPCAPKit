# -*- coding: utf-8 -*-
"""#1963: GraalPy's leg runs its tier in shards, so no xdist worker outlives its heap.

#1753 gives every GraalPy process a 2 GiB heap and an exit once it is spent, and a
worker's live heap grows with every test it runs. Over the curated ``ALL`` tier
that took job 118912680486's workers to 2.5-3.0 GB RSS and nine of them down, each
failing the test it ran, though each such test passes alone. So ``Run unit tests``
hands GraalPy's pytest command to :file:`util/pytest_shards.py`, which runs it once
per directory ``SHARDS`` names and once over the rest, each run with workers of its
own, all under the step's one ``timeout``, scope and watcher. 3.14t's leg runs
pytest once.

:class:`TestTheStep` reads the step, :class:`TestTheStepRuns` runs it with
``sudo`` and ``python`` stubbed on ``PATH``, and :class:`TestTheScript` runs the
script alone.

"""

from __future__ import annotations

import os
import pathlib
import shutil
import signal
import subprocess  # nosec: B404
import sys
import tempfile
import unittest

from tests._tiers import TIER_ALL, latest_tier_paths, module_tier
from tests.project.test_python_matrix_tiers_1633 import legs
from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_resource_monitor_1740 import DEFAULT, EXPERIMENTAL, HEAP, TESTS, by_impl, sh, step
from util import pytest_shards

#: GraalPy's shards, in the order they run; the rest of the tier runs last.
SHARDS = ('tests/const tests/corekit/test_fields_n* tests/corekit/test_[a-h]* tests/corekit/test_i* tests/corekit '
          'tests/foundation tests/protocols/internet tests/protocols/[a-m]* tests/protocols tests/toolkit')
SCRIPT = ROOT / 'util' / 'pytest_shards.py'
#: The lines that build the command the step's caps run, in order.
PYTEST = 'set -- python -m pytest "$@"\n'
SHARDED = 'set -- /usr/bin/python3 util/pytest_shards.py "$SHARDS" -- "$@"\n'
CAPPED = 'set -- prlimit --fsize=2147483648 "$gnu_timeout" --signal=INT --kill-after=3m 110m "$@"\n'


def rest_ignores(shards: 'str') -> 'list[str]':
    """What util/pytest_shards.py's last run, the rest, adds to the command for ``shards``.

    Asked of the script from the root, as the tests step runs it, since a glob shard
    resolves against the working directory.

    """
    code = 'import sys; from util import pytest_shards; print(*pytest_shards.runs(sys.argv[1].split(), [])[-1][1])'
    result = subprocess.run([sys.executable, '-c', code, shards], cwd=ROOT, capture_output=True,  # nosec: B603
                            text=True, check=True, timeout=60)
    return result.stdout.split()


class TestTheStep(unittest.TestCase):

    def test_graalpy_alone_runs_in_shards(self) -> None:
        env = step(TESTS)['env']
        versions = [leg['python-version'] for leg in legs(*EXPERIMENTAL)]
        self.assertTrue(any(version.startswith('graalpy') for version in versions), versions)
        self.assertTrue(any(not version.startswith('graalpy') for version in versions), versions)
        for version in versions:
            with self.subTest(version=version):
                self.assertEqual(by_impl(env['SHARDS'], version), SHARDS if version.startswith('graalpy') else '')
        # The heap and the workers are #1753's and #1740's.
        self.assertEqual(by_impl(env['GRAAL_PYTHON_VM_ARGS'], 'graalpy-25.4'), HEAP)
        self.assertEqual(by_impl(env['WORKERS'], 'graalpy-25.4'), '3')

    def test_each_shard_holds_tests_of_the_tier(self) -> None:
        for shard in SHARDS.split():
            with self.subTest(shard=shard):
                self.assertTrue(shard.startswith('tests/') and not shard.startswith('tests/integration'), shard)
                # A directory, or a glob of one directory's entries, as util/pytest_shards.py takes them.
                found = sorted(ROOT.glob(shard)) if pytest_shards.MAGIC.search(shard) else [ROOT / shard]
                self.assertTrue(found and all(path.exists() for path in found), shard)
                modules = [module for path in found
                           for module in ([path] if path.is_file() else path.rglob('test_*.py'))]
                self.assertTrue(any(module_tier(module) == TIER_ALL for module in modules), shard)
        self.assertEqual(len(set(SHARDS.split())), len(SHARDS.split()))

    def test_the_shards_run_under_the_one_timeout_scope_and_watcher(self) -> None:
        script = step(TESTS)['run']
        self.assertLess(script.index(PYTEST), script.index(SHARDED))
        self.assertLess(script.index(SHARDED), script.index(CAPPED))
        self.assertIn(f'if [ -n "$SHARDS" ]; then\n  {SHARDED}fi\n', script)
        self.assertLess(script.index(CAPPED), script.index('set -- scoped pcapkit-tests.scope "$@"\n'))
        self.assertLess(script.index(CAPPED), script.index('util/superseded.py watch'))
        self.assertEqual(script.count('python -m pytest'), 1)

    def test_every_runs_junit_file_is_uploaded(self) -> None:
        upload = step('Upload test timings')
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/junit*.xml')
        self.assertIn('--junitxml="$RUNNER_TEMP/junit.xml"', step(TESTS)['run'])

    def test_the_docs_say_it(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ('#1963', ':file:`util/pytest_shards.py`', '``SHARDS``', '``junit-tests-protocols.xml``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheStepRuns(unittest.TestCase):
    """The tests step with no scope, its ``python`` a stub that records each run's argv."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1963-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.temp = self.tmp / 'temp'
        self.temp.mkdir()
        self.bindir = self.tmp / 'bin'
        self.bindir.mkdir()
        (self.temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        self.vmstat = self.tmp / 'vmstat'
        self.vmstat.write_text('oom_kill 0\n', encoding='utf-8')
        self.calls = self.tmp / 'calls'
        self.env = dict(os.environ, RUNNER_TEMP=str(self.temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3',
                        GRAAL_PYTHON_VM_ARGS=HEAP, SHARDS='tests/a tests/b/c',
                        PATH=str(self.bindir) + os.pathsep + os.environ.get('PATH', ''))
        self.stub('sudo', 'exit 1\n')

    def stub(self, name: 'str', body: 'str') -> 'None':
        path = self.bindir / name
        path.write_text('#!/bin/sh\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def run_step(self, python: 'str', script: 'str | None' = None) -> 'subprocess.CompletedProcess[str]':
        """The step, the image's interpreter this one, each run's argv a line of ``self.calls``."""
        self.stub('python', f'echo "$*" >> {self.calls}\n' + python)
        self.assertEqual(shutil.which('sudo', path=self.env['PATH']), str(self.bindir / 'sudo'))
        script = step(TESTS)['run'] if script is None else script
        script = script.replace('/proc/vmstat', str(self.vmstat))
        script = script.replace('/usr/bin/python3 util/pytest_shards.py', f'"{sys.executable}" "{SCRIPT}"')
        return sh(script, self.env, DEFAULT)

    def runs(self) -> 'list[list[str]]':
        return [line.split() for line in self.calls.read_text(encoding='utf-8').splitlines()]

    def status(self) -> 'dict[str, str]':
        text = (self.temp / 'tests-status').read_text(encoding='utf-8')
        return dict(line.split('=', 1) for line in text.splitlines())

    def test_each_shard_then_the_rest_runs_with_workers_of_its_own(self) -> None:
        # The second run fails, and a worker goes down in the first and the last.
        result = self.run_step(f'n=$(wc -l < {self.calls})\n'
                               '[ "$n" = 2 ] || echo "[gw0] node down: Not properly terminated"\n'
                               '[ "$n" = 2 ] && exit 1\nexit 0\n')
        self.assertEqual(result.returncode, 1, result.stderr)
        first, second, rest = self.runs()
        junit = f'--junitxml={self.temp}/junit.xml'
        for run in (first, second, rest):
            self.assertEqual(run[:9], ['-m', 'pytest', '-q', '-n', '3', '--dist', 'load',
                                       '--max-worker-restart=30', '--durations=30'])
            self.assertIn(junit, run)
        self.assertEqual(first[-2:], [f'--junitxml={self.temp}/junit-tests-a.xml', 'tests/a'])
        self.assertEqual(second[-3:], [f'--junitxml={self.temp}/junit-tests-b-c.xml', '--ignore=tests/a', 'tests/b/c'])
        self.assertEqual(rest[-2:], ['--ignore=tests/a', '--ignore=tests/b/c'])
        self.assertEqual([arg for arg in rest if arg.startswith('--junitxml')], [junit])
        self.assertNotIn('tests/a', rest)
        self.assertIn('pytest_shards: run 3 of 3, the rest', result.stdout)
        status = self.status()
        self.assertEqual((status['exit'], status['crashed_workers']), ('1', '2'))

    def test_without_shards_pytest_runs_once_as_before(self) -> None:
        self.env['SHARDS'] = ''
        result = self.run_step('exit 0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        (run,) = self.runs()
        self.assertEqual(run[:2], ['-m', 'pytest'])
        self.assertEqual([arg for arg in run if arg.startswith('--junitxml')], [f'--junitxml={self.temp}/junit.xml'])
        self.assertNotIn('pytest_shards', result.stdout)

    def test_the_timeout_ends_the_run_in_progress_and_starts_no_other(self) -> None:
        # pytest ends on SIGINT, which timeout sends to its whole process group, with exit 2.
        script = step(TESTS)['run'].replace('--kill-after=3m 110m', '--kill-after=5s 1s')
        self.assertNotEqual(script, step(TESTS)['run'])
        result = self.run_step("trap 'echo interrupted; exit 2' INT\nsleep 30 &\nwait $!\nexit 0\n", script)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(len(self.runs()), 1)
        self.assertIn('interrupted\n', result.stdout)
        self.assertIn('pytest_shards: interrupted during tests/a; no later run starts', result.stdout)
        self.assertEqual(self.status()['exit'], '124')


class TestTheShardsPartitionTheTier(unittest.TestCase):
    """GraalPy's runs, collected by pytest through the script: every test of the tier once, none twice."""

    def test_every_test_runs_once(self) -> None:
        collect = [sys.executable, '-m', 'pytest', '--collect-only', '-q', '-p', 'no:cacheprovider',
                   '--ignore=tests/integration', '--ignore-glob=*_runtime.py', '--ignore-glob=*_regression.py',
                   *(f'--ignore={module}' for module in latest_tier_paths())]
        whole = subprocess.run(collect, cwd=ROOT, capture_output=True, text=True,  # nosec: B603
                               check=False, timeout=600)
        self.assertEqual(whole.returncode, 0, whole.stdout[-2000:] + whole.stderr[-2000:])
        sharded = subprocess.run([sys.executable, str(SCRIPT), SHARDS, '--', *collect], cwd=ROOT,  # nosec: B603
                                 capture_output=True, text=True, check=False, timeout=600)
        self.assertEqual(sharded.returncode, 0, sharded.stdout[-2000:] + sharded.stderr[-2000:])
        self.assertNotIn('pytest_shards: skipping', sharded.stdout)
        self.assertIn(f'pytest_shards: run {len(SHARDS.split()) + 1} of {len(SHARDS.split()) + 1}, the rest',
                      sharded.stdout)
        tests = [line for line in whole.stdout.splitlines() if '::' in line]
        self.assertTrue(tests)
        self.assertEqual(sorted(line for line in sharded.stdout.splitlines() if '::' in line), sorted(tests))


class TestTheScript(unittest.TestCase):

    def test_the_runs(self) -> None:
        command = ['python', '-m', 'pytest', '-q', '--junitxml=/tmp/t/junit.xml', '--ignore=tests/x']
        self.assertEqual(pytest_shards.runs(['tests/protocols', 'tests/corekit'], command), [
            ('tests/protocols', [*command, '--junitxml=/tmp/t/junit-tests-protocols.xml', 'tests/protocols']),
            ('tests/corekit', [*command, '--junitxml=/tmp/t/junit-tests-corekit.xml', '--ignore=tests/protocols',
                               'tests/corekit']),
            ('the rest', [*command, '--ignore=tests/protocols', '--ignore=tests/corekit']),
        ])

    def test_a_glob_takes_part_of_a_directory_and_the_directory_the_remainder(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1963-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name) / 'd'
        (root / 'sub').mkdir(parents=True)
        for name in ('test_a.py', 'test_b.py', 'test_c.py', '__init__.py', 'conftest.py', '_helper.py'):
            (root / name).write_text('', encoding='utf-8')
        a, b, c, sub = (str(root / name) for name in ('test_a.py', 'test_b.py', 'test_c.py', 'sub'))
        command = ['pytest']
        # The glob's run collects its directory with the rest of its entries ignored, never the
        # package's own files, so pytest's patterns and the command's ignores hold.
        self.assertEqual(pytest_shards.runs([f'{root}/test_[ab]*', str(root)], command), [
            (f'{root}/test_[ab]*', [*command, f'--ignore={sub}', f'--ignore={c}', str(root)]),
            (str(root), [*command, f'--ignore={a}', f'--ignore={b}', str(root)]),
            ('the rest', [*command, f'--ignore={a}', f'--ignore={b}', f'--ignore={root}']),
        ])
        self.assertEqual(pytest_shards.junit_for(['--junitxml=t/junit.xml'], 'tests/corekit/test_[a-f]*'),
                         '--junitxml=t/junit-tests-corekit-test_a-f.xml')

    def test_a_glob_that_selects_nothing_is_skipped(self) -> None:
        for shard in ('tests/corekit/test_no_such_module_*', 'tests/*/test_io.py', 'test_*'):
            with self.subTest(shard=shard):
                self.assertEqual(pytest_shards.runs([shard], ['pytest']), [('the rest', ['pytest'])])

    def test_a_command_without_a_junit_file_gets_none(self) -> None:
        command = ['python', '-m', 'pytest']
        self.assertIsNone(pytest_shards.junit_for(command, 'tests/a'))
        self.assertEqual(pytest_shards.runs(['tests/a'], command)[0], ('tests/a', [*command, 'tests/a']))

    def run_script(self, *args: 'str') -> 'subprocess.CompletedProcess[str]':
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True,  # nosec: B603
                              check=False, timeout=60)

    def test_a_bad_command_line_is_a_usage_error(self) -> None:
        for args in ((), ('tests/a',), ('--', 'true'), ('tests/a', '--')):
            with self.subTest(args=args):
                self.assertEqual(self.run_script(*args).returncode, pytest_shards.USAGE)

    def test_the_status_is_the_last_failures_and_a_signal_reads_as_a_shells(self) -> None:
        self.assertEqual(self.run_script('a b', '--', 'true').returncode, 0)
        self.assertEqual(self.run_script('a', '--', 'sh', '-c', 'exit 3', 'sh').returncode, 3)
        killed = self.run_script('a', '--', 'sh', '-c', 'kill -TERM $$', 'sh')
        self.assertEqual(killed.returncode, 128 + signal.SIGTERM, killed.stderr)


if __name__ == '__main__':
    unittest.main()
