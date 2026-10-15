# -*- coding: utf-8 -*-
"""#1753: a GraalPy xdist worker whose heap is spent exits, and xdist replaces it.

Under #1740's 2 GiB heap a GraalPy worker's live heap grows with the tests it
runs, until a ``MemoryError`` lands in pytest's own failure report and ends the
session, exit 3 (job 116172356218, 16 minutes in, at ``34 failed, 569 passed``).
So every GraalPy process gets ``-XX:+ExitOnOutOfMemoryError`` with its heap, and
pytest ``--max-worker-restart=30``: the worker exits, xdist fails the test it ran
as crashed and starts another, and the tier goes on to its end or its timeout.
``Run unit tests`` counts xdist's ``[gwN] node down:`` lines, and ``Containment
summary`` warns of them.

"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import unittest

from tests.project.test_python_matrix_tiers_1633 import legs, workflow_commands
from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_resource_monitor_1740 import (BASH, DEFAULT, EXPERIMENTAL, SUMMARY, TESTS, by_impl, sh,
                                                      step)

#: What every GraalPy process reads: #1740's 2 GiB heap, and an exit where it is spent.
GRAAL_VM_ARGS = '--vm.Xmx2g --vm.XX:+ExitOnOutOfMemoryError'
#: About 7 replacements a worker in 110 minutes, at a heap that lasts 16; xdist's default is 4 a worker.
RESTARTS = '--max-worker-restart=30'
#: xdist's line for a worker that went down with an error, which ``-q`` still prints.
NODE_DOWN = '[gw0] node down: Not properly terminated'


class TestTheWorkersAreReplaced(unittest.TestCase):

    def test_graalpy_exits_on_a_spent_heap(self) -> None:
        env = step(TESTS)['env']
        versions = [leg['python-version'] for leg in legs(*EXPERIMENTAL)]
        self.assertTrue(any(version.startswith('graalpy') for version in versions), versions)
        for version in versions:
            with self.subTest(version=version):
                self.assertEqual(by_impl(env['GRAAL_PYTHON_VM_ARGS'], version),
                                 GRAAL_VM_ARGS if version.startswith('graalpy') else '')

    def test_xdist_may_replace_30_workers(self) -> None:
        script = step(TESTS)['run']
        self.assertIn(f'set -- -q -n "$WORKERS" --dist load {RESTARTS} \\\n', script)
        self.assertEqual(script.count('--max-worker-restart'), 1)

    def test_the_docs_say_it(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in (f'``GRAAL_PYTHON_VM_ARGS={GRAAL_VM_ARGS}``', f'``{RESTARTS}``', '#1753',
                       '``tests lost an xdist worker``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheCrashesAreCounted(unittest.TestCase):
    """The tests step and ``Containment summary``, with ``sudo`` and ``python`` stubbed on ``PATH``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1753-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.temp = self.tmp / 'temp'
        self.temp.mkdir()
        self.bindir = self.tmp / 'bin'
        self.bindir.mkdir()
        (self.temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        self.vmstat = self.tmp / 'vmstat'
        self.vmstat.write_text('oom_kill 0\n', encoding='utf-8')
        self.env = dict(os.environ, RUNNER_TEMP=str(self.temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3',
                        GRAAL_PYTHON_VM_ARGS=GRAAL_VM_ARGS,
                        LEG='Python graalpy-25.4 (experimental, non-blocking)',
                        GITHUB_STEP_SUMMARY=str(self.tmp / 'summary.md'),
                        PATH=str(self.bindir) + os.pathsep + os.environ.get('PATH', ''))
        # No scope: the probe fails, so the tests run the same argv uncapped.
        self.stub('sudo', 'exit 1\n')

    def stub(self, name: 'str', body: 'str') -> 'None':
        path = self.bindir / name
        path.write_text('#!/bin/sh\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def status(self, pytest: 'str') -> 'dict[str, str]':
        self.stub('python', pytest)
        self.assertEqual(shutil.which('sudo', path=self.env['PATH']), str(self.bindir / 'sudo'))
        result = sh(step(TESTS)['run'].replace('/proc/vmstat', str(self.vmstat)), self.env, DEFAULT)
        self.assertEqual(result.returncode, 1, result.stderr)
        text = (self.temp / 'tests-status').read_text(encoding='utf-8')
        return dict(line.split('=', 1) for line in text.splitlines())

    def test_the_heap_and_the_restarts_reach_pytest(self) -> None:
        status = self.status(f'printf "%s\\n" "$@" > {self.tmp / "argv"}\necho "heap $GRAAL_PYTHON_VM_ARGS"\nexit 1\n')
        argv = (self.tmp / 'argv').read_text(encoding='utf-8').splitlines()
        self.assertEqual(argv[:8], ['-m', 'pytest', '-q', '-n', '3', '--dist', 'load', RESTARTS])
        self.assertEqual(status['crashed_workers'], '0')

    def test_every_worker_that_went_down_is_counted(self) -> None:
        # As job 116172356218's progress line runs into it, and on a line of its own.
        status = self.status(f'echo "..F.{NODE_DOWN}"\necho "[gw2] node down: Not properly terminated"\n'
                             'echo "replacing crashed worker gw2"\nexit 1\n')
        self.assertEqual(status['crashed_workers'], '2')
        self.assertEqual(status['memory_errors'], '0')

    def test_a_java_out_of_memory_line_is_no_memory_error(self) -> None:
        """``-w``: the flag, and Java's ``OutOfMemoryError``, are not Python's ``MemoryError``."""
        status = self.status('echo "heap $GRAAL_PYTHON_VM_ARGS"\necho "java.lang.OutOfMemoryError: Java heap space"\n'
                             'echo "E   MemoryError"\necho "MemoryError: out of memory"\nexit 1\n')
        self.assertEqual(status['memory_errors'], '2')

    def test_the_summary_warns_of_the_lost_workers(self) -> None:
        (self.temp / 'tests-status').write_text(
            'exit=1\nscope=12G\nprobe=\nelapsed=6000\noom_kills=0\nmemory_errors=0\ncrashed_workers=7\n',
            encoding='utf-8')
        result = sh(step(SUMMARY)['run'], self.env, BASH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [
            '::warning title=tests lost an xdist worker on Python graalpy-25.4 (experimental%2C non-blocking)::7 '
            'xdist worker(s) went down, each failing the test it ran, and xdist replaces up to 30; exit 1, scope 12G; '
            'no resource-monitor sample. Experimental legs never block (#1660), so this job still succeeds.'])
        self.assertIn('7 worker(s) down', result.stdout)

    def test_a_status_without_the_count_warns_of_nothing_new(self) -> None:
        """A ``tests-status`` from before #1753, or a partial one, is no crash."""
        (self.temp / 'tests-status').write_text('exit=1\nscope=12G\noom_kills=0\nmemory_errors=0\n', encoding='utf-8')
        result = sh(step(SUMMARY)['run'], self.env, BASH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [])
        self.assertIn('0 worker(s) down', result.stdout)


if __name__ == '__main__':
    unittest.main()
