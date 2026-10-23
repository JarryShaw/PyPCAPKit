# -*- coding: utf-8 -*-
"""A superseded Experimental leg warns of no missing JUnit file (#2073).

In Experimental Tests run 39898029852 both legs were stopped by
util/superseded.py's ``watch`` 60 s in, ``main`` having moved on, and each then
warned ``No files were found with the provided path:
/home/runner/work/_temp/junit*.xml``: pytest, stopped, writes no JUnit file,
and ``Upload test timings`` ran on as for any finished run. The watcher's
``Superseded`` notice already says why the file is missing, so the watcher
now writes ``stopped=true`` to the step's outputs and the upload reads it.

"""

from __future__ import annotations

import io
import os
import pathlib
import re
import shutil
import sys
import tempfile
import threading
import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_release_gates import evaluate_expression
from tests.project.test_resource_monitor_1740 import DEFAULT, TESTS, sh, step
from tests.project.test_superseded_runs_1938 import NEWER, OURS, POSIX, REPO, SLEEPER, FakeApi, Files, Handler, \
    Server, main_at
from util import superseded

if TYPE_CHECKING:
    from typing import Any, Dict

UPLOAD = 'Upload test timings'


def upload() -> 'Dict[str, Any]':
    return step(UPLOAD)


def if_no_files_found(stopped: 'Any') -> 'Any':
    """The upload's ``if-no-files-found`` where the tests step's ``stopped`` output is ``stopped``."""
    outputs = {} if stopped is None else {'stopped': stopped}
    return evaluate_expression(upload()['with']['if-no-files-found'], {'steps': {'tests': {'outputs': outputs}}})


class TestTheUpload(unittest.TestCase):

    def test_a_stopped_run_expects_no_file_and_any_other_still_warns(self) -> None:
        self.assertEqual(if_no_files_found('true'), 'ignore')
        for stopped in (None, '', 'false'):
            with self.subTest(stopped=stopped):
                self.assertEqual(if_no_files_found(stopped), 'warn')

    def test_the_upload_reads_the_tests_steps_junit_files(self) -> None:
        """The glob is where ``Run unit tests`` writes junit.xml, and the shards beside it."""
        written = re.findall(r'--junitxml="(\$RUNNER_TEMP/[^"]+)"', step(TESTS)['run'])
        self.assertEqual(written, ['$RUNNER_TEMP/junit.xml'])
        path = upload()['with']['path']
        self.assertEqual(path, '${{ runner.temp }}/junit*.xml')
        self.assertTrue(pathlib.PurePath('junit.xml').match(pathlib.PurePath(path).name))
        self.assertEqual(step(TESTS)['id'], 'tests')

    def test_the_docs_say_it(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ('`#2073 <https://github.com/JarryShaw/PyPCAPKit/issues/2073>`__', '``stopped=true``',
                       '``if-no-files-found: ignore``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)


@unittest.skipUnless(POSIX, 'the watcher signals a process group, as on the Ubuntu runners')
class TestTheWatcherSaysItStopped(unittest.TestCase):

    def test_a_stop_writes_stopped_true(self) -> None:
        files, out = Files(self), io.StringIO()
        code = superseded.main(['watch', '--interval', '0.2', '--grace', '5', '--', *SLEEPER],
                               env=files.env(), transport=FakeApi(main_at(NEWER)), out=out)
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(files.read(files.output), 'stopped=true\n')

    def test_a_command_that_ends_on_its_own_writes_nothing(self) -> None:
        files, out = Files(self), io.StringIO()
        code = superseded.main(['watch', '--interval', '0.2', '--', sys.executable, '-c', 'import sys; sys.exit(3)'],
                               env=files.env(), transport=FakeApi(main_at(OURS)), out=out)
        self.assertEqual(code, 3)
        self.assertEqual(files.read(files.output), '')

    def test_an_unwritable_output_does_not_fail_the_stop(self) -> None:
        files, out = Files(self), io.StringIO()
        env = files.env(GITHUB_OUTPUT=str(files.root / 'missing' / 'output'))
        code = superseded.main(['watch', '--interval', '0.2', '--grace', '5', '--', *SLEEPER],
                               env=env, transport=FakeApi(main_at(NEWER)), out=out)
        self.assertEqual(code, 0)
        self.assertIn('Could not write the step output: ', out.getvalue())


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheTestsStepOutput(unittest.TestCase):
    """``Run unit tests`` itself, as in test_superseded_runs_1938.py: its ``stopped`` output reaches the upload."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2073-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        self.temp, bindir, self.output = root / 'temp', root / 'bin', root / 'output'
        self.temp.mkdir()
        bindir.mkdir()
        (self.temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        self.python = bindir / 'python'
        for name, body in (('sudo', 'echo "sudo: a password is required" >&2\nexit 1\n'),
                           ('python', 'echo collected\nexec sleep 60\n')):
            (bindir / name).write_text('#!/bin/sh\n' + body, encoding='utf-8')
            (bindir / name).chmod(0o755)
        self.server = Server(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
        self.env.update(RUNNER_TEMP=str(self.temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3', GRAAL_PYTHON_VM_ARGS='',
                        GITHUB_STEP_SUMMARY=str(root / 'summary.md'), GITHUB_OUTPUT=str(self.output), GH_TOKEN='token',
                        GITHUB_API_URL=f'http://127.0.0.1:{self.server.server_address[1]}',
                        GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=OURS,
                        GITHUB_REPOSITORY=REPO, PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''),
                        WATCHER='success', WATCHER_PYTHON=sys.executable)

    def script(self) -> 'str':
        script = step(TESTS)['run']
        quick = script.replace('watch --interval 60 --grace 30 ', 'watch --interval 0.5 --grace 2 --kill-wait 2 ')
        self.assertNotEqual(quick, script)
        return quick

    def stopped(self) -> 'Any':
        """The ``stopped`` output, ``None`` where the step wrote none."""
        text = self.output.read_text(encoding='utf-8') if self.output.exists() else ''
        values = [line.split('=', 1)[1] for line in text.splitlines() if line.startswith('stopped=')]
        return values[-1] if values else None

    def test_a_stopped_run_writes_no_junit_and_its_upload_expects_none(self) -> None:
        result = sh(self.script(), self.env, DEFAULT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.temp.glob('junit*.xml')), [])
        self.assertEqual(self.stopped(), 'true')
        self.assertEqual(if_no_files_found(self.stopped()), 'ignore')

    def test_a_current_run_still_warns_of_a_missing_file(self) -> None:
        self.server.head = OURS  # type: ignore[attr-defined]
        self.python.write_text('#!/bin/sh\nsleep 1.5\nexit 1\n', encoding='utf-8')
        result = sh(self.script(), self.env, DEFAULT)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIsNone(self.stopped())
        self.assertEqual(if_no_files_found(self.stopped()), 'warn')


if __name__ == '__main__':
    unittest.main()
