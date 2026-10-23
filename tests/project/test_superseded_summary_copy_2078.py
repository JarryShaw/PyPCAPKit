# -*- coding: utf-8 -*-
"""#2078: a stopped experimental leg's summary line reaches the uploaded job summary.

Experimental Tests run 39898485708 uploaded no ``job-summary-*`` artifact: its
legs were stopped as superseded, and the one line their job summaries held was
util/superseded.py's, which went to ``$GITHUB_STEP_SUMMARY`` alone, so
``job-summary.md`` was never written and ``Upload the job summary`` found nothing.
The watcher now takes the copy's path as ``--summary-copy``, which ``Run unit
tests`` passes it, and the tests it runs never see.

* :class:`TestTheSteps` runs ``Run unit tests`` and ``Name the job summary`` as
  experimental.yml has them, against a local server standing in for the API,
  and reads the files where ``Upload the job summary`` looks for them.
* :class:`TestTheWatchersCopy` drives util/superseded.py's ``watch`` itself.

"""

from __future__ import annotations

import io
import os
import pathlib
import shutil
import signal
import sys
import tempfile
import threading
import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_versions_1660 import ROOT
from tests.project.test_resource_monitor_1740 import BASH, DEFAULT, TESTS, sh, step
from tests.project.test_superseded_runs_1938 import (NEWER, OURS, REPO, SLEEPER, FakeApi, Files, Handler, Server,
                                                     main_at)
from util import superseded

if TYPE_CHECKING:
    from typing import Dict, List, Tuple

SAVE, UPLOAD = 'Name the job summary', 'Upload the job summary'
JOB_NAME = 'Python 3.14t (experimental)'
#: The line a stopped run's watcher writes, up to its elapsed seconds.
STOPPED = f'- Superseded: main is at {NEWER[:9]}, no longer at {OURS[:9]}. The tests were stopped after '


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheSteps(unittest.TestCase):
    """The tests step, then the step that names the copy, then the upload's own paths."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2078-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.temp = self.tmp / 'temp'
        self.temp.mkdir()
        self.seen = self.tmp / 'seen'
        bindir = self.tmp / 'bin'
        bindir.mkdir()
        (self.temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        # No real sudo, so the tests run uncapped; `python`, the tests, records whether it sees the copy.
        for name, body in (('sudo', 'echo "sudo: a password is required" >&2\nexit 1\n'),
                           ('python', f'echo "${{JOB_SUMMARY_COPY-unset}}" > {self.seen}\nexec sleep 60\n')):
            (bindir / name).write_text('#!/bin/sh\n' + body, encoding='utf-8')
            (bindir / name).chmod(0o755)
        self.server = Server(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.summary = self.tmp / 'summary.md'
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GITHUB_') and key != 'JOB_SUMMARY_COPY'}
        self.env.update(RUNNER_TEMP=str(self.temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3', GRAAL_PYTHON_VM_ARGS='',
                        GITHUB_STEP_SUMMARY=str(self.summary), GH_TOKEN='token',
                        GITHUB_API_URL=f'http://127.0.0.1:{self.server.server_address[1]}',
                        GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=OURS,
                        GITHUB_REPOSITORY=REPO, PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''),
                        WATCHER='success', WATCHER_PYTHON=sys.executable)

    def tests(self, **env: 'str') -> 'None':
        script = step(TESTS)['run']
        quick = script.replace('watch --interval 60 --grace 30 ', 'watch --interval 0.5 --grace 2 --kill-wait 2 ')
        self.assertNotEqual(quick, script)
        result = sh(quick, dict(self.env, **env), DEFAULT)
        self.assertEqual(result.returncode, 0 if self.server.head == NEWER else 1, result.stderr)

    def save(self) -> 'None':
        save = step(SAVE)
        self.assertEqual(save['env']['JOB_NAME'], 'Python ${{ matrix.python-version }} (experimental)')
        result = sh(save['run'], dict(self.env, JOB_NAME=JOB_NAME), BASH)
        self.assertEqual(result.returncode, 0, result.stderr)

    def uploaded(self) -> 'Dict[str, str]':
        """What ``Upload the job summary`` finds, by file name: each of its paths, with ``runner.temp`` resolved."""
        found = {}
        for line in step(UPLOAD)['with']['path'].splitlines():
            self.assertTrue(line.startswith('${{ runner.temp }}/'), line)
            path = self.temp / line[len('${{ runner.temp }}/'):]
            if path.exists():
                found[path.name] = path.read_text(encoding='utf-8')
        return found

    def test_a_stopped_run_uploads_its_summary_line(self) -> None:
        self.tests()
        self.save()
        page = self.summary.read_text(encoding='utf-8')
        self.assertTrue(page.startswith(STOPPED), page)
        # The copy holds exactly what the job's summary does, and the name is written beside it.
        self.assertEqual(self.uploaded(), {'job-summary.md': page, 'job-summary.name': JOB_NAME + '\n'})

    def test_the_tests_never_see_the_copy(self) -> None:
        self.assertNotIn('JOB_SUMMARY_COPY', step(TESTS).get('env') or {})
        self.tests()
        self.assertEqual(self.seen.read_text(encoding='utf-8'), 'unset\n')

    def test_a_run_left_to_finish_has_nothing_to_upload(self) -> None:
        """A current commit's run writes no summary line here, so there is no copy, and no artifact."""
        self.server.head = OURS
        bindir = pathlib.Path(self.env['PATH'].split(os.pathsep)[0])
        (bindir / 'python').write_text(f'#!/bin/sh\necho "${{JOB_SUMMARY_COPY-unset}}" > {self.seen}\nexit 1\n',
                                       encoding='utf-8')
        for watcher in ('success', 'failure'):
            with self.subTest(watcher=watcher):
                self.tests(WATCHER=watcher)
                self.save()
                self.assertEqual(self.uploaded(), {})
                self.assertEqual(self.seen.read_text(encoding='utf-8'), 'unset\n')


@unittest.skipUnless(os.name == 'posix', 'the watcher signals a process group, as on the Ubuntu runners')
class TestTheWatchersCopy(unittest.TestCase):
    """``watch --summary-copy``: each summary line goes to the copy as well as to the job's summary."""

    def watch(self, command: 'List[str]', copy: 'pathlib.Path', *options: 'str',
              **env: 'str') -> 'Tuple[int, str, Files]':
        files, out = Files(self), io.StringIO()
        code = superseded.main(['watch', '--interval', '0.2', '--grace', '2', '--summary-copy', str(copy), *options,
                                '--', *command], env=files.env(**env), transport=FakeApi(main_at(NEWER)), out=out)
        return code, out.getvalue(), files

    def test_a_stopped_runs_line_goes_to_both(self) -> None:
        copy = Files(self).root / 'job-summary.md'
        code, _, files = self.watch(SLEEPER, copy)
        self.assertEqual(code, 0)
        self.assertTrue(files.read(files.summary).startswith(STOPPED))
        self.assertEqual(files.read(copy), files.read(files.summary))

    def test_a_run_not_stopped_has_its_line_copied_too(self) -> None:
        tmp = Files(self).root
        copy, pidfile = tmp / 'job-summary.md', tmp / 'pid'
        command = [sys.executable, '-c', f'import os, time; open({str(pidfile)!r}, "w").write(str(os.getpid())); '
                                         'time.sleep(60)']

        def cleanup() -> 'None':
            try:
                os.kill(int(pidfile.read_text(encoding='utf-8')), signal.SIGKILL)
            except (OSError, ValueError):
                pass
        self.addCleanup(cleanup)
        files, out = Files(self), io.StringIO()
        code = superseded.main(['watch', '--interval', '0.2', '--grace', '0.5', '--kill-wait', '0.5',
                                '--scope', 'pcapkit-tests.scope', '--summary-copy', str(copy), '--', *command],
                               env=files.env(), transport=FakeApi(main_at(NEWER)), out=out,
                               run=lambda argv: 1, kill=lambda pid, signum: None)
        self.assertEqual(code, superseded.STOP_FAILED, out.getvalue())
        self.assertTrue(files.read(files.summary).startswith('- Superseded run not stopped: main is at'))
        self.assertEqual(files.read(copy), files.read(files.summary))

    def test_without_a_job_summary_nothing_is_copied(self) -> None:
        copy = Files(self).root / 'job-summary.md'
        code, _, _ = self.watch(SLEEPER, copy, GITHUB_STEP_SUMMARY='')
        self.assertEqual(code, 0)
        self.assertFalse(copy.exists())

    def test_a_copy_that_cannot_be_written_is_left_out(self) -> None:
        copy = Files(self).root / 'no' / 'job-summary.md'
        code, out, files = self.watch(SLEEPER, copy)
        self.assertEqual(code, 0)
        self.assertTrue(files.read(files.summary).startswith(STOPPED))
        self.assertNotIn('Could not write', out)

    def test_a_summary_that_cannot_be_written_is_logged_and_not_copied(self) -> None:
        tmp = Files(self).root
        copy = tmp / 'job-summary.md'
        code, out, _ = self.watch(SLEEPER, copy, GITHUB_STEP_SUMMARY=str(tmp / 'no' / 'summary.md'))
        self.assertEqual(code, 0)
        self.assertIn('Could not write the job summary: ', out)
        self.assertFalse(copy.exists())


if __name__ == '__main__':
    unittest.main()
