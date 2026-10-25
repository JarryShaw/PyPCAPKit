# -*- coding: utf-8 -*-
"""A superseded Experimental leg's ``Containment summary`` says it was stopped (#2077).

In Experimental Tests run 39898029852, job 120233865230, util/superseded.py's
``watch`` stopped pytest 61 s in, ``main`` having moved on, and exited 0 as it
does for every stop. ``Containment summary`` read that status and closed on
``tests exited 0 after 61 s``, which reads as a pass. The watcher writes
``stopped=true`` to ``Run unit tests``'s outputs (#2076), so the summary
reads it and says the tests were stopped as superseded. It adds no warning for
the stop, as the watcher's ``Superseded`` notice already says why, and keeps
every warning it gives for a real cause.

"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import sys
import tempfile
import threading
import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_matrix_tiers_1633 import workflow_commands
from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_release_gates import NULL, evaluate_expression
from tests.project.test_resource_monitor_1740 import BASH, DEFAULT, SUMMARY, TESTS, sh, step
from tests.project.test_superseded_runs_1938 import OURS, REPO, Handler, Server

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional

LEG = 'Python 3.14t (experimental, non-blocking)'
#: The cited job's ``tests-status``, as its ``Containment summary`` line reports it.
STOPPED_STATUS = ('exit=0\nscope=12G\nprobe=\nelapsed=61\noom_kills=0\nmemory_errors=0\ncrashed_workers=0\n')
STOPPED_LINE = (f'{LEG}: tests were stopped as superseded after 61 s, scope 12G, 0 OOM kill(s), '
                '0 MemoryError line(s), 0 worker(s) down; no resource-monitor sample.')


def stopped_env(outputs: 'Dict[str, Any]') -> 'str':
    """``Containment summary``'s ``STOPPED``, as the runner renders it where ``Run unit tests`` wrote ``outputs``."""
    expression = step(SUMMARY).get('env', {}).get('STOPPED')
    if expression is None:  # a step that does not read the output sees none
        return ''
    value = evaluate_expression(expression, {'steps': {'tests': {'outputs': outputs}}})
    # An unset output renders as the empty string in `env:`, as for any `${{ }}` there.
    return '' if value is NULL or value is None else str(value)


class Summary(unittest.TestCase):
    """Runs the real ``Containment summary`` script over a ``RUNNER_TEMP`` of its own."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2077-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.temp = self.root / 'temp'
        self.temp.mkdir()
        self.page = self.root / 'summary.md'
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
        self.env.update(RUNNER_TEMP=str(self.temp), LEG=LEG, GITHUB_STEP_SUMMARY=str(self.page))

    def summary(self, outputs: 'Dict[str, Any]', status: 'Optional[str]' = None) -> 'List[str]':
        """The step's output lines, given the tests step's ``outputs`` and, if not left by it, ``tests-status``."""
        if status is not None:
            (self.temp / 'tests-status').write_text(status, encoding='utf-8')
        env = dict(self.env, STOPPED=stopped_env(outputs))
        result = sh(step(SUMMARY)['run'], env, BASH)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def job_summary(self) -> 'str':
        return self.page.read_text(encoding='utf-8') if self.page.exists() else ''


@unittest.skipUnless(shutil.which('bash'), 'the step runs under bash, as on the runners')
class TestTheSummaryLine(Summary):

    def test_a_stopped_run_says_it_was_stopped_with_no_warning(self) -> None:
        lines = self.summary({'stopped': 'true'}, STOPPED_STATUS)
        self.assertEqual(lines, [STOPPED_LINE])
        self.assertNotIn('exited', '\n'.join(lines))
        self.assertEqual(workflow_commands('\n'.join(lines)), [])
        self.assertEqual(self.job_summary(), '')

    def test_any_other_run_still_gives_its_exit_status(self) -> None:
        for outputs in ({}, {'stopped': ''}, {'stopped': 'false'}):
            with self.subTest(outputs=outputs):
                self.assertEqual(self.summary(outputs, STOPPED_STATUS.replace('exit=0', 'exit=1')), [
                    f'{LEG}: tests exited 1 after 61 s, scope 12G, 0 OOM kill(s), 0 MemoryError line(s), '
                    '0 worker(s) down; no resource-monitor sample.'])

    def test_a_stopped_run_keeps_its_warnings_for_real_causes(self) -> None:
        status = 'exit=0\nscope=none\nprobe=sudo: no\nelapsed=61\noom_kills=1\nmemory_errors=2\ncrashed_workers=3\n'
        warnings = {}  # type: Dict[str, List[str]]
        for stopped in ('true', 'false'):
            lines = self.summary({'stopped': stopped}, status)
            warnings[stopped] = workflow_commands('\n'.join(lines))
            self.assertEqual(len(lines), len(warnings[stopped]) + 1)
        self.assertEqual(warnings['true'], warnings['false'])
        self.assertEqual([line.split('::')[1].split(' on ')[0] for line in warnings['true']],
                         ['warning title=No memory cap', 'warning title=tests lost a process to the OOM killer',
                          'warning title=tests raised MemoryError', 'warning title=tests lost an xdist worker'])

    def test_the_output_reaches_the_step_through_env(self) -> None:
        summary = step(SUMMARY)
        self.assertEqual(summary['env']['STOPPED'], '${{ steps.tests.outputs.stopped }}')
        self.assertNotIn('${{', summary['run'])
        self.assertEqual(step(TESTS)['id'], 'tests')
        self.assertEqual(stopped_env({'stopped': 'true'}), 'true')
        self.assertEqual(stopped_env({}), '')


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheStepsInTurn(Summary):
    """``Run unit tests`` stopped by the real watcher, then ``Containment summary`` over what it left."""

    def setUp(self) -> None:
        super().setUp()
        bindir, self.output = self.root / 'bin', self.root / 'output'
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
        self.env.update(GITHUB_WORKSPACE=str(ROOT), WORKERS='3', GRAAL_PYTHON_VM_ARGS='', GITHUB_OUTPUT=str(self.output),
                        GH_TOKEN='token', GITHUB_API_URL=f'http://127.0.0.1:{self.server.server_address[1]}',
                        GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=OURS,
                        GITHUB_REPOSITORY=REPO, PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''),
                        WATCHER='success', WATCHER_PYTHON=sys.executable)

    def run_tests(self) -> 'Dict[str, str]':
        """``Run unit tests``, its watcher quickened; the outputs it wrote."""
        script = step(TESTS)['run']
        quick = script.replace('watch --interval 60 --grace 30 ', 'watch --interval 0.5 --grace 2 --kill-wait 2 ')
        self.assertNotEqual(quick, script)
        sh(quick, self.env, DEFAULT)
        text = self.output.read_text(encoding='utf-8') if self.output.exists() else ''
        return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

    def last_line(self, outputs: 'Dict[str, str]') -> 'str':
        lines = self.summary(outputs)
        self.assertEqual(workflow_commands('\n'.join(lines)), ['::warning title=No memory cap on '
                                                               'Python 3.14t (experimental%2C non-blocking)::'
                                                               'The probe, sudo -n systemd-run --scope with the '
                                                               "tests' flags, failed (sudo: a password is required), "
                                                               'so the tests ran without the 12G scope. Experimental '
                                                               'legs never block (#1660), so this job still succeeds.'])
        return lines[-1]

    def test_a_superseded_run_is_reported_as_stopped(self) -> None:
        outputs = self.run_tests()
        self.assertEqual(outputs, {'stopped': 'true'})
        line = self.last_line(outputs)
        self.assertRegex(line, '^' + re.escape(LEG) + r': tests were stopped as superseded after \d+ s, scope none, ')

    def test_a_current_run_is_reported_by_its_exit_status(self) -> None:
        self.server.head = OURS  # type: ignore[attr-defined]
        self.python.write_text('#!/bin/sh\nsleep 1.5\nexit 1\n', encoding='utf-8')
        outputs = self.run_tests()
        self.assertEqual(outputs, {})
        self.assertRegex(self.last_line(outputs), r': tests exited 1 after \d+ s, scope none, ')


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_says_a_stopped_run_was_stopped(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ('`#2077 <https://github.com/JarryShaw/PyPCAPKit/issues/2077>`__',
                       '``tests were stopped as superseded``', '``tests exited 0``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)


if __name__ == '__main__':
    unittest.main()
