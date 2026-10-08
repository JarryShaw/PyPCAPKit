# -*- coding: utf-8 -*-
"""Tests for the coverage leg's check that no process's data file went missing.

#1387: PR #1345's coverage leg combined 29 data files where #1341's combined 30,
with every test passing in both, and posted 85.85% against about 88.9%. A
process that dies before coverage's atexit save leaves no ``.coverage.*`` file,
and ``coverage combine`` reports what is left as the whole. So the ``Run unit
tests`` step of :file:`.github/workflows/unit-tests.yml` logs every measured
process (``COVERAGE_DEBUG=pid,process``), and ``Report coverage`` runs a check
before ``coverage combine`` that fails the step, posting no total, unless the
controller and each of its direct children -- the xdist workers -- saved a file.

The check is extracted from the workflow and run here, both on hand-written
logs and on one written by a real ``coverage run``, so the format it parses is
the one coverage emits rather than one assumed.

"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import types
import typing
import unittest
import unittest.mock

if typing.TYPE_CHECKING:
    import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'unit-tests.yml'
RCFILE = ROOT / '.github' / 'coverage.toml'
LOG = 'coverage-processes.log'
CONTROLLER_CMD = ("['/x/coverage/__main__.py', 'run', '--rcfile=.github/coverage.toml', "
                  "'-m', 'pytest', '-q', '-n', 'auto']")
#: A ``['-c']`` child's pid in a debug log; coverage pads pids under five digits with spaces.
CHILD = re.compile(r"^ *(\d+)\.\w+: New process: cmd: \['-c'\]", re.M)


def _report_step() -> str:
    """The ``run:`` text of the ``Report coverage`` step."""
    text = WORKFLOW.read_text(encoding='utf-8')
    return text.split('- name: Report coverage', 1)[1].split('\n      - name:', 1)[0]


def _guard() -> str:
    """The Python source of the check, the first heredoc in ``Report coverage``."""
    body = _report_step().split("python - <<'PY'\n", 1)[1].split('\n          PY\n', 1)[0]
    return textwrap.dedent(body)


def _has_coverage() -> bool:
    try:
        import coverage  # pylint: disable=import-outside-toplevel
    except ImportError:
        return False
    return tuple(int(x) for x in coverage.__version__.split('.')[:2]) >= (7, 10)


def _entry(pid: int, parent: int, cmd: str) -> str:
    # coverage right-aligns the pid prefix to a fixed width, so short pids lead with spaces
    return (f'{pid:5d}.ab12: New process: pid={pid}, executable: /usr/bin/python\n'
            f'{pid:5d}.ab12: New process: cmd: {cmd}\n'
            f'{pid:5d}.ab12: New process parent pid: {parent}\n')


class CoverageDataGuardTests(unittest.TestCase):
    """The check fails exactly when the controller or an xdist worker saved nothing."""

    def setUp(self) -> None:
        self.tempdir = pathlib.Path(tempfile.mkdtemp(prefix='coverage-guard-'))
        self.addCleanup(shutil.rmtree, self.tempdir, ignore_errors=True)
        self.summary = self.tempdir / 'summary.md'
        self.summary.touch()

    def run_guard(self) -> 'subprocess.CompletedProcess[str]':
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(self.summary))
        return subprocess.run([sys.executable, '-c', _guard()], cwd=self.tempdir, env=env,  # nosec: B603
                              capture_output=True, text=True, check=False, timeout=60)

    def write(self, log: str, pids: 'list[int]') -> None:
        (self.tempdir / LOG).write_text(log, encoding='utf-8')
        for pid in pids:
            (self.tempdir / f'.coverage.runner.pid{pid}.Xabcdefgh.Habcdefghijkh').touch()

    def assert_fails(self, why: str) -> None:
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f'::error::Coverage data is incomplete: {why}', result.stdout)
        self.assertIn('**Coverage not reported:**', self.summary.read_text(encoding='utf-8'))

    def test_the_check_runs_before_combine(self) -> None:
        """``combine`` deletes the data files it merges, so the check must come first."""
        step = _report_step()
        self.assertLess(step.index('#1387'), step.index('coverage combine'))
        tests = WORKFLOW.read_text(encoding='utf-8').split('- name: Run unit tests', 1)[1]
        self.assertRegex(tests.split('- name:', 1)[0],
                         r'COVERAGE_DEBUG=pid,process COVERAGE_DEBUG_FILE="\$PWD/' + re.escape(LOG))

    def test_a_complete_run_passes(self) -> None:
        """A child of a worker that saved nothing is not the controller's or a worker's loss."""
        log = (_entry(100, 1, CONTROLLER_CMD) + _entry(101, 100, "['-c']")
               + _entry(102, 100, "['-c']") + _entry(200, 101, "['-c']"))
        self.write(log, [100, 101, 102])
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("2 xdist workers, missing data: []", result.stdout)
        self.assertEqual(self.summary.read_text(encoding='utf-8'), '')

    def test_a_missing_worker_fails(self) -> None:
        """#1345's case: one worker's file absent, every test passed."""
        log = _entry(100, 1, CONTROLLER_CMD) + _entry(101, 100, "['-c']") + _entry(102, 100, "['-c']")
        self.write(log, [100, 101])
        self.assert_fails("no data file from pid ['102']")

    def test_a_missing_controller_fails(self) -> None:
        self.write(_entry(100, 1, CONTROLLER_CMD) + _entry(101, 100, "['-c']"), [101])
        self.assert_fails("no data file from pid ['100']")

    def test_a_log_naming_no_worker_fails(self) -> None:
        """A blind check -- the log format changed, or debug output went elsewhere -- fails."""
        self.write(_entry(100, 1, CONTROLLER_CMD), [100])
        self.assert_fails('the process log is missing or unreadable')

    def test_a_missing_log_fails_without_a_traceback(self) -> None:
        """No log at all -- the test step died before writing one -- is the same clean failure."""
        result = self.run_guard()
        self.assertNotIn('Traceback', result.stderr)
        self.assert_fails('the process log is missing or unreadable')

    @unittest.skipUnless(_has_coverage(), 'needs coverage 7.10+ (`[run] patch`)')
    def test_the_log_coverage_writes_is_the_one_parsed(self) -> None:
        """A real ``coverage run`` whose child stands in for an xdist worker."""
        (self.tempdir / '.github').mkdir()
        shutil.copy(RCFILE, self.tempdir / '.github' / 'coverage.toml')
        (self.tempdir / 'spawn.py').write_text(
            'import subprocess, sys\nsubprocess.run([sys.executable, "-c", "pass"], check=True)\n',
            encoding='utf-8')
        env = {k: v for k, v in os.environ.items() if not k.startswith('COVERAGE')}
        env.update(COVERAGE_DEBUG='pid,process', COVERAGE_DEBUG_FILE=str(self.tempdir / LOG))
        subprocess.run([sys.executable, '-m', 'coverage', 'run', '--rcfile=.github/coverage.toml',  # nosec: B603
                        'spawn.py'], cwd=self.tempdir, env=env, check=True, timeout=120,
                       capture_output=True)
        files = sorted(self.tempdir.glob('.coverage.*'))
        self.assertEqual(len(files), 2, files)
        self.assertEqual(self.run_guard().returncode, 0)

        # dropping the child's file is what a lost worker looks like
        child = CHILD.search((self.tempdir / LOG).read_text(encoding='utf-8'))[1]
        next(f for f in files if f'.pid{child}.' in f.name).unlink()
        self.assert_fails(f"no data file from pid ['{child}']")

    def test_the_child_lookup_allows_a_padded_pid(self) -> None:
        """The real-log test above finds its child under a pid shorter than the padding."""
        self.assertEqual(CHILD.search(_entry(9832, 9800, "['-c']"))[1], '9832')

    def test_a_missing_worker_is_named_with_its_fate(self) -> None:
        """#1423: the failure says which process it was and whether its atexit save ran."""
        log = (_entry(100, 1, CONTROLLER_CMD) + _entry(101, 100, "['-c']")
               + _entry(102, 100, "['-c']") + _entry(103, 100, "['-c']")
               + '  102.ab12: atexit: pid: 102, instance: <Coverage data_file=x>\n')
        self.write(log, [100, 101])
        result = self.run_guard()
        self.assertIn("pid 102: cmd ['-c']", result.stdout)
        self.assertIn('pid 102: atexit: instance: <Coverage data_file=x>', result.stdout)
        self.assertIn('pid 103: no atexit/sigterm entry -- died before saving', result.stdout)
        self.assert_fails("no data file from pid ['102', '103']")

    def test_the_process_log_is_kept_as_an_artifact(self) -> None:
        """The log is the only record of a lost worker's fate once the runner is gone (#1423)."""
        text = WORKFLOW.read_text(encoding='utf-8')
        step = text.split('- name: Upload coverage process log', 1)[1]
        step = step.split('\n      - name:', 1)[0]
        self.assertIn('if: ${{ !cancelled() && matrix.coverage }}', step)
        self.assertIn(f'path: {LOG}', step)


class WorkerSessionFinishSaveTests(unittest.TestCase):
    """#1423: an xdist worker writes its data at session finish, not only at exit."""

    def finish(self, *, worker: bool) -> int:
        """Run the conftest hook under a stand-in auto-started coverage; return its saves."""
        import coverage  # pylint: disable=import-outside-toplevel

        from tests import conftest  # pylint: disable=import-outside-toplevel

        cov = unittest.mock.Mock()
        sentinel = object()
        before = getattr(coverage.process_startup, 'coverage', sentinel)
        coverage.process_startup.coverage = cov  # type: ignore[attr-defined]
        try:
            config = types.SimpleNamespace(**({'workerinput': {}} if worker else {}))
            conftest.pytest_sessionfinish(typing.cast('pytest.Session',
                                                      types.SimpleNamespace(config=config)))
        finally:
            if before is sentinel:
                del coverage.process_startup.coverage  # type: ignore[attr-defined]
            else:
                coverage.process_startup.coverage = before  # type: ignore[attr-defined]
        return int(cov.save.call_count)

    @unittest.skipUnless(_has_coverage(), 'needs coverage 7.10+ (`[run] patch`)')
    def test_a_worker_saves(self) -> None:
        """The file exists before shutdown, so a death there cannot lose it whole."""
        self.assertEqual(self.finish(worker=True), 1)

    @unittest.skipUnless(_has_coverage(), 'needs coverage 7.10+ (`[run] patch`)')
    def test_the_controller_does_not(self) -> None:
        """The controller saves at its own exit; only workers die after reporting."""
        self.assertEqual(self.finish(worker=False), 0)


if __name__ == '__main__':
    unittest.main()
