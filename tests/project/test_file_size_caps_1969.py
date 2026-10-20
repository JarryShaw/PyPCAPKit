# -*- coding: utf-8 -*-
"""#1969: every pytest and unittest command in ``unit-tests.yml`` caps the files it writes.

A test that writes without bound fills the runner's disk (#1372's ``out.json``).
:file:`util/cap_file_size.py` sets ``RLIMIT_FSIZE`` and execs the command, and is
the one place the limit is written down. This module pins both halves: every step
of :file:`.github/workflows/unit-tests.yml` that runs pytest, unittest or
:file:`util/run_unittest_leg.py` does so through the script, so a new step without
it fails here; and the script caps what its command writes, so that a write past
the cap errors rather than passes.

"""

from __future__ import annotations

import errno
import os
import pathlib
import re
import signal
import subprocess  # nosec: B404
import sys
import tempfile
import unittest

from tests._workflows import WORKFLOWS, load, loads

try:
    import resource
except ImportError:  # pragma: no cover - not on Windows
    resource = None  # type: ignore[assignment]

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'cap_file_size.py'
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'
WORKFLOW = 'unit-tests.yml'
#: How a step runs a command under the cap.
CAP = 'python util/cap_file_size.py '
#: A command that runs tests: pytest or unittest as a module, coverage over
#: either, or util/run_unittest_leg.py.
RUNS_TESTS = re.compile(r'-m (?:pytest|unittest|coverage run)\b|util/run_unittest_leg\.py\b')
#: The jobs that run tests, each of which must be found running some.
TEST_JOBS = frozenset({
    'test', 'test-ktlo', 'integration', 'integration-ktlo', 'engine-tests',
    'pypcap-parity', 'pypcap-parity-ktlo', 'unittest-ordering', 'project-tests', 'gate',
})

if str(ROOT / 'util') not in sys.path:
    sys.path.insert(0, str(ROOT / 'util'))

import cap_file_size  # noqa: E402  pylint: disable=wrong-import-position


def commands(script: 'str') -> 'list[str]':
    """The logical lines of ``script``, continuations joined, comments and blanks dropped."""
    lines = []
    for line in script.replace('\\\n', ' ').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


def suite_commands(workflow: 'dict[str, object]') -> 'list[tuple[str, str, str]]':
    """Every ``(job, step, command)`` of ``workflow`` that runs tests."""
    found = []
    for job_id, spec in workflow['jobs'].items():  # type: ignore[attr-defined]
        for entry in spec.get('steps', ()):
            for line in commands(str(entry.get('run', ''))):
                if RUNS_TESTS.search(line):
                    found.append((job_id, entry.get('name', entry.get('id', '?')), line))
    return found


def uncapped(workflow: 'dict[str, object]') -> 'list[tuple[str, str, str]]':
    """The test commands of ``workflow`` that do not run through :data:`CAP`."""
    bad = []
    for where in suite_commands(workflow):
        line = where[2]
        start = RUNS_TESTS.search(line).start()  # type: ignore[union-attr]
        at = line.find(CAP)
        if at == -1 or at + len(CAP) > start or not line[at + len(CAP):].startswith('python '):
            bad.append(where)
    return bad


class TestEveryTestStepIsCapped(unittest.TestCase):
    """Each pytest and unittest command in ``unit-tests.yml`` runs under the cap."""

    def setUp(self) -> None:
        self.text = (WORKFLOWS / WORKFLOW).read_text(encoding='utf-8')
        self.workflow = load(WORKFLOW)

    def test_every_test_command_runs_through_the_script(self) -> None:
        self.assertEqual(uncapped(self.workflow), [])

    def test_every_test_job_is_seen(self) -> None:
        # The scan is not vacuous: each job that runs tests is found doing so,
        # the KTLO ones through their YAML alias, the engine cells inside the
        # script their step writes.
        seen = {job_id for job_id, _, _ in suite_commands(self.workflow)}
        self.assertLessEqual(TEST_JOBS, seen)

    def test_a_doctored_copy_without_the_cap_is_caught(self) -> None:
        bare = uncapped(loads(self.text.replace(CAP, '')))
        self.assertLessEqual(TEST_JOBS, {job_id for job_id, _, _ in bare})
        extra = loads(self.text.replace(
            '      - name: Run full test suite\n        run: ' + CAP,
            '      - name: Run a new suite\n        run: python -m pytest tests/project\n'
            '      - name: Run full test suite\n        run: ' + CAP, 1))
        self.assertEqual(uncapped(extra), [('gate', 'Run a new suite', 'python -m pytest tests/project')])

    def test_the_cap_has_one_mechanism(self) -> None:
        for word in ('ulimit -f', 'prlimit'):
            self.assertEqual([line for line in commands(self.text) if word in line], [], word)


@unittest.skipIf(resource is None, 'RLIMIT_FSIZE is POSIX')
class TestTheScript(unittest.TestCase):
    """util/cap_file_size.py caps the file size of the command it execs."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'out')

    def capped(self, limit: 'int', *command: 'str', **kwargs: 'object') -> 'subprocess.CompletedProcess[str]':
        """``command`` run by the script, with :data:`cap_file_size.LIMIT` set to ``limit``."""
        main = ('import sys; sys.path.insert(0, sys.argv[1]); import cap_file_size; '
                'cap_file_size.LIMIT = int(sys.argv[2]); cap_file_size.main(sys.argv[3:])')
        return subprocess.run([sys.executable, '-c', main, str(SCRIPT.parent), str(limit), *command],  # nosec: B603
                              cwd=self.tmp.name, text=True, check=False, timeout=60, **kwargs)  # type: ignore[call-overload]

    def test_the_limit_is_two_gib(self) -> None:
        self.assertEqual(cap_file_size.LIMIT, 2 * 1024 ** 3)

    def test_the_command_runs_under_the_limit(self) -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        expected = cap_file_size.LIMIT if hard == resource.RLIM_INFINITY else min(cap_file_size.LIMIT, hard)
        probe = 'import resource; print(*resource.getrlimit(resource.RLIMIT_FSIZE))'
        result = subprocess.run([sys.executable, str(SCRIPT), sys.executable, '-c', probe],  # nosec: B603
                                capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), [str(expected)] * 2)

    def test_a_lower_hard_limit_is_kept(self) -> None:
        def lower() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))

        probe = 'import resource; print(*resource.getrlimit(resource.RLIMIT_FSIZE))'
        result = self.capped(1 << 30, sys.executable, '-c', probe, capture_output=True,
                             preexec_fn=lower)  # pylint: disable=subprocess-popen-preexec-fn
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), [str(1 << 20)] * 2)

    def test_a_python_write_past_the_limit_raises_efbig(self) -> None:
        writer = ('import sys\nwith open(sys.argv[1], "wb") as file:\n'
                  '    file.write(b"x" * 8192)\n')
        result = self.capped(4096, sys.executable, '-c', writer, self.path, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'OSError: [Errno {errno.EFBIG}] File too large', result.stderr)
        self.assertEqual(os.path.getsize(self.path), 4096)

    def test_another_program_is_killed_by_sigxfsz(self) -> None:
        # CPython ignores SIGXFSZ, and an ignored signal stays ignored across
        # exec, so this holds only because the script restores the default.
        with open(self.path, 'wb') as file:
            result = self.capped(4096, 'head', '-c', '8192', '/dev/zero', stdout=file,
                                 stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, -signal.SIGXFSZ, result.stderr)
        self.assertEqual(os.path.getsize(self.path), 4096)

    def test_no_command_is_a_usage_error(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True,  # nosec: B603
                                check=False, timeout=60)
        self.assertEqual(result.returncode, cap_file_size.USAGE)
        self.assertIn('usage:', result.stderr)


class TestTheWorkflowsPage(unittest.TestCase):
    """docs/source/contributing/workflows.rst names the script for the cap."""

    def test_the_page_names_the_script(self) -> None:
        text = DOC.read_text(encoding='utf-8')
        self.assertIn('``util/cap_file_size.py``', text)
        self.assertNotIn('ulimit -f', text)


if __name__ == '__main__':
    unittest.main()
