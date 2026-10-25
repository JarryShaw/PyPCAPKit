# -*- coding: utf-8 -*-
"""#1962: ``Run unit tests`` counts the ``MemoryError`` raised, not a mention of one.

The count behind ``Containment summary``'s ``tests raised MemoryError`` warning
must not be a bare ``grep -cw MemoryError``: that also matches a test's
docstring that a traceback prints (``fail with :exc:`MemoryError```), and so
warned of a ``MemoryError`` none of a timed-out GraalPy run's tests raised (job
118149195212). Instead the step counts the lines that ``MemoryError`` heads, as an exception's own line: at
the line's start, or after pytest's ``E``, an ``INTERNALERROR>`` or an exception
group's ``|``. The lines below are the experimental logs' own, the raised one
from job 116172356218 (#1753).

"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import unittest

from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_resource_monitor_1740 import DEFAULT, TESTS, sh, step

#: The docstring line job 118149195212 printed in a traceback, which ``-w`` counted.
DOCSTRING = '        much and either hang or fail with :exc:`MemoryError` rather than'
#: The line that reported #1753's ``MemoryError`` in pytest's own failure report.
INTERNAL = 'INTERNALERROR> E             MemoryError'
#: Lines that mention ``MemoryError`` but report none raised.
MENTIONS = (
    DOCSTRING,
    '    MemoryError: if the heap is spent',
    'heap --vm.Xmx2g --vm.XX:+ExitOnOutOfMemoryError',
    'java.lang.OutOfMemoryError: Java heap space',
    '>       raise MemoryError()',
)
#: Lines that report a raised ``MemoryError``, each in a form pytest or Python prints.
RAISED = (
    INTERNAL,
    'E   MemoryError',
    'E       MemoryError: java.lang.OutOfMemoryError: Java heap space',
    'MemoryError',
    'MemoryError: out of memory',
    '    | MemoryError',
)


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheMemoryErrorsAreCounted(unittest.TestCase):
    """The tests step, with ``sudo`` and ``python`` stubbed on ``PATH``, and pytest's output a file."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1962-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.temp = self.tmp / 'temp'
        self.temp.mkdir()
        self.bindir = self.tmp / 'bin'
        self.bindir.mkdir()
        (self.temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        self.vmstat = self.tmp / 'vmstat'
        self.vmstat.write_text('oom_kill 0\n', encoding='utf-8')
        self.output = self.tmp / 'pytest-output'
        self.env = dict(os.environ, RUNNER_TEMP=str(self.temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3',
                        GRAAL_PYTHON_VM_ARGS='', PATH=str(self.bindir) + os.pathsep + os.environ.get('PATH', ''))
        # No scope: the probe fails, so the tests run the same argv uncapped.
        self.stub('sudo', 'exit 1\n')
        self.stub('python', f"cat '{self.output}'\nexit 1\n")

    def stub(self, name: 'str', body: 'str') -> 'None':
        path = self.bindir / name
        path.write_text('#!/bin/sh\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def count(self, *lines: 'str') -> 'int':
        """The ``memory_errors`` the step writes where pytest prints ``lines``."""
        self.output.write_text(''.join(line + '\n' for line in lines), encoding='utf-8')
        self.assertEqual(shutil.which('sudo', path=self.env['PATH']), str(self.bindir / 'sudo'))
        result = sh(step(TESTS)['run'].replace('/proc/vmstat', str(self.vmstat)), self.env, DEFAULT)
        self.assertEqual(result.returncode, 1, result.stderr)
        text = (self.temp / 'tests-status').read_text(encoding='utf-8')
        return int(dict(line.split('=', 1) for line in text.splitlines())['memory_errors'])

    def test_a_docstring_mention_is_no_memory_error(self) -> None:
        self.assertEqual(self.count('F.', DOCSTRING, 'KeyboardInterrupt'), 0)

    def test_no_mention_is_counted(self) -> None:
        for line in MENTIONS:
            with self.subTest(line=line):
                self.assertEqual(self.count(line), 0)

    def test_a_raised_memory_error_is_counted(self) -> None:
        self.assertEqual(self.count(DOCSTRING, INTERNAL, 'INTERNALERROR> E           assert False'), 1)

    def test_every_raised_form_is_counted(self) -> None:
        for line in RAISED:
            with self.subTest(line=line):
                self.assertEqual(self.count(line), 1)
        self.assertEqual(self.count(*RAISED, *MENTIONS), len(RAISED))


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_says_what_is_counted(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        self.assertIn('raised ``MemoryError`` (#1962)', page)


if __name__ == '__main__':
    unittest.main()
