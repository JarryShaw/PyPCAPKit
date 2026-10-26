# -*- coding: utf-8 -*-
"""#2020: every workflow ``timeout`` that needs GNU's semantics runs GNU's.

Ubuntu 26.04, which ``ubuntu-latest`` serves, ships uutils coreutils 0.10.0
as ``timeout`` and GNU coreutils 9.7 as ``gnutimeout``. uutils' ``--kill-after``
sends SIGKILL with the first signal, and to its child alone: in ``ubuntu:26.04``,
``timeout --signal=INT --kill-after=3s 1 sleep 30`` exits 137 after 1 s where
``gnutimeout`` exits 124, and a grandchild that ignores SIGINT outlives uutils'
kill. ``Run unit tests`` in experimental.yml relies on that grace for pytest's
teardown, so it resolves ``gnutimeout`` where it exists and ``timeout`` otherwise.

A ``timeout`` with no option, ``timeout 60 apt-get update`` as the apt steps run
it, behaves alike under both in the same image: exit 124, and its child's own
children end with it. So the rule here is that a ``timeout`` given any option runs
through that resolution, in every workflow. The steps' shell lives in ``util/``
scripts (#1967), so the rule covers what those run too: no string in one is an
optioned ``timeout`` command, and no command one builds as a sequence,
``['sudo', 'timeout', '60', 'apt-get', 'update']`` as :file:`util/apt_packages.py`
does, gives ``timeout`` an option.

"""

from __future__ import annotations

import ast
import os
import pathlib
import re
import shutil
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._support import bash_argv
from tests.project.test_resource_monitor_1740 import DEFAULT, TESTS, sh, step

if TYPE_CHECKING:
    from typing import Iterator

#: How the tests step resolves GNU's ``timeout``, and how it runs it.
RESOLVE = 'gnu_timeout=$(command -v gnutimeout || command -v timeout)\n'
RUN = '"$gnu_timeout" --signal=INT --kill-after=3m 110m "$@"\n'
#: ``timeout`` run as a command and given an option, which only GNU's honours as GNU does.
OPTIONED = re.compile(r'(?<![\w$"/.-])timeout\s+-')
#: A shell comment, a whole line of one or one after a space.
COMMENT = re.compile(r'(?m)(^|\s)#.*$')
#: The ``util/`` scripts the workflows run (#1967).
UTIL = pathlib.Path(__file__).resolve().parents[2] / 'util'
#: The programs whose options only GNU's honours as GNU does.
TIMEOUTS = frozenset({'timeout', '/usr/bin/timeout'})


def scripts() -> 'Iterator[tuple[str, str, str]]':
    """Every ``run:`` script of every workflow, as (file, step, script with comments stripped)."""
    for path in sorted(_workflows.WORKFLOWS.glob('*.yml')):
        for job_id, job in (_workflows.load(path.name).get('jobs') or {}).items():
            for entry in job.get('steps') or ():
                if 'run' in entry:
                    name = f"{job_id}: {entry.get('name') or entry.get('id') or entry['run'][:40]}"
                    yield path.name, name, COMMENT.sub(r'\1', entry['run'])


def optioned_commands(source: 'str') -> 'Iterator[tuple[int, str]]':
    """Each ``(line, text)`` in Python ``source`` that runs ``timeout`` with an option.

    A string holding an optioned ``timeout`` command, as a shell line would, or a
    list or tuple display whose element after a :data:`TIMEOUTS` one is a string
    starting with ``-`` or a starred, so unknown, expression.

    """
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and OPTIONED.search(node.value):
            yield node.lineno, node.value
        elif isinstance(node, (ast.List, ast.Tuple)):
            for here, after in zip(node.elts, node.elts[1:]):
                if isinstance(here, ast.Constant) and here.value in TIMEOUTS and (
                        isinstance(after, ast.Starred)
                        or isinstance(after, ast.Constant) and str(after.value).startswith('-')):
                    yield node.lineno, ast.dump(node)


def timeout_commands(source: 'str') -> 'int':
    """How many list or tuple displays in ``source`` run one of :data:`TIMEOUTS`."""
    return sum(1 for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.List, ast.Tuple))
               and any(isinstance(item, ast.Constant) and item.value in TIMEOUTS for item in node.elts))


class TestNoUtilScriptRunsAnOptionedTimeout(unittest.TestCase):
    """#1967: the scripts the steps run keep to the same rule as the steps' shell."""

    def test_the_detector(self) -> None:
        for source in ("call(['sudo', 'timeout', '-k', '3', '60', 'x'])", "('timeout', '--signal=INT', '1')",
                       "['timeout', *options, '60']", "script = 'sudo timeout -s INT 1 x'"):
            with self.subTest(source=source):
                self.assertTrue(list(optioned_commands(source)))
        for source in ("call(['sudo', 'timeout', str(BOUND), 'apt-get', 'update'])", "['timeout', '60', '-x']",
                       "'sudo timeout 60 apt-get update'", "['gnutimeout', '-k', '1', '1']"):
            with self.subTest(source=source):
                self.assertEqual(list(optioned_commands(source)), [])

    def test_every_util_script(self) -> None:
        found = 0
        for path in sorted(UTIL.glob('*.py')):
            source = path.read_text(encoding='utf-8')
            found += timeout_commands(source)
            with self.subTest(script=path.name):
                self.assertEqual(list(optioned_commands(source)), [])
        # util/apt_packages.py's update and install bounds, so the scan is not blind.
        self.assertGreaterEqual(found, 2)


class TestNoWorkflowRunsAnOptionedTimeoutDirectly(unittest.TestCase):

    def test_the_pattern(self) -> None:
        for text in ('timeout --signal=INT 1 x', 'sudo timeout -k 3 1 x', 'set -- prlimit timeout -s INT 1 x'):
            with self.subTest(text=text):
                self.assertRegex(text, OPTIONED)
        for text in ('"$gnu_timeout" --signal=INT 1 x', 'sudo timeout 60 apt-get update', 'command -v timeout)',
                     '/usr/bin/gnutimeout -k 1 1 x', 'warn "tests timed out" "timeout sent SIGINT (exit 124)"'):
            with self.subTest(text=text):
                self.assertNotRegex(text, OPTIONED)

    def test_every_workflow(self) -> None:
        seen = 0
        for name, entry, script in scripts():
            seen += 1
            with self.subTest(workflow=name, step=entry):
                self.assertIsNone(OPTIONED.search(script), script)
                if '$gnu_timeout' in script:
                    self.assertIn(RESOLVE, script)
                    self.assertLess(script.index(RESOLVE), script.index('"$gnu_timeout"'))
        self.assertTrue(seen)

    def test_a_direct_timeout_fails_it(self) -> None:
        script = step(TESTS)['run']
        self.assertIn(RUN, script)
        self.assertRegex(script.replace(RUN, 'timeout' + RUN[len('"$gnu_timeout"'):]), OPTIONED)

    def test_the_tests_step_resolves_before_it_runs(self) -> None:
        script = step(TESTS)['run']
        self.assertEqual(script.count(RESOLVE), 1)
        self.assertEqual(script.count('"$gnu_timeout"'), 1)
        self.assertLess(script.index(RESOLVE), script.index(RUN))


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheTestsStepRunsGNUs(unittest.TestCase):
    """The resolution alone, then the whole step, with ``sudo``, ``python`` and ``gnutimeout`` stubbed."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2020-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bindir = self.tmp / 'bin'
        self.bindir.mkdir()
        self.calls = self.tmp / 'calls'

    def stub(self, name: 'str', body: 'str', bindir: 'pathlib.Path | None' = None) -> 'str':
        path = (bindir or self.bindir) / name
        path.write_text('#!/bin/sh\n' + body, encoding='utf-8')
        path.chmod(0o755)
        return str(path)

    def resolve(self, path: 'str') -> 'str':
        # bash by its own path, since ``path`` holds the stubs alone.
        result = sh(RESOLVE + 'echo "$gnu_timeout"\n', {'PATH': path},
                    tuple(bash_argv('-e', executable=str(shutil.which('bash')))))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_gnutimeout_first_then_timeout(self) -> None:
        only = self.tmp / 'only'
        only.mkdir()
        plain = self.stub('timeout', 'exit 0\n', only)
        self.assertEqual(self.resolve(str(only)), plain)
        gnu = self.stub('gnutimeout', 'exit 0\n', only)
        self.assertEqual(self.resolve(str(only)), gnu)

    def test_the_step_runs_gnutimeout_where_it_exists(self) -> None:
        temp = self.tmp / 'temp'
        temp.mkdir()
        (temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        vmstat = self.tmp / 'vmstat'
        vmstat.write_text('oom_kill 0\n', encoding='utf-8')
        real = shutil.which('gnutimeout') or shutil.which('timeout')
        self.stub('gnutimeout', f'echo "gnutimeout $*" >> {self.calls}\nexec {real} "$@"\n')
        self.stub('sudo', 'exit 1\n')
        self.stub('python', 'exit 0\n')
        env = dict(os.environ, RUNNER_TEMP=str(temp), GITHUB_WORKSPACE=str(self.tmp), WORKERS='3',
                   GRAAL_PYTHON_VM_ARGS='', SHARDS='', LATEST_TIER='',
                   PATH=str(self.bindir) + os.pathsep + os.environ.get('PATH', ''))
        self.assertEqual(shutil.which('sudo', path=env['PATH']), str(self.bindir / 'sudo'))
        result = sh(step(TESTS)['run'].replace('/proc/vmstat', str(vmstat)), env, DEFAULT)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(calls), 1, calls)
        self.assertTrue(calls[0].startswith('gnutimeout --signal=INT --kill-after=3m 110m python -m pytest '), calls)


if __name__ == '__main__':
    unittest.main()
