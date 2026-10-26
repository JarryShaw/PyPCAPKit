# -*- coding: utf-8 -*-
"""#2306: every ``bash`` a test starts skips the startup files, as a runner's does.

A ``bash -c`` whose parent is a top-level shell sources :file:`~/.bashrc` when
``SSH_CLIENT`` is set or its stdin is a socket. Run from an SSH session, that
file's output and ``PATH`` leak into the step under test: a stray line in output a
test compares, or the real ``gh`` found ahead of a stub. GitHub Actions runs a
``shell: bash`` step as ``bash --noprofile --norc``, and the tests run theirs
through :func:`tests._support.bash_argv`, which does the same. Pinned here:

* :class:`TestTheHelperSkipsTheStartupFiles`: with a socket on stdin and
  ``SSH_CLIENT`` set, a plain ``bash -c`` sources a stand-in :file:`~/.bashrc`, and
  the helper's argv does not;
* :class:`TestEveryBashGoesThroughTheHelper`: no module under :file:`tests/` spells
  out a ``bash`` argv of its own. This module is exempt, since its control run is
  the plain ``bash -c`` the others must not be.

"""

from __future__ import annotations

import ast
import os
import pathlib
import shutil
import socket
import subprocess  # nosec: B404
import tempfile
import unittest

from tests import _support

#: Test tier (#1958): reads the test sources and runs ``bash``.
__tier__ = 'LATEST'

TESTS = pathlib.Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')

#: What the stand-in :file:`~/.bashrc` prints, so a run that sourced it shows it.
MARKER = 'pcapkit-2306-bashrc-ran'


@unittest.skipIf(os.name == 'nt' or BASH is None, 'needs bash and a POSIX socket on stdin')
class TestTheHelperSkipsTheStartupFiles(unittest.TestCase):
    """The flags :func:`~tests._support.bash_argv` adds are what keeps the bashrc out."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2306-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        home = pathlib.Path(tmp.name)
        (home / '.bashrc').write_text(f'echo {MARKER}\n', encoding='utf-8')
        # SHLVL 0 makes the child a top-level shell, as one sshd starts is.
        self.env = {'HOME': str(home), 'PATH': os.environ.get('PATH', ''),
                    'SSH_CLIENT': '192.0.2.1 50000 22', 'SHLVL': '0'}

    def run_bash(self, argv: 'list[str]') -> 'str':
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        result = subprocess.run(argv, stdin=theirs, env=self.env, capture_output=True,  # nosec: B603
                                text=True, check=False, timeout=_support.scale_timeout(30))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_a_plain_bash_sources_the_bashrc(self) -> None:
        self.assertIn(MARKER, self.run_bash([str(BASH), '-c', 'echo step']))

    def test_the_helper_does_not(self) -> None:
        self.assertEqual(self.run_bash(_support.bash_argv('-e', '-c', 'echo step', executable=str(BASH))), 'step\n')


def names_bash(node: 'ast.expr') -> 'bool':
    """Whether ``node`` is ``'bash'``, a path to it, or ``BASH`` as the tests resolve it."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.replace('\\', '/').rsplit('/', 1)[-1] in ('bash', 'bash.exe')
    if isinstance(node, ast.Name):
        return node.id == 'BASH'
    if isinstance(node, ast.Call) and node.args:
        callee = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, 'attr', None)
        return callee in ('str', 'which') and names_bash(node.args[0])
    if isinstance(node, ast.BoolOp):
        return any(names_bash(value) for value in node.values)
    return False


def is_bash_argv(node: 'ast.AST') -> 'bool':
    """A list or tuple opening with a ``bash``, and not a list of tool names."""
    if not (isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) > 1 and names_bash(node.elts[0])):
        return False
    return not all(isinstance(item, ast.Constant)
                   and (item.value is None or isinstance(item.value, str) and not item.value.startswith('-'))
                   for item in node.elts[1:])


class TestEveryBashGoesThroughTheHelper(unittest.TestCase):
    """A ``bash`` argv written out by hand is one that can drop the flags."""

    def test_no_module_spells_out_a_bash_argv(self) -> None:
        found = []
        for path in sorted(TESTS.rglob('*.py')):
            if path.resolve() == pathlib.Path(__file__).resolve():
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'), str(path))
            found.extend(f'{path.relative_to(TESTS.parent).as_posix()}:{node.lineno}: {ast.unparse(node)}'
                         for node in ast.walk(tree) if is_bash_argv(node))
        self.assertEqual(found, [], 'build these with tests._support.bash_argv')

    def test_the_scan_sees_the_shapes_it_replaced(self) -> None:
        for source in ("['bash', '-e', '-c', script]", "(str(BASH), '-e')", "[BASH or 'bash', *flags]",
                       "['/bin/bash', str(path), py]", "[str(shutil.which('bash')), '-c', 'true']"):
            with self.subTest(source=source):
                self.assertTrue(is_bash_argv(ast.parse(source, mode='eval').body))
        for source in ("('bash', 'timeout', 'prlimit')", "('bash', None)", "bash_argv('-e', '-c', script)"):
            with self.subTest(source=source):
                self.assertFalse(is_bash_argv(ast.parse(source, mode='eval').body))


if __name__ == '__main__':
    unittest.main()
