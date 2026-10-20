# -*- coding: utf-8 -*-
"""#1958: :mod:`pcapkit` imports on PyPy 8.0, whose :mod:`builtins` binds ``NoneType``.

aenum 3.1.17's ``_common`` binds a ``NoneType`` of its own only where the name
raises :exc:`NameError`, and aenum's ``__init__`` then star-imports ``_common``,
whose ``__all__`` lists the name. PyPy 8.0 binds it in :mod:`builtins`, so there
``_common`` binds none and ``import aenum`` failed with ``AttributeError: module
'aenum._common' has no attribute 'NoneType'``, and :mod:`pcapkit` with it.
:mod:`pcapkit.utilities.compat` binds the name in ``aenum._common`` and imports
aenum again.

Each test runs a fresh interpreter, so that this module's own imports have not
loaded aenum already. :class:`TheAenumPremiseTests` binds the builtin on any
interpreter and shows aenum still fails without the fix, which tells when an
aenum release makes it unneeded. :class:`PyPyImportTests` runs on PyPy, where
the shim does.

"""

from __future__ import annotations

import os
import subprocess  # nosec: B404
import sys
import textwrap
import unittest

#: Test tier (#1958): a compat shim behind an implementation gate.
__tier__ = 'ALL'

#: Repository root, first on the child's path, so it imports this tree.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
#: Whether the shim in pcapkit/utilities/compat.py runs here.
ON_PYPY = sys.implementation.name == 'pypy'


def run_child(code: 'str') -> 'subprocess.CompletedProcess[str]':
    """Run ``code`` in a fresh interpreter, with this tree first on its path."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([REPO_ROOT] + [entry for entry in sys.path if entry]),
               PYTHONSAFEPATH='1', PCAPKIT_DEVMODE='0')
    return subprocess.run([sys.executable, '-c', textwrap.dedent(code)],  # nosec: B603
                          cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120, check=False)


class TheAenumPremiseTests(unittest.TestCase):
    """aenum, imported on its own, still fails where :mod:`builtins` binds ``NoneType``."""

    def test_aenum_alone_fails_on_the_builtin(self) -> 'None':
        proc = run_child('''
            import builtins
            builtins.NoneType = type(None)
            try:
                import aenum
            except AttributeError as error:
                print('FAILED', error)
            else:
                print('IMPORTED')
        ''')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split()[0], 'FAILED',
                         'aenum imports with builtins.NoneType bound; the shim in '
                         'pcapkit/utilities/compat.py may no longer be needed')
        self.assertIn("'NoneType'", proc.stdout)


@unittest.skipUnless(ON_PYPY, 'the shim runs on PyPy alone')
class PyPyImportTests(unittest.TestCase):
    """On PyPy, :mod:`pcapkit` imports, and leaves :mod:`builtins` as PyPy has it."""

    def test_pcapkit_imports_and_builtins_keep_none_type(self) -> 'None':
        proc = run_child('''
            import builtins
            import sys
            print('BEFORE', 'NoneType' in vars(builtins))
            import pcapkit
            import aenum
            print('FILE', pcapkit.__file__)
            print('AFTER', 'NoneType' in vars(builtins))
            print('AENUM', aenum.NoneType is type(None), sys.modules['aenum._common'].NoneType is type(None))
        ''')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = dict(line.split(' ', 1) for line in proc.stdout.splitlines() if ' ' in line)
        self.assertTrue(lines['FILE'].startswith(REPO_ROOT), lines['FILE'])
        self.assertEqual(lines['AFTER'], lines['BEFORE'], 'importing pcapkit changed builtins.NoneType')
        self.assertEqual(lines['AENUM'], 'True True')


if __name__ == '__main__':
    unittest.main()
