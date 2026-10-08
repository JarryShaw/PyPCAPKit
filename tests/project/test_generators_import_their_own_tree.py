# -*- coding: utf-8 -*-
"""The sample generators build from their own tree's :mod:`pcapkit`.

GitHub issue #1343. Run as a script, a generator's ``sys.path[0]`` is
:file:`examples/generators/`, not the tree root, so ``import pcapkit`` fell
through to whatever was installed. An editable install pins one checkout, so a
worktree's generators silently built their fixtures from *that* checkout's
library: 257 captured cases instead of 266, with nothing failing.

Each generator that imports :mod:`pcapkit` now puts its own tree root first on
:data:`sys.path`. The probe below proves it from a scratch worktree, whose path
no install points at, and with ``PYTHONPATH`` and ``PYTHONSAFEPATH`` stripped.
The probe script lives outside the tree, so -- exactly as when a generator is run
as a script -- nothing but the generator itself can put the tree on the path.

The second half of the issue is that the shortfall was silent:
``options.generate()`` recorded each failing case and carried on. It now raises
once the captures it could build are written, which
:meth:`OptionsGenerateTests.test_left_out_case_raises` pins.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]
#: Directory holding the generators.
GENERATORS = ROOT / 'examples' / 'generators'
#: A top-level or function-local import of :mod:`pcapkit`.
IMPORTS_PCAPKIT = re.compile(r'^\s*(?:from|import)\s+pcapkit\b', re.MULTILINE)

#: Executes a generator's module body without its ``__main__`` block, then says
#: where :mod:`pcapkit` resolves from. Kept outside the tree under test.
PROBE = '''\
import runpy, sys
runpy.run_path(sys.argv[1], run_name='_probe_1343')
import pcapkit
print(pcapkit.__file__)
'''


def _git(*args: 'str') -> 'subprocess.CompletedProcess[str]':
    return subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True,
                          text=True, check=False, timeout=120)


def _generators() -> 'list[pathlib.Path]':
    """:file:`make_samples.py`, plus every sibling that imports :mod:`pcapkit`."""
    return sorted(path for path in GENERATORS.glob('*.py')
                  if path.name == 'make_samples.py'
                  or IMPORTS_PCAPKIT.search(path.read_text(encoding='utf-8')))


class OwnTreeImportTests(unittest.TestCase):
    """Run from a scratch worktree, every generator imports that worktree."""

    scratch: 'pathlib.Path'
    tree: 'pathlib.Path'

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which('git') is None:
            raise unittest.SkipTest('git is not installed')
        if _git('rev-parse', '--is-inside-work-tree').stdout.strip() != 'true':
            raise unittest.SkipTest('not a git work tree')

        cls.scratch = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-1343-'))
        cls.tree = cls.scratch / 'tree'
        added = _git('worktree', 'add', '--detach', str(cls.tree), 'HEAD')
        if added.returncode != 0:
            shutil.rmtree(cls.scratch, ignore_errors=True)
            raise unittest.SkipTest(f'git worktree add failed: {added.stderr.strip()}')

        # Test the generators as they stand in this tree, committed or not.
        for path in GENERATORS.glob('*.py'):
            shutil.copy2(path, cls.tree / 'examples' / 'generators' / path.name)
        (cls.scratch / 'probe.py').write_text(PROBE, encoding='utf-8')

    @classmethod
    def tearDownClass(cls) -> None:
        # ``remove`` drops this worktree's own admin entry. No ``prune``: that
        # would touch every other worktree of the repository too.
        _git('worktree', 'remove', '--force', str(cls.tree))
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def test_generators_resolve_pcapkit_inside_their_tree(self) -> None:
        """``pcapkit.__file__`` lies in the scratch worktree, from any cwd."""
        env = {key: value for key, value in os.environ.items()
               if key not in ('PYTHONPATH', 'PYTHONSAFEPATH')}
        expected = (self.tree / 'pcapkit').resolve()

        generators = _generators()
        self.assertIn('options.py', [path.name for path in generators])
        for path in generators:
            for cwd in (self.scratch, pathlib.Path('/')):
                with self.subTest(generator=path.name, cwd=str(cwd)):
                    result = subprocess.run(
                        [sys.executable, str(self.scratch / 'probe.py'),
                         str(self.tree / 'examples' / 'generators' / path.name)],
                        cwd=cwd, env=env, capture_output=True, text=True,
                        check=False, timeout=300)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    resolved = pathlib.Path(result.stdout.strip().splitlines()[-1]).resolve()
                    self.assertEqual(resolved.parent, expected,
                                     f'{path.name} imported pcapkit from {resolved}')


class OptionsGenerateTests(unittest.TestCase):
    """``options.generate()`` fails rather than writing a smaller fixture set."""

    def test_left_out_case_raises(self) -> None:
        if importlib.util.find_spec('scapy') is None:
            self.skipTest('options.generate() needs scapy')

        spec = importlib.util.spec_from_file_location(
            'pcapkit_samples_options_1343', GENERATORS / 'options.py')
        assert spec is not None and spec.loader is not None
        options = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(options)

        family = next(family for family in options.FAMILIES if family.capture is not None)
        case = options.Case(family.label, 0, 'Probe', {})
        left_out = options.Outcome(case, 'CONSTRUCT', 'ValueError: probe', None, ())

        with mock.patch.object(options, 'outcomes', lambda: iter([left_out])), \
                tempfile.TemporaryDirectory(prefix='pcapkit-1343-') as dest:
            with self.assertRaisesRegex(RuntimeError, r'1 case\(s\) left out'):
                options.generate(pathlib.Path(dest))


if __name__ == '__main__':
    unittest.main()
