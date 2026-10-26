# -*- coding: utf-8 -*-
"""#2206: ``Compat Python 3.8 (KTLO)`` compiles the :file:`util/` scripts held to 3.8.

The project tests that hold a :file:`util/` script to ``requires-python``'s floor
parse it with ``ast.parse(..., feature_version=FLOOR)``, which CPython documents
as best-effort: on 3.14 it accepts parenthesized context managers, relaxed
decorators, ``a[*b]`` and quotes reused inside an f-string, none of which 3.8
compiles. The owner ruled for a real 3.8 compile beside ``Verify package``'s
``compileall`` of :mod:`pcapkit`. Pinned here, of the step ``Compile the
3.8-floor util scripts`` in :file:`.github/workflows/python-compatibility.yml`'s
``compatibility`` job:

* it runs on the floor's leg alone, once the install succeeded, and is masked
  and reported there as ``Verify package`` is;
* it compiles exactly the scripts the floor tests parse at
  :data:`~tests.project.test_requires_python_floor_2051.FLOOR`, found by running
  those tests with :func:`ast.parse` recorded, so a test that adds a script, drops
  one or raises one's floor fails here until the step's list follows;
* a script that does not compile fails it with one annotation at
  ``ANNOTATION_LEVEL`` naming the first error.

The list stays inline in the step, as plain commands do (see
:file:`docs/source/contributing/workflows.rst`, "Workflow Scripts"), and this
module is what keeps it in step with the tests.

"""

from __future__ import annotations

import ast
import functools
import importlib
import inspect
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._workflows import job
from tests.project.test_python_matrix_tiers_1633 import legs
from tests.project.test_release_gates import evaluate_condition
from tests.project.test_requires_python_floor_2051 import FLOOR

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow and runs the tree's own floor tests.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
WORKFLOW = 'python-compatibility.yml'
JOB = 'compatibility'
STEP = 'Compile the 3.8-floor util scripts'
#: The floor as the matrix spells the leg's version.
FLOOR_VERSION = '.'.join(map(str, FLOOR))
#: A :file:`util/` script named in a step's ``run:``.
UTIL_SCRIPT = re.compile(r'\butil/[\w-]+\.py\b')
#: The leg the step is for, as its annotations name it.
LEG = f'Python {FLOOR_VERSION} (KTLO, non-blocking)'


def step() -> 'dict[str, Any]':
    """The compile step of the ``compatibility`` job."""
    found = [spec for spec in job(WORKFLOW, JOB)['steps'] if spec.get('name') == STEP]
    if len(found) != 1:
        raise AssertionError(f'{WORKFLOW} {JOB} holds {len(found)} steps named {STEP!r}')
    return found[0]


@functools.lru_cache(maxsize=None)
def floor_scripts() -> 'frozenset[str]':
    """Each :file:`util/` script a ``tests/project`` test parses with ``feature_version=FLOOR``.

    Every test whose source passes ``feature_version`` runs once with
    :func:`ast.parse` recorded, and each source parsed at :data:`FLOOR` is matched
    to the :file:`util/` file holding that text.

    """
    by_text = {path.read_text(encoding='utf-8'): f'util/{path.name}' for path in UTIL.glob('*.py')}
    parsed = []  # type: list[str]
    real = ast.parse

    def record(source: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
        if kwargs.get('feature_version') == FLOOR:
            parsed.append(source)
        return real(source, *args, **kwargs)

    for path in sorted((ROOT / 'tests' / 'project').glob('test_*.py')):
        if path.name == pathlib.Path(__file__).name or 'feature_version=' not in path.read_text(encoding='utf-8'):
            continue
        module = importlib.import_module(f'tests.project.{path.stem}')
        for case in iterate(unittest.defaultTestLoader.loadTestsFromModule(module)):
            method = getattr(type(case), case._testMethodName)  # pylint: disable=protected-access
            if 'feature_version=' not in inspect.getsource(method):
                continue
            result = unittest.TestResult()
            with mock.patch.object(ast, 'parse', record):
                unittest.TestSuite([case]).run(result)
            if not result.wasSuccessful() or result.skipped:
                raise AssertionError(f'{case.id()} did not pass, so what it parses is unknown: '
                                     f'{result.failures + result.errors + result.skipped}')
    unknown = [source[:80] for source in parsed if source not in by_text]
    if unknown:
        raise AssertionError(f'a floor test parses text no util/ script holds: {unknown}')
    return frozenset(by_text[source] for source in parsed)


def iterate(suite: 'unittest.TestSuite') -> 'list[unittest.TestCase]':
    """Every test case in ``suite``, nested suites flattened."""
    found = []  # type: list[unittest.TestCase]
    for item in suite:
        found.extend(iterate(item) if isinstance(item, unittest.TestSuite) else [item])
    return found


def run_step(cwd: 'pathlib.Path', tmp: 'pathlib.Path') -> 'subprocess.CompletedProcess[str]':
    """The step's ``run:`` in ``cwd``, as the runner's bash runs it, with this interpreter as ``python``."""
    bindir = tmp / 'bin'
    bindir.mkdir()
    (bindir / 'python').symlink_to(sys.executable)
    env = dict(os.environ, PATH=f'{bindir}{os.pathsep}{os.environ["PATH"]}', RUNNER_TEMP=str(tmp),
               ANNOTATION_LEVEL='warning', LEG=LEG)
    return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', step()['run']],
                          cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=60)


class TestTheFloorLegCompilesTheFloorScripts(unittest.TestCase):
    """The 3.8 leg's compile covers what the floor tests can only best-effort check."""

    def test_it_compiles_exactly_the_scripts_the_floor_tests_parse(self) -> None:
        compiled = sorted(set(UTIL_SCRIPT.findall(step()['run'])))
        self.assertIn('util/_actions.py', floor_scripts(), 'the recording sees the helper TestStandardLibraryOnly '
                                                           'parses from setUp')
        self.assertNotIn('util/python_versions.py', floor_scripts(), 'a script held to a higher floor is left out')
        self.assertEqual(compiled, sorted(floor_scripts()))

    def test_it_runs_on_the_floor_leg_alone(self) -> None:
        condition = str(step()['if'])
        for outcome in ('success', 'failure'):
            ran = [leg['python-version'] for leg in legs(WORKFLOW, JOB)
                   if evaluate_condition(condition, {'matrix': leg, 'steps': {'install': {'outcome': outcome}}})]
            with self.subTest(install=outcome):
                self.assertEqual(ran, [FLOOR_VERSION] if outcome == 'success' else [])

    def test_it_is_masked_and_reported_as_verify_package_is(self) -> None:
        verify = next(spec for spec in job(WORKFLOW, JOB)['steps'] if spec.get('name') == 'Verify package')
        compile_util = step()
        self.assertIn('id', compile_util, 'KTLO summary reads only steps with an id')
        for key in ('continue-on-error', 'shell', 'env'):
            with self.subTest(key=key):
                self.assertEqual(compile_util.get(key), verify.get(key))
        self.assertIn('python -m compileall -q', compile_util['run'])


class TestAScriptThatDoesNotCompileFailsTheStep(unittest.TestCase):
    """The step's script, run against a copy of :file:`util/`."""

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tree = self.tmp / 'tree'
        shutil.copytree(UTIL, self.tree / 'util', ignore=shutil.ignore_patterns('__pycache__'))

    def test_the_tree_compiles_quietly(self) -> None:
        result = run_step(self.tree, self.tmp)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def test_a_syntax_error_fails_with_one_annotation(self) -> None:
        target = self.tree / 'util' / 'release_tags.py'
        lines = target.read_text(encoding='utf-8').count('\n')
        with target.open('a', encoding='utf-8') as file:
            file.write('def (:\n')
        result = run_step(self.tree, self.tmp)
        self.assertEqual(result.returncode, 1)
        annotations = [line for line in result.stdout.splitlines() if line.startswith('::')]
        self.assertEqual(annotations, [
            f'::warning title=util/ does not compile on {LEG.replace(",", "%2C")}::1 scripts fail to compile, '
            f'the first at File "util/release_tags.py", line {lines + 1}; see this step\'s log.',
        ])


if __name__ == '__main__':
    unittest.main()
