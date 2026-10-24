# -*- coding: utf-8 -*-
"""#2044: the conda jobs' ``macos-26-intel`` legs install Miniforge.

The step "Conda environment creation and activation" of ``conda-dist`` in
:file:`.github/workflows/cron-conda.yml` and of ``conda`` in
:file:`.github/workflows/create-release.yml` named no installer, so on the Intel
runner setup-miniconda downloaded ``Miniconda3-latest-MacOSX-x86_64.sh``. That
installer is frozen at conda 25.7.0, which conflicts with conda-forge's
conda-content-trust plugin and has no py314 build. The Intel legs now pass
``miniforge-version: latest``; every other leg passes an empty string, which
names no installer, so it keeps the bundled or downloaded Miniconda.

The step's inputs are evaluated per matrix leg with
:func:`tests.project.test_release_gates.evaluate_expression`, cast to a string as
the runner casts a ``with:`` value, and trimmed as ``core.getInput`` trims it.
:func:`installer` then chooses the way setup-miniconda's provider list does: an
``installer-url`` first, then Miniforge when ``miniforge-version`` or
``miniforge-variant`` is non-empty, else Miniconda.

#2123: with Miniforge, the Intel legs broke twice more. Installing the matrix
Python into base rebuilt conda-forge's libmambapy at 2.10.0, which
conda-libmamba-solver 26.10.0 cannot drive, so the Intel legs now leave base's
Python alone, as 3.15 does everywhere; :class:`TestTheIntelLegsKeepBasesPython`
pins that. And conda-build 26.9's rpath relocation failed on the vendored chardet
extensions, so :file:`conda/pypcapkit/meta.yaml` turns it off on osx-64 alone;
:class:`TestOsx64SkipsBinaryRelocation` evaluates that line's selector as
conda-build does, for each leg's platform.

"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests.project.test_python_versions_1660 import script as versions_script
from tests.project.test_release_gates import _as_string, evaluate_expression
from util import release_conda

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

#: The conda jobs, as (workflow, job).
JOBS = (('cron-conda.yml', 'conda-dist'), ('create-release.yml', 'conda'))
STEP = 'Conda environment creation and activation'
ACTION = 'conda-incubator/setup-miniconda'
#: The leg whose Miniconda installer is frozen.
INTEL = 'macos-26-intel'
#: The installer inputs setup-miniconda reads to choose a provider.
INSTALLER_INPUTS = ('installer-url', 'miniconda-version', 'miniforge-variant', 'miniforge-version')


def step(name: 'str', job_id: 'str') -> 'dict[str, Any]':
    """The setup-miniconda step of job ``job_id`` in workflow ``name``."""
    found = [entry for entry in _workflows.steps(name, job_id) if entry.get('name') == STEP]
    if len(found) != 1:
        raise AssertionError(f'{name}: {job_id} has {len(found)} steps named {STEP!r}, not one')
    return found[0]


def legs(name: 'str', job_id: 'str') -> 'list[str]':
    """The ``os`` values of job ``job_id``'s matrix in workflow ``name``."""
    return list(_workflows.job(name, job_id)['strategy']['matrix']['os'])


def inputs(entry: 'dict[str, Any]', os: 'str') -> 'dict[str, str]':
    """Each installer input of ``entry`` as the action receives it on leg ``os``."""
    context = {'matrix': {'os': os}}  # type: dict[str, object]
    given = entry.get('with', {})
    return {key: _as_string(evaluate_expression(str(given[key]), context)).strip() if key in given else ''
            for key in INSTALLER_INPUTS}


def installer(received: 'dict[str, str]') -> 'str':
    """The installer setup-miniconda picks for ``received``, per its provider order."""
    if received['installer-url']:
        return 'installer-url'
    if received['miniforge-version'] or received['miniforge-variant']:
        return 'Miniforge'
    return 'Miniconda'


class TestTheIntelLegsInstallMiniforge(unittest.TestCase):
    """Miniforge on ``macos-26-intel``, and the former installer on every other leg."""

    def test_the_step_is_setup_miniconda(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertTrue(_workflows.pinned(step(name, job_id).get('uses'), ACTION))

    def test_the_intel_leg_installs_the_latest_miniforge(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertIn(INTEL, legs(name, job_id))
                received = inputs(step(name, job_id), INTEL)
                self.assertEqual(installer(received), 'Miniforge')
                self.assertEqual(received['miniforge-version'], 'latest')
                self.assertEqual(received['miniforge-variant'], '')

    def test_the_other_legs_keep_miniconda(self) -> None:
        for name, job_id in JOBS:
            others = [os for os in legs(name, job_id) if os != INTEL]
            with self.subTest(workflow=name, job=job_id):
                self.assertTrue(others, 'no other leg to check')
            for os in others:
                with self.subTest(workflow=name, job=job_id, os=os):
                    self.assertEqual(installer(inputs(step(name, job_id), os)), 'Miniconda')

    def test_no_leg_names_two_installers(self) -> None:
        """setup-miniconda refuses ``miniforge-version`` with ``miniconda-version`` or ``installer-url``."""
        for name, job_id in JOBS:
            for os in legs(name, job_id):
                received = inputs(step(name, job_id), os)
                with self.subTest(workflow=name, job=job_id, os=os):
                    if received['miniforge-version']:
                        self.assertEqual(received['miniconda-version'], '')
                        self.assertEqual(received['installer-url'], '')


def python_input(entry: 'dict[str, Any]', os: 'str', python: 'str') -> 'str':
    """The ``python-version`` setup-miniconda receives on leg ``os`` with ``python``."""
    context = {'matrix': {'os': os, 'python-version': python}}  # type: dict[str, object]
    return _as_string(evaluate_expression(str(entry['with']['python-version']), context)).strip()


class TestTheIntelLegsKeepBasesPython(unittest.TestCase):
    """#2123: no Python install into base on ``macos-26-intel``; the other legs as before."""

    supported = ()  # type: tuple[str, ...]

    @classmethod
    def setUpClass(cls) -> None:
        script = versions_script()
        cls.supported = tuple(script.tier(script.load(), 'cpython', 'supported'))

    def test_the_intel_leg_installs_no_python(self) -> None:
        self.assertTrue(self.supported, 'no supported CPython to check')
        for name, job_id in JOBS:
            for python in self.supported:
                with self.subTest(workflow=name, job=job_id, python=python):
                    self.assertEqual(python_input(step(name, job_id), INTEL, python), '')

    def test_the_other_legs_install_the_matrix_python_but_315(self) -> None:
        for name, job_id in JOBS:
            for os in legs(name, job_id):
                if os == INTEL:
                    continue
                for python in self.supported:
                    with self.subTest(workflow=name, job=job_id, os=os, python=python):
                        expected = '' if python == '3.15' else python
                        self.assertEqual(python_input(step(name, job_id), os, python), expected)


#: The recipe whose ``build:`` section carries the relocation switch.
META = pathlib.Path(__file__).resolve().parents[2] / 'conda' / 'pypcapkit' / 'meta.yaml'
#: A ``key: value  # [selector]`` line, as conda-build reads one.
SELECTED = re.compile(r'^\s*(?P<key>[\w-]+):\s*(?P<value>\S+)\s*#\s*\[(?P<selector>[^\]]+)\]\s*$')
#: conda-build's ``ARCH_MAP``: the subdir arch names that are not selector names.
ARCH_MAP = {'32': 'x86', '64': 'x86_64'}


def selectors(subdir: 'str') -> 'dict[str, bool]':
    """The OS and arch selectors conda-build 26.9's ``get_selectors`` sets for ``subdir``."""
    subdirs = set(release_conda.PLATFORMS.values()) | {subdir, 'linux-aarch64', 'linux-32'}
    names = {'unix': subdir.startswith(('linux-', 'osx-', 'emscripten-'))}
    for os in {entry.split('-')[0] for entry in subdirs}:
        names[os] = subdir.startswith(f'{os}-')
    for arch in {entry.split('-')[1] for entry in subdirs}:
        names[ARCH_MAP.get(arch, arch)] = subdir.endswith(f'-{arch}')
    return names


def holds(selector: 'str', names: 'dict[str, bool]') -> 'bool':
    """Whether ``selector``, of names, ``and``, ``or`` and ``not``, holds; an unknown name raises."""
    def walk(node: 'ast.AST') -> 'bool':
        if isinstance(node, ast.BoolOp):
            values = [walk(value) for value in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not walk(node.operand)
        if isinstance(node, ast.Name):
            return names[node.id]
        raise AssertionError(f'unsupported selector {selector!r}')
    return walk(ast.parse(selector, mode='eval').body)


class TestOsx64SkipsBinaryRelocation(unittest.TestCase):
    """#2123: ``binary_relocation: false`` on osx-64 alone, so the other platforms still relocate."""

    def line(self) -> 're.Match[str]':
        found = [match for match in map(SELECTED.match, META.read_text(encoding='utf-8').splitlines())
                 if match and match['key'] == 'binary_relocation']
        self.assertEqual(len(found), 1, f'{META.name} has {len(found)} selected binary_relocation lines')
        return found[0]

    def test_the_line_turns_relocation_off(self) -> None:
        self.assertEqual(self.line()['value'], 'false')

    def test_it_applies_to_the_intel_legs_platform_alone(self) -> None:
        selector = self.line()['selector']
        for os, subdir in sorted(release_conda.PLATFORMS.items()):
            with self.subTest(os=os, subdir=subdir):
                self.assertEqual(holds(selector, selectors(subdir)), os == INTEL)


if __name__ == '__main__':
    unittest.main()
