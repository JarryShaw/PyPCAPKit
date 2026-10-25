# -*- coding: utf-8 -*-
"""#1660: the Python version tiers are declared once, in :file:`.github/python-versions.toml`.

Before #1660 every matrix spelt its versions out, so a tier change -- 3.11
reaching end-of-life, a new pre-release -- meant editing many files by hand.
:file:`util/python_versions.py` reads the file instead, and each workflow takes
its matrices, and each single-interpreter job its ``latest``, from that script's
step outputs. These things are pinned here:

* **The file and the script.** :func:`python_versions.load` rejects a malformed
  file, ``latest`` is the newest supported CPython (the owner's ruling on
  #1661), each exemption's reason is the comment above it, and the script runs
  on the ``python3`` of every runner that runs it.
* **Nothing moved.** The tiers as this change introduced them expand to exactly
  the legs, in the same order, that ``main`` spelt out at :data:`MAIN`, apart
  from the one deliberate move: the coverage leg and the ``gate`` from 3.14 to
  ``latest``, 3.15. Job-name templates are compared too, since rulesets match
  check names literally. Where git still has :data:`MAIN`, the recorded
  matrices are read back against it.
* **Every version comes from the file.** No workflow pins a Python version --
  in a setup action's input, a matrix, a comparison, a job name, an ``env``
  value, or a wheel or conda tag and version loop in a script -- unless the
  file's ``exemptions`` list that pin with its value and its reason, and every
  exemption still matches a pin. Every single-interpreter job reads ``latest``,
  and Create Release's Anaconda check is run to show it counts what the file
  lists. (Expected outcomes per engine and version in ``engine-tests``' cell
  script are facts about the engines, not pins, and are not read.)
* **The prose follows the file.** The classifiers, README, SECURITY.md, the
  docs' version lists, the bug-report template, and the comments and docs
  naming the coverage leg's or the sdist leg's version. None of
  them is a workflow: the weekly job that regenerates them
  (:file:`util/update_python_versions.py`) cannot push one, so workflow
  comments name the tiers instead, as
  :mod:`tests.project.test_python_versions_update_1660` pins.

The script reads the file with :mod:`tomllib`, in the standard library from 3.11,
so every test that reads it skips on the KTLO interpreters, 3.8-3.10 -- the
:mod:`tests.project.test_python_matrix_tiers_1633` and
:mod:`tests.project.test_ktlo_legs_stay_green_1672` modules and
:mod:`tests.project.test_ci_timing` whole, since they read it on import. What
they check is the repository's files, which read the same on any interpreter.

"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows

try:
    import tomllib
except ImportError:  # Python 3.10 and older
    tomllib = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
SCRIPT = ROOT / 'util' / 'python_versions.py'
TIER_FILE = ROOT / '.github' / 'python-versions.toml'
#: How every workflow runs the script.
SCRIPT_STEP = 'python3 util/python_versions.py --github-output'
#: Why a test that reads the tier file skips where :mod:`tomllib` is missing.
NO_TOMLLIB = 'tomllib, which reads .github/python-versions.toml, needs Python 3.11+'


def load_script() -> 'Any':
    """:file:`util/python_versions.py`, which is a script and not a package."""
    spec = importlib.util.spec_from_file_location('python_versions', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


#: Loaded once, so a missing script fails each test rather than the import. It
#: imports tomllib, so it is not loaded at all without one.
try:
    python_versions = None if tomllib is None else load_script()
except FileNotFoundError:  # pragma: no cover
    python_versions = None


def script() -> 'Any':
    """The script; a test that needs it skips without :mod:`tomllib`, as on 3.8-3.10."""
    if tomllib is None:
        raise unittest.SkipTest(NO_TOMLLIB)
    if python_versions is None:
        raise AssertionError(f'{SCRIPT.relative_to(ROOT)} is missing')
    return python_versions


def live_outputs() -> 'dict[str, str]':
    """Every output the script writes for the file as it stands."""
    return script().outputs(script().load())


def workflow(name: 'str') -> 'dict[str, Any]':
    """``name`` parsed, or the test skipped when PyYAML (the ``test`` extra) is absent."""
    return _workflows.load(WORKFLOWS / name)


def has_main() -> 'bool':
    """Whether this clone holds :data:`MAIN`; a shallow CI checkout does not."""
    found = subprocess.run(['git', 'cat-file', '-e', f'{MAIN}^{{commit}}'], cwd=ROOT, capture_output=True, check=False)
    return not found.returncode


def workflow_at_main(name: 'str') -> 'dict[str, Any]':
    """``name`` as it stood at :data:`MAIN`."""
    text = subprocess.run(['git', 'show', f'{MAIN}:.github/workflows/{name}'], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout
    return _workflows.loads(text)


def workflows(load: 'Callable[[str], dict[str, Any]]' = workflow) -> 'Iterator[tuple[str, dict[str, Any]]]':
    for path in sorted(WORKFLOWS.glob('*.yml')):
        if load is workflow_at_main and subprocess.run(
                ['git', 'cat-file', '-e', f'{MAIN}:.github/workflows/{path.name}'], cwd=ROOT,
                capture_output=True, check=False).returncode:
            continue  # added since MAIN, as cron-python-versions.yml was (#1660)
        yield path.name, load(path.name)


#: ``${{ needs.J.outputs.O }}`` or ``${{ steps.S.outputs.O }}``, optionally in ``fromJSON()``.
READ = re.compile(r'\$\{\{\s*(fromJSON\(\s*)?((?:needs|steps)\.[\w-]+\.outputs\.[\w-]+)\s*\)?\s*\}\}')
REF = re.compile(r'(needs|steps)\.([\w-]+)\.outputs\.([\w-]+)')


def script_output(name: 'str', job_id: 'str', ref: 'str') -> 'str':
    """The script output that reference ``ref``, read in job ``job_id``, ends at.

    A ``needs`` reference is followed through the job it names, which must be in
    ``job_id``'s ``needs``, to that job's own ``outputs``; a ``steps`` one must
    name a step of the job that runs :data:`SCRIPT_STEP`.

    """
    jobs = workflow(name)['jobs']
    kind, target, output = REF.fullmatch(ref).groups()  # type: ignore[union-attr]
    if kind == 'needs':
        needs = jobs[job_id].get('needs', [])
        assert target in ([needs] if isinstance(needs, str) else needs), f'{name} {job_id} does not need {target}'
        value = jobs[target]['outputs'][output]
        inner = READ.fullmatch(value)
        assert inner is not None and not inner.group(1), f'{name} {target}.outputs.{output} is {value!r}'
        return script_output(name, target, inner.group(2))
    step = next(step for step in jobs[job_id]['steps'] if step.get('id') == target)
    assert step['run'].strip() == SCRIPT_STEP, f'{name} {job_id} step {target} runs {step["run"]!r}'
    return output


def resolve(name: 'str', job_id: 'str', text: 'Any', values: 'Optional[dict[str, str]]' = None) -> 'Any':
    """What ``text`` reads from the script's outputs, or :data:`None` if it reads none."""
    match = READ.fullmatch(str(text).strip())
    if match is None:
        return None
    output = script_output(name, job_id, match.group(2))
    values = live_outputs() if values is None else values
    assert output in values, f'{name} {job_id} reads {output!r}, which the script does not write'
    return json.loads(values[output]) if match.group(1) else values[output]


def matrix(name: 'str', job_id: 'str', values: 'Optional[dict[str, str]]' = None) -> 'dict[str, Any]':
    """Job ``job_id``'s ``strategy.matrix``, each expression read from the script."""
    raw = workflow(name)['jobs'][job_id]['strategy']['matrix']
    if isinstance(raw, str):
        found = resolve(name, job_id, raw, values)
        assert isinstance(found, dict), f'{name} {job_id} matrix is {raw!r}'
        return found
    return {key: (resolve(name, job_id, value, values) if isinstance(value, str) else value)
            for key, value in raw.items()}


def legs(spec: 'dict[str, Any]') -> 'list[dict[str, Any]]':
    """The matrix combinations GitHub expands ``spec`` to, in its order.

    The base axes' product, then each ``include`` entry: merged into every
    combination whose original values it matches, or added as one of its own --
    GitHub's documented ``include`` rule, which is what lets ``ktlo: true`` mark
    an existing leg as well as add a new one.

    """
    spec = dict(spec)
    include = spec.pop('include', [])
    combos = [{}]  # type: list[dict[str, Any]]
    for key, values in spec.items():
        combos = [dict(combo, **{key: str(value)}) for combo in combos for value in values]
    for entry in include:
        entry = {key: str(value) if key in spec else value for key, value in entry.items()}
        matched = [combo for combo in combos
                   if all(combo.get(key) == value for key, value in entry.items() if key in spec)]
        added = False
        for combo in matched:
            if all(key in spec or key not in combo for key in entry):
                combo.update(entry)
                added = True
        if not added:
            combos.append(dict(entry))
    return combos


def setups(spec: 'dict[str, Any]') -> 'list[dict[str, Any]]':
    """A job's setup-python and setup-miniconda steps."""
    return [step for step in spec.get('steps', [])
            if str(step.get('uses', '')).startswith(('actions/setup-python@', 'conda-incubator/setup-miniconda@'))]


#: The last commit before the file: its matrices are what the file must reproduce.
MAIN = '1024109fc1a8d16d67d24d5ed5af2c57bb81076b'
#: Every Python matrix as MAIN spelt it out, as (workflow, job): ``strategy.matrix``.
SUPPORTED_AT_MAIN = ['3.11', '3.12', '3.13', '3.14', '3.15']
KTLO_AT_MAIN = [{'python-version': '3.7', 'ktlo': True, 'os': 'ubuntu-22.04'},
                {'python-version': '3.8', 'ktlo': True, 'os': 'ubuntu-24.04'},
                {'python-version': '3.9', 'ktlo': True, 'os': 'ubuntu-24.04'},
                {'python-version': '3.10', 'ktlo': True}]
CONDA_AT_MAIN = {'os': ['macos-latest', 'ubuntu-latest'], 'python-version': SUPPORTED_AT_MAIN}
#: The conda jobs' ``os`` axis since #1822, which added the Intel macOS runner,
#: and #2060, which added the Windows one.
CONDA_JOBS = (('create-release.yml', 'conda'), ('cron-conda.yml', 'conda-dist'))
CONDA_OS = ['macos-latest', 'macos-26-intel', 'ubuntu-latest', 'windows-latest']
MAIN_MATRICES = {
    ('unit-tests.yml', 'test'): {
        'python-version': SUPPORTED_AT_MAIN,
        'include': [{'python-version': '3.14', 'coverage': True}] + KTLO_AT_MAIN},
    ('unit-tests.yml', 'integration'): {'python-version': SUPPORTED_AT_MAIN, 'include': KTLO_AT_MAIN},
    ('unit-tests.yml', 'pypcap-parity'): {
        'python-version': ['3.10', '3.11'], 'include': [{'python-version': '3.10', 'ktlo': True}]},
    ('python-compatibility.yml', 'compatibility'): {'python-version': SUPPORTED_AT_MAIN, 'include': KTLO_AT_MAIN},
    ('create-release.yml', 'pypi'): {
        'python-version': SUPPORTED_AT_MAIN + ['pypy3.11'],
        'include': [{'python-version': '3.10', 'ktlo': True}, {'python-version': 'pypy3.10', 'ktlo': True}]},
    ('create-release.yml', 'conda'): CONDA_AT_MAIN,
    ('cron-conda.yml', 'conda-dist'): CONDA_AT_MAIN,
}
#: engine-tests' two setup inputs at MAIN, (KTLO step, supported step), and its loops.
ENGINES_AT_MAIN = ('3.10', '\n'.join(SUPPORTED_AT_MAIN))
#: Each matrix job's name template at MAIN, which must not change.
TEMPLATES_AT_MAIN = {
    ('unit-tests.yml', 'test'): "Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO)' || '' }}",
    ('unit-tests.yml', 'integration'):
        "Integration Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO)' || '' }}",
    ('unit-tests.yml', 'pypcap-parity'):
        "PyPCAP/PyPCAPFile parity Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO)' || '' }}",
    ('python-compatibility.yml', 'compatibility'):
        "Compat Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO)' || '' }}",
    ('create-release.yml', 'pypi'):
        "PyPI distribution for Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO)' || '' }}",
    ('create-release.yml', 'conda'):
        'Conda deployment (release) on ${{ matrix.os }} with Python ${{ matrix.python-version }}',
    ('cron-conda.yml', 'conda-dist'):
        'Conda deployment (update) on ${{ matrix.os }} with Python ${{ matrix.python-version }}',
}
#: Each unit-tests.yml job MAIN ran KTLO legs in, and the job those legs run in
#: since #1738, which nothing gating waits on.
KTLO_TWINS = {('unit-tests.yml', 'test'): 'test-ktlo', ('unit-tests.yml', 'integration'): 'integration-ktlo',
              ('unit-tests.yml', 'pypcap-parity'): 'pypcap-parity-ktlo'}
#: Ruleset 23497679's required contexts at MAIN.
REQUIRED_AT_MAIN = {'Required checks passed'} | {f'Compat Python {v}' for v in SUPPORTED_AT_MAIN}
#: The tiers MAIN's matrices encode, as this change first wrote them into the file.
TIERS_AT_MAIN = {
    'latest': '3.15',
    'versions': {
        'cpython': {'3.7': {'tier': 'ktlo', 'runner': 'ubuntu-22.04'},
                    '3.8': {'tier': 'ktlo', 'runner': 'ubuntu-24.04'},
                    '3.9': {'tier': 'ktlo', 'runner': 'ubuntu-24.04'},
                    '3.10': {'tier': 'ktlo'},
                    **{version: {'tier': 'supported'} for version in SUPPORTED_AT_MAIN}},
        'pypy': {'pypy3.10': {'tier': 'ktlo'}, 'pypy3.11': {'tier': 'supported'}},
    },
}


#: #1958, the owner's ruling E: every implementation runs the ``ALL`` tier, so
#: ``test`` and ``integration`` gained PyPy's supported legs, after CPython's, and
#: their KTLO twins PyPy's KTLO ones -- the one move besides ``latest``'s. Read
#: from :data:`TIERS_AT_MAIN`, as each leg is a version the file lists.
PYPY_TESTED = (('unit-tests.yml', 'test'), ('unit-tests.yml', 'integration'))
PYPY_SUPPORTED = [{'python-version': version}
                  for version, entry in TIERS_AT_MAIN['versions']['pypy'].items() if entry['tier'] == 'supported']
PYPY_KTLO = [{'python-version': version, 'ktlo': True}
             for version, entry in TIERS_AT_MAIN['versions']['pypy'].items() if entry['tier'] == 'ktlo']


def with_pypy(name: 'str', job_id: 'str', expected: 'list[dict[str, Any]]') -> 'list[dict[str, Any]]':
    """``expected``, :data:`MAIN`'s legs of a job, with the PyPy legs #1958 added to it."""
    if (name, job_id) not in PYPY_TESTED:
        return expected
    supported = [leg for leg in expected if leg.get('ktlo') is not True]
    ktlo = [leg for leg in expected if leg.get('ktlo') is True]
    return supported + [dict(leg) for leg in PYPY_SUPPORTED] + ktlo + [dict(leg) for leg in PYPY_KTLO]


#: The experimental legs' job name (#1732), which ``test``'s was on those legs from #1660.
EXPERIMENTAL_TEMPLATE = 'Python ${{ matrix.python-version }} (experimental)'


def render(template: 'str', leg: 'dict[str, Any]') -> 'str':
    """A matrix job's name for one leg, for the three expression shapes these names use."""
    name = template.replace("${{ matrix.ktlo && ' (KTLO)' || '' }}", ' (KTLO)' if leg.get('ktlo') is True else '')
    name = name.replace("${{ matrix.experimental && ' (experimental)' || '' }}",
                        ' (experimental)' if leg.get('experimental') is True else '')
    name = re.sub(r'\$\{\{ matrix\.([\w-]+) \}\}', lambda match: str(leg[match.group(1)]), name)
    assert '${{' not in name, name
    return name


def toml(value: 'Any') -> 'str':
    """``value`` as a TOML value, every table inline; JSON's string escapes are TOML's."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, dict):
        return '{%s}' % ', '.join(f'{json.dumps(key)} = {toml(item)}' for key, item in value.items())
    if isinstance(value, list):
        return '[%s]' % ', '.join(map(toml, value))
    raise TypeError(f'no TOML for {value!r}')


def write_tiers(directory: 'pathlib.Path', data: 'dict[str, Any]') -> 'pathlib.Path':
    """``data`` written as a tier file, one top-level key per line."""
    path = directory / 'python-versions.toml'
    path.write_text(''.join(f'{json.dumps(key)} = {toml(value)}\n' for key, value in data.items()), encoding='utf-8')
    return path


#: :mod:`tomllib` is in the standard library from this version.
TOMLLIB_FLOOR = (3, 11)
#: The ``python3`` each runner label a job runs the script on puts on ``PATH``, every
#: image it may mean: actions/runner-images at 2c421200c (2026-10-12), "Language and
#: Runtime" in images/ubuntu/Ubuntu2404-Readme.md (what ``ubuntu-latest`` named then),
#: Ubuntu2604-Readme.md (from 2026-10-19) and images/macos/macos-26-arm64-Readme.md
#: (``macos-latest``). Ubuntu2204-Readme.md's is 3.10.12, which has no tomllib.
RUNNER_PYTHON3 = {'ubuntu-latest': ((3, 12), (3, 14)), 'macos-latest': ((3, 14),)}


class TestTheFileAndTheScript(unittest.TestCase):
    """The file is well formed, and the script reads it as a runner's ``python3`` would."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1660-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def test_the_file_loads_and_latest_is_the_newest_supported_version(self) -> None:
        """The owner's ruling (#1661): single-interpreter jobs run the newest supported version."""
        data = script().load()
        supported = script().tier(data, 'cpython', 'supported')
        self.assertEqual(data['latest'], max(supported, key=script().key))
        self.assertTrue(supported and script().tier(data, 'pypy', 'supported'))

    def test_the_file_is_toml_and_the_json_is_gone(self) -> None:
        """The owner asked for a format with comments (#1677); TOML is the repo's config format."""
        self.assertEqual(script().FILE, TIER_FILE)
        self.assertEqual(tomllib.loads(TIER_FILE.read_text(encoding='utf-8')), script().load())
        self.assertFalse((ROOT / '.github' / 'python-versions.json').exists())
        self.assertEqual(tomllib.loads(write_tiers(self.tmp, TIERS_AT_MAIN).read_text(encoding='utf-8')),
                         TIERS_AT_MAIN)

    def test_each_exemption_says_why_in_a_comment(self) -> None:
        """tomllib drops comments, so the file's text is read: a comment heads each exemption."""
        lines = TIER_FILE.read_text(encoding='utf-8').splitlines()
        headers = [index for index, line in enumerate(lines) if line.strip() == '[[exemptions]]']
        self.assertEqual(len(headers), len(script().load()['exemptions']))
        for index in headers:
            with self.subTest(line=index + 1):
                self.assertTrue(index and lines[index - 1].startswith('# '), 'say why above the exemption')

    def test_a_malformed_file_is_refused_with_its_reason(self) -> None:
        cpython = TIERS_AT_MAIN['versions']['cpython']
        cases = {
            'unknown tier': dict(cpython, **{'3.15': {'tier': 'blocking'}}),
            'pre-release': dict(cpython, **{'3.16': {'tier': 'pre-release'}}),
            'misspelt version': dict(cpython, **{'3.16.0': {'tier': 'supported'}}),
            'runner typo': dict(cpython, **{'3.10': {'tier': 'ktlo', 'runner': 'ubuntu-latest'}}),
            'unknown key': dict(cpython, **{'3.10': {'tier': 'ktlo', 'os': 'ubuntu-24.04'}}),
            'out of order': dict(list(cpython.items())[::-1]),
        }
        for label, versions in cases.items():
            with self.subTest(case=label):
                data = dict(TIERS_AT_MAIN, versions=dict(TIERS_AT_MAIN['versions'], cpython=versions))
                with self.assertRaises(ValueError):
                    script().load(write_tiers(self.tmp, data))
        exemption = {'workflow': 'lint.yml', 'job': 'lint', 'where': 'x', 'value': '3.14'}
        self.assertEqual(script().load(write_tiers(self.tmp, dict(TIERS_AT_MAIN, exemptions=[exemption])))[
            'exemptions'], [exemption])
        for label, data in (('latest is not supported', dict(TIERS_AT_MAIN, latest='3.10')),
                            ('an exemption has no value', dict(TIERS_AT_MAIN, exemptions=[
                                dict(exemption, value='')])),
                            ('a reason is a comment, not a field', dict(TIERS_AT_MAIN, exemptions=[
                                dict(exemption, reason='why')])),
                            ('an unknown top-level key', dict(TIERS_AT_MAIN, matrices={})),
                            ('no PyPy', dict(TIERS_AT_MAIN, versions={'cpython': cpython})),
                            ('PyPy lists nothing', dict(TIERS_AT_MAIN, versions={'cpython': cpython, 'pypy': {}}))):
            with self.subTest(case=label), self.assertRaises(ValueError):
                script().load(write_tiers(self.tmp, data))
        invalid = self.tmp / 'invalid.toml'
        invalid.write_text('latest = 3.15\nlatest = "3.15"\n', encoding='utf-8')
        with self.subTest(case='not TOML'), self.assertRaises(ValueError):
            script().load(invalid)

    def test_a_supported_version_on_an_older_runner_is_refused(self) -> None:
        """A job pinned to ``ubuntu-latest`` would otherwise stop testing it without a word."""
        pinned = {'3.11': {'tier': 'supported', 'runner': 'ubuntu-24.04'}}
        cpython = dict(TIERS_AT_MAIN['versions']['cpython'], **pinned)
        data = script().load(write_tiers(self.tmp, dict(TIERS_AT_MAIN, versions=dict(
            TIERS_AT_MAIN['versions'], cpython=cpython))))
        with self.assertRaisesRegex(ValueError, 'cannot run supported 3.11'):
            script().outputs(data)

    @staticmethod
    def parse_github_output(text: 'str') -> 'dict[str, str]':
        """``$GITHUB_OUTPUT`` as the runner reads it: ``name=value``, or ``name<<DELIMITER`` lines."""
        parsed = {}  # type: dict[str, str]
        lines = iter(text.splitlines())
        for line in lines:
            if '<<' in line and '=' not in line.split('<<', 1)[0]:
                name, delimiter = line.split('<<', 1)
                value = []
                for nested in lines:
                    if nested == delimiter:
                        break
                    value.append(nested)
                parsed[name] = '\n'.join(value)
            else:
                name, _, value_text = line.partition('=')
                parsed[name] = value_text
        return parsed

    def main(self, *argv: 'str', github_output: 'Optional[str]' = None) -> 'tuple[int, str]':
        """The script's ``main`` run in this process, with its status and stdout."""
        environ = {key: value for key, value in os.environ.items() if key != 'GITHUB_OUTPUT'}
        if github_output is not None:
            environ['GITHUB_OUTPUT'] = github_output
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, environ, clear=True), contextlib.redirect_stdout(stdout):
            status = script().main(list(argv))
        return status, stdout.getvalue()

    def test_the_command_line_writes_each_output_as_the_runner_reads_it(self) -> None:
        """One ``name=value`` line each, a multi-line value under a fresh delimiter."""
        output = self.tmp / 'github-output'
        status, printed = self.main('--github-output', github_output=str(output))
        self.assertEqual(status, 0, printed)
        self.assertEqual(self.parse_github_output(output.read_text(encoding='utf-8')), live_outputs())
        self.assertEqual(self.main('latest', 'conda'), (0, f"{live_outputs()['latest']}\n{live_outputs()['conda']}\n"))
        for argv, env, title in ((('nope',), None, 'Cannot read the Python version tiers'),
                                 (('--github-output',), None, 'GITHUB_OUTPUT is not set'),
                                 (('--file', str(write_tiers(self.tmp, dict(TIERS_AT_MAIN, latest='3.10')))),
                                  None, 'Cannot read the Python version tiers')):
            with self.subTest(argv=argv):
                status, printed = self.main(*argv, github_output=env)
                self.assertEqual(status, 1)
                self.assertRegex(printed, rf'^::error title={title}::')
        # And as a workflow runs it, by path, with nothing but the runner's environment.
        output.unlink()
        result = subprocess.run([sys.executable, str(SCRIPT), '--github-output'],
                                cwd=ROOT, env={'GITHUB_OUTPUT': str(output), 'PATH': ''},
                                capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.parse_github_output(output.read_text(encoding='utf-8')), live_outputs())

    def test_the_workflow_commands_byte_for_byte(self) -> None:
        """#2047: the whole of each run's output, so moving it onto util/_actions.py can be shown to change nothing.

        Each multi-line output's delimiter is fresh, so it is read as ``EOF`` once
        each is shown to open and close one value, and to differ from the others.

        """
        values = live_outputs()
        output = self.tmp / 'github-output'
        output.write_bytes(b'before\n')
        self.assertEqual(self.main('--github-output', github_output=str(output)),
                         (0, ''.join(f'{name}: {value}'.replace('\n', ' ') + '\n' for name, value in values.items())))
        written = output.read_bytes().decode('utf-8')
        delimiters = re.findall(r'^[\w-]+<<(EOF_[0-9a-f]{32})$', written, re.M)
        self.assertEqual(len(delimiters), sum('\n' in value for value in values.values()))
        self.assertEqual(len(set(delimiters)), len(delimiters))
        for delimiter in delimiters:
            self.assertEqual(written.count(delimiter), 2)
        self.assertEqual(re.sub(r'EOF_[0-9a-f]{32}', 'EOF', written), 'before\n' + ''.join(
            f'{name}<<EOF\n{value}\nEOF\n' if '\n' in value else f'{name}={value}\n' for name, value in values.items()))
        error = '::error title=GITHUB_OUTPUT is not set::--github-output only works inside a workflow step\n'
        for env in (None, ''):
            with self.subTest(github_output=env):
                self.assertEqual(self.main('--github-output', github_output=env), (1, error))
        names = ', '.join(values)
        self.assertEqual(self.main('latest', 'a%b\r\nc'),
                         (1, f'::error title=Cannot read the Python version tiers::{script().FILE}: no output named '
                             f'a%25b%0D%0Ac; there are {names}\n'))
        self.assertEqual(output.read_bytes().decode('utf-8'), written)

    def test_the_file_named_in_an_error_is_escaped(self) -> None:
        """#2047: ``--file``'s ``%`` and line breaks are escaped, as the error text's always were.

        Before util/_actions.py the path went out as written, so a ``%`` in it read
        as the start of an escape, and a line break split the command in two.

        """
        missing = self.tmp / '50%\nmissing.toml'
        escaped = str(missing).replace('%', '%25').replace('\n', '%0A')
        repr_escaped = repr(str(missing)).replace('%', '%25')
        self.assertEqual(self.main('--file', str(missing), 'latest'),
                         (1, f'::error title=Cannot read the Python version tiers::{escaped}: [Errno 2] No such file '
                             f'or directory: {repr_escaped}\n'))

    def test_the_script_runs_on_every_runners_own_python3(self) -> None:
        """Standard library only, tomllib's 3.11 the floor, and each image that runs it newer.

        Each job running :data:`SCRIPT_STEP` does so before any setup-python step,
        so on the image's ``python3``: :data:`RUNNER_PYTHON3`.

        """
        ast.parse(SCRIPT.read_text(encoding='utf-8'), feature_version=TOMLLIB_FLOOR)
        tree = ast.parse(SCRIPT.read_text(encoding='utf-8'))
        imported = {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                    for alias in node.names}
        imported |= {node.module.split('.')[0] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom) and node.module and not node.level}
        # util/_actions.py (#2047), as `_actions` or `util._actions`, is held to the
        # standard library by tests/project/test_actions_helper_2047.py.
        self.assertLessEqual(imported, {'__future__', '_actions', 'argparse', 'json', 'os', 'pathlib', 're', 'sys',
                                        'tomllib', 'typing', 'util'})
        self.assertIn('tomllib', imported)
        found = 0
        for name, spec in workflows():
            for job_id, job in spec.get('jobs', {}).items():
                steps = job.get('steps', [])
                runs = [i for i, step in enumerate(steps) if str(step.get('run', '')).strip() == SCRIPT_STEP]
                for index in runs:
                    found += 1
                    with self.subTest(workflow=name, job=job_id):
                        self.assertEqual(setups({'steps': steps[:index]}), [])
                        self.assertIn(job.get('runs-on'), RUNNER_PYTHON3)
                        self.assertGreaterEqual(min(RUNNER_PYTHON3[job['runs-on']]), TOMLLIB_FLOOR)
        self.assertGreaterEqual(found, 10)

    def test_without_tomllib_the_tests_that_read_the_file_skip(self) -> None:
        """On 3.8-3.10 these modules skip, or their tests do, rather than fail to import.

        Run in a fresh interpreter whose ``import tomllib`` fails, as it does there,
        where the two scripts that read the file cannot load at all. That
        interpreter may already hold :mod:`tomllib`: on the coverage leg,
        ``patch = subprocess`` starts coverage in it, which reads its TOML
        config first. So the module is dropped and its entry set to ``None``,
        which makes any import of it raise :exc:`ModuleNotFoundError`.

        """
        probe = textwrap.dedent('''\
            import importlib, importlib.util, json, sys, unittest
            for name in [name for name in sys.modules if name == 'tomllib' or name.startswith('tomllib.')]:
                del sys.modules[name]
            sys.modules['tomllib'] = None
            found = {}
            for name in sys.argv[1:]:
                try:
                    importlib.import_module(name)
                    found[name] = 'imported'
                except unittest.SkipTest as error:
                    found[name] = f'skipped: {error}'
            try:
                importlib.import_module(sys.argv[1]).script()
            except unittest.SkipTest as error:
                found['script()'] = f'skipped: {error}'
            for path in ('util/python_versions.py', 'util/ci_timing.py'):
                spec = importlib.util.spec_from_file_location(path, path)
                try:
                    spec.loader.exec_module(importlib.util.module_from_spec(spec))
                    found[path] = 'loaded'
                except ImportError as error:
                    found[path] = f'{type(error).__name__}: {error}'
            print(json.dumps(found))
        ''')
        modules = ['tests.project.test_python_versions_1660', 'tests.project.test_python_matrix_tiers_1633',
                   'tests.project.test_ktlo_legs_stay_green_1672', 'tests.project.test_ci_timing',
                   'tests.project.test_unit_tests_queue', 'tests.project.test_workflow_apt_cache']
        result = subprocess.run([sys.executable, '-c', probe, *modules], cwd=ROOT, capture_output=True,
                                text=True, check=False, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        skipped = f'skipped: {NO_TOMLLIB}'
        blocked = 'ModuleNotFoundError: import of tomllib halted; None in sys.modules'
        self.assertEqual(json.loads(result.stdout.splitlines()[-1]), {
            'tests.project.test_python_versions_1660': 'imported',
            'tests.project.test_python_matrix_tiers_1633': skipped,
            'tests.project.test_ktlo_legs_stay_green_1672': skipped,
            'tests.project.test_ci_timing': skipped,
            'tests.project.test_unit_tests_queue': 'imported',
            'tests.project.test_workflow_apt_cache': 'imported',
            'script()': skipped,
            'util/python_versions.py': blocked,
            'util/ci_timing.py': blocked,
        })


class TestNothingMovedButLatest(unittest.TestCase):
    """The file reproduces every matrix ``main`` spelt out, but for the coverage leg."""

    @classmethod
    def setUpClass(cls) -> None:
        with tempfile.TemporaryDirectory(prefix='pcapkit-1660-') as tmp:
            cls.values = script().outputs(script().load(write_tiers(pathlib.Path(tmp), TIERS_AT_MAIN)))

    def test_every_matrix_expands_to_mains_legs(self) -> None:
        """Same legs, same order; the coverage leg moves from 3.14 to ``latest`` (#1661), and PyPy's join (#1958).

        Where the clone holds :data:`MAIN`, :data:`MAIN_MATRICES` is read back
        against it first, so the comparison is with what ``main`` really ran.

        """
        for (name, job_id), spec in MAIN_MATRICES.items():
            if has_main():
                with self.subTest(recorded=name, job=job_id):
                    self.assertEqual(workflow_at_main(name)['jobs'][job_id]['strategy']['matrix'], spec)
            expected = legs(spec)
            if (name, job_id) == ('unit-tests.yml', 'test'):
                for leg in expected:
                    leg.pop('coverage', None)
                    if leg['python-version'] == TIERS_AT_MAIN['latest']:
                        leg['coverage'] = True
            if (name, job_id) in CONDA_JOBS:
                # #1822: an Intel macOS leg per version, so osx-64 is built natively;
                # #2060: and a Windows one, for win-64.
                expected = legs(dict(spec, os=CONDA_OS))
            expected = with_pypy(name, job_id, expected)
            if (name, job_id) in KTLO_TWINS:
                # #1738: the KTLO legs, in MAIN's order, are the twin job's.
                twin = KTLO_TWINS[(name, job_id)]
                with self.subTest(workflow=name, job=twin):
                    self.assertEqual(legs(matrix(name, twin, self.values)),
                                     [leg for leg in expected if leg.get('ktlo') is True])
                expected = [leg for leg in expected if leg.get('ktlo') is not True]
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(legs(matrix(name, job_id, self.values)), expected)

    def test_engine_tests_installs_and_runs_mains_cells(self) -> None:
        if has_main():
            engines = tuple(step['with']['python-version'].strip()
                            for step in setups(workflow_at_main('unit-tests.yml')['jobs']['engine-tests']))
            self.assertEqual(engines, ENGINES_AT_MAIN)
        spec = workflow('unit-tests.yml')['jobs']['engine-tests']
        inputs = tuple(resolve('unit-tests.yml', 'engine-tests', step['with']['python-version'], self.values)
                       for step in setups(spec))
        self.assertEqual(inputs, ENGINES_AT_MAIN)
        loops = {step['name']: resolve('unit-tests.yml', 'engine-tests', step['env']['PYTHONS'], self.values)
                 for step in spec['steps'] if 'PYTHONS' in step.get('env', {})}
        self.assertEqual(loops, {'Run the supported cells': ENGINES_AT_MAIN[1],
                                 'Run the KTLO cells (non-blocking)': ENGINES_AT_MAIN[0]})

    def test_no_job_name_changes_but_the_gates(self) -> None:
        """Rulesets match check names literally, so each template and leg name stays.

        ``test``'s template is :data:`MAIN`'s again since its experimental legs
        left it for a job of their own (#1732). Since #1738 each job of
        :data:`KTLO_TWINS` names its legs with a template of its own, the KTLO
        job's ending `` (KTLO)``, so what stays is each leg's rendered name.

        """
        for (name, job_id), template in TEMPLATES_AT_MAIN.items():
            with self.subTest(workflow=name, job=job_id):
                if (name, job_id) not in KTLO_TWINS:
                    self.assertEqual(workflow(name)['jobs'][job_id]['name'], template)
                    continue
                spec = MAIN_MATRICES[(name, job_id)]
                before = sorted(render(template, leg) for leg in with_pypy(name, job_id, legs(spec)))
                after = sorted(render(workflow(name)['jobs'][job]['name'], leg)
                               for job in (job_id, KTLO_TWINS[(name, job_id)])
                               for leg in legs(matrix(name, job, self.values)))
                self.assertEqual(after, before)
        compat = TEMPLATES_AT_MAIN[('python-compatibility.yml', 'compatibility')]
        compat_legs = legs(matrix('python-compatibility.yml', 'compatibility', self.values))
        blocking = {render(compat, leg) for leg in compat_legs
                    if leg.get('ktlo') is not True}
        self.assertEqual(blocking | {'Required checks passed'}, REQUIRED_AT_MAIN)
        self.assertEqual(workflow('unit-tests.yml')['jobs']['required-checks']['name'], 'Required checks passed')
        gate = workflow('unit-tests.yml')['jobs']['gate']['name']
        expression = re.search(r'\$\{\{[^}]*\}\}', gate).group(0)  # type: ignore[union-attr]
        self.assertEqual(gate.replace(expression, resolve('unit-tests.yml', 'gate', expression, self.values)),
                         'Gate (full suite, Python 3.15)')
        if has_main():
            self.assertEqual(workflow_at_main('unit-tests.yml')['jobs']['gate']['name'],
                             'Gate (full suite, Python 3.14)')
            for (name, job_id), template in TEMPLATES_AT_MAIN.items():
                with self.subTest(recorded=name, job=job_id):
                    self.assertEqual(workflow_at_main(name)['jobs'][job_id]['name'], template)


#: Setup actions whose ``python-version`` input picks the interpreter.
SETUP_ACTIONS = ('actions/setup-python@', 'conda-incubator/setup-miniconda@')
#: A literal version, or a list of them.
VERSIONS = re.compile(r'\s*(?:pypy)?3\.\d+(?:\s+(?:pypy)?3\.\d+)*\s*')
#: ``matrix.python-version`` compared with a literal version.
COMPARED = re.compile(r"matrix\.python-version\s*[!=]=\s*'([^']+)'|'([^']+)'\s*[!=]=\s*matrix\.python-version")
#: A job name naming its Python outside an expression.
NAMED = re.compile(r'\bPython ((?:pypy)?3\.\d+)\b')
#: A wheel or conda build tag, and a shell loop over literal versions.
TAG = re.compile(r'\b(?:cp|pp|py)3\d{1,2}\b')
LOOP = re.compile(r'\bfor \w+ in ((?:(?:pypy)?3\.\d+\s*)+)')


def strings(node: 'Any', where: 'str') -> 'Iterator[tuple[str, str]]':
    """Every string under ``node``, with a readable path to it."""
    if isinstance(node, str):
        yield where, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from strings(value, f'{where}.{key}' if where else str(key))
    elif isinstance(node, list):
        for value in node:
            yield from strings(value, where)


def step_label(step: 'dict[str, Any]') -> 'str':
    """A step's name, else ``Set up Python`` for a setup action, else what it ``uses``."""
    if 'name' in step:
        return str(step['name'])
    return 'Set up Python' if str(step.get('uses', '')).startswith(SETUP_ACTIONS) else str(step.get('uses'))


def pins(load: 'Callable[[str], dict[str, Any]]' = workflow) -> 'dict[tuple[str, str, str], list[str]]':
    """Every literal Python version a workflow selects with, as (workflow, job, where): values."""
    found = {}  # type: dict[tuple[str, str, str], list[str]]

    def add(name: 'str', job_id: 'str', where: 'str', value: 'str') -> None:
        found.setdefault((name, job_id, where), []).append(' '.join(value.split()))

    for name, spec in workflows(load):
        for job_id, job in spec.get('jobs', {}).items():
            title = str(job.get('name', ''))
            for version in NAMED.findall(re.sub(r'\$\{\{.*?\}\}', '', title)):
                add(name, job_id, 'name', version)
            raw = job.get('strategy', {}).get('matrix', {})
            if isinstance(raw, dict):
                for where, text in strings({key: value for key, value in raw.items()
                                            if key in ('python-version', 'include')}, 'strategy.matrix'):
                    if VERSIONS.fullmatch(text):
                        add(name, job_id, where, text)
            for where, text in strings({key: value for key, value in job.items() if key != 'steps'}, ''):
                for a, b in COMPARED.findall(text):
                    add(name, job_id, where, a or b)
                if where.startswith('env.') and VERSIONS.fullmatch(text):
                    add(name, job_id, where, text)
            for step in job.get('steps', ()):
                label = step_label(step)
                version = step.get('with', {}).get('python-version')
                if str(step.get('uses', '')).startswith(SETUP_ACTIONS) and isinstance(version, str) \
                        and '${{' not in version:
                    add(name, job_id, f'{label}: with.python-version', version)
                for where, text in strings({key: value for key, value in step.items() if key != 'run'}, ''):
                    for a, b in COMPARED.findall(text):
                        add(name, job_id, f'{label}: {where}', a or b)
                    if where.startswith('env.') and VERSIONS.fullmatch(text):
                        add(name, job_id, f'{label}: {where}', text)
                code = '\n'.join(line for line in str(step.get('run', '')).splitlines()
                                 if not line.strip().startswith('#'))
                for found_tag in TAG.findall(code):
                    add(name, job_id, f'{label}: run', found_tag)
                for loop in LOOP.findall(code):
                    add(name, job_id, f'{label}: run', loop)
                for a, b in COMPARED.findall(code):
                    add(name, job_id, f'{label}: run', a or b)
    return found


#: The jobs that run on one interpreter, which the ruling (#1661) puts on ``latest``.
SINGLE = (('unit-tests.yml', 'gate'), ('unit-tests.yml', 'unittest-ordering'), ('unit-tests.yml', 'changelog'),
          ('unit-tests.yml', 'project-tests'), ('create-release.yml', 'version_check'),
          ('cron-conda.yml', 'conda-update'), ('cron-vendor.yml', 'vendor-update'),
          ('deploy-pages.yml', 'deploy-pages'), ('ci-timing.yml', 'report'), ('lint.yml', 'lint'),
          ('cron-python-versions.yml', 'detect'))


class TestEveryVersionComesFromTheFile(unittest.TestCase):
    """No workflow selects a Python version the file does not give it, bar the exemptions."""

    #: A pin of each kind the scan reads, as it stood at :data:`MAIN`.
    PINS_AT_MAIN = (
        ('unit-tests.yml', 'gate', 'name'),
        ('unit-tests.yml', 'gate', 'Set up Python: with.python-version'),
        ('unit-tests.yml', 'test', 'strategy.matrix.python-version'),
        ('unit-tests.yml', 'test', 'strategy.matrix.include.python-version'),
        ('unit-tests.yml', 'engine-tests', 'Run the 3.11-3.15 cells: run'),
        ('create-release.yml', 'version_check', 'Check PyPI publish completeness: run'),
        ('create-release.yml', 'pypi', 'No Source Distribution for Python ${{ matrix.python-version }}: if'),
        ('unit-tests.yml', 'pypcap-parity', 'env.APT_CACHE_SAVE'),
        ('lint.yml', 'lint', 'Set up Python: with.python-version'),
    )

    def test_no_pin_but_the_files_exemptions(self) -> None:
        """Each pin is exempt with its value; each exemption still matches a pin.

        Where the clone holds :data:`MAIN`, the scan is shown not to be blind
        first: it finds :data:`PINS_AT_MAIN` in ``main``'s workflows.

        """
        if has_main():
            at_main = pins(workflow_at_main)
            for key in self.PINS_AT_MAIN:
                with self.subTest(at_main=key):
                    self.assertIn(key, at_main)
        exemptions = {(e['workflow'], e['job'], e['where']): e['value'] for e in script().load()['exemptions']}
        found = pins()
        for key, values in found.items():
            with self.subTest(pin=key):
                self.assertIn(key, exemptions, f'{key} pins {values}: read it from the file, or exempt it there')
                self.assertEqual(values, [exemptions[key]] * len(values))
        for key in exemptions:
            with self.subTest(exemption=key):
                self.assertIn(key, found, 'this exemption matches no pin: drop it from the file')

    def test_every_setup_reads_the_matrix_or_the_file(self) -> None:
        """A setup action's version is ``matrix.python-version``, a script output, or an exempt literal."""
        exemptions = {(e['workflow'], e['job'], e['where']) for e in script().load()['exemptions']}
        for name, spec in workflows():
            for job_id, job in spec.get('jobs', {}).items():
                for step in setups(job):
                    text = str(step.get('with', {}).get('python-version', ''))
                    where = (name, job_id, f'{step_label(step)}: with.python-version')
                    with self.subTest(step=where):
                        if where in exemptions or 'matrix.python-version' in text:
                            continue
                        output = script_output(name, job_id, READ.fullmatch(text).group(2))  # type: ignore[union-attr]
                        # #2125: benchmark.yml's `benchmark` installs the engines' interpreters too.
                        expected = {'engine-tests': ('engine-supported', 'engine-ktlo'),
                                    'benchmark': ('engine-supported', 'engine-ktlo')}.get(job_id, ('latest',))
                        self.assertIn(output, expected)

    def test_every_single_interpreter_job_runs_latest(self) -> None:
        latest = script().load()['latest']
        for name, job_id in SINGLE:
            job = workflow(name)['jobs'][job_id]
            with self.subTest(workflow=name, job=job_id):
                steps = [step for step in setups(job) if str(step['uses']).startswith('actions/setup-python@')]
                self.assertEqual([resolve(name, job_id, step['with']['python-version']) for step in steps], [latest])

    def test_the_coverage_leg_and_the_sdist_leg_are_latest(self) -> None:
        latest = script().load()['latest']
        covered = [leg['python-version'] for leg in legs(matrix('unit-tests.yml', 'test')) if leg.get('coverage')]
        self.assertEqual(covered, [latest])
        step = next(step for step in workflow('create-release.yml')['jobs']['pypi']['steps']
                    if step.get('id') == 'no_sdist')
        condition = re.fullmatch(r"\$\{\{ matrix\.python-version != (\S+) && steps\.build\.outcome == 'success' \}\}",
                                 step['if'])
        self.assertIsNotNone(condition, step['if'])
        self.assertEqual(resolve('create-release.yml', 'pypi', '${{ %s }}' % condition.group(1)), latest)  # type: ignore[union-attr]

    def test_the_versions_jobs_read_the_tiers_and_write_nothing(self) -> None:
        """``unit-tests.yml`` is a reusable workflow whose callers grant only ``contents: read``."""
        for name in ('unit-tests.yml', 'python-compatibility.yml'):
            spec = workflow(name)
            job = spec['jobs']['python-versions']
            with self.subTest(workflow=name):
                self.assertEqual(job.get('permissions', spec['permissions']), {'contents': 'read'})
                checkout = job['steps'][0]
                self.assertTrue(checkout['uses'].startswith('actions/checkout@'))
                self.assertEqual(checkout['with']['sparse-checkout'].split(),
                                 ['.github/python-versions.toml', 'util/_actions.py', 'util/python_versions.py'])
                self.assertIs(checkout['with']['sparse-checkout-cone-mode'], False)
                self.assertEqual(job['steps'][1]['run'].strip(), SCRIPT_STEP)
                self.assertNotIn('if', job)


class TestTheAnacondaCheckCountsTheFile(unittest.TestCase):
    """``version_check``'s Anaconda evidence, run as the workflow runs it, ``curl`` stubbed.

    Its PyPI twin is executed by ``test_python_matrix_tiers_1633``.

    """

    def setUp(self) -> None:
        if shutil.which('bash') is None or shutil.which('python3') is None:  # pragma: no cover
            self.skipTest('bash and python3 are needed to run the workflow shell')

    def complete(self, distributions: 'list[tuple[str, str]]') -> 'str':
        """``PCAPKIT_CONDA_COMPLETE`` for a release holding these (platform, build) pairs.

        The builds are this run's, which the ``released`` step passes on while the
        version is untagged; ``test_release_tags_the_run_sha_1634`` runs it tagged.

        """
        steps = workflow('create-release.yml')['jobs']['version_check']['steps']
        step = next(step for step in steps if step.get('name') == 'Check Anaconda publish completeness')
        self.assertEqual(step['env']['PCAPKIT_CONDA_BUILDS'], '${{ steps.released.outputs.conda-builds }}')
        released = next(step for step in steps if step.get('id') == 'released')
        builds = resolve('create-release.yml', 'version_check', released['env']['PCAPKIT_CONDA_BUILDS'])
        with tempfile.TemporaryDirectory(prefix='pcapkit-1660-') as tmp:
            scratch = pathlib.Path(tmp)
            reply = scratch / 'reply.json'
            reply.write_text(json.dumps({'distributions': [{'attrs': {'subdir': platform, 'build': f'{build}_0'}}
                                                           for platform, build in distributions]}), encoding='utf-8')
            curl = scratch / 'curl'
            curl.write_text('#!/bin/bash\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && cp "$REPLY" "$2"; shift; done\n'
                            'printf 200\n', encoding='utf-8')
            curl.chmod(0o755)
            output = scratch / 'output'
            output.write_text('', encoding='utf-8')
            # #1967: ``python3 util/release_published.py anaconda ...``, on this interpreter.
            words = step['run'].replace('/tmp/anaconda_release.json', str(scratch / 'release.json')).split()
            self.assertEqual(words[:2], ['python3', 'util/release_published.py'])
            result = subprocess.run(
                [sys.executable, str(ROOT / words[1]), *words[2:]],
                env=dict(os.environ, PATH=f'{scratch}{os.pathsep}{os.environ["PATH"]}', REPLY=str(reply),
                         GITHUB_OUTPUT=str(output), PCAPKIT_VERSION='1.5.0', PCAPKIT_CONDA_BUILDS=builds,
                         PCAPKIT_TAG_EXISTS='false'),
                capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            written = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').split())
            return written['PCAPKIT_CONDA_COMPLETE']

    def test_each_platform_needs_each_supported_build(self) -> None:
        builds = live_outputs()['conda-builds'].split()
        every = [(platform, build) for platform in ('linux-64', 'osx-64', 'osx-arm64', 'win-64')
                 for build in builds]
        ktlo = [('linux-64', 'py' + version.replace('.', ''))
                for version in script().tier(script().load(), 'cpython', 'ktlo')]
        self.assertEqual(self.complete(every), 'true')
        self.assertEqual(self.complete(every[1:] + ktlo), 'false')
        self.assertEqual(self.complete([]), 'false')


def prose(path: 'pathlib.Path') -> 'str':
    """``path``'s text with each line break, and a leading ``#``/``#:`` after it, as one space."""
    return re.sub(r'[ \t]*\n[ \t]*(?:#:?[ \t]*)?', ' ', path.read_text(encoding='utf-8'))


class TestTheProseFollowsTheFile(unittest.TestCase):
    """What the classifiers, docs and comments say about the versions, read against the file."""

    @classmethod
    def setUpClass(cls) -> None:
        data = script().load()
        cls.latest = data['latest']
        cls.supported = script().tier(data, 'cpython', 'supported')
        cls.ktlo = script().tier(data, 'cpython', 'ktlo')

    def test_the_classifiers_name_the_supported_tier_and_both_implementations(self) -> None:
        text = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'"Programming Language :: Python :: (3\.\d+)"', text), self.supported)
        self.assertEqual(re.findall(r'"Programming Language :: Python :: Implementation :: (\w+)"', text),
                         ['CPython', 'PyPy'])

    #: (file, claim with the first and last version of a tier captured, which tier).
    RANGES = (
        ('README.md', r'CI supports (3\.\d+) to (3\.\d+)', 'supported'),
        ('README.md', r'tests the end-of-life (3\.\d+) to (3\.\d+)', 'ktlo'),
        ('docs/source/index.rst', r'CI supports (3\.\d+) to (3\.\d+)', 'supported'),
        ('docs/source/index.rst', r'tests the end-of-life (3\.\d+) to (3\.\d+)', 'ktlo'),
        ('docs/source/index.rst', r'(3\.\d+) to (3\.\d+) are end-of-life and best-effort', 'ktlo'),
        ('docs/source/contributing/pep.rst', r'in CI against Python (3\.\d+) through (3\.\d+)', 'supported'),
        ('docs/source/contributing/pep.rst', r'against the end-of-life (3\.\d+) through (3\.\d+)', 'ktlo'),
        ('docs/source/contributing/workflows.rst', r'The \*\*supported\*\* tier, (3\.\d+)-(3\.\d+),', 'supported'),
        ('docs/source/contributing/workflows.rst', r'end-of-life (3\.\d+)-(3\.\d+), still built', 'ktlo'),
        ('SECURITY.md', r'blocking tier: CPython (3\.\d+) through (3\.\d+)', 'supported'),
        ('SECURITY.md', r'but (3\.\d+) to (3\.\d+) are best-effort', 'ktlo'),
        ('pyproject.toml', r'\*\*(3\.\d+) through (3\.\d+)\*\* are supported', 'supported'),
        ('pyproject.toml', r'\*\*(3\.\d+) through (3\.\d+)\*\* are KTLO', 'ktlo'),
        ('pyproject.toml', r'the KTLO tier \((3\.\d+)-(3\.\d+)\)', 'ktlo'),
    )

    def test_each_tier_range_names_the_files_tier(self) -> None:
        """Its first and last version, and so every one between: "3.8 to 3.10" says 3.9 is in it."""
        for path, pattern, name in self.RANGES:
            versions = self.supported if name == 'supported' else self.ktlo
            with self.subTest(path=path, claim=pattern):
                self.assertEqual(re.findall(pattern, prose(ROOT / path)), [(versions[0], versions[-1])])
        for name, versions in (('supported', self.supported), ('ktlo', self.ktlo)):
            minors = [int(version.split('.')[1]) for version in versions]
            with self.subTest(tier=name):
                self.assertEqual(minors, list(range(minors[0], minors[0] + len(minors))),
                                 f'a range cannot state the {name} tier {versions}; reword the claims by hand')

    def test_the_required_contexts_table_is_the_supported_tier(self) -> None:
        """The docs' copy of ruleset 23497679, which a tier change edits with it."""
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        self.assertEqual(re.findall(r'\* - ``Compat Python (3\.\d+)``', page), self.supported)

    def test_the_workflows_page_cites_each_version_by_its_key(self) -> None:
        """The required contexts' rows, and the two tiers' spans under them, cite the file's keys (#2165).

        A key names its entry; a line number has to be looked up, so none is cited.

        """
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        self.assertNotRegex(page, r'python-versions\.toml:\d')
        rows = re.findall(r'``Compat Python (3\.\d+)`` .*? key ``"(3\.\d+)"`` of ``\.github/python-versions\.toml``',
                          page)
        self.assertEqual([version for version, _ in rows], self.supported)
        for version, key in rows:
            with self.subTest(version=version):
                self.assertEqual(key, version)
        for label, versions in (('supported tier', self.supported), ('KTLO legs', self.ktlo)):
            spans = re.findall(rf'its {label} \(keys ``"(3\.\d+)"`` to ``"(3\.\d+)"``\)', page)
            with self.subTest(tier=label):
                self.assertEqual(spans, [(versions[0], versions[-1])])

    def test_the_bug_report_template_offers_supported_versions(self) -> None:
        text = (ROOT / '.github' / 'ISSUE_TEMPLATE' / 'bug_report.md').read_text(encoding='utf-8')
        versions = re.search(r'Python Version: \[e\.g\. ([^\]]+)\]', text).group(1).split(', ')  # type: ignore[union-attr]
        self.assertEqual(versions[0], self.latest)
        self.assertLessEqual(set(versions), set(self.supported))
        implementations = re.search(r'Python Implementation: \[e\.g\. ([^\]]+)\]', text).group(1)  # type: ignore[union-attr]
        self.assertEqual(implementations.split(', '), ['CPython', 'PyPy'])

    #: (file, a claim naming the coverage leg's or the sdist leg's version) -- ``latest``.
    LATEST = (
        ('.github/coverage.toml', r'\(`test`, Python (\d+\.\d+)\)'),
        ('docs/source/contributing/workflows.rst',
         r'the ``Python (\d+\.\d+)`` leg of ``test`` \(matrix key ``coverage: true``\)'),
        ('docs/source/contributing/conventions/test-coverage.rst', r"the ``test`` job's Python (\d+\.\d+) cell"),
        ('docs/source/contributing/releasing.rst', r'the sdist kept only on the (\d+\.\d+) leg'),
    )

    def test_each_claim_about_the_latest_leg_names_latest(self) -> None:
        for path, pattern in self.LATEST:
            with self.subTest(path=path, claim=pattern):
                self.assertEqual(re.findall(pattern, prose(ROOT / path)), [self.latest])


#: The two builds as setup-python spells them, at actions/setup-python 3892123fb: a
#: free-threaded CPython as ``3.14t`` (src/find-python.ts's ``desugarFreeThreadedVersion``,
#: ``/^(\d+\.\d+(\.\d+)?)(t)$/``), and GraalPy as ``graalpy-<version>``
#: (src/find-graalpy.ts's ``parseGraalPyVersion``; README.md's "Basic usage",
#: ``graalpy-24.0``), the version being a GraalPy release line, matched as a semver
#: range against oracle/graalpython's release tags (src/install-graalpy.ts's ``findRelease``).
SETUP_PYTHON = {'cpython': re.compile(r'3\.\d+t'), 'graalpy': re.compile(r'graalpy-\d+\.\d+')}
#: :data:`TIERS_AT_MAIN` with one experimental build of each, listed last as the file lists them.
EXPERIMENTAL_LEGS = [{'python-version': '3.14t', 'experimental': True},
                     {'python-version': 'graalpy-25.4', 'experimental': True}]
TIERS_WITH_EXPERIMENTAL = dict(TIERS_AT_MAIN, versions=dict(
    TIERS_AT_MAIN['versions'],
    cpython=dict(TIERS_AT_MAIN['versions']['cpython'], **{'3.14t': {'tier': 'experimental'}}),
    graalpy={'graalpy-25.4': {'tier': 'experimental'}}))


def experimental(data: 'dict[str, Any]') -> 'list[str]':
    """Every experimental version in ``data``, CPython's then GraalPy's."""
    return [version for impl in ('cpython', 'pypy', 'graalpy') for version in script().tier(data, impl, 'experimental')]


class TestTheExperimentalTier(unittest.TestCase):
    """#1660, the owner's option 1: GraalPy and free-threaded CPython run non-blocking legs, nothing else.

    #1732, the owner's option 2: those legs are the ``experimental`` job of
    experimental.yml, a workflow of its own, so nothing in unit-tests.yml waits on them.

    :mod:`tests.project.test_ktlo_legs_stay_green_1672` runs those legs' steps to
    show they cannot fail the job; this reads the file, the matrices and the names.

    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1660-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def outputs(self, data: 'dict[str, Any]') -> 'dict[str, str]':
        return script().outputs(script().load(write_tiers(self.tmp, data)))

    def test_the_file_lists_free_threaded_cpython_and_graalpy(self) -> None:
        """Each spelt as setup-python's ``python-version`` reads it, and nothing else experimental."""
        data = script().load()
        for impl, spelling in SETUP_PYTHON.items():
            found = script().tier(data, impl, 'experimental')
            with self.subTest(implementation=impl):
                self.assertTrue(found, f'no experimental {impl}')
                for version in found:
                    self.assertRegex(version, rf'^{spelling.pattern}$')
        self.assertEqual(script().tier(data, 'pypy', 'experimental'), [])

    def test_load_holds_the_tier_to_those_builds(self) -> None:
        """Either way round: no other build is experimental, and neither build is anything else."""
        self.assertEqual(script().load(write_tiers(self.tmp, TIERS_WITH_EXPERIMENTAL))['versions'],
                         TIERS_WITH_EXPERIMENTAL['versions'])
        versions = TIERS_WITH_EXPERIMENTAL['versions']
        cpython = {key: value for key, value in versions['cpython'].items() if key != '3.14t'}
        cases = {
            'a free-threaded build in a blocking tier': dict(versions, cpython=dict(cpython, **{
                '3.14t': {'tier': 'supported'}})),
            'GraalPy in a blocking tier': dict(versions, graalpy={'graalpy-25.4': {'tier': 'ktlo'}}),
            'a plain CPython experimental': dict(versions, cpython=dict(cpython, **{
                '3.16': {'tier': 'experimental'}})),
            'PyPy experimental': dict(versions, pypy=dict(versions['pypy'], **{
                'pypy3.12': {'tier': 'experimental'}})),
            'experimental before the rest': dict(versions, cpython=dict({'3.14t': {'tier': 'experimental'}},
                                                                        **cpython)),
            "setup-python's other GraalPy spelling": dict(versions, graalpy={'graalpy25.4': {'tier': 'experimental'}}),
            'GraalPy lists nothing': dict(versions, graalpy={}),
            'an implementation the script cannot spell': dict(versions, jython={'2.7': {'tier': 'experimental'}}),
        }
        for label, data in cases.items():
            with self.subTest(case=label), self.assertRaises(ValueError):
                script().load(write_tiers(self.tmp, dict(TIERS_WITH_EXPERIMENTAL, versions=data)))

    def test_only_the_experimental_output_gains_a_leg(self) -> None:
        """No ``test``, ``integration``, ``Compat``, parity, engine, wheel or conda leg, and no release count."""
        base, values = self.outputs(TIERS_AT_MAIN), self.outputs(TIERS_WITH_EXPERIMENTAL)
        self.assertEqual({name: value for name, value in values.items() if name != 'experimental'},
                         {name: value for name, value in base.items() if name != 'experimental'})
        self.assertEqual(json.loads(base['experimental']), {'python-version': [], 'include': []})
        self.assertEqual(json.loads(values['experimental']),
                         {'python-version': ['3.14t', 'graalpy-25.4'], 'include': EXPERIMENTAL_LEGS})
        self.assertEqual(legs(json.loads(values['experimental'])), EXPERIMENTAL_LEGS)

    def test_on_main_no_job_but_experimental_runs_an_experimental_version(self) -> None:
        """Every matrix and setup-python input any workflow reads from the script, as the file stands."""
        found = experimental(script().load())
        self.assertTrue(found)
        read = []
        for name, spec in workflows():
            for job_id, job in spec.get('jobs', {}).items():
                raw = job.get('strategy', {}).get('matrix')
                texts = [raw] if isinstance(raw, str) else list((raw or {}).values()) if isinstance(raw, dict) else []
                if not any(isinstance(text, str) and READ.fullmatch(text.strip()) for text in texts):
                    continue
                read.append((name, job_id))
                expected = [{'python-version': version, 'experimental': True} for version in found] \
                    if (name, job_id) == ('experimental.yml', 'experimental') else []
                with self.subTest(workflow=name, job=job_id):
                    self.assertEqual([leg for leg in legs(matrix(name, job_id)) if leg['python-version'] in found],
                                     expected)
        self.assertGreaterEqual(len(read), 7, 'the scan is blind')
        values = live_outputs()
        for output in ('conda', 'engine-supported', 'engine-ktlo', 'pypi-wheels', 'conda-builds', 'pypi'):
            with self.subTest(output=output):
                self.assertFalse(set(re.findall(r'[\w.-]+', values[output])) & set(found))

    def test_each_leg_is_named_experimental_and_never_required(self) -> None:
        """#1732: the names ``test`` gave these legs, so no check name changes."""
        found = experimental(script().load())
        self.assertEqual(workflow('experimental.yml')['jobs']['experimental']['name'], EXPERIMENTAL_TEMPLATE)
        names = [render(workflow(name)['jobs'][job_id]['name'], leg)
                 for name, job_id in (('unit-tests.yml', 'test'), ('experimental.yml', 'experimental'))
                 for leg in legs(matrix(name, job_id))]
        self.assertEqual(len(names), len(set(names)), names)
        self.assertEqual([name for name in names if name.endswith(' (experimental)')],
                         [f'Python {version} (experimental)' for version in found])
        supported = script().tier(script().load(), 'cpython', 'supported')
        required = {'Required checks passed'} | {f'Compat Python {version}' for version in supported}
        self.assertFalse(required & set(names))
        compat = [leg['python-version'] for leg in legs(matrix('python-compatibility.yml', 'compatibility'))]
        self.assertFalse(set(compat) & set(found))

    def test_the_workflows_page_names_each_experimental_version(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        listed = re.findall(r'spelt as setup-python reads them \(((?:``[^`]+``(?:, )?)+)\)', page)
        self.assertEqual(len(listed), 1, listed)
        self.assertEqual(re.findall(r'``([^`]+)``', listed[0]), experimental(script().load()))


if __name__ == '__main__':
    unittest.main()
