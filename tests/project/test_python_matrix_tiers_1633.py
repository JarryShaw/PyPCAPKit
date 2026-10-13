# -*- coding: utf-8 -*-
"""#1633: every Python matrix is two tiers, and only one of them can block.

Python 3.10 reached end-of-life on 2026-10-01 and 3.15.0 was released on
2026-10-09, so the owner's ruling on #1633 split the matrices:

* **Supported** -- 3.11 to 3.15, in every matrix (unit tests, compatibility,
  conda, PyPI), blocking as before.
* **KTLO** -- end-of-life versions that still build and test (3.10 wherever it
  ran, plus 3.7, 3.8 and 3.9 in the test matrices), never blocking: not CI, not
  a release, not a required context.
* ``requires-python`` stays ``>=3.6, <4``.

A KTLO leg can block in more ways than one, so each is pinned on its own: a job
that ``required-checks`` or ``release_status`` aggregates through one
``needs.<job>.result`` must keep the leg's failure inside its steps (GitHub
documents step-level ``continue-on-error``, not what that result reads under a
job-level one); a compatibility leg must never carry a required context's name;
and PyPI's completeness evidence must not count a KTLO wheel, or one failed KTLO
leg would leave every later release run retrying it. The release-side checks
execute the workflow's own shell, stubbing only ``curl``. The last class reads
the prose that states the tiers back against the matrices.

3.7 joined the tier afterwards, at the owner's request, and cannot install or
import pcapkit: the ``test`` extra's ``pytest>=8`` needs 3.8, and the sources use
3.8 syntax. So its legs are red by design, and :class:`TestPython37IsKTLO` pins
that they fail fast and say why -- the install and verify steps are executed with
``python`` stubbed. 3.6 stays out: setup-python builds it only for retired images.

"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from typing import TYPE_CHECKING

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'

SUPPORTED = ('3.11', '3.12', '3.13', '3.14', '3.15')
#: The step-level guard every failure-prone step of an aggregated job carries.
KTLO_GUARD = '${{ matrix.ktlo == true }}'
#: Ruleset 23497679's required contexts once the owner applies #1633's edit.
REQUIRED = frozenset({'Required checks passed'} | {f'Compat Python {v}' for v in SUPPORTED})

#: Every Python matrix, as (workflow, job, the blocking versions it must run).
MATRICES = (
    ('unit-tests.yml', 'test', SUPPORTED),
    ('unit-tests.yml', 'integration', SUPPORTED),
    ('unit-tests.yml', 'pypcap-parity', ('3.11',)),  # PyPCAP/PyPCAPFile's `< '3.12'` marker
    ('python-compatibility.yml', 'compatibility', SUPPORTED),
    ('create-release.yml', 'pypi', SUPPORTED + ('pypy3.11',)),
    ('create-release.yml', 'conda', SUPPORTED),
    ('cron-conda.yml', 'conda-dist', SUPPORTED),
)
#: The jobs a single ``needs.<job>.result`` aggregates, so KTLO must stay step-level.
AGGREGATED = (('unit-tests.yml', 'test'), ('unit-tests.yml', 'integration'),
              ('unit-tests.yml', 'pypcap-parity'), ('create-release.yml', 'pypi'))
#: Where each KTLO leg must be, as (workflow, job, KTLO versions).
KTLO_LEGS = (
    ('unit-tests.yml', 'test', ('3.7', '3.8', '3.9', '3.10')),
    ('unit-tests.yml', 'integration', ('3.7', '3.8', '3.9', '3.10')),
    ('unit-tests.yml', 'pypcap-parity', ('3.10',)),
    ('python-compatibility.yml', 'compatibility', ('3.7', '3.8', '3.9', '3.10')),
    ('create-release.yml', 'pypi', ('3.10', 'pypy3.10')),
)
#: The newest Ubuntu each pinned KTLO version has a setup-python build for; the
#: rest run on ``ubuntu-latest``. ubuntu-22.04 is deprecated and retires 2027-04-17.
PINNED_OS = {'3.7': 'ubuntu-22.04', '3.8': 'ubuntu-24.04', '3.9': 'ubuntu-24.04'}
#: The jobs 3.7 joins (#1633), each as (workflow, job, install-or-verify step).
LEGACY_37 = (
    ('unit-tests.yml', 'test', 'Install package and test dependencies'),
    ('unit-tests.yml', 'integration', 'Install package, test and generator dependencies'),
    ('python-compatibility.yml', 'compatibility', 'Verify package'),
)

#: Claims the tier split made false, each worded as it was somewhere before #1633,
#: or before 3.7 joined the KTLO tier. A denylist: it catches these phrasings
#: coming back and examines no others.
RETIRED_CLAIMS = re.compile('|'.join((
    r'3\.15 as an allowed-to-fail leg',
    r'3\.15 runs allowed-to-fail',
    r'supported range starts at 3\.10',
    r'CI matrix starts at 3\.10',
    r'CI covers \**3\.10',
    r'runs on 3\.10 through 3\.1[45]',
    r'repository supports 3\.10',
    r'matrix floor is 3\.(?:10|8)',
    r'3\.6 and 3\.7 are (?:in no matrix|left out|not run)',
    r'KTLO tier \(3\.8-3\.10\)',
    r'3\.8 through 3\.10\** are KTLO',
    r'end-of-life (?:versions that still run, )?3\.8(?:-| to )3\.10',
    r'the 3\.8-3\.10 legs',
    r'3\.8 to 3\.10 are best-effort',
    r'3\.8, 3\.9 and 3\.10 are end-of-life',
)))
#: Where :data:`RETIRED_CLAIMS` is looked for, as (directory, globs), plus root files.
#: The changelog is history and is left out.
PROSE_SCAN = (
    ('.github', ('*.yml', '*.md')),
    ('docs', ('*.rst', '*.py')),
    ('examples', ('*.rst', '*.txt', '*.py', '*.sh')),
    ('pcapkit', ('*.py',)),
    ('tests', ('*.py',)),
    ('util', ('*.py',)),
)
PROSE_FILES = ('pyproject.toml', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'Makefile')
#: Spelled-out counts, as the workflows page writes them.
WORDS = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5,
         'six': 6, 'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10}


def workflow(name: 'str') -> 'dict[str, Any]':
    """``name`` parsed, or the test skipped when PyYAML (the ``test`` extra) is absent."""
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest('PyYAML, from the test extra, is not installed')
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding='utf-8'))


def job(name: 'str', job_id: 'str') -> 'dict[str, Any]':
    """One job of a workflow."""
    return workflow(name)['jobs'][job_id]


def legs(spec: 'dict[str, Any]') -> 'list[dict[str, Any]]':
    """The matrix combinations GitHub expands ``spec`` to.

    The base axes' product, then each ``include`` entry: merged into every
    combination whose original values it matches, or added as one of its own --
    GitHub's documented ``include`` rule, which is what lets ``ktlo: true`` mark
    an existing leg as well as add a new one.

    """
    matrix = dict(spec['strategy']['matrix'])
    include = matrix.pop('include', [])
    combos = [{}]  # type: list[dict[str, Any]]
    for key, values in matrix.items():
        combos = [dict(combo, **{key: str(value)}) for combo in combos for value in values]
    for entry in include:
        entry = {key: str(value) if key in matrix else value for key, value in entry.items()}
        matched = [combo for combo in combos
                   if all(combo.get(key) == value for key, value in entry.items() if key in matrix)]
        added = False
        for combo in matched:
            if all(key in matrix or key not in combo for key in entry):
                combo.update(entry)
                added = True
        if not added:
            combos.append(dict(entry))
    return combos


def is_ktlo(leg: 'dict[str, Any]') -> 'bool':
    return leg.get('ktlo') is True


def bash(script: 'str', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
    """``script`` under ``bash -e``, GitHub's default shell, with ``env`` added."""
    return subprocess.run(['bash', '-e', '-c', script], env=dict(os.environ, **env),
                          capture_output=True, text=True, check=False, timeout=60)


class TestTheSupportedTierBlocks(unittest.TestCase):
    """3.11-3.15 everywhere, and nothing softens a supported leg."""

    def test_every_matrix_runs_the_supported_tier_as_blocking(self) -> None:
        for name, job_id, blocking in MATRICES:
            with self.subTest(workflow=name, job=job_id):
                spec = job(name, job_id)
                versions = sorted({leg['python-version'] for leg in legs(spec) if not is_ktlo(leg)})
                self.assertEqual(versions, sorted(blocking))
                self.assertIn(spec.get('continue-on-error', False), (False, KTLO_GUARD))

    def test_engine_tests_runs_every_supported_cell_in_its_blocking_step(self) -> None:
        steps = job('unit-tests.yml', 'engine-tests')['steps']
        setups = [step for step in steps if str(step.get('uses', '')).startswith('actions/setup-python@')]
        blocking = [step for step in setups if 'continue-on-error' not in step]
        self.assertEqual(len(blocking), 1)
        self.assertEqual(blocking[0]['with']['python-version'].split(), list(SUPPORTED))
        loop = next(step for step in steps if step.get('name') == 'Run the 3.11-3.15 cells')
        self.assertNotIn('continue-on-error', loop)
        self.assertNotIn('if', loop)
        self.assertIn(f"for py in {' '.join(SUPPORTED)};", loop['run'])

    def test_the_supported_tier_is_what_the_classifiers_list(self) -> None:
        text = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        listed = re.findall(r'"Programming Language :: Python :: (3\.\d+)"', text)
        self.assertEqual(listed, list(SUPPORTED))

    def test_requires_python_is_unchanged(self) -> None:
        """The owner's ruling: KTLO keeps old versions installable, it does not raise the floor."""
        text = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'(?m)^requires-python = (.+)$', text), ['">=3.6, <4"'])

    def test_ci_timing_pairs_the_coverage_leg_with_supported_legs_only(self) -> None:
        text = (ROOT / 'util' / 'ci_timing.py').read_text(encoding='utf-8')
        coverage = ast.literal_eval(re.search(r'(?m)^COVERAGE_JOB = (.+)$', text).group(1))  # type: ignore[union-attr]
        paired = ast.literal_eval(re.search(r'(?m)^PAIRED_JOBS = (\(.+\))$', text).group(1))  # type: ignore[union-attr]
        self.assertEqual(sorted((coverage,) + paired), [f'Python {v}' for v in SUPPORTED])


class TestTheKTLOTierNeverBlocks(unittest.TestCase):
    """Each KTLO leg exists, and none of them can fail what aggregates it."""

    def test_each_ktlo_leg_is_there(self) -> None:
        for name, job_id, versions in KTLO_LEGS:
            with self.subTest(workflow=name, job=job_id):
                found = sorted(leg['python-version'] for leg in legs(job(name, job_id)) if is_ktlo(leg))
                self.assertEqual(found, sorted(versions))

    def test_37_to_39_run_where_setup_python_still_builds_them(self) -> None:
        """No Ubuntu 26.04 build of any, and ``ubuntu-latest`` moves to 26.04."""
        for name, job_id, _ in KTLO_LEGS:
            spec = job(name, job_id)
            for leg in legs(spec):
                if leg['python-version'] in PINNED_OS:
                    with self.subTest(workflow=name, job=job_id, python=leg['python-version']):
                        self.assertEqual(leg.get('os'), PINNED_OS[leg['python-version']])
                        self.assertEqual(spec['runs-on'], "${{ matrix.os || 'ubuntu-latest' }}")

    def test_no_ktlo_leg_can_fail_an_aggregated_job(self) -> None:
        """Every step that can run and fail on a KTLO leg keeps that failure to itself."""
        for name, job_id in AGGREGATED:
            spec = job(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                self.assertNotIn('continue-on-error', spec)
            for step in spec['steps']:
                label = step.get('name') or step.get('uses')
                if str(step.get('uses', '')).startswith('actions/checkout@'):
                    continue
                condition = str(step.get('if', ''))
                if 'matrix.coverage' in condition or 'APT_CACHE_SAVE' in condition:
                    continue  # only ever on a supported leg: the coverage one, the cache saver
                if label == "Check the release tags name this run's commit":
                    continue  # #1634: blocks every leg alike, pinned in its own test module
                with self.subTest(workflow=name, job=job_id, step=label):
                    self.assertIn(step.get('continue-on-error'), (True, KTLO_GUARD))

    def test_engine_tests_isolates_the_ktlo_interpreter_and_cell(self) -> None:
        steps = job('unit-tests.yml', 'engine-tests')['steps']
        setup = [step for step in steps if str(step.get('uses', '')).startswith('actions/setup-python@')
                 and step.get('continue-on-error') is True]
        self.assertEqual([step['with']['python-version'] for step in setup], ['3.10'])
        cell = next(step for step in steps if step.get('name') == 'Run the 3.10 cell (KTLO, non-blocking)')
        self.assertIs(cell.get('continue-on-error'), True)
        self.assertIn('engine-cell.sh" 3.10', cell['run'])

    def test_a_compatibility_ktlo_leg_shows_red_without_failing_the_run(self) -> None:
        """No aggregate reads this job, so job-level ``continue-on-error`` is the right form."""
        spec = job('python-compatibility.yml', 'compatibility')
        self.assertEqual(spec.get('continue-on-error'), KTLO_GUARD)

    def test_no_ktlo_leg_is_a_required_context(self) -> None:
        spec = job('python-compatibility.yml', 'compatibility')
        template = spec['name']
        names = {}
        for leg in legs(spec):
            names[template.replace('${{ matrix.python-version }}', leg['python-version'])
                  .replace("${{ matrix.ktlo && ' (KTLO)' || '' }}", ' (KTLO)' if is_ktlo(leg) else '')] = leg
        self.assertNotIn('${{', ''.join(names), template)
        self.assertEqual({n for n, leg in names.items() if not is_ktlo(leg)}, REQUIRED - {'Required checks passed'})
        self.assertFalse({n for n, leg in names.items() if is_ktlo(leg)} & REQUIRED)
        comment = (WORKFLOWS / 'unit-tests.yml').read_text(encoding='utf-8')
        self.assertIn('five for `Compat Python 3.11`-`3.15`', comment)


class TestNoKTLOLegCanFailTheRelease(unittest.TestCase):
    """``release_status`` and the PyPI evidence, run as the workflow runs them."""

    def setUp(self) -> None:
        if shutil.which('bash') is None or shutil.which('python3') is None:  # pragma: no cover
            self.skipTest('bash and python3 are needed to run the workflow shell')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1633-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def pypi_complete(self, files: 'list[str]') -> 'str':
        """``PCAPKIT_PYPI_COMPLETE`` for a release holding ``files``, ``curl`` stubbed."""
        steps = job('create-release.yml', 'version_check')['steps']
        script = next(step for step in steps if step.get('name') == 'Check PyPI publish completeness')['run']
        reply = self.tmp / 'reply.json'
        reply.write_text(json.dumps({'urls': [{'filename': name} for name in files]}), encoding='utf-8')
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir(exist_ok=True)
        curl = bin_dir / 'curl'
        curl.write_text('#!/bin/bash\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && cp "$REPLY" "$2"; shift; done\n'
                        'printf 200\n', encoding='utf-8')
        curl.chmod(0o755)
        output = self.tmp / 'output'
        output.write_text('', encoding='utf-8')
        result = bash(script.replace('/tmp/pypi_release.json', str(self.tmp / 'release.json')),
                      {'PATH': f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', 'REPLY': str(reply),
                       'GITHUB_OUTPUT': str(output), 'PCAPKIT_VERSION': '1.5.0'})
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').split())['PCAPKIT_PYPI_COMPLETE']

    def test_pypi_completeness_counts_the_supported_tier_only(self) -> None:
        supported = [f'pypcapkit-1.5.0-{tag}-none-any.whl'
                     for tag in ('cp311', 'cp312', 'cp313', 'cp314', 'cp315', 'pp311')]
        ktlo = ['pypcapkit-1.5.0-cp310-none-any.whl', 'pypcapkit-1.5.0-pp310-none-any.whl']
        sdist = ['pypcapkit-1.5.0.tar.gz']
        self.assertEqual(self.pypi_complete(supported + sdist), 'true')
        self.assertEqual(self.pypi_complete(supported + ktlo + sdist), 'true')
        self.assertEqual(self.pypi_complete(supported[1:] + ktlo + sdist), 'false')
        self.assertEqual(self.pypi_complete(supported), 'false')

    def test_each_ktlo_leg_records_its_outcome_for_release_status(self) -> None:
        spec = job('create-release.yml', 'pypi')
        record = next(step for step in spec['steps'] if step.get('id') == 'ktlo')
        status = job('create-release.yml', 'release_status')['steps'][0]['env']
        for leg in (leg for leg in legs(spec) if is_ktlo(leg)):
            key = 'ktlo_' + leg['python-version'].replace('.', '')
            with self.subTest(leg=leg['python-version']):
                self.assertEqual(spec['outputs'][key], f'${{{{ steps.ktlo.outputs.{key} }}}}')
                self.assertIn(f'${{{{ needs.pypi.outputs.{key} }}}}', status.values())
                for outcomes, expected in (('success success failure success', 'failure'),
                                           ('success skipped success', 'success')):
                    output = self.tmp / 'output'
                    output.write_text('', encoding='utf-8')
                    result = bash(record['run'], {'LEG': leg['python-version'], 'OUTCOMES': outcomes,
                                                  'GITHUB_OUTPUT': str(output)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(encoding='utf-8'), f'{key}={expected}\n')

    def test_release_status_reports_a_failed_ktlo_leg_without_warning(self) -> None:
        script = job('create-release.yml', 'release_status')['steps'][0]['run']
        base = {'PCAPKIT_EVENT_NAME': 'push', 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': '',
                'PCAPKIT_UNIT_TESTS': 'success', 'PCAPKIT_VERSION_CHECK': 'success',
                'PCAPKIT_GITHUB_JOB': 'success', 'PCAPKIT_TAG_JOB': 'success',
                'PCAPKIT_PYPI_JOB': 'success', 'PCAPKIT_CONDA_JOB': 'success',
                'PCAPKIT_VERSION': '1.5.0', 'PCAPKIT_TAG_EXISTS': 'false',
                'PCAPKIT_CONDA_TAG_EXISTS': 'false', 'PCAPKIT_PYPI_COMPLETE': 'false',
                'PCAPKIT_CONDA_COMPLETE': 'false'}
        clean = bash(script, base)
        failed = bash(script, dict(base, PCAPKIT_PYPI_KTLO_310='failure',
                                   PCAPKIT_PYPI_KTLO_PYPY310='failure'))
        self.assertEqual((clean.returncode, failed.returncode), (0, 0), failed.stderr)
        self.assertIn('::notice title=Release complete::', failed.stdout)
        self.assertRegex(failed.stdout, r'::notice title=KTLO legs \(non-blocking\)::pypi 3\.10=failure '
                                        r'pypy3\.10=failure')
        self.assertNotRegex(failed.stdout, r'(?m)^::(warning|error)')
        self.assertNotIn('KTLO', clean.stdout)

    def test_no_conda_leg_is_ktlo_and_315_leaves_base_python_alone(self) -> None:
        """A KTLO 3.10 conda leg could only fail (soupsieve 3 needs >=3.11.5); 3.15 needs base left alone."""
        for name, job_id in (('create-release.yml', 'conda'), ('cron-conda.yml', 'conda-dist')):
            spec = job(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                self.assertFalse([leg for leg in legs(spec) if is_ktlo(leg)])
                setup = next(step for step in spec['steps']
                             if str(step.get('uses', '')).startswith('conda-incubator/setup-miniconda@'))
                self.assertEqual(setup['with']['python-version'],
                                 "${{ matrix.python-version != '3.15' && matrix.python-version || '' }}")


#: ``python`` for an install step: ``pip install -U`` passes, ``pip install -e`` prints
#: ``$PIP_OUTPUT`` and exits ``$PIP_STATUS``.
PIP_STUB = '''\
case "$*" in
  "-m pip install -U pip setuptools wheel") exit 0 ;;
  "-m pip install -e "*) printf '%s\\n' "$PIP_OUTPUT"; exit "$PIP_STATUS" ;;
esac
echo "unexpected python $*" >&2
exit 99
'''
#: ``python`` for ``Verify package``: compileall and the import, each scripted by env.
VERIFY_STUB = '''\
case "$1" in
  -m) printf '%s\\n' "$COMPILE_OUTPUT"; exit "$COMPILE_STATUS" ;;
  -c) [ "$IMPORT_STATUS" != 0 ] || echo 1.5.0; exit "$IMPORT_STATUS" ;;
esac
exit 99
'''
#: The head of ``python -m compileall -q pcapkit``'s output on CPython 3.7.16.
COMPILE_37 = '''\
*** Error compiling 'pcapkit/const/ftp/command.py'...
  File "pcapkit/const/ftp/command.py", line 286
    ABOR: 'Command' = 'ABOR', FEATCode.base, 'Abort', CommandType.S, ConformanceRequirement.M
                            ^
SyntaxError: invalid syntax

*** Error compiling 'pcapkit/const/ftp/return_code.py'...
  File "pcapkit/const/ftp/return_code.py", line 116
    CODE_110: 'ReturnCode' = 110, 'Restart marker replay.'
                                ^
SyntaxError: invalid syntax
'''
#: pip 24.0's last lines installing ``.[test,...]`` on CPython 3.7.16.
PIP_37 = ('INFO: pip is looking at multiple versions of pypcapkit[crypto,dpkt,ngap,test] to '
          'determine which version is compatible with other requirements.\n'
          'ERROR: Ignored the following versions that require a different python version: '
          '8.0.0 Requires-Python >=3.8\n'
          'ERROR: Could not find a version that satisfies the requirement pytest>=8; '
          'extra == "test" (from pypcapkit[crypto,dpkt,ngap,test]) (from versions: 7.4.4)\n'
          'ERROR: No matching distribution found for pytest>=8; extra == "test"')
LEG_37 = 'Python 3.7 (KTLO, non-blocking)'


def workflow_commands(output: 'str') -> 'list[str]':
    """The workflow-command lines of ``output``."""
    return [line for line in output.splitlines() if line.startswith('::')]


class TestPython37IsKTLO(unittest.TestCase):
    """3.7 runs, non-blocking, and stops at the first failure with one annotation."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is needed to run the workflow shell')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1633-37-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def run_step(self, name: 'str', job_id: 'str', step_name: 'str', stub: 'str',
                 env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
        """Step ``step_name`` under ``shell: bash`` (``-eo pipefail``), ``python`` stubbed."""
        step = next(step for step in job(name, job_id)['steps'] if step.get('name') == step_name)
        self.assertEqual(step.get('shell'), 'bash', 'pipefail is what keeps `tee` from hiding a failure')
        self.assertEqual(step['env']['LEG'], "Python ${{ matrix.python-version }}"
                                             "${{ matrix.ktlo && ' (KTLO, non-blocking)' || '' }}")
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir(exist_ok=True)
        python = bin_dir / 'python'
        python.write_text('#!/bin/bash\n' + stub, encoding='utf-8')
        python.chmod(0o755)
        return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', step['run']],
                              env=dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}',
                                       RUNNER_TEMP=str(self.tmp), LEG=LEG_37, **env),
                              capture_output=True, text=True, check=False, timeout=60)

    def test_37_is_a_ktlo_leg_of_exactly_the_three_test_matrices(self) -> None:
        """On ubuntu-22.04; not engine-tests or pypcap-parity (``ubuntu-latest`` only), nor a release leg."""
        for name, job_id, _ in LEGACY_37:
            spec = job(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                found = [leg for leg in legs(spec) if leg['python-version'] == '3.7']
                self.assertEqual(found, [{'python-version': '3.7', 'ktlo': True, 'os': 'ubuntu-22.04'}])
                self.assertTrue(spec['name'].endswith("${{ matrix.ktlo && ' (KTLO)' || '' }}"))
        joined = {(name, job_id) for name, job_id, _ in MATRICES
                  if '3.7' in [leg['python-version'] for leg in legs(job(name, job_id))]}
        engines = [str(step['with']['python-version']) for step in job('unit-tests.yml', 'engine-tests')['steps']
                   if str(step.get('uses', '')).startswith('actions/setup-python@')]
        if '3.7' in ' '.join(engines).split():
            joined.add(('unit-tests.yml', 'engine-tests'))
        self.assertEqual(joined, {(name, job_id) for name, job_id, _ in LEGACY_37})

    def test_a_leg_that_cannot_install_stops_there(self) -> None:
        """The install needs setup-python's interpreter, and every later step needs the install.

        ``outcome``, not ``conclusion``: ``continue-on-error`` turns a failed step's
        conclusion into ``success``, so only its outcome still says it failed.

        """
        for name, job_id, install in LEGACY_37[:2]:
            steps = job(name, job_id)['steps']
            setup = next(step for step in steps if str(step.get('uses', '')).startswith('actions/setup-python@'))
            index = next(i for i, step in enumerate(steps) if step.get('name') == install)
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(setup.get('id'), 'python')
                self.assertEqual(steps[index].get('id'), 'install')
                self.assertEqual(steps[index].get('if'), "${{ steps.python.outcome == 'success' }}")
            for step in steps[index + 1:]:
                condition = str(step.get('if', ''))
                if 'matrix.coverage' in condition:
                    continue  # the 3.14 leg only, which a failed install fails anyway
                with self.subTest(workflow=name, job=job_id, step=step.get('name') or step.get('uses')):
                    self.assertIn("steps.install.outcome == 'success'", condition)

    def test_a_failed_install_fails_once_naming_pips_reason(self) -> None:
        for name, job_id, install in LEGACY_37[:2]:
            with self.subTest(job=job_id):
                result = self.run_step(name, job_id, install, PIP_STUB, {'PIP_OUTPUT': PIP_37, 'PIP_STATUS': '1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(workflow_commands(result.stdout + result.stderr), [
                    f'::error title=pcapkit did not install on {LEG_37}::No matching distribution found '
                    'for pytest>=8; extra == "test". The rest of this leg is skipped.'])
                self.assertEqual((self.tmp / 'pip-install.log').read_text(encoding='utf-8'), PIP_37 + '\n')

    def test_an_install_failure_without_an_error_line_is_still_named(self) -> None:
        for output, reason in (('Killed', "pip failed without an ERROR line; see this step's log"),
                               ('ERROR: 100% of the index timed out', '100%25 of the index timed out')):
            with self.subTest(output=output):
                result = self.run_step('unit-tests.yml', 'test', LEGACY_37[0][2], PIP_STUB,
                                       {'PIP_OUTPUT': output, 'PIP_STATUS': '1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(workflow_commands(result.stdout), [
                    f'::error title=pcapkit did not install on {LEG_37}::{reason}. The rest of this leg is skipped.'])

    def test_a_clean_install_passes_without_an_annotation(self) -> None:
        for name, job_id, install in LEGACY_37[:2]:
            with self.subTest(job=job_id):
                result = self.run_step(name, job_id, install, PIP_STUB,
                                       {'PIP_OUTPUT': 'Successfully installed pypcapkit-1.5.0', 'PIP_STATUS': '0'})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(workflow_commands(result.stdout), [])

    def test_the_compatibility_leg_names_its_first_compile_error(self) -> None:
        cases = (
            ({'COMPILE_OUTPUT': COMPILE_37, 'COMPILE_STATUS': '1', 'IMPORT_STATUS': '0'},
             [f'::error title=pcapkit does not compile on {LEG_37}::2 modules fail to compile, the first at '
              'File "pcapkit/const/ftp/command.py", line 286; see this step\'s log.']),
            ({'COMPILE_OUTPUT': '', 'COMPILE_STATUS': '0', 'IMPORT_STATUS': '1'},
             [f"::error title=pcapkit does not import on {LEG_37}::See the traceback in this step's log."]),
            ({'COMPILE_OUTPUT': '', 'COMPILE_STATUS': '0', 'IMPORT_STATUS': '0'}, []),
        )  # type: tuple[tuple[dict[str, str], list[str]], ...]
        for env, expected in cases:
            with self.subTest(compile=env['COMPILE_STATUS'], imported=env['IMPORT_STATUS']):
                result = self.run_step('python-compatibility.yml', 'compatibility', 'Verify package',
                                       VERIFY_STUB, env)
                self.assertEqual(bool(result.returncode), bool(expected), result.stderr)
                self.assertEqual(workflow_commands(result.stdout), expected)
                if env['COMPILE_STATUS'] != '0':
                    self.assertIn('SyntaxError: invalid syntax', result.stdout)


def prose(path: 'pathlib.Path') -> 'str':
    """``path``'s text with each line break, and a leading ``#``/``#:`` after it, as one space."""
    return re.sub(r'[ \t]*\n[ \t]*(?:#:?[ \t]*)?', ' ', path.read_text(encoding='utf-8', errors='replace'))


class TestTheProseFollowsTheTiers(unittest.TestCase):
    """What the docs and comments say about the matrices, read against the matrices.

    Nothing executes these, so a tier change leaves them stale without failing
    anything else: round one of #1633 left the workflows page counting five
    ``test`` legs where there are eight, and six comments naming 3.10 as CI's floor
    or 3.15 as allowed to fail.

    """

    def test_the_workflows_page_counts_each_matrix_jobs_legs(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        engines = {version for step in job('unit-tests.yml', 'engine-tests')['steps']
                   if str(step.get('uses', '')).startswith('actions/setup-python@')
                   for version in str(step['with']['python-version']).split()}
        claims = {
            r'``test`` \((\w+) Python legs': len(legs(job('unit-tests.yml', 'test'))),
            r'``integration`` \((\w+)\)': len(legs(job('unit-tests.yml', 'integration'))),
            r'``pypcap-parity`` \((\w+)\)': len(legs(job('unit-tests.yml', 'pypcap-parity'))),
            r'each looping over (\w+) Python versions': len(engines),
        }
        for pattern, count in claims.items():
            with self.subTest(claim=pattern):
                self.assertEqual([WORDS.get(word) for word in re.findall(pattern, page)], [count])

    def test_no_retired_tier_claim_is_left_in_the_tree(self) -> None:
        paths = [ROOT / name for name in PROSE_FILES if (ROOT / name).is_file()]
        for directory, globs in PROSE_SCAN:
            paths.extend(path for pattern in globs for path in (ROOT / directory).rglob(pattern))
        found = []
        for path in sorted(set(paths)):
            relative = path.relative_to(ROOT)
            if path == pathlib.Path(__file__).resolve() or any(
                    part.startswith('changelog') for part in relative.parts):
                continue
            found.extend(f'{relative}: {match.group(0)!r}' for match in RETIRED_CLAIMS.finditer(prose(path)))
        self.assertEqual(found, [])


if __name__ == '__main__':
    unittest.main()
