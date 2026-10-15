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
the prose that states the tiers back against the matrices. #1672 later made
every KTLO leg conclude ``success``, Compat's included, and report a failed step
as a warning; :mod:`tests.project.test_ktlo_legs_stay_green_1672` pins that.

3.7 joined the tier afterwards, at the owner's request, and cannot install or
import pcapkit: the ``test`` extra's ``pytest>=8`` needs 3.8, and the sources use
3.8 syntax. So each of its legs fails a step by design, and
:class:`TestPython37IsKTLO` pins that they fail fast and say why, at warning level
-- the install and verify steps are executed with ``python`` stubbed, and each
annotation is parsed as the runner parses it. 3.6 stays out: setup-python builds
it only for retired images.

Since #1660 the tiers are declared once, in :file:`.github/python-versions.toml`,
and every matrix is read from it, so the expectations below are read from it
too: what is pinned here is that each tier keeps its mechanics wherever the file
puts a version. :mod:`tests.project.test_python_versions_1660` pins that the file
reproduces the matrices ``main`` spelt out before.

"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_versions_1660 import legs as expand
from tests.project.test_python_versions_1660 import matrix, resolve, setups, workflow
from tests.project.test_python_versions_1660 import script as versions_script

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'

#: The tiers, from .github/python-versions.toml (#1660); empty if it is missing.
try:
    TIERS = versions_script().load()
except AssertionError:  # pragma: no cover
    TIERS = {'latest': None, 'versions': {'cpython': {}, 'pypy': {}}}


def tier(impl: 'str', name: 'str') -> 'tuple[str, ...]':
    return tuple(v for v, entry in TIERS['versions'][impl].items() if entry['tier'] == name)


SUPPORTED = tier('cpython', 'supported')
KTLO = tier('cpython', 'ktlo')
#: The image each version needs where ``ubuntu-latest`` cannot provide it:
#: setup-python has no Ubuntu 26.04 build of 3.7-3.9, and ubuntu-22.04, 3.7's, is
#: deprecated and retires 2027-04-17.
PINNED_OS = {v: entry['runner'] for v, entry in TIERS['versions']['cpython'].items() if 'runner' in entry}
#: The KTLO versions a job pinned to ``ubuntu-latest`` runs.
KTLO_ON_LATEST = tuple(v for v in KTLO if v not in PINNED_OS)
#: PyPCAP/PyPCAPFile's ``python_version < '3.12'`` marker bounds ``pypcap-parity``.
PARITY = tuple(v for v in SUPPORTED + KTLO_ON_LATEST if tuple(map(int, v.split('.'))) < (3, 12))
#: The step-level guard every failure-prone step of a KTLO leg's job carries.
KTLO_GUARD = '${{ matrix.ktlo == true }}'
#: The job-level level of every annotation a failing step writes (#1672).
ANNOTATION_LEVEL = "${{ matrix.ktlo && 'warning' || 'error' }}"
#: The experimental job's guard, level and ``LEG`` (#1732): every leg of it is
#: experimental, so each is a literal.
EXPERIMENTAL_GUARD = True
EXPERIMENTAL_LEVEL = 'warning'
#: A step's ``LEG``, the leg's name in its annotations, in a KTLO job and in ``experimental``.
LEG_TEMPLATE = "Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO, non-blocking)' || '' }}"
EXPERIMENTAL_LEG_TEMPLATE = 'Python ${{ matrix.python-version }} (experimental, non-blocking)'
#: The job holding experimental legs, the only one (#1660), in a workflow of its own
#: since #1732, so that nothing in unit-tests.yml waits on it.
EXPERIMENTAL_JOB = ('experimental.yml', 'experimental')
#: Ruleset 23497679's required contexts, which a tier change edits with the file.
REQUIRED = frozenset({'Required checks passed'} | {f'Compat Python {v}' for v in SUPPORTED})

#: Every Python matrix, as (workflow, job, the blocking versions it must run).
MATRICES = (
    ('unit-tests.yml', 'test', SUPPORTED),
    ('unit-tests.yml', 'integration', SUPPORTED),
    ('unit-tests.yml', 'pypcap-parity', tuple(v for v in PARITY if v in SUPPORTED)),
    ('python-compatibility.yml', 'compatibility', SUPPORTED),
    ('create-release.yml', 'pypi', SUPPORTED + tier('pypy', 'supported')),
    ('create-release.yml', 'conda', SUPPORTED),
    ('cron-conda.yml', 'conda-dist', SUPPORTED),
)
#: The jobs a single ``needs.<job>.result`` aggregates, so KTLO must stay step-level.
AGGREGATED = (('unit-tests.yml', 'test'), ('unit-tests.yml', 'integration'),
              ('unit-tests.yml', 'pypcap-parity'), ('create-release.yml', 'pypi'))
#: Where each KTLO leg must be, as (workflow, job, KTLO versions). unit-tests.yml's
#: are jobs of their own since #1738, which nothing gating waits on.
KTLO_LEGS = (
    ('unit-tests.yml', 'test-ktlo', KTLO),
    ('unit-tests.yml', 'integration-ktlo', KTLO),
    ('unit-tests.yml', 'pypcap-parity-ktlo', tuple(v for v in PARITY if v in KTLO)),
    ('python-compatibility.yml', 'compatibility', KTLO),
    ('create-release.yml', 'pypi', KTLO_ON_LATEST + tier('pypy', 'ktlo')),
)
#: The jobs 3.7 joins (#1633), each as (workflow, job, install-or-verify step).
LEGACY_37 = (
    ('unit-tests.yml', 'test-ktlo', 'Install package and test dependencies'),
    ('unit-tests.yml', 'integration-ktlo', 'Install package, test and generator dependencies'),
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
    r'end-of-life (?:versions that still run, )?3\.8(?:-| to | through )3\.10',
    r'the 3\.8-3\.10 legs',
    r'KTLO legs 3\.8-3\.10',
    r'3\.8 to 3\.10 are best-effort',
    r'3\.8, 3\.9 and 3\.10 are end-of-life',
    r"CI's range starts at 3\.8",
    r'oldest tested leg is ``Python 3\.8',
    r"3\.7's legs are red by design",
    # #1672: no KTLO leg shows red, Compat's included, and a failed KTLO step's
    # own annotation is a warning.
    r'3\.7 is red by design',
    r'a failed leg shows red without failing the run',
    r'it shows red, and the run stays green',
    r'Only the ``Compat`` leg shows red',
    r'only Compat.s shows red',
    r'may stay red without blocking',
    r'shows as a red step and an error annotation',
    r'shows as a failed step and an error annotation',
    r'with one error annotation saying why',
    r'a KTLO leg carries job-level',
)))
#: Where :data:`RETIRED_CLAIMS` is looked for, as (directory, globs), plus root files.
#: The changelog is history and is left out.
PROSE_SCAN = (
    ('.github', ('*.yml', '*.md')),
    ('docs', ('*.rst', '*.py')),
    ('examples', ('*.md', '*.txt', '*.py', '*.sh')),
    ('pcapkit', ('*.py',)),
    ('tests', ('*.py',)),
    ('util', ('*.py',)),
)
PROSE_FILES = ('pyproject.toml', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'Makefile')
#: Spelled-out counts, as the workflows page writes them.
WORDS = {'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5,
         'six': 6, 'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10,
         'eleven': 11, 'twelve': 12, 'thirteen': 13, 'fourteen': 14, 'fifteen': 15}


def job(name: 'str', job_id: 'str') -> 'dict[str, Any]':
    """One job of a workflow."""
    return workflow(name)['jobs'][job_id]


def legs(name: 'str', job_id: 'str') -> 'list[dict[str, Any]]':
    """The legs GitHub expands job ``job_id``'s matrix to, read from the tier file (#1660)."""
    return expand(matrix(name, job_id))


def engine_inputs() -> 'list[tuple[dict[str, Any], str]]':
    """engine-tests' setup-python steps, each with the versions its input reads."""
    return [(step, resolve('unit-tests.yml', 'engine-tests', step['with']['python-version']))
            for step in setups(job('unit-tests.yml', 'engine-tests'))]


def is_ktlo(leg: 'dict[str, Any]') -> 'bool':
    return leg.get('ktlo') is True


def is_experimental(leg: 'dict[str, Any]') -> 'bool':
    """An experimental leg (#1660): non-blocking like a KTLO one, but not KTLO."""
    return leg.get('experimental') is True


def is_nonblocking(leg: 'dict[str, Any]') -> 'bool':
    return is_ktlo(leg) or is_experimental(leg)


def guard(name: 'str', job_id: 'str') -> 'Any':
    """The step-level guard of job ``job_id``'s failure-prone steps."""
    return EXPERIMENTAL_GUARD if (name, job_id) == EXPERIMENTAL_JOB else KTLO_GUARD


def annotation_level(name: 'str', job_id: 'str') -> 'str':
    """Job ``job_id``'s ``ANNOTATION_LEVEL``."""
    return EXPERIMENTAL_LEVEL if (name, job_id) == EXPERIMENTAL_JOB else ANNOTATION_LEVEL


def leg_template(name: 'str', job_id: 'str') -> 'str':
    """Job ``job_id``'s ``LEG``, on each step that names the leg in an annotation."""
    return EXPERIMENTAL_LEG_TEMPLATE if (name, job_id) == EXPERIMENTAL_JOB else LEG_TEMPLATE


def leg_label(leg: 'dict[str, Any]') -> 'str':
    """What ``LEG`` reads on ``leg``."""
    if is_experimental(leg):
        return f"Python {leg['python-version']} (experimental, non-blocking)"
    return f"Python {leg['python-version']}{' (KTLO, non-blocking)' if is_ktlo(leg) else ''}"


def bash(script: 'str', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
    """``script`` under ``bash -e``, GitHub's default shell, with ``env`` added."""
    return subprocess.run(['bash', '-e', '-c', script], env=dict(os.environ, **env),
                          capture_output=True, text=True, check=False, timeout=60)


class TestTheSupportedTierBlocks(unittest.TestCase):
    """The supported tier everywhere, and nothing softens a supported leg."""

    def test_every_matrix_runs_the_supported_tier_as_blocking(self) -> None:
        self.assertTrue(SUPPORTED, 'the tier file lists no supported CPython')
        for name, job_id, blocking in MATRICES:
            with self.subTest(workflow=name, job=job_id):
                spec = job(name, job_id)
                versions = sorted({leg['python-version'] for leg in legs(name, job_id) if not is_nonblocking(leg)})
                self.assertEqual(versions, sorted(blocking))
                # #1672: not even KTLO-only; job-level, a failed leg's check run is red.
                self.assertNotIn('continue-on-error', spec)

    def test_engine_tests_runs_every_supported_cell_in_its_blocking_step(self) -> None:
        steps = job('unit-tests.yml', 'engine-tests')['steps']
        blocking = [versions for step, versions in engine_inputs() if 'continue-on-error' not in step]
        self.assertEqual([versions.split() for versions in blocking], [list(SUPPORTED)])
        loop = next(step for step in steps if step.get('name') == 'Run the supported cells')
        self.assertNotIn('continue-on-error', loop)
        self.assertNotIn('if', loop)
        self.assertEqual(resolve('unit-tests.yml', 'engine-tests', loop['env']['PYTHONS']).split(), list(SUPPORTED))
        self.assertIn('for py in $PYTHONS;', loop['run'])

    def test_the_supported_tier_is_what_the_classifiers_list(self) -> None:
        text = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        listed = re.findall(r'"Programming Language :: Python :: (3\.\d+)"', text)
        self.assertEqual(listed, list(SUPPORTED))

    def test_requires_python_is_unchanged(self) -> None:
        """The owner's ruling: KTLO keeps old versions installable, it does not raise the floor."""
        text = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'(?m)^requires-python = (.+)$', text), ['">=3.6, <4"'])

    def test_ci_timing_pairs_the_coverage_leg_with_supported_legs_only(self) -> None:
        spec = importlib.util.spec_from_file_location('ci_timing_1633', ROOT / 'util' / 'ci_timing.py')
        assert spec is not None and spec.loader is not None
        ci_timing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ci_timing)  # type: ignore[union-attr]
        self.assertEqual(ci_timing.COVERAGE_JOB, f"Python {TIERS['latest']}")
        self.assertEqual(sorted((ci_timing.COVERAGE_JOB,) + ci_timing.PAIRED_JOBS),
                         sorted(f'Python {v}' for v in SUPPORTED))

    def test_pypcap_parity_stops_where_the_engines_markers_do(self) -> None:
        """The script's ``PARITY_BELOW`` is pyproject.toml's PyPCAP and PyPCAPFile marker."""
        text = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        for extra in ('PyPCAP', 'PyPCAPFile'):
            with self.subTest(extra=extra):
                marker = re.search(rf"(?m)^{extra} = \[ \"\w+; python_version < '(3\.\d+)'\" \]$", text)
                self.assertIsNotNone(marker)
                self.assertEqual(tuple(map(int, marker.group(1).split('.'))), versions_script().PARITY_BELOW)  # type: ignore[union-attr]


class TestTheKTLOTierNeverBlocks(unittest.TestCase):
    """Each KTLO leg exists, and none of them can fail what aggregates it."""

    def test_each_ktlo_leg_is_there(self) -> None:
        self.assertTrue(KTLO, 'the tier file lists no KTLO CPython')
        for name, job_id, versions in KTLO_LEGS:
            with self.subTest(workflow=name, job=job_id):
                found = sorted(leg['python-version'] for leg in legs(name, job_id) if is_ktlo(leg))
                self.assertEqual(found, sorted(versions))

    def test_37_to_39_run_where_setup_python_still_builds_them(self) -> None:
        """No Ubuntu 26.04 build of any, and ``ubuntu-latest`` moves to 26.04."""
        for name, job_id, _ in KTLO_LEGS:
            spec = job(name, job_id)
            for leg in legs(name, job_id):
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
                condition = str(step.get('if', ''))
                if 'matrix.coverage' in condition or 'APT_CACHE_SAVE' in condition:
                    continue  # only ever on a supported leg: the coverage one, the cache saver
                if label in ('Checkout code', "Check the release tags name this run's commit"):
                    continue  # #1634: blocks every leg alike, pinned in its own test module
                # The summary's own guard: it runs on KTLO legs only.
                expected = {'KTLO summary': KTLO_GUARD}.get(label, guard(name, job_id))
                with self.subTest(workflow=name, job=job_id, step=label):
                    self.assertIn(step.get('continue-on-error'), (True, expected))

    def test_engine_tests_isolates_the_ktlo_interpreter_and_cell(self) -> None:
        """The KTLO versions ``ubuntu-latest`` can run, in steps of their own that cannot fail the job."""
        steps = job('unit-tests.yml', 'engine-tests')['steps']
        setup = [versions for step, versions in engine_inputs() if step.get('continue-on-error') is True]
        self.assertEqual([versions.split() for versions in setup], [list(KTLO_ON_LATEST)])
        cell = next(step for step in steps if step.get('name') == 'Run the KTLO cells (non-blocking)')
        self.assertIs(cell.get('continue-on-error'), True)
        self.assertEqual(resolve('unit-tests.yml', 'engine-tests', cell['env']['PYTHONS']).split(),
                         list(KTLO_ON_LATEST))
        self.assertIn('engine-cell.sh" "$py"', cell['run'])

    def test_no_ktlo_leg_is_a_required_context(self) -> None:
        spec = job('python-compatibility.yml', 'compatibility')
        template = spec['name']
        names = {}
        for leg in legs('python-compatibility.yml', 'compatibility'):
            names[template.replace('${{ matrix.python-version }}', leg['python-version'])
                  .replace("${{ matrix.ktlo && ' (KTLO)' || '' }}", ' (KTLO)' if is_ktlo(leg) else '')] = leg
        self.assertNotIn('${{', ''.join(names), template)
        self.assertEqual({n for n, leg in names.items() if not is_ktlo(leg)}, REQUIRED - {'Required checks passed'})
        self.assertFalse({n for n, leg in names.items() if is_ktlo(leg)} & REQUIRED)


class TestNoKTLOLegCanFailTheRelease(unittest.TestCase):
    """``release_status`` and the PyPI evidence, run as the workflow runs them."""

    def setUp(self) -> None:
        if shutil.which('bash') is None or shutil.which('python3') is None:  # pragma: no cover
            self.skipTest('bash and python3 are needed to run the workflow shell')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1633-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def pypi_complete(self, files: 'list[str]') -> 'str':
        """``PCAPKIT_PYPI_COMPLETE`` for a release holding ``files``, ``curl`` stubbed.

        The supported wheel tags reach the step as ``PCAPKIT_PYPI_WHEELS``, read
        from the tier file as the workflow reads it (#1660): this run's, which
        the ``released`` step passes on while the version is untagged.

        """
        steps = job('create-release.yml', 'version_check')['steps']
        step = next(step for step in steps if step.get('name') == 'Check PyPI publish completeness')
        script = step['run']
        self.assertEqual(step['env']['PCAPKIT_PYPI_WHEELS'], '${{ steps.released.outputs.pypi-wheels }}')
        released = next(step for step in steps if step.get('id') == 'released')
        wheels = resolve('create-release.yml', 'version_check', released['env']['PCAPKIT_PYPI_WHEELS'])
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
                       'GITHUB_OUTPUT': str(output), 'PCAPKIT_VERSION': '1.5.0',
                       'PCAPKIT_PYPI_WHEELS': wheels})
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').split())['PCAPKIT_PYPI_COMPLETE']

    def test_pypi_completeness_counts_the_supported_tier_only(self) -> None:
        tags = {leg['python-version']: versions_script().wheel_tag(leg['python-version'])
                for leg in legs('create-release.yml', 'pypi')}
        supported = [f'pypcapkit-1.5.0-{tags[v]}-none-any.whl' for v in SUPPORTED + tier('pypy', 'supported')]
        ktlo = [f'pypcapkit-1.5.0-{tags[v]}-none-any.whl' for v in KTLO_ON_LATEST + tier('pypy', 'ktlo')]
        self.assertTrue(supported and ktlo)
        sdist = ['pypcapkit-1.5.0.tar.gz']
        self.assertEqual(self.pypi_complete(supported + sdist), 'true')
        self.assertEqual(self.pypi_complete(supported + ktlo + sdist), 'true')
        self.assertEqual(self.pypi_complete(supported[1:] + ktlo + sdist), 'false')
        self.assertEqual(self.pypi_complete(supported), 'false')

    def test_each_ktlo_leg_records_its_outcome_for_release_status(self) -> None:
        spec = job('create-release.yml', 'pypi')
        record = next(step for step in spec['steps'] if step.get('id') == 'ktlo')
        status = job('create-release.yml', 'release_status')['steps'][0]['env']
        for leg in (leg for leg in legs('create-release.yml', 'pypi') if is_ktlo(leg)):
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
                self.assertFalse([leg for leg in legs(name, job_id) if is_ktlo(leg)])
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
#: :data:`LEG_37` as a ``title=`` property must carry it: ``,`` escaped (see :func:`runner_parse`).
TITLE_37 = 'Python 3.7 (KTLO%2C non-blocking)'
#: The 3.7 leg's matrix entry, and a supported leg's, as :meth:`TestPython37IsKTLO.run_step` takes them.
KTLO_37 = {'python-version': '3.7', 'ktlo': True}
SUPPORTED_312 = {'python-version': '3.12'}
#: Every KTLO leg's install step, as (workflow, job, step): it needs setup-python's ``python`` (#1672).
INSTALLS = (
    LEGACY_37[0], LEGACY_37[1],
    ('unit-tests.yml', 'pypcap-parity', 'Install package, test and generator dependencies'),
    ('python-compatibility.yml', 'compatibility', 'Install package'),
)


def workflow_commands(output: 'str') -> 'list[str]':
    """The workflow-command lines of ``output``."""
    return [line for line in output.splitlines() if line.startswith('::')]


#: ``(escaped, character)`` pairs, in the order actions/runner un-escapes them.
PROPERTY_ESCAPES = (('%0D', '\r'), ('%0A', '\n'), ('%3A', ':'), ('%2C', ','), ('%25', '%'))
DATA_ESCAPES = (('%0D', '\r'), ('%0A', '\n'), ('%25', '%'))


def runner_parse(line: 'str') -> 'Optional[tuple[str, dict[str, str], str]]':
    """``line`` as the runner reads it: ``(command, properties, message)``, or :data:`None`.

    A port of ``ActionCommand.TryParseV2`` and its un-escaping, from
    ``src/Runner.Common/ActionCommand.cs`` in actions/runner at 5f0b3ddcc. The
    properties end at the first ``::`` after the leading one (``:69``), and are
    split on every ``,`` (``:100``, ``propertiesStr.Split(new[] { ',' }, ...)``)
    *before* ``%2C`` becomes a comma (``:30``, ``:106``). A piece holding no
    ``=`` is dropped without a word, so ``title=on 3.7 (KTLO, non-blocking)``
    renders as "on 3.7 (KTLO".

    """
    message = line.lstrip()
    if not message.startswith('::'):
        return None
    end = message.find('::', 2)
    if end < 0:
        return None
    command, _, rest = message[2:end].partition(' ')
    properties = {}  # type: dict[str, str]
    for piece in filter(None, rest.strip().split(',')):
        pair = [part for part in piece.split('=', 1) if part]
        if len(pair) == 2:
            value = pair[1]
            for escaped, char in PROPERTY_ESCAPES:
                value = value.replace(escaped, char)
            properties[pair[0].lower()] = value  # an OrdinalIgnoreCase dictionary
    data = message[end + 2:]
    for escaped, char in DATA_ESCAPES:
        data = data.replace(escaped, char)
    return command, properties, data


def titles(output: 'str') -> 'list[str]':
    """Each workflow command's ``title`` in ``output``, as the run summary shows it."""
    parsed = (runner_parse(line) for line in workflow_commands(output))
    return [command[1].get('title', '') for command in parsed if command is not None]


class TestPython37IsKTLO(unittest.TestCase):
    """3.7 runs, non-blocking, and stops at the first failure with one warning."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is needed to run the workflow shell')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1633-37-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def run_step(self, name: 'str', job_id: 'str', step_name: 'str', stub: 'str',
                 env: 'dict[str, str]', leg: 'Optional[dict[str, Any]]' = None,
                 ) -> 'subprocess.CompletedProcess[str]':
        """Step ``step_name`` on ``leg`` (3.7's by default) under ``shell: bash``, ``python`` stubbed.

        ``LEG`` and the job's ``ANNOTATION_LEVEL`` get the values their expressions
        take on that leg, and ``-eo pipefail`` is what ``shell: bash`` runs.

        """
        leg = KTLO_37 if leg is None else leg
        spec = job(name, job_id)
        step = next(step for step in spec['steps'] if step.get('name') == step_name)
        self.assertEqual(step.get('shell'), 'bash', 'pipefail is what keeps `tee` from hiding a failure')
        self.assertEqual(step['env']['LEG'], leg_template(name, job_id))
        self.assertEqual(spec['env']['ANNOTATION_LEVEL'], annotation_level(name, job_id))
        env = dict(env, LEG=leg_label(leg), ANNOTATION_LEVEL='warning' if is_nonblocking(leg) else 'error')
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir(exist_ok=True)
        python = bin_dir / 'python'
        python.write_text('#!/bin/bash\n' + stub, encoding='utf-8')
        python.chmod(0o755)
        return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', step['run']],
                              env=dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}',
                                       RUNNER_TEMP=str(self.tmp), **env),
                              capture_output=True, text=True, check=False, timeout=60)

    def test_37_is_a_ktlo_leg_of_exactly_the_three_test_matrices(self) -> None:
        """On ubuntu-22.04; not engine-tests or pypcap-parity (``ubuntu-latest`` only), nor a release leg."""
        for name, job_id, _ in LEGACY_37:
            spec = job(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                found = [leg for leg in legs(name, job_id) if leg['python-version'] == '3.7']
                self.assertEqual(found, [{'python-version': '3.7', 'ktlo': True, 'os': 'ubuntu-22.04'}])
                self.assertTrue(spec['name'].endswith((' (KTLO)', "${{ matrix.ktlo && ' (KTLO)' || '' }}")))
        joined = {(name, job_id) for name, job_id, _ in MATRICES + KTLO_LEGS
                  if '3.7' in [leg['python-version'] for leg in legs(name, job_id)]}
        engines = [versions for _, versions in engine_inputs()]
        if '3.7' in ' '.join(engines).split():
            joined.add(('unit-tests.yml', 'engine-tests'))
        self.assertEqual(joined, {(name, job_id) for name, job_id, _ in LEGACY_37})

    def test_a_leg_that_cannot_install_stops_there(self) -> None:
        """The install needs setup-python's interpreter, and every later step needs the install.

        ``outcome``, not ``conclusion``: ``continue-on-error`` turns a failed step's
        conclusion into ``success``, so only its outcome still says it failed. #1672
        brought Compat and ``pypcap-parity`` in; ``KTLO summary`` is the one step
        that has to run after a failed install, to report it.

        """
        for name, job_id, install in INSTALLS:
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
                    continue  # the `latest` leg only, which a failed install fails anyway
                if step.get('name') in ('KTLO summary', 'Experimental summary'):
                    continue
                with self.subTest(workflow=name, job=job_id, step=step.get('name') or step.get('uses')):
                    self.assertIn("steps.install.outcome == 'success'", condition)

    def test_a_failed_install_fails_once_naming_pips_reason(self) -> None:
        for name, job_id, install in LEGACY_37[:2]:
            with self.subTest(job=job_id):
                result = self.run_step(name, job_id, install, PIP_STUB, {'PIP_OUTPUT': PIP_37, 'PIP_STATUS': '1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(workflow_commands(result.stdout + result.stderr), [
                    f'::warning title=pcapkit did not install on {TITLE_37}::No matching distribution found '
                    'for pytest>=8; extra == "test". The rest of this leg is skipped.'])
                self.assertEqual(titles(result.stdout), [f'pcapkit did not install on {LEG_37}'])
                self.assertEqual((self.tmp / 'pip-install.log').read_text(encoding='utf-8'), PIP_37 + '\n')

    def test_an_install_failure_without_an_error_line_is_still_named(self) -> None:
        for output, reason in (('Killed', "pip failed without an ERROR line; see this step's log"),
                               ('ERROR: 100% of the index timed out', '100%25 of the index timed out')):
            with self.subTest(output=output):
                result = self.run_step('unit-tests.yml', 'test', LEGACY_37[0][2], PIP_STUB,
                                       {'PIP_OUTPUT': output, 'PIP_STATUS': '1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(workflow_commands(result.stdout), [
                    f'::warning title=pcapkit did not install on {TITLE_37}::{reason}. '
                    'The rest of this leg is skipped.'])

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
             [f'::warning title=pcapkit does not compile on {TITLE_37}::2 modules fail to compile, the first at '
              'File "pcapkit/const/ftp/command.py", line 286; see this step\'s log.']),
            ({'COMPILE_OUTPUT': '', 'COMPILE_STATUS': '0', 'IMPORT_STATUS': '1'},
             [f"::warning title=pcapkit does not import on {TITLE_37}::See the traceback in this step's log."]),
            ({'COMPILE_OUTPUT': '', 'COMPILE_STATUS': '0', 'IMPORT_STATUS': '0'}, []),
        )  # type: tuple[tuple[dict[str, str], list[str]], ...]
        for env, expected in cases:
            with self.subTest(compile=env['COMPILE_STATUS'], imported=env['IMPORT_STATUS']):
                result = self.run_step('python-compatibility.yml', 'compatibility', 'Verify package',
                                       VERIFY_STUB, env)
                self.assertEqual(bool(result.returncode), bool(expected), result.stderr)
                self.assertEqual(workflow_commands(result.stdout), expected)
                for title in titles(result.stdout):
                    self.assertTrue(title.endswith(f' on {LEG_37}'), title)
                if env['COMPILE_STATUS'] != '0':
                    self.assertIn('SyntaxError: invalid syntax', result.stdout)

    def test_a_supported_leg_fails_the_same_steps_at_error_level(self) -> None:
        """#1672 changed the KTLO level only: on 3.12 each of these still fails as an ``::error``."""
        cases = [(name, job_id, install, PIP_STUB, {'PIP_OUTPUT': PIP_37, 'PIP_STATUS': '1'},
                  '::error title=pcapkit did not install on Python 3.12::No matching distribution found '
                  'for pytest>=8; extra == "test". The rest of this leg is skipped.')
                 for name, job_id, install in LEGACY_37[:2]]
        cases.append(('python-compatibility.yml', 'compatibility', 'Verify package', VERIFY_STUB,
                      {'COMPILE_OUTPUT': '', 'COMPILE_STATUS': '0', 'IMPORT_STATUS': '1'},
                      "::error title=pcapkit does not import on Python 3.12::See the traceback in this step's log."))
        for name, job_id, step_name, stub, env, expected in cases:
            with self.subTest(workflow=name, job=job_id):
                result = self.run_step(name, job_id, step_name, stub, env, leg=SUPPORTED_312)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(workflow_commands(result.stdout), [expected])


#: The properties an annotation takes; anything else in one is a value cut at a ``,``.
ANNOTATION_PROPERTIES = frozenset({'title', 'file', 'line', 'endline', 'col', 'endcolumn'})
#: An annotation command and its properties, which end at the next ``::``. The level
#: can also be ``${ANNOTATION_LEVEL}``, a job's per-leg one (#1672).
ANNOTATION = re.compile(r'::(?:error|warning|notice|\$\{ANNOTATION_LEVEL\}) (.*?)::')
#: A ``${...}`` expansion: the shell replaces it, so the runner never sees its text.
BRACED = re.compile(r'\$\{([^}]*)\}')
#: The one braced form that escapes what it expands: ``${NAME//,/%2C}``.
ESCAPED = re.compile(r'\w+//,/%2C')
#: A plain ``$NAME`` or ``${NAME}``.
PLAIN = re.compile(r'\$(?:\{(\w+)\}|(\w+))')


class TestNoAnnotationTitleIsCutAtAComma(unittest.TestCase):
    """Every ``title=`` a workflow emits reaches the run summary whole.

    The runner splits an annotation's properties on ``,`` before un-escaping
    ``%2C`` (:func:`runner_parse`), so ``title=failed on 3.10 (KTLO, non-blocking)``
    shows as "failed on 3.10 (KTLO". A comma in the source text is one way; an
    ``env:`` value holding one, such as ``LEG``'s ``(KTLO, non-blocking)``,
    expanded plainly into a title is the other. ``${LEG//,/%2C}`` is the fix.

    """

    def test_no_title_holds_an_unescaped_comma(self) -> None:
        found = []
        for path in sorted(WORKFLOWS.glob('*.yml')):
            spec = workflow(path.name)
            for job_id, body in spec.get('jobs', {}).items():
                for step in body.get('steps', []):
                    if 'run' not in step:
                        continue
                    env = {**(spec.get('env') or {}), **(body.get('env') or {}), **(step.get('env') or {})}
                    label = f"{path.name} {job_id} {step.get('name') or step.get('id')!r}"
                    for match in ANNOTATION.finditer(step['run']):
                        properties = match.group(1)
                        found.extend(f'{label}: ${{{body}}} can expand a comma' for body in BRACED.findall(properties)
                                     if ',' in body and not ESCAPED.fullmatch(body))
                        found.extend(f'{label}: ${name} expands {env[name]!r}'
                                     for name in (a or b for a, b in PLAIN.findall(properties))
                                     if ',' in str(env.get(name, '')))
                        found.extend(f'{label}: {piece!r} is not a property'
                                     for piece in BRACED.sub('_', properties).strip().split(',')
                                     if piece.split('=', 1)[0].strip().lower() not in ANNOTATION_PROPERTIES)
        self.assertEqual(found, [])

    def test_the_parser_cuts_where_the_runner_does(self) -> None:
        """:func:`runner_parse` against the two forms, so the test above reads what GitHub would."""
        cut = runner_parse('::error title=pcapkit failed on Python 3.10 (KTLO, non-blocking)::message')
        whole = runner_parse('::error file=a.py,line=3,title=on Python 3.10 (KTLO%2C non-blocking)::100%25 done')
        self.assertEqual(cut, ('error', {'title': 'pcapkit failed on Python 3.10 (KTLO'}, 'message'))
        self.assertEqual(whole, ('error', {'file': 'a.py', 'line': '3',
                                           'title': 'on Python 3.10 (KTLO, non-blocking)'}, '100% done'))


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
        engines = {version for _, versions in engine_inputs() for version in versions.split()}
        claims = {
            r'``test`` \((\w+) Python legs': len(legs('unit-tests.yml', 'test')),
            r'``test-ktlo`` \((\w+)\)': len(legs('unit-tests.yml', 'test-ktlo')),
            r'``integration`` \((\w+)\)': len(legs('unit-tests.yml', 'integration')),
            r'``integration-ktlo`` \((\w+)\)': len(legs('unit-tests.yml', 'integration-ktlo')),
            r'``pypcap-parity`` \((\w+)\)': len(legs('unit-tests.yml', 'pypcap-parity')),
            r'``pypcap-parity-ktlo`` \((\w+)\)': len(legs('unit-tests.yml', 'pypcap-parity-ktlo')),
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
