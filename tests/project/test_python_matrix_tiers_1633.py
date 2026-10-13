# -*- coding: utf-8 -*-
"""#1633: every Python matrix is two tiers, and only one of them can block.

Python 3.10 reached end-of-life on 2026-10-01 and 3.15.0 was released on
2026-10-09, so the owner's ruling on #1633 split the matrices:

* **Supported** -- 3.11 to 3.15, in every matrix (unit tests, compatibility,
  conda, PyPI), blocking as before.
* **KTLO** -- end-of-life versions that still build and test (3.10 wherever it
  ran, plus 3.8 and 3.9 in the test matrices), never blocking: not CI, not a
  release, not a required context.
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
    ('unit-tests.yml', 'test', ('3.8', '3.9', '3.10')),
    ('unit-tests.yml', 'integration', ('3.8', '3.9', '3.10')),
    ('unit-tests.yml', 'pypcap-parity', ('3.10',)),
    ('python-compatibility.yml', 'compatibility', ('3.8', '3.9', '3.10')),
    ('create-release.yml', 'pypi', ('3.10', 'pypy3.10')),
)

#: Claims the tier split made false, each worded as it was somewhere before #1633.
#: A denylist: it catches these phrasings coming back and examines no others.
RETIRED_CLAIMS = re.compile('|'.join((
    r'3\.15 as an allowed-to-fail leg',
    r'3\.15 runs allowed-to-fail',
    r'supported range starts at 3\.10',
    r'CI matrix starts at 3\.10',
    r'CI covers \**3\.10',
    r'runs on 3\.10 through 3\.1[45]',
    r'repository supports 3\.10',
    r'matrix floor is 3\.10',
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

    def test_38_and_39_run_where_setup_python_still_builds_them(self) -> None:
        """No Ubuntu 26.04 build of either, and ``ubuntu-latest`` moves to 26.04."""
        for name, job_id, _ in KTLO_LEGS:
            spec = job(name, job_id)
            for leg in legs(spec):
                if leg['python-version'] in ('3.8', '3.9'):
                    with self.subTest(workflow=name, job=job_id, python=leg['python-version']):
                        self.assertEqual(leg.get('os'), 'ubuntu-24.04')
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
