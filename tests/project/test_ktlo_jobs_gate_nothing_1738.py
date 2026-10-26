# -*- coding: utf-8 -*-
"""#1738: unit-tests.yml's KTLO legs are jobs of their own, which nothing gating waits on.

The owner's option A. As legs of ``test``, ``integration`` and
``pypcap-parity``, kept from failing their job by step-level
``continue-on-error`` alone, a KTLO failure no step can contain -- a lost runner,
the job cap -- would still fail the job, and so ``Required checks passed``, which
reads one ``needs.<job>.result`` per job, and skip ``unittest-ordering``, which
needs ``test``. So they are ``test-ktlo``, ``integration-ktlo`` and
``pypcap-parity-ktlo``, and this module pins the three things that make that hold:

* no job that can fail the run -- one without job-level ``continue-on-error`` --
  ``needs:`` a KTLO job, directly or through another job;
* none of those jobs holds a KTLO leg;
* each leg's check name is its job's prefix and version, with ``(KTLO)`` on a
  KTLO leg: rulesets match names literally.

It also pins that each KTLO job runs its gating twin's steps, keeps the KTLO
mechanics of #1672, and that :file:`util/ci_timing.py` tells the twins apart.

"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_matrix_tiers_1633 import (KTLO, KTLO_GUARD, PARITY, REQUIRED, SUPPORTED, TESTED_KTLO,
                                                         TESTED_SUPPORTED)
from tests.project.test_python_versions_1660 import legs as expand
from tests.project.test_python_versions_1660 import matrix, workflow

if TYPE_CHECKING:
    from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'unit-tests.yml'
NAME = 'unit-tests.yml'
#: Each gating job and the job holding its KTLO legs.
TWINS = {'test': 'test-ktlo', 'integration': 'integration-ktlo', 'pypcap-parity': 'pypcap-parity-ktlo'}
#: Each gating job's check-name prefix, which its KTLO twin's legs share.
PREFIX = {'test': 'Python', 'integration': 'Integration Python', 'pypcap-parity': 'PyPCAP/PyPCAPFile parity Python'}
#: The KTLO versions each twin runs; ``pypcap-parity`` runs on ``ubuntu-latest`` and below 3.12 only, and
#: on CPython alone, where ``test`` and ``integration`` run PyPy's too (#1958).
KTLO_OF = {'test': TESTED_KTLO, 'integration': TESTED_KTLO, 'pypcap-parity': tuple(v for v in PARITY if v in KTLO)}
SUPPORTED_OF = {'test': TESTED_SUPPORTED, 'integration': TESTED_SUPPORTED,
                'pypcap-parity': tuple(v for v in PARITY if v in SUPPORTED)}


def jobs() -> 'dict[str, Any]':
    return workflow(NAME)['jobs']


def needs(spec: 'dict[str, Any]') -> 'list[str]':
    found = spec.get('needs', [])
    return [found] if isinstance(found, str) else list(found)


def closure(job_id: 'str') -> 'set[str]':
    """``job_id`` and every job it waits on, through ``needs:``."""
    found, todo = set(), [job_id]
    while todo:
        current = todo.pop()
        if current not in found:
            found.add(current)
            todo.extend(needs(jobs()[current]))
    return found


def matrix_legs(job_id: 'str') -> 'list[dict[str, Any]]':
    """The legs of ``job_id``'s matrix, read from the tier file; none for a job without one."""
    if 'matrix' not in jobs()[job_id].get('strategy', {}):
        return []
    return expand(matrix(NAME, job_id))


def holds_ktlo(job_id: 'str') -> 'bool':
    return any(leg.get('ktlo') is True for leg in matrix_legs(job_id))


def render(template: 'str', leg: 'dict[str, Any]') -> 'str':
    """A leg's check name, for the two expression shapes these jobs' names have used."""
    name = template.replace("${{ matrix.ktlo && ' (KTLO)' || '' }}", ' (KTLO)' if leg.get('ktlo') is True else '')
    name = name.replace('${{ matrix.python-version }}', leg['python-version'])
    assert '${{' not in name, name
    return name


def gating() -> 'list[str]':
    """Every job that can fail the run: each one without job-level ``continue-on-error``."""
    return [job_id for job_id, spec in jobs().items() if spec.get('continue-on-error') is not True]


class TestNothingGatingWaitsOnKTLO(unittest.TestCase):
    """A KTLO job's failure, of any kind, reaches nothing that gates."""

    def test_no_gating_job_needs_a_ktlo_job_transitively(self) -> None:
        ktlo = {job_id for job_id in jobs() if holds_ktlo(job_id)}
        self.assertTrue(ktlo, 'no job holds a KTLO leg')
        for job_id in gating():
            with self.subTest(job=job_id):
                self.assertEqual(sorted((closure(job_id) - {job_id}) & ktlo), [])

    def test_the_named_gates_wait_on_no_ktlo_job(self) -> None:
        """``Required checks passed`` and ``unittest-ordering``, by name, so neither can drop out of :func:`gating`."""
        for job_id in ('required-checks', 'unittest-ordering'):
            with self.subTest(job=job_id):
                self.assertIn(job_id, gating())
                self.assertEqual(sorted(job for job in closure(job_id) if holds_ktlo(job)), [])
                self.assertFalse(set(TWINS.values()) & closure(job_id))

    def test_no_gating_job_holds_a_ktlo_leg(self) -> None:
        for job_id in gating():
            with self.subTest(job=job_id):
                self.assertEqual([leg['python-version'] for leg in matrix_legs(job_id) if leg.get('ktlo') is True], [])

    def test_the_gating_jobs_keep_the_supported_legs(self) -> None:
        for job_id, versions in SUPPORTED_OF.items():
            with self.subTest(job=job_id):
                self.assertIn(job_id, gating())
                self.assertIn(job_id, needs(jobs()['required-checks']))
                self.assertEqual(sorted(leg['python-version'] for leg in matrix_legs(job_id)), sorted(versions))


class TestTheCheckNamesAreUnchanged(unittest.TestCase):
    """Each leg is named ``<prefix> <version>``, with ``(KTLO)`` after it on a KTLO job."""

    def test_each_leg_keeps_its_name(self) -> None:
        for job_id, twin in TWINS.items():
            with self.subTest(job=job_id):
                found = {job: sorted(render(jobs()[job]['name'], leg) for leg in matrix_legs(job))
                         for job in (job_id, twin)}
                self.assertEqual(found, {
                    job_id: sorted(f'{PREFIX[job_id]} {v}' for v in SUPPORTED_OF[job_id]),
                    twin: sorted(f'{PREFIX[job_id]} {v} (KTLO)' for v in KTLO_OF[job_id]),
                })

    def test_no_ktlo_name_is_a_required_context(self) -> None:
        for twin in TWINS.values():
            with self.subTest(job=twin):
                names = {render(jobs()[twin]['name'], leg) for leg in matrix_legs(twin)}
                self.assertTrue(names)
                self.assertFalse(names & REQUIRED)


class TestTheKTLOJobsKeepTheirMechanics(unittest.TestCase):
    """#1633 and #1672 hold on each KTLO job."""

    def test_each_runs_its_twins_steps_on_ktlo_legs_only(self) -> None:
        for job_id, twin in TWINS.items():
            spec, gate = jobs()[twin], jobs()[job_id]
            with self.subTest(job=twin):
                self.assertEqual(spec['steps'], gate['steps'])
                self.assertEqual(needs(spec), needs(gate))
                # #2243: and skips a test-only pull request, which `test` and
                # `integration` run on `latest` alone and `pypcap-parity` skips.
                skip = " && needs.changes.outputs.test-only != 'true'"
                self.assertEqual(spec['if'], gate['if'].replace(skip, '').replace(' }}', f'{skip} }}}}'))
                self.assertEqual((spec['runs-on'], spec['timeout-minutes']), (gate['runs-on'], gate['timeout-minutes']))
                self.assertEqual(spec['env']['ANNOTATION_LEVEL'], gate['env']['ANNOTATION_LEVEL'])
                self.assertTrue(all(leg.get('ktlo') is True for leg in matrix_legs(twin)))
                # #2030: last but the steps that name and upload the job's summary.
                self.assertEqual([step['name'] for step in spec['steps'][-3:]],
                                 ['KTLO summary', 'Name the job summary', 'Upload the job summary'])
                self.assertEqual(spec['steps'][-3]['continue-on-error'], KTLO_GUARD)

    def test_each_has_the_job_level_backstop(self) -> None:
        for twin in TWINS.values():
            with self.subTest(job=twin):
                self.assertIs(jobs()[twin].get('continue-on-error'), True)

    def test_each_reads_its_own_output(self) -> None:
        outputs = jobs()['python-versions']['outputs']
        for twin in TWINS.values():
            with self.subTest(job=twin):
                self.assertEqual(jobs()[twin]['strategy']['matrix'],
                                 f'${{{{ fromJSON(needs.python-versions.outputs.{twin}) }}}}')
                self.assertEqual(outputs[twin], f'${{{{ steps.read.outputs.{twin} }}}}')

    def test_the_steps_are_one_yaml_node(self) -> None:
        """An alias, not a copy, so the twins cannot drift: ``steps: &<job>-steps`` and ``steps: *<job>-steps``."""
        text = WORKFLOW.read_text(encoding='utf-8')
        for job_id, twin in TWINS.items():
            with self.subTest(job=twin):
                self.assertEqual(len(re.findall(rf'(?m)^    steps: &{re.escape(job_id)}-steps$', text)), 1)
                self.assertEqual(len(re.findall(rf'(?m)^    steps: \*{re.escape(job_id)}-steps$', text)), 1)


def ci_timing() -> 'Any':
    spec = importlib.util.spec_from_file_location('ci_timing_1738', ROOT / 'util' / 'ci_timing.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class TestCITimingTellsTheTwinsApart(unittest.TestCase):
    """util/ci_timing.py reads the workflow's text, aliases included, and names each leg's job."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = ci_timing()
        cls.specs = cls.module.parse_workflow(WORKFLOW.read_text(encoding='utf-8'))

    def test_a_ktlo_leg_is_its_ktlo_jobs(self) -> None:
        for job_id, twin in TWINS.items():
            with self.subTest(job=twin):
                ktlo = f'{PREFIX[job_id]} {KTLO_OF[job_id][-1]} (KTLO)'
                supported = f'{PREFIX[job_id]} {SUPPORTED_OF[job_id][0]}'
                self.assertEqual(self.module.match_job(self.specs, ktlo)['id'], twin)
                self.assertEqual(self.module.match_job(self.specs, supported)['id'], job_id)
                self.assertTrue(self.module.non_blocking(NAME, ktlo))

    def test_an_aliased_job_has_its_anchors_steps(self) -> None:
        by_id = {spec['id']: spec for spec in self.specs}
        for job_id, twin in TWINS.items():
            with self.subTest(job=twin):
                self.assertTrue(by_id[job_id]['steps'])
                self.assertEqual(by_id[twin]['steps'], by_id[job_id]['steps'])
        caps = {step['name']: step['timeout'] for step in by_id['pypcap-parity-ktlo']['steps'] if step['timeout']}
        self.assertEqual(caps, {'Plan the system packages': 4,
                                'Install libpcap headers, a C toolchain, and tshark': 10})

    def test_the_critical_path_leaves_the_ktlo_jobs_out(self) -> None:
        required = next(spec for spec in self.specs if spec['name'] == self.module.REQUIRED_JOB)
        self.assertFalse(set(TWINS.values()) & set(required['needs']))
        # The KTLO leg finishes last, so counted as `test`'s it would lead.
        run = {'event': 'pull_request', 'conclusion': 'success', 'jobs': [
            {'name': name, 'runner_name': 'GitHub Actions 1', 'conclusion': 'success',
             'started_at': '2026-10-14T00:00:00Z', 'completed_at': end}
            for name, end in (('Python 3.15', '2026-10-14T00:20:00Z'),
                              ('Python 3.10 (KTLO)', '2026-10-14T00:40:00Z'))]}
        path = self.module._critical_path({'runs': [run]}, self.specs)  # pylint: disable=protected-access
        self.assertEqual(path['pull_request']['leader'], 'Python 3.15')


if __name__ == '__main__':
    unittest.main()
