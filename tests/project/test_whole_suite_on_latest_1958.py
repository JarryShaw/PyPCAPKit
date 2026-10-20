# -*- coding: utf-8 -*-
"""#1958: latest CPython runs the whole suite, with what the whole suite gates on.

The owner's rulings on #1958, paraphrased: every implementation runs the same
minimal ``ALL`` tier, and latest CPython runs the whole suite as the sanity check
and the gate; tests that run nowhere get a job. So each job's ``latest`` leg
installs the engines pip can install there, html5lib (``vendor``), Sphinx
(``docs``) and emoji (``cli``), and the ``HAS_*`` gates those extras close run
there. This module pins the install lines, the leg they run on, the gates they
close, and the page that describes them. :mod:`tests._dependency_gates` derives
the gaps; :file:`tests/test_tier_guard.py` checks its reading of the workflow.

"""

from __future__ import annotations

import pathlib
import re
import tempfile
import unittest

from tests import _dependency_gates, _workflows
from tests.project.test_python_matrix_tiers_1633 import legs
from tests.project.test_python_versions_1660 import script

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'
WORKFLOW = 'unit-tests.yml'

#: What a ``latest`` leg installs: every extra a gate asks for that installs there.
WHOLE_SUITE = frozenset({'test', 'Scapy', 'DPKT', 'crypto', 'cli', 'NGAP', 'vendor', 'docs', 'PyShark'})
#: The step ``test`` and ``integration`` add on ``latest``.
LATEST_STEP = "Install the whole suite's dependencies on latest"
LATEST_IF = ("${{ steps.install.outcome == 'success' && "
             'matrix.python-version == needs.python-versions.outputs.latest }}')
#: The install line every leg of each matrix job runs, unchanged by #1958.
BASE = {
    'test': frozenset({'test', 'DPKT', 'crypto', 'NGAP'}),
    'integration': frozenset({'test', 'Scapy', 'DPKT', 'cli'}),
}
#: The jobs that run on ``latest`` alone, each with one install step.
LATEST_ONLY = {
    'project-tests': 'Install package and test dependencies',
    'gate': 'Install package, test and generator dependencies',
}
#: The gates still dark somewhere: lint tools no extra declares, and the engines
#: ``latest`` cannot install (PCAP_CT needs a system libpcap; the PyPCAP and
#: PyPCAPFile markers stop below 3.12). ``engine-tests`` and ``pypcap-parity`` run them.
STILL_DARK = frozenset({'HAS_MYPY', 'HAS_PYLINT', 'HAS_PCAP_CT', 'HAS_PYPCAP', 'HAS_PYPCAPFILE'})
#: A test the audit found running nowhere, or in ``gate`` alone, per flag.
DARK_TESTS = {
    'HAS_RUNTIME': 'tests/foundation/engines/test_runtime_engines.py',
    'HAS_SCAPY': 'tests/interface/test_core.py',
    'HAS_PYSHARK': 'tests/integration/test_engine_runtime.py',
    'HAS_VENDOR_DEPS': 'tests/vendor/test_user_agent_unit.py',
    'HAS_DOCUTILS': 'tests/vendor/test_vendor_wrap_comment_unit.py',
    'HAS_SPHINX': 'tests/project/test_docs_ambiguous_xrefs_1775_unit.py',
    'HAS_FURO': 'tests/project/test_docs_table_wrapper_ids_1861_unit.py',
}


def step(job_id: 'str', name: 'str') -> 'dict[str, object]':
    found = [entry for entry in _workflows.steps(WORKFLOW, job_id) if entry.get('name') == name]
    if len(found) != 1:
        raise AssertionError(f'expected one {name!r} step in {job_id}, found {len(found)}')
    return found[0]


def extras(run: 'object') -> 'frozenset[str]':
    found = re.findall(r"pip install -e '\.\[([^]]*)\]'", str(run))
    if len(found) != 1:
        raise AssertionError(f'expected one editable install in {run!r}, found {len(found)}')
    return frozenset(extra.strip() for extra in found[0].split(','))


class TestTheLatestLegsInstallTheWholeSuite(unittest.TestCase):
    """Each ``latest`` leg installs :data:`WHOLE_SUITE`; every other leg keeps its line."""

    def test_the_matrix_jobs_add_it_on_latest_alone(self) -> None:
        for job_id in BASE:
            with self.subTest(job=job_id):
                names = [entry.get('name') for entry in _workflows.steps(WORKFLOW, job_id)]
                added = step(job_id, LATEST_STEP)
                self.assertEqual(added['if'], LATEST_IF)
                self.assertEqual(extras(added['run']), WHOLE_SUITE)
                # Right after the install every leg runs, whose outcome it waits on.
                install = next(entry for entry in _workflows.steps(WORKFLOW, job_id) if entry.get('id') == 'install')
                self.assertEqual(names.index(LATEST_STEP), names.index(install['name']) + 1)
                self.assertEqual(extras(install['run']), BASE[job_id])

    def test_the_jobs_on_latest_alone_install_it(self) -> None:
        for job_id, name in LATEST_ONLY.items():
            with self.subTest(job=job_id):
                self.assertEqual(extras(step(job_id, name)['run']), WHOLE_SUITE)

    def test_no_ktlo_leg_is_latest(self) -> None:
        """The KTLO twins run the same steps by alias, so the ``latest`` step must skip on each."""
        latest = script().load()['latest']
        for twin, job_id in (('test', 'test-ktlo'), ('integration', 'integration-ktlo')):
            with self.subTest(job=job_id):
                shared = _workflows.steps(WORKFLOW, job_id)
                self.assertEqual(shared, _workflows.steps(WORKFLOW, twin))
                self.assertIn(LATEST_STEP, [entry.get('name') for entry in shared])
                versions = [leg['python-version'] for leg in legs(WORKFLOW, job_id)]
                self.assertTrue(versions)
                self.assertNotIn(latest, versions)
                self.assertIn(latest, [leg['python-version'] for leg in legs(WORKFLOW, twin)])


class TestTheDarkTestsRunOnLatest(unittest.TestCase):
    """The gates those extras close are no gap on any job; the rest are the known ones."""

    def setUp(self) -> None:
        reason = _dependency_gates._tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

    def test_the_guard_reads_the_latest_step_as_that_legs_extras(self) -> None:
        jobs = {job.name: job for job in _dependency_gates.pytest_jobs() if job.name != 'engine-tests'}
        for job_id, base in BASE.items():
            with self.subTest(job=job_id):
                self.assertEqual(frozenset(jobs[job_id].extras), base)
                self.assertEqual(frozenset(jobs[job_id].latest_extras), WHOLE_SUITE)
        for job_id in LATEST_ONLY:
            with self.subTest(job=job_id):
                self.assertEqual(frozenset(jobs[job_id].extras), WHOLE_SUITE)
        self.assertEqual(jobs['pypcap-parity'].latest_extras, ())

    def test_an_unconditional_second_install_is_still_refused(self) -> None:
        """Only a step gated on ``latest`` is read apart; any other second line is ambiguous."""
        text = (_workflows.WORKFLOWS / WORKFLOW).read_text(encoding='utf-8')
        doctored = text.replace(f'        if: {LATEST_IF}\n', '', 1)
        self.assertNotEqual(doctored, text)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / WORKFLOW
            path.write_text(doctored, encoding='utf-8')
            with self.assertRaises(AssertionError) as caught:
                _dependency_gates.pytest_jobs(path)
        self.assertIn("'test' job runs pytest but has 2", str(caught.exception))

    def test_only_the_known_gates_stay_dark(self) -> None:
        self.assertEqual({gap.flag for gap in _dependency_gates.dependency_gate_gaps()}, STILL_DARK)
        self.assertEqual(set(_dependency_gates.DEPENDENCY_GATE_EXCLUSIONS), STILL_DARK)

    def test_each_dark_test_runs_on_a_latest_leg(self) -> None:
        gaps = {(gap.flag, gap.job) for gap in _dependency_gates.dependency_gate_gaps()}
        jobs = [job for job in _dependency_gates.pytest_jobs() if job.name in set(BASE) | set(LATEST_ONLY)]
        for flag, module in DARK_TESTS.items():
            with self.subTest(flag=flag):
                gates = [gate for gate in _dependency_gates.gated_scopes()
                         if gate.flag == flag and gate.module == module]
                self.assertTrue(gates, f'{module} no longer gates on {flag}')
                reaching = {job.name for job in jobs for gate in gates if _dependency_gates.job_reaches(job, gate)}
                self.assertTrue(reaching, f'no latest leg collects {module}')
                for job_id in sorted(reaching):
                    self.assertNotIn((flag, job_id), gaps)


class TestTheWorkflowsPage(unittest.TestCase):
    """:file:`docs/source/contributing/workflows.rst` names the step and this module."""

    def test_it_describes_the_latest_install(self) -> None:
        text = ' '.join(DOC.read_text(encoding='utf-8').split())
        self.assertIn(f'the step ``{LATEST_STEP}`` runs on the ``latest`` leg alone', text)
        for job_id, name in LATEST_ONLY.items():
            with self.subTest(job=job_id):
                self.assertIn(f'``{name}', text)
        self.assertIn(':file:`tests/project/test_whole_suite_on_latest_1958.py`', text)


if __name__ == '__main__':
    unittest.main()
