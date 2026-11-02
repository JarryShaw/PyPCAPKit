# -*- coding: utf-8 -*-
"""#2648: only Create Release waits for a deployment approval.

``github-release`` is the environment with a required reviewer, and it holds the
release App's key, ``RELEASE_APP_PRIVATE_KEY``, for Create Release's ``github``.
The owner ruled on #2648 that an approval at a deployment gate is for Create
Release alone, so the scheduled ``pr`` jobs of Python Versions and Issue and PR
Kinds read the same key from ``release-app``, which has no reviewer.

* :class:`TestOnlyCreateReleaseNamesTheGate` scans every workflow: Create
  Release's ``github`` is the only job naming ``github-release``, and every other
  job reading the key names ``release-app``. Its mutation rows show the scan
  failing on a cron job pointed back at the gate, on ``github`` moved off it,
  and on any other job, in Create Release or elsewhere, reading the key outside
  ``release-app``.
* :class:`TestTheKeyCheck` pins how a ``release-app`` reader behaves while that
  environment holds no key: it warns and skips its other steps rather than
  failing at minting. The check's shell runs here under :program:`bash`.

Which environments exist, their reviewers, branch policies and secrets are
repository settings, which no test here can read.

"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import bash_argv
from tests._workflows import WORKFLOWS, load
from tests.project.test_release_gates import evaluate_condition, evaluate_expression
from tests.project.test_secret_environments_1968 import environment

if TYPE_CHECKING:
    from typing import Any

#: The environment with the required reviewer, and the one without.
GATE, APP = 'github-release', 'release-app'
#: Create Release, and its job that names :data:`GATE`.
RELEASE, RELEASE_JOB = 'create-release.yml', 'github'
#: The scheduled jobs reading the key from :data:`APP`.
CRON_READERS = {('cron-issue-pr-kinds.yml', 'pr'), ('cron-python-versions.yml', 'pr')}
#: A read of the App's private key, as ``secrets.X`` or ``secrets['X']``.
KEY = re.compile(r"""secrets\s*(?:\.\s*|\[\s*['"])RELEASE_APP_PRIVATE_KEY\b""")

#: The first step of every :data:`APP` reader, its ``env:``, and the ``if:`` on
#: every step after it.
CHECK_STEP = "Check for the release App's key"
CHECK_ENV = {'KEY_SET': "${{ secrets.RELEASE_APP_PRIVATE_KEY != '' }}"}
GATED = "${{ steps.key.outputs.set == 'true' }}"

BASH = shutil.which('bash')


def workflows() -> 'dict[str, dict[str, Any]]':
    """Every workflow, parsed: a fresh copy, so a test may edit it."""
    return {path.name: load(path.name) for path in sorted(WORKFLOWS.glob('*.yml'))}


def jobs(specs: 'dict[str, dict[str, Any]]') -> 'list[tuple[str, str, dict[str, Any]]]':
    """``(workflow, job id, job)`` for every job in ``specs``."""
    return [(name, job_id, job) for name, spec in sorted(specs.items())
            for job_id, job in sorted((spec.get('jobs') or {}).items())]


def readers(specs: 'dict[str, dict[str, Any]]') -> 'set[tuple[str, str]]':
    """Each ``(workflow, job id)`` in ``specs`` that reads the App's key."""
    return {(name, job_id) for name, job_id, job in jobs(specs) if KEY.search(repr(job))}


def violations(specs: 'dict[str, dict[str, Any]]') -> 'list[str]':
    """What in ``specs`` breaks #2648's rule; empty where it holds."""
    found = []
    gated = sorted((name, job_id) for name, job_id, job in jobs(specs) if environment(job) == GATE)
    if gated != [(RELEASE, RELEASE_JOB)]:
        found.append(f'the jobs naming {GATE} are {gated}, not {RELEASE}\'s {RELEASE_JOB} alone')
    read = readers(specs)
    for name, job_id, job in jobs(specs):
        if (name, job_id) != (RELEASE, RELEASE_JOB) and (name, job_id) in read and environment(job) != APP:
            found.append(f'{name}\'s {job_id} reads the App\'s key from {environment(job)!r}, not {APP}')
    return found


class TestOnlyCreateReleaseNamesTheGate(unittest.TestCase):
    """``github-release`` is Create Release's alone; the key's other readers use ``release-app``."""

    def test_the_rule_holds(self) -> None:
        self.assertEqual(violations(workflows()), [])

    def test_the_scan_finds_the_readers(self) -> None:
        """Not vacuous: ``github`` and the cron ``pr`` jobs read the key."""
        self.assertEqual(readers(workflows()), CRON_READERS | {(RELEASE, RELEASE_JOB)})

    def test_each_mutation_is_caught(self) -> None:
        def point(name: 'str', job: 'str', value: 'Any') -> 'Any':
            def mutate(specs: 'dict[str, dict[str, Any]]') -> 'None':
                if value is None:
                    del specs[name]['jobs'][job]['environment']
                else:
                    specs[name]['jobs'][job]['environment'] = value
            return mutate

        def reader(name: 'str', value: 'Any') -> 'Any':
            def mutate(specs: 'dict[str, dict[str, Any]]') -> 'None':
                probe = {'runs-on': 'ubuntu-latest',
                         'steps': [{'run': 'true', 'env': {'KEY': '${{ secrets.RELEASE_APP_PRIVATE_KEY }}'}}]}
                if value is not None:
                    probe['environment'] = value
                specs[name]['jobs']['probe'] = probe
            return mutate

        mutations = {
            'Python Versions pointed back at the gate': point('cron-python-versions.yml', 'pr', GATE),
            'Issue and PR Kinds pointed back at the gate': point('cron-issue-pr-kinds.yml', 'pr', GATE),
            'a cron reader naming no environment': point('cron-issue-pr-kinds.yml', 'pr', None),
            "Create Release's github moved off the gate": point(RELEASE, RELEASE_JOB, APP),
            "Create Release's github naming no environment": point(RELEASE, RELEASE_JOB, None),
            'another Create Release job reading the key from conda-tag': reader(RELEASE, 'conda-tag'),
            'another Create Release job reading the key from no environment': reader(RELEASE, None),
            'a job elsewhere reading the key from conda-tag': reader('lint.yml', 'conda-tag'),
        }
        for label, mutate in sorted(mutations.items()):
            with self.subTest(mutation=label):
                specs = workflows()
                mutate(specs)
                self.assertTrue(violations(specs), label)


class TestTheKeyCheck(unittest.TestCase):
    """Without the key in ``release-app``, a reader warns and skips; with it, it runs."""

    @classmethod
    def setUpClass(cls) -> None:
        specs = workflows()
        cls.jobs = {(name, job_id): specs[name]['jobs'][job_id] for name, job_id in sorted(CRON_READERS)}

    def test_the_first_step_checks_and_every_other_waits_on_it(self) -> None:
        for (name, job_id), job in self.jobs.items():
            check, *rest = job['steps']
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual((check.get('name'), check.get('id'), check.get('env')),
                                 (CHECK_STEP, 'key', CHECK_ENV))
                self.assertNotIn('if', check)
                self.assertTrue(rest)
                self.assertEqual([step.get('if') for step in rest], [GATED] * len(rest))
        self.assertEqual(len({repr(job['steps'][0]) for job in self.jobs.values()}), 1, 'the checks differ')

    def test_an_unset_key_skips_every_other_step(self) -> None:
        """An unset secret reads as an empty string; ``env:`` gets the boolean as text."""
        for key, expected in (('', False), ('-----BEGIN RSA PRIVATE KEY-----', True)):
            with self.subTest(key=bool(key)):
                value = evaluate_expression(CHECK_ENV['KEY_SET'], {'secrets': {'RELEASE_APP_PRIVATE_KEY': key}})
                self.assertIs(value, expected)
                context = {'steps': {'key': {'outputs': {'set': str(value).lower()}}}}
                self.assertIs(evaluate_condition(GATED, context), expected)

    @unittest.skipIf(not BASH, 'needs bash on PATH')
    def test_the_check_warns_and_writes_its_output(self) -> None:
        script = next(iter(self.jobs.values()))['steps'][0]['run']
        for value, warned in (('false', True), ('true', False)):
            with self.subTest(KEY_SET=value), tempfile.TemporaryDirectory(prefix='pcapkit-2648-') as tmp:
                root = pathlib.Path(tmp)
                (root / 'step.sh').write_text(script, encoding='utf-8')
                output = root / 'output'
                env = {'PATH': os.environ.get('PATH', ''), 'GITHUB_OUTPUT': str(output), 'KEY_SET': value}
                result = subprocess.run(bash_argv('-e', str(root / 'step.sh'), executable=str(BASH)),  # nosec: B603
                                        cwd=root, env=env, capture_output=True, text=True, check=False, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(encoding='utf-8'), f'set={value}\n')
                if warned:
                    self.assertTrue(result.stdout.startswith(
                        "::warning title=No pull request without the release App's key::"), result.stdout)
                    for named in (APP, 'RELEASE_APP_PRIVATE_KEY', 'docs/source/contributing/releasing.rst'):
                        self.assertIn(named, result.stdout)
                else:
                    self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
