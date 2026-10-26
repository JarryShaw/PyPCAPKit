# -*- coding: utf-8 -*-
"""#1968: every job that reads an environment-scoped secret names its environment.

``ANACONDA_TOKEN`` lives in the ``anaconda`` environment, and the ``PYPCAPKIT``
PAT and ``PYPCAPKIT_ACTIONS_DEPLOY_KEY`` in ``conda-tag``, rather than at
repository level. GitHub hands an environment's secrets only to a job that
names it, so a job reading one without the matching ``environment:`` gets an
empty string -- the shape #1968 found in the scheduled jobs of Conda Update and
Vendor Update.

The scan covers every workflow, so a new job reading one of these secrets is
held to the same rule. YAML drops comments, so a secret named only in a comment
does not count.

A manual run (``workflow_dispatch``) builds only and names no environment, so a
job may name its environment through an expression; :func:`environment` reads
the name it gives every other event, where the secrets are read.
:mod:`tests.project.test_build_only_dispatch` pins the manual run's side. In
Conda Update the expression reads its ``mode`` job's ``publishes``, which is
'true' on every other event and on a manual run with ``publish`` (#2060).

"""

from __future__ import annotations

import re
import unittest
from typing import TYPE_CHECKING

from tests._workflows import WORKFLOWS, load, loads
from tests.project.test_release_gates import evaluate_expression

if TYPE_CHECKING:
    from typing import Any, Optional

#: Each environment-scoped secret, mapped to the environment that holds it.
SECRET_ENVIRONMENTS = {
    'ANACONDA_TOKEN': 'anaconda',
    'PYPCAPKIT': 'conda-tag',
    'PYPCAPKIT_ACTIONS_DEPLOY_KEY': 'conda-tag',
}
#: A ``secrets.<name>`` reference in an expression.
SECRET = re.compile(r'\bsecrets\.(\w+)')


def environment(job: 'dict[str, Any]', event_name: 'str' = 'schedule',
                publish: 'bool' = False) -> 'Optional[str]':
    """The environment ``job`` names on ``event_name``, in either spelling, or :data:`None`.

    ``publish`` is a manual run's input of that name, as Conda Update's ``mode``
    job reads it from ``main``.

    """
    value = job.get('environment')
    if isinstance(value, dict):
        value = value.get('name')
    if isinstance(value, str) and value.startswith('${{'):
        publishes = 'true' if publish or event_name != 'workflow_dispatch' else 'false'
        value = str(evaluate_expression(value, {'github': {'event_name': event_name},
                                                'needs': {'mode': {'outputs': {'publishes': publishes}}}}))
    return value


def readers() -> 'dict[tuple[str, str], set[str]]':
    """Each ``(workflow, job)`` reading an environment-scoped secret, with the environments those need."""
    found = {}  # type: dict[tuple[str, str], set[str]]
    for path in sorted(WORKFLOWS.glob('*.yml')):
        for job_id, job in (load(path.name).get('jobs') or {}).items():
            needed = {SECRET_ENVIRONMENTS[name] for name in SECRET.findall(repr(job))
                      if name in SECRET_ENVIRONMENTS}
            if needed:
                found[(path.name, job_id)] = needed
    return found


class TestSecretsReachTheirJobs(unittest.TestCase):
    """A job reading ``ANACONDA_TOKEN``, ``PYPCAPKIT`` or the deploy key names its environment."""

    def test_every_reader_names_the_environment_holding_its_secrets(self) -> None:
        for (name, job_id), needed in sorted(readers().items()):
            with self.subTest(workflow=name, job=job_id):
                # A job can name one environment only, so it cannot read both.
                self.assertEqual(len(needed), 1, f'`{job_id}` reads secrets of {sorted(needed)}')
                self.assertEqual(environment(load(name)['jobs'][job_id]), next(iter(needed)))

    def test_the_scan_finds_the_known_readers(self) -> None:
        """Not vacuous: the scheduled jobs #1968 is about, and the release jobs."""
        self.assertLessEqual({
            ('cron-conda.yml', 'conda-update'): {'conda-tag'},
            ('cron-conda.yml', 'conda-tag'): {'conda-tag'},
            ('cron-conda.yml', 'conda-dist'): {'anaconda'},
            ('cron-vendor.yml', 'vendor-update'): {'conda-tag'},
            ('create-release.yml', 'tag'): {'conda-tag'},
            ('create-release.yml', 'conda'): {'anaconda'},
        }.items(), readers().items())

    def test_a_commented_reference_does_not_count(self) -> None:
        job = loads('jobs:\n  a:\n    # ${{ secrets.PYPCAPKIT }}\n    runs-on: x\n'
                    '    steps:\n      - run: echo ${{ secrets.ANACONDA_TOKEN }}\n')['jobs']['a']
        self.assertEqual(SECRET.findall(repr(job)), ['ANACONDA_TOKEN'])

    def test_both_spellings_of_environment(self) -> None:
        self.assertIsNone(environment({}))
        self.assertEqual(environment({'environment': 'anaconda'}), 'anaconda')
        self.assertEqual(environment({'environment': {'name': 'anaconda', 'url': 'x'}}), 'anaconda')

    def test_an_expression_is_read_per_event(self) -> None:
        job = {'environment': "${{ github.event_name != 'workflow_dispatch' && 'anaconda' || '' }}"}
        self.assertEqual(environment(job), 'anaconda')
        self.assertEqual(environment(job, 'workflow_dispatch'), '')
        job = {'environment': "${{ needs.mode.outputs.publishes == 'true' && 'anaconda' || '' }}"}
        self.assertEqual(environment(job), 'anaconda')
        self.assertEqual(environment(job, 'workflow_dispatch'), '')
        self.assertEqual(environment(job, 'workflow_dispatch', publish=True), 'anaconda')


if __name__ == '__main__':
    unittest.main()
