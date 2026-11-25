# -*- coding: utf-8 -*-
"""#2942: ``develop`` carries the next minor, so CI runs there as on ``main``.

* :class:`TestCIRunsOnDevelop` pins the branch filters: Unit Tests, Experimental
  Tests, Python Compatibility and CodeQL run on ``develop``'s pushes and pull
  requests as on ``main``'s, and Lint on its pull requests.
* :class:`TestGitHubPagesBuildsDevelopPullRequests` pins GitHub Pages' docs build
  on ``develop``'s pull requests, and evaluates its jobs to show a pull request's
  run, or a ``develop`` push's Unit Tests run, publishes nothing.
* :class:`TestUnittestOrderingRunsOnDevelop` evaluates ``unittest-ordering``'s
  ``if:`` on a ``develop`` push, once the trigger lets that push run Unit Tests.
* :class:`TestDependabotTargetsDevelop` checks every update entry of
  :file:`.github/dependabot.yml` sets ``target-branch: develop``.

"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._tiers import ROOT
from tests.project.test_release_gates import STATUS, job_blocks, job_runs

if TYPE_CHECKING:
    from typing import Any

#: The branches CI runs on.
BRANCHES = ['main', 'develop']
#: The workflows whose ``push`` and ``pull_request`` filters name :data:`BRANCHES`.
PUSH_AND_PULL_REQUEST = ('unit-tests.yml', 'experimental.yml', 'python-compatibility.yml', 'codeql-analysis.yml')
#: Lint has no ``push`` trigger: the pull request already linted the commit.
PULL_REQUEST_ONLY = ('lint.yml',)
DEPENDABOT = ROOT / '.github' / 'dependabot.yml'


def on(name: 'str') -> 'dict[str, Any]':
    """The ``on:`` block of workflow ``name``."""
    return _workflows.load(name)['on']


class TestCIRunsOnDevelop(unittest.TestCase):

    def test_the_test_workflows_run_on_develop_pushes_and_pull_requests(self) -> None:
        for name in PUSH_AND_PULL_REQUEST:
            for event in ('push', 'pull_request'):
                with self.subTest(workflow=name, event=event):
                    self.assertEqual(on(name)[event]['branches'], BRANCHES)

    def test_lint_runs_on_develop_pull_requests(self) -> None:
        for name in PULL_REQUEST_ONLY:
            with self.subTest(workflow=name):
                self.assertEqual(on(name)['pull_request']['branches'], BRANCHES)
                self.assertNotIn('push', on(name))


class TestGitHubPagesBuildsDevelopPullRequests(unittest.TestCase):
    """The docs build runs for a pull request to either branch; publishing stays on ``main``."""

    PULL = {'event_name': 'pull_request', 'ref': 'refs/pull/2942/merge', 'event': {}}

    @staticmethod
    def runs(job: 'str', github: 'dict[str, Any]') -> 'bool':
        jobs = job_blocks((_workflows.WORKFLOWS / 'deploy-pages.yml').read_text(encoding='utf-8'))
        context = {STATUS: {'cancelled': False}, 'github': github,
                   'needs': {'head': {'result': 'success', 'outputs': {'verified': 'true'}},
                             'deploy-pages': {'result': 'success', 'outputs': {}},
                             'publish-pages': {'result': 'skipped', 'outputs': {}}}}
        return job_runs(jobs, job, context)

    def test_a_develop_pull_request_builds_the_docs_and_publishes_nothing(self) -> None:
        """And ``deploy-pages``' ``workflow_run`` clause takes a Unit Tests run on ``main`` alone."""
        self.assertEqual(on('deploy-pages.yml')['pull_request']['branches'], BRANCHES)
        self.assertTrue(self.runs('deploy-pages', self.PULL))
        for job in ('publish-pages', 'discussion'):
            with self.subTest(job=job):
                self.assertFalse(self.runs(job, self.PULL))
        for branch, expected in (('main', True), ('develop', False)):
            run = {'conclusion': 'success', 'event': 'push', 'head_branch': branch}
            github = {'event_name': 'workflow_run', 'ref': 'refs/heads/main', 'event': {'workflow_run': run}}
            with self.subTest(head_branch=branch):
                self.assertIs(self.runs('deploy-pages', github), expected)


class TestUnittestOrderingRunsOnDevelop(unittest.TestCase):
    """#1052 item H: every push and no pull request, ``develop``'s included."""

    @staticmethod
    def runs(event: 'str', ref: 'str', gate_only: 'bool' = False) -> 'bool':
        jobs = job_blocks((_workflows.WORKFLOWS / 'unit-tests.yml').read_text(encoding='utf-8'))
        context = {STATUS: {'cancelled': False}, 'github': {'event_name': event, 'ref': ref},
                   'inputs': {'gate-only': gate_only}, 'needs': {'test': {'result': 'success', 'outputs': {}}}}
        return job_runs(jobs, 'unittest-ordering', context)

    def test_a_develop_push_runs_the_ordering_legs(self) -> None:
        self.assertIn('develop', on('unit-tests.yml')['push']['branches'])
        self.assertTrue(self.runs('push', 'refs/heads/develop'))
        self.assertFalse(self.runs('pull_request', 'refs/pull/2942/merge'))
        self.assertFalse(self.runs('push', 'refs/heads/develop', gate_only=True))


class TestDependabotTargetsDevelop(unittest.TestCase):

    def test_every_update_targets_develop(self) -> None:
        updates = _workflows.loads(DEPENDABOT.read_text(encoding='utf-8'))['updates']
        self.assertTrue(updates)
        for entry in updates:
            with self.subTest(ecosystem=entry['package-ecosystem']):
                self.assertEqual(entry.get('target-branch'), 'develop')


if __name__ == '__main__':
    unittest.main()
