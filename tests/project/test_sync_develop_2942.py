# -*- coding: utf-8 -*-
"""#2942: Sync Develop proposes merging ``main`` into ``develop`` while ``develop`` lags.

:file:`.github/workflows/sync-develop.yml` runs :file:`util/sync_develop.py` on every
push to ``main`` and on dispatch. ``check`` compares the branches with a read-only
token; ``pr``, in ``release-app``, opens the pull request from ``main`` into
``develop`` with the release App's token, or updates the open one.

* :class:`TestTheWorkflow` pins the triggers, the permissions, the bounds, the
  token each job spends and the guard on ``pr``.
* :class:`TestTheScript` runs both modes against a stand-in for :program:`gh`: a
  missing ``develop``, a level one, one behind, an open pull request it updates
  rather than duplicating, and a failed read.

:mod:`tests.project.test_release_app_environment_2648` pins ``pr``'s key check.

"""

from __future__ import annotations

import io
import json
import os
import pathlib
import subprocess  # nosec B404
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows
from tests.project.test_release_gates import evaluate_condition
from util import sync_develop

if TYPE_CHECKING:
    from typing import Any, Optional

WORKFLOW = 'sync-develop.yml'
REPO = 'o/r'
SHA = 'a' * 40
#: The token minting step, as Create Release's ``github`` job runs it.
MINT = "Mint the release App's token"
PROPOSE = 'Open or update the pull request from main into develop'


def done(returncode: 'int' = 0, stdout: 'str' = '', stderr: 'str' = '') -> 'subprocess.CompletedProcess[str]':
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def step(job: 'dict[str, Any]', name: 'str') -> 'dict[str, Any]':
    return next(entry for entry in job['steps'] if entry.get('name') == name)


class TestTheWorkflow(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = _workflows.load(WORKFLOW)
        cls.jobs = cls.spec['jobs']

    def test_it_runs_on_a_push_to_main_and_on_dispatch(self) -> None:
        self.assertEqual(self.spec['on'], {'push': {'branches': ['main']}, 'workflow_dispatch': None})

    def test_its_permissions_and_bounds(self) -> None:
        """No scope by default, one run at a time, a cap on every job, no write scope for ``GITHUB_TOKEN``."""
        self.assertEqual(self.spec['permissions'], {})
        self.assertEqual(self.spec['concurrency'], {'group': 'sync-develop', 'cancel-in-progress': False})
        self.assertEqual(sorted(self.jobs), ['check', 'pr'])
        for job_id, job in self.jobs.items():
            with self.subTest(job=job_id):
                self.assertLessEqual(job['timeout-minutes'], 5)
                self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertNotIn('environment', self.jobs['check'])
        self.assertNotIn('secrets.', repr(self.jobs['check']))
        self.assertEqual(self.jobs['pr']['environment'], 'release-app')

    def test_the_pull_request_is_opened_with_the_release_apps_token(self) -> None:
        """Create Release's action and inputs, with pull requests write and contents read alone."""
        release = step(_workflows.load('create-release.yml')['jobs']['github'], MINT)
        mint = step(self.jobs['pr'], MINT)
        self.assertEqual(mint['uses'], release['uses'])
        self.assertEqual({key: mint['with'][key] for key in ('client-id', 'private-key')},
                         {key: release['with'][key] for key in ('client-id', 'private-key')})
        self.assertEqual({key: value for key, value in mint['with'].items() if key.startswith('permission-')},
                         {'permission-contents': 'read', 'permission-pull-requests': 'write'})
        self.assertEqual(step(self.jobs['pr'], PROPOSE)['env']['GH_TOKEN'], '${{ steps.app.outputs.token }}')
        self.assertIn('--propose', step(self.jobs['pr'], PROPOSE)['run'])
        compare = step(self.jobs['check'], 'Check whether develop lacks commits of main')
        self.assertEqual(compare['env'], {'GH_TOKEN': '${{ github.token }}'})
        self.assertEqual(compare['run'], 'python3 util/sync_develop.py --check')

    def test_pr_runs_only_when_develop_lags_on_main_with_the_app_set_up(self) -> None:
        condition = self.jobs['pr']['if']
        for behind, client, ref, expected in (('true', 'Iv23example', 'refs/heads/main', True),
                                              ('false', 'Iv23example', 'refs/heads/main', False),
                                              ('', 'Iv23example', 'refs/heads/main', False),
                                              ('true', '', 'refs/heads/main', False),
                                              ('true', 'Iv23example', 'refs/heads/feat/x', False)):
            context = {'needs': {'check': {'outputs': {'behind': behind}}},
                       'vars': {'RELEASE_APP_CLIENT_ID': client}, 'github': {'ref': ref}}
            with self.subTest(behind=behind, client=bool(client), ref=ref):
                self.assertIs(evaluate_condition(condition, context), expected)

    def test_nothing_merges_or_pushes(self) -> None:
        text = (_workflows.WORKFLOWS / WORKFLOW).read_text(encoding='utf-8')
        for word in ('git push', 'gh pr merge', 'write-all', 'contents: write', 'permission-contents: write'):
            with self.subTest(word=word):
                self.assertNotIn(word, text)


class FakeGh:
    """A stand-in for :func:`util.sync_develop.run`: the repository's state, each call recorded."""

    def __init__(self, develop: 'bool' = True, ahead: 'int' = 3, open_pr: 'Optional[int]' = None,
                 fail: 'str' = '') -> None:
        self.develop, self.ahead, self.open_pr, self.fail = develop, ahead, open_pr, fail
        self.calls = []  # type: list[tuple[str, ...]]

    def __call__(self, *argv: 'str') -> 'subprocess.CompletedProcess[str]':
        self.calls.append(argv)
        self.assertion(argv[:2] == ('gh', 'api'), argv)
        path = next(arg for arg in argv[2:] if arg.startswith('repos/'))
        if self.fail and self.fail in path:
            return done(1, stderr='gh: Server Error (HTTP 502)')
        if path == f'repos/{REPO}/branches/develop':
            return done(stdout='develop\n') if self.develop else done(1, stderr='gh: Branch not found (HTTP 404)')
        if path == f'repos/{REPO}/compare/develop...main':
            return done(stdout=f'{self.ahead}\n')
        if path.startswith(f'repos/{REPO}/pulls?'):
            return done(stdout=f'{self.open_pr}\n' if self.open_pr else '')
        if path == f'repos/{REPO}/pulls' and '-X' in argv and argv[argv.index('-X') + 1] == 'POST':
            return done(stdout=json.dumps({'number': 42, 'html_url': f'https://github.com/{REPO}/pull/42'}))
        if path.startswith(f'repos/{REPO}/pulls/') and argv[argv.index('-X') + 1] == 'PATCH':
            return done(stdout=path.rsplit('/', 1)[1])
        raise AssertionError(f'unexpected call {argv}')

    @staticmethod
    def assertion(holds: 'bool', argv: 'tuple[str, ...]') -> None:
        if not holds:
            raise AssertionError(f'not a gh api call: {argv}')

    def writes(self, method: 'str') -> 'list[tuple[str, ...]]':
        return [call for call in self.calls if '-X' in call and call[call.index('-X') + 1] == method]

    @staticmethod
    def field(call: 'tuple[str, ...]', name: 'str') -> 'str':
        values = [call[index + 1][len(name) + 1:] for index, arg in enumerate(call)
                  if arg == '-f' and call[index + 1].startswith(f'{name}=')]
        assert len(values) == 1, (name, call)
        return values[0]


class TestTheScript(unittest.TestCase):

    def run_script(self, *args: 'str', **state: 'Any') -> 'tuple[int, str, str, FakeGh]':
        fake = FakeGh(**state)
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp, 'output')
            output.write_text('', encoding='utf-8')
            with mock.patch.object(sync_develop, 'run', fake), \
                    mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), \
                    mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
                code = sync_develop.main([*args, '--repo', REPO])
            return code, output.read_text(encoding='utf-8'), stdout.getvalue(), fake

    def test_a_develop_that_does_not_exist_yet_is_a_notice(self) -> None:
        code, output, stdout, fake = self.run_script('--check', develop=False)
        self.assertEqual((code, output), (0, 'behind=false\n'))
        self.assertIn('::notice title=No develop branch::', stdout)
        self.assertEqual(len(fake.calls), 1, 'compared a branch that does not exist')
        code, _, _, fake = self.run_script('--propose', develop=False)
        self.assertEqual(code, 0)
        self.assertEqual((fake.writes('POST'), fake.writes('PATCH')), ([], []))

    def test_a_level_develop_needs_nothing(self) -> None:
        code, output, _, _ = self.run_script('--check', ahead=0)
        self.assertEqual((code, output), (0, 'behind=false\n'))
        code, _, _, fake = self.run_script('--propose', ahead=0)
        self.assertEqual(code, 0)
        self.assertEqual((fake.writes('POST'), fake.writes('PATCH')), ([], []))

    def test_a_develop_that_lacks_commits_of_main_is_behind(self) -> None:
        code, output, stdout, _ = self.run_script('--check', ahead=3)
        self.assertEqual((code, output), (0, 'behind=true\n'))
        self.assertIn('develop lacks 3 commit(s) of main', stdout)

    def test_a_failed_comparison_warns_and_proposes_nothing(self) -> None:
        code, output, stdout, _ = self.run_script('--check', fail='compare')
        self.assertEqual((code, output), (0, 'behind=false\n'))
        self.assertIn('::warning title=develop not compared::', stdout)
        code, _, stdout, fake = self.run_script('--propose', fail='compare')
        self.assertEqual(code, 1)
        self.assertIn('::error title=No pull request::', stdout)
        self.assertEqual(fake.writes('POST'), [])

    def test_one_pull_request_opens_from_main_into_develop(self) -> None:
        code, _, stdout, fake = self.run_script('--propose', '--sha', SHA, '--run-url', 'https://run')
        self.assertEqual(code, 0)
        [created] = fake.writes('POST')
        self.assertEqual(fake.writes('PATCH'), [])
        self.assertIn(f'repos/{REPO}/pulls', created)
        self.assertEqual([fake.field(created, name) for name in ('title', 'head', 'base')],
                         ['chore: merge main into develop', 'main', 'develop'])
        body = fake.field(created, 'body')
        self.assertIn('**Merge with a merge commit, not a squash**', body)
        self.assertIn('- [x] `chore`', body)
        self.assertIn(f'`main` at `{SHA[:9]}`', body)
        self.assertIn('lacks 3 of its commits', body)
        self.assertIn('(https://run)', body)
        self.assertIn('opened pull request #42', stdout)

    def test_an_open_pull_request_is_updated_and_never_duplicated(self) -> None:
        code, _, stdout, fake = self.run_script('--propose', open_pr=41)
        self.assertEqual(code, 0)
        self.assertEqual(fake.writes('POST'), [])
        [edited] = fake.writes('PATCH')
        self.assertIn(f'repos/{REPO}/pulls/41', edited)
        self.assertEqual(fake.field(edited, 'title'), 'chore: merge main into develop')
        self.assertIn('**Merge with a merge commit, not a squash**', fake.field(edited, 'body'))
        self.assertIn('updated pull request #41', stdout)
        # The lookup names this repository's own `main`, so a fork's `main` is no match.
        [listed] = [call for call in fake.calls if any(arg.startswith(f'repos/{REPO}/pulls?') for arg in call)]
        self.assertIn(f'repos/{REPO}/pulls?state=open&head=o:main&base=develop', listed)

    def test_every_call_reads_or_writes_a_pull_request_and_none_merges(self) -> None:
        for state in ({}, {'open_pr': 41}):
            with self.subTest(**state):
                _, _, _, fake = self.run_script('--propose', **state)
                for call in fake.calls:
                    self.assertEqual(call[:2], ('gh', 'api'))
                    self.assertFalse(any(arg.endswith('/merge') or '/merges' in arg or '/git/' in arg
                                         for arg in call), call)


if __name__ == '__main__':
    unittest.main()
