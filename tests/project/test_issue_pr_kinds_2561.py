# -*- coding: utf-8 -*-
"""#2561: Issue and PR Kinds proposes a refresh of the #1103 roles test's snapshot.

:file:`.github/workflows/cron-issue-pr-kinds.yml` runs :file:`util/issue_pr_kinds.py`
every Monday and on dispatch. ``detect`` regenerates
:file:`tests/project/issue_pr_roles_fixtures/kinds.json` with a read-only token;
``pr``, behind ``github-release``, commits it on ``bot/issue-pr-kinds`` with the
release App's token and opens that branch's pull request. ``main`` is never pushed.

* :class:`TestTheWorkflow` pins the triggers, the permissions, the one secret and
  the guard on ``pr``.
* :class:`TestDeciding` runs ``--github-output``'s decision against a stand-in
  for :program:`git` and :program:`gh`.
* :class:`TestPublishing` runs ``--publish`` against the same stand-in: the
  lease, the recreated branch and the pull request it opens or leaves.

:mod:`tests.project.test_docs_issue_pr_roles_1103_unit` checks the file's form.

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
from util import issue_pr_kinds

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): reads the workflow and runs the script against stand-ins.
__tier__ = 'LATEST'

WORKFLOW = 'cron-issue-pr-kinds.yml'
#: The kinds file a stand-in run proposes.
TEXT = issue_pr_kinds.render({2: 'issue', 3: 'pr'})


def done(returncode: 'int' = 0, stdout: 'str' = '', stderr: 'str' = '') -> 'subprocess.CompletedProcess[str]':
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class FakeRun:
    """A stand-in for :func:`util.issue_pr_kinds.run`: each call recorded, each answered by ``reply``."""

    def __init__(self, reply: 'Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]]') -> None:
        self.calls = []  # type: list[tuple[str, ...]]
        self.reply = reply

    def __call__(self, *argv: 'str', check: 'bool' = True) -> 'subprocess.CompletedProcess[str]':
        self.calls.append(argv)
        result = self.reply(argv)
        if check and result.returncode:
            raise RuntimeError(f'{argv} failed')
        return result

    def made(self, *prefix: 'str') -> 'list[tuple[str, ...]]':
        return [call for call in self.calls if call[:len(prefix)] == prefix]


class TestTheWorkflow(unittest.TestCase):
    """Two jobs: ``detect`` with no secret, ``pr`` with the App's token behind ``github-release``."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = _workflows.load(WORKFLOW)
        cls.jobs = cls.spec['jobs']

    def step(self, job: 'str', label: 'str') -> 'dict[str, Any]':
        return next(step for step in self.jobs[job]['steps'] if step.get('name') == label)

    def test_it_runs_on_a_schedule_and_on_dispatch_one_at_a_time(self) -> None:
        self.assertEqual(self.spec['name'], 'Issue and PR Kinds')
        self.assertEqual(self.spec['on'], {'schedule': [{'cron': '17 6 * * 1'}], 'workflow_dispatch': None})
        self.assertEqual(self.spec['permissions'], {})
        self.assertEqual(self.spec['concurrency'], {'group': 'issue-pr-kinds', 'cancel-in-progress': False})
        self.assertEqual(sorted(self.jobs), ['detect', 'pr'])

    def test_detect_reads_only_and_decides_with_the_script(self) -> None:
        job = self.jobs['detect']
        self.assertEqual(job['permissions'], {'contents': 'read', 'issues': 'read', 'pull-requests': 'read'})
        self.assertNotIn('environment', job)
        self.assertNotIn('secrets.', json.dumps(job))
        regenerate = self.step('detect', 'Regenerate the kinds')
        self.assertEqual(regenerate['run'], 'python3 util/issue_pr_kinds.py --github-output')
        self.assertEqual(regenerate['env'], {'GH_TOKEN': '${{ github.token }}'})
        self.assertEqual(job['outputs'], {'publish': '${{ steps.regenerate.outputs.publish }}'})
        upload = self.step('detect', 'Upload the kinds')
        self.assertEqual(upload['with']['path'], issue_pr_kinds.PATH)

    def test_pr_runs_only_with_something_to_propose_the_app_and_main(self) -> None:
        condition = self.jobs['pr']['if']
        for publish, client, ref, expected in (('true', 'Iv23example', 'refs/heads/main', True),
                                               ('true', '', 'refs/heads/main', False),
                                               ('false', 'Iv23example', 'refs/heads/main', False),
                                               ('true', 'Iv23example', 'refs/heads/feature', False)):
            with self.subTest(publish=publish, client=client, ref=ref):
                state = {'needs': {'detect': {'outputs': {'publish': publish}}},
                         'vars': {'RELEASE_APP_CLIENT_ID': client}, 'github': {'ref': ref}}
                self.assertIs(evaluate_condition(condition, state), expected)

    def test_pr_mints_the_narrow_token_behind_github_release_and_pushes_through_the_script(self) -> None:
        job = self.jobs['pr']
        self.assertEqual(job['environment'], 'github-release')
        self.assertEqual(job['needs'], 'detect')
        self.assertEqual(job['permissions'], {'actions': 'read'})
        mint = self.step('pr', "Mint the release App's token")
        self.assertTrue(_workflows.pinned(mint['uses'], 'actions/create-github-app-token'), mint['uses'])
        self.assertEqual(mint['with'], {
            'client-id': '${{ vars.RELEASE_APP_CLIENT_ID }}',
            'private-key': '${{ secrets.RELEASE_APP_PRIVATE_KEY }}',
            'permission-contents': 'write',
            'permission-pull-requests': 'write',
        })
        self.assertEqual([step for step in job['steps'] if 'secrets.' in json.dumps(step)], [mint])
        push = self.step('pr', 'Push the kinds and open or update their pull request')
        self.assertEqual(push['run'].split()[:4], ['python3', 'util/issue_pr_kinds.py', '--publish',
                                                   '"$RUNNER_TEMP/kinds/kinds.json"'])
        self.assertEqual(push['env']['GH_TOKEN'], '${{ steps.app.outputs.token }}')
        text = (_workflows.WORKFLOWS / WORKFLOW).read_text(encoding='utf-8')
        self.assertNotIn('git push', text)
        self.assertEqual(issue_pr_kinds.BRANCH, 'bot/issue-pr-kinds')
        self.assertEqual(issue_pr_kinds.BASE, 'main')


class TestDeciding(unittest.TestCase):
    """``publish`` is true for a change the open pull request does not already hold."""

    def decide(self, changed: 'bool', open_pr: 'bool', held: 'str') -> 'tuple[bool, FakeRun]':
        def reply(argv: 'tuple[str, ...]') -> 'subprocess.CompletedProcess[str]':
            if argv[:2] == ('git', 'diff'):
                return done(1 if changed else 0)
            if argv[:3] == ('gh', 'pr', 'list'):
                return done(stdout='41\n' if open_pr else '')
            return done(stdout=held)

        fake = FakeRun(reply)
        with mock.patch.object(issue_pr_kinds, 'run', fake):
            return issue_pr_kinds.should_publish('o/r', TEXT), fake

    def test_each_case(self) -> None:
        for changed, open_pr, held, expected in ((False, True, 'other', False), (True, False, '', True),
                                                 (True, True, TEXT, False), (True, True, 'other', True)):
            with self.subTest(changed=changed, open_pr=open_pr, held=held[:5]):
                decided, fake = self.decide(changed, open_pr, held)
                self.assertIs(decided, expected)
                if open_pr and changed:
                    self.assertEqual(fake.calls[-1][-1], f'repos/o/r/contents/{issue_pr_kinds.PATH}'
                                                         f'?ref={issue_pr_kinds.BRANCH}')

    def test_main_writes_the_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output, kinds = pathlib.Path(tmp, 'out'), pathlib.Path(tmp, 'kinds.json')
            with mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), \
                    mock.patch.object(issue_pr_kinds, 'fetch', return_value={2: 'issue', 3: 'pr'}), \
                    mock.patch.object(issue_pr_kinds, 'should_publish', return_value=True) as decide, \
                    mock.patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(issue_pr_kinds.main(['--github-output', '--output', str(kinds)]), 0)
            self.assertEqual(output.read_text('utf-8'), 'publish=true\n')
            self.assertEqual(decide.call_args.args[1], TEXT)


class TestPublishing(unittest.TestCase):
    """``--publish`` moves only :data:`util.issue_pr_kinds.BRANCH` and opens its pull request once."""

    def publish(self, staged: 'bool' = True, remote: 'str' = '', pushes: 'tuple[str, ...]' = ('',),
                open_pr: 'bool' = False) -> 'FakeRun':
        results = list(pushes)

        def reply(argv: 'tuple[str, ...]') -> 'subprocess.CompletedProcess[str]':
            if argv[:3] == ('git', 'diff', '--cached'):
                return done(1 if staged else 0)
            if argv[:2] == ('git', 'ls-remote'):
                return done(stdout=f'{remote}\trefs/heads/{issue_pr_kinds.BRANCH}\n' if remote else '')
            if argv[:2] == ('git', 'push') and argv[-1].startswith('HEAD:'):
                stderr = results.pop(0)
                return done(1 if stderr else 0, stderr=stderr)
            if argv[:3] == ('gh', 'pr', 'list'):
                return done(stdout='41\n' if open_pr else '')
            if argv[:3] == ('gh', 'pr', 'create'):
                return done(stdout='https://github.com/o/r/pull/42\n')
            return done()

        fake = FakeRun(reply)
        with tempfile.TemporaryDirectory() as tmp:
            source = pathlib.Path(tmp, 'kinds.json')
            source.write_text(TEXT, encoding='utf-8')
            with mock.patch.object(issue_pr_kinds, 'run', fake), \
                    mock.patch.object(issue_pr_kinds, 'OUTPUT', pathlib.Path(tmp, 'out.json')), \
                    mock.patch.dict(os.environ, {'APP_SLUG': 'pcapkit-release', 'APP_BOT_ID': '7'}), \
                    mock.patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(issue_pr_kinds.publish('o/r', source, 'https://run'), 0)
                self.assertEqual(pathlib.Path(tmp, 'out.json').read_text('utf-8'), TEXT)
        return fake

    def test_nothing_staged_pushes_nothing(self) -> None:
        fake = self.publish(staged=False)
        self.assertEqual(fake.made('git', 'commit'), [])
        self.assertEqual(fake.made('git', 'push'), [])

    def test_a_new_branch_is_pushed_and_its_pull_request_opened(self) -> None:
        fake = self.publish()
        commit = fake.made('git', '-c')
        self.assertEqual(commit[0][:4], ('git', '-c', 'user.name=pcapkit-release[bot]',
                                         '-c'))
        self.assertIn('user.email=7+pcapkit-release[bot]@users.noreply.github.com', commit[0])
        self.assertEqual(fake.made('git', 'push'), [
            ('git', 'push', f'--force-with-lease=refs/heads/{issue_pr_kinds.BRANCH}:', 'origin',
             f'HEAD:refs/heads/{issue_pr_kinds.BRANCH}')])
        created = fake.made('gh', 'pr', 'create')
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0][created[0].index('--head') + 1], issue_pr_kinds.BRANCH)
        self.assertEqual(created[0][created[0].index('--base') + 1], 'main')

    def test_an_open_pull_request_is_updated_by_the_push_alone(self) -> None:
        fake = self.publish(remote='a' * 40, open_pr=True)
        self.assertEqual(fake.made('git', 'push')[0][2], f'--force-with-lease=refs/heads/{issue_pr_kinds.BRANCH}:'
                                                         f'{"a" * 40}')
        self.assertEqual(fake.made('gh', 'pr', 'create'), [])

    def test_a_workflow_change_on_main_recreates_the_branch(self) -> None:
        fake = self.publish(remote='a' * 40, pushes=(f'refusing {issue_pr_kinds.WORKFLOWS_REFUSAL}', ''))
        pushes = fake.made('git', 'push')
        self.assertEqual([push[-1] for push in pushes], [f'HEAD:refs/heads/{issue_pr_kinds.BRANCH}',
                                                         f':refs/heads/{issue_pr_kinds.BRANCH}',
                                                         f'HEAD:refs/heads/{issue_pr_kinds.BRANCH}'])
        self.assertEqual(pushes[-1][2], f'--force-with-lease=refs/heads/{issue_pr_kinds.BRANCH}:')

    def test_another_push_failure_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            self.publish(remote='a' * 40, pushes=('rejected: stale info',))

    def test_the_body_fills_in_the_template(self) -> None:
        text = issue_pr_kinds.body(TEXT, 'https://run')
        self.assertIn('- [x] `test`', text)
        self.assertIn('up to #3', text)
        self.assertIn('https://run', text)
        self.assertNotIn('Explanation of your *pull request*', text)
        self.assertIn('[Searched]', text)


if __name__ == '__main__':
    unittest.main()
