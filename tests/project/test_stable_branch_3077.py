# -*- coding: utf-8 -*-
"""#3077: Stable Branch keeps ``stable`` at ``main``'s head, for Read the Docs's ``stable``.

Read the Docs builds ``stable`` from a branch of that name where one exists, rather
than from the newest release tag. :file:`.github/workflows/stable-branch.yml` runs
:file:`util/stable_branch.py` on every push to ``main`` and on dispatch, in
``release-app`` with the release App's token, which force-updates ``stable`` to
``main``'s head through the REST API, as Sync Develop moves ``sync/main``.

* :class:`TestTheWorkflow` pins the triggers, the concurrency, the permissions, the
  ref the job runs on, the token the write spends and the script it runs, through
  :func:`problems`; its mutation rows show each check failing.
* :class:`TestTheScript` runs the script against a stand-in for :program:`gh`:
  ``stable`` created, moved or left alone, ``main`` read afresh rather than from the
  run, no other ref written, and a failed read or write.

:mod:`tests.project.test_release_app_environment_2648` pins the job's environment,
key check and mint step, and :mod:`tests.project.test_sync_develop_2942` the helpers
it shares.
The ruleset on ``stable`` is a repository setting, which no test here can read.

"""

from __future__ import annotations

import io
import os
import pathlib
import re
import subprocess  # nosec B404
import sys
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows
from tests.project.test_release_gates import evaluate_condition
from util import stable_branch

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = 'stable-branch.yml'
REPO = 'o/r'
MAIN = 'a' * 40
STEP = 'Mirror main to stable'
#: The refs the script reads and writes, and the paths that name them.
STABLE_REF = 'refs/heads/stable'
CREATE = f'repos/{REPO}/git/refs'
UPDATE = f'repos/{REPO}/git/refs/heads/stable'


def step(job: 'dict[str, Any]', name: 'str') -> 'Optional[dict[str, Any]]':
    return next((entry for entry in job.get('steps') or [] if entry.get('name') == name), None)


def problems(spec: 'dict[str, Any]') -> 'list[str]':
    """Every way ``spec`` breaks the rule; empty where it holds."""
    found = []
    if spec.get('on') != {'push': {'branches': ['main']}, 'workflow_dispatch': None}:
        found.append(f"it runs on {spec.get('on')!r}, not a push to main and dispatch")
    if spec.get('concurrency') != {'group': 'stable-branch', 'cancel-in-progress': False}:
        found.append(f"its concurrency is {spec.get('concurrency')!r}, not one queued group that cancels nothing")
    if spec.get('permissions') != {}:
        found.append(f"GITHUB_TOKEN holds {spec.get('permissions')!r} by default, not nothing")
    jobs = spec.get('jobs') or {}
    if sorted(jobs) != ['mirror']:
        return found + [f'its jobs are {sorted(jobs)}, not mirror alone']
    job = jobs['mirror']
    if job.get('permissions') != {'contents': 'read'}:
        found.append(f"mirror's GITHUB_TOKEN holds {job.get('permissions')!r}, not contents read")
    if job.get('environment') != 'release-app':
        found.append(f"mirror names {job.get('environment')!r}, not release-app")
    if not 0 < job.get('timeout-minutes', 0) <= 5:
        found.append(f"mirror's cap is {job.get('timeout-minutes')!r} minutes, not at most 5")
    for ref, runs in (('refs/heads/main', True), ('refs/heads/develop', False), ('refs/heads/feat/x', False),
                      (STABLE_REF, False), ('refs/tags/v1.8.0', False)):
        if evaluate_condition(job.get('if', 'true'), {'github': {'ref': ref}}) is not runs:
            found.append(f"mirror {'skips' if runs else 'runs'} on {ref}")
    move = step(job, STEP) or {}
    if move.get('env') != {'GH_TOKEN': '${{ steps.app.outputs.token }}'}:
        found.append(f"the mirror step spends {move.get('env')!r}, not the App's token alone")
    if move.get('run') != 'python3 util/stable_branch.py':
        found.append(f"the mirror step runs {move.get('run')!r}, not util/stable_branch.py")
    listed = [str((entry.get('with') or {}).get('sparse-checkout') or '').split()
              for entry in job.get('steps') or [] if str(entry.get('uses', '')).startswith('actions/checkout@')]
    if listed != [['util/_actions.py', 'util/sync_develop.py', 'util/stable_branch.py']]:
        found.append(f'the checkout holds {listed}, not the script and what it imports')
    text = repr(spec)
    for word in ('github.token', 'secrets.GITHUB_TOKEN', 'git push', 'write-all'):
        if word in text:
            found.append(f'it names {word}')
    return found


class TestTheWorkflow(unittest.TestCase):

    def test_the_rule_holds(self) -> None:
        self.assertEqual(problems(_workflows.load(WORKFLOW)), [])

    def test_each_mutation_is_caught(self) -> None:
        def setting(*path: 'str', value: 'Any') -> 'Callable[[dict[str, Any]], None]':
            def mutate(spec: 'dict[str, Any]') -> None:
                *parents, key = path
                for parent in parents:
                    spec = spec[parent]
                if value is None:
                    del spec[key]
                else:
                    spec[key] = value
            return mutate

        def in_step(name: 'str', *path: 'str', value: 'Any') -> 'Callable[[dict[str, Any]], None]':
            def mutate(spec: 'dict[str, Any]') -> None:
                found = step(spec['jobs']['mirror'], name)
                assert found is not None, name
                setting(*path, value=value)(found)
            return mutate

        def checkout_holds(paths: 'str') -> 'Callable[[dict[str, Any]], None]':
            def mutate(spec: 'dict[str, Any]') -> None:
                found = next(entry for entry in spec['jobs']['mirror']['steps']
                             if str(entry.get('uses', '')).startswith('actions/checkout@'))
                found['with']['sparse-checkout'] = paths
            return mutate

        mutations = {
            'a push to develop as well': setting('on', 'push', 'branches', value=['main', 'develop']),
            'a pull request trigger': setting('on', 'pull_request', value={'branches': ['main']}),
            'no dispatch': setting('on', 'workflow_dispatch', value=None),
            'a run in progress cancelled': setting('concurrency', 'cancel-in-progress', value=True),
            'no concurrency group': setting('concurrency', value=None),
            'a default write scope': setting('permissions', value={'contents': 'write'}),
            "mirror's token given contents write": setting('jobs', 'mirror', 'permissions',
                                                           value={'contents': 'write'}),
            'mirror outside release-app': setting('jobs', 'mirror', 'environment', value=None),
            'no cap on mirror': setting('jobs', 'mirror', 'timeout-minutes', value=None),
            'mirror on every ref': setting('jobs', 'mirror', 'if', value=None),
            'mirror on develop': setting('jobs', 'mirror', 'if', value="${{ github.ref == 'refs/heads/develop' }}"),
            'a second job': setting('jobs', 'probe', value={'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}),
            'the write on GITHUB_TOKEN': in_step(STEP, 'env', 'GH_TOKEN', value='${{ github.token }}'),
            'the write on secrets.GITHUB_TOKEN': in_step(STEP, 'env', 'GH_TOKEN',
                                                         value='${{ secrets.GITHUB_TOKEN }}'),
            'another script': in_step(STEP, 'run', value='python3 util/sync_develop.py --propose'),
            'a push by git': in_step(STEP, 'run', value='git push --force origin HEAD:refs/heads/stable'),
            'sync_develop.py left out of the checkout': checkout_holds('util/_actions.py\nutil/stable_branch.py\n'),
        }
        for label, mutate in sorted(mutations.items()):
            with self.subTest(mutation=label):
                spec = _workflows.load(WORKFLOW)
                mutate(spec)
                self.assertTrue(problems(spec), label)


def done(returncode: 'int' = 0, stdout: 'str' = '', stderr: 'str' = '') -> 'subprocess.CompletedProcess[str]':
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class FakeGh:
    """A stand-in for :func:`util.sync_develop.run`: the repository's branches, each call recorded.

    ``refs`` maps a branch to its commit; ``stable`` is missing where it does not exist.
    """

    def __init__(self, refs: 'dict[str, str]', fail: 'str' = '') -> None:
        self.refs, self.fail = dict(refs), fail
        self.calls = []  # type: list[tuple[str, ...]]

    def __call__(self, *argv: 'str') -> 'subprocess.CompletedProcess[str]':
        self.calls.append(argv)
        if argv[:2] != ('gh', 'api'):
            raise AssertionError(f'not a gh api call: {argv}')
        path = next(arg for arg in argv[2:] if arg.startswith('repos/'))
        method = argv[argv.index('-X') + 1] if '-X' in argv else 'GET'
        if self.fail and self.fail in path:
            return done(1, stderr='gh: Server Error (HTTP 502)')
        read = f'repos/{REPO}/git/ref/heads/'
        if method == 'GET' and path.startswith(read):
            sha = self.refs.get(path[len(read):])
            return done(stdout=f'{sha}\n') if sha is not None else done(1, stderr='gh: Not Found (HTTP 404)')
        if method == 'POST' and path == CREATE:
            self.refs[self.field(argv, 'ref')[len('refs/heads/'):]] = self.field(argv, 'sha')
            return done(stdout=self.field(argv, 'sha') + '\n')
        if method == 'PATCH' and path.startswith(CREATE + '/heads/'):
            self.refs[path[len(CREATE + '/heads/'):]] = self.field(argv, 'sha')
            return done(stdout=self.field(argv, 'sha') + '\n')
        raise AssertionError(f'unexpected call {argv}')

    def writes(self) -> 'list[tuple[str, ...]]':
        return [call for call in self.calls if '-X' in call]

    @staticmethod
    def field(call: 'tuple[str, ...]', name: 'str') -> 'str':
        values = [call[index + 1][len(name) + 1:] for index, arg in enumerate(call)
                  if arg in ('-f', '-F') and call[index + 1].startswith(f'{name}=')]
        assert len(values) == 1, (name, call)
        return values[0]


class TestTheScript(unittest.TestCase):

    def run_script(self, refs: 'dict[str, str]', fail: 'str' = '',
                   env: 'Optional[dict[str, str]]' = None) -> 'tuple[int, str, FakeGh]':
        fake = FakeGh(refs, fail)
        with mock.patch.object(stable_branch.sync_develop, 'run', fake), \
                mock.patch.dict(os.environ, env or {}), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            code = stable_branch.main(['--repo', REPO])
        return code, stdout.getvalue(), fake

    def test_a_missing_stable_is_created_at_mains_head(self) -> None:
        code, stdout, fake = self.run_script({'main': MAIN})
        self.assertEqual(code, 0)
        [created] = fake.writes()
        self.assertIn(CREATE, created)
        self.assertEqual((fake.field(created, 'ref'), fake.field(created, 'sha')), (STABLE_REF, MAIN))
        self.assertEqual(fake.refs, {'main': MAIN, 'stable': MAIN})
        self.assertIn(f'stable set to {MAIN[:9]}', stdout)

    def test_a_stable_anywhere_else_is_force_updated_to_mains_head(self) -> None:
        """Behind, ahead of or beside ``main``: force, since the mirror is reset rather than advanced."""
        code, stdout, fake = self.run_script({'main': MAIN, 'stable': 'b' * 40})
        self.assertEqual(code, 0)
        [moved] = fake.writes()
        self.assertEqual(moved[:4], ('gh', 'api', '-X', 'PATCH'))
        self.assertIn(UPDATE, moved)
        self.assertEqual((fake.field(moved, 'sha'), fake.field(moved, 'force')), (MAIN, 'true'))
        self.assertEqual(fake.refs['stable'], MAIN)
        self.assertIn(f'stable set to {MAIN[:9]}', stdout)

    def test_a_stable_at_mains_head_is_left_alone(self) -> None:
        code, stdout, fake = self.run_script({'main': MAIN, 'stable': MAIN})
        self.assertEqual((code, fake.writes()), (0, []))
        self.assertIn(f'stable is already at {MAIN[:9]}', stdout)

    def test_mains_head_is_read_afresh_not_taken_from_the_run(self) -> None:
        """A re-run of an older push carries that push's ``GITHUB_SHA``; ``stable`` still goes to the head."""
        code, _, fake = self.run_script({'main': MAIN, 'stable': 'b' * 40},
                                        env={'GITHUB_SHA': 'c' * 40, 'GITHUB_REF': 'refs/heads/main'})
        self.assertEqual(code, 0)
        self.assertEqual(fake.calls[0][:3], ('gh', 'api', f'repos/{REPO}/git/ref/heads/main'))
        self.assertEqual([fake.field(call, 'sha') for call in fake.writes()], [MAIN])

    def test_only_stable_is_written(self) -> None:
        for refs in ({'main': MAIN}, {'main': MAIN, 'stable': 'b' * 40}):
            with self.subTest(stable=refs.get('stable')):
                _, _, fake = self.run_script(refs)
                for call in fake.writes():
                    self.assertTrue(UPDATE in call or (CREATE in call and fake.field(call, 'ref') == STABLE_REF),
                                    call)
                self.assertEqual(fake.refs['main'], MAIN)
                self.assertEqual(len(fake.writes()), 1)

    def test_an_unreadable_main_moves_nothing(self) -> None:
        for refs, fail in (({'main': MAIN}, 'git/ref/heads/main'), ({'main': ''}, ''), ({'main': 'not-a-sha'}, ''),
                           ({}, '')):
            with self.subTest(main=refs.get('main'), fail=fail):
                code, stdout, fake = self.run_script(refs, fail)
                self.assertEqual(code, 1)
                self.assertIn('::error title=stable not mirrored::', stdout)
                self.assertEqual(fake.writes(), [])

    def test_a_failed_read_or_write_of_stable_is_an_error(self) -> None:
        for refs, fail in (({'main': MAIN}, 'git/refs'), ({'main': MAIN, 'stable': 'b' * 40}, 'git/refs'),
                           ({'main': MAIN}, 'git/ref/heads/stable')):
            with self.subTest(stable=refs.get('stable'), fail=fail):
                code, stdout, _ = self.run_script(refs, fail)
                self.assertEqual(code, 1)
                self.assertIn('::error title=stable not mirrored::', stdout)

    def test_run_as_the_step_runs_it(self) -> None:
        """``python3 util/stable_branch.py`` from the root, with util/ first on the path, finds both imports."""
        env = {key: value for key, value in os.environ.items() if not key.startswith(('GITHUB_', 'PYTHON'))}
        result = subprocess.run([sys.executable, 'util/stable_branch.py', '--help'],  # nosec B603
                                cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(re.search(r'Force-update stable to main\'s head', result.stdout), result.stdout)


if __name__ == '__main__':
    unittest.main()
