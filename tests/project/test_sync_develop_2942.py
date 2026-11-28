# -*- coding: utf-8 -*-
"""#2942: Sync Develop merges ``main`` into ``develop`` while ``develop`` lags.

:file:`.github/workflows/sync-develop.yml` runs :file:`util/sync_develop.py` on every
push to ``main`` and on dispatch. ``check`` compares the branches with a read-only
token; ``merge``, in ``conda-tag``, merges ``main`` into a checkout of ``develop`` and
pushes it through the maintenance deploy key, with no pull request (#3102). Only a
merge that conflicts reaches ``pr``, in ``release-app``: it force-updates
``sync/main`` to ``main``'s head and opens the pull request from it into ``develop``
with the release App's token, or updates the open one. The head is that mirror
rather than ``main`` so that "Update branch", which merges the base into the head,
never writes to ``main`` (#3075).

* :class:`TestTheWorkflow` pins the triggers, the permissions, the bounds, the
  credential each job spends and the guards on ``merge`` and ``pr``.
* :class:`TestTheMerge` runs ``--merge`` against scratch repositories: a clean
  merge pushed, a level ``develop`` left alone, a conflict aborted and handed to
  ``pr``, a push refused while ``develop`` moved merged afresh once, and the
  refusals that fail the job.
* :class:`TestTheScript` runs the other modes against a stand-in for :program:`gh`:
  a missing ``develop``, a level one, one behind, the mirror created, moved or left
  alone, an open pull request it updates rather than duplicating, one from ``main``
  itself it closes, and a failed read or write.

:mod:`tests.project.test_release_app_environment_2648` pins ``pr``'s key check and
mint step.

"""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec B404
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows
from tests._support import scale_timeout
from tests.project.test_release_gates import evaluate_condition
from util import sync_develop

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

WORKFLOW = 'sync-develop.yml'
REPO = 'o/r'
SHA = 'a' * 40
PROPOSE = 'Mirror main to sync/main and open or update its pull request into develop'
#: The mirror, and the ref path its writes name.
MIRROR = 'sync/main'
MIRROR_REF = f'repos/{REPO}/git/refs/heads/{MIRROR}'
#: The steps of ``merge``, in order; ``None`` is the checkout of ``main``'s script.
KEY_STEP, DEVELOP_STEP = 'Load maintenance deploy key', 'Check out develop'
CONFIGURE, MERGE = 'Configure git for the deploy key', 'Merge main into develop and push it'
WARN = 'Say why no pull request opens'
MERGE_STEPS = [KEY_STEP, None, DEVELOP_STEP, CONFIGURE, MERGE, WARN]
GIT = shutil.which('git')


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
        """No scope by default, one run at a time, a cap on every job, no write scope for ``GITHUB_TOKEN``.

        ``merge`` fetches ``develop``'s whole history, so its cap is the longest.
        """
        self.assertEqual(self.spec['permissions'], {})
        self.assertEqual(self.spec['concurrency'], {'group': 'sync-develop', 'cancel-in-progress': False})
        self.assertEqual(sorted(self.jobs), ['check', 'merge', 'pr'])
        for job_id, job in self.jobs.items():
            with self.subTest(job=job_id):
                self.assertLessEqual(job['timeout-minutes'], 10 if job_id == 'merge' else 5)
                self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertNotIn('environment', self.jobs['check'])
        self.assertNotIn('secrets.', repr(self.jobs['check']))
        self.assertEqual(self.jobs['merge']['environment'], 'conda-tag')
        self.assertEqual(self.jobs['pr']['environment'], 'release-app')
        self.assertEqual((self.jobs['merge']['needs'], self.jobs['pr']['needs']), ('check', 'merge'))

    def test_develop_is_pushed_through_the_deploy_key(self) -> None:
        """Create Release's key and git set-up, in a checkout of ``develop`` beside ``main``'s script.

        The deploy key is what ``develop``'s ruleset lets past its pull request
        rule; the release App's token is not, and no step of ``merge`` reads it.
        """
        tag = _workflows.load('create-release.yml')['jobs']['tag']
        merge = self.jobs['merge']
        self.assertEqual([entry.get('name') for entry in merge['steps']], MERGE_STEPS)
        key = step(merge, KEY_STEP)
        self.assertEqual({name: key[name] for name in ('uses', 'with')},
                         {name: step(tag, KEY_STEP)[name] for name in ('uses', 'with')})
        self.assertEqual(key['with'], {'ssh-private-key': '${{ secrets.PYPCAPKIT_ACTIONS_DEPLOY_KEY }}'})
        configure = step(merge, CONFIGURE)
        self.assertEqual(configure['run'], step(tag, CONFIGURE)['run'])
        self.assertEqual(configure['working-directory'], 'develop')
        script = merge['steps'][1]
        self.assertEqual(script['uses'], step(merge, DEVELOP_STEP)['uses'])
        self.assertTrue(script['uses'].startswith('actions/checkout@'), script)
        self.assertEqual(script['with'], self.jobs['check']['steps'][0]['with'], "not main's script alone")
        self.assertEqual(step(merge, DEVELOP_STEP)['with'],
                         {'ref': 'develop', 'path': 'develop', 'fetch-depth': 0, 'persist-credentials': False})
        run = step(merge, MERGE)
        self.assertEqual((run['id'], run['run']),
                         ('merge', 'python3 util/sync_develop.py --merge --work-tree develop --run-url "$RUN_URL"'))
        self.assertEqual(list(run['env']), ['RUN_URL'], 'a token besides the deploy key')
        self.assertEqual(merge['outputs'], {'conflict': '${{ steps.merge.outputs.conflict }}'})
        self.assertEqual(set(re.findall(r'\bsecrets\.(\w+)', repr(merge))), {'PYPCAPKIT_ACTIONS_DEPLOY_KEY'})

    def test_merge_runs_when_develop_lags_on_main_without_the_app(self) -> None:
        condition = self.jobs['merge']['if']
        for behind, ref, expected in (('true', 'refs/heads/main', True), ('false', 'refs/heads/main', False),
                                      ('', 'refs/heads/main', False), ('true', 'refs/heads/feat/x', False)):
            context = {'needs': {'check': {'outputs': {'behind': behind}}}, 'vars': {'RELEASE_APP_CLIENT_ID': ''},
                       'github': {'ref': ref}}
            with self.subTest(behind=behind, ref=ref):
                self.assertIs(evaluate_condition(condition, context), expected)

    def test_without_the_app_a_conflict_warns(self) -> None:
        condition = step(self.jobs['merge'], WARN)['if']
        for conflict, client, expected in (('true', '', True), ('true', 'Iv23example', False), ('false', '', False),
                                           ('', '', False)):
            context = {'steps': {'merge': {'outputs': {'conflict': conflict}}},
                       'vars': {'RELEASE_APP_CLIENT_ID': client}}
            with self.subTest(conflict=conflict, client=bool(client)):
                self.assertIs(evaluate_condition(condition, context), expected)
        self.assertIn('::warning title=No pull request without the release App::',
                      step(self.jobs['merge'], WARN)['run'])

    def test_the_pull_request_is_opened_with_the_release_apps_token(self) -> None:
        """test_release_app_environment_2648.py pins the mint step: contents and workflows write move
        the mirror past a workflow change of ``main``'s, and pull requests write opens its pull request."""
        self.assertEqual(step(self.jobs['pr'], PROPOSE)['env']['GH_TOKEN'], '${{ steps.app.outputs.token }}')
        self.assertEqual(step(self.jobs['pr'], PROPOSE)['run'],
                         'python3 util/sync_develop.py --propose --run-url "$RUN_URL"')
        compare = step(self.jobs['check'], 'Check whether develop lacks commits of main')
        self.assertEqual(compare['env'], {'GH_TOKEN': '${{ github.token }}'})
        self.assertEqual(compare['run'], 'python3 util/sync_develop.py --check')

    def test_pr_runs_only_on_a_conflict_on_main_with_the_app_set_up(self) -> None:
        """A clean merge, or a failed one, opens no pull request."""
        condition = self.jobs['pr']['if']
        for conflict, client, ref, expected in (('true', 'Iv23example', 'refs/heads/main', True),
                                                ('false', 'Iv23example', 'refs/heads/main', False),
                                                ('', 'Iv23example', 'refs/heads/main', False),
                                                ('true', '', 'refs/heads/main', False),
                                                ('true', 'Iv23example', 'refs/heads/feat/x', False)):
            context = {'needs': {'merge': {'outputs': {'conflict': conflict}}},
                       'vars': {'RELEASE_APP_CLIENT_ID': client}, 'github': {'ref': ref}}
            with self.subTest(conflict=conflict, client=bool(client), ref=ref):
                self.assertIs(evaluate_condition(condition, context), expected)

    def test_nothing_merges_or_pushes_by_git(self) -> None:
        """No step pushes or merges itself: ``--merge`` does, which :class:`TestTheMerge` pins."""
        text = (_workflows.WORKFLOWS / WORKFLOW).read_text(encoding='utf-8')
        for word in ('git push', 'gh pr merge', 'write-all'):
            with self.subTest(word=word):
                self.assertNotIn(word, text)


@unittest.skipIf(not GIT, 'needs git on PATH')
class TestTheMerge(unittest.TestCase):
    """``--merge`` in a clone of a bare ``origin``'s ``develop``, as ``merge`` checks it out.

    The clone's ``origin`` is a path rather than the deploy key's ssh URL, which is
    all ``Configure git for the deploy key`` changes. ``develop`` starts with a
    commit ``main`` lacks, and ``main`` with a fix ``develop`` lacks.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-3102-')
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        home = self.root / 'home'
        home.mkdir()
        (home / '.gitconfig').write_text(
            '[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n'
            '[maintenance]\n\tauto = false\n\tautoDetach = false\n'
            '[gc]\n\tauto = 0\n\tautoDetach = false\n'
            '[user]\n\tname = Jarry Shaw\n\temail = jarryshaw@icloud.com\n', encoding='utf-8')
        self.env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(home), 'XDG_CONFIG_HOME': str(home / '.config'),
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}
        self.origin, self.seed, self.work = self.root / 'origin.git', self.root / 'seed', self.root / 'develop'
        self.git('init', '-q', '--bare', str(self.origin), cwd=self.root)
        self.git('clone', '-q', str(self.origin), str(self.seed), cwd=self.root)
        (self.seed / 'shared.txt').write_text('base\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        self.git('push', '-q', 'origin', 'HEAD:refs/heads/main', 'HEAD:refs/heads/develop')
        self.develop = self.commit('develop', 'next.txt', 'next minor\n')
        self.main = self.commit('main', 'fix.txt', 'patch fix\n')
        self.git('clone', '-q', '--branch', 'develop', str(self.origin), str(self.work), cwd=self.root)
        self.pushes = 0

    def git(self, *args: 'str', cwd: 'Optional[pathlib.Path]' = None) -> 'str':
        result = subprocess.run(['git', *args], cwd=cwd or self.seed, env=self.env,  # nosec B603 B607
                                capture_output=True, text=True, check=False, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def commit(self, branch: 'str', path: 'str', text: 'str') -> 'str':
        """Commit ``text`` to ``path`` on ``origin``'s ``branch``, from the seed clone; the new head."""
        self.git('fetch', '-q', 'origin')
        self.git('checkout', '-q', '-B', branch, f'origin/{branch}')
        (self.seed / path).write_text(text, encoding='utf-8')
        self.git('add', path)
        self.git('commit', '-qm', f'{branch}: {path}')
        self.git('push', '-q', 'origin', f'HEAD:refs/heads/{branch}')
        return self.git('rev-parse', 'HEAD')

    def origin_git(self, *args: 'str') -> 'str':
        return self.git(f'--git-dir={self.origin}', *args, cwd=self.root)

    def head(self, branch: 'str') -> 'str':
        return self.origin_git('rev-parse', f'refs/heads/{branch}')

    def parents(self, sha: 'str') -> 'list[str]':
        return self.origin_git('rev-list', '--parents', '-n', '1', sha).split()[1:]

    def run_merge(self, before_push: 'Optional[Callable[[int], Any]]' = None) -> 'tuple[int, str, str, str]':
        """Exit status, ``$GITHUB_OUTPUT``, the step summary and standard output of ``--merge``.

        ``before_push`` runs ahead of each ``git push`` with its count; what it
        returns, unless :data:`None`, stands in for that push's result.
        """
        real = sync_develop.run

        def run(*argv: 'str') -> 'subprocess.CompletedProcess[str]':
            if argv[:2] == ('git', '-C') and argv[3] == 'push':
                self.pushes += 1
                refused = before_push(self.pushes) if before_push else None
                if refused is not None:
                    return refused
            return real(*argv)

        output, summary = self.root / 'output', self.root / 'summary'
        for file in (output, summary):
            file.write_text('', encoding='utf-8')
        env = dict(self.env, GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary))
        with mock.patch.object(sync_develop, 'run', run), mock.patch.dict(os.environ, env, clear=True), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            code = sync_develop.main(['--merge', '--work-tree', str(self.work), '--run-url', 'https://run'])
        return (code, output.read_text(encoding='utf-8'), summary.read_text(encoding='utf-8'),
                stdout.getvalue())

    def test_a_clean_merge_is_pushed_to_develop_with_no_pull_request(self) -> None:
        code, output, summary, stdout = self.run_merge()
        self.assertEqual((code, output), (0, 'conflict=false\n'), stdout)
        merged = self.head('develop')
        self.assertEqual(self.parents(merged), [self.develop, self.main], 'not a merge commit of the two')
        self.assertEqual(self.origin_git('log', '-1', '--format=%s', merged), 'chore: merge main into develop')
        self.assertEqual(self.origin_git('log', '-1', '--format=%b', merged),
                         'Pushed by Sync Develop (#3102): https://run')
        self.assertEqual(self.origin_git('ls-tree', '--name-only', merged).split(),
                         ['fix.txt', 'next.txt', 'shared.txt'])
        self.assertEqual(self.head('main'), self.main)
        self.assertEqual(self.origin_git('for-each-ref', '--format=%(refname)').split(),
                         ['refs/heads/develop', 'refs/heads/main'], f'{MIRROR} or another ref written')
        self.assertEqual(self.pushes, 1)
        self.assertIn(f'pushed it at `{merged[:9]}`, with no pull request (#3102)', summary)

    def test_a_develop_behind_main_alone_still_gets_a_merge_commit(self) -> None:
        """No fast-forward: ``develop`` with no commit of its own records the merge too."""
        self.git('push', '-q', '--force', 'origin', f'{self.main}:refs/heads/develop')
        main = self.commit('main', 'fix2.txt', 'another patch fix\n')
        code, output, _, stdout = self.run_merge()
        self.assertEqual((code, output), (0, 'conflict=false\n'), stdout)
        merged = self.head('develop')
        self.assertEqual(self.parents(merged), [self.main, main], 'fast-forwarded rather than merged')
        self.assertEqual(self.origin_git('log', '-1', '--format=%s', merged), 'chore: merge main into develop')

    def test_a_develop_already_holding_main_is_left_alone(self) -> None:
        self.assertEqual(self.run_merge()[0], 0)
        merged = self.head('develop')
        code, output, summary, _ = self.run_merge()
        self.assertEqual((code, output), (0, 'conflict=false\n'))
        self.assertEqual((self.head('develop'), self.pushes), (merged, 1), 'pushed a level develop')
        self.assertIn(f'`develop` already holds `main` at `{self.main[:9]}`; nothing to merge.', summary)

    def test_a_conflict_is_aborted_and_left_to_the_pull_request(self) -> None:
        develop = self.commit('develop', 'shared.txt', "develop's edit\n")
        main = self.commit('main', 'shared.txt', "main's edit\n")
        code, output, summary, stdout = self.run_merge()
        self.assertEqual((code, output), (0, 'conflict=true\n'), stdout)
        self.assertEqual((self.head('develop'), self.pushes), (develop, 0))
        self.assertEqual(self.git('status', '--porcelain', cwd=self.work), '')
        self.assertFalse((self.work / '.git' / 'MERGE_HEAD').exists(), 'the merge is left in progress')
        self.assertIn('Merge conflict in shared.txt', stdout)
        self.assertIn(f'`main` at `{main[:9]}` conflicts with `develop` at `{develop[:9]}`, so the `pr` job opens '
                      f'or updates the pull request from `{MIRROR}` into `develop` (#3075).', summary)

    def test_a_push_refused_while_develop_moved_is_merged_afresh_once(self) -> None:
        moved = []  # type: list[str]

        def move(count: 'int') -> 'None':
            if count == 1:
                moved.append(self.commit('develop', 'later.txt', 'pushed meanwhile\n'))

        code, output, _, stdout = self.run_merge(move)
        self.assertEqual((code, output), (0, 'conflict=false\n'), stdout)
        self.assertEqual(self.pushes, 2)
        self.assertEqual(self.parents(self.head('develop')), [moved[0], self.main])
        self.assertIn(f'develop moved from {self.develop[:9]} while merging; merging afresh', stdout)

    def test_a_conflict_on_the_retry_is_left_to_the_pull_request(self) -> None:
        self.main = self.commit('main', 'shared.txt', "main's edit\n")
        moved = []  # type: list[str]

        def move(_: 'int') -> 'None':
            moved.append(self.commit('develop', 'shared.txt', "develop's edit, pushed meanwhile\n"))

        code, output, _, stdout = self.run_merge(move)
        self.assertEqual((code, output), (0, 'conflict=true\n'), stdout)
        self.assertEqual((self.pushes, self.head('develop')), (1, moved[0]))

    def test_a_push_refused_twice_fails_the_job(self) -> None:
        """The next push to ``main`` runs the merge again."""
        moved = []  # type: list[str]

        def move(count: 'int') -> 'None':
            moved.append(self.commit('develop', f'later{count}.txt', 'pushed meanwhile\n'))

        code, output, _, stdout = self.run_merge(move)
        self.assertEqual((code, output), (1, ''))
        self.assertEqual((self.pushes, self.head('develop')), (2, moved[-1]), 'retried more than once')
        self.assertIn('::error title=develop not pushed::git push failed (1)', stdout)
        self.assertIn('refused again after merging afresh, so the next push to main merges it', stdout)

    def test_a_push_refused_while_develop_stayed_put_is_not_retried(self) -> None:
        """A rule refusing the key, say, would refuse a retry too."""
        refusal = done(1, stderr='remote: error: GH013: Repository rule violations found for refs/heads/develop.')
        code, output, _, stdout = self.run_merge(lambda _: refusal)
        self.assertEqual((code, output), (1, ''))
        self.assertEqual((self.pushes, self.head('develop')), (1, self.develop))
        self.assertIn('GH013: Repository rule violations', stdout)
        self.assertIn('develop has not moved, so a retry would be refused too', stdout)

    def test_a_failed_fetch_fails_the_job(self) -> None:
        self.git('remote', 'set-url', 'origin', str(self.root / 'missing.git'), cwd=self.work)
        code, output, _, stdout = self.run_merge()
        self.assertEqual((code, output, self.pushes), (1, '', 0))
        self.assertIn('::error title=develop not pushed::git fetch failed (128)', stdout)


class FakeGh:
    """A stand-in for :func:`util.sync_develop.run`: the repository's state, each call recorded.

    ``mirror`` is the commit ``sync/main`` points at, :data:`None` where it does not
    exist; ``open_pr`` is the open pull request from it, ``legacy`` one from ``main``.
    """

    def __init__(self, develop: 'bool' = True, ahead: 'int' = 3, main: 'str' = SHA,
                 mirror: 'Optional[str]' = None, open_pr: 'Optional[int]' = None,
                 legacy: 'Optional[int]' = None, fail: 'str' = '') -> None:
        self.develop, self.ahead, self.main, self.mirror = develop, ahead, main, mirror
        self.open_pr, self.legacy, self.fail = open_pr, legacy, fail
        self.calls = []  # type: list[tuple[str, ...]]

    def __call__(self, *argv: 'str') -> 'subprocess.CompletedProcess[str]':
        self.calls.append(argv)
        self.assertion(argv[:2] == ('gh', 'api'), argv)
        path = next(arg for arg in argv[2:] if arg.startswith('repos/'))
        method = argv[argv.index('-X') + 1] if '-X' in argv else 'GET'
        if self.fail and self.fail in path:
            return done(1, stderr='gh: Server Error (HTTP 502)')
        if path == f'repos/{REPO}/branches/develop':
            return done(stdout='develop\n') if self.develop else done(1, stderr='gh: Branch not found (HTTP 404)')
        if path == f'repos/{REPO}/compare/develop...main':
            return done(stdout=f'{self.ahead}\n')
        if path == f'repos/{REPO}/git/ref/heads/main':
            return done(stdout=f'{self.main}\n')
        if path == f'repos/{REPO}/git/ref/heads/{MIRROR}':
            return done(stdout=f'{self.mirror}\n') if self.mirror else done(1, stderr='gh: Not Found (HTTP 404)')
        if (path, method) in ((f'repos/{REPO}/git/refs', 'POST'), (MIRROR_REF, 'PATCH')):
            self.mirror = self.field(argv, 'sha')
            return done(stdout=f'{self.mirror}\n')
        if path == f'repos/{REPO}/pulls?state=open&head=o:{MIRROR}&base=develop':
            return done(stdout=f'{self.open_pr}\n' if self.open_pr else '')
        if path == f'repos/{REPO}/pulls?state=open&head=o:main&base=develop':
            return done(stdout=f'{self.legacy}\n' if self.legacy else '')
        if path == f'repos/{REPO}/pulls' and method == 'POST':
            return done(stdout=json.dumps({'number': 42, 'html_url': f'https://github.com/{REPO}/pull/42'}))
        if path.startswith(f'repos/{REPO}/pulls/') and method == 'PATCH':
            return done(stdout=path.rsplit('/', 1)[1])
        if path.startswith(f'repos/{REPO}/issues/') and path.endswith('/comments') and method == 'POST':
            return done(stdout='1\n')
        raise AssertionError(f'unexpected call {argv}')

    @staticmethod
    def assertion(holds: 'bool', argv: 'tuple[str, ...]') -> None:
        if not holds:
            raise AssertionError(f'not a gh api call: {argv}')

    def writes(self, method: 'str', path: 'str' = '') -> 'list[tuple[str, ...]]':
        """The calls with ``method``, naming ``path`` exactly where it is given."""
        return [call for call in self.calls if '-X' in call and call[call.index('-X') + 1] == method
                and (not path or path in call)]

    def ref_writes(self) -> 'list[tuple[str, ...]]':
        return self.writes('POST', f'repos/{REPO}/git/refs') + self.writes('PATCH', MIRROR_REF)

    @staticmethod
    def field(call: 'tuple[str, ...]', name: 'str') -> 'str':
        values = [call[index + 1][len(name) + 1:] for index, arg in enumerate(call)
                  if arg in ('-f', '-F') and call[index + 1].startswith(f'{name}=')]
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
        """Not even the mirror moves."""
        code, output, _, _ = self.run_script('--check', ahead=0)
        self.assertEqual((code, output), (0, 'behind=false\n'))
        code, _, _, fake = self.run_script('--propose', ahead=0, mirror='b' * 40)
        self.assertEqual(code, 0)
        self.assertEqual((fake.writes('POST'), fake.writes('PATCH')), ([], []))
        self.assertEqual(fake.mirror, 'b' * 40)

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

    def test_the_mirror_is_created_at_mains_head_before_its_pull_request_opens(self) -> None:
        main = 'c' * 40
        code, _, stdout, fake = self.run_script('--propose', main=main)
        self.assertEqual(code, 0)
        [created] = fake.writes('POST', f'repos/{REPO}/git/refs')
        self.assertEqual((fake.field(created, 'ref'), fake.field(created, 'sha')), (f'refs/heads/{MIRROR}', main))
        self.assertEqual(fake.writes('PATCH', MIRROR_REF), [])
        [opened] = fake.writes('POST', f'repos/{REPO}/pulls')
        self.assertLess(fake.calls.index(created), fake.calls.index(opened))
        self.assertIn(f'`main` at `{main[:9]}`', fake.field(opened, 'body'))
        self.assertIn(f'{MIRROR} set to {main[:9]}', stdout)

    def test_a_mirror_anywhere_else_is_force_updated_to_mains_head(self) -> None:
        """Ahead of, behind or beside ``main``, as after "Update branch" merged ``develop`` into it."""
        code, _, _, fake = self.run_script('--propose', mirror='b' * 40, open_pr=41)
        self.assertEqual(code, 0)
        [moved] = fake.writes('PATCH', MIRROR_REF)
        self.assertEqual((fake.field(moved, 'sha'), fake.field(moved, 'force')), (SHA, 'true'))
        self.assertEqual(fake.writes('POST', f'repos/{REPO}/git/refs'), [])
        [edited] = fake.writes('PATCH', f'repos/{REPO}/pulls/41')
        self.assertLess(fake.calls.index(moved), fake.calls.index(edited))
        self.assertEqual(fake.mirror, SHA)

    def test_a_mirror_at_mains_head_is_left_alone(self) -> None:
        code, _, stdout, fake = self.run_script('--propose', mirror=SHA, open_pr=41)
        self.assertEqual(code, 0)
        self.assertEqual(fake.ref_writes(), [])
        self.assertIn(f'{MIRROR} is already at {SHA[:9]}', stdout)

    def test_a_failed_mirror_write_opens_no_pull_request(self) -> None:
        for state in ({}, {'mirror': 'b' * 40}, {'mirror': 'b' * 40, 'open_pr': 41}):
            with self.subTest(**state):
                code, _, stdout, fake = self.run_script('--propose', fail='git/refs', **state)
                self.assertEqual(code, 1)
                self.assertIn('::error title=No pull request::', stdout)
                self.assertEqual([call for call in fake.writes('POST') + fake.writes('PATCH')
                                  if any('/pulls' in arg or '/issues/' in arg for arg in call)], [])

    def test_an_unreadable_main_moves_nothing(self) -> None:
        for state in ({'fail': 'git/ref/heads/main'}, {'main': ''}, {'main': 'not-a-sha'}):
            with self.subTest(**state):
                code, _, stdout, fake = self.run_script('--propose', **state)
                self.assertEqual(code, 1)
                self.assertIn('::error title=No pull request::', stdout)
                self.assertEqual((fake.writes('POST'), fake.writes('PATCH')), ([], []))

    def test_one_pull_request_opens_from_the_mirror_into_develop(self) -> None:
        code, _, stdout, fake = self.run_script('--propose', '--run-url', 'https://run')
        self.assertEqual(code, 0)
        [created] = fake.writes('POST', f'repos/{REPO}/pulls')
        self.assertEqual(fake.writes('PATCH', f'repos/{REPO}/pulls/42'), [])
        self.assertEqual([fake.field(created, name) for name in ('title', 'head', 'base')],
                         ['chore: merge main into develop', MIRROR, 'develop'])
        body = fake.field(created, 'body')
        self.assertIn('this one **conflicts**: resolve it here, then **merge with a merge commit, not a squash**',
                      body)
        self.assertIn(f'"Update branch" only touches `{MIRROR}`, never `main`', body)
        self.assertIn('- [x] `chore`', body)
        self.assertIn(f'`main` at `{SHA[:9]}`', body)
        self.assertIn('lacks 3 of its commits', body)
        self.assertIn('(https://run)', body)
        self.assertIn('opened pull request #42', stdout)

    def test_an_open_pull_request_is_updated_and_never_duplicated(self) -> None:
        code, _, stdout, fake = self.run_script('--propose', open_pr=41, mirror=SHA)
        self.assertEqual(code, 0)
        self.assertEqual(fake.writes('POST'), [])
        [edited] = fake.writes('PATCH')
        self.assertIn(f'repos/{REPO}/pulls/41', edited)
        self.assertEqual(fake.field(edited, 'title'), 'chore: merge main into develop')
        self.assertIn('**merge with a merge commit, not a squash**', fake.field(edited, 'body'))
        self.assertIn('updated pull request #41', stdout)
        # The lookup names this repository's own mirror, so a fork's branch of that name is no match.
        listed = [arg for call in fake.calls for arg in call if arg.startswith(f'repos/{REPO}/pulls?')]
        self.assertIn(f'repos/{REPO}/pulls?state=open&head=o:{MIRROR}&base=develop', listed)

    def test_a_pull_request_from_main_itself_is_closed_naming_its_replacement(self) -> None:
        """A pull request's head cannot be changed, so the one from ``main`` is replaced."""
        for state, replacement in (({}, 42), ({'open_pr': 41}, 41)):
            with self.subTest(**state):
                code, _, stdout, fake = self.run_script('--propose', legacy=3075, **state)
                self.assertEqual(code, 0)
                [comment] = fake.writes('POST', f'repos/{REPO}/issues/3075/comments')
                self.assertIn(f'Replaced by #{replacement}, opened from `{MIRROR}`', fake.field(comment, 'body'))
                [closed] = fake.writes('PATCH', f'repos/{REPO}/pulls/3075')
                self.assertEqual(fake.field(closed, 'state'), 'closed')
                [proposed] = (fake.writes('POST', f'repos/{REPO}/pulls') +
                              fake.writes('PATCH', f'repos/{REPO}/pulls/{replacement}'))
                self.assertLess(fake.calls.index(proposed), fake.calls.index(comment))
                self.assertLess(fake.calls.index(comment), fake.calls.index(closed))
                self.assertIn(f'closed pull request #3075, replaced by #{replacement}', stdout)
        _, _, _, fake = self.run_script('--propose')
        self.assertEqual(fake.writes('POST', f'repos/{REPO}/issues/3075/comments'), [])

    def test_every_call_is_gh_api_none_merges_and_only_the_mirror_is_written(self) -> None:
        for state in ({}, {'open_pr': 41}, {'mirror': 'b' * 40, 'legacy': 3075}):
            with self.subTest(**state):
                _, _, _, fake = self.run_script('--propose', **state)
                for call in fake.calls:
                    self.assertEqual(call[:2], ('gh', 'api'))
                    self.assertFalse(any(arg.endswith('/merge') or '/merges' in arg for arg in call), call)
                    if any('/git/' in arg for arg in call) and '-X' in call:
                        self.assertIn(call, fake.ref_writes())
                for call in fake.writes('POST', f'repos/{REPO}/git/refs'):
                    self.assertEqual(fake.field(call, 'ref'), f'refs/heads/{MIRROR}')
                self.assertEqual(len(fake.ref_writes()), 1)


if __name__ == '__main__':
    unittest.main()
