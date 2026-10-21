# -*- coding: utf-8 -*-
"""Tests that Conda Update, Vendor Update and GitHub Pages act only under a verdict
for the commit they build (#1643).

Each chains off ``Unit Tests`` completing and checks out ``github.sha``, which
for a ``workflow_run`` is ``main``'s tip when the event is raised -- not the commit
the completed run verified. Conda Update 38325136710 was raised 2 s after the run
for 9083163f5 succeeded, ran on 2e941bbb7 (with later pull requests merged), and
pushed f4f94bcad at 00:03:38Z; 2e941bbb7's own run 38323130015 finished at
00:13:35Z.

Two layers, as in :mod:`tests.project.test_release_gates`:

* :class:`TestTheRuleOnRealRunShapes` runs :file:`util/verdict_covers_checkout.py`
  in throwaway repositories rebuilt from that merge wave, so ancestry, authorship
  and paths are git's answers rather than a model's;
* :class:`TestEachWorkflowGatesOnTheVerdict` evaluates each workflow's job
  conditions and concurrency group over the scenarios, with the evaluator
  :mod:`tests.project.test_release_gates` pins. Since #1967 the test gate and
  the ``verdict`` job are one copy, in :data:`HEAD`, which each workflow calls
  as its ``head`` job.

"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import scale_timeout
from tests.project.test_release_gates import (NULL, STATUS, _evaluate, declared_if, declared_needs,
                                              evaluate_condition, job_blocks, parse_condition)

if TYPE_CHECKING:
    from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'verdict_covers_checkout.py'
WORKFLOWS = ROOT / '.github' / 'workflows'

#: The reusable workflow holding the test gate and the ``verdict`` job (#1967).
HEAD = 'cron-head.yml'
#: ``{workflow file: the job the verdict gates}``, each of which calls :data:`HEAD`.
ACTING_JOBS = {
    'cron-conda.yml': 'conda-update',
    'cron-vendor.yml': 'vendor-update',
    'deploy-pages.yml': 'deploy-pages',
}


def _load_script():
    """:file:`util/verdict_covers_checkout.py` as a module; it has no import-time effects."""
    spec = importlib.util.spec_from_file_location('verdict_covers_checkout', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verdict_covers_checkout = _load_script()

#: The identities on the 2026-10-13 commits: a squash merge is authored by its PR's
#: author and committed by GitHub; pyup's weekly update the same way.
HUMAN = ('Jarry Shaw', 'jarryshaw@icloud.com')
GITHUB = ('GitHub', 'noreply@github.com')
PYUP = ('pyup.io bot', 'github-bot@pyup.io')
BOT = ('github-actions[bot]', verdict_covers_checkout.BOT_EMAIL)


class TestTheRuleOnRealRunShapes(unittest.TestCase):
    """The script against a repository shaped like ``main`` on 2026-10-13.

    Each commit carries the real one's identities and paths, keyed by its real
    abbreviated sha in :attr:`sha`, and the content is placeholder text. The root,
    ee324e1dc, also seeds every file the later commits touch.

    """

    def setUp(self) -> None:
        if shutil.which('git') is None:
            raise unittest.SkipTest('git not found on PATH')
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.repo = self.root / 'repo'

        # Isolated from the caller's git configuration, which may sign commits or
        # rewrite URLs of its own. No automatic maintenance either, whose detached
        # repack can outlive the test and race its cleanup: maintenance.auto is
        # what commit, merge and fetch consult, gc.auto what they fall back to
        # (actions/checkout sets it to 0 in every checkout), and autoDetach keeps
        # anything that still runs in the foreground. See
        # test_the_harness_git_runs_no_maintenance.
        home = self.root / 'home'
        home.mkdir()
        (home / '.gitconfig').write_text(
            '[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n'
            '[maintenance]\n\tauto = false\n\tautoDetach = false\n'
            '[gc]\n\tauto = 0\n\tautoDetach = false\n', encoding='utf-8')
        self.env = {
            'PATH': os.environ.get('PATH', ''),
            'HOME': str(home),
            'XDG_CONFIG_HOME': str(home / '.config'),
            'GIT_CONFIG_NOSYSTEM': '1',
            'LC_ALL': 'C',
        }
        self._git('init', str(self.repo), cwd=self.root)

        conda = ['conda/build', 'conda/requirements.txt']
        dpkt, scapy = 'pcapkit/toolkit/dpkt.py', 'pcapkit/toolkit/scapy.py'
        self.sha = {}  # type: dict[str, str]
        self.sha['ee324e1dc'] = self._commit(
            'Bumped build to 2',
            conda + ['docs/requirements.txt', 'pcapkit/protocols/protocol.py', dpkt, scapy], BOT, BOT)
        self.sha['01151b13f'] = self._commit('fix(protocols): bound a frame (#1620)',
                                             ['pcapkit/protocols/protocol.py'])
        self.sha['9083163f5'] = self._commit('fix(toolkit): dpkt reads SYN (#1621)', [dpkt])
        self.sha['bbcabf1dd'] = self._commit('fix(toolkit): dpkt hands IPv4 (#1622)', [dpkt])
        self.sha['e5f3af373'] = self._commit('fix(toolkit): dpkt and scapy (#1624)', [dpkt, scapy])
        self.sha['2e941bbb7'] = self._commit('Scheduled weekly dependency update (#1629)',
                                             ['docs/requirements.txt'], PYUP)
        self.sha['f4f94bcad'] = self._commit('Bumped build to 3', conda, BOT, BOT)

    def _git(self, *args: 'str', cwd: 'Optional[pathlib.Path]' = None,
             env: 'Optional[dict[str, str]]' = None) -> 'str':
        result = subprocess.run(['git', *args], cwd=cwd or self.repo, env=env or self.env,
                                capture_output=True, text=True, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, f'git {" ".join(args)}: {result.stderr}')
        return result.stdout.strip()

    def _commit(self, message: 'str', paths: 'list[str]', author: 'tuple[str, str]' = HUMAN,
                committer: 'tuple[str, str]' = GITHUB) -> 'str':
        """Commit a change to each of ``paths`` as ``author``/``committer``; the new sha."""
        for path in paths:
            file = self.repo / path
            file.parent.mkdir(parents=True, exist_ok=True)
            with file.open('a', encoding='utf-8') as stream:
                stream.write(f'{message}\n')
        self._git('add', '--', *paths)
        env = dict(self.env, GIT_AUTHOR_NAME=author[0], GIT_AUTHOR_EMAIL=author[1],
                   GIT_COMMITTER_NAME=committer[0], GIT_COMMITTER_EMAIL=committer[1])
        self._git('commit', '-q', '-m', message, env=env)
        return self._git('rev-parse', 'HEAD')

    def _run(self, verdict: 'str', head: 'str', repo: 'Optional[pathlib.Path]' = None,
             ) -> 'tuple[subprocess.CompletedProcess[str], Optional[str]]':
        """Check ``head`` out and run the script under ``verdict``: the result and ``verified``."""
        repo = repo or self.repo
        self._git('checkout', '-q', '--detach', head, cwd=repo)
        output = self.root / 'output'
        output.write_text('', encoding='utf-8')
        result = subprocess.run([sys.executable, str(SCRIPT)], cwd=repo,
                                env=dict(self.env, VERDICT_SHA=verdict, GITHUB_OUTPUT=str(output)),
                                capture_output=True, text=True, timeout=scale_timeout(60))
        written = re.findall(r'^verified=(.*)$', output.read_text(encoding='utf-8'), re.M)
        self.assertLessEqual(len(written), 1, written)
        return result, written[0] if written else None

    def assertVerdict(self, verdict: 'str', head: 'str', expected: 'str',
                      repo: 'Optional[pathlib.Path]' = None) -> 'str':
        """Assert the script answers ``expected`` and exits 0; its stdout."""
        result, verified = self._run(verdict, head, repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(verified, expected, result.stdout)
        return result.stdout

    def test_run_38325136710_a_verdict_under_three_human_commits_is_refused(self) -> None:
        """The issue: 9083163f5's verdict, 2e941bbb7 checked out."""
        stdout = self.assertVerdict(self.sha['9083163f5'], self.sha['2e941bbb7'], 'false')
        self.assertIn('::notice title=Skipped', stdout)
        self.assertIn(self.sha['bbcabf1dd'], stdout, 'the notice names the first unverified commit')

    def test_the_tips_own_completion_is_accepted(self) -> None:
        """2e941bbb7's own run, had nothing landed on it yet."""
        self.assertVerdict(self.sha['2e941bbb7'], self.sha['2e941bbb7'], 'true')

    def test_run_38326184463_a_conda_bump_on_the_verified_tip_is_accepted(self) -> None:
        """2e941bbb7's own run completing with f4f94bcad already on top."""
        self.assertVerdict(self.sha['2e941bbb7'], self.sha['f4f94bcad'], 'true')

    def test_several_bot_commits_to_conda_on_top_are_accepted(self) -> None:
        """A bump and then Create Release's reset, both bot-managed paths only."""
        reset = self._commit('Reset conda build number', ['conda/build'], BOT, BOT)
        self.assertVerdict(self.sha['2e941bbb7'], reset, 'true')

    def test_run_38326990571_the_bot_commits_own_completion_is_accepted(self) -> None:
        self.assertVerdict(self.sha['f4f94bcad'], self.sha['f4f94bcad'], 'true')

    def test_a_human_commit_on_top_is_refused(self) -> None:
        human = self._commit('fix(toolkit): another merge', ['pcapkit/toolkit/scapy.py'])
        self.assertVerdict(self.sha['f4f94bcad'], human, 'false')

    def test_a_human_commit_under_a_bot_commit_is_refused(self) -> None:
        """e5f3af373's verdict: pyup's 2e941bbb7 sits between it and the bump."""
        stdout = self.assertVerdict(self.sha['e5f3af373'], self.sha['f4f94bcad'], 'false')
        self.assertIn(PYUP[1], stdout)

    def test_a_human_commit_between_bot_commits_is_refused(self) -> None:
        self._commit('fix(toolkit): another merge', ['pcapkit/toolkit/scapy.py'])
        reset = self._commit('Reset conda build number', ['conda/build'], BOT, BOT)
        self.assertVerdict(self.sha['2e941bbb7'], reset, 'false')

    def test_a_vendor_bump_on_top_is_refused(self) -> None:
        """e58618bdf's paths: its own run failed 12 tests its parent's had passed."""
        bump = self._commit('Bumped version to 1.5.0b5', [
            'CITATION.cff', 'conda/build', 'pcapkit/__init__.py',
            'pcapkit/const/pcapng/record_type.py', 'pcapkit/const/pcapng/secrets_type.py',
        ], BOT, BOT)
        stdout = self.assertVerdict(self.sha['f4f94bcad'], bump, 'false')
        self.assertIn('touches CITATION.cff, pcapkit/__init__.py, pcapkit/const/pcapng/record_type.py, '
                      'pcapkit/const/pcapng/secrets_type.py, which', stdout)

    def test_a_bot_authored_commit_someone_else_committed_is_refused(self) -> None:
        """A cherry-pick of a bump, say: the bot did not push it."""
        picked = self._commit('Bumped build to 4', ['conda/build'], BOT, HUMAN)
        self.assertVerdict(self.sha['f4f94bcad'], picked, 'false')

    def test_a_merge_on_top_is_refused(self) -> None:
        base = self.sha['f4f94bcad']
        self._git('checkout', '-q', '-b', 'side', base)
        side = self._commit('Bumped build to 4', ['conda/build'], BOT, BOT)
        self._git('checkout', '-q', '--detach', base)
        bump = self._commit('Bumped build to 4', ['conda/requirements.txt'], BOT, BOT)
        env = dict(self.env, GIT_AUTHOR_NAME=BOT[0], GIT_AUTHOR_EMAIL=BOT[1],
                   GIT_COMMITTER_NAME=BOT[0], GIT_COMMITTER_EMAIL=BOT[1])
        self._git('merge', '-q', '--no-ff', '-m', 'Merge', side, env=env)
        merge = self._git('rev-parse', 'HEAD')
        self.assertNotEqual(merge, bump)
        self.assertVerdict(base, merge, 'false')

    def test_a_verdict_that_is_not_an_ancestor_is_refused(self) -> None:
        """A verdict for a commit no longer on ``main``: a sibling bump of
        f4f94bcad's, as 644b9c197 was. Only the ancestry check refuses it, since
        what lies between the two is a bot commit to bot-managed paths.

        """
        self._git('checkout', '-q', '--detach', self.sha['2e941bbb7'])
        sibling = self._commit('Bumped build to 3, again', ['conda/build', 'conda/requirements.txt'],
                               BOT, BOT)
        stdout = self.assertVerdict(sibling, self.sha['f4f94bcad'], 'false')
        self.assertIn('not an ancestor', stdout)

    def test_a_verdict_beyond_a_shallow_checkout_is_refused_not_failed(self) -> None:
        """What the ``fetch-depth`` bound means: too far back is not covered."""
        clone = self.root / 'clone'
        self._git('clone', '-q', '--depth', '2', '--branch', 'main', self.repo.as_uri(), str(clone),
                  cwd=self.root)
        self.assertEqual(self._git('rev-parse', 'HEAD', cwd=clone), self.sha['f4f94bcad'])
        stdout = self.assertVerdict(self.sha['9083163f5'], self.sha['f4f94bcad'], 'false', repo=clone)
        self.assertIn('not in the history', stdout)
        self.assertVerdict(self.sha['2e941bbb7'], self.sha['f4f94bcad'], 'true', repo=clone)

    def test_a_merge_deeper_than_the_checkout_is_refused_not_failed(self) -> None:
        """A merged side branch longer than the verdict job's ``fetch-depth: 20``
        puts the clone's boundary commit, parentless there, between the verdict and
        ``HEAD``. Two merges on ``main`` since 2026-08-15 brought in that many:
        e23817bdb 76 commits, 4a151c0ac 43.

        """
        base = self.sha['f4f94bcad']
        self._git('checkout', '-q', '-b', 'side', base)
        for index in range(30):
            self._commit(f'fix(toolkit): step {index}', ['pcapkit/toolkit/scapy.py'])
        self._git('checkout', '-q', 'main')
        env = dict(self.env, GIT_AUTHOR_NAME=HUMAN[0], GIT_AUTHOR_EMAIL=HUMAN[1],
                   GIT_COMMITTER_NAME=GITHUB[0], GIT_COMMITTER_EMAIL=GITHUB[1])
        self._git('merge', '-q', '--no-ff', '-m', 'Merge pull request #7 from side', 'side', env=env)
        merge = self._git('rev-parse', 'HEAD')

        clone = self.root / 'clone'
        self._git('clone', '-q', '--depth', '20', '--branch', 'main', self.repo.as_uri(), str(clone),
                  cwd=self.root)
        self.assertEqual(self._git('rev-parse', 'HEAD', cwd=clone), merge)
        boundary = (clone / '.git' / 'shallow').read_text(encoding='utf-8').split()
        self.assertEqual(len(boundary), 1, 'the clone is cut on the side branch only')
        self.assertEqual(self._git('show', '-s', '--format=%P', boundary[0], cwd=clone), '',
                         'the boundary commit shows no parents, the case under test')

        stdout = self.assertVerdict(base, merge, 'false', repo=clone)
        self.assertIn('::notice title=Skipped', stdout)

    def test_push_changes_form_answers_in_the_exit_status(self) -> None:
        """``--head`` and ``--exit-code``, as Conda Update's Push Changes runs it
        (#1632): ``VERDICT_SHA`` is the checkout, ``--head`` the tip it fetched,
        and the answer is the exit status, with nothing written for the step.

        """
        checkout = self.sha['f4f94bcad']
        human = self._commit('fix(toolkit): another merge', ['pcapkit/toolkit/scapy.py'])
        cases = ((checkout, 0, 'Unit Tests verified'),
                 (human, verdict_covers_checkout.NOT_COVERED, 'not by the bot'),
                 ('no-such-ref', 1, '::error title=No commit to compare::'))
        for head, status, text in cases:
            with self.subTest(head=head):
                self._git('checkout', '-q', '--detach', self.sha['2e941bbb7'])
                output = self.root / 'output'
                output.write_text('', encoding='utf-8')
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), '--head', head, '--exit-code'], cwd=self.repo,
                    env=dict(self.env, VERDICT_SHA=checkout, GITHUB_OUTPUT=str(output)),
                    capture_output=True, text=True, timeout=scale_timeout(60))
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertIn(text, result.stdout)
                self.assertEqual(output.read_text(encoding='utf-8'), '')

    def test_a_missing_verdict_fails_loudly_and_writes_nothing(self) -> None:
        """No sha is a broken payload, not a stale verdict."""
        for verdict in ('', 'main', self.sha['f4f94bcad'][:9]):
            with self.subTest(verdict=verdict):
                result, verified = self._run(verdict, self.sha['f4f94bcad'])
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('::error', result.stdout)
                self.assertIsNone(verified)

    def test_the_harness_git_runs_no_maintenance(self) -> None:
        """No git process outlives the command that started it.

        A commit, merge or fetch runs ``git maintenance run --auto``, detached by
        default, and since git 2.54 that repacks once ``objects/17`` holds two
        loose objects. :meth:`test_a_merge_on_top_is_refused` gets there at its
        second bump every run: setUp's ``protocol.py`` blob 17a8c7ab3 and the
        bump's root tree 17d5a5af3, both content-addressed. On git 2.55.0, the
        runner's, the repack can still be writing into ``.git`` when the temporary
        directory is removed: "OSError: [Errno 39] Directory not empty: 'objects'"
        in run 38349290407 (Python 3.10). Here a commit-graph write is due on
        every commit and runs in the foreground, so any maintenance at all leaves
        a file behind.

        """
        for key, value in (('maintenance.commit-graph.enabled', 'true'),
                           ('maintenance.commit-graph.auto', '-1'),
                           ('maintenance.autoDetach', 'false')):
            self._git('config', key, value)
        self._commit('fix(toolkit): another merge', ['pcapkit/toolkit/scapy.py'])
        written = sorted(path.name for path in (self.repo / '.git' / 'objects' / 'info').glob('*'))
        self.assertEqual(written, [], 'a commit ran maintenance in the test repository')


def head_result(unit_tests: 'str', verdict: 'str') -> 'str':
    """What the caller's ``needs.head.result`` is taken to be, from the two jobs of
    :data:`HEAD` (#1967).

    A failure in either is a failure, which is what the acting jobs' ``!=
    'failure'`` reads. How Actions reports a call whose jobs partly skipped is
    not pinned by any run here, so a skip-and-success call is modelled as
    ``success`` and an all-skipped one as ``skipped``; the acting jobs accept
    both, which ``test_a_skipped_head_cannot_cascade_into_the_acting_job``
    checks for the second.

    """
    results = (unit_tests, verdict)
    for result in ('failure', 'cancelled', 'success'):
        if result in results:
            return result
    return 'skipped'


def _context(event_name: 'str' = 'workflow_run', conclusion: 'str' = 'success',
             event: 'str' = 'push', head_branch: 'str' = 'main', head_sha: 'str' = 'f' * 40,
             unit_tests: 'str' = 'skipped', verdict: 'str' = 'success',
             verified: 'object' = 'true', cancelled: bool = False) -> 'dict[str, object]':
    """One run's ``github``/``needs`` context; the defaults are a verdict that covers its checkout.

    ``unit_tests`` and ``verdict`` are the results of :data:`HEAD`'s two jobs,
    which make the caller's ``head`` result through :func:`head_result`.
    ``verified=NULL`` is a ``verdict`` job that wrote no output, which is what a
    skipped or failed one leaves, and the call passes it on as it is.

    """
    outputs = {} if verified is NULL else {'verified': verified}
    github = {
        'event_name': event_name,
        'ref': 'refs/pull/7/merge' if event_name == 'pull_request' else 'refs/heads/main',
        'event': {},
    }  # type: dict[str, object]
    if event_name == 'workflow_run':
        github['event'] = {'workflow_run': {'conclusion': conclusion, 'event': event,
                                            'head_branch': head_branch, 'head_sha': head_sha}}
    return {
        'github': github,
        'needs': {'head': {'result': head_result(unit_tests, verdict), 'outputs': outputs}},
        STATUS: {'cancelled': cancelled},
    }


def _head_context(context: 'dict[str, object]') -> 'dict[str, object]':
    """``context`` as :data:`HEAD`'s own jobs see it: the caller's ``github``, no ``needs``."""
    return {**context, 'needs': {}}


#: ``[(row, context, whether the test gate's if: holds, whether verdict's does,
#: whether the acting job's does)]``, for every workflow above; :data:`None`
#: asserts nothing about that job. The first two are :data:`HEAD`'s jobs.
ROWS = [
    ('run 38325136710: the verdict is for an older commit',
     _context(verified='false'), False, True, False),
    ("run 38326990571: the verdict covers the checkout",
     _context(), False, True, True),
    ('verdict failed before writing its answer',
     _context(verdict='failure', verified=NULL), False, True, False),
    ('the Saturday schedule, the gate green',
     _context(event_name='schedule', unit_tests='success', verdict='skipped', verified=NULL),
     True, False, True),
    ('the Saturday schedule, the gate failed',
     _context(event_name='schedule', unit_tests='failure', verdict='skipped', verified=NULL),
     True, False, False),
    ("a pull request's Unit Tests completed",
     _context(event='pull_request', verdict='skipped', verified=NULL), False, False, False),
    ('Unit Tests failed on main',
     _context(conclusion='failure', verdict='skipped', verified=NULL), False, False, False),
    ('Unit Tests completed on a branch that is not main',
     _context(head_branch='dependabot/pip/scapy-2.6.2', verdict='skipped', verified=NULL),
     False, False, False),
    ('the run was cancelled',
     _context(cancelled=True), None, None, False),
]

#: GitHub Pages also builds, without deploying, for a pull request against ``main``.
PAGES_ROWS = [
    ('a pull request against main',
     _context(event_name='pull_request', verdict='skipped', verified=NULL), False, False, True),
]

_GROUP = re.compile(r'^concurrency:\n  group: (?P<prefix>[^$\n]*)\$\{\{(?P<body>[^}]*)\}\}\n', re.M)
#: The line each caller's ``head`` job calls :data:`HEAD` with.
_CALL = f'uses: ./.github/workflows/{HEAD}'


class TestEachWorkflowGatesOnTheVerdict(unittest.TestCase):
    """:data:`HEAD`'s jobs, and the job they gate, in each :data:`ACTING_JOBS` workflow."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.texts = {name: (WORKFLOWS / name).read_text(encoding='utf-8')
                     for name in (*ACTING_JOBS, HEAD)}
        cls.jobs = {name: job_blocks(text) for name, text in cls.texts.items()}

    def _jobs(self, workflow: 'str') -> 'dict[str, str]':
        jobs = self.jobs[workflow]
        if 'head' not in jobs or _CALL not in jobs['head']:
            self.fail(f'{workflow} has no `head` job calling {HEAD}, so it acts on whatever '
                      f'commit it checks out')
        return jobs

    def test_each_acting_job_needs_the_head(self) -> None:
        for workflow, job in ACTING_JOBS.items():
            with self.subTest(workflow=workflow):
                self.assertEqual(declared_needs(self._jobs(workflow)[job]), ['head'])

    def test_every_scenario_decides_correctly(self) -> None:
        """The table above, for :data:`HEAD`'s jobs and each acting job."""
        head = self.jobs[HEAD]
        violations = []  # type: list[str]
        for workflow, job in ACTING_JOBS.items():
            jobs = self._jobs(workflow)
            rows = ROWS + (PAGES_ROWS if workflow == 'deploy-pages.yml' else [])
            for name, context, gate_runs, verdict_runs, acting_runs in rows:
                for target, block, scope, expected in (
                        ('unit-tests', head.get('unit-tests'), _head_context(context), gate_runs),
                        ('verdict', head.get('verdict'), _head_context(context), verdict_runs),
                        (job, jobs.get(job), context, acting_runs)):
                    if expected is None:
                        continue
                    if block is None:
                        violations.append(f'{workflow}: {name}: no `{target}` job')
                        continue
                    if evaluate_condition(declared_if(block), scope) != expected:
                        violations.append(f'{workflow}: {name}: `{target}` should '
                                          f'{"run" if expected else "skip"}, it does not')
        if violations:
            self.fail(f'{len(violations)} scenario(s) decided wrongly:\n' + '\n'.join(violations))

    def test_a_skipped_head_cannot_cascade_into_the_acting_job(self) -> None:
        """A job of ``head`` skips on every path, so without a status-check
        function the implicit ``success()`` could skip the job behind it.

        """
        skipped = _context(event_name='schedule', unit_tests='skipped', verdict='skipped', verified=NULL)
        for workflow, job in ACTING_JOBS.items():
            with self.subTest(workflow=workflow):
                condition = declared_if(self._jobs(workflow)[job])
                self.assertTrue(condition.startswith('!cancelled() && '))
                self.assertTrue(evaluate_condition(condition, skipped))

    def test_the_three_call_one_head(self) -> None:
        """#1967: one copy of the gate and the verdict, called the same way from each.

        The ``head`` jobs differ in their ``name:`` alone, no acting workflow
        keeps a gate or a ``verdict`` of its own, and nothing else calls
        :data:`HEAD`.

        """
        blocks = {}  # type: dict[str, str]
        for workflow in ACTING_JOBS:
            jobs = self._jobs(workflow)
            with self.subTest(workflow=workflow):
                self.assertNotIn('verdict', jobs)
                self.assertNotIn('uses: ./.github/workflows/unit-tests.yml', self.texts[workflow])
                self.assertNotIn('run: python3 util/verdict_covers_checkout.py\n', self.texts[workflow])
                blocks[workflow] = re.sub(r'(?m)^    name: .*\n', '', jobs['head'] + '\n')
        self.assertEqual(len(set(blocks.values())), 1, blocks)
        callers = sorted(path.name for path in WORKFLOWS.glob('*.yml')
                         if _CALL in path.read_text(encoding='utf-8'))
        self.assertEqual(callers, sorted(ACTING_JOBS))

    def test_the_schedules_are_spread_with_vendor_before_conda(self) -> None:
        """#1967: one Saturday schedule each, at distinct hours, so no two heads
        gate at once; Conda Update after Vendor Update, so its GitHub upload
        finds the release Vendor Update's Create Release made (#1634).

        """
        hours = {}  # type: dict[str, int]
        for workflow in ACTING_JOBS:
            crons = re.findall(r"(?m)^    - cron: '(\d+) (\d+) \* \* (\d)'", self.texts[workflow])
            with self.subTest(workflow=workflow):
                self.assertEqual(len(crons), 1, crons)
                minute, hour, day = crons[0]
                self.assertEqual((minute, day), ('0', '6'))
                hours[workflow] = int(hour)
        self.assertEqual(len(set(hours.values())), len(hours), hours)
        self.assertLess(hours['cron-vendor.yml'], hours['cron-conda.yml'])

    def test_the_head_is_reusable_only_and_holds_what_its_callers_grant(self) -> None:
        """``workflow_call`` alone, ``verified`` passed out from ``verdict``, and
        ``contents: read`` everywhere: what each caller grants ``head``, and what
        ``unit-tests.yml`` is called with elsewhere.

        """
        text = self.texts[HEAD]
        triggers = re.search(r'(?ms)^on:\n(.*?)^\S', text)
        self.assertIsNotNone(triggers)
        self.assertEqual(re.findall(r'(?m)^  ([\w-]+):', triggers.group(1)),  # type: ignore[union-attr]
                         ['workflow_call'])
        self.assertIn('value: ${{ jobs.verdict.outputs.verified }}', text)
        self.assertIn('\npermissions:\n  contents: read\n', text)
        scopes = {line.strip() for line in text.splitlines()
                  if re.match(r'^ +(actions|attestations|checks|contents|deployments|discussions|'
                              r'id-token|issues|models|packages|pages|pull-requests|'
                              r'security-events|statuses): ', line)}
        self.assertEqual(scopes, {'contents: read'})
        self.assertIn('    permissions:\n      contents: read\n    uses: ./.github/workflows/unit-tests.yml\n'
                      '    with:\n      gate-only: true', self.jobs[HEAD]['unit-tests'])
        for workflow in ACTING_JOBS:
            with self.subTest(workflow=workflow):
                self.assertIn('    permissions:\n      contents: read\n', self._jobs(workflow)['head'])

    def test_the_verdict_job_reads_the_payload_as_data(self) -> None:
        """The sha arrives through ``env:``, and the script it runs exists."""
        block = self.jobs[HEAD]['verdict']
        self.assertIn('VERDICT_SHA: ${{ github.event.workflow_run.head_sha }}', block)
        command = re.search(r'(?m)^ +run: python3 (\S+)$', block)
        self.assertIsNotNone(command, block)
        self.assertEqual(ROOT / command.group(1), SCRIPT)  # type: ignore[union-attr]
        self.assertEqual(block.count('${{'), 2, 'the only expressions are the output and the env value')

    def test_the_verdict_job_checks_out_what_the_acting_job_builds(self) -> None:
        """Neither checkout names a ``ref:``, so both are the default ``github.sha``,
        which in a called workflow is the caller's.

        """
        for workflow, job in ACTING_JOBS.items():
            for target, block in (('verdict', self.jobs[HEAD]['verdict']),
                                  (job, self._jobs(workflow)[job])):
                with self.subTest(workflow=workflow, job=target):
                    self.assertIn('uses: actions/checkout@', block)
                    self.assertNotRegex(block, r'(?m)^ +ref:')

    def test_the_verdict_checkout_reaches_past_a_bot_commit(self) -> None:
        """At ``fetch-depth: 1`` only ``HEAD`` is fetched, so with a bot commit on
        top the verified commit is never found and the bot-commit allowance is dead:
        a fail-safe skip, but every tip with a bump on it waits for its own run.
        ``0`` fetches all history.

        """
        depths = re.findall(r'(?m)^ +fetch-depth: *(\S+)$', self.jobs[HEAD]['verdict'])
        self.assertEqual(len(depths), 1, 'one checkout, with an explicit fetch-depth')
        self.assertRegex(depths[0], r'^\d+$')
        depth = int(depths[0])
        self.assertTrue(depth == 0 or depth >= 2,
                        f'fetch-depth {depth} cannot hold the verdict under a bot commit')

    def test_a_stale_run_cannot_share_a_concurrency_group_with_a_fresh_one(self) -> None:
        """GitHub cancels a pending run when a newer one joins its group, so a run
        that will skip must not join the group of one that will not. Every other
        event keeps the group it had.

        """
        for workflow in ACTING_JOBS:
            with self.subTest(workflow=workflow):
                match = _GROUP.search(self.texts[workflow])
                self.assertIsNotNone(match, 'no workflow-level concurrency group')
                prefix, body = match.group('prefix'), match.group('body')  # type: ignore[union-attr]

                def group(context: 'dict[str, object]') -> 'str':
                    return prefix + str(_evaluate(parse_condition('${{' + body + '}}'), context))

                stale, fresh = _context(head_sha='9' * 40), _context(head_sha='2' * 40)
                self.assertNotEqual(group(stale), group(fresh),
                                    'a run for an older verdict joins the group of the run whose '
                                    'verdict matches, so it can cancel that run while it is pending')
                self.assertEqual(group(fresh), group(_context(head_sha='2' * 40, verified='false')))
                self.assertEqual(group(_context(event_name='schedule')), prefix + 'refs/heads/main')
                if workflow == 'deploy-pages.yml':
                    self.assertEqual(group(_context(event_name='pull_request')), prefix + 'refs/pull/7/merge')

    def test_the_scanner_agrees_with_yaml(self) -> None:
        """What :func:`job_blocks`/:func:`declared_if` read is what a YAML parse reads."""
        try:
            import yaml  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.skipTest('PyYAML is only installed with the test extra')
        targets = list(ACTING_JOBS.items()) + [(HEAD, 'unit-tests'), (HEAD, 'verdict')]
        for workflow, target in targets:
            parsed = yaml.safe_load(self.texts[workflow])['jobs']
            with self.subTest(workflow=workflow, job=target):
                self.assertIn(target, sorted(parsed))
                self.assertEqual(' '.join(parsed[target]['if'].split()),
                                 ' '.join(declared_if(self.jobs[workflow][target]).split()))
        for workflow in ACTING_JOBS:
            parsed = yaml.safe_load(self.texts[workflow])['jobs']['head']
            with self.subTest(workflow=workflow, job='head'):
                self.assertEqual(parsed['uses'], f'./.github/workflows/{HEAD}')
                self.assertEqual(parsed['permissions'], {'contents': 'read'})
                for key in ('if', 'with', 'secrets'):
                    self.assertNotIn(key, parsed)


if __name__ == '__main__':
    unittest.main()
