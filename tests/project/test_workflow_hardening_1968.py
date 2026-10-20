# -*- coding: utf-8 -*-
"""#1968: no third-party code after the deploy key, and permissions stated in every workflow.

* :class:`TestNoThirdPartyCodeAfterTheDeployKey`: ``webfactory/ssh-agent``
  exports the deploy key's agent socket to every later step of its job, so no
  later step may run an action from outside ``actions/``, ``github/`` or this
  repository. ``tj-actions/verify-changed-files`` did, in Vendor Update and Conda
  Update.
* :class:`TestTheChangedFilesStep` runs the ``Verify Changed files`` script that
  replaced it, in a throwaway repository, on paths a crawl could write.
* :class:`TestEveryWorkflowDeclaresPermissions`: a workflow without top-level
  ``permissions:`` hands the repository default to any job without its own.
  GitHub Pages builds a pull request's tree, so that build holds ``contents:
  read`` and the push to ``gh-pages`` is a job of its own.

Read with :func:`yaml.safe_load`, from the test extra.

"""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import scale_timeout
from tests.project.test_release_gates import STATUS, job_blocks, job_runs

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'

#: The action that loads the deploy key into an agent for the rest of the job.
DEPLOY_KEY_ACTION = 'webfactory/ssh-agent@'
#: Owners whose actions may run with the deploy key loaded: GitHub's own, and
#: ``./`` for an action in this repository.
FIRST_PARTY = ('actions/', 'github/', './')
#: The jobs that load the deploy key and then commit, which the step replaced
#: by #1968 ran in.
CHANGED_FILES_JOBS = (('cron-vendor.yml', 'vendor-update'), ('cron-conda.yml', 'conda-update'))
#: The step's id, which every reader of its outputs names.
STEP_ID = 'verify-changed-files'


def workflow(name: 'str') -> 'dict[Any, Any]':
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding='utf-8'))


def step(name: 'str', job: 'str') -> 'dict[str, Any]':
    found = [entry for entry in workflow(name)['jobs'][job]['steps'] if entry.get('id') == STEP_ID]
    if len(found) != 1:
        raise AssertionError(f'{name}: `{job}` has {len(found)} steps with id {STEP_ID!r}')
    return found[0]


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class TestNoThirdPartyCodeAfterTheDeployKey(unittest.TestCase):
    """Every step after ``webfactory/ssh-agent`` uses a first-party action, or none."""

    def test_no_job_runs_a_third_party_action_after_the_key(self) -> None:
        keyed = []  # type: list[tuple[str, str]]
        for path in sorted(WORKFLOWS.glob('*.yml')):
            for job_id, job in (workflow(path.name).get('jobs') or {}).items():
                steps = job.get('steps') or []
                loads = [index for index, entry in enumerate(steps)
                         if str(entry.get('uses', '')).startswith(DEPLOY_KEY_ACTION)]
                if not loads:
                    continue
                keyed.append((path.name, job_id))
                for entry in steps[loads[0] + 1:]:
                    uses = str(entry.get('uses', ''))
                    with self.subTest(workflow=path.name, job=job_id, step=entry.get('name') or uses):
                        self.assertTrue(not uses or uses.startswith(FIRST_PARTY),
                                        f'{uses} runs with the deploy key loaded')
        # Not vacuous: the jobs #1968 was about are among those that load the key.
        for where in CHANGED_FILES_JOBS:
            self.assertIn(where, keyed)

    def test_the_changed_files_step_is_a_script(self) -> None:
        """The same script in both jobs, so neither can drift from the other."""
        scripts = set()
        for name, job in CHANGED_FILES_JOBS:
            entry = step(name, job)
            with self.subTest(workflow=name):
                self.assertNotIn('uses', entry)
                self.assertEqual(entry['name'], 'Verify Changed files')
                scripts.add(entry['run'])
        self.assertEqual(len(scripts), 1)

    def test_the_list_reaches_a_script_only_through_env(self) -> None:
        """The list is file names; spliced into a ``run:`` it would be shell text."""
        output = f'steps.{STEP_ID}.outputs.changed_files'
        for name, job in CHANGED_FILES_JOBS:
            readers = 0
            for entry in workflow(name)['jobs'][job]['steps']:
                with self.subTest(workflow=name, step=entry.get('name')):
                    self.assertNotIn(output, str(entry.get('run', '')))
                    readers += output in str(entry.get('env', {}))
            with self.subTest(workflow=name):
                self.assertGreater(readers, 0, f'nothing in {name} reads {output}')


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class TestTheChangedFilesStep(unittest.TestCase):
    """``Verify Changed files``' script, in a throwaway repository, as ``bash -e`` runs it."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.repo = self.root / 'repo'
        home = self.root / 'home'
        home.mkdir()
        (home / '.gitconfig').write_text(
            '[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n'
            '[maintenance]\n\tauto = false\n\tautoDetach = false\n'
            '[gc]\n\tauto = 0\n\tautoDetach = false\n'
            '[user]\n\tname = Jarry Shaw\n\temail = jarryshaw@icloud.com\n', encoding='utf-8')
        self.env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(home),
                    'XDG_CONFIG_HOME': str(home / '.config'), 'GIT_CONFIG_NOSYSTEM': '1',
                    'LC_ALL': 'C'}
        self.git('init', '-q', str(self.repo), cwd=self.root)
        for path in ('pcapkit/const/a.py', 'pcapkit/const/b.py', 'conda/requirements.txt'):
            self.write(path, 'x = 1\n')
        self.write('.gitignore', 'build/\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')

    def git(self, *args: 'str', cwd: 'Optional[pathlib.Path]' = None) -> 'str':
        result = subprocess.run(['git', *args], cwd=cwd or self.repo, env=self.env,
                                capture_output=True, text=True, check=False, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def write(self, path: 'str', text: 'str') -> None:
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding='utf-8')

    def run_step(self) -> 'dict[str, str]':
        """The step's outputs, each ``GITHUB_OUTPUT`` line read as ``key=value``."""
        script = self.root / 'step.sh'
        script.write_text(step(*CHANGED_FILES_JOBS[0])['run'], encoding='utf-8')
        output = self.root / 'step.output'
        output.write_text('', encoding='utf-8')
        result = subprocess.run(['bash', '-e', str(script)], cwd=self.repo,
                                env=dict(self.env, GITHUB_OUTPUT=str(output)),
                                capture_output=True, text=True, check=False, timeout=scale_timeout(60))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = {}  # type: dict[str, str]
        for line in output.read_text(encoding='utf-8').splitlines():
            key, sep, value = line.partition('=')
            self.assertTrue(sep, f'{line!r} is not a `key=value` line')
            self.assertNotIn(key, outputs)
            outputs[key] = value
        return outputs

    def test_nothing_changed(self) -> None:
        self.write('build/out.txt', 'ignored\n')
        self.assertEqual(self.run_step(), {'files_changed': 'false'})

    def test_modified_untracked_and_deleted_files(self) -> None:
        self.write('pcapkit/const/a.py', 'x = 2\n')
        self.write('pcapkit/const/new/c.py', 'x = 3\n')
        (self.repo / 'pcapkit/const/b.py').unlink()
        self.write('build/out.txt', 'ignored\n')
        self.assertEqual(self.run_step(), {
            'files_changed': 'true',
            'changed_files': 'pcapkit/const/a.py pcapkit/const/b.py pcapkit/const/new/c.py',
        })

    def test_a_staged_change_counts(self) -> None:
        """``git commit -a`` carries it, so it is a change to commit."""
        self.write('conda/requirements.txt', 'y\n')
        self.git('add', 'conda/requirements.txt')
        self.assertEqual(self.run_step(), {'files_changed': 'true', 'changed_files': 'conda/requirements.txt'})

    def test_awkward_names_stay_one_line_and_never_run(self) -> None:
        """git C-quotes a space, a newline or a quote, so the output file stays
        ``key=value`` lines, and a name holding ``$(...)`` is data.

        """
        names = ('pcapkit/const/a b.py', 'pcapkit/const/n\nl.py', 'pcapkit/const/q"t.py',
                 'pcapkit/const/$(touch ran).py', 'pcapkit/const/`touch ran`.py')
        for name in names:
            self.write(name, 'x = 4\n')
        outputs = self.run_step()
        self.assertEqual(outputs['files_changed'], 'true')
        self.assertEqual(set(outputs), {'files_changed', 'changed_files'})
        for quoted in ('"pcapkit/const/$(touch ran).py"', '"pcapkit/const/`touch ran`.py"',
                       '"pcapkit/const/a b.py"', '"pcapkit/const/n\\nl.py"', '"pcapkit/const/q\\"t.py"'):
            self.assertIn(quoted, outputs['changed_files'])
        self.assertFalse((self.repo / 'ran').exists())
        self.assertFalse((self.repo / 'pcapkit/const/ran').exists())


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class TestEveryWorkflowDeclaresPermissions(unittest.TestCase):
    """A top-level ``permissions:`` in every workflow, and no write scope for a pull request's build."""

    def test_every_workflow_declares_them(self) -> None:
        paths = sorted(WORKFLOWS.glob('*.yml'))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(workflow=path.name):
                self.assertIn('permissions', workflow(path.name))

    def test_where_every_job_declares_its_own_the_default_is_nothing(self) -> None:
        """So the top-level block changes none of them."""
        for name in ('create-release.yml', 'codeql-analysis.yml'):
            spec = workflow(name)
            with self.subTest(workflow=name):
                self.assertEqual(spec['permissions'], {})
                for job_id, job in spec['jobs'].items():
                    with self.subTest(job=job_id):
                        self.assertIn('permissions', job)

    def test_a_pull_request_builds_the_docs_with_read_only_contents(self) -> None:
        spec = workflow('deploy-pages.yml')
        jobs = job_blocks((WORKFLOWS / 'deploy-pages.yml').read_text(encoding='utf-8'))
        self.assertEqual(spec['permissions'], {'contents': 'read'})
        build, publish = spec['jobs']['deploy-pages'], spec['jobs']['publish-pages']
        self.assertNotIn('permissions', build)
        self.assertEqual(publish['permissions'], {'actions': 'read', 'contents': 'write'})
        self.assertEqual(publish['needs'], ['deploy-pages'])

        # `(event, unit-tests, verdict, deploy-pages, whether publish-pages runs)`.
        # One of the first two always skips, and a skip anywhere in the chain
        # skips a job left with the implicit `success()` (#1632).
        rows = (
            ('workflow_run', 'skipped', 'success', 'success', True),
            ('schedule', 'success', 'skipped', 'success', True),
            ('pull_request', 'skipped', 'skipped', 'success', False),
            ('workflow_run', 'skipped', 'success', 'skipped', False),
            ('workflow_run', 'skipped', 'success', 'failure', False),
            ('schedule', 'success', 'skipped', 'cancelled', False),
        )
        for event, gate, verdict, built, expected in rows:
            context = {STATUS: {'cancelled': False}, 'github': {'event_name': event, 'event': {}}, 'needs': {
                'unit-tests': {'result': gate}, 'verdict': {'result': verdict},
                'deploy-pages': {'result': built},
            }}  # type: dict[str, object]
            with self.subTest(event=event, built=built):
                self.assertEqual(job_runs(jobs, 'publish-pages', context), expected)

        # Only the job that runs no project code holds the write token, and
        # only it pushes.
        for job_id, job in spec['jobs'].items():
            uses = [str(entry.get('uses', '')) for entry in job.get('steps') or []]
            with self.subTest(job=job_id):
                pushes = any(entry.startswith('JamesIves/github-pages-deploy-action@') for entry in uses)
                self.assertEqual(pushes, job_id == 'publish-pages')
                writes = 'write' in (job.get('permissions') or spec['permissions']).values()
                self.assertEqual(writes, job_id == 'publish-pages')
        self.assertFalse([entry for entry in publish['steps'] if 'pip install' in str(entry.get('run', ''))])

    def test_the_deploy_waits_on_the_freshness_check(self) -> None:
        steps = workflow('deploy-pages.yml')['jobs']['publish-pages']['steps']
        ids = [entry.get('id') for entry in steps]
        deploy = next(index for index, entry in enumerate(steps) if 'JamesIves' in str(entry.get('uses', '')))
        self.assertLess(ids.index('fresh'), deploy)
        self.assertEqual(steps[deploy]['if'], "steps.fresh.outputs.publish == 'true'")

    def test_the_built_site_reaches_the_publish_job_whole(self) -> None:
        """``.nojekyll`` is a hidden file, which upload-artifact drops by default."""
        build = workflow('deploy-pages.yml')['jobs']['deploy-pages']['steps']
        upload = [entry for entry in build if str(entry.get('uses', '')).startswith('actions/upload-artifact@')]
        self.assertEqual(len(upload), 1)
        self.assertEqual(upload[0]['if'], "${{ github.event_name != 'pull_request' }}")
        self.assertEqual(upload[0]['with']['path'], 'docs/build/html')
        self.assertIs(upload[0]['with']['include-hidden-files'], True)
        publish = workflow('deploy-pages.yml')['jobs']['publish-pages']['steps']
        download = next(entry for entry in publish if entry.get('name') == 'Download the built site')
        self.assertIn(f"--name {upload[0]['with']['name']}", download['run'])
        self.assertIn('--dir docs/build/html', download['run'])
        deploy = next(entry for entry in publish if 'JamesIves' in str(entry.get('uses', '')))
        self.assertEqual(deploy['with']['folder'], 'docs/build/html')


#: A ``gh`` that answers the two ``gh api`` calls the check makes from the
#: environment, and logs each call. ``$2`` is the endpoint.
GH_STUB = '''#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$2" in
  */commits/gh-pages) [ -z "$STUB_COMMITS_FAIL" ] || exit 1; printf '%s\\n' "$STUB_MESSAGE" ;;
  */compare/*) [ -z "$STUB_COMPARE_FAIL" ] || exit 1; printf '%s\\n' "$STUB_STATUS" ;;
  *) exit 2 ;;
esac
'''

#: This run's commit, and the one ``gh-pages`` last published.
OURS = '1' * 40
THEIRS = '2' * 40


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class TestPublishSkipsAnOlderBuild(unittest.TestCase):
    """``Check gh-pages holds no newer build``, run as ``bash -e`` runs it, ``gh`` stubbed.

    Builds finish in any order, so an older run's publish can reach ``gh-pages``
    after a newer one's; the check is what stops it replacing the newer docs.

    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        stub = self.root / 'bin' / 'gh'
        stub.parent.mkdir()
        stub.write_text(GH_STUB, encoding='utf-8')
        stub.chmod(0o755)
        self.steps = workflow('deploy-pages.yml')['jobs']['publish-pages']['steps']
        self.check = next(entry for entry in self.steps if entry.get('id') == 'fresh')
        deploy = next(entry for entry in self.steps if 'JamesIves' in str(entry.get('uses', '')))
        #: What the deploy writes as the ``gh-pages`` commit for ``THEIRS``.
        self.ours_message = deploy['with']['commit-message'].replace('${{ github.sha }}', THEIRS)

    def run_check(self, message: 'str', status: 'str' = '', **flags: 'str') -> 'tuple[dict[str, str], str, str]':
        """The check's outputs, its stdout, and the ``gh`` calls it made."""
        script = self.root / 'check.sh'
        script.write_text(self.check['run'], encoding='utf-8')
        output, log = self.root / 'check.output', self.root / 'gh.log'
        output.write_text('', encoding='utf-8')
        log.write_text('', encoding='utf-8')
        env = {'PATH': f'{self.root / "bin"}{os.pathsep}{os.environ.get("PATH", "")}', 'LC_ALL': 'C',
               'GITHUB_SHA': OURS, 'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit', 'GITHUB_OUTPUT': str(output),
               'STUB_LOG': str(log), 'STUB_MESSAGE': message, 'STUB_STATUS': status, **flags}
        result = subprocess.run(['bash', '-e', str(script)], cwd=self.root, env=env, capture_output=True,
                                text=True, check=False, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').splitlines())
        return outputs, result.stdout, log.read_text(encoding='utf-8')

    def test_a_newer_published_build_is_kept(self) -> None:
        outputs, stdout, calls = self.run_check(self.ours_message, 'behind')
        self.assertEqual(outputs, {'publish': 'false'})
        self.assertIn('::notice title=Newer documentation already published::', stdout)
        self.assertIn(f'compare/{THEIRS}...{OURS}', calls)

    def test_an_older_or_unrelated_published_build_is_replaced(self) -> None:
        for status in ('ahead', 'diverged', 'identical', ''):
            with self.subTest(status=status):
                self.assertEqual(self.run_check(self.ours_message, status)[0], {'publish': 'true'})

    def test_a_rerun_of_the_published_commit_publishes(self) -> None:
        message = self.ours_message.replace(THEIRS, OURS)
        outputs, _, calls = self.run_check(message, 'behind')
        self.assertEqual(outputs, {'publish': 'true'})
        self.assertNotIn('compare/', calls)

    def test_what_it_cannot_read_publishes_as_before(self) -> None:
        """A head this workflow did not write, or an API error: the old behaviour."""
        default = f'Deploying to gh-pages from @ JarryShaw/PyPCAPKit@{THEIRS} \U0001f680'
        self.assertEqual(self.run_check(default, 'behind')[0], {'publish': 'true'})
        self.assertEqual(self.run_check(self.ours_message, 'behind', STUB_COMMITS_FAIL='1')[0], {'publish': 'true'})
        self.assertEqual(self.run_check(self.ours_message, 'behind', STUB_COMPARE_FAIL='1')[0], {'publish': 'true'})


if __name__ == '__main__':
    unittest.main()
