# -*- coding: utf-8 -*-
"""#2030: the test workflows' runs posted to Discussions, through util/check_suite_report.py.

``unit-tests.yml`` is a reusable workflow whose callers grant ``contents: read``,
so a Unit Tests run on a push reaches its thread through
:file:`coverage-comment.yml`'s ``workflow_run`` relay, as a pull request's
coverage reaches its comment; Experimental Tests and Python Compatibility reach
theirs through :file:`ci-reports.yml`'s. Both relays run the same steps.

* :class:`TestTheJobs` pins the layout: ``comment`` keeps the pull-request path,
  its ``if:`` and its scopes; each ``discussion`` takes the events it posts and is
  the one job holding ``discussions: write``; a relayed run's concurrency group
  is its own; the checkout is the default branch's scripts, never the run's head;
  and the two relays' steps are one.
* :class:`TestTheScriptsWorkflows` holds the script's :data:`WORKFLOWS` to the
  workflow files: their names, file stems, by-design lists and gated legs.
* :class:`TestTheJobSummaries` pins how each job keeps a copy of its summary and
  uploads it, since the API serves none.
* :class:`TestTheReport` runs ``Write the run report`` with a stand-in ``gh``:
  the status each run gets, the owner's push rule, pip's retries, a run that
  tested nothing, and the job summaries folded in; :class:`TestTheDownload` and
  :class:`TestTheFit` pin how the summaries are read and shared out, and
  :class:`TestTheHelperCopies` how util/_actions.py copies a summary.
* :class:`TestThePostStep` runs ``Post the report to Discussions`` with a
  stand-in ``python3``, and :class:`TestEndToEnd` runs both steps and the real
  scripts against the stand-in GitHub of
  :mod:`tests.project.test_discussion_report_2030`.

"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
import unittest.mock
from typing import TYPE_CHECKING

from tests._workflows import WORKFLOWS, load, pinned
from tests.project.test_discussion_report_2030 import (CATEGORY, MARKER,
                                                       _FakeGitHub)
from tests.project.test_ktlo_legs_stay_green_1672 import interpolate
from tests.project.test_python_matrix_tiers_1633 import legs
from tests.project.test_release_gates import evaluate_condition, job_blocks, job_runs
from util import _actions, check_suite_report, discussion_report

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = ('_actions.py', 'check_suite_report.py', 'discussion_report.py')
BASH = shutil.which('bash')
NAME = 'coverage-comment.yml'
RELAY = 'ci-reports.yml'
#: The workflow each relay reports, by its file.
REPORTED = {NAME: ('unit-tests.yml',), RELAY: ('experimental.yml', 'python-compatibility.yml')}

TITLE = 'unit-tests: main push runs'
REPORT = 'report/run-report.md'
RUN_URL = 'https://github.com/JarryShaw/PyPCAPKit/actions/runs/39718608950'
RUN_ID = '39718608950'
SHA = 'da8596414e3e6a53f43b20b85c86755cc2ed6686'
SUITE = 'CS_kwDOBotKYc8AAAAZD_cS-g'
POSTER = {'actions': 'read', 'checks': 'read', 'contents': 'read', 'discussions': 'write'}
#: The pull-request comment's condition and scopes, as before #2030.
COMMENT_IF = ("${{ github.event.workflow_run.event == 'pull_request' && "
              "github.event.workflow_run.conclusion != 'cancelled' }}")
COMMENT_SCOPES = {'actions': 'read', 'pull-requests': 'write'}
#: GitHub's run conclusions, and the ``--status`` each posts as.
CONCLUSIONS = {
    'success': 'success', 'failure': 'failure', 'cancelled': 'cancelled', 'skipped': 'skipped',
    'timed_out': 'failure', 'startup_failure': 'failure', 'action_required': 'failure',
    'neutral': 'skipped', 'stale': 'cancelled', '': 'failure',
}
RUN = 'python3 util/discussion_report.py'
WRITE = 'python3 util/check_suite_report.py --report report/run-report.md'
#: The ``needs`` a job's name reads: ``gate``'s, the latest version.
NEEDS = {'python-versions': {'outputs': {'latest': '3.15'}}}
#: The step outputs ``Write the run report`` hands on.
OUTPUTS = ('post', 'title', 'mode', 'status')
#: The job summary's copy, and the two steps that end each job that writes one.
COPY = '${{ runner.temp }}/job-summary.md'
SAVE, UPLOAD = 'Name the job summary', 'Upload the job summary'
#: Each job that writes its summary, as ``(workflow, job)``: the KTLO summaries,
#: the coverage table, the engine cells' table and the experimental summaries.
SUMMARISED = (
    ('unit-tests.yml', 'test'), ('unit-tests.yml', 'test-ktlo'), ('unit-tests.yml', 'integration'),
    ('unit-tests.yml', 'integration-ktlo'), ('unit-tests.yml', 'engine-tests'),
    ('unit-tests.yml', 'pypcap-parity'), ('unit-tests.yml', 'pypcap-parity-ktlo'),
    ('experimental.yml', 'experimental'), ('python-compatibility.yml', 'compatibility'),
)
#: The steps that copy the summary through util/_actions.py's JOB_SUMMARY_COPY.
COPYING = ('Report coverage', 'KTLO summary', 'Experimental summary')
#: The shell's copy of a summary line.
TEE = '| tee -a "$RUNNER_TEMP/job-summary.md" >> "$GITHUB_STEP_SUMMARY"'


def discussion(name: 'str' = NAME) -> 'dict[str, Any]':
    return load(name)['jobs']['discussion']


def named(name: 'str', workflow: 'str' = NAME) -> 'dict[str, Any]':
    [step] = [entry for entry in discussion(workflow)['steps'] if entry.get('name') == name]
    return step


def note(level: 'str', title: 'str', message: 'str' = 'Process completed with exit code 1.') -> 'dict[str, str]':
    return {'annotationLevel': level, 'title': title, 'message': message}


def check_runs(*runs: 'tuple[str, str, list[tuple[str, ...]]]', more: 'bool' = False) -> 'dict[str, Any]':
    """The check-suite answer: ``(name, conclusion, [(level, title[, message])])`` per job."""
    return {'data': {'node': {'checkRuns': {'pageInfo': {'hasNextPage': more}, 'nodes': [
        {'name': name, 'conclusion': conclusion, 'annotations': {'nodes': [note(*entry) for entry in notes]}}
        for name, conclusion, notes in runs]}}}}


def nodes(*runs: 'tuple[str, str, list[tuple[str, ...]]]') -> 'list[dict[str, Any]]':
    return check_runs(*runs)['data']['node']['checkRuns']['nodes']


#: A job with the runner's notice alone.
GREEN = ('Python 3.14', 'SUCCESS', [('NOTICE', 'The ubuntu-latest label will migrate')])
#: A KTLO leg whose tests failed, which ``KTLO summary`` reports as a warning (#1672).
KTLO = ('Python 3.8 (KTLO)', 'SUCCESS', [('WARNING', 'tests failed on Python 3.8 (KTLO, non-blocking)'),
                                         ('FAILURE', '')])
#: A blocking job that passed with a warning, as a problem matcher writes one.
BLOCKING = ('Python 3.13', 'SUCCESS', [('WARNING', '', 'DeprecationWarning: something old')])
#: pip retrying a request, as Unit Tests run 39846357077's ``Project tests`` showed it.
RETRY = ('WARNING', '', "WARNING: Retrying (Retry(total=4, connect=None, read=None, redirect=None, status=None)) "
                        "after connection broken by 'ReadTimeoutError(\"HTTPSConnectionPool(host='pypi.org', "
                        "port=443): Read timed out. (read timeout=15)\")': /simple/scapy/")
#: An engine's KTLO cell that failed, in a blocking job (#1672).
ENGINE_KTLO = ('Engines (Scapy)', 'SUCCESS', [('WARNING', 'Scapy failed on Python 3.9 (KTLO, non-blocking)'),
                                              ('FAILURE', '')])
#: The list as it stood for pypy3.10's install failure, before #2040, which the
#: tests of the matching itself pass in place of a workflow's empty one.
LISTED = {'Python pypy3.10 (KTLO)': (('WARNING', 'install failed on Python pypy3.10 (KTLO, non-blocking)'),
                                     ('FAILURE', ''),
                                     ('WARNING', 'pcapkit did not install on Python pypy3.10 (KTLO, non-blocking)'))}
#: Unit Tests run 39718608950's pypy3.10 job, as the check-suite query returned it on 2026-10-22.
REAL_KTLO = "KTLO legs never block (#1633), so this job still succeeds (#1672); see the install step's log."
PYPY = ('Python pypy3.10 (KTLO)', 'SUCCESS', [
    ('WARNING', 'install failed on Python pypy3.10 (KTLO, non-blocking)', REAL_KTLO),
    ('FAILURE', '', 'Process completed with exit code 1.'),
    ('WARNING', 'pcapkit did not install on Python pypy3.10 (KTLO, non-blocking)',
     "pip failed without an ERROR line; see this step's log. The rest of this leg is skipped."),
    ('NOTICE', '', 'The ubuntu-latest label will migrate to Ubuntu 26')])

#: A stand-in ``gh``: ``api graphql -f ...``, the check-suite query, answers
#: ``$FAKE_SUITE_ANSWER``; ``run download`` copies ``$FAKE_ARTIFACTS``' folders,
#: or, given ``say:TEXT``, fails printing ``TEXT``;
#: both log their arguments to ``$FAKE_SUITE_LOG``. ``api graphql --input -``, the
#: posting script's own calls, goes to the stand-in GitHub beside it.
FAKE_GH = textwrap.dedent('''\
    import json, os, runpy, shutil, sys
    if '--input' in sys.argv:
        runpy.run_path(os.path.join(os.path.dirname(__file__), 'discussions.py'), run_name='__main__')
        sys.exit(0)
    with open(os.environ['FAKE_SUITE_LOG'], 'a', encoding='utf-8') as file:
        file.write(json.dumps(sys.argv[1:]) + '\\n')
    if sys.argv[1:3] == ['run', 'download']:
        source = os.environ.get('FAKE_ARTIFACTS')
        if source == 'fail':
            print('HTTP 403: Resource not accessible by integration', file=sys.stderr)
            sys.exit(1)
        if source.startswith('say:'):
            print(source[4:], file=sys.stderr)
            sys.exit(1)
        if not source or not os.listdir(source):
            print('no valid artifacts found to download', file=sys.stderr)
            sys.exit(1)
        target = sys.argv[sys.argv.index('--dir') + 1]
        for name in os.listdir(source):
            shutil.copytree(os.path.join(source, name), os.path.join(target, name))
        sys.exit(0)
    answer = os.environ.get('FAKE_SUITE_ANSWER')
    if not answer:
        print('gh: HTTP 403', file=sys.stderr)
        sys.exit(1)
    with open(answer, encoding='utf-8') as file:
        sys.stdout.write(file.read())
''')


def write_launcher(directory: 'pathlib.Path', name: 'str', script: 'str') -> None:
    """``directory/name``, running ``script`` (beside it) on this interpreter."""
    (directory / f'{name}.py').write_text(script, encoding='utf-8')
    launcher = directory / name
    launcher.write_text(f'#!/bin/sh\nexec \'{sys.executable}\' "$(dirname "$0")/{name}.py" "$@"\n',
                        encoding='utf-8')
    launcher.chmod(0o755)


def run_step(name: 'str', cwd: 'pathlib.Path', env: 'dict[str, str]',
             workflow: 'str' = NAME) -> 'subprocess.CompletedProcess[str]':
    """Step ``name``'s ``run:`` as a bash step runs it."""
    script = cwd.parent / 'step.sh'
    script.write_text(named(name, workflow)['run'], encoding='utf-8')
    return subprocess.run([str(BASH), '--noprofile', '--norc', '-eo', 'pipefail', str(script)],  # nosec: B603
                          cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=120)


def checkout(work: 'pathlib.Path') -> None:
    """The scripts the job's sparse checkout holds, in ``work/util``."""
    (work / 'util').mkdir(parents=True)
    for script in SCRIPTS:
        shutil.copy(ROOT / 'util' / script, work / 'util')


class TestTheJobs(unittest.TestCase):
    """The relays' jobs, and what each may do."""

    def test_the_pull_request_comment_is_as_it_was(self) -> None:
        spec = load(NAME)
        self.assertEqual(sorted(spec['jobs']), ['comment', 'discussion'])
        comment = spec['jobs']['comment']
        self.assertEqual(comment['if'], COMMENT_IF)
        self.assertEqual(comment['permissions'], COMMENT_SCOPES)
        self.assertEqual(spec['permissions'], {})
        self.assertNotIn('discussion_report', json.dumps(comment))

    def test_each_job_takes_its_own_events(self) -> None:
        """``comment`` a pull request's run not cancelled; ``discussion`` a push, and in the relay a schedule too."""
        jobs = job_blocks((WORKFLOWS / NAME).read_text(encoding='utf-8'))
        relay = job_blocks((WORKFLOWS / RELAY).read_text(encoding='utf-8'))
        self.assertEqual(sorted(relay), ['discussion'])
        for event in ('push', 'pull_request', 'merge_group', 'schedule', 'workflow_dispatch'):
            for conclusion in CONCLUSIONS:
                context = {'github': {'event': {'workflow_run': {'event': event, 'conclusion': conclusion}}}}
                with self.subTest(event=event, conclusion=conclusion):
                    self.assertEqual(job_runs(jobs, 'discussion', context), event == 'push')
                    self.assertEqual(job_runs(jobs, 'comment', context),
                                     event == 'pull_request' and conclusion != 'cancelled')
                    self.assertEqual(job_runs(relay, 'discussion', context), event in ('push', 'schedule'))

    def test_the_relay_waits_on_the_workflows_it_reports(self) -> None:
        for relay, files in REPORTED.items():
            spec = load(relay)
            with self.subTest(relay=relay):
                self.assertEqual(spec['on'], {'workflow_run': {
                    'workflows': [load(name)['name'] for name in files], 'types': ['completed']}})
                self.assertEqual(spec['permissions'], {})
                self.assertEqual(spec['env'], {'REPORT_CATEGORY': CATEGORY})

    def test_the_reported_workflows_gain_no_write_scope(self) -> None:
        """Posting is the relays'; ``unit-tests.yml`` stays callable with ``contents: read``."""
        for name in (name for files in REPORTED.values() for name in files):
            spec = load(name)
            with self.subTest(workflow=name):
                self.assertEqual(spec['permissions'], {'contents': 'read'})
                for job_id, job in spec['jobs'].items():
                    scopes = job.get('permissions') or {}
                    self.assertNotIn('write', json.dumps(scopes), job_id)

    def test_only_the_posting_job_may_write_discussions(self) -> None:
        for relay in REPORTED:
            self.assertEqual(discussion(relay)['permissions'], POSTER)
        for path in sorted(WORKFLOWS.glob('*.yml')):
            spec = load(path.name)
            with self.subTest(workflow=path.name):
                self.assertNotIn('discussions', str(spec.get('permissions')))
                for job_id, job in spec['jobs'].items():
                    if 'discussions' in str(job.get('permissions')):
                        self.assertEqual(job_id, 'discussion')
                        self.assertIn(RUN, json.dumps(job))

    def test_a_relayed_runs_group_is_its_own(self) -> None:
        """A pull request's group is the one it was; a pending relay is never cancelled by the next."""
        group = ' '.join(load(NAME)['concurrency']['group'].split())
        run = 'github.event.workflow_run'
        self.assertEqual(group, (
            f"coverage-comment-${{{{ {run}.event == 'pull_request' && "
            f"format('{{0}}-{{1}}', {run}.head_repository.full_name, {run}.head_branch) || {run}.id }}}}"))
        self.assertEqual(load(RELAY)['concurrency'], {'group': f'ci-reports-${{{{ {run}.id }}}}',
                                                      'cancel-in-progress': False})
        self.assertIs(load(NAME)['concurrency']['cancel-in-progress'], False)

    def test_the_relays_run_one_set_of_steps(self) -> None:
        mine = {key: value for key, value in discussion(NAME).items() if key not in ('if', 'name')}
        theirs = {key: value for key, value in discussion(RELAY).items() if key not in ('if', 'name')}
        self.assertEqual(mine, theirs)

    def test_it_writes_with_one_script_and_posts_with_the_other(self) -> None:
        job = discussion()
        self.assertIs(job['continue-on-error'], True)
        for name in ('Write the run report', 'Post the report to Discussions'):
            with self.subTest(step=name):
                self.assertIs(named(name)['continue-on-error'], True)
        write = named('Write the run report')
        self.assertEqual(write['id'], 'report')
        self.assertEqual(write['run'], WRITE)
        run = 'github.event.workflow_run'
        self.assertEqual(write['env'], {
            'GH_TOKEN': '${{ github.token }}', 'WORKFLOW': f'${{{{ {run}.name }}}}',
            'SUITE': f'${{{{ {run}.check_suite_node_id }}}}', 'RUN_ID': f'${{{{ {run}.id }}}}',
            'RUN_URL': f'${{{{ {run}.html_url }}}}', 'RUN_EVENT': f'${{{{ {run}.event }}}}',
            'RUN_CONCLUSION': f'${{{{ {run}.conclusion }}}}', 'HEAD_SHA': f'${{{{ {run}.head_sha }}}}',
            'HEAD_BRANCH': f'${{{{ {run}.head_branch }}}}'})
        post = named('Post the report to Discussions')
        self.assertEqual(post['if'], "${{ steps.report.outputs.post == 'true' }}")
        command = ' '.join(post['run'].replace('\\\n', ' ').split())
        self.assertEqual(command, (
            f'GITHUB_WORKFLOW="$WORKFLOW" {RUN} --category "$REPORT_CATEGORY" --title "$TITLE" '
            f'--report {REPORT} --mode "$MODE" --status "$STATUS" --run-url "$RUN_URL" --sha "$HEAD_SHA"'))
        self.assertEqual(post['env'], {
            'GH_TOKEN': '${{ github.token }}', 'WORKFLOW': f'${{{{ {run}.name }}}}',
            'TITLE': '${{ steps.report.outputs.title }}', 'MODE': '${{ steps.report.outputs.mode }}',
            'STATUS': '${{ steps.report.outputs.status }}', 'RUN_URL': f'${{{{ {run}.html_url }}}}',
            'HEAD_SHA': f'${{{{ {run}.head_sha }}}}'})

    def test_the_post_step_runs_only_on_a_report_to_post(self) -> None:
        condition = named('Post the report to Discussions')['if']
        for value, runs in (('true', True), ('false', False), ('', False)):
            context = {'steps': {'report': {'outputs': {'post': value}}}}
            with self.subTest(post=value):
                self.assertIs(evaluate_condition(condition, context), runs)

    def test_it_never_checks_out_the_runs_head(self) -> None:
        """The default branch's scripts alone, as ``workflow_run`` checks out; the head is data in ``env:``."""
        uses = [entry for entry in discussion()['steps'] if 'uses' in entry]
        self.assertEqual(len(uses), 1)
        self.assertTrue(pinned(uses[0]['uses'], 'actions/checkout'), uses[0]['uses'])
        self.assertEqual(uses[0]['with'], {
            'sparse-checkout': ''.join(f'util/{script}\n' for script in SCRIPTS),
            'sparse-checkout-cone-mode': False, 'persist-credentials': False})
        for entry in discussion()['steps']:
            outside = {key: value for key, value in entry.items() if key != 'env'}
            with self.subTest(step=entry.get('name') or entry['uses']):
                self.assertNotIn('workflow_run.head', json.dumps(outside))
                self.assertNotIn('${{', entry.get('run', ''))


class TestTheScriptsWorkflows(unittest.TestCase):
    """:data:`check_suite_report.WORKFLOWS` against the workflow files."""

    def test_it_reports_the_relayed_workflows(self) -> None:
        files = [name for names in REPORTED.values() for name in names]
        self.assertEqual(sorted(check_suite_report.WORKFLOWS), sorted(load(name)['name'] for name in files))
        for name in files:
            with self.subTest(workflow=name):
                self.assertEqual(check_suite_report.WORKFLOWS[load(name)['name']].stem, name[:-len('.yml')])

    def test_no_annotation_is_by_design(self) -> None:
        """The owner's rulings: each list is empty (#2051, #2040 for Unit Tests; #2030 for the others)."""
        for name, workflow in check_suite_report.WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertEqual(workflow.expected, {})

    def test_the_legs_are_the_gated_jobs(self) -> None:
        """``legs`` names each job ``current`` or ``changes.code`` can skip, and no other; Compat's matrix alone."""
        gates = ("needs.current.outputs.current != 'false'", "needs.changes.outputs.code != 'false'")
        for name in (name for names in REPORTED.values() for name in names):
            pattern = check_suite_report.WORKFLOWS[load(name)['name']].legs
            for job_id, job in load(name)['jobs'].items():
                gated = any(gate in str(job.get('if', '')) for gate in gates) or job_id == 'compatibility'
                gated = gated and job_id not in ('python-versions', 'changes')
                for leg in (legs(name, job_id) if 'strategy' in job else [{}]):
                    title = interpolate(str(job.get('name', job_id)), {'matrix': leg, 'needs': NEEDS})
                    with self.subTest(workflow=name, job=job_id, name=title):
                        self.assertIs(bool(pattern.match(title)), gated)


class TestTheJobSummaries(unittest.TestCase):
    """Each job that writes its summary keeps a copy, names it, and uploads both (#2030)."""

    def test_each_summary_step_copies_its_lines(self) -> None:
        found = set()
        for name, job_id in SUMMARISED:
            for step in load(name)['jobs'][job_id]['steps']:
                text = step.get('run', '')
                with self.subTest(workflow=name, job=job_id, step=step.get('name')):
                    if step.get('name') in COPYING:
                        found.add(step['name'])
                        self.assertEqual(step['env']['JOB_SUMMARY_COPY'], COPY)
                    else:
                        self.assertNotIn('JOB_SUMMARY_COPY', step.get('env') or {})
                    self.assertEqual(text.count('"$GITHUB_STEP_SUMMARY"'), text.count(TEE))
        self.assertEqual(found, set(COPYING))

    def test_no_test_step_carries_the_copy(self) -> None:
        """A test writing the summary through util/_actions.py would write the job's copy."""
        for path in sorted(WORKFLOWS.glob('*.yml')):
            spec = load(path.name)
            self.assertNotIn('JOB_SUMMARY_COPY', json.dumps(spec.get('env') or {}))
            for job_id, job in spec['jobs'].items():
                with self.subTest(workflow=path.name, job=job_id):
                    self.assertNotIn('JOB_SUMMARY_COPY', json.dumps(job.get('env') or {}))
                    for step in job.get('steps', []):
                        if 'JOB_SUMMARY_COPY' in (step.get('env') or {}):
                            self.assertIn(step['name'], COPYING)
                            self.assertNotIn('pytest', step['run'])

    def test_every_writer_is_listed(self) -> None:
        """No other job of the reported workflows writes a summary, so none is left out."""
        writers = re.compile(r'GITHUB_STEP_SUMMARY|util/(?:leg_summary|coverage_report)\.py')
        for name in (name for names in REPORTED.values() for name in names):
            for job_id, job in load(name)['jobs'].items():
                if (name, job_id) in SUMMARISED or job_id == 'current':
                    continue
                with self.subTest(workflow=name, job=job_id):
                    self.assertIsNone(writers.search(json.dumps(job.get('steps', []))))

    def test_each_job_names_and_uploads_it(self) -> None:
        for name, job_id in SUMMARISED:
            job = load(name)['jobs'][job_id]
            save, upload = job['steps'][-2:]
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual((save['name'], upload['name']), (SAVE, UPLOAD))
                self.assertEqual(save['run'], 'if [ -s "$RUNNER_TEMP/job-summary.md" ]; then printf \'%s\\n\' '
                                              '"$JOB_NAME" > "$RUNNER_TEMP/job-summary.name"; fi')
                self.assertTrue(pinned(upload['uses'], 'actions/upload-artifact'), upload['uses'])
                self.assertEqual(upload['with'], {
                    'name': 'job-summary-${{ github.job }}-${{ strategy.job-index }}',
                    'path': f'{COPY}\n${{{{ runner.temp }}}}/job-summary.name\n',
                    'if-no-files-found': 'ignore', 'retention-days': 7})
                for step in (save, upload):
                    self.assertEqual(step['if'], '${{ always() }}')
                    self.assertIs(step['continue-on-error'], True)
                # The name the job's check run carries, on every leg.
                for leg in legs(name, job_id):
                    self.assertEqual(interpolate(save['env']['JOB_NAME'], {'matrix': leg}),
                                     interpolate(job['name'], {'matrix': leg}))

    @unittest.skipIf(not BASH, 'needs bash')
    def test_the_name_is_written_beside_a_summary_alone(self) -> None:
        save = load('unit-tests.yml')['jobs']['test']['steps'][-2]
        with tempfile.TemporaryDirectory() as tmp:
            temp = pathlib.Path(tmp)
            for text in ('', '| table |\n'):
                (temp / 'job-summary.md').write_text(text, encoding='utf-8')
                result = subprocess.run([str(BASH), '--noprofile', '--norc', '-eo', 'pipefail', '-c', save['run']],
                                        env={'RUNNER_TEMP': tmp, 'JOB_NAME': 'Python 3.8 (KTLO)',
                                             'PATH': os.environ.get('PATH', '')},
                                        capture_output=True, text=True, check=False, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                with self.subTest(summary=bool(text)):
                    self.assertEqual((temp / 'job-summary.name').exists(), bool(text))
            self.assertEqual((temp / 'job-summary.name').read_text(encoding='utf-8'), 'Python 3.8 (KTLO)\n')


@unittest.skipIf(not BASH or os.name == 'nt', 'needs bash and a POSIX shell')
class TestTheReport(unittest.TestCase):
    """``Write the run report``, against a stand-in ``gh`` answering the check suite and the artifacts."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-push-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        write_launcher(self.bin, 'gh', FAKE_GH)
        (self.bin / 'python3').symlink_to(sys.executable)
        self.work = self.root / 'work'
        checkout(self.work)
        self.answer = self.root / 'answer.json'
        self.log = self.root / 'suite.log'
        self.output = self.root / 'output'
        self.artifacts = self.root / 'artifacts'
        self.artifacts.mkdir()

    def artifact(self, folder: 'str', summary: 'str', job: 'Optional[str]' = None) -> None:
        """An artifact of the run: a job's copy of its summary, and its name if given."""
        path = self.artifacts / folder
        path.mkdir()
        (path / 'job-summary.md').write_text(summary, encoding='utf-8')
        if job is not None:
            (path / 'job-summary.name').write_text(job + '\n', encoding='utf-8')

    def report(self, conclusion: 'str' = 'success', answer: 'Optional[object]' = None, branch: 'str' = 'main',
               workflow: 'str' = 'Unit Tests', event: 'str' = 'push',
               **extra: 'str') -> 'tuple[dict[str, str], str, str]':
        """The step's outputs, its report (``''`` where it wrote none) and its stdout."""
        shutil.rmtree(self.work / 'report', ignore_errors=True)
        self.output.write_text('', encoding='utf-8')
        env = {'PATH': f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', 'FAKE_SUITE_LOG': str(self.log),
               'GITHUB_OUTPUT': str(self.output), 'RUNNER_TEMP': str(self.root), 'GH_TOKEN': 'token',
               'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit', 'FAKE_ARTIFACTS': str(self.artifacts),
               'WORKFLOW': workflow, 'SUITE': SUITE, 'RUN_ID': RUN_ID, 'RUN_URL': RUN_URL, 'RUN_EVENT': event,
               'RUN_CONCLUSION': conclusion, 'HEAD_SHA': SHA, 'HEAD_BRANCH': branch, **extra}
        if answer is not None:
            self.answer.write_text(answer if isinstance(answer, str) else json.dumps(answer), encoding='utf-8')
            env['FAKE_SUITE_ANSWER'] = str(self.answer)
        result = run_step('Write the run report', self.work, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = dict(line.split('=', 1) for line in self.output.read_text(encoding='utf-8').splitlines())
        self.assertEqual(sorted(outputs), sorted(OUTPUTS))
        path = self.work / REPORT
        return outputs, path.read_text(encoding='utf-8') if path.exists() else '', result.stdout

    def test_each_conclusion_maps_to_a_status(self) -> None:
        for conclusion, status in CONCLUSIONS.items():
            with self.subTest(conclusion=conclusion):
                outputs, report, _ = self.report(conclusion, check_runs(GREEN))
                self.assertEqual(outputs, {'post': 'true', 'title': TITLE, 'mode': 'push', 'status': status})
                self.assertIn(f'concluded `{conclusion or "unknown"}`.', report)

    def test_it_asks_for_the_runs_check_suite_and_summaries(self) -> None:
        self.report('success', check_runs(GREEN))
        suite, download = [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(suite[:2], ['api', 'graphql'])
        self.assertEqual(suite[-2:], ['-f', f'id={SUITE}'])
        self.assertIn('checkRuns(first: 100)', suite[3])
        self.assertEqual(download[:-1], ['run', 'download', RUN_ID, '--repo', 'JarryShaw/PyPCAPKit',
                                         '--pattern', 'job-summary-*', '--dir'])

    def test_a_clean_green_run(self) -> None:
        outputs, report, _ = self.report('success', check_runs(GREEN))
        self.assertEqual(outputs['status'], 'success')
        self.assertEqual(report, (
            '### Unit Tests push run\n\n'
            f'[Unit Tests run]({RUN_URL}) for `{SHA[:9]}` concluded `success`.\n\n'
            'Every job passed, with no warning.\n'))

    def test_a_green_run_whose_ktlo_leg_warned_is_a_warning(self) -> None:
        outputs, report, _ = self.report('success', check_runs(GREEN, KTLO, ('Python 3.15', 'SKIPPED', [])))
        self.assertEqual(outputs['status'], 'warning')
        self.assertEqual(report, (
            '### Unit Tests push run\n\n'
            f'[Unit Tests run]({RUN_URL}) for `{SHA[:9]}` concluded `success`.\n\n'
            '**Warned, in jobs that passed:**\n\n'
            '- `Python 3.8 (KTLO)`: `tests failed on Python 3.8 (KTLO, non-blocking)`; '
            '`Process completed with exit code 1.`\n'))

    def test_a_push_runs_passing_blocking_job_earns_no_post(self) -> None:
        """The owner's push rule: its warnings neither count nor are listed."""
        outputs, report, _ = self.report('success', check_runs(GREEN, BLOCKING))
        self.assertEqual(outputs['status'], 'success')
        self.assertNotIn('DeprecationWarning', report)
        self.assertIn('Every job passed, with no warning that counts.\n', report)

    def test_a_non_blocking_legs_warning_still_counts_on_a_push(self) -> None:
        for job in (KTLO, ENGINE_KTLO, ('Python 3.15t (experimental)', 'SUCCESS',
                                        [('WARNING', 'tests failed on Python 3.15t (experimental, non-blocking)')])):
            with self.subTest(job=job[0]):
                outputs, report, _ = self.report('success', check_runs(GREEN, BLOCKING, job))
                self.assertEqual(outputs['status'], 'warning')
                self.assertIn(f'- `{job[0]}`: `{job[2][0][1]}`', report)
                self.assertNotIn('DeprecationWarning', report)

    def test_a_failed_push_run_lists_every_warning(self) -> None:
        """Annotations on a passing blocking job matter once the run failed."""
        outputs, report, _ = self.report('failure', check_runs(GREEN, BLOCKING, ('Python 3.12', 'FAILURE', [])))
        self.assertEqual(outputs['status'], 'failure')
        self.assertIn('**Did not pass:**\n\n- `Python 3.12` (failure)\n', report)
        self.assertIn('- `Python 3.13`: `DeprecationWarning: something old`', report)

    def test_a_scheduled_run_counts_every_warning(self) -> None:
        """A run that posts every time keeps the rule as it was: any annotation on a passing job warns."""
        outputs, report, _ = self.report('success', check_runs(('Compat Python 3.13', 'SUCCESS', BLOCKING[2])),
                                         workflow='Python Compatibility', event='schedule')
        self.assertEqual(outputs, {'post': 'true', 'title': 'python-compatibility: main scheduled runs',
                                   'mode': 'scheduled', 'status': 'warning'})
        self.assertTrue(report.startswith('### Python Compatibility scheduled run\n\n'
                                          f'[Python Compatibility run]({RUN_URL})'), report)
        self.assertIn('- `Compat Python 3.13`: `DeprecationWarning: something old`', report)

    def test_pips_retries_never_count(self) -> None:
        """On a non-blocking leg on a push, or any job on the schedule, where every other warning counts."""
        for workflow, event, job in (('Unit Tests', 'push', 'Python 3.8 (KTLO)'),
                                     ('Python Compatibility', 'schedule', 'Compat Python 3.13'),
                                     ('Python Compatibility', 'push', 'Compat Python 3.9 (KTLO)')):
            with self.subTest(workflow=workflow, event=event, job=job):
                outputs, report, _ = self.report('success', check_runs((job, 'SUCCESS', [RETRY])),
                                                 workflow=workflow, event=event)
                self.assertEqual(outputs['status'], 'success')
                self.assertNotIn('Retrying', report)
                self.assertIn('Every job passed, with no warning that counts.\n', report)

    def test_a_retry_title_or_message_matches(self) -> None:
        for annotation in (note(*RETRY), note('FAILURE', RETRY[2], 'x')):
            with self.subTest(annotation=annotation):
                self.assertTrue(check_suite_report.ignored('Project tests', annotation, {}))
        self.assertFalse(check_suite_report.ignored('Project tests', note('WARNING', '', 'Retrying soon'), {}))

    def test_the_by_design_matching(self) -> None:
        """A listed title, at its level, on its job; an empty prefix only an empty title; anything else warns."""
        found = check_suite_report.assess(nodes(PYPY, GREEN), 'success', 'scheduled', LISTED)
        self.assertEqual(found, check_suite_report.Assessment('success', [], [], True))
        reworded = [(level, title, 'something else entirely') for level, title, _ in PYPY[2]]
        found = check_suite_report.assess(nodes((PYPY[0], 'SUCCESS', reworded)), 'success', 'scheduled', LISTED)
        self.assertEqual(found.status, 'success')
        cases = {
            'a failed tests step on a by-design job': (
                PYPY[0], 'WARNING', 'tests failed on Python pypy3.10 (KTLO, non-blocking)'),
            'a titled failure on a by-design job': (PYPY[0], 'FAILURE', 'Something broke'),
            'a by-design title at another level': (
                PYPY[0], 'FAILURE', 'install failed on Python pypy3.10 (KTLO, non-blocking)'),
            'a by-design title on another job': (
                'Python 3.8 (KTLO)', 'WARNING', 'install failed on Python pypy3.10 (KTLO, non-blocking)'),
        }
        for case, (job, level, title) in cases.items():
            runs = [PYPY, GREEN] if job == PYPY[0] else [PYPY, GREEN, (job, 'SUCCESS', [])]
            runs = [(name, result, list(notes) + ([(level, title, 'extra')] if name == job else []))
                    for name, result, notes in runs]
            for mode in ('push', 'scheduled'):
                with self.subTest(case=case, mode=mode):
                    found = check_suite_report.assess(nodes(*runs), 'success', mode, LISTED)
                    self.assertEqual(found.status, 'warning')
                    self.assertEqual(found.warned, [f'`{job}`: `{title}`'])

    def test_with_nothing_listed_the_old_install_failures_warn(self) -> None:
        """Run 39718608950's pypy3.10 install failure is no longer by design (#2040)."""
        outputs, report, _ = self.report('success', check_runs(PYPY, GREEN))
        self.assertEqual(outputs['status'], 'warning')
        self.assertIn('- `Python pypy3.10 (KTLO)`: `install failed on Python pypy3.10 (KTLO, non-blocking)`', report)

    def test_a_job_that_failed_without_failing_the_run_is_a_warning(self) -> None:
        outputs, report, _ = self.report('success', check_runs(GREEN, ('Python 3.9 (KTLO)', 'FAILURE', [])))
        self.assertEqual(outputs['status'], 'warning')
        self.assertIn('**Failed without failing the run:**\n\n- `Python 3.9 (KTLO)` (failure)\n', report)

    def test_a_failed_run_names_its_jobs(self) -> None:
        answer = check_runs(PYPY, KTLO, ('Project tests', 'FAILURE', [('FAILURE', '')]),
                            ('Required checks passed', 'FAILURE', []), ('Python 3.13', 'TIMED_OUT', []))
        outputs, report, _ = self.report('failure', answer)
        self.assertEqual(outputs['status'], 'failure')
        self.assertIn('**Did not pass:**\n\n- `Project tests` (failure)\n- `Required checks passed` (failure)\n'
                      '- `Python 3.13` (timed_out)\n', report)
        self.assertIn('- `Python 3.8 (KTLO)`: ', report)

    def test_a_run_that_tested_nothing_posts_nothing(self) -> None:
        """Every leg skipped, as for a superseded commit (``current``) or no code change (``changes``)."""
        superseded = check_runs(('Check the commit is still current', 'SUCCESS', []),
                                ('Read the Python versions', 'SKIPPED', []), ('Classify changed files', 'SKIPPED', []),
                                ('Python 3.15t (experimental)', 'SKIPPED', []))
        docs_only = check_runs(('Classify changed files', 'SUCCESS', []), ('Python 3.14', 'SKIPPED', []),
                               ('Engines (Scapy)', 'SKIPPED', []), ('Project tests', 'SUCCESS', []),
                               ('Required checks passed', 'SUCCESS', []))
        for workflow, answer in (('Experimental Tests', superseded), ('Unit Tests', docs_only)):
            for conclusion in ('success', 'skipped'):
                with self.subTest(workflow=workflow, conclusion=conclusion):
                    outputs, report, stdout = self.report(conclusion, answer, workflow=workflow)
                    self.assertEqual(outputs['post'], 'false')
                    self.assertEqual(report, '')
                    self.assertIn('nothing is posted', stdout)

    def test_a_run_that_failed_before_its_legs_still_posts(self) -> None:
        answer = check_runs(('Check the commit is still current', 'SUCCESS', []),
                            ('Classify changed files', 'FAILURE', []), ('Python 3.15t (experimental)', 'SKIPPED', []))
        outputs, report, _ = self.report('failure', answer, workflow='Experimental Tests')
        self.assertEqual((outputs['post'], outputs['status'], outputs['title']),
                         ('true', 'failure', 'experimental: main push runs'))
        self.assertIn('- `Classify changed files` (failure)', report)

    def test_an_unknown_workflow_or_a_pull_request_posts_nothing(self) -> None:
        outputs, _, stdout = self.report('success', check_runs(GREEN), workflow='Lint')
        self.assertEqual(outputs['post'], 'false')
        self.assertIn("::warning title=CI report not written::'Lint' is no workflow", stdout)
        outputs, _, stdout = self.report('success', check_runs(GREEN), event='pull_request')
        self.assertEqual(outputs['post'], 'false')
        self.assertNotIn('::warning', stdout)

    def test_unreadable_jobs_keep_the_conclusion(self) -> None:
        for answer in (None, '<html>', json.dumps({'data': {'node': None}})):
            for conclusion in ('success', 'failure'):
                with self.subTest(answer=answer, conclusion=conclusion):
                    outputs, report, stdout = self.report(conclusion, answer)
                    self.assertEqual((outputs['post'], outputs['status']), ('true', conclusion))
                    self.assertTrue(report.endswith("The run's jobs could not be read, so none is named here.\n"),
                                    report)
                    self.assertIn("::warning title=CI report not written::The run's jobs could not be read", stdout)

    def test_a_long_suite_says_it_was_cut(self) -> None:
        _, report, _ = self.report('success', check_runs(GREEN, more=True))
        self.assertTrue(report.endswith('Only the first 100 jobs were read.\n'), report)

    def test_the_runs_text_renders_as_code(self) -> None:
        """A job name or annotation holding Markdown, a mention or a newline stays one inert code span."""
        noisy = ('Py `3` @JarryShaw (KTLO)', 'SUCCESS', [('WARNING', 'a\n**b** `c` @d ' + 'x' * 300)])
        _, report, _ = self.report('success', check_runs(noisy), RUN_URL='javascript:alert(1)', HEAD_SHA='nope')
        [line] = [line for line in report.splitlines() if line.startswith('- ')]
        flat = "a **b** 'c' @d "
        self.assertEqual(line, f"- `Py '3' @JarryShaw (KTLO)`: `{flat}{'x' * (197 - len(flat))}...`")
        self.assertIn('\nThe Unit Tests run concluded `success`.\n', report)

    def test_the_branch_and_mode_name_the_thread(self) -> None:
        for branch, event, title in (('main', 'push', TITLE),
                                     ('release/1.4', 'push', 'unit-tests: release/1.4 push runs'),
                                     ('a b$(x)`y`', 'push', 'unit-tests: a-b--x--y- push runs'),
                                     ('', 'push', 'unit-tests: unknown push runs'),
                                     ('main', 'schedule', 'unit-tests: main scheduled runs'),
                                     ('main', 'workflow_dispatch', 'unit-tests: main scheduled runs')):
            with self.subTest(branch=branch, event=event):
                outputs, _, _ = self.report('success', check_runs(GREEN), branch=branch, event=event)
                self.assertEqual((outputs['title'], outputs['mode']),
                                 (title, 'push' if event == 'push' else 'scheduled'))

    def test_the_job_summaries_are_folded_in(self) -> None:
        """One ``<details>`` a job, in the check suite's order, named from the artifact; mentions neutralised."""
        self.artifact('job-summary-test-0', '| Package | Cover |\n| --- | --- |\n| `pcapkit` | 91% |\n', 'Python 3.14')
        self.artifact('job-summary-test-ktlo-0',
                      '- Python 3.8 (KTLO, non-blocking): step `tests` failed; cc @someone\n', 'Python 3.8 (KTLO)')
        self.artifact('job-summary-x-1', 'An unnamed summary.\n')
        _, report, _ = self.report('success', check_runs(KTLO, GREEN))
        head, _, rest = report.partition('\n\n**Job summaries:**\n\n')
        self.assertTrue(head.endswith('`Process completed with exit code 1.`'), head)
        self.assertEqual(rest, (
            '<details><summary><code>Python 3.8 (KTLO)</code></summary>\n\n'
            '- Python 3.8 (KTLO, non-blocking): step `tests` failed; cc @\u2060someone\n\n</details>\n\n'
            '<details><summary><code>Python 3.14</code></summary>\n\n'
            '| Package | Cover |\n| --- | --- |\n| `pcapkit` | 91% |\n\n</details>\n\n'
            '<details><summary><code>job-summary-x-1</code></summary>\n\nAn unnamed summary.\n\n</details>\n'))

    def test_a_summary_too_long_is_trimmed_with_a_link(self) -> None:
        self.artifact('job-summary-test-0', 'short\n', 'Python 3.14')
        self.artifact('job-summary-engine-tests-0', ''.join(f'| 3.{n % 10} | Scapy | supported | passed |\n'
                                                            for n in range(4000)), 'Engines (Scapy)')
        _, report, _ = self.report('success', check_runs(GREEN))
        self.assertLessEqual(len(report), check_suite_report.LIMIT - check_suite_report.FOOTER)
        self.assertIn('<details><summary><code>Python 3.14</code></summary>\n\nshort\n\n</details>', report)
        self.assertIn(f'\n\n*Trimmed to fit the comment; the whole summary is on [the run]({RUN_URL}).*'
                      '\n\n</details>\n', report)
        comment = discussion_report.compose(report, 'Posted from the run.', 'success')
        self.assertNotIn('cut short', comment)

    def test_no_summary_is_no_section_and_no_warning(self) -> None:
        _, report, stdout = self.report('success', check_runs(GREEN))
        self.assertNotIn('Job summaries', report)
        self.assertNotIn('::warning', stdout)

    def test_unreadable_summaries_warn(self) -> None:
        outputs, report, stdout = self.report('success', check_runs(GREEN), FAKE_ARTIFACTS='fail')
        self.assertEqual(outputs['post'], 'true')
        self.assertIn('The job summaries could not be read: `HTTP 403: Resource not accessible by integration`.',
                      report)
        self.assertIn('::warning title=CI report not written::The job summaries could not be read', stdout)

    def test_each_nothing_to_download_wording_is_no_summary(self) -> None:
        # #2074: each way gh's pkg/cmd/run/download/download.go says it found nothing.
        for text in ('no valid artifacts found to download',
                     'no artifact matches any of the names or patterns provided',
                     'no artifact matches any of the names provided'):
            with self.subTest(text=text):
                outputs, report, stdout = self.report('success', check_runs(GREEN), FAKE_ARTIFACTS=f'say:{text}')
                self.assertEqual(outputs['post'], 'true')
                self.assertNotIn('Job summaries', report)
                self.assertNotIn('could not be read', report)
                self.assertNotIn('::warning', stdout)

    def test_a_genuine_download_error_still_warns(self) -> None:
        # The last holds a wording inside a longer line, which is not gh saying it.
        for text in ('error fetching artifacts: HTTP 401: Bad credentials (https://api.github.com/repos/'
                     'JarryShaw/PyPCAPKit/actions/runs/1/artifacts?per_page=100)',
                     'error fetching artifacts: HTTP 404: Not Found (https://api.github.com/repos/'
                     'JarryShaw/PyPCAPKit/actions/runs/1/artifacts?per_page=100)',
                     'error fetching artifacts: Get "https://api.github.com/repos/JarryShaw/PyPCAPKit/actions/'
                     'runs/1/artifacts?per_page=100": dial tcp: lookup api.github.com: no such host',
                     'error downloading job-summary-test-0: unexpected EOF (not: no valid artifacts found to download)'):
            with self.subTest(text=text):
                _, report, stdout = self.report('success', check_runs(GREEN), FAKE_ARTIFACTS=f'say:{text}')
                self.assertIn(f'The job summaries could not be read: `{text}`.', report)
                self.assertIn('::warning title=CI report not written::The job summaries could not be read', stdout)


class TestTheDownload(unittest.TestCase):
    """:func:`check_suite_report.download` reads each artifact's folder, and one unpacked in place."""

    def test_folders_and_the_directory_itself(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / 'job-summary.md').write_text('lone\n', encoding='utf-8')
            (root / 'job-summary-a-0').mkdir()
            (root / 'job-summary-a-0' / 'job-summary.md').write_text('first\n', encoding='utf-8')
            (root / 'job-summary-a-0' / 'job-summary.name').write_text('Python 3.14\nignored\n', encoding='utf-8')
            (root / 'job-summary-b-0').mkdir()
            (root / 'job-summary-b-0' / 'job-summary.md').write_text('  \n', encoding='utf-8')
            done = subprocess.CompletedProcess([], 0, '', '')
            with unittest.mock.patch.object(check_suite_report.subprocess, 'run', return_value=done) as run:
                found = check_suite_report.download('o/r', RUN_ID, root)
            self.assertEqual(found, ([(root.name, 'lone\n'), ('Python 3.14', 'first\n')], ''))
            self.assertEqual(run.call_args[0][0][-2:], ['--dir', str(root)])
            self.assertEqual(check_suite_report.download('o/r', '1; rm', root), ([], "the run id '1; rm' is not a number"))


class TestTheFit(unittest.TestCase):
    """:func:`check_suite_report.fit` shares the room smallest first."""

    URL = RUN_URL

    def test_the_limits_agree(self) -> None:
        self.assertEqual(check_suite_report.LIMIT, discussion_report.LIMIT)

    def test_all_fit_whole(self) -> None:
        blocks = check_suite_report.fit([('a', 'one'), ('b', 'two')], 1000, self.URL)
        self.assertEqual(blocks, ['<details><summary><code>a</code></summary>\n\none\n\n</details>',
                                  '<details><summary><code>b</code></summary>\n\ntwo\n\n</details>'])

    def test_a_short_one_stays_whole_beside_long_ones(self) -> None:
        texts = [('long', 'x\n' * 5000), ('short', 'y'), ('longer', 'z\n' * 8000)]
        for room in (3000, 9000, 20000):
            with self.subTest(room=room):
                blocks = check_suite_report.fit(texts, room, self.URL)
                self.assertLessEqual(sum(map(len, blocks)), room)
                self.assertEqual(len(blocks), 3)
                self.assertIn('\n\ny\n\n', blocks[1])
                for block in (blocks[0], blocks[2]):
                    self.assertIn('*Trimmed to fit the comment', block)

    def test_a_cut_closes_its_code_fence(self) -> None:
        [block] = check_suite_report.fit([('job', '```\n' + 'line\n' * 1000 + '```\n')], 600, self.URL)
        body = block.split('</summary>\n\n', 1)[1].split('\n\n*Trimmed', 1)[0]
        self.assertEqual(body.count('```') % 2, 0)

    def test_no_room_leaves_a_summary_out_and_says_so(self) -> None:
        self.assertEqual(check_suite_report.fit([('job', 'x' * 1000)], 50, self.URL), [])
        found = check_suite_report.Assessment('success', [], [], False)
        text = check_suite_report.render('Unit Tests', 'push', 'success', SHA, RUN_URL, found, [], False,
                                         [('job', 'x' * 1000)] * 400, '')
        self.assertLessEqual(len(text), check_suite_report.LIMIT - check_suite_report.FOOTER)
        self.assertRegex(text, r'\*\d+ job summaries did not fit; the run holds them\.\*$')


#: A stand-in ``python3`` for the post step, recording its arguments and environment.
FAKE_PYTHON = textwrap.dedent('''\
    import json, os, sys
    with open(os.environ['FAKE_PYTHON_LOG'], 'w', encoding='utf-8') as file:
        json.dump({'args': sys.argv[1:], 'workflow': os.environ.get('GITHUB_WORKFLOW')}, file)
''')


@unittest.skipIf(not BASH or os.name == 'nt', 'needs bash and a POSIX shell')
class TestThePostStep(unittest.TestCase):
    """``Post the report to Discussions``, with a stand-in ``python3``."""

    def test_it_passes_the_relayed_run(self) -> None:
        for relay in REPORTED:
            with self.subTest(relay=relay), tempfile.TemporaryDirectory(prefix='pcapkit-2030-push-post-') as tmp:
                root = pathlib.Path(tmp)
                (root / 'bin').mkdir()
                (root / 'work').mkdir()
                write_launcher(root / 'bin', 'python3', FAKE_PYTHON)
                env = {'PATH': f'{root / "bin"}{os.pathsep}{os.environ.get("PATH", "")}',
                       'FAKE_PYTHON_LOG': str(root / 'log.json'), 'REPORT_CATEGORY': CATEGORY, 'TITLE': TITLE,
                       'MODE': 'push', 'STATUS': 'warning', 'RUN_URL': RUN_URL, 'HEAD_SHA': SHA,
                       'WORKFLOW': 'Unit Tests', 'GITHUB_WORKFLOW': 'Coverage Comment'}
                result = run_step('Post the report to Discussions', root / 'work', env, relay)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                logged = json.loads((root / 'log.json').read_text(encoding='utf-8'))
                self.assertEqual(logged, {'workflow': 'Unit Tests', 'args': [
                    'util/discussion_report.py', '--category', CATEGORY, '--title', TITLE, '--report', REPORT,
                    '--mode', 'push', '--status', 'warning', '--run-url', RUN_URL, '--sha', SHA]})


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestEndToEnd(_FakeGitHub):
    """Both steps and the real scripts: the cadence each relay's runs post at."""

    def setUp(self) -> None:
        super().setUp()
        (self.bin / 'gh.py').rename(self.bin / 'discussions.py')
        write_launcher(self.bin, 'gh', FAKE_GH)
        (self.bin / 'python3').symlink_to(sys.executable)
        self.work = self.tmp / 'work'
        checkout(self.work)
        self.answer = self.tmp / 'answer.json'

    def run_of(self, workflow: 'str', event: 'str', conclusion: 'str',
               *runs: 'tuple[str, str, list[tuple[str, ...]]]') -> None:
        self.answer.write_text(json.dumps(check_runs(*runs)), encoding='utf-8')
        shutil.rmtree(self.work / 'report', ignore_errors=True)
        output = self.tmp / 'output'
        output.write_text('', encoding='utf-8')
        env = self.env(FAKE_SUITE_ANSWER=str(self.answer), FAKE_SUITE_LOG=str(self.tmp / 'suite.log'),
                       GITHUB_OUTPUT=str(output), RUNNER_TEMP=str(self.tmp), GITHUB_WORKFLOW='CI Reports',
                       WORKFLOW=workflow, SUITE=SUITE, RUN_ID=RUN_ID, RUN_URL=RUN_URL, RUN_EVENT=event,
                       RUN_CONCLUSION=conclusion, HEAD_SHA=SHA, HEAD_BRANCH='main', REPORT_CATEGORY=CATEGORY)
        result = run_step('Write the run report', self.work, env, RELAY)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for line in output.read_text(encoding='utf-8').splitlines():
            key, value = line.split('=', 1)
            env[key.upper()] = value
        # The step's `if:`.
        if env['POST'] != 'true':
            return
        result = run_step('Post the report to Discussions', self.work, env, RELAY)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('::warning', result.stdout)

    def comments(self, title: 'str') -> 'list[str]':
        found = [entry for entry in self.state['discussions'] if entry['title'] == title]
        return found[0]['comments'] if found else []

    def test_the_push_cadence(self) -> None:
        self.run_of('Unit Tests', 'push', 'success', GREEN)
        self.assertEqual(self.state['discussions'], [])
        self.run_of('Unit Tests', 'push', 'success', GREEN, BLOCKING)
        self.assertEqual(self.state['discussions'], [])
        self.run_of('Unit Tests', 'push', 'success', GREEN, KTLO)
        self.run_of('Unit Tests', 'push', 'failure', GREEN, ('Python 3.13', 'FAILURE', []))
        self.run_of('Unit Tests', 'push', 'success', GREEN)
        self.run_of('Unit Tests', 'push', 'success', GREEN)
        comments = self.comments(TITLE)
        self.assertEqual([MARKER.findall(body) for body in comments], [['warning'], ['failure'], ['success']])
        self.assertIn('- `Python 3.8 (KTLO)`: ', comments[0])
        self.assertIn('- `Python 3.13` (failure)', comments[1])
        self.assertIn(f'Posted from [Unit Tests run]({RUN_URL}) at commit `{SHA}`, which ended `success`.',
                      comments[2])

    def test_a_superseded_experimental_run_is_no_recovery(self) -> None:
        """After a bad report, a run whose legs all skipped posts no "back to green"; a tested one does."""
        title = 'experimental: main push runs'
        leg = 'Python 3.15t (experimental)'
        self.run_of('Experimental Tests', 'push', 'success', (leg, 'SUCCESS', [('WARNING', 'tests failed')]))
        self.run_of('Experimental Tests', 'push', 'success', ('Check the commit is still current', 'SUCCESS', []),
                    (leg, 'SKIPPED', []))
        self.assertEqual([MARKER.findall(body) for body in self.comments(title)], [['warning']])
        self.run_of('Experimental Tests', 'push', 'success', (leg, 'SUCCESS', []))
        self.assertEqual([MARKER.findall(body) for body in self.comments(title)], [['warning'], ['success']])

    def test_a_scheduled_compatibility_run_posts_every_time(self) -> None:
        title = 'python-compatibility: main scheduled runs'
        for _ in range(2):
            self.run_of('Python Compatibility', 'schedule', 'success', ('Compat Python 3.14', 'SUCCESS', []))
        comments = self.comments(title)
        self.assertEqual([MARKER.findall(body) for body in comments], [['success'], ['success']])
        self.assertIn('Posted from [Python Compatibility run]', comments[0])


class TestTheHelperCopies(unittest.TestCase):
    """util/_actions.py writes the job's copy of its summary where ``JOB_SUMMARY_COPY`` names one."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.page = pathlib.Path(tmp.name) / 'summary'
        self.copy = pathlib.Path(tmp.name) / 'job-summary.md'
        self.copy.write_text('earlier step\n', encoding='utf-8')

    def test_both_writers_copy(self) -> None:
        env = {'GITHUB_STEP_SUMMARY': str(self.page), _actions.SUMMARY_COPY: str(self.copy)}
        self.assertEqual(_actions.SUMMARY_COPY, 'JOB_SUMMARY_COPY')
        self.assertTrue(_actions.summary('- one', environ=env))
        with _actions.open_summary(environ=env) as page:
            print('| table |', file=page)
            page.write('tail\n')
        self.assertEqual(self.page.read_text(encoding='utf-8'), '- one\n| table |\ntail\n')
        self.assertEqual(self.copy.read_text(encoding='utf-8'), 'earlier step\n- one\n| table |\ntail\n')

    def test_without_it_nothing_is_copied(self) -> None:
        env = {'GITHUB_STEP_SUMMARY': str(self.page), _actions.SUMMARY_COPY: ''}
        _actions.summary('- one', environ=env)
        with _actions.open_summary(environ={'GITHUB_STEP_SUMMARY': str(self.page)}) as page:
            print('two', file=page)
        self.assertEqual(self.page.read_text(encoding='utf-8'), '- one\ntwo\n')
        self.assertEqual(self.copy.read_text(encoding='utf-8'), 'earlier step\n')

    def test_a_copy_that_cannot_open_is_left_out(self) -> None:
        env = {'GITHUB_STEP_SUMMARY': str(self.page), _actions.SUMMARY_COPY: str(self.copy.parent / 'no' / 'file')}
        self.assertTrue(_actions.summary('- one', environ=env))
        self.assertEqual(self.page.read_text(encoding='utf-8'), '- one\n')

    def test_the_scripts_copy_as_the_steps_run_them(self) -> None:
        """``KTLO summary``'s script, run with the step's environment, writes both files."""
        env = {key: value for key, value in os.environ.items() if not key.startswith(('GITHUB_', 'PYTHON'))}
        env.update(GITHUB_STEP_SUMMARY=str(self.page), JOB_SUMMARY_COPY=str(self.copy),
                   LEG='Python 3.8 (KTLO, non-blocking)', STEPS=json.dumps({'tests': {'outcome': 'failure'}}))
        result = subprocess.run([sys.executable, 'util/leg_summary.py', 'ktlo'], cwd=ROOT, env=env,  # nosec: B603
                                capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        line = '- Python 3.8 (KTLO, non-blocking): step `tests` failed; non-blocking, so this job still succeeds.\n'
        self.assertEqual(self.page.read_text(encoding='utf-8'), line)
        self.assertEqual(self.copy.read_text(encoding='utf-8'), 'earlier step\n' + line)


if __name__ == '__main__':
    unittest.main()
