# -*- coding: utf-8 -*-
"""Create Release tags and builds exactly the commit its run was created for (#1634).

Run 38008819343 was created for ``b6b95bc8e`` ("Bumped version to 1.5.0b9"),
waited three days on the ``github-release`` approval, and then tagged ``main``'s
tip ``2c0008c3c`` as both ``v1.5.0b9`` and ``conda-1.5.0b9+0``. Two moving refs
did it: ``softprops/action-gh-release`` defaults ``target_commitish`` to the
default branch, and the ``tag`` job ran ``git pull --rebase origin main`` --
fast-forwarding ``b6b95bc8e..2c0008c3c`` in job 115087308551 -- before tagging.
``pypi`` and ``conda`` then checked those tags out, so the build-0 packages
carried ``2c0008c3c``'s pins, whose ``conda/build`` reads 3.

The owner's ruling: tag and build exactly the run's commit, with the
``conda/build`` reset as a commit of its own on top. ``github.sha`` is that
commit on both triggers -- the pushed tag's commit, or ``main``'s tip when a
``workflow_run`` run was created -- whereas ``github.event.workflow_run.head_sha``
is the commit Vendor Update *ran on*, before it pushed its bump.

Asserted here, over :file:`.github/workflows/create-release.yml`:

* every ``actions/checkout`` pins ``ref: ${{ github.sha }}``, and ``github``'s
  ``action-gh-release`` names it as ``target_commitish`` only on
  ``workflow_run``, where it creates the tag;
* ``pypi`` and ``conda`` attach their files with ``gh release upload`` rather
  than ``action-gh-release``, which calls Update a release -- where GitHub
  re-checks that target -- before every upload, and leave a file already on the
  release alone (#1640) unless its asset is not ``uploaded``, which is deleted
  and uploaded again; their shared script is run here against a stand-in
  ``gh``;
* :file:`cron-conda.yml`'s ``conda-dist`` updates the release only when one is
  published, and names the default branch as its target, so it neither creates
  the pending version's tag at ``main``'s tip nor has a stale target re-checked;
* ``tag`` tags before anything looks at ``main``, never pulls, merges, rebases
  or force-pushes, and its two scripts -- run here against a scratch repository
  -- tag the run's commit, then reset ``conda/build`` on ``main``'s tip unless a
  build number that would free is already tagged;
* ``github``, ``pypi`` and ``conda`` refuse to publish under a tag that names any
  other commit, which is likewise run, not just read;
* once the version is tagged, ``version_check``'s PyPI and Anaconda counts are
  of the tiers at the tag's commit, not this run's (#1660), run against a
  scratch repository, so a tier added since cannot fail the check above;
* every step handed ``PCAPKIT_RUN_SHA`` is handed ``github.sha``, and no
  expression names ``workflow_run.head_sha`` -- the scratch-repository tests
  inject their own values, so these are what tie them to the job;
* ``github`` creates the release with a token of the release App, minted with
  Contents and Workflows write from a ``github-release`` environment secret
  only that job reads, and spends ``GITHUB_TOKEN`` while no App is set up;
  ``version_check`` skips the tag-push run the App's tag starts, and
  ``release_status`` reports that skip quietly -- the owner's choice on #1634.

The scanner is indentation-based so the module runs without the ``test`` extra;
:class:`TestYAMLAgreesWithTheScanner` checks it against :func:`yaml.safe_load`
where PyYAML is installed, the split ``test_release_gates.py`` uses.

"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._support import scale_timeout
from tests.project import test_release_gates as gates
from tests.project.test_release_gates import (declared_environment, declared_if, evaluate_condition,
                                              evaluate_expression, job_blocks, strip_comments)

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): drives the release workflow's tag job against temporary
#: repositories.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
WORKFLOW = ROOT / '.github' / 'workflows' / 'create-release.yml'
CONDA_WORKFLOW = ROOT / '.github' / 'workflows' / 'cron-conda.yml'

#: The one ref every checkout and every release tag must name.
RUN_SHA = '${{ github.sha }}'

#: ``github``'s ``target_commitish``: the run's commit where the step creates the
#: tag, and ``''`` -- unset, to the action -- on a ``v*`` push, where it exists.
RELEASE_TARGET = "${{ github.event_name == 'workflow_run' && github.sha || '' }}"

#: The version ``version_check`` read from that commit.
VERSION_OUTPUT = '${{ needs.version_check.outputs.PCAPKIT_VERSION }}'

#: The step ``github``, ``pypi`` and ``conda`` each run before publishing.
CHECK_STEP = "Check the release tags name this run's commit"

#: ``github``'s step minting the release App's token, and its inputs, exactly.
MINT_STEP = "Mint the release App's token"
MINT_ACTION = 'actions/create-github-app-token'
MINT_WITH = {
    'client-id': '${{ vars.RELEASE_APP_CLIENT_ID }}',
    'private-key': '${{ secrets.RELEASE_APP_PRIVATE_KEY }}',
    'permission-contents': 'write',
    'permission-workflows': 'write',
}

#: Create Release's ``token``: the App's where it was minted, else ``GITHUB_TOKEN``.
RELEASE_TOKEN = '${{ steps.app_token.outputs.token || secrets.GITHUB_TOKEN }}'

#: The step explaining a refused Create Release.
EXPLAIN_STEP = 'Explain a refused release tag'

#: A read of the App's private key, as ``secrets.X`` or ``secrets['X']``.
SECRET = re.compile(r"""secrets\s*(?:\.\s*|\[\s*['"])RELEASE_APP_PRIVATE_KEY\b""")

#: The step ``pypi`` and ``conda`` attach their files to the GitHub Release with.
UPLOAD_STEP = 'Upload package to GitHub Release'

#: Its ``env:`` in each job: a glob in ``pypi``, ``conda_build``'s list in ``conda``.
UPLOAD_ENV = {
    job: {'GH_TOKEN': '${{ secrets.GITHUB_TOKEN }}', 'PCAPKIT_RELEASE_TAG': f'v{VERSION_OUTPUT}',
          'PCAPKIT_ASSETS': assets}
    for job, assets in (('pypi', 'dist/*'), ('conda', '${{ steps.conda_build.outputs.packages }}'))
}

#: ``tag``'s two scripts, in the order the job runs them.
TAG_STEPS = ('Create Tag', 'Reset Build Number')

#: #1748: ``version_check``'s step resolving the ``v*`` tag as :data:`CHECK_STEP`
#: does, and ``release_status``'s report, which names this run's commit.
OWNER_STEP = "Check which commit the version's tag names"
REPORT_STEP = 'Report why this run did or did not release anything'

#: Steps whose ``env:`` names ``PCAPKIT_RUN_SHA``, so the scan below cannot pass vacuously.
RUN_SHA_STEPS = {
    'version_check': [OWNER_STEP],
    'github': [CHECK_STEP, EXPLAIN_STEP],
    'tag': list(TAG_STEPS),
    'pypi': [CHECK_STEP],
    'conda': [CHECK_STEP],
    'release_status': [REPORT_STEP],
}

#: Expressions naming another run's commit: ``workflow_run.head_sha`` is the
#: commit Vendor Update ran *on*, ``945c3c3d8`` for run 38008819343, not its bump.
UPSTREAM_COMMIT = re.compile(r'\bworkflow_run\.head_|\bhead_commit\b')

#: The jobs that check out the repository, which is every job with steps but
#: ``vendor_update``, whose shell is inline: ``release_status`` checks out util/
#: for its script (#1967).
CHECKOUT_JOBS = ('version_check', 'github', 'tag', 'pypi', 'conda', 'release_status')

#: Git commands that move a checkout onto ``main``'s history or rewrite it.
#: ``merge-base`` is a read, so it is excluded from ``git merge``.
FORBIDDEN_GIT = {
    'git pull': re.compile(r'\bgit\s+pull\b'),
    'git merge': re.compile(r'\bgit\s+merge\b(?!-base)'),
    'git rebase': re.compile(r'\bgit\s+rebase\b'),
    'git reset': re.compile(r'\bgit\s+reset\b'),
    'a forced git push': re.compile(r'\bgit\s+push\b[^\n]*(?:--force|\s-f\b|\s"?\+)'),
}

_JOB = re.compile(r'^  ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(?:#.*)?$')
_STEP = re.compile(r'^      - (.*)$')
_KEY = {indent: re.compile(r'^ {%d}([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]+(.*))?$' % indent)
        for indent in (8, 10)}


def _indent(line: 'str') -> 'int':
    return len(line) - len(line.lstrip(' '))


def _scalar(value: 'str') -> 'str':
    """A one-line YAML value without its trailing comment or surrounding quotes."""
    value = re.sub(r'\s+#.*$', '', value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        value = value[1:-1]
    return value


def parse_step(lines: 'list[str]') -> 'dict[str, Any]':
    """One step's keys: scalars as strings, ``with:``/``env:`` as dicts, ``run: |`` as text."""
    step = {}  # type: dict[str, Any]
    index = 0
    while index < len(lines):
        match = _KEY[8].match(lines[index])
        index += 1
        if match is None or lines[index - 1].strip().startswith('#'):
            continue
        key, value = match.group(1), (match.group(2) or '').strip()
        if value in ('|', '|-'):
            body = []  # type: list[str]
            while index < len(lines) and (not lines[index].strip() or _indent(lines[index]) >= 10):
                body.append(lines[index][10:] if lines[index].strip() else '')
                index += 1
            while body and not body[-1]:
                body.pop()
            step[key] = '\n'.join(body) + '\n'
        elif not value or value.startswith('#'):
            mapping = {}  # type: dict[str, str]
            while index < len(lines) and (not lines[index].strip() or _indent(lines[index]) >= 10):
                child = _KEY[10].match(lines[index])
                if child is not None and not lines[index].strip().startswith('#'):
                    mapping[child.group(1)] = _scalar(child.group(2) or '')
                index += 1
            step[key] = mapping
        else:
            step[key] = _scalar(value)
    return step


def workflow_steps(text: 'str') -> 'dict[str, list[dict[str, Any]]]':
    """``{job: [step, ...]}`` for every job of a workflow, in file order."""
    lines = text.splitlines()
    jobs = {}  # type: dict[str, list[str]]
    current = None  # type: Optional[str]
    for line in lines[lines.index('jobs:') + 1:]:
        if line.strip() and not line.strip().startswith('#') and not line.startswith(' '):
            break
        match = _JOB.match(line)
        if match is not None:
            current = match.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)

    result = {}  # type: dict[str, list[dict[str, Any]]]
    for job, body in jobs.items():
        items = []  # type: list[list[str]]
        if '    steps:' in body:
            for line in body[body.index('    steps:') + 1:]:
                if line.strip() and not line.strip().startswith('#') and _indent(line) <= 4:
                    break
                match = _STEP.match(line)
                if match is not None:
                    items.append([' ' * 8 + match.group(1)])
                elif items:
                    items[-1].append(line)
        result[job] = [parse_step(item) for item in items]
    return result


def label(step: 'dict[str, Any]') -> 'str':
    return step.get('name') or step.get('uses') or '<unnamed>'


def script_command(run: 'str') -> 'Optional[list[str]]':
    """A ``run:`` of ``python3 util/<script>.py ...`` (#1967), as this interpreter runs it from any directory.

    :data:`None` for any other ``run:``, which the tests run under ``bash``.

    """
    words = shlex.split(run)
    if len(run.strip().splitlines()) != 1 or words[:1] != ['python3'] or not words[1].startswith('util/'):
        return None
    return [sys.executable, str(ROOT / words[1]), *words[2:]]


class WorkflowMixin:
    """Reads and scans :attr:`workflow` once per class."""

    workflow = WORKFLOW
    steps = {}  # type: dict[str, list[dict[str, Any]]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.steps = workflow_steps(cls.workflow.read_text(encoding='utf-8'))

    def step(self, job: 'str', name: 'str') -> 'dict[str, Any]':
        found = [step for step in self.steps[job] if step.get('name') == name]
        if len(found) != 1:
            message = f'{job} has {len(found)} steps named {name!r}, expected exactly one'
            self.fail(message)  # type: ignore[attr-defined]
        return found[0]

    def index(self, job: 'str', name: 'str') -> 'int':
        return self.steps[job].index(self.step(job, name))


class TestEveryCheckoutPinsTheRunSha(WorkflowMixin, unittest.TestCase):
    """No job builds, tags or reads a version from a ref that can move."""

    def checkouts(self) -> 'dict[str, list[dict[str, Any]]]':
        return {job: [step for step in steps if step.get('uses', '').startswith('actions/checkout@')]
                for job, steps in self.steps.items()}

    def test_the_scan_found_every_checkout(self) -> None:
        found = {job: len(steps) for job, steps in self.checkouts().items() if steps}
        self.assertEqual(found, dict.fromkeys(CHECKOUT_JOBS, 1))

    def test_every_checkout_pins_the_run_sha(self) -> None:
        """``tag``'s used no ``ref:``, ``pypi``'s ``v<version>``, ``conda``'s ``conda-<version>+0``."""
        for job, steps in sorted(self.checkouts().items()):
            for step in steps:
                with self.subTest(job=job):
                    self.assertEqual(
                        step.get('with', {}).get('ref'), RUN_SHA,
                        f'{job} checks out {step.get("with", {}).get("ref")!r} rather than '
                        f'the commit this run was created for',
                    )


class TestEveryReleaseTagIsCreatedAtTheRunSha(WorkflowMixin, unittest.TestCase):
    """``action-gh-release`` creates a missing tag at ``target_commitish``, default ``main``."""

    def releases(self) -> 'list[tuple[str, dict[str, Any]]]':
        return [(job, step) for job, steps in sorted(self.steps.items()) for step in steps
                if step.get('uses', '').startswith('softprops/action-gh-release@')]

    def test_only_github_runs_the_release_action(self) -> None:
        """``pypi`` and ``conda`` used it to upload, which re-checked the target.

        ``action-gh-release`` 3.0.2 calls Update a release on an existing
        release before uploading anything (``src/github.ts:631-683``), passing
        the release's own ``target_commitish`` when the input is unset, and
        GitHub's REST docs apply the workflow-file rule there to "the new value
        of target_commitish if you are changing it, otherwise the existing
        target". On ``workflow_run`` that target is ``github.sha``, so by the
        docs a workflow change reaching ``main`` after ``github`` ran would have
        failed these uploads after PyPI and anaconda.org had published.
        """
        self.assertEqual([(job, label(step)) for job, step in self.releases()], [('github', 'Create Release')])

    def test_the_tag_creating_release_names_the_run_sha_on_workflow_run_only(self) -> None:
        """Create a release applies the workflow-file rule to ``target_commitish``
        or, when it is omitted, the default branch's latest commit.

        On a ``v*`` push the tag exists, a target adds nothing the tag check does
        not prove, and naming one would expose the hand-pushed recovery tag to
        that rule.
        """
        (_, step), = self.releases()
        self.assertEqual(step.get('with', {}).get('target_commitish'), RELEASE_TARGET)

    def test_a_refused_tag_is_explained(self) -> None:
        """GitHub refuses ``GITHUB_TOKEN`` a target that differs from ``main`` in a workflow file.

        The REST docs give 404 Not Found, or on some paths 403, and the step
        fires on any Create Release failure, so it names both. Which token was
        spent decides the fix, so it reads the mint step's outcome;
        :class:`TestTheRefusalExplanation` runs both branches.
        """
        step = self.step('github', EXPLAIN_STEP)
        self.assertEqual(step.get('if'), "${{ failure() && steps.create_release.outcome == 'failure' }}")
        self.assertEqual(step.get('env'), {'PCAPKIT_VERSION': VERSION_OUTPUT, 'PCAPKIT_RUN_SHA': RUN_SHA,
                                           'PCAPKIT_APP_TOKEN_OUTCOME': '${{ steps.app_token.outcome }}'})
        for status in ('404 Not Found', "403 'Resource not accessible by integration'"):
            with self.subTest(status=status):
                self.assertIn(status, step['run'])
        # A final release is created as a draft and published by Update a release
        # in the same step (``src/github.ts:1025``); a re-run would find a draft
        # left behind and keep its target (``:636-647``).
        self.assertIn('delete any draft release', step['run'])
        self.assertGreater(self.index('github', EXPLAIN_STEP),
                           self.steps['github'].index(next(
                               s for s in self.steps['github'] if s.get('id') == 'create_release')))


class TestTheReleaseAppToken(WorkflowMixin, unittest.TestCase):
    """#1634, the owner's choice: Create Release spends a GitHub App installation token.

    Create a release's REST docs: for a target that "adds or modifies any file
    under .github/workflows/ relative to the repository's default branch",
    "GitHub App installation tokens also need the "Workflows" repository
    permission (write). The GITHUB_TOKEN available to GitHub Actions cannot be
    authorized for this". ``actions/create-github-app-token`` v3.3.0, which
    ``v3`` names: ``client-id`` "GitHub App Client ID", ``private-key``
    required, one ``permission-<name>`` input each, ``permission-workflows``
    "Can be set to 'write'" (``action.yml:8-17,51-52,147-148``), and output
    ``token``. With no ``owner`` or ``repositories``, "access will be scoped to
    only the current repository", and the token "is revoked in the ``post``
    step of the action, which means it cannot be passed to another job"
    (``README.md:389,436``). Without a ``permission-*`` input "the token
    inherits all of the installation's permissions" (``:402``), so both are
    named and nothing else is.
    """

    def create_release(self) -> 'dict[str, Any]':
        return next(step for step in self.steps['github'] if step.get('id') == 'create_release')

    def test_github_mints_with_contents_and_workflows_write_only(self) -> None:
        step = self.step('github', MINT_STEP)
        self.assertTrue(_workflows.pinned(step.get('uses'), MINT_ACTION), step.get('uses'))
        self.assertEqual({version.split('.')[0] for version in _workflows.versions(WORKFLOW, MINT_ACTION)}, {'v3'})
        self.assertEqual(step.get('id'), 'app_token')
        self.assertEqual(step.get('with'), MINT_WITH)

    def test_it_is_minted_straight_before_create_release(self) -> None:
        """Nothing runs between minting and spending the token, which lasts an hour."""
        self.assertEqual(self.index('github', MINT_STEP) + 1, self.steps['github'].index(self.create_release()))

    def test_only_create_release_spends_it(self) -> None:
        """The ``token:`` input, with no ``env:`` beside it: 3.0.2's ``parseToken``
        prefers a non-empty ``INPUT_TOKEN`` and falls back to ``GITHUB_TOKEN``
        (``src/util.ts:107-113``), so an ``env:`` token would only ever be a
        second credential handed to the action."""
        step = self.create_release()
        self.assertEqual(step.get('with', {}).get('token'), RELEASE_TOKEN)
        self.assertNotIn('env', step)
        for path in sorted(WORKFLOW.parent.glob('*.yml')):
            lines = strip_comments(path.read_text(encoding='utf-8')).splitlines()
            found = [line.strip() for line in lines if 'steps.app_token.outputs' in line]
            with self.subTest(workflow=path.name):
                self.assertEqual(found, [f'token: {RELEASE_TOKEN}'] if path == WORKFLOW else [])

    def test_without_the_variable_nothing_is_minted_and_github_token_is_spent(self) -> None:
        """An unset variable reads as "an empty string" (the ``vars`` context docs).

        A skipped step's ``outputs`` hold nothing, which is ``null`` or ``''``.
        """
        step = self.step('github', MINT_STEP)
        token = self.create_release()['with']['token']
        self.assertFalse(evaluate_condition(step['if'], {'vars': {'RELEASE_APP_CLIENT_ID': ''}}))
        self.assertTrue(evaluate_condition(step['if'], {'vars': {'RELEASE_APP_CLIENT_ID': 'Iv23example'}}))
        secrets = {'GITHUB_TOKEN': 'the run token'}
        for outputs in ({}, {'token': ''}):
            with self.subTest(outputs=outputs):
                context = {'steps': {'app_token': {'outputs': outputs}}, 'secrets': secrets}
                self.assertEqual(evaluate_expression(token, context), 'the run token')
        minted = {'steps': {'app_token': {'outputs': {'token': 'the App token'}}}, 'secrets': secrets}
        self.assertEqual(evaluate_expression(token, minted), 'the App token')

    def test_the_private_key_is_read_only_in_github_behind_its_environment(self) -> None:
        """An environment secret: "If the environment requires approval, a job cannot
        access environment secrets until one of the required reviewers approves it".

        #1660's Python Versions ``pr`` job is the one other reader, behind the same
        environment, minting the token it opens its pull request with.
        """
        readers_by_workflow = {WORKFLOW.name: ['github'], 'cron-python-versions.yml': ['pr']}
        for path in sorted(WORKFLOW.parent.glob('*.yml')):
            text = strip_comments(path.read_text(encoding='utf-8'))
            blocks = job_blocks(text, path)
            readers = sorted(job for job, block in blocks.items() if SECRET.search(block))
            with self.subTest(workflow=path.name):
                self.assertEqual(readers, readers_by_workflow.get(path.name, []))
                self.assertNotRegex(text, r'(?i)toJSON\(\s*secrets\s*\)', 'every secret, this one included')
                for job in readers:
                    self.assertEqual(declared_environment(blocks[job]), 'github-release')
        uses = [label(step) for step in self.steps['github'] if SECRET.search(repr(step))]
        self.assertEqual(uses, [MINT_STEP])
        self.assertEqual(declared_environment(job_blocks(WORKFLOW.read_text(encoding='utf-8'))['github']),
                         'github-release')


class TestTheAppsTagPushReleasesNothing(WorkflowMixin, unittest.TestCase):
    """The tag the App's token creates starts a run, unlike ``GITHUB_TOKEN``'s
    ("events triggered by the ``GITHUB_TOKEN`` ... will not create a new
    workflow run"). ``version_check`` skips it and ``release_status`` says why.

    ``github.actor_id`` is "The account ID of the person or app that triggered
    the initial workflow run"; whether this push carries the bot's is
    unmeasured, and if it does not the guard never matches.
    """

    GUARD = "!(github.event_name == 'push' && github.actor_id == vars.RELEASE_APP_BOT_ID)"
    TRIGGER = ("(github.event_name != 'workflow_run' || (github.event.workflow_run.conclusion == 'success' && "
               "github.event.workflow_run.event != 'workflow_dispatch'))")

    #: Edits a review round could make, each of which some row must catch.
    MUTATIONS = {
        'the guard is dropped': (f' && {GUARD}', ''),
        'the trigger clause loses its parentheses, so the guard binds to its right half only':
            (TRIGGER, TRIGGER[1:-1]),
        'the guard skips every bot run, not only a push': ("github.event_name == 'push' && github.actor_id",
                                                          'github.actor_id'),
        'the guard is not negated': (GUARD, GUARD[1:]),
    }

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.condition = declared_if(job_blocks(WORKFLOW.read_text(encoding='utf-8'))['version_check'])

    def runs(self, condition: 'str', **context: 'str') -> 'bool':
        return evaluate_condition(condition, gates.release_context(**context))  # type: ignore[arg-type]

    def test_the_apps_push_skips_and_everything_else_runs(self) -> None:
        bot = gates.RELEASE_APP_BOT_ID
        self.assertFalse(self.runs(self.condition, event_name='push', actor_id=bot))
        self.assertTrue(self.runs(self.condition, event_name='push'))
        self.assertTrue(self.runs(self.condition, event_name='push', release_app_bot_id=''))
        self.assertTrue(self.runs(self.condition, event_name='workflow_run', actor_id=bot))

    def test_every_mutation_changes_a_version_check_row(self) -> None:
        rows = gates.TestGateExpressionsEvaluateCorrectly.VERSION_CHECK_ROWS
        for name, (old, new) in sorted(self.MUTATIONS.items()):
            with self.subTest(mutation=name):
                self.assertIn(old, self.condition)
                mutant = self.condition.replace(old, new, 1)
                self.assertTrue([row for row, context, expected in rows
                                 if evaluate_condition(mutant, context) != expected], mutant)

    def test_release_status_reads_what_version_check_compares(self) -> None:
        """The quiet notice is the guard's own test, so the two must not drift apart."""
        step = self.step('release_status', REPORT_STEP)
        env = step['env']
        self.assertEqual(env.get('PCAPKIT_EVENT_NAME'), '${{ github.event_name }}')
        self.assertEqual(env.get('PCAPKIT_ACTOR_ID'), '${{ github.actor_id }}')
        self.assertEqual(env.get('PCAPKIT_RELEASE_APP_BOT_ID'), '${{ vars.RELEASE_APP_BOT_ID }}')
        # #1967: the step runs util/release_status.py, which compares them.
        self.assertEqual(step['run'], 'python3 util/release_status.py')
        script = (UTIL / 'release_status.py').read_text(encoding='utf-8')
        self.assertIn("if event == 'push' and var('PCAPKIT_RELEASE_APP_BOT_ID') \\\n", script)
        self.assertIn("and var('PCAPKIT_ACTOR_ID') == var('PCAPKIT_RELEASE_APP_BOT_ID'):", script)


class TestTagNeverMovesOntoMain(WorkflowMixin, unittest.TestCase):
    """``tag`` names the run's commit and touches ``main`` only to add the reset on top."""

    def scripts(self) -> 'list[tuple[str, str]]':
        return [(label(step), step['run']) for step in self.steps['tag'] if 'run' in step]

    def test_no_step_pulls_merges_rebases_or_force_pushes(self) -> None:
        for name, script in self.scripts():
            for what, pattern in sorted(FORBIDDEN_GIT.items()):
                with self.subTest(step=name, forbidden=what):
                    self.assertIsNone(pattern.search(script), f'{name!r} runs {what}')

    def test_the_scripts_are_handed_the_run_sha_and_its_version(self) -> None:
        """The scratch-repository tests inject this env themselves; only this reads the job's."""
        for name in TAG_STEPS:
            with self.subTest(step=name):
                self.assertEqual(self.step('tag', name).get('env'),
                                 {'PCAPKIT_VERSION': VERSION_OUTPUT, 'PCAPKIT_RUN_SHA': RUN_SHA})

    def test_the_conda_tag_names_the_run_commit(self) -> None:
        step = self.step('tag', 'Create Tag')
        self.assertEqual(step.get('env', {}).get('PCAPKIT_RUN_SHA'), RUN_SHA)
        self.assertIn('run_commit="$(git rev-parse --verify "${PCAPKIT_RUN_SHA}^{commit}")"', step['run'])
        tagging = [line for line in step['run'].splitlines() if re.search(r'\bgit\s+tag\b', line)]
        self.assertEqual(len(tagging), 1, tagging)
        self.assertTrue(tagging[0].rstrip().endswith('"$run_commit"'), tagging[0])

    def test_nothing_before_the_tag_reads_main(self) -> None:
        """The defect was a fast-forward onto ``main`` *before* ``git tag`` ran."""
        upto = self.index('tag', 'Create Tag')
        for step in self.steps['tag'][:upto + 1]:
            with self.subTest(step=label(step)):
                self.assertNotRegex(step.get('run', ''), r'\bmain\b')

    def test_the_scripts_take_their_inputs_through_env(self) -> None:
        """No ``${{ }}`` inside a script, which is also what lets the tests below run them."""
        for name, script in self.scripts():
            with self.subTest(step=name):
                self.assertNotIn('${{', script)

    def test_the_configure_step_only_configures(self) -> None:
        """The scratch-repository tests skip this step, so it must hold nothing else."""
        self.assertEqual(self.step('tag', 'Configure git for the deploy key')['run'].splitlines(), [
            'git remote set-url origin git@github.com:JarryShaw/PyPCAPKit.git',
            'git config --local user.email "github-actions[bot]@users.noreply.github.com"',
            'git config --local user.name "github-actions[bot]"',
        ])


class TestPublishersCheckTheirTags(WorkflowMixin, unittest.TestCase):
    """``github``, ``pypi`` and ``conda`` refuse a tag that names another commit."""

    EXPECTED_TAGS = {
        'github': f'v{VERSION_OUTPUT}',
        'pypi': f'v{VERSION_OUTPUT}',
        'conda': f'v{VERSION_OUTPUT} conda-{VERSION_OUTPUT}+0',
    }

    def test_each_publisher_checks_the_tags_it_publishes_under(self) -> None:
        for job, tags in sorted(self.EXPECTED_TAGS.items()):
            with self.subTest(job=job):
                self.assertEqual(self.step(job, CHECK_STEP).get('env'),
                                 {'PCAPKIT_TAGS': tags, 'PCAPKIT_RUN_SHA': RUN_SHA})

    def test_the_check_is_one_script(self) -> None:
        scripts = {job: self.step(job, CHECK_STEP)['run'] for job in self.EXPECTED_TAGS}
        self.assertEqual(len(set(scripts.values())), 1, 'the three copies have drifted apart')

    def test_the_check_blocks_every_leg(self) -> None:
        """#1633's KTLO legs carry ``continue-on-error`` on every other step; this one must not.

        It fails alike on every leg, and with ``continue-on-error`` a KTLO leg
        would run its later steps and publish under a tag naming another commit.
        """
        for job in sorted(self.EXPECTED_TAGS):
            with self.subTest(job=job):
                self.assertNotIn('continue-on-error', self.step(job, CHECK_STEP))

    def test_the_builders_check_before_anything_else(self) -> None:
        """Straight after the checkout, so nothing is built, let alone uploaded, first."""
        for job in ('pypi', 'conda'):
            with self.subTest(job=job):
                self.assertTrue(self.steps[job][0].get('uses', '').startswith('actions/checkout@'))
                self.assertEqual(self.index(job, CHECK_STEP), 1)

    def test_github_checks_the_tag_it_just_created(self) -> None:
        create = next(i for i, s in enumerate(self.steps['github']) if s.get('id') == 'create_release')
        self.assertEqual(self.index('github', CHECK_STEP), create + 1)


class TestUploadsStayOffUpdateARelease(WorkflowMixin, unittest.TestCase):
    """``pypi`` and ``conda`` attach files through the release-assets endpoint only.

    GitHub's REST docs state the workflow-file rule for Create a release and
    Update a release, and none for Upload a release asset. ``gh release upload``
    reads the release, then POSTs each file to its ``upload_url``
    (cli/cli 2.102.0, ``pkg/cmd/release/upload/upload.go:89-116``). Without
    ``--clobber`` it refuses a name the release already has (``:94-108``); with
    it, it deletes that asset first (``pkg/cmd/release/shared/upload.go:141-146``),
    which Delete a release asset's docs state no workflow-file rule for either.
    """

    def test_each_upload_is_a_script_with_its_inputs_in_env(self) -> None:
        for job, env in sorted(UPLOAD_ENV.items()):
            with self.subTest(job=job):
                step = self.step(job, UPLOAD_STEP)
                self.assertNotIn('uses', step)
                self.assertEqual(step.get('shell'), 'bash')
                self.assertEqual(step.get('env'), env)
                self.assertNotIn('${{', step['run'])

    def test_the_upload_is_one_script(self) -> None:
        scripts = {job: self.step(job, UPLOAD_STEP)['run'] for job in UPLOAD_ENV}
        self.assertEqual(len(set(scripts.values())), 1, 'the two copies have drifted apart')

    def test_it_only_reads_the_release_and_uploads(self) -> None:
        """No ``gh`` call that could edit the release itself, and one ``--clobber``.

        That one replaces an asset whose ``state`` is not ``uploaded``, which
        :class:`TestTheUploadScript` runs; nothing else may delete an asset.
        """
        self.assertEqual(self.step('pypi', UPLOAD_STEP)['run'], 'python3 util/release_upload.py')
        script = (UTIL / 'release_upload.py').read_text(encoding='utf-8')
        calls = re.findall(r"\bgh\('(\w+)', '(\w+)'", script)
        self.assertEqual(sorted(set(calls)), [('release', 'upload'), ('release', 'view')])
        self.assertEqual(script.count("'--clobber'"), 1)
        self.assertIn("ASSETS_JQ = '.assets[] | [.name, .state] | @tsv'", script)
        self.assertEqual(re.findall(r'subprocess\.\w+\(', script), ['subprocess.run('])

    def test_conda_uploads_whatever_check_leg_found(self) -> None:
        """Only the Anaconda upload is gated per leg.

        A leg whose Anaconda upload landed and whose GitHub upload then failed
        must still get its GitHub asset on a re-run; skipping files the release
        already has is what stops the replacement #1640 measured.
        """
        self.assertEqual(self.step('conda', UPLOAD_STEP).get('if'), "${{ matrix.os == 'ubuntu-latest' }}")
        # #2044: each Anaconda upload also names its legs.
        self.assertEqual(self.step('conda', 'Upload conda packages to Anaconda').get('if'),
                         "${{ matrix.os != 'macos-26-intel' && steps.check_leg.outputs.PCAPKIT_LEG_EXISTS != 'true' }}")
        self.assertEqual(self.step('conda', 'Upload conda packages to Anaconda (Intel)').get('if'),
                         "${{ matrix.os == 'macos-26-intel' && steps.check_leg.outputs.PCAPKIT_LEG_EXISTS != 'true' }}")


class TestEveryScriptIsHandedTheRunSha(WorkflowMixin, unittest.TestCase):
    """Whatever reads ``PCAPKIT_RUN_SHA`` reads ``github.sha``, in every job."""

    def test_every_run_sha_is_github_sha(self) -> None:
        found = {}  # type: dict[str, list[str]]
        for job, steps in sorted(self.steps.items()):
            for step in steps:
                value = step.get('env', {}).get('PCAPKIT_RUN_SHA')
                if value is None:
                    continue
                found.setdefault(job, []).append(label(step))
                with self.subTest(job=job, step=label(step)):
                    self.assertEqual(value, RUN_SHA)
        self.assertEqual(found, RUN_SHA_STEPS)

    def test_every_script_reading_it_declares_it(self) -> None:
        """Not inherited from a job- or workflow-level ``env:`` that the scan does not check."""
        for job, steps in sorted(self.steps.items()):
            for step in steps:
                if 'PCAPKIT_RUN_SHA' in step.get('run', ''):
                    with self.subTest(job=job, step=label(step)):
                        self.assertIn('PCAPKIT_RUN_SHA', step.get('env', {}))

    def test_no_expression_names_the_upstream_runs_commit(self) -> None:
        text = WORKFLOW.read_text(encoding='utf-8')
        for number, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith('#'):
                continue
            for expression in re.findall(r'\$\{\{(.*?)\}\}', line):
                with self.subTest(line=number):
                    self.assertIsNone(UPSTREAM_COMMIT.search(expression), line.strip())


GIT = shutil.which('git') or ''
BASH = shutil.which('bash') or ''


@unittest.skipIf(not GIT or not BASH, 'needs git and bash on PATH')
class ScratchRepository(WorkflowMixin, unittest.TestCase):
    """An ``origin`` that refuses non-fast-forward pushes, a seed clone that writes
    to it, and a ``work`` clone standing in for the job's detached checkout."""

    VERSION = '1.5.0b9'

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-1634-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # #1644, #1906: no automatic maintenance in any repository here, before the
        # first git command. A file, since a push to a local path strips GIT_CONFIG_*
        # from receive-pack, whose detached repack of origin otherwise deletes the
        # loose objects checkout()'s local clone is copying.
        config = self.tmp / 'gitconfig'
        config.write_text('[maintenance]\n\tauto = false\n\tautoDetach = false\n'
                          '[gc]\n\tauto = 0\n\tautoDetach = false\n'
                          '[receive]\n\tautogc = false\n', encoding='utf-8')
        self.env = {
            'PATH': os.environ.get('PATH', ''), 'HOME': str(self.tmp), 'LC_ALL': 'C',
            'GIT_CONFIG_GLOBAL': str(config), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_AUTHOR_NAME': 'test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
            'GIT_COMMITTER_NAME': 'test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
        }
        self.origin = self.tmp / 'origin.git'
        self.seed = self.tmp / 'seed'
        self.work = self.tmp / 'work'
        self.git('init', '-q', '--bare', '-b', 'main', str(self.origin))
        self.git('-C', str(self.origin), 'config', 'receive.denyNonFastForwards', 'true')
        self.git('-C', str(self.origin), 'config', 'receive.denyDeletes', 'true')
        self.git('init', '-q', '-b', 'main', str(self.seed))
        self.git('-C', str(self.seed), 'remote', 'add', 'origin', str(self.origin))

    def git(self, *args: 'str') -> 'str':
        result = subprocess.run([GIT, *args], env=self.env, capture_output=True, text=True,
                                check=False, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, f'git {" ".join(args)}: {result.stderr}')
        return result.stdout.strip()

    def commit(self, version: 'str', build: 'str', note: 'str' = '') -> 'str':
        """Commit ``__version__``/``conda/build`` (and a note) in the seed; return the sha."""
        (self.seed / 'pcapkit').mkdir(exist_ok=True)
        (self.seed / 'conda').mkdir(exist_ok=True)
        (self.seed / 'pcapkit' / '__init__.py').write_text(f"__version__ = '{version}'\n")
        (self.seed / 'conda' / 'build').write_text(build)
        (self.seed / 'NOTE').write_text(note)
        self.git('-C', str(self.seed), 'add', '-A')
        self.git('-C', str(self.seed), 'commit', '-q', '--allow-empty', '-m', f'{version} build {build} {note}')
        return self.git('-C', str(self.seed), 'rev-parse', 'HEAD')

    def push(self, sha: 'str', ref: 'str') -> None:
        self.git('-C', str(self.seed), 'push', '-q', 'origin', f'{sha}:{ref}')

    def remote(self, ref: 'str') -> 'Optional[str]':
        result = subprocess.run([GIT, '-C', str(self.origin), 'rev-parse', '-q', '--verify',
                                 f'{ref}^{{commit}}'], env=self.env, capture_output=True, text=True,
                                check=False, timeout=scale_timeout(30))
        return result.stdout.strip() or None

    def checkout(self, sha: 'str') -> None:
        """What ``actions/checkout`` leaves: every branch and tag fetched, HEAD detached at ``sha``."""
        self.git('clone', '-q', str(self.origin), str(self.work))
        self.git('-C', str(self.work), 'fetch', '-q', 'origin', '+refs/tags/*:refs/tags/*')
        self.git('-C', str(self.work), 'switch', '-q', '--detach', sha)

    def run_steps(self, job: 'str', names: 'tuple[str, ...]', env: 'dict[str, str]',
                  path: 'Optional[str]' = None) -> 'subprocess.CompletedProcess[str]':
        """Run the named steps in order, stopping at a failure: a script under ``bash -e``, a
        ``python3 util/`` command (#1967) under this interpreter.

        ``env`` stands in for each step's own ``env:``, so it must name the same
        variables; their values in the workflow are checked by the classes above.
        """
        output = []
        result = None  # type: Optional[subprocess.CompletedProcess[str]]
        for name in names:
            self.assertEqual(sorted(env), sorted(self.step(job, name).get('env', {})), name)
            script = self.tmp / 'step.sh'
            script.write_text(self.step(job, name)['run'])
            step_env = dict(self.env, **env)
            if path is not None:
                step_env['PATH'] = path + os.pathsep + step_env['PATH']
            command = script_command(self.step(job, name)['run']) or [BASH, '-e', str(script)]
            result = subprocess.run(command, cwd=self.work, env=step_env,
                                    capture_output=True, text=True, check=False,
                                    timeout=scale_timeout(60))
            output.append(result.stdout + result.stderr)
            if result.returncode:
                break
        assert result is not None
        return subprocess.CompletedProcess(result.args, result.returncode, '\n'.join(output), '')

    def test_no_git_here_starts_automatic_maintenance(self) -> None:
        """#1906: after each class's ``setUp``, a commit, pushes and :meth:`checkout` start no maintenance.

        receive-pack starts it in ``origin`` after a push, detached by default;
        on git 2.55.0 its repack deleted a loose object :meth:`checkout`'s local
        clone was copying. trace2 reaches receive-pack where ``GIT_CONFIG_*`` does not.

        """
        trace = self.tmp / 'trace2.json'
        self.env['GIT_TRACE2_EVENT'] = str(trace)
        sha = self.commit(self.VERSION, '1', 'traced')
        self.push(sha, 'refs/heads/traced')
        self.push(sha, 'refs/tags/traced')
        self.checkout(sha)
        events = [json.loads(line) for line in trace.read_text(encoding='utf-8').splitlines()]
        self.assertTrue(any('receive-pack' in ' '.join(event.get('argv', ())) for event in events
                            if event.get('event') == 'start'), 'the trace never reached receive-pack')
        started = [event['argv'] for event in events if event.get('event') == 'child_start'
                   and {'maintenance', 'gc'} & set(event.get('argv', ()))]
        self.assertEqual(started, [])


class TestTagJobScripts(ScratchRepository):
    """``tag``'s "Create Tag" then "Reset Build Number", as the job runs them."""

    STEPS = TAG_STEPS

    def release(self, run_sha: 'str', path: 'Optional[str]' = None) -> 'subprocess.CompletedProcess[str]':
        return self.run_steps('tag', self.STEPS, {'PCAPKIT_VERSION': self.VERSION, 'PCAPKIT_RUN_SHA': run_sha},
                              path)

    @property
    def conda_tag(self) -> 'str':
        return f'refs/tags/conda-{self.VERSION}+0'

    def released(self, run_sha: 'str') -> None:
        """``github``'s half: the ``v*`` tag at the run's commit."""
        self.push(run_sha, f'refs/tags/v{self.VERSION}')

    def tag_builds(self, bumps: 'dict[str, str]') -> None:
        """Conda Update's half: ``conda-<version>+N`` at the bump that wrote N."""
        for build, sha in bumps.items():
            self.push(sha, f'refs/tags/conda-{self.VERSION}+{build}')
            self.assertEqual(self.remote(f'refs/tags/conda-{self.VERSION}+{build}'), sha)

    def test_the_1634_shape_tags_the_run_commit_and_resets_mains_tip(self) -> None:
        """Run 38008819343: a bump with build 0, then three Conda Update bumps
        before approval, none tagged (#1632) -- origin has only ``conda-1.5.0b9+0``."""
        older = self.commit('1.5.0b8', '1')
        self.push(older, 'refs/tags/conda-1.5.0b8+1')
        run_sha = self.commit(self.VERSION, '0')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        for build in ('1', '2', '3'):
            tip = self.commit(self.VERSION, build)
        self.push(tip, 'refs/heads/main')
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote(self.conda_tag), run_sha)
        self.assertEqual(self.remote('refs/heads/main~1'), tip, 'the reset is not on top of the tip')
        self.assertEqual(self.git('-C', str(self.origin), 'show', 'main:conda/build'), '0')
        self.assertEqual(self.git('-C', str(self.origin), 'diff', '--name-only', tip, 'main'), 'conda/build')
        self.assertIn('conda/build reset from 3 to 0 on main', result.stdout)

    def test_a_stale_counter_at_the_tip_is_reset_on_top_of_it(self) -> None:
        """A hand-made version change that left the previous version's counter behind."""
        run_sha = self.commit(self.VERSION, '2')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote(self.conda_tag), run_sha)
        head = self.remote('refs/heads/main')
        self.assertEqual(self.remote('refs/heads/main~1'), run_sha)
        self.assertEqual(self.git('-C', str(self.origin), 'show', f'{head}:conda/build'), '0')
        self.assertEqual(self.git('-C', str(self.origin), 'diff', '--name-only', run_sha, str(head)), 'conda/build')

    def test_the_reset_is_replayed_onto_a_tip_that_kept_the_counter(self) -> None:
        run_sha = self.commit(self.VERSION, '2')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        tip = self.commit(self.VERSION, '2', 'an unrelated change')
        self.push(tip, 'refs/heads/main')
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote(self.conda_tag), run_sha)
        self.assertEqual(self.remote('refs/heads/main~1'), tip)
        self.assertEqual(self.git('-C', str(self.origin), 'show', 'main:conda/build'), '0')
        self.assertEqual(self.git('-C', str(self.origin), 'show', 'main:NOTE'), 'an unrelated change')

    def test_a_counter_whose_builds_are_tagged_is_not_rewound(self) -> None:
        """The 1634 shape once #1632 tags each bump: resetting would hand +1 out twice.

        The tags land after the checkout, so the decision reads origin, not the
        tags ``actions/checkout`` fetched.
        """
        run_sha = self.commit(self.VERSION, '0')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        bumps = {build: self.commit(self.VERSION, build) for build in ('1', '2', '3')}
        tip = bumps['3']
        self.push(tip, 'refs/heads/main')
        self.checkout(run_sha)
        self.tag_builds(bumps)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote(self.conda_tag), run_sha)
        self.assertEqual(self.remote('refs/heads/main'), tip, 'main was touched')
        self.assertIn(f'::warning title=conda/build not reset::conda-{self.VERSION} is already tagged '
                      f'at +1 +2 +3; resetting conda/build 3', result.stdout)

    def test_a_tagged_build_number_is_never_freed_at_the_run_commit(self) -> None:
        """A ``v*`` tag pushed on a Conda Update bump: its counter is tagged, so it stays."""
        self.commit(self.VERSION, '0')
        bumps = {build: self.commit(self.VERSION, build) for build in ('1', '2')}
        run_sha = bumps['2']
        self.push(run_sha, 'refs/heads/main')
        self.tag_builds(bumps)
        self.released(run_sha)
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote(self.conda_tag), run_sha)
        self.assertEqual(self.remote('refs/heads/main'), run_sha, 'main was touched')
        self.assertIn('is already tagged at +1 +2;', result.stdout)

    def test_a_tip_already_at_build_zero_is_left_alone(self) -> None:
        run_sha = self.commit(self.VERSION, '2')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        tip = self.commit(self.VERSION, '0')
        self.push(tip, 'refs/heads/main')
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote('refs/heads/main'), tip)

    def test_a_tip_on_a_later_version_is_left_alone(self) -> None:
        run_sha = self.commit(self.VERSION, '2')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        self.commit('1.5.0b10', '0')
        tip = self.commit('1.5.0b10', '2')
        self.push(tip, 'refs/heads/main')
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote('refs/heads/main'), tip)
        self.assertIn("has moved on to __version__ '1.5.0b10'", result.stdout)

    def test_a_commit_off_main_never_writes_to_main(self) -> None:
        base = self.commit('1.5.0b8', '2')
        self.push(base, 'refs/heads/main')
        run_sha = self.commit(self.VERSION, '2')
        self.push(run_sha, 'refs/heads/side')
        self.released(run_sha)
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.remote(self.conda_tag), run_sha)
        self.assertEqual(self.remote('refs/heads/main'), base)
        self.assertIn('is not on main', result.stdout)

    def test_a_push_lost_to_a_concurrent_one_is_retried_on_top_of_it(self) -> None:
        """No force: the rejected reset is rebuilt on the new tip, which survives."""
        run_sha = self.commit(self.VERSION, '2')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        racer = self.commit(self.VERSION, '2', 'pushed while the reset was in flight')
        self.checkout(run_sha)

        shim = self.tmp / 'bin'
        shim.mkdir()
        (shim / 'git').write_text(
            '#!/bin/sh\n'
            'case "$1 $*" in\n'
            '  "push "*refs/heads/main*)\n'
            '    if [ ! -e "$RACE_MARKER" ]; then\n'
            '      : > "$RACE_MARKER"\n'
            '      "$REAL_GIT" -C "$RACE_FROM" push -q origin "$RACE_SHA:refs/heads/main" || exit 99\n'
            '    fi ;;\n'
            'esac\n'
            'exec "$REAL_GIT" "$@"\n'
        )
        (shim / 'git').chmod(0o755)
        self.env.update(REAL_GIT=str(GIT), RACE_FROM=str(self.seed), RACE_SHA=racer,
                        RACE_MARKER=str(self.tmp / 'raced'))

        result = self.release(run_sha, path=str(shim))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue((self.tmp / 'raced').exists(), 'the race never happened')
        self.assertIn('push to main rejected on attempt 1', result.stdout)
        self.assertEqual(self.remote('refs/heads/main~1'), racer)
        self.assertEqual(self.git('-C', str(self.origin), 'show', 'main:conda/build'), '0')
        self.assertEqual(self.remote(self.conda_tag), run_sha)

    def test_a_rerun_keeps_a_conda_tag_already_on_the_run_commit(self) -> None:
        run_sha = self.commit(self.VERSION, '0')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        self.push(run_sha, self.conda_tag)
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('already names', result.stdout)

    def test_a_conda_tag_on_another_commit_is_never_moved(self) -> None:
        other = self.commit('1.5.0b8', '0')
        run_sha = self.commit(self.VERSION, '0')
        self.push(run_sha, 'refs/heads/main')
        self.released(run_sha)
        self.push(other, self.conda_tag)
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('::error title=conda-1.5.0b9+0 is not this run', result.stdout)
        self.assertEqual(self.remote(self.conda_tag), other)

    def test_a_release_tag_on_another_commit_stops_the_conda_tag(self) -> None:
        """What a later run sees after a release tagged elsewhere, as ``v1.5.0b9`` is."""
        run_sha = self.commit(self.VERSION, '0')
        tip = self.commit(self.VERSION, '3')
        self.push(tip, 'refs/heads/main')
        self.released(tip)
        self.checkout(run_sha)

        result = self.release(run_sha)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f'::error title=v{self.VERSION} is not this run', result.stdout)
        self.assertIsNone(self.remote(self.conda_tag))


class TestTheTagCheckScript(ScratchRepository):
    """The check ``github``, ``pypi`` and ``conda`` share, run against real tags."""

    TAGS = 'v1.5.0b9 conda-1.5.0b9+0'

    def check(self, run_sha: 'str') -> 'subprocess.CompletedProcess[str]':
        return self.run_steps('conda', (CHECK_STEP,), {'PCAPKIT_TAGS': self.TAGS, 'PCAPKIT_RUN_SHA': run_sha})

    def setUp(self) -> None:
        super().setUp()
        self.run_sha = self.commit(self.VERSION, '0')
        self.later = self.commit(self.VERSION, '3')
        self.push(self.later, 'refs/heads/main')

    def test_tags_on_the_run_commit_pass(self) -> None:
        for tag in self.TAGS.split():
            self.push(self.run_sha, f'refs/tags/{tag}')
        self.checkout(self.run_sha)
        result = self.check(self.run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_a_tag_on_another_commit_fails(self) -> None:
        self.push(self.run_sha, 'refs/tags/v1.5.0b9')
        self.push(self.later, 'refs/tags/conda-1.5.0b9+0')
        self.checkout(self.run_sha)
        result = self.check(self.run_sha)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"::error title=conda-1.5.0b9+0 is not this run's commit (#1634)::conda-1.5.0b9+0 "
                      f"resolves to '{self.later}'", result.stdout)

    def test_a_missing_tag_fails(self) -> None:
        self.push(self.run_sha, 'refs/tags/v1.5.0b9')
        self.checkout(self.run_sha)
        result = self.check(self.run_sha)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("resolves to 'no commit'", result.stdout)

    def test_a_tag_pushed_after_the_checkout_is_still_seen(self) -> None:
        """``github``'s copy runs moments after creating the tag its checkout predates."""
        self.checkout(self.run_sha)
        for tag in self.TAGS.split():
            self.push(self.run_sha, f'refs/tags/{tag}')
        result = self.check(self.run_sha)
        self.assertEqual(result.returncode, 0, result.stdout)


class TestTheOwnerStep(ScratchRepository):
    """#1748: ``owner`` reads ``elsewhere`` exactly where :data:`CHECK_STEP` would refuse a tag that exists.

    So the gates that skip on ``PCAPKIT_RELEASED_ELSEWHERE`` skip only runs the
    check would fail, and a missing tag -- which the check also refuses, but
    which ``github`` creates -- is not "elsewhere".

    """

    TAG = 'v1.5.0b9'

    def setUp(self) -> None:
        super().setUp()
        self.output = self.tmp / 'github-output'
        self.env['GITHUB_OUTPUT'] = str(self.output)
        self.run_sha = self.commit(self.VERSION, '0')
        self.later = self.commit(self.VERSION, '3')
        self.push(self.later, 'refs/heads/main')

    def owner(self, run_sha: 'str') -> 'dict[str, str]':
        self.output.write_text('', encoding='utf-8')
        result = self.run_steps('version_check', (OWNER_STEP,), {'PCAPKIT_TAG': self.TAG, 'PCAPKIT_RUN_SHA': run_sha})
        self.assertEqual(result.returncode, 0, result.stdout)
        return dict(line.split('=', 1) for line in self.output.read_text(encoding='utf-8').splitlines())

    def refused(self, run_sha: 'str') -> 'bool':
        result = self.run_steps('github', (CHECK_STEP,), {'PCAPKIT_TAGS': self.TAG, 'PCAPKIT_RUN_SHA': run_sha})
        return result.returncode != 0

    def test_the_step_is_handed_the_tag_and_the_run_sha(self) -> None:
        step = self.step('version_check', OWNER_STEP)
        self.assertEqual(step.get('id'), 'owner')
        self.assertEqual(step.get('env'), {'PCAPKIT_TAG': 'v${{ steps.get_version.outputs.PCAPKIT_VERSION }}',
                                           'PCAPKIT_RUN_SHA': RUN_SHA})
        ids = [each.get('id') for each in self.steps['version_check']]
        self.assertEqual(ids.index('owner'), ids.index('check_conda') + 1)

    def test_a_tag_on_another_commit_is_elsewhere_and_refused(self) -> None:
        """``v1.5.0b12``'s shape: tagged at ``2025da5e5``, read from a later commit."""
        self.push(self.run_sha, f'refs/tags/{self.TAG}')
        self.checkout(self.later)
        self.assertEqual(self.owner(self.later),
                         {'PCAPKIT_RELEASED_AT': self.run_sha, 'PCAPKIT_RELEASED_ELSEWHERE': 'true'})
        self.assertTrue(self.refused(self.later))

    def test_a_tag_on_this_commit_is_not_elsewhere(self) -> None:
        self.push(self.run_sha, f'refs/tags/{self.TAG}')
        self.checkout(self.run_sha)
        self.assertEqual(self.owner(self.run_sha),
                         {'PCAPKIT_RELEASED_AT': self.run_sha, 'PCAPKIT_RELEASED_ELSEWHERE': 'false'})
        self.assertFalse(self.refused(self.run_sha))

    def test_no_tag_is_not_elsewhere(self) -> None:
        """``github`` creates it, so the gates run."""
        self.checkout(self.later)
        self.assertEqual(self.owner(self.later), {'PCAPKIT_RELEASED_AT': '', 'PCAPKIT_RELEASED_ELSEWHERE': 'false'})

    def test_a_tag_pushed_after_the_checkout_is_fetched(self) -> None:
        self.checkout(self.later)
        self.push(self.run_sha, f'refs/tags/{self.TAG}')
        self.assertEqual(self.owner(self.later)['PCAPKIT_RELEASED_ELSEWHERE'], 'true')

    def test_it_resolves_the_tag_as_the_check_does(self) -> None:
        """One script's ``run_commit`` and ``resolve`` (#1967), so the two cannot read the tag differently."""
        self.assertEqual(self.step('version_check', OWNER_STEP)['run'], 'python3 util/release_tags.py owner')
        self.assertEqual(self.step('github', CHECK_STEP)['run'], 'python3 util/release_tags.py check')
        source = (UTIL / 'release_tags.py').read_text(encoding='utf-8')
        bodies = dict(re.findall(r'^def (check|owner)\(\).*\n((?:    .*\n|\n)+)', source, re.M))
        self.assertEqual(sorted(bodies), ['check', 'owner'])
        for name, body in sorted(bodies.items()):
            with self.subTest(command=name):
                self.assertEqual(body.count('run_commit()'), 1)
                self.assertEqual(body.count('resolve(tag)'), 1)
                self.assertNotIn('git(', body)

    def test_both_outputs_reach_the_jobs(self) -> None:
        block = job_blocks(WORKFLOW.read_text(encoding='utf-8'))['version_check']
        for name in ('PCAPKIT_RELEASED_AT', 'PCAPKIT_RELEASED_ELSEWHERE'):
            with self.subTest(output=name):
                self.assertIn(f'{name}: ${{{{ steps.owner.outputs.{name} }}}}', block)
                self.assertEqual(self.step('release_status', REPORT_STEP)['env'][name],
                                 f'${{{{ needs.version_check.outputs.{name} }}}}')


RELEASED_STEP = 'Read the released Python versions'
#: The tier file as #1677 added it, before the first weekly proposal, and its reader.
FIRST_TIERS = ROOT / 'tests' / 'project' / 'python_versions_fixtures' / 'python-versions.toml'
READER = ROOT / 'util' / 'python_versions.py'
#: What :data:`READER` imports from beside it (#2047).
HELPER = ROOT / 'util' / '_actions.py'
#: A ``curl`` answering 200 with ``$REPLY`` as the body it writes to ``-o``.
FAKE_CURL = '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && cp "$REPLY" "$2"; shift; done\nprintf 200\n'


@unittest.skipIf(sys.version_info < (3, 11), 'util/python_versions.py reads the tier file with tomllib, from 3.11')
class TestTheCountsAreOfTheReleasedTiers(ScratchRepository):
    """``version_check`` counts the wheels and conda builds a tagged version was released with (#1660).

    ``pre`` is tagged before the tier file existed, ``added`` adds it as #1677
    did, and ``grown`` merges the first weekly proposal, pypy3.12; the run is on
    ``grown``. Counting ``grown``'s tiers for a version tagged earlier read the
    finished release as incomplete, ran the gate and ``pypi``, and failed the
    tag check above on every run.

    """

    VERSION = '1.5.0b12'

    def setUp(self) -> None:
        super().setUp()
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        for name, text in (('python3', f'#!/bin/sh\nexec "{sys.executable}" "$@"\n'), ('curl', FAKE_CURL)):
            (self.bin / name).write_text(text, encoding='utf-8')
            (self.bin / name).chmod(0o755)
        self.env['PATH'] = f'{self.bin}{os.pathsep}{self.env["PATH"]}'
        self.output = self.tmp / 'github-output'
        self.env['GITHUB_OUTPUT'] = str(self.output)

        self.pre = self.commit(self.VERSION, '0', 'before the tier file')
        tiers = self.seed / '.github' / 'python-versions.toml'
        tiers.parent.mkdir()
        (self.seed / 'util').mkdir()
        shutil.copyfile(FIRST_TIERS, tiers)
        shutil.copyfile(READER, self.seed / 'util' / 'python_versions.py')
        # #2047: the reader imports the helper from beside it.
        shutil.copyfile(HELPER, self.seed / 'util' / '_actions.py')
        self.added = self.commit(self.VERSION, '0', 'the tier file')
        self.values = {self.added: self.read(tiers)}
        line = '"pypy3.11" = { tier = "supported" }\n'
        grown = tiers.read_text(encoding='utf-8').replace(line, line + '"pypy3.12" = { tier = "supported" }\n')
        tiers.write_text(grown, encoding='utf-8')
        self.grown = self.commit(self.VERSION, '0', 'pypy3.12 joins the supported tier')
        self.values[self.grown] = self.read(tiers)
        self.push(self.grown, 'refs/heads/main')

    @staticmethod
    def read(tiers: 'pathlib.Path') -> 'dict[str, str]':
        """``pypi-wheels`` and ``conda-builds`` as "Read the Python versions" writes them for ``tiers``."""
        names = ('pypi-wheels', 'conda-builds')
        printed = subprocess.run([sys.executable, str(READER), '--file', str(tiers), *names], capture_output=True,
                                 text=True, check=True, timeout=scale_timeout(60)).stdout
        return dict(zip(names, printed.splitlines()))

    def released(self, exists: 'bool') -> 'tuple[subprocess.CompletedProcess[str], dict[str, str]]':
        """The step, handed what this run's "Read the Python versions" and ``check_tag`` output."""
        self.output.write_text('', encoding='utf-8')
        run = self.values[self.grown]
        result = self.run_steps('version_check', (RELEASED_STEP,), {
            'PCAPKIT_TAG': f'v{self.VERSION}', 'PCAPKIT_TAG_EXISTS': str(exists).lower(),
            'PCAPKIT_PYPI_WHEELS': run['pypi-wheels'], 'PCAPKIT_CONDA_BUILDS': run['conda-builds']})
        self.assertEqual(result.returncode, 0, result.stdout)
        return result, dict(line.split('=', 1) for line in self.output.read_text(encoding='utf-8').splitlines())

    def complete(self, step: 'str', wheels: 'str', builds: 'str', reply: 'dict[str, Any]') -> 'str':
        """The completeness check ``step`` for a release ``reply`` describes, given what the step above wrote."""
        script = self.step('version_check', step)['run']
        for path in ('/tmp/pypi_release.json', '/tmp/anaconda_release.json'):
            script = script.replace(path, str(self.tmp / 'release.json'))
        (self.tmp / 'reply.json').write_text(json.dumps(reply), encoding='utf-8')
        (self.tmp / 'check.sh').write_text(script, encoding='utf-8')
        self.output.write_text('', encoding='utf-8')
        env = dict(self.env, REPLY=str(self.tmp / 'reply.json'), PCAPKIT_VERSION=self.VERSION,
                   PCAPKIT_PYPI_WHEELS=wheels, PCAPKIT_CONDA_BUILDS=builds)
        # #1967: ``python3 util/release_published.py ...``, on this interpreter.
        command = script_command(script) or [BASH, '-e', str(self.tmp / 'check.sh')]
        result = subprocess.run(command, cwd=self.tmp, env=env, capture_output=True,
                                text=True, check=False, timeout=scale_timeout(60))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        written = dict(line.split('=', 1) for line in self.output.read_text(encoding='utf-8').splitlines())
        return next(iter(written.values()))

    def test_the_checks_count_what_this_step_read(self) -> None:
        ids = [step.get('id') for step in self.steps['version_check']]
        self.assertLess(ids.index('check_tag'), ids.index('released'))
        self.assertLess(ids.index('released'), min(ids.index('check_pypi'), ids.index('check_conda')))
        self.assertEqual(self.step('version_check', RELEASED_STEP)['env'], {
            'PCAPKIT_TAG': 'v${{ steps.get_version.outputs.PCAPKIT_VERSION }}',
            'PCAPKIT_TAG_EXISTS': '${{ steps.check_tag.outputs.exists }}',
            'PCAPKIT_PYPI_WHEELS': '${{ steps.python-versions.outputs.pypi-wheels }}',
            'PCAPKIT_CONDA_BUILDS': '${{ steps.python-versions.outputs.conda-builds }}',
        })
        for step, name, output in (('Check PyPI publish completeness', 'PCAPKIT_PYPI_WHEELS', 'pypi-wheels'),
                                   ('Check Anaconda publish completeness', 'PCAPKIT_CONDA_BUILDS', 'conda-builds')):
            with self.subTest(step=step):
                self.assertEqual(self.step('version_check', step)['env'][name],
                                 f'${{{{ steps.released.outputs.{output} }}}}')
        # git log and every tag: the whole history.
        self.assertEqual(self.step('version_check', 'Checkout code')['with']['fetch-depth'], '0')

    def test_before_the_tag_this_runs_tiers_count(self) -> None:
        self.checkout(self.grown)
        _, written = self.released(exists=False)
        self.assertEqual(written, self.values[self.grown])
        self.assertIn('pp312', written['pypi-wheels'].split())

    def test_a_tag_on_this_runs_commit_counts_this_runs_tiers(self) -> None:
        self.push(self.grown, f'refs/tags/v{self.VERSION}')
        self.checkout(self.grown)
        self.assertEqual(self.released(exists=True)[1], self.values[self.grown])

    def test_a_tag_on_an_earlier_commit_counts_its_tiers(self) -> None:
        self.push(self.added, f'refs/tags/v{self.VERSION}')
        self.checkout(self.grown)
        _, written = self.released(exists=True)
        self.assertEqual(written, self.values[self.added])
        self.assertNotIn('pp312', written['pypi-wheels'].split())

    def test_a_tag_pushed_after_the_checkout_is_fetched(self) -> None:
        self.checkout(self.grown)
        self.push(self.added, f'refs/tags/v{self.VERSION}')
        self.assertEqual(self.released(exists=True)[1], self.values[self.added])

    def test_a_tag_older_than_the_tier_file_counts_the_tiers_it_was_added_with(self) -> None:
        """As ``v1.5.0b12`` (``2025da5e5``) is: tagged before #1677 (``727c0fc60``) added the file."""
        self.push(self.pre, f'refs/tags/v{self.VERSION}')
        self.checkout(self.grown)
        result, written = self.released(exists=True)
        self.assertEqual(written, self.values[self.added])
        self.assertIn(f'::notice title=Released before the tier file::v{self.VERSION} predates '
                      f'.github/python-versions.toml; counting the tiers {self.added} added it with.', result.stdout)

    def test_the_released_reader_runs_with_its_own_helper(self) -> None:
        """#2047: the reader is copied out of the tree with the helper it imports, where its commit has one."""
        self.push(self.added, f'refs/tags/v{self.VERSION}')
        self.checkout(self.grown)
        result, written = self.released(exists=True)
        self.assertEqual(written, self.values[self.added])
        self.assertNotIn('Error', result.stdout + result.stderr)

    def test_a_reader_from_before_the_helper_runs_alone(self) -> None:
        """A commit without util/_actions.py, whose reader imports nothing from it, is read as before."""
        (self.seed / 'util' / '_actions.py').unlink()
        (self.seed / 'util' / 'python_versions.py').write_text(
            "import sys\nprint({'pypi-wheels': 'cp37 cp38', 'conda-builds': 'py37 py38'}[sys.argv[-1]])\n",
            encoding='utf-8')
        older = self.commit(self.VERSION, '0', 'a reader from before the helper')
        self.push(older, f'refs/tags/v{self.VERSION}')
        self.checkout(self.grown)
        _, written = self.released(exists=True)
        self.assertEqual(written, {'pypi-wheels': 'cp37 cp38', 'conda-builds': 'py37 py38'})

    def test_a_finished_release_reads_complete_after_the_tiers_grow(self) -> None:
        """The two checks, fed the step's answer and, as before it, this run's tiers."""
        self.push(self.added, f'refs/tags/v{self.VERSION}')
        self.checkout(self.grown)
        _, written = self.released(exists=True)
        released, run = self.values[self.added], self.values[self.grown]
        files = [f'pypcapkit-{self.VERSION}-{tag}-none-any.whl' for tag in released['pypi-wheels'].split()]
        pypi = {'urls': [{'filename': name} for name in files + [f'pypcapkit-{self.VERSION}.tar.gz']]}
        conda = {'distributions': [{'attrs': {'subdir': platform, 'build': f'{build}_0'}}
                                   for platform in ('linux-64', 'osx-64', 'osx-arm64')
                                   for build in released['conda-builds'].split()]}
        step = 'Check PyPI publish completeness'
        self.assertEqual(self.complete(step, written['pypi-wheels'], '', pypi), 'true')
        self.assertEqual(self.complete(step, run['pypi-wheels'], '', pypi), 'false')
        step = 'Check Anaconda publish completeness'
        self.assertEqual(self.complete(step, '', written['conda-builds'], conda), 'true')


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestTheRefusalExplanation(WorkflowMixin, unittest.TestCase):
    """``github``'s "Explain a refused release tag", run as the job runs it."""

    #: The App's one-time setup, named whenever ``GITHUB_TOKEN`` was refused.
    SETUP = ('Contents and Workflows read and write, installed on this repository only',
             'RELEASE_APP_CLIENT_ID', 'RELEASE_APP_BOT_ID', 'github-release environment secret RELEASE_APP_PRIVATE_KEY')

    def explain(self, outcome: 'str') -> 'str':
        step = self.step('github', EXPLAIN_STEP)
        env = {'PCAPKIT_VERSION': '1.5.0b9', 'PCAPKIT_RUN_SHA': 'b6b95bc8e', 'PCAPKIT_APP_TOKEN_OUTCOME': outcome}
        self.assertEqual(sorted(env), sorted(step['env']))
        tmp = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-1634-explain-'))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / 'step.sh').write_text(step['run'])
        result = subprocess.run([BASH, '-e', str(tmp / 'step.sh')], env=dict(env, PATH=os.environ.get('PATH', '')),
                                capture_output=True, text=True, check=False, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith('::error title=Could not create v1.5.0b9 at b6b95bc8e (#1634)::'))
        return lines[0]

    def test_github_token_refused_names_the_apps_setup(self) -> None:
        """``skipped``: ``vars.RELEASE_APP_CLIENT_ID`` was unset."""
        message = self.explain('skipped')
        self.assertIn('Create Release spent GITHUB_TOKEN', message)
        for part in self.SETUP:
            with self.subTest(part=part):
                self.assertIn(part, message)
        self.assertIn('re-run this job', message)

    def test_the_apps_token_refused_names_its_permissions(self) -> None:
        message = self.explain('success')
        self.assertIn("Create Release spent the release App's token", message)
        self.assertIn('Contents and Workflows read and write and is installed on this repository', message)
        self.assertNotIn('RELEASE_APP_PRIVATE_KEY', message)


#: A stand-in for ``gh``. ``$GH_ASSETS`` holds the release's assets as
#: ``name<TAB>state`` lines; absent, there is no release, and ``release view``
#: fails as the real one does ("release not found", exit 1, measured with gh
#: 2.102.0). It answers the three ``--json``/``--jq`` pairs the workflows ask,
#: the bare-name one being the script's before ``state`` was read, and
#: ``isDraft`` from ``$GH_DRAFT``. ``release upload`` appends the file as
#: ``uploaded`` and, like the real one, refuses a name already there unless
#: ``--clobber`` deletes it first. ``$GH_FAIL`` fails any call. Anything else
#: exits 96-99.
FAKE_GH = r'''#!/bin/sh
printf '%s\n' "$*" >> "$GH_LOG"
[ -z "${GH_FAIL:-}" ] || { echo "$GH_FAIL" >&2; exit 1; }
case "$1 $2" in
  'release view')
    [ "$3 $4 $5" = "$PCAPKIT_RELEASE_TAG --repo $GITHUB_REPOSITORY" ] || exit 97
    [ -f "$GH_ASSETS" ] || { echo 'release not found' >&2; exit 1; }
    shift 5
    case "$*" in
      '--json assets --jq .assets[] | [.name, .state] | @tsv') cat "$GH_ASSETS" ;;
      '--json assets --jq .assets[].name') cut -f 1 "$GH_ASSETS" ;;
      '--json isDraft --jq .isDraft') echo "${GH_DRAFT:-false}" ;;
      *) exit 96 ;;
    esac ;;
  'release upload')
    [ "$3" = "$PCAPKIT_RELEASE_TAG" ] && [ "$5 $6" = "--repo $GITHUB_REPOSITORY" ] || exit 98
    name="$(basename "$4")"
    if [ "$#" -eq 7 ] && [ "$7" = --clobber ]; then
      awk -F '\t' -v name="$name" '$1 != name' "$GH_ASSETS" > "$GH_ASSETS.new"
      mv "$GH_ASSETS.new" "$GH_ASSETS"
    elif [ "$#" -ne 6 ]; then
      exit 98
    elif cut -f 1 "$GH_ASSETS" | grep -Fqx -e "$name"; then
      echo "asset under the same name already exists: [$name]" >&2
      exit 1
    fi
    printf '%s\tuploaded\n' "$name" >> "$GH_ASSETS" ;;
  *) exit 99 ;;
esac
'''

#: The ``--jq`` the upload script reads the release's assets with.
ASSETS_JQ = '.assets[] | [.name, .state] | @tsv'


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestTheUploadScript(WorkflowMixin, unittest.TestCase):
    """``pypi`` and ``conda``'s upload, its ``python3 util/`` command (#1967) run under this
    interpreter, against :data:`FAKE_GH`."""

    TAG = 'v1.5.0b9'
    WHEEL = 'pypcapkit-1.5.0b9-cp311-none-any.whl'
    SDIST = 'pypcapkit-1.5.0b9.tar.gz'
    CONDA = 'pypcapkit-1.5.0b9-py311_0.tar.bz2'

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-1640-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin' / 'gh').write_text(FAKE_GH)
        (self.tmp / 'bin' / 'gh').chmod(0o755)
        self.work = self.tmp / 'work'
        self.work.mkdir()
        self.assets = self.tmp / 'assets'
        self.log = self.tmp / 'log'

    def build(self, *names: 'str', folder: 'str' = 'dist') -> 'list[str]':
        (self.work / folder).mkdir(exist_ok=True)
        for name in names:
            (self.work / folder / name).write_text(name)
        return [str(self.work / folder / name) for name in names]

    def published(self, *names: 'str', state: 'str' = 'uploaded') -> None:
        """The release's assets, each in ``state``, the only one a finished upload has."""
        self.assets.write_text(''.join(f'{name}\t{state}\n' for name in names))

    def on_release(self) -> 'list[str]':
        return self.assets.read_text().splitlines()

    def upload(self, job: 'str', assets: 'Optional[str]' = None) -> 'subprocess.CompletedProcess[str]':
        """Run ``job``'s copy with its own ``PCAPKIT_ASSETS`` unless ``assets`` replaces an expression."""
        step = self.step(job, UPLOAD_STEP)
        env = {'GH_TOKEN': 'not-a-token', 'PCAPKIT_RELEASE_TAG': self.TAG,
               'PCAPKIT_ASSETS': step['env']['PCAPKIT_ASSETS'] if assets is None else assets}
        self.assertEqual(sorted(env), sorted(step['env']))
        script = self.tmp / 'step.sh'
        script.write_text(step['run'])
        env.update({
            'PATH': str(self.tmp / 'bin') + os.pathsep + os.environ.get('PATH', ''), 'HOME': str(self.tmp),
            'LC_ALL': 'C', 'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit',
            'GH_ASSETS': str(self.assets), 'GH_LOG': str(self.log),
        })
        command = script_command(step['run']) or [BASH, '--noprofile', '--norc', '-eo', 'pipefail', str(script)]
        return subprocess.run(command,
                              cwd=self.work, env=env, capture_output=True, text=True, check=False,
                              timeout=scale_timeout(60))

    def calls(self) -> 'list[str]':
        return self.log.read_text().splitlines() if self.log.exists() else []

    def expected_calls(self, *paths: 'str', clobber: 'bool' = False) -> 'list[str]':
        view = f'release view {self.TAG} --repo JarryShaw/PyPCAPKit --json assets --jq {ASSETS_JQ}'
        flag = ' --clobber' if clobber else ''
        return [view] + [f'release upload {self.TAG} {path} --repo JarryShaw/PyPCAPKit{flag}' for path in paths]

    def test_a_published_conda_package_is_left_alone(self) -> None:
        """#1640: run 38335468075 deleted and re-uploaded this file, rebuilt against live PyPI."""
        paths = self.build(self.CONDA, folder='linux-64')
        self.published(self.WHEEL, self.CONDA)
        result = self.upload('conda', '\n'.join(paths))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), self.expected_calls())
        self.assertIn(f'::notice title={self.CONDA} already on {self.TAG}::', result.stdout)
        self.assertEqual(self.on_release(), [f'{self.WHEEL}\tuploaded', f'{self.CONDA}\tuploaded'])

    def test_an_asset_left_by_a_failed_upload_is_uploaded_again(self) -> None:
        """Only ``uploaded`` is a published file.

        Upload a release asset's REST docs: "When an upstream failure occurs,
        you will receive a 502 Bad Gateway status. This may leave an empty
        asset with a state of starter. It can be safely deleted." The response
        schema's ``state`` enum is ``uploaded`` and ``open``, so both of the
        others are tried. Kept, that asset is empty under the published name.
        """
        for state in ('starter', 'open'):
            with self.subTest(state=state):
                self.log.unlink(missing_ok=True)
                paths = self.build(self.CONDA, folder='linux-64')
                self.published(self.CONDA, state=state)
                result = self.upload('conda', '\n'.join(paths))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(), self.expected_calls(*paths, clobber=True))
                self.assertIn(f"::warning title={self.CONDA} uploaded again::{self.TAG} holds it in "
                              f"state '{state}', not 'uploaded'", result.stdout)
                self.assertEqual(self.on_release(), [f'{self.CONDA}\tuploaded'])

    def test_only_the_files_the_release_lacks_go_up(self) -> None:
        """``pypi``'s own ``dist/*``: the 3.15 leg's sdist, after its wheel landed."""
        self.build(self.WHEEL, self.SDIST)
        self.published(self.WHEEL)
        result = self.upload('pypi')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), self.expected_calls(f'dist/{self.SDIST}'))
        self.assertEqual(self.on_release(), [f'{self.WHEEL}\tuploaded', f'{self.SDIST}\tuploaded'])

    def test_a_new_release_gets_every_file_in_order(self) -> None:
        paths = self.build(self.CONDA, 'pypcapkit-1.5.0b9-py312_0.tar.bz2', folder='linux-64')
        self.published()
        result = self.upload('conda', '\n'.join(paths) + '\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), self.expected_calls(*paths))

    def test_a_pattern_matching_nothing_fails(self) -> None:
        """A change from the action, which only warned: ``fail_on_unmatched_files``
        is unset here, so 3.0.2's ``src/run.ts:15-20`` logs "🤔 Pattern '…' does
        not match any files." and carries on."""
        self.published()
        result = self.upload('pypi')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error title=Nothing to upload::'dist/*' matches no file", result.stdout)
        self.assertEqual(self.calls(), self.expected_calls())

    def test_a_missing_release_fails_before_any_upload(self) -> None:
        """A change from the action, which made one: with no release for the tag,
        3.0.2 calls ``createRelease`` (``src/github.ts:617-628``) with no notes
        and ``target_commitish`` unset (``:1026``, ``src/util.ts:133``), which
        Create a release defaults to "the repository's default branch". Making
        the release is ``github``'s job, at the run's commit."""
        self.build(self.WHEEL)
        result = self.upload('pypi')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('release not found', result.stderr)
        self.assertEqual(self.calls(), self.expected_calls())


#: ``conda-dist``'s release check, the step before the action it gates.
RELEASE_CHECK_STEP = 'Check the GitHub release exists'
CONDA_RELEASE_TAG = 'v${{ needs.conda-update.outputs.PCAPKIT_VERSION }}'

#: The action's ``commit``: the default branch on :file:`cron-conda.yml`'s triggers.
DEFAULT_BRANCH = '${{ github.ref_name }}'


class CondaDistMixin(WorkflowMixin):
    """``conda-dist`` of :file:`cron-conda.yml`, and whether its GitHub upload runs."""

    workflow = CONDA_WORKFLOW

    def upload(self) -> 'dict[str, Any]':
        return self.step('conda-dist', UPLOAD_STEP)

    def runs(self, outputs: 'dict[str, str]', runner: 'str' = 'ubuntu-latest') -> 'bool':
        """Whether the action's ``if:`` lets it run, given the release check's ``outputs``."""
        return evaluate_condition(self.upload()['if'], {
            'matrix': {'os': runner}, 'steps': {'release': {'outputs': outputs}},
            'github': {'event_name': 'schedule'},
        })


class TestCondaUpdateNeverMakesTheRelease(CondaDistMixin, unittest.TestCase):
    """:file:`cron-conda.yml`'s GitHub upload only ever updates a published release.

    ``conda-dist`` attaches its packages with ``ncipollo/release-action@v1.21.0``
    and ``allowUpdates: true``, kept so #1632's ``test_cron_conda_really_does_publish``
    still finds it. That action's ``createOrUpdateRelease`` (``src/Action.ts:53-70``)
    reads the release by tag, which GitHub's REST docs give as "a published
    release"; on a 404 it updates a draft of that tag or else calls
    ``createRelease`` (``:72-92``), both with ``target_commitish: commit``
    (``:107-120``, ``src/Releases.ts:76-99,150-174``). With no release, a bump
    made while Create Release waits on its approval -- 1.5.0b9 waited three
    days, and cron-conda bumped three times meanwhile -- would put
    ``v<version>`` on ``main``'s tip, and Create Release's tag check would then
    fail. A draft stays a draft (``omitDraftDuringUpdate``,
    ``src/Inputs.ts:210-213``) but is retargeted at ``commit``; Create Release's
    ``workflow_run`` run finds the draft and resets its target to the run's sha
    (``action-gh-release`` 3.0.2's ``src/github.ts:636-646,832-866``), so
    skipping a draft is a precaution against retargeting a release Create
    Release owns. On an existing release it calls Update a release with
    ``target_commitish: commit`` (``src/Action.ts:107-120``,
    ``src/Releases.ts:150-174``), and GitHub's REST docs check "the new value of
    target_commitish if you are changing it, otherwise the existing target"
    against the workflow-file rule, which since #1634 is the run's commit.
    """

    def test_the_action_is_still_the_upload(self) -> None:
        step = self.upload()
        self.assertTrue(_workflows.pinned(step.get('uses'), 'ncipollo/release-action'), step.get('uses'))
        self.assertEqual(_workflows.versions(CONDA_WORKFLOW, 'ncipollo/release-action'), ['v1.21.0'])
        self.assertEqual(step['with'].get('allowUpdates'), 'true')
        self.assertEqual(step['with'].get('tag'), CONDA_RELEASE_TAG)

    def test_no_published_release_means_no_upload(self) -> None:
        """The action runs on ``ubuntu-latest`` only, and only once the check says ``true``."""
        self.assertFalse(self.runs({}), 'the action runs without the release check')
        self.assertFalse(self.runs({'published': 'false'}),
                         'the action runs with no published release, and would make it')
        self.assertFalse(self.runs({'published': 'true'}, runner='macos-latest'))
        self.assertTrue(self.runs({'published': 'true'}))

    def test_the_check_reads_the_release_the_action_updates(self) -> None:
        check = self.step('conda-dist', RELEASE_CHECK_STEP)
        self.assertEqual(self.index('conda-dist', RELEASE_CHECK_STEP) + 1, self.index('conda-dist', UPLOAD_STEP))
        self.assertEqual(check.get('id'), 'release')
        self.assertEqual(check.get('if'),
                         "${{ github.event_name != 'workflow_dispatch' && matrix.os == 'ubuntu-latest' }}")
        self.assertEqual(check.get('shell'), 'bash')
        self.assertEqual(check.get('env'), {'GH_TOKEN': '${{ secrets.GITHUB_TOKEN }}',
                                            'PCAPKIT_RELEASE_TAG': CONDA_RELEASE_TAG})
        self.assertNotIn('${{', check['run'])

    def test_the_anaconda_upload_is_not_gated_on_it(self) -> None:
        # #2044: gated on the leg alone; #2060: Windows publishes nothing.
        # A manual run uploads nothing (tests/project/test_build_only_dispatch.py).
        self.assertEqual(self.step('conda-dist', 'Upload conda packages to Anaconda').get('if'),
                         "${{ github.event_name != 'workflow_dispatch' && "
                         "matrix.os != 'macos-26-intel' && matrix.os != 'windows-latest' }}")
        self.assertEqual(self.step('conda-dist', 'Upload conda packages to Anaconda (Intel)').get('if'),
                         "${{ github.event_name != 'workflow_dispatch' && matrix.os == 'macos-26-intel' }}")

    def test_an_update_targets_the_default_branch(self) -> None:
        """``github.ref_name`` is the default branch on this workflow's triggers.

        "Events that trigger workflows" gives ``GITHUB_REF`` as "Default branch"
        for both ``schedule`` and ``workflow_run``, so the triggers are pinned
        too: another one could name another ref. ``workflow_dispatch`` does, the
        dispatched branch, so the upload never runs on it.
        """
        self.assertEqual(self.upload()['with'].get('commit'), DEFAULT_BRANCH)
        lines = CONDA_WORKFLOW.read_text(encoding='utf-8').splitlines()
        start = lines.index('on:') + 1
        end = next(i for i in range(start, len(lines)) if lines[i] and not lines[i].startswith((' ', '#')))
        triggers = [m.group(1) for line in lines[start:end] for m in [re.match(r'^  ([a-z_]+):', line)] if m]
        self.assertEqual(triggers, ['schedule', 'workflow_run', 'workflow_dispatch'])
        self.assertFalse(evaluate_condition(self.upload()['if'], {
            'matrix': {'os': 'ubuntu-latest'}, 'steps': {'release': {'outputs': {'published': 'true'}}},
            'github': {'event_name': 'workflow_dispatch'},
        }))


#: A ``gh`` failing as it does without a token, for the check's other branch.
GH_AUTH_ERROR = 'HTTP 401: Bad credentials (https://api.github.com/graphql)'


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestTheReleaseCheckScript(CondaDistMixin, unittest.TestCase):
    """``conda-dist``'s check, run as ``shell: bash`` runs it against :data:`FAKE_GH`,
    and the action's ``if:`` evaluated on what it outputs."""

    TAG = 'v1.5.0b9'

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-1634-conda-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin' / 'gh').write_text(FAKE_GH)
        (self.tmp / 'bin' / 'gh').chmod(0o755)
        self.assets = self.tmp / 'assets'
        self.output = self.tmp / 'output'
        self.log = self.tmp / 'log'

    def check(self, **env: 'str') -> 'tuple[subprocess.CompletedProcess[str], dict[str, str]]':
        step = self.step('conda-dist', RELEASE_CHECK_STEP)
        script = self.tmp / 'step.sh'
        script.write_text(step['run'])
        env.update({
            'GH_TOKEN': 'not-a-token', 'PCAPKIT_RELEASE_TAG': self.TAG,
            'PATH': str(self.tmp / 'bin') + os.pathsep + os.environ.get('PATH', ''), 'HOME': str(self.tmp),
            'TMPDIR': str(self.tmp), 'LC_ALL': 'C', 'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit',
            'GITHUB_OUTPUT': str(self.output), 'GH_ASSETS': str(self.assets), 'GH_LOG': str(self.log),
        })
        result = subprocess.run([BASH, '--noprofile', '--norc', '-eo', 'pipefail', str(script)],
                                cwd=self.tmp, env=env, capture_output=True, text=True, check=False,
                                timeout=scale_timeout(60))
        lines = self.output.read_text().splitlines() if self.output.exists() else []
        return result, {key: value for key, _, value in (line.partition('=') for line in lines)}

    def assert_viewed_once(self) -> None:
        self.assertEqual(self.log.read_text().splitlines(),
                         [f'release view {self.TAG} --repo JarryShaw/PyPCAPKit --json isDraft --jq .isDraft'])

    def test_no_release_skips_the_github_upload(self) -> None:
        result, outputs = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(outputs, {'published': 'false'})
        self.assertFalse(self.runs(outputs), 'the action would run, and create the release at main')
        self.assertIn(f'::notice title=No GitHub upload for {self.TAG}::{self.TAG} does not exist, and the '
                      "upload would create it, tagging main's tip. Create Release makes it", result.stdout)
        self.assert_viewed_once()

    def test_a_draft_skips_the_github_upload(self) -> None:
        """What a refused final release leaves behind, until it is deleted."""
        self.assets.write_text('')
        result, outputs = self.check(GH_DRAFT='true')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(outputs, {'published': 'false'})
        self.assertFalse(self.runs(outputs), 'the action would run, and retarget the draft at main')
        self.assertIn(f'::notice title=No GitHub upload for {self.TAG}::{self.TAG} is a draft, which the '
                      'upload would retarget at main. Create Release makes it', result.stdout)

    def test_a_published_release_is_uploaded_to(self) -> None:
        """With ``commit`` the default branch, so Update a release resolves ``main``."""
        self.assets.write_text('')
        result, outputs = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(outputs, {'published': 'true'})
        self.assertNotIn('::notice', result.stdout)
        self.assertTrue(self.runs(outputs))
        self.assertEqual(self.upload()['with'].get('commit'), DEFAULT_BRANCH)
        self.assert_viewed_once()

    def test_any_other_failure_fails_the_step(self) -> None:
        """Not read as "no release": that would skip a GitHub upload that was owed."""
        result, outputs = self.check(GH_FAIL=GH_AUTH_ERROR)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(outputs, {})
        self.assertIn(GH_AUTH_ERROR, result.stderr)
        self.assertIn(f'::error title=Could not read {self.TAG}::gh release view exited 1.', result.stdout)


class TestYAMLAgreesWithTheScanner(WorkflowMixin, unittest.TestCase):
    """The hand-rolled scanner against :func:`yaml.safe_load`, where PyYAML is installed."""

    def test_the_same_steps(self) -> None:
        self.assert_the_same_steps(WORKFLOW, self.steps, every_job=True)

    def test_the_same_conda_dist_steps(self) -> None:
        """The one job of :file:`cron-conda.yml` read here."""
        steps = workflow_steps(CONDA_WORKFLOW.read_text(encoding='utf-8'))
        self.assert_the_same_steps(CONDA_WORKFLOW, {'conda-dist': steps['conda-dist']})

    def assert_the_same_steps(self, workflow: 'pathlib.Path', steps: 'dict[str, list[dict[str, Any]]]',
                              every_job: 'bool' = False) -> None:
        try:
            import yaml  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.skipTest('PyYAML is not installed (the `test` extra)')
        jobs = yaml.safe_load(workflow.read_text(encoding='utf-8'))['jobs']
        if every_job:
            self.assertEqual(sorted(steps), sorted(jobs))
        for job in sorted(steps):
            expected = jobs[job].get('steps', [])
            scanned = steps[job]
            with self.subTest(job=job):
                self.assertEqual([label(step) for step in scanned], [label(step) for step in expected])
                for mine, theirs in zip(scanned, expected):
                    for key in ('uses', 'id', 'if', 'run'):
                        self.assertEqual(mine.get(key), theirs.get(key), f'{label(theirs)}: {key}')
                    for key in ('ref', 'target_commitish', 'commit', 'token', *MINT_WITH):
                        self.assertEqual(mine.get('with', {}).get(key), theirs.get('with', {}).get(key),
                                         f'{label(theirs)}: with.{key}')
                    self.assertEqual(mine.get('env', {}), {k: str(v) for k, v in theirs.get('env', {}).items()},
                                     f'{label(theirs)}: env')


if __name__ == '__main__':
    unittest.main()
