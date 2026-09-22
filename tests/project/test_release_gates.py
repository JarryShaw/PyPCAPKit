# -*- coding: utf-8 -*-
"""Tests that nothing in :file:`.github/workflows/create-release.yml` publishes ungated.

#641: the ``pypi`` job's ``environment: release`` was commented out while the
``id-token: write`` from the same upstream snippet had been re-added live below it,
and the ``conda`` job never had an ``environment:`` at all. A scheduled vendor crawl
that bumps the version is enough to enter that workflow, so both package indexes
were reachable with no human in the path.

What makes that worth a test rather than just a fix is how quietly it came about.
Nothing about a missing ``environment:`` line fails, warns, or shows up in a run's
output -- the job simply runs -- and the line that was missing sat inside a
commented block that read as though it had been disabled deliberately and as a
unit. So the regression is invisible by construction, and the only thing that can
notice it is an assertion over the file.

The rule asserted here is not a copy of the current file: **any job in that
workflow which runs a publishing action or pushes to git must declare an
``environment:``.** Stated that way it also catches a *new* publishing job added
later without a gate, and a job renamed or reordered.

Be clear about how far that generalises, though, because it is easy to overstate.
:data:`PUBLISHING_MARKERS` is what decides "publishing", and it is a finite,
hand-maintained list of four substrings. So the rule generalises across job
*identity* and not across publishing *mechanism*: a job uploading by some route
none of those four names -- ``twine upload``, ``gh release upload``, a fork of a
pinned action under another name, a ``curl`` straight at an index -- matches no
marker, and would pass this test while genuinely ungated.
:class:`TestMarkersStillMatch` only keeps the existing four from going blind; it
cannot invent a fifth. Adding a publishing route to this workflow therefore means
adding its marker here, and that is a maintenance obligation rather than something
the test enforces.

Two things this deliberately does **not** test, because it cannot:

* **Whether the environments exist, and whether they have required reviewers.**
  That is repository settings, not repository content, and an ``environment:``
  naming an environment that does not exist is created implicitly with no
  protection rules -- so the workflow half passing here is necessary and not
  sufficient. The check needs an authenticated ``GET
  /repos/{owner}/{repo}/environments``, which a unit-tier test may not make: the
  tier runs on a fresh clone with no network and no token. It is written down in
  the workflow's own comment and in #641 instead.
* **Whether GitHub requests one approval per environment or one per matrix leg.**
  ``pypi`` is a 7-leg matrix and ``conda`` a 10-leg one. That is a property of the
  Actions runner, observable only from a real run.

:mod:`yaml` is not in the ``test`` extra, so the scanner in this module is
hand-rolled and dependency-free, and :class:`TestYAMLAgreesWithTheScanner` checks
it against :func:`yaml.safe_load` only when PyYAML happens to be installed. The
same split as ``test_the_rewritten_date_is_a_string_and_not_a_yaml_date`` in
:file:`tests/project/test_bump_version.py`: the assertion that must run everywhere
does not need the dependency, and the one that needs it guards the substitute.

"""

from __future__ import annotations

import pathlib
import re
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The workflow under test. The only one that publishes: :file:`cron-conda.yml`
#: and :file:`cron-vendor.yml` build and commit but upload nothing, and
#: :file:`deploy-pages.yml` publishes documentation rather than a package, which is
#: a separate question from #641 and is not gated here.
WORKFLOW = ROOT / '.github' / 'workflows' / 'create-release.yml'

#: Strings whose presence in a job means that job has an effect outside the run,
#: each mapped to what it does, so a failure can say *why* the job needed a gate.
#:
#: Matched as substrings of the job's source with comments stripped, which is
#: coarse on purpose -- an action pinned to a different version, or reached through
#: a different input, still matches. ``git push`` is here because the ``tag`` job's
#: write to ``main`` does not go through an action at all, and its ``permissions:
#: {}`` makes the job look inert while the deploy key it loads does the writing.
#:
#: **Extend this when a new publishing route is added to the workflow.** Being an
#: allowlist, it is silent about a mechanism it does not name -- see the limitation
#: spelled out in this module's docstring.
PUBLISHING_MARKERS = {
    'pypa/gh-action-pypi-publish': 'uploads a distribution to PyPI or TestPyPI',
    'anaconda/actions/upload-package': 'uploads a package to anaconda.org',
    'softprops/action-gh-release': 'creates a public GitHub Release, and the tag it names',
    'git push': 'pushes a commit or a tag to the repository',
}

#: A top-level job header, i.e. a mapping key at two spaces of indent.
_JOB_HEADER = re.compile(r'^ {2}([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(?:#.*)?$')
#: A job-level ``environment:`` key, i.e. at four spaces of indent. A commented
#: ``#environment:`` cannot match this, which is the whole point -- that is the
#: exact shape #641 was.
_ENVIRONMENT = re.compile(r'^ {4}environment:[ \t]*(.*)$')
#: The ``name:`` of an ``environment:`` written in its mapping form.
_ENVIRONMENT_NAME = re.compile(r'^ {6}name:[ \t]*(\S+)')


def strip_comments(text: 'str') -> 'str':
    """``text`` with YAML comments removed, for substring matching only.

    Naive -- it would also cut a ``#`` inside a scalar -- and that is acceptable
    here because the result is never parsed, only searched for the literals in
    :data:`PUBLISHING_MARKERS`. Doing it at all matters: without it, a comment
    *explaining* why a job is gated would count as evidence that it publishes.

    """
    return '\n'.join(re.sub(r'(?:(?<=\s)|^)#.*$', '', line) for line in text.splitlines())


def job_blocks(text: 'str') -> 'dict[str, str]':
    """``{job name: the job's own lines}`` for a workflow's top-level ``jobs:``.

    Indentation-based rather than a YAML parse, so that this module keeps working
    on a fresh clone where PyYAML is not installed.
    :class:`TestYAMLAgreesWithTheScanner` is what stops the two from drifting.

    """
    lines = text.splitlines()

    try:
        start = next(i for i, line in enumerate(lines) if line.rstrip() == 'jobs:')
    except StopIteration:
        raise AssertionError(f'no top-level `jobs:` mapping found in {WORKFLOW}') from None

    blocks = {}  # type: dict[str, list[str]]
    current = None  # type: Optional[str]
    for line in lines[start + 1:]:
        stripped = line.strip()
        # A blank line or a comment belongs to whatever block is open; neither
        # carries indentation that can be trusted to end one.
        if stripped and not stripped.startswith('#') and not line.startswith('  '):
            break  # dedented back to a top-level key, so `jobs:` is over

        header = _JOB_HEADER.match(line)
        if header is not None:
            current = header.group(1)
            blocks[current] = []
            continue
        if current is not None:
            blocks[current].append(line)

    return {name: '\n'.join(body) for name, body in blocks.items()}


def declared_environment(block: 'str') -> 'Optional[str]':
    """The environment a job block declares, or :data:`None` for an ungated job.

    Handles both spellings: ``environment: pypi`` and the mapping form that
    carries a ``url:`` alongside its ``name:``.

    """
    lines = block.splitlines()
    for index, line in enumerate(lines):
        match = _ENVIRONMENT.match(line)
        if match is None:
            continue

        inline = match.group(1).split('#')[0].strip()
        if inline:
            return inline.strip('\'"')

        for nested in lines[index + 1:]:
            name = _ENVIRONMENT_NAME.match(nested)
            if name is not None:
                return name.group(1).strip('\'"')
            if nested.strip() and not nested.startswith(' ' * 6):
                break
        raise AssertionError(f'`environment:` declared with no name:\n{line!r}')
    return None


def publishing_reasons(block: 'str') -> 'list[str]':
    """Why this job has an effect outside the run, empty when it has none."""
    body = strip_comments(block)
    return [reason for marker, reason in sorted(PUBLISHING_MARKERS.items()) if marker in body]


class WorkflowMixin:
    """Reads and scans the workflow once per test."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding='utf-8')  # type: ignore[attr-defined]
        cls.jobs = job_blocks(cls.text)  # type: ignore[attr-defined]


class TestPublishingJobsAreGated(WorkflowMixin, unittest.TestCase):
    """The rule #641 asks for: publish, and you declare an environment."""

    def test_the_scan_found_the_jobs(self) -> None:
        """A scanner that finds nothing would pass every test below it."""
        self.assertEqual(
            sorted(self.jobs),
            ['conda', 'github', 'pypi', 'tag', 'unit-tests', 'version_check'],
            'the job list moved; if that is intended, the expectations in this '
            'module need revisiting rather than this line being updated alone',
        )

    def test_every_publishing_job_declares_an_environment(self) -> None:
        """No job may reach PyPI, Anaconda, a Release or a git push unapproved.

        An ``environment:`` is the only thing in Actions that will hold a job for
        a human. Without one the job runs the moment its ``needs:`` are met, which
        for this workflow means "whenever a version bump lands".

        """
        ungated = {
            name: reasons
            for name, block in self.jobs.items()
            if (reasons := publishing_reasons(block)) and declared_environment(block) is None
        }
        self.assertEqual(
            ungated, {},
            'these jobs publish with no `environment:`, so nothing holds them for '
            'approval: ' + '; '.join(
                f'{name} ({", ".join(reasons)})' for name, reasons in sorted(ungated.items())
            ),
        )

    def test_the_gated_jobs_are_the_publishing_ones(self) -> None:
        """Stated the other way round, so a gate on the wrong job is visible too."""
        gated = {name for name, block in self.jobs.items()
                 if declared_environment(block) is not None}
        publishing = {name for name, block in self.jobs.items() if publishing_reasons(block)}
        self.assertEqual(gated, publishing)
        self.assertEqual(gated, {'github', 'tag', 'pypi', 'conda'})


class TestEnvironmentsAreNotShared(WorkflowMixin, unittest.TestCase):
    """One environment per target, which is a decision and not an accident."""

    def test_each_gated_job_has_its_own_environment(self) -> None:
        """Approval is granted to an environment, so sharing one merges two gates.

        A single ``release`` environment approved once releases PyPI *and*
        Anaconda, which is the outcome #641's fix is supposed to prevent rather
        than rename. Different credentials reach the two indexes -- OIDC trusted
        publishing and ``ANACONDA_TOKEN`` -- and ``tag``'s write to ``main`` uses a
        third, so each gets an approval that can be refused on its own.

        """
        environments = {}  # type: dict[str, list[str]]
        for name, block in sorted(self.jobs.items()):
            environment = declared_environment(block)
            if environment is not None:
                environments.setdefault(environment, []).append(name)

        shared = {env: jobs for env, jobs in environments.items() if len(jobs) > 1}
        self.assertEqual(
            shared, {},
            'these environments gate more than one job, so one approval releases '
            f'all of them: {shared}',
        )

    def test_pypi_and_anaconda_are_separate(self) -> None:
        """Named explicitly, because these two are the ones #641 is about."""
        pypi = declared_environment(self.jobs['pypi'])
        anaconda = declared_environment(self.jobs['conda'])
        self.assertIsNotNone(pypi)
        self.assertIsNotNone(anaconda)
        self.assertNotEqual(pypi, anaconda)


class TestMarkersStillMatch(WorkflowMixin, unittest.TestCase):
    """:data:`PUBLISHING_MARKERS` has to keep matching the file it describes."""

    def test_each_marker_matches_at_least_one_job(self) -> None:
        """A marker that matches nothing is a rule that has stopped being checked.

        This is the failure mode of the test above: bump ``action-gh-release`` to a
        fork under another name, or replace the ``git push`` with an action, and
        ``test_every_publishing_job_declares_an_environment`` keeps passing while
        checking less. Better to fail here, where the message says which marker
        went stale.

        """
        bodies = {name: strip_comments(block) for name, block in self.jobs.items()}
        unmatched = [marker for marker in PUBLISHING_MARKERS
                     if not any(marker in body for body in bodies.values())]
        self.assertEqual(
            unmatched, [],
            'these publishing markers no longer match any job, so they are '
            f'checking nothing: {unmatched}',
        )

    def test_the_test_gate_is_not_mistaken_for_a_publisher(self) -> None:
        """``unit-tests`` and ``version_check`` have no outward effect.

        ``unit-tests`` could not carry an ``environment:`` even if it wanted one --
        a job that calls a reusable workflow may not declare one -- so a marker
        broad enough to match it would make the rule unsatisfiable.

        """
        for name in ('unit-tests', 'version_check'):
            with self.subTest(job=name):
                self.assertEqual(publishing_reasons(self.jobs[name]), [])


class TestScannerRecognisesTheDefect(unittest.TestCase):
    """The scanner, against the shape #641 actually had.

    Unlike everything above, these read a fixture rather than the repository, so
    they keep pinning the defect after the file has moved on.

    """

    #: The ``pypi`` job as #641 found it, trimmed to the keys that matter.
    COMMENTED_OUT = (
        'jobs:\n'
        '  pypi:\n'
        '    runs-on: ubuntu-latest\n'
        '    ## Specifying a GitHub environment is optional, but strongly encouraged\n'
        '    #environment: release\n'
        '    #permissions:\n'
        '    #  # IMPORTANT: this permission is mandatory for trusted publishing\n'
        '    #  id-token: write\n'
        '    permissions:\n'
        '      contents: write\n'
        '      id-token: write\n'
        '    steps:\n'
        '      - name: Publish to PyPI\n'
        '        uses: pypa/gh-action-pypi-publish@release/v1\n'
    )

    def test_a_commented_environment_is_not_a_gate(self) -> None:
        """``#environment: release`` is prose, and must read as ungated."""
        block = job_blocks(self.COMMENTED_OUT)['pypi']

        self.assertIsNone(declared_environment(block))
        self.assertEqual(publishing_reasons(block),
                         ['uploads a distribution to PyPI or TestPyPI'])

    def test_an_explaining_comment_is_not_evidence_of_publishing(self) -> None:
        """The converse: a comment naming an action does not make a job publish."""
        block = job_blocks(
            'jobs:\n'
            '  notes:\n'
            '    runs-on: ubuntu-latest\n'
            '    # Unlike softprops/action-gh-release, this uploads nothing.\n'
            '    steps:\n'
            '      - run: echo hello\n'
        )['notes']

        self.assertEqual(publishing_reasons(block), [])

    def test_the_mapping_form_of_environment_is_read(self) -> None:
        """``environment:`` with a nested ``name:`` and ``url:`` is still a gate."""
        block = job_blocks(
            'jobs:\n'
            '  pypi:\n'
            '    environment:\n'
            '      name: pypi\n'
            '      url: https://pypi.org/p/pypcapkit\n'
            '    steps:\n'
            '      - uses: pypa/gh-action-pypi-publish@release/v1\n'
        )['pypi']

        self.assertEqual(declared_environment(block), 'pypi')

    def test_a_quoted_inline_environment_is_read(self) -> None:
        block = job_blocks(
            'jobs:\n'
            '  pypi:\n'
            "    environment: 'pypi'  # quoted, and with a trailing comment\n"
        )['pypi']

        self.assertEqual(declared_environment(block), 'pypi')

    def test_jobs_end_at_the_next_top_level_key(self) -> None:
        """A key after ``jobs:`` is not a job, however tempting its name."""
        blocks = job_blocks(
            'jobs:\n'
            '  build:\n'
            '    runs-on: ubuntu-latest\n'
            'environment: not-a-job\n'
        )

        self.assertEqual(sorted(blocks), ['build'])


class TestYAMLAgreesWithTheScanner(WorkflowMixin, unittest.TestCase):
    """The hand-rolled scan has to say what a real YAML parse says."""

    def test_the_same_job_to_environment_mapping(self) -> None:
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML is not in the test extra; the textual scan is '
                          'asserted by TestPublishingJobsAreGated')

        parsed = yaml.safe_load(self.text)
        self.assertIsInstance(parsed, dict, 'the workflow is not a YAML mapping')

        expected = {name: job.get('environment')
                    for name, job in parsed['jobs'].items()}
        scanned = {name: declared_environment(block) for name, block in self.jobs.items()}

        self.assertEqual(scanned, expected,
                         'the indentation-based scanner and yaml.safe_load disagree '
                         'about which jobs are gated')


if __name__ == '__main__':
    unittest.main()
