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
  ``pypi`` is a 7-leg matrix and ``conda`` a 10-leg one. That is a property of
  the Actions runner, observable only from a real run -- and now moot for both,
  since #887 removed their required reviewers. The question would resurface
  only if a matrix job were gated by its own environment again.

:mod:`yaml` is not in the ``test`` extra, so the scanner in this module is
hand-rolled and dependency-free, and :class:`TestYAMLAgreesWithTheScanner` checks
it against :func:`yaml.safe_load` only when PyYAML happens to be installed. The
same split as ``test_the_rewritten_date_is_a_string_and_not_a_yaml_date`` in
:file:`tests/project/test_bump_version.py`: the assertion that must run everywhere
does not need the dependency, and the one that needs it guards the substitute.

#888: every job past ``version_check`` used to share one guard -- "the ``v*``
tag exists" -- as a proxy for "this version was already published", which
diverges exactly when a release half-completes and made every downstream job
skip silently while the run reported green. :class:`TestEvidenceBasedGating`
below asserts the fix: ``tag``, ``pypi`` and ``conda`` each read their own
evidence instead of that shared tag, and -- the part that is easy to get
subtly wrong -- their ``if:`` conditions bypass GitHub's default status check
explicitly (``!cancelled()``) rather than relying on evidence alone, because a
job whose ``needs:`` includes a legitimately-skipped predecessor is skipped
before its own ``if:`` is even evaluated otherwise. :func:`declared_if` is
what makes an ``if:`` condition -- including the multi-line, folded-scalar
form this fix introduces -- checkable the same coarse, textual way the rest of
this module already checks ``environment:`` and ``needs:``.

A cross-review of the #888 change (PR #905) found two defects that every test
above -- being a string assertion over the YAML -- was structurally unable to
catch, because none of them executed anything the workflow itself executes:

* **``release_status``'s branch logic demanded uniformity across all four
  release jobs**, reading a self-heal -- ``github``/``tag`` legitimately
  skipping because their artefacts already exist, ``pypi``/``conda`` running
  and succeeding because theirs did not -- as the stranded-partial shape #888
  is about, and erroring on the very run that fixed it.
  :class:`TestReleaseStatusScriptExecutesCorrectly` actually runs the
  extracted shell script, over a table of the shapes a real run can take,
  and checks which branch each one takes -- the uniformity bug fails exactly
  the self-heal row.
* **The ``python3 -c`` snippets computing PyPI/Anaconda evidence had their
  source indented**, which only ``compile()``s on Python 3.14 -- every
  interpreter from 3.9 through 3.13 raises ``IndentationError: unexpected
  indent`` on the leading whitespace the surrounding YAML block scalar's own
  indentation forces onto it, measured directly against each one. Two of the
  three snippets run before ``actions/setup-python`` even installs a chosen
  version, so ``python3`` there is whatever the runner image ships by
  default -- 3.12 on ``ubuntu-latest`` as of writing, never 3.14.
  :class:`TestPythonSnippetsSurviveOlderInterpreters` extracts each snippet
  and actually runs it under an interpreter older than 3.14 when one can be
  found on ``PATH``, skipping otherwise -- ``compile()`` under whatever
  interpreter happens to be running this test suite proves nothing when that
  interpreter is 3.14 itself, which is exactly how both defects shipped
  despite every earlier test in this module passing.

"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
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
#: A job-level ``needs:`` key written as a single-line inline list, i.e.
#: ``needs: [ a, b ]``. The only form this workflow uses -- confirmed by
#: :class:`TestYAMLAgreesWithTheScanner` -- so, like :data:`PUBLISHING_MARKERS`,
#: extending it to the multi-line ``needs:\n  - a`` form is a maintenance
#: obligation for whoever adds one, not something this scan infers.
_NEEDS = re.compile(r'^ {4}needs:[ \t]*\[([^\]]*)\][ \t]*(?:#.*)?$')
#: A job-level ``if:`` key, either inline (``if: ${{ ... }}``) or opening a
#: folded block scalar (``if: >-``, continued below at six spaces). #888
#: introduced the second form, since ``tag``/``pypi``/``conda``'s conditions
#: grew past one comfortable line; :func:`declared_if` handles both.
_IF = re.compile(r'^ {4}if:[ \t]*(.*)$')


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


def declared_needs(block: 'str') -> 'list[str]':
    """The job names in this job's ``needs: [ ... ]`` list, empty if it has none.

    ``unit-tests`` has no ``needs:`` at all and correctly returns ``[]`` rather
    than raising, since it is the root of the graph this module walks.

    """
    for line in block.splitlines():
        match = _NEEDS.match(line)
        if match is not None:
            return [name.strip() for name in match.group(1).split(',') if name.strip()]
    return []


def declared_if(block: 'str') -> 'str':
    """The job's own ``if:`` condition, flattened to one line; ``''`` if it has none.

    Handles both the single-line ``if: ${{ ... }}`` form used elsewhere in this
    file and the folded block-scalar form (``if: >-``, continued below at six
    spaces) #888 introduces for ``tag``, ``pypi`` and ``conda``, whose
    conditions grew past one line. Folding is exactly what YAML itself does to
    a ``>``/``>-`` scalar -- join each continuation line with a single space --
    so flattening it the same way here reproduces a real parse rather than
    approximating one; :class:`TestYAMLAgreesWithTheScanner` is what checks
    that claim against :func:`yaml.safe_load` when it is installed.

    """
    lines = block.splitlines()
    for index, line in enumerate(lines):
        match = _IF.match(line)
        if match is None:
            continue

        inline = match.group(1).split('#')[0].strip()
        if inline and inline not in ('>', '>-', '|', '|-'):
            return inline

        parts = []
        for nested in lines[index + 1:]:
            if nested.strip() and not nested.startswith(' ' * 6):
                break
            if nested.strip():
                parts.append(nested.strip())
        return ' '.join(parts)
    return ''


def needs_closure(jobs: 'dict[str, str]', name: str) -> 'set[str]':
    """Every job ``name`` depends on, directly or transitively.

    A plain graph walk over :func:`declared_needs`, not a topological sort --
    nothing here needs an order, only membership. A dependency that is not a
    key of ``jobs`` (there is none in this workflow, but a rename could produce
    one) is walked as if it declared no ``needs:`` of its own, rather than
    raising, so a scanner bug surfaces as a missing closure member instead of
    an exception unrelated to what the caller is checking.

    """
    seen = set()  # type: set[str]
    stack = list(declared_needs(jobs[name]))
    while stack:
        dep = stack.pop()
        if dep in seen:
            continue
        seen.add(dep)
        stack.extend(declared_needs(jobs.get(dep, '')))
    return seen


def publishing_reasons(block: 'str') -> 'list[str]':
    """Why this job has an effect outside the run, empty when it has none."""
    body = strip_comments(block)
    return [reason for marker, reason in sorted(PUBLISHING_MARKERS.items()) if marker in body]


#: A job-level ``run:`` key opening a literal block scalar (``run: |``), at
#: whatever indent the step it belongs to happens to sit -- unlike
#: :data:`_ENVIRONMENT`/:data:`_NEEDS`/:data:`_IF`, this one is not pinned to
#: a fixed column, since a step's ``run:`` is one level deeper than a job's
#: own keys and this module has no reason to otherwise care how deep.
_RUN_LITERAL = re.compile(r'^(\s*)run:\s*\|\s*$')


def block_scalar_after(block: 'str', key: 're.Pattern[str]') -> 'str':
    """The dedented body of the literal block scalar (``|``) opened by the
    first line in ``block`` matching ``key``.

    Only used for :data:`_RUN_LITERAL` against ``release_status``, which has
    exactly one step and therefore exactly one ``run:`` -- ambiguous for a
    job with more than one, which is why this is not the general-purpose
    ``run:`` extractor the rest of this module reaches for. Dedents by the
    body's *own* first line, the same rule a real YAML literal block scalar
    follows, rather than assuming a fixed indent.

    """
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if key.match(line) is None:
            continue

        base_indent = None  # type: Optional[int]
        body = []
        for nested in lines[index + 1:]:
            if not nested.strip():
                body.append('')
                continue
            indent = len(nested) - len(nested.lstrip(' '))
            if base_indent is None:
                base_indent = indent
            if indent < base_indent:
                break
            body.append(nested[base_indent:])
        return '\n'.join(body)
    raise AssertionError(f'no line in the block matches {key.pattern!r}')


#: A ``printf '%s\n' "line" "line" ... | python3 -`` snippet, #905's fix for
#: feeding Python source through a `python3 -c "..."` argument whose
#: indentation only ``compile()``s on 3.14 -- see this module's docstring.
#: Matches the exact shape :func:`printf_python_snippets` was written
#: against; a differently-formatted equivalent (different quoting, `printf`
#: on one line, ...) would need this pattern extended, same maintenance
#: obligation as :data:`PUBLISHING_MARKERS`.
_PRINTF_PYTHON_SNIPPET = re.compile(
    r"printf '%s\\n' \\\n"
    r"(?P<lines>(?:[ \t]*\"[^\"\n]*\"[ \t]*\\\n)+)"
    r"[ \t]*\|[ \t]*python3 -",
)
_PRINTF_LINE = re.compile(r'"([^"\n]*)"')


def printf_python_snippets(text: 'str') -> 'list[str]':
    """Every :data:`_PRINTF_PYTHON_SNIPPET` in ``text``, reconstructed as the
    Python source ``python3 -`` actually receives on stdin -- each snippet's
    lines joined with ``\\n``, carrying none of the YAML block scalar's own
    indentation, since that indentation is exactly what this scan is for:
    confirming it never reaches the Python source itself.

    """
    snippets = []
    for match in _PRINTF_PYTHON_SNIPPET.finditer(text):
        lines = _PRINTF_LINE.findall(match.group('lines'))
        snippets.append('\n'.join(lines))
    return snippets


def pre_314_interpreter() -> 'Optional[str]':
    """A Python executable older than 3.14, or :data:`None` if none is found.

    Only 3.14 tolerates the leading-whitespace-on-``-c``-source hazard
    :class:`TestPythonSnippetsSurviveOlderInterpreters` exists to catch --
    measured directly against 3.9 through 3.14, see this module's docstring.
    :data:`sys.executable` is exactly that hazard's blind spot whenever *this*
    test suite happens to be running under 3.14 itself, which is why this
    looks for another interpreter on ``PATH`` rather than trusting its own.

    """
    if sys.version_info < (3, 14):
        return sys.executable
    for minor in (13, 12, 11, 10, 9):
        candidate = shutil.which(f'python3.{minor}')
        if candidate:
            return candidate
    return None


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
            ['conda', 'github', 'pypi', 'release_status', 'tag', 'unit-tests', 'version_check'],
            'the job list moved; if that is intended, the expectations in this '
            'module need revisiting rather than this line being updated alone',
        )

    def test_every_publishing_job_declares_an_environment(self) -> None:
        """No job may reach PyPI, Anaconda, a Release or a git push unapproved.

        An ``environment:`` is what lets Actions hold a job for a human, but
        since #887 only ``github-release``'s actually does -- ``conda-tag``,
        ``pypi`` and ``anaconda`` kept their environments with no reviewer on
        them, and are held instead by depending on ``github`` through
        ``needs:``. This test only checks that the line is present, not that
        it still carries a reviewer or that the dependency exists;
        :class:`TestGatedJobsDependOnGithub` below is what checks the latter.
        Without either, the job runs the moment its ``needs:`` are met, which
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

        A single ``release`` environment approved once would release PyPI
        *and* Anaconda together, which is the outcome #641's fix was meant to
        prevent rather than rename. Different credentials reach the two
        indexes -- OIDC trusted publishing and ``ANACONDA_TOKEN`` -- and
        ``tag``'s write to ``main`` uses a third, so sharing one environment
        would still merge those blast radii even though, since #887, only
        ``github-release`` carries a reviewer of its own; the other three are
        held by depending on it instead. That each *does* depend on it is
        :class:`TestGatedJobsDependOnGithub`'s check, not this one -- this
        test only stops the four gates from being collapsed back into one.

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


class TestGatedJobsDependOnGithub(WorkflowMixin, unittest.TestCase):
    """#887: with only ``github-release`` still holding a required reviewer,
    the other three gated jobs have to reach it through ``needs:`` instead,
    or removing their own reviewer left them ungated in every sense that
    matters.

    Nothing above this class reads ``needs:`` at all -- :class:`WorkflowMixin`
    aside, every test in :class:`TestPublishingJobsAreGated` and
    :class:`TestEnvironmentsAreNotShared` passes identically if ``tag``'s
    ``needs:`` is reverted to ``[ version_check ]``, which is the exact
    regression #887 fixed. This is the one test in the module that would
    catch it.

    """

    def test_every_gated_job_depends_on_github(self) -> None:
        """Every ``environment:``-declaring job but ``github`` itself must
        have ``github`` in its ``needs:`` closure, directly or transitively.

        """
        for name, block in sorted(self.jobs.items()):
            if name == 'github' or declared_environment(block) is None:
                continue
            with self.subTest(job=name):
                closure = needs_closure(self.jobs, name)
                self.assertIn(
                    'github', closure,
                    f'`{name}` declares an environment but its `needs:` closure '
                    f'{sorted(closure)} does not include `github` -- removing '
                    f'its own required reviewer (#887) would let it run before '
                    f'the one approval left to gate it',
                )


class TestEvidenceBasedGating(WorkflowMixin, unittest.TestCase):
    """#888: ``tag``, ``pypi`` and ``conda`` read their own evidence now,
    instead of ``PCAPKIT_TAG_EXISTS`` -- the tag ``github`` creates, which
    answers "was this tagged" and not "was this published", and those diverge
    exactly when a release half-completes.

    """

    def test_github_still_gates_on_the_v_tag_it_creates(self) -> None:
        """The one job for which ``PCAPKIT_TAG_EXISTS`` *is* the right question.

        ``github``'s own artefact is the ``v*`` tag that output answers for,
        so this is deliberate asymmetry, not a leftover of the bug -- this
        test is what stops a future "fix" from making it symmetric by mistake.

        """
        condition = declared_if(self.jobs['github'])
        self.assertIn('PCAPKIT_TAG_EXISTS', condition)

    def test_tag_gates_on_its_own_conda_tag_evidence(self) -> None:
        condition = declared_if(self.jobs['tag'])
        self.assertIn('PCAPKIT_CONDA_TAG_EXISTS', condition)
        self.assertNotIn(
            'PCAPKIT_TAG_EXISTS ==', condition,
            '`tag` still reads the v* tag as its gating evidence, which is '
            "github's artefact, not tag's",
        )

    def test_pypi_gates_on_its_own_file_count_evidence(self) -> None:
        condition = declared_if(self.jobs['pypi'])
        self.assertIn('PCAPKIT_PYPI_COMPLETE', condition)
        self.assertNotIn('PCAPKIT_TAG_EXISTS ==', condition)

    def test_conda_gates_on_its_own_aggregate_evidence(self) -> None:
        condition = declared_if(self.jobs['conda'])
        self.assertIn('PCAPKIT_CONDA_COMPLETE', condition)
        self.assertNotIn('PCAPKIT_TAG_EXISTS ==', condition)

    def test_evidence_gated_jobs_survive_a_legitimately_skipped_predecessor(self) -> None:
        """The half of the fix that has nothing to do with *which* evidence is read.

        ``tag``, ``pypi`` and ``conda`` each depend (directly) on ``github``,
        and ``conda`` also on ``tag``. GitHub Actions skips a job whose
        ``needs:`` included a job that itself skipped -- before that job's own
        ``if:`` is even evaluated -- unless the ``if:`` itself calls a
        status-check function. ``github`` legitimately skips whenever its own
        tag already exists, which is exactly the retry case #888 is about, so
        without this escape hatch the evidence checks above would never get a
        chance to run: a correctly-computed "not yet on PyPI, please run"
        would still be silently discarded by the default ``success()`` check.

        The escape hatch has to be a real status-check function
        (``!cancelled()``, ``always()``, ...), not just the *word* appearing
        in a comment -- so this greps the condition text itself, the same
        coarse substring style :data:`PUBLISHING_MARKERS` already uses.

        Each dependency has to be checked for ``== 'success' || == 'skipped'``
        explicitly, not merely ``!= 'failure'``: the latter still admits
        ``cancelled``, and a cancelled ``tag`` would send ``conda`` into its
        ``actions/checkout`` with ``ref: conda-<version>+0`` for a tag ``tag``
        never pushed -- a checkout failure standing in for a clean skip,
        found on the same cross-review as the two blocking defects above.

        """
        direct_deps = {
            'tag': ['github'],
            'pypi': ['github'],
            'conda': ['github', 'tag'],
        }
        for name, deps in sorted(direct_deps.items()):
            with self.subTest(job=name):
                condition = declared_if(self.jobs[name])
                self.assertTrue(
                    'cancelled()' in condition or 'always()' in condition,
                    f'`{name}`\'s `if:` ({condition!r}) calls neither `cancelled()` '
                    f'nor `always()`, so the default `success()` check GitHub Actions '
                    f'prepends will skip it the moment any direct dependency skips -- '
                    f'including a dependency that skipped for the legitimate #888 '
                    f'reason that its own artefact already exists',
                )
                for dep in deps:
                    self.assertIn(
                        f"needs.{dep}.result == 'success'", condition,
                        f'`{name}` does not explicitly accept `{dep}` (a direct '
                        f'dependency) succeeding',
                    )
                    self.assertIn(
                        f"needs.{dep}.result == 'skipped'", condition,
                        f'`{name}` does not explicitly accept `{dep}` (a direct '
                        f'dependency) having legitimately skipped',
                    )
                    self.assertNotIn(
                        f"needs.{dep}.result != 'failure'", condition,
                        f'`{name}` checks `{dep}` with `!= \'failure\'`, which still '
                        f'admits `cancelled` -- see this test\'s own docstring',
                    )

    def test_conda_checks_its_own_leg_before_uploading(self) -> None:
        """The correctness half for ``conda``: ``anaconda/actions/upload-package``
        has no ``skip-existing``, so the job-level evidence above is only a cost
        saver -- each matrix leg has to check for itself.

        """
        block = self.jobs['conda']
        self.assertIn('api.anaconda.org/release/jarryshaw/pypcapkit', block)
        self.assertIn('PCAPKIT_LEG_EXISTS', block)
        self.assertIn(
            "steps.check_leg.outputs.PCAPKIT_LEG_EXISTS != 'true'", block,
            "the 'Upload conda packages to Anaconda' step has no `if:` gating "
            'it on the per-leg evidence check, so a leg that already has this '
            'exact distribution would fail outright on retry instead of skipping',
        )

    def test_a_predicted_skip_is_announced(self) -> None:
        """#888's other half: a skip must never be silent.

        ``conda``'s per-leg skip gets its own ``::notice`` at the point of the
        skip, since ``release_status`` only sees the job's aggregate result and
        cannot say *which* leg was already published.

        """
        self.assertIn('::notice title=conda leg already published', self.jobs['conda'])

    def test_version_check_exposes_the_new_evidence_outputs(self) -> None:
        """The three outputs the jobs above actually read have to exist for
        them to read anything at all -- a typo'd output name fails silently
        (an empty string, not an error), so this is worth asserting directly.

        """
        block = self.jobs['version_check']
        for output in ('PCAPKIT_CONDA_TAG_EXISTS', 'PCAPKIT_PYPI_COMPLETE', 'PCAPKIT_CONDA_COMPLETE'):
            with self.subTest(output=output):
                self.assertIn(f'{output}:', block)

    def test_pypi_evidence_reads_the_per_version_endpoint(self) -> None:
        """Not ``releases[<version>]``: that field was empty on every live
        request made while building this check, including against a version
        that genuinely has all 8 files -- ``urls`` is what the per-version
        endpoint actually populates. A regression back to ``releases`` would
        make the evidence check always read 0 files.

        """
        block = self.jobs['version_check']
        self.assertIn('pypi.org/pypi/pypcapkit/', block)
        self.assertIn("data.get('urls'", block)

    def test_conda_evidence_checks_both_platforms(self) -> None:
        block = self.jobs['version_check']
        self.assertIn('linux-64', block)
        self.assertIn('osx-64', block)


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
        """``unit-tests``, ``version_check`` and ``release_status`` have no
        outward effect.

        ``unit-tests`` could not carry an ``environment:`` even if it wanted one --
        a job that calls a reusable workflow may not declare one -- so a marker
        broad enough to match it would make the rule unsatisfiable.
        ``release_status`` (#888) only reads the ``needs:`` context and prints
        ``::notice``/``::warning``/``::error`` annotations; it touches neither
        the repository nor either package index.

        """
        for name in ('unit-tests', 'version_check', 'release_status'):
            with self.subTest(job=name):
                self.assertEqual(publishing_reasons(self.jobs[name]), [])


class TestReleaseStatusReportsHonestly(WorkflowMixin, unittest.TestCase):
    """#888's other job: a run that released nothing must say why, in one
    place, regardless of which upstream job or gate made it release nothing.

    """

    def test_it_depends_directly_on_every_other_job(self) -> None:
        """Not a closure -- a *direct* ``needs:`` on each one.

        ``needs.<job>.result`` and ``needs.<job>.outputs`` are only readable
        for jobs actually named in this job's own ``needs:``; a transitive
        dependency (the shortcut :class:`TestGatedJobsDependOnGithub` allows
        for the other four jobs) would leave this one unable to see, say,
        ``pypi``'s result at all.

        """
        self.assertEqual(
            declared_needs(self.jobs['release_status']),
            ['unit-tests', 'version_check', 'github', 'tag', 'pypi', 'conda'],
        )

    def test_it_runs_regardless_of_what_upstream_did(self) -> None:
        """``unit-tests`` and ``version_check`` can each skip before any
        evidence output exists at all, so this job cannot condition on their
        outputs the way the gated jobs do -- it has to bypass the default
        status check outright.

        """
        condition = declared_if(self.jobs['release_status'])
        self.assertTrue(
            'cancelled()' in condition or 'always()' in condition,
            f'`release_status`\'s `if:` ({condition!r}) would otherwise skip '
            f'the moment anything it depends on skips, which is precisely the '
            f'situation it exists to report on',
        )

    def test_it_has_no_outward_effect(self) -> None:
        self.assertIsNone(declared_environment(self.jobs['release_status']))
        self.assertEqual(publishing_reasons(self.jobs['release_status']), [])

    def test_the_888_shape_is_reported_as_a_real_failure(self) -> None:
        """The one case this job must never let pass as green: the tag exists,
        the release is not fully out, and yet nothing ran to finish it. With
        the evidence-based guards in place this should be unreachable, but if
        it is ever reached it must fail loudly, not print a warning and exit 0
        the way every other branch does.

        """
        block = self.jobs['release_status']
        self.assertIn('::error title=Stranded partial release (#888)', block)
        self.assertIn('exit 1', block)

    def test_routine_skips_are_quiet(self) -> None:
        """The steady state -- nothing to release, or a release that just
        completed -- must not read as a problem.

        """
        block = self.jobs['release_status']
        self.assertIn('::notice title=Nothing to release', block)
        self.assertIn('::notice title=Release complete', block)


class TestReleaseStatusScriptExecutesCorrectly(WorkflowMixin, unittest.TestCase):
    """Actually runs ``release_status``'s shell script, rather than only
    grepping it, over a table of the shapes a real run can take.

    A cross-review of the #888 change found that an earlier revision of this
    script demanded the same outcome (all four release jobs ``skipped``, or
    all four ``success``) before treating a run as complete, which reads a
    self-heal -- ``github``/``tag`` skipping because their artefacts already
    exist, ``pypi``/``conda`` running and succeeding because theirs did not --
    as the #888 shape itself, erroring on the run that just fixed it. Every
    other test in this module is a string assertion over the YAML, so none
    of them executed the script and none of them could have caught that.

    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if shutil.which('bash') is None:
            raise unittest.SkipTest('bash not found on PATH')
        cls.script = block_scalar_after(cls.jobs['release_status'], _RUN_LITERAL)  # type: ignore[attr-defined]

    def _run(self, overrides: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
        env = {
            'PCAPKIT_EVENT_NAME': 'workflow_run',
            'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'success',
            'PCAPKIT_UNIT_TESTS': 'success',
            'PCAPKIT_VERSION_CHECK': 'success',
            'PCAPKIT_GITHUB_JOB': 'success',
            'PCAPKIT_TAG_JOB': 'success',
            'PCAPKIT_PYPI_JOB': 'success',
            'PCAPKIT_CONDA_JOB': 'success',
            'PCAPKIT_VERSION': '1.5.0',
            'PCAPKIT_TAG_EXISTS': 'false',
            'PCAPKIT_CONDA_TAG_EXISTS': 'false',
            'PCAPKIT_PYPI_COMPLETE': 'false',
            'PCAPKIT_CONDA_COMPLETE': 'false',
        }
        env.update(overrides)
        return subprocess.run(  # type: ignore[return-value]
            ['bash', '-c', self.script],  # type: ignore[attr-defined]
            env=env, capture_output=True, text=True, timeout=10,
        )

    #: ``(scenario name, env overrides, expected title substring, expected exit code)``.
    #: The self-heal row is the one an earlier revision of the script got
    #: wrong: mixed results, all reconciled against their own evidence.
    VECTORS = [
        (
            'vendor_update_had_nothing_to_do',
            {'PCAPKIT_UNIT_TESTS': 'skipped', 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'skipped'},
            '::notice title=Nothing to release',
            0,
        ),
        (
            'vendor_update_itself_broke',
            {'PCAPKIT_UNIT_TESTS': 'skipped', 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'failure'},
            '::warning title=Release test gate skipped',
            0,
        ),
        (
            'version_check_failed',
            {
                'PCAPKIT_VERSION_CHECK': 'failure',
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
            },
            '::warning title=Release blocked before it could start',
            0,
        ),
        (
            'steady_state_already_fully_released',
            {
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_PYPI_COMPLETE': 'true', 'PCAPKIT_CONDA_COMPLETE': 'true',
            },
            '::notice title=Nothing to release',
            0,
        ),
        (
            'self_heal_mixed_skip_and_success',
            {
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'success', 'PCAPKIT_CONDA_JOB': 'success',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_PYPI_COMPLETE': 'false', 'PCAPKIT_CONDA_COMPLETE': 'false',
            },
            '::notice title=Release complete',
            0,
        ),
        (
            'fresh_full_release_all_four_ran',
            {},  # every override already defaults to `success` / `false`
            '::notice title=Release complete',
            0,
        ),
        (
            'a_release_job_genuinely_failed',
            {
                'PCAPKIT_PYPI_JOB': 'failure',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_CONDA_COMPLETE': 'true',
            },
            '::warning title=Release did not complete',
            0,
        ),
        (
            'stranded_partial_the_888_shape',
            {
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
                'PCAPKIT_TAG_EXISTS': 'true',  # github's own evidence: reconciled
                # everything else still incomplete, yet its job skipped anyway
            },
            '::error title=Stranded partial release (#888)',
            1,
        ),
    ]

    def test_each_scenario_takes_the_right_branch(self) -> None:
        for name, overrides, expected_marker, expected_rc in self.VECTORS:
            with self.subTest(scenario=name):
                result = self._run(overrides)
                self.assertEqual(
                    result.returncode, expected_rc,
                    f'scenario {name!r} exited {result.returncode}, expected '
                    f'{expected_rc}. stdout={result.stdout!r} stderr={result.stderr!r}',
                )
                self.assertIn(
                    expected_marker, result.stdout,
                    f'scenario {name!r} did not print {expected_marker!r}. '
                    f'stdout={result.stdout!r}',
                )


class TestPythonSnippetsSurviveOlderInterpreters(WorkflowMixin, unittest.TestCase):
    """A cross-review of the #888 change found that the ``python3 -c``
    snippets computing PyPI/Anaconda evidence had their source indented by
    the surrounding YAML block scalar, which only ``compile()``s on Python
    3.14 -- 3.9 through 3.13 all raise ``IndentationError: unexpected
    indent``, measured directly. Two of the three run before
    ``actions/setup-python`` installs a chosen version, so ``python3`` there
    is the runner image's default (3.12 on ``ubuntu-latest`` as of writing),
    never 3.14. #905's fix feeds one line per ``printf`` argument instead, so
    no line in the actual Python source is indented that Python did not
    itself put there -- this class is what actually runs each snippet under
    an older interpreter to check that claim, rather than trusting it.

    """

    def test_the_scan_found_the_snippets(self) -> None:
        """A scan that finds nothing would pass every test below it."""
        snippets = printf_python_snippets(self.text)  # type: ignore[attr-defined]
        self.assertEqual(
            len(snippets), 3,
            'expected exactly 3 printf-fed python3 snippets (the PyPI and '
            'Anaconda evidence checks in version_check, plus the per-leg '
            'check in conda); found a different count -- if that is '
            'intended, this expectation needs revisiting alongside it',
        )

    def test_each_snippet_runs_without_an_indentation_error(self) -> None:
        interpreter = pre_314_interpreter()
        if interpreter is None:
            self.skipTest('no Python interpreter older than 3.14 found on PATH')

        version = subprocess.run(
            [interpreter, '--version'], capture_output=True, text=True,
        ).stdout.strip()

        for index, snippet in enumerate(printf_python_snippets(self.text)):  # type: ignore[attr-defined]
            with self.subTest(snippet=index):
                # `$target_platform`/`$py_tag` are bash interpolation the real
                # step performs before Python ever sees this text; harmless
                # stand-ins reproduce the same shape without needing bash here.
                source = (
                    snippet
                    .replace('$target_platform', 'linux-64')
                    .replace('$py_tag', 'py310')
                )
                result = subprocess.run(
                    [interpreter, '-'], input=source, capture_output=True,
                    text=True, timeout=10,
                )
                self.assertNotIn(
                    'IndentationError', result.stderr,
                    f'snippet {index} raised IndentationError under '
                    f'{interpreter} ({version}):\n{result.stderr}',
                )


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

    def test_the_same_job_to_needs_mapping(self) -> None:
        """:func:`declared_needs` against the same real parse, for the same reason."""
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML is not in the test extra; the textual scan is '
                          'asserted by TestGatedJobsDependOnGithub')

        parsed = yaml.safe_load(self.text)
        self.assertIsInstance(parsed, dict, 'the workflow is not a YAML mapping')

        expected = {name: list(job.get('needs', []))
                    for name, job in parsed['jobs'].items()}
        scanned = {name: declared_needs(block) for name, block in self.jobs.items()}

        self.assertEqual(scanned, expected,
                         'the indentation-based `needs:` scanner and yaml.safe_load '
                         'disagree about the dependency graph')

    def test_the_same_job_to_if_mapping(self) -> None:
        """:func:`declared_if` against the same real parse, for the same reason.

        This is the one that actually exercises the folded block-scalar form
        #888 introduces -- ``test_the_same_job_to_environment_mapping`` and
        ``test_the_same_job_to_needs_mapping`` above only ever see single-line
        values, so neither would have caught a folding mistake the way this
        one does.

        """
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML is not in the test extra; the textual scan is '
                          'asserted by TestEvidenceBasedGating')

        parsed = yaml.safe_load(self.text)
        self.assertIsInstance(parsed, dict, 'the workflow is not a YAML mapping')

        expected = {name: (job.get('if') or '') for name, job in parsed['jobs'].items()}
        scanned = {name: declared_if(block) for name, block in self.jobs.items()}

        self.assertEqual(scanned, expected,
                         'the indentation-based `if:` scanner and yaml.safe_load '
                         'disagree about at least one job\'s condition')


if __name__ == '__main__':
    unittest.main()
