# -*- coding: utf-8 -*-
"""Tests that every workflow step invoking :program:`apt-get` declares a ``timeout-minutes``.

#974: the ``engine-tests`` install step fetched its ``InRelease`` metadata from
``archive.ubuntu.com`` and then went silent for 29m52s, until the job's own
``timeout-minutes: 30`` killed it. A job killed that way reports ``cancelled``,
and ``cancelled`` correctly fails the ``Required checks passed`` gate, so one
unresponsive mirror turned a docs-only PR red after burning the entire job
budget. It happened twice inside forty minutes.

What makes that worth a test rather than only a fix is that the same hazard
existed in a *second* step nobody was looking at. ``pypcap-parity`` installs the
union of the packages ``engine-tests`` installs, from the same mirrors, and had
no bound either -- it simply had not been the leg that stalled yet. Fixing only
the step that happened to bite is the recurrence this module exists to prevent:
nothing about an unbounded ``apt-get`` warns, and the failure is invisible until
a mirror misbehaves on whichever step was left out.

The rule asserted here is not a copy of the current file: **any step in any
workflow whose script invokes ``apt-get`` must declare a ``timeout-minutes``,
and that value must be below its job's own budget.** Stated that way it also
catches a *new* apt-installing step added later without a bound, in a workflow
that has none today.

The second half of the rule matters as much as the first. A step timeout at or
above the job's budget is decorative -- the job's own timer fires first and the
run is cancelled exactly as before -- so a bound that does not actually bind is
treated as a failure here rather than passing on the strength of the key being
present.

Two things this deliberately does **not** test:

* **That the number is well chosen.** Whether 15 minutes is the right bound
  depends on how long the step legitimately takes, which is a property of
  Ubuntu's mirrors on the day and is not observable from the file. The reasoning
  and the measurements behind the current value live in the workflow's own
  comment; this module only asserts that *some* binding value is declared.
* **That the step will not hang in a way the timeout misses.** ``timeout-minutes``
  is enforced by the Actions runner, so nothing here can exercise it. The test is
  an assertion over the file, as #641's gating test is.

:mod:`yaml` is in no extra of :file:`pyproject.toml`, so the scanner here is
hand-rolled and dependency-free, and :class:`TestYAMLAgreesWithTheScanner`
checks it against :func:`yaml.safe_load` only when PyYAML happens to be
installed. That is the same split :file:`tests/project/test_release_gates.py`
uses, and for the same reason: the assertion that must run everywhere does not
need the dependency, and the one that needs it guards the substitute.

Comments are stripped before the ``apt-get`` marker is looked for. Without that,
prose *about* apt -- including the long note #974 added above the very step this
module guards -- would register as an invocation, so a step could be flagged for
mentioning apt and, worse, a commented-out invocation could be credited as a
live one. :func:`tests._dependency_gates._engine_matrix_variants` strips
comments before its own scan for the same class of reason.

"""

from __future__ import annotations

import pathlib
import re
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every workflow, rather than only the one #974 was filed against. The hazard is
#: a property of invoking apt unbounded, not of a particular file, and scanning
#: the directory is what lets a new apt step in a workflow that has none today be
#: caught by this module rather than by a stalled run.
WORKFLOW_DIR = ROOT / '.github' / 'workflows'

#: What counts as invoking apt. A substring of the comment-stripped step script,
#: coarse on purpose: ``sudo apt-get``, ``DEBIAN_FRONTEND=noninteractive
#: apt-get`` and a bare ``apt-get`` all match, as does an invocation this
#: repository does not currently write.
#:
#: It does not match :program:`apt`, :program:`aptitude`, or a package manager
#: reached some other way. That is the same allowlist limitation
#: :data:`~tests.project.test_release_gates.PUBLISHING_MARKERS` carries, and
#: :class:`TestTheScannerIsNotBlind` only keeps this marker from going blind --
#: it cannot invent a second one. Adding a different installer to a workflow
#: means adding its marker here.
APT_MARKER = 'apt-get'

#: The steps known to invoke apt today, as ``(workflow name, step name)``. Quoted
#: so :class:`TestTheScannerIsNotBlind` can tell "the rule holds everywhere" from
#: "the scanner found nothing to check", which look identical in a passing run.
KNOWN_APT_STEPS = {
    ('unit-tests.yml', "Install this engine's system packages"),
    ('unit-tests.yml', 'Install libpcap headers, a C toolchain, and tshark'),
}

#: A step's opening line: a ``-`` at some indent, then a key. Steps in this
#: repository's workflows open with ``name:`` or ``uses:``.
_STEP_RE = re.compile(r'^(?P<indent>[ ]*)-[ ]+(?P<key>[\w-]+):(?P<rest>.*)$')
#: A two-space-indented ``key:`` line, which is what opens a job -- the same
#: boundary :func:`tests._dependency_gates.job_sections` keys on.
_JOB_RE = re.compile(r'^[ ]{2}(?P<name>[\w-]+):[ ]*$')
#: ``timeout-minutes: N`` anywhere in a block.
_TIMEOUT_RE = re.compile(r'(?m)^[ ]*timeout-minutes:[ ]*(?P<minutes>\d+)[ ]*$')
#: ``name: ...``, for naming a step in a failure message.
_NAME_RE = re.compile(r'(?m)^[ ]*(?:-[ ]+)?name:[ ]*(?P<name>.+?)[ ]*$')


def strip_comments(text: 'str') -> 'str':
    """``text`` with whole-line ``#`` comments removed.

    Whole-line only: a ``#`` inside a script line can be a shell comment but can
    equally be part of a string or a URL fragment, and dropping from it would
    corrupt the line. Every comment in these workflows is a whole-line one.

    """
    return '\n'.join(line for line in text.splitlines()
                     if not line.strip().startswith('#'))


class Step:
    """One step of one workflow: its name, its script, and the job it belongs to."""

    def __init__(self, workflow: 'str', job: 'Optional[str]', name: 'str',
                 block: 'str', job_timeout: 'Optional[int]') -> None:
        self.workflow = workflow
        self.job = job
        self.name = name
        self.block = block
        self.job_timeout = job_timeout

    @property
    def timeout(self) -> 'Optional[int]':
        """The step's own ``timeout-minutes``, or :data:`None` when it declares none."""
        match = _TIMEOUT_RE.search(self.block)
        return None if match is None else int(match.group('minutes'))

    def invokes(self, marker: 'str') -> 'bool':
        """Whether the step's script, comments stripped, contains ``marker``."""
        return marker in strip_comments(self.block)

    def __repr__(self) -> 'str':
        return f'<Step {self.workflow}:{self.job}:{self.name!r}>'


def steps(path: 'pathlib.Path') -> 'list[Step]':
    """Every step of the workflow at ``path``.

    An indentation scan rather than a YAML parse, for the reason this module's
    docstring gives: PyYAML is in no extra, so the assertion that must run
    everywhere cannot depend on it.

    A step runs from its ``- key:`` line to just before the next line that is
    neither blank nor indented past the ``-``, which is what ends a block in
    YAML's block style.

    """
    text = path.read_text(encoding='utf-8')
    lines = text.splitlines()

    # Job boundaries first, so a step can report which job it is in and compare
    # against that job's budget.
    job_at = {}  # type: dict[int, str]
    job_timeout_at = {}  # type: dict[int, Optional[int]]
    in_jobs = False
    current = None  # type: Optional[str]
    for i, line in enumerate(lines):
        if line.rstrip() == 'jobs:':
            in_jobs = True
            continue
        if in_jobs:
            match = _JOB_RE.match(line)
            if match is not None:
                current = match.group('name')
        job_at[i] = current  # type: ignore[assignment]

    # A job's own timeout-minutes is a four-space-indented key of that job.
    job_timeouts = {}  # type: dict[str, int]
    for i, line in enumerate(lines):
        match = re.match(r'^[ ]{4}timeout-minutes:[ ]*(\d+)[ ]*$', line)
        if match is not None and job_at.get(i):
            job_timeouts[job_at[i]] = int(match.group(1))

    found = []  # type: list[Step]
    starts = [(i, m) for i, m in ((i, _STEP_RE.match(line)) for i, line in enumerate(lines))
              if m is not None]
    for index, (start, match) in enumerate(starts):
        indent = len(match.group('indent'))
        end = len(lines)
        for i in range(start + 1, len(lines)):
            stripped = lines[i].strip()
            if not stripped:
                continue
            if len(lines[i]) - len(lines[i].lstrip(' ')) <= indent:
                end = i
                break
        block = '\n'.join(lines[start:end])
        name_match = _NAME_RE.search(block)
        name = name_match.group('name') if name_match is not None else f'<line {start + 1}>'
        job = job_at.get(start)
        found.append(Step(path.name, job, name, block,
                          job_timeouts.get(job) if job else None))
    return found


def apt_steps() -> 'list[Step]':
    """Every step of every workflow that invokes apt."""
    found = []  # type: list[Step]
    for path in sorted(WORKFLOW_DIR.glob('*.yml')):
        found.extend(step for step in steps(path) if step.invokes(APT_MARKER))
    return found


class TestAptStepsAreBounded(unittest.TestCase):
    """#974: an unbounded apt invocation can spend its job's whole budget."""

    def test_every_apt_step_declares_a_timeout(self) -> None:
        """Each apt-invoking step has a ``timeout-minutes`` of its own."""
        for step in apt_steps():
            with self.subTest(workflow=step.workflow, job=step.job, step=step.name):
                self.assertIsNotNone(
                    step.timeout,
                    f'{step.workflow}: the {step.name!r} step of the {step.job!r} job '
                    f'invokes {APT_MARKER} but declares no timeout-minutes, so a stalled '
                    f"mirror can spend that job's entire budget and report `cancelled` "
                    f'rather than a failure anyone can attribute -- which is #974, and '
                    f'which the `Required checks passed` gate correctly treats as a '
                    f'blocked PR. Give the step a timeout-minutes below its job\'s.'
                )

    def test_every_apt_step_timeout_actually_binds(self) -> None:
        """A step timeout at or above its job's budget would never fire first."""
        for step in apt_steps():
            if step.timeout is None or step.job_timeout is None:
                continue
            with self.subTest(workflow=step.workflow, job=step.job, step=step.name):
                self.assertLess(
                    step.timeout, step.job_timeout,
                    f'{step.workflow}: the {step.name!r} step of the {step.job!r} job '
                    f'declares timeout-minutes: {step.timeout}, which is not below its '
                    f"job's timeout-minutes: {step.job_timeout}, so the job's own timer "
                    f'fires first and the step bound never binds -- the run is cancelled '
                    f'exactly as #974 describes, while the file reads as though it were '
                    f'protected.'
                )


class TestTheScannerIsNotBlind(unittest.TestCase):
    """A rule that matches nothing passes vacuously, so pin what it should match."""

    def test_the_known_apt_steps_are_found(self) -> None:
        """The scanner still finds the apt steps this repository is known to have."""
        found = {(step.workflow, step.name) for step in apt_steps()}
        missing = KNOWN_APT_STEPS - found
        self.assertFalse(
            missing,
            f'the apt-step scanner no longer finds {sorted(missing)}, so this module '
            f'would pass without checking them. Either the steps were renamed or '
            f'removed -- update KNOWN_APT_STEPS -- or the scanner has gone blind, in '
            f'which case every assertion here is vacuous. Found: {sorted(found)}.'
        )

    def test_the_scanner_finds_steps_at_all(self) -> None:
        """The step scanner reads the workflow directory as steps, not as nothing."""
        total = sum(len(steps(path)) for path in sorted(WORKFLOW_DIR.glob('*.yml')))
        self.assertGreater(
            total, 20,
            f'the step scanner found only {total} steps across {WORKFLOW_DIR}, which is '
            f'far fewer than these workflows contain -- the indentation scan has broken '
            f'and every assertion in this module is passing vacuously.'
        )


class TestYAMLAgreesWithTheScanner(unittest.TestCase):
    """The hand-rolled scanner against a real parse, when PyYAML is available."""

    def setUp(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML is in no extra of pyproject.toml; scanner unchecked here')

    def test_yaml_finds_the_same_apt_steps(self) -> None:
        """:func:`yaml.safe_load` agrees on which steps invoke apt."""
        import yaml

        parsed = set()
        for path in sorted(WORKFLOW_DIR.glob('*.yml')):
            data = yaml.safe_load(path.read_text(encoding='utf-8'))
            for job in (data.get('jobs') or {}).values():
                if not isinstance(job, dict):
                    continue
                for step in job.get('steps') or []:
                    if not isinstance(step, dict):
                        continue
                    if APT_MARKER in strip_comments(step.get('run') or ''):
                        parsed.add((path.name, step.get('name')))

        scanned = {(step.workflow, step.name) for step in apt_steps()}
        self.assertEqual(
            parsed, scanned,
            'the indentation-based apt-step scanner and yaml.safe_load disagree about '
            'which steps invoke apt, so one of the two is wrong and the rule in this '
            'module is being applied to the wrong set of steps'
        )

    def test_yaml_agrees_on_the_declared_timeouts(self) -> None:
        """:func:`yaml.safe_load` agrees on each apt step's ``timeout-minutes``."""
        import yaml

        parsed = {}  # type: dict[tuple[str, Optional[str]], Optional[int]]
        for path in sorted(WORKFLOW_DIR.glob('*.yml')):
            data = yaml.safe_load(path.read_text(encoding='utf-8'))
            for job in (data.get('jobs') or {}).values():
                if not isinstance(job, dict):
                    continue
                for step in job.get('steps') or []:
                    if not isinstance(step, dict):
                        continue
                    if APT_MARKER in strip_comments(step.get('run') or ''):
                        parsed[(path.name, step.get('name'))] = step.get('timeout-minutes')

        scanned = {(step.workflow, step.name): step.timeout for step in apt_steps()}
        self.assertEqual(
            parsed, scanned,
            'the indentation-based timeout-minutes scanner and yaml.safe_load disagree '
            'about what the apt steps declare, so the bound this module checks is not '
            'the bound the Actions runner would enforce'
        )


if __name__ == '__main__':
    unittest.main()
