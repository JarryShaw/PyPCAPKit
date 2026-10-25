# -*- coding: utf-8 -*-
"""#1967: Lint runs actionlint, pinned to a checksum-verified release.

Nothing ran actionlint over the workflows before #1967. Lint's ``lint`` job
has an ``actionlint`` step that downloads one release, named by
``ACTIONLINT_VERSION``, checks it against ``ACTIONLINT_SHA256`` before unpacking
it, and runs it over every workflow. The version is 1.7.12 or newer: the
workflows use YAML anchors, which 1.7.7 cannot read.

* :class:`TestTheStep` pins the step: one of it, the version, the checksum, and
  the order download, verify, unpack, run.
* :class:`TestItBlocks` pins that a finding fails Lint, as the owner ruled on
  #1967 once #2023, #2037 and #2038 had fixed every finding: no
  ``continue-on-error``, actionlint's own exit status, and a place below every
  advisory step, run on ``!cancelled()``, so a finding skips none of them and a
  failed setup does not skip it.
* :class:`TestTheIgnores` pins each ``-ignore`` pattern to the false positive it
  exists for, so a blanket pattern fails here, and checks that a workflow still
  uses the key, so the pattern goes when the key does.

"""

from __future__ import annotations

import re
import unittest
from typing import TYPE_CHECKING

from tests import _workflows

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

WORKFLOW = 'lint.yml'
JOB = 'lint'
STEP = 'actionlint'
#: The oldest release the step may pin.
MINIMUM = (1, 7, 12)
#: Each ``-ignore`` pattern the step may pass, with a message it must hide and
#: messages it must not. A pattern is matched against the message alone.
IGNORES = {
    # rhysd/actionlint#657: GitHub documents ``concurrency.queue``, which
    # project-status.yml sets; no actionlint release knows the key yet.
    r'^unexpected key "queue" for "concurrency" section\.': (
        'unexpected key "queue" for "concurrency" section. expected one of '
        '"cancel-in-progress", "group"',
        (
            'unexpected key "queues" for "concurrency" section. expected one of '
            '"cancel-in-progress", "group"',
            'unexpected key "queue" for "job" section. expected one of "runs-on"',
            'unexpected key "group" for "concurrency" section',
        ),
    ),
}
#: The ``if:`` values under which a step still runs after an earlier step failed.
#: The last is the run report's (#2030), which a pull request skips whatever
#: actionlint found.
RUNS_AFTER_A_FAILURE = frozenset({'${{ !cancelled() }}', '${{ always() }}', '!cancelled()', 'always()',
                                  "${{ !cancelled() && github.event_name != 'pull_request' }}"})
#: An ``-ignore`` argument in the step's script, quoted either way.
IGNORE = re.compile(r'''-ignore\s+(?P<quote>['"])(?P<pattern>.*?)(?P=quote)''')


def step() -> 'dict[str, Any]':
    """The ``actionlint`` step of Lint's ``lint`` job."""
    found = [entry for entry in _workflows.steps(WORKFLOW, JOB) if entry.get('name') == STEP]
    if len(found) != 1:
        raise AssertionError(f'expected one {STEP!r} step in {WORKFLOW}:{JOB}, found {len(found)}')
    return found[0]


def concurrency_keys(workflow: 'dict[str, Any]') -> 'set[str]':
    """Every key of every ``concurrency:`` mapping in ``workflow``, workflow and job level."""
    blocks = [workflow.get('concurrency')]
    blocks.extend(spec.get('concurrency') for spec in (workflow.get('jobs') or {}).values())
    return {key for block in blocks if isinstance(block, dict) for key in block}


class TestTheStep(unittest.TestCase):
    """The ``actionlint`` step downloads a pinned release, verifies it, then runs it."""

    def test_the_version_is_pinned_and_new_enough(self) -> None:
        version = str(step()['env']['ACTIONLINT_VERSION'])
        self.assertRegex(version, r'^\d+\.\d+\.\d+$')
        self.assertGreaterEqual(tuple(map(int, version.split('.'))), MINIMUM)

    def test_the_checksum_is_pinned(self) -> None:
        self.assertRegex(str(step()['env']['ACTIONLINT_SHA256']), r'^[0-9a-f]{64}$')

    def test_it_downloads_verifies_unpacks_then_runs(self) -> None:
        script = step()['run']
        order = [
            ('download', r'curl\b.*releases/download/v\$\{ACTIONLINT_VERSION\}/'),
            ('verify', r'\$ACTIONLINT_SHA256\b.*\|\s*sha256sum -c -'),
            ('unpack', r'tar -xzf\b'),
            ('run', r'"\$RUNNER_TEMP/actionlint" -oneline\b'),
        ]
        positions = []
        for what, pattern in order:
            match = re.search(pattern, script, re.S)
            self.assertIsNotNone(match, f'the step does not {what}: {pattern!r}')
            positions.append(match.start())  # type: ignore[union-attr]
        self.assertEqual(positions, sorted(positions), 'download, verify, unpack and run are out of order')

    def test_it_bounds_its_time(self) -> None:
        minutes = step().get('timeout-minutes')
        self.assertIsInstance(minutes, int)
        self.assertLess(minutes, _workflows.job(WORKFLOW, JOB)['timeout-minutes'])


class TestItBlocks(unittest.TestCase):
    """An actionlint finding fails Lint, and skips none of Lint's advisory steps."""

    def test_it_is_not_continue_on_error(self) -> None:
        self.assertNotIn('continue-on-error', step())

    def test_it_exits_with_actionlints_status(self) -> None:
        script = step()['run']
        # The command with its continuation lines, up to the end of its last line.
        run = re.search(r'"\$RUNNER_TEMP/actionlint" -oneline\b(?:[^\n]*\\\n)*[^\n]*\n', script)
        self.assertIsNotNone(run, 'the step does not run actionlint')
        self.assertNotRegex(run[0], r'\|\|')  # type: ignore[index]
        after = script[run.end():].splitlines()  # type: ignore[union-attr]
        self.assertEqual(after[0].strip(), 'status=${PIPESTATUS[0]}')
        self.assertEqual([line for line in after if line.strip()][-1].strip(), 'exit "$status"')

    def test_it_runs_after_a_failed_setup(self) -> None:
        self.assertIn(step().get('if'), RUNS_AFTER_A_FAILURE)

    def test_no_step_after_it_is_skipped_by_a_finding(self) -> None:
        steps = _workflows.steps(WORKFLOW, JOB)
        index = next(i for i, entry in enumerate(steps) if entry.get('name') == STEP)
        skipped = [entry.get('name') or entry.get('uses') for entry in steps[index + 1:]
                   if entry.get('if') not in RUNS_AFTER_A_FAILURE]
        self.assertEqual(skipped, [], 'a finding would skip these steps; move actionlint below them')


class TestTheIgnores(unittest.TestCase):
    """Each ``-ignore`` hides one known false positive, and only while it can occur."""

    def test_every_pattern_is_a_known_one(self) -> None:
        patterns = [match['pattern'] for match in IGNORE.finditer(step()['run'])]
        self.assertEqual(sorted(patterns), sorted(IGNORES))

    def test_each_pattern_hides_only_its_message(self) -> None:
        for pattern, (hidden, shown) in IGNORES.items():
            with self.subTest(pattern=pattern):
                self.assertRegex(hidden, pattern)
                for message in shown:
                    self.assertNotRegex(message, pattern)

    def test_a_workflow_still_sets_concurrency_queue(self) -> None:
        users = sorted(path.name for path in _workflows.WORKFLOWS.glob('*.yml')
                       if 'queue' in concurrency_keys(_workflows.load(path)))
        self.assertTrue(users, 'no workflow sets concurrency.queue; drop its -ignore pattern from Lint')


if __name__ == '__main__':
    unittest.main()
