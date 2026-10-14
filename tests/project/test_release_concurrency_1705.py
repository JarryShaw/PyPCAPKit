# -*- coding: utf-8 -*-
"""#1705: a Create Release run that cannot release must not displace one that can.

Create Release serialises on one workflow-level group per ref, and a group holds
one pending run, cancelling it when another joins. Every Vendor Update completion
raises a run, whatever its conclusion, and the one ``version_check`` skips used
to join ``main``'s group too. On 2026-10-14, read off the runs' timestamps (each
Create Release run was created 2-3 s after a Vendor Update run completed):

* 38497299656, from Vendor Update 38497182777 (``success``), ran until 02:12:48Z;
* 38499150441, from 38498670543 (``success``), was pending from 02:04:54Z;
* 38499295798, from 38499290316 (``skipped``), joined at 02:06:32Z and
  cancelled it;
* 38499303910, from 38499299431 (``skipped``), cancelled that in turn, and was
  the run that eventually ran.

So the group is now keyed on the ref only for a run ``version_check`` can run;
any other run is keyed on its own ``github.run_id``. These tests evaluate the
group with the evaluator :mod:`tests.project.test_release_gates` pins.

"""

from __future__ import annotations

import re
import unittest

from tests.project.test_release_gates import (HUMAN_ACTOR_ID, NULL, RELEASE_APP_BOT_ID, WORKFLOW,
                                              declared_if, evaluate_condition, evaluate_expression,
                                              job_blocks)

#: The workflow-level ``concurrency:`` block: a one-line ``group:`` holding one
#: interpolation after a literal prefix, then ``cancel-in-progress:``.
_CONCURRENCY = re.compile(
    r'^concurrency:\n'
    r'  group: (?P<prefix>[^$\n]*)\$\{\{(?P<body>[^\n]*)\}\}\n'
    r'  cancel-in-progress: (?P<cancel>\S+)\n',
    re.M,
)

#: Conclusions a Vendor Update run can end with, besides ``success``.
OTHER_CONCLUSIONS = ('skipped', 'failure', 'cancelled', 'timed_out', 'neutral',
                     'action_required', 'stale', 'startup_failure')

MAIN = 'refs/heads/main'
TAG = 'refs/tags/v1.5.0'


def run_context(run_id: 'str', event_name: 'str' = 'workflow_run',
                conclusion: 'object' = 'success', ref: 'str' = MAIN,
                actor_id: 'str' = HUMAN_ACTOR_ID) -> 'dict[str, object]':
    """One run's ``github``/``vars`` context; a ``push`` carries no ``workflow_run``."""
    event = {}  # type: dict[str, object]
    if event_name == 'workflow_run':
        event = {'workflow_run': {'conclusion': conclusion}}
    return {
        'github': {
            'event_name': event_name,
            'ref': ref,
            'ref_name': ref.split('/', 2)[2],
            'run_id': run_id,
            'actor_id': actor_id,
            'event': event,
        },
        'vars': {'RELEASE_APP_BOT_ID': RELEASE_APP_BOT_ID},
    }


class TestReleaseConcurrency(unittest.TestCase):
    """The group each kind of run joins, evaluated."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding='utf-8')
        match = _CONCURRENCY.search(cls.text)
        if match is None:
            raise AssertionError(f'no workflow-level concurrency group in {WORKFLOW}')
        cls.prefix = match.group('prefix')
        cls.body = match.group('body')
        cls.cancel = match.group('cancel')
        cls.version_check = declared_if(job_blocks(cls.text)['version_check'])

    def group(self, context: 'dict[str, object]') -> 'str':
        value = evaluate_expression('${{' + self.body + '}}', context)
        self.assertIsInstance(value, str, f'the group key evaluated to {value!r}')
        return self.prefix + str(value)

    def test_a_workflow_run_shares_the_group_exactly_when_version_check_runs(self) -> None:
        """Anything else releases nothing, so it gets a group of its own."""
        for conclusion in ('success', NULL) + OTHER_CONCLUSIONS:
            with self.subTest(conclusion=conclusion):
                context = run_context('38499295798', conclusion=conclusion)
                runs = evaluate_condition(self.version_check, context)
                self.assertEqual(self.group(context) == f'create-release-{MAIN}', runs,
                                 f'version_check {"runs" if runs else "skips"} on a Vendor Update '
                                 f'that concluded {conclusion!r}, but the run joins '
                                 f'{self.group(context)!r}')

    def test_skipped_vendor_updates_cannot_displace_run_38499150441(self) -> None:
        """The 2026-10-14 runs: neither skipped one meets the pending run, nor each other."""
        pending = self.group(run_context('38499150441'))
        first = self.group(run_context('38499295798', conclusion='skipped'))
        second = self.group(run_context('38499303910', conclusion='skipped'))
        self.assertEqual(pending, f'create-release-{MAIN}')
        self.assertEqual(len({pending, first, second}), 3, (pending, first, second))
        self.assertFalse(first.startswith('create-release-refs/'), first)

    def test_runs_that_may_release_still_wait_for_each_other(self) -> None:
        """The double-publish guard the group was for: never per run, never cancelling."""
        self.assertEqual(self.cancel, 'false')
        self.assertEqual(self.group(run_context('34894022730')),
                         self.group(run_context('34894646592')))
        for actor_id in (HUMAN_ACTOR_ID, RELEASE_APP_BOT_ID):
            for run_id in ('1', '2'):
                with self.subTest(actor_id=actor_id, run_id=run_id):
                    context = run_context(run_id, event_name='push', ref=TAG, actor_id=actor_id)
                    self.assertEqual(self.group(context), f'create-release-{TAG}')

    def test_the_scanner_agrees_with_yaml(self) -> None:
        """What :data:`_CONCURRENCY` reads is what a YAML parse reads."""
        try:
            import yaml  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.skipTest('PyYAML is only installed with the test extra')
        parsed = yaml.safe_load(self.text)['concurrency']
        self.assertEqual(parsed, {'group': self.prefix + '${{' + self.body + '}}',
                                  'cancel-in-progress': False})


if __name__ == '__main__':
    unittest.main()
