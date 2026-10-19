# -*- coding: utf-8 -*-
"""#1903: a newer run on ``main`` supersedes Experimental Tests' older one.

Every push to ``main`` used to get a concurrency group of its own, by run id, so
a merge wave queued a GraalPy leg of up to two hours per commit and held runners
that the open pull requests' CI then waited behind. The owner chose option 1: in
experimental.yml only, a push to ``main`` joins one group per ref and cancels the
run in progress, as a pull request's run already did. Nothing waits on these legs
(#1732), so the newest commit's run is enough.

unit-tests.yml keeps a group per push, because its ``unittest-ordering`` leg runs
only on ``main`` and a cancelled run there would leave a commit with no ordering
check at all: :class:`TestUnitTestsKeepsARunPerCommit`.

The expressions are evaluated, with the evaluator
:mod:`tests.project.test_release_gates` pins, rather than matched as text: what
is checked is the group each kind of run lands in and whether it cancels, which
a reworded expression can keep or break without any substring changing.

"""

from __future__ import annotations

import re
import unittest

import yaml

from tests import _tiers
from tests.project.test_release_gates import evaluate_condition, evaluate_expression

WORKFLOWS = _tiers.ROOT / '.github' / 'workflows'

MAIN = 'refs/heads/main'
PULL = 'refs/pull/1903/merge'

#: One ``${{ }}`` interpolation in a ``group:`` value, its body captured.
_INTERPOLATION = re.compile(r'\$\{\{(.*?)\}\}', re.S)


def concurrency(name: 'str') -> 'dict[str, str]':
    """The workflow-level ``concurrency:`` mapping of ``name``."""
    with open(WORKFLOWS / name, encoding='utf-8') as file:
        return yaml.safe_load(file)['concurrency']


def context(event_name: 'str', ref: 'str', run_id: 'str', workflow: 'str' = 'Experimental Tests') -> 'dict[str, object]':
    """One run's ``github`` context, as far as a ``concurrency:`` block reads it."""
    return {'github': {'event_name': event_name, 'ref': ref, 'run_id': run_id, 'workflow': workflow}}


class Concurrency:
    """A ``concurrency:`` block, evaluated per run."""

    def __init__(self, name: 'str') -> None:
        self.raw = concurrency(name)

    def group(self, run: 'dict[str, object]') -> 'str':
        """The group key: literal text kept, each interpolation evaluated in turn.

        unit-tests.yml's interpolates ``github.workflow`` too, so a key may hold
        more than one; the evaluator takes one whole expression at a time.

        """
        parts = _INTERPOLATION.split(self.raw['group'])
        return ''.join(part if index % 2 == 0 else str(evaluate_expression('${{' + part + '}}', run))
                       for index, part in enumerate(parts))

    def cancels(self, run: 'dict[str, object]') -> 'bool':
        value = self.raw['cancel-in-progress']
        if isinstance(value, bool):
            return value
        return evaluate_condition(value, run)


class TestExperimentalSupersedesOnMain(unittest.TestCase):
    """experimental.yml: a pull request's and ``main``'s runs are superseded per ref."""

    def setUp(self) -> None:
        self.own = Concurrency('experimental.yml')

    def test_the_cases_below_cover_every_trigger(self) -> None:
        # Pushes to `main` and pull requests are all experimental.yml runs on
        # today; the other events below are the guard for a trigger added later.
        with open(WORKFLOWS / 'experimental.yml', encoding='utf-8') as file:
            spec = yaml.safe_load(file)
        on = spec.get('on', spec.get(True))
        self.assertEqual(set(on), {'push', 'pull_request'})
        self.assertEqual(on['push'], {'branches': ['main']})

    def test_pushes_to_main_share_one_cancelling_group(self) -> None:
        """#1903: the next push's run cancels the one in progress."""
        first, second = context('push', MAIN, '1'), context('push', MAIN, '2')
        self.assertEqual(self.own.group(first), f'experimental-tests-{MAIN}')
        self.assertEqual(self.own.group(first), self.own.group(second))
        self.assertTrue(self.own.cancels(second))

    def test_a_pull_request_still_shares_one_per_ref(self) -> None:
        first, second = context('pull_request', PULL, '1'), context('pull_request', PULL, '2')
        self.assertEqual(self.own.group(first), f'experimental-tests-{PULL}')
        self.assertEqual(self.own.group(first), self.own.group(second))
        self.assertTrue(self.own.cancels(second))
        other = context('pull_request', 'refs/pull/1904/merge', '3')
        self.assertNotEqual(self.own.group(other), self.own.group(first))
        self.assertNotEqual(self.own.group(first), self.own.group(context('push', MAIN, '1')))

    def test_any_other_run_gets_a_group_of_its_own_and_is_never_cancelled(self) -> None:
        """Including a dispatch or schedule on ``main``, which must not join the pushes' group."""
        for event_name, ref in (('push', 'refs/heads/feature'), ('schedule', MAIN),
                                ('workflow_dispatch', MAIN), ('workflow_run', MAIN)):
            with self.subTest(event_name=event_name, ref=ref):
                run = context(event_name, ref, '38497299656')
                self.assertEqual(self.own.group(run), 'experimental-tests-38497299656')
                self.assertFalse(self.own.cancels(run))


class TestUnitTestsKeepsARunPerCommit(unittest.TestCase):
    """unit-tests.yml is unchanged: only a pull request's run is superseded."""

    def setUp(self) -> None:
        self.unit = Concurrency('unit-tests.yml')

    def test_the_block_is_unchanged(self) -> None:
        self.assertEqual(self.unit.raw, {
            'group': "unit-tests-${{ github.workflow }}-"
                     "${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            'cancel-in-progress': "${{ github.event_name == 'pull_request' }}",
        })

    def test_each_push_to_main_gets_its_own_group(self) -> None:
        first = context('push', MAIN, '1', workflow='Unit Tests')
        second = context('push', MAIN, '2', workflow='Unit Tests')
        self.assertEqual(self.unit.group(first), 'unit-tests-Unit Tests-1')
        self.assertNotEqual(self.unit.group(first), self.unit.group(second))
        self.assertFalse(self.unit.cancels(second))


if __name__ == '__main__':
    unittest.main()
