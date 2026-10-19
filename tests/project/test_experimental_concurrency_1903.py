# -*- coding: utf-8 -*-
"""#1903: a newer run on ``main`` supersedes Experimental Tests' older one.

A group per push queues a GraalPy leg of up to two hours per commit in a merge
wave, holding runners the open pull requests' CI then waits behind. The owner
chose option 1: in experimental.yml only, a push to ``main`` is superseded by
the next one, as a pull request's run is. Nothing waits on these legs (#1732),
so the newest commit's run is enough. #1938 keeps that rule and drops the
cancelling: experimental.yml has no group (:class:`TestExperimentalHasNoGroup`),
and its gate and watcher skip or stop a superseded run instead, which
:mod:`tests.project.test_superseded_runs_1938` pins.

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


class TestExperimentalHasNoGroup(unittest.TestCase):
    """#1938: experimental.yml has no group, so nothing of it is ever cancelled.

    A newer commit still supersedes a run, by #1903's rule, through a gate and a
    watcher: :mod:`tests.project.test_superseded_runs_1938`.

    """

    def test_no_concurrency_block(self) -> None:
        with open(WORKFLOWS / 'experimental.yml', encoding='utf-8') as file:
            self.assertNotIn('concurrency', yaml.safe_load(file))


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
