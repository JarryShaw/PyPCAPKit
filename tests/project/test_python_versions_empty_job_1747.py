# -*- coding: utf-8 -*-
"""#1747: the version updater names a job its update would leave with no leg.

``pypcap-parity`` holds the supported versions below 3.12 only (#1746), so 3.11
reaching end of life leaves its matrix empty while ``required-checks`` still
needs it. The owner's ruling on #1747: the updater retires nothing; its
proposal flags the job as a manual step, for him to retire or remove it, rather
than quietly writing a zero-leg matrix. The tier file is still written as
computed, and the fingerprint is still the tiers alone.

The scenarios are :mod:`tests.project.test_python_versions_update_1660`'s.

"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_versions_update_1660 import (FROZEN, ROOT, as_of_the_file, changes, drop_build,
                                                            drop_image, notes, plan_for, set_status, snapshot,
                                                            three_eleven_ends_and_three_sixteen_ships, updater,
                                                            with_experimental)

if TYPE_CHECKING:
    from typing import Any

#: What 3.11 reaching end of life asks of the owner.
PARITY = ('unit-tests.yml: `pypcap-parity` would have no leg left once 3.11 moves to KTLO; retire or remove the '
          'job (and its `needs:` in `required-checks`) before merging this update')
#: What 3.10 losing its ubuntu-26.04 build asks: no job needs a KTLO twin (#1738).
PARITY_KTLO = ('unit-tests.yml: `pypcap-parity-ktlo` would have no leg left once 3.10 runs on ubuntu-24.04; '
               'retire or remove the job before merging this update')


def describe(plan: 'dict[str, Any]') -> 'str':
    return updater().describe_plan(plan, ('success', []), 'https://example.invalid/run')


class TestAnEmptiedJobIsAManualStep(unittest.TestCase):
    """Each job a tier move leaves with no leg is named, with what to retire; the tiers are written regardless."""

    def test_three_eleven_ending_names_pypcap_parity(self) -> None:
        for label, sources in (('3.11 ends', set_status(as_of_the_file(snapshot()), '3.11', 'end-of-life')),
                               ('and 3.16 ships', three_eleven_ends_and_three_sixteen_ships(snapshot()))):
            with self.subTest(scenario=label):
                _, plan, texts = plan_for(self, sources)
                self.assertEqual(plan['retire'], [PARITY])
                self.assertIn(PARITY, notes(plan, 'manual'))
                # The tier move is still proposed as computed.
                self.assertEqual(changes(plan)['3.11'], ({'tier': 'supported'}, {'tier': 'ktlo'}))
                self.assertIn('"3.11" = { tier = "ktlo" }\n', texts['.github/python-versions.toml'])

    def test_the_body_puts_it_first_and_once(self) -> None:
        _, plan, _ = plan_for(self, set_status(as_of_the_file(snapshot()), '3.11', 'end-of-life'))
        description = describe(plan)
        self.assertEqual(description.count(PARITY), 1)
        block = description.index('**Before merging, retire or remove these jobs by hand**')
        self.assertLess(block, description.index(f'- {PARITY}'))
        self.assertLess(description.index(f'- {PARITY}'), description.index('**Before merging, edit ruleset'))
        self.assertLess(description.index(f'- {PARITY}'), description.index('Not done here:'))

    def test_no_note_when_no_job_empties(self) -> None:
        """PyPy 3.12 joining, and 3.7 leaving ``test-ktlo`` with three legs; ``experimental`` was empty already."""
        for label, sources in (('pypy3.12 joins', snapshot()),
                               ('3.7 drops', drop_image(as_of_the_file(snapshot()), 'ubuntu-22.04'))):
            with self.subTest(scenario=label):
                _, plan, _ = plan_for(self, sources)
                self.assertTrue(plan['changes'])
                self.assertEqual(plan['retire'], [])
                self.assertFalse([text for text in notes(plan, 'manual') if 'no leg left' in text])
                self.assertNotIn('retire or remove', describe(plan))

    def test_a_ktlo_twin_emptying_is_flagged(self) -> None:
        """3.10, ``pypcap-parity-ktlo``'s one leg, needs ubuntu-24.04, which that job does not run on."""
        _, plan, _ = plan_for(self, drop_build(as_of_the_file(snapshot()), '3.10', '26.04'))
        self.assertEqual(plan['retire'], [PARITY_KTLO])
        self.assertIn(PARITY_KTLO, notes(plan, 'manual'))
        self.assertIn(f'- {PARITY_KTLO}', describe(plan))

    def test_experimental_yml_is_covered_too(self) -> None:
        """Its entries are hand-kept, so no run empties it; the check reads every matrix job all the same."""
        module = updater()
        workflows = module.load_workflows(ROOT)
        before = module.pv.outputs(module.validate(with_experimental(FROZEN.read_text(encoding='utf-8'))))
        after = module.pv.outputs(module.validate(FROZEN.read_text(encoding='utf-8')))
        self.assertEqual(module.emptied_jobs(workflows, before, after, {}), [
            'experimental.yml: `experimental` would have no leg left once 3.14t leaves it and graalpy-25.4 leaves '
            'it; retire or remove the job before merging this update'])
        self.assertEqual(module.emptied_jobs(workflows, after, after, {}), [])
