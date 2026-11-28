# -*- coding: utf-8 -*-
"""#1732 and #1958: what the ``LATEST`` ignores leave out, by pytest's own collection.

:mod:`tests.project.test_sweeps_on_latest_only_1732` checks which modules each leg's
step ignores; :class:`TestTheIgnoresAreTheLatestTier` asks pytest what those ignores
then leave out of a directory, and checks the tier the harnesses' users fall in.

It is a module of its own because its child pytest imports :mod:`pcapkit` while it
collects, which makes a module no project pin (#1954). The module it left runs
nothing that imports the package, so it is a pin and runs once per push.

"""

from __future__ import annotations

import re
import subprocess  # nosec B404
import sys
import unittest

from tests import _tiers

#: Test tier (#1958): checks the workflows' tier selections.
__tier__ = 'LATEST'

ROOT = _tiers.ROOT
#: A directory holding sweeps, hand-picked round trips, and modules that only import
#: the sweeps' harnesses' packet builders, for :class:`TestTheIgnoresAreTheLatestTier`.
PROBE = 'tests/protocols/internet'


class TestTheIgnoresAreTheLatestTier(unittest.TestCase):
    """What the ``LATEST`` ignores leave out, by pytest's own collection."""

    def collect(self, *extra: 'str') -> 'set[str]':
        result = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '-q', '-p', 'no:cacheprovider',
                                 PROBE, *extra], cwd=ROOT, capture_output=True, text=True,  # nosec B603
                                check=False, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        return {line.split('::', 1)[0] for line in result.stdout.splitlines() if '::' in line}

    def test_pytest_leaves_out_exactly_the_latest_modules(self) -> None:
        """Run from the root, as CI runs it: the modules the ignores drop are the ``LATEST`` ones."""
        everything = self.collect()
        rest = self.collect(*(f'--ignore={module}' for module in _tiers.latest_tier_paths()))
        latest = {module for module in everything if _tiers.module_tier(module) == _tiers.TIER_LATEST}
        self.assertTrue(latest)
        self.assertEqual(everything - rest, latest)
        # A hand-picked round trip stays, and so does a module that imports a sweep's harness.
        self.assertTrue([module for module in rest if 'roundtrip' in module])
        builders = [module for module in rest if 'tests.foundation import _roundtrip'
                    in (ROOT / module).read_text(encoding='utf-8')]
        self.assertTrue(builders, f'no module under {PROBE} imports the harness without being LATEST')

    def test_the_tier_is_no_name_rule(self) -> None:
        """#1958: a name says nothing about the tier; ``LATEST`` sweeps go by other names too."""
        modules = _tiers.suite_modules()
        named = [module for module in modules if 'roundtrip' in module.rsplit('/', 1)[1]]
        latest = set(_tiers.latest_tier_paths())
        self.assertTrue([module for module in named if module not in latest])
        self.assertTrue([module for module in named if module in latest])
        self.assertTrue([module for module in latest if module not in named and 'tests/project/' not in module])

    @staticmethod
    def harness_users(harness: 'str') -> 'list[str]':
        """The unit-tier modules that import a table type from ``harness``."""
        return [module for module in _tiers.suite_modules() if _tiers.is_unit_tier(module) and re.search(
            rf'^from {re.escape(harness[:-3].replace("/", "."))} import .*\b(?:Case|KnownFailureTable)\b',
            (ROOT / module).read_text(encoding='utf-8'), re.M)]

    def test_every_module_on_the_corekit_harness_is_latest(self) -> None:
        """The corekit tables build a case for every class they enumerate, so their users are sweeps."""
        users = self.harness_users('tests/corekit/_roundtrip.py')
        self.assertTrue(users)
        self.assertEqual([module for module in users if _tiers.module_tier(module) != _tiers.TIER_LATEST], [])

    def test_the_edge_case_tables_run_on_every_leg(self) -> None:
        """#1958: the #1202 edge-case tables are written out by hand, so they run on every leg."""
        deadline = 'tests/protocols/test_edge_roundtrip_deadline_1736_unit.py'
        users = self.harness_users('tests/protocols/_edge_roundtrip.py')
        self.assertIn(deadline, users)
        tables = [module for module in users if module != deadline]
        self.assertTrue(tables)
        self.assertEqual([module for module in tables if _tiers.module_tier(module) != _tiers.TIER_ALL], [])
        self.assertEqual(_tiers.module_tier(deadline), _tiers.TIER_LATEST)


if __name__ == '__main__':
    unittest.main()
