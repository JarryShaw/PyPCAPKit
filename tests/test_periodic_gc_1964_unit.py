# -*- coding: utf-8 -*-
"""Tests that ``tests/conftest.py`` collects cyclic garbage every few tests (#1964).

Every test leaves unreachable cycles behind, and the free-threaded build's
collector reclaims them so rarely that a free-threaded xdist worker grows until
the experimental leg's memory scope kills it. The conftest collects on a fixed
count of finished tests instead of waiting for the collector's own thresholds.

"""

from __future__ import annotations

import gc
import unittest
from unittest import mock

from tests import conftest


class TestPeriodicCollection(unittest.TestCase):

    def setUp(self):
        # Start from a clean count, and hand the running session its own back.
        saved = conftest._tests_since_collect
        self.addCleanup(setattr, conftest, '_tests_since_collect', saved)
        conftest._tests_since_collect = 0

    def test_the_interval_is_pinned(self):
        self.assertEqual(conftest.GC_EVERY, 50)

    def test_it_collects_once_every_interval(self):
        with mock.patch.object(gc, 'collect') as collect:
            ran = [conftest._collect_periodically() for _ in range(3 * conftest.GC_EVERY)]
        self.assertEqual(collect.call_count, 3)
        self.assertEqual([i for i, hit in enumerate(ran, 1) if hit],
                         [conftest.GC_EVERY, 2 * conftest.GC_EVERY, 3 * conftest.GC_EVERY])

    def test_the_hook_counts_after_the_test_has_run(self):
        conftest._tests_since_collect = conftest.GC_EVERY - 1
        with mock.patch.object(gc, 'collect') as collect:
            hook = conftest.pytest_runtest_protocol(item=None, nextitem=None)
            next(hook)
            # Setup, call and teardown happen here; nothing is collected yet, so
            # the generation restore_module_table drops on teardown is included.
            collect.assert_not_called()
            with self.assertRaises(StopIteration):
                next(hook)
        collect.assert_called_once_with()
        self.assertEqual(conftest._tests_since_collect, 0)

    def test_it_is_a_wrapper(self):
        self.assertTrue(conftest.pytest_runtest_protocol.pytest_impl['hookwrapper'])


if __name__ == '__main__':
    unittest.main()
