# -*- coding: utf-8 -*-
"""Tests that ``tests/conftest.py`` drops pytest-timeout's retained timer (#1052).

pytest-timeout's ``thread`` method leaves ``item.cancel_timeout`` -- a closure over
the test's :class:`threading.Timer` -- on every item for the whole session, and the
timer pins the :mod:`pcapkit` generation whose tbtrim excepthooks were live when it
was created. Kept, that took the ``test`` legs' runners past their memory on CI.

"""

from __future__ import annotations

import types
import unittest

from tests import conftest


class TestCancelTimerHook(unittest.TestCase):

    def _drive(self, item):
        hook = conftest.pytest_timeout_cancel_timer(item)
        next(hook)
        with self.assertRaises(StopIteration):
            next(hook)

    def test_the_retained_timer_is_dropped_after_cancel(self):
        item = types.SimpleNamespace(cancel_timeout=lambda: None)
        self._drive(item)
        self.assertFalse(hasattr(item, 'cancel_timeout'))

    def test_an_item_without_a_timer_is_left_alone(self):
        item = types.SimpleNamespace(nodeid='x')
        self._drive(item)
        self.assertEqual(vars(item), {'nodeid': 'x'})

    def test_it_is_an_optional_wrapper(self):
        opts = conftest.pytest_timeout_cancel_timer.pytest_impl
        self.assertTrue(opts['hookwrapper'])
        self.assertTrue(opts['optionalhook'])


if __name__ == '__main__':
    unittest.main()
