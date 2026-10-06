# -*- coding: utf-8 -*-
"""Tests for ``util/run_unittest_leg.py``'s stall dump, periodic collect and no-restore contract (#1052).

A leg that stalls is killed by the step cap with nothing in the log to say where
it was, so the runner arms :func:`faulthandler.dump_traceback_later` before it
builds the suite and cancels it on the way out. The in-process tests mock
:mod:`faulthandler`, because this module itself runs inside the ``project`` leg,
whose own dump is armed; the subprocess test lets a real one fire.

The last class pins the decision #1052 recorded against restoring
:data:`sys.modules` between tests: a sibling's write to the ``pcapkit`` region
must survive into the next test, or the leg stops seeing #981's class of skew.

"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]

if str(ROOT / 'util') not in sys.path:
    sys.path.insert(0, str(ROOT / 'util'))

import run_unittest_leg as leg  # noqa: E402  pylint: disable=wrong-import-position


class TestStallDumpArming(unittest.TestCase):

    def _main(self, argv, env=None, run=None):
        environ = {k: v for k, v in os.environ.items() if k != leg.STALL_DUMP_ENV}
        environ.update(env or {})
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(leg.faulthandler, 'dump_traceback_later') as arm, \
                mock.patch.object(leg.faulthandler, 'cancel_dump_traceback_later') as cancel, \
                mock.patch.object(leg, '_run', run or mock.Mock(return_value=0)):
            try:
                code = leg.main(argv)
            except (Exception, SystemExit) as exc:  # pylint: disable=broad-except
                code = exc
        return code, arm, cancel

    def test_default_is_just_under_a_twenty_minute_cap(self):
        code, arm, cancel = self._main(['cli'])
        self.assertEqual(code, 0)
        arm.assert_called_once()
        self.assertEqual(arm.call_args.args, (1080.0,))
        self.assertEqual(arm.call_args.kwargs['repeat'], False)
        self.assertEqual(arm.call_args.kwargs['exit'], False)
        self.assertLess(leg.DEFAULT_STALL_DUMP, 20 * 60)
        cancel.assert_called_once_with()

    def test_environment_overrides_the_default(self):
        _, arm, _ = self._main(['cli'], env={leg.STALL_DUMP_ENV: '30'})
        self.assertEqual(arm.call_args.args, (30.0,))

    def test_flag_overrides_the_environment(self):
        _, arm, _ = self._main(['cli', '--stall-dump', '7'], env={leg.STALL_DUMP_ENV: '30'})
        self.assertEqual(arm.call_args.args, (7.0,))

    def test_zero_disables_it(self):
        _, arm, _ = self._main(['cli', '--stall-dump', '0'])
        arm.assert_not_called()

    def test_bad_environment_value_is_a_usage_error(self):
        with mock.patch('sys.stderr'):
            code, arm, _ = self._main(['cli'], env={leg.STALL_DUMP_ENV: 'soon'})
        self.assertIsInstance(code, SystemExit)
        self.assertEqual(code.code, 2)
        arm.assert_not_called()

    def test_cancelled_when_the_leg_raises(self):
        code, arm, cancel = self._main(['cli'], run=mock.Mock(side_effect=KeyError('boom')))
        self.assertIsInstance(code, KeyError)
        arm.assert_called_once()
        cancel.assert_called_once_with()


class TestStallDumpFires(unittest.TestCase):

    def test_a_stalled_leg_dumps_its_stack_and_keeps_running(self):
        script = textwrap.dedent(f'''
            import sys, time, unittest
            sys.path.insert(0, {str(ROOT / 'util')!r})
            import run_unittest_leg as leg

            class Stall(unittest.TestCase):
                def test_sleeps_past_the_dump(self):
                    time.sleep(2)

            leg.build_suite = lambda *a: unittest.TestLoader().loadTestsFromTestCase(Stall)
            sys.exit(leg.main(['cli', '--stall-dump', '0.5']))
        ''')
        proc = subprocess.run([sys.executable, '-c', script], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Timeout (0:00:00.500000)!', proc.stderr)
        self.assertIn('test_sleeps_past_the_dump', proc.stderr)
        self.assertEqual(proc.stderr.count('Timeout ('), 1, 'repeat=False dumps once')
        self.assertIn('1 test(s), 0 failure(s), 0 error(s)', proc.stdout)


class TestPeriodicCollect(unittest.TestCase):
    """``--gc-every N`` frees unreachable re-import generations every N tests (#1052)."""

    @staticmethod
    def _suite(n):
        class Trivial(unittest.TestCase):
            pass
        for i in range(n):
            setattr(Trivial, f'test_{i}', lambda self: None)
        return unittest.TestLoader().loadTestsFromTestCase(Trivial)

    def _collects(self, argv, tests=6):
        with mock.patch.object(leg, 'build_suite', return_value=self._suite(tests)), \
                mock.patch.object(leg.faulthandler, 'dump_traceback_later'), \
                mock.patch.object(leg.faulthandler, 'cancel_dump_traceback_later'), \
                mock.patch.object(leg.gc, 'collect') as collect, \
                mock.patch('sys.stderr'), mock.patch('sys.stdout'):
            self.assertEqual(leg.main(argv), 0)
        return collect.call_count

    def test_default_collects_every_ten_tests(self):
        self.assertEqual(leg.DEFAULT_GC_EVERY, 10)
        self.assertEqual(self._collects(['cli'], tests=25), 2)

    def test_every_n_tests(self):
        self.assertEqual(self._collects(['cli', '--gc-every', '4'], tests=9), 2)
        self.assertEqual(self._collects(['cli', '--gc-every', '1'], tests=3), 3)

    def test_zero_disables_it(self):
        self.assertEqual(self._collects(['cli', '--gc-every', '0']), 0)


class TestNoModuleTableRestore(unittest.TestCase):
    """The leg must not heal a sibling's ``sys.modules`` write (#981, #1052)."""

    PROBE = 'pcapkit._run_unittest_leg_probe'

    def tearDown(self):
        sys.modules.pop(self.PROBE, None)

    def test_a_write_survives_into_the_next_test(self):
        probe, seen = object(), []

        class Writer(unittest.TestCase):
            def test_a(self_):  # pylint: disable=no-self-argument
                sys.modules[TestNoModuleTableRestore.PROBE] = probe

        class Reader(unittest.TestCase):
            def test_b(self_):  # pylint: disable=no-self-argument
                seen.append(sys.modules.get(TestNoModuleTableRestore.PROBE))

        loader = unittest.TestLoader()
        suite = unittest.TestSuite([loader.loadTestsFromTestCase(Writer),
                                    loader.loadTestsFromTestCase(Reader)])
        args = leg.argparse.Namespace(directory='cli', exclude=[], verbose=False,
                                     gc_every=leg.DEFAULT_GC_EVERY)
        with mock.patch.object(leg, 'build_suite', return_value=suite), \
                mock.patch('sys.stderr'), mock.patch('sys.stdout'):
            self.assertEqual(leg._run(args, 0.0), 0)  # pylint: disable=protected-access
        self.assertEqual(seen, [probe])


if __name__ == '__main__':
    unittest.main()
