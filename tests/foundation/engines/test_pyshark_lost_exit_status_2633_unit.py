# -*- coding: utf-8 -*-
"""The PyShark engine does not raise for a tshark whose exit status asyncio lost. C.f. #2633.

A ``Popen.poll`` that reaps a tshark before the event loop has handled its
``SIGCHLD`` leaves the child watcher no child, so it reports ``255``, and pyshark's
``close`` raises ``TSharkCrashException`` into :meth:`PyShark.close` for a capture
read in full. pyshark 0.6 hits it at end of file, killing tshark through asyncio,
whose ``kill`` polls through ``Popen.send_signal`` on CPython 3.9 to 3.12
(gh-87744; found on #2620). The engine checks the evidence, never the version.

:class:`LostExitStatusTests` closes stand-ins for pyshark's capture and asyncio's
processes. Each case pairs the crash the engine absorbs with the same crash
differing in one condition, which still raises. :class:`RealPollTests` loses a real
exit status to a real poll, in a child interpreter so that its child watcher and
``SIGCHLD`` handler stay there. ``pyshark`` itself is never imported, so this runs
where it is absent or cannot run.

"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import subprocess
import sys
import threading
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): asyncio's child watchers differ by interpreter, and this drives
#: a third-party engine whose installable releases vary by interpreter.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _loop_reaps() -> bool:
    """Whether asyncio reaps a child only when its event loop runs, as pyshark's watcher does."""
    if os.name != 'posix':
        return False
    import asyncio.unix_events  # isort:skip

    pidfd = getattr(asyncio.unix_events, 'can_use_pidfd', lambda: False)
    return hasattr(asyncio, 'SafeChildWatcher') or bool(pidfd())


#: The engine's logger.
LOGGER = 'pcapkit.foundation.engines.pyshark'

#: The pid every stand-in process has.
PID = 4242


class TSharkCrashException(Exception):
    """A stand-in for ``pyshark.capture.capture.TSharkCrashException``."""


def stand_in_pyshark() -> 'Any':
    """Patch in a ``pyshark.capture.capture`` whose ``TSharkCrashException`` is the stand-in."""
    module = types.ModuleType('pyshark.capture.capture')
    module.TSharkCrashException = TSharkCrashException  # type: ignore[attr-defined]
    return mock.patch.dict(sys.modules, {
        'pyshark': types.ModuleType('pyshark'),
        'pyshark.capture': types.ModuleType('pyshark.capture'),
        'pyshark.capture.capture': module,
    })


class Process:
    """A stand-in asyncio subprocess: the status it reports, and what its ``Popen`` read."""

    def __init__(self, reported: 'Optional[int]', read: 'Optional[int]') -> None:
        self.pid = PID
        self.returncode = reported
        popen = types.SimpleNamespace(returncode=read)
        self._transport = types.SimpleNamespace(get_extra_info={'subprocess': popen}.get)


class Capture:
    """A stand-in for pyshark 0.6's ``Capture``, keeping what its ``close`` and ``__del__`` do.

    Takes real asyncio processes as readily as :class:`Process` stand-ins.

    """

    def __init__(self, *processes: 'Any', eof: bool = True,
                 error: 'type[Exception]' = TSharkCrashException) -> None:
        self._running_processes = set(processes)
        self._eof_reached = eof
        self.error = error
        self.closes = 0
        self.raised = []  # type: list[Exception]

    def crash(self, pid: int, returncode: int) -> None:
        self.raised.append(self.error(f'TShark (pid {pid}) seems to have crashed '
                                      f'(retcode: {returncode}).'))
        raise self.raised[-1]

    def _cleanup_subprocess(self, process: 'Any') -> None:
        # a tshark that exited above 0 crashed, unless it exited 1 before end of file
        if process.returncode is not None and process.returncode > 0:
            if process.returncode != 1 or self._eof_reached:
                self.crash(process.pid, process.returncode)

    def close(self) -> None:
        self.closes += 1
        for process in self._running_processes.copy():
            self._cleanup_subprocess(process)
        self._running_processes.clear()

    def __del__(self) -> None:
        if self._running_processes:
            self.close()


class Unlisted(Capture):
    """A capture whose ``close`` raises the crash with no tshark listed."""

    def close(self) -> None:
        self.closes += 1
        self.crash(PID, 255)


#: Marks a stand-in process with no ``_transport`` at all.
NO_TRANSPORT = object()


def engine(capture: 'Capture') -> 'Any':
    """A PyShark engine whose capture is ``capture``."""
    from pcapkit.foundation.engines.pyshark import PyShark

    instance = PyShark.__new__(PyShark)  # skip __init__, which imports pyshark
    instance._extmp = capture
    return instance


def lost() -> 'Capture':
    """A capture read to its end whose tshark exited 0, and asyncio reported 255."""
    return Capture(Process(255, 0))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class LostExitStatusTests(unittest.TestCase):
    """:meth:`PyShark.close` absorbs a lost exit status, and nothing else."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def close(self, capture: 'Capture') -> 'Optional[Exception]':
        """Close ``capture`` through the engine; what it raised, if anything."""
        closing = engine(capture)
        with stand_in_pyshark():
            try:
                closing.close()
            except Exception as error:  # pylint: disable=broad-except
                capture._running_processes.clear()  # keep its __del__ quiet here
                return error
        return None

    def assertRaisedOnlyWithout(self, raised: 'Capture') -> None:
        """A lost status is absorbed, and ``raised``, one condition away from it, is not."""
        self.addCleanup(raised._running_processes.clear)  # in case it is never closed
        self.assertIsNone(self.close(lost()))
        error = self.close(raised)
        # the crash pyshark raised, as it raised it, and its close not run again
        self.assertEqual(raised.raised, [error])
        self.assertEqual(raised.closes, 1)

    def test_a_lost_exit_status_is_not_raised(self) -> None:
        import pcapkit.foundation.engines.pyshark  # isort:skip # pylint: disable=unused-import

        # read once pcapkit is imported, which installs hooks of its own
        hooks = sys.excepthook, threading.excepthook
        capture = lost()
        with self.assertLogs(LOGGER, logging.DEBUG) as logs:
            self.assertIsNone(self.close(capture))
        self.assertEqual(capture._running_processes, set())
        self.assertEqual(capture.closes, 2, "pyshark's own close runs to its end")
        # a handled condition: logged at DEBUG alone, and no hook installed
        self.assertEqual([record.levelno for record in logs.records], [logging.DEBUG])
        self.assertIn(f'pid {PID}', logs.output[0])
        self.assertIn('asyncio reports 255, but its Popen read 0', logs.output[0])
        self.assertEqual((sys.excepthook, threading.excepthook), hooks)

    def test_no_python_version_gates_it(self) -> None:
        closing = engine(Capture())  # imported first, on the real version_info
        for python in ((3, 8), (3, 9), (3, 12), (3, 13), (3, 14), (3, 15)):
            with self.subTest(python=python):
                capture = closing._extmp = lost()
                with stand_in_pyshark(), mock.patch.object(sys, 'version_info',
                                                           (*python, 0, 'final', 0)):
                    closing.close()
                self.assertEqual(capture._running_processes, set())

    def test_the_capture_is_left_nothing_for_its_finaliser_to_raise(self) -> None:
        capture = lost()
        self.assertIsNone(self.close(capture))
        capture.__del__()  # what pyshark runs when the capture is collected
        self.assertEqual(capture.closes, 2)

    def test_a_crash_before_end_of_file_still_raises(self) -> None:
        self.assertRaisedOnlyWithout(Capture(Process(255, 0), eof=False))

    def test_a_retcode_other_than_255_still_raises(self) -> None:
        for reported in (1, 2, 254):
            with self.subTest(retcode=reported):
                self.assertRaisedOnlyWithout(Capture(Process(reported, 0)))

    def test_a_failure_its_popen_read_still_raises(self) -> None:
        # a tshark that failed, or exited 255 itself, before the poll took its status
        for read in (2, 255):
            with self.subTest(read=read):
                self.assertRaisedOnlyWithout(Capture(Process(255, read)))

    def test_a_tshark_still_listed_alongside_still_raises(self) -> None:
        self.assertRaisedOnlyWithout(Capture(Process(255, 0), Process(None, None)))

    def test_another_error_with_the_same_message_still_raises(self) -> None:
        self.assertRaisedOnlyWithout(Capture(Process(255, 0), error=RuntimeError))

    def test_a_crash_with_no_tshark_listed_still_raises(self) -> None:
        self.assertRaisedOnlyWithout(Unlisted())

    def test_a_process_whose_popen_cannot_be_read_still_raises(self) -> None:
        # each shape lacks what the lookup reads; asyncio's own processes lack none of it
        shapes = {
            'no _transport': NO_TRANSPORT,
            '_transport is None': None,
            'no get_extra_info': types.SimpleNamespace(),
            'no subprocess': types.SimpleNamespace(get_extra_info={}.get),
            'no returncode': types.SimpleNamespace(
                get_extra_info={'subprocess': types.SimpleNamespace()}.get),
        }
        for shape, transport in shapes.items():
            with self.subTest(shape=shape):
                process = Process(255, 0)
                if transport is NO_TRANSPORT:
                    del process._transport
                else:
                    process._transport = transport
                self.assertRaisedOnlyWithout(Capture(process))


#: A child interpreter that loses real exit statuses to a real ``Popen.poll``, under
#: the ``SafeChildWatcher`` pyshark 0.6 installs where asyncio has one, and
#: closes each through the engine. ``argv[1]`` is the checkout. It prints one JSON
#: object per exit code.
REAL_POLL_CHILD = '''\
import asyncio, json, logging, os, re, subprocess, sys, warnings
sys.path.insert(0, sys.argv[1])
from tests.foundation.engines.test_pyshark_lost_exit_status_2633_unit import (
    Capture, engine, stand_in_pyshark)

warnings.simplefilter('ignore', DeprecationWarning)
records = []


class Keep(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())


logging.getLogger('asyncio').addHandler(Keep())
logging.getLogger('asyncio').propagate = False

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
if hasattr(asyncio, 'SafeChildWatcher'):  # otherwise the pidfd watcher, also loop-driven
    asyncio.set_child_watcher(asyncio.SafeChildWatcher())
    asyncio.get_child_watcher().attach_loop(loop)


async def run(code):
    process = await asyncio.create_subprocess_exec(
        sys.executable, '-c', f'raise SystemExit({code})',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)  # exited, not yet reaped
    # reap it as the poll in Popen.send_signal does under asyncio's kill (gh-87744)
    process._transport.get_extra_info('subprocess').poll()
    await asyncio.wait_for(process.wait(), 60)
    return process


for code in (0, 2):
    process = loop.run_until_complete(run(code))
    capture = Capture(process)
    closing = engine(capture)  # imports pcapkit before patch.dict, whose exit would unload it
    with stand_in_pyshark():
        try:
            closing.close()
            raised = None
        except Exception as error:
            raised = type(error).__name__
    print(json.dumps({
        'exit': code, 'raised': raised, 'asyncio': process.returncode,
        'popen': process._transport.get_extra_info('subprocess').returncode,
        'lost': any(re.search(rf'\\bpid {process.pid}\\b.*will report returncode 255', message)
                    for message in records),
        'listed': len(capture._running_processes),
    }))
    capture._running_processes.clear()
'''


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
# a watcher thread reaps the child at once, so no poll can take its status first
@unittest.skipUnless(hasattr(os, 'waitid') and _loop_reaps(),
                     "needs os.waitid, to wait for a child's exit without reaping it, and a "
                     'child watcher driven by the event loop')
class RealPollTests(unittest.TestCase):
    """The status a real poll takes is absorbed for a clean exit, and raised for a failure."""

    def test_a_real_lost_exit_status(self) -> None:
        child = subprocess.run([sys.executable, '-c', REAL_POLL_CHILD, str(ROOT)],
                               capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(child.returncode, 0, child.stderr)
        clean, failed = (json.loads(line) for line in child.stdout.splitlines()
                         if line.startswith('{'))

        # asyncio lost both statuses to the poll, which read the real ones
        self.assertEqual((clean['asyncio'], clean['popen'], clean['lost']), (255, 0, True))
        self.assertEqual((failed['asyncio'], failed['popen'], failed['lost']), (255, 2, True))
        self.assertEqual((clean['raised'], clean['listed']), (None, 0))
        self.assertEqual((failed['raised'], failed['listed']), ('TSharkCrashException', 1))


if __name__ == '__main__':
    unittest.main()
