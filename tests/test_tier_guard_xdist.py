# -*- coding: utf-8 -*-
"""The tier guard's diagnostic survives running under pytest-xdist.

:func:`tests.conftest.pytest_collection_modifyitems` raises :exc:`pytest.UsageError`
with a detailed diagnostic when a unit-tier module reads a generated capture. Under
``-n auto --dist load`` that message can be lost entirely: each xdist worker
runs this hook inside its own nested :program:`pytest` session
(:mod:`xdist.remote`), and that session's ``pytest_collection_finish`` fires from a
``finally:`` regardless of the ``UsageError``, so the controller sees what looks
like a normal collection and may schedule a test to a worker that is already
unwinding. The controller then reports that test as crashed --
``assert not crashitem`` in :mod:`xdist.dsession` -- which prints an
``INTERNALERROR`` instead of the diagnostic and describes the violation as a
worker crash rather than as the tier-guard failure it is.

So the hook sets ``session.shouldfail`` before raising, but only inside a worker
(``hasattr(config, 'workerinput')``): that is the signal the controller already
knows how to shut a worker down on cleanly, with no crash-item assertion, and it is
a no-op outside a worker so the serial path is untouched.

:class:`CollectionModifyItemsXdistTests` pins the hook's own logic directly and
runs unconditionally. :class:`XdistSubprocessTests` reproduces the bug
end-to-end with a real violation and a real ``pytest -n auto --dist load``
invocation, and skips when :mod:`xdist` is not importable -- the repository venv
this suite normally runs under deliberately has no xdist installed.

A second, independent race lives at the same address. :mod:`tests.test_tier_guard`'s
``SuiteIsCleanTests`` walks the whole :file:`tests/` tree looking for exactly the
kind of violation :class:`XdistSubprocessTests` deliberately writes to disk; under
``-n auto --dist load`` pytest-xdist may run the two in different worker processes
at the same moment, and the scan then reports a violation nobody committed --
measured on a real CI run, ``Integration Python 3.13``, one leg in five, 466s in.
:func:`tests.conftest._tier_guard_lock` closes it with a readers-writer mutex:
:class:`XdistSubprocessTests` below takes the exclusive hold in ``setUp`` for as
long as the probe sits on disk, and :func:`tests.conftest._tier_guard_reader_lock`
takes the shared hold on behalf of every other unit-tier test, including
``SuiteIsCleanTests``, from :mod:`tests.conftest` alone.
:class:`ProbeWriteLockTests` pins the mutex itself, independently of xdist.

A third (#1756): a worker that dies mid-probe never runs its cleanup, and the
replacement worker xdist starts collects the stale probe. ``collect_ignore`` in
:mod:`tests.conftest` keeps the probe out of every recursive collection, and
:class:`ProbeWorkerCrashTests` kills a real worker mid-probe to pin that.

A fourth (#1758): checking for a leftover probe before the exclusive hold is
granted mistakes another worker's live probe for one. Both probe writers check
only under the lock, and :class:`ProbeLeftoverCheckTests` pins that ordering.

A fifth (#1977): GraalPy holds the GIL inside a blocking :func:`fcntl.flock`, so
a blocking lock deadlocks :class:`ProbeWriteLockTests`'s own process and queues
every worker behind it. On GraalPy the lock polls with ``LOCK_NB``, and
:class:`ProbeLockNonBlockingTests` pins that it never makes a blocking call.

Kept separate from :mod:`tests.test_tier_guard`: this module exercises
:mod:`tests.conftest`, and none of :mod:`tests.test_tier_guard`'s code.

"""
from __future__ import annotations

import errno
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import types
import unittest
import unittest.mock
from typing import TYPE_CHECKING

from tests import _tiers, conftest as _conftest

if TYPE_CHECKING:
    from typing import Callable, ContextManager

#: Test tier (#1958): checks the guard in xdist workers on each leg's interpreter.
__tier__ = 'ALL'

#: Why the nested-session probes skip GraalPy (#1963): each starts a whole
#: ``pytest -n`` session of fresh GraalPy interpreters, which took minutes a test
#: on the experimental leg while the other workers idled. What they pin is the
#: guard's xdist handling, which no interpreter changes, so the CPython legs cover it.
SKIP_NESTED_ON_GRAALPY = 'a nested pytest-xdist session is too slow on GraalPy (#1963)'

#: Capture name the probe module in :class:`XdistSubprocessTests` reads. Not
#: tracked by git -- see :func:`tests._tiers.committed_captures` -- so it is a
#: tier violation regardless of what ``make samples`` has built locally.
_GENERATED_CAPTURE = 'xdist_probe_generated.pcap'

#: Diagnostic text that must survive however the suite is run, per
#: :func:`tests.conftest.pytest_collection_modifyitems`.
_DIAGNOSTIC_MARKER = 'read(s) of a generated sample capture'


class _FakeSession:
    """Stands in for :class:`pytest.Session`; the hook touches only this attribute."""

    def __init__(self) -> None:
        self.shouldfail = False  # type: 'bool | str'


class _FakeConfig:
    """Stands in for :class:`pytest.Config`.

    ``workerinput`` is set only by :mod:`xdist.remote` inside an actual worker
    process, and its mere presence -- never its content -- is what the hook
    checks; see ``xdist/remote.py``'s bootstrap, which does
    ``config.workerinput = workerinput``.

    """

    def __init__(self, is_worker: bool) -> None:
        if is_worker:
            self.workerinput = {'workerid': 'gw0'}  # type: dict[str, str]


class CollectionModifyItemsXdistTests(unittest.TestCase):
    """:func:`tests.conftest.pytest_collection_modifyitems` against a fake worker."""

    def _findings(self, session: '_FakeSession', config: '_FakeConfig') -> 'str':
        """Run the hook with one synthetic finding and return the raised message.

        ``_audit`` and ``guard_unavailable_reason`` are patched so the outcome
        depends only on the ``if findings:`` branch under test, never on whether
        this checkout's own git state happens to be clean.

        """
        with unittest.mock.patch.object(_conftest, 'guard_unavailable_reason',
                                         return_value=None), \
             unittest.mock.patch.object(_conftest, '_audit',
                                         return_value=['a synthetic finding']):
            with self.assertRaises(Exception) as caught:
                _conftest.pytest_collection_modifyitems(
                    session=session, config=config, items=[])
        self.assertIsInstance(caught.exception, Exception)
        return str(caught.exception)

    def test_worker_context_sets_shouldfail_before_raising(self) -> None:
        """Inside a worker, the diagnostic is also stashed on ``session.shouldfail``.

        Without the fix, ``session.shouldfail`` stays at its initial
        :data:`False` because nothing ever assigns to it.

        """
        session = _FakeSession()
        message = self._findings(session, _FakeConfig(is_worker=True))

        self.assertEqual(session.shouldfail, message)
        self.assertIn(_DIAGNOSTIC_MARKER, message)
        self.assertIn('a synthetic finding', message)

    def test_serial_context_leaves_shouldfail_untouched(self) -> None:
        """Outside a worker, ``session.shouldfail`` is left untouched."""
        session = _FakeSession()
        message = self._findings(session, _FakeConfig(is_worker=False))

        self.assertIs(session.shouldfail, False)
        self.assertIn(_DIAGNOSTIC_MARKER, message)


def _child_environ() -> 'dict[str, str]':
    """The environment a subprocess :program:`pytest` run should inherit.

    Same rationale as :func:`tests.project.test_module_isolation.child_environ`:
    the child must import the tree this test runs from, and must not inherit this
    process's own pytest session variables.

    """
    environ = dict(os.environ)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(_tiers.ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH')
        else [str(_tiers.ROOT)]
    )
    environ.pop('PYTEST_ADDOPTS', None)
    environ.pop('PYTEST_CURRENT_TEST', None)
    return environ


@unittest.skipUnless(importlib.util.find_spec('xdist') is not None,
                      'pytest-xdist not installed')
@unittest.skipIf(sys.implementation.name == 'graalpy', SKIP_NESTED_ON_GRAALPY)
class XdistSubprocessTests(unittest.TestCase):
    """End-to-end reproduction: a real violation, a real ``pytest`` subprocess.

    Skipped whenever the interpreter running this suite has no ``xdist`` to
    import -- true of the repository's own venv by design, so this class
    contributes nothing there and everything under a venv that has xdist
    installed.

    """

    #: Sorts late and is unambiguously a probe, in case a stray copy is ever left
    #: behind by an interrupted run. Kept as an alias of
    #: :data:`tests._tiers.PROBE_MODULE_NAME` rather than a second literal --
    #: that name is what tells :func:`tests.conftest._tier_guard_reader_lock` to
    #: leave this class's own writes unlocked, and the two must never drift.
    PROBE_NAME = _tiers.PROBE_MODULE_NAME

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        self.probe_path = _tiers.TESTS_ROOT / 'protocols' / self.PROBE_NAME

        # Exclusive for as long as the probe sits on disk: see
        # tests.conftest._tier_guard_lock for the SuiteIsCleanTests race this
        # closes under -n auto --dist load. Entered manually, rather than with
        # a `with` block around the rest of setUp, because the hold has to
        # outlive this method and span the test body and cleanup too; released
        # only after the probe is gone -- addCleanup runs LIFO, so registering
        # the release first and the unlink second is what makes the unlink run
        # while still holding the lock and the release run after it.
        lock = _conftest._tier_guard_lock(exclusive=True)
        lock.__enter__()
        self.addCleanup(lock.__exit__, None, None, None)
        # Only under the lock (#1758): before it, a probe on disk may be another
        # worker's live one -- this class's other test, or ProbeWorkerCrashTests
        # -- rather than a leftover. The release is registered first, so a
        # failure here still lets go of the lock.
        self.assertFalse(
            self.probe_path.exists(),
            f'{self.probe_path} already exists -- a previous run did not clean up',
        )

        source = textwrap.dedent(f"""
            import unittest

            from tests._support import sample_path


            class ProbeTierViolationTests(unittest.TestCase):
                def test_reads_a_generated_capture_with_no_handler(self) -> None:
                    self.assertTrue(sample_path({_GENERATED_CAPTURE!r}))
            """).lstrip('\n')
        self.probe_path.write_text(source, encoding='utf-8')
        self.addCleanup(self.probe_path.unlink, missing_ok=True)

    def _run(self, *extra_args: str) -> 'subprocess.CompletedProcess[str]':
        selection = str(self.probe_path.relative_to(_tiers.ROOT))
        return subprocess.run(
            [sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider', '-q',
             *extra_args, selection],
            cwd=str(_tiers.ROOT), env=_child_environ(), capture_output=True,
            text=True, timeout=120, check=False,
        )

    def test_serial_run_reports_the_diagnostic_and_fails(self) -> None:
        completed = self._run()
        output = completed.stdout + completed.stderr

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output.count(_DIAGNOSTIC_MARKER), 1)
        self.assertNotIn('INTERNALERROR', output)

    def test_xdist_run_reports_the_diagnostic_and_fails(self) -> None:
        """The end-to-end reproduction of the lost diagnostic.

        Without the fix, the run exits non-zero from an
        ``INTERNALERROR`` (``assert not crashitem`` in ``xdist/dsession.py``,
        naming the probe's test id) and ``_DIAGNOSTIC_MARKER`` never appears.

        """
        completed = self._run('-n', '2', '--dist', 'load')
        output = completed.stdout + completed.stderr

        self.assertNotEqual(completed.returncode, 0)
        self.assertGreaterEqual(output.count(_DIAGNOSTIC_MARKER), 1)
        self.assertNotIn('INTERNALERROR', output)
        self.assertNotIn('crashitem', output)


#: Module name of the ``-p`` plugin :class:`ProbeWorkerCrashTests` loads into
#: its throwaway session; written to a temporary directory, never to the tree.
_CRASH_PLUGIN_NAME = 'pcapkit_tier_guard_probe_crash'

#: Kills a worker mid-probe, as CI's GraalPy leg lost one (job 116215824320):
#: after :class:`XdistSubprocessTests` has written the probe and before its
#: cleanup can remove it. The lock becomes a no-op because the test
#: that launched the session holds the exclusive hold on the probe's behalf.
_CRASH_PLUGIN_SOURCE = textwrap.dedent(f"""
    import contextlib
    import os
    import subprocess

    _run = subprocess.run


    def _crashing_run(args, *posargs, **kwargs):
        if any(str(arg).endswith({_tiers.PROBE_MODULE_NAME!r}) for arg in args):
            os._exit(1)
        return _run(args, *posargs, **kwargs)


    def pytest_runtest_setup(item):
        if hasattr(item.config, 'workerinput'):
            from tests import conftest
            conftest._tier_guard_lock = lambda exclusive: contextlib.nullcontext()
            subprocess.run = _crashing_run
    """).lstrip('\n')


@unittest.skipUnless(importlib.util.find_spec('xdist') is not None,
                      'pytest-xdist not installed')
@unittest.skipIf(sys.implementation.name == 'graalpy', SKIP_NESTED_ON_GRAALPY)
class ProbeWorkerCrashTests(unittest.TestCase):
    """A worker dying mid-probe fails that one test, not the session (#1756).

    xdist replaces the dead worker, and the replacement collects ``tests/``
    afresh while the probe's cleanup never ran. Before ``collect_ignore`` in
    :mod:`tests.conftest`, that collection audited the stale probe and the
    controller ended the session with ``xdist.dsession.Interrupted``, exit 2.

    """

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        self.probe_path = _tiers.TESTS_ROOT / 'protocols' / _tiers.PROBE_MODULE_NAME
        # Exclusive for the whole throwaway session and until the stale probe is
        # gone, so a concurrent SuiteIsCleanTests never sees it; LIFO cleanups
        # unlink while still holding the lock, as in XdistSubprocessTests.
        lock = _conftest._tier_guard_lock(exclusive=True)
        lock.__enter__()
        self.addCleanup(lock.__exit__, None, None, None)
        self.assertFalse(
            self.probe_path.exists(),
            f'{self.probe_path} already exists -- a previous run did not clean up',
        )
        self.addCleanup(self.probe_path.unlink, missing_ok=True)

        self.plugin_dir = tempfile.mkdtemp(prefix='pcapkit-1756-')
        self.addCleanup(shutil.rmtree, self.plugin_dir, ignore_errors=True)
        with open(os.path.join(self.plugin_dir, f'{_CRASH_PLUGIN_NAME}.py'), 'w',
                  encoding='utf-8') as handle:
            handle.write(_CRASH_PLUGIN_SOURCE)

    def test_a_worker_crash_mid_probe_does_not_interrupt_the_session(self) -> None:
        """Fails on main: exit 2 and the probe's diagnostic as the interrupt reason."""
        protocols = self.probe_path.parent
        environ = _child_environ()
        environ['PYTHONPATH'] = os.pathsep.join([self.plugin_dir, environ['PYTHONPATH']])
        probe_test = ('tests/test_tier_guard_xdist.py::XdistSubprocessTests'
                      '::test_xdist_run_reports_the_diagnostic_and_fails')
        completed = subprocess.run(
            [sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider', '-p', _CRASH_PLUGIN_NAME,
             '-q', '-n', '2', '--dist', 'load', '--max-worker-restart=2', probe_test,
             # The directory the probe lives in, as CI collects it, minus every
             # module but test_z*: only the probe could be left there.
             'tests/protocols', f'--ignore-glob={protocols}/[!t]*',
             f'--ignore-glob={protocols}/t[!e]*', f'--ignore-glob={protocols}/test_[!z]*'],
            cwd=str(_tiers.ROOT), env=environ, capture_output=True, text=True,
            timeout=300, check=False,
        )
        output = completed.stdout + completed.stderr

        self.assertIn(f"crashed while running '{probe_test}'", output)
        self.assertTrue(self.probe_path.exists(), 'the crash did not leave the probe behind')
        self.assertNotIn('Interrupted', output)
        self.assertNotIn(_DIAGNOSTIC_MARKER, output)
        self.assertEqual(completed.returncode, 1, output)


class ProbeWriteLockTests(unittest.TestCase):
    """:func:`tests.conftest._tier_guard_lock` actually excludes a concurrent reader.

    Independent of :mod:`xdist` and of the two classes above: it exercises the
    mutex directly, with a background thread standing in for a concurrent
    worker process. :func:`fcntl.flock` locks are per open file description,
    not per process or thread, so a conflict between two file descriptors
    opened by two threads of one process is the same conflict pytest-xdist's
    separate worker processes would see -- this is not a weaker stand-in for
    the real race, it is the identical kernel mechanism at smaller scale.

    Runs unconditionally in the venv this suite normally runs under: unlike
    :class:`XdistSubprocessTests`, nothing here needs ``xdist`` importable, only
    :mod:`fcntl`, so this is the case that actually exercises the mutex on the
    interpreter without ``xdist`` installed.

    """

    @unittest.skipUnless(_conftest.fcntl is not None,
                          'fcntl unavailable on this platform')
    def test_a_concurrent_reader_waits_out_the_writer(self) -> None:
        """A shared hold cannot be granted while the exclusive one is live.

        Without the fix, :func:`tests.conftest._tier_guard_lock` does not
        exist, so there is nothing to import and nothing to wait on.

        """
        reader_acquired = threading.Event()
        reader_errors = []  # type: list[BaseException]

        def reader() -> None:
            try:
                with _conftest._tier_guard_lock(exclusive=False):
                    reader_acquired.set()
            except BaseException as exc:  # pylint: disable=broad-except
                reader_errors.append(exc)

        with _conftest._tier_guard_lock(exclusive=True):
            thread = threading.Thread(target=reader)
            thread.start()
            # Every chance for the reader to have raced ahead if the writer's
            # hold did not actually exclude it.
            got_it_early = reader_acquired.wait(timeout=0.5)
            self.assertFalse(
                got_it_early,
                'a concurrent reader acquired the shared lock while the writer still held it',
            )

        thread.join(timeout=5)
        self.assertFalse(reader_errors, reader_errors)
        self.assertTrue(
            reader_acquired.wait(timeout=5),
            'the reader never acquired the lock after the writer released it',
        )


def _redirect_tier_guard_lock(case: 'unittest.TestCase', prefix: 'str') -> None:
    """Point :func:`tests.conftest._tier_guard_lock` at a lock file of ``case``'s own."""
    root = pathlib.Path(tempfile.mkdtemp(prefix=prefix))
    case.addCleanup(shutil.rmtree, root, ignore_errors=True)
    patcher = unittest.mock.patch.object(_conftest, '_tier_guard_lock_path',
                                         return_value=root / 'tier-guard.lock')
    patcher.start()
    case.addCleanup(patcher.stop)


@unittest.skipUnless(_conftest.fcntl is not None, 'fcntl unavailable on this platform')
class ProbeLockNonBlockingTests(unittest.TestCase):
    """On GraalPy, :func:`tests.conftest._tier_guard_lock` never waits inside :func:`fcntl.flock` (#1977).

    There a thread blocked in ``flock`` keeps the GIL, so the holder it waits on
    can never run to release it. CPython releases the GIL there, so no real lock
    can reproduce the hang on it; a fake ``flock`` stands in instead, and
    :data:`tests.conftest.TIER_GUARD_LOCK_POLLS` selects GraalPy's path. The fake
    refuses ``LOCK_NB`` requests while "held", and records, then grants, any
    request made without ``LOCK_NB`` -- the call that hangs on GraalPy.

    """

    #: ``LOCK_NB`` attempts the fake refuses before it lets the lock go.
    REFUSALS = 3

    def setUp(self) -> None:
        real = _conftest.fcntl
        self.calls = []  # type: list[int]
        self.blocking = []  # type: list[int]
        self.refusals = self.REFUSALS
        self.held = 0

        def flock(fd: 'int', operation: 'int') -> None:
            del fd
            self.calls.append(operation)
            if operation & real.LOCK_UN:
                self.held -= 1
                return
            if not operation & real.LOCK_NB:
                self.blocking.append(operation)
            elif self.refusals:
                self.refusals -= 1
                raise BlockingIOError(errno.EWOULDBLOCK, 'Resource temporarily unavailable')
            self.held += 1

        fake = types.SimpleNamespace(LOCK_SH=real.LOCK_SH, LOCK_EX=real.LOCK_EX,
                                     LOCK_NB=real.LOCK_NB, LOCK_UN=real.LOCK_UN, flock=flock)
        _redirect_tier_guard_lock(self, 'pcapkit-1977-')
        for patcher in (
            unittest.mock.patch.object(_conftest, 'fcntl', fake),
            unittest.mock.patch.object(_conftest, 'TIER_GUARD_LOCK_POLL', 0.001, create=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _take(self, polls: 'bool', exclusive: 'bool') -> None:
        self.calls.clear()
        self.blocking.clear()
        self.refusals = self.REFUSALS
        with unittest.mock.patch.object(_conftest, 'TIER_GUARD_LOCK_POLLS', polls, create=True):
            with _conftest._tier_guard_lock(exclusive=exclusive):
                self.assertGreater(self.held, 0, 'the block ran without the lock')
        self.assertEqual(self.held, 0, f'not every lock taken was released: {self.calls!r}')

    def test_graalpys_path_polls_and_never_blocks(self) -> None:
        """Fails on the code before db36aed75, which asked for the lock blocking::

            AssertionError: Lists differ: [1] != []

        """
        for exclusive in (False, True):
            with self.subTest(exclusive=exclusive):
                self._take(polls=True, exclusive=exclusive)
                self.assertEqual(self.blocking, [])
                self.assertEqual(self.refusals, 0, 'acquired before the holder let go')

    def test_cpythons_path_still_blocks(self) -> None:
        """Polling is GraalPy's workaround only: elsewhere the kernel queues the wait."""
        real = _conftest.fcntl
        for exclusive in (False, True):
            with self.subTest(exclusive=exclusive):
                self._take(polls=False, exclusive=exclusive)
                taken = [op for op in self.calls if not op & real.LOCK_UN]
                self.assertTrue(taken)
                self.assertEqual(self.blocking, taken)

    def test_an_unrelated_error_is_raised_not_retried(self) -> None:
        """Only "would block" means "held": any other ``flock`` error propagates."""
        def broken(fd: 'int', operation: 'int') -> None:
            del fd
            self.calls.append(operation)
            raise OSError(errno.EBADF, 'Bad file descriptor')

        with unittest.mock.patch.object(_conftest, 'TIER_GUARD_LOCK_POLLS', True, create=True), \
                unittest.mock.patch.object(_conftest.fcntl, 'flock', broken):
            with self.assertRaises(OSError) as context:
                with _conftest._tier_guard_lock(exclusive=True):
                    self.fail('the lock was reported held after flock failed')
        self.assertEqual(context.exception.errno, errno.EBADF)
        self.assertEqual(len(self.calls), 1)


@unittest.skipUnless(_conftest.fcntl is not None, 'fcntl unavailable on this platform')
class ProbeLockWriterPriorityTests(unittest.TestCase):
    """A waiting writer keeps new readers out of :func:`tests.conftest._tier_guard_lock` (#1977).

    Linux grants a shared ``flock`` whenever no exclusive hold is granted, so
    without the gate a reader arriving while the writer waits walks straight in,
    and readers whose holds overlap -- every xdist worker takes one per test --
    can keep the writer out for good. Real locks, threads standing in for
    workers as in :class:`ProbeWriteLockTests`, on both the blocking and the
    polling path.

    """

    def setUp(self) -> None:
        _redirect_tier_guard_lock(self, 'pcapkit-1977-')
        patcher = unittest.mock.patch.object(_conftest, 'TIER_GUARD_LOCK_POLL', 0.01, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_reader_arriving_behind_a_waiting_writer_waits_for_it(self) -> None:
        """Fails on db36aed75 and before, which have no gate: ``['R'] != []``."""
        # The blocking path only where it is the real one: on GraalPy it holds
        # the GIL, and these threads would deadlock exactly as #1977 describes.
        for polls in sorted({getattr(_conftest, 'TIER_GUARD_LOCK_POLLS', False), True}):
            with self.subTest(polls=polls), \
                    unittest.mock.patch.object(_conftest, 'TIER_GUARD_LOCK_POLLS', polls,
                                               create=True):
                self._run_once()

    def _run_once(self) -> None:
        order = []  # type: list[str]
        errors = []  # type: list[BaseException]
        first_in, release_first = threading.Event(), threading.Event()

        def run(body: 'Callable[[], None]') -> threading.Thread:
            def target() -> None:
                try:
                    body()
                except BaseException as exc:  # pylint: disable=broad-except
                    errors.append(exc)
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 5)
            return thread

        def first_reader() -> None:
            with _conftest._tier_guard_lock(exclusive=False):
                first_in.set()
                release_first.wait(10)

        def writer() -> None:
            with _conftest._tier_guard_lock(exclusive=True):
                order.append('W')
                time.sleep(0.1)

        def late_reader() -> None:
            with _conftest._tier_guard_lock(exclusive=False):
                order.append('R')

        self.addCleanup(release_first.set)
        threads = [run(first_reader)]
        self.assertTrue(first_in.wait(5), 'the first reader never got the lock')
        threads.append(run(writer))
        time.sleep(0.3)  # the writer is now waiting on the first reader
        threads.append(run(late_reader))
        time.sleep(0.3)
        self.assertEqual(order, [], 'someone got in while the first reader held the lock')
        release_first.set()
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive(), 'a thread never got the lock')
        self.assertFalse(errors, errors)
        self.assertEqual(order, ['W', 'R'])


@unittest.skipUnless(_conftest.fcntl is not None, 'fcntl unavailable on this platform')
class ProbeLeftoverCheckTests(unittest.TestCase):
    """:meth:`XdistSubprocessTests.setUp` checks for a leftover probe under the lock (#1758).

    Drives that ``setUp`` directly, so neither :mod:`xdist` nor git is needed. The
    probe directory and the lock file are redirected into a temporary directory:
    nothing here writes to the tree or contends with a real probe on another
    worker. A thread stands in for the other worker, as in
    :class:`ProbeWriteLockTests`.

    """

    def setUp(self) -> None:
        root = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-1758-'))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / 'protocols').mkdir()
        self.probe_path = root / 'protocols' / _tiers.PROBE_MODULE_NAME
        for patcher in (
            unittest.mock.patch.object(_tiers, 'TESTS_ROOT', root),
            unittest.mock.patch.object(_tiers, 'guard_unavailable_reason', return_value=None),
            unittest.mock.patch.object(_conftest, '_tier_guard_lock_path',
                                       return_value=root / 'tier-guard.lock'),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.real_lock = _conftest._tier_guard_lock
        self.case = XdistSubprocessTests('test_serial_run_reports_the_diagnostic_and_fails')

    def _assert_lock_free(self) -> None:
        fcntl = _conftest.fcntl
        with open(_conftest._tier_guard_lock_path(), 'a', encoding='utf-8') as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.fail('setUp left the exclusive lock held')
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def test_a_live_probe_is_waited_for_not_reported_as_a_leftover(self) -> None:
        """Without the fix, ``setUp`` raises "already exists"
        at once, without ever asking for the lock the live probe's writer holds.

        """
        progressed = threading.Event()  # setUp asked for the lock, or finished
        settled = threading.Event()  # setUp finished, either way
        outcome = []  # type: list[BaseException | None]
        written = []  # type: list[bool]

        def signalling_lock(exclusive: 'bool') -> 'ContextManager[None]':
            progressed.set()
            return self.real_lock(exclusive)

        def other_worker() -> None:
            try:
                self.case.setUp()
                written.append(self.probe_path.exists())
                outcome.append(None)
            except BaseException as exc:  # pylint: disable=broad-except
                outcome.append(exc)
            finally:
                self.case.doCleanups()
                progressed.set()
                settled.set()

        thread = threading.Thread(target=other_worker, daemon=True)
        with self.real_lock(exclusive=True):
            self.probe_path.write_text("# another worker's live probe\n", encoding='utf-8')
            with unittest.mock.patch.object(_conftest, '_tier_guard_lock', signalling_lock):
                thread.start()
                self.addCleanup(thread.join, 5)
                self.assertTrue(progressed.wait(timeout=5), 'setUp never reached the lock')
                self.assertFalse(settled.wait(timeout=0.5),
                                 f'setUp did not wait for the lock: {outcome!r}')
            self.probe_path.unlink()

        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), 'setUp never proceeded once the lock was free')
        self.assertEqual(outcome, [None])
        self.assertEqual(written, [True])
        self.assertFalse(self.probe_path.exists(), "setUp's cleanup left its probe behind")
        self._assert_lock_free()

    def test_a_real_leftover_still_fails_and_releases_the_lock(self) -> None:
        """A probe still there under the lock is reported, kept, and the lock let go.

        The failure is kept, traceback and all, as a runner's report keeps it:
        ``assertRaises`` would clear the frames, and refcounting would then close
        the lock even if ``setUp`` never registered its release.

        """
        self.probe_path.write_text('# a leftover\n', encoding='utf-8')

        failure = None  # type: AssertionError | None
        try:
            self.case.setUp()
        except AssertionError as exc:
            failure = exc
        self.assertIn('already exists', str(failure))
        self.case.doCleanups()

        self.assertTrue(self.probe_path.exists(), 'setUp removed a probe it did not write')
        self._assert_lock_free()


#: What :class:`ProbeLockNestedRunTests` runs in a child, as a nested
#: :program:`pytest` would: take a test's shared hold on the lock file named by
#: ``sys.argv[1]``, under the environment the parent's hold handed down.
_NESTED_READER = '''
import pathlib, sys, unittest.mock
from tests import conftest
with unittest.mock.patch.object(conftest, '_tier_guard_lock_path',
                                return_value=pathlib.Path(sys.argv[1])):
    with conftest._tier_guard_reader_hold():
        print('IN', flush=True)
'''


@unittest.skipUnless(_conftest.fcntl is not None, 'fcntl unavailable on this platform')
class ProbeLockNestedRunTests(unittest.TestCase):
    """A process under a test's shared hold does not ask for the lock again (#2082).

    :mod:`tests.project.test_module_isolation` runs a nested :program:`pytest`
    inside its shared hold. A writer arriving meanwhile holds the gate while it
    waits on that hold, so a nested shared request waited behind it, and the
    hold waited on the nested run: on GraalPy the run's ``subprocess.run``
    timeout, 600 s, was what broke it, with the writer and every other reader
    stalled as long.

    """

    def setUp(self) -> None:
        _redirect_tier_guard_lock(self, 'pcapkit-2082-')
        patcher = unittest.mock.patch.object(_conftest, 'TIER_GUARD_LOCK_POLL', 0.01, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        environ = unittest.mock.patch.dict(os.environ)
        environ.start()
        self.addCleanup(environ.stop)
        os.environ.pop(_conftest.TIER_GUARD_HELD_ENV, None)

    def _held(self, suffix: 'str', operation: 'int') -> 'bool':
        """Whether ``operation`` on the lock file plus ``suffix`` would block."""
        fcntl = _conftest.fcntl
        path = _conftest._tier_guard_lock_path()
        with open(path.with_name(path.name + suffix), 'a', encoding='utf-8') as handle:
            try:
                fcntl.flock(handle.fileno(), operation | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return False

    def test_a_nested_run_does_not_queue_behind_a_waiting_writer(self) -> None:
        """Without the fix (#2082), the child times out at the gate."""
        order = []  # type: list[str]

        def writer() -> None:
            with _conftest._tier_guard_lock(exclusive=True):
                order.append('W')

        with _conftest._tier_guard_reader_hold():
            thread = threading.Thread(target=writer, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 10)
            end = time.monotonic() + 10
            while not self._held('.gate', _conftest.fcntl.LOCK_SH):
                self.assertLess(time.monotonic(), end, 'the writer never took the gate')
                time.sleep(0.01)
            try:
                child = subprocess.run(  # nosec: B603
                    [sys.executable, '-c', _NESTED_READER, str(_conftest._tier_guard_lock_path())],
                    cwd=str(_tiers.ROOT), env=_child_environ(), capture_output=True, text=True,
                    timeout=120, check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail('the nested reader queued behind the writer the outer hold keeps waiting')
            self.assertEqual((child.returncode, child.stdout), (0, 'IN\n'), child.stderr)
            self.assertEqual(order, [], 'the writer got in under the outer hold')
        thread.join(10)
        self.assertEqual(order, ['W'], 'the writer never got the lock once the hold ended')

    def test_the_variable_names_the_hold_only_while_it_lasts(self) -> None:
        """Set for the hold and put back after; another lock file's value is no hold."""
        name = _conftest.TIER_GUARD_HELD_ENV
        for before in (None, '/elsewhere/tier-guard.lock'):
            with self.subTest(before=before):
                if before is not None:
                    os.environ[name] = before
                with _conftest._tier_guard_reader_hold():
                    self.assertEqual(os.environ.get(name), str(_conftest._tier_guard_lock_path()))
                    self.assertTrue(self._held('', _conftest.fcntl.LOCK_EX),
                                    'the hold did not take the lock')
                self.assertEqual(os.environ.get(name), before)
                self.assertFalse(self._held('', _conftest.fcntl.LOCK_EX))
