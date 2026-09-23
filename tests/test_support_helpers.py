# -*- coding: utf-8 -*-
"""Tests for the helpers in :mod:`tests._support`.

Two of them are pinned here, both for the same reason: they are *machinery* the
rest of the suite leans on, so a fault in either reports itself as a failure in
whichever test happened to be running rather than as a fault in the helper.
:func:`~tests._support.time_limit` is covered by :class:`TimeLimitTests` at the
end; the rest of the module is :func:`~tests._support.close_extractor`.

That helper is teardown machinery: nearly every runtime and integration test
hands it an extractor from ``addCleanup`` or a ``finally`` block. Teardown code
is exactly the code whose bugs stay invisible -- a leak leaks silently, and a
teardown that raises reports itself as a failure in whichever test happened to
be running rather than as a fault in the helper. So the contract is pinned here
rather than left to be inferred from the call sites.

Three things are worth pinning, and they are the three ways this could rot:

* both resources are released, not just the input file
  (:class:`ClosesBothTests`) -- the original helper closed ``_ifile`` alone and
  leaked the engine's :class:`pcap.pcap` handle on every abandoned extractor;
* one broken resource cannot strand the other
  (:class:`IndependenceTests`);
* nothing it is handed in teardown makes it raise
  (:class:`ToleranceTests`).

The module-isolation helpers are pinned here too, for the same reason and with
more cause: :class:`SnapshotRestoreTests` and
:class:`StandInsDoNotOutliveTheirTestTests` cover
:func:`~tests._support.isolate_modules` and the snapshot/restore pair beneath it,
which exist because issue #660 -- twelve failures in :mod:`tests.project`,
visible only in some collection orders -- was a stand-in module left bound in
:data:`sys.modules` by a test that had finished.

:class:`LoadedModulesDoNotOutliveTheirTestTests` and
:class:`ArrangedRestoreTests` are the same story one helper along, and are issue
#674: :func:`~tests._support.load_module` and
:func:`~tests._support.bootstrap_core_modules` left *bare stub packages* bound
over ``pcapkit``, ``pcapkit.corekit`` and ``pcapkit.utilities``, so the next test
to walk ``pcapkit.__all__`` saw a library that declared no exports. Three
failures in :mod:`tests.project.test_public_api`, again only in some orders.

Both of those run their polluting cases through :class:`unittest.TestResult`
rather than letting :mod:`pytest` run them, and that is load-bearing rather than
stylistic: :func:`tests.conftest.restore_module_table` repairs the region after
every test, so under :mod:`pytest` the assertions pass whether or not the helper
under test was ever fixed. A suite-wide net that hides one helper's bug hides the
next one too, which is why the helpers are pinned against the bare runner.

This module is unit-tier: it drives the helper with stand-ins rather than real
extractors, so it reads no sample capture and needs no engine installed.

"""
from __future__ import annotations

import importlib
import pathlib
import signal
import sys
import threading
import time
import types
import unittest

from tests._support import (bootstrap_core_modules, close_extractor, ensure_package,
                            install_fake_protocol_module, isolate_modules, purge_modules,
                            restore_modules, restore_modules_after, snapshot_modules,
                            time_limit)


class Closeable:
    """A stand-in for a resource that records having been closed.

    Args:
        error: Exception to raise from :meth:`close`, or :data:`None` to close
            cleanly. A resource that raises on close is the half-constructed
            engine case, and is why the helper guards each call.

    """

    def __init__(self, error: 'BaseException | None' = None) -> None:
        self.error = error
        self.calls = 0

    def close(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


class Extractor:
    """A stand-in exposing the two private attributes the helper reads."""

    def __init__(self, ifile: 'object' = None, exeng: 'object' = None) -> None:
        self._ifile = ifile
        self._exeng = exeng


class ClosesBothTests(unittest.TestCase):
    """The engine is closed as well as the input file."""

    def test_closes_the_input_file_and_the_engine(self) -> None:
        stream, engine = Closeable(), Closeable()

        close_extractor(Extractor(stream, engine))

        self.assertEqual(stream.calls, 1)
        # The regression this guards: closing the stream alone leaves the
        # engine's OS-level handle open for the rest of the process.
        self.assertEqual(engine.calls, 1)


class IndependenceTests(unittest.TestCase):
    """Neither resource can prevent the other from being released."""

    def test_engine_is_closed_even_when_the_stream_close_fails(self) -> None:
        stream, engine = Closeable(OSError('stream is already gone')), Closeable()

        close_extractor(Extractor(stream, engine))

        self.assertEqual(engine.calls, 1)

    def test_stream_is_closed_even_when_the_engine_close_fails(self) -> None:
        stream, engine = Closeable(), Closeable(AttributeError('_extmp'))

        close_extractor(Extractor(stream, engine))

        self.assertEqual(stream.calls, 1)


class ToleranceTests(unittest.TestCase):
    """Nothing teardown can hand the helper makes it raise.

    Each case below is reached in practice: an extractor whose ``__init__``
    failed before assigning ``_exeng``, a test double that is neither, and an
    engine whose ``close`` raises because its handle was never opened.

    """

    def test_absent_attributes_are_ignored(self) -> None:
        close_extractor(object())

    def test_none_valued_attributes_are_ignored(self) -> None:
        close_extractor(Extractor(None, None))

    def test_half_constructed_extractor_without_an_engine(self) -> None:
        stream = Closeable()

        # ``_exeng`` is assigned only once the engine has been selected, so an
        # extractor that raised before that point has no such attribute at all.
        class Partial:
            def __init__(self) -> None:
                self._ifile = stream

        close_extractor(Partial())

        self.assertEqual(stream.calls, 1)

    def test_non_callable_close_attribute_is_ignored(self) -> None:
        class NotReallyCloseable:
            close = 'not a method'

        close_extractor(Extractor(NotReallyCloseable(), NotReallyCloseable()))

    def test_both_closes_raising_is_still_swallowed(self) -> None:
        stream = Closeable(OSError('stream'))
        engine = Closeable(RuntimeError('engine'))

        close_extractor(Extractor(stream, engine))

        self.assertEqual(stream.calls, 1)
        self.assertEqual(engine.calls, 1)

    def test_a_close_lookup_that_raises_is_ignored(self) -> None:
        """Reaching ``close`` at all can fail, and that is tolerated too.

        ``close`` need not be a plain method: as a property, or resolved through
        ``__getattr__``, the *lookup* raises rather than the call. Guarding only
        the call would let that escape and mask the real failure.

        """
        class HostileLookup:
            @property
            def close(self) -> 'object':
                raise RuntimeError('lookup')

        engine = Closeable()

        close_extractor(Extractor(HostileLookup(), engine))

        # And the engine is still closed: one unreachable resource must not
        # strand the other, exactly as when the call itself raises.
        self.assertEqual(engine.calls, 1)


class PropagationTests(unittest.TestCase):
    """What the helper deliberately does *not* swallow."""

    def test_base_exception_is_not_swallowed(self) -> None:
        """A :exc:`KeyboardInterrupt` during teardown still ends the run.

        The helper catches :exc:`Exception`, not :exc:`BaseException`, so
        interrupting a suite mid-teardown is not quietly absorbed by a cleanup
        helper.

        """
        with self.assertRaises(KeyboardInterrupt):
            close_extractor(Extractor(Closeable(KeyboardInterrupt()), Closeable()))


@unittest.skipUnless(hasattr(signal, 'SIGALRM'), 'signal.alarm is unavailable')
class TimeLimitTests(unittest.TestCase):
    """A deadline that arrives, and an enclosing one that survives.

    A process has one pending alarm, so arming a deadline cancels whatever was
    already scheduled. The helper reads what it displaced and puts it back; these
    pin that, because an enclosing deadline going missing is invisible until the
    run it should have bounded hangs instead.

    """

    def setUp(self) -> None:
        # Whatever a test leaves behind, the next one starts from nothing pending
        # and from a handler this class owns rather than the helper's.
        self.handled = []  # type: list[int]
        previous = signal.signal(signal.SIGALRM, lambda signum, frame: self.handled.append(signum))
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        self.addCleanup(signal.alarm, 0)

    def test_the_deadline_fires_on_a_body_that_overruns(self) -> None:
        """The point of the helper, pinned so the rest cannot be met by disarming."""
        with self.assertRaises(TimeoutError):
            with time_limit(1):
                while True:
                    pass

    def test_an_enclosing_alarm_is_restored(self) -> None:
        """An outer deadline keeps counting down across the ``with``.

        Before this was fixed the helper cancelled the pending alarm on the way out
        and never re-armed it, so an outer ``signal.alarm(30)`` read back as ``0``
        afterwards: the enclosing deadline was gone, silently.

        """
        own_handler = signal.getsignal(signal.SIGALRM)

        signal.alarm(30)
        with time_limit(5):
            pass

        # Reading the remaining seconds cancels the alarm, which is the cleanup
        # this test wanted anyway.
        remaining = signal.alarm(0)

        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 30)
        self.assertIs(signal.getsignal(signal.SIGALRM), own_handler)
        self.assertEqual(self.handled, [])

    def test_an_enclosing_alarm_that_expired_in_the_body_is_re_armed(self) -> None:
        """An outer deadline overtaken by the body is honoured late, not dropped.

        The body holds the process past the moment the outer alarm was due, so it
        cannot be delivered on time. The helper re-arms it for a second rather than
        cancelling it, since cancelling is how an outer timeout goes missing
        altogether.

        """
        signal.alarm(1)
        with time_limit(5):
            time.sleep(1.2)

        remaining = signal.alarm(0)

        self.assertGreaterEqual(remaining, 1)
        self.assertEqual(self.handled, [])

    def test_nothing_is_re_armed_when_nothing_was_pending(self) -> None:
        """The common case: no enclosing deadline, nothing left behind."""
        with time_limit(5):
            pass

        self.assertEqual(signal.alarm(0), 0)


class SnapshotRestoreTests(unittest.TestCase):
    """:func:`~tests._support.restore_modules` is an exact inverse.

    Three ways a test can leave the table different, and the restore has to undo
    all three: a name it added, a name it dropped, and a name it rebound to
    something else. The third is the one issue #660 turned on -- a stand-in bound
    over ``pcapkit.protocols.protocol`` is a rebind, and a restore that only
    removed additions would leave it in place.

    Every name used here is under ``pcapkit.`` so the helpers actually match it,
    and every one is removed again on teardown whatever the assertions do.

    """

    ADDED = 'pcapkit.__support_probe_added'
    REBOUND = 'pcapkit.__support_probe_rebound'
    DROPPED = 'pcapkit.__support_probe_dropped'

    def setUp(self) -> None:
        self.addCleanup(self._forget_probes)
        self.original = types.ModuleType(self.REBOUND)
        self.dropped = types.ModuleType(self.DROPPED)
        sys.modules[self.REBOUND] = self.original
        sys.modules[self.DROPPED] = self.dropped

    def _forget_probes(self) -> None:
        for name in (self.ADDED, self.REBOUND, self.DROPPED):
            sys.modules.pop(name, None)

    def test_restore_undoes_an_addition_a_drop_and_a_rebind(self) -> None:
        snapshot = snapshot_modules(['pcapkit'])

        sys.modules[self.ADDED] = types.ModuleType(self.ADDED)
        sys.modules[self.REBOUND] = types.ModuleType(self.REBOUND)
        del sys.modules[self.DROPPED]

        restore_modules(snapshot, ['pcapkit'])

        self.assertNotIn(self.ADDED, sys.modules)
        self.assertIs(sys.modules[self.REBOUND], self.original)
        self.assertIs(sys.modules[self.DROPPED], self.dropped)

    def test_the_snapshot_is_the_whole_pcapkit_region_and_nothing_else(self) -> None:
        snapshot = snapshot_modules(['pcapkit'])

        self.assertIn(self.REBOUND, snapshot)
        self.assertTrue(all(name == 'pcapkit' or name.startswith('pcapkit.')
                            for name in snapshot),
                        'snapshot_modules captured a name outside the prefixes it was given')
        # A prefix match is on dotted components, not on the string: a
        # differently-named top-level package that merely starts with the same
        # letters is a different package and must not be swept up.
        sibling = 'pcapkit_not_ours'
        sys.modules[sibling] = types.ModuleType(sibling)
        self.addCleanup(sys.modules.pop, sibling, None)

        self.assertNotIn(sibling, snapshot_modules(['pcapkit']))

        restore_modules(snapshot_modules(['pcapkit']), ['pcapkit'])
        self.assertIn(sibling, sys.modules)


class StandInsDoNotOutliveTheirTestTests(unittest.TestCase):
    """A test that installs a stand-in leaves :data:`sys.modules` as it found it.

    The regression test for issue #660, and written the way it is on purpose.
    The real polluting test case is *run* here, through
    :class:`unittest.TestResult`, exactly as a runner would run it -- so what is
    measured is the test case's own isolation and nothing else. Going through
    :mod:`pytest` instead would prove nothing about it, because
    :func:`tests.conftest.restore_module_table` would clean up after it either
    way and the assertion would pass whether or not the test case had been
    fixed.

    Before the fix this failed on any ordering, on the fake ``ProtocolBase`` and
    the stub ``pcapkit`` that ``ProtoChainTests.setUp`` left behind.

    """

    def setUp(self) -> None:
        # This test case re-imports pcapkit into a table it then compares, so it
        # gets the same isolation it is asserting about.
        isolate_modules(self)

    def _run_and_diff(self, case: 'unittest.TestCase') -> 'unittest.TestResult':
        """Run ``case`` and assert it changed no ``pcapkit.*`` binding."""
        before = snapshot_modules(['pcapkit'])

        result = unittest.TestResult()
        case.run(result)

        after = snapshot_modules(['pcapkit'])

        _assert_module_table_unchanged(self, before, after)
        return result

    def test_protochain_leaves_no_fake_protocol_module_behind(self) -> None:
        from tests.corekit.test_protochain import ProtoChainTests

        case = ProtoChainTests(sorted(_method_names(ProtoChainTests))[0])

        result = self._run_and_diff(case)

        # Asserted after the isolation check, so a genuine failure in that test
        # case is reported as its own failure rather than as a leak here.
        self.assertEqual((len(result.failures), len(result.errors)), (0, 0),
                         f'the borrowed test case did not pass: '
                         f'{result.failures or result.errors}')

    def test_the_real_protocol_base_still_subscripts_afterwards(self) -> None:
        """The failure mode itself, rather than the table it came from.

        ``pcapkit/protocols/misc/pcap/frame.py:59`` is the line that raised
        ``TypeError: type 'ProtocolBase' is not subscriptable``, so importing it
        after the polluting test case has run is the most direct statement of
        what #660 was.

        """
        from tests.corekit.test_protochain import ProtoChainTests

        case = ProtoChainTests(sorted(_method_names(ProtoChainTests))[0])
        case.run(unittest.TestResult())

        frame = importlib.import_module('pcapkit.protocols.misc.pcap.frame')
        protocol = importlib.import_module('pcapkit.protocols.protocol')

        self.assertTrue(hasattr(frame, 'Frame'))
        self.assertIsNotNone(getattr(protocol.ProtocolBase, '__class_getitem__', None),
                             'pcapkit.protocols.protocol.ProtocolBase is not the real '
                             'generic class -- a stand-in is still bound over it (#660)')

    def test_installing_a_stand_in_without_isolation_is_refused(self) -> None:
        """The other half: the mistake cannot be made quietly again.

        A future test file that calls the installer without arranging its removal
        gets a :exc:`RuntimeError` naming the fix, in its own ``setUp``, instead
        of a green run that breaks a different directory.

        """
        class Unisolated(unittest.TestCase):
            def runTest(self) -> None:
                pass

        with self.assertRaises(RuntimeError) as caught:
            install_fake_protocol_module(Unisolated())

        self.assertIn('isolate_modules', str(caught.exception))


class LoadedModulesDoNotOutliveTheirTestTests(unittest.TestCase):
    """A test that *loads* modules leaves :data:`sys.modules` as it found it.

    The regression test for issue #674, and the sibling of
    :class:`StandInsDoNotOutliveTheirTestTests` above: the same shape over a
    different helper. :func:`~tests._support.load_module` writes to
    :data:`sys.modules` twice over -- the module it was asked for, and a bare stub
    package for each parent of that module's dotted name, via
    :func:`~tests._support.ensure_package` -- and before the fix neither write was
    taken back off again.

    What that cost: ``pcapkit``, ``pcapkit.corekit`` and ``pcapkit.utilities``
    stayed bound to stubs carrying nothing but a ``__path__``, so the next test to
    walk ``pcapkit.__all__`` found no exports and reported the library as
    declaring none. Measured on ``b34f132f6``, where each module passes alone::

        $ python -m unittest tests.corekit.test_multidict tests.project.test_public_api
        FAILED (failures=3)

    Run through :class:`unittest.TestResult` rather than :mod:`pytest`, for the
    reason the sibling class gives and with more force here:
    :func:`tests.conftest.restore_module_table` repairs the region after every
    test, so under :mod:`pytest` these assertions pass whether or not the helper
    was ever fixed. That guard arrived with #662, it is why the two-file
    :mod:`pytest` repro quoted in #674 no longer fails, and it is not a substitute
    for the helper putting its own writes back -- the stdlib runner reads no
    ``conftest.py`` at all, and a suite-wide net that hides a helper's bug also
    hides the next one.

    The polluting cases are *borrowed* rather than written here, so what is pinned
    is the behaviour of call sites the suite actually has. All five leaked before
    the fix, and none of them looked wrong.

    """

    #: Borrowed test cases, as ``module`` / ``class`` pairs. The first three reach
    #: the loaders through :func:`~tests._support.bootstrap_core_modules`, the
    #: last two through :func:`~tests._support.load_module` on its own. Both
    #: routes installed stubs, so both are pinned -- fixing only the former would
    #: have left :mod:`tests.utilities.test_compat` leaking.
    BORROWED = (
        ('tests.corekit.test_multidict', 'MultiDictTests'),
        ('tests.corekit.test_io', 'SeekableReaderTests'),
        ('tests.utilities.test_exceptions_warnings', 'ExceptionsWarningsTests'),
        ('tests.corekit.test_module', 'ModuleDescriptorTests'),
        ('tests.utilities.test_compat', 'CompatTests'),
    )

    def setUp(self) -> None:
        # This test case compares a table it also re-imports pcapkit into, so it
        # gets the same isolation it is asserting about.
        isolate_modules(self)

    def test_borrowed_loaders_leave_the_module_table_as_they_found_it(self) -> None:
        """Every borrowed case, one subtest each, so one leak names itself."""
        for module_name, class_name in self.BORROWED:
            with self.subTest(case=f'{module_name}.{class_name}'):
                case_class = getattr(importlib.import_module(module_name), class_name)
                # One method is enough and is deliberately the first by name:
                # every one of these classes does its loading in ``setUp``, so the
                # body of the method chosen is beside the point, and running all of
                # them would drag in whatever else they happen to exercise.
                case = case_class(sorted(_method_names(case_class))[0])

                before = snapshot_modules(['pcapkit'])
                result = unittest.TestResult()
                case.run(result)
                after = snapshot_modules(['pcapkit'])

                _assert_module_table_unchanged(self, before, after)

                # Asserted after the leak check, so a genuine failure in the
                # borrowed case is reported as its own failure rather than as a
                # leak here.
                self.assertEqual((len(result.failures), len(result.errors)), (0, 0),
                                 f'the borrowed test case did not pass: '
                                 f'{result.failures or result.errors}')

    def test_the_stub_packages_are_absent_again_afterwards(self) -> None:
        """The failure mode itself, rather than the table it came from.

        The three names in question did not exist before the test ran, so
        ``assertNotIn`` is the whole assertion -- and it is the one a restore
        written as ``sys.modules.update(snapshot)`` would pass the other two
        directions of while still failing this one.

        """
        # Defined here rather than at module scope so that neither runner collects
        # it as a test of its own: :mod:`pytest` instantiates every
        # ``unittest.TestCase`` subclass it finds in a module, underscore or not.
        saw_stubs = []  # type: list[bool]

        class Bootstrapping(unittest.TestCase):
            def runTest(self) -> None:
                purge_modules(['pcapkit'])
                bootstrap_core_modules()
                # Recorded rather than asserted, so that the *absence* assertions
                # below cannot pass by the stubs never having been bound at all.
                saw_stubs.append(all(name in sys.modules for name in
                                     ('pcapkit', 'pcapkit.corekit', 'pcapkit.utilities')))

        result = unittest.TestResult()
        Bootstrapping().run(result)

        self.assertEqual((len(result.failures), len(result.errors)), (0, 0),
                         f'the probe did not pass: {result.failures or result.errors}')
        self.assertEqual(saw_stubs, [True],
                         'the probe never saw the stub packages it was meant to install, '
                         'so its teardown had nothing to put back and this proves nothing')
        for name in ('pcapkit', 'pcapkit.corekit', 'pcapkit.utilities'):
            with self.subTest(name=name):
                self.assertNotIn(
                    name, sys.modules,
                    f'{name} did not exist before the probe ran and must not exist '
                    f'after it; a bare stub left here is #674')


class ArrangedRestoreTests(unittest.TestCase):
    """The guards and the bookkeeping around :func:`~tests._support.restore_modules_after`.

    Four things that have to hold for the #674 fix to be more than a patch on
    five call sites: the snapshot kept is the earliest one, the test found on the
    stack is the running one rather than any object that happens to be called
    ``self``, a loader that cannot find a test to restore for refuses rather than
    proceeding, and :func:`~tests._support.ensure_package` refuses to bind a stub
    for a test that has arranged nothing.

    """

    PROBE = 'pcapkit.__support_probe_arranged'

    def setUp(self) -> None:
        isolate_modules(self)
        self.addCleanup(sys.modules.pop, self.PROBE, None)

    def test_the_first_snapshot_is_the_one_kept(self) -> None:
        """Repeated calls register one restore, to the table before any load.

        :func:`~tests._support.bootstrap_core_modules` announces itself and then
        makes seven :func:`~tests._support.load_module` calls, each of which
        announces itself too. Re-snapshotting on the later calls would capture a
        table that already held the earlier loads, and restoring to *that* would
        leave them bound -- which is the original bug with more steps.

        """
        probe = _bare_case()

        restore_modules_after(probe)
        sys.modules[self.PROBE] = types.ModuleType(self.PROBE)
        restore_modules_after(probe)

        probe.doCleanups()

        self.assertNotIn(self.PROBE, sys.modules,
                         'the second call re-snapshotted, so the restore put back a '
                         'module that was added after the first snapshot was taken')

    def test_a_loader_with_no_test_case_on_the_stack_is_refused(self) -> None:
        """A loader that cannot find a test to restore for raises, not loads.

        Called on a fresh thread on purpose: the helper finds the nearest
        :class:`~unittest.TestCase` on the stack, and *this* method's frame has
        one, so a call made here would legitimately find it and succeed. A new
        thread is the cheapest stack with no test on it, and it stands in for the
        real cases -- a ``setUpClass``, or a module-level call.

        """
        outcome = []  # type: list[BaseException | None]

        def attempt() -> None:
            try:
                bootstrap_core_modules()
            except BaseException as exc:  # pylint: disable=broad-except
                outcome.append(exc)
            else:
                outcome.append(None)

        thread = threading.Thread(target=attempt)
        thread.start()
        thread.join()

        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(
            outcome[0], RuntimeError,
            'bootstrap_core_modules() found no test to restore for and loaded the '
            'modules anyway; the stubs it installed have nothing to take them off')
        self.assertIn('#674', str(outcome[0]))
        self.assertIn('test=self', str(outcome[0]),
                      'the error has to name the way out, or the next author has to '
                      'read tests/_support.py to find it')

    def test_an_idle_test_case_in_a_local_named_self_is_not_used(self) -> None:
        """A local called ``self`` is not proof that the frame is a method call.

        A *free function* taking a parameter it happens to name ``self`` presents
        the same frame as a method does. Handed some other, already-finished
        :class:`~unittest.TestCase`, it would win the walk on the name alone --
        and a cleanup registered on a test that has already finished is never run,
        so the stubs outlive the test exactly as in #674 but with no error to show
        for it. Measured before :func:`~tests._support._is_running_test` was
        consulted: ten names left bound, silently.

        Contrived, and deliberately so: no call site in the suite looks like this,
        which is the point. The heuristic has to be sound for the call sites
        nobody has written yet, since a wrong answer here is silent by
        construction.

        """
        class Stranger(unittest.TestCase):
            def runTest(self) -> None:  # pragma: no cover  # only ever run once, below
                pass

        stranger = Stranger()
        # Run and finish it, so it is a genuinely idle instance rather than one
        # that has merely never started.
        stranger.run(unittest.TestResult())

        # The unused ``self`` is the whole point: it is what puts a TestCase in a
        # frame local of that name without the frame being a method call.
        def free_function(self: 'unittest.TestCase') -> 'dict[str, object]':  # pylint: disable=unused-argument
            """Not a method, whatever the parameter is called."""
            return bootstrap_core_modules()

        class Victim(unittest.TestCase):
            def runTest(self) -> None:
                free_function(stranger)

        before = snapshot_modules(['pcapkit'])
        result = unittest.TestResult()
        Victim().run(result)
        after = snapshot_modules(['pcapkit'])

        self.assertEqual((len(result.failures), len(result.errors)), (0, 0),
                         f'the probe did not pass: {result.failures or result.errors}')
        _assert_module_table_unchanged(self, before, after)
        self.assertFalse(
            getattr(stranger, '_cleanups', None),
            'the restore was registered on the finished test case the free function '
            'was handed, where nothing will ever run it')

    def test_binding_a_stub_without_an_arranged_restore_is_refused(self) -> None:
        """The other half: the mistake cannot be made quietly again.

        Mirrors
        :meth:`StandInsDoNotOutliveTheirTestTests.test_installing_a_stand_in_without_isolation_is_refused`
        for the stub packages. Run as a borrowed case rather than called directly,
        because the guard reads the *running* test's bookkeeping and this method's
        own test is isolated -- calling it from here would satisfy the guard and
        assert nothing.

        """
        class UnarrangedStub(unittest.TestCase):
            def runTest(self) -> None:
                # The path is never read -- ``ensure_package`` only stores
                # ``str(path)`` on the stub's ``__path__`` -- and the guard fires
                # before the stub is built at all.
                ensure_package('pcapkit.__support_probe_unarranged',
                               pathlib.Path('/nonexistent'))

        result = unittest.TestResult()
        UnarrangedStub().run(result)

        self.assertEqual(len(result.errors), 1,
                         'ensure_package() bound a bare stub over a real pcapkit name '
                         'for a test that had arranged nothing to put sys.modules back')
        self.assertIn('RuntimeError', result.errors[0][1])
        self.assertIn('restore_modules_after', result.errors[0][1],
                      'the error has to name the helper that fixes it')


def _bare_case() -> 'unittest.TestCase':
    """A :class:`~unittest.TestCase` instance that is not being run.

    Somewhere for :meth:`~unittest.TestCase.addCleanup` to put a cleanup that the
    caller then runs itself with :meth:`~unittest.TestCase.doCleanups`.

    """
    class Bare(unittest.TestCase):
        def runTest(self) -> None:  # pragma: no cover  # never run
            pass

    return Bare()


def _assert_module_table_unchanged(test: 'unittest.TestCase',
                                   before: 'dict[str, types.ModuleType]',
                                   after: 'dict[str, types.ModuleType]') -> None:
    """Assert ``after`` is the ``pcapkit`` region ``before`` was, exactly.

    All three directions, because a restore that gets two of them right is still
    a leak, and the two issues this guards turned on different ones:

    * a name that was **added** has to be gone again. Absence is the direction a
      ``dict.update`` of the snapshot silently gets wrong, and it is the whole of
      issue #674 -- ``pcapkit`` did not exist before the test ran and was a bare
      stub package carrying nothing but a ``__path__`` after it;
    * a name that was **dropped** has to be back;
    * a name that was **rebound** has to point at the object it pointed at
      before, which is the direction issue #660 turned on.

    Args:
        test: The test to report through, for its assertion methods.
        before: Snapshot taken before the borrowed test case ran.
        after: Snapshot taken after it finished *and its cleanups had run* --
            :meth:`unittest.TestCase.run` does both, which is what makes the
            comparison a statement about the case's teardown rather than about
            its body.

    """
    test.assertEqual(
        sorted(set(after) - set(before)), [],
        'the test left new pcapkit entries in sys.modules; whatever imports '
        'pcapkit next inherits them -- a bare stub package here is #674, a '
        'stand-in module is #660')
    test.assertEqual(
        sorted(set(before) - set(after)), [],
        'the test dropped pcapkit entries from sys.modules and did not put them back')
    test.assertEqual(
        sorted(name for name in before if before[name] is not after.get(name)), [],
        'the test rebound a pcapkit name to a different module object and left it '
        'rebound; a non-generic ProtocolBase stand-in left this way makes every '
        'later `class X(Protocol[...])` raise TypeError (#660)')


def _method_names(case_class: type) -> 'list[str]':
    """Test-method names on ``case_class``, however many it happens to have.

    Read off the class rather than hard-coded, so that renaming or adding a test
    in the borrowed module does not break this one.

    """
    return [name for name in dir(case_class)
            if name.startswith('test') and callable(getattr(case_class, name))]


if __name__ == '__main__':
    unittest.main()
