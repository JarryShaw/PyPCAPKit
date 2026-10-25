# -*- coding: utf-8 -*-
"""Suite-wide :program:`pytest` configuration.

Besides session hooks documented where they are defined -- the warm import
and coverage flush in :func:`pytest_sessionstart` and
:func:`pytest_sessionfinish`, the timer release in
:func:`pytest_timeout_cancel_timer`, and the periodic garbage collection in
:func:`pytest_runtest_protocol` -- it holds the following. The first is
:func:`restore_module_table`, the guard that
puts the :mod:`pcapkit` region of :data:`sys.modules` back after every test; see
its own docstring for why it is here rather than left to each test file.

The second is the collection-time half of the tier guard described in
:mod:`tests._tiers`. Every unit-tier module about to be run is read and checked
for a ``sample_path('...')`` call naming a capture git does not track, and the
run is stopped before any test executes if one is found.

Stopping the run rather than failing the offending tests is the intended
behaviour. This is a repository-hygiene violation, not a bug in the code under
test -- the tests in question very likely pass on the machine that is running
them -- so the useful outcome is one loud, explanatory message at the top of the
output rather than a red test buried in a summary. Only modules the current
invocation actually collected are checked, so a narrow run is never stopped by a
file it was not going to run.

The static pass here and the runtime pass in :func:`tests._support.sample_path`
cover each other's blind spots: this one sees a violation in a test that never
runs (skipped for a missing optional engine, say) but only when the capture name
is a literal, while the runtime one sees any name however it was computed but
only when the call is reached.

The third is :func:`_tier_guard_lock` and :func:`_tier_guard_reader_lock`, a
readers-writer mutex that keeps
:class:`tests.test_tier_guard.SuiteIsCleanTests`'s live filesystem scan from
observing :class:`tests.test_tier_guard_xdist.XdistSubprocessTests`'s
deliberately-violating probe module while it is momentarily on disk. See
:func:`_tier_guard_lock`'s docstring for the race and why a mutex is what closes
it.

"""
from __future__ import annotations

import contextlib
import errno
import gc
import hashlib
import importlib
import os
import pathlib
import sys
import tempfile
import time
import types
import warnings
from typing import TYPE_CHECKING

import pytest

from tests._support import ISOLATED_PREFIXES, restore_modules, snapshot_modules
from tests._tiers import (PROBE_MODULE_NAME, ROOT, TierGuardWarning, audit_module, guard_unavailable_reason,
                          is_unit_tier)

try:
    import fcntl
except ImportError:  # pragma: no cover -- POSIX-only
    fcntl = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Optional


#: The :mod:`pcapkit` region of :data:`sys.modules`, pinned once by
#: :func:`_pin_module_snapshot` and never reassigned after that. :data:`None`
#: until the first call, which is what makes a second call a no-op rather than
#: a re-pin -- see that function's docstring for why the *first* call has to
#: win.
_pinned_snapshot = None  # type: Optional[dict[str, types.ModuleType]]

#: What :func:`pytest_sessionstart` imports before the pin: the package, plus the
#: two app-type registries it loads on first use rather than with itself (GitHub
#: issue #1538). See that hook for why the registries cannot be left out.
WARM_MODULES = ('pcapkit', 'pcapkit.const.reg.apptype.tcp', 'pcapkit.const.reg.apptype.udp')


def _pin_module_snapshot() -> None:
    """Capture the :mod:`pcapkit` region as the restore target, once.

    :func:`restore_module_table` restores to this pinned snapshot, not to one
    taken at its own entry. An entry snapshot is exact for a leak the fixture's
    own window can see, but blind to one planted outside it. :meth:`~unittest.TestCase.setUpClass` runs *before* the first
    test's fixture entry and a class-level cleanup runs *after* the last one's
    fixture exit, so a purge in either place is invisible to an entry-snapshot
    restore: the entry snapshot for that first test is already the post-purge
    state, and there is no exit for the class's last test left to catch a purge
    that has not happened yet. GitHub issue #720 is a purge of the first kind,
    in :meth:`tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
    .setUpClass`, with no ``tearDownClass`` to undo it, and left uncaught for
    exactly that reason.

    A *pinned* snapshot closes both, because :func:`restore_module_table` below
    restores to it before the test as well as after: whatever a class-level hook
    left the region as, the next test's own entry restores it before that test's
    ``setUp`` or body ever runs, and the same test's exit restores it again in
    case its own run (or a class-level hook firing on its way out) changed
    anything. This is a strict extension of the entry-snapshot restore rather
    than a departure from it -- between two tests that behave, nothing has
    touched the region, so the pinned snapshot and an entry snapshot taken at
    that moment are the same dictionary in every case that was already correct.
    The two views diverge only where a class-level hook mutated the region
    outside the per-test window, which is precisely the gap #720 found.

    It follows that the pin has to happen before *any* ``setUpClass`` can run,
    or it would capture whatever the first one purged, reproducing the very
    problem it exists to fix at one remove. :func:`pytest_sessionstart` runs
    before collection, which runs before any class's setup, so pinning there is
    always early enough; this function is called from there. It is also called
    from :func:`restore_module_table` itself, as a fallback for a runtime that
    skipped :func:`pytest_sessionstart` for some reason -- guarded by the same
    "first call wins" rule, so on every ordinary run that second call is a
    no-op.

    Does not itself import anything: whatever :func:`pytest_sessionstart` did or
    did not manage to import is what gets pinned, cold or warm alike.

    """
    global _pinned_snapshot
    if _pinned_snapshot is None:
        _pinned_snapshot = snapshot_modules(ISOLATED_PREFIXES)


def pytest_sessionstart(session: 'pytest.Session') -> 'None':
    """Import :mod:`pcapkit` once, before the first test takes a snapshot.

    Purely a performance measure, and it belongs to
    :func:`restore_module_table`: that fixture restores the region to the
    snapshot :func:`_pin_module_snapshot` takes immediately below, so what
    happens here decides what every test is restored *to*. Left cold, the
    region is empty at the pin and restored to empty after every test, which
    makes each of the tests that does not purge for itself -- :mod:`tests.project`
    is the bulk of them -- pay a fresh ``import pcapkit`` it would otherwise get
    from the warm table. Measured over ``tests/project/``: 1.59s with no
    guard at all, **9.34s** guarded from a cold table, **0.35s** guarded from a
    warm one. The last is the fastest of the three because the import it would
    otherwise do inside the first test has moved here instead.

    It helps a class that purges in :meth:`~unittest.TestCase.setUpClass` too.
    Such a class purges *after* this hook and *before* its first test, so a
    snapshot taken at that test's own entry would be whatever the class left --
    warming the table earlier would change nothing about it, as
    :func:`_pin_module_snapshot` explains. Restoring to a *pinned* snapshot
    before each test as well as after is what makes the warm-up matter to a
    purging class: the pin below captures this import, and every later test --
    including a purging class's own first one -- is restored to it going in as
    well as coming out, regardless of whether that class reloads anything for
    itself.
    So a class that purges and reimports for itself, as
    :class:`tests.integration._helpers.EndToEndTestCase` does, still runs its
    tests on the pin. Only a module object a class attribute holds a direct
    reference to survives the rebinding, since restoring :data:`sys.modules`
    does not invalidate it.

    Warming it also means the restore is a no-op for the common case. A test
    that imports the library and nothing else leaves the region exactly as it
    found it, so there is nothing to put back.

    The two lazily loaded app-type registries in :data:`WARM_MODULES` are
    imported here too, and that is for correctness rather than speed. Left out
    of the pin, they were dropped from :data:`sys.modules` after whichever test
    first loaded them, while the package kept the classes it had already bound
    in ``TCP``/``UDP`` and :attr:`AppType.__registries__
    <pcapkit.const.reg.apptype.apptype.AppType.__registries__>`. The next direct
    import of the submodule then built a second ``TCP`` and ``UDP``, and
    :mod:`tests.project.test_conventions_doc_claims` counted both generations, and
    its registry count came out wrong on the 3.10-3.13 unit legs of PR #1560.

    Failure here is not an error. A checkout without the runtime dependencies
    installed cannot import the package at all -- which is a supported way to run
    the parts of the suite that are guarded by ``skipUnless`` -- so this degrades
    to the cold baseline rather than taking the run down with it.

    Args:
        session: The pytest session, unused; the hook's signature requires it.

    """
    try:
        for name in WARM_MODULES:
            importlib.import_module(name)
    except Exception:  # pragma: no cover  # pylint: disable=broad-except
        # Deliberately broad: anything at all going wrong here should cost
        # nothing but the optimisation. ``BaseException`` is not caught, so an
        # interrupt during startup still ends the run.
        pass
    _pin_module_snapshot()


def pytest_sessionfinish(session: 'pytest.Session') -> 'None':
    """Write an xdist worker's coverage data out before the process can die (#1423).

    The coverage leg of ``unit-tests.yml`` measures each worker through
    coverage's ``patch = ["subprocess"]`` hook, and that measurement is saved by
    an :mod:`atexit` handler -- so it is written *after* the worker has already
    reported its results and told the controller it is finished. Anything that
    kills the process in that window takes the whole worker's data with it, and
    takes it silently: pytest has its results, so every test still passes, while
    ``coverage combine`` merges one file fewer and reports the rest as the whole.
    That is #1387, and the guard in ``Report coverage`` turns it into a failed
    step rather than a quietly low number -- four times on 2026-10-08.

    Saving here closes the window instead of policing it. :func:`cov.save` is
    safe to call mid-run (coverage's own long-running-process recipe), and the
    later ``atexit`` save appends to the same file, so the data file exists from
    this point on and a worker that dies during shutdown costs at most the arcs
    executed after this hook.

    A no-op outside that one leg: it returns immediately unless the process is
    an xdist worker (``workerinput``) whose coverage was auto-started by the
    subprocess patch.

    Args:
        session: The pytest session, for its config's ``workerinput``.

    """
    if not hasattr(session.config, 'workerinput'):
        return
    try:
        import coverage  # pylint: disable=import-outside-toplevel
    except ImportError:  # pragma: no cover
        return
    cov = getattr(coverage.process_startup, 'coverage', None)
    if cov is None:
        return
    try:
        cov.save()
    except Exception:  # pragma: no cover  # pylint: disable=broad-except
        # Deliberately broad, as in `pytest_sessionstart`: a failure to flush
        # early must not fail a run whose tests have already passed. The atexit
        # save still gets its turn, and the guard still catches a lost file.
        pass


@pytest.fixture(autouse=True)
def restore_module_table() -> 'Iterator[None]':
    """Put the :mod:`pcapkit` region of :data:`sys.modules` back to a known-good state.

    The suite tests a library by re-importing it from source over and over, and
    a good deal of it works by binding a stand-in over a real module name --
    :func:`tests._support.install_fake_protocol_module` and its neighbours, the
    hand-rolled equivalents in :mod:`tests.interface.test_core` and
    :mod:`tests.cli.test_main`. :data:`sys.modules` is process-global, so every
    one of those is a write that outlives the test unless something undoes it.

    Issue #660 is what that costs. A stand-in ``ProtocolBase`` that is not
    :class:`~typing.Generic` stayed bound after the test that installed it, and
    the next test to import :mod:`pcapkit` died on ``TypeError: type
    'ProtocolBase' is not subscriptable`` at the :class:`Frame` class statement
    in :mod:`pcapkit.protocols.misc.pcap.frame` -- a run of tests in
    :mod:`tests.project`, and only when the polluting file happened to be
    collected first. Several files turned out to leak this way, one of
    which -- :mod:`tests.cli.test_main` -- did not import :mod:`tests._support`
    at all.

    Hence a guard here rather than a ``tearDown`` in each of them. Every known
    leak is also fixed at its call site, with
    :func:`tests._support.isolate_modules`, because that is the honest fix and it
    holds under :mod:`unittest` as well; but a per-file fix only covers the files
    that have it, and the next one written without it would reintroduce the same
    order-dependent failure. This covers every test that exists and every test
    that will be written, which is the difference between the failure being
    unlikely and being impossible.

    A guard that repairs a leak also hides it. Issue #688 -- a purge loop in
    :mod:`tests.cli.test_main` that purged and restored nothing, which this
    fixture quietly healed for every test -- took an audit rather than a
    failing run to find. That is why every leak is fixed at its call site as
    well.

    Deliberately *not* fixed by moving ``test_protochain.py`` so it sorts
    elsewhere, or by leaning on a neighbouring test's purge to heal the state.
    Accidental healing by a neighbour is precisely why this survived for as long
    as it did -- the full CI selection passes because unrelated directories sort
    between the polluter and its victims -- so a fix of that shape would hide the
    defect again rather than remove it.

    Restoring to a *pinned* snapshot rather than one taken on entry is what
    closes issue #720, the same failure shape one level up:
    :meth:`~unittest.TestCase.setUpClass` runs *before* this fixture's first
    entry for the class and a class-level cleanup runs *after* its last exit, so
    either can plant exactly the kind of leak the paragraphs above describe
    without this fixture's old, entry-scoped restore ever seeing it -- an
    entry-scoped snapshot faithfully preserves whatever a ``setUpClass`` purge
    already did, rather than undoing it, and a class-level cleanup that purges
    again has no later exit here to be caught by at all. See
    :func:`_pin_module_snapshot` for why the fix is to restore to a fixed target
    instead, both before the test and after it, rather than to change what is
    snapshotted and when: doing it on both sides means neither a ``setUpClass``
    purge nor a class-exit purge survives past the next test's own entry,
    regardless of which one planted it or whether the class in between reimports
    anything. This is the same "leaning on a neighbour" trap the paragraph above
    already rejects, generalised: healing a class-level leak by restoring before
    the *next* test runs is the guard doing its own job on a fixed schedule, not
    an accident of collection order -- unlike relying on some *other* class's own
    purge to happen to reimport first, which is exactly the accident #720's
    reproduction shows failing half the time.

    Yields:
        Nothing; the region is already restored by the time control passes to
        the test, and restored again on the way out.

    """
    _pin_module_snapshot()  # no-op on every ordinary run; see that function
    restore_modules(_pinned_snapshot, ISOLATED_PREFIXES)
    try:
        yield
    finally:
        restore_modules(_pinned_snapshot, ISOLATED_PREFIXES)


@pytest.hookimpl(hookwrapper=True, optionalhook=True)
def pytest_timeout_cancel_timer(item: 'pytest.Item') -> 'Iterator[None]':
    """Drop the timer :mod:`pytest_timeout` leaves on ``item`` once it is cancelled.

    Issue #1052. pytest-timeout's ``thread`` method keeps ``item.cancel_timeout``, a
    closure over the test's :class:`threading.Timer`, for the whole session. A
    :class:`~threading.Thread` captures :data:`sys.excepthook` and
    :data:`threading.excepthook` when it is created, and every ``import pcapkit``
    installs fresh tbtrim hooks there, so each retained timer pins the
    :mod:`pcapkit` generation that was live when its test started. Measured on
    ``tests/const/test_const_registry_protocol.py`` under ``thread``: past 9 GiB
    and killed, against 283 MiB with this hook. ``optionalhook``: without
    pytest-timeout installed the hookspec does not exist.

    """
    yield
    item.__dict__.pop('cancel_timeout', None)


#: How many tests a process runs between the explicit :func:`gc.collect` calls
#: :func:`pytest_runtest_protocol` makes (#1964). Every test leaves unreachable
#: reference cycles behind -- the :mod:`pcapkit` generation
#: :func:`restore_module_table` drops, with its ABC caches and its ``InfoMeta``
#: and ``EnumMeta`` classes -- and the free-threaded build's collector reclaims
#: them far less often than the default build's, so a free-threaded xdist
#: worker grows until the experimental leg's memory scope kills it. A fixed
#: count rather than every test keeps nearly all of the saving for a fraction of
#: the cost; see that hook for the measurements.
GC_EVERY = 50

#: Tests this process has finished since its last periodic collection. Each
#: xdist worker is its own process, so each counts its own tests.
_tests_since_collect = 0


def _collect_periodically() -> 'bool':
    """Count one finished test, and collect cyclic garbage every :data:`GC_EVERY`.

    Returns:
        Whether this call ran :func:`gc.collect`.

    """
    global _tests_since_collect
    _tests_since_collect += 1
    if _tests_since_collect < GC_EVERY:
        return False
    _tests_since_collect = 0
    gc.collect()
    return True


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: 'pytest.Item',
                            nextitem: 'Optional[pytest.Item]') -> 'Iterator[None]':
    """Collect cyclic garbage every :data:`GC_EVERY` tests, so workers stay in memory (#1964).

    The experimental leg's 3.14t job runs its xdist workers under one 12G
    memory scope, and was OOM-killed whenever their sum crossed it: the
    garbage :data:`GC_EVERY` describes is not a leak, but the free-threaded
    collector frees it too late to keep a worker small. A wrapper is used so the
    count is taken once the whole protocol has finished, teardown included, so
    the generation :func:`restore_module_table` drops on the way out is already
    unreachable when the collection runs.

    Not gated on ``Py_GIL_DISABLED``: the default build holds the same garbage
    between its own collections, and collecting it cost no time on either build.
    Peak RSS per process over ``tests/protocols``, unpatched against patched, on
    local CPython 3.14.8 builds:

    * 3.14t, serial: 1668 MB to 1000 MB; 217 s to 205 s.
    * 3.14t, ``-n 2``: 3129 and 1968 MB to 669 and 891 MB; 142 s to 110 s.
    * 3.14, serial: 1602 MB to 856 MB; 397 s to 336 s.
    * 3.14, ``-n 2``: 4047 and 1020 MB to 855 and 462 MB; 294 s to 178 s.

    Collecting after every test instead cut the 3.14t serial peak only a little
    further and nearly doubled its time. Plain :mod:`unittest` runs never load
    this file, so they keep the collector's own schedule.

    Args:
        item: The test about to run, unused.
        nextitem: The test after it, unused.

    """
    yield
    _collect_periodically()


def _collected_modules(items: 'Iterable[pytest.Item]') -> 'Iterator[pathlib.Path]':
    """Distinct module paths behind ``items``, in collection order.

    Every test of a module maps to the same file, so the paths are deduplicated
    before anything reads them off disk.

    """
    seen = set()  # type: set[pathlib.Path]
    for item in items:
        # `item.path` since pytest 7; `item.fspath` is the legacy py.path spelling
        # and is kept as a fallback so the guard does not depend on which one a
        # given pytest exposes.
        location = getattr(item, 'path', None) or getattr(item, 'fspath', None)
        if location is None:
            continue
        path = pathlib.Path(str(location))
        if path in seen:
            continue
        seen.add(path)
        yield path


def _audit(items: 'Iterable[pytest.Item]') -> 'list[str]':
    """Tier violations across the collected unit-tier modules."""
    findings = []  # type: list[str]
    for path in _collected_modules(items):
        if is_unit_tier(path):
            findings.extend(audit_module(path))
    return findings


def pytest_collection_modifyitems(session: 'pytest.Session', config: 'pytest.Config',
                                  items: 'list[pytest.Item]') -> 'None':
    """Refuse to run a unit-tier module that depends on a generated fixture."""
    reason = None  # type: Optional[str]
    findings = []  # type: list[str]
    try:
        reason = guard_unavailable_reason()
        if reason is None:
            findings = _audit(items)
    except Exception as exc:  # pragma: no cover
        # The guard is not the thing under test. If it breaks, say so loudly and
        # let the suite run -- an exception escaping this hook would take every
        # test with it, which is a far worse outcome than an unchecked tier rule.
        warnings.warn(
            f'the test-tier guard (tests/_tiers.py) failed and did not run: '
            f'{type(exc).__name__}: {exc}',
            TierGuardWarning, stacklevel=1,
        )
        return

    if reason is not None:
        warnings.warn(
            f'the test-tier guard (tests/_tiers.py) did not run, because {reason}. Unit-tier '
            f'modules were not checked for reads of generated sample captures.',
            TierGuardWarning, stacklevel=1,
        )
        return

    if findings:
        message = (
            f'{len(findings)} read(s) of a generated sample capture from a unit-tier test '
            f'module; see tests/_tiers.py for the tier rule.\n\n' + '\n\n'.join(findings)
        )
        # Under pytest-xdist this hook runs inside each worker's own nested
        # session (xdist/remote.py), and that session's `pytest_collection_finish`
        # fires from a `finally:` regardless of the UsageError below, so the
        # controller sees a normal collection and may schedule a test to a worker
        # that is already unwinding. The controller then reports that test as
        # crashed -- `assert not crashitem` in xdist/dsession.py -- swallowing
        # this message and printing an INTERNALERROR instead. Measured against
        # pytest-xdist 3.8.0/pytest 9.1.1: setting `shouldfail` first is what the
        # controller already knows how to shut a worker down on cleanly, no
        # crash-item assertion, and the message still comes through -- as
        # ``xdist.dsession.Interrupted: <message>`` rather than ``ERROR:
        # <message>``, which is the one visible difference from the serial path.
        # A no-op outside a worker, so serial behaviour is unchanged.
        if hasattr(config, 'workerinput'):
            session.shouldfail = message
        raise pytest.UsageError(message)


#: Keeps the probe, :data:`tests._tiers.PROBE_MODULE_NAME`, out of every
#: session that does not name it on the command line (GitHub issue #1756),
#: as :func:`tests._tiers.suite_modules` keeps it out of the tiers. A worker that dies mid-probe never runs the
#: probe's cleanup, and xdist's replacement worker then collects ``tests/``
#: afresh: without this, its collection-time audit finds the stale probe, sets
#: ``session.shouldfail``, and the controller interrupts the whole session.
#: pytest consults ``collect_ignore`` only while recursing into a directory,
#: never for an initial path (``Dir.collect`` skips the check for
#: ``session.isinitpath``), so the probe's own nested run, which passes the
#: probe's path explicitly, still collects and audits it. Only this one
#: reserved path is ignored, and :class:`tests.test_tier_guard.SuiteIsCleanTests`
#: still scans it on disk like any other module wherever :func:`_tier_guard_lock`
#: can keep the live probe out of that scan.
collect_ignore = [f'protocols/{PROBE_MODULE_NAME}']

#: Module names whose own tests manage :func:`_tier_guard_lock` themselves and
#: must not also take the shared hold :func:`_tier_guard_reader_lock` puts on
#: every other unit-tier test.
#:
#: :data:`~tests._tiers.PROBE_MODULE_NAME` is excluded because it runs *inside* the writer's
#: exclusive hold by construction (that hold is what protects it), so taking a
#: shared one too would be a self-deadlock: the same lock file, opened twice by
#: the one process tree that also has to wait on itself to finish before either
#: side would let go. ``test_tier_guard_xdist.py`` is excluded for the same
#: reason -- :class:`~tests.test_tier_guard_xdist.XdistSubprocessTests` takes
#: the exclusive hold directly in its own ``setUp``, so the generic shared hold
#: below would collide with it in exactly the same way.
#:
#: This covers every test that manages the lock *directly*. It does not
#: generalise to a unit-tier test that spawns its own nested ``pytest``
#: subprocess while holding the outer shared hold --
#: :mod:`tests.project.test_module_isolation` is exactly such a test, and if
#: its selection ever grew to include this module or the probe, its outer
#: shared hold (spanning the whole test, including the blocking
#: ``subprocess.run``) would wait on an inner exclusive request that cannot be
#: granted until the outer test finishes: the same deadlock shape as above, one
#: level removed. It selects neither; a future change to that
#: selection should keep it that way, or add the module in question here too.
#: The nested run's own *shared* holds are a different matter, and
#: :data:`TIER_GUARD_HELD_ENV` covers them.
_LOCK_MANAGED_ELSEWHERE = frozenset({PROBE_MODULE_NAME, 'test_tier_guard_xdist.py'})

#: Whether :func:`_tier_guard_flock` polls with ``LOCK_NB`` instead of blocking
#: (#1977). GraalPy keeps the GIL while a thread sits in a blocking
#: :func:`fcntl.flock`, so a waiter there stops every other thread of its
#: process -- the holder it waits on, when both are threads of one process as in
#: :class:`~tests.test_tier_guard_xdist.ProbeWriteLockTests`, and
#: pytest-timeout's timer thread, so nothing ends the wait. CPython releases the
#: GIL there, and keeps the blocking call: the kernel wakes a blocked waiter the
#: moment the lock frees, where a poller only wins if it happens to ask inside a
#: gap between readers' holds.
TIER_GUARD_LOCK_POLLS = sys.implementation.name == 'graalpy'

#: Seconds :func:`_tier_guard_flock` sleeps between non-blocking attempts, when
#: :data:`TIER_GUARD_LOCK_POLLS` is set. :func:`time.sleep` releases the GIL on
#: GraalPy as on CPython.
TIER_GUARD_LOCK_POLL = 0.05

#: Set, to :func:`_tier_guard_lock_path`, while :func:`_tier_guard_reader_hold`
#: holds the lock shared, so that a nested :program:`pytest` the test spawns
#: inherits it and does not ask for that lock again (#2082). The writer's gate
#: makes a second shared request wait behind any writer already queued, and the
#: writer waits on the outer hold, which waits on the nested run: a deadlock
#: that only the nested run's ``subprocess.run`` timeout ends, as
#: :mod:`tests.project.test_module_isolation` hit on GraalPy, whose slow start
#: leaves the writer time to queue. The outer hold already keeps the writer out
#: for as long as the nested run lasts, so skipping the inner one loses nothing.
TIER_GUARD_HELD_ENV = 'PCAPKIT_TEST_TIER_GUARD_HELD'


def _tier_guard_lock_path() -> 'pathlib.Path':
    """Where the probe/scan mutex lives, one file per checkout.

    Keyed by :data:`tests._tiers.ROOT` rather than a fixed name, so two
    worktrees of this repository each running their own ``-n auto`` session on
    the same host never share a lock file neither of them needs shared.

    """
    digest = hashlib.sha1(str(ROOT).encode('utf-8')).hexdigest()[:16]
    return pathlib.Path(tempfile.gettempdir()) / f'pcapkit-tier-guard-probe-{digest}.lock'


def _tier_guard_flock(fd: 'int', operation: 'int') -> None:
    """Take :func:`fcntl.flock` ``operation`` on ``fd``, waiting as long as it takes.

    A blocking call, except where :data:`TIER_GUARD_LOCK_POLLS` says that would
    hold the GIL: there, ``LOCK_NB`` retried after a :data:`TIER_GUARD_LOCK_POLL`
    sleep, so no thread ever sits inside a blocking ``flock``. Only "would
    block" is retried; any other error propagates.

    """
    if not TIER_GUARD_LOCK_POLLS:
        fcntl.flock(fd, operation)
        return
    while True:
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise
            time.sleep(TIER_GUARD_LOCK_POLL)
        else:
            return


@contextlib.contextmanager
def _tier_guard_lock(exclusive: 'bool') -> 'Iterator[None]':
    """Hold the probe/scan mutex, shared or exclusive, for the block's duration.

    :class:`~tests.test_tier_guard.SuiteIsCleanTests` walks every unit-tier
    module on disk with :meth:`pathlib.Path.rglob`, which is sound against a
    committed tree but not against a concurrent write:
    :class:`~tests.test_tier_guard_xdist.XdistSubprocessTests` deliberately
    writes a real violation to disk, under :data:`~tests._tiers.PROBE_MODULE_NAME`, to
    reproduce the tier guard's own collection-time diagnostic end to end.
    Serially the two never overlap; under the ``-n auto --dist load`` this
    suite's CI jobs use, pytest-xdist may hand the two tests to different
    worker processes at the same moment, and the scan can then observe the
    probe mid-life and report a violation nobody committed -- a real defect in
    the test suite's own concurrency, not a false positive, since the guard is
    doing exactly what its docstring says: looking at everything on disk.

    The fix is an ordinary readers-writer mutex over one lock file every
    process opens independently: :class:`XdistSubprocessTests` holds it
    exclusively for as long as the probe module sits on disk (see its
    ``setUp``), and :func:`_tier_guard_reader_lock` below holds it shared, for
    the duration of the test, on behalf of every other unit-tier test --
    including :class:`SuiteIsCleanTests`, without that file having to change at
    all. :func:`fcntl.flock` enforces shared-vs-exclusive across processes as
    well as threads of one process, which is what makes the two truly unable to
    overlap rather than merely unlikely to.

    A no-op wherever :data:`fcntl` is :data:`None` -- true only off POSIX, such
    as the Windows leg of :file:`.github/workflows/experimental.yml`, which runs
    ``-n auto`` too. Nothing that has to stay correct there relies on the lock
    (#2114): :func:`tests._tiers.suite_modules` never lists the probe, and
    :class:`~tests.test_tier_guard.SuiteIsCleanTests` skips it where this is a
    no-op. :func:`msvcrt.locking` is no substitute, since it has no shared mode.

    Linux :func:`fcntl.flock` grants a shared request whenever no exclusive
    hold is *granted*, however long a writer has been waiting, so readers whose
    holds overlap can keep a writer out indefinitely -- and on GraalPy, which
    has to poll (see :data:`TIER_GUARD_LOCK_POLLS`), they do (#1977). A second
    lock file, the gate, gives the writer priority: a writer holds the gate
    exclusively while it waits for the lock, and a reader passes through the
    gate, shared and released at once, before asking for the lock. Readers
    hold the gate only for that instant, so the writer gets it almost at once,
    and the readers already past it then drain. The kernel drops both locks
    with a dying process, so no crash can leave the gate shut. Every wait is
    unbounded, as before: proceeding without the lock would reopen the race.

    Args:
        exclusive: :data:`True` for the writer's hold, :data:`False` for a
            reader's.

    """
    if fcntl is None:
        yield
        return
    path = _tier_guard_lock_path()
    gate_path = path.with_name(f'{path.name}.gate')
    with open(gate_path, 'a', encoding='utf-8') as gate, \
            open(path, 'a', encoding='utf-8') as handle:
        if exclusive:
            _tier_guard_flock(gate.fileno(), fcntl.LOCK_EX)
            try:
                _tier_guard_flock(handle.fileno(), fcntl.LOCK_EX)
            finally:
                fcntl.flock(gate.fileno(), fcntl.LOCK_UN)
        else:
            _tier_guard_flock(gate.fileno(), fcntl.LOCK_SH)
            fcntl.flock(gate.fileno(), fcntl.LOCK_UN)
            _tier_guard_flock(handle.fileno(), fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def _tier_guard_reader_hold() -> 'Iterator[None]':
    """A test's shared hold, unless an ancestor process already has one (#2082).

    Takes :func:`_tier_guard_lock` shared and sets :data:`TIER_GUARD_HELD_ENV`
    for the block, putting the variable back as it was afterwards. Where the
    variable already names this lock file, the hold is an ancestor's that spans
    this whole process, so the lock is not asked for again.

    """
    held = str(_tier_guard_lock_path())
    if os.environ.get(TIER_GUARD_HELD_ENV) == held:
        yield
        return
    with _tier_guard_lock(exclusive=False):
        previous = os.environ.get(TIER_GUARD_HELD_ENV)
        os.environ[TIER_GUARD_HELD_ENV] = held
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop(TIER_GUARD_HELD_ENV, None)
            else:
                os.environ[TIER_GUARD_HELD_ENV] = previous


@pytest.fixture(autouse=True)
def _tier_guard_reader_lock(request: 'pytest.FixtureRequest') -> 'Iterator[None]':
    """Hold the probe/scan mutex shared, for every unit-tier test but the two
    that self-manage it.

    See :func:`_tier_guard_lock` for the race this closes. Deciding by
    :func:`tests._tiers.is_unit_tier` rather than by this one test's name is
    deliberate: every unit-tier test is a potential
    :class:`~tests.test_tier_guard.SuiteIsCleanTests`, so the protection is
    structural and covers a similarly-scanning test written later without this
    fixture changing at all -- and it never has to touch that module's own
    source to do it. :func:`_tier_guard_reader_hold` takes the hold.

    """
    location = getattr(request.node, 'path', None) or getattr(request.node, 'fspath', None)
    path = pathlib.Path(str(location)) if location is not None else None
    if path is None or path.name in _LOCK_MANAGED_ELSEWHERE or not is_unit_tier(path):
        yield
        return
    with _tier_guard_reader_hold():
        yield
