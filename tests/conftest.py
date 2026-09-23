# -*- coding: utf-8 -*-
"""Suite-wide :program:`pytest` configuration.

Holds two things. The first is :func:`restore_module_table`, the guard that puts
the :mod:`pcapkit` region of :data:`sys.modules` back after every test; see its
own docstring for why it is here rather than left to each test file.

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

"""
from __future__ import annotations

import importlib
import pathlib
import types
import warnings
from typing import TYPE_CHECKING

import pytest

from tests._support import ISOLATED_PREFIXES, restore_modules, snapshot_modules
from tests._tiers import (TierGuardWarning, audit_module, guard_unavailable_reason,
                          is_unit_tier)

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Optional


#: The :mod:`pcapkit` region of :data:`sys.modules`, pinned once by
#: :func:`_pin_module_snapshot` and never reassigned after that. :data:`None`
#: until the first call, which is what makes a second call a no-op rather than
#: a re-pin -- see that function's docstring for why the *first* call has to
#: win.
_pinned_snapshot = None  # type: Optional[dict[str, types.ModuleType]]


def _pin_module_snapshot() -> None:
    """Capture the :mod:`pcapkit` region as the restore target, once.

    :func:`restore_module_table` used to restore to a snapshot taken at its own
    entry -- "whatever the region held when this test began" -- which is exact
    for a leak the fixture's own window can see, but blind to one planted
    outside it. :meth:`~unittest.TestCase.setUpClass` runs *before* the first
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
    is the bulk of them -- pay a fresh ``import pcapkit`` it used to get from the
    warm table. Measured over the 96 tests of ``tests/project/``: 1.59s with no
    guard at all, **9.34s** guarded from a cold table, **0.35s** guarded from a
    warm one. The last is the fastest of the three because the import it would
    otherwise do inside the first test has moved here instead.

    This used **not** to help a class that purges in
    :meth:`~unittest.TestCase.setUpClass`, for the reason
    :func:`_pin_module_snapshot` explains: such a class purges *after* this hook
    and *before* the first snapshot the old, entry-scoped fixture took, so that
    snapshot was whatever the class left -- warming the table earlier changed
    nothing about it. Restoring to a *pinned* snapshot before each test as well
    as after, rather than to one taken at that test's own entry, is what makes
    the warm-up matter to a purging class too now: the pin below still captures
    this import, and every later test -- including a purging class's own first
    one -- is restored to it going in as well as coming out, regardless of
    whether that class reloads anything for itself.
    :class:`tests.integration._helpers.EndToEndTestCase` does reload immediately
    after its own purge, for the unrelated reason given in its own docstring --
    saving roughly 45s across its 92 test methods -- and nothing here disturbs
    that: rebinding :data:`sys.modules` to the pin does not invalidate a module
    object a class attribute already holds a direct reference to, so a class
    that reimports for itself keeps exactly what it reimported.

    Warming it also means the restore is a no-op for the common case. A test
    that imports the library and nothing else leaves the region exactly as it
    found it, so there is nothing to put back.

    Failure here is not an error. A checkout without the runtime dependencies
    installed cannot import the package at all -- which is a supported way to run
    the parts of the suite that are guarded by ``skipUnless`` -- so this degrades
    to the cold baseline rather than taking the run down with it.

    Args:
        session: The pytest session, unused; the hook's signature requires it.

    """
    try:
        importlib.import_module('pcapkit')
    except Exception:  # pragma: no cover  # pylint: disable=broad-except
        # Deliberately broad: anything at all going wrong here should cost
        # nothing but the optimisation. ``BaseException`` is not caught, so an
        # interrupt during startup still ends the run.
        pass
    _pin_module_snapshot()


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
    'ProtocolBase' is not subscriptable`` at
    ``pcapkit/protocols/misc/pcap/frame.py:59`` -- twelve tests in
    :mod:`tests.project`, and only when the polluting file happened to be
    collected first. Three separate files turned out to leak this way, one of
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

    Two of the three were fixed at their call sites when this guard landed, and
    the third was not: :mod:`tests.cli.test_main` kept its own purge loop, which
    purges and restores nothing, and this fixture went on quietly healing it for
    every test. That is issue #688 -- it took an audit rather than a failing run
    to find, because a guard that repairs a leak also hides it. It is now fixed
    at its call site too, which is what makes the paragraph above true of all
    three rather than of two.

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


def pytest_collection_modifyitems(config: 'pytest.Config',
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
        raise pytest.UsageError(
            f'{len(findings)} read(s) of a generated sample capture from a unit-tier test '
            f'module; see tests/_tiers.py for the tier rule.\n\n' + '\n\n'.join(findings)
        )
