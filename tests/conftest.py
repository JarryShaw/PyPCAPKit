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
import warnings
from typing import TYPE_CHECKING

import pytest

from tests._support import ISOLATED_PREFIXES, restore_modules, snapshot_modules
from tests._tiers import (TierGuardWarning, audit_module, guard_unavailable_reason,
                          is_unit_tier)

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Optional


def pytest_sessionstart(session: 'pytest.Session') -> 'None':
    """Import :mod:`pcapkit` once, before the first test takes a snapshot.

    Purely a performance measure, and it belongs to
    :func:`restore_module_table`: that fixture restores whatever the region held
    when the test began, so what it restores *to* decides what the next test has
    to re-import. Left cold, the region is empty at the first snapshot and
    restored to empty after every test, which makes each of the tests that does
    not purge for itself -- :mod:`tests.project` is the bulk of them -- pay a
    fresh ``import pcapkit`` it used to get from the warm table. Measured over
    the 96 tests of ``tests/project/``: 1.59s with no guard at all, **9.34s**
    guarded from a cold table, **0.35s** guarded from a warm one. The last is the
    fastest of the three because the import it would otherwise do inside the
    first test has moved here instead.

    This does **not** help a class that purges in
    :meth:`~unittest.TestCase.setUpClass`, and it is worth being clear about why,
    because the obvious reading is wrong. Such a class purges *after* this hook
    and *before* the first snapshot, so its snapshot is whatever it left --
    warming the table earlier changes nothing about it. Where the class loads
    something straight after its own purge the snapshot is populated anyway and
    nothing is lost; where it purges and defers the import to its test methods,
    every one of them re-imports. Exactly one class in the suite did the latter,
    :class:`tests.integration._helpers.EndToEndTestCase`, at a measured cost of
    some 45s across its 92 test methods, and it now re-imports in its own
    ``setUpClass`` rather than deferring. A future class that purges per class
    should do the same.

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


@pytest.fixture(autouse=True)
def restore_module_table() -> 'Iterator[None]':
    """Put the :mod:`pcapkit` region of :data:`sys.modules` back after every test.

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

    Function-scoped, so :meth:`~unittest.TestCase.setUpClass` runs *inside* the
    snapshot: pytest instantiates class-scoped fixtures before function-scoped
    ones, so a class that purges once for all its tests has that purge captured
    here and restored to, rather than undone between its own tests.

    Yields:
        Nothing; the restore happens on the way out.

    """
    snapshot = snapshot_modules(ISOLATED_PREFIXES)
    try:
        yield
    finally:
        restore_modules(snapshot, ISOLATED_PREFIXES)


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
