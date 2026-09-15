# -*- coding: utf-8 -*-
"""Suite-wide :program:`pytest` configuration.

Holds one thing: the collection-time half of the tier guard described in
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

import pathlib
import warnings
from typing import TYPE_CHECKING

import pytest

from tests._tiers import (TierGuardWarning, audit_module, guard_unavailable_reason,
                          is_unit_tier)

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Optional


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
