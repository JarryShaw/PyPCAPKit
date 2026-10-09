# -*- coding: utf-8 -*-
"""Shared known-failure tables for the corekit round-trip modules. C.f. #1202.

The owner's rule is that every round trip the library offers reproduces its
input exactly. The ``test_*_roundtrip_unit`` modules beside this one enumerate
the corekit round trips -- a field's ``pack``/``unpack``, a schema's
``pack``/``unpack`` and ``from_dict``/``to_dict``, an :class:`~pcapkit.corekit.
infoclass.Info`'s ``from_dict``/``to_dict`` -- and report one :class:`Outcome`
per case. A case that does not close is listed in its module's
``KNOWN_FAILURES``, one :class:`Gap` per root cause, in the style of
:mod:`tests.protocols._edge_roundtrip`.

The table is asserted in both directions: a case that fails and is not listed
turns its module red, and so does a listed case that passes, so a fix has to
delete its entry in the same change. A pattern that matches no case is stale and
fails too.

"""

from __future__ import annotations

import fnmatch
import importlib.util
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import time_limit

if TYPE_CHECKING:
    from typing import Any, Callable, Iterable, Optional

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one case may take; a working case takes milliseconds.
CASE_TIMEOUT = 30


class Outcome(NamedTuple):
    """What one check found."""

    #: ``'OK'`` or a module-specific failure status.
    status: 'str'
    #: Failure detail; empty when the case closed.
    detail: 'str' = ''


#: The outcome of a case that closed.
OK = Outcome('OK')


class Gap(NamedTuple):
    """One root cause, and every case it stops."""

    #: GitHub issue tracking the defect.
    issue: 'Optional[int]'
    #: The defect, with the ``file:line`` that causes it.
    defect: 'str'
    #: Status every case below reports, or a tuple of which each reports one.
    status: 'str | tuple[str, ...]'
    #: Substring every failure detail must contain, or a tuple of which each
    #: detail must contain one.
    fragment: 'str | tuple[str, ...]'
    #: Labels of the cases this defect stops, as :mod:`fnmatch` patterns. Each
    #: pattern must match at least one case, and every case it matches must fail
    #: as recorded, so a pattern is only as wide as the defect.
    cases: 'tuple[str, ...]'


def describe(exc: 'BaseException') -> 'str':
    """``Type: message``, as a failure detail."""
    return f'{type(exc).__name__}: {exc}'


def diff(got: 'bytes', want: 'bytes') -> 'str':
    """Two octet strings as a failure detail."""
    return f'{len(got)} octets {got.hex()} != {len(want)} octets {want.hex()}'


def run(func: 'Callable[..., Outcome]', *args: 'Any') -> 'Outcome':
    """Run ``func(*args)``, one check, under :data:`CASE_TIMEOUT`."""
    try:
        with time_limit(CASE_TIMEOUT):
            return func(*args)
    except TimeoutError as exc:
        return Outcome('TIMEOUT', str(exc))


def _as_tuple(value: 'str | tuple[str, ...]') -> 'tuple[str, ...]':
    return (value,) if isinstance(value, str) else value


class KnownFailureTable:
    """The table assertions, mixed into a :class:`unittest.TestCase`."""

    #: Known failures, one entry per root cause.
    KNOWN_FAILURES = ()  # type: tuple[Gap, ...]
    #: Statuses a case in this module may report.
    STATUSES = ('OK',)  # type: tuple[str, ...]

    def gap_table(self: 'Any', labels: 'Iterable[str]') -> 'dict[str, Gap]':
        """Every label a ``KNOWN_FAILURES`` pattern matches, to its entry."""
        labels = sorted(labels)
        table = {}  # type: dict[str, Gap]
        for gap in self.KNOWN_FAILURES:
            for pattern in gap.cases:
                for label in fnmatch.filter(labels, pattern):
                    self.assertIs(table.setdefault(label, gap), gap,
                                  f'{label} is listed under two root causes')
        return table

    def check_table(self: 'Any', labels: 'Iterable[str]') -> 'None':
        """Every pattern names a case, and every entry is well formed."""
        labels = sorted(labels)
        self.assertEqual(len(labels), len(set(labels)), 'duplicate case labels')
        stale = [pattern for gap in self.KNOWN_FAILURES for pattern in gap.cases
                 if not fnmatch.filter(labels, pattern)]
        self.assertEqual(stale, [], 'KNOWN_FAILURES patterns that match no case')
        for gap in self.KNOWN_FAILURES:
            self.assertTrue(gap.cases, f'empty KNOWN_FAILURES entry: {gap.defect}')
            for status in _as_tuple(gap.status):
                self.assertIn(status, self.STATUSES)
                self.assertNotEqual(status, 'OK', gap.defect)

    def check_outcome(self: 'Any', label: 'str', outcome: 'Outcome',
                      gaps: 'dict[str, Gap]') -> 'None':
        """Assert ``outcome`` is ``OK``, or fails as its entry records."""
        gap = gaps.get(label)
        if gap is None:
            self.assertEqual(
                outcome.status, 'OK',
                f'{label} does not round-trip: {outcome.status}: {outcome.detail}. '
                f'If this is a new defect, add it to KNOWN_FAILURES under its root cause.')
            return
        self.assertIn(
            outcome.status, _as_tuple(gap.status),
            f'{label} was recorded as failing with {gap.status} (#{gap.issue}: '
            f'{gap.defect}) but came back {outcome.status}: {outcome.detail}. '
            f'If the defect is fixed, delete the label from its entry.')
        fragments = [fragment for fragment in _as_tuple(gap.fragment) if fragment]
        if fragments:
            self.assertTrue(
                any(fragment in outcome.detail for fragment in fragments),
                f'{label} fails, but not in the recorded way ({gap.defect}); '
                f'detail was {outcome.detail!r}')


def skip_without_runtime(case: 'unittest.TestCase') -> 'None':
    """Skip ``case`` when the runtime dependencies are not installed."""
    if not HAS_RUNTIME:
        case.skipTest('runtime dependencies not installed')
