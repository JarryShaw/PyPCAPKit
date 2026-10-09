# -*- coding: utf-8 -*-
"""Shared harness for the protocol edge-case round-trip modules. C.f. #1202.

The owner's rule is that parse -> rebuild and make -> parse are byte-exact
everywhere. The ``test_*_edge_roundtrip_unit`` modules beside this one hold
hand-built edge-case packets -- minimum and maximum lengths, reserved bits set,
zero-length values, padding variants, unassigned codes -- and this module runs
them through three checks:

* a **parse case** must parse, its ``data`` must be the input, and
  ``from_data(info).data`` must be the input too;
* a **cut** of a parse case (the same octets one short, and half as long) must
  either be rejected with an in-library exception or meet the same two
  equalities -- a truncated packet may be refused, but not crash and not
  rebuild differently;
* a **make case** must construct, its octets must parse back to themselves, and
  ``from_data`` over the parsed ``info`` must construct the same octets again.

A case that does not close goes in its module's ``KNOWN_FAILURES``, grouped by
root cause, and the table is asserted in both directions so that a fixed defect
turns the module red. Malformed inputs a protocol is entitled to refuse go in
``REJECTED`` instead, with the exception they raise.

Nothing here imports :mod:`pcapkit` at module level: classes are named by
dotted path and resolved inside each test, after
:func:`~tests._support.reimport_once_per_class`, for the reason
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""

from __future__ import annotations

import fnmatch
import importlib
import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple

from tests._support import reimport_once_per_class, time_limit

if TYPE_CHECKING:
    from typing import Any, Optional

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one case may take; a working case takes milliseconds.
CASE_TIMEOUT = 30

#: Statuses a check can report. ``REJECTED`` is an in-library exception raised
#: while parsing; it is a pass for a cut and for a ``REJECTED`` entry only.
#: ``PADDED`` is a ``MISMATCH`` whose rebuild is the input followed by zero
#: octets, the signature of octets the parse never read being written back.
STATUSES = ('OK', 'REJECTED', 'PARSE', 'SELF', 'REBUILD', 'MISMATCH', 'PADDED',
            'MAKE', 'REPARSE', 'REMAKE', 'TIMEOUT')


class Case(NamedTuple):
    """One packet to parse and rebuild."""

    #: Unique label, ``family/what``.
    label: 'str'
    #: Protocol class as ``module:Class``.
    cls: 'str'
    #: Wire octets.
    raw: 'bytes'
    #: Extra parse keywords, e.g. ``{'extension': True}``.
    kwargs: 'dict[str, Any]' = {}
    #: Octets the layer itself owns, when fewer than ``raw``: an extension
    #: header parsed with ``extension=True`` covers only its own header in
    #: ``data`` (#1446). :data:`None` means all of ``raw``.
    owned: 'Optional[int]' = None


class MakeCase(NamedTuple):
    """One ``make`` call to construct, parse and construct again."""

    #: Unique label, ``family/make/what``.
    label: 'str'
    #: Protocol class as ``module:Class``.
    cls: 'str'
    #: ``make`` keywords.
    kwargs: 'dict[str, Any]'
    #: Extra parse keywords for the re-parse.
    parse_kwargs: 'dict[str, Any]' = {}


class Outcome(NamedTuple):
    """What one check found."""

    status: 'str'
    detail: 'str'


class Gap(NamedTuple):
    """One root cause, and every case it stops."""

    #: GitHub issue tracking the defect, or :data:`None` if not filed yet.
    issue: 'Optional[int]'
    #: The defect, with the ``file:line`` that causes it.
    defect: 'str'
    #: Expected status of every case below, or the statuses one root cause
    #: shows as, of which each case must report one.
    status: 'str | tuple[str, ...]'
    #: Substring every failure detail must contain, or a tuple of which each
    #: detail must contain at least one -- one per symptom or per case where
    #: the details differ -- or ``''`` where the status is itself the signature
    #: (``PADDED``).
    fragment: 'str | tuple[str, ...]'
    #: Labels of the cases this defect stops, as :mod:`fnmatch` patterns. Each
    #: pattern must match at least one case, and every case it matches must
    #: fail as recorded, so a pattern is only as wide as the defect.
    cases: 'tuple[str, ...]'


class Reject(NamedTuple):
    """A malformed input the protocol is entitled to refuse."""

    #: Name of the in-library exception class raised.
    exc: 'str'
    #: Substring the message must contain.
    fragment: 'str'


def _statuses(gap: 'Gap') -> 'tuple[str, ...]':
    return (gap.status,) if isinstance(gap.status, str) else gap.status


def resolve(path: 'str') -> 'type':
    """Import ``module:Class`` from the current :mod:`pcapkit` import."""
    module, _, name = path.partition(':')
    return getattr(importlib.import_module(module), name)


def _describe(exc: 'BaseException') -> 'str':
    return f'{type(exc).__name__}: {exc}'


def _in_library(exc: 'BaseException') -> 'bool':
    base = importlib.import_module('pcapkit.utilities.exceptions').BaseError
    return isinstance(exc, base)


def _diff(got: 'bytes', want: 'bytes') -> 'str':
    return f'{len(got)} octets {got.hex()} != {len(want)} octets {want.hex()}'


def run_parse(case: 'Case') -> 'Outcome':
    """Parse ``case.raw``, then rebuild it from ``info``."""
    cls = resolve(case.cls)
    raw = case.raw if case.owned is None else case.raw[:case.owned]
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            proto = cls(case.raw, len(case.raw), **case.kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REJECTED' if _in_library(exc) else 'PARSE', _describe(exc))
        if proto.data != raw:
            return Outcome('SELF', _diff(proto.data, raw))
        try:
            rebuilt = type(proto).from_data(proto.info).data
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REBUILD', _describe(exc))
    if rebuilt != raw:
        if len(rebuilt) > len(raw) and rebuilt == raw.ljust(len(rebuilt), b'\x00'):
            return Outcome('PADDED', _diff(rebuilt, raw))
        return Outcome('MISMATCH', _diff(rebuilt, raw))
    return Outcome('OK', '')


def run_make(case: 'MakeCase') -> 'Outcome':
    """Construct, parse the octets back, and construct from the parsed ``info``."""
    cls = resolve(case.cls)
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            made = cls(**case.kwargs).data
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('MAKE', _describe(exc))
        try:
            parsed = cls(made, len(made), **case.parse_kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REPARSE', _describe(exc))
        if parsed.data != made:
            return Outcome('REPARSE', _diff(parsed.data, made))
        try:
            again = type(parsed).from_data(parsed.info).data
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REMAKE', _describe(exc))
    if again != made:
        return Outcome('REMAKE', _diff(again, made))
    return Outcome('OK', '')


def cuts(cases: 'tuple[Case, ...]') -> 'tuple[Case, ...]':
    """Each case one octet short, and half as long; at most two per case."""
    out = []  # type: list[Case]
    for case in cases:
        size = len(case.raw)
        for keep in sorted({size - 1, size // 2}):
            if keep > 0:
                owned = None if case.owned is None else min(case.owned, keep)
                out.append(case._replace(label=f'{case.label}/cut{keep}', raw=case.raw[:keep], owned=owned))
    return tuple(out)


class EdgeRoundTripBase(unittest.TestCase):
    """The assertions, shared by every family module.

    A subclass sets the four tables; this class is not collected itself
    because it has no tables (:attr:`CASES` is empty).

    """

    #: Parse cases.
    CASES = ()  # type: tuple[Case, ...]
    #: Make cases.
    MAKE_CASES = ()  # type: tuple[MakeCase, ...]
    #: Labels of malformed inputs that must be refused, and how.
    REJECTED = {}  # type: dict[str, Reject]
    #: Known failures, one entry per root cause.
    KNOWN_FAILURES = ()  # type: tuple[Gap, ...]

    def setUp(self) -> None:
        if not self.CASES:
            self.skipTest('base class')
        if not HAS_RUNTIME:
            self.skipTest('runtime dependencies not installed')
        reimport_once_per_class(self)

    # -- helpers ----------------------------------------------------------

    def _gaps(self) -> 'dict[str, Gap]':
        """Every case label a ``KNOWN_FAILURES`` pattern matches, to its entry."""
        labels = sorted(self._labels())
        table = {}  # type: dict[str, Gap]
        for gap in self.KNOWN_FAILURES:
            for pattern in gap.cases:
                for label in fnmatch.filter(labels, pattern):
                    self.assertIs(table.setdefault(label, gap), gap,
                                  f'{label} is listed under two root causes')
        return table

    def _all_cases(self) -> 'tuple[Case, ...]':
        return self.CASES + cuts(tuple(c for c in self.CASES if c.label not in self.REJECTED))

    def _labels(self) -> 'set[str]':
        return {c.label for c in self._all_cases()} | {c.label for c in self.MAKE_CASES}

    def _check(self, label: 'str', outcome: 'Outcome', passing: 'tuple[str, ...]',
               gaps: 'dict[str, Gap]') -> None:
        gap = gaps.get(label)
        if gap is None:
            self.assertIn(
                outcome.status, passing,
                f'{label} does not round-trip: {outcome.status}: {outcome.detail}. '
                f'If this is a new defect, add it to KNOWN_FAILURES under its root cause.')
            return
        self.assertIn(
            outcome.status, _statuses(gap),
            f'{label} was recorded as failing with {gap.status} '
            f'(#{gap.issue}: {gap.defect}) but came back {outcome.status}: '
            f'{outcome.detail}. If the defect is fixed, delete the label from its entry.')
        fragments = (gap.fragment,) if isinstance(gap.fragment, str) else gap.fragment
        if any(fragments):
            self.assertTrue(
                any(fragment in outcome.detail for fragment in fragments if fragment),
                f'{label} fails, but not in the recorded way ({gap.defect}); '
                f'detail was {outcome.detail!r}')

    def _run(self, func: 'Any', case: 'Any') -> 'Outcome':
        try:
            with time_limit(CASE_TIMEOUT):
                return func(case)
        except TimeoutError as exc:
            return Outcome('TIMEOUT', str(exc))

    # -- the tables -------------------------------------------------------

    def test_labels_are_unique(self) -> None:
        labels = [c.label for c in self.CASES] + [c.label for c in self.MAKE_CASES]
        self.assertEqual(len(labels), len(set(labels)), 'duplicate case labels')

    def test_tables_name_real_cases(self) -> None:
        """Every ``KNOWN_FAILURES`` pattern and ``REJECTED`` label names a case."""
        labels = sorted(self._labels())
        stale = [pattern for gap in self.KNOWN_FAILURES for pattern in gap.cases
                 if not fnmatch.filter(labels, pattern)]
        self.assertEqual(stale, [], 'KNOWN_FAILURES patterns that match no case')
        self.assertEqual(sorted(set(self.REJECTED) - set(labels)), [], 'stale REJECTED labels')
        self.assertEqual(sorted(set(self._gaps()) & set(self.REJECTED)), [],
                         'a label cannot be both rejected and a known failure')
        for gap in self.KNOWN_FAILURES:
            for status in _statuses(gap):
                self.assertIn(status, STATUSES)
                self.assertNotEqual(status, 'OK', gap.defect)
            self.assertTrue(gap.cases, f'empty KNOWN_FAILURES entry: {gap.defect}')

    # -- the checks -------------------------------------------------------

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        gaps = self._gaps()
        for case in self.CASES:
            if case.label in self.REJECTED:
                continue
            with self.subTest(case=case.label):
                self._check(case.label, self._run(run_parse, case), ('OK',), gaps)

    def test_cut_is_rejected_or_byte_exact(self) -> None:
        gaps = self._gaps()
        for case in cuts(tuple(c for c in self.CASES if c.label not in self.REJECTED)):
            with self.subTest(case=case.label):
                self._check(case.label, self._run(run_parse, case), ('OK', 'REJECTED'), gaps)

    def test_make_then_parse_is_stable(self) -> None:
        gaps = self._gaps()
        for case in self.MAKE_CASES:
            with self.subTest(case=case.label):
                self._check(case.label, self._run(run_make, case), ('OK',), gaps)

    def test_malformed_input_is_rejected_in_library(self) -> None:
        cases = {c.label: c for c in self.CASES}
        for label, reject in self.REJECTED.items():
            with self.subTest(case=label):
                outcome = self._run(run_parse, cases[label])
                self.assertEqual(outcome.status, 'REJECTED', f'{label}: {outcome.detail}')
                self.assertTrue(outcome.detail.startswith(f'{reject.exc}: '), outcome.detail)
                self.assertIn(reject.fragment, outcome.detail)
