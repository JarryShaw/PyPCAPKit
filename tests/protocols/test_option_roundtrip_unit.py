# -*- coding: utf-8 -*-
"""Construct -> parse -> construct identity, over every option-like code.

Every option, chunk, parameter, message type, frame type and block type this
library claims to support is enumerated *from the dispatch registries* and put
through one cycle: construct it through the public construction API, parse the
result back, construct it again from what was parsed, and require the octets to
be identical across the round trip.

That third step is what this module exists for. A construct-then-parse test
passes for a ``_make_*`` that takes only keyword arguments and cannot consume
the data model its own ``_read_*`` produced -- which is a defect that ships, and
one such a test cannot see. HIP parameters are the example: their data models
declare a ``tuple``, which :class:`~pcapkit.protocols.schema.schema.Schema`'s
``ListField`` pack branch has to accept as well as a ``list`` (#476).

The case list and the cycle both live in
:file:`examples/generators/options.py`, next to the generator that turns the
same cases into the ``options-*.pcap`` fixtures, so that the captures and these
assertions can never describe different things. See that module for why the
enumeration is registry-driven and how the per-code arguments were chosen.

What this module adds is the *judgement*: :data:`EXPECTED_FAILURES` records, case
by case, which cycles do not close and which defect stops each one. A case
absent from that table has to come back ``'OK'``.

That table can only speak about cycles that *fail*, though, and a defect can
leave the cycle closed -- the generator constructing and reconstructing the same
wrong octets, which match each other and so match the assertion. Those are
pinned as tests of their own rather than as entries, since an entry would have to
record ``'OK'`` as a failure. HIP's parameter padding is the example: a rule
aligning the contents to eight rather than the record makes every parameter
``4 (mod 8)``, so the header ``len`` field cannot represent a lone one, and a
round trip cannot see it, because pcapkit's writer and reader share the rule.
#651 pins the padding against :rfc:`7401` Section 5.2.1 rather than against a
round trip, and
:meth:`OptionRoundTripTests.test_a_hip_packet_carrying_one_parameter_round_trips`
asserts that the case closes.

IPv4's ``SID`` option width is another (#534): the generator constructs and
reconstructs through the same ``_make_opt_sid``, so the width is asserted against
wire octets instead, by
:meth:`IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire
<tests.protocols.internet.test_ipv4_unit.IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire>`,
in the IPv4 unit suite beside the rest of that option's coverage.

Why the table is asserted in both directions
--------------------------------------------

An expected failure that is only allowed to fail is a test that rots. So each
entry is checked to still fail, *and* to fail in the recorded way -- so fixing
one of these defects turns this module red, which is the reminder to delete the
entry. The reverse check matters as much: :meth:`test_expected_failures_name_real_cases`
fails if the table names a case that no longer exists, which is what happens when
a registry entry is renamed or removed.

Nothing here is a workaround for the defects it records. Every ``_make_*``
argument in the generator's tables is a legitimate value for that option, and
none of the assertions below has been loosened to make a failing case pass. HIP's
``HIP_COPIES`` puts one copy of each parameter in a packet (#689) -- see the
constant's note in the generator -- so no argument routes around a lone
parameter's length. The single-parameter case is asserted directly by
:meth:`OptionRoundTripTests.test_a_hip_packet_carrying_one_parameter_round_trips`,
which is also where the two-copy shape is exercised, as this table does not
produce it.

This module is unit tier: it constructs its own octets and reads no capture, so
it runs on a fresh checkout with nothing generated.

"""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import purge_modules, time_limit
from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): a sweep over every registered option code.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one case may take. Generous next to a working case, which takes
#: low single-digit milliseconds; the point of the deadline is the cases that
#: never finish at all.
CASE_TIMEOUT = 30


class Gap(NamedTuple):
    """One cycle that does not close, and the defect that stops it."""

    #: Expected :attr:`~examples.generators.options.Outcome.status`.
    status: 'str'
    #: Substring the failure detail must contain, or a tuple of substrings *all*
    #: of which it must contain, or ``''`` to assert only the status. Empty is
    #: used where the detail is a pair of long hex strings, or where it embeds a
    #: timestamp and so is not stable between runs.
    #:
    #: Make it as specific as the message allows, because a fragment that matches
    #: half the tree does not pin anything: ``'invalid format'`` alone occurs at
    #: sites across many modules, and repeatedly within
    #: :file:`pcapkit/protocols/internet/hip.py` and
    #: :file:`pcapkit/protocols/transport/tcp.py`, so it is satisfied by a
    #: regression at any of them. Prefer the alias and whatever bracketed code the
    #: message carries -- ``'TCP: [OptNo 28] invalid format'`` narrows the TCP
    #: sites to the one option that can print ``28``. The tuple form is for
    #: messages whose stable parts are not contiguous, so that a fragment does
    #: not have to bake in a rendering that is itself defective.
    fragment: 'str | tuple[str, ...]'
    #: The defect, naming the function, class or method that causes it. This is
    #: the field that makes the entry worth keeping rather than just silencing.
    defect: 'str'


#: Every case whose cycle does not close, and the defect that stops it. Empty:
#: every case round-trips.
#:
#: Group entries by defect rather than by family, because failures cluster far
#: more tightly by cause than by protocol.
EXPECTED_FAILURES = {
    # A cycle can close on wrong octets, since this suite checks only that it is
    # self-consistent. Such defects are pinned against their specifications
    # elsewhere:
    #
    # * the Multipath TCP option lengths, per option against RFC 8684, in
    #   :mod:`tests.protocols.transport.test_tcp_mptcp_length_arithmetic_unit`
    #   (#576);
    # * the three MP_JOIN layouts of RFC 8684 section 3.2, of which this suite
    #   reaches only the SYN form that ``examples.generators.options``'
    #   ``TCP_BASE`` selects, in
    #   :mod:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit`
    #   (#587);
    # * the IPv4 ``SID`` option width, against wire octets, in
    #   :meth:`IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire
    #   <tests.protocols.internet.test_ipv4_unit.IPv4UnitTests.test_ipv4_sid_option_is_four_octets_wide_on_the_wire>`
    #   (#534);
    # * HIP's parameter padding, against :rfc:`7401` Section 5.2.1, in
    #   :meth:`test_a_hip_packet_carrying_one_parameter_round_trips` (#651).
    #
    # The RPL source route header (#564) round-trips here. Its fixed area is
    # pinned against :rfc:`6554#section-3` by
    # :meth:`IPv6ExtensionUnitTests.test_ipv6_route_rpl_fixed_area_is_four_octets
    # <tests.protocols.internet.test_ipv6_extension_unit.IPv6ExtensionUnitTests.test_ipv6_route_rpl_fixed_area_is_four_octets>`,
    # which records that without the fix a constructed header is 41 octets
    # against the 48 its ``Hdr Ext Len`` of 5 declares. The caveat #489
    # records holds: none of it has been checked against a real RPL capture.
    #
    # The deadline in the sweep protects against a non-progress defect, under
    # which a cycle hangs rather than fails (#432, #441). ``SMF_DPD`` is the
    # case: a stray nested ``test`` ``ForwardMatchField`` in ``ipv6_opts``
    # over-reports the option's size by one octet. Measured on the same octets,
    # ``1100080100010100``, ``len(schema)`` is 3 in ``hopopt`` against 4 in
    # ``ipv6_opts``, so ``HOPOPT`` reads ``options=[SMF_DPD, PadN]`` where
    # ``IPv6_Opts`` raises ``ProtocolError: IPv6-Opts: invalid format`` --
    # identical on 3.10.20 and 3.14.7, so not interpreter-dependent.
    # :meth:`IPv6ExtensionUnitTests.test_ipv6_opts_identification_based_dpd_null_tid_option_area_matches
    # <tests.protocols.internet.test_ipv6_extension_unit.IPv6ExtensionUnitTests.test_ipv6_opts_identification_based_dpd_null_tid_option_area_matches>`
    # pins it.
}


def _gap_for(label: 'str') -> 'Optional[Gap]':
    """The recorded expectation for ``label``, or :data:`None` if it should pass.

    Args:
        label: Case label, e.g. ``'tcp-mptcp/MP_JOIN'``.

    Returns:
        The recorded :class:`Gap`, or :data:`None` when the case is expected to
        round-trip on this interpreter.

    """
    return EXPECTED_FAILURES.get(label)


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path.

    That directory is not a package, and its module names are too generic to put
    on :data:`sys.path` -- which is exactly why
    :file:`examples/generators/make_samples.py` loads its siblings by path too.
    This follows it.

    Returns:
        The generator module, which exposes ``cases``, ``roundtrip``, ``FAMILIES``
        and ``SKIP``.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location('pcapkit_samples_options', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option case table from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OptionRoundTripTests(unittest.TestCase):
    """One construct -> parse -> construct cycle per registered code."""

    #: The generator module, loaded once for the whole class. Loading it imports
    #: :mod:`pcapkit`, so it must happen after the purge in :meth:`setUpClass`
    #: -- hence a class attribute filled in there rather than a module-level
    #: import.
    options = None  # type: Any

    @classmethod
    def setUpClass(cls) -> None:
        purge_modules(['pcapkit'])
        cls.options = _load_generator()

    def _run(self, case: 'Any') -> 'Any':
        """One cycle, under this suite's deadline rather than the generator's.

        The generator applies its own :func:`signal.alarm` deadline, because
        ``make samples`` must not hang either. Letting both arm the alarm would
        break the outer one: the inner context cancels the pending alarm on the
        way out, which is the outer deadline's countdown. So the generator's is
        switched off here and :func:`tests._support.time_limit` owns the clock,
        which is what the rest of the suite uses.

        Args:
            case: The case to exercise.

        Returns:
            The cycle's outcome, with a timeout reported as ``'TIMEOUT'`` rather
            than raised, so that it is asserted on like any other failure.

        """
        try:
            with time_limit(CASE_TIMEOUT):
                return self.options.roundtrip(case, deadline=0)
        except TimeoutError as exc:
            return self.options.Outcome(case, 'TIMEOUT', str(exc), None, ())

    def test_every_registered_code_has_a_case(self) -> None:
        """No registry entry is left without a case.

        This is what makes the coverage self-maintaining. Registering a new
        option and forgetting to exercise it fails here, rather than going
        unnoticed until the option turns out not to construct.

        """
        for family in self.options.FAMILIES:
            with self.subTest(family=family.label):
                registry = family.registry()
                covered = {case.code for case in self.options.cases((family,))}
                skipped = {
                    code for code in registry
                    if (family.label, self.options.code_name(code)) in self.options.SKIP
                }
                self.assertEqual(
                    set(registry), covered | skipped,
                    f'{family.label}: every code in the registry needs a case in '
                    f'examples/generators/options.py, or an entry in its SKIP table'
                )

    def test_every_registered_code_resolves_without_growing_the_registry(self) -> None:
        """Each code resolves to a handler, and asking does not mutate the registry.

        Two things at once, because they are the same lookup.

        A registry entry naming a handler that does not exist is a live bug that
        nothing else catches: dispatch falls through to the fallback and the
        option is quietly parsed as unassigned. Two of the ``MH`` registries'
        own docstrings name prefixes that were never implemented
        (``_read_option_*`` and ``_read_extension_*``, where the code uses
        ``_read_opt_*`` and ``_read_ext_*``), so the hazard is not theoretical.

        And every one of these registries is a :class:`collections.defaultdict`
        on a class attribute, so a lookup that misses *inserts*, permanently, for
        the whole process. The sizes are compared either side to prove the
        non-recording path was used.

        """
        for family in self.options.FAMILIES:
            with self.subTest(family=family.label):
                registry = family.registry()
                before = len(registry)

                for code in list(registry):
                    resolved = self.options.handler(registry, code)
                    self.assertIsNotNone(
                        resolved,
                        f'{family.label}: {self.options.code_name(code)} resolves '
                        f'to nothing'
                    )

                self.assertEqual(
                    len(registry), before,
                    f'{family.label}: the registry grew while being read; a '
                    f'lookup went through registry[code] instead of '
                    f'ProtocolBase._lookup_registry'
                )

    def test_expected_failures_name_real_cases(self) -> None:
        """Both tables name only cases that exist.

        Without this they rot silently: a renamed or removed registry entry
        leaves behind an entry that can never be checked, and which then reads as
        documentation of a defect nobody can find.

        """
        labels = {case.label for case in self.options.cases()}
        stale = sorted(set(EXPECTED_FAILURES) - labels)
        self.assertEqual(
            stale, [],
            f'these entries of EXPECTED_FAILURES name cases that no longer '
            f'exist; delete them, or fix the label'
        )

    def test_round_trip_is_identity_or_a_recorded_gap(self) -> None:
        """Every case either closes the cycle, or fails exactly as recorded.

        Both halves matter. A case absent from :data:`EXPECTED_FAILURES` must
        come back ``'OK'``; a case present in it must still fail, and with the
        recorded status and detail, so that fixing the defect turns this red and
        the entry gets deleted rather than left behind.

        """
        cases = self.options.cases()
        self.assertGreater(len(cases), 200,
                           'the registries should yield a few hundred codes; a '
                           'much smaller number means the enumeration broke')

        for case in cases:
            with self.subTest(case=case.label):
                outcome = self._run(case)
                gap = _gap_for(case.label)

                if gap is None:
                    self.assertEqual(
                        outcome.status, 'OK',
                        f'{case.label} no longer round-trips: {outcome.detail}. '
                        f'If this is a newly found defect, add it to '
                        f'EXPECTED_FAILURES naming the function, class or method that '
                        f'causes it -- '
                        f'do not change the case to avoid it.'
                    )
                    continue

                self.assertEqual(
                    outcome.status, gap.status,
                    f'{case.label} was recorded as failing with '
                    f'{gap.status} ({gap.defect}) but came back '
                    f'{outcome.status}: {outcome.detail}. If the defect is fixed, '
                    f'delete its EXPECTED_FAILURES entry.'
                )
                fragments = ((gap.fragment,) if isinstance(gap.fragment, str)
                             else gap.fragment)
                for fragment in fragments:
                    if not fragment:
                        continue
                    self.assertIn(
                        fragment, outcome.detail,
                        f'{case.label} still fails with {gap.status}, but not in '
                        f'the recorded way ({gap.defect}); detail was '
                        f'{outcome.detail!r}'
                    )

    def test_a_hip_packet_carrying_one_parameter_round_trips(self) -> None:
        """A HIP packet carrying exactly one parameter is accepted by its own reader.

        ``HIP.make`` computes the header's ``len`` as ``total_length // 8 + 4``,
        which is lossless only when the parameter octets are a multiple of eight.
        A padding rule that aligns the *contents* to eight and ignores the
        four-octet type-and-length header makes one parameter always
        ``4 (mod 8)``; the floor division drops those four octets and
        ``_read_hip_param``, which compares the recovered length exactly,
        raises. :rfc:`7401` Section 5.2.1's
        ``Total Length = 11 + Length - (Length + 3) % 8`` (#651) makes a lone
        parameter 8-aligned by construction, so the case closes, and this test
        says so positively rather than recording a raise.

        One copy and two copies must *both* work, and must both come back as the
        octets they went out as. ``SEQ`` is the case that discriminates hardest,
        at ``Length = 4``: the record needs no padding at all
        (``11 + 4 - (4 + 3) % 8 == 8``), so a contents-aligning rule's four
        appended octets are pure surplus rather than a shortfall, and a reader
        that pads by any non-zero amount lands in the wrong place at the start of
        the second copy.

        ``HIP_COPIES`` is ``1`` (#689) -- see the constant's note in the
        generator -- so the ``copies=1`` subtest below overlaps the main sweep,
        which exercises ``hip-parameter/SEQ`` at exactly one copy itself; it is
        kept because it pins the exact wire layout (``len(built)``, the header's
        ``len`` byte, the reparsed count) rather than only the round-trip
        identity the sweep checks. The generator does not build the two-copy
        shape, so the ``copies=2`` subtest is the one place that asserts the
        pair round-trips.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        base = dict(self.options.HIP_BASE)
        one = [(Parameter.SEQ, {})]  # type: list[tuple[Any, dict[str, Any]]]

        for copies in (1, 2):
            with self.subTest(copies=copies):
                built = bytes(HIP(parameters=one * copies, extension=True, **base))

                # 40 octets of fixed header, then one 8-octet SEQ per copy --
                # the RFC total for Length = 4, and what the header's own
                # ``len`` field can represent exactly.
                self.assertEqual(len(built), 40 + 8 * copies)
                self.assertEqual(built[1], 4 + copies)

                reparsed = HIP(built, len(built), extension=True)
                self.assertEqual(
                    len(reparsed.info.parameters.getlist(Parameter.SEQ)), copies)

                again = bytes(HIP(parameters=reparsed.info.parameters,
                                  extension=True, **base))
                self.assertEqual(built, again)

    def test_recorded_gaps_are_a_minority(self) -> None:
        """Most of the option space round-trips, and the rest is accounted for.

        A guard on the shape of the result rather than on any one case: if a
        change makes the failures outnumber the successes, something systemic
        broke and the per-case assertions above will be too noisy to read.

        """
        total = len(self.options.cases())
        recorded = len(EXPECTED_FAILURES)
        self.assertLess(
            recorded, total // 2,
            f'{recorded} of {total} cases are recorded as failing; that is more '
            f'than half, which suggests the harness rather than the library is at '
            f'fault'
        )


if __name__ == '__main__':
    unittest.main()
