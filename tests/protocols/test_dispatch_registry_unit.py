# -*- coding: utf-8 -*-
"""Every ``__proto__`` dispatch-registry entry, enumerated rather than hand-picked.

GitHub issue #496: :file:`pcapkit/foundation/registry/protocols.py` documents
seven registries -- 38 entries in total -- that decide which
:class:`~pcapkit.protocols.protocol.Protocol` subclass parses the next layer.
Nothing walked all of them. :file:`test_registry_runtime.py` checks that a
table entry *resolves* to the right class object, and
:file:`test_dispatch_bindings_unit.py` checks that eleven hand-picked codes
actually parse a packet into the class the table names -- the property that
matters, since a resolvable entry whose target cannot parse a packet is
exactly what shipped once: :class:`~pcapkit.protocols.link.ospf.OSPF` was
reachable from no table at all, per that module's own docstring.

This module closes the gap the same way
:file:`test_option_roundtrip_unit.py` closed it for the option/parameter
registries: :func:`examples.generators.dispatch.cases` walks the seven
``__proto__`` tables directly, so a code registered tomorrow gets a case here
tomorrow -- or fails :meth:`DispatchRegistryTests
.test_every_registered_code_has_a_case`, which is what makes the coverage
self-maintaining rather than a snapshot of today's registries.

Every case builds its own octets in memory and reads no capture under
:file:`examples/captures/`, so this belongs to the unit tier.

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
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one case may take. A working case takes low single-digit
#: milliseconds; the point of the deadline is a case that never finishes.
CASE_TIMEOUT = 10


class Degrade(NamedTuple):
    """One code known to degrade to :class:`~pcapkit.protocols.misc.raw.Raw` today."""

    #: Substring the ``'error'`` value :func:`~examples.generators.dispatch.probe`
    #: found must contain, or ``''`` to assert only that dispatch is degraded.
    #: A tuple means *any* of its substrings is acceptable, for a case whose
    #: degradation reason legitimately varies by environment -- NGAP reports a
    #: malformed PDU where its optional dependency is installed, and reports
    #: the missing dependency where it is not. Both are the same
    #: placeholder-payload limitation rather than two different defects.
    fragment: 'str | tuple[str, ...]'
    #: The reason, so the entry is worth keeping rather than just silencing.
    defect: 'str'


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/dispatch.py` by path.

    Follows :file:`test_option_roundtrip_unit.py`'s
    :func:`~tests.protocols.test_option_roundtrip_unit._load_generator`: the
    directory is not a package and its module name is too generic to put on
    :data:`sys.path`.

    Returns:
        The generator module, which exposes ``cases``, ``probe``, ``FAMILIES``
        and ``KNOWN_DEGRADED``.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'dispatch.py'
    spec = importlib.util.spec_from_file_location('pcapkit_samples_dispatch', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the dispatch case table from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DispatchRegistryTests(unittest.TestCase):
    """One dispatch probe per entry across all seven ``__proto__`` registries."""

    #: The generator module, loaded once for the whole class. Loading it
    #: imports :mod:`pcapkit`, so it must happen after :meth:`setUp` has purged
    #: the previous test's copy -- hence a class attribute filled in
    #: :meth:`setUpClass` rather than a module-level import.
    dispatch = None  # type: Any

    @classmethod
    def setUpClass(cls) -> None:
        purge_modules(['pcapkit'])
        cls.dispatch = _load_generator()

    #: Every case whose dispatch does not reach its registered target today,
    #: and the recorded reason -- kept in the test rather than only in the
    #: generator so that a change to either is a change a reviewer sees next
    #: to the assertion it affects.
    KNOWN_DEGRADED = {
        label: Degrade(*value)
        for label, value in {
            'link/Novell_Inc_0x8137': ('0 is not a valid Socket',
                                       'pcapkit/protocols/internet/ipx.py -- Socket(0) is not '
                                       'a valid member; IPX cannot be constructed or parsed '
                                       'at all (#492)'),
            'internet/IPX_in_IP': ('0 is not a valid Socket',
                                   'same defect as link/Novell_Inc_0x8137 -- both dispatch to '
                                   'pcapkit.protocols.internet.ipx.IPX (#492)'),
            'sctp/PayloadProtocolIdentifier_3GPP_NG_Application_Protocol': (
                ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
                'placeholder payload is not an aligned PER NGAP-PDU; building '
                'one is out of scope for a minimal dispatch probe, not a '
                'library defect'),
            'sctp/PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP': (
                ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
                'pcapkit implements no DTLS, and the same placeholder payload '
                'is not a DTLS record either'),
        }.items()
    }

    def _run(self, case: 'Any') -> 'Any':
        """One probe, under this suite's deadline rather than an ambient one.

        Args:
            case: The case to exercise.

        Returns:
            The probe's outcome, with a timeout reported as such rather than
            raised, so it is asserted on like any other failure.

        """
        try:
            with time_limit(CASE_TIMEOUT):
                return self.dispatch.probe(case)
        except TimeoutError as exc:
            return self.dispatch.Outcome(case, '', False, str(exc), '')

    def test_every_registered_code_has_a_case(self) -> None:
        """No registry entry is left without a case.

        This is what makes the coverage self-maintaining: registering a new
        protocol against one of the seven tables and forgetting to add a case
        for it fails here, rather than going unnoticed until the entry turns
        out not to be able to parse a packet.

        """
        for family in self.dispatch.FAMILIES:
            with self.subTest(family=family.label):
                registry = family.registry()
                covered = {case.code for case in self.dispatch.cases((family,))}
                self.assertEqual(
                    set(registry), covered,
                    f'{family.label}: every code in the registry needs a case in '
                    f'examples/generators/dispatch.py'
                )

    def test_every_case_has_a_pinned_target(self) -> None:
        """No case relies on the registry to say what it should reach.

        :data:`~examples.generators.dispatch.PINNED_TARGETS` records the
        expected class by hand, independently of whatever the corresponding
        ``__proto__`` table currently holds -- see that table's own docstring
        for why: checking dispatch against a value read out of the very table
        under test cannot tell a correct entry from a mis-pointed one. A case
        with no pinned entry has :attr:`Case.target` set to :data:`None`,
        which is the "registered but unpinned" signal this asserts against --
        the same property :meth:`test_every_registered_code_has_a_case` gives
        for a *missing* case, but for a code that has a case yet nothing
        independent to check it against.

        """
        unpinned = sorted(case.label for case in self.dispatch.cases()
                          if case.target is None)
        self.assertEqual(
            unpinned, [],
            f'these cases have no entry in PINNED_TARGETS, so dispatch to '
            f'them cannot be checked against anything independent of the '
            f'registry: {unpinned}'
        )

    def test_registry_currently_matches_pinned_target(self) -> None:
        """The live registry still names the class :data:`PINNED_TARGETS` expects.

        This is the check that actually catches a mis-pointed entry --
        registry size unchanged, code still present, class wrong. Measured:
        pointing ``Internet.__proto__[TransType.AH]`` at
        :class:`~pcapkit.protocols.misc.raw.Raw` instead of
        :class:`~pcapkit.protocols.internet.ah.AH` changed nothing
        :meth:`test_cases_cover_every_table_named_in_the_issue` or the old,
        registry-derived version of :meth:`test_dispatch_reaches_target_or_is_a_recorded_degrade`
        looked at, and both kept passing. This does not: it compares
        :attr:`Case.registered` -- what the table says right now -- against
        :attr:`Case.target` -- what it is pinned to say -- and is independent
        of whether the target dissector can actually parse anything, which is
        :meth:`test_dispatch_reaches_target_or_is_a_recorded_degrade`'s job.

        """
        for case in self.dispatch.cases():
            with self.subTest(case=case.label):
                self.assertIs(
                    case.registered, case.target,
                    f'{case.label}: the registry currently resolves to '
                    f'{case.registered!r}, but PINNED_TARGETS expects '
                    f'{case.target!r}. Either the registry regressed, or '
                    f'PINNED_TARGETS is stale and needs updating to match a '
                    f'deliberate change.'
                )

    def test_cases_cover_every_table_named_in_the_issue(self) -> None:
        """The enumeration finds all 38 entries the issue counted, across all seven tables.

        A guard on the shape of the result rather than on any one case: if the
        registries grow or shrink without this module noticing, the per-family
        counts below catch it even if every individual case still passes.

        """
        cases = self.dispatch.cases()
        self.assertEqual(len(cases), 38,
                         'expected exactly 38 entries across the seven __proto__ '
                         'tables named in GitHub issue #496; a different count '
                         'means a registry changed shape and this module was not '
                         'updated to match')

        by_family = {}  # type: dict[str, int]
        for case in cases:
            by_family[case.family] = by_family.get(case.family, 0) + 1
        self.assertEqual(by_family, {
            'link': 7, 'internet': 16, 'tcp': 4, 'udp': 3, 'sctp': 2,
            'pcap-frame': 3, 'pcapng-frame': 3,
        })

    def test_dispatch_reaches_target_or_is_a_recorded_degrade(self) -> None:
        """Every code either dispatches to its registered class, or degrades exactly as recorded.

        Both halves matter, the same as
        :meth:`~tests.protocols.test_option_roundtrip_unit.OptionRoundTripTests
        .test_round_trip_is_identity_or_a_recorded_gap`: a case absent from
        :attr:`KNOWN_DEGRADED` must reach its target, and a case present in it
        must still fail to, and with the recorded ``'error'`` fragment -- so
        that fixing the underlying defect turns this red, which is the
        reminder to delete the entry.

        """
        cases = self.dispatch.cases()
        for case in cases:
            with self.subTest(case=case.label):
                outcome = self._run(case)
                gap = self.KNOWN_DEGRADED.get(case.label)

                if gap is None:
                    self.assertEqual(
                        outcome.reached, True,
                        f'{case.label} no longer dispatches to {case.target!r}: '
                        f'chain was {outcome.chain!r} ({outcome.detail}). If this '
                        f'is a newly found defect, add it to KNOWN_DEGRADED with '
                        f'the file:line that causes it -- do not change the case '
                        f'to avoid it.'
                    )
                    continue

                self.assertEqual(
                    outcome.reached, False,
                    f'{case.label} was recorded as degrading ({gap.defect}) but '
                    f'now reaches its target ({outcome.chain!r}). If the defect '
                    f'is fixed, delete its KNOWN_DEGRADED entry.'
                )
                if gap.fragment:
                    accepted = ((gap.fragment,) if isinstance(gap.fragment, str)
                                else gap.fragment)
                    self.assertTrue(
                        any(fragment in outcome.error for fragment in accepted),
                        f'{case.label} still degrades, but not in the recorded '
                        f'way ({gap.defect}); error was {outcome.error!r} and '
                        f'none of the accepted reasons {accepted!r} appear in '
                        f'it. If this is a new way for the case to degrade, add '
                        f'it to the entry rather than widening it to match '
                        f'anything.'
                    )

    def test_known_degraded_names_real_cases(self) -> None:
        """:attr:`KNOWN_DEGRADED` names only cases that still exist.

        Without this it rots silently: a renamed or removed registry entry
        leaves behind an entry nothing can ever check, which then reads as
        documentation of a defect nobody can find.

        """
        labels = {case.label for case in self.dispatch.cases()}
        stale = sorted(set(self.KNOWN_DEGRADED) - labels)
        self.assertEqual(
            stale, [],
            f'these entries of KNOWN_DEGRADED name cases that no longer exist; '
            f'delete them, or fix the label'
        )

    def test_degraded_cases_are_a_small_minority(self) -> None:
        """Most of the dispatch space reaches its target, and the rest is accounted for.

        A guard on the shape of the result: if a change makes degraded cases
        outnumber working ones, something systemic broke and the per-case
        assertions above will be too noisy to read.

        """
        total = len(self.dispatch.cases())
        recorded = len(self.KNOWN_DEGRADED)
        self.assertLess(
            recorded, total // 4,
            f'{recorded} of {total} cases are recorded as degraded; that is a '
            f'larger fraction than expected, which suggests the harness rather '
            f'than the library is at fault'
        )


if __name__ == '__main__':
    unittest.main()
