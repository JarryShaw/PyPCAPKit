# -*- coding: utf-8 -*-
"""Every ``__proto__`` dispatch-registry entry, enumerated rather than hand-picked.

GitHub issue #496: the ``__proto__`` dispatch registries decide which
:class:`~pcapkit.protocols.protocol.Protocol` subclass parses the next layer.
#496 names the tables, joined by #904's
``Internet.__proto__[TransType.Shim6]``, #1574's loopback table and #2560's
FRAD table.
:file:`test_registry_runtime.py` checks that a table entry *resolves* to the
right class object, and
:file:`test_dispatch_bindings_unit.py` checks that a hand-picked set of codes
actually parse a packet into the class the table names -- the property that
matters, since an entry can resolve to a target that cannot parse a packet.

This module covers every table the same way
:file:`test_option_roundtrip_unit.py` covers the option/parameter
registries: :func:`examples.generators.dispatch.cases` walks every
``__proto__`` table directly, so a code registered tomorrow gets a case here
tomorrow -- or fails :meth:`DispatchRegistryTests
.test_every_registered_code_has_a_case`, which is what makes the coverage
self-maintaining rather than a snapshot of today's registries.

Every case builds its own octets in memory and reads no capture under
:file:`examples/captures/`, so this belongs to the unit tier.

"""
from __future__ import annotations

import collections
import importlib
import importlib.util
import pkgutil
import sys
import types
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import purge_modules, time_limit
from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): a sweep over every ``__proto__`` registry entry.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one case may take. A working case takes low single-digit
#: milliseconds; the point of the deadline is a case that never finishes.
CASE_TIMEOUT = 30

#: The non-empty ``__proto__`` tables no family probes, by ``module.Class``
#: path, and why. Every other one is some family's registry (#2615).
UNCOVERED = {
    'pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__':
        'its ARPHRD entries are pinned as shipped and probed one by one by '
        'tests/protocols/link/test_linux_sll_arphrd_registry_unit.py (#2510)',
}


def _proto_tables() -> 'dict[str, dict[Any, Any]]':
    """Every non-empty ``__proto__`` table a protocol class defines itself, by path.

    Found by walking every :class:`~pcapkit.protocols.protocol.ProtocolBase`
    descendant once every shipped protocol module is imported, as
    :mod:`tests.foundation.registry.test_registry_wrapper_coverage_2511_unit`
    finds its maps.

    """
    import pcapkit.protocols as package
    from pcapkit.protocols.protocol import ProtocolBase

    for info in pkgutil.walk_packages(package.__path__, 'pcapkit.protocols.'):
        if 'NotImplemented' not in info.name:
            importlib.import_module(info.name)
    found = {}  # type: dict[str, dict[Any, Any]]
    seen = set()  # type: set[type]
    pending = [ProtocolBase]  # type: list[type]
    while pending:
        klass = pending.pop()
        if klass in seen:
            continue
        seen.add(klass)
        pending.extend(klass.__subclasses__())
        table = vars(klass).get('__proto__')
        if isinstance(table, dict) and table:
            found[f'{klass.__module__}.{klass.__qualname__}.__proto__'] = table
    return found


class Degrade(NamedTuple):
    """One code known to degrade to :class:`~pcapkit.protocols.misc.raw.Raw`."""

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
    """One dispatch probe per entry across every ``__proto__`` registry."""

    #: The generator module, loaded once for the whole class. Loading it
    #: imports :mod:`pcapkit`, so it must happen after the purge in
    #: :meth:`setUpClass` -- hence a class attribute filled in there rather
    #: than a module-level import.
    dispatch = None  # type: Any

    @classmethod
    def setUpClass(cls) -> None:
        purge_modules(['pcapkit'])
        cls.dispatch = _load_generator()

    #: Every case whose dispatch does not reach its registered target,
    #: and the recorded reason -- kept in the test rather than only in the
    #: generator so that a change to either is a change a reviewer sees next
    #: to the assertion it affects.
    #: :meth:`test_known_degraded_matches_the_generator` holds the two copies
    #: to each other.
    KNOWN_DEGRADED = {
        label: Degrade(*value)
        for label, value in {
            'sctp/PayloadProtocolIdentifier_3GPP_NG_Application_Protocol': (
                ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
                'placeholder payload is not an aligned PER NGAP-PDU; building '
                'one is out of scope for a minimal dispatch probe, not a '
                'library defect'),
            'sctp/PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP': (
                ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
                'PPID 66 is not routed through DTLS, and the same placeholder '
                'payload is not a DTLS record either'),
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
        protocol against one of the tables and forgetting to add a case
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
                    f'its module under examples/generators/dispatch_families/'
                )

    def test_every_case_has_a_pinned_target(self) -> None:
        """No case relies on the registry to say what it should reach.

        :data:`~examples.generators.dispatch.PINNED_TARGETS` records the
        expected class by hand, independently of whatever the corresponding
        ``__proto__`` table holds -- see that table's own docstring
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

    def test_registry_matches_pinned_target(self) -> None:
        """The live registry still names the class :data:`PINNED_TARGETS` expects.

        This is the check that actually catches a mis-pointed entry --
        registry size unchanged, code still present, class wrong. Measured:
        pointing ``Internet.__proto__[TransType.AH]`` at
        :class:`~pcapkit.protocols.misc.raw.Raw` instead of
        :class:`~pcapkit.protocols.internet.ah.AH` changes nothing
        :meth:`test_cases_match_the_pinned_targets` looks at, nor
        anything a registry-derived dispatch check would, and both pass. This
        test does not: it compares
        :attr:`Case.registered` -- what the table says at run time -- against
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

    def test_cases_match_the_pinned_targets(self) -> None:
        """The enumeration finds exactly the entries :data:`PINNED_TARGETS` records.

        A guard on the shape of the result rather than on any one case: a
        table that loses an entry, or a family whose table goes missing, leaves
        a pinned target that no case reaches, and a table that gains one leaves
        a case that nothing pins -- even if every individual case still
        passes. Each family module records its own table's entries beside the
        family (#2615), so the expected shape is derived from those records
        rather than pinned here as counts, and a failure names the entry.

        """
        labels = [case.label for case in self.dispatch.cases()]
        pinned = set(self.dispatch.PINNED_TARGETS)
        found = collections.Counter(labels)
        self.assertEqual(
            {'found twice': sorted(label for label, count in found.items() if count > 1),
             'not pinned': sorted(set(found) - pinned),
             'pinned but not found': sorted(pinned - set(found))},
            {'found twice': [], 'not pinned': [], 'pinned but not found': []},
            'the __proto__ tables and the PINNED_TARGETS of their modules under '
            'examples/generators/dispatch_families/ disagree; a registry changed '
            'shape and its family module was not updated to match')

        families = {family.label for family in self.dispatch.FAMILIES}
        self.assertEqual(sorted(families - {case.family for case in self.dispatch.cases()}), [],
                         'a family whose table holds no entry probes nothing')

    def test_each_family_module_pins_its_own_families(self) -> None:
        """A family module pins its own families' entries, under labels no other module uses.

        Merging the modules' tables would otherwise let one module's entry
        replace another's without a word, and a family's entries filed in the
        wrong module would put two changes to one family in two files.

        """
        labels = [family.label for family in self.dispatch.FAMILIES]
        self.assertEqual(sorted(labels), sorted(set(labels)), 'a family label is used twice')
        for stem, module in self.dispatch.FAMILY_MODULES.items():
            own = {family.label for family in module.FAMILIES}
            with self.subTest(module=stem):
                self.assertTrue(own, f'{stem} adds no family')
                strays = sorted(label for label in module.PINNED_TARGETS
                                if label.split('/', 1)[0] not in own)
                self.assertEqual(strays, [], f'{stem} pins entries of another module\'s family')

    def test_every_dispatch_table_has_a_family(self) -> None:
        """Every non-empty ``__proto__`` table is a family's registry, or in :data:`UNCOVERED`.

        Derived from the tree's own tables rather than from the family modules,
        so a family module that goes missing, its pinned targets with it, still
        fails here, as does a table no family probes. Checked both ways, so an
        :data:`UNCOVERED` entry whose table gains a family, or empties, is stale.

        """
        covered = {id(family.registry()) for family in self.dispatch.FAMILIES}
        uncovered = sorted(path for path, table in _proto_tables().items()
                           if id(table) not in covered)
        self.assertEqual(uncovered, sorted(UNCOVERED),
                         'a non-empty __proto__ table needs a family module under '
                         'examples/generators/dispatch_families/, or an UNCOVERED '
                         'entry saying what covers it instead')

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
                        f'is a newly found defect, add it to KNOWN_DEGRADED naming '
                        f'the function, class or method that causes it -- do not '
                        f'change the case to avoid it.'
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

    def test_known_degraded_matches_the_generator(self) -> None:
        """:attr:`KNOWN_DEGRADED` and the generator's copy record the same entries (#2229).

        The copy here is deliberate, per :attr:`KNOWN_DEGRADED`'s own note,
        but :data:`examples.generators.dispatch.KNOWN_DEGRADED` is what the
        generator's ``__main__`` summary counts, so the two must not drift: a
        label, fragment or reason changed in one is changed in both.

        """
        generator = {label: Degrade(*value)
                     for label, value in self.dispatch.KNOWN_DEGRADED.items()}
        self.assertEqual(
            sorted(self.KNOWN_DEGRADED), sorted(generator),
            'KNOWN_DEGRADED here and in examples/generators/dispatch.py name '
            'different cases; update both together'
        )
        for label, gap in self.KNOWN_DEGRADED.items():
            with self.subTest(case=label):
                self.assertEqual(
                    gap, generator[label],
                    f'{label}: the fragment or reason recorded here differs '
                    f'from examples/generators/dispatch.py; update both together'
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
