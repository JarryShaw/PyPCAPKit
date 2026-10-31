# -*- coding: utf-8 -*-
"""Registry-wide regression tests for ``get()``'s ``default`` parameter.

GitHub issue #584: the ``default`` parameter that every generated ``get()``
documents was never consulted on the integer path, because ``get`` delegated the
lookup straight to the enum call and ``_missing_`` has no access to the caller's
``default``::

    >>> Hardware.get(99999, 0)
    ValueError: 99999 is not a valid Hardware

Only the ``str`` path passed ``default`` through to :func:`~aenum.extend_enum`.
The integer path -- the one every numeric lookup takes -- could not.

The sweep below is the one #584 asked for before fixing ("the real scope is
likely wider since most ``const/`` modules are generated from the same
skeleton"), and it bore that out: across the :class:`~aenum.IntEnum` and
:class:`~aenum.IntFlag` registries defined under :mod:`pcapkit.const`, the
defect was live in nearly all of them -- not just the ones the issue named. The
rest either never raise on an out-of-range integer, because they auto-extend
the whole space, or carry no ``get(key, default)`` at all.

GitHub issue #647 moved one of the auto-extending registries into the sweep.
:class:`~pcapkit.const.tcp.flags.Flags` resolved every integer only because it
defined no ``_missing_`` to bound its domain; it defines one, so its ``get``
has a failure for ``default`` to fall back from like the others.

GitHub issue #860 step 2 then brought :class:`~pcapkit.const.ftp.return_code.
GroupingInformation` and :class:`~pcapkit.const.ftp.return_code.ResponseKind`
onto :class:`~pcapkit.corekit.enum.EnumRegistry`, giving each the base
``get(key, default)`` it never had before -- moving both out of the set with
no integer ``default`` at all and into the main sweep. The full composition,
spelled out rather than left to imply a total that silently dropped
:class:`~pcapkit.const.pcapng.filter_type.FilterType` (in
:data:`EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK`, excused from the main sweep
for a separate reason and covered by its own test below): the main sweep,
plus :data:`EXPECTED_TO_RESOLVE_ANYTHING`, plus
:data:`EXPECTED_WITHOUT_AN_INTEGER_DEFAULT`, plus ``FilterType`` -- together,
the population :meth:`test_the_sweep_size_is_pinned` counts.

:class:`~pcapkit.const.pcapng.option_type.OptionType` and
:class:`~pcapkit.const.reg.apptype.AppType` are outside this sweep because
they are :class:`~aenum.StrEnum` rather than integer enums, and were
deliberately left alone: each carries a bespoke integer fallback that already
resolves every value, so neither drops a default by raising. The string-keyed
registries :class:`~pcapkit.const.ftp.command.Command` and
:class:`~pcapkit.const.http.method.Method` have no integer path at all; they are
the subject of #582 and #583 instead.

``-1`` is the placeholder the generated signature carries, and it is what
separates "no default was supplied" from "a default was supplied and should be
used". Both halves are pinned here, because a fix that made an unresolvable key
fall back *silently* when the caller asked for no fallback would be a worse
defect than the one it replaced.

These modules are generated from :mod:`pcapkit.vendor`, so
``test_the_vendor_template_leaves_get_to_the_base`` renders the shared template and
compares it against a generated module. Without it a regeneration would quietly
undo the fix and the rest of this suite would still pass, because the *tree* is
what is committed and the *template* is what rebuilds it.

"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import pkgutil
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag

from tests._support import ISOLATED_PREFIXES, purge_modules, restore_modules, snapshot_modules

#: Test tier (#1958): exercises metaclass, ABC or enum machinery, which differs by
#: interpreter.
__tier__ = 'ALL'

#: An integer no wire field in the library is wide enough to carry, so every
#: registry that bounds its own domain rejects it. Deliberately far outside the
#: ``0..0xFF`` range the Mobility Header flag registries check, because a value
#: *inside* that range is resolved by their ``_missing_`` (through
#: ``super()._missing_``) rather than rejected, so it would exercise flag
#: composition rather than the ``default`` fallback this module is about.
UNRESOLVABLE = 1 << 70

#: Enums whose integer path resolves *anything* rather than raising, so there is
#: no fallback for ``default`` to supply.
#:
#: :class:`~pcapkit.const.tcp.flags.Flags` is not in this set: it bounds its
#: own domain like the rest of the tree (GitHub issue #647), and so belongs in
#: the sweep below. Without that guard it resolves anything for a different
#: reason -- it defines no ``_missing_`` at all, so ``aenum`` composes a
#: pseudo-member for any integer, and ``Flags(-1)`` reads back as every TCP
#: header flag set at once.
#:
#: Both resolve their unassigned span across the full integer range.
#: :class:`~pcapkit.const.ipv4.protection_authority.ProtectionAuthority`'s
#: bare ``Unassigned`` label resolves via
#: :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`, per the
#: #775/#847 mint-criterion ruling -- it resolves anything (the property that
#: excuses it from the sweep below), it just does not extend.
#: :class:`~pcapkit.const.mh.cga_type.CGAType` auto-*extends* via
#: :func:`~aenum.extend_enum`: its ``Tag_<hex>`` mint is not an IANA-style
#: range at all, so the ruling does not apply.
EXPECTED_TO_RESOLVE_ANYTHING = frozenset({
    'pcapkit.const.ipv4.protection_authority.ProtectionAuthority',
    'pcapkit.const.mh.cga_type.CGAType',
})

#: Enums carrying no ``get(key, default)``, so there is no ``default`` to drop.
#: Empty: every enumeration the sweep walks takes the base ``get(key,
#: default)`` through :class:`~pcapkit.corekit.enum.EnumLookup`, including
#: :class:`~pcapkit.const.ftp.command.CommandType` and
#: :class:`~pcapkit.const.ftp.command.ConformanceRequirement` (GitHub issue
#: #930), :class:`~pcapkit.const.reg.apptype.TransportProtocol` (GitHub issue
#: #877), and :class:`~pcapkit.const.ftp.return_code.GroupingInformation` and
#: :class:`~pcapkit.const.ftp.return_code.ResponseKind`, which are on
#: :class:`~pcapkit.corekit.enum.EnumRegistry` (GitHub issue #860 step 2).
EXPECTED_WITHOUT_AN_INTEGER_DEFAULT = frozenset()  # type: frozenset[str]

#: :class:`~pcapkit.const.pcapng.filter_type.FilterType` declares *no* static
#: members at all -- every one of its 256 codes reaches ``_missing_``.
#: Importing :mod:`pcapkit.protocols.misc.pcapng` evaluates
#: ``Enum_FilterType(0)`` as a default argument at class-definition time, but
#: FilterType's bare ``Unassigned`` label resolves to an unregistered member
#: (the #775/#847 ruling), so that import mints nothing -- a minting label
#: would permanently mint ``'Unassigned_0'`` as a side effect of merely
#: importing the library, leaving exactly one member for this sweep's
#: ``next(iter(obj))`` fallback to find. The registry is genuinely empty:
#: :func:`next` on it raises :exc:`StopIteration`, with no value at all that
#: ``obj(fallback)`` would resolve to a *cached* identity for. Excused from the
#: main sweep for that reason and covered by its own test instead,
#: :meth:`ConstEnumGetDefaultTests.
#: test_filter_type_default_never_resolves_but_key_path_still_uses_an_uncached_member`.
EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK = frozenset({
    'pcapkit.const.pcapng.filter_type.FilterType',
})


def _iter_const_enums() -> 'list[type]':
    """Every :class:`~aenum.IntEnum` and :class:`~aenum.IntFlag` under :mod:`pcapkit.const`.

    Wider than the sweep in :mod:`tests.const.test_const_enum_lookup`, which
    excludes :class:`~aenum.IntFlag` because ``Enum(0)`` is a different contract
    for a flag registry. ``get()``'s integer path is not: the flag registries
    carry the same generated ``get`` and dropped ``default`` the same way, so
    they belong in this sweep.

    Collects only classes *defined* in the module being walked, so a
    re-exported registry is counted once.

    Returns:
        The discovered enum classes, in walk order.

    """
    import pcapkit.const as const_pkg

    classes = []  # type: list[type]
    for module_info in pkgutil.walk_packages(const_pkg.__path__, const_pkg.__name__ + '.'):
        module = importlib.import_module(module_info.name)
        for _, obj in vars(module).items():
            if (inspect.isclass(obj) and issubclass(obj, (IntEnum, IntFlag))
                    and obj.__module__ == module_info.name):
                classes.append(obj)
    return classes


def _qualname(obj: 'type') -> 'str':
    """The fully qualified name used as a sweep key."""
    return f'{obj.__module__}.{obj.__qualname__}'


class ConstEnumGetDefaultTests(unittest.TestCase):
    """``get(key, default)`` must consult ``default`` on the integer path."""

    if TYPE_CHECKING:
        enums: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.enums = _iter_const_enums()
        # ``test_the_always_resolving_registries_have_nothing_to_fall_back_to``
        # probes registries whose ``_missing_`` extends for *any* integer, which
        # permanently registers a junk member on a module-global class. Restore
        # the region to what it held before this class purged it, so those
        # polluted class objects are unreachable rather than merely dropped from
        # :data:`sys.modules` -- purging again here (GitHub issue #720) does
        # not achieve that: it only forces whoever imports
        # ``pcapkit`` next to rebuild it from source, and until they do, the
        # region sits empty for them exactly as it does for this class's own
        # first test, which is the leak #720 reports. Restoring is exact and
        # immediate, and does not depend on the next test's own ``setUp`` to
        # purge -- that protection is incidental, and this class should not
        # depend on it. Class-level rather than per-test, so ``cls.enums`` stays
        # valid for every test in this class.
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_the_reported_case_returns_the_default(self) -> None:
        """#584's own repro, on the enum it was reported against."""
        from pcapkit.const.arp.hardware import Hardware

        # Without the fix this raises ValueError('99999 is not a valid
        # Hardware'), dropping the caller's default entirely. Both ``0``
        # (``Reserved_0``) and ``1`` (``Ethernet``) are genuinely registered
        # members, so under #864's restriction too a registered default
        # resolves, exactly as #584 asked for.
        self.assertIs(Hardware.get(99999, 0), Hardware(0))
        self.assertIs(Hardware.get(99999, 1), Hardware.Ethernet)

        # An *unresolvable* default is a different matter: #584 passed a
        # ``str`` where the signature says ``int``, and ``'X'`` is not a
        # registered value either way. GitHub issue #864's ruling (only
        # ``register`` can mint, and ``get`` may mint only where the lookup
        # falls through to the ranges ``_missing_`` mints) consults ``default``
        # through a plain ``_value2member_map_`` lookup rather than
        # ``cls(default)``, so an unresolvable default gets no attempt of its
        # own to fail from (which would name ``'X'``) -- it falls through to
        # the *original* key lookup's own error instead, same as if no default
        # had been supplied at all.
        with self.assertRaises(ValueError) as caught:
            Hardware.get(99999, 'X')
        self.assertIn('99999', str(caught.exception))
        self.assertNotIn('X', str(caught.exception))

        # A resolvable key is untouched.
        self.assertIs(Hardware.get(1), Hardware.Ethernet)
        # 40 falls in Hardware's unassigned 39-255 range, which mints no
        # permanent member (#775 tier 1), so each lookup returns its own
        # unregistered pseudo-member -- equal, but not the same object, which
        # is why this is assertEqual rather than assertIs.
        self.assertEqual(Hardware.get(40), Hardware(40))
        self.assertIs(Hardware.get('Ethernet'), Hardware.Ethernet)

    def test_omitting_the_default_still_raises_for_the_original_key(self) -> None:
        """GitHub issue #857: guards against ``-1`` being compared with ``==``
        against :data:`~pcapkit.corekit.sentinels.NO_DEFAULT`, which silently
        reads a caller-supplied ``-1`` as *no default was supplied*.
        :data:`~pcapkit.corekit.sentinels.NO_DEFAULT` is an exported instance
        of the dedicated :class:`~pcapkit.corekit.sentinels.NoDefaultType`,
        compared with ``is`` rather than ``==`` -- so a caller-supplied
        ``-1`` is never confused with the sentinel. That fact is pinned
        directly, independent of ``get()``, by
        :class:`~tests.const.test_const_registry_protocol.NoDefaultSentinelTests
        .test_no_default_is_not_equal_to_any_plausible_caller_value`.

        Through ``get()`` itself the distinction is not observable for an
        *unregistered* default: GitHub issue #864's ruling (only ``register``
        can mint, and ``get`` may mint only where the lookup falls through to
        the ranges ``_missing_`` mints) keeps ``default`` from reaching
        ``cls(default)`` at all, and ``-1`` is not a registered value on either
        registry here (both domains start at ``0``), so supplying it converges
        on exactly the *same* original-key error as omitting it outright --
        pinned below for both.

        The genuinely-consulted half of #857's claim is pinned with a
        *registered* default instead (``0``, ``Reserved_0`` on both
        registries), which resolves rather than raising.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.arp.operation import Operation

        for enum in (Hardware, Operation):
            with self.subTest(enum=_qualname(enum)):
                with self.assertRaises(ValueError) as omitted:
                    enum.get(99999)
                self.assertIn('99999', str(omitted.exception))

                # An unregistered default (neither registry here has a member
                # at ``-1``) converges on the *same* original-key error as
                # omission (#864), rather than a distinct one naming ``-1``.
                with self.assertRaises(ValueError) as supplied:
                    enum.get(99999, -1)
                self.assertIn('99999', str(supplied.exception))
                self.assertNotIn('-1', str(supplied.exception))

                # A *registered* default, by contrast, is genuinely consulted
                # rather than raising at all.
                self.assertIs(enum.get(99999, 0), enum(0))

    def test_operation_and_linktype_get_honour_a_default(self) -> None:
        """#584 named ``Operation`` and ``LinkType`` but verified only ``Hardware``."""
        from pcapkit.const.arp.operation import Operation
        from pcapkit.const.reg.linktype import LinkType

        self.assertIs(Operation.get(99999, 1), Operation.REQUEST)
        self.assertIs(LinkType.get(-5, 1), LinkType.ETHERNET)

    def test_the_sweep_size_is_pinned(self) -> None:
        # If this drifts, a const enum was added, removed or renamed, and the
        # exception sets below need a fresh look rather than a silent pass.
        # GitHub issue #880's ngap.ProcedureCode and ngap.ProtocolIE are on
        # EnumRegistry rather than hand-rolled IntEnum classes in
        # pcapkit.protocols.application.ngap; neither needs an exception-set
        # entry, since both take the base's own get(key, default).
        names = {_qualname(obj) for obj in self.enums}
        self.assertEqual(len(self.enums), 132)
        for expected in (EXPECTED_TO_RESOLVE_ANYTHING, EXPECTED_WITHOUT_AN_INTEGER_DEFAULT,
                          EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK):
            self.assertTrue(expected.issubset(names),
                            f'sweep is missing: {expected - names}')

    def test_every_integer_path_consults_the_default(self) -> None:
        """The registry-wide form of #584, across every integer registry."""
        covered = 0
        for obj in self.enums:
            qualname = _qualname(obj)
            if qualname in EXPECTED_WITHOUT_AN_INTEGER_DEFAULT:
                # Assert the reason they are excused, so the set cannot quietly
                # start covering a registry that does take a ``default``.
                get = getattr(obj, 'get', None)
                self.assertTrue(
                    get is None or 'default' not in inspect.signature(get).parameters,
                    f'{qualname} does take a `default` and belongs in the sweep')
                continue
            if qualname in EXPECTED_TO_RESOLVE_ANYTHING:
                # Covered by its own test below. Probing them here would extend
                # a module-global registry as a side effect of a sweep whose
                # subject is something else, and for these two the ``try``
                # never raises, so it would assert nothing about the fix.
                continue
            if qualname in EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK:
                # Covered by its own test below: it raises for UNRESOLVABLE
                # like the rest of this sweep, but has no real member to use
                # as ``fallback`` -- see the set's own comment.
                continue
            with self.subTest(enum=qualname):
                with self.assertRaises(ValueError):
                    obj.get(UNRESOLVABLE)
                fallback = next(iter(obj)).value
                self.assertIs(obj.get(UNRESOLVABLE, fallback), obj(fallback))
                covered += 1
        # The sweep size ``test_the_sweep_size_is_pinned`` pins, less every
        # registry excused above: ``EXPECTED_TO_RESOLVE_ANYTHING`` and
        # ``EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK``, with
        # ``EXPECTED_WITHOUT_AN_INTEGER_DEFAULT`` empty.
        self.assertEqual(covered, 129)

    def test_the_always_resolving_registries_have_nothing_to_fall_back_to(self) -> None:
        """The two registries excused from the sweep, and why.

        Their ``_missing_`` resolves for *any* integer, so the integer path
        never raises and ``default`` has nothing to supply. Asserted rather
        than merely listed, so ``EXPECTED_TO_RESOLVE_ANYTHING`` cannot quietly
        grow to hide a registry that does raise.

        Probing :class:`~pcapkit.const.mh.cga_type.CGAType` *mutates* the
        registry: the call permanently registers a member on a module-global
        class, because the #775/#847 ruling does not cover its mint. That is
        done deliberately here, and ``setUpClass`` registers a class cleanup
        that purges :mod:`pcapkit` afterwards so the pollution cannot reach
        another module.
        :class:`~pcapkit.const.ipv4.protection_authority.ProtectionAuthority`
        mutates nothing -- its bare ``Unassigned`` resolves through a throwaway
        pseudo-member -- which is why the identity check below only applies to
        ``CGAType``.

        Measured: ``CGAType`` grows 7 members to 8; ``ProtectionAuthority``
        stays at 8.
        """
        for qualname in sorted(EXPECTED_TO_RESOLVE_ANYTHING):
            module_name, _, class_name = qualname.rpartition('.')
            obj = getattr(importlib.import_module(module_name), class_name)
            with self.subTest(enum=qualname):
                # Resolving an out-of-range integer at all is the property that
                # excuses them from the sweep.
                resolved = obj.get(UNRESOLVABLE)
                self.assertIsNotNone(resolved)
                self.assertEqual(int(resolved), UNRESOLVABLE)
                # It resolves with or without a default, so the ``NO_DEFAULT``
                # sentinel branch is never reached for either of them.
                self.assertEqual(resolved, obj.get(UNRESOLVABLE, 0))
                if qualname == 'pcapkit.const.mh.cga_type.CGAType':
                    # Mints permanently -- identity holds.
                    self.assertIs(resolved, obj.get(UNRESOLVABLE, 0))
                else:
                    # Converted: a fresh, equal-but-not-identical pseudo-member
                    # every time, and the registry never grows for it.
                    self.assertIsNot(resolved, obj.get(UNRESOLVABLE, 0))

    def test_filter_type_default_never_resolves_but_key_path_still_uses_an_uncached_member(self) -> None:
        """:class:`~pcapkit.const.pcapng.filter_type.FilterType`'s own
        replacement for the sweep above -- see
        :data:`EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK` for why it needs one.

        FilterType declares *no* static members at all, so its own
        ``_value2member_map_`` is permanently empty -- not ``0``, not
        anything. GitHub issue #864 restricts ``default`` to a plain
        ``_value2member_map_`` lookup rather than ``cls(default)``, which
        would reach ``_missing_`` and its converted, uncached pseudo-member
        path, so *no* default can ever resolve for this registry -- the
        strongest instance of the ruling's own accepted cost, since it is not
        one range that does not resolve but the registry's entire domain.

        ``key`` resolution is outside #864's restriction, and it is where the
        uncached pseudo-member path this test covers lives:
        ``FilterType.get(0)`` -- ``0`` as the *key*, no default at all --
        reaches ``cls(0)`` -> ``_missing_`` directly, resolving to a fresh,
        equal-but-not-identical pseudo-member every call.
        """
        from pcapkit.const.pcapng.filter_type import FilterType

        with self.assertRaises(ValueError):
            FilterType.get(UNRESOLVABLE)

        # No default can resolve on FilterType -- it has no registered
        # members at all -- so even a value that is in-bounds (0x00-0xFF)
        # for the *key* path, like ``0``, falls through to
        # the *original* ``UNRESOLVABLE`` error rather than resolving.
        before = len(FilterType.__members__)
        with self.assertRaises(ValueError) as caught:
            FilterType.get(UNRESOLVABLE, 0)
        self.assertIn(str(UNRESOLVABLE), str(caught.exception))
        self.assertEqual(len(FilterType.__members__), before)

        # The uncached pseudo-member path itself: as a *key* (no default
        # supplied), ``0`` resolves via ``cls(0)`` -> ``_missing_``,
        # returning a fresh, equal-but-not-identical member every time rather
        # than a cached identity -- the strength this test adds over the
        # generic sweep.
        resolved = FilterType.get(0)
        self.assertEqual(int(resolved), 0)
        self.assertEqual(resolved, FilterType(0))
        self.assertIsNot(resolved, FilterType(0))
        self.assertEqual(len(FilterType.__members__), before)

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_vendor_template_leaves_get_to_the_base(self) -> None:
        """A regeneration must not undo the fix.

        #584's fix lives in :meth:`~pcapkit.corekit.enum.EnumRegistry.get`
        (GitHub issue #775's tier 3), which every default-template registry
        *inherits* rather than copies, so neither the template's output nor
        the generated module has a per-file ``get()`` block for a
        regeneration to drop the fix from.

        What a regeneration could undo is the inheritance itself, or bring
        back a local copy of ``get``, ``register`` or ``_unregistered_member``
        that would shadow the base and silently resurrect #775's two-contract
        bug -- this pins their absence, and the presence of the mix-in, on
        both the freshly rendered template (with synthetic content) and the
        real, committed module.
        """
        import pathlib

        from pcapkit.vendor.default import LINE

        rendered = LINE('Hardware', 'Hardware Type [:rfc:`826`]',
                        'isinstance(value, int) and 0 <= value <= 65535',
                        "PLACEHOLDER = 'enum'", '        return None',
                        'pcapkit.vendor.arp.hardware')

        import pcapkit.const.arp.hardware as generated_module
        generated = pathlib.Path(generated_module.__file__).read_text(encoding='utf-8')

        removed_signatures = (
            "def get(key: 'int | str'",
            "def register(cls, value: 'int', name: 'str')",
            'def _unregistered_member(',
        )
        for label, rendering in (('template', rendered), ('generated module', generated)):
            with self.subTest(rendering=label):
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', rendering)
                self.assertIn('class Hardware(EnumRegistry, IntEnum):', rendering)
                for signature in removed_signatures:
                    self.assertNotIn(signature, rendering,
                                     f'{label} still carries a local {signature!r}, '
                                     f'shadowing EnumRegistry')


if __name__ == '__main__':
    unittest.main()
