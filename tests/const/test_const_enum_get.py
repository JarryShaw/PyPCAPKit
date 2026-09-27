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
skeleton"). Measured: of the 118 :class:`~aenum.IntEnum` and
:class:`~aenum.IntFlag` registries defined under :mod:`pcapkit.const`, the
defect was live in 110 -- not just the three the issue named. Three of the
remaining eight never raise on an out-of-range integer because they auto-extend
the whole space, and five carry no ``get(key, default)`` at all.

GitHub issue #647 moved one of those three into the sweep, so the arithmetic is
now 111 + 2 + 5. :class:`~pcapkit.const.tcp.flags.Flags` resolved every integer
only because it defined no ``_missing_`` to bound its domain; it does now, so its
``get`` has a failure for ``default`` to fall back from like the other 110.

Two more registries are outside this sweep because they are
:class:`~aenum.StrEnum` rather than integer enums, and both were deliberately
left alone: :class:`~pcapkit.const.pcapng.option_type.OptionType` and
:class:`~pcapkit.const.reg.apptype.AppType` each carry a bespoke integer
fallback that already resolves every value, so neither drops a default by
raising. The two string-keyed registries
:class:`~pcapkit.const.ftp.command.Command` and
:class:`~pcapkit.const.http.method.Method` have no integer path at all; they are
the subject of #582 and #583 instead.

``-1`` is the placeholder the generated signature carries, and it is what
separates "no default was supplied" from "a default was supplied and should be
used". Both halves are pinned here, because a fix that made an unresolvable key
fall back *silently* when the caller asked for no fallback would be a worse
defect than the one it replaced.

These modules are generated from :mod:`pcapkit.vendor`, so
``test_the_vendor_template_still_emits_the_fix`` renders the shared template and
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

#: An integer no wire field in the library is wide enough to carry, so every
#: registry that bounds its own domain rejects it. Deliberately far outside the
#: ``0..0xFF`` range the Mobility Header flag registries check, because a value
#: *inside* an unbounded-but-undefined span reaches a separate, pre-existing
#: recursion in their ``_missing_`` (``return cls(value)``) that is not what
#: this module is about.
UNRESOLVABLE = 1 << 70

#: Enums whose integer path resolves *anything* rather than raising, so there is
#: no fallback for ``default`` to supply.
#:
#: :class:`~pcapkit.const.tcp.flags.Flags` was a third entry until GitHub issue
#: #647. It resolved anything for a different reason -- it defined no
#: ``_missing_`` at all, so ``aenum`` composed a pseudo-member for any integer,
#: and ``Flags(-1)`` read back as every TCP header flag set at once. It now
#: bounds its own domain like the rest of the tree and so belongs in the sweep
#: below rather than in this set.
#:
#: Both used to auto-*extend* their unassigned span across the full integer
#: range, via :func:`~aenum.extend_enum`. GitHub issues #775/#847's
#: mint-criterion ruling converted :class:`~pcapkit.const.ipv4.
#: protection_authority.ProtectionAuthority`'s bare ``Unassigned`` label, so it
#: now resolves via :meth:`~pcapkit.corekit.enum.EnumRegistry.
#: _unregistered_member` instead -- it still resolves anything (the property
#: that excuses it from the sweep below), it just no longer extends.
#: :class:`~pcapkit.const.mh.cga_type.CGAType` is untouched: its ``Tag_<hex>``
#: mint is not an IANA-style range at all, so the ruling never applied.
EXPECTED_TO_RESOLVE_ANYTHING = frozenset({
    'pcapkit.const.ipv4.protection_authority.ProtectionAuthority',
    'pcapkit.const.mh.cga_type.CGAType',
})

#: Enums carrying no ``get(key, default)``, so there is no ``default`` to drop.
#: The first four are helper enums describing a registry's columns rather than
#: registries themselves and have no ``get`` at all;
#: :class:`~pcapkit.const.reg.apptype.TransportProtocol` has a ``get`` whose
#: signature takes no ``default`` -- which is why the rewrite had to check the
#: signature rather than pattern-match the body.
EXPECTED_WITHOUT_AN_INTEGER_DEFAULT = frozenset({
    'pcapkit.const.ftp.command.CommandType',
    'pcapkit.const.ftp.command.ConformanceRequirement',
    'pcapkit.const.ftp.return_code.GroupingInformation',
    'pcapkit.const.ftp.return_code.ResponseKind',
    'pcapkit.const.reg.apptype.apptype.TransportProtocol',
})

#: :class:`~pcapkit.const.pcapng.filter_type.FilterType` declares *no* static
#: members at all -- every one of its 256 codes reaches ``_missing_``. Before
#: GitHub issues #775/#847's ruling that was masked by an accident: importing
#: :mod:`pcapkit.protocols.misc.pcapng` evaluates ``Enum_FilterType(0)`` as a
#: default argument at class-definition time, which used to permanently mint
#: ``'Unassigned_0'`` as a side effect of merely importing the library --
#: leaving exactly one member for this sweep's ``next(iter(obj))`` fallback to
#: find. The ruling correctly converted FilterType's bare ``Unassigned`` label,
#: so that same import no longer mints anything, and the registry is now
#: genuinely empty: :func:`next` on it raises :exc:`StopIteration`, with no
#: value at all that ``obj(fallback)`` would resolve to a *cached* identity
#: for. Excused from the main sweep for that reason and covered by its own
#: test instead, :meth:`ConstEnumGetDefaultTests.
#: test_filter_type_default_is_consulted_without_a_cached_fallback`.
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
        # :data:`sys.modules` -- purging again here (as this used to do, GitHub
        # issue #720) does not achieve that: it only forces whoever imports
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

        # Before the fix this raised ValueError('99999 is not a valid Hardware'),
        # dropping the caller's default entirely.
        self.assertIs(Hardware.get(99999, 0), Hardware(0))
        self.assertIs(Hardware.get(99999, 1), Hardware.Ethernet)

        # The default is genuinely consulted rather than merely swallowing the
        # error: a default that is itself unresolvable is now what fails, and
        # the message names it rather than the original key. #584 passed a
        # ``str`` where the signature says ``int``, and that is still invalid.
        with self.assertRaises(ValueError) as caught:
            Hardware.get(99999, 'X')
        self.assertIn('X', str(caught.exception))
        self.assertNotIn('99999', str(caught.exception))

        # A resolvable key is untouched.
        self.assertIs(Hardware.get(1), Hardware.Ethernet)
        # 40 falls in Hardware's unassigned 39-255 range: since #775 tier 1,
        # that no longer mints a permanent member, so each lookup returns its
        # own unregistered pseudo-member -- equal, but no longer the same
        # object, which is why this is assertEqual rather than assertIs.
        self.assertEqual(Hardware.get(40), Hardware(40))
        self.assertIs(Hardware.get('Ethernet'), Hardware.Ethernet)

    def test_omitting_the_default_still_raises_for_the_original_key(self) -> None:
        """GitHub issue #857: ``-1`` used to be compared with ``==`` against
        :data:`~pcapkit.corekit.enum.NO_DEFAULT`, so a caller-supplied ``-1``
        was silently read as *no default was supplied* -- "explicitly passing
        the placeholder is the same as omitting it", as this test used to
        assert. :data:`~pcapkit.corekit.enum.NO_DEFAULT` is now an exported
        instance of the dedicated :class:`~pcapkit.corekit.enum.NoDefaultType`
        compared with ``is``, so ``-1`` is a genuine default like any other:
        omitting ``default`` entirely still raises for the *original* key
        (unchanged, pinned below), while explicitly passing ``-1`` now raises
        for the *attempted fallback* ``cls(-1)`` instead -- no longer the same
        error, since every registry's domain here starts at ``0`` and ``-1``
        is never a legitimate value.
        """
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.arp.operation import Operation

        for enum in (Hardware, Operation):
            with self.subTest(enum=_qualname(enum)):
                with self.assertRaises(ValueError) as omitted:
                    enum.get(99999)
                self.assertIn('99999', str(omitted.exception))

                # No longer "the same as omitting it": this now names the
                # failed fallback (``-1``), not the original key (``99999``).
                with self.assertRaises(ValueError) as supplied:
                    enum.get(99999, -1)
                self.assertIn('-1', str(supplied.exception))
                self.assertNotIn('99999', str(supplied.exception))

    def test_the_two_unverified_enums_from_the_issue(self) -> None:
        """#584 named ``Operation`` and ``LinkType`` but verified only ``Hardware``."""
        from pcapkit.const.arp.operation import Operation
        from pcapkit.const.reg.linktype import LinkType

        self.assertIs(Operation.get(99999, 1), Operation.REQUEST)
        self.assertIs(LinkType.get(-5, 1), LinkType.ETHERNET)

    def test_the_sweep_size_is_pinned(self) -> None:
        # If this drifts, a const enum was added, removed or renamed, and the
        # exception sets below need a fresh look rather than a silent pass.
        names = {_qualname(obj) for obj in self.enums}
        self.assertEqual(len(self.enums), 118)
        for expected in (EXPECTED_TO_RESOLVE_ANYTHING, EXPECTED_WITHOUT_AN_INTEGER_DEFAULT,
                          EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK):
            self.assertTrue(expected.issubset(names),
                            f'sweep is missing: {expected - names}')

    def test_every_integer_path_consults_the_default(self) -> None:
        """The registry-wide form of #584, across all 118 integer registries."""
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
        # 111 from GitHub issue #647, which gave
        # :class:`~pcapkit.const.tcp.flags.Flags` a range guard and moved it
        # out of ``EXPECTED_TO_RESOLVE_ANYTHING`` and into this sweep; minus 1
        # for ``FilterType``, which #775/#847's ruling moved the other way --
        # it used to be counted here only because an import-time side effect
        # (see ``EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK``) happened to leave it
        # one real member to use as ``fallback``, and the ruling removed that
        # side effect along with the mint it came from.
        self.assertEqual(covered, 110)

    def test_the_always_resolving_registries_have_nothing_to_fall_back_to(self) -> None:
        """The two registries excused from the sweep, and why.

        Their ``_missing_`` resolves for *any* integer, so the integer path
        never raises and ``default`` has nothing to supply. Asserted rather
        than merely listed, so ``EXPECTED_TO_RESOLVE_ANYTHING`` cannot quietly
        grow to hide a registry that does raise.

        Probing :class:`~pcapkit.const.mh.cga_type.CGAType` still *mutates*
        the registry: the call permanently registers a member on a
        module-global class, because its mint is untouched by GitHub issues
        #775/#847's ruling. That is done deliberately here, and
        ``setUpClass`` registers a class cleanup that purges :mod:`pcapkit`
        afterwards so the pollution cannot reach another module.
        :class:`~pcapkit.const.ipv4.protection_authority.ProtectionAuthority`
        no longer mutates anything -- its bare ``Unassigned`` converted, so it
        resolves through a throwaway pseudo-member instead -- which is why the
        identity check below only applies to ``CGAType``.

        Measured: ``CGAType`` still grows 7 members to 8; ``ProtectionAuthority``
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
                # It resolves with or without a default, so the sentinel branch
                # this change added is never reached for either of them.
                self.assertEqual(resolved, obj.get(UNRESOLVABLE, 0))
                if qualname == 'pcapkit.const.mh.cga_type.CGAType':
                    # Still mints permanently -- identity holds.
                    self.assertIs(resolved, obj.get(UNRESOLVABLE, 0))
                else:
                    # Converted: a fresh, equal-but-not-identical pseudo-member
                    # every time, and the registry never grows for it.
                    self.assertIsNot(resolved, obj.get(UNRESOLVABLE, 0))

    def test_filter_type_default_is_consulted_without_a_cached_fallback(self) -> None:
        """:class:`~pcapkit.const.pcapng.filter_type.FilterType`'s own
        replacement for the sweep above -- see
        :data:`EXPECTED_WITHOUT_A_CACHEABLE_FALLBACK` for why it needs one."""
        from pcapkit.const.pcapng.filter_type import FilterType

        with self.assertRaises(ValueError):
            FilterType.get(UNRESOLVABLE)

        # 0 is in-bounds (0x00-0xFF) but not a real member either -- FilterType
        # declares none -- so this resolves via the same converted pseudo-member
        # path as UNRESOLVABLE-with-a-default does, not via a cached identity.
        before = len(FilterType.__members__)
        resolved = FilterType.get(UNRESOLVABLE, 0)
        self.assertEqual(int(resolved), 0)
        self.assertEqual(resolved, FilterType(0))
        self.assertIsNot(resolved, FilterType(0))
        self.assertEqual(len(FilterType.__members__), before)

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_vendor_template_still_emits_the_fix(self) -> None:
        """A regeneration must not undo the fix.

        GitHub issue #775's tier 3 moved #584's fix off the per-file generated
        ``get()`` entirely: it now lives permanently in
        :meth:`~pcapkit.corekit.enum.EnumRegistry.get`, which every one of the
        105 default-template registries *inherits* rather than copies, so
        there is no longer a ``get()`` block here for a regeneration to drop
        the fix from -- the block this test used to extract and compare no
        longer exists in either the template's output or the generated
        module, in either case for the same reason.

        What a regeneration could still undo is the inheritance itself, or
        bring back a local copy of ``get``, ``register`` or
        ``_unregistered_member`` that would shadow the base and silently
        resurrect the pre-#775 two-contract bug -- this pins their absence,
        and the presence of the mix-in, on both the freshly rendered template
        (with synthetic content, as the pre-#775 version of this test did for
        ``get()``) and the real, committed module.
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
