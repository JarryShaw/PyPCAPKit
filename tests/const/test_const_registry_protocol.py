# -*- coding: utf-8 -*-
"""Tests for :class:`pcapkit.corekit.enum.EnumRegistry`, tier 2 of issue #775.

Tier 1 (#838) removed the mint from the two sites in
:data:`pcapkit.vendor.default.LINE` that the 107 default-template registries
inherit. It could not reach the eleven crawlers that replace that template with
their own, because each of those carries a hand-copied ``get()`` -- and none of
them carries ``register``, ``register_alias`` or ``get_all`` at all.

The maintainer's ruling on #842, verbatim: *"to finalise the abstraction idea,
get/get_all/register/register_alias should always exist on the const enums - so
they're to be moved to the base class. And AppType's sub-base class will do its
necessary overrides and dispatching logic; AppType subclasses will have their
necessary overrides again pertaining their different contracts."*

:class:`~pcapkit.corekit.enum.EnumRegistry` is tier one of that hierarchy. This
module pins both halves of the claim: that the generated registries in this batch
really do inherit the protocol rather than carry a copy of it, and that each of
the four methods honours the contract the maintainer wrote for it.

"""
from __future__ import annotations

import importlib
import pathlib
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag, StrEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry
from tests._support import ISOLATED_PREFIXES, purge_modules, restore_modules, snapshot_modules

if TYPE_CHECKING:
    from typing import Any

#: Repository root, for reading generated sources as text.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The batch converted onto :class:`~pcapkit.corekit.enum.EnumRegistry`: the
#: six bespoke-template registries whose members carry no extra attributes, so
#: the shared ``_unregistered_member`` -- which sets only ``_name_`` and
#: ``_value_`` -- builds a complete member for them. ``tcp/flags`` joined the
#: original five once measurement showed its exclusion rationale did not hold:
#: the PR description had grouped it with the five templates below on the
#: strength of "each attach extra attributes in ``__new__``", but
#: ``grep -c 'def __new__'`` reports ``0`` for both ``pcapkit/vendor/tcp/flags.py``
#: and ``pcapkit/const/tcp/flags.py`` -- it never defined one, so it is the same
#: shape as the four ``mh/*_flag`` registries, not the five below. Its own
#: ``_missing_`` still does its own 16-bit range check ending in
#: ``super()._missing_(value)``, unchanged by the conversion: that call chain
#: resolves through :mod:`aenum`'s own :class:`~aenum.Flag` machinery either
#: way, since :class:`~pcapkit.corekit.enum.EnumRegistry` never defines
#: ``_missing_`` itself. The remaining five bespoke templates (``ftp/command``,
#: ``ftp/return_code``, ``http/method``, ``http/status_code``,
#: ``pcapng/option_type``) do each define a custom ``__new__`` attaching further
#: attributes, so an unregistered member of theirs would be missing them; they
#: need their own override and stay out of this batch.
CONVERTED = (
    ('pcapkit.const.mh.binding_ack_flag', 'BindingACKFlag', 'pcapkit/const/mh/binding_ack_flag.py'),
    ('pcapkit.const.mh.binding_update_flag', 'BindingUpdateFlag', 'pcapkit/const/mh/binding_update_flag.py'),
    ('pcapkit.const.mh.handover_ack_flag', 'HandoverACKFlag', 'pcapkit/const/mh/handover_ack_flag.py'),
    ('pcapkit.const.mh.handover_initiate_flag', 'HandoverInitiateFlag', 'pcapkit/const/mh/handover_initiate_flag.py'),
    ('pcapkit.const.ipv6.extension_header', 'ExtensionHeader', 'pcapkit/const/ipv6/extension_header.py'),
    ('pcapkit.const.tcp.flags', 'Flags', 'pcapkit/const/tcp/flags.py'),
)

#: The crawlers whose bespoke templates were converted, and which must therefore
#: no longer spell a ``get()`` of their own.
CONVERTED_VENDORS = (
    'pcapkit/vendor/mh/binding_ack_flag.py',
    'pcapkit/vendor/mh/binding_update_flag.py',
    'pcapkit/vendor/mh/handover_ack_flag.py',
    'pcapkit/vendor/mh/handover_initiate_flag.py',
    'pcapkit/vendor/ipv6/extension_header.py',
    'pcapkit/vendor/tcp/flags.py',
)

#: Every method of the protocol the ruling says must always exist.
PROTOCOL = ('get', 'get_all', 'register', 'register_alias', 'register_aliases',
            '_unregistered_member')


def _unused_value(cls: 'Any') -> 'int':
    """First non-negative integer no member of ``cls`` carries.

    Read from ``_value2member_map_`` rather than by calling ``cls(value)``:
    after tier 1 a declared-but-unassigned value resolves to an unregistered
    member instead of raising, so a successful call proves nothing about
    membership -- the same reason ``register_alias`` itself tests that table.

    """
    for candidate in range(1 << 16):
        if candidate not in cls._value2member_map_:
            return candidate
    raise AssertionError(f'{cls.__name__} has no unused value below 65536')


def _purge_member(cls: 'Any', name: 'str') -> 'None':
    """Undo an :func:`~aenum.extend_enum` so a test's explicit ``register()`` or
    ``register_alias()`` call does not leak into the rest of the suite.

    Mirrors ``tests.const.test_const_enum_no_mint._purge_member``, but leaves
    ``_value2member_map_`` alone when the name being dropped was an *alias*:
    that entry belongs to the pre-existing member, and removing it would make
    the alias case destructive where the mint case's is not.

    """
    member = cls._member_map_.pop(name, None)
    if member is None:
        return
    if name in cls._member_names_:
        cls._member_names_.remove(name)
    if cls._value2member_map_.get(member.value) is member and member.name == name:
        cls._value2member_map_.pop(member.value, None)


class GeneratedSourceInheritsTests(unittest.TestCase):
    """The generated registries must *inherit* the protocol, not copy it."""

    def test_converted_const_modules_declare_the_base(self) -> None:
        for _, name, relpath in CONVERTED:
            with self.subTest(registry=name):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertIn(f'class {name}(EnumRegistry, ', source)

    def test_converted_const_modules_carry_no_copy_of_the_protocol(self) -> None:
        """A ``def get``/``def register`` left behind would silently shadow the
        base class, which is the failure this batch exists to remove."""
        for _, name, relpath in CONVERTED:
            source = (REPO_ROOT / relpath).read_text()
            for method in PROTOCOL:
                with self.subTest(registry=name, method=method):
                    self.assertNotIn(f'def {method}(', source)

    def test_converted_crawlers_no_longer_spell_their_own_get(self) -> None:
        for relpath in CONVERTED_VENDORS:
            with self.subTest(vendor=relpath):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertNotIn("def get(key: 'int | str'", source)


class ProtocolIsInheritedTests(unittest.TestCase):
    """All of the protocol must be present, and reached from the base class."""

    if TYPE_CHECKING:
        registries: 'list[Any]'
        base: 'Any'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.registries = [
            getattr(importlib.import_module(module_name), class_name)
            for module_name, class_name, _ in CONVERTED
        ]
        # NOTE: resolved from the re-imported module rather than reusing the
        # module-scope import. purge_modules() above drops every ``pcapkit``
        # entry from ``sys.modules``, so the freshly imported registries inherit
        # a *new* EnumRegistry class object -- identity against the outer one
        # would fail for a reason that says nothing about the product.
        cls.base = importlib.import_module('pcapkit.corekit.enum').EnumRegistry
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_base_class_is_in_the_mro(self) -> None:
        for registry in self.registries:
            with self.subTest(registry=registry.__qualname__):
                self.assertIn(self.base, registry.__mro__)

    def test_every_method_resolves_to_the_base_implementation(self) -> None:
        for registry in self.registries:
            for method in PROTOCOL:
                with self.subTest(registry=registry.__qualname__, method=method):
                    self.assertEqual(getattr(registry, method).__func__,
                                     getattr(self.base, method).__func__)

    def test_mixing_in_the_base_leaves_the_member_type_alone(self) -> None:
        """One base for three member types is what a generated fragment could
        not do, so the mix-in must not become the member data type itself."""
        class _Int(EnumRegistry, IntEnum):
            one = 1

        class _Flag(EnumRegistry, IntFlag):
            two = 2

        class _Str(EnumRegistry, StrEnum):
            three = 'three'

        self.assertIs(_Int._member_type_, int)
        self.assertIs(_Flag._member_type_, int)
        self.assertIs(_Str._member_type_, str)
        self.assertEqual(int(_Int.one), 1)
        self.assertEqual(str(_Str.three), 'three')


class _PreConversionFlags(IntFlag):
    """A reproduction of ``pcapkit.const.tcp.flags.Flags`` exactly as it stood
    on commit ``02296b5dd`` (this batch's prior head), before ``tcp/flags``
    joined :data:`CONVERTED`: a plain ``class Flags(IntFlag)`` with its own
    hand-copied ``get`` (omitted here -- irrelevant to ``_missing_``) and this
    ``_missing_``, copied verbatim. Kept inline rather than fetched from git
    history so :class:`TCPFlagsConversionTests` runs offline and the
    comparison is exact rather than approximate.
    """

    Reserved_4 = 1 << 4
    Reserved_5 = 1 << 5
    Reserved_6 = 1 << 6
    AE = 1 << 7
    CWR = 1 << 8
    ECE = 1 << 9
    URG = 1 << 10
    ACK = 1 << 11
    PSH = 1 << 12
    RST = 1 << 13
    SYN = 1 << 14
    FIN = 1 << 15

    @classmethod
    def _missing_(cls, value: 'Any') -> 'Any':
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        return super()._missing_(value)


def _resolve_or_raise(cls: 'Any', value: 'Any') -> 'Any':
    """``(int value, name)`` on success, or the exception type on failure.

    The shared probe :meth:`TCPFlagsConversionTests.test_missing_resolves_identically_to_the_pre_conversion_shape`
    runs against both the reference above and the real, converted registry.

    """
    try:
        member = cls(value)
    except Exception as error:  # pylint: disable=broad-except
        return type(error)
    return (int(member), member.name)


class TCPFlagsConversionTests(unittest.TestCase):
    """GitHub issue #775's own finding: the PR description's stated reason
    for excluding ``tcp/flags`` from this batch -- "each attach extra
    attributes in ``__new__``" -- does not hold for it.
    ``grep -c 'def __new__'`` reports ``0`` for both
    ``pcapkit/vendor/tcp/flags.py`` and ``pcapkit/const/tcp/flags.py``, the
    same shape as the four ``mh/*_flag`` registries this batch already
    converts, so it belongs in :data:`CONVERTED` rather than in the five
    templates excluded for actually defining one.
    """

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_tcp_flags_now_inherits_the_base(self) -> None:
        """Fails on ``02296b5dd``, where ``Flags`` is a plain ``IntFlag``.

        Resolves ``EnumRegistry`` freshly from the just-reimported
        ``pcapkit.corekit.enum`` rather than the module-scope import above --
        ``setUp`` purged ``pcapkit`` from ``sys.modules``, so ``Flags`` now
        inherits a *new* ``EnumRegistry`` class object, and identity against
        the stale outer one would fail for a reason that says nothing about
        the product (see ``ProtocolIsInheritedTests.setUpClass`` above, which
        hits the same trap).
        """
        from pcapkit.const.tcp.flags import Flags

        base = importlib.import_module('pcapkit.corekit.enum').EnumRegistry
        self.assertIn(base, Flags.__mro__)

    def test_missing_resolves_identically_to_the_pre_conversion_shape(self) -> None:
        """The conversion changes *what the class inherits*, not
        ``_missing_``'s own logic -- :class:`~pcapkit.corekit.enum.EnumRegistry`
        never defines ``_missing_`` itself, so ``super()._missing_(value)``
        inside ``Flags._missing_`` resolves through :mod:`aenum`'s
        :class:`~aenum.Flag` machinery exactly as it did when ``Flags``
        inherited from ``IntFlag`` directly. Swept rather than sampled at a
        few boundary values, across every declared member, every boundary of
        the 16-bit field the range check bounds, and several composites,
        so a widened or narrowed range check would be caught here rather
        than only in the composite-specific tests in
        ``tests/const/test_const_enum_builtin_parity.py``.
        """
        from pcapkit.const.tcp.flags import Flags

        probes = [0, 1, 0xF, 0x10, 0xFFFF, 0x10000, -1, -0x10000,
                  1 << 70, 0xFFF0]
        for member in _PreConversionFlags:
            probes.append(int(member))
        for first, second in (('PSH', 'ACK'), ('SYN', 'FIN'), ('RST', 'URG')):
            probes.append(int(_PreConversionFlags[first]) | int(_PreConversionFlags[second]))

        for value in probes:
            with self.subTest(value=value):
                self.assertEqual(_resolve_or_raise(_PreConversionFlags, value),
                                 _resolve_or_raise(Flags, value))

    def test_tcp_flags_gains_the_protocol_it_never_had(self) -> None:
        """On ``02296b5dd`` none of these exist on ``Flags`` at all -- its own
        hand-copied ``get`` was the only member of the protocol it carried,
        and it had no ``get_all``, ``register``, ``register_alias``,
        ``register_aliases`` or ``_unregistered_member`` -- so this raises
        :exc:`AttributeError` there and only passes once the conversion lands.
        """
        from pcapkit.const.tcp.flags import Flags

        target = list(Flags)[0]
        self.assertEqual(Flags.get_all(target.name), (target,))

        value = _unused_value(Flags)
        self.addCleanup(_purge_member, Flags, 'unit_test_tcp_flags_minted')
        member = Flags.register(value, 'unit_test_tcp_flags_minted')
        self.assertEqual(member.value, value)

        unregistered = Flags._unregistered_member(_unused_value(Flags), 'unit_test_tcp_flags_absent')
        self.assertEqual(unregistered.name, 'unit_test_tcp_flags_absent')
        self.assertNotIn('unit_test_tcp_flags_absent', Flags.__members__)


class GetContractTests(unittest.TestCase):
    """*"get is a shortcut for ``[]`` operation and returns the canonical enum."*"""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_name_and_value_both_resolve_to_the_same_member(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.assertIs(ExtensionHeader.get(target.name), target)
        self.assertIs(ExtensionHeader.get(target.value), target)
        self.assertIs(ExtensionHeader.get(target.name), ExtensionHeader[target.name])

    def test_an_alias_resolves_to_its_canonical_member(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_canonical')
        ExtensionHeader.register_alias(target.value, 'unit_test_canonical')

        self.assertIs(ExtensionHeader.get('unit_test_canonical'), target)
        self.assertEqual(ExtensionHeader.get('unit_test_canonical').name, target.name)

    def test_string_miss_without_default_raises_and_does_not_mint(self) -> None:
        from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag

        before = len(BindingUpdateFlag.__members__)
        with self.assertRaises(KeyError):
            BindingUpdateFlag.get('Definitely-Not-A-Member')
        self.assertEqual(before, len(BindingUpdateFlag.__members__))

    def test_string_miss_with_default_falls_back_by_value(self) -> None:
        """The normalisation half of this batch: the hand-copied ``get()`` ended
        in a bare ``return NAME[key]``, so ``default`` silently applied to
        integer keys only."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        before = len(ExtensionHeader.__members__)

        self.assertIs(ExtensionHeader.get('Definitely-Not-A-Member', target.value), target)
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_value_miss_without_default_raises(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(ValueError):
            ExtensionHeader.get(_unused_value(ExtensionHeader))
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_value_miss_with_default_falls_back(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        before = len(ExtensionHeader.__members__)

        result = ExtensionHeader.get(_unused_value(ExtensionHeader), target.value)

        self.assertIs(result, target)
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_get_never_mints_on_any_converted_registry(self) -> None:
        for module_name, class_name, _ in CONVERTED:
            with self.subTest(registry=class_name):
                registry = getattr(importlib.import_module(module_name), class_name)
                before = len(registry.__members__)
                with self.assertRaises(KeyError):
                    registry.get('Definitely-Not-A-Member')
                self.assertEqual(before, len(registry.__members__))


class GetAllContractTests(unittest.TestCase):
    """*"get_all returns all matching enums."*"""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_a_one_to_one_registry_matches_exactly_one_member(self) -> None:
        """An alias is a second *name* for the canonical member, not a second
        member, so a registry that maps one key to one member answers with one
        entry even after an alias is registered."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.assertEqual(ExtensionHeader.get_all(target.value), (target,))

        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_all')
        ExtensionHeader.register_alias(target.value, 'unit_test_all')

        self.assertEqual(ExtensionHeader.get_all(target.value), (target,))
        self.assertEqual(ExtensionHeader.get_all('unit_test_all'), (target,))

    def test_get_all_is_present_on_every_converted_registry(self) -> None:
        for module_name, class_name, _ in CONVERTED:
            with self.subTest(registry=class_name):
                registry = getattr(importlib.import_module(module_name), class_name)
                target = list(registry)[0]
                self.assertEqual(registry.get_all(target.name), (target,))

    def test_get_all_propagates_a_miss(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        with self.assertRaises(KeyError):
            HandoverACKFlag.get_all('Definitely-Not-A-Member')


class RegisterContractTests(unittest.TestCase):
    """*"register mints new enum to the class at runtime with specified names."*"""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_register_adds_a_new_member_under_the_given_name(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        value = _unused_value(ExtensionHeader)
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_minted')
        before = len(ExtensionHeader._member_names_)

        member = ExtensionHeader.register(value, 'unit_test_minted')

        self.assertEqual(member.value, value)
        self.assertEqual(member.name, 'unit_test_minted')
        self.assertIn(value, ExtensionHeader._value2member_map_)
        self.assertEqual(before + 1, len(ExtensionHeader._member_names_))

    def test_register_on_a_flag_registry_resolves_by_name_and_value(self) -> None:
        """Measured on :class:`~aenum.IntFlag`: a value that is the bitwise
        composite of existing flags -- which the first unused integer often is --
        registers as a *composite* pseudo-member, so ``_member_names_`` does not
        grow even though the name and value both resolve. That is
        :mod:`aenum`'s own flag semantics rather than anything this base does,
        so the assertion here is what actually holds for a flag registry."""
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        value = _unused_value(HandoverACKFlag)
        self.addCleanup(_purge_member, HandoverACKFlag, 'unit_test_minted')

        member = HandoverACKFlag.register(value, 'unit_test_minted')

        self.assertEqual(member.value, value)
        self.assertIn(value, HandoverACKFlag._value2member_map_)
        self.assertIn('unit_test_minted', HandoverACKFlag.__members__)

    def test_register_over_a_taken_name_raises_value_error(self) -> None:
        """:mod:`aenum` reports a name collision as :exc:`TypeError`; the base
        translates it so one call has one failure type."""
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        target = list(HandoverACKFlag)[0]
        before = len(HandoverACKFlag.__members__)

        with self.assertRaises(ValueError):
            HandoverACKFlag.register(_unused_value(HandoverACKFlag), target.name)

        self.assertEqual(before, len(HandoverACKFlag.__members__))

    def test_register_over_a_taken_value_raises_value_error_and_does_not_alias(self) -> None:
        """The guard this batch adds: :func:`~aenum.extend_enum` does not mint
        anything for a value that already has a member -- :mod:`aenum` treats
        that as a request to *alias* the existing member under the caller's
        name instead, silently. Without a guard, ``register(existing_value,
        'TOTALLY_NEW_NAME')`` returns the *existing* member (``.name`` still
        the original), makes ``'TOTALLY_NEW_NAME'`` reachable in
        ``__members__`` pointing at it, and mints nothing -- reachable under
        the wrong method, unannounced, and contradicting the method's own
        docstring contract that ``register`` is what mints and nothing else
        does so silently. Reproduced against this exact shape on
        ``pcapkit.const.reg.apptype.apptype.TransportProtocol`` (a different,
        non-:class:`~pcapkit.corekit.enum.EnumRegistry` registry, since
        that one is not gated the same way) before this guard existed:
        ``TransportProtocol.register(6, 'TOTALLY_NEW_NAME')`` returned
        ``TransportProtocol.tcp`` unchanged and minted nothing. This pins the
        fix on the base class every :data:`CONVERTED` registry actually uses.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        names_before = list(ExtensionHeader._member_names_)
        members_before = dict(ExtensionHeader.__members__)

        with self.assertRaises(ValueError) as caught:
            ExtensionHeader.register(target.value, 'TOTALLY_NEW_NAME')

        self.assertIn(str(target.value), str(caught.exception))
        self.assertIn(target.name, str(caught.exception))
        self.assertIn('register_alias', str(caught.exception))
        # Nothing minted, and the wrong name never became reachable at all --
        # the failure mode this guard exists to rule out.
        self.assertEqual(names_before, list(ExtensionHeader._member_names_))
        self.assertEqual(members_before, dict(ExtensionHeader.__members__))
        self.assertNotIn('TOTALLY_NEW_NAME', ExtensionHeader.__members__)
        # And the pre-existing member is exactly as it was -- not renamed, not
        # replaced.
        self.assertIs(ExtensionHeader(target.value), target)
        self.assertEqual(target.name, ExtensionHeader(target.value).name)

    def test_register_over_a_taken_value_on_a_flag_registry_also_refuses(self) -> None:
        """The same guard, on an :class:`~aenum.IntFlag` registry: value
        collision is checked the same way regardless of member type, since
        both share :meth:`~pcapkit.corekit.enum.EnumRegistry._extend`."""
        from pcapkit.const.mh.binding_ack_flag import BindingACKFlag

        target = list(BindingACKFlag)[0]
        before = len(BindingACKFlag.__members__)

        with self.assertRaises(ValueError):
            BindingACKFlag.register(target.value, 'TOTALLY_NEW_FLAG_NAME')

        self.assertEqual(before, len(BindingACKFlag.__members__))
        self.assertNotIn('TOTALLY_NEW_FLAG_NAME', BindingACKFlag.__members__)

    def test_register_alias_still_aliases_after_the_value_guard(self) -> None:
        """:meth:`register_alias` depends on :meth:`register` accepting an
        already-registered value -- that dependency moved to the shared,
        ungated :meth:`~pcapkit.corekit.enum.EnumRegistry._extend` when this
        guard was added, so this pins that the move did not also gate the
        path :meth:`register_alias` needs. A naive guard placed directly in
        the body :meth:`register` calls would make every alias registration
        raise the exact error this test's sibling above checks for, rather
        than aliasing. Deliberately on ``ExtensionHeader`` rather than
        ``Flags``: this registry already inherited
        :class:`~pcapkit.corekit.enum.EnumRegistry` before this change, so
        this is a regression pin on the internal refactor and holds on both
        the prior head and this one -- unlike this class's ``Flags``-based
        siblings above, which pin the guard itself and so only hold once
        ``tcp/flags`` has joined :data:`CONVERTED` too."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_alias_after_guard')

        result = ExtensionHeader.register_alias(target.value, 'unit_test_alias_after_guard')

        self.assertIs(result, target)
        self.assertIs(ExtensionHeader['unit_test_alias_after_guard'], target)


class RegisterAliasContractTests(unittest.TestCase):
    """*"register_alias(es) adds additional alias(es) to a given enum's mapping."*

    And, on whether an enum must be given: *"actually i think it should always be
    for an existing member"*.

    """

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_alias_adds_a_name_not_a_member(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_alias')
        names_before = list(ExtensionHeader._member_names_)
        members_before = len(ExtensionHeader.__members__)

        result = ExtensionHeader.register_alias(target.value, 'unit_test_alias')

        self.assertIs(result, target)
        self.assertIs(ExtensionHeader['unit_test_alias'], target)
        self.assertEqual(names_before, list(ExtensionHeader._member_names_))
        self.assertEqual(members_before + 1, len(ExtensionHeader.__members__))

    def test_alias_for_an_unregistered_value_is_refused(self) -> None:
        from pcapkit.const.mh.binding_ack_flag import BindingACKFlag

        value = _unused_value(BindingACKFlag)
        before = len(BindingACKFlag.__members__)

        with self.assertRaises(ValueError) as caught:
            BindingACKFlag.register_alias(value, 'unit_test_alias')

        self.assertIn('is not a registered BindingACKFlag', str(caught.exception))
        self.assertEqual(before, len(BindingACKFlag.__members__))
        self.assertNotIn('unit_test_alias', BindingACKFlag.__members__)

    def test_alias_over_a_taken_name_raises_value_error(self) -> None:
        from pcapkit.const.mh.binding_ack_flag import BindingACKFlag

        target = list(BindingACKFlag)[0]
        before = len(BindingACKFlag.__members__)

        with self.assertRaises(ValueError):
            BindingACKFlag.register_alias(target.value, target.name)

        self.assertEqual(before, len(BindingACKFlag.__members__))

    def test_register_aliases_adds_several(self) -> None:
        from pcapkit.const.mh.handover_initiate_flag import HandoverInitiateFlag

        target = list(HandoverInitiateFlag)[0]
        for name in ('unit_test_a', 'unit_test_b'):
            self.addCleanup(_purge_member, HandoverInitiateFlag, name)
        names_before = list(HandoverInitiateFlag._member_names_)

        result = HandoverInitiateFlag.register_aliases(
            target.value, 'unit_test_a', 'unit_test_b')

        self.assertEqual(result, (target, target))
        self.assertIs(HandoverInitiateFlag['unit_test_a'], target)
        self.assertIs(HandoverInitiateFlag['unit_test_b'], target)
        self.assertEqual(names_before, list(HandoverInitiateFlag._member_names_))


class UnregisteredMemberTests(unittest.TestCase):
    """``_unregistered_member`` must stay outside the lookup tables, for both
    member types the base serves."""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_int_valued_registries(self) -> None:
        for module_name, class_name, _ in CONVERTED:
            with self.subTest(registry=class_name):
                registry = getattr(importlib.import_module(module_name), class_name)
                value = _unused_value(registry)

                member = registry._unregistered_member(value, 'unit_test_absent')

                self.assertEqual(member.value, value)
                self.assertEqual(member.name, 'unit_test_absent')
                self.assertNotIn(value, registry._value2member_map_)
                self.assertNotIn('unit_test_absent', registry.__members__)

    def test_str_valued_registries(self) -> None:
        """``cls._member_type_.__new__`` is what generalises this beyond ``int``
        -- the generated fragment it replaces hardcoded ``int.__new__``, so the
        five :class:`~aenum.StrEnum` registries could not have shared it."""
        class _Str(EnumRegistry, StrEnum):
            known = 'known'

        member = _Str._unregistered_member('absent', 'unit_test_absent')

        self.assertEqual(member.value, 'absent')
        self.assertEqual(str(member), 'absent')
        self.assertEqual(member.name, 'unit_test_absent')
        self.assertNotIn('absent', _Str._value2member_map_)
        self.assertNotIn('unit_test_absent', _Str.__members__)


#: Sample of the 107 default-template registries GitHub issue #775's tier 3
#: moved onto :class:`~pcapkit.corekit.enum.EnumRegistry`, chosen to cover
#: the two shapes the census turned up in ``pcapkit/vendor/default.py``'s
#: ``LINE`` template: a registry whose own ``_missing_`` mints directly via
#: :func:`~aenum.extend_enum` for an unassigned value (``TransType``,
#: ``LinkType``, ``RecordType``, ``Parameter`` -- the last two from crawlers
#: that override ``process()`` to supply that ``_missing_`` body themselves),
#: and one that resolves a bounded-but-unassigned value through the
#: inherited ``_unregistered_member`` instead (``Hardware``). The template's
#: own ``from aenum import IntEnum{, extend_enum}`` import line depends on
#: which shape a given registry's crawler produces, so the sample deliberately
#: covers both.
GENERATED_SAMPLE = (
    ('pcapkit.const.reg.transtype', 'TransType', 'pcapkit/const/reg/transtype.py'),
    ('pcapkit.const.reg.linktype', 'LinkType', 'pcapkit/const/reg/linktype.py'),
    ('pcapkit.const.arp.hardware', 'Hardware', 'pcapkit/const/arp/hardware.py'),
    ('pcapkit.const.pcapng.record_type', 'RecordType', 'pcapkit/const/pcapng/record_type.py'),
    ('pcapkit.const.hip.parameter', 'Parameter', 'pcapkit/const/hip/parameter.py'),
)

#: Const modules tier 3 deliberately leaves alone. The first six override
#: their crawler's own ``process()``/``context()`` with a bespoke ``get()``/
#: ``_missing_`` pair that does not share :mod:`pcapkit.vendor.default`'s
#: template at all -- mixing :class:`~pcapkit.corekit.enum.EnumRegistry` in
#: without further care would still have silently changed behaviour rather
#: than just moved it, since four of the six are :class:`~aenum.StrEnum`
#: registries whose own ``__new__`` attaches further attributes the base's
#: generic ``_unregistered_member`` does not set. GitHub issue #860 fixed
#: the base ``get()``'s own str-key-never-tries-the-value-path limitation
#: this comment used to cite -- measured on a synthetic registry in
#: :class:`StrEnumValueFallbackTests` below -- and issue #860's step 2 has
#: since actually converted all six (``FEATCode``, ``Command``, ``Method``,
#: ``ReturnCode``/``ResponseKind``/``GroupingInformation``, ``StatusCode``
#: and ``OptionType`` in PR 1; ``AppType`` and its four transport subclasses
#: in PR 2), each with its own ``_unregistered_member`` override where a
#: custom ``__new__`` needed one. They stay excluded from *this* file's
#: tier-3 sweep regardless, because the exclusion here is about their
#: bespoke ``process()``/``get()`` shape not sharing the generated template,
#: which conversion onto the base does not change -- unlike the 107
#: :data:`GENERATED_SAMPLE` registries below, each of these five classes'
#: (nine files') own ``_missing_`` stays bespoke rather than sharing the
#: generated template, and several also keep a bespoke
#: ``_unregistered_member`` (``Command``, ``Method``, ``OptionType``,
#: ``ReturnCode``, ``StatusCode``) or a bespoke ``get`` of their own
#: (``Command``, ``Method``, ``OptionType``; ``AppType`` and its four
#: transport subclasses keep all four ``get``/``get_all``/``register``/
#: ``register_alias``, added in PR 2) -- but not every one does:
#: ``FEATCode``, ``ResponseKind`` and ``GroupingInformation`` resolve every
#: protocol method to the base's generic implementation unchanged.
#: ``TransportProtocol`` alone is excluded for
#: the separate reason it always was: it never mixes in
#: :class:`~pcapkit.corekit.enum.EnumRegistry` at all, by the owner's own
#: ruling against extending it (GitHub PR #836) -- there is no registry
#: protocol here to inherit or shadow.
#:
#: The name below is deliberately about what the set *does*, not why: it is
#: everything this file's ``IntEnum``-only census (:data:`GENERATED_SAMPLE`
#: and the ``generated`` list below) leaves out, historical and anchored at
#: commit ``05468a06b`` like the counts in
#: ``test_every_generated_const_module_is_accounted_for`` below -- not a
#: claim that every entry shares one reason. At least three apply, and the
#: grouping below tags each entry with its own: (a) is a
#: :class:`~aenum.StrEnum` registry, so would miss this file's
#: ``class \w+(EnumRegistry, IntEnum):`` regex regardless of anything else;
#: (b) mixes in the base but overrides its generic protocol with a bespoke
#: one, per the paragraph above; (c) ``TransportProtocol`` alone, which never
#: mixes in the base at all. A file can carry more than one -- ``apptype.py``
#: is (a) via ``AppType`` and (c) via ``TransportProtocol`` in the same
#: module.
#:
#: ``pcapkit/const/pcapng/tls_key_label.py`` (GitHub issue #886) is reason
#: (a) too, but on narrower grounds worth spelling out, since -- unlike the
#: rest of that group -- it does not carry a bespoke ``get()``/``register()``
#: at all; its own ``get``/``get_all``/``register``/``register_alias`` are
#: exactly the base's generic implementation, same as every one of the 107
#: :data:`GENERATED_SAMPLE`-shaped registries below. What excludes it is
#: simply that this whole census, and its
#: ``class \w+(EnumRegistry, IntEnum):`` regex a few lines down, is scoped to
#: the :class:`~aenum.IntEnum` batch tier 3 of #775 converted.
#: ``TLSKeyLabel`` is :class:`~aenum.StrEnum`-valued -- RFC 9850's labels are
#: strings, matched by value -- and it was generated after that batch
#: closed, so it was never a candidate for it either way. Excluding it here
#: is not a judgement about its own inherited-protocol cleanliness;
#: :mod:`tests.const.test_const_enum_get`,
#: :mod:`tests.const.test_const_enum_lookup` and
#: :mod:`tests.const.test_const_enum_builtin_parity`'s dynamic
#: ``pkgutil.walk_packages`` sweeps already discover and cover it
#: generically -- it is simply outside what this file's historical,
#: IntEnum-only census counts.
EXCLUDED_FROM_INTENUM_CENSUS = frozenset({
    # (a) str-valued: not an IntEnum, so excluded from the regex census
    # regardless of override.
    'pcapkit/const/ftp/command.py',           # Command, FEATCode
    'pcapkit/const/http/method.py',           # Method
    'pcapkit/const/pcapng/option_type.py',    # OptionType
    'pcapkit/const/pcapng/tls_key_label.py',  # TLSKeyLabel -- see the paragraph above
    'pcapkit/const/reg/apptype/dccp.py',      # DCCP
    'pcapkit/const/reg/apptype/sctp.py',      # SCTP
    'pcapkit/const/reg/apptype/tcp.py',       # TCP
    'pcapkit/const/reg/apptype/udp.py',       # UDP

    # (b) int-valued and mixes in the base, but carries a custom __new__
    # plus its own _unregistered_member override, so it is not the
    # generated shape -- get()/get_all()/register()/register_alias() all
    # still resolve to the base's generic implementation.
    'pcapkit/const/ftp/return_code.py',       # ReturnCode (ResponseKind and
                                               # GroupingInformation, same file,
                                               # are clean; excluded only as
                                               # co-residents)
    'pcapkit/const/http/status_code.py',      # StatusCode

    # (a) and (c) together: AppType is str-valued like the group above (and
    # overrides get()/get_all()/register()/register_alias() more fully than
    # either (b) file above); TransportProtocol, in the same file, never
    # mixes in the base at all.
    'pcapkit/const/reg/apptype/apptype.py',   # AppType, TransportProtocol
})


class GeneratedTemplateSourceInheritsTests(unittest.TestCase):
    """The 107 default-template registries must inherit the protocol too,
    not just the six bespoke ones :class:`GeneratedSourceInheritsTests`
    above (tier 2) already covers."""

    def test_generated_sample_declares_the_base(self) -> None:
        for _, name, relpath in GENERATED_SAMPLE:
            with self.subTest(registry=name):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertIn(f'class {name}(EnumRegistry, IntEnum):', source)

    def test_generated_sample_carries_no_copy_of_the_protocol(self) -> None:
        """A ``def get``/``def register``/``def _unregistered_member`` left
        behind would silently shadow the base -- the exact two-contract bug
        this tier exists to remove. ``_missing_`` must survive, since it
        carries each registry's own bounded ranges and was never meant to
        move."""
        for _, name, relpath in GENERATED_SAMPLE:
            source = (REPO_ROOT / relpath).read_text()
            for method in PROTOCOL:
                with self.subTest(registry=name, method=method):
                    self.assertNotIn(f'def {method}(', source)
            with self.subTest(registry=name, method='_missing_'):
                self.assertIn("def _missing_(cls, value: 'int')", source)

    def test_every_generated_const_module_is_accounted_for(self) -> None:
        """The full census, measured on this batch rather than assumed: 124
        modules under :mod:`pcapkit.const`, splitting exactly three ways --
        the 6 :data:`CONVERTED` bespoke ones tier 2 already handled, the 11
        :data:`EXCLUDED_FROM_INTENUM_CENSUS` deliberately left alone, and the
        remaining 107 this tier converts. Measured by me on the prior head
        (commit ``05468a06b``, this batch's own base): of those 121, 6 carried
        :class:`~pcapkit.corekit.enum.EnumRegistry` and 111 carried the
        literal "Backport support for original codes." docstring (including
        the 6 bespoke StrEnum/AppType files, since a hand-copied docstring is
        not proof of a shared template) -- 105 is what is left once the 6
        converted and the 10 excluded are both taken out.

        121 became 122 with GitHub issue #886's
        ``pcapkit/const/pcapng/tls_key_label.py``, and the 10 excluded became
        11 to hold it -- see the comment directly above
        :data:`EXCLUDED_FROM_INTENUM_CENSUS` for why it lands there rather
        than among the 105. 105 itself does not move there: the new file is
        absorbed by the excluded side of the split, not the generated side.

        122 became 124 with GitHub issue #880's
        ``pcapkit/const/ngap/procedure_code.py`` and
        ``pcapkit/const/ngap/protocol_ie.py``. Unlike #886's file, both are
        the generated shape outright -- plain ``EnumRegistry`` + ``IntEnum``,
        no bespoke ``get()``/``_missing_``-carrying ``__new__`` -- so neither
        joins :data:`EXCLUDED_FROM_INTENUM_CENSUS`; they land on the
        *generated* side instead. 6 and 11 hold; 105 becomes 107, and 122
        becomes 124.
        """
        const_root = REPO_ROOT / 'pcapkit' / 'const'
        all_files = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in const_root.rglob('*.py')
            if path.name != '__init__.py'
        )
        converted_relpaths = {relpath for _, _, relpath in CONVERTED}
        generated = [path for path in all_files
                     if path not in converted_relpaths and path not in EXCLUDED_FROM_INTENUM_CENSUS]

        self.assertEqual(len(all_files), 124)
        self.assertEqual(len(generated), 107)

        for relpath in generated:
            with self.subTest(module=relpath):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertRegex(source, r'class \w+\(EnumRegistry, IntEnum\):')
                for method in PROTOCOL:
                    self.assertNotIn(f'def {method}(', source)


class GeneratedProtocolIsInheritedTests(unittest.TestCase):
    """The generated sample's protocol methods must resolve to the base
    class, exactly as :class:`ProtocolIsInheritedTests` above pins for the
    six bespoke ones."""

    if TYPE_CHECKING:
        registries: 'list[Any]'
        base: 'Any'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.registries = [
            getattr(importlib.import_module(module_name), class_name)
            for module_name, class_name, _ in GENERATED_SAMPLE
        ]
        cls.base = importlib.import_module('pcapkit.corekit.enum').EnumRegistry
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_base_class_is_in_the_mro(self) -> None:
        for registry in self.registries:
            with self.subTest(registry=registry.__qualname__):
                self.assertIn(self.base, registry.__mro__)

    def test_every_method_resolves_to_the_base_implementation(self) -> None:
        for registry in self.registries:
            for method in PROTOCOL:
                with self.subTest(registry=registry.__qualname__, method=method):
                    self.assertEqual(getattr(registry, method).__func__,
                                     getattr(self.base, method).__func__)

    def test_member_type_stays_int_not_enumregistry(self) -> None:
        """The base-class ordering rule #855 established:
        ``class {NAME}(EnumRegistry, IntEnum)`` with the non-``Enum`` mixin
        first is what keeps :mod:`aenum` resolving ``_member_type_`` from
        ``IntEnum`` rather than from the mix-in -- verified rather than
        assumed, per this tier's own instructions."""
        for registry in self.registries:
            with self.subTest(registry=registry.__qualname__):
                self.assertIs(registry._member_type_, int)


class GeneratedMissingRangeParityTests(unittest.TestCase):
    """``_missing_``'s own bounded ranges must behave identically after the
    conversion -- it was deliberately left untouched, so this is a
    regression pin on that claim rather than a test of new behaviour."""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_hardware_still_bounds_and_resolves_its_unassigned_ranges(self) -> None:
        """:class:`~pcapkit.const.arp.hardware.Hardware` declares ``0..38``
        and ``39..255``/``258..65534`` as unassigned-but-in-range, ``65535``
        as its own reserved member, and rejects anything else -- unchanged by
        this tier, which only removed the duplicate ``get``/``register``/
        ``_unregistered_member`` sitting next to it."""
        from pcapkit.const.arp.hardware import Hardware

        # In range, unassigned: resolves without minting a permanent member
        # (tier 1's fix), reachable via the now-inherited get() too.
        for value in (39, 255, 258, 65534):
            with self.subTest(value=value):
                self.assertEqual(Hardware(value).value, value)
                self.assertEqual(Hardware(value).name, 'Unassigned')
                self.assertNotIn(value, Hardware._value2member_map_)
                self.assertEqual(Hardware.get(value).value, value)

        # Out of the declared 0..65535 range: still raises, with or without
        # a default -- the default is only consulted once _missing_ itself
        # has already failed to resolve the key.
        with self.assertRaises(ValueError):
            Hardware(65536)
        with self.assertRaises(ValueError):
            Hardware.get(65536)
        self.assertIs(Hardware.get(65536, 1), Hardware.Ethernet)

    def test_transtype_no_longer_mints_its_declared_unassigned_range(self) -> None:
        """:class:`~pcapkit.const.reg.transtype.TransType` used to be the
        other shape: its own ``_missing_`` minted permanently via
        :func:`~aenum.extend_enum` for ``148..252`` rather than going through
        ``_unregistered_member``. GitHub issues #775/#847's mint-criterion
        ruling converted it: the label is a bare ``Unassigned``, which is a
        notation for the reader rather than a name IANA assigned, so it now
        matches :class:`~pcapkit.const.arp.hardware.Hardware`'s shape above
        instead of standing apart from it."""
        from pcapkit.const.reg.transtype import TransType

        before = len(TransType._member_names_)
        member = TransType(200)

        self.assertEqual(member.value, 200)
        self.assertEqual(member.name, 'Unassigned')
        self.assertNotIn(200, TransType._value2member_map_)
        self.assertEqual(before, len(TransType._member_names_))
        self.assertEqual(TransType(200), TransType.get(200))

        with self.assertRaises(ValueError):
            TransType(9999)


class RegisterAlreadyRegisteredNowRaisesOnAGeneratedRegistryTests(unittest.TestCase):
    """The residue #855 disclosed and this tier's own instructions name:
    ``register()`` on an already-registered value used to silently alias
    rather than mint or raise, on every one of the 107 generated registries
    (they had no guard of their own -- only the six bespoke ones tier 2
    already fixed did). Measured directly, before and after, in the
    docstring below rather than only asserted.

    Before (commit ``05468a06b``, this batch's own base)::

        >>> TransType.register(6, 'TOTALLY_NEW_NAME')
        <TransType.TCP: 6>              # returned the *existing* member
        # 'TOTALLY_NEW_NAME' in TransType.__members__ == True
        # _member_names_ grew by 0 -- nothing minted, nothing raised

    After (this commit)::

        >>> TransType.register(6, 'TOTALLY_NEW_NAME')
        ValueError: 6 is already registered on TransType as 'TCP'; use
        TransType.register_alias() to add a further name for it
        # 'TOTALLY_NEW_NAME' in TransType.__members__ == False

    """

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_register_over_a_taken_value_now_raises(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        names_before = list(TransType._member_names_)
        members_before = dict(TransType.__members__)

        with self.assertRaises(ValueError) as caught:
            TransType.register(6, 'TOTALLY_NEW_NAME')

        self.assertIn('6', str(caught.exception))
        self.assertIn('TCP', str(caught.exception))
        self.assertIn('register_alias', str(caught.exception))
        self.assertEqual(names_before, list(TransType._member_names_))
        self.assertEqual(members_before, dict(TransType.__members__))
        self.assertNotIn('TOTALLY_NEW_NAME', TransType.__members__)
        self.assertIs(TransType(6), TransType.TCP)

    def test_register_still_mints_for_a_genuinely_new_value(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        value = _unused_value(TransType)
        self.addCleanup(_purge_member, TransType, 'unit_test_generated_minted')

        member = TransType.register(value, 'unit_test_generated_minted')

        self.assertEqual(member.value, value)
        self.assertIn(value, TransType._value2member_map_)


class GetDispatchMatrixTests(unittest.TestCase):
    """The dispatch flip this tier's own instructions name: the generated
    ``get()`` checked ``isinstance(key, int)`` first and treated anything
    else as a name; the inherited base checks ``isinstance(key, str)`` first
    and treats anything else as a value. For a key that actually is an ``int``
    or a ``str``, both orderings agree, so every probe below except the
    "neither" one is a parity pin rather than a change; the "neither" probe
    is the one documented, deliberate difference, measured before and after
    on ``TransType`` (a plain generated ``IntEnum`` registry):

    Before (commit ``05468a06b``)::

        >>> TransType.get(3.5)
        KeyError: 3.5          # not int -> treated as a name -> dict miss

    After (this commit)::

        >>> TransType.get(3.5)
        ValueError: 3.5 is not a valid TransType   # not str -> treated as a
        # value -> TransType(3.5) -> _missing_(3.5) -> not int -> ValueError

    Neither raised exception mints anything, and both are still exactly the
    kind of error :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s own
    docstring promises for an unresolvable key with no default.
    """

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_valid_int_value(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get(6), TransType.TCP)

    def test_valid_name(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get('TCP'), TransType.TCP)

    def test_missing_name_without_default_raises_key_error(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        with self.assertRaises(KeyError):
            TransType.get('Definitely_Not_A_Member')

    def test_missing_name_with_default_falls_back(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get('Definitely_Not_A_Member', 6), TransType.TCP)

    def test_missing_int_without_default_raises_value_error(self) -> None:
        """``9999`` is outside TransType's declared ``0..255`` domain
        entirely, so this is a genuine miss rather than an unassigned-but
        in-range value that ``_missing_`` would otherwise mint."""
        from pcapkit.const.reg.transtype import TransType

        with self.assertRaises(ValueError):
            TransType.get(9999)

    def test_missing_int_with_default_falls_back(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get(9999, 6), TransType.TCP)

    def test_a_key_that_is_neither_int_nor_str_flips_exception_type(self) -> None:
        """The one deliberate, documented behaviour change this tier makes,
        pinned to the *new* (post-migration) shape: a key that is neither
        ``int`` nor ``str`` now raises :exc:`ValueError` (treated as a value,
        rejected by ``_missing_``'s own ``isinstance(value, int)`` guard)
        rather than the old :exc:`KeyError` (treated as a name, rejected by
        a plain dict lookup) -- measured before/after in this class's own
        docstring above."""
        from pcapkit.const.reg.transtype import TransType

        for key in (3.5, None, b'x'):
            with self.subTest(key=key):
                with self.assertRaises(ValueError) as caught:
                    TransType.get(key)
                self.assertIn('is not a valid TransType', str(caught.exception))


class GetDispatchMatrixIntFlagTests(unittest.TestCase):
    """The same matrix as :class:`GetDispatchMatrixTests`, on an
    :class:`~aenum.IntFlag` registry rather than a plain
    :class:`~aenum.IntEnum` one -- GitHub issue #860's own instructions call
    for measuring both member types the base serves, not just one. Every
    probe here is unchanged by #860's ``str``-branch fix, since
    ``HandoverACKFlag.get`` never takes that branch for an ``int`` key or a
    key that is neither ``int`` nor ``str``; this class exists to pin that
    the ``IntFlag`` path really is untouched, not to assume it."""

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_valid_int_value(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get(0x80), HandoverACKFlag.U)

    def test_valid_name(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get('U'), HandoverACKFlag.U)

    def test_missing_name_without_default_raises_key_error(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        with self.assertRaises(KeyError):
            HandoverACKFlag.get('Definitely_Not_A_Member')

    def test_missing_name_with_default_falls_back(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get('Definitely_Not_A_Member', 0x40), HandoverACKFlag.P)

    def test_missing_int_without_default_raises_value_error(self) -> None:
        """``9999`` is outside the ``0..0xFF`` range ``HandoverACKFlag``'s own
        ``_missing_`` bounds, so this is a genuine miss."""
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        with self.assertRaises(ValueError):
            HandoverACKFlag.get(9999)

    def test_missing_int_with_default_falls_back(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get(9999, 0x40), HandoverACKFlag.P)

    def test_a_key_that_is_neither_int_nor_str_raises_value_error(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        for key in (3.5, None, b'x'):
            with self.subTest(key=key):
                with self.assertRaises(ValueError) as caught:
                    HandoverACKFlag.get(key)
                self.assertIn('is not a valid HandoverACKFlag', str(caught.exception))


class StrEnumValueFallbackTests(unittest.TestCase):
    """GitHub issue #860, step 1: the base ``get()``'s ``isinstance(key, str)``
    branch used to try only ``cls._member_map_[key]`` -- a *name* lookup --
    and never fall back to treating a ``str`` key as a *value*, unlike the
    integer path. That was pre-existing behaviour of
    :class:`~pcapkit.corekit.enum.EnumRegistry` itself (added by tier 1,
    #855, which never converted a :class:`~aenum.StrEnum` registry either),
    found during #858's review on a synthetic registry rather than a real
    one, since at the time none of the four bespoke ``StrEnum`` const
    registries mixed in this base yet (:data:`EXCLUDED_FROM_INTENUM_CENSUS`
    above, which still holds them out of *this* file's tier-3 sweep for a
    different reason -- they are :class:`~aenum.StrEnum`, not
    :class:`~aenum.IntEnum`, which is reason (a) there regardless of
    whether any one of them also overrides the base) --
    that conversion was #860's separate step 2, landed by PR 1 for three of
    the four (``FEATCode``, ``Command``, ``Method``) and by PR 2 for the
    fourth (``AppType``, along with its four transport subclasses, which
    were not themselves among the original four but inherit the same fix).

    Fixed here by falling back to a plain ``_value2member_map_`` lookup, not
    ``cls(key)``: at the time this was written, :class:`~pcapkit.const.ftp.
    command.FEATCode`'s own ``_missing_`` minted directly via
    :func:`~aenum.extend_enum` for any unrecognised value (that minting call
    reproduced verbatim in
    :meth:`test_get_never_mints_on_a_registry_whose_missing_mints_directly`
    below), so routing the value fallback through the constructor would have
    let a failed *name* lookup mint a permanent member the moment #860's
    step 2 converted a registry like it onto this base -- exactly the
    "never mints" defect :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s
    own docstring rules out. Step 2 has since landed and converted
    ``FEATCode`` itself (its ``_missing_`` now calls
    ``_unregistered_member`` rather than ``extend_enum``, per the owner's
    #860 ruling), which is why the fixture below is a synthetic local class
    reproducing the *old* shape rather than importing the real one -- the
    defect this test guards against is general, not tied to one now-fixed
    example. A raw dict lookup can never reach ``_missing_``, so it cannot
    mint regardless of what a subclass's own ``_missing_`` does.
    """

    def test_a_str_key_that_is_a_value_but_not_a_name_now_resolves(self) -> None:
        """The defect itself. Fails on ``main`` (raises ``KeyError``, see the
        module docstring's reproduction), passes here."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

        # The name resolves, as it always would.
        self.assertIs(_Str.get('KNOWN'), _Str.KNOWN)

        # The *value* -- a different string from the name -- now resolves
        # too, matching what the constructor already did directly.
        self.assertIs(_Str('known-value'), _Str.KNOWN)
        self.assertIs(_Str.get('known-value'), _Str.KNOWN)

    def test_name_wins_over_a_different_members_value(self) -> None:
        """Ordering decision: a name match wins over a value match, so a
        string that is *both* a member's name and a different member's
        value resolves to the name's member. This already held for a name
        that resolves before this fix (the name branch is untouched), so it
        passes on both trees -- it is the ordering this fix's fall-through
        had to preserve, not new behaviour, and is pinned here so the
        ordering stays a decision rather than an accident."""
        class _Str(EnumRegistry, StrEnum):
            ALPHA = 'BETA'
            BETA = 'gamma'

        self.assertIs(_Str.get('BETA'), _Str.BETA)
        self.assertIsNot(_Str.get('BETA'), _Str.ALPHA)

    def test_a_str_value_match_wins_over_a_supplied_default(self) -> None:
        """A second, compounding half of the same defect: on ``main``, the
        ``str`` branch's ``except KeyError`` fires for *any* non-name key,
        so a supplied ``default`` was returned even when the key itself was
        a perfectly good value -- the default silently overrode a match that
        should have won. Fails on ``main`` (returns ``_Str('elsewhere')``
        instead of ``_Str.KNOWN``), passes here."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'
            ELSEWHERE = 'elsewhere'

        self.assertIs(_Str.get('known-value', 'elsewhere'), _Str.KNOWN)

    def test_missing_value_with_no_match_and_no_default_still_raises_key_error(self) -> None:
        """A ``str`` key that resolves neither as a name nor as a value, with
        no default, still raises :exc:`KeyError` -- not :exc:`ValueError` --
        matching :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s own
        documented contract for a name miss. Unchanged by this fix: passes
        on both trees."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

        with self.assertRaises(KeyError):
            _Str.get('totally-unknown')

    def test_get_never_mints_on_a_registry_whose_missing_mints_directly(self) -> None:
        """The crux this fix has to get right: the minting half of this
        fixture's ``_missing_`` was, at the time this test was written,
        verbatim :meth:`~pcapkit.const.ftp.command.FEATCode._missing_`'s own
        body -- ``extend_enum(cls, value.upper(), value)`` for any
        unrecognised string. GitHub issue #860 step 2 has since converted
        the real ``FEATCode`` onto ``_unregistered_member`` (per the owner's
        ruling that ``get``/``_missing_`` should not mint there either), so
        this fixture is kept as a synthetic, self-contained reproduction of
        the *old* shape rather than updated to import the real class --
        the point of this test is the general defect class, which a fixed
        example can no longer demonstrate. Its non-``str`` branch differs
        from that old shape (delegates to ``super()._missing_`` rather than
        ``FEATCode``'s own explicit ``ValueError``), which is immaterial to
        what this test proves. A naive ``return cls(key)`` fallback would
        mint a permanent member from a mere failed lookup; the
        ``_value2member_map_`` lookup this fix uses instead never reaches
        ``_missing_`` at all, so it cannot. Passes on both trees -- ``main``
        never attempts the value path in the first place, so it cannot mint
        either; this pins that the fix does not regress that guarantee while
        closing the gap."""
        class _MintingStr(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

            @classmethod
            def _missing_(cls, value: 'Any') -> 'Any':
                if not isinstance(value, str):
                    return super()._missing_(value)
                return extend_enum(cls, value.upper(), value)

        values_before = {member.value for member in _MintingStr}
        members_before = set(_MintingStr.__members__)

        with self.assertRaises(KeyError):
            _MintingStr.get('never-seen-before')

        self.assertEqual(values_before, {member.value for member in _MintingStr})
        self.assertEqual(members_before, set(_MintingStr.__members__))


class NoDefaultSentinelTests(unittest.TestCase):
    """GitHub issue #857: :data:`~pcapkit.corekit.enum.NO_DEFAULT` is now an
    instance of the dedicated :class:`~pcapkit.corekit.enum.NoDefaultType`
    compared with ``is``, rather than the magic value ``-1`` compared with
    ``==``. Owner ruling on #859: a bare :class:`object` -- this batch's first
    attempt -- is no less safe under ``is``, but a dedicated class matches the
    house convention :class:`~pcapkit.corekit.module.NullType` and
    :class:`~pcapkit.corekit.fields.field.NoValueType` already set, and gives
    a readable :func:`repr` in a signature, in :func:`help`, and in a
    traceback.

    Before #857, ``default == NO_DEFAULT`` read a caller-supplied ``-1`` --
    or, worse, ``-1.0``, since ``-1.0 == -1`` -- as if no default had been
    supplied at all, so the caller's own fallback silently never took effect.
    There is no live defect in :mod:`pcapkit.const` today (no registry's
    domain reaches ``-1``), so this batch pins the *clarity* fix: ``-1`` and
    ``-1.0`` are ordinary defaults now, indistinguishable from any other
    value a caller might pass.
    """

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_no_default_is_not_equal_to_any_plausible_caller_value(self) -> None:
        """The sentinel's whole point: unlike ``-1``, a
        :class:`~pcapkit.corekit.enum.NoDefaultType` instance -- which defines
        no ``__eq__`` of its own, so it inherits identity comparison from
        :class:`object` -- cannot compare equal to anything a caller might
        legitimately pass as ``default``, not even ``-1.0``, which the old
        ``-1`` marker could not tell apart from itself."""
        from pcapkit.corekit.enum import NO_DEFAULT

        for value in (-1, -1.0, 0, '', None, False):
            with self.subTest(value=value):
                self.assertNotEqual(NO_DEFAULT, value)
                self.assertIsNot(NO_DEFAULT, value)

    def test_repr_is_the_readable_form_not_a_bare_object_address(self) -> None:
        """The concrete reason #859 asked for a dedicated class over a bare
        ``object()``: the latter prints as ``<object object at 0x...>``
        wherever it turns up -- a signature, :func:`help`, a traceback --
        and this prints as ``<NO_DEFAULT>`` instead."""
        from pcapkit.corekit.enum import NO_DEFAULT

        rendered = repr(NO_DEFAULT)
        self.assertEqual(rendered, '<NO_DEFAULT>')
        self.assertNotIn('0x', rendered)

    def test_type_is_the_dedicated_sentinel_class_and_only_the_object_is_exported(self) -> None:
        """GitHub issue #911 reversed half of what this used to assert.

        It read ``assertIn('NoDefaultType', enum_module.__all__)`` -- the type
        *and* the object were exported. The owner's ruling: *"we should ONLY
        export the objects (like* ``NULL`` *) to users"*, so the type is out of
        :attr:`__all__` while staying importable by its dotted path, which is
        what the last assertion here pins.
        """
        import pcapkit.corekit.enum as enum_module

        self.assertIs(type(enum_module.NO_DEFAULT), enum_module.NoDefaultType)
        self.assertIn('NO_DEFAULT', enum_module.__all__)
        self.assertNotIn('NoDefaultType', enum_module.__all__)
        self.assertTrue(hasattr(enum_module, 'NoDefaultType'))

    def test_constructing_the_type_again_returns_the_same_instance(self) -> None:
        """The ``__new__`` singleton guard: a caller who does not realise
        :data:`~pcapkit.corekit.enum.NO_DEFAULT` already exists and writes
        ``NoDefaultType()`` themselves still gets back the one canonical
        sentinel, rather than a second, non-identical object that would
        silently fail ``is NO_DEFAULT`` inside
        :meth:`~pcapkit.corekit.enum.EnumRegistry.get` and be treated as a
        real (if useless) default instead of *no default*."""
        from pcapkit.corekit.enum import NO_DEFAULT, NoDefaultType

        self.assertIs(NoDefaultType(), NO_DEFAULT)
        # And repeatedly -- not merely once by coincidence.
        self.assertIs(NoDefaultType(), NoDefaultType())

    def test_identity_survives_an_ordinary_second_import(self) -> None:
        """An already-loaded module is cached in :data:`sys.modules`, so
        importing it again -- by any of the usual spellings -- must not
        construct a second sentinel. Only a genuine :func:`importlib.reload`
        would do that (see :class:`~pcapkit.corekit.enum.NoDefaultType`'s own
        docstring caveat, and :class:`~pcapkit.corekit.module.NullType`'s
        before it), and nothing in this package reloads
        :mod:`pcapkit.corekit.enum` after import."""
        import importlib

        from pcapkit.corekit.enum import NO_DEFAULT as first_import

        module_again = importlib.import_module('pcapkit.corekit.enum')

        self.assertIs(module_again.NO_DEFAULT, first_import)

    def test_missing_name_with_default_negative_one_is_now_a_real_default(self) -> None:
        """Coincidentally passes on the pre-#857 tree too, not just this one:
        ``ExtensionHeader.get(<missing>, -1)`` raised :exc:`KeyError` there
        as well, because ``-1 == NO_DEFAULT`` read the caller's ``-1`` as *no
        default* and re-raised the name lookup's own error -- the same
        exception type and content this test asserts, but for the wrong
        reason (silently discarding an explicit default rather than
        genuinely attempting and failing to resolve it). This test no longer
        discriminates that defect; the pin for it is
        :meth:`NoDefaultSentinelTests.test_no_default_is_not_equal_to_any_plausible_caller_value`,
        which checks the sentinel's identity comparison directly, never
        touches :meth:`~pcapkit.corekit.enum.EnumRegistry.get`, and so is
        unaffected by #864 -- look there, not here, for that discrimination.

        ``-1`` is a genuine default here, not a rediscovered sentinel; it is
        simply not a *resolvable* one, since #864 restricts
        ``default`` to :attr:`~pcapkit.corekit.enum.EnumRegistry._value2member_map_`,
        every registry's domain starts at ``0``, and there is no
        ``cls(default)`` fallback left to attempt and raise a fresh
        :exc:`ValueError` from. So the original name lookup's own
        :exc:`KeyError` propagates instead, exactly as it would with no
        default at all. Updated from the pre-#864 tree, which asserted
        :exc:`ValueError` mentioning ``-1`` and not the original key -- that
        assertion described ``cls(-1)`` failing, a code path #864 removes; it
        is not weakened here, it is retargeted at the deliberate replacement
        contract, and still pins that ``-1`` never mints anything.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(KeyError) as caught:
            ExtensionHeader.get('Definitely-Not-A-Member', -1)
        self.assertIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_missing_name_with_default_negative_one_float_is_now_a_real_default(self) -> None:
        """The float case that actually motivates #857: ``-1.0 == -1`` is
        ``True``, so the old ``==`` comparison could not tell a caller's
        ``-1.0`` apart from the ``-1`` marker either. Coincidentally passes
        on the pre-#857 tree too, for the same reason its sibling test above
        explains -- the old comparison read ``-1.0`` as the sentinel there,
        producing the very same :exc:`KeyError` this asserts, for the wrong
        reason. The discriminating pin for #857 lives in
        :meth:`NoDefaultSentinelTests.test_no_default_is_not_equal_to_any_plausible_caller_value`
        instead, not here -- see that sibling test's docstring for why.

        Raises :exc:`KeyError` here, post-#864, for the reason its sibling
        test above explains: ``-1.0`` is not a registered value, ``default``
        no longer reaches ``cls(default)`` to fail on its own terms, and the
        original name lookup's error propagates instead. Updated from the
        pre-#864 tree, which asserted :exc:`ValueError` mentioning ``-1.0``
        for ``ExtensionHeader(-1.0)`` -- that path no longer exists; this is
        the same no-weaker retargeting as above.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(KeyError) as caught:
            ExtensionHeader.get('Definitely-Not-A-Member', -1.0)
        self.assertIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_missing_name_without_default_still_raises_on_an_int_enum(self) -> None:
        """Omitting ``default`` entirely is unaffected by this change -- it
        was, and remains, ``NO_DEFAULT`` by the parameter's own default
        value, so identity trivially holds either way."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(KeyError) as caught:
            ExtensionHeader.get('Definitely-Not-A-Member')
        self.assertIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_missing_name_without_default_still_raises_on_an_int_flag(self) -> None:
        """As above, on an :class:`~aenum.IntFlag` registry -- the base
        ``get()`` does not branch on member type before consulting
        ``NO_DEFAULT``."""
        from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag

        before = len(BindingUpdateFlag.__members__)
        with self.assertRaises(KeyError) as caught:
            BindingUpdateFlag.get('Definitely-Not-A-Member')
        self.assertIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(BindingUpdateFlag.__members__))


class GetDefaultNoMintTests(unittest.TestCase):
    """GitHub issue #864. Both ``cls(default)`` sites -- the ``str`` branch's
    and the value branch's -- reached ``_missing_`` for a ``default`` that
    fell inside a still-minting registry's own range, growing the registry
    as a side effect of resolving ``default`` rather than ``key``. The
    owner's ruling, verbatim: *"Take (b). Only register can mint. get should
    not mint unless it falls through the ``_missing_``'s minted ranges."*,
    and on the implementation, choosing option 1 of three: *"I think 1 is
    correct mechanism we'd like."* -- ``default`` now resolves through a
    plain ``_value2member_map_`` lookup only, so it cannot mint by
    construction, while ``key`` resolution -- and whatever it lets
    ``_missing_`` do -- is deliberately unchanged.
    """

    def setUp(self) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_the_issues_own_case_no_longer_mints_and_raises_instead(self) -> None:
        """The exact reproduction from #864, on the real shipped registry.
        Measured live on ``main`` before this fix::

            >>> len(EtherType.__members__)
            160
            >>> EtherType.get(0x1234, 0x0888)
            <EtherType.Xyplex_0x0888: 2184>
            >>> len(EtherType.__members__)
            161

        ``0x1234`` (4660) falls in no ``_missing_`` range, so the lookup
        falls to ``default``; ``0x0888`` (2184) falls inside the ``Xyplex``
        range #775's *original* ruling deliberately kept minting at the
        time -- but only when reached as a ``key``. (#775's final round has
        since converted that range too; see
        :meth:`GetDefaultNoMintTests.test_key_path_minting_is_preserved`.)
        Fails on the pre-#864 tree for that reason; passes here because
        ``default`` no longer reaches ``cls(default)`` at all, so ``0x0888``
        not being an *already-registered* value propagates the ``0x1234``
        lookup's own failure instead of minting anything."""
        from pcapkit.const.reg.ethertype import EtherType

        before = len(EtherType.__members__)
        self.assertEqual(before, 160)  # the issue's own measured baseline
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)

        with self.assertRaises(ValueError) as caught:
            EtherType.get(0x1234, 0x0888)
        self.assertIn('4660', str(caught.exception))  # 0x1234 -- the key
        self.assertNotIn('2184', str(caught.exception))  # 0x0888 -- the default

        self.assertEqual(before, len(EtherType.__members__))
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)

    def test_key_path_minting_is_preserved(self) -> None:
        """Originally a no-change guard: ``EtherType.get(0x0888)`` -- no
        ``default`` at all -- used to mint ``Xyplex_0x0888`` through its own
        ``_missing_``, back when ruling one's mint/unmint criterion
        (*"get should not mint unless it falls through the _missing_'s
        minted ranges"*) still classed ``Xyplex`` as a kept-minting,
        real-attributed-name range. GitHub issue #775's final round converts
        that range (and every other one still minting on ``EtherType``/
        :class:`~pcapkit.const.ipx.socket.Socket`) to :meth:`~pcapkit.corekit.
        enum.EnumRegistry._unregistered_member`, preserving the hex-suffixed
        name unchanged -- so ``key`` resolution through ``get()`` now goes
        through the same non-minting path ``_missing_`` always did for this
        value, and the guard flips to prove that rather than the opposite.
        #864's own point -- that ``default`` never reaches ``_missing_`` at
        all -- is unaffected either way."""
        from pcapkit.const.reg.ethertype import EtherType

        before = len(EtherType.__members__)
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)
        self.assertNotIn(0x0888, EtherType._value2member_map_)  # type: ignore[attr-defined]

        result = EtherType.get(0x0888)

        self.assertEqual(result.name, 'Xyplex_0x0888')
        self.assertEqual(result.value, 0x0888)
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)
        self.assertNotIn(0x0888, EtherType._value2member_map_)  # type: ignore[attr-defined]
        self.assertEqual(before, len(EtherType.__members__))

        second = EtherType.get(0x0888)
        self.assertEqual(result, second)
        self.assertIsNot(result, second)

    def test_default_still_resolves_when_registered_int(self) -> None:
        """The ruling's other half: a ``default`` that *is* already a member
        still resolves, on an ``int``-valued (and, here, still-minting)
        registry -- #864 restricts ``default`` to
        ``_value2member_map_``, it does not disable it."""
        from pcapkit.const.reg.ethertype import EtherType

        target = EtherType.Internet_Protocol_version_4
        before = len(EtherType.__members__)

        result = EtherType.get(0x1234, target.value)

        self.assertIs(result, target)
        self.assertEqual(before, len(EtherType.__members__))

    def test_default_still_resolves_when_registered_str(self) -> None:
        """As above, on a ``str``-valued registry. Not a hypothetical shape
        any more: ten shipped :class:`~aenum.StrEnum` registries mix in the
        base now (``Command``, ``FEATCode``, ``Method``, ``OptionType``,
        ``TLSKeyLabel``, ``AppType`` and its four transport subclasses --
        :data:`EXCLUDED_FROM_INTENUM_CENSUS` holds all ten out of *this*
        file's ``IntEnum``-only sweep, not out of existence). This case
        still builds its own rather than importing one of them, so the
        assertion stays pinned to the base's fallback behaviour itself
        rather than to a shipped registry's incidental member values."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'
            OTHER = 'other-value'

        result = _Str.get('totally-unknown-name', 'other-value')

        self.assertIs(result, _Str.OTHER)
        self.assertEqual({'KNOWN', 'OTHER'}, set(_Str.__members__))

    def test_default_naming_no_registered_member_raises_the_original_error(self) -> None:
        """Ruling one's accepted cost, made concrete: a ``default`` inside a
        declared-but-unassigned range used to resolve via ``cls(default)`` ->
        ``_missing_``; now it simply does not resolve, on either branch, and
        the *original* lookup error -- the one ``key`` itself would have
        raised -- propagates rather than a new error about ``default``."""
        from pcapkit.const.reg.ethertype import EtherType

        before = len(EtherType.__members__)

        # Non-``str`` branch: the original error is ValueError, about ``key``.
        with self.assertRaises(ValueError) as caught_value:
            EtherType.get(0x1234, 0x0888)
        self.assertIn('4660', str(caught_value.exception))
        self.assertNotIn('2184', str(caught_value.exception))

        # ``str`` branch: the original error is KeyError, about ``key``.
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

        with self.assertRaises(KeyError) as caught_key:
            _Str.get('totally-unknown-name', 'also-not-a-member')
        self.assertIn('totally-unknown-name', str(caught_key.exception))
        self.assertNotIn('also-not-a-member', str(caught_key.exception))

        self.assertEqual(before, len(EtherType.__members__))


if __name__ == '__main__':
    unittest.main()
