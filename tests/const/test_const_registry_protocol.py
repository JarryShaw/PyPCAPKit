# -*- coding: utf-8 -*-
"""Tests for :class:`pcapkit.corekit.enum.EnumRegistry`, tier 2 of issue #775.

Tier 1 (#838) removed the mint from the two sites in
:data:`pcapkit.vendor.default.LINE` that the 105 default-template registries
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

from aenum import IntEnum, IntFlag, StrEnum

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


#: Sample of the 105 default-template registries GitHub issue #775's tier 3
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
#: their crawler's own ``process()``/``context()`` with a bespoke,
#: mint-on-lookup ``get()``/``_missing_`` pair that does not share
#: :mod:`pcapkit.vendor.default`'s template at all -- converting any of them
#: onto :class:`~pcapkit.corekit.enum.EnumRegistry` would silently change
#: behaviour rather than just move it, per the base ``get()``'s own
#: str-key-never-tries-the-value-path limitation measured in
#: :class:`StrEnumValuePathLimitationTests` below. The remaining four
#: (``reg/apptype``'s transport subclasses) plus ``AppType``/
#: ``TransportProtocol`` themselves are excluded for the separate reason
#: :mod:`pcapkit.corekit.enum`'s own module docstring gives: they are tier 2
#: of GitHub issue #842's three-tier hierarchy, not tier 3, and stay as they
#: are until tier 2 lands.
EXCLUDED_STILL_BESPOKE = frozenset({
    'pcapkit/const/ftp/command.py',
    'pcapkit/const/ftp/return_code.py',
    'pcapkit/const/http/method.py',
    'pcapkit/const/http/status_code.py',
    'pcapkit/const/pcapng/option_type.py',
    'pcapkit/const/reg/apptype/apptype.py',
    'pcapkit/const/reg/apptype/dccp.py',
    'pcapkit/const/reg/apptype/sctp.py',
    'pcapkit/const/reg/apptype/tcp.py',
    'pcapkit/const/reg/apptype/udp.py',
})


class GeneratedTemplateSourceInheritsTests(unittest.TestCase):
    """The 105 default-template registries must inherit the protocol too,
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
        """The full census, measured on this batch rather than assumed: 121
        modules under :mod:`pcapkit.const`, splitting exactly three ways --
        the 6 :data:`CONVERTED` bespoke ones tier 2 already handled, the 10
        :data:`EXCLUDED_STILL_BESPOKE` deliberately left alone, and the
        remaining 105 this tier converts. Measured by me on the prior head
        (commit ``05468a06b``, this batch's own base): of those 121, 6 carried
        :class:`~pcapkit.corekit.enum.EnumRegistry` and 111 carried the
        literal "Backport support for original codes." docstring (including
        the 6 bespoke StrEnum/AppType files, since a hand-copied docstring is
        not proof of a shared template) -- 105 is what is left once the 6
        converted and the 10 excluded are both taken out.
        """
        const_root = REPO_ROOT / 'pcapkit' / 'const'
        all_files = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in const_root.rglob('*.py')
            if path.name != '__init__.py'
        )
        converted_relpaths = {relpath for _, _, relpath in CONVERTED}
        generated = [path for path in all_files
                     if path not in converted_relpaths and path not in EXCLUDED_STILL_BESPOKE]

        self.assertEqual(len(all_files), 121)
        self.assertEqual(len(generated), 105)

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

    def test_transtype_still_mints_its_declared_unassigned_range(self) -> None:
        """:class:`~pcapkit.const.reg.transtype.TransType` is the other
        shape: its own ``_missing_`` mints permanently via
        :func:`~aenum.extend_enum` for ``148..252`` rather than going through
        ``_unregistered_member`` -- also unchanged by this tier."""
        from pcapkit.const.reg.transtype import TransType

        before = len(TransType._member_names_)
        member = TransType(200)

        self.assertEqual(member.value, 200)
        self.assertEqual(member.name, 'Unassigned_200')
        self.assertIn(200, TransType._value2member_map_)
        self.assertEqual(before + 1, len(TransType._member_names_))

        with self.assertRaises(ValueError):
            TransType(9999)


class RegisterAlreadyRegisteredNowRaisesOnAGeneratedRegistryTests(unittest.TestCase):
    """The residue #855 disclosed and this tier's own instructions name:
    ``register()`` on an already-registered value used to silently alias
    rather than mint or raise, on every one of the 105 generated registries
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


class StrEnumValuePathLimitationTests(unittest.TestCase):
    """Justifies excluding every :class:`~aenum.StrEnum` const module from
    this tier (:data:`EXCLUDED_STILL_BESPOKE`'s ``ftp``/``http``/``pcapng``/
    ``reg.apptype`` entries): the base ``get()``'s ``isinstance(key, str)``
    branch only ever tries ``cls._member_map_[key]`` -- a *name* lookup -- and
    never falls back to treating a ``str`` key as a *value*, unlike the
    integer path. That is pre-existing behaviour of
    :class:`~pcapkit.corekit.enum.EnumRegistry` itself (added by tier 1,
    #855, which never converted a :class:`~aenum.StrEnum` registry either),
    not something this tier introduces -- reproduced here on a synthetic
    registry so the exclusion decision is measured rather than assumed, and
    so a future tier that does take on the ``StrEnum`` registries knows
    exactly what it would need to fix first.
    """

    def test_a_str_key_that_is_a_value_but_not_a_name_is_not_resolved(self) -> None:
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

        # The name resolves, as it always would.
        self.assertIs(_Str.get('KNOWN'), _Str.KNOWN)

        # The *value* -- a different string from the name -- does not, even
        # though ``_Str('known-value')`` (the constructor) resolves it fine.
        # This is the gap: get() never reaches the constructor for a str key.
        self.assertIs(_Str('known-value'), _Str.KNOWN)
        with self.assertRaises(KeyError):
            _Str.get('known-value')


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

    def test_type_is_the_dedicated_sentinel_class_and_both_are_exported(self) -> None:
        import pcapkit.corekit.enum as enum_module

        self.assertIs(type(enum_module.NO_DEFAULT), enum_module.NoDefaultType)
        self.assertIn('NO_DEFAULT', enum_module.__all__)
        self.assertIn('NoDefaultType', enum_module.__all__)

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
        """Fails on the pre-#857 tree: ``ExtensionHeader.get(<missing>, -1)``
        raised :exc:`KeyError` there, because ``-1 == NO_DEFAULT`` read the
        caller's ``-1`` as *no default* and re-raised the name lookup's own
        error. On this head it raises :exc:`ValueError` instead, for the
        *attempted fallback* ``ExtensionHeader(-1)`` -- ``-1`` is now a
        genuine default, and every registry's domain starts at ``0``, so it
        is itself unresolvable.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(ValueError) as caught:
            ExtensionHeader.get('Definitely-Not-A-Member', -1)
        self.assertIn('-1', str(caught.exception))
        self.assertNotIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_missing_name_with_default_negative_one_float_is_now_a_real_default(self) -> None:
        """The float case that actually motivates #857: ``-1.0 == -1`` is
        ``True``, so the old ``==`` comparison could not tell a caller's
        ``-1.0`` apart from the ``-1`` marker either. Fails on the pre-#857
        tree with :exc:`KeyError` for the same reason as the ``-1`` case
        above; raises :exc:`ValueError` here, for ``ExtensionHeader(-1.0)``.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(ValueError) as caught:
            ExtensionHeader.get('Definitely-Not-A-Member', -1.0)
        self.assertIn('-1.0', str(caught.exception))
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


if __name__ == '__main__':
    unittest.main()
