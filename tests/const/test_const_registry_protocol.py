# -*- coding: utf-8 -*-
"""Tests for :class:`pcapkit.corekit.enums.EnumRegistry`, tier 2 of issue #775.

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

:class:`~pcapkit.corekit.enums.EnumRegistry` is tier one of that hierarchy. This
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

from pcapkit.corekit.enums import EnumRegistry
from tests._support import ISOLATED_PREFIXES, purge_modules, restore_modules, snapshot_modules

if TYPE_CHECKING:
    from typing import Any

#: Repository root, for reading generated sources as text.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The batch converted onto :class:`~pcapkit.corekit.enums.EnumRegistry`: the
#: five bespoke-template registries whose members carry no extra attributes, so
#: the shared ``_unregistered_member`` -- which sets only ``_name_`` and
#: ``_value_`` -- builds a complete member for them. The other six bespoke
#: templates (``ftp/command``, ``ftp/return_code``, ``http/method``,
#: ``http/status_code``, ``pcapng/option_type``, ``tcp/flags``) each define a
#: custom ``__new__`` attaching further attributes, so an unregistered member of
#: theirs would be missing them; they need their own override and are out of this
#: batch.
CONVERTED = (
    ('pcapkit.const.mh.binding_ack_flag', 'BindingACKFlag', 'pcapkit/const/mh/binding_ack_flag.py'),
    ('pcapkit.const.mh.binding_update_flag', 'BindingUpdateFlag', 'pcapkit/const/mh/binding_update_flag.py'),
    ('pcapkit.const.mh.handover_ack_flag', 'HandoverACKFlag', 'pcapkit/const/mh/handover_ack_flag.py'),
    ('pcapkit.const.mh.handover_initiate_flag', 'HandoverInitiateFlag', 'pcapkit/const/mh/handover_initiate_flag.py'),
    ('pcapkit.const.ipv6.extension_header', 'ExtensionHeader', 'pcapkit/const/ipv6/extension_header.py'),
)

#: The crawlers whose bespoke templates were converted, and which must therefore
#: no longer spell a ``get()`` of their own.
CONVERTED_VENDORS = (
    'pcapkit/vendor/mh/binding_ack_flag.py',
    'pcapkit/vendor/mh/binding_update_flag.py',
    'pcapkit/vendor/mh/handover_ack_flag.py',
    'pcapkit/vendor/mh/handover_initiate_flag.py',
    'pcapkit/vendor/ipv6/extension_header.py',
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
                self.assertIn('from pcapkit.corekit.enums import EnumRegistry', source)
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
                self.assertIn('from pcapkit.corekit.enums import EnumRegistry', source)
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
        cls.base = importlib.import_module('pcapkit.corekit.enums').EnumRegistry
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


if __name__ == '__main__':
    unittest.main()
